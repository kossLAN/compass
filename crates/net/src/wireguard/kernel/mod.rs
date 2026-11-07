mod dump;
mod genetlink;
mod stun;

use std::sync::Arc;

use ipnet::IpNet;
use rtnetlink::LinkWireguard;
use rtnetlink::packet_route::link::InfoKind;

pub use self::stun::KernelStun;

use self::genetlink::Genetlink;
use crate::link::Links;
use crate::{DeviceSpec, DeviceState, NetError, PeerOp};

pub struct KernelDevice {
    spec: DeviceSpec,
    links: Links,
    genetlink: Genetlink,
    stun: Option<Arc<KernelStun>>,
}

impl KernelDevice {
    pub async fn connect(spec: &DeviceSpec, links: Links) -> Result<Option<Self>, NetError> {
        let genetlink = Genetlink::connect()?;

        if !genetlink.available().await {
            return Ok(None);
        }

        let stun = KernelStun::bind(spec.listen_port, spec.fwmark)
            .inspect_err(|error| tracing::warn!(%error, "cannot open a raw socket for STUN"))
            .ok()
            .map(Arc::new);

        Ok(Some(Self {
            spec: spec.clone(),
            links,
            genetlink,
            stun,
        }))
    }

    pub async fn ensure(&self, mtu: u16, addresses: &[IpNet]) -> Result<(), NetError> {
        let name = &self.spec.name;
        let index = match self.links.find(name).await? {
            Some(link) if link.kind == Some(InfoKind::Wireguard) => link.index,
            found => {
                if let Some(link) = found {
                    tracing::warn!(device = name, "replacing non-WireGuard interface");
                    self.links.delete(link.index).await?;
                }

                self.links.add(LinkWireguard::new(name).build()).await?;
                self.links.index(name).await?
            },
        };

        let current = self
            .genetlink
            .get(index)
            .await?
            .ok_or_else(|| NetError::MissingDevice(name.clone()))?;
        let key = (current.public_key != Some(self.spec.private_key.public_key()))
            .then_some(&self.spec.private_key);
        let port = (current.listen_port != self.spec.listen_port).then_some(self.spec.listen_port);
        let fwmark = (current.fwmark != self.spec.fwmark).then_some(self.spec.fwmark);

        if key.is_some() || port.is_some() || fwmark.is_some() {
            self.genetlink.configure(index, key, port, fwmark).await?;
        }

        self.links.configure(index, mtu, addresses).await
    }

    pub async fn state(&self) -> Result<DeviceState, NetError> {
        let missing = || NetError::MissingDevice(self.spec.name.clone());

        match self.links.find(&self.spec.name).await? {
            Some(link) if link.kind == Some(InfoKind::Wireguard) => {
                self.genetlink.get(link.index).await?.ok_or_else(missing)
            },
            _ => Err(missing()),
        }
    }

    pub async fn apply(&self, ops: &[PeerOp]) -> Result<(), NetError> {
        if ops.is_empty() {
            return Ok(());
        }

        let index = self.links.index(&self.spec.name).await?;
        self.genetlink.apply(index, ops).await
    }

    pub fn stun(&self) -> Option<Arc<KernelStun>> {
        self.stun.clone()
    }

    pub async fn delete(&self) -> Result<(), NetError> {
        self.links.delete_named(&self.spec.name).await
    }
}
