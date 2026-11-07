use std::collections::BTreeSet;

use ipnet::IpNet;

use crate::link::Links;
use crate::wg::Wireguard;
use crate::{
    DeviceSpec, DeviceState, LinkDns, LocalAddress, NetError, PeerOp, RouteSpec, RuleSpec,
    resolvconf, route, rule, sysctl,
};

pub struct Dataplane {
    links: Links,
    wireguard: Wireguard,
}

impl Dataplane {
    pub fn new() -> Result<Self, NetError> {
        Ok(Self {
            links: Links::connect()?,
            wireguard: Wireguard::connect()?,
        })
    }

    pub async fn ensure_device(&self, spec: &DeviceSpec) -> Result<(), NetError> {
        let index = match self.links.find(&spec.name).await? {
            Some(link) if link.is_wireguard => link.index,
            found => {
                if let Some(link) = found {
                    tracing::warn!(device = spec.name, "replacing non-WireGuard interface");
                    self.links.delete(link.index).await?;
                }

                self.links.create_wireguard(&spec.name).await?;
                self.links.index(&spec.name).await?
            },
        };

        let current = self
            .wireguard
            .get(index)
            .await?
            .ok_or_else(|| NetError::MissingDevice(spec.name.clone()))?;
        let key = (current.public_key != Some(spec.private_key.public_key()))
            .then_some(&spec.private_key);
        let port = spec.listen_port.filter(|port| *port != current.listen_port);
        let fwmark = (current.fwmark != spec.fwmark).then_some(spec.fwmark);

        if key.is_some() || port.is_some() || fwmark.is_some() {
            self.wireguard.configure(index, key, port, fwmark).await?;
        }

        self.configure(index, spec.mtu, &spec.addresses).await
    }

    pub async fn device(&self, name: &str) -> Result<DeviceState, NetError> {
        let missing = || NetError::MissingDevice(name.to_owned());

        match self.links.find(name).await? {
            Some(link) if link.is_wireguard => {
                self.wireguard.get(link.index).await?.ok_or_else(missing)
            },
            _ => Err(missing()),
        }
    }

    pub async fn apply_peers(&self, device: &str, ops: &[PeerOp]) -> Result<(), NetError> {
        if ops.is_empty() {
            return Ok(());
        }

        let index = self.links.index(device).await?;
        self.wireguard.apply(index, ops).await
    }

    pub async fn delete_device(&self, name: &str) -> Result<(), NetError> {
        match self.links.find(name).await? {
            Some(link) => self.links.delete(link.index).await,
            None => Ok(()),
        }
    }

    pub async fn sync_routes(&self, routes: &BTreeSet<RouteSpec>) -> Result<(), NetError> {
        route::sync(&self.links, routes).await
    }

    pub async fn sync_rules(&self, rules: &BTreeSet<RuleSpec>) -> Result<(), NetError> {
        rule::sync(&self.links, rules).await
    }

    pub async fn remove_rules(&self) -> Result<(), NetError> {
        rule::sync(&self.links, &BTreeSet::new()).await
    }

    pub async fn wireguard_available(&self) -> bool {
        self.wireguard.available().await
    }

    pub async fn configure_link(
        &self,
        name: &str,
        mtu: u16,
        addresses: &[IpNet],
    ) -> Result<(), NetError> {
        let index = self.links.index(name).await?;
        self.configure(index, mtu, addresses).await
    }

    async fn configure(&self, index: u32, mtu: u16, addresses: &[IpNet]) -> Result<(), NetError> {
        self.links.bring_up(index, mtu).await?;
        self.links.sync_addresses(index, addresses).await
    }

    pub async fn set_dns(&self, device: &str, dns: Option<&LinkDns>) -> Result<(), NetError> {
        match dns {
            Some(dns) => resolvconf::configure(device, dns).await,
            None => resolvconf::remove(device).await,
        }
    }

    pub async fn sysctl(&self, key: &str) -> Result<Option<String>, NetError> {
        sysctl::read(key).await
    }

    pub async fn local_addresses(&self) -> Result<Vec<LocalAddress>, NetError> {
        let names = self.links.names().await?;
        Ok(self
            .links
            .addresses()
            .await?
            .into_iter()
            .filter_map(|(index, address)| {
                let interface = names.get(&index)?.clone();
                Some(LocalAddress { interface, address })
            })
            .collect())
    }
}
