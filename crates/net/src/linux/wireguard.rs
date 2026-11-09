use std::fmt;
use std::sync::Arc;

use ipnet::IpNet;

use super::kernel::KernelDevice;
use super::link::Links;
use crate::{DeviceSpec, DeviceState, NetError, PeerOp, Stun, Tun, UserspaceDevice};

pub enum Wireguard {
    Kernel(KernelDevice),
    Userspace {
        device: UserspaceDevice,
        name: String,
        links: Links,
    },
}

impl Wireguard {
    pub async fn detect(spec: &DeviceSpec) -> Result<Self, NetError> {
        let links = Links::connect()?;

        if let Some(device) = KernelDevice::connect(spec, links.clone()).await? {
            return Ok(Self::Kernel(device));
        }

        let tun = tun_rs::DeviceBuilder::new()
            .name(&spec.name)
            .offload(true)
            .build_async()
            .map_err(NetError::Tun)?;
        let mut device =
            UserspaceDevice::new(&spec.private_key, spec.listen_port, Some(spec.fwmark), None)?;
        device.set_tun(Arc::new(Tun::offload(tun)));

        Ok(Self::Userspace {
            device,
            name: spec.name.clone(),
            links,
        })
    }

    pub async fn ensure(&mut self, mtu: u16, addresses: &[IpNet]) -> Result<(), NetError> {
        match self {
            Self::Kernel(device) => device.ensure(mtu, addresses).await,
            Self::Userspace {
                device,
                name,
                links,
            } => {
                device.set_mtu(mtu);
                let index = links.index(name).await?;
                links.configure(index, mtu, addresses).await
            },
        }
    }

    pub async fn state(&self) -> Result<DeviceState, NetError> {
        match self {
            Self::Kernel(device) => device.state().await,
            Self::Userspace { device, .. } => Ok(device.state()),
        }
    }

    pub async fn apply(&mut self, ops: &[PeerOp]) -> Result<(), NetError> {
        match self {
            Self::Kernel(device) => device.apply(ops).await,
            Self::Userspace { device, .. } => {
                device.apply(ops);
                Ok(())
            },
        }
    }

    pub fn stun(&self) -> Option<Stun> {
        match self {
            Self::Kernel(device) => device.stun().map(Stun::Kernel),
            Self::Userspace { device, .. } => Some(Stun::Userspace(device.stun())),
        }
    }

    pub async fn delete(&mut self) -> Result<(), NetError> {
        match self {
            Self::Kernel(device) => device.delete().await,
            Self::Userspace {
                device,
                name,
                links,
            } => {
                device.delete().await;
                links.delete_named(name).await
            },
        }
    }
}

impl fmt::Display for Wireguard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kernel(_) => "kernel",
            Self::Userspace { .. } => "userspace",
        })
    }
}
