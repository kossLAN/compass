mod kernel;
mod userspace;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ipnet::IpNet;

use self::kernel::{KernelDevice, KernelStun};
use self::userspace::{UserspaceDevice, UserspaceStun};
use crate::link::Links;
use crate::stun::Datagram;
use crate::{DeviceSpec, DeviceState, NetError, PeerOp};

pub enum Wireguard {
    Kernel(KernelDevice),
    Userspace(UserspaceDevice),
}

impl Wireguard {
    pub async fn detect(spec: &DeviceSpec) -> Result<Self, NetError> {
        let links = Links::connect()?;

        if let Some(device) = KernelDevice::connect(spec, links.clone()).await? {
            return Ok(Self::Kernel(device));
        }

        UserspaceDevice::start(spec, links).map(Self::Userspace)
    }

    pub async fn ensure(&mut self, mtu: u16, addresses: &[IpNet]) -> Result<(), NetError> {
        match self {
            Self::Kernel(device) => device.ensure(mtu, addresses).await,
            Self::Userspace(device) => device.ensure(mtu, addresses).await,
        }
    }

    pub async fn state(&self) -> Result<DeviceState, NetError> {
        match self {
            Self::Kernel(device) => device.state().await,
            Self::Userspace(device) => Ok(device.state()),
        }
    }

    pub async fn apply(&mut self, ops: &[PeerOp]) -> Result<(), NetError> {
        match self {
            Self::Kernel(device) => device.apply(ops).await,
            Self::Userspace(device) => {
                device.apply(ops);
                Ok(())
            },
        }
    }

    pub fn stun(&self) -> Option<Stun> {
        match self {
            Self::Kernel(device) => device.stun().map(Stun::Kernel),
            Self::Userspace(device) => Some(Stun::Userspace(device.stun())),
        }
    }

    pub async fn delete(&mut self) -> Result<(), NetError> {
        match self {
            Self::Kernel(device) => device.delete().await,
            Self::Userspace(device) => device.delete().await,
        }
    }
}

impl fmt::Display for Wireguard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kernel(_) => "kernel",
            Self::Userspace(_) => "userspace",
        })
    }
}

#[derive(Clone)]
pub enum Stun {
    Kernel(Arc<KernelStun>),
    Userspace(Arc<UserspaceStun>),
}

impl Stun {
    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Kernel(stun) => stun.send(remote, payload).await,
            Self::Userspace(stun) => stun.send(remote, payload).await,
        }
    }

    pub async fn recv(&self) -> io::Result<Datagram> {
        match self {
            Self::Kernel(stun) => stun.recv().await,
            Self::Userspace(stun) => stun.recv().await,
        }
    }
}
