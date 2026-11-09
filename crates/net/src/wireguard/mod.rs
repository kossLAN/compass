mod userspace;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use self::userspace::UserspaceStun;
pub use self::userspace::{Intercept, Tun, UserspaceDevice};
use crate::stun::Datagram;

#[derive(Clone)]
pub enum Stun {
    #[cfg(feature = "linux")]
    Kernel(Arc<crate::linux::KernelStun>),
    Userspace(Arc<UserspaceStun>),
}

impl Stun {
    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        match self {
            #[cfg(feature = "linux")]
            Self::Kernel(stun) => stun.send(remote, payload).await,
            Self::Userspace(stun) => stun.send(remote, payload).await,
        }
    }

    pub async fn recv(&self) -> io::Result<Datagram> {
        match self {
            #[cfg(feature = "linux")]
            Self::Kernel(stun) => stun.recv().await,
            Self::Userspace(stun) => stun.recv().await,
        }
    }
}
