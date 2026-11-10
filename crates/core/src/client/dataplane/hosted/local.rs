use std::io;
use std::net::IpAddr;
use std::os::fd::BorrowedFd;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use compass_net::{Intercept, Protect, Tun};
use etherparse::IpSlice;
use ipnet::Ipv4Net;
use tokio::sync::mpsc;

use super::Underlying;
use crate::client::dns::Zone;

const QUEUE: usize = 64;

pub struct Resolver {
    pub network: Ipv4Net,
    pub zone: Zone,
}

impl Resolver {
    pub fn address(&self) -> IpAddr {
        IpAddr::V4(self.network.network())
    }
}

pub struct Local {
    resolver: ArcSwapOption<Resolver>,
    queries: mpsc::Sender<Vec<u8>>,
    tun: ArcSwapOption<Tun>,
    underlying: Arc<ArcSwap<Underlying>>,
    protect: Arc<dyn Protect>,
}

impl Local {
    pub fn new(
        underlying: Arc<ArcSwap<Underlying>>,
        protect: Arc<dyn Protect>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (queries, received) = mpsc::channel(QUEUE);
        let local = Self {
            resolver: ArcSwapOption::empty(),
            queries,
            tun: ArcSwapOption::empty(),
            underlying,
            protect,
        };
        (Arc::new(local), received)
    }

    pub fn set_tun(&self, tun: Arc<Tun>) {
        self.tun.store(Some(tun));
    }

    pub fn set_resolver(&self, resolver: Option<Resolver>) {
        self.resolver.store(resolver.map(Arc::new));
    }

    pub fn resolver(&self) -> Option<Arc<Resolver>> {
        self.resolver.load_full()
    }

    pub fn dns_servers(&self) -> Vec<IpAddr> {
        self.underlying.load().dns_servers.clone()
    }

    pub fn protect(&self, socket: BorrowedFd<'_>) -> io::Result<()> {
        self.protect.protect(socket)
    }

    pub async fn write(&self, packet: &[u8]) {
        let Some(tun) = self.tun.load_full() else {
            return;
        };

        if let Err(error) = tun.send(packet).await {
            tracing::debug!(%error, "failed to write a packet to the tunnel");
        }
    }
}

impl Intercept for Local {
    fn take(&self, packet: &[u8]) -> bool {
        let Some(resolver) = &*self.resolver.load() else {
            return false;
        };
        let destination = IpSlice::from_slice(packet).map(|ip| ip.destination_addr());

        if destination != Ok(resolver.address()) {
            return false;
        }

        if self.queries.try_send(packet.to_vec()).is_err() {
            tracing::debug!("dropped a DNS query, too many are waiting");
        }

        true
    }
}
