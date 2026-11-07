use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use bunnyhop_proto::PublicKey;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use crate::PeerSpec;

const SESSION_BITS: u32 = 8;

pub struct Peer {
    pub index: u32,
    session: Mutex<Session>,
}

pub struct Session {
    pub tunn: Tunn,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
    keepalive_sent: Instant,
}

impl Peer {
    pub fn new(
        spec: &PeerSpec,
        index: u32,
        secret: &StaticSecret,
        rate_limiter: &Arc<RateLimiter>,
    ) -> Self {
        let tunn = Tunn::new(
            secret.clone(),
            X25519PublicKey::from(spec.key.to_bytes()),
            None,
            None,
            index,
            Some(Arc::clone(rate_limiter)),
        );

        Self {
            index,
            session: Mutex::new(Session {
                tunn,
                endpoint: spec.endpoint,
                keepalive: spec.keepalive,
                keepalive_sent: Instant::now(),
            }),
        }
    }

    pub fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn update(&self, spec: &PeerSpec) -> bool {
        let mut session = self.session();

        if let Some(endpoint) = spec.endpoint {
            session.endpoint = Some(endpoint);
        }

        let enabled = session.keepalive == 0 && spec.keepalive > 0;
        session.keepalive = spec.keepalive;
        enabled
    }
}

impl Session {
    pub fn keepalive_due(&self, now: Instant) -> bool {
        self.keepalive > 0
            && now.duration_since(self.keepalive_sent)
                >= Duration::from_secs(u64::from(self.keepalive))
    }

    pub fn send_keepalive(&mut self, now: Instant, dst: &mut [u8]) -> Option<usize> {
        self.keepalive_sent = now;

        match self.tunn.encapsulate(&[], dst) {
            TunnResult::WriteToNetwork(datagram) => Some(datagram.len()),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Entry {
    pub peer: Arc<Peer>,
    pub allowed_ips: Vec<IpNet>,
}

#[derive(Default)]
pub struct Table {
    entries: HashMap<PublicKey, Entry>,
    by_index: HashMap<u32, Arc<Peer>>,
    v4: PrefixMap<Ipv4Net, Arc<Peer>>,
    v6: PrefixMap<Ipv6Net, Arc<Peer>>,
}

impl Table {
    pub fn new(entries: HashMap<PublicKey, Entry>) -> Self {
        let mut by_index = HashMap::with_capacity(entries.len());
        let mut v4 = PrefixMap::new();
        let mut v6 = PrefixMap::new();

        for entry in entries.values() {
            by_index.insert(entry.peer.index, Arc::clone(&entry.peer));

            for net in &entry.allowed_ips {
                match net.trunc() {
                    IpNet::V4(net) => v4.insert(net, Arc::clone(&entry.peer)),
                    IpNet::V6(net) => v6.insert(net, Arc::clone(&entry.peer)),
                };
            }
        }

        Self {
            entries,
            by_index,
            v4,
            v6,
        }
    }

    pub const fn entries(&self) -> &HashMap<PublicKey, Entry> {
        &self.entries
    }

    pub fn peers(&self) -> impl Iterator<Item = &Arc<Peer>> {
        self.by_index.values()
    }

    pub fn by_key(&self, key: &PublicKey) -> Option<&Arc<Peer>> {
        self.entries.get(key).map(|entry| &entry.peer)
    }

    pub fn by_receiver(&self, receiver: u32) -> Option<&Arc<Peer>> {
        self.by_index.get(&(receiver >> SESSION_BITS))
    }

    pub fn lookup(&self, address: IpAddr) -> Option<&Arc<Peer>> {
        match address {
            IpAddr::V4(address) => self
                .v4
                .get_lpm(&Ipv4Net::from(address))
                .map(|(_, peer)| peer),
            IpAddr::V6(address) => self
                .v6
                .get_lpm(&Ipv6Net::from(address))
                .map(|(_, peer)| peer),
        }
    }

    pub fn routes_to(&self, peer: &Arc<Peer>, source: IpAddr) -> bool {
        self.lookup(source)
            .is_some_and(|found| Arc::ptr_eq(found, peer))
    }
}
