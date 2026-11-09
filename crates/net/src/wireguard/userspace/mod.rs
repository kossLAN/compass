mod filter;
mod inbound;
#[cfg(feature = "linux")]
#[path = "offload/linux.rs"]
mod offload;
#[cfg(not(feature = "linux"))]
#[path = "offload/plain.rs"]
mod offload;
mod outbound;
mod stun;
mod table;
mod udp;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

pub use self::offload::Tun;
pub use self::stun::UserspaceStun;
use arc_swap::{ArcSwap, ArcSwapOption};
use boringtun::noise::TunnResult;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use compass_proto::{PrivateKey, PublicKey};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use self::filter::Filter;
use self::table::{Entry, Peer, Table};
use self::udp::{Batch, Sockets};
use crate::stun::{Datagram, local_address_for};
use crate::{DeviceState, MeshRules, NetError, PeerOp, PeerSpec, PeerState};

const INDEX_MASK: u32 = (1 << 24) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 100;
const HANDSHAKE_INIT_LEN: usize = 148;
const COOKIE_REPLY_LEN: usize = 64;
const DATA_OVERHEAD: usize = 32;
const TIMER_TICK: Duration = Duration::from_millis(250);
const RATE_LIMIT_RESET: Duration = Duration::from_secs(1);
const FLOW_SWEEP: Duration = Duration::from_secs(30);
const STUN_QUEUE: usize = 64;

pub trait Intercept: Send + Sync + 'static {
    fn take(&self, packet: &[u8]) -> bool;
}

struct Shared {
    table: ArcSwap<Table>,
    secret: StaticSecret,
    public: X25519PublicKey,
    rate_limiter: Arc<RateLimiter>,
    sockets: Sockets,
    tun: ArcSwapOption<Tun>,
    stun: mpsc::Sender<Datagram>,
    intercept: Option<Arc<dyn Intercept>>,
    filter: Filter,
}

impl Shared {
    fn deliver_stun(&self, remote: SocketAddr, payload: &[u8]) {
        let local = match local_address_for(remote, self.sockets.mark()) {
            Ok(local) => local,
            Err(error) => {
                tracing::debug!(%remote, %error, "no local address for a STUN datagram");
                return;
            },
        };
        let datagram = Datagram {
            local: SocketAddr::new(local, self.sockets.port()),
            remote,
            payload: payload.to_vec(),
        };

        if self.stun.try_send(datagram).is_err() {
            tracing::debug!(%remote, "dropped a STUN datagram");
        }
    }

    fn send_keepalive(&self, peer: &Peer) {
        let mut buffer = [0; HANDSHAKE_INIT_LEN];
        let mut session = peer.session();
        let Some(endpoint) = session.endpoint else {
            return;
        };

        if let Some(len) = session.send_keepalive(Instant::now(), &mut buffer)
            && let Err(error) = self.sockets.try_send_to(endpoint, &buffer[..len])
        {
            tracing::debug!(%endpoint, %error, "failed to send a keepalive");
        }
    }

    fn update_timers(&self, batch: &mut Batch) {
        let table = self.table.load();
        let now = Instant::now();

        for peer in table.peers() {
            let mut session = peer.session();
            let len = match session.tunn.update_timers(batch.spare(HANDSHAKE_INIT_LEN)) {
                TunnResult::WriteToNetwork(datagram) => Some(datagram.len()),
                _ if session.keepalive_due(now) => {
                    session.send_keepalive(now, batch.spare(HANDSHAKE_INIT_LEN))
                },
                _ => None,
            };

            if let (Some(len), Some(endpoint)) = (len, session.endpoint) {
                batch.commit(endpoint, len);
            }
        }
    }
}

pub struct UserspaceDevice {
    shared: Arc<Shared>,
    public_key: PublicKey,
    stun: Arc<UserspaceStun>,
    mtu: Option<u16>,
    next_index: u32,
    tasks: JoinSet<()>,
    outbound: JoinSet<()>,
}

impl UserspaceDevice {
    pub fn new(
        key: &PrivateKey,
        listen_port: u16,
        mark: Option<u32>,
        intercept: Option<Arc<dyn Intercept>>,
    ) -> Result<Self, NetError> {
        let sockets = Sockets::bind(listen_port, mark).map_err(NetError::Bind)?;
        let secret = StaticSecret::from(*key.to_bytes());
        let public = X25519PublicKey::from(&secret);
        let (stun, received) = mpsc::channel(STUN_QUEUE);

        let shared = Arc::new(Shared {
            table: ArcSwap::from_pointee(Table::default()),
            rate_limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)),
            secret,
            public,
            sockets,
            tun: ArcSwapOption::empty(),
            stun,
            intercept,
            filter: Filter::default(),
        });

        let mut tasks = JoinSet::new();

        for socket in shared.sockets.receivers() {
            spawn(
                &mut tasks,
                "inbound",
                inbound::run(Arc::clone(&shared), socket),
            );
        }

        spawn(&mut tasks, "timers", timers(Arc::clone(&shared)));

        Ok(Self {
            stun: Arc::new(UserspaceStun::new(Arc::downgrade(&shared), received)),
            shared,
            public_key: key.public_key(),
            mtu: None,
            next_index: 0,
            tasks,
            outbound: JoinSet::new(),
        })
    }

    pub fn set_tun(&mut self, tun: Arc<Tun>) {
        self.shared.tun.store(Some(tun));
        self.restart_outbound();
    }

    pub fn filter_inbound(&self, rules: Vec<MeshRules>) {
        self.shared.filter.set_rules(rules);
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        if self.mtu == Some(mtu) {
            return;
        }

        self.mtu = Some(mtu);
        self.restart_outbound();
    }

    fn restart_outbound(&mut self) {
        let mut outbound = JoinSet::new();

        if let (Some(tun), Some(mtu)) = (self.shared.tun.load_full(), self.mtu) {
            spawn(
                &mut outbound,
                "outbound",
                outbound::run(Arc::clone(&self.shared), tun, usize::from(mtu)),
            );
        }

        self.outbound = outbound;
    }

    pub fn apply(&mut self, ops: &[PeerOp]) {
        if ops.is_empty() {
            return;
        }

        let mut entries = self.shared.table.load().entries().clone();
        let mut keepalives = Vec::new();

        for op in ops {
            match op {
                PeerOp::Remove(key) => {
                    entries.remove(key);
                },
                PeerOp::Upsert(spec) => {
                    let (peer, keepalive) = entries.get(&spec.key).map_or_else(
                        || (self.create(&entries, spec), spec.keepalive > 0),
                        |entry| (Arc::clone(&entry.peer), entry.peer.update(spec)),
                    );

                    if keepalive {
                        keepalives.push(Arc::clone(&peer));
                    }

                    entries.insert(
                        spec.key,
                        Entry {
                            peer,
                            allowed_ips: spec.allowed_ips.clone(),
                        },
                    );
                },
            }
        }

        self.shared.table.store(Arc::new(Table::new(entries)));

        for peer in &keepalives {
            self.shared.send_keepalive(peer);
        }
    }

    fn create(&mut self, entries: &HashMap<PublicKey, Entry>, spec: &PeerSpec) -> Arc<Peer> {
        let index = self.allocate_index(entries);

        Arc::new(Peer::new(
            spec,
            index,
            &self.shared.secret,
            &self.shared.rate_limiter,
        ))
    }

    fn allocate_index(&mut self, entries: &HashMap<PublicKey, Entry>) -> u32 {
        loop {
            let index = self.next_index;
            self.next_index = (index + 1) & INDEX_MASK;

            if entries.values().all(|entry| entry.peer.index != index) {
                return index;
            }
        }
    }

    pub fn state(&self) -> DeviceState {
        let table = self.shared.table.load();
        let now = SystemTime::now();
        let peers = table
            .entries()
            .iter()
            .map(|(key, entry)| {
                let session = entry.peer.session();
                let (since, tx_bytes, rx_bytes, _, _) = session.tunn.stats();
                let state = PeerState {
                    endpoint: session.endpoint,
                    allowed_ips: entry.allowed_ips.clone(),
                    keepalive: session.keepalive,
                    last_handshake: since.and_then(|since| now.checked_sub(since)),
                    rx_bytes: rx_bytes as u64,
                    tx_bytes: tx_bytes as u64,
                };
                (*key, state)
            })
            .collect();

        DeviceState {
            public_key: Some(self.public_key),
            listen_port: self.shared.sockets.port(),
            fwmark: self.shared.sockets.mark().unwrap_or_default(),
            peers,
        }
    }

    pub fn stun(&self) -> Arc<UserspaceStun> {
        Arc::clone(&self.stun)
    }

    pub async fn delete(&mut self) {
        self.outbound.shutdown().await;
        self.tasks.shutdown().await;
    }
}

fn spawn(
    tasks: &mut JoinSet<()>,
    name: &'static str,
    task: impl Future<Output = io::Result<()>> + Send + 'static,
) {
    tasks.spawn(async move {
        if let Err(error) = task.await {
            tracing::error!(task = name, %error, "userspace WireGuard task stopped");
        }
    });
}

async fn timers(shared: Arc<Shared>) -> io::Result<()> {
    let mut tick = tokio::time::interval(TIMER_TICK);
    let mut reset = tokio::time::interval(RATE_LIMIT_RESET);
    let mut sweep = tokio::time::interval(FLOW_SWEEP);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    reset.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut batch = Batch::default();

    loop {
        tokio::select! {
            _ = tick.tick() => {
                shared.update_timers(&mut batch);
                shared.sockets.send(&batch).await;
                batch.clear();
            },
            _ = reset.tick() => shared.rate_limiter.reset_count(),
            _ = sweep.tick() => shared.filter.expire(),
        }
    }
}
