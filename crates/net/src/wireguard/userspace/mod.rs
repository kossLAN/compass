mod inbound;
mod outbound;
mod stun;
mod table;
mod udp;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use boringtun::noise::TunnResult;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use compass_proto::PublicKey;
use ipnet::IpNet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub use self::stun::UserspaceStun;

use self::table::{Entry, Peer, Table};
use self::udp::{Batch, Sockets};
use crate::link::Links;
use crate::stun::{Datagram, local_address_for};
use crate::{DeviceSpec, DeviceState, NetError, PeerOp, PeerSpec, PeerState};

const INDEX_MASK: u32 = (1 << 24) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 100;
const HANDSHAKE_INIT_LEN: usize = 148;
const COOKIE_REPLY_LEN: usize = 64;
const DATA_OVERHEAD: usize = 32;
const TIMER_TICK: Duration = Duration::from_millis(250);
const RATE_LIMIT_RESET: Duration = Duration::from_secs(1);
const STUN_QUEUE: usize = 64;

struct Shared {
    table: ArcSwap<Table>,
    secret: StaticSecret,
    public: X25519PublicKey,
    rate_limiter: Arc<RateLimiter>,
    sockets: Sockets,
    tun: AsyncDevice,
    stun: mpsc::Sender<Datagram>,
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
    name: String,
    links: Links,
    shared: Arc<Shared>,
    public_key: PublicKey,
    stun: Arc<UserspaceStun>,
    mtu: Option<u16>,
    next_index: u32,
    tasks: JoinSet<()>,
    outbound: JoinSet<()>,
}

impl UserspaceDevice {
    pub fn start(spec: &DeviceSpec, links: Links) -> Result<Self, NetError> {
        let tun = DeviceBuilder::new()
            .name(&spec.name)
            .offload(true)
            .build_async()
            .map_err(NetError::Tun)?;
        let sockets = Sockets::bind(spec.listen_port, spec.fwmark).map_err(NetError::Bind)?;
        let secret = StaticSecret::from(*spec.private_key.to_bytes());
        let public = X25519PublicKey::from(&secret);
        let (stun, received) = mpsc::channel(STUN_QUEUE);

        let shared = Arc::new(Shared {
            table: ArcSwap::from_pointee(Table::default()),
            rate_limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)),
            secret,
            public,
            sockets,
            tun,
            stun,
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
            name: spec.name.clone(),
            links,
            stun: Arc::new(UserspaceStun::new(Arc::downgrade(&shared), received)),
            shared,
            public_key: spec.private_key.public_key(),
            mtu: None,
            next_index: 0,
            tasks,
            outbound: JoinSet::new(),
        })
    }

    pub async fn ensure(&mut self, mtu: u16, addresses: &[IpNet]) -> Result<(), NetError> {
        self.set_mtu(mtu);
        let index = self.links.index(&self.name).await?;
        self.links.configure(index, mtu, addresses).await
    }

    fn set_mtu(&mut self, mtu: u16) {
        if self.mtu == Some(mtu) {
            return;
        }

        let mut outbound = JoinSet::new();
        spawn(
            &mut outbound,
            "outbound",
            outbound::run(Arc::clone(&self.shared), usize::from(mtu)),
        );
        self.outbound = outbound;
        self.mtu = Some(mtu);
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
            fwmark: self.shared.sockets.mark(),
            peers,
        }
    }

    pub fn stun(&self) -> Arc<UserspaceStun> {
        Arc::clone(&self.stun)
    }

    pub async fn delete(&mut self) -> Result<(), NetError> {
        self.outbound.shutdown().await;
        self.tasks.shutdown().await;
        self.links.delete_named(&self.name).await
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
        }
    }
}
