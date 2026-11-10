mod plan;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use compass_net::NetError;
use compass_proto::{
    CONTROL_PREFIX, DnsName, NodeId, PathKind, Peer, PeerStatus, PrivateKey, PublicKey,
    SignalMessage,
};
use ipnet::IpNet;
use tokio::sync::mpsc;

use crate::client::dataplane::{Backend, DataplaneError, Path, Plan, Platform, Stats};
use crate::client::dns;
use crate::client::ice::{self, IceEvent, IceHandle, IcePeer};
use crate::client::meshes::Mesh;
use crate::client::relay::Relay;

const RESOLVE_RETRY: Duration = Duration::from_secs(15);
const RESOLVE_INTERVAL: Duration = Duration::from_secs(300);
const RESYNC: Duration = Duration::from_secs(10);
const SESSION_LIFETIME: Duration = Duration::from_secs(180);
const HANDSHAKE_PATIENCE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Default)]
pub struct View {
    pub meshes: Vec<Mesh>,
    pub attached: BTreeMap<PublicKey, BTreeSet<usize>>,
    pub connected: BTreeSet<usize>,
    pub serves: BTreeMap<usize, usize>,
}

impl View {
    fn peers(&self) -> impl Iterator<Item = (&Mesh, &Peer)> {
        self.meshes
            .iter()
            .flat_map(|mesh| mesh.netmap.peers.iter().map(move |peer| (mesh, peer)))
    }

    fn lists(&self, key: &PublicKey) -> bool {
        self.peers().any(|(_, peer)| peer.key == *key)
    }
}

pub struct ExitNode {
    pub peer: DnsName,
    /// `None` takes the first mesh that offers `peer` as an exit node.
    pub mesh: Option<usize>,
}

pub struct Engine {
    backend: Box<dyn Backend>,
    relay: Arc<Relay>,
    ice: IceHandle,
    own_key: PublicKey,
    dns_meshes: BTreeSet<usize>,
    hubs: Vec<Hub>,
    exit_node: Option<ExitNode>,
    view: View,
    direct: BTreeMap<PublicKey, SocketAddr>,
    stats: Stats,
    applied: Option<Plan>,
    synced_at: Option<Instant>,
}

pub struct Hub {
    key: PublicKey,
    endpoint: String,
    addresses: Vec<SocketAddr>,
    resolved_at: Option<Instant>,
    chosen: usize,
    chosen_at: Instant,
}

impl Hub {
    pub fn new(key: PublicKey, endpoint: String) -> Self {
        Self {
            key,
            endpoint,
            addresses: Vec::new(),
            resolved_at: None,
            chosen: 0,
            chosen_at: Instant::now(),
        }
    }

    fn address(&self) -> Option<SocketAddr> {
        self.addresses.get(self.chosen).copied()
    }

    fn due(&self) -> bool {
        let interval = if self.addresses.is_empty() {
            RESOLVE_RETRY
        } else {
            RESOLVE_INTERVAL
        };
        self.resolved_at.is_none_or(|at| at.elapsed() >= interval)
    }

    async fn resolve(&mut self) {
        let found: io::Result<Vec<SocketAddr>> = tokio::net::lookup_host(self.endpoint.as_str())
            .await
            .map(Iterator::collect);

        match found {
            Ok(addresses) => {
                let current = self.address();
                self.addresses = addresses;
                self.choose(
                    self.addresses
                        .iter()
                        .position(|address| Some(*address) == current)
                        .unwrap_or(0),
                );
            },
            Err(error) => tracing::warn!(hub = self.endpoint, %error, "failed to resolve the hub"),
        }

        self.resolved_at = Some(Instant::now());
    }

    fn choose(&mut self, address: usize) {
        if address != self.chosen {
            self.chosen = address;
            self.chosen_at = Instant::now();
        }
    }

    fn fail_over(&mut self, last_handshake: Option<SystemTime>) {
        let answering = last_handshake
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age < SESSION_LIFETIME);
        let waited = self.chosen_at.elapsed() >= HANDSHAKE_PATIENCE;

        if !answering && waited && self.addresses.len() > 1 {
            self.choose((self.chosen + 1) % self.addresses.len());
        }
    }
}

pub struct Setup<'a> {
    pub key: &'a PrivateKey,
    pub listen_port: u16,
    pub dns_meshes: BTreeSet<usize>,
    pub hubs: Vec<Hub>,
    pub exit_node: Option<ExitNode>,
    pub local_networks: Vec<IpNet>,
    pub ice_events: mpsc::Sender<(u64, IceEvent)>,
    pub generation: u64,
}

impl Engine {
    pub async fn start<P>(
        platform: &P,
        device: &P::Device,
        setup: Setup<'_>,
    ) -> Result<Self, DataplaneError>
    where
        P: Platform,
    {
        let backend = platform.start(device, setup.key, setup.listen_port).await?;
        let own_key = setup.key.public_key();
        let ice = IceHandle::spawn(
            backend.stun(),
            setup.listen_port,
            own_key,
            setup.local_networks,
            setup.ice_events,
            setup.generation,
        );
        Ok(Self {
            backend,
            relay: Relay::new(setup.listen_port),
            ice,
            own_key,
            dns_meshes: setup.dns_meshes,
            hubs: setup.hubs,
            exit_node: setup.exit_node,
            view: View::default(),
            direct: BTreeMap::new(),
            stats: Stats::default(),
            applied: None,
            synced_at: None,
        })
    }

    pub fn relay(&self) -> Arc<Relay> {
        Arc::clone(&self.relay)
    }

    pub async fn apply(&mut self, view: View) -> Result<(), DataplaneError> {
        self.backend.check_exit_serving(&view.meshes).await?;

        self.direct.retain(|key, _| view.lists(key));
        self.relay
            .set_peers(&view.peers().map(|(_, peer)| peer.id).collect());

        let mut ice_peers: BTreeMap<PublicKey, IcePeer> = BTreeMap::new();

        for (_, peer) in view.peers() {
            ice_peers.entry(peer.key).or_insert_with(|| IcePeer {
                id: peer.id,
                key: peer.key,
                online: view.attached.contains_key(&peer.key),
            });
        }

        self.ice.set_peers(
            ice_peers.into_values().collect(),
            view.meshes
                .iter()
                .flat_map(|mesh| mesh.routed.iter().copied())
                .chain([IpNet::V6(CONTROL_PREFIX)])
                .collect(),
        );

        let meshes: Vec<Mesh> = view
            .meshes
            .iter()
            .filter(|mesh| self.dns_meshes.contains(&mesh.index))
            .cloned()
            .collect();
        let mut lighthouses: BTreeMap<usize, String> = BTreeMap::new();

        for (lighthouse, mesh) in &view.serves {
            if let Some(hub) = self.hubs.get(*lighthouse) {
                lighthouses
                    .entry(*mesh)
                    .or_insert_with(|| hub.endpoint.clone());
            }
        }

        self.view = view;
        self.sync(&[]).await?;

        if !self.dns_meshes.is_empty() {
            self.backend.update_dns(&meshes, &lighthouses).await;
        }

        Ok(())
    }

    fn plan(&self) -> Plan {
        let view = &self.view;
        let relayed = self.relay.connected();
        let healthy: BTreeSet<usize> = view.connected.intersection(&relayed).copied().collect();
        let proxies = self.relay.endpoints();
        plan::build(&plan::Inputs {
            view,
            own_key: &self.own_key,
            hubs: &self.hubs,
            direct: &self.direct,
            proxies: &proxies,
            healthy: &healthy,
            exit_node: self.exit_node.as_ref(),
            local_dns: dns::stub_address(
                view.meshes
                    .iter()
                    .filter(|mesh| self.dns_meshes.contains(&mesh.index)),
            ),
        })
    }

    async fn sync(&mut self, rehandshake: &[PublicKey]) -> Result<(), DataplaneError> {
        let plan = self.plan();
        self.synced_at = Some(Instant::now());
        self.ice.set_hubs(
            self.hubs
                .iter()
                .flat_map(|hub| hub.addresses.iter().copied())
                .collect(),
        );
        self.relay
            .set_routes(plan.peers.iter().map(|peer| (peer.id, peer.relay)));
        self.backend.apply(&plan, rehandshake).await?;
        self.applied = Some(plan);
        Ok(())
    }

    pub async fn tick(&mut self) -> Result<(), DataplaneError> {
        if self.applied.is_some() {
            match self.backend.stats().await {
                Ok(stats) => self.stats = stats,
                Err(DataplaneError::Net(NetError::MissingDevice(device))) => {
                    tracing::warn!(device, "interface disappeared; recreating it");
                    self.applied = None;
                },
                Err(error) => return Err(error),
            }
        }

        for hub in &mut self.hubs {
            if hub.due() {
                hub.resolve().await;
            }

            let counters = self.stats.peers.get(&hub.key);
            hub.fail_over(counters.and_then(|counters| counters.last_handshake));
        }

        let due = self.synced_at.is_none_or(|at| at.elapsed() >= RESYNC);

        if due || self.applied.as_ref() != Some(&self.plan()) {
            self.sync(&[]).await?;
        }

        Ok(())
    }

    pub async fn set_exit_node(
        &mut self,
        exit_node: Option<ExitNode>,
    ) -> Result<(), DataplaneError> {
        self.exit_node = exit_node;
        self.sync(&[]).await
    }

    pub fn exit_node_active(&self) -> bool {
        self.applied
            .as_ref()
            .and_then(|plan| plan.exit.as_ref())
            .is_some_and(|exit| exit.peer.is_some())
    }

    pub async fn network_changed(
        &mut self,
        local_networks: Vec<IpNet>,
    ) -> Result<(), DataplaneError> {
        self.ice.set_local_networks(local_networks);
        self.sync(&[]).await
    }

    pub fn signal(&self, from: NodeId, message: SignalMessage) {
        self.ice.signal(from, message);
    }

    pub async fn set_path(
        &mut self,
        key: PublicKey,
        endpoint: Option<SocketAddr>,
    ) -> Result<(), DataplaneError> {
        let known = self.view.lists(&key);

        let previous = match endpoint {
            Some(endpoint) if known => self.direct.insert(key, endpoint),
            _ => self.direct.remove(&key),
        };

        if previous == self.direct.get(&key).copied() {
            return Ok(());
        }

        let rehandshake = if ice::controls(&self.own_key, &key) && self.direct.contains_key(&key) {
            vec![key]
        } else {
            Vec::new()
        };

        self.sync(&rehandshake).await
    }

    pub async fn teardown(&mut self) {
        self.backend.teardown().await;
        self.view = View::default();
        self.applied = None;
        self.direct.clear();
        self.synced_at = None;
    }

    pub fn status(&self) -> Vec<PeerStatus> {
        let Some(plan) = &self.applied else {
            return Vec::new();
        };

        let view = &self.view;
        let now = SystemTime::now();
        view.peers()
            .map(|(mesh, peer)| {
                let path = plan
                    .peers
                    .iter()
                    .find(|planned| planned.key == peer.key)
                    .map_or(PathKind::None, |planned| match planned.path {
                        Path::Direct(endpoint) => PathKind::Direct(endpoint),
                        Path::Relay(lighthouse) => self
                            .hubs
                            .get(lighthouse)
                            .map_or(PathKind::None, |hub| PathKind::Relay(hub.endpoint.clone())),
                        Path::None => PathKind::None,
                    });
                let counters = self.stats.peers.get(&peer.key);
                PeerStatus {
                    hostname: peer.hostname.clone(),
                    fqdn: format!("{}.{}", peer.hostname, mesh.netmap.network.domain),
                    addresses: mesh.peer_addresses(&peer.key).to_vec(),
                    taken: mesh.peer_taken(peer),
                    online: view.attached.contains_key(&peer.key),
                    exit_node: peer.exit_node,
                    path,
                    last_handshake_secs: counters
                        .and_then(|counters| counters.last_handshake)
                        .map(|at| now.duration_since(at).unwrap_or_default().as_secs()),
                    rx_bytes: counters.map_or(0, |counters| counters.rx_bytes),
                    tx_bytes: counters.map_or(0, |counters| counters.tx_bytes),
                }
            })
            .collect()
    }
}
