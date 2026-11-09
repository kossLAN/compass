mod plan;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use compass_net::NetError;
use compass_proto::{
    DnsName, HubInfo, NodeId, PathKind, Peer, PeerStatus, PrivateKey, PublicKey, SignalMessage,
};
use ipnet::IpNet;
use tokio::sync::mpsc;
use url::Url;

use crate::client::dataplane::{Backend, DataplaneError, Path, Plan, Platform, Stats};
use crate::client::dns;
use crate::client::ice::{self, IceEvent, IceHandle, IcePeer};
use crate::client::meshes::Mesh;
use crate::client::relay::Relay;

const RESOLVE_RETRY: Duration = Duration::from_secs(15);
const RESOLVE_INTERVAL: Duration = Duration::from_secs(300);
const RESYNC: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct View {
    pub meshes: Vec<Mesh>,
    pub hubs: BTreeMap<usize, HubInfo>,
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
    pub bypass: Vec<IpAddr>,
}

pub struct Engine {
    backend: Box<dyn Backend>,
    relay: Arc<Relay>,
    ice: IceHandle,
    own_key: PublicKey,
    dns_meshes: BTreeSet<usize>,
    lighthouses: Vec<Url>,
    exit_node: Option<ExitNode>,
    view: Option<View>,
    hubs: BTreeMap<usize, HubEndpoint>,
    direct: BTreeMap<PublicKey, SocketAddr>,
    stats: Stats,
    applied: Option<Plan>,
    synced_at: Option<Instant>,
}

#[derive(Default)]
struct HubEndpoint {
    name: String,
    addresses: Vec<SocketAddr>,
    resolved_at: Option<Instant>,
}

impl HubEndpoint {
    fn due(&self) -> bool {
        let interval = if self.addresses.is_empty() {
            RESOLVE_RETRY
        } else {
            RESOLVE_INTERVAL
        };
        self.resolved_at.is_none_or(|at| at.elapsed() >= interval)
    }

    async fn resolve(&mut self) {
        match tokio::net::lookup_host(self.name.as_str()).await {
            Ok(addresses) => {
                let mut addresses: Vec<SocketAddr> = addresses.collect();
                addresses.sort_unstable();
                addresses.dedup();
                self.addresses = addresses;
            },
            Err(error) => tracing::warn!(hub = self.name, %error, "failed to resolve the hub"),
        }

        self.resolved_at = Some(Instant::now());
    }
}

pub struct Setup<'a> {
    pub key: &'a PrivateKey,
    pub listen_port: u16,
    pub dns_meshes: BTreeSet<usize>,
    pub lighthouses: Vec<Url>,
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
            lighthouses: setup.lighthouses,
            exit_node: None,
            view: None,
            hubs: BTreeMap::new(),
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
        for (lighthouse, hub) in &view.hubs {
            let endpoint = self.hubs.entry(*lighthouse).or_default();

            if endpoint.name != hub.endpoint {
                hub.endpoint.clone_into(&mut endpoint.name);
                endpoint.addresses.clear();
                endpoint.resolve().await;
            }
        }

        self.hubs
            .retain(|lighthouse, _| view.hubs.contains_key(lighthouse));
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
                .flat_map(|mesh| mesh.netmap.network.prefixes())
                .collect(),
        );

        let meshes: Vec<Mesh> = view
            .meshes
            .iter()
            .filter(|mesh| self.dns_meshes.contains(&mesh.index))
            .cloned()
            .collect();
        let mut lighthouses: BTreeMap<usize, Url> = BTreeMap::new();

        for (lighthouse, mesh) in &view.serves {
            if let Some(url) = self.lighthouses.get(*lighthouse) {
                lighthouses.entry(*mesh).or_insert_with(|| url.clone());
            }
        }

        self.view = Some(view);
        self.sync(&[]).await?;

        if !self.dns_meshes.is_empty() {
            self.backend.update_dns(&meshes, &lighthouses).await;
        }

        Ok(())
    }

    fn plan(&self) -> Option<Plan> {
        let view = self.view.as_ref()?;
        let relayed = self.relay.connected();
        let healthy: BTreeSet<usize> = view.connected.intersection(&relayed).copied().collect();
        let proxies = self.relay.endpoints();
        Some(plan::build(&plan::Inputs {
            view,
            own_key: &self.own_key,
            direct: &self.direct,
            proxies: &proxies,
            healthy: &healthy,
            exit_node: self.exit_node.as_ref(),
            local_dns: dns::stub_address(
                view.meshes
                    .iter()
                    .filter(|mesh| self.dns_meshes.contains(&mesh.index)),
            ),
        }))
    }

    async fn sync(&mut self, rehandshake: &[PublicKey]) -> Result<(), DataplaneError> {
        let Some(plan) = self.plan() else {
            return Ok(());
        };

        self.synced_at = Some(Instant::now());
        self.ice.set_hubs(
            self.hubs
                .values()
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
        if self.view.is_none() {
            return Ok(());
        }

        match self.backend.stats().await {
            Ok(stats) => self.stats = stats,
            Err(DataplaneError::Net(NetError::MissingDevice(device))) => {
                tracing::warn!(device, "interface disappeared; recreating it");
                self.applied = None;
            },
            Err(error) => return Err(error),
        }

        for hub in self.hubs.values_mut().filter(|hub| hub.due()) {
            hub.resolve().await;
        }

        let due = self.synced_at.is_none_or(|at| at.elapsed() >= RESYNC);

        if due || self.plan() != self.applied {
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
        let known = self.view.as_ref().is_some_and(|view| view.lists(&key));

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
        self.view = None;
        self.applied = None;
        self.direct.clear();
        self.synced_at = None;
    }

    pub fn status(&self) -> Vec<PeerStatus> {
        let (Some(view), Some(plan)) = (&self.view, &self.applied) else {
            return Vec::new();
        };

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
                            .lighthouses
                            .get(lighthouse)
                            .map_or(PathKind::None, |url| PathKind::Relay(url.clone())),
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
