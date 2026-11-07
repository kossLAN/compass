mod plan;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bunnyhop_config::InterfaceConfig;
use bunnyhop_net::{Dataplane, NetError};
use bunnyhop_proto::{
    DnsName, HubInfo, NetMap, NodeId, PathKind, PeerStatus, PrivateKey, PublicKey, SignalMessage,
};
use ipnet::IpNet;
use tokio::sync::mpsc;
use url::Url;

use crate::client::dataplane::{self, Backend, DataplaneError, Path, Plan, Stats};
use crate::client::dns::{self, DnsService};
use crate::client::ice::{self, IceEvent, IceHandle, IcePeer};
use crate::client::relay::Relay;

const RESOLVE_RETRY: Duration = Duration::from_secs(15);
const RESOLVE_INTERVAL: Duration = Duration::from_secs(300);
const RESYNC: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct View {
    pub netmap: NetMap,
    pub hubs: BTreeMap<usize, HubInfo>,
    pub attached: BTreeMap<PublicKey, BTreeSet<usize>>,
    pub connected: BTreeSet<usize>,
}

pub struct ExitNode {
    pub peer: DnsName,
    pub bypass: Vec<IpAddr>,
}

pub struct Engine {
    dataplane: Arc<Dataplane>,
    backend: Box<dyn Backend>,
    relay: Arc<Relay>,
    ice: IceHandle,
    dns: DnsService,
    own_key: PublicKey,
    accept_dns: bool,
    lighthouses: Vec<Url>,
    exit_node: Option<ExitNode>,
    view: Option<View>,
    hubs: BTreeMap<usize, HubEndpoint>,
    direct: BTreeMap<PublicKey, SocketAddr>,
    stats: Stats,
    applied: Option<Plan>,
    synced_at: Option<Instant>,
    exit_warned: bool,
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
    pub dataplane: Arc<Dataplane>,
    pub interface: &'a InterfaceConfig,
    pub key: &'a PrivateKey,
    pub accept_dns: bool,
    pub lighthouses: Vec<Url>,
    pub local_networks: Vec<IpNet>,
    pub ice_events: mpsc::Sender<(u64, IceEvent)>,
    pub generation: u64,
}

impl Engine {
    pub async fn start(setup: Setup<'_>) -> Result<Self, DataplaneError> {
        let backend =
            dataplane::start(Arc::clone(&setup.dataplane), setup.interface, setup.key).await?;
        let own_key = setup.key.public_key();
        let ice = IceHandle::spawn(
            backend.stun(),
            setup.interface.listen_port,
            own_key,
            setup.local_networks,
            setup.ice_events,
            setup.generation,
        );
        Ok(Self {
            dataplane: setup.dataplane,
            backend,
            relay: Relay::new(setup.interface.listen_port),
            ice,
            dns: DnsService::default(),
            own_key,
            accept_dns: setup.accept_dns,
            lighthouses: setup.lighthouses,
            exit_node: None,
            view: None,
            hubs: BTreeMap::new(),
            direct: BTreeMap::new(),
            stats: Stats::default(),
            applied: None,
            synced_at: None,
            exit_warned: false,
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
        self.check_exit_serving(&view.netmap).await?;

        self.direct
            .retain(|key, _| view.netmap.peers.iter().any(|peer| peer.key == *key));
        self.relay
            .set_peers(&view.netmap.peers.iter().map(|peer| peer.id).collect());
        self.ice.set_peers(
            view.netmap
                .peers
                .iter()
                .map(|peer| IcePeer {
                    id: peer.id,
                    key: peer.key,
                    online: view.attached.contains_key(&peer.key),
                })
                .collect(),
            view.netmap.network.clone(),
        );

        let netmap = view.netmap.clone();
        self.view = Some(view);
        self.sync(&[]).await?;

        if self.accept_dns {
            self.dns
                .update(&self.dataplane, self.backend.interface(), &netmap)
                .await;
        }

        Ok(())
    }

    async fn check_exit_serving(&mut self, netmap: &NetMap) -> Result<(), DataplaneError> {
        if self.exit_warned || netmap.exit_clients.is_empty() {
            return Ok(());
        }

        for (family, ipv6, key) in [
            ("IPv4", false, "net/ipv4/conf/all/forwarding"),
            ("IPv6", true, "net/ipv6/conf/all/forwarding"),
        ] {
            if netmap
                .exit_clients
                .iter()
                .any(|net| net.addr().is_ipv6() == ipv6)
                && self.dataplane.sysctl(key).await?.as_deref() != Some("1")
            {
                tracing::warn!("serving as an exit node, but {family} forwarding is disabled");
                self.exit_warned = true;
            }
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
            local_dns: self
                .accept_dns
                .then(|| dns::stub_address(&view.netmap))
                .flatten(),
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
        let known = self
            .view
            .as_ref()
            .is_some_and(|view| view.netmap.peers.iter().any(|peer| peer.key == key));

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
        self.dns
            .stop(&self.dataplane, self.backend.interface())
            .await;
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
        view.netmap
            .peers
            .iter()
            .map(|peer| {
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
                    addresses: peer.addresses,
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
