use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use compass_config::ConfigError;
use compass_proto::{
    DnsName, DnsRecord, ExitNodeChoice, ExitNodeStatus, LighthouseState, LighthouseStatus,
    MAX_RECORDS, NetMap, Network, NodeInfo, NodeStatus, Phase, RecordEntry, SignalEnvelope,
    StatusReport,
};
use ipnet::IpNet;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::client::api::ApiClient;
use crate::client::dataplane::{LocalNetworks, Platform};
use crate::client::engine::{Engine, ExitNode, Hub, Setup, View};
use crate::client::ice::IceEvent;
use crate::client::meshes;
use crate::client::session::{Session, SessionEvent};
use crate::client::settings::{ClientSettings, LighthouseSettings};

const SIGNAL_QUEUE: usize = 256;

struct RunningSession {
    id: u64,
    task: JoinHandle<()>,
    signals: mpsc::Sender<SignalEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeshSettings {
    records: Vec<DnsRecord>,
    accept_dns: bool,
    exit_peer: Option<DnsName>,
    advertise_exit_node: bool,
}

struct LighthouseConnection {
    endpoint: String,
    mesh: usize,
    session: Option<RunningSession>,
    netmap: Option<NetMap>,
    state: LighthouseState,
}

impl LighthouseConnection {
    const fn new(endpoint: String, mesh: usize) -> Self {
        Self {
            endpoint,
            mesh,
            session: None,
            netmap: None,
            state: LighthouseState::Connecting,
        }
    }

    fn usable_netmap(&self) -> Option<&NetMap> {
        self.netmap
            .as_ref()
            .filter(|_| !matches!(self.state, LighthouseState::Rejected(_)))
    }

    fn connected(&self) -> bool {
        self.state == LighthouseState::Connected
    }
}

pub struct Agent<P: Platform> {
    config: ClientSettings,
    device: P::Device,
    platform: P,
    engine: Option<Engine>,
    reflexive: Vec<SocketAddr>,
    engines_started: u64,
    ice_events: mpsc::Sender<(u64, IceEvent)>,
    lighthouses: Vec<LighthouseConnection>,
    sessions_started: u64,
    events: mpsc::Sender<(u64, SessionEvent)>,
    failure: Option<String>,
    apply_error: Option<String>,
    infos: Vec<watch::Sender<NodeInfo>>,
    settings: Vec<MeshSettings>,
    avoided: BTreeMap<usize, Vec<IpAddr>>,
    pinned: BTreeMap<usize, Network>,
    local_networks: LocalNetworks,
    overlapping: Vec<(usize, IpNet)>,
    exit_choice: ExitNodeChoice,
}

impl<P: Platform> Agent<P> {
    pub fn new(
        config: ClientSettings,
        device: P::Device,
        platform: P,
        events: mpsc::Sender<(u64, SessionEvent)>,
        ice_events: mpsc::Sender<(u64, IceEvent)>,
    ) -> Result<Self, ConfigError> {
        let settings = mesh_settings(&config)?;
        let lighthouses = lighthouses(&config);
        let infos = infos(&config, &settings);
        Ok(Self {
            config,
            device,
            platform,
            engine: None,
            reflexive: Vec::new(),
            engines_started: 0,
            ice_events,
            lighthouses,
            sessions_started: 0,
            events,
            failure: None,
            apply_error: None,
            infos,
            settings,
            avoided: BTreeMap::new(),
            pinned: BTreeMap::new(),
            local_networks: LocalNetworks::default(),
            overlapping: Vec::new(),
            exit_choice: ExitNodeChoice::Config,
        })
    }

    pub async fn start(&mut self) {
        self.refresh_local_addresses().await;
        self.connect().await;
    }

    pub async fn shutdown(&mut self) {
        self.stop_sessions().await;

        for lighthouse in &mut self.lighthouses {
            lighthouse.netmap = None;
            lighthouse.state = LighthouseState::Connecting;
        }

        self.avoided.clear();
        self.pinned.clear();

        if let Some(mut engine) = self.engine.take() {
            engine.teardown().await;
        }

        self.reflexive.clear();
    }

    pub async fn set_exit_node(&mut self, choice: ExitNodeChoice) {
        self.exit_choice = choice;
        self.update_exit_node().await;
    }

    fn exit_node(&self) -> Option<ExitNode> {
        let (mesh, peer) = match &self.exit_choice {
            ExitNodeChoice::Config => self
                .settings
                .iter()
                .enumerate()
                .find_map(|(index, mesh)| Some((Some(index), mesh.exit_peer.clone()?)))?,
            ExitNodeChoice::Off => return None,
            ExitNodeChoice::Peer(peer) => (None, peer.clone()),
        };

        Some(ExitNode { peer, mesh })
    }

    async fn update_exit_node(&mut self) {
        let exit_node = self.exit_node();

        if let Some(engine) = &mut self.engine
            && let Err(error) = engine.set_exit_node(exit_node).await
        {
            tracing::warn!(%error, "failed to change the exit node");
        }
    }

    pub async fn on_event(&mut self, id: u64, event: SessionEvent) {
        let Some(index) = self.lighthouses.iter().position(|lighthouse| {
            lighthouse
                .session
                .as_ref()
                .is_some_and(|session| session.id == id)
        }) else {
            return;
        };

        let lighthouse = &mut self.lighthouses[index];
        let endpoint = lighthouse.endpoint.clone();

        match event {
            SessionEvent::NetMap(response) => {
                let netmap = response.netmap;

                if let Err(error) = netmap.check() {
                    tracing::error!(lighthouse = endpoint, %error, "ignoring an invalid netmap");
                    lighthouse.state =
                        LighthouseState::Unreachable(format!("sent an invalid netmap: {error}"));
                    return;
                }

                let pinned = self
                    .pinned
                    .entry(lighthouse.mesh)
                    .or_insert_with(|| netmap.network.clone());

                if *pinned != netmap.network {
                    tracing::error!(
                        lighthouse = endpoint,
                        "ignoring a netmap for a different network than the rest of this mesh"
                    );
                    lighthouse.state = LighthouseState::Unreachable(
                        "serves a different network than the rest of this mesh".to_owned(),
                    );
                    return;
                }

                lighthouse.netmap = Some(netmap);
                lighthouse.state = LighthouseState::Connected;
                self.refresh().await;
            },
            SessionEvent::Signal(from, message) => {
                if let Some(engine) = &self.engine {
                    engine.signal(from, message);
                }
            },
            SessionEvent::Error(message) => {
                tracing::warn!(
                    lighthouse = endpoint,
                    "lighthouse connection failed: {message}"
                );
                let was_connected = lighthouse.connected();
                lighthouse.state = LighthouseState::Unreachable(message);

                if was_connected {
                    self.refresh().await;
                }
            },
            SessionEvent::Rejected(reason) => {
                tracing::error!(
                    lighthouse = endpoint,
                    "the lighthouse rejected this node: {reason}"
                );
                lighthouse.netmap = None;
                lighthouse.state = LighthouseState::Rejected(reason.clone());
                let all_rejected = self
                    .lighthouses
                    .iter()
                    .all(|lighthouse| matches!(lighthouse.state, LighthouseState::Rejected(_)));

                if all_rejected {
                    self.shutdown().await;
                    self.failure = Some(reason);
                } else {
                    self.refresh().await;
                }
            },
        }
    }

    pub async fn on_ice_event(&mut self, generation: u64, event: IceEvent) {
        if generation != self.engines_started {
            return;
        }

        let Some(engine) = &mut self.engine else {
            return;
        };

        let result = match event {
            IceEvent::Signal { to, message } => {
                for lighthouse in &self.lighthouses {
                    let knows_peer = lighthouse.connected()
                        && lighthouse
                            .netmap
                            .as_ref()
                            .is_some_and(|netmap| netmap.peers.iter().any(|peer| peer.id == to));

                    if let Some(session) = &lighthouse.session
                        && knows_peer
                    {
                        let envelope = SignalEnvelope {
                            to,
                            message: message.clone(),
                        };

                        if session.signals.try_send(envelope).is_err() {
                            tracing::debug!(%to, "dropping an ICE signal");
                        }
                    }
                }

                Ok(())
            },
            IceEvent::Direct { key, endpoint } => {
                tracing::info!(peer = %key, %endpoint, "direct path");
                engine.set_path(key, Some(endpoint)).await
            },
            IceEvent::Relayed { key } => {
                tracing::info!(peer = %key, "relaying through a hub");
                engine.set_path(key, None).await
            },
            IceEvent::Reflexive(addresses) => {
                tracing::debug!(?addresses, "the hubs see this node at new addresses");
                self.reflexive = addresses;
                Ok(())
            },
        };

        if let Err(error) = result {
            tracing::warn!(%error, "failed to change a peer's path");
        }
    }

    pub async fn tick(&mut self) {
        if let Some(engine) = &mut self.engine
            && let Err(error) = engine.tick().await
        {
            tracing::warn!(%error, "failed to sync the mesh interfaces");
        }
    }

    pub async fn refresh_local_addresses(&mut self) {
        let Some(networks) = self.platform.local_networks(&self.device).await else {
            return;
        };

        if networks == self.local_networks {
            return;
        }

        self.local_networks = networks;

        if let Some(engine) = &mut self.engine
            && let Err(error) = engine
                .network_changed(self.local_networks.offered.clone())
                .await
        {
            tracing::debug!(%error, "failed to handle the network change");
        }

        self.refresh().await;
    }

    pub async fn reload(
        &mut self,
        config: ClientSettings,
        device: P::Device,
    ) -> Result<(), ConfigError> {
        let settings = mesh_settings(&config)?;
        let rebuild = changed(&self.config, &config, |lighthouse| &lighthouse.endpoint)
            || changed(&self.config, &config, |lighthouse| &lighthouse.key)
            || changed(&self.config, &config, |lighthouse| &lighthouse.mesh)
            || config.private_key != self.config.private_key
            || config.listen_port != self.config.listen_port
            || device != self.device
            || dns_meshes(&settings) != dns_meshes(&self.settings);
        let restart = rebuild || self.failure.is_some();

        self.config = config;
        self.device = device;
        self.settings = settings;
        self.exit_choice = ExitNodeChoice::Config;

        if rebuild {
            self.shutdown().await;
            self.lighthouses = lighthouses(&self.config);
            self.infos = infos(&self.config, &self.settings);
        }

        self.publish_info();

        if restart {
            self.connect().await;
        }

        self.update_exit_node().await;
        Ok(())
    }

    fn view(&self) -> Option<View> {
        let netmaps: Vec<(usize, NetMap)> = (0..self.infos.len())
            .filter_map(|mesh| {
                let serving = || {
                    self.lighthouses
                        .iter()
                        .filter(move |lighthouse| lighthouse.mesh == mesh)
                };
                serving()
                    .filter(|lighthouse| lighthouse.connected())
                    .find_map(LighthouseConnection::usable_netmap)
                    .or_else(|| serving().find_map(LighthouseConnection::usable_netmap))
                    .map(|netmap| (mesh, netmap.clone()))
            })
            .collect();

        if netmaps.is_empty() {
            return None;
        }

        let mut view = View {
            meshes: meshes::resolve(netmaps, &self.avoided, &self.local_networks.attached),
            attached: BTreeMap::new(),
            connected: BTreeSet::new(),
            serves: BTreeMap::new(),
        };

        for (index, lighthouse) in self.lighthouses.iter().enumerate() {
            let Some(netmap) = lighthouse.usable_netmap() else {
                continue;
            };

            view.serves.insert(index, lighthouse.mesh);

            if !lighthouse.connected() {
                continue;
            }

            view.connected.insert(index);

            for peer in netmap.peers.iter().filter(|peer| peer.online) {
                view.attached.entry(peer.key).or_default().insert(index);
            }
        }

        Some(view)
    }

    async fn refresh(&mut self) {
        let Some(view) = self.view() else {
            return;
        };

        let avoided: BTreeMap<usize, Vec<IpAddr>> = view
            .meshes
            .iter()
            .map(|mesh| (mesh.index, mesh.avoid.clone()))
            .collect();

        if avoided != self.avoided {
            self.avoided = avoided;
            self.publish_info();
        }

        let overlapping: Vec<(usize, IpNet)> = view
            .meshes
            .iter()
            .flat_map(|mesh| mesh.overlapping.iter().map(|net| (mesh.index, *net)))
            .collect();

        for mesh in &view.meshes {
            for network in mesh
                .overlapping
                .iter()
                .filter(|net| !self.overlapping.contains(&(mesh.index, **net)))
            {
                tracing::warn!(
                    mesh = %mesh.netmap.network.domain,
                    %network,
                    "a local network overlaps this mesh; only peers outside it are routed through the mesh",
                );
            }
        }

        self.overlapping = overlapping;

        let Some(engine) = &mut self.engine else {
            return;
        };

        self.apply_error = match engine.apply(view).await {
            Ok(()) => None,
            Err(error) => {
                tracing::warn!(%error, "failed to apply the netmap");
                Some(format!("failed to apply the netmap: {error}"))
            },
        };
    }

    fn phase(&self) -> Phase {
        if let Some(reason) = &self.failure {
            return Phase::Failed(reason.clone());
        }

        if let Some(error) = &self.apply_error {
            return Phase::Degraded(error.clone());
        }

        let unreachable = self
            .lighthouses
            .iter()
            .find_map(|lighthouse| match &lighthouse.state {
                LighthouseState::Unreachable(reason) => Some(reason.clone()),
                _ => None,
            });
        let connected = self.lighthouses.iter().any(LighthouseConnection::connected);
        let has_netmap = self
            .lighthouses
            .iter()
            .any(|lighthouse| lighthouse.usable_netmap().is_some());

        match (connected, has_netmap, unreachable) {
            (true, true, _) => Phase::Running,
            (false, _, Some(reason)) => {
                Phase::Degraded(format!("no lighthouse is reachable: {reason}"))
            },
            _ => Phase::Connecting,
        }
    }

    pub fn records(&self) -> Vec<RecordEntry> {
        let meshes = self.view().map(|view| view.meshes).unwrap_or_default();

        self.settings
            .iter()
            .enumerate()
            .flat_map(|(index, settings)| {
                let mesh = meshes.iter().find(|mesh| mesh.index == index);
                let lighthouses: Vec<String> = self
                    .lighthouses
                    .iter()
                    .filter(|lighthouse| lighthouse.mesh == index)
                    .map(|lighthouse| lighthouse.endpoint.clone())
                    .collect();

                settings.records.iter().map(move |record| RecordEntry {
                    record: record.clone(),
                    mesh: mesh.map(|mesh| mesh.netmap.network.domain.clone()),
                    lighthouses: lighthouses.clone(),
                    state: mesh.and_then(|mesh| {
                        mesh.netmap
                            .node
                            .records
                            .iter()
                            .find(|status| status.record == *record)
                            .map(|status| status.state)
                    }),
                })
            })
            .collect()
    }

    pub fn status(&self) -> StatusReport {
        let meshes = self.view().map(|view| view.meshes).unwrap_or_default();
        let relayed = self
            .engine
            .as_ref()
            .map(|engine| engine.relay().connected())
            .unwrap_or_default();
        StatusReport {
            phase: self.phase(),
            lighthouses: self
                .lighthouses
                .iter()
                .enumerate()
                .map(|(index, lighthouse)| LighthouseStatus {
                    endpoint: lighthouse.endpoint.clone(),
                    mesh: meshes
                        .iter()
                        .find(|mesh| mesh.index == lighthouse.mesh)
                        .map(|mesh| mesh.netmap.network.domain.clone()),
                    state: lighthouse.state.clone(),
                    relay: relayed.contains(&index),
                })
                .collect(),
            key: self.config.private_key.public_key(),
            observed_endpoints: self.reflexive.clone(),
            nodes: meshes
                .iter()
                .map(|mesh| {
                    let node = &mesh.netmap.node;
                    NodeStatus {
                        id: node.id,
                        hostname: node.hostname.clone(),
                        fqdn: format!("{}.{}", node.hostname, mesh.netmap.network.domain),
                        addresses: mesh.addresses.clone(),
                        taken: mesh.taken(),
                    }
                })
                .collect(),
            exit_node: self.exit_node().map(|exit_node| ExitNodeStatus {
                active: self.engine.as_ref().is_some_and(Engine::exit_node_active),
                peer: exit_node.peer,
            }),
            peers: self.engine.as_ref().map(Engine::status).unwrap_or_default(),
        }
    }

    async fn connect(&mut self) {
        self.stop_sessions().await;
        self.failure = None;
        let own_key = self.config.private_key.public_key();
        let mut clients = Vec::new();

        for entry in &self.config.lighthouses {
            match ApiClient::new(&own_key, &entry.key) {
                Ok(client) => clients.push(client),
                Err(error) => {
                    tracing::error!(
                        lighthouse = entry.endpoint,
                        %error,
                        "failed to set up the API client"
                    );
                    self.failure = Some(error.to_string());
                    return;
                },
            }
        }

        if self.engine.is_none() {
            self.engines_started += 1;
            let setup = Setup {
                key: &self.config.private_key,
                listen_port: self.config.listen_port,
                dns_meshes: dns_meshes(&self.settings),
                hubs: self
                    .config
                    .lighthouses
                    .iter()
                    .map(|entry| Hub::new(entry.key, entry.endpoint.clone()))
                    .collect(),
                exit_node: self.exit_node(),
                local_networks: self.local_networks.offered.clone(),
                ice_events: self.ice_events.clone(),
                generation: self.engines_started,
            };

            match Engine::start(&self.platform, &self.device, setup).await {
                Ok(engine) => self.engine = Some(engine),
                Err(error) => {
                    tracing::error!(%error, "failed to set up the dataplane");
                    self.failure = Some(format!("failed to set up the dataplane: {error}"));
                    return;
                },
            }
        }

        self.tick().await;

        let Some(engine) = &self.engine else {
            return;
        };
        let relay = engine.relay();
        let tunnel = engine.readiness();

        for (index, (lighthouse, client)) in self.lighthouses.iter_mut().zip(clients).enumerate() {
            self.sessions_started += 1;
            let id = self.sessions_started;
            let (signals, outgoing) = mpsc::channel(SIGNAL_QUEUE);
            let session = Session {
                client,
                relay: Arc::clone(&relay),
                lighthouse: index,
                tunnel: tunnel.clone(),
            };
            let info = self.infos[lighthouse.mesh].subscribe();
            let task = tokio::spawn(session.run(id, info, outgoing, self.events.clone()));

            lighthouse.session = Some(RunningSession { id, task, signals });
            lighthouse.state = LighthouseState::Connecting;
        }
    }

    async fn stop_sessions(&mut self) {
        for lighthouse in &mut self.lighthouses {
            if let Some(session) = lighthouse.session.take() {
                session.task.abort();

                if let Err(error) = session.task.await
                    && error.is_panic()
                {
                    tracing::error!(%error, "a lighthouse session panicked");
                }
            }
        }
    }

    fn publish_info(&self) {
        for (mesh, sender) in self.infos.iter().enumerate() {
            let avoid = self.avoided.get(&mesh).cloned().unwrap_or_default();
            let info = node_info(&self.config, &self.settings[mesh], avoid);
            sender.send_if_modified(|current| {
                let changed = *current != info;
                *current = info;
                changed
            });
        }
    }
}

fn changed<T>(
    old: &ClientSettings,
    new: &ClientSettings,
    field: impl Fn(&LighthouseSettings) -> &T,
) -> bool
where
    T: PartialEq,
{
    old.lighthouses
        .iter()
        .map(&field)
        .ne(new.lighthouses.iter().map(&field))
}

fn mesh_indices(config: &ClientSettings) -> Vec<usize> {
    let mut meshes: Vec<&Option<String>> = Vec::new();
    config
        .lighthouses
        .iter()
        .map(|lighthouse| {
            let name = &lighthouse.mesh;
            meshes
                .iter()
                .position(|known| *known == name)
                .unwrap_or_else(|| {
                    meshes.push(name);
                    meshes.len() - 1
                })
        })
        .collect()
}

fn lighthouses(config: &ClientSettings) -> Vec<LighthouseConnection> {
    config
        .lighthouses
        .iter()
        .zip(mesh_indices(config))
        .map(|(entry, mesh)| LighthouseConnection::new(entry.endpoint.clone(), mesh))
        .collect()
}

/// Every lighthouse of a mesh must be sent the same node info, so the settings listed on each of
/// them are combined: records are merged, and the rest may be set on any of them but must not
/// disagree.
fn mesh_settings(config: &ClientSettings) -> Result<Vec<MeshSettings>, ConfigError> {
    #[derive(Default)]
    struct Combined {
        records: Vec<DnsRecord>,
        accept_dns: Option<bool>,
        exit_peer: Option<DnsName>,
        advertise_exit_node: Option<bool>,
    }

    let mut meshes: Vec<Combined> = Vec::new();

    for (entry, mesh) in config.lighthouses.iter().zip(mesh_indices(config)) {
        if mesh == meshes.len() {
            meshes.push(Combined::default());
        }

        let lighthouse = &entry.endpoint;
        let combined = &mut meshes[mesh];

        for record in &entry.dns.records {
            if !combined.records.contains(record) {
                combined.records.push(record.clone());
            }
        }

        if combined.records.len() > MAX_RECORDS {
            return Err(ConfigError::invalid(
                "client.lighthouses",
                format!(
                    "\"{lighthouse}\" serves one mesh with other lighthouses, and together they list \
                     more than {MAX_RECORDS} records"
                ),
            ));
        }

        agree(
            lighthouse,
            "dns.accept",
            &mut combined.accept_dns,
            entry.dns.accept,
        )?;
        agree(
            lighthouse,
            "exit_node.peer",
            &mut combined.exit_peer,
            entry.exit_node.peer.clone(),
        )?;
        agree(
            lighthouse,
            "exit_node.advertise",
            &mut combined.advertise_exit_node,
            entry.exit_node.advertise,
        )?;
    }

    if meshes
        .iter()
        .filter(|mesh| mesh.exit_peer.is_some())
        .count()
        > 1
    {
        return Err(ConfigError::invalid(
            "client.lighthouses",
            "exit_node.peer is set for more than one mesh, but internet traffic leaves through a \
             single exit node",
        ));
    }

    Ok(meshes
        .into_iter()
        .map(|combined| MeshSettings {
            records: combined.records,
            accept_dns: combined.accept_dns.unwrap_or(true),
            exit_peer: combined.exit_peer,
            advertise_exit_node: combined.advertise_exit_node.unwrap_or_default(),
        })
        .collect())
}

fn agree<T>(
    lighthouse: &str,
    setting: &str,
    combined: &mut Option<T>,
    value: Option<T>,
) -> Result<(), ConfigError>
where
    T: PartialEq,
{
    let Some(value) = value else {
        return Ok(());
    };

    if combined.as_ref().is_some_and(|current| *current != value) {
        return Err(ConfigError::invalid(
            "client.lighthouses",
            format!(
                "\"{lighthouse}\" sets {setting} differently from another lighthouse, though they \
                 serve one mesh"
            ),
        ));
    }

    *combined = Some(value);
    Ok(())
}

fn dns_meshes(settings: &[MeshSettings]) -> BTreeSet<usize> {
    settings
        .iter()
        .enumerate()
        .filter(|(_, mesh)| mesh.accept_dns)
        .map(|(index, _)| index)
        .collect()
}

fn infos(config: &ClientSettings, settings: &[MeshSettings]) -> Vec<watch::Sender<NodeInfo>> {
    settings
        .iter()
        .map(|mesh| watch::channel(node_info(config, mesh, Vec::new())).0)
        .collect()
}

fn node_info(config: &ClientSettings, mesh: &MeshSettings, avoid: Vec<IpAddr>) -> NodeInfo {
    let hostname = config
        .hostname
        .clone()
        .or_else(|| {
            let system = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
            DnsName::sanitize_label(system.trim())
        })
        .unwrap_or_else(|| "node".parse().expect("valid label"));
    NodeInfo {
        hostname,
        records: mesh.records.clone(),
        advertise_exit_node: mesh.advertise_exit_node,
        avoid,
    }
}
