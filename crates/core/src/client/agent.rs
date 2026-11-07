use std::collections::{BTreeMap, BTreeSet};
use std::iter;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bunnyhop_config::{ClientConfig, ConfigError, read_key};
use bunnyhop_net::Dataplane;
use bunnyhop_proto::{
    AuthKey, DnsName, ExitNodeChoice, ExitNodeStatus, LighthouseState, LighthouseStatus, NetMap,
    Network, NodeInfo, NodeStatus, Phase, PrivateKey, RecordEntry, SecretHash, SignalEnvelope,
    StatusReport, Token,
};
use ipnet::IpNet;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use url::{Host, Url};

use crate::client::api::ApiClient;
use crate::client::endpoints::local_networks;
use crate::client::engine::{Engine, ExitNode, Setup, View};
use crate::client::ice::IceEvent;
use crate::client::meshes;
use crate::client::session::{Session, SessionEvent};

const LOGOUT_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNAL_QUEUE: usize = 256;

struct RunningSession {
    id: u64,
    task: JoinHandle<()>,
    signals: mpsc::Sender<SignalEnvelope>,
}

struct LighthouseConnection {
    url: Url,
    mesh: usize,
    auth_key: AuthKey,
    api: Option<ApiClient>,
    session: Option<RunningSession>,
    token: Option<Token>,
    netmap: Option<NetMap>,
    state: LighthouseState,
}

impl LighthouseConnection {
    const fn new(url: Url, mesh: usize, auth_key: AuthKey) -> Self {
        Self {
            url,
            mesh,
            auth_key,
            api: None,
            session: None,
            token: None,
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

pub struct Agent {
    config: ClientConfig,
    key: PrivateKey,
    dataplane: Arc<Dataplane>,
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
    avoided: BTreeMap<usize, Vec<IpAddr>>,
    pinned: BTreeMap<usize, Network>,
    local_networks: Vec<IpNet>,
    exit_choice: ExitNodeChoice,
    lighthouse_addresses: Vec<IpAddr>,
}

impl Agent {
    pub fn new(
        config: ClientConfig,
        dataplane: Arc<Dataplane>,
        events: mpsc::Sender<(u64, SessionEvent)>,
        ice_events: mpsc::Sender<(u64, IceEvent)>,
    ) -> Result<Self, ConfigError> {
        let keys = config.read_auth_keys()?;
        let key = if let Some(path) = &config.private_key_file {
            read_key(path)?
        } else {
            tracing::info!(
                "private_key_file is not set, so this node gets a new identity each start; \
                 its pre-auth key should have a short offline_ttl"
            );
            PrivateKey::generate()
        };
        let lighthouses = lighthouses(&config, keys);
        let infos = infos(&config, &lighthouses);
        Ok(Self {
            config,
            key,
            dataplane,
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
            avoided: BTreeMap::new(),
            pinned: BTreeMap::new(),
            local_networks: Vec::new(),
            exit_choice: ExitNodeChoice::Config,
            lighthouse_addresses: Vec::new(),
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

    pub async fn logout_if_ephemeral(&mut self) {
        if self.config.private_key_file.is_none() {
            self.logout().await;
        }
    }

    async fn logout(&mut self) {
        self.stop_sessions().await;

        for lighthouse in &mut self.lighthouses {
            let (Some(token), Some(api)) = (lighthouse.token.take(), &lighthouse.api) else {
                continue;
            };

            let url = &lighthouse.url;

            match tokio::time::timeout(LOGOUT_TIMEOUT, api.logout(&token)).await {
                Ok(Ok(())) => tracing::info!(lighthouse = %url, "logged out"),
                Ok(Err(error)) => tracing::warn!(lighthouse = %url, %error, "failed to log out"),
                Err(_) => tracing::warn!(lighthouse = %url, "failed to log out: no answer"),
            }
        }
    }

    pub async fn set_exit_node(&mut self, choice: ExitNodeChoice) {
        self.exit_choice = choice;
        self.update_exit_node().await;
    }

    fn exit_node(&self) -> Option<ExitNode> {
        let peer = match &self.exit_choice {
            ExitNodeChoice::Config => self.config.exit_node.peer.clone()?,
            ExitNodeChoice::Off => return None,
            ExitNodeChoice::Peer(peer) => peer.clone(),
        };

        Some(ExitNode {
            peer,
            bypass: self.lighthouse_addresses.clone(),
        })
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
        let url = lighthouse.url.clone();

        match event {
            SessionEvent::Registered(token) => lighthouse.token = Some(token),
            SessionEvent::NetMap(response) => {
                let netmap = response.netmap;

                if let Err(error) = netmap.check() {
                    tracing::error!(lighthouse = %url, %error, "ignoring an invalid netmap");
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
                        lighthouse = %url,
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
                tracing::warn!(lighthouse = %url, "lighthouse connection failed: {message}");
                let was_connected = lighthouse.connected();
                lighthouse.state = LighthouseState::Unreachable(message);

                if was_connected {
                    self.refresh().await;
                }
            },
            SessionEvent::Rejected(reason) => {
                tracing::error!(lighthouse = %url, "the lighthouse rejected this node: {reason}");
                lighthouse.token = None;
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
        let networks = match self.dataplane.local_addresses().await {
            Ok(all) => local_networks(
                &all,
                &self.config.interface.name,
                &self.config.interface.exclude,
            ),
            Err(error) => {
                tracing::debug!(%error, "failed to list local addresses");
                return;
            },
        };

        if networks == self.local_networks {
            return;
        }

        self.local_networks = networks;

        if let Some(engine) = &mut self.engine
            && let Err(error) = engine.network_changed(self.local_networks.clone()).await
        {
            tracing::debug!(%error, "failed to handle the network change");
        }
    }

    pub async fn reload(&mut self, config: ClientConfig) -> Result<(), ConfigError> {
        let keys = config.read_auth_keys()?;
        let key = match &config.private_key_file {
            Some(path) => read_key(path)?,
            None => self.key.clone(),
        };

        let lighthouses_changed = config.lighthouses != self.config.lighthouses;
        let auth_keys_changed = self
            .lighthouses
            .iter()
            .map(|lighthouse| &lighthouse.auth_key)
            .ne(keys.iter());
        let key_changed = key != self.key;
        let rebuild = lighthouses_changed
            || auth_keys_changed
            || key_changed
            || config.interface != self.config.interface
            || config.dns.accept != self.config.dns.accept;
        let restart = rebuild || config.ca_file != self.config.ca_file || self.failure.is_some();

        if key_changed {
            self.logout().await;
        } else if lighthouses_changed {
            self.logout_if_ephemeral().await;
        }

        self.config = config;
        self.key = key;
        self.exit_choice = ExitNodeChoice::Config;

        if rebuild {
            self.shutdown().await;
            self.lighthouses = lighthouses(&self.config, keys);
            self.infos = infos(&self.config, &self.lighthouses);
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
            meshes: meshes::resolve(netmaps, &self.avoided),
            hubs: BTreeMap::new(),
            attached: BTreeMap::new(),
            connected: BTreeSet::new(),
            serves: BTreeMap::new(),
        };

        for (index, lighthouse) in self.lighthouses.iter().enumerate() {
            let Some(netmap) = lighthouse.usable_netmap() else {
                continue;
            };

            view.hubs.insert(index, netmap.hub.clone());
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
        let records = &self.config.dns.records;

        let Some(view) = self.view() else {
            return records
                .iter()
                .map(|record| RecordEntry {
                    record: record.clone(),
                    mesh: None,
                    state: None,
                })
                .collect();
        };

        view.meshes
            .iter()
            .flat_map(|mesh| {
                records.iter().map(|record| RecordEntry {
                    record: record.clone(),
                    mesh: Some(mesh.netmap.network.domain.clone()),
                    state: mesh
                        .netmap
                        .node
                        .records
                        .iter()
                        .find(|status| status.record == *record)
                        .map(|status| status.state),
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
                    url: lighthouse.url.clone(),
                    mesh: meshes
                        .iter()
                        .find(|mesh| mesh.index == lighthouse.mesh)
                        .map(|mesh| mesh.netmap.network.domain.clone()),
                    state: lighthouse.state.clone(),
                    relay: relayed.contains(&index),
                })
                .collect(),
            key: self.key.public_key(),
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
        let mut clients = Vec::new();

        for entry in &self.config.lighthouses {
            let url = &entry.url;

            match ApiClient::new(url.clone(), self.config.ca_file.as_deref()) {
                Ok(client) => clients.push(client),
                Err(error) => {
                    tracing::error!(lighthouse = %url, %error, "failed to set up the API client");
                    self.failure = Some(error.to_string());
                    return;
                },
            }
        }

        if self.engine.is_none() {
            self.engines_started += 1;
            let setup = Setup {
                dataplane: Arc::clone(&self.dataplane),
                interface: &self.config.interface,
                key: &self.key,
                accept_dns: self.config.dns.accept,
                lighthouses: self
                    .config
                    .lighthouses
                    .iter()
                    .map(|entry| entry.url.clone())
                    .collect(),
                local_networks: self.local_networks.clone(),
                ice_events: self.ice_events.clone(),
                generation: self.engines_started,
            };

            match Engine::start(setup).await {
                Ok(engine) => self.engine = Some(engine),
                Err(error) => {
                    tracing::error!(%error, "failed to set up the dataplane");
                    self.failure = Some(format!("failed to set up the dataplane: {error}"));
                    return;
                },
            }
        }

        self.resolve_lighthouse_addresses().await;
        self.update_exit_node().await;

        let Some(relay) = self.engine.as_ref().map(Engine::relay) else {
            return;
        };

        for (index, (lighthouse, client)) in self.lighthouses.iter_mut().zip(clients).enumerate() {
            self.sessions_started += 1;
            let id = self.sessions_started;
            let (signals, outgoing) = mpsc::channel(SIGNAL_QUEUE);
            let session = Session {
                client: client.clone(),
                auth_key: lighthouse.auth_key.clone(),
                key: self.key.clone(),
                relay: Arc::clone(&relay),
                lighthouse: index,
            };
            let info = self.infos[lighthouse.mesh].subscribe();
            let task = tokio::spawn(session.run(id, info, outgoing, self.events.clone()));

            lighthouse.api = Some(client);
            lighthouse.session = Some(RunningSession { id, task, signals });
            lighthouse.state = LighthouseState::Connecting;
        }
    }

    async fn resolve_lighthouse_addresses(&mut self) {
        let mut addresses = Vec::new();

        for entry in &self.config.lighthouses {
            let lighthouse = &entry.url;
            let port = lighthouse.port_or_known_default().unwrap_or(443);

            match lighthouse.host() {
                Some(Host::Domain(domain)) => match tokio::net::lookup_host((domain, port)).await {
                    Ok(found) => addresses.extend(found.map(|address| address.ip())),
                    Err(error) => {
                        tracing::warn!(%lighthouse, %error, "failed to resolve the lighthouse");
                    },
                },
                Some(Host::Ipv4(address)) => addresses.push(IpAddr::V4(address)),
                Some(Host::Ipv6(address)) => addresses.push(IpAddr::V6(address)),
                None => {},
            }
        }

        addresses.sort_unstable();
        addresses.dedup();
        self.lighthouse_addresses = addresses;
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
            let info = node_info(&self.config, avoid);
            sender.send_if_modified(|current| {
                let changed = *current != info;
                *current = info;
                changed
            });
        }
    }
}

fn lighthouses(config: &ClientConfig, keys: Vec<AuthKey>) -> Vec<LighthouseConnection> {
    let mut meshes: Vec<SecretHash> = Vec::new();
    config
        .lighthouses
        .iter()
        .zip(keys)
        .map(|(entry, auth_key)| {
            let hash = auth_key.hash();
            let mesh = meshes
                .iter()
                .position(|known| *known == hash)
                .unwrap_or_else(|| {
                    meshes.push(hash);
                    meshes.len() - 1
                });
            LighthouseConnection::new(entry.url.clone(), mesh, auth_key)
        })
        .collect()
}

fn infos(
    config: &ClientConfig,
    lighthouses: &[LighthouseConnection],
) -> Vec<watch::Sender<NodeInfo>> {
    let count = lighthouses
        .iter()
        .map(|lighthouse| lighthouse.mesh + 1)
        .max()
        .unwrap_or_default();
    iter::repeat_with(|| watch::channel(node_info(config, Vec::new())).0)
        .take(count)
        .collect()
}

fn node_info(config: &ClientConfig, avoid: Vec<IpAddr>) -> NodeInfo {
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
        records: config.dns.records.clone(),
        advertise_exit_node: config.exit_node.advertise,
        avoid,
    }
}
