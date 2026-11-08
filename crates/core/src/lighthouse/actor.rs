use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use compass_config::LighthouseConfig;
use compass_proto::{
    LONG_POLL, NodeId, NodeInfo, PublicKey, RegisterRequest, RegisterResponse, Token,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::lighthouse::registry::{ReconcileReport, RegisterError, Registry};
use crate::lighthouse::world::{Liveness, World};

const TICK: Duration = Duration::from_secs(5);
const ONLINE_AFTER_ACTIVITY: Duration = LONG_POLL.saturating_add(Duration::from_secs(40));

enum Command {
    Register(
        RegisterRequest,
        oneshot::Sender<Result<RegisterResponse, RegisterError>>,
    ),
    Update(NodeId, NodeInfo, oneshot::Sender<Result<(), RegisterError>>),
    Logout(NodeId, oneshot::Sender<()>),
    Reload(Box<LighthouseConfig>, oneshot::Sender<ReconcileReport>),
}

type Presence = Arc<Mutex<HashMap<NodeId, Instant>>>;

#[derive(Clone)]
pub struct RegistryHandle {
    commands: mpsc::Sender<Command>,
    world: watch::Receiver<Arc<World>>,
    presence: Presence,
}

impl RegistryHandle {
    pub fn subscribe(&self) -> watch::Receiver<Arc<World>> {
        self.world.clone()
    }

    pub fn authenticate(&self, token: &Token) -> Option<NodeId> {
        self.world.borrow().authenticate(token)
    }

    pub fn sees(&self, from: NodeId, to: NodeId) -> bool {
        self.world.borrow().sees(from, to)
    }

    pub fn touch(&self, id: NodeId) {
        self.presence
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Instant::now());
    }

    pub async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<RegisterResponse, RegisterError> {
        self.call(|reply| Command::Register(request, reply))
            .await
            .unwrap_or(Err(RegisterError::Unavailable))
    }

    pub async fn update(&self, id: NodeId, info: NodeInfo) -> Result<(), RegisterError> {
        self.call(|reply| Command::Update(id, info, reply))
            .await
            .unwrap_or(Err(RegisterError::Unavailable))
    }

    pub async fn logout(&self, id: NodeId) {
        let _ = self.call(|reply| Command::Logout(id, reply)).await;
    }

    pub async fn reload(&self, config: LighthouseConfig) -> Option<ReconcileReport> {
        self.call(|reply| Command::Reload(Box::new(config), reply))
            .await
    }

    async fn call<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (reply, response) = oneshot::channel();
        self.commands.send(command(reply)).await.ok()?;
        response.await.ok()
    }
}

struct Actor {
    config: Arc<LighthouseConfig>,
    hub_key: PublicKey,
    registry: Registry,
    presence: Presence,
    last_active: HashMap<NodeId, Instant>,
    liveness: Liveness,
    world: watch::Sender<Arc<World>>,
}

pub fn spawn(
    config: Arc<LighthouseConfig>,
    hub_key: PublicKey,
    cancel: CancellationToken,
) -> (RegistryHandle, tokio::task::JoinHandle<()>) {
    let registry = Registry::default();
    let liveness = Liveness::default();
    let world = World::build(Arc::clone(&config), hub_key, &registry, &liveness);
    let (world_sender, world_receiver) = watch::channel(Arc::new(world));
    let (commands, receiver) = mpsc::channel(64);
    let presence = Presence::default();

    let actor = Actor {
        config,
        hub_key,
        last_active: HashMap::new(),
        registry,
        presence: Arc::clone(&presence),
        liveness,
        world: world_sender,
    };
    let task = tokio::spawn(actor.run(receiver, cancel));
    (
        RegistryHandle {
            commands,
            world: world_receiver,
            presence,
        },
        task,
    )
}

impl Actor {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(TICK);

        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                Some(command) = commands.recv() => self.handle(command),
                _ = tick.tick() => self.tick(),
            }
        }
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Register(request, reply) => {
                let _ = reply.send(self.register(request));
            },
            Command::Update(id, info, reply) => {
                let result = self.registry.update(&self.config, id, info);

                if result == Ok(true) {
                    self.publish();
                }

                let _ = reply.send(result.map(drop));
            },
            Command::Logout(id, reply) => {
                if self.registry.remove(&self.config, id) {
                    tracing::info!(node = %id, "node logged out");
                    self.forget(id);
                    self.publish();
                }

                let _ = reply.send(());
            },
            Command::Reload(config, reply) => {
                self.config = Arc::new(*config);
                let report = self.registry.reconcile(&self.config);

                for id in &report.removed {
                    self.forget(*id);
                }

                self.publish();
                let _ = reply.send(report);
            },
        }
    }

    fn register(&mut self, request: RegisterRequest) -> Result<RegisterResponse, RegisterError> {
        let (id, token) = self.registry.register(&self.config, request)?;
        self.last_active.insert(id, Instant::now());
        self.publish();
        tracing::info!(node = %id, "node registered");

        let netmap = self
            .world
            .borrow()
            .netmap(id)
            .cloned()
            .ok_or(RegisterError::Unavailable)?;
        Ok(RegisterResponse {
            node_id: id,
            token,
            netmap,
        })
    }

    fn tick(&mut self) {
        self.refresh_liveness();

        if self.collect_offline() {
            self.publish();
        }
    }

    fn publish(&self) {
        let world = World::build(
            Arc::clone(&self.config),
            self.hub_key,
            &self.registry,
            &self.liveness,
        );
        self.world.send_replace(Arc::new(world));
    }

    fn refresh_liveness(&mut self) {
        let now = Instant::now();
        let presence = self
            .presence
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();

        let mut liveness = Liveness::default();

        for node in self.registry.nodes().values() {
            let active = presence
                .get(&node.id)
                .is_some_and(|seen| now.duration_since(*seen) < ONLINE_AFTER_ACTIVITY);

            if active {
                liveness.online.insert(node.id);
                self.last_active.insert(node.id, now);
            }
        }

        if liveness != self.liveness {
            self.liveness = liveness;
            self.publish();
        }
    }

    fn collect_offline(&mut self) -> bool {
        let now = Instant::now();
        let expired: Vec<NodeId> = self
            .registry
            .nodes()
            .values()
            .filter(|node| {
                let active = self.last_active.get(&node.id);
                self.config.keys.get(&node.key_name).is_none_or(|key| {
                    active.is_none_or(|at| now.duration_since(*at) > key.offline_ttl)
                })
            })
            .map(|node| node.id)
            .collect();

        for id in &expired {
            tracing::info!(node = %id, "removing a node that has been offline too long");
            self.registry.remove(&self.config, *id);
            self.forget(*id);
        }

        !expired.is_empty()
    }

    fn forget(&mut self, id: NodeId) {
        self.last_active.remove(&id);
        self.presence
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }
}
