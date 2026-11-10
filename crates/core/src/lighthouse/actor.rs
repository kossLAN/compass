use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use compass_config::LighthouseConfig;
use compass_proto::{LONG_POLL, NodeId, NodeInfo};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::lighthouse::registry::{AnnounceError, ReconcileReport, Registry};
use crate::lighthouse::world::{Liveness, World};

const TICK: Duration = Duration::from_secs(5);
const ONLINE_AFTER_ACTIVITY: Duration = LONG_POLL.saturating_add(Duration::from_secs(40));

enum Command {
    Announce(NodeId, NodeInfo, oneshot::Sender<Result<(), AnnounceError>>),
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

    pub fn lists(&self, id: NodeId) -> bool {
        self.world.borrow().lists(id)
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

    pub async fn announce(&self, id: NodeId, info: NodeInfo) -> Result<(), AnnounceError> {
        self.call(|reply| Command::Announce(id, info, reply))
            .await
            .unwrap_or(Err(AnnounceError::Unavailable))
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
    registry: Registry,
    presence: Presence,
    liveness: Liveness,
    world: watch::Sender<Arc<World>>,
}

pub fn spawn(
    config: Arc<LighthouseConfig>,
    cancel: CancellationToken,
) -> (RegistryHandle, tokio::task::JoinHandle<()>) {
    let registry = Registry::default();
    let liveness = Liveness::default();
    let world = World::build(Arc::clone(&config), &registry, &liveness);
    let (world_sender, world_receiver) = watch::channel(Arc::new(world));
    let (commands, receiver) = mpsc::channel(64);
    let presence = Presence::default();

    let actor = Actor {
        config,
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
                _ = tick.tick() => self.refresh_liveness(),
            }
        }
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Announce(id, info, reply) => {
                let _ = reply.send(self.announce(id, info));
            },
            Command::Reload(config, reply) => {
                self.config = Arc::new(*config);
                let report = self.registry.reconcile(&self.config);

                self.presence
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retain(|id, _| !report.removed.contains(id));
                self.publish();
                let _ = reply.send(report);
            },
        }
    }

    fn announce(&mut self, id: NodeId, info: NodeInfo) -> Result<(), AnnounceError> {
        let joined = !self.registry.nodes().contains_key(&id);

        if self.registry.announce(&self.config, id, info)? {
            self.publish();
        }

        if joined {
            tracing::info!(node = self.config.nodes[&id].name, %id, "node joined");
        }

        Ok(())
    }

    fn publish(&self) {
        let world = World::build(Arc::clone(&self.config), &self.registry, &self.liveness);
        self.world.send_replace(Arc::new(world));
    }

    fn refresh_liveness(&mut self) {
        let now = Instant::now();
        let presence = self
            .presence
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();

        let online = self
            .registry
            .nodes()
            .keys()
            .filter(|id| {
                presence
                    .get(id)
                    .is_some_and(|seen| now.duration_since(*seen) < ONLINE_AFTER_ACTIVITY)
            })
            .copied()
            .collect();
        let liveness = Liveness { online };

        if liveness != self.liveness {
            self.liveness = liveness;
            self.publish();
        }
    }
}
