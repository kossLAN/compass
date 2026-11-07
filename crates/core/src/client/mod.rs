mod agent;
mod api;
mod dataplane;
mod dns;
mod endpoints;
mod engine;
mod ice;
mod meshes;
mod relay;
mod session;

use std::sync::Arc;
use std::time::Duration;

use bunnyhop_config::{ClientConfig, ConfigError};
use bunnyhop_net::{Dataplane, NetError};
use bunnyhop_proto::{ExitNodeChoice, RecordEntry, StatusReport};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use self::agent::Agent;
use self::ice::IceEvent;
use self::session::SessionEvent;

const TICK: Duration = Duration::from_secs(1);
const ADDRESS_SCAN: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Net(#[from] NetError),
}

#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Stopped(#[from] Stopped),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("the client has stopped")]
pub struct Stopped;

enum Command {
    Status(oneshot::Sender<StatusReport>),
    Records(oneshot::Sender<Vec<RecordEntry>>),
    SetExitNode(ExitNodeChoice, oneshot::Sender<StatusReport>),
    Reload(Box<ClientConfig>, oneshot::Sender<Result<(), ConfigError>>),
}

pub struct Client {
    commands: mpsc::Sender<Command>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Client {
    pub async fn start(config: ClientConfig) -> Result<Self, StartError> {
        let dataplane = Arc::new(Dataplane::new()?);
        let (events_sender, events) = mpsc::channel(64);
        let (ice_sender, ice_events) = mpsc::channel(256);
        let mut agent = Agent::new(config, dataplane, events_sender, ice_sender)?;
        agent.start().await;

        let (commands, receiver) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(agent, receiver, events, ice_events, cancel.clone()));
        Ok(Self {
            commands,
            cancel,
            task,
        })
    }

    pub async fn status(&self) -> Result<StatusReport, Stopped> {
        self.call(Command::Status).await
    }

    pub async fn records(&self) -> Result<Vec<RecordEntry>, Stopped> {
        self.call(Command::Records).await
    }

    pub async fn set_exit_node(&self, choice: ExitNodeChoice) -> Result<StatusReport, Stopped> {
        self.call(|reply| Command::SetExitNode(choice, reply)).await
    }

    pub async fn reload(&self, config: ClientConfig) -> Result<(), ReloadError> {
        Ok(self
            .call(|reply| Command::Reload(Box::new(config), reply))
            .await??)
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();

        if let Err(error) = self.task.await
            && error.is_panic()
        {
            tracing::error!(%error, "the client panicked");
        }
    }

    async fn call<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, Stopped> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| Stopped)?;
        response.await.map_err(|_| Stopped)
    }
}

async fn run(
    mut agent: Agent,
    mut commands: mpsc::Receiver<Command>,
    mut events: mpsc::Receiver<(u64, SessionEvent)>,
    mut ice_events: mpsc::Receiver<(u64, IceEvent)>,
    cancel: CancellationToken,
) {
    let mut tick = tokio::time::interval(TICK);
    let mut scan = tokio::time::interval(ADDRESS_SCAN);

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            Some(command) = commands.recv() => match command {
                Command::Status(reply) => {
                    let _ = reply.send(agent.status());
                },
                Command::Records(reply) => {
                    let _ = reply.send(agent.records());
                },
                Command::SetExitNode(choice, reply) => {
                    agent.set_exit_node(choice).await;
                    let _ = reply.send(agent.status());
                },
                Command::Reload(config, reply) => {
                    let _ = reply.send(agent.reload(*config).await);
                },
            },
            Some((id, event)) = events.recv() => agent.on_event(id, event).await,
            Some((generation, event)) = ice_events.recv() => agent.on_ice_event(generation, event).await,
            _ = tick.tick() => agent.tick().await,
            _ = scan.tick() => agent.refresh_local_addresses().await,
        }
    }

    agent.logout_if_ephemeral().await;
    agent.shutdown().await;
}
