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
mod settings;

use std::time::Duration;

use compass_config::ConfigError;
use compass_proto::{ExitNodeChoice, RecordEntry, StatusReport};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use self::agent::Agent;
#[cfg(feature = "linux")]
pub use self::dataplane::LinuxPlatform;
pub use self::dataplane::{HostedPlatform, Platform, TunProvider, TunShape, Underlying};
use self::ice::IceEvent;
use self::session::SessionEvent;
pub use self::settings::{ClientSettings, LighthouseSettings};

const TICK: Duration = Duration::from_secs(1);
const ADDRESS_SCAN: Duration = Duration::from_secs(10);

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

enum Command<D> {
    Status(oneshot::Sender<StatusReport>),
    Records(oneshot::Sender<Vec<RecordEntry>>),
    SetExitNode(ExitNodeChoice, oneshot::Sender<StatusReport>),
    Reload(
        Box<(ClientSettings, D)>,
        oneshot::Sender<Result<(), ConfigError>>,
    ),
}

pub struct Client<P: Platform> {
    commands: mpsc::Sender<Command<P::Device>>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl<P: Platform> Client<P> {
    pub async fn start(
        config: ClientSettings,
        device: P::Device,
        platform: P,
    ) -> Result<Self, ConfigError> {
        let (events_sender, events) = mpsc::channel(64);
        let (ice_sender, ice_events) = mpsc::channel(256);
        let mut agent = Agent::new(config, device, platform, events_sender, ice_sender)?;
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

    pub async fn reload(
        &self,
        config: ClientSettings,
        device: P::Device,
    ) -> Result<(), ReloadError> {
        Ok(self
            .call(|reply| Command::Reload(Box::new((config, device)), reply))
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
        command: impl FnOnce(oneshot::Sender<T>) -> Command<P::Device>,
    ) -> Result<T, Stopped> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| Stopped)?;
        response.await.map_err(|_| Stopped)
    }
}

async fn run<P>(
    mut agent: Agent<P>,
    mut commands: mpsc::Receiver<Command<P::Device>>,
    mut events: mpsc::Receiver<(u64, SessionEvent)>,
    mut ice_events: mpsc::Receiver<(u64, IceEvent)>,
    cancel: CancellationToken,
) where
    P: Platform,
{
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
                Command::Reload(reload, reply) => {
                    let (config, device) = *reload;
                    let _ = reply.send(agent.reload(config, device).await);
                },
            },
            Some((id, event)) = events.recv() => agent.on_event(id, event).await,
            Some((generation, event)) = ice_events.recv() => agent.on_ice_event(generation, event).await,
            _ = tick.tick() => agent.tick().await,
            _ = scan.tick() => agent.refresh_local_addresses().await,
        }
    }

    agent.shutdown().await;
}
