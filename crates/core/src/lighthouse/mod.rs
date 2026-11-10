mod actor;
mod api;
mod hub;
mod registry;
mod signal;
mod stun;
mod world;

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use compass_config::{ConfigError, LighthouseConfig, read_key};
use compass_net::NetError;
use compass_proto::{CONTROL_PORT, NodeId, PublicKey};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use self::actor::RegistryHandle;
use self::hub::Hub;
pub use self::registry::ReconcileReport;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    HubKey(#[from] HubKeyListed),
    #[error("setting up the hub's WireGuard interface: {0}")]
    Hub(NetError),
    #[error("listening on {address}: {error}")]
    Listen {
        address: SocketAddr,
        error: io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("{0} only changes on a restart")]
    NeedsRestart(&'static str),
    #[error(transparent)]
    HubKey(#[from] HubKeyListed),
    #[error("updating the hub's WireGuard peers: {0}")]
    Hub(NetError),
    #[error("the lighthouse is shutting down")]
    Stopped,
}

#[derive(Debug, thiserror::Error)]
#[error("lighthouse.nodes.{0} has the hub's own public key")]
pub struct HubKeyListed(String);

pub struct Lighthouse {
    config: LighthouseConfig,
    registry: RegistryHandle,
    hub: Hub,
    cancel: CancellationToken,
    tasks: TaskTracker,
    actor: JoinHandle<()>,
    server: JoinHandle<io::Result<()>>,
}

impl Lighthouse {
    pub async fn start(config: LighthouseConfig) -> Result<Self, StartError> {
        warn_unknown_tags(&config);

        let key = read_key(&config.hub.private_key_file)?;
        check_hub_key(&config, &key.public_key())?;

        let mut hub = Hub::start(&config, &key).await.map_err(StartError::Hub)?;
        let address = SocketAddr::new(IpAddr::V6(hub.address()), CONTROL_PORT);
        let listener = match TcpListener::bind(address)
            .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))
        {
            Ok(listener) => listener,
            Err(error) => {
                hub.stop().await;
                return Err(StartError::Listen { address, error });
            },
        };

        let cancel = CancellationToken::new();
        let (registry, actor) = actor::spawn(Arc::new(config.clone()), cancel.clone());
        let tasks = TaskTracker::new();

        if let Some(stun) = hub.stun() {
            tasks.spawn(stun::answer(stun, cancel.clone()));
        } else {
            tracing::warn!(
                "the hub cannot answer STUN, so nodes will not find direct paths to each other"
            );
        }

        let state = api::AppState::new(registry.clone(), cancel.clone(), tasks.clone());
        tasks.spawn(api::maintain(state.clone(), cancel.clone()));
        let server = tokio::spawn(serve(listener, api::router(state), cancel.clone()));
        tracing::info!(
            key = %hub.key(),
            port = config.hub.listen_port,
            nodes = config.nodes.len(),
            "lighthouse listening"
        );

        Ok(Self {
            config,
            registry,
            hub,
            cancel,
            tasks,
            actor,
            server,
        })
    }

    pub async fn reload(
        &mut self,
        config: LighthouseConfig,
    ) -> Result<ReconcileReport, ReloadError> {
        if let Some(setting) = self.config.startup_setting_changed(&config) {
            return Err(ReloadError::NeedsRestart(setting));
        }

        check_hub_key(&config, &self.hub.key())?;
        warn_unknown_tags(&config);

        self.hub.sync(&config).await.map_err(ReloadError::Hub)?;
        let report = self
            .registry
            .reload(config.clone())
            .await
            .ok_or(ReloadError::Stopped)?;
        self.config = config;
        Ok(report)
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.cancel.cancel();
        let served = self
            .server
            .await
            .unwrap_or_else(|error| Err(io::Error::other(error)));

        self.tasks.close();
        self.tasks.wait().await;
        let _ = self.actor.await;
        self.hub.stop().await;
        served
    }
}

fn check_hub_key(config: &LighthouseConfig, hub: &PublicKey) -> Result<(), HubKeyListed> {
    config
        .nodes
        .get(&NodeId::of(hub))
        .map_or(Ok(()), |node| Err(HubKeyListed(node.name.clone())))
}

fn warn_unknown_tags(config: &LighthouseConfig) {
    for tag in config.unknown_tags() {
        tracing::warn!(%tag, "an ACL refers to a tag that no node has");
    }
}

async fn serve(
    listener: TcpListener,
    router: axum::Router,
    cancel: CancellationToken,
) -> io::Result<()> {
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        cancel.cancelled().await;
        shutdown.graceful_shutdown(Some(SHUTDOWN_GRACE));
    });

    let mut server = axum_server::from_tcp(listener)?.handle(handle);
    configure(server.http_builder());
    server
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
}

fn configure(builder: &mut Builder<TokioExecutor>) {
    *builder = builder.clone().http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
}
