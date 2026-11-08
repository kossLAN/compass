mod actor;
mod api;
mod registry;
mod signal;
mod stun;
mod world;

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use compass_config::{ConfigError, LighthouseConfig, read_key};
use compass_proto::PrivateKey;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use self::actor::RegistryHandle;
pub use self::registry::ReconcileReport;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("listening for STUN on port {port}: {error}")]
    Stun { port: u16, error: io::Error },
    #[error("loading the TLS certificate: {0}")]
    Tls(io::Error),
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
    #[error("reloading the TLS certificate: {0}")]
    Tls(io::Error),
    #[error("the lighthouse is shutting down")]
    Stopped,
}

pub struct Lighthouse {
    config: LighthouseConfig,
    registry: RegistryHandle,
    tls: Option<RustlsConfig>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    actor: JoinHandle<()>,
    server: JoinHandle<io::Result<()>>,
}

impl Lighthouse {
    pub async fn start(config: LighthouseConfig) -> Result<Self, StartError> {
        warn_unknown_tags(&config);

        let hub_key = match &config.hub.private_key_file {
            Some(path) => read_key(path)?,
            None => PrivateKey::generate(),
        };

        let tls = match &config.api.tls {
            Some(files) => {
                let tls = RustlsConfig::from_pem_file(&files.cert_file, &files.key_file)
                    .await
                    .map_err(StartError::Tls)?;
                offer_http1_only(&tls);
                Some(tls)
            },
            None => None,
        };

        let address = config.api.listen;
        let listener = TcpListener::bind(address)
            .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))
            .map_err(|error| StartError::Listen { address, error })?;

        let port = config.hub.listen_port;
        let stun = stun::bind(port).map_err(|error| StartError::Stun { port, error })?;

        let cancel = CancellationToken::new();
        let (registry, actor) = actor::spawn(
            Arc::new(config.clone()),
            hub_key.public_key(),
            cancel.clone(),
        );

        let tasks = TaskTracker::new();
        tasks.spawn(stun::answer(stun, cancel.clone()));

        let state = api::AppState::new(registry.clone(), hub_key, cancel.clone(), tasks.clone());
        tasks.spawn(api::maintain(state.clone(), cancel.clone()));
        let server = tokio::spawn(serve(
            listener,
            tls.clone(),
            api::router(state),
            cancel.clone(),
        ));
        tracing::info!(listen = %address, "lighthouse listening");

        Ok(Self {
            config,
            registry,
            tls,
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

        warn_unknown_tags(&config);

        if let (Some(tls), Some(files)) = (&self.tls, &config.api.tls) {
            tls.reload_from_pem_file(&files.cert_file, &files.key_file)
                .await
                .map_err(ReloadError::Tls)?;
            offer_http1_only(tls);
        }

        let report = self
            .registry
            .reload(config.clone())
            .await
            .ok_or(ReloadError::Stopped)?;
        self.config = config;
        Ok(report)
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.cancel.cancel();
        let served = self
            .server
            .await
            .unwrap_or_else(|error| Err(io::Error::other(error)));

        self.tasks.close();
        self.tasks.wait().await;
        let _ = self.actor.await;
        served
    }
}

fn warn_unknown_tags(config: &LighthouseConfig) {
    for tag in config.unknown_tags() {
        tracing::warn!(%tag, "an ACL refers to a tag that no key grants");
    }
}

async fn serve(
    listener: TcpListener,
    tls: Option<RustlsConfig>,
    router: axum::Router,
    cancel: CancellationToken,
) -> io::Result<()> {
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        cancel.cancelled().await;
        shutdown.graceful_shutdown(Some(SHUTDOWN_GRACE));
    });

    let service = router.into_make_service();

    if let Some(tls) = tls {
        let mut server = axum_server::from_tcp_rustls(listener, tls)?.handle(handle);
        configure(server.http_builder());
        server.serve(service).await
    } else {
        let mut server = axum_server::from_tcp(listener)?.handle(handle);
        configure(server.http_builder());
        server.serve(service).await
    }
}

fn configure(builder: &mut Builder<TokioExecutor>) {
    *builder = builder.clone().http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
}

fn offer_http1_only(tls: &RustlsConfig) {
    let mut config = (*tls.get_inner()).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.reload_from_config(Arc::new(config));
}
