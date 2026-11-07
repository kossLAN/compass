use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;

use anyhow::Context as _;
use bunnyhop_config::{ClientConfig, DaemonConfig, LighthouseConfig, SocketConfig};
use bunnyhop_core::{Client, Lighthouse};
use bunnyhop_proto::{IpcRequest, IpcResponse};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ipc;

struct Roles {
    socket: SocketConfig,
    lighthouse: Option<Lighthouse>,
    client: Option<Client>,
}

pub async fn run(path: &Path) -> anyhow::Result<()> {
    let load = || DaemonConfig::load(path).with_context(|| format!("loading {}", path.display()));
    let config = load()?;
    let mut hangups = signal(SignalKind::hangup())?;
    let mut interrupts = signal(SignalKind::interrupt())?;
    let mut terminations = signal(SignalKind::terminate())?;

    let lighthouse = match config.lighthouse {
        Some(config) => Some(Lighthouse::start(config).await?),
        None => None,
    };

    let client = match config.client {
        Some(config) => Some(Client::start(config).await?),
        None => None,
    };

    let mut roles = Roles {
        socket: config.socket,
        lighthouse,
        client,
    };

    let listener = ipc::bind(&roles.socket)?;
    let cancel = CancellationToken::new();
    let (calls_sender, mut calls) = mpsc::channel(16);
    tokio::spawn(ipc::serve(listener, calls_sender, cancel.clone()));
    notify_systemd_ready();

    loop {
        tokio::select! {
            _ = interrupts.recv() => break,
            _ = terminations.recv() => break,
            _ = hangups.recv() => match load() {
                Ok(config) => roles.reload(config).await,
                Err(error) => tracing::error!("keeping the running config: {error:#}"),
            },
            Some((request, reply)) = calls.recv() => {
                let _ = reply.send(roles.handle(request).await);
            },
        }
    }

    tracing::info!("shutting down");
    cancel.cancel();
    let socket = roles.socket.path.clone();
    roles.shutdown().await;
    let _ = std::fs::remove_file(socket);
    Ok(())
}

impl Roles {
    async fn reload(&mut self, config: DaemonConfig) {
        if config.socket != self.socket {
            tracing::warn!("socket changes take effect when bunnyhopd restarts");
        }

        self.reload_lighthouse(config.lighthouse).await;
        self.reload_client(config.client).await;
    }

    async fn reload_lighthouse(&mut self, config: Option<LighthouseConfig>) {
        match (self.lighthouse.as_mut(), config) {
            (Some(lighthouse), Some(config)) => match lighthouse.reload(config).await {
                Ok(report) => tracing::info!(
                    removed = ?report.removed,
                    readdressed = ?report.readdressed,
                    "lighthouse config reloaded"
                ),
                Err(error) => tracing::error!(%error, "keeping the running lighthouse config"),
            },
            (None, Some(config)) => match Lighthouse::start(config).await {
                Ok(lighthouse) => self.lighthouse = Some(lighthouse),
                Err(error) => tracing::error!(%error, "failed to start the lighthouse"),
            },
            (Some(_), None) => {
                if let Some(lighthouse) = self.lighthouse.take()
                    && let Err(error) = lighthouse.shutdown().await
                {
                    tracing::warn!(%error, "the lighthouse stopped with an error");
                }
            },
            (None, None) => {},
        }
    }

    async fn reload_client(&mut self, config: Option<ClientConfig>) {
        match (self.client.as_ref(), config) {
            (Some(client), Some(config)) => {
                if let Err(error) = client.reload(config).await {
                    tracing::error!(%error, "keeping the running client config");
                }
            },
            (None, Some(config)) => match Client::start(config).await {
                Ok(client) => self.client = Some(client),
                Err(error) => tracing::error!(%error, "failed to start the client"),
            },
            (Some(_), None) => {
                if let Some(client) = self.client.take() {
                    client.shutdown().await;
                }
            },
            (None, None) => {},
        }
    }

    async fn handle(&self, request: IpcRequest) -> IpcResponse {
        let Some(client) = &self.client else {
            return IpcResponse::Failed {
                message: "this node runs no client".to_owned(),
            };
        };

        let response = match request {
            IpcRequest::Status => client
                .status()
                .await
                .map(|report| IpcResponse::Status(Box::new(report))),
            IpcRequest::DnsList => client
                .records()
                .await
                .map(|records| IpcResponse::Records { records }),
            IpcRequest::SetExitNode(choice) => client
                .set_exit_node(choice)
                .await
                .map(|report| IpcResponse::Status(Box::new(report))),
        };

        response.unwrap_or_else(|stopped| IpcResponse::Failed {
            message: stopped.to_string(),
        })
    }

    async fn shutdown(self) {
        if let Some(client) = self.client {
            client.shutdown().await;
        }

        if let Some(lighthouse) = self.lighthouse
            && let Err(error) = lighthouse.shutdown().await
        {
            tracing::warn!(%error, "the lighthouse stopped with an error");
        }
    }
}

fn notify_systemd_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };

    let sent = UnixDatagram::unbound().and_then(|socket| {
        let address = match path.as_bytes().strip_prefix(b"@") {
            Some(name) => SocketAddr::from_abstract_name(name)?,
            None => SocketAddr::from_pathname(&path)?,
        };

        socket.send_to_addr(b"READY=1", &address)
    });

    if let Err(error) = sent {
        tracing::warn!(%error, "failed to notify systemd");
    }
}
