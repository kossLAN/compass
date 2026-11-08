use std::io;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::time::Duration;

use anyhow::{Context as _, bail};
use compass_config::SocketConfig;
use compass_proto::{IpcRequest, IpcResponse, MAX_IPC_LINE};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LinesCodec};
use tokio_util::sync::CancellationToken;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

pub type IpcCall = (IpcRequest, oneshot::Sender<IpcResponse>);

pub fn bind(config: &SocketConfig) -> anyhow::Result<UnixListener> {
    let path = &config.path;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_socket() => {
            bail!("{} exists and is not a socket", path.display());
        },
        Ok(_) if std::os::unix::net::UnixStream::connect(path).is_ok() => {
            bail!("another daemon is listening on {}", path.display());
        },
        Ok(_) => std::fs::remove_file(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }

    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;

    if let Some(group) = &config.group {
        std::os::unix::fs::chown(path, None, Some(group_id(group)?))?;
    }

    Ok(listener)
}

fn group_id(group: &str) -> anyhow::Result<u32> {
    if let Ok(gid) = group.parse() {
        return Ok(gid);
    }

    let groups = std::fs::read_to_string("/etc/group")?;
    groups
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let gid = fields.nth(1)?.parse().ok()?;
            Some((name, gid))
        })
        .find_map(|(name, gid)| (name == group).then_some(gid))
        .with_context(|| format!("unknown group \"{group}\""))
}

pub async fn serve(
    listener: UnixListener,
    calls: mpsc::Sender<IpcCall>,
    cancel: CancellationToken,
) {
    loop {
        let stream = tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    tracing::warn!(%error, "failed to accept a control connection");
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                },
            },
        };

        let calls = calls.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(CONNECTION_TIMEOUT, handle(stream, calls)).await {
                Ok(Ok(())) => {},
                Ok(Err(error)) => tracing::debug!(%error, "control connection failed"),
                Err(_) => tracing::debug!("control connection timed out"),
            }
        });
    }
}

async fn handle(stream: UnixStream, calls: mpsc::Sender<IpcCall>) -> anyhow::Result<()> {
    let mut lines = Framed::new(stream, LinesCodec::new_with_max_length(MAX_IPC_LINE));

    let Some(line) = lines.next().await.transpose()? else {
        return Ok(());
    };

    let response = match serde_json::from_str::<IpcRequest>(&line) {
        Ok(request) => {
            let (reply, response) = oneshot::channel();
            calls.send((request, reply)).await?;
            response.await?
        },
        Err(error) => IpcResponse::Failed {
            message: format!("invalid request: {error}"),
        },
    };

    lines.send(serde_json::to_string(&response)?).await?;
    Ok(())
}
