use std::net::SocketAddr;
use std::time::Duration;

use compass_net::Stun;
use tokio_util::sync::CancellationToken;

use crate::binding;

const READ_RETRY: Duration = Duration::from_millis(100);

pub async fn answer(stun: Stun, cancel: CancellationToken) {
    loop {
        let request = tokio::select! {
            () = cancel.cancelled() => break,
            received = stun.recv() => match received {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(%error, "failed to read STUN");
                    tokio::time::sleep(READ_RETRY).await;
                    continue;
                },
            },
        };

        let remote = request.remote;
        let mapped = SocketAddr::new(remote.ip().to_canonical(), remote.port());

        if let Some(response) = binding::response(&request.payload, mapped)
            && let Err(error) = stun.send(remote, &response).await
        {
            tracing::debug!(%remote, %error, "failed to answer STUN");
        }
    }
}
