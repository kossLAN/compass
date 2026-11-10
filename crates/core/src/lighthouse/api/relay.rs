use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use bytes::Bytes;
use compass_proto::{
    MAX_RELAY_FRAME, NodeId, RELAY_KEEPALIVE, RELAY_PROTOCOL, RELAY_TIMEOUT, RelayFrame,
};
use futures_util::{SinkExt as _, StreamExt as _};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use super::auth::authenticate;
use super::{ApiError, AppState};

const QUEUE: usize = 256;

#[derive(Default)]
pub struct Relays {
    links: Mutex<HashMap<NodeId, Link>>,
    attached: AtomicU64,
}

struct Link {
    generation: u64,
    frames: mpsc::Sender<Bytes>,
}

impl Relays {
    fn attach(&self, id: NodeId) -> (u64, mpsc::Receiver<Bytes>) {
        let generation = self.attached.fetch_add(1, Ordering::Relaxed);
        let (frames, receiver) = mpsc::channel(QUEUE);
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Link { generation, frames });
        (generation, receiver)
    }

    fn detach(&self, id: NodeId, generation: u64) {
        let mut links = self.links.lock().unwrap_or_else(PoisonError::into_inner);

        if links
            .get(&id)
            .is_some_and(|link| link.generation == generation)
        {
            links.remove(&id);
        }
    }

    fn forward(&self, to: NodeId, frame: Bytes) {
        let links = self.links.lock().unwrap_or_else(PoisonError::into_inner);

        if let Some(link) = links.get(&to) {
            let _ = link.frames.try_send(frame);
        }
    }
}

pub async fn accept(
    State(state): State<AppState>,
    mut request: Request,
) -> Result<Response, ApiError> {
    let id = authenticate(request.extensions(), &state)?;
    let wants_relay = request
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|protocol| {
            protocol
                .as_bytes()
                .eq_ignore_ascii_case(RELAY_PROTOCOL.as_bytes())
        });
    let upgrade = request
        .extensions_mut()
        .remove::<OnUpgrade>()
        .filter(|_| wants_relay)
        .ok_or_else(|| ApiError::bad_request(format!("expected an upgrade to {RELAY_PROTOCOL}")))?;

    state.tasks.spawn(serve(state.clone(), id, upgrade));
    Ok((
        StatusCode::SWITCHING_PROTOCOLS,
        [
            (header::CONNECTION, "upgrade"),
            (header::UPGRADE, RELAY_PROTOCOL),
        ],
    )
        .into_response())
}

async fn serve(state: AppState, id: NodeId, upgrade: OnUpgrade) {
    let stream = match upgrade.await {
        Ok(stream) => TokioIo::new(stream),
        Err(error) => {
            tracing::debug!(node = %id, %error, "the relay upgrade failed");
            return;
        },
    };

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_RELAY_FRAME)
        .new_codec();
    let mut connection = Framed::new(stream, codec);
    let (generation, mut outgoing) = state.relays.attach(id);
    let mut worlds = state.registry.subscribe();
    let mut keepalive = tokio::time::interval(RELAY_KEEPALIVE);
    let mut deadline = Instant::now() + RELAY_TIMEOUT;
    tracing::debug!(node = %id, "relay connected");

    let reason = loop {
        tokio::select! {
            () = state.cancel.cancelled() => break "the lighthouse is shutting down",
            () = tokio::time::sleep_until(deadline) => break "the node stopped answering",
            changed = worlds.changed() => {
                if changed.is_err() || !worlds.borrow_and_update().lists(id) {
                    break "the node is no longer listed";
                }
            },
            frame = outgoing.recv() => {
                let Some(frame) = frame else {
                    break "the node opened another relay connection";
                };

                if connection.send(frame).await.is_err() {
                    break "the connection failed";
                }
            },
            _ = keepalive.tick() => {
                if connection.send(RelayFrame::Keepalive.encode()).await.is_err() {
                    break "the connection failed";
                }
            },
            received = connection.next() => {
                let Some(Ok(frame)) = received else {
                    break "the node closed the connection";
                };

                deadline = Instant::now() + RELAY_TIMEOUT;

                match RelayFrame::decode(frame) {
                    Some(RelayFrame::Packet { peer, payload }) => {
                        if worlds.borrow().sees(id, peer) {
                            let frame = RelayFrame::Packet { peer: id, payload }.encode();
                            state.relays.forward(peer, frame);
                        }
                    },
                    Some(RelayFrame::Keepalive) => state.registry.touch(id),
                    None => break "the node sent an invalid frame",
                }
            },
        }
    };

    state.relays.detach(id, generation);
    tracing::debug!(node = %id, reason, "relay disconnected");
}
