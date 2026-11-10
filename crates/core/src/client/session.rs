use std::sync::Arc;
use std::time::Duration;

use compass_proto::{ErrorCode, NetMapResponse, NodeId, NodeInfo, SignalEnvelope, SignalMessage};
use tokio::sync::{mpsc, watch};

use crate::client::api::{ApiClient, ApiError};
use crate::client::relay::Relay;

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum SessionEvent {
    NetMap(Box<NetMapResponse>),
    Signal(NodeId, SignalMessage),
    Error(String),
    Rejected(String),
}

pub struct Session {
    pub client: ApiClient,
    pub relay: Arc<Relay>,
    pub lighthouse: usize,
}

struct Emitter {
    id: u64,
    events: mpsc::Sender<(u64, SessionEvent)>,
}

impl Emitter {
    async fn send(&self, event: SessionEvent) {
        let _ = self.events.send((self.id, event)).await;
    }
}

impl Session {
    pub async fn run(
        self,
        id: u64,
        mut info: watch::Receiver<NodeInfo>,
        mut signals: mpsc::Receiver<SignalEnvelope>,
        events: mpsc::Sender<(u64, SessionEvent)>,
    ) {
        let emit = Emitter { id, events };
        let mut backoff = Backoff::default();

        loop {
            let current = info.borrow_and_update().clone();

            let error = match self.client.announce(&current).await {
                Ok(()) => {
                    let error = self
                        .serve(&mut info, &mut signals, &emit, &mut backoff)
                        .await;

                    if error.code() == Some(ErrorCode::Unannounced) {
                        continue;
                    }

                    error
                },
                Err(error) if error.is_fatal() => {
                    emit.send(SessionEvent::Rejected(error.describe())).await;
                    return;
                },
                Err(error) => error,
            };

            emit.send(SessionEvent::Error(error.describe())).await;
            tokio::time::sleep(backoff.next()).await;
        }
    }

    async fn serve(
        &self,
        info: &mut watch::Receiver<NodeInfo>,
        signals: &mut mpsc::Receiver<SignalEnvelope>,
        emit: &Emitter,
        backoff: &mut Backoff,
    ) -> ApiError {
        tokio::select! {
            error = follow(&self.client, emit, backoff) => error,
            error = announce_changes(&self.client, info, emit) => error,
            error = follow_signals(&self.client, emit) => error,
            error = push_signals(&self.client, signals) => error,
            error = relay(&self.client, &self.relay, self.lighthouse) => error,
        }
    }
}

async fn follow(client: &ApiClient, emit: &Emitter, backoff: &mut Backoff) -> ApiError {
    let mut since: Option<String> = None;

    loop {
        match client.poll(since.as_deref()).await {
            Ok(Some(netmap)) => {
                backoff.reset();
                since = Some(netmap.hash.clone());
                emit.send(SessionEvent::NetMap(Box::new(netmap))).await;
            },
            Ok(None) => backoff.reset(),
            Err(error) => return error,
        }
    }
}

async fn announce_changes(
    client: &ApiClient,
    info: &mut watch::Receiver<NodeInfo>,
    emit: &Emitter,
) -> ApiError {
    loop {
        if info.changed().await.is_err() {
            return std::future::pending().await;
        }

        let current = info.borrow_and_update().clone();

        match client.announce(&current).await {
            Ok(()) => {},
            Err(error) if error.code() == Some(ErrorCode::BadRequest) => {
                emit.send(SessionEvent::Error(error.describe())).await;
            },
            Err(error) => return error,
        }
    }
}

async fn follow_signals(client: &ApiClient, emit: &Emitter) -> ApiError {
    loop {
        match client.poll_signals().await {
            Ok(batch) => {
                for delivery in batch.messages {
                    emit.send(SessionEvent::Signal(delivery.from, delivery.message))
                        .await;
                }
            },
            Err(error) => return error,
        }
    }
}

async fn push_signals(
    client: &ApiClient,
    signals: &mut mpsc::Receiver<SignalEnvelope>,
) -> ApiError {
    loop {
        let Some(envelope) = signals.recv().await else {
            return std::future::pending().await;
        };

        match client.signal(&envelope).await {
            Ok(()) => {},
            Err(error)
                if matches!(
                    error.code(),
                    Some(ErrorCode::BadRequest | ErrorCode::RateLimited | ErrorCode::UnknownPeer)
                ) =>
            {
                tracing::debug!(to = %envelope.to, %error, "the lighthouse refused an ICE signal");
            },
            Err(error) => return error,
        }
    }
}

async fn relay(client: &ApiClient, relay: &Relay, lighthouse: usize) -> ApiError {
    match client.relay().await {
        Ok(stream) => ApiError::Relay(relay.run(lighthouse, stream).await),
        Err(error) => error,
    }
}

#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { next: MIN_BACKOFF }
    }
}

impl Backoff {
    fn next(&mut self) -> Duration {
        let current = self.next;
        self.next = (self.next * 2).min(MAX_BACKOFF);
        let jitter = getrandom::u64().unwrap_or_default() % (current.as_millis() as u64 / 2 + 1);
        current + Duration::from_millis(jitter)
    }

    fn reset(&mut self) {
        self.next = MIN_BACKOFF;
    }
}
