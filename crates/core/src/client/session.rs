use std::sync::Arc;
use std::time::Duration;

use bunnyhop_proto::{
    AuthKey, ErrorCode, KeyProof, NetMapResponse, NodeId, NodeInfo, PROTOCOL_VERSION, PrivateKey,
    RegisterRequest, RegisterResponse, SignalEnvelope, SignalMessage, Token,
};
use tokio::sync::{mpsc, watch};

use crate::client::api::{ApiClient, ApiError};
use crate::client::relay::Relay;

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum SessionEvent {
    Registered(Token),
    NetMap(Box<NetMapResponse>),
    Signal(NodeId, SignalMessage),
    Error(String),
    Rejected(String),
}

pub struct Session {
    pub client: ApiClient,
    pub auth_key: AuthKey,
    pub key: PrivateKey,
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
        let mut token = None;

        loop {
            let error = self
                .connect(&mut token, &mut info, &mut signals, &emit, &mut backoff)
                .await;

            let registered = token.is_some();

            if registered && error.code() == Some(ErrorCode::Unauthorized) {
                token = None;
                continue;
            }

            if !registered && error.is_fatal() {
                emit.send(SessionEvent::Rejected(error.describe())).await;
                return;
            }

            emit.send(SessionEvent::Error(error.describe())).await;
            tokio::time::sleep(backoff.next()).await;
        }
    }

    async fn connect(
        &self,
        token: &mut Option<Token>,
        info: &mut watch::Receiver<NodeInfo>,
        signals: &mut mpsc::Receiver<SignalEnvelope>,
        emit: &Emitter,
        backoff: &mut Backoff,
    ) -> ApiError {
        let token = match token {
            Some(token) => token,
            None => match self.register(info).await {
                Ok(response) => {
                    emit.send(SessionEvent::Registered(response.token.clone()))
                        .await;
                    emit.send(SessionEvent::NetMap(Box::new(response.netmap)))
                        .await;
                    token.insert(response.token)
                },
                Err(error) => return error,
            },
        };

        tokio::select! {
            error = follow(&self.client, token, emit, backoff) => error,
            error = push_updates(&self.client, token, info, emit) => error,
            error = follow_signals(&self.client, token, emit) => error,
            error = push_signals(&self.client, token, signals) => error,
            error = relay(&self.client, token, &self.relay, self.lighthouse) => error,
        }
    }

    async fn register(
        &self,
        info: &mut watch::Receiver<NodeInfo>,
    ) -> Result<RegisterResponse, ApiError> {
        let hub = self.client.hub().await?;
        let proof = KeyProof::new(&hub.key, &self.key, hub.time).ok_or(ApiError::UnusableHubKey)?;
        let request = RegisterRequest {
            protocol: PROTOCOL_VERSION,
            auth_key: self.auth_key.clone(),
            key: self.key.public_key(),
            proof,
            info: info.borrow_and_update().clone(),
        };
        let response = self.client.register(&request).await?;
        tracing::info!(node = %response.node_id, "registered with the lighthouse");
        Ok(response)
    }
}

async fn follow(
    client: &ApiClient,
    token: &Token,
    emit: &Emitter,
    backoff: &mut Backoff,
) -> ApiError {
    let mut since: Option<String> = None;

    loop {
        match client.poll(token, since.as_deref()).await {
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

async fn push_updates(
    client: &ApiClient,
    token: &Token,
    info: &mut watch::Receiver<NodeInfo>,
    emit: &Emitter,
) -> ApiError {
    loop {
        let current = info.borrow_and_update().clone();

        match client.update(token, &current).await {
            Ok(()) => {},
            Err(error) if error.code() == Some(ErrorCode::BadRequest) => {
                emit.send(SessionEvent::Error(error.describe())).await;
            },
            Err(error) => return error,
        }

        if info.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

async fn follow_signals(client: &ApiClient, token: &Token, emit: &Emitter) -> ApiError {
    loop {
        match client.poll_signals(token).await {
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
    token: &Token,
    signals: &mut mpsc::Receiver<SignalEnvelope>,
) -> ApiError {
    loop {
        let Some(envelope) = signals.recv().await else {
            return std::future::pending().await;
        };

        match client.signal(token, &envelope).await {
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

async fn relay(client: &ApiClient, token: &Token, relay: &Relay, lighthouse: usize) -> ApiError {
    match client.relay(token).await {
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
