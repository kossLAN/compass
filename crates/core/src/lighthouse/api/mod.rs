mod auth;
mod error;
mod relay;

use std::hash::Hash;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use compass_proto::{ErrorCode, LONG_POLL, NodeId, NodeInfo, SignalBatch, SignalEnvelope};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use self::auth::Authenticated;
pub use self::error::ApiError;
use self::relay::Relays;
use crate::lighthouse::actor::RegistryHandle;
use crate::lighthouse::signal::Mailboxes;

const MAX_BODY: usize = 64 * 1024;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
const ANNOUNCEMENTS_PER_MINUTE: NonZeroU32 = NonZeroU32::new(30).unwrap();
const ANNOUNCEMENT_BURST: NonZeroU32 = NonZeroU32::new(10).unwrap();
const SIGNALS_PER_MINUTE: NonZeroU32 = NonZeroU32::new(600).unwrap();
const SIGNAL_BURST: NonZeroU32 = NonZeroU32::new(200).unwrap();

#[derive(Clone)]
pub struct AppState {
    registry: RegistryHandle,
    announcements: Arc<DefaultKeyedRateLimiter<NodeId>>,
    signals: Arc<DefaultKeyedRateLimiter<NodeId>>,
    mailboxes: Arc<Mailboxes>,
    relays: Arc<Relays>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl AppState {
    pub fn new(registry: RegistryHandle, cancel: CancellationToken, tasks: TaskTracker) -> Self {
        Self {
            registry,
            announcements: limiter(ANNOUNCEMENTS_PER_MINUTE, ANNOUNCEMENT_BURST),
            signals: limiter(SIGNALS_PER_MINUTE, SIGNAL_BURST),
            mailboxes: Arc::default(),
            relays: Arc::default(),
            cancel,
            tasks,
        }
    }
}

fn limiter<K>(per_minute: NonZeroU32, burst: NonZeroU32) -> Arc<DefaultKeyedRateLimiter<K>>
where
    K: Hash + Eq + Clone,
{
    Arc::new(RateLimiter::keyed(
        Quota::per_minute(per_minute).allow_burst(burst),
    ))
}

pub async fn maintain(state: AppState, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(MAINTENANCE_INTERVAL);

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = interval.tick() => {},
        }

        state.announcements.retain_recent();
        state.signals.retain_recent();
        state.mailboxes.sweep();
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/netmap", get(netmap))
        .route("/v1/announce", post(announce))
        .route("/v1/signal", get(receive_signals).post(send_signal))
        .route("/v1/relay", get(relay::accept))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

#[derive(Deserialize)]
struct NetMapQuery {
    since: Option<String>,
}

async fn netmap(
    State(state): State<AppState>,
    Authenticated(id): Authenticated,
    Query(query): Query<NetMapQuery>,
) -> Result<Response, ApiError> {
    let mut worlds = state.registry.subscribe();
    let deadline = tokio::time::Instant::now() + LONG_POLL;

    loop {
        let world = worlds.borrow_and_update().clone();
        let netmap = world.netmap(id).ok_or_else(ApiError::unannounced)?;

        if query.since.as_deref() != Some(netmap.hash.as_str()) {
            return Ok(Json(netmap).into_response());
        }

        tokio::select! {
            changed = worlds.changed() => {
                if changed.is_err() {
                    return Ok(StatusCode::NOT_MODIFIED.into_response());
                }
            },
            () = tokio::time::sleep_until(deadline) => {
                return Ok(StatusCode::NOT_MODIFIED.into_response());
            },
        }
    }
}

async fn announce(
    State(state): State<AppState>,
    Authenticated(id): Authenticated,
    Json(info): Json<NodeInfo>,
) -> Result<StatusCode, ApiError> {
    if state.announcements.check_key(&id).is_err() {
        return Err(ApiError::rate_limited("too many announcements"));
    }

    state.registry.announce(id, info).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn send_signal(
    State(state): State<AppState>,
    Authenticated(from): Authenticated,
    Json(envelope): Json<SignalEnvelope>,
) -> Result<StatusCode, ApiError> {
    if state.signals.check_key(&from).is_err() {
        return Err(ApiError::rate_limited("too many signals"));
    }

    envelope
        .message
        .session()
        .check()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;

    if !state.registry.sees(from, envelope.to) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::UnknownPeer,
            format!("node {} is not a peer", envelope.to),
        ));
    }

    state.mailboxes.push(envelope.to, from, envelope.message);
    Ok(StatusCode::NO_CONTENT)
}

async fn receive_signals(
    State(state): State<AppState>,
    Authenticated(id): Authenticated,
) -> Json<SignalBatch> {
    let mut pushed = state.mailboxes.subscribe(id);
    let deadline = tokio::time::Instant::now() + LONG_POLL;

    loop {
        let messages = state.mailboxes.take(id);

        if !messages.is_empty() {
            return Json(SignalBatch { messages });
        }

        tokio::select! {
            changed = pushed.changed() => {
                if changed.is_err() {
                    break;
                }
            },
            () = tokio::time::sleep_until(deadline) => break,
        }
    }

    Json(SignalBatch::default())
}
