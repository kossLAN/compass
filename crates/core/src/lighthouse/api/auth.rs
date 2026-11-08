use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use compass_proto::{NodeId, Token};

use super::{ApiError, AppState};

pub struct Authenticated(pub NodeId);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(authenticate(parts, state).map(Self))
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<Token> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(Token::new)
}

fn authenticate(parts: &Parts, state: &AppState) -> Result<NodeId, ApiError> {
    let token = bearer(&parts.headers).ok_or_else(ApiError::unauthorized)?;
    let id = state
        .registry
        .authenticate(&token)
        .ok_or_else(ApiError::unauthorized)?;
    state.registry.touch(id);
    Ok(id)
}
