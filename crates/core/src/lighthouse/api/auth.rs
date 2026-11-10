use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::Extensions;
use axum::http::request::Parts;
use compass_proto::NodeId;

use super::{ApiError, AppState};

pub struct Authenticated(pub NodeId);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(authenticate(&parts.extensions, state).map(Self))
    }
}

pub fn authenticate(extensions: &Extensions, state: &AppState) -> Result<NodeId, ApiError> {
    let id = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .and_then(|ConnectInfo(remote)| match remote.ip() {
            IpAddr::V6(address) => NodeId::from_control_address(address),
            IpAddr::V4(_) => None,
        })
        .filter(|id| state.registry.lists(*id))
        .ok_or_else(ApiError::unlisted)?;
    state.registry.touch(id);
    Ok(id)
}
