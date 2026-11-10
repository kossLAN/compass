use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use compass_proto::{
    ApiErrorBody, CONTROL_PORT, ErrorCode, NetMapResponse, NodeId, NodeInfo, PublicKey,
    RELAY_PROTOCOL, SignalBatch, SignalEnvelope,
};
use reqwest::header::{CONNECTION, UPGRADE};
use reqwest::{Client, RequestBuilder, Response, StatusCode, Upgraded, Url};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Rejected(ApiErrorBody),
    #[error("unexpected response: {0}")]
    Unexpected(StatusCode),
    #[error(transparent)]
    Transport(reqwest::Error),
    #[error("the relay connection failed: {0}")]
    Relay(io::Error),
}

impl From<reqwest::Error> for ApiError {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url())
    }
}

impl ApiError {
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Rejected(body) => Some(body.code),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        let mut message = self.to_string();
        let mut source = std::error::Error::source(self);

        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }

        message
    }

    pub fn is_fatal(&self) -> bool {
        self.code() == Some(ErrorCode::BadRequest)
    }
}

#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    base: Url,
}

impl ApiClient {
    pub fn new(node: &PublicKey, hub: &PublicKey) -> Result<Self, reqwest::Error> {
        let local = NodeId::of(node).control_address();
        let remote = SocketAddr::new(IpAddr::V6(NodeId::of(hub).control_address()), CONTROL_PORT);
        let base = format!("http://{remote}/")
            .parse()
            .expect("a socket address is a valid URL authority");
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .local_address(IpAddr::V6(local))
            .no_proxy()
            .build()?;
        Ok(Self { http, base })
    }

    fn url(&self, path: &str) -> Url {
        self.base
            .join(path)
            .expect("API paths are valid relative URLs")
    }

    pub async fn poll(&self, since: Option<&str>) -> Result<Option<NetMapResponse>, ApiError> {
        let request = self
            .http
            .get(self.url("v1/netmap"))
            .query(&[("since", since.unwrap_or_default())])
            .timeout(POLL_TIMEOUT);
        let response = send(request).await?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }

        Ok(Some(response.json().await?))
    }

    pub async fn announce(&self, info: &NodeInfo) -> Result<(), ApiError> {
        send(self.http.post(self.url("v1/announce")).json(info))
            .await
            .map(drop)
    }

    pub async fn signal(&self, envelope: &SignalEnvelope) -> Result<(), ApiError> {
        send(self.http.post(self.url("v1/signal")).json(envelope))
            .await
            .map(drop)
    }

    pub async fn poll_signals(&self) -> Result<SignalBatch, ApiError> {
        let request = self.http.get(self.url("v1/signal")).timeout(POLL_TIMEOUT);
        Ok(send(request).await?.json().await?)
    }

    pub async fn relay(&self) -> Result<Upgraded, ApiError> {
        let request = self
            .http
            .get(self.url("v1/relay"))
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, RELAY_PROTOCOL);
        let response = send(request).await?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(ApiError::Unexpected(response.status()));
        }

        Ok(response.upgrade().await?)
    }
}

async fn send(request: RequestBuilder) -> Result<Response, ApiError> {
    let response = request.send().await?;
    let status = response.status();

    if status.is_success()
        || status == StatusCode::NOT_MODIFIED
        || status == StatusCode::SWITCHING_PROTOCOLS
    {
        return Ok(response);
    }

    let body = response.json::<ApiErrorBody>().await;
    Err(body.map_or(ApiError::Unexpected(status), ApiError::Rejected))
}
