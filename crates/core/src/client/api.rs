use std::io;
use std::path::PathBuf;
use std::time::Duration;

use compass_proto::{
    ApiErrorBody, ErrorCode, HubResponse, NetMapResponse, NodeInfo, RELAY_PROTOCOL,
    RegisterRequest, RegisterResponse, SignalBatch, SignalEnvelope, Token,
};
use reqwest::header::{CONNECTION, UPGRADE};
use reqwest::{Certificate, Client, RequestBuilder, Response, StatusCode, Upgraded};
use url::Url;

use crate::client::settings::CaCertificate;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Rejected(ApiErrorBody),
    #[error("unexpected response: {0}")]
    Unexpected(StatusCode),
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("the hub's public key cannot be used to prove this node's keys")]
    UnusableHubKey,
    #[error("the relay connection failed: {0}")]
    Relay(io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("reading {}: {error}", path.display())]
    ReadCa { path: PathBuf, error: io::Error },
    #[error("{} is not a PEM certificate: {error}", path.display())]
    ParseCa {
        path: PathBuf,
        error: reqwest::Error,
    },
    #[error("the CA is not a PEM certificate: {0}")]
    ParsePem(reqwest::Error),
    #[error("setting up HTTPS: {0}")]
    Http(reqwest::Error),
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
        matches!(
            self.code(),
            Some(
                ErrorCode::InvalidAuthKey
                    | ErrorCode::Revoked
                    | ErrorCode::BadRequest
                    | ErrorCode::UnsupportedProtocol
            )
        )
    }
}

#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    base: Url,
}

impl ApiClient {
    pub fn new(
        base: Url,
        ca: Option<&CaCertificate>,
        roots: Option<&[Certificate]>,
    ) -> Result<Self, SetupError> {
        let mut builder = Client::builder().timeout(REQUEST_TIMEOUT);
        let ca = ca.map(certificate).transpose()?;

        if let Some(roots) = roots {
            builder = builder.tls_certs_only(roots.iter().cloned().chain(ca));
        } else if let Some(ca) = ca {
            builder = builder.tls_certs_merge([ca]);
        }

        Ok(Self {
            http: builder.build().map_err(SetupError::Http)?,
            base,
        })
    }

    fn url(&self, path: &str) -> Url {
        self.base
            .join(path)
            .expect("API paths are valid relative URLs")
    }

    pub async fn hub(&self) -> Result<HubResponse, ApiError> {
        let response = send(self.http.get(self.url("v1/hub"))).await?;
        Ok(response.json().await?)
    }

    pub async fn register(&self, request: &RegisterRequest) -> Result<RegisterResponse, ApiError> {
        let response = send(self.http.post(self.url("v1/register")).json(request)).await?;
        Ok(response.json().await?)
    }

    pub async fn poll(
        &self,
        token: &Token,
        since: Option<&str>,
    ) -> Result<Option<NetMapResponse>, ApiError> {
        let request = self
            .http
            .get(self.url("v1/netmap"))
            .bearer_auth(token.expose())
            .query(&[("since", since.unwrap_or_default())])
            .timeout(POLL_TIMEOUT);
        let response = send(request).await?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }

        Ok(Some(response.json().await?))
    }

    pub async fn update(&self, token: &Token, info: &NodeInfo) -> Result<(), ApiError> {
        send(
            self.http
                .post(self.url("v1/update"))
                .bearer_auth(token.expose())
                .json(info),
        )
        .await
        .map(drop)
    }

    pub async fn signal(&self, token: &Token, envelope: &SignalEnvelope) -> Result<(), ApiError> {
        send(
            self.http
                .post(self.url("v1/signal"))
                .bearer_auth(token.expose())
                .json(envelope),
        )
        .await
        .map(drop)
    }

    pub async fn poll_signals(&self, token: &Token) -> Result<SignalBatch, ApiError> {
        let request = self
            .http
            .get(self.url("v1/signal"))
            .bearer_auth(token.expose())
            .timeout(POLL_TIMEOUT);
        Ok(send(request).await?.json().await?)
    }

    pub async fn relay(&self, token: &Token) -> Result<Upgraded, ApiError> {
        let request = self
            .http
            .get(self.url("v1/relay"))
            .bearer_auth(token.expose())
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, RELAY_PROTOCOL);
        let response = send(request).await?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(ApiError::Unexpected(response.status()));
        }

        Ok(response.upgrade().await?)
    }

    pub async fn logout(&self, token: &Token) -> Result<(), ApiError> {
        send(
            self.http
                .post(self.url("v1/logout"))
                .bearer_auth(token.expose()),
        )
        .await
        .map(drop)
    }
}

fn certificate(ca: &CaCertificate) -> Result<Certificate, SetupError> {
    match ca {
        CaCertificate::File(path) => {
            let pem = std::fs::read(path).map_err(|error| SetupError::ReadCa {
                path: path.clone(),
                error,
            })?;
            Certificate::from_pem(&pem).map_err(|error| SetupError::ParseCa {
                path: path.clone(),
                error,
            })
        },
        CaCertificate::Pem(pem) => {
            Certificate::from_pem(pem.as_bytes()).map_err(SetupError::ParsePem)
        },
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
