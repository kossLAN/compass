use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{AuthKey, DnsName, DnsRecord, KeyProof, NetMapResponse, NodeId, PublicKey, Token};

pub const PROTOCOL_VERSION: u16 = 1;

pub const LONG_POLL: Duration = Duration::from_secs(50);

pub const MAX_RECORDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub hostname: DnsName,
    pub records: Vec<DnsRecord>,
    pub advertise_exit_node: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub protocol: u16,
    pub auth_key: AuthKey,
    pub key: PublicKey,
    pub proof: KeyProof,
    pub info: NodeInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubResponse {
    pub key: PublicKey,
    pub time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: NodeId,
    pub token: Token,
    pub netmap: NetMapResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidAuthKey,
    Revoked,
    Unauthorized,
    BadRequest,
    AddressesExhausted,
    RateLimited,
    UnknownPeer,
    UnsupportedProtocol,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

impl fmt::Display for ApiErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
