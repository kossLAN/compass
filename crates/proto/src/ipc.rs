use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{DnsName, DnsRecord, NodeId, PublicKey, RecordState};

pub const MAX_IPC_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub enum IpcRequest {
    Status,
    DnsList,
    SetExitNode(ExitNodeChoice),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "choice", content = "peer")]
pub enum ExitNodeChoice {
    Config,
    Off,
    Peer(DnsName),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum IpcResponse {
    Status(Box<StatusReport>),
    Records { records: Vec<RecordEntry> },
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "phase", content = "detail")]
pub enum Phase {
    Connecting,
    Running,
    Degraded(String),
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub phase: Phase,
    pub lighthouses: Vec<LighthouseStatus>,
    pub key: PublicKey,
    pub observed_endpoints: Vec<SocketAddr>,
    pub nodes: Vec<NodeStatus>,
    pub exit_node: Option<ExitNodeStatus>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseStatus {
    pub endpoint: String,
    pub mesh: Option<DnsName>,
    pub state: LighthouseState,
    pub relay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum LighthouseState {
    Connecting,
    Connected,
    Unreachable(String),
    Rejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitNodeStatus {
    pub peer: DnsName,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: NodeId,
    pub hostname: DnsName,
    pub fqdn: String,
    pub addresses: Vec<IpAddr>,
    pub taken: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "via")]
pub enum PathKind {
    Direct(SocketAddr),
    Relay(String),
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub hostname: DnsName,
    pub fqdn: String,
    pub addresses: Vec<IpAddr>,
    pub taken: Vec<IpAddr>,
    pub online: bool,
    pub exit_node: bool,
    pub path: PathKind,
    pub last_handshake_secs: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEntry {
    pub record: DnsRecord,
    pub mesh: Option<DnsName>,
    #[serde(default)]
    pub lighthouses: Vec<String>,
    pub state: Option<RecordState>,
}
