use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use compass_proto::{PacketRule, PrivateKey, PublicKey};
use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    pub name: String,
    pub private_key: PrivateKey,
    pub listen_port: u16,
    pub fwmark: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceState {
    pub public_key: Option<PublicKey>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: BTreeMap<PublicKey, PeerState>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerState {
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: u16,
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpec {
    pub key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerOp {
    Upsert(PeerSpec),
    Remove(PublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteSpec {
    pub destination: IpNet,
    pub device: String,
    pub source: Option<IpAddr>,
    pub table: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleSpec {
    pub priority: u32,
    pub ipv6: bool,
    pub table: u32,
    pub destination: Option<IpNet>,
    pub unless_fwmark: Option<u32>,
    pub suppress_prefix_length: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDns {
    pub servers: Vec<IpAddr>,
    pub search: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    pub interface: String,
    pub address: IpNet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRules {
    pub prefixes: Vec<IpNet>,
    pub addresses: Vec<IpAddr>,
    pub inbound: Vec<PacketRule>,
    pub exit_clients: Vec<IpNet>,
}
