use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use crate::{DnsName, DnsRecord, NodeId};

pub const CONTROL_PREFIX: Ipv6Net = Ipv6Net::new_assert(
    Ipv6Addr::new(0xfd63, 0x6f6d, 0x7061, 0x7373, 0, 0, 0, 0),
    64,
);

pub const CONTROL_PORT: u16 = 51819;

pub const LONG_POLL: Duration = Duration::from_secs(50);

pub const MAX_RECORDS: usize = 64;

pub const MAX_AVOID: usize = 64;

impl NodeId {
    pub fn control_address(self) -> Ipv6Addr {
        Ipv6Addr::from_bits(CONTROL_PREFIX.network().to_bits() | u128::from(self.0))
    }

    pub fn from_control_address(address: Ipv6Addr) -> Option<Self> {
        CONTROL_PREFIX
            .contains(&address)
            .then(|| Self(address.to_bits() as u64))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub hostname: DnsName,
    pub records: Vec<DnsRecord>,
    pub advertise_exit_node: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub avoid: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Unannounced,
    BadRequest,
    AddressesExhausted,
    RateLimited,
    UnknownPeer,
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
