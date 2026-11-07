mod dataplane;
mod link;
mod model;
mod nft;
mod plan;
mod resolvconf;
mod route;
mod rule;
mod stun_socket;
mod sysctl;
mod wg;

use std::io;

pub use dataplane::Dataplane;
pub use model::{
    DeviceSpec, DeviceState, LinkDns, LocalAddress, PeerOp, PeerSpec, PeerState, RouteSpec,
    RuleSpec,
};
pub use nft::NodeRules;
pub use plan::plan_peers;
pub use stun_socket::{Datagram, StunSocket, is_stun};

const PROTOCOL: u8 = 82;
const TABLE: &str = "bunnyhop";

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const ENODEV: i32 = 19;
const EADDRNOTAVAIL: i32 = 99;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("failed to open a netlink socket: {0}")]
    Socket(io::Error),
    #[error("netlink request failed: {0}")]
    Netlink(io::Error),
    #[error("netlink protocol error: {0}")]
    Protocol(String),
    #[error("interface {0} does not exist")]
    MissingDevice(String),
    #[error("failed to run nft: {0}")]
    NftSpawn(io::Error),
    #[error("nft rejected the ruleset: {0}")]
    Nft(String),
    #[error("failed to run resolvconf: {0}")]
    ResolvconfSpawn(io::Error),
    #[error("resolvconf failed: {0}")]
    Resolvconf(String),
    #[error("failed to access sysctl {key}: {error}")]
    Sysctl { key: String, error: io::Error },
}

impl NetError {
    fn is_os_error(&self, code: i32) -> bool {
        matches!(self, Self::Netlink(error) if error.raw_os_error() == Some(code))
    }

    fn genetlink(error: genetlink::GenetlinkError) -> Self {
        match error {
            genetlink::GenetlinkError::NetlinkError(error) => Self::Netlink(error),
            error => Self::Protocol(error.to_string()),
        }
    }

    fn rtnetlink(error: rtnetlink::Error) -> Self {
        match error {
            rtnetlink::Error::NetlinkError(message) => Self::Netlink(message.to_io()),
            error => Self::Protocol(error.to_string()),
        }
    }
}

fn ignore_gone(result: Result<(), NetError>, gone: i32) -> Result<(), NetError> {
    match result {
        Err(error) if error.is_os_error(gone) => Ok(()),
        result => result,
    }
}
