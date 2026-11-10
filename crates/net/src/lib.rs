#[cfg(feature = "linux")]
mod linux;
mod model;
mod plan;
mod protect;
mod stun;
mod wireguard;

use std::io;

#[cfg(feature = "linux")]
pub use linux::{Dataplane, Firewall, NodeRules, Wireguard};
pub use model::{
    DeviceSpec, DeviceState, LinkDns, LocalAddress, MeshRules, PeerOp, PeerSpec, PeerState,
    RouteSpec, RuleSpec,
};
pub use plan::plan_peers;
pub use protect::{Fwmark, Protect};
pub use stun::{Datagram, is_stun};
pub use tun_rs::AsyncDevice;
pub use wireguard::{Intercept, Stun, Tun, UserspaceDevice};

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
    #[error("failed to run {program}: {error}")]
    FirewallSpawn {
        program: &'static str,
        error: io::Error,
    },
    #[error("{program} failed: {message}")]
    Firewall {
        program: &'static str,
        message: String,
    },
    #[error("no usable firewall: {nft}, and {iptables}")]
    NoFirewall { nft: Box<Self>, iptables: Box<Self> },
    #[error("failed to run resolvconf: {0}")]
    ResolvconfSpawn(io::Error),
    #[error("resolvconf failed: {0}")]
    Resolvconf(String),
    #[error("failed to access sysctl {key}: {error}")]
    Sysctl { key: String, error: io::Error },
    #[error("failed to create the TUN device: {0}")]
    Tun(io::Error),
    #[error("failed to bind the WireGuard socket: {0}")]
    Bind(io::Error),
}
