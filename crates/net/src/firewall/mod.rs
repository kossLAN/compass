mod iptables;
mod nft;

use std::fmt;
use std::net::IpAddr;
use std::process::Stdio;

use bunnyhop_proto::PacketRule;
use ipnet::IpNet;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::NetError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRules {
    pub interface: String,
    pub meshes: Vec<MeshRules>,
    pub local_dns: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRules {
    pub prefixes: Vec<IpNet>,
    pub addresses: Vec<IpAddr>,
    pub inbound: Vec<PacketRule>,
    pub exit_clients: Vec<IpNet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firewall {
    Nftables,
    Iptables,
}

impl Firewall {
    pub async fn detect() -> Result<Self, NetError> {
        let Err(nft) = nft::available().await else {
            return Ok(Self::Nftables);
        };
        let Err(iptables) = iptables::available().await else {
            return Ok(Self::Iptables);
        };

        Err(NetError::NoFirewall {
            nft: Box::new(nft),
            iptables: Box::new(iptables),
        })
    }

    pub async fn apply(self, rules: &NodeRules) -> Result<(), NetError> {
        match self {
            Self::Nftables => nft::apply(rules).await,
            Self::Iptables => iptables::apply(rules).await,
        }
    }

    pub async fn remove(self) -> Result<(), NetError> {
        match self {
            Self::Nftables => nft::remove().await,
            Self::Iptables => iptables::remove().await,
        }
    }
}

impl fmt::Display for Firewall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        })
    }
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    const ALL: [Self; 2] = [Self::V4, Self::V6];

    const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    const fn matches(self, net: &IpNet) -> bool {
        matches!(
            (self, net),
            (Self::V4, IpNet::V4(_)) | (Self::V6, IpNet::V6(_))
        )
    }

    const fn holds(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }

    const fn icmp(self) -> &'static str {
        match self {
            Self::V4 => "icmp",
            Self::V6 => "ipv6-icmp",
        }
    }
}

async fn run(
    program: &'static str,
    args: &[&str],
    input: Option<&str>,
) -> Result<String, NetError> {
    let spawn = |error| NetError::FirewallSpawn { program, error };
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(spawn)?;

    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(input.as_bytes()).await.map_err(spawn)?;
    }

    let output = child.wait_with_output().await.map_err(spawn)?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(NetError::Firewall {
            program,
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}
