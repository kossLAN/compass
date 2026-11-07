mod kernel;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use bunnyhop_config::InterfaceConfig;
use bunnyhop_net::{
    Datagram, Dataplane, Firewall, MeshRules, NetError, NodeRules, RuleSpec, StunSocket,
};
use bunnyhop_proto::{NodeId, PacketRule, PrivateKey, PublicKey};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use self::kernel::Kernel;

pub const FWMARK: u32 = 0x5254;
pub const KEEPALIVE: u16 = 25;

const MAIN_TABLE: u32 = 254;
const EXIT_TABLE: u32 = 5254;
const BYPASS_PRIORITY: u32 = 5250;
const MAIN_PRIORITY: u32 = 5251;
const EXIT_PRIORITY: u32 = 5252;

#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error(transparent)]
    Net(#[from] NetError),
    #[error("the kernel lacks {0}, which the dataplane needs")]
    Unsupported(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub meshes: Vec<MeshPlan>,
    pub mtu: u16,
    pub peers: Vec<PeerPlan>,
    pub exit: Option<ExitPlan>,
    pub local_dns: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPlan {
    pub addresses: Vec<IpAddr>,
    pub prefixes: Vec<IpNet>,
    pub peers: Vec<IpAddr>,
    pub inbound: Vec<PacketRule>,
    pub exit_clients: Vec<IpNet>,
}

impl MeshPlan {
    fn source(&self, net: &IpNet) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == net.addr().is_ipv4())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPlan {
    pub id: NodeId,
    pub key: PublicKey,
    pub addresses: Vec<IpAddr>,
    pub path: Path,
    pub relay: Option<usize>,
    pub proxy: Option<SocketAddr>,
    pub keepalive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct(SocketAddr),
    Relay(usize),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPlan {
    pub peer: Option<PublicKey>,
    pub sources: Vec<IpAddr>,
    pub bypass: Vec<IpAddr>,
}

impl ExitPlan {
    fn source(&self, net: &IpNet) -> Option<IpAddr> {
        self.sources
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == net.addr().is_ipv4())
    }
}

impl Plan {
    fn exit_peer(&self) -> Option<PublicKey> {
        self.exit.as_ref()?.peer
    }

    fn addresses(&self) -> Vec<IpNet> {
        let addresses: BTreeSet<IpAddr> = self
            .meshes
            .iter()
            .flat_map(|mesh| mesh.addresses.iter().copied())
            .collect();
        addresses.into_iter().map(IpNet::from).collect()
    }

    fn firewall(&self, interface: String) -> NodeRules {
        NodeRules {
            interface,
            meshes: self
                .meshes
                .iter()
                .map(|mesh| MeshRules {
                    prefixes: mesh.prefixes.clone(),
                    addresses: mesh.addresses.clone(),
                    inbound: mesh.inbound.clone(),
                    exit_clients: mesh.exit_clients.clone(),
                })
                .collect(),
            local_dns: self.local_dns,
        }
    }

    fn exit_rules(&self) -> BTreeSet<RuleSpec> {
        let mut rules = BTreeSet::new();

        let Some(exit) = &self.exit else {
            return rules;
        };

        for address in &exit.bypass {
            rules.insert(RuleSpec {
                priority: BYPASS_PRIORITY,
                ipv6: address.is_ipv6(),
                table: MAIN_TABLE,
                destination: Some(IpNet::from(*address)),
                unless_fwmark: None,
                suppress_prefix_length: None,
            });
        }

        for ipv6 in [false, true] {
            rules.insert(RuleSpec {
                priority: MAIN_PRIORITY,
                ipv6,
                table: MAIN_TABLE,
                destination: None,
                unless_fwmark: None,
                suppress_prefix_length: Some(0),
            });
            rules.insert(RuleSpec {
                priority: EXIT_PRIORITY,
                ipv6,
                table: EXIT_TABLE,
                destination: None,
                unless_fwmark: Some(FWMARK),
                suppress_prefix_length: None,
            });
        }

        rules
    }
}

fn default_routes() -> [IpNet; 2] {
    [IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub peers: BTreeMap<PublicKey, Counters>,
}

#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn apply(&mut self, plan: &Plan, rehandshake: &[PublicKey])
    -> Result<(), DataplaneError>;

    async fn stats(&mut self) -> Result<Stats, DataplaneError>;

    async fn teardown(&mut self);

    fn interface(&self) -> &str;

    fn stun(&self) -> Option<Arc<dyn Stun>>;
}

#[async_trait::async_trait]
pub trait Stun: Send + Sync {
    async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()>;
    async fn recv(&self) -> io::Result<Datagram>;
}

#[async_trait::async_trait]
impl Stun for StunSocket {
    async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        Self::send(self, remote, payload).await
    }

    async fn recv(&self) -> io::Result<Datagram> {
        Self::recv(self).await
    }
}

pub async fn start(
    dataplane: Arc<Dataplane>,
    interface: &InterfaceConfig,
    key: &PrivateKey,
) -> Result<Box<dyn Backend>, DataplaneError> {
    if !dataplane.wireguard_available().await {
        return Err(DataplaneError::Unsupported("WireGuard"));
    }

    let firewall = Firewall::detect().await?;
    tracing::info!(%firewall, "using firewall");

    let stun = StunSocket::bind(interface.listen_port, FWMARK)
        .inspect_err(|error| tracing::warn!(%error, "cannot open a raw socket for STUN"))
        .ok();

    Ok(Box::new(Kernel::new(
        dataplane, firewall, interface, key, stun,
    )))
}
