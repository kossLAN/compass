mod hosted;
#[cfg(feature = "linux")]
mod linux;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use compass_net::{DeviceState, MeshRules, NetError, PeerOp, PeerSpec, Stun, plan_peers};
use compass_proto::{NodeId, PacketRule, PrivateKey, PublicKey};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use reqwest::Certificate;
use url::Url;

pub use self::hosted::{HostedPlatform, TunProvider, TunShape, Underlying};
#[cfg(feature = "linux")]
pub use self::linux::LinuxPlatform;
use crate::client::meshes::Mesh;

pub const KEEPALIVE: u16 = 25;

#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error(transparent)]
    Net(#[from] NetError),
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

    fn peer_specs(&self) -> Vec<PeerSpec> {
        let exit_peer = self.exit_peer();
        self.peers
            .iter()
            .map(|peer| {
                let mut allowed_ips: Vec<IpNet> =
                    peer.addresses.iter().copied().map(IpNet::from).collect();

                if exit_peer == Some(peer.key) {
                    allowed_ips.extend(default_routes());
                }

                let endpoint = match peer.path {
                    Path::Direct(endpoint) => Some(endpoint),
                    Path::Relay(_) | Path::None => peer.proxy,
                };

                PeerSpec {
                    key: peer.key,
                    endpoint,
                    allowed_ips,
                    keepalive: if peer.keepalive { KEEPALIVE } else { 0 },
                }
            })
            .collect()
    }

    fn peer_ops(&self, actual: &DeviceState, rehandshake: &[PublicKey]) -> Vec<PeerOp> {
        let desired = self.peer_specs();
        let mut ops: Vec<PeerOp> = plan_peers(&desired, actual)
            .into_iter()
            .filter(|op| !matches!(op, PeerOp::Upsert(spec) if rehandshake.contains(&spec.key)))
            .collect();

        for spec in desired
            .iter()
            .filter(|spec| rehandshake.contains(&spec.key))
        {
            ops.push(PeerOp::Remove(spec.key));
            ops.push(PeerOp::Upsert(spec.clone()));
        }

        ops
    }

    pub fn mesh_rules(&self) -> Vec<MeshRules> {
        self.meshes
            .iter()
            .map(|mesh| MeshRules {
                prefixes: mesh.prefixes.clone(),
                addresses: mesh.addresses.clone(),
                inbound: mesh.inbound.clone(),
                exit_clients: mesh.exit_clients.clone(),
            })
            .collect()
    }
}

fn default_routes() -> [IpNet; 2] {
    [IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalNetworks {
    pub offered: Vec<IpNet>,
    pub attached: Vec<IpNet>,
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

impl From<DeviceState> for Stats {
    fn from(device: DeviceState) -> Self {
        let peers = device
            .peers
            .into_iter()
            .map(|(key, peer)| {
                let counters = Counters {
                    last_handshake: peer.last_handshake,
                    rx_bytes: peer.rx_bytes,
                    tx_bytes: peer.tx_bytes,
                };
                (key, counters)
            })
            .collect();
        Self { peers }
    }
}

#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn apply(&mut self, plan: &Plan, rehandshake: &[PublicKey])
    -> Result<(), DataplaneError>;

    async fn stats(&mut self) -> Result<Stats, DataplaneError>;

    async fn teardown(&mut self);

    fn stun(&self) -> Option<Stun>;

    async fn check_exit_serving(&mut self, _meshes: &[Mesh]) -> Result<(), DataplaneError> {
        Ok(())
    }

    async fn update_dns(&mut self, _meshes: &[Mesh], _lighthouses: &BTreeMap<usize, Url>) {}
}

#[async_trait::async_trait]
pub trait Platform: Send + Sync + 'static {
    type Device: PartialEq + Send + Sync + 'static;

    async fn local_networks(&self, device: &Self::Device) -> Option<LocalNetworks>;

    fn roots(&self) -> Option<&[Certificate]> {
        None
    }

    async fn start(
        &self,
        device: &Self::Device,
        key: &PrivateKey,
        listen_port: u16,
    ) -> Result<Box<dyn Backend>, DataplaneError>;
}
