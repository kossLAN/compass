use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};

use crate::{DnsName, DnsRecord, PublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub u64);

impl NodeId {
    pub fn of(key: &PublicKey) -> Self {
        let digest = Sha256::digest(key.to_bytes());
        Self(
            digest[..8]
                .iter()
                .fold(0, |id, byte| (id << 8) | u64::from(*byte)),
        )
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Addresses {
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
}

impl Addresses {
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        [IpAddr::V4(self.v4), IpAddr::V6(self.v6)].into_iter()
    }

    pub fn host_nets(&self) -> Vec<IpNet> {
        self.iter().map(IpNet::from).collect()
    }
}

pub const MESH_RANGE_V4: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10);
pub const MESH_RANGE_V6: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7);
pub const MIN_MTU: u16 = 1280;
pub const MAX_MTU: u16 = 9000;
const REVERSE_ROOTS: [&str; 2] = ["in-addr.arpa", "ip6.arpa"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetMapError {
    #[error("mesh prefix {0} is outside {MESH_RANGE_V4} and {MESH_RANGE_V6}")]
    Prefix(IpNet),
    #[error("address {0} is outside the mesh prefixes")]
    Address(IpAddr),
    #[error("rule source {0} is outside the mesh prefixes")]
    Source(IpNet),
    #[error("mesh domain \"{0}\" needs at least two labels")]
    Domain(DnsName),
    #[error("MTU {0} is outside {MIN_MTU} to {MAX_MTU}")]
    Mtu(u16),
    #[error("zone \"{0}\" overlaps \"{1}\"")]
    Zone(DnsName, DnsName),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Network {
    pub domain: DnsName,
    #[serde(default)]
    pub zones: Vec<DnsName>,
    pub ipv4: Ipv4Net,
    pub ipv6: Ipv6Net,
    pub mtu: u16,
}

impl Network {
    pub fn check(&self) -> Result<(), NetMapError> {
        if !MESH_RANGE_V4.contains(&self.ipv4) {
            return Err(NetMapError::Prefix(self.ipv4.into()));
        }

        if !MESH_RANGE_V6.contains(&self.ipv6) {
            return Err(NetMapError::Prefix(self.ipv6.into()));
        }

        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(NetMapError::Mtu(self.mtu));
        }

        if self.domain.is_label() {
            return Err(NetMapError::Domain(self.domain.clone()));
        }

        let reverse: [DnsName; 2] =
            REVERSE_ROOTS.map(|root| root.parse().expect("reverse roots are valid DNS names"));
        let mut served: Vec<&DnsName> = vec![&self.domain];
        served.extend(&reverse);

        for zone in &self.zones {
            if let Some(other) = served.iter().find(|other| zone.overlaps(other)) {
                return Err(NetMapError::Zone(zone.clone(), (*other).clone()));
            }

            served.push(zone);
        }

        Ok(())
    }

    pub fn prefixes(&self) -> Vec<IpNet> {
        vec![IpNet::V4(self.ipv4), IpNet::V6(self.ipv6)]
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(v4) => self.ipv4.contains(&v4),
            IpAddr::V6(v6) => self.ipv6.contains(&v6),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HubInfo {
    pub key: PublicKey,
    pub endpoint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    NotPermitted,
    OwnedByOther,
    Taken,
    CnameConflict,
    InvalidValue,
    Reserved,
    TooLong,
    UnknownZone,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotPermitted => "not permitted by the node's key",
            Self::OwnedByOther => "owned by another node",
            Self::Taken => "already claimed by another node",
            Self::CnameConflict => "a CNAME cannot coexist with other records",
            Self::InvalidValue => "points at a mesh address the node does not own",
            Self::Reserved => "hostnames only carry their automatic records",
            Self::TooLong => "too long together with its zone",
            Self::UnknownZone => "the mesh does not serve this zone",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum RecordState {
    Accepted,
    Rejected(RejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordStatus {
    pub record: DnsRecord,
    #[serde(flatten)]
    pub state: RecordState,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SelfNode {
    pub id: NodeId,
    pub hostname: DnsName,
    pub addresses: Addresses,
    pub records: Vec<RecordStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Peer {
    pub id: NodeId,
    pub key: PublicKey,
    pub hostname: DnsName,
    pub addresses: Addresses,
    pub online: bool,
    pub records: Vec<DnsRecord>,
    pub exit_node: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid port range \"{0}\"; expected a port like 443 or a range like 8000-8010")]
pub struct PortRangeError(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = PortRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || PortRangeError(s.to_owned());
        let (start, end) = s.split_once('-').unwrap_or((s, s));
        let start: u16 = start.trim().parse().map_err(|_| invalid())?;
        let end: u16 = end.trim().parse().map_err(|_| invalid())?;

        if start == 0 || start > end {
            return Err(invalid());
        }

        Ok(Self { start, end })
    }
}

impl Serialize for PortRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.start == self.end {
            serializer.serialize_u16(self.start)
        } else {
            serializer.collect_str(self)
        }
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = PortRange;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a port number or a \"start-end\" range")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match u16::try_from(v) {
                    Ok(port) if port > 0 => Ok(PortRange::single(port)),
                    _ => Err(E::custom(PortRangeError(v.to_string()))),
                }
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let v = u64::try_from(v).map_err(E::custom)?;
                self.visit_u64(v)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PacketRule {
    pub src: Vec<IpNet>,
    pub protos: Vec<Proto>,
    pub ports: Vec<PortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetMap {
    pub network: Network,
    pub hub: HubInfo,
    pub node: SelfNode,
    pub peers: Vec<Peer>,
    pub inbound: Vec<PacketRule>,
    pub exit_clients: Vec<IpNet>,
}

impl NetMap {
    pub fn check(&self) -> Result<(), NetMapError> {
        self.network.check()?;
        let mut addresses = self
            .node
            .addresses
            .iter()
            .chain(self.peers.iter().flat_map(|peer| peer.addresses.iter()));

        if let Some(outside) = addresses.find(|address| !self.network.contains(*address)) {
            return Err(NetMapError::Address(outside));
        }

        let prefixes = self.network.prefixes();
        let mut sources = self
            .inbound
            .iter()
            .flat_map(|rule| &rule.src)
            .chain(&self.exit_clients);

        if let Some(outside) =
            sources.find(|net| !prefixes.iter().any(|prefix| prefix.contains(*net)))
        {
            return Err(NetMapError::Source(*outside));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetMapResponse {
    pub hash: String,
    pub netmap: NetMap,
}
