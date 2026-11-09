mod message;
#[cfg(feature = "linux")]
mod stub;
mod zone;

use std::collections::BTreeMap;
use std::iter;
use std::net::IpAddr;

use compass_proto::DnsName;
use hickory_server::proto::rr::Name;
use ipnet::IpNet;
use url::Url;

pub use self::message::{Reply, answer, failure, frame, unframe};
#[cfg(feature = "linux")]
pub use self::stub::DnsService;
pub use self::zone::Zone;
use crate::client::meshes::Mesh;

const ARPA_LABELS: usize = 2;

pub fn stub_address<'a>(meshes: impl IntoIterator<Item = &'a Mesh>) -> Option<IpAddr> {
    meshes.into_iter().next()?.addresses.first().copied()
}

/// The forward zones each mesh answers for on this node, in the order of `meshes`, and the ones
/// left out because an earlier mesh answers for an overlapping zone. Reverse zones are not
/// claimed: meshes often share a prefix, and `meshes::resolve` already gives each address to a
/// single node.
fn claim_zones(meshes: &[Mesh]) -> (Vec<Vec<DnsName>>, Vec<(usize, DnsName)>) {
    let mut claimed: Vec<&DnsName> = Vec::new();
    let mut owned = Vec::new();
    let mut shadowed = Vec::new();

    for mesh in meshes {
        let network = &mesh.netmap.network;
        let mut zones = Vec::new();

        for zone in iter::once(&network.domain).chain(&network.zones) {
            if claimed.iter().any(|other| zone.overlaps(other)) {
                shadowed.push((mesh.index, zone.clone()));
            } else {
                claimed.push(zone);
                zones.push(zone.clone());
            }
        }

        owned.push(zones);
    }

    (owned, shadowed)
}

fn search(meshes: &[Mesh], owned: &[Vec<DnsName>]) -> Vec<String> {
    meshes
        .iter()
        .zip(owned)
        .filter(|(mesh, zones)| zones.contains(&mesh.netmap.network.domain))
        .map(|(mesh, _)| mesh.netmap.network.domain.to_string())
        .collect()
}

fn origins(meshes: &[Mesh], owned: &[Vec<DnsName>]) -> Vec<DnsName> {
    let mut origins: Vec<DnsName> = owned.iter().flatten().cloned().collect();
    let reverse = meshes
        .iter()
        .flat_map(|mesh| mesh.netmap.network.prefixes())
        .flat_map(reverse_zones);

    for zone in reverse {
        if !origins.contains(&zone) {
            origins.push(zone);
        }
    }

    origins
}

fn reverse_zones(prefix: IpNet) -> Vec<DnsName> {
    let step = match prefix {
        IpNet::V4(_) => 8,
        IpNet::V6(_) => 4,
    };

    let aligned = prefix.prefix_len().div_ceil(step) * step;
    prefix
        .subnets(aligned)
        .expect("rounding up to a boundary keeps the prefix length valid")
        .map(|subnet| {
            Name::from(subnet.network())
                .trim_to(usize::from(aligned / step) + ARPA_LABELS)
                .to_string()
                .parse()
                .expect("reverse zone names are valid DNS names")
        })
        .collect()
}

pub struct Zones {
    pub zone: Zone,
    pub search: Vec<String>,
    pub shadowed: Vec<(usize, DnsName)>,
}

impl Zones {
    pub fn new(meshes: &[Mesh]) -> Self {
        let (owned, shadowed) = claim_zones(meshes);
        let origins = origins(meshes, &owned);

        Self {
            zone: Zone::from_meshes(meshes, &owned, &origins),
            search: search(meshes, &owned),
            shadowed,
        }
    }

    pub fn warn_shadowed(&self, before: &[(usize, DnsName)], lighthouses: &BTreeMap<usize, Url>) {
        for (mesh, zone) in self.shadowed.iter().filter(|entry| !before.contains(entry)) {
            tracing::warn!(
                %zone,
                lighthouse = lighthouses.get(mesh).map_or("", |url| url.as_str()),
                "an earlier lighthouse in client.lighthouses already answers for this zone or one overlapping it; ignoring the names this lighthouse has in it",
            );
        }
    }
}
