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
        let (zones, lost): (Vec<&DnsName>, Vec<&DnsName>) = iter::once(&network.domain)
            .chain(&network.zones)
            .partition(|zone| !claimed.iter().any(|other| zone.overlaps(other)));

        shadowed.extend(lost.into_iter().map(|zone| (mesh.index, zone.clone())));
        owned.push(zones.iter().map(|zone| (*zone).clone()).collect());
        claimed.extend(zones);
    }

    (owned, shadowed)
}

fn domains(meshes: &[Mesh], owned: &[Vec<DnsName>]) -> Vec<DnsName> {
    meshes
        .iter()
        .zip(owned)
        .map(|(mesh, zones)| (&mesh.netmap.network.domain, zones))
        .filter(|(domain, zones)| zones.contains(domain))
        .map(|(domain, _)| domain.clone())
        .collect()
}

fn authoritative(meshes: &[Mesh], domains: &[DnsName]) -> Vec<DnsName> {
    let mut zones = domains.to_vec();
    let reverse = meshes
        .iter()
        .flat_map(|mesh| mesh.routed.iter().copied())
        .flat_map(reverse_zones);

    for zone in reverse {
        if !zones.contains(&zone) {
            zones.push(zone);
        }
    }

    zones
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
        let domains = domains(meshes, &owned);

        Self {
            zone: Zone::from_meshes(meshes, &owned, &authoritative(meshes, &domains)),
            search: domains.iter().map(ToString::to_string).collect(),
            shadowed,
        }
    }

    pub fn warn_shadowed(
        &self,
        before: &[(usize, DnsName)],
        lighthouses: &BTreeMap<usize, String>,
    ) {
        for (mesh, zone) in self.shadowed.iter().filter(|entry| !before.contains(entry)) {
            tracing::warn!(
                %zone,
                lighthouse = lighthouses.get(mesh).map_or("", String::as_str),
                "an earlier lighthouse in client.lighthouses already answers for this zone or one overlapping it; ignoring the names this lighthouse has in it",
            );
        }
    }
}
