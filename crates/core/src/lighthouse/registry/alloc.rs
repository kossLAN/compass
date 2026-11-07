use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bunnyhop_proto::{Addresses, Network, NodeId, PublicKey};
use ipnet::{Ipv4Net, Ipv6Net};

use super::Registration;

const MAX_PROBES: u128 = 1 << 20;

fn seed(key: &PublicKey) -> u128 {
    key.to_bytes()
        .iter()
        .fold(0, |acc: u128, byte| acc.rotate_left(8) ^ u128::from(*byte))
}

pub fn assign(
    network: &Network,
    registrations: &BTreeMap<NodeId, Registration>,
) -> Option<BTreeMap<NodeId, Addresses>> {
    let mut taken_v4 = BTreeSet::new();
    let mut taken_v6 = BTreeSet::new();
    registrations
        .iter()
        .map(|(id, registration)| {
            let avoid = &registration.info.avoid;
            let v4 = allocate_v4(network.ipv4, &registration.key, |address| {
                taken_v4.contains(&address) || avoid.contains(&IpAddr::V4(address))
            })?;
            let v6 = allocate_v6(network.ipv6, &registration.key, |address| {
                taken_v6.contains(&address) || avoid.contains(&IpAddr::V6(address))
            })?;
            taken_v4.insert(v4);
            taken_v6.insert(v6);
            Some((*id, Addresses { v4, v6 }))
        })
        .collect()
}

fn allocate_v4(
    net: Ipv4Net,
    key: &PublicKey,
    unavailable: impl Fn(Ipv4Addr) -> bool,
) -> Option<Ipv4Addr> {
    let first = net.network().to_bits() + 1;
    let size = net.broadcast().to_bits() - first;
    let start = (seed(key) % u128::from(size)) as u32;
    (0..size)
        .map(|offset| Ipv4Addr::from_bits(first + (start + offset) % size))
        .find(|address| !unavailable(*address))
}

fn allocate_v6(
    net: Ipv6Net,
    key: &PublicKey,
    unavailable: impl Fn(Ipv6Addr) -> bool,
) -> Option<Ipv6Addr> {
    let first = net.network().to_bits() + 1;
    let size = net.broadcast().to_bits() - first + 1;
    let start = seed(key) % size;
    (0..size.min(MAX_PROBES))
        .map(|offset| Ipv6Addr::from_bits(first + (start + offset) % size))
        .find(|address| !unavailable(*address))
}
