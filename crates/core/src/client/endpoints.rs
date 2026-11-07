use std::net::{IpAddr, Ipv6Addr};

use bunnyhop_net::LocalAddress;
use ipnet::IpNet;

pub fn local_networks(
    addresses: &[LocalAddress],
    interface: &str,
    exclude: &[String],
) -> Vec<IpNet> {
    let mut networks: Vec<IpNet> = addresses
        .iter()
        .filter(|local| local.interface != "lo" && local.interface != interface)
        .filter(|local| {
            !exclude
                .iter()
                .any(|pattern| matches_glob(pattern, &local.interface))
        })
        .map(|local| local.address)
        .filter(|network| match network.addr() {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unicast_link_local(),
        })
        .collect();
    networks.sort_unstable();
    networks.dedup();
    networks
}

pub fn endpoint_addresses(networks: &[IpNet]) -> Vec<IpAddr> {
    let mut usable: Vec<IpAddr> = networks
        .iter()
        .map(IpNet::addr)
        .filter(|address| match address {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => is_global_unicast(*v6) || v6.is_unique_local(),
        })
        .collect();
    usable.sort_unstable();
    usable.dedup();
    usable
}

const fn is_global_unicast(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xe000 == 0x2000
}

fn matches_glob(pattern: &str, name: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == name, |prefix| name.starts_with(prefix))
}
