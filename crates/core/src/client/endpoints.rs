use std::net::{IpAddr, Ipv6Addr};

use compass_proto::CONTROL_PREFIX;
use ipnet::IpNet;

pub fn endpoint_addresses(networks: &[IpNet]) -> Vec<IpAddr> {
    let mut usable: Vec<IpAddr> = networks
        .iter()
        .map(IpNet::addr)
        .filter(|address| match address {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => {
                is_global_unicast(*v6) || v6.is_unique_local() && !CONTROL_PREFIX.contains(v6)
            },
        })
        .collect();
    usable.sort_unstable();
    usable.dedup();
    usable
}

const fn is_global_unicast(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xe000 == 0x2000
}
