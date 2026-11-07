use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bunnyhop_proto::{CandidateKind, IceCandidate, MAX_CANDIDATES};
use ipnet::IpNet;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use rtc_ice::candidate::{Candidate, CandidateConfig};
use rtc_shared::error::Error;

use crate::client::endpoints::endpoint_addresses;

pub fn gather(networks: &[IpNet], port: u16, observed: &[SocketAddr]) -> Vec<IceCandidate> {
    let hosts: Vec<IceCandidate> = endpoint_addresses(networks)
        .into_iter()
        .map(|address| IceCandidate {
            kind: CandidateKind::Host,
            address: SocketAddr::new(address, port),
        })
        .collect();
    let mut candidates: Vec<IceCandidate> = observed
        .iter()
        .filter(|address| !hosts.iter().any(|host| host.address == **address))
        .map(|address| IceCandidate {
            kind: CandidateKind::ServerReflexive,
            address: *address,
        })
        .collect();
    candidates.extend(hosts);
    candidates.truncate(MAX_CANDIDATES);
    candidates
}

pub fn usable(candidate: &IceCandidate, prefixes: &[IpNet]) -> bool {
    let address = candidate.address.ip();

    let unicast = match address {
        IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unicast_link_local()),
    };

    unicast
        && candidate.address.port() != 0
        && !address.is_unspecified()
        && !address.is_multicast()
        && !prefixes.iter().any(|prefix| prefix.contains(&address))
}

pub fn to_rtc(candidate: &IceCandidate) -> Result<Candidate, Error> {
    let base_config = CandidateConfig {
        network: "udp".to_owned(),
        address: candidate.address.ip().to_string(),
        port: candidate.address.port(),
        component: 1,
        ..CandidateConfig::default()
    };

    match candidate.kind {
        CandidateKind::Host => CandidateHostConfig {
            base_config,
            ..CandidateHostConfig::default()
        }
        .new_candidate_host(),
        CandidateKind::ServerReflexive => {
            let unspecified = match candidate.address {
                SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };

            CandidateServerReflexiveConfig {
                base_config,
                rel_addr: unspecified.to_string(),
                rel_port: 0,
                url: None,
            }
            .new_candidate_server_reflexive()
        },
    }
}
