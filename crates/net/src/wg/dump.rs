use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bunnyhop_proto::PublicKey;
use ipnet::IpNet;
use netlink_packet_wireguard::{
    WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute, WireguardMessage,
    WireguardPeer, WireguardPeerAttribute, WireguardTimeSpec,
};

use crate::{DeviceState, PeerState};

pub fn parse_device(messages: Vec<WireguardMessage>) -> DeviceState {
    let mut state = DeviceState::default();

    for attribute in messages.into_iter().flat_map(|message| message.attributes) {
        match attribute {
            WireguardAttribute::PublicKey(key) => {
                state.public_key = Some(PublicKey::from_bytes(key));
            },
            WireguardAttribute::ListenPort(port) => state.listen_port = port,
            WireguardAttribute::Fwmark(mark) => state.fwmark = mark,
            WireguardAttribute::Peers(peers) => merge_peers(&mut state.peers, peers),
            _ => {},
        }
    }

    state
}

fn merge_peers(peers: &mut BTreeMap<PublicKey, PeerState>, fragments: Vec<WireguardPeer>) {
    for fragment in fragments {
        let Some(key) = fragment.0.iter().find_map(|attribute| match attribute {
            WireguardPeerAttribute::PublicKey(key) => Some(PublicKey::from_bytes(*key)),
            _ => None,
        }) else {
            continue;
        };

        let peer = peers.entry(key).or_default();

        for attribute in fragment.0 {
            match attribute {
                WireguardPeerAttribute::Endpoint(endpoint) => peer.endpoint = Some(endpoint),
                WireguardPeerAttribute::PersistentKeepalive(interval) => peer.keepalive = interval,
                WireguardPeerAttribute::LastHandshake(time) => {
                    peer.last_handshake = handshake_time(time);
                },
                WireguardPeerAttribute::RxBytes(bytes) => peer.rx_bytes = bytes,
                WireguardPeerAttribute::TxBytes(bytes) => peer.tx_bytes = bytes,
                WireguardPeerAttribute::AllowedIps(ips) => {
                    peer.allowed_ips
                        .extend(ips.iter().filter_map(parse_allowed_ip));
                },
                _ => {},
            }
        }
    }
}

fn handshake_time(time: WireguardTimeSpec) -> Option<SystemTime> {
    let seconds = u64::try_from(time.seconds).ok()?;
    let nanos = u32::try_from(time.nano_seconds).ok()?;
    (seconds != 0 || nanos != 0).then(|| SystemTime::UNIX_EPOCH + Duration::new(seconds, nanos))
}

fn parse_allowed_ip(allowed: &WireguardAllowedIp) -> Option<IpNet> {
    let address = allowed.0.iter().find_map(|attribute| match attribute {
        WireguardAllowedIpAttr::IpAddr(address) => Some(*address),
        _ => None,
    })?;
    let prefix = allowed.0.iter().find_map(|attribute| match attribute {
        WireguardAllowedIpAttr::Cidr(prefix) => Some(*prefix),
        _ => None,
    })?;
    IpNet::new(address, prefix).ok()
}
