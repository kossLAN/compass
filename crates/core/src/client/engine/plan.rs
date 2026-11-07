use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};

use bunnyhop_proto::{NodeId, Peer, PublicKey};

use super::{ExitNode, View};
use crate::client::dataplane::{ExitPlan, Path, PeerPlan, Plan};
use crate::client::ice;

pub struct Inputs<'a> {
    pub view: &'a View,
    pub own_key: &'a PublicKey,
    pub direct: &'a BTreeMap<PublicKey, SocketAddr>,
    pub proxies: &'a HashMap<NodeId, SocketAddr>,
    pub healthy: &'a BTreeSet<usize>,
    pub exit_node: Option<&'a ExitNode>,
    pub local_dns: Option<IpAddr>,
}

pub fn build(inputs: &Inputs<'_>) -> Plan {
    let view = inputs.view;
    let netmap = &view.netmap;
    let default_relay = view
        .hubs
        .keys()
        .copied()
        .find(|lighthouse| inputs.healthy.contains(lighthouse))
        .or_else(|| view.hubs.keys().next().copied());

    let peers = netmap
        .peers
        .iter()
        .map(|peer| {
            let relay = relay_for(peer, view, inputs.healthy).or(default_relay);
            let path = inputs.direct.get(&peer.key).map_or_else(
                || relay.map_or(Path::None, Path::Relay),
                |endpoint| Path::Direct(*endpoint),
            );
            PeerPlan {
                id: peer.id,
                key: peer.key,
                addresses: peer.addresses,
                path,
                relay,
                proxy: inputs.proxies.get(&peer.id).copied(),
                keepalive: matches!(path, Path::Direct(_))
                    && ice::controls(inputs.own_key, &peer.key),
            }
        })
        .collect();

    let exit = inputs.exit_node.map(|exit_node| ExitPlan {
        peer: netmap
            .peers
            .iter()
            .find(|peer| {
                peer.exit_node
                    && peer.hostname == exit_node.peer
                    && inputs.direct.contains_key(&peer.key)
            })
            .map(|peer| peer.key),
        bypass: exit_node.bypass.clone(),
    });

    Plan {
        addresses: netmap.node.addresses,
        prefixes: netmap.network.prefixes(),
        mtu: netmap.network.mtu,
        peers,
        exit,
        inbound: netmap.inbound.clone(),
        local_dns: inputs.local_dns,
        exit_clients: netmap.exit_clients.clone(),
    }
}

fn relay_for(peer: &Peer, view: &View, healthy: &BTreeSet<usize>) -> Option<usize> {
    let attached = view.attached.get(&peer.key)?;
    let usable = || {
        attached
            .iter()
            .copied()
            .filter(|lighthouse| view.hubs.contains_key(lighthouse))
    };
    usable()
        .find(|lighthouse| healthy.contains(lighthouse))
        .or_else(|| usable().next())
}
