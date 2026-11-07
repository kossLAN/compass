use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};

use bunnyhop_proto::{MIN_MTU, NodeId, PacketRule, Peer, PublicKey};
use ipnet::IpNet;

use super::{ExitNode, View};
use crate::client::dataplane::{ExitPlan, MeshPlan, Path, PeerPlan, Plan};
use crate::client::ice;
use crate::client::meshes::Mesh;

pub struct Inputs<'a> {
    pub view: &'a View,
    pub own_key: &'a PublicKey,
    pub direct: &'a BTreeMap<PublicKey, SocketAddr>,
    pub proxies: &'a HashMap<NodeId, SocketAddr>,
    pub healthy: &'a BTreeSet<usize>,
    pub exit_node: Option<&'a ExitNode>,
    pub local_dns: Option<IpAddr>,
}

struct Merged<'a> {
    peer: &'a Peer,
    addresses: Vec<IpAddr>,
    meshes: BTreeSet<usize>,
}

pub fn build(inputs: &Inputs<'_>) -> Plan {
    let view = inputs.view;
    let mut merged: BTreeMap<PublicKey, Merged<'_>> = BTreeMap::new();

    for mesh in &view.meshes {
        for peer in &mesh.netmap.peers {
            let entry = merged.entry(peer.key).or_insert_with(|| Merged {
                peer,
                addresses: Vec::new(),
                meshes: BTreeSet::new(),
            });

            for address in mesh.peer_addresses(&peer.key) {
                if !entry.addresses.contains(address) {
                    entry.addresses.push(*address);
                }
            }

            entry.meshes.insert(mesh.index);
        }
    }

    let peers = merged
        .into_values()
        .map(|merged| {
            let peer = merged.peer;
            let relay = relay_for(&peer.key, &merged.meshes, view, inputs.healthy);
            let path = inputs.direct.get(&peer.key).map_or_else(
                || relay.map_or(Path::None, Path::Relay),
                |endpoint| Path::Direct(*endpoint),
            );
            PeerPlan {
                id: peer.id,
                key: peer.key,
                addresses: merged.addresses,
                path,
                relay,
                proxy: inputs.proxies.get(&peer.id).copied(),
                keepalive: matches!(path, Path::Direct(_))
                    && ice::controls(inputs.own_key, &peer.key),
            }
        })
        .collect();

    let exit = inputs.exit_node.map(|exit_node| {
        let granted = view
            .meshes
            .iter()
            .filter(|mesh| exit_node.mesh.is_none_or(|index| index == mesh.index))
            .find_map(|mesh| {
                mesh.netmap
                    .peers
                    .iter()
                    .find(|peer| {
                        peer.exit_node
                            && peer.hostname == exit_node.peer
                            && inputs.direct.contains_key(&peer.key)
                    })
                    .map(|peer| (peer.key, mesh.addresses.clone()))
            });
        let (peer, sources) =
            granted.map_or((None, Vec::new()), |(key, sources)| (Some(key), sources));
        ExitPlan {
            peer,
            sources,
            bypass: exit_node.bypass.clone(),
        }
    });

    Plan {
        meshes: view.meshes.iter().map(mesh_plan).collect(),
        mtu: view
            .meshes
            .iter()
            .map(|mesh| mesh.netmap.network.mtu)
            .min()
            .unwrap_or(MIN_MTU),
        peers,
        exit,
        local_dns: inputs.local_dns,
    }
}

fn mesh_plan(mesh: &Mesh) -> MeshPlan {
    let peers: BTreeSet<IpAddr> = mesh.peers.values().flatten().copied().collect();
    let kept = |net: &IpNet| peers.contains(&net.addr());
    let inbound = mesh
        .netmap
        .inbound
        .iter()
        .filter_map(|rule| {
            let src: Vec<IpNet> = rule.src.iter().copied().filter(kept).collect();
            (!src.is_empty()).then(|| PacketRule {
                src,
                protos: rule.protos.clone(),
                ports: rule.ports.clone(),
            })
        })
        .collect();

    MeshPlan {
        addresses: mesh.addresses.clone(),
        prefixes: mesh.netmap.network.prefixes(),
        inbound,
        exit_clients: mesh
            .netmap
            .exit_clients
            .iter()
            .copied()
            .filter(kept)
            .collect(),
        peers: peers.into_iter().collect(),
    }
}

fn relay_for(
    key: &PublicKey,
    meshes: &BTreeSet<usize>,
    view: &View,
    healthy: &BTreeSet<usize>,
) -> Option<usize> {
    let attached: Vec<usize> = view
        .attached
        .get(key)
        .into_iter()
        .flatten()
        .copied()
        .filter(|lighthouse| view.hubs.contains_key(lighthouse))
        .collect();
    let serving: Vec<usize> = view
        .serves
        .iter()
        .filter(|(_, mesh)| meshes.contains(mesh))
        .map(|(lighthouse, _)| *lighthouse)
        .collect();

    let pick = |candidates: &[usize]| {
        candidates
            .iter()
            .copied()
            .find(|lighthouse| healthy.contains(lighthouse))
            .or_else(|| candidates.first().copied())
    };
    pick(&attached).or_else(|| pick(&serving))
}
