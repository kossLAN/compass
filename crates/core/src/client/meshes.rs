use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::IpAddr;

use compass_proto::{MAX_AVOID, NetMap, NodeId, Peer, PublicKey};
use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mesh {
    pub index: usize,
    pub netmap: NetMap,
    pub addresses: Vec<IpAddr>,
    pub peers: BTreeMap<PublicKey, Vec<IpAddr>>,
    pub avoid: Vec<IpAddr>,
    pub routed: Vec<IpNet>,
    pub overlapping: Vec<IpNet>,
}

impl Mesh {
    pub fn peer_addresses(&self, key: &PublicKey) -> &[IpAddr] {
        self.peers.get(key).map_or(&[], Vec::as_slice)
    }

    pub fn taken(&self) -> Vec<IpAddr> {
        self.netmap
            .node
            .addresses
            .iter()
            .filter(|address| !self.addresses.contains(address))
            .collect()
    }

    pub fn peer_taken(&self, peer: &Peer) -> Vec<IpAddr> {
        let kept = self.peer_addresses(&peer.key);
        peer.addresses
            .iter()
            .filter(|address| !kept.contains(address))
            .collect()
    }
}

pub fn resolve(
    netmaps: Vec<(usize, NetMap)>,
    avoided: &BTreeMap<usize, Vec<IpAddr>>,
    local: &[IpNet],
) -> Vec<Mesh> {
    let mut owners: BTreeMap<IpAddr, NodeId> = BTreeMap::new();
    let on_link = |address: &IpAddr| local.iter().any(|net| net.contains(address));

    netmaps
        .into_iter()
        .map(|(index, netmap)| {
            let own = netmap.node.id;
            let held_elsewhere = |address: &IpAddr| {
                on_link(address) || owners.get(address).is_some_and(|holder| *holder != own)
            };

            // A mesh is asked to move this node off any address that a local network or a node of
            // an earlier mesh already holds. An address stays on the list for as long as it is
            // still held, so the node is not handed that address again right after moving away
            // from it.
            let mut avoid: Vec<IpAddr> = avoided
                .get(&index)
                .into_iter()
                .flatten()
                .copied()
                .chain(netmap.node.addresses.iter())
                .filter(held_elsewhere)
                .collect();
            avoid.sort_unstable();
            avoid.dedup();
            avoid.truncate(MAX_AVOID);

            let off_link = |address: &IpAddr| !on_link(address);
            let addresses = claim(
                &mut owners,
                own,
                netmap.node.addresses.iter().filter(off_link),
            );
            let peers: BTreeMap<PublicKey, Vec<IpAddr>> = netmap
                .peers
                .iter()
                .map(|peer| {
                    let kept = claim(&mut owners, peer.id, peer.addresses.iter().filter(off_link));
                    (peer.key, kept)
                })
                .collect();

            let overlapping: Vec<IpNet> = local
                .iter()
                .filter(|net| {
                    netmap
                        .network
                        .prefixes()
                        .iter()
                        .any(|prefix| overlaps(net, prefix))
                })
                .copied()
                .collect();
            let routed = routed(&netmap, &peers, &overlapping);

            Mesh {
                index,
                netmap,
                addresses,
                peers,
                avoid,
                routed,
                overlapping,
            }
        })
        .collect()
}

fn routed(
    netmap: &NetMap,
    peers: &BTreeMap<PublicKey, Vec<IpAddr>>,
    overlapping: &[IpNet],
) -> Vec<IpNet> {
    netmap
        .network
        .prefixes()
        .into_iter()
        .flat_map(|prefix| {
            if overlapping.iter().any(|net| overlaps(net, &prefix)) {
                peers
                    .values()
                    .flatten()
                    .filter(|address| prefix.contains(*address))
                    .map(|address| IpNet::from(*address))
                    .collect()
            } else {
                vec![prefix]
            }
        })
        .collect()
}

pub fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn claim(
    owners: &mut BTreeMap<IpAddr, NodeId>,
    holder: NodeId,
    addresses: impl Iterator<Item = IpAddr>,
) -> Vec<IpAddr> {
    addresses
        .filter(|address| match owners.entry(*address) {
            Entry::Vacant(entry) => {
                entry.insert(holder);
                true
            },
            Entry::Occupied(entry) => *entry.get() == holder,
        })
        .collect()
}
