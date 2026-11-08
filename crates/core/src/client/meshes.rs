use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::IpAddr;

use compass_proto::{MAX_AVOID, NetMap, NodeId, Peer, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mesh {
    pub index: usize,
    pub netmap: NetMap,
    pub addresses: Vec<IpAddr>,
    pub peers: BTreeMap<PublicKey, Vec<IpAddr>>,
    pub avoid: Vec<IpAddr>,
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

pub fn resolve(netmaps: Vec<(usize, NetMap)>, avoided: &BTreeMap<usize, Vec<IpAddr>>) -> Vec<Mesh> {
    let mut owners: BTreeMap<IpAddr, NodeId> = BTreeMap::new();

    netmaps
        .into_iter()
        .map(|(index, netmap)| {
            let own = netmap.node.id;
            let held_elsewhere =
                |address: &IpAddr| owners.get(address).is_some_and(|holder| *holder != own);

            // A mesh listed later is asked to move this node off any address that a node of an
            // earlier mesh already holds. An address stays on the list for as long as it is still
            // held, so the node is not handed that address again right after moving away from it.
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

            let addresses = claim(&mut owners, own, netmap.node.addresses.iter());
            let peers = netmap
                .peers
                .iter()
                .map(|peer| {
                    let kept = claim(&mut owners, peer.id, peer.addresses.iter());
                    (peer.key, kept)
                })
                .collect();

            Mesh {
                index,
                netmap,
                addresses,
                peers,
                avoid,
            }
        })
        .collect()
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
