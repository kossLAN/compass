use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use bunnyhop_config::LighthouseConfig;
use bunnyhop_config::acl::{Compiled, Subject, compile};
use bunnyhop_proto::{
    HubInfo, NetMap, NetMapResponse, NodeId, Peer, PublicKey, SecretHash, SelfNode, Token,
};
use sha2::{Digest as _, Sha256};

use crate::lighthouse::registry::{Names, Node, Registry};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Liveness {
    pub online: BTreeSet<NodeId>,
}

#[derive(Debug, Clone)]
pub struct World {
    config: Arc<LighthouseConfig>,
    hub_key: PublicKey,
    nodes: BTreeMap<NodeId, Node>,
    names: Names,
    access: Compiled,
    liveness: Liveness,
    tokens: HashMap<SecretHash, NodeId>,
    netmaps: BTreeMap<NodeId, NetMapResponse>,
}

impl World {
    pub fn build(
        config: Arc<LighthouseConfig>,
        hub_key: PublicKey,
        registry: &Registry,
        liveness: &Liveness,
    ) -> Self {
        let nodes = registry.nodes().clone();
        let names = Names::resolve(&nodes, &config);
        let subjects: Vec<Subject<'_>> = nodes
            .values()
            .map(|node| {
                let key = config.keys.get(&node.key_name);
                Subject {
                    id: node.id,
                    owner: key.and_then(|key| key.owner.as_deref()),
                    tags: key.map_or(&[], |key| key.tags.as_slice()),
                    addresses: node.addresses,
                    exit_node: node.info.advertise_exit_node
                        && key.is_some_and(|key| key.exit_node),
                }
            })
            .collect();
        let access = compile(&config.policy, &subjects);
        let tokens = nodes
            .values()
            .map(|node| (node.token_hash, node.id))
            .collect();

        let mut world = Self {
            config,
            hub_key,
            nodes,
            names,
            access,
            liveness: liveness.clone(),
            tokens,
            netmaps: BTreeMap::new(),
        };
        world.netmaps = world
            .nodes
            .keys()
            .map(|id| (*id, world.build_netmap(*id)))
            .collect();
        world
    }

    pub fn authenticate(&self, token: &Token) -> Option<NodeId> {
        self.token_owner(&token.hash())
    }

    pub fn token_owner(&self, hash: &SecretHash) -> Option<NodeId> {
        self.tokens.get(hash).copied()
    }

    pub fn sees(&self, from: NodeId, to: NodeId) -> bool {
        self.access
            .access(from)
            .is_some_and(|access| access.visible.contains(&to))
    }

    pub fn netmap(&self, id: NodeId) -> Option<&NetMapResponse> {
        self.netmaps.get(&id)
    }

    fn build_netmap(&self, id: NodeId) -> NetMapResponse {
        let node = &self.nodes[&id];
        let access = self.access.access(id).cloned().unwrap_or_default();
        let netmap = NetMap {
            network: self.config.network.clone(),
            hub: HubInfo {
                key: self.hub_key,
                endpoint: self.config.hub.endpoint.clone(),
            },
            node: SelfNode {
                id,
                hostname: node.hostname.clone(),
                addresses: node.addresses,
                records: self.names.records[&id].clone(),
            },
            peers: access
                .visible
                .iter()
                .map(|peer| self.peer(&self.nodes[peer], access.exit_nodes.contains(peer)))
                .collect(),
            inbound: access.inbound,
            exit_clients: access.exit_clients.into_iter().collect(),
        };
        let bytes = serde_json::to_vec(&netmap).expect("netmaps always serialize");
        NetMapResponse {
            hash: hex_digest(&bytes),
            netmap,
        }
    }

    fn peer(&self, node: &Node, exit_node: bool) -> Peer {
        Peer {
            id: node.id,
            key: node.key,
            hostname: node.hostname.clone(),
            addresses: node.addresses,
            online: self.liveness.online.contains(&node.id),
            records: self.names.accepted(node.id),
            exit_node,
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
            hex
        })
}
