use std::collections::{BTreeMap, BTreeSet};

use bunnyhop_proto::{Addresses, NodeId, PacketRule};
use ipnet::IpNet;

use crate::{Policy, Selector, Tag};

#[derive(Debug, Clone)]
pub struct Subject<'a> {
    pub id: NodeId,
    pub owner: Option<&'a str>,
    pub tags: &'a [Tag],
    pub addresses: Addresses,
    pub exit_node: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeAccess {
    pub visible: BTreeSet<NodeId>,
    pub inbound: Vec<PacketRule>,
    pub exit_nodes: BTreeSet<NodeId>,
    pub exit_clients: BTreeSet<IpNet>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Compiled {
    pub nodes: BTreeMap<NodeId, NodeAccess>,
}

impl Compiled {
    pub fn access(&self, id: NodeId) -> Option<&NodeAccess> {
        self.nodes.get(&id)
    }
}

fn host_nets<'a>(subjects: impl IntoIterator<Item = &'a &'a Subject<'a>>) -> Vec<IpNet> {
    subjects
        .into_iter()
        .flat_map(|subject| subject.addresses.host_nets())
        .collect()
}

fn connect(nodes: &mut BTreeMap<NodeId, NodeAccess>, a: NodeId, b: NodeId) {
    nodes.entry(a).or_default().visible.insert(b);
    nodes.entry(b).or_default().visible.insert(a);
}

pub fn compile(policy: &Policy, subjects: &[Subject<'_>]) -> Compiled {
    let mut nodes: BTreeMap<NodeId, NodeAccess> = subjects
        .iter()
        .map(|subject| (subject.id, NodeAccess::default()))
        .collect();
    for rule in policy.rules() {
        let select = |selectors: &[Selector]| -> Vec<&Subject<'_>> {
            subjects
                .iter()
                .filter(|subject| selectors.iter().any(|s| policy.matches(s, subject)))
                .collect()
        };
        let sources = select(&rule.src);
        let destinations = select(&rule.dst);

        for destination in &destinations {
            let others: Vec<&Subject<'_>> = sources
                .iter()
                .copied()
                .filter(|s| s.id != destination.id)
                .collect();

            if others.is_empty() {
                continue;
            }

            for source in &others {
                connect(&mut nodes, source.id, destination.id);
            }

            let packet_rule = PacketRule {
                src: host_nets(&others),
                protos: rule.protos.clone(),
                ports: rule.ports.clone(),
            };
            let inbound = &mut nodes.entry(destination.id).or_default().inbound;

            if !inbound.contains(&packet_rule) {
                inbound.push(packet_rule);
            }
        }

        if rule.dst.contains(&Selector::Internet) {
            for exit in subjects.iter().filter(|subject| subject.exit_node) {
                for source in sources.iter().filter(|source| source.id != exit.id) {
                    connect(&mut nodes, source.id, exit.id);
                    let access = nodes.entry(source.id).or_default();
                    access.exit_nodes.insert(exit.id);
                    let access = nodes.entry(exit.id).or_default();
                    access.exit_clients.extend(source.addresses.host_nets());
                }
            }
        }
    }

    Compiled { nodes }
}
