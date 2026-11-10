mod alloc;
mod names;

use std::collections::BTreeMap;

use compass_config::LighthouseConfig;
use compass_proto::{Addresses, DnsName, MAX_AVOID, MAX_RECORDS, NodeId, NodeInfo, PublicKey};

pub use self::names::Names;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub key: PublicKey,
    pub addresses: Addresses,
    pub hostname: DnsName,
    pub info: NodeInfo,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    announced: BTreeMap<NodeId, NodeInfo>,
    nodes: BTreeMap<NodeId, Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnnounceError {
    #[error("this node's public key is not listed in lighthouse.nodes")]
    Unlisted,
    #[error("no free addresses are left in the mesh prefix")]
    AddressesExhausted,
    #[error("{0}")]
    Invalid(String),
    #[error("the lighthouse is shutting down")]
    Unavailable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub removed: Vec<NodeId>,
    pub readdressed: Vec<NodeId>,
}

impl Registry {
    pub const fn nodes(&self) -> &BTreeMap<NodeId, Node> {
        &self.nodes
    }

    pub fn announce(
        &mut self,
        config: &LighthouseConfig,
        id: NodeId,
        info: NodeInfo,
    ) -> Result<bool, AnnounceError> {
        validate(&info)?;

        if !config.nodes.contains_key(&id) {
            return Err(AnnounceError::Unlisted);
        }

        if self.announced.get(&id) == Some(&info) {
            return Ok(false);
        }

        let mut announced = self.announced.clone();
        announced.insert(id, info);
        self.replace(config, announced)?;
        Ok(true)
    }

    pub fn reconcile(&mut self, config: &LighthouseConfig) -> ReconcileReport {
        let (announced, removed): (BTreeMap<_, _>, BTreeMap<_, _>) = self
            .announced
            .clone()
            .into_iter()
            .partition(|(id, _)| config.nodes.contains_key(id));
        let previous: BTreeMap<NodeId, Addresses> = self
            .nodes
            .iter()
            .map(|(id, node)| (*id, node.addresses))
            .collect();
        self.replace(config, announced)
            .expect("fewer nodes always fit in the prefix");
        let readdressed = self
            .nodes
            .values()
            .filter(|node| {
                previous
                    .get(&node.id)
                    .is_some_and(|addresses| *addresses != node.addresses)
            })
            .map(|node| node.id)
            .collect();
        ReconcileReport {
            removed: removed.into_keys().collect(),
            readdressed,
        }
    }

    fn replace(
        &mut self,
        config: &LighthouseConfig,
        announced: BTreeMap<NodeId, NodeInfo>,
    ) -> Result<(), AnnounceError> {
        let addresses =
            alloc::assign(config, &announced).ok_or(AnnounceError::AddressesExhausted)?;
        let hostnames = names::hostnames(config, &announced);
        self.nodes = announced
            .iter()
            .map(|(id, info)| {
                let node = Node {
                    id: *id,
                    key: config.nodes[id].key,
                    addresses: addresses[id],
                    hostname: hostnames[id].clone(),
                    info: info.clone(),
                };
                (*id, node)
            })
            .collect();
        self.announced = announced;
        Ok(())
    }
}

fn validate(info: &NodeInfo) -> Result<(), AnnounceError> {
    if !info.hostname.is_label() {
        return Err(AnnounceError::Invalid(
            "hostname must be a single DNS label".into(),
        ));
    }

    if info.records.len() > MAX_RECORDS {
        return Err(AnnounceError::Invalid(format!(
            "at most {MAX_RECORDS} records are allowed"
        )));
    }

    if info.avoid.len() > MAX_AVOID {
        return Err(AnnounceError::Invalid(format!(
            "at most {MAX_AVOID} addresses to avoid are allowed"
        )));
    }

    Ok(())
}
