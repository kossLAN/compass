mod alloc;
mod names;

use std::collections::BTreeMap;

use bunnyhop_config::LighthouseConfig;
use bunnyhop_proto::{
    Addresses, DnsName, MAX_AVOID, MAX_RECORDS, NodeId, NodeInfo, PublicKey, RegisterRequest,
    SecretHash, Token,
};

pub use self::names::Names;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub key_name: String,
    pub key: PublicKey,
    pub token_hash: SecretHash,
    pub addresses: Addresses,
    pub hostname: DnsName,
    pub info: NodeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Registration {
    key_name: String,
    key: PublicKey,
    token_hash: SecretHash,
    info: NodeInfo,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    registrations: BTreeMap<NodeId, Registration>,
    nodes: BTreeMap<NodeId, Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    #[error("unknown pre-auth key")]
    InvalidAuthKey,
    #[error("this node's key has been revoked")]
    Revoked,
    #[error("this node is not registered")]
    UnknownNode,
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

    pub fn register(
        &mut self,
        config: &LighthouseConfig,
        request: RegisterRequest,
    ) -> Result<(NodeId, Token), RegisterError> {
        let (key_name, _) = config
            .find_key(&request.auth_key.hash())
            .ok_or(RegisterError::InvalidAuthKey)?;
        if config.nodes.revoked.contains(&request.key) {
            return Err(RegisterError::Revoked);
        }

        validate(&request.info)?;

        let id = NodeId::of(&request.key);

        if self
            .registrations
            .get(&id)
            .is_some_and(|registration| registration.key != request.key)
        {
            return Err(RegisterError::Invalid(
                "another node's key has the same id".into(),
            ));
        }

        let token = Token::generate();
        let mut registrations = self.registrations.clone();
        registrations.insert(
            id,
            Registration {
                key_name: key_name.to_owned(),
                key: request.key,
                token_hash: token.hash(),
                info: request.info,
            },
        );
        self.replace(config, registrations)?;
        Ok((id, token))
    }

    pub fn update(
        &mut self,
        config: &LighthouseConfig,
        id: NodeId,
        info: NodeInfo,
    ) -> Result<bool, RegisterError> {
        validate(&info)?;
        let mut registrations = self.registrations.clone();
        let registration = registrations
            .get_mut(&id)
            .ok_or(RegisterError::UnknownNode)?;

        if registration.info == info {
            return Ok(false);
        }

        registration.info = info;
        self.replace(config, registrations)?;
        Ok(true)
    }

    pub fn remove(&mut self, config: &LighthouseConfig, id: NodeId) -> bool {
        let mut registrations = self.registrations.clone();

        if registrations.remove(&id).is_none() {
            return false;
        }

        self.replace(config, registrations)
            .expect("fewer nodes always fit in the prefix");
        true
    }

    pub fn reconcile(&mut self, config: &LighthouseConfig) -> ReconcileReport {
        let revoked = &config.nodes.revoked;
        let (registrations, removed): (BTreeMap<_, _>, BTreeMap<_, _>) = self
            .registrations
            .clone()
            .into_iter()
            .partition(|(_, registration)| {
                config.keys.contains_key(&registration.key_name)
                    && !revoked.contains(&registration.key)
            });
        let previous: BTreeMap<NodeId, Addresses> = self
            .nodes
            .iter()
            .map(|(id, node)| (*id, node.addresses))
            .collect();
        self.replace(config, registrations)
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
        registrations: BTreeMap<NodeId, Registration>,
    ) -> Result<(), RegisterError> {
        let addresses = alloc::assign(&config.network, &registrations)
            .ok_or(RegisterError::AddressesExhausted)?;
        let hostnames = names::hostnames(config, &registrations);
        self.nodes = registrations
            .iter()
            .map(|(id, registration)| {
                let node = Node {
                    id: *id,
                    key_name: registration.key_name.clone(),
                    key: registration.key,
                    token_hash: registration.token_hash,
                    addresses: addresses[id],
                    hostname: hostnames[id].clone(),
                    info: registration.info.clone(),
                };
                (*id, node)
            })
            .collect();
        self.registrations = registrations;
        Ok(())
    }
}

fn validate(info: &NodeInfo) -> Result<(), RegisterError> {
    if !info.hostname.is_label() {
        return Err(RegisterError::Invalid(
            "hostname must be a single DNS label".into(),
        ));
    }

    if info.records.len() > MAX_RECORDS {
        return Err(RegisterError::Invalid(format!(
            "at most {MAX_RECORDS} records are allowed"
        )));
    }

    if info.avoid.len() > MAX_AVOID {
        return Err(RegisterError::Invalid(format!(
            "at most {MAX_AVOID} addresses to avoid are allowed"
        )));
    }

    Ok(())
}
