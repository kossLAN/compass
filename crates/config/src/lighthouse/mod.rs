mod raw;

pub use self::raw::RawLighthouseConfig;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use compass_proto::{MAX_LABEL_LEN, MAX_NAME_LEN, Network, NodeId, PublicKey};

use self::raw::{RawHub, RawNetwork, RawNode};
use crate::ConfigError;
use crate::acl::{NamePattern, Policy, Selector, Tag};
use crate::interface::{MAX_INTERFACE_NAME, validate_interface_name};

const MAX_DOMAIN_LEN: usize = MAX_NAME_LEN - MAX_LABEL_LEN - 1;

#[derive(Debug, Clone)]
pub struct LighthouseConfig {
    pub network: Network,
    pub hub: HubConfig,
    pub nodes: BTreeMap<NodeId, NodeConfig>,
    pub policy: Policy,
}

#[derive(Debug, Clone)]
pub struct HubConfig {
    pub interface: String,
    pub listen_port: u16,
    pub private_key_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub name: String,
    pub key: PublicKey,
    pub owner: Option<String>,
    pub tags: Vec<Tag>,
    pub exit_node: bool,
}

impl LighthouseConfig {
    pub fn startup_setting_changed(&self, new: &Self) -> Option<&'static str> {
        let without_zones = |network: &Network| Network {
            zones: Vec::new(),
            ..network.clone()
        };

        [
            (
                "lighthouse.network",
                without_zones(&self.network) != without_zones(&new.network),
            ),
            (
                "lighthouse.hub.interface",
                self.hub.interface != new.hub.interface,
            ),
            (
                "lighthouse.hub.listen_port",
                self.hub.listen_port != new.hub.listen_port,
            ),
            (
                "lighthouse.hub.private_key_file",
                self.hub.private_key_file != new.hub.private_key_file,
            ),
        ]
        .into_iter()
        .find_map(|(setting, changed)| changed.then_some(setting))
    }

    pub(crate) fn from_raw(raw: RawLighthouseConfig) -> Result<Self, ConfigError> {
        let network = network_from_raw(raw.network)?;
        let nodes = nodes_from_raw(raw.nodes)?;
        let policy = Policy::new(raw.groups, raw.acl, &network.domain)?;

        Ok(Self {
            network,
            hub: HubConfig::from_raw(raw.hub)?,
            nodes,
            policy,
        })
    }

    pub fn dns_names<'a>(&'a self, node: &'a NodeConfig) -> impl Iterator<Item = &'a NamePattern> {
        self.policy.dns_names(node.owner.as_deref(), &node.tags)
    }

    pub fn unknown_tags(&self) -> Vec<&Tag> {
        let granted: BTreeSet<&Tag> = self.nodes.values().flat_map(|node| &node.tags).collect();
        self.policy
            .referenced_tags()
            .into_iter()
            .filter(|tag| !granted.contains(tag))
            .collect()
    }
}

fn nodes_from_raw(
    raw: BTreeMap<String, RawNode>,
) -> Result<BTreeMap<NodeId, NodeConfig>, ConfigError> {
    let mut nodes = BTreeMap::new();

    for (name, node) in raw {
        let node = NodeConfig::from_raw(name, node)?;

        match nodes.entry(NodeId::of(&node.key)) {
            Entry::Vacant(entry) => {
                entry.insert(node);
            },
            Entry::Occupied(entry) => {
                return Err(ConfigError::invalid(
                    format!("lighthouse.nodes.{}", node.name),
                    format!(
                        "shares its public key or node id with lighthouse.nodes.{}",
                        entry.get().name
                    ),
                ));
            },
        }
    }

    Ok(nodes)
}
fn network_from_raw(raw: RawNetwork) -> Result<Network, ConfigError> {
    if raw.domain.as_str().len() > MAX_DOMAIN_LEN {
        return Err(ConfigError::invalid(
            "lighthouse.network.domain",
            format!("must be at most {MAX_DOMAIN_LEN} characters, so every hostname fits"),
        ));
    }

    if raw.ipv4.prefix_len() > 30 {
        return Err(ConfigError::invalid(
            "lighthouse.network.ipv4",
            "prefix length must be at most 30",
        ));
    }

    if !(16..=126).contains(&raw.ipv6.prefix_len()) {
        return Err(ConfigError::invalid(
            "lighthouse.network.ipv6",
            "prefix length must be 16 to 126",
        ));
    }

    let network = Network {
        domain: raw.domain,
        zones: raw.zones,
        ipv4: raw.ipv4.trunc(),
        ipv6: raw.ipv6.trunc(),
        mtu: raw.mtu,
    };
    network
        .check()
        .map_err(|error| ConfigError::invalid("lighthouse.network", error.to_string()))?;
    Ok(network)
}

impl HubConfig {
    fn from_raw(raw: RawHub) -> Result<Self, ConfigError> {
        validate_interface_name(
            "lighthouse.hub.interface",
            &raw.interface,
            MAX_INTERFACE_NAME,
        )?;

        if raw.listen_port == 0 {
            return Err(ConfigError::invalid(
                "lighthouse.hub.listen_port",
                "must not be 0",
            ));
        }

        Ok(Self {
            interface: raw.interface,
            listen_port: raw.listen_port,
            private_key_file: raw.private_key_file,
        })
    }
}

impl NodeConfig {
    fn from_raw(name: String, raw: RawNode) -> Result<Self, ConfigError> {
        let field = |suffix: &str| format!("lighthouse.nodes.{name}{suffix}");
        let valid_name = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));

        if name.is_empty() || !valid_name {
            return Err(ConfigError::invalid(
                field(""),
                "use letters, digits, '-' and '_'",
            ));
        }

        if let Some(owner) = &raw.owner
            && !matches!(owner.parse(), Ok(Selector::User(_)))
        {
            return Err(ConfigError::invalid(
                field(".owner"),
                format!("\"{owner}\" is not a user"),
            ));
        }

        Ok(Self {
            name,
            key: raw.public_key,
            owner: raw.owner,
            tags: raw.tags,
            exit_node: raw.exit_node,
        })
    }
}
