use std::collections::BTreeMap;
use std::path::PathBuf;

use compass_proto::{DnsName, MIN_MTU, PublicKey};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::acl::{RuleConfig, Tag};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLighthouseConfig {
    pub network: RawNetwork,
    pub hub: RawHub,
    #[serde(default)]
    pub nodes: BTreeMap<String, RawNode>,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub acl: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawNetwork {
    pub domain: DnsName,
    #[serde(default)]
    pub zones: Vec<DnsName>,
    pub ipv4: Ipv4Net,
    pub ipv6: Ipv6Net,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHub {
    #[serde(default = "default_hub_interface")]
    pub interface: String,
    #[serde(default = "default_hub_port")]
    pub listen_port: u16,
    pub private_key_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawNode {
    pub public_key: PublicKey,
    pub owner: Option<String>,
    #[serde(default)]
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub exit_node: bool,
}

const fn default_mtu() -> u16 {
    MIN_MTU
}

fn default_hub_interface() -> String {
    "compass-hub".to_owned()
}

const fn default_hub_port() -> u16 {
    51820
}
