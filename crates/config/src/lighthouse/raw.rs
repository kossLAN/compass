use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use bunnyhop_proto::{DnsName, MIN_MTU, PublicKey};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::acl::{RuleConfig, Tag};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLighthouseConfig {
    #[serde(default)]
    pub api: RawApi,
    pub network: RawNetwork,
    pub hub: RawHub,
    #[serde(default)]
    pub nodes: RawNodes,
    #[serde(default)]
    pub keys: BTreeMap<String, RawKey>,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub acl: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawApi {
    pub listen: SocketAddr,
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,
}

impl Default for RawApi {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0; 16], 8443)),
            tls_cert_file: None,
            tls_key_file: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawNetwork {
    pub domain: DnsName,
    pub ipv4: Ipv4Net,
    pub ipv6: Ipv6Net,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHub {
    #[serde(default = "default_hub_port")]
    pub listen_port: u16,
    pub endpoint: String,
    pub private_key_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawNodes {
    pub offline_ttl: String,
    pub revoked: Vec<PublicKey>,
}

impl Default for RawNodes {
    fn default() -> Self {
        Self {
            offline_ttl: "30d".to_owned(),
            revoked: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawKey {
    pub secret_file: PathBuf,
    pub owner: Option<String>,
    #[serde(default)]
    pub tags: Vec<Tag>,
    pub offline_ttl: Option<String>,
    #[serde(default)]
    pub exit_node: bool,
    #[serde(default)]
    pub dns: Vec<String>,
}

const fn default_mtu() -> u16 {
    MIN_MTU
}

const fn default_hub_port() -> u16 {
    51820
}
