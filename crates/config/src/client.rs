use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

use bunnyhop_proto::{AuthKey, DnsName, DnsRecord, MAX_RECORDS};
use serde::Deserialize;
use url::{Host, Url};

use crate::ConfigError;
use crate::interface::{MAX_INTERFACE_NAME, validate_interface_name};
use crate::secret::read_secret;

pub const MAX_LIGHTHOUSES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub lighthouses: Vec<Url>,
    pub auth_key_file: PathBuf,
    pub hostname: Option<DnsName>,
    pub ca_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub exit_node: ExitNodeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterfaceConfig {
    pub name: String,
    pub listen_port: u16,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub accept: bool,
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExitNodeConfig {
    pub peer: Option<DnsName>,
    pub advertise: bool,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: "bh0".to_owned(),
            listen_port: 51821,
            exclude: ["docker*", "br-*", "veth*", "virbr*"]
                .map(str::to_owned)
                .to_vec(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            accept: true,
            records: Vec::new(),
        }
    }
}

impl ClientConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        validate_interface_name(
            "client.interface.name",
            &self.interface.name,
            MAX_INTERFACE_NAME,
        )?;

        if self.interface.listen_port == 0 {
            return Err(ConfigError::invalid(
                "client.interface.listen_port",
                "must not be 0",
            ));
        }

        if self.dns.records.len() > MAX_RECORDS {
            return Err(ConfigError::invalid(
                "client.dns.records",
                format!("at most {MAX_RECORDS} records are allowed"),
            ));
        }

        self.validate_lighthouses()?;

        if let Some(hostname) = &self.hostname
            && !hostname.is_label()
        {
            return Err(ConfigError::invalid(
                "client.hostname",
                "must be a single DNS label",
            ));
        }

        if let Some(peer) = &self.exit_node.peer
            && !peer.is_label()
        {
            return Err(ConfigError::invalid(
                "client.exit_node.peer",
                "must be a peer's hostname",
            ));
        }

        Ok(())
    }

    fn validate_lighthouses(&self) -> Result<(), ConfigError> {
        let field = "client.lighthouses";

        if self.lighthouses.is_empty() {
            return Err(ConfigError::invalid(field, "list at least one lighthouse"));
        }

        if self.lighthouses.len() > MAX_LIGHTHOUSES {
            return Err(ConfigError::invalid(
                field,
                format!("at most {MAX_LIGHTHOUSES} lighthouses are supported"),
            ));
        }

        let unique: BTreeSet<&Url> = self.lighthouses.iter().collect();

        if unique.len() != self.lighthouses.len() {
            return Err(ConfigError::invalid(field, "lists a lighthouse twice"));
        }

        for lighthouse in &self.lighthouses {
            let loopback = match lighthouse.host() {
                Some(Host::Domain(domain)) => domain == "localhost",
                Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
                Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
                None => false,
            };

            let secure = match lighthouse.scheme() {
                "https" => true,
                "http" => loopback,
                _ => false,
            };

            if !secure {
                return Err(ConfigError::invalid(
                    field,
                    format!("\"{lighthouse}\" must use https (http is only allowed to loopback)"),
                ));
            }
        }

        Ok(())
    }

    pub fn read_auth_key(&self) -> Result<AuthKey, ConfigError> {
        read_secret(&self.auth_key_file).map(|secret| AuthKey::new(secret.as_str()))
    }
}
