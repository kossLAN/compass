use std::collections::BTreeSet;
use std::path::PathBuf;

use compass_proto::{DnsName, DnsRecord, MAX_RECORDS, PublicKey};
use serde::Deserialize;

use crate::ConfigError;
use crate::interface::{MAX_INTERFACE_NAME, validate_interface_name};

pub const MAX_LIGHTHOUSES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub lighthouses: Vec<LighthouseEntry>,
    pub hostname: Option<DnsName>,
    pub private_key_file: PathBuf,
    #[serde(default)]
    pub interface: InterfaceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LighthouseEntry {
    pub endpoint: String,
    pub public_key: PublicKey,
    pub mesh: Option<String>,
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

/// Settings left unset take their default, unless another lighthouse of the same mesh sets them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub accept: Option<bool>,
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExitNodeConfig {
    pub peer: Option<DnsName>,
    pub advertise: Option<bool>,
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

        self.validate_lighthouses()?;

        if let Some(hostname) = &self.hostname
            && !hostname.is_label()
        {
            return Err(ConfigError::invalid(
                "client.hostname",
                "must be a single DNS label",
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

        let unique: BTreeSet<&PublicKey> = self
            .lighthouses
            .iter()
            .map(|entry| &entry.public_key)
            .collect();

        if unique.len() != self.lighthouses.len() {
            return Err(ConfigError::invalid(field, "lists a lighthouse twice"));
        }

        for entry in &self.lighthouses {
            let lighthouse = &entry.endpoint;

            if !is_endpoint(lighthouse) {
                return Err(ConfigError::invalid(
                    field,
                    format!("endpoint \"{lighthouse}\" must be \"host:port\""),
                ));
            }

            if entry.mesh.as_ref().is_some_and(String::is_empty) {
                return Err(ConfigError::invalid(
                    field,
                    format!("\"{lighthouse}\" has an empty mesh name"),
                ));
            }

            if entry.dns.records.len() > MAX_RECORDS {
                return Err(ConfigError::invalid(
                    field,
                    format!("\"{lighthouse}\" lists more than {MAX_RECORDS} records"),
                ));
            }

            if let Some(peer) = &entry.exit_node.peer
                && !peer.is_label()
            {
                return Err(ConfigError::invalid(
                    field,
                    format!("\"{lighthouse}\" has an exit_node.peer that is not a peer's hostname"),
                ));
            }
        }

        Ok(())
    }
}

pub fn is_endpoint(endpoint: &str) -> bool {
    endpoint
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0))
}
