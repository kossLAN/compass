use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use bunnyhop_proto::{AuthKey, DnsName, DnsRecord, MAX_RECORDS};
use serde::de::value::MapAccessDeserializer;
use serde::{Deserialize, Deserializer, de};
use url::{Host, Url};

use crate::ConfigError;
use crate::interface::{MAX_INTERFACE_NAME, validate_interface_name};
use crate::secret::read_secret;

pub const MAX_LIGHTHOUSES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub lighthouses: Vec<LighthouseEntry>,
    pub auth_key_file: Option<PathBuf>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LighthouseEntry {
    pub url: Url,
    pub auth_key_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLighthouseEntry {
    url: Url,
    auth_key_file: Option<PathBuf>,
}

impl<'de> Deserialize<'de> for LighthouseEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = LighthouseEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a lighthouse URL or a table with url and auth_key_file")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let url = v.parse().map_err(E::custom)?;
                Ok(LighthouseEntry {
                    url,
                    auth_key_file: None,
                })
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let raw = RawLighthouseEntry::deserialize(MapAccessDeserializer::new(map))?;
                Ok(LighthouseEntry {
                    url: raw.url,
                    auth_key_file: raw.auth_key_file,
                })
            }
        }

        deserializer.deserialize_any(Visitor)
    }
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

        let unique: BTreeSet<&Url> = self.lighthouses.iter().map(|entry| &entry.url).collect();

        if unique.len() != self.lighthouses.len() {
            return Err(ConfigError::invalid(field, "lists a lighthouse twice"));
        }

        for entry in &self.lighthouses {
            let lighthouse = &entry.url;

            if self.auth_key_file_for(entry).is_none() {
                return Err(ConfigError::invalid(
                    field,
                    format!(
                        "\"{lighthouse}\" has no auth_key_file and client.auth_key_file is not set"
                    ),
                ));
            }

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

    fn auth_key_file_for<'a>(&'a self, entry: &'a LighthouseEntry) -> Option<&'a Path> {
        entry
            .auth_key_file
            .as_deref()
            .or(self.auth_key_file.as_deref())
    }

    pub fn read_auth_keys(&self) -> Result<Vec<AuthKey>, ConfigError> {
        self.lighthouses
            .iter()
            .map(|entry| {
                let path = self.auth_key_file_for(entry).ok_or_else(|| {
                    ConfigError::invalid("client.lighthouses", "a lighthouse has no auth_key_file")
                })?;
                read_secret(path).map(|secret| AuthKey::new(secret.as_str()))
            })
            .collect()
    }
}
