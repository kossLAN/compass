use std::path::PathBuf;

use compass_config::{ClientConfig, ConfigError, DnsConfig, ExitNodeConfig, read_key};
use compass_proto::{AuthKey, DnsName, PrivateKey};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    pub private_key: Option<PrivateKey>,
    pub hostname: Option<DnsName>,
    pub listen_port: u16,
    pub lighthouses: Vec<LighthouseSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LighthouseSettings {
    pub url: Url,
    pub auth_key: AuthKey,
    pub ca: Option<CaCertificate>,
    pub dns: DnsConfig,
    pub exit_node: ExitNodeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaCertificate {
    File(PathBuf),
    Pem(String),
}

impl ClientSettings {
    pub fn from_config(config: &ClientConfig) -> Result<Self, ConfigError> {
        let private_key = config
            .private_key_file
            .as_deref()
            .map(read_key)
            .transpose()?;
        let lighthouses = config
            .lighthouses
            .iter()
            .zip(config.read_auth_keys()?)
            .map(|(entry, auth_key)| LighthouseSettings {
                url: entry.url.clone(),
                auth_key,
                ca: config.ca_file.clone().map(CaCertificate::File),
                dns: entry.dns.clone(),
                exit_node: entry.exit_node.clone(),
            })
            .collect();

        Ok(Self {
            private_key,
            hostname: config.hostname.clone(),
            listen_port: config.interface.listen_port,
            lighthouses,
        })
    }
}
