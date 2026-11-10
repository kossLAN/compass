use compass_config::{ClientConfig, ConfigError, DnsConfig, ExitNodeConfig, read_key};
use compass_proto::{DnsName, PrivateKey, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    pub private_key: PrivateKey,
    pub hostname: Option<DnsName>,
    pub listen_port: u16,
    pub lighthouses: Vec<LighthouseSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LighthouseSettings {
    pub endpoint: String,
    pub key: PublicKey,
    pub mesh: Option<String>,
    pub dns: DnsConfig,
    pub exit_node: ExitNodeConfig,
}

impl ClientSettings {
    pub fn from_config(config: &ClientConfig) -> Result<Self, ConfigError> {
        let lighthouses = config
            .lighthouses
            .iter()
            .map(|entry| LighthouseSettings {
                endpoint: entry.endpoint.clone(),
                key: entry.public_key,
                mesh: entry.mesh.clone(),
                dns: entry.dns.clone(),
                exit_node: entry.exit_node.clone(),
            })
            .collect();

        Ok(Self {
            private_key: read_key(&config.private_key_file)?,
            hostname: config.hostname.clone(),
            listen_port: config.interface.listen_port,
            lighthouses,
        })
    }
}
