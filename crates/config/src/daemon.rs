use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::lighthouse::RawLighthouseConfig;
use crate::{ClientConfig, ConfigError, LighthouseConfig, read_file};

pub const DEFAULT_SOCKET: &str = "/run/compass/compass.sock";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket: SocketConfig,
    pub client: Option<ClientConfig>,
    pub lighthouse: Option<LighthouseConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SocketConfig {
    pub path: PathBuf,
    pub group: Option<String>,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_SOCKET),
            group: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemonConfig {
    #[serde(default)]
    socket: SocketConfig,
    client: Option<ClientConfig>,
    lighthouse: Option<RawLighthouseConfig>,
}

impl DaemonConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&read_file(path)?)
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let raw: RawDaemonConfig = toml::from_str(text)?;

        if raw.client.is_none() && raw.lighthouse.is_none() {
            return Err(ConfigError::invalid(
                "client, lighthouse",
                "configure a client, a lighthouse or both",
            ));
        }

        if let Some(client) = &raw.client {
            client.validate()?;
        }

        let config = Self {
            socket: raw.socket,
            client: raw.client,
            lighthouse: raw.lighthouse.map(LighthouseConfig::from_raw).transpose()?,
        };
        config.check_shared_host()?;
        Ok(config)
    }

    fn check_shared_host(&self) -> Result<(), ConfigError> {
        let (Some(client), Some(lighthouse)) = (&self.client, &self.lighthouse) else {
            return Ok(());
        };

        if client.interface.listen_port == lighthouse.hub.listen_port {
            return Err(ConfigError::invalid(
                "lighthouse.hub.listen_port",
                "is the client's listen port",
            ));
        }

        Ok(())
    }
}
