pub mod acl;
mod client;
mod daemon;
mod error;
mod interface;
mod lighthouse;
mod secret;

use std::fs;
use std::path::Path;

pub use client::{
    ClientConfig, DnsConfig, ExitNodeConfig, InterfaceConfig, LighthouseEntry, MAX_LIGHTHOUSES,
};
pub use daemon::{DEFAULT_SOCKET, DaemonConfig, SocketConfig};
pub use error::ConfigError;
pub use lighthouse::{
    ApiConfig, HubConfig, KeyConfig, LighthouseConfig, NamePattern, NodesConfig, TlsConfig,
};
pub use secret::read_key;

fn read_file(path: &Path) -> Result<String, ConfigError> {
    fs::read_to_string(path).map_err(|error| ConfigError::Read {
        path: path.to_owned(),
        error,
    })
}
