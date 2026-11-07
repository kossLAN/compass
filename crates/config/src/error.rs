use std::io;
use std::path::PathBuf;

use bunnyhop_acl::AclError;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {}: {error}", path.display())]
    Read { path: PathBuf, error: io::Error },
    #[error(transparent)]
    Parse(Box<toml::de::Error>),
    #[error(transparent)]
    Acl(#[from] AclError),
    #[error("{field}: {reason}")]
    Invalid { field: String, reason: String },
}

impl ConfigError {
    pub fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Parse(Box::new(error))
    }
}
