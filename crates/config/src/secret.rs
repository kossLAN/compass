use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use compass_proto::PrivateKey;
use zeroize::Zeroizing;

use crate::ConfigError;

pub fn read_key(path: &Path) -> Result<PrivateKey, ConfigError> {
    let read_error = |error| ConfigError::Read {
        path: path.to_owned(),
        error,
    };
    let contents = Zeroizing::new(fs::read_to_string(path).map_err(read_error)?);
    let mode = fs::metadata(path).map_err(read_error)?.permissions().mode();

    if mode & 0o004 != 0 {
        tracing::warn!(path = %path.display(), "key file is world-readable");
    }

    PrivateKey::from_base64(&contents)
        .map_err(|error| ConfigError::invalid(path.display().to_string(), error.to_string()))
}
