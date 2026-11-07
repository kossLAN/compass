use std::io;
use std::path::Path;

use crate::NetError;

pub async fn read(key: &str) -> Result<Option<String>, NetError> {
    match tokio::fs::read_to_string(Path::new("/proc/sys").join(key)).await {
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(NetError::Sysctl {
            key: key.to_owned(),
            error,
        }),
    }
}
