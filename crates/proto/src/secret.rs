use std::fmt;

use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const SECRET_BYTES: usize = 32;

fn random_secret(prefix: &str) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0; SECRET_BYTES]);
    getrandom::fill(bytes.as_mut_slice()).expect("the OS random number generator failed");
    Zeroizing::new(format!(
        "{prefix}{}",
        BASE64_URL_SAFE_NO_PAD.encode(bytes.as_slice())
    ))
}

macro_rules! secret_string {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Zeroizing<String>);

        impl $name {
            pub fn generate() -> Self {
                Self(random_secret($prefix))
            }

            pub fn new(secret: impl Into<String>) -> Self {
                Self(Zeroizing::new(secret.into()))
            }

            pub fn expose(&self) -> &str {
                &self.0
            }

            pub fn hash(&self) -> SecretHash {
                SecretHash::of(self.0.as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_string!(AuthKey, "bhk_");

secret_string!(Token, "bht_");

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretHash([u8; 32]);

impl SecretHash {
    pub fn of(secret: &[u8]) -> Self {
        Self(Sha256::digest(secret).into())
    }
}

impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretHash(")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))?;
        f.write_str(")")
    }
}
