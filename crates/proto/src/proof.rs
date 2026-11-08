use std::fmt;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Sha256;

use crate::{PrivateKey, PublicKey};

const LABEL: &[u8] = b"compass key proof v1";
const MAX_PROOF_AGE: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyProof {
    pub timestamp: u64,
    tag: MacTag,
}

impl KeyProof {
    pub fn new(hub: &PublicKey, node: &PrivateKey, timestamp: u64) -> Option<Self> {
        let secret = node.shared_secret(hub)?;
        let tag = mac(hub, &node.public_key(), timestamp, secret.as_slice())
            .finalize()
            .into_bytes()
            .into();
        Some(Self {
            timestamp,
            tag: MacTag(tag),
        })
    }

    pub fn verify(&self, hub: &PrivateKey, node: &PublicKey, now: u64) -> bool {
        if now.abs_diff(self.timestamp) > MAX_PROOF_AGE {
            return false;
        }

        hub.shared_secret(node).is_some_and(|secret| {
            mac(&hub.public_key(), node, self.timestamp, secret.as_slice())
                .verify_slice(&self.tag.0)
                .is_ok()
        })
    }
}

fn mac(hub: &PublicKey, node: &PublicKey, timestamp: u64, secret: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(LABEL);
    mac.update(&hub.to_bytes());
    mac.update(&node.to_bytes());
    mac.update(timestamp.to_string().as_bytes());
    mac
}

#[derive(Clone, PartialEq, Eq)]
struct MacTag([u8; 32]);

impl fmt::Debug for MacTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacTag(..)")
    }
}

impl Serialize for MacTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for MacTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(encoded).map_err(de::Error::custom)?;
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| de::Error::custom("a proof tag is 32 bytes"))
    }
}
