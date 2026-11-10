use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key is not valid base64")]
    Encoding,
    #[error("key must be {KEY_LEN} bytes")]
    Length,
}

fn decode(encoded: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    let bytes = Zeroizing::new(
        BASE64_STANDARD
            .decode(encoded.trim())
            .map_err(|_| KeyError::Encoding)?,
    );
    let mut key = Zeroizing::new([0; KEY_LEN]);

    if bytes.len() != KEY_LEN {
        return Err(KeyError::Length);
    }

    key.copy_from_slice(&bytes);
    Ok(key)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64_STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode(s).map(|key| Self(*key))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        encoded.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone)]
pub struct PrivateKey(StaticSecret);

impl PrivateKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random())
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, KeyError> {
        decode(encoded).map(|key| Self::from_bytes(*key))
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64_STANDARD.encode(self.0.as_bytes()))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key() == other.public_key()
    }
}

impl Eq for PrivateKey {}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey(public: {})", self.public_key())
    }
}
