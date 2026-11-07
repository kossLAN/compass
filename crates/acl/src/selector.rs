use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

use crate::AclError;

const TAG_PREFIX: &str = "tag:";
const GROUP_PREFIX: &str = "group:";
const INTERNET: &str = "autogroup:internet";

pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(String);

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Tag {
    type Err = AclError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_prefix(TAG_PREFIX) {
            Some(name) if validate_name(name) => Ok(Self(s.to_owned())),
            _ => Err(AclError::InvalidSelector(
                s.to_owned(),
                "tags look like \"tag:web\"",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Selector {
    All,
    User(String),
    Group(String),
    Tag(Tag),
    Internet,
}

impl FromStr for Selector {
    type Err = AclError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason| AclError::InvalidSelector(s.to_owned(), reason);

        if s == "*" {
            Ok(Self::All)
        } else if s == INTERNET {
            Ok(Self::Internet)
        } else if s.starts_with(TAG_PREFIX) {
            s.parse().map(Self::Tag)
        } else if let Some(group) = s.strip_prefix(GROUP_PREFIX) {
            if validate_name(group) {
                Ok(Self::Group(group.to_owned()))
            } else {
                Err(invalid(
                    "group names use letters, digits, '-', '_', '.' and '@'",
                ))
            }
        } else if validate_name(s) {
            Ok(Self::User(s.to_owned()))
        } else {
            Err(invalid(
                "expected \"*\", a user, \"group:<name>\", \"tag:<name>\" or \"autogroup:internet\"",
            ))
        }
    }
}

impl<'de> Deserialize<'de> for Selector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}
