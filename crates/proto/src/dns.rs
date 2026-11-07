use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const MAX_NAME_LEN: usize = 253;
pub const MAX_LABEL_LEN: usize = 63;
pub const DNS_PORT: u16 = 53;
pub const APEX: &str = "@";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("invalid DNS name \"{name}\": {reason}")]
    InvalidName { name: String, reason: &'static str },
    #[error("invalid {kind} record value \"{value}\"")]
    InvalidValue { kind: RecordKind, value: String },
    #[error("unknown record type \"{0}\"; expected A, AAAA or CNAME")]
    UnknownKind(String),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

impl DnsName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_label(&self) -> bool {
        !self.0.contains('.')
    }

    pub fn is_under(&self, parent: &Self) -> bool {
        self.0
            .strip_suffix(parent.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'))
    }

    pub fn is_at_or_under(&self, parent: &Self) -> bool {
        self == parent || self.is_under(parent)
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.is_at_or_under(other) || other.is_at_or_under(self)
    }

    pub fn relative_to(&self, parent: &Self) -> Option<Self> {
        let prefix = self.0.strip_suffix(parent.as_str())?.strip_suffix('.')?;
        Some(Self(prefix.to_owned()))
    }

    pub fn last_label(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    pub fn join(&self, suffix: &Self) -> Result<Self, DnsError> {
        format!("{self}.{suffix}").parse()
    }

    pub fn sanitize_label(raw: &str) -> Option<Self> {
        let first = raw
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let replaced: String = first
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .take(MAX_LABEL_LEN)
            .collect();
        replaced.trim_matches('-').parse().ok()
    }
}

fn validate_label(name: &str, label: &str) -> Result<(), DnsError> {
    let invalid = |reason| DnsError::InvalidName {
        name: name.to_owned(),
        reason,
    };

    if label.is_empty() {
        return Err(invalid("empty label"));
    }

    if label.len() > MAX_LABEL_LEN {
        return Err(invalid("label longer than 63 characters"));
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(invalid("label starts or ends with a hyphen"));
    }

    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid("only letters, digits and hyphens are allowed"));
    }

    Ok(())
}

impl FromStr for DnsName {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().trim_end_matches('.').to_ascii_lowercase();

        if name.len() > MAX_NAME_LEN {
            return Err(DnsError::InvalidName {
                name,
                reason: "longer than 253 characters",
            });
        }

        name.split('.')
            .try_for_each(|label| validate_label(&name, label))?;
        Ok(Self(name))
    }
}

impl TryFrom<String> for DnsName {
    type Error = DnsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<DnsName> for String {
    fn from(name: DnsName) -> Self {
        name.0
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({})", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CnameTarget {
    Mesh(DnsName),
    External(DnsName),
}

impl FromStr for CnameTarget {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        s.strip_suffix('.').map_or_else(
            || s.parse().map(Self::Mesh),
            |absolute| absolute.parse().map(Self::External),
        )
    }
}

impl fmt::Display for CnameTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mesh(name) => write!(f, "{name}"),
            Self::External(name) => write!(f, "{name}."),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum RecordKind {
    A,
    Aaaa,
    Cname,
}

impl RecordKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordKind {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "CNAME" => Ok(Self::Cname),
            _ => Err(DnsError::UnknownKind(s.to_owned())),
        }
    }
}

impl TryFrom<String> for RecordKind {
    type Error = DnsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<RecordKind> for String {
    fn from(kind: RecordKind) -> Self {
        kind.as_str().to_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(CnameTarget),
}

impl RecordData {
    pub fn parse(kind: RecordKind, value: &str) -> Result<Self, DnsError> {
        let invalid = || DnsError::InvalidValue {
            kind,
            value: value.to_owned(),
        };

        match kind {
            RecordKind::A => value.trim().parse().map(Self::A).map_err(|_| invalid()),
            RecordKind::Aaaa => value.trim().parse().map(Self::Aaaa).map_err(|_| invalid()),
            RecordKind::Cname => value.parse().map(Self::Cname).map_err(|_| invalid()),
        }
    }

    pub const fn kind(&self) -> RecordKind {
        match self {
            Self::A(_) => RecordKind::A,
            Self::Aaaa(_) => RecordKind::Aaaa,
            Self::Cname(_) => RecordKind::Cname,
        }
    }
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(address) => write!(f, "{address}"),
            Self::Aaaa(address) => write!(f, "{address}"),
            Self::Cname(target) => write!(f, "{target}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RecordRepr", into = "RecordRepr")]
pub struct DnsRecord {
    /// `None` is the mesh domain.
    pub zone: Option<DnsName>,
    /// `None` is the zone's apex.
    pub name: Option<DnsName>,
    pub data: RecordData,
}

impl DnsRecord {
    pub const fn kind(&self) -> RecordKind {
        self.data.kind()
    }

    pub fn fqdn(&self, domain: &DnsName) -> Result<DnsName, DnsError> {
        let zone = self.zone.as_ref().unwrap_or(domain);
        self.name
            .as_ref()
            .map_or_else(|| Ok(zone.clone()), |name| name.join(zone))
    }

    pub fn owner(&self) -> String {
        match (&self.zone, &self.name) {
            (None, Some(name)) => name.to_string(),
            (None, None) => APEX.to_owned(),
            (Some(zone), Some(name)) => format!("{name}.{zone}."),
            (Some(zone), None) => format!("{zone}."),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRepr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zone: Option<DnsName>,
    name: String,
    #[serde(rename = "type")]
    kind: RecordKind,
    value: String,
}

impl TryFrom<RecordRepr> for DnsRecord {
    type Error = DnsError;

    fn try_from(repr: RecordRepr) -> Result<Self, Self::Error> {
        let name = match repr.name.trim() {
            APEX => None,
            name => Some(name.parse()?),
        };
        let data = RecordData::parse(repr.kind, &repr.value)?;
        Ok(Self {
            zone: repr.zone,
            name,
            data,
        })
    }
}

impl From<DnsRecord> for RecordRepr {
    fn from(record: DnsRecord) -> Self {
        Self {
            kind: record.kind(),
            value: record.data.to_string(),
            name: record.name.map_or_else(|| APEX.to_owned(), String::from),
            zone: record.zone,
        }
    }
}
