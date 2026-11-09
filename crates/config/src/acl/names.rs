use compass_proto::{DnsError, DnsName};

const HOSTNAME: &str = "{hostname}";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NamePattern {
    Any,
    Exact(DnsName),
    Below(DnsName),
    BelowHostname,
}

impl NamePattern {
    pub fn matches(&self, name: &DnsName, fqdn: &DnsName) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(exact) => name == exact,
            Self::Below(parent) => name.is_under(parent),
            Self::BelowHostname => name.is_under(fqdn),
        }
    }

    /// Patterns with a trailing dot are absolute; the rest are relative to `domain`.
    pub fn parse(pattern: &str, domain: &DnsName) -> Result<Self, DnsError> {
        let pattern = pattern.trim();

        if pattern == "*" {
            return Ok(Self::Any);
        }

        let (below, name) = pattern
            .strip_prefix("*.")
            .map_or((false, pattern), |parent| (true, parent));

        if below && name == HOSTNAME {
            return Ok(Self::BelowHostname);
        }

        if name.contains(HOSTNAME) {
            return Err(DnsError::InvalidName {
                name: pattern.to_owned(),
                reason: "{hostname} only works as \"*.{hostname}\"",
            });
        }

        let name = match name.strip_suffix('.') {
            Some(absolute) => absolute.parse()?,
            None => name.parse::<DnsName>()?.join(domain)?,
        };

        Ok(if below {
            Self::Below(name)
        } else {
            Self::Exact(name)
        })
    }
}
