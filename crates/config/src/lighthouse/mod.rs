mod raw;

pub use self::raw::RawLighthouseConfig;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use compass_proto::{MAX_LABEL_LEN, MAX_NAME_LEN, Network, PublicKey, SecretHash};
use jiff::{Span, SpanRelativeTo};

use self::raw::{RawApi, RawHub, RawKey, RawNetwork, RawNodes};
use crate::ConfigError;
use crate::acl::{NamePattern, Policy, Selector, Tag};
use crate::secret::read_secret;

const MIN_SECRET_LEN: usize = 32;
const MAX_DOMAIN_LEN: usize = MAX_NAME_LEN - MAX_LABEL_LEN - 1;

#[derive(Debug, Clone)]
pub struct LighthouseConfig {
    pub api: ApiConfig,
    pub network: Network,
    pub hub: HubConfig,
    pub nodes: NodesConfig,
    pub keys: BTreeMap<String, KeyConfig>,
    pub policy: Policy,
}

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct HubConfig {
    pub listen_port: u16,
    pub endpoint: String,
    pub private_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct NodesConfig {
    pub revoked: BTreeSet<PublicKey>,
}

#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub secret: SecretHash,
    pub owner: Option<String>,
    pub tags: Vec<Tag>,
    pub offline_ttl: Duration,
    pub exit_node: bool,
}

impl LighthouseConfig {
    pub fn startup_setting_changed(&self, new: &Self) -> Option<&'static str> {
        let without_zones = |network: &Network| Network {
            zones: Vec::new(),
            ..network.clone()
        };

        [
            ("lighthouse.api.listen", self.api.listen != new.api.listen),
            (
                "lighthouse.api.tls_cert_file",
                self.api.tls.is_some() != new.api.tls.is_some(),
            ),
            (
                "lighthouse.network",
                without_zones(&self.network) != without_zones(&new.network),
            ),
            (
                "lighthouse.hub.listen_port",
                self.hub.listen_port != new.hub.listen_port,
            ),
            (
                "lighthouse.hub.private_key_file",
                self.hub.private_key_file != new.hub.private_key_file,
            ),
        ]
        .into_iter()
        .find_map(|(setting, changed)| changed.then_some(setting))
    }

    pub(crate) fn from_raw(raw: RawLighthouseConfig) -> Result<Self, ConfigError> {
        let default_ttl = parse_ttl("lighthouse.nodes.offline_ttl", &raw.nodes.offline_ttl)?;
        let nodes = NodesConfig::from_raw(raw.nodes);
        let network = network_from_raw(raw.network)?;
        let keys = raw
            .keys
            .into_iter()
            .map(|(name, key)| {
                let key = KeyConfig::from_raw(&name, key, default_ttl)?;
                Ok((name, key))
            })
            .collect::<Result<BTreeMap<_, _>, ConfigError>>()?;
        ensure_unique_secrets(&keys)?;
        let policy = Policy::new(raw.groups, raw.acl, &network.domain)?;

        Ok(Self {
            api: ApiConfig::from_raw(raw.api)?,
            network,
            hub: HubConfig::from_raw(raw.hub)?,
            nodes,
            keys,
            policy,
        })
    }

    pub fn find_key(&self, secret: &SecretHash) -> Option<(&str, &KeyConfig)> {
        self.keys
            .iter()
            .find(|(_, key)| key.secret == *secret)
            .map(|(name, key)| (name.as_str(), key))
    }

    pub fn dns_names<'a>(&'a self, key: &'a KeyConfig) -> impl Iterator<Item = &'a NamePattern> {
        self.policy.dns_names(key.owner.as_deref(), &key.tags)
    }

    pub fn unknown_tags(&self) -> Vec<&Tag> {
        let granted: BTreeSet<&Tag> = self.keys.values().flat_map(|key| &key.tags).collect();
        self.policy
            .referenced_tags()
            .into_iter()
            .filter(|tag| !granted.contains(tag))
            .collect()
    }
}

fn ensure_unique_secrets(keys: &BTreeMap<String, KeyConfig>) -> Result<(), ConfigError> {
    let mut seen = BTreeMap::new();

    for (name, key) in keys {
        if let Some(other) = seen.insert(key.secret, name) {
            return Err(ConfigError::invalid(
                format!("lighthouse.keys.{name}"),
                format!("shares its secret with lighthouse.keys.{other}"),
            ));
        }
    }

    Ok(())
}

impl ApiConfig {
    fn from_raw(raw: RawApi) -> Result<Self, ConfigError> {
        let tls = match (raw.tls_cert_file, raw.tls_key_file) {
            (Some(cert_file), Some(key_file)) => Some(TlsConfig {
                cert_file,
                key_file,
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::invalid(
                    "lighthouse.api",
                    "tls_cert_file and tls_key_file must be set together",
                ));
            },
        };

        Ok(Self {
            listen: raw.listen,
            tls,
        })
    }
}

fn network_from_raw(raw: RawNetwork) -> Result<Network, ConfigError> {
    if raw.domain.as_str().len() > MAX_DOMAIN_LEN {
        return Err(ConfigError::invalid(
            "lighthouse.network.domain",
            format!("must be at most {MAX_DOMAIN_LEN} characters, so every hostname fits"),
        ));
    }

    if raw.ipv4.prefix_len() > 30 {
        return Err(ConfigError::invalid(
            "lighthouse.network.ipv4",
            "prefix length must be at most 30",
        ));
    }

    if !(16..=126).contains(&raw.ipv6.prefix_len()) {
        return Err(ConfigError::invalid(
            "lighthouse.network.ipv6",
            "prefix length must be 16 to 126",
        ));
    }

    let network = Network {
        domain: raw.domain,
        zones: raw.zones,
        ipv4: raw.ipv4.trunc(),
        ipv6: raw.ipv6.trunc(),
        mtu: raw.mtu,
    };
    network
        .check()
        .map_err(|error| ConfigError::invalid("lighthouse.network", error.to_string()))?;
    Ok(network)
}

impl HubConfig {
    fn from_raw(raw: RawHub) -> Result<Self, ConfigError> {
        if raw.listen_port == 0 {
            return Err(ConfigError::invalid(
                "lighthouse.hub.listen_port",
                "must not be 0",
            ));
        }

        let has_port = raw.endpoint.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0)
        });

        if !has_port {
            return Err(ConfigError::invalid(
                "lighthouse.hub.endpoint",
                "expected \"host:port\"",
            ));
        }

        Ok(Self {
            listen_port: raw.listen_port,
            endpoint: raw.endpoint,
            private_key_file: raw.private_key_file,
        })
    }
}

impl NodesConfig {
    fn from_raw(raw: RawNodes) -> Self {
        Self {
            revoked: raw.revoked.into_iter().collect(),
        }
    }
}

fn parse_ttl(field: impl Into<String>, raw: &str) -> Result<Duration, ConfigError> {
    let duration = raw
        .parse::<Span>()
        .and_then(|span| span.to_duration(SpanRelativeTo::days_are_24_hours()))
        .ok()
        .and_then(|duration| Duration::try_from(duration).ok())
        .filter(|duration| !duration.is_zero());
    duration.ok_or_else(|| {
        ConfigError::invalid(
            field,
            "expected a duration longer than zero, like \"10m\", \"12h\" or \"30d\"",
        )
    })
}

impl KeyConfig {
    fn from_raw(name: &str, raw: RawKey, default_ttl: Duration) -> Result<Self, ConfigError> {
        let field = |suffix: &str| format!("lighthouse.keys.{name}{suffix}");
        let valid_name = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));

        if name.is_empty() || !valid_name {
            return Err(ConfigError::invalid(
                field(""),
                "use letters, digits, '-' and '_'",
            ));
        }

        let secret = read_secret(&raw.secret_file)?;

        if secret.len() < MIN_SECRET_LEN {
            return Err(ConfigError::invalid(
                field(".secret_file"),
                format!("secret must be at least {MIN_SECRET_LEN} characters"),
            ));
        }

        if let Some(owner) = &raw.owner
            && !matches!(owner.parse(), Ok(Selector::User(_)))
        {
            return Err(ConfigError::invalid(
                field(".owner"),
                format!("\"{owner}\" is not a user"),
            ));
        }

        let offline_ttl = match &raw.offline_ttl {
            Some(ttl) => parse_ttl(field(".offline_ttl"), ttl)?,
            None => default_ttl,
        };

        Ok(Self {
            secret: SecretHash::of(secret.as_bytes()),
            owner: raw.owner,
            tags: raw.tags,
            offline_ttl,
            exit_node: raw.exit_node,
        })
    }
}
