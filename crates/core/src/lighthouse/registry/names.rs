use std::collections::{BTreeMap, BTreeSet};

use compass_config::acl::{Compiled, NamePattern};
use compass_config::{KeyConfig, LighthouseConfig};
use compass_proto::{
    CnameTarget, DnsName, DnsRecord, MAX_LABEL_LEN, NodeId, RecordData, RecordKind, RecordState,
    RecordStatus, RejectReason,
};

use super::{Node, Registration};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    pub records: BTreeMap<NodeId, Vec<RecordStatus>>,
}

impl Names {
    pub fn resolve(
        nodes: &BTreeMap<NodeId, Node>,
        access: &Compiled,
        config: &LighthouseConfig,
    ) -> Self {
        let mut claims = Claims::default();
        let records = nodes
            .values()
            .map(|node| {
                let context = Context {
                    node,
                    nodes,
                    access,
                    config,
                    fqdn: node
                        .hostname
                        .join(&config.network.domain)
                        .expect("hostnames always fit under the mesh domain"),
                };
                let statuses = unique(&node.info.records)
                    .map(|record| {
                        let state = match context.check(record, &mut claims) {
                            Ok(()) => RecordState::Accepted,
                            Err(reason) => RecordState::Rejected(reason),
                        };

                        RecordStatus {
                            record: record.clone(),
                            state,
                        }
                    })
                    .collect();
                (node.id, statuses)
            })
            .collect();
        Self { records }
    }

    pub fn accepted(&self, id: NodeId) -> Vec<DnsRecord> {
        self.records
            .get(&id)
            .into_iter()
            .flatten()
            .filter(|status| status.state == RecordState::Accepted)
            .map(|status| status.record.clone())
            .collect()
    }
}

fn unique(records: &[DnsRecord]) -> impl Iterator<Item = &DnsRecord> {
    let mut seen = BTreeSet::new();
    records.iter().filter(move |record| seen.insert(*record))
}

pub fn hostnames(
    config: &LighthouseConfig,
    registrations: &BTreeMap<NodeId, Registration>,
) -> BTreeMap<NodeId, DnsName> {
    let mut held = BTreeSet::new();
    registrations
        .iter()
        .map(|(id, registration)| {
            let reserved = reserved_hostnames(config, &registration.key_name);
            let hostname = candidates(&registration.info.hostname, *id)
                .find(|candidate| !held.contains(candidate) && !reserved.contains(candidate))
                .expect("numbered candidates never run out");
            held.insert(hostname.clone());
            (*id, hostname)
        })
        .collect()
}

fn candidates(requested: &DnsName, id: NodeId) -> impl Iterator<Item = DnsName> {
    let hex = format!("{:016x}", id.0);
    [
        requested.clone(),
        suffixed(requested, &hex[..4]),
        suffixed(requested, &hex),
    ]
    .into_iter()
    .chain((2_u64..).map(move |n| suffixed(requested, &n.to_string())))
}

fn reserved_hostnames(config: &LighthouseConfig, own: &str) -> BTreeSet<DnsName> {
    let domain = &config.network.domain;
    let claimed = |key: &KeyConfig| -> BTreeSet<DnsName> {
        config
            .dns_names(key)
            .filter_map(|pattern| match pattern {
                NamePattern::Any | NamePattern::BelowHostname => None,
                NamePattern::Exact(name) | NamePattern::Below(name) => {
                    name.relative_to(domain)?.last_label().parse().ok()
                },
            })
            .collect()
    };
    let own_claims = config.keys.get(own).map(claimed).unwrap_or_default();
    config
        .keys
        .iter()
        .filter(|(name, _)| *name != own)
        .flat_map(|(_, key)| claimed(key))
        .filter(|hostname| !own_claims.contains(hostname))
        .collect()
}

fn suffixed(base: &DnsName, suffix: &str) -> DnsName {
    let suffix = format!("-{suffix}");
    let keep = base.as_str().len().min(MAX_LABEL_LEN - suffix.len());
    let stem = base.as_str()[..keep].trim_end_matches('-');
    format!("{stem}{suffix}")
        .parse()
        .expect("a truncated label with a suffix is valid")
}

#[derive(Default)]
struct Claims {
    names: BTreeMap<DnsName, (NodeId, BTreeSet<RecordKind>)>,
}

struct Context<'a> {
    node: &'a Node,
    nodes: &'a BTreeMap<NodeId, Node>,
    access: &'a Compiled,
    config: &'a LighthouseConfig,
    fqdn: DnsName,
}

impl Context<'_> {
    fn check(&self, record: &DnsRecord, claims: &mut Claims) -> Result<(), RejectReason> {
        let network = &self.config.network;
        let domain = &network.domain;
        let zone = record.zone.as_ref().unwrap_or(domain);

        if zone != domain && !network.zones.contains(zone) {
            return Err(RejectReason::UnknownZone);
        }

        let target_fits = match &record.data {
            RecordData::Cname(CnameTarget::Mesh(target)) => target.join(domain).is_ok(),
            _ => true,
        };

        let name = match record.fqdn(domain) {
            Ok(name) if target_fits => name,
            _ => return Err(RejectReason::TooLong),
        };

        let hostname = &self.node.hostname;
        let mesh_name = if zone == domain {
            record.name.as_ref()
        } else {
            None
        };

        if let Some(mesh_name) = mesh_name {
            if mesh_name == hostname {
                return Err(RejectReason::Reserved);
            }

            if self
                .nodes
                .values()
                .any(|other| other.id != self.node.id && mesh_name.is_at_or_under(&other.hostname))
            {
                return Err(RejectReason::OwnedByOther);
            }
        }

        let permitted = self
            .access
            .access(self.node.id)
            .is_some_and(|access| access.may_publish(&name, &self.fqdn));

        if !permitted {
            return Err(RejectReason::NotPermitted);
        }

        if !self.value_is_valid(&record.data) {
            return Err(RejectReason::InvalidValue);
        }

        let kind = record.kind();
        let (owner, kinds) = claims
            .names
            .entry(name)
            .or_insert_with(|| (self.node.id, BTreeSet::new()));

        if *owner != self.node.id {
            return Err(RejectReason::Taken);
        }

        let cname_conflict = if kind == RecordKind::Cname {
            !kinds.is_empty()
        } else {
            kinds.contains(&RecordKind::Cname)
        };

        if cname_conflict {
            return Err(RejectReason::CnameConflict);
        }

        kinds.insert(kind);
        Ok(())
    }

    fn value_is_valid(&self, data: &RecordData) -> bool {
        let network = &self.config.network;

        match data {
            RecordData::A(v4) => !network.ipv4.contains(v4) || self.node.addresses.v4 == *v4,
            RecordData::Aaaa(v6) => !network.ipv6.contains(v6) || self.node.addresses.v6 == *v6,
            RecordData::Cname(_) => true,
        }
    }
}
