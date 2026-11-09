use std::collections::{BTreeMap, BTreeSet};

use compass_proto::{DnsName, PortRange, Proto};
use serde::Deserialize;

use crate::acl::selector::validate_name;
use crate::acl::{AclError, NamePattern, Selector, Tag};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub src: Vec<Selector>,
    #[serde(default)]
    pub dst: Vec<Selector>,
    #[serde(default)]
    pub proto: Option<Proto>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub src: Vec<Selector>,
    pub dst: Vec<Selector>,
    pub protos: Vec<Proto>,
    pub ports: Vec<PortRange>,
    pub dns: Vec<NamePattern>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    groups: BTreeMap<String, BTreeSet<String>>,
    rules: Vec<Rule>,
}

impl Policy {
    pub fn new(
        groups: BTreeMap<String, Vec<String>>,
        rules: Vec<RuleConfig>,
        domain: &DnsName,
    ) -> Result<Self, AclError> {
        let groups = groups
            .into_iter()
            .map(|(name, members)| validate_group(name, members))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let rules = rules
            .into_iter()
            .enumerate()
            .map(|(index, rule)| validate_rule(&groups, domain, index, rule))
            .collect::<Result<_, _>>()?;
        Ok(Self { groups, rules })
    }

    pub(crate) fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn referenced_tags(&self) -> BTreeSet<&Tag> {
        self.rules
            .iter()
            .flat_map(|rule| rule.src.iter().chain(&rule.dst))
            .filter_map(|selector| match selector {
                Selector::Tag(tag) => Some(tag),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn dns_names<'a>(
        &'a self,
        owner: Option<&'a str>,
        tags: &'a [Tag],
    ) -> impl Iterator<Item = &'a NamePattern> {
        self.rules
            .iter()
            .filter(move |rule| rule.src.iter().any(|s| self.matches(s, owner, tags)))
            .flat_map(|rule| &rule.dns)
    }

    pub(crate) fn matches(&self, selector: &Selector, owner: Option<&str>, tags: &[Tag]) -> bool {
        match selector {
            Selector::All => true,
            Selector::User(user) => owner == Some(user.as_str()),
            Selector::Group(group) => {
                owner.is_some_and(|owner| self.groups.get(group).is_some_and(|m| m.contains(owner)))
            },
            Selector::Tag(tag) => tags.contains(tag),
            Selector::Internet => false,
        }
    }
}

fn validate_group(
    name: String,
    members: Vec<String>,
) -> Result<(String, BTreeSet<String>), AclError> {
    if !validate_name(&name) {
        return Err(AclError::InvalidGroupName(name));
    }

    let members = members
        .into_iter()
        .map(|member| match member.parse() {
            Ok(Selector::User(user)) => Ok(user),
            _ => Err(AclError::InvalidMember {
                group: name.clone(),
                member,
            }),
        })
        .collect::<Result<_, _>>()?;
    Ok((name, members))
}

fn validate_rule(
    groups: &BTreeMap<String, BTreeSet<String>>,
    domain: &DnsName,
    index: usize,
    rule: RuleConfig,
) -> Result<Rule, AclError> {
    let invalid = |reason| AclError::InvalidRule { index, reason };

    if rule.src.is_empty() {
        return Err(invalid("src must not be empty"));
    }

    if rule.dst.is_empty() && rule.dns.is_empty() {
        return Err(invalid("rules need a dst, dns or both"));
    }

    if rule.dst.is_empty() && (rule.proto.is_some() || !rule.ports.is_empty()) {
        return Err(invalid("proto and ports need a dst"));
    }

    for selector in rule.src.iter().chain(&rule.dst) {
        if let Selector::Group(group) = selector
            && !groups.contains_key(group)
        {
            return Err(AclError::UnknownGroup(group.clone()));
        }
    }

    if rule.src.contains(&Selector::Internet) {
        return Err(invalid("autogroup:internet can only be a destination"));
    }

    if rule.dst.contains(&Selector::Internet) && (rule.proto.is_some() || !rule.ports.is_empty()) {
        return Err(invalid(
            "rules for autogroup:internet cannot limit protocols or ports",
        ));
    }

    let protos = match (rule.proto, rule.ports.is_empty()) {
        (Some(Proto::Icmp), false) => return Err(invalid("icmp rules cannot have ports")),
        (Some(proto), _) => vec![proto],
        (None, false) => vec![Proto::Tcp, Proto::Udp],
        (None, true) => Vec::new(),
    };

    let dns = rule
        .dns
        .iter()
        .map(|pattern| NamePattern::parse(pattern, domain))
        .collect::<Result<_, _>>()
        .map_err(|error| AclError::InvalidName { index, error })?;

    Ok(Rule {
        src: rule.src,
        dst: rule.dst,
        protos,
        ports: rule.ports,
        dns,
    })
}
