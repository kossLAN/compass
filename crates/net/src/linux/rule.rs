use std::collections::BTreeSet;

use futures_util::TryStreamExt as _;
use ipnet::IpNet;
use rtnetlink::IpVersion;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::RouteProtocol;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};

use super::link::Links;
use super::{ENOENT, PROTOCOL, ignore_gone};
use crate::{NetError, RuleSpec};

pub async fn sync(links: &Links, desired: &BTreeSet<RuleSpec>) -> Result<(), NetError> {
    let handle = links.handle();
    let mut present = BTreeSet::new();

    for message in owned(links).await? {
        let spec = spec_of(&message);

        if desired.contains(&spec) {
            present.insert(spec);
        } else {
            let deleted = handle
                .rule()
                .del(message)
                .execute()
                .await
                .map_err(NetError::rtnetlink);
            ignore_gone(deleted, ENOENT)?;
        }
    }

    for spec in desired.difference(&present) {
        let mut request = handle.rule().add();
        *request.message_mut() = build(spec);
        request.execute().await.map_err(NetError::rtnetlink)?;
    }

    Ok(())
}

async fn owned(links: &Links) -> Result<Vec<RuleMessage>, NetError> {
    let mut rules = Vec::new();

    for version in [IpVersion::V4, IpVersion::V6] {
        let messages: Vec<RuleMessage> = links
            .handle()
            .rule()
            .get(version)
            .execute()
            .try_collect()
            .await
            .map_err(NetError::rtnetlink)?;
        rules.extend(messages.into_iter().filter(|message| {
            message
                .attributes
                .contains(&RuleAttribute::Protocol(RouteProtocol::from(PROTOCOL)))
        }));
    }

    Ok(rules)
}

fn spec_of(message: &RuleMessage) -> RuleSpec {
    let mut spec = RuleSpec {
        priority: 0,
        ipv6: message.header.family == AddressFamily::Inet6,
        table: u32::from(message.header.table),
        destination: None,
        unless_fwmark: None,
        suppress_prefix_length: None,
    };

    for attribute in &message.attributes {
        match attribute {
            RuleAttribute::Priority(priority) => spec.priority = *priority,
            RuleAttribute::Table(table) => spec.table = *table,
            RuleAttribute::Destination(address) => {
                spec.destination = IpNet::new(*address, message.header.dst_len).ok();
            },
            RuleAttribute::FwMark(mark) if message.header.flags.contains(RuleFlags::Invert) => {
                spec.unless_fwmark = Some(*mark);
            },
            RuleAttribute::SuppressPrefixLen(length) => {
                spec.suppress_prefix_length = u8::try_from(*length).ok();
            },
            _ => {},
        }
    }

    spec
}

fn build(spec: &RuleSpec) -> RuleMessage {
    let mut message = RuleMessage::default();

    message.header.family = if spec.ipv6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };

    message.header.action = RuleAction::ToTable;
    message.attributes = vec![
        RuleAttribute::Priority(spec.priority),
        RuleAttribute::Table(spec.table),
        RuleAttribute::Protocol(RouteProtocol::from(PROTOCOL)),
    ];

    if let Some(destination) = spec.destination {
        message.header.dst_len = destination.prefix_len();
        message
            .attributes
            .push(RuleAttribute::Destination(destination.addr()));
    }

    if let Some(mark) = spec.unless_fwmark {
        message.header.flags.insert(RuleFlags::Invert);
        message.attributes.push(RuleAttribute::FwMark(mark));
    }

    if let Some(length) = spec.suppress_prefix_length {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::from(length)));
    }

    message
}
