use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt as _;
use ipnet::IpNet;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope,
};

use super::link::Links;
use super::{ESRCH, PROTOCOL, ignore_gone};
use crate::{NetError, RouteSpec};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    destination: IpNet,
    interface: u32,
    source: Option<IpAddr>,
    table: u32,
}

pub async fn sync(links: &Links, desired: &BTreeSet<RouteSpec>) -> Result<(), NetError> {
    let mut indices = BTreeMap::new();

    for route in desired {
        if !indices.contains_key(&route.device) {
            indices.insert(route.device.clone(), links.index(&route.device).await?);
        }
    }

    let wanted: BTreeSet<RouteKey> = desired
        .iter()
        .map(|route| RouteKey {
            destination: route.destination,
            interface: indices[&route.device],
            source: route.source,
            table: route.table,
        })
        .collect();

    let handle = links.handle();
    let mut present = BTreeSet::new();

    for message in owned(links).await? {
        let key = key_of(&message);

        if key.as_ref().is_some_and(|key| wanted.contains(key)) {
            present.extend(key);
        } else {
            let deleted = handle
                .route()
                .del(message)
                .execute()
                .await
                .map_err(NetError::rtnetlink);
            ignore_gone(deleted, ESRCH)?;
        }
    }

    for key in wanted.difference(&present) {
        handle
            .route()
            .add(build(key)?)
            .execute()
            .await
            .map_err(NetError::rtnetlink)?;
    }

    Ok(())
}

async fn owned(links: &Links) -> Result<Vec<RouteMessage>, NetError> {
    let mut routes = Vec::new();

    for query in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let messages: Vec<RouteMessage> = links
            .handle()
            .route()
            .get(query)
            .execute()
            .try_collect()
            .await
            .map_err(NetError::rtnetlink)?;
        routes.extend(
            messages
                .into_iter()
                .filter(|message| message.header.protocol == RouteProtocol::from(PROTOCOL)),
        );
    }

    Ok(routes)
}

fn key_of(message: &RouteMessage) -> Option<RouteKey> {
    let attributes = &message.attributes;

    let unspecified = match message.header.address_family {
        AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        AddressFamily::Inet6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => return None,
    };

    let destination = attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(v4)) => Some(IpAddr::V4(*v4)),
            RouteAttribute::Destination(RouteAddress::Inet6(v6)) => Some(IpAddr::V6(*v6)),
            _ => None,
        })
        .unwrap_or(unspecified);
    let interface = attributes.iter().find_map(|attribute| match attribute {
        RouteAttribute::Oif(index) => Some(*index),
        _ => None,
    })?;
    let source = attributes.iter().find_map(|attribute| match attribute {
        RouteAttribute::PrefSource(RouteAddress::Inet(v4)) => Some(IpAddr::V4(*v4)),
        RouteAttribute::PrefSource(RouteAddress::Inet6(v6)) => Some(IpAddr::V6(*v6)),
        _ => None,
    });
    let table = attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or_else(|| u32::from(message.header.table));
    Some(RouteKey {
        destination: IpNet::new(destination, message.header.destination_prefix_length).ok()?,
        interface,
        source,
        table,
    })
}

fn build(key: &RouteKey) -> Result<RouteMessage, NetError> {
    let invalid = |error| NetError::Protocol(format!("invalid route {}: {error}", key.destination));
    let mut builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(key.destination.addr(), key.destination.prefix_len())
        .map_err(invalid)?
        .output_interface(key.interface)
        .table_id(key.table)
        .protocol(RouteProtocol::from(PROTOCOL));

    if let Some(source) = key.source {
        builder = builder.pref_source(source).map_err(invalid)?;
    }

    if key.destination.addr().is_ipv4() {
        builder = builder.scope(RouteScope::Link);
    }

    Ok(builder.build())
}
