use std::collections::BTreeSet;

use super::link::Links;
use super::{resolvconf, route, rule, sysctl};
use crate::{LinkDns, LocalAddress, NetError, RouteSpec, RuleSpec};

pub struct Dataplane {
    links: Links,
}

impl Dataplane {
    pub fn new() -> Result<Self, NetError> {
        Ok(Self {
            links: Links::connect()?,
        })
    }

    pub async fn sync_routes(&self, routes: &BTreeSet<RouteSpec>) -> Result<(), NetError> {
        route::sync(&self.links, routes).await
    }

    pub async fn sync_rules(&self, rules: &BTreeSet<RuleSpec>) -> Result<(), NetError> {
        rule::sync(&self.links, rules).await
    }

    pub async fn remove_rules(&self) -> Result<(), NetError> {
        rule::sync(&self.links, &BTreeSet::new()).await
    }

    pub async fn set_dns(&self, device: &str, dns: Option<&LinkDns>) -> Result<(), NetError> {
        match dns {
            Some(dns) => resolvconf::configure(device, dns).await,
            None => resolvconf::remove(device).await,
        }
    }

    pub async fn sysctl(&self, key: &str) -> Result<Option<String>, NetError> {
        sysctl::read(key).await
    }

    pub async fn local_addresses(&self) -> Result<Vec<LocalAddress>, NetError> {
        let names = self.links.names().await?;
        Ok(self
            .links
            .addresses()
            .await?
            .into_iter()
            .filter_map(|(index, address)| {
                let interface = names.get(&index)?.clone();
                Some(LocalAddress { interface, address })
            })
            .collect())
    }
}
