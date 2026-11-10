use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use compass_config::InterfaceConfig;
use compass_net::{
    Dataplane, DeviceSpec, Firewall, LocalAddress, NetError, NodeRules, RouteSpec, RuleSpec, Stun,
    Wireguard,
};
use compass_proto::{PrivateKey, PublicKey};
use ipnet::IpNet;

use super::{
    Backend, DataplaneError, ExitPlan, LocalNetworks, MeshPlan, Names, Plan, Platform, Stats,
    default_routes,
};
use crate::FWMARK;
use crate::client::dns::DnsService;
use crate::client::meshes::{Mesh, overlaps};

const MAIN_TABLE: u32 = 254;
const EXIT_TABLE: u32 = 5254;
const MAIN_PRIORITY: u32 = 5251;
const EXIT_PRIORITY: u32 = 5252;

pub struct LinuxPlatform {
    dataplane: Arc<Dataplane>,
}

impl LinuxPlatform {
    pub fn new() -> Result<Self, NetError> {
        Ok(Self {
            dataplane: Arc::new(Dataplane::new()?),
        })
    }
}

#[async_trait::async_trait]
impl Platform for LinuxPlatform {
    type Device = InterfaceConfig;

    async fn local_networks(&self, device: &InterfaceConfig) -> Option<LocalNetworks> {
        match self.dataplane.local_addresses().await {
            Ok(all) => Some(LocalNetworks {
                offered: local_networks(&all, &device.name, &device.exclude),
                attached: local_networks(&all, &device.name, &[]),
            }),
            Err(error) => {
                tracing::debug!(%error, "failed to list local addresses");
                None
            },
        }
    }

    async fn start(
        &self,
        device: &InterfaceConfig,
        key: &PrivateKey,
        listen_port: u16,
    ) -> Result<Box<dyn Backend>, DataplaneError> {
        let firewall = Firewall::detect().await?;
        tracing::info!(%firewall, "using firewall");

        let wireguard = Wireguard::detect(&DeviceSpec {
            name: device.name.clone(),
            private_key: key.clone(),
            listen_port,
            fwmark: FWMARK,
        })
        .await?;
        tracing::info!(%wireguard, "using WireGuard");

        Ok(Box::new(Linux::new(
            Arc::clone(&self.dataplane),
            firewall,
            wireguard,
            &device.name,
        )))
    }
}

pub struct Linux {
    dataplane: Arc<Dataplane>,
    firewall: Firewall,
    wireguard: Wireguard,
    interface: String,
    dns: DnsService,
    exit_warned: bool,
}

impl Linux {
    pub fn new(
        dataplane: Arc<Dataplane>,
        firewall: Firewall,
        wireguard: Wireguard,
        interface: &str,
    ) -> Self {
        Self {
            dataplane,
            firewall,
            wireguard,
            interface: interface.to_owned(),
            dns: DnsService::default(),
            exit_warned: false,
        }
    }

    async fn sync_peers(
        &mut self,
        plan: &Plan,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        let actual = self.wireguard.state().await?;
        let ops = plan.peer_ops(&actual, rehandshake);
        Ok(self.wireguard.apply(&ops).await?)
    }

    fn routes(&self, plan: &Plan) -> BTreeSet<RouteSpec> {
        let route = |destination, source, table| RouteSpec {
            source,
            destination,
            device: self.interface.clone(),
            table,
        };

        let mut covered: Vec<IpNet> = Vec::new();
        let mut routes: BTreeSet<RouteSpec> = plan
            .hubs
            .iter()
            .map(|hub| route(hub.address(), Some(IpAddr::V6(plan.control)), MAIN_TABLE))
            .collect();

        for mesh in &plan.meshes {
            for prefix in &mesh.prefixes {
                let Some(source) = mesh.source(prefix) else {
                    continue;
                };

                let destinations: Vec<IpNet> = if covered.iter().any(|net| overlaps(net, prefix)) {
                    mesh.peers
                        .iter()
                        .filter(|address| prefix.contains(*address))
                        .map(|address| IpNet::from(*address))
                        .collect()
                } else {
                    vec![*prefix]
                };

                for destination in destinations {
                    if !covered.contains(&destination) {
                        covered.push(destination);
                        routes.insert(route(destination, Some(source), MAIN_TABLE));
                    }
                }
            }
        }

        if let Some(exit) = &plan.exit {
            routes.extend(
                default_routes()
                    .into_iter()
                    .map(|net| route(net, exit.source(&net), EXIT_TABLE)),
            );
        }

        routes
    }
}

#[async_trait::async_trait]
impl Backend for Linux {
    async fn apply(
        &mut self,
        plan: &Plan,
        names: Option<Names<'_>>,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        self.firewall
            .apply(&plan.firewall(self.interface.clone()))
            .await?;
        self.wireguard.ensure(plan.mtu, &plan.addresses()).await?;
        self.sync_peers(plan, rehandshake).await?;
        self.dataplane.sync_routes(&self.routes(plan)).await?;
        self.dataplane.sync_rules(&plan.exit_rules()).await?;

        if let Some(names) = names {
            self.dns
                .update(
                    &self.dataplane,
                    &self.interface,
                    names.meshes,
                    names.lighthouses,
                )
                .await;
        }

        Ok(())
    }

    async fn stats(&mut self) -> Result<Stats, DataplaneError> {
        Ok(self.wireguard.state().await?.into())
    }

    async fn teardown(&mut self) {
        self.dns.stop(&self.dataplane, &self.interface).await;
        let deleted = self.wireguard.delete().await;

        if let Err(error) = &deleted {
            tracing::warn!(%error, "failed to delete the mesh interface");
        }

        if deleted.is_ok()
            && let Err(error) = self.firewall.remove().await
        {
            tracing::warn!(%error, "failed to remove firewall rules");
        }

        if let Err(error) = self.dataplane.remove_rules().await {
            tracing::warn!(%error, "failed to remove routing rules");
        }
    }

    fn stun(&self) -> Option<Stun> {
        self.wireguard.stun()
    }

    async fn check_exit_serving(&mut self, meshes: &[Mesh]) -> Result<(), DataplaneError> {
        let serving = meshes
            .iter()
            .any(|mesh| !mesh.netmap.exit_clients.is_empty());

        if self.exit_warned || !serving {
            return Ok(());
        }

        for (family, ipv6, key) in [
            ("IPv4", false, "net/ipv4/conf/all/forwarding"),
            ("IPv6", true, "net/ipv6/conf/all/forwarding"),
        ] {
            if meshes
                .iter()
                .flat_map(|mesh| &mesh.netmap.exit_clients)
                .any(|net| net.addr().is_ipv6() == ipv6)
                && self.dataplane.sysctl(key).await?.as_deref() != Some("1")
            {
                tracing::warn!("serving as an exit node, but {family} forwarding is disabled");
                self.exit_warned = true;
            }
        }

        Ok(())
    }
}

impl MeshPlan {
    fn source(&self, net: &IpNet) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == net.addr().is_ipv4())
    }
}

impl ExitPlan {
    fn source(&self, net: &IpNet) -> Option<IpAddr> {
        self.sources
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == net.addr().is_ipv4())
    }
}

impl Plan {
    fn firewall(&self, interface: String) -> NodeRules {
        NodeRules {
            interface,
            meshes: self.mesh_rules(),
            local_dns: self.local_dns,
        }
    }

    fn exit_rules(&self) -> BTreeSet<RuleSpec> {
        let mut rules = BTreeSet::new();

        if self.exit.is_none() {
            return rules;
        }

        for ipv6 in [false, true] {
            rules.insert(RuleSpec {
                priority: MAIN_PRIORITY,
                ipv6,
                table: MAIN_TABLE,
                destination: None,
                unless_fwmark: None,
                suppress_prefix_length: Some(0),
            });
            rules.insert(RuleSpec {
                priority: EXIT_PRIORITY,
                ipv6,
                table: EXIT_TABLE,
                destination: None,
                unless_fwmark: Some(FWMARK),
                suppress_prefix_length: None,
            });
        }

        rules
    }
}

fn local_networks(addresses: &[LocalAddress], interface: &str, exclude: &[String]) -> Vec<IpNet> {
    let mut networks: Vec<IpNet> = addresses
        .iter()
        .filter(|local| local.interface != "lo" && local.interface != interface)
        .filter(|local| {
            !exclude
                .iter()
                .any(|pattern| matches_glob(pattern, &local.interface))
        })
        .map(|local| local.address)
        .filter(|network| match network.addr() {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unicast_link_local(),
        })
        .collect();
    networks.sort_unstable();
    networks.dedup();
    networks
}

fn matches_glob(pattern: &str, name: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == name, |prefix| name.starts_with(prefix))
}
