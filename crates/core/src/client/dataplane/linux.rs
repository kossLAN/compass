use std::collections::BTreeSet;
use std::sync::Arc;

use compass_config::InterfaceConfig;
use compass_net::{Dataplane, Firewall, PeerOp, PeerSpec, RouteSpec, Stun, Wireguard, plan_peers};
use compass_proto::PublicKey;
use ipnet::IpNet;

use super::{
    Backend, Counters, DataplaneError, EXIT_TABLE, KEEPALIVE, MAIN_TABLE, Path, Plan, Stats,
    default_routes,
};

pub struct Linux {
    dataplane: Arc<Dataplane>,
    firewall: Firewall,
    wireguard: Wireguard,
    interface: InterfaceConfig,
}

impl Linux {
    pub fn new(
        dataplane: Arc<Dataplane>,
        firewall: Firewall,
        wireguard: Wireguard,
        interface: &InterfaceConfig,
    ) -> Self {
        Self {
            dataplane,
            firewall,
            wireguard,
            interface: interface.clone(),
        }
    }

    async fn sync_peers(
        &mut self,
        plan: &Plan,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        let exit_peer = plan.exit_peer();
        let desired: Vec<PeerSpec> = plan
            .peers
            .iter()
            .map(|peer| {
                let mut allowed_ips: Vec<IpNet> =
                    peer.addresses.iter().copied().map(IpNet::from).collect();

                if exit_peer == Some(peer.key) {
                    allowed_ips.extend(default_routes());
                }

                let endpoint = match peer.path {
                    Path::Direct(endpoint) => Some(endpoint),
                    Path::Relay(_) | Path::None => peer.proxy,
                };

                PeerSpec {
                    key: peer.key,
                    endpoint,
                    allowed_ips,
                    keepalive: if peer.keepalive { KEEPALIVE } else { 0 },
                }
            })
            .collect();

        let actual = self.wireguard.state().await?;
        let mut ops: Vec<PeerOp> = plan_peers(&desired, &actual)
            .into_iter()
            .filter(|op| !matches!(op, PeerOp::Upsert(spec) if rehandshake.contains(&spec.key)))
            .collect();

        for spec in desired
            .iter()
            .filter(|spec| rehandshake.contains(&spec.key))
        {
            ops.push(PeerOp::Remove(spec.key));
            ops.push(PeerOp::Upsert(spec.clone()));
        }

        Ok(self.wireguard.apply(&ops).await?)
    }

    fn routes(&self, plan: &Plan) -> BTreeSet<RouteSpec> {
        let route = |destination, source, table| RouteSpec {
            source,
            destination,
            device: self.interface.name.clone(),
            table,
        };

        let mut covered: Vec<IpNet> = Vec::new();
        let mut routes = BTreeSet::new();

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

fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[async_trait::async_trait]
impl Backend for Linux {
    async fn apply(
        &mut self,
        plan: &Plan,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        self.firewall
            .apply(&plan.firewall(self.interface.name.clone()))
            .await?;
        self.wireguard.ensure(plan.mtu, &plan.addresses()).await?;
        self.sync_peers(plan, rehandshake).await?;
        self.dataplane.sync_routes(&self.routes(plan)).await?;
        self.dataplane.sync_rules(&plan.exit_rules()).await?;
        Ok(())
    }

    async fn stats(&mut self) -> Result<Stats, DataplaneError> {
        let device = self.wireguard.state().await?;
        let peers = device
            .peers
            .into_iter()
            .map(|(key, peer)| {
                let counters = Counters {
                    last_handshake: peer.last_handshake,
                    rx_bytes: peer.rx_bytes,
                    tx_bytes: peer.tx_bytes,
                };
                (key, counters)
            })
            .collect();
        Ok(Stats { peers })
    }

    async fn teardown(&mut self) {
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

    fn interface(&self) -> &str {
        &self.interface.name
    }

    fn stun(&self) -> Option<Stun> {
        self.wireguard.stun()
    }
}
