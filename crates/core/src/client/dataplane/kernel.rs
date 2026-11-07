use std::collections::BTreeSet;
use std::sync::Arc;

use bunnyhop_config::InterfaceConfig;
use bunnyhop_net::{Dataplane, DeviceSpec, PeerOp, PeerSpec, RouteSpec, StunSocket, plan_peers};
use bunnyhop_proto::{PrivateKey, PublicKey};

use super::{
    Backend, Counters, DataplaneError, EXIT_TABLE, FWMARK, KEEPALIVE, MAIN_TABLE, Path, Plan,
    Stats, Stun, default_routes,
};

pub struct Kernel {
    dataplane: Arc<Dataplane>,
    interface: InterfaceConfig,
    key: PrivateKey,
    stun: Option<Arc<dyn Stun>>,
}

impl Kernel {
    pub fn new(
        dataplane: Arc<Dataplane>,
        interface: &InterfaceConfig,
        key: &PrivateKey,
        stun: Option<StunSocket>,
    ) -> Self {
        Self {
            dataplane,
            interface: interface.clone(),
            key: key.clone(),
            stun: stun.map(|stun| Arc::new(stun) as Arc<dyn Stun>),
        }
    }

    fn device(&self, plan: &Plan) -> DeviceSpec {
        DeviceSpec {
            name: self.interface.name.clone(),
            private_key: self.key.clone(),
            listen_port: Some(self.interface.listen_port),
            mtu: plan.mtu,
            addresses: plan.addresses.host_nets(),
            fwmark: FWMARK,
        }
    }

    async fn sync_peers(
        &self,
        plan: &Plan,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        let exit_peer = plan.exit_peer();
        let desired: Vec<PeerSpec> = plan
            .peers
            .iter()
            .map(|peer| {
                let mut allowed_ips = peer.addresses.host_nets();

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

        let device = &self.interface.name;
        let actual = self.dataplane.device(device).await?;
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

        Ok(self.dataplane.apply_peers(device, &ops).await?)
    }

    fn routes(&self, plan: &Plan) -> BTreeSet<RouteSpec> {
        let route = |destination, table| RouteSpec {
            source: Some(plan.source(&destination)),
            destination,
            device: self.interface.name.clone(),
            table,
        };

        let mut routes: BTreeSet<RouteSpec> = plan
            .prefixes
            .iter()
            .map(|prefix| route(*prefix, MAIN_TABLE))
            .collect();

        if plan.exit.is_some() {
            routes.extend(
                default_routes()
                    .into_iter()
                    .map(|net| route(net, EXIT_TABLE)),
            );
        }

        routes
    }
}

#[async_trait::async_trait]
impl Backend for Kernel {
    async fn apply(
        &mut self,
        plan: &Plan,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        self.dataplane
            .apply_firewall(&plan.firewall(self.interface.name.clone()))
            .await?;
        self.dataplane.ensure_device(&self.device(plan)).await?;
        self.sync_peers(plan, rehandshake).await?;
        self.dataplane.sync_routes(&self.routes(plan)).await?;
        self.dataplane.sync_rules(&plan.exit_rules()).await?;
        Ok(())
    }

    async fn stats(&mut self) -> Result<Stats, DataplaneError> {
        let device = self.dataplane.device(&self.interface.name).await?;
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
        let deleted = self.dataplane.delete_device(&self.interface.name).await;

        if let Err(error) = &deleted {
            tracing::warn!(%error, "failed to delete the mesh interface");
        }

        if deleted.is_ok()
            && let Err(error) = self.dataplane.remove_firewall().await
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

    fn stun(&self) -> Option<Arc<dyn Stun>> {
        self.stun.clone()
    }
}
