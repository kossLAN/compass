use std::net::{IpAddr, Ipv6Addr};

use compass_config::LighthouseConfig;
use compass_net::{DeviceSpec, NetError, PeerSpec, Stun, Wireguard, plan_peers};
use compass_proto::{CONTROL_PREFIX, NodeId, PrivateKey, PublicKey};
use ipnet::{IpNet, Ipv6Net};

use crate::FWMARK;

pub struct Hub {
    wireguard: Wireguard,
    key: PublicKey,
    mtu: u16,
}

impl Hub {
    pub async fn start(config: &LighthouseConfig, key: &PrivateKey) -> Result<Self, NetError> {
        let wireguard = Wireguard::detect(&DeviceSpec {
            name: config.hub.interface.clone(),
            private_key: key.clone(),
            listen_port: config.hub.listen_port,
            fwmark: FWMARK,
        })
        .await?;
        tracing::info!(%wireguard, "using WireGuard for the hub");

        let mut hub = Self {
            wireguard,
            key: key.public_key(),
            mtu: config.network.mtu,
        };

        if let Err(error) = hub.sync(config).await {
            hub.stop().await;
            return Err(error);
        }

        Ok(hub)
    }

    pub const fn key(&self) -> PublicKey {
        self.key
    }

    pub fn address(&self) -> Ipv6Addr {
        NodeId::of(&self.key).control_address()
    }

    pub async fn sync(&mut self, config: &LighthouseConfig) -> Result<(), NetError> {
        let address = Ipv6Net::new_assert(self.address(), CONTROL_PREFIX.prefix_len());
        self.wireguard
            .ensure(self.mtu, &[IpNet::V6(address)])
            .await?;

        let peers: Vec<PeerSpec> = config
            .nodes
            .iter()
            .map(|(id, node)| PeerSpec {
                key: node.key,
                endpoint: None,
                allowed_ips: vec![IpNet::from(IpAddr::V6(id.control_address()))],
                keepalive: 0,
            })
            .collect();
        let ops = plan_peers(&peers, &self.wireguard.state().await?);
        self.wireguard.apply(&ops).await
    }

    pub fn stun(&self) -> Option<Stun> {
        self.wireguard.stun()
    }

    pub async fn stop(&mut self) {
        if let Err(error) = self.wireguard.delete().await {
            tracing::warn!(%error, "failed to delete the hub interface");
        }
    }
}
