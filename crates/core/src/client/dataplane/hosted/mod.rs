mod host;
mod local;
mod resolver;

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use compass_net::{AsyncDevice, NetError, Stun, Tun, UserspaceDevice};
use compass_proto::{DnsName, PrivateKey, PublicKey};
use ipnet::IpNet;
use reqwest::Certificate;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use self::local::{Local, Resolver};
use super::{Backend, DataplaneError, LocalNetworks, Plan, Platform, Stats, default_routes};
use crate::client::dns::Zones;
use crate::client::meshes::Mesh;

pub trait TunProvider: Send + Sync + 'static {
    fn establish(&self, shape: &TunShape) -> io::Result<AsyncDevice>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunShape {
    pub addresses: Vec<IpNet>,
    pub routes: Vec<IpNet>,
    pub mtu: u16,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Underlying {
    pub local_networks: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Clone)]
pub struct HostedPlatform {
    provider: Arc<dyn TunProvider>,
    underlying: Arc<ArcSwap<Underlying>>,
    roots: Arc<[Certificate]>,
}

impl HostedPlatform {
    pub fn new(provider: Arc<dyn TunProvider>, roots: &[Vec<u8>]) -> Self {
        Self {
            provider,
            underlying: Arc::default(),
            roots: roots
                .iter()
                .filter_map(|der| Certificate::from_der(der).ok())
                .collect(),
        }
    }

    pub fn set_underlying(&self, underlying: Underlying) {
        self.underlying.store(Arc::new(underlying));
    }
}

#[async_trait::async_trait]
impl Platform for HostedPlatform {
    type Device = ();

    async fn local_networks(&self, (): &()) -> Option<LocalNetworks> {
        let networks = self.underlying.load().local_networks.clone();
        Some(LocalNetworks {
            offered: networks.clone(),
            attached: networks,
        })
    }

    fn roots(&self) -> Option<&[Certificate]> {
        Some(&self.roots)
    }

    async fn start(
        &self,
        (): &(),
        key: &PrivateKey,
        listen_port: u16,
    ) -> Result<Box<dyn Backend>, DataplaneError> {
        let (local, queries) = Local::new(Arc::clone(&self.underlying));
        let device = UserspaceDevice::new(key, listen_port, None, Some(local.clone()))?;
        let resolver = tokio::spawn(resolver::serve(Arc::clone(&local), queries));

        Ok(Box::new(Hosted {
            device,
            local,
            resolver: AbortOnDropHandle::new(resolver),
            provider: Arc::clone(&self.provider),
            shape: None,
            dns: Dns::default(),
            shadowed: Vec::new(),
        }))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Dns {
    servers: Vec<IpAddr>,
    search: Vec<String>,
}

struct Hosted {
    device: UserspaceDevice,
    local: Arc<Local>,
    resolver: AbortOnDropHandle<()>,
    provider: Arc<dyn TunProvider>,
    shape: Option<TunShape>,
    dns: Dns,
    shadowed: Vec<(usize, DnsName)>,
}

impl Hosted {
    fn shape(&self, plan: &Plan) -> TunShape {
        let mut routes: Vec<IpNet> = plan
            .meshes
            .iter()
            .flat_map(|mesh| mesh.prefixes.iter().copied())
            .collect();

        if plan.exit.is_some() {
            routes.extend(default_routes());
        }

        routes.sort_unstable();
        routes.dedup();

        TunShape {
            addresses: plan.addresses(),
            routes,
            mtu: plan.mtu,
            dns_servers: self.dns.servers.clone(),
            search_domains: self.dns.search.clone(),
        }
    }

    async fn establish(&mut self, shape: TunShape) -> Result<(), DataplaneError> {
        if self.shape.as_ref() == Some(&shape) {
            return Ok(());
        }

        let provider = Arc::clone(&self.provider);
        let requested = shape.clone();
        let tun = tokio::task::spawn_blocking(move || provider.establish(&requested))
            .await
            .map_err(|error| NetError::Tun(io::Error::other(error)))?
            .map_err(NetError::Tun)?;
        let tun = Arc::new(Tun::plain(tun));
        self.local.set_tun(Arc::clone(&tun));
        self.device.set_mtu(shape.mtu);
        self.device.set_tun(tun);
        self.shape = Some(shape);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Backend for Hosted {
    async fn apply(
        &mut self,
        plan: &Plan,
        rehandshake: &[PublicKey],
    ) -> Result<(), DataplaneError> {
        self.device.filter_inbound(plan.mesh_rules());
        let ops = plan.peer_ops(&self.device.state(), rehandshake);
        self.device.apply(&ops);
        self.establish(self.shape(plan)).await
    }

    async fn stats(&mut self) -> Result<Stats, DataplaneError> {
        Ok(self.device.state().into())
    }

    async fn teardown(&mut self) {
        self.resolver.abort();
        self.device.delete().await;
    }

    fn stun(&self) -> Option<Stun> {
        Some(Stun::Userspace(self.device.stun()))
    }

    async fn update_dns(&mut self, meshes: &[Mesh], lighthouses: &BTreeMap<usize, Url>) {
        let zones = Zones::new(meshes);
        zones.warn_shadowed(&self.shadowed, lighthouses);
        self.shadowed = zones.shadowed;

        let resolver = meshes.first().map(|mesh| Resolver {
            network: mesh.netmap.network.ipv4,
            zone: zones.zone,
        });
        self.dns = Dns {
            servers: resolver.iter().map(Resolver::address).collect(),
            search: zones.search,
        };
        self.local.set_resolver(resolver);

        let Some(shape) = &self.shape else {
            return;
        };
        let shape = TunShape {
            dns_servers: self.dns.servers.clone(),
            search_domains: self.dns.search.clone(),
            ..shape.clone()
        };

        if let Err(error) = self.establish(shape).await {
            tracing::warn!(%error, "failed to give the tunnel its resolver");
        }
    }
}
