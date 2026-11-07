mod stub;
mod zone;

use std::collections::BTreeMap;
use std::iter;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bunnyhop_net::{Dataplane, LinkDns};
use bunnyhop_proto::{DNS_PORT, DnsName};
use hickory_server::proto::rr::Name;
use ipnet::IpNet;
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use url::Url;

use self::stub::Stub;
use self::zone::Zone;
use crate::client::meshes::Mesh;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_RESPONSE_BUFFER: usize = 32;
const ARPA_LABELS: usize = 2;

pub fn stub_address<'a>(meshes: impl IntoIterator<Item = &'a Mesh>) -> Option<IpAddr> {
    meshes.into_iter().next()?.addresses.first().copied()
}

/// The forward zones each mesh answers for on this node, in the order of `meshes`, and the ones
/// left out because an earlier mesh answers for an overlapping zone. Reverse zones are not
/// claimed: meshes often share a prefix, and `meshes::resolve` already gives each address to a
/// single node.
fn claim_zones(meshes: &[Mesh]) -> (Vec<Vec<DnsName>>, Vec<(usize, DnsName)>) {
    let mut claimed: Vec<&DnsName> = Vec::new();
    let mut owned = Vec::new();
    let mut shadowed = Vec::new();

    for mesh in meshes {
        let network = &mesh.netmap.network;
        let mut zones = Vec::new();

        for zone in iter::once(&network.domain).chain(&network.zones) {
            if claimed.iter().any(|other| zone.overlaps(other)) {
                shadowed.push((mesh.index, zone.clone()));
            } else {
                claimed.push(zone);
                zones.push(zone.clone());
            }
        }

        owned.push(zones);
    }

    (owned, shadowed)
}

fn search(meshes: &[Mesh], owned: &[Vec<DnsName>]) -> Vec<String> {
    meshes
        .iter()
        .zip(owned)
        .filter(|(mesh, zones)| zones.contains(&mesh.netmap.network.domain))
        .map(|(mesh, _)| mesh.netmap.network.domain.to_string())
        .collect()
}

fn origins(meshes: &[Mesh], owned: &[Vec<DnsName>]) -> Vec<DnsName> {
    let mut origins: Vec<DnsName> = owned.iter().flatten().cloned().collect();
    let reverse = meshes
        .iter()
        .flat_map(|mesh| mesh.netmap.network.prefixes())
        .flat_map(reverse_zones);

    for zone in reverse {
        if !origins.contains(&zone) {
            origins.push(zone);
        }
    }

    origins
}

fn reverse_zones(prefix: IpNet) -> Vec<DnsName> {
    let step = match prefix {
        IpNet::V4(_) => 8,
        IpNet::V6(_) => 4,
    };

    let aligned = prefix.prefix_len().div_ceil(step) * step;
    prefix
        .subnets(aligned)
        .expect("rounding up to a boundary keeps the prefix length valid")
        .map(|subnet| {
            Name::from(subnet.network())
                .trim_to(usize::from(aligned / step) + ARPA_LABELS)
                .to_string()
                .parse()
                .expect("reverse zone names are valid DNS names")
        })
        .collect()
}

#[derive(Default)]
pub struct DnsService {
    zone: Arc<ArcSwap<Zone>>,
    stub: Option<(IpAddr, CancellationToken)>,
    registered: Option<LinkDns>,
    registration_failing: bool,
    shadowed: Vec<(usize, DnsName)>,
}

impl DnsService {
    pub async fn update(
        &mut self,
        dataplane: &Dataplane,
        device: &str,
        meshes: &[Mesh],
        lighthouses: &BTreeMap<usize, Url>,
    ) {
        let (owned, shadowed) = claim_zones(meshes);

        for (mesh, zone) in shadowed
            .iter()
            .filter(|entry| !self.shadowed.contains(entry))
        {
            tracing::warn!(
                %zone,
                lighthouse = lighthouses.get(mesh).map_or("", |url| url.as_str()),
                "an earlier lighthouse in client.lighthouses already answers for this zone or one overlapping it; ignoring the names this lighthouse has in it",
            );
        }

        self.shadowed = shadowed;
        let origins = origins(meshes, &owned);
        self.zone
            .store(Arc::new(Zone::from_meshes(meshes, &owned, &origins)));

        let Some(address) = stub_address(meshes) else {
            return;
        };

        if self.stub.as_ref().map(|(bound, _)| *bound) != Some(address) {
            self.stop_stub();

            match self.start_stub(address).await {
                Ok(cancel) => self.stub = Some((address, cancel)),
                Err(error) => tracing::warn!(%address, %error, "failed to start the DNS stub"),
            }
        }

        let dns = LinkDns {
            servers: vec![address],
            search: search(meshes, &owned),
        };

        if self.registered.as_ref() == Some(&dns) {
            return;
        }

        match dataplane.set_dns(device, Some(&dns)).await {
            Ok(()) => {
                if self.registration_failing {
                    tracing::info!(%address, "registered the DNS stub with resolvconf");
                }
                self.registered = Some(dns);
                self.registration_failing = false;
            },
            Err(error) if !self.registration_failing => {
                self.registration_failing = true;
                tracing::warn!(
                    %error,
                    %address,
                    "could not register the DNS stub with resolvconf; mesh names resolve only through a resolver that forwards to it",
                );
            },
            Err(error) => tracing::debug!(%error, "resolvconf is still failing"),
        }
    }

    pub async fn stop(&mut self, dataplane: &Dataplane, device: &str) {
        self.stop_stub();

        if self.registered.take().is_some()
            && let Err(error) = dataplane.set_dns(device, None).await
        {
            tracing::warn!(%error, "failed to remove the DNS stub from resolvconf");
        }
    }

    async fn start_stub(&self, address: IpAddr) -> std::io::Result<CancellationToken> {
        let mut server = hickory_server::Server::new(Stub {
            zone: Arc::clone(&self.zone),
        });
        server.register_socket(UdpSocket::bind((address, DNS_PORT)).await?);
        server.register_listener(
            TcpListener::bind((address, DNS_PORT)).await?,
            TCP_TIMEOUT,
            TCP_RESPONSE_BUFFER,
        );
        let cancel = server.shutdown_token().clone();
        tokio::spawn(async move {
            if let Err(error) = server.block_until_done().await {
                tracing::warn!(%error, "DNS stub stopped");
            }
        });
        Ok(cancel)
    }

    fn stop_stub(&mut self) {
        if let Some((_, cancel)) = self.stub.take() {
            cancel.cancel();
        }
    }
}
