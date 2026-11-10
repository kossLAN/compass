use std::collections::BTreeMap;
use std::iter;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use compass_net::{Dataplane, LinkDns};
use compass_proto::{DNS_PORT, DnsName};
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::zone::{Answer, Zone};
use super::{Zones, stub_address};
use crate::client::meshes::Mesh;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_RESPONSE_BUFFER: usize = 32;

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
        lighthouses: &BTreeMap<usize, String>,
    ) {
        let zones = Zones::new(meshes);
        zones.warn_shadowed(&self.shadowed, lighthouses);
        self.shadowed = zones.shadowed;
        self.zone.store(Arc::new(zones.zone));

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
            search: zones.search,
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

struct Stub {
    zone: Arc<ArcSwap<Zone>>,
}

#[async_trait::async_trait]
impl RequestHandler for Stub {
    async fn handle_request<R, T>(&self, request: &Request, mut response_handle: R) -> ResponseInfo
    where
        R: ResponseHandler,
        T: Time,
    {
        let zone = self.zone.load();
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.authoritative = true;

        let answers = match request.request_info() {
            Err(_) => {
                metadata.response_code = ResponseCode::FormErr;
                Vec::new()
            },
            Ok(info) => match zone.lookup(info.query.name(), info.query.query_type()) {
                Answer::Refused => {
                    metadata.response_code = ResponseCode::Refused;
                    Vec::new()
                },
                Answer::NotFound => {
                    metadata.response_code = ResponseCode::NXDomain;
                    Vec::new()
                },
                Answer::Found(records) => records,
            },
        };

        let response = MessageResponseBuilder::from_message_request(request).build(
            metadata,
            answers.iter(),
            iter::empty(),
            iter::empty(),
            iter::empty(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(error) => {
                tracing::debug!(%error, "failed to send a DNS response");
                metadata.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                })
            },
        }
    }
}
