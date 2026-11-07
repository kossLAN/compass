use std::iter;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use super::zone::{Answer, Zone};

pub struct Stub {
    pub zone: Arc<ArcSwap<Zone>>,
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
