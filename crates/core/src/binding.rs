use std::net::SocketAddr;

use rtc_stun::attributes::ATTR_PADDING;
use rtc_stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Getter as _, Message, TransactionId};
use rtc_stun::xoraddr::XorMappedAddress;

const REQUEST_PADDING: [u8; 32] = [0; 32];

pub fn request(transaction: [u8; 12]) -> Vec<u8> {
    let mut message = Message::new();
    message
        .build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId(transaction)),
        ])
        .expect("a binding request always encodes");
    message.add(ATTR_PADDING, &REQUEST_PADDING);
    message.raw
}

#[cfg(feature = "linux")]
pub fn response(request: &[u8], mapped: SocketAddr) -> Option<Vec<u8>> {
    let mut message = Message::new();
    message.unmarshal_binary(request).ok()?;

    if message.typ != BINDING_REQUEST {
        return None;
    }

    let mut response = Message::new();
    response
        .build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(message.transaction_id),
            Box::new(XorMappedAddress {
                ip: mapped.ip(),
                port: mapped.port(),
            }),
        ])
        .ok()?;
    (response.raw.len() <= request.len()).then_some(response.raw)
}

pub fn mapped_address(response: &[u8]) -> Option<SocketAddr> {
    let mut message = Message::new();
    message.unmarshal_binary(response).ok()?;

    if message.typ != BINDING_SUCCESS {
        return None;
    }

    let mut mapped = XorMappedAddress::default();
    mapped.get_from(&message).ok()?;
    Some(SocketAddr::new(mapped.ip, mapped.port))
}
