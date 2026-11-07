use std::time::Duration;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use crate::NodeId;

pub const RELAY_PROTOCOL: &str = "bunnyhop-relay";
pub const RELAY_KEEPALIVE: Duration = Duration::from_secs(15);
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(45);
pub const MAX_RELAY_PAYLOAD: usize = u16::MAX as usize;
pub const MAX_RELAY_FRAME: usize = HEADER_LEN + MAX_RELAY_PAYLOAD;

const HEADER_LEN: usize = 1 + 8;
const PACKET: u8 = 1;
const KEEPALIVE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    Packet { peer: NodeId, payload: Bytes },
    Keepalive,
}

impl RelayFrame {
    pub fn encode(&self) -> Bytes {
        match self {
            Self::Packet { peer, payload } => {
                let mut frame = BytesMut::with_capacity(HEADER_LEN + payload.len());
                frame.put_u8(PACKET);
                frame.put_u64(peer.0);
                frame.put_slice(payload);
                frame.freeze()
            },
            Self::Keepalive => Bytes::from_static(&[KEEPALIVE]),
        }
    }

    pub fn decode(mut frame: BytesMut) -> Option<Self> {
        match *frame.first()? {
            PACKET if frame.len() >= HEADER_LEN && frame.len() <= MAX_RELAY_FRAME => {
                frame.advance(1);
                let peer = NodeId(frame.get_u64());
                Some(Self::Packet {
                    peer,
                    payload: frame.freeze(),
                })
            },
            KEEPALIVE if frame.len() == 1 => Some(Self::Keepalive),
            _ => None,
        }
    }
}
