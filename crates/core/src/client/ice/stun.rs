#![expect(
    clippy::big_endian_bytes,
    reason = "STUN headers are in network byte order"
)]

use bunnyhop_net::is_stun;

const HEADER_LEN: usize = 20;
const USERNAME: u16 = 0x0006;

pub type TransactionId = [u8; 12];

pub struct Header<'a> {
    pub request: bool,
    pub transaction: TransactionId,
    attributes: &'a [u8],
}

pub fn parse(packet: &[u8]) -> Option<Header<'_>> {
    let message_type = be16(packet, 0)?;

    if message_type & 0xc000 != 0 || !is_stun(packet) {
        return None;
    }

    let class = ((message_type >> 7) & 0b10) | ((message_type >> 4) & 0b01);
    let length = usize::from(be16(packet, 2)?);
    Some(Header {
        request: class == 0,
        transaction: packet.get(8..HEADER_LEN)?.try_into().ok()?,
        attributes: packet.get(HEADER_LEN..HEADER_LEN + length)?,
    })
}

impl Header<'_> {
    pub fn receiver_ufrag(&self) -> Option<&str> {
        let mut rest = self.attributes;

        while !rest.is_empty() {
            let kind = be16(rest, 0)?;
            let len = usize::from(be16(rest, 2)?);

            if kind == USERNAME {
                let username = std::str::from_utf8(rest.get(4..4 + len)?).ok()?;
                return username.split(':').next();
            }

            rest = rest.get(4 + len.next_multiple_of(4)..)?;
        }

        None
    }
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}
