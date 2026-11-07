#![expect(
    clippy::big_endian_bytes,
    reason = "the STUN magic cookie is in network byte order"
)]

use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};

pub const MAGIC_COOKIE: u32 = 0x2112_a442;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub payload: Vec<u8>,
}

pub fn is_stun(payload: &[u8]) -> bool {
    payload.get(4..8) == Some(MAGIC_COOKIE.to_be_bytes().as_slice())
}

pub fn local_address_for(destination: SocketAddr, mark: u32) -> io::Result<IpAddr> {
    let probe = Socket::new(
        Domain::for_address(destination),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    probe.set_mark(mark)?;
    probe.connect(&destination.into())?;
    probe
        .local_addr()?
        .as_socket()
        .map(|local| local.ip())
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))
}
