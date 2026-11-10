#![expect(
    clippy::big_endian_bytes,
    reason = "UDP and IP headers are in network byte order"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use socket2::{Domain, Protocol, SockFilter, Socket, Type};
use tokio::net::UdpSocket;

use crate::Fwmark;
use crate::stun::{Datagram, MAGIC_COOKIE, local_address_for};

const UDP_HEADER_LEN: usize = 8;
const UDP_PROTOCOL: u32 = 17;
const MAX_DATAGRAM: usize = 2048;

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

pub struct KernelStun {
    port: u16,
    mark: u32,
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

impl KernelStun {
    pub fn bind(port: u16, mark: u32) -> io::Result<Self> {
        let v4 = raw_socket(Domain::IPV4, mark, &ipv4_filter(port))?;
        let v6 = raw_socket(Domain::IPV6, mark, &ipv6_filter(port))
            .inspect_err(|error| tracing::debug!(%error, "no IPv6 STUN socket"))
            .ok();
        Ok(Self { port, mark, v4, v6 })
    }

    pub async fn recv(&self) -> io::Result<Datagram> {
        let mut v4_buffer = [0; MAX_DATAGRAM];
        let mut v6_buffer = [0; MAX_DATAGRAM];

        loop {
            let datagram = tokio::select! {
                received = self.v4.recv_from(&mut v4_buffer) => {
                    let (len, _) = received?;
                    parse_ipv4(&v4_buffer[..len])
                },
                received = recv_optional(self.v6.as_ref(), &mut v6_buffer) => {
                    let (len, from) = received?;
                    self.parse_ipv6(&v6_buffer[..len], from.ip())
                },
            };

            if let Some(datagram) = datagram {
                return Ok(datagram);
            }
        }
    }

    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let socket = match remote {
            SocketAddr::V4(_) => Some(&self.v4),
            SocketAddr::V6(_) => self.v6.as_ref(),
        }
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
        let source = SocketAddr::new(self.source_for(remote)?, self.port);
        let packet = udp_packet(source, remote, payload);
        socket
            .send_to(&packet, SocketAddr::new(remote.ip(), 0))
            .await?;
        Ok(())
    }

    fn parse_ipv6(&self, segment: &[u8], source: IpAddr) -> Option<Datagram> {
        let (source_port, destination_port, payload) = parse_udp(segment)?;
        let remote = SocketAddr::new(source, source_port);
        let local = self.source_for(remote).ok()?;
        Some(Datagram {
            local: SocketAddr::new(local, destination_port),
            remote,
            payload: payload.to_vec(),
        })
    }

    fn source_for(&self, destination: SocketAddr) -> io::Result<IpAddr> {
        local_address_for(destination, Some(&Fwmark(self.mark)))
    }
}

fn raw_socket(domain: Domain, mark: u32, filter: &[SockFilter]) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_mark(mark)?;
    socket.attach_filter(filter)?;
    UdpSocket::from_std(socket.into())
}

async fn recv_optional(
    socket: Option<&UdpSocket>,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => std::future::pending().await,
    }
}

fn ipv4_filter(port: u16) -> [SockFilter; 7] {
    [
        SockFilter::new(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0),
        SockFilter::new(BPF_LD | BPF_H | BPF_IND, 0, 0, 2),
        SockFilter::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, u32::from(port)),
        SockFilter::new(BPF_LD | BPF_W | BPF_IND, 0, 0, 12),
        SockFilter::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, MAGIC_COOKIE),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, u32::MAX),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 0),
    ]
}

fn ipv6_filter(port: u16) -> [SockFilter; 6] {
    [
        SockFilter::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, 2),
        SockFilter::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, u32::from(port)),
        SockFilter::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, 12),
        SockFilter::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, MAGIC_COOKIE),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, u32::MAX),
        SockFilter::new(BPF_RET | BPF_K, 0, 0, 0),
    ]
}

fn parse_ipv4(packet: &[u8]) -> Option<Datagram> {
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
    let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    let (source_port, destination_port, payload) = parse_udp(packet.get(header_len..)?)?;
    Some(Datagram {
        local: SocketAddr::new(Ipv4Addr::from(destination).into(), destination_port),
        remote: SocketAddr::new(Ipv4Addr::from(source).into(), source_port),
        payload: payload.to_vec(),
    })
}

fn parse_udp(segment: &[u8]) -> Option<(u16, u16, &[u8])> {
    let source_port = be16(segment, 0)?;
    let destination_port = be16(segment, 2)?;
    let length = usize::from(be16(segment, 4)?).min(segment.len());
    Some((
        source_port,
        destination_port,
        segment.get(UDP_HEADER_LEN..length)?,
    ))
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let length = UDP_HEADER_LEN + payload.len();
    let mut packet = Vec::with_capacity(length);
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet.extend_from_slice(&(length as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);

    let checksum = checksum(source.ip(), destination.ip(), &packet);
    packet[6..8].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn checksum(source: IpAddr, destination: IpAddr, segment: &[u8]) -> u16 {
    let mut sum = UDP_PROTOCOL + segment.len() as u32;

    for address in [source, destination] {
        match address {
            IpAddr::V4(v4) => add_words(&mut sum, &v4.octets()),
            IpAddr::V6(v6) => add_words(&mut sum, &v6.octets()),
        }
    }

    add_words(&mut sum, segment);

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    match !(sum as u16) {
        0 => 0xffff,
        checksum => checksum,
    }
}

fn add_words(sum: &mut u32, bytes: &[u8]) {
    for pair in bytes.chunks(2) {
        let low = pair.get(1).copied().unwrap_or(0);
        *sum += u32::from(u16::from_be_bytes([pair[0], low]));
    }
}
