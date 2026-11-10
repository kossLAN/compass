use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, SockaddrStorage, recvmsg};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use super::offload;
use crate::Protect;

pub const MAX_DATAGRAM: usize = u16::MAX as usize;

const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const MAX_GSO_BYTES: usize = MAX_DATAGRAM - IPV4_HEADER - UDP_HEADER;
const MAX_GSO_SEGMENTS: usize = 64;
const SOCKET_BUFFER: usize = 7 << 20;

pub struct Sockets {
    port: u16,
    protect: Option<Arc<dyn Protect>>,
    v4: Arc<UdpSocket>,
    v6: Option<Arc<UdpSocket>>,
    gso: AtomicBool,
}

impl Sockets {
    pub fn bind(port: u16, protect: Option<Arc<dyn Protect>>) -> io::Result<Self> {
        let v4 = bind(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            protect.as_deref(),
        )?;
        let v6 = bind(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
            protect.as_deref(),
        )
        .inspect_err(|error| tracing::debug!(%error, "no IPv6 WireGuard socket"))
        .ok();

        Ok(Self {
            port,
            protect,
            gso: AtomicBool::new(offload::supports_gso(&v4)),
            v4: Arc::new(v4),
            v6: v6.map(Arc::new),
        })
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn protect(&self) -> Option<&dyn Protect> {
        self.protect.as_deref()
    }

    pub fn receivers(&self) -> impl Iterator<Item = Arc<UdpSocket>> {
        std::iter::once(Arc::clone(&self.v4)).chain(self.v6.clone())
    }

    pub async fn send_to(&self, destination: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.socket_for(destination)?
            .send_to(payload, destination)
            .await
            .map(drop)
    }

    pub fn try_send_to(&self, destination: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.socket_for(destination)?
            .try_send_to(payload, destination)
            .map(drop)
    }

    pub async fn send(&self, batch: &Batch) {
        for group in batch.groups() {
            if let Err(error) = self.send_group(&group).await {
                tracing::debug!(
                    destination = %group.destination,
                    %error,
                    "failed to send WireGuard datagrams",
                );
            }
        }
    }

    async fn send_group(&self, group: &Group<'_>) -> io::Result<()> {
        let socket = self.socket_for(group.destination)?;

        if group.count > 1 && self.gso.load(Ordering::Relaxed) {
            let sent =
                offload::send_segments(socket, group.destination, group.payload, group.segment);

            match sent.await {
                Err(error) if error.raw_os_error() == Some(Errno::EIO as i32) => {
                    tracing::debug!("UDP segmentation offload is unavailable");
                    self.gso.store(false, Ordering::Relaxed);
                },
                result => return result,
            }
        }

        for datagram in group.payload.chunks(group.segment) {
            socket.send_to(datagram, group.destination).await?;
        }

        Ok(())
    }

    fn socket_for(&self, destination: SocketAddr) -> io::Result<&UdpSocket> {
        match destination {
            SocketAddr::V4(_) => Ok(&self.v4),
            SocketAddr::V6(_) => self
                .v6
                .as_deref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable)),
        }
    }
}

#[derive(Default)]
pub struct Batch {
    buffer: Vec<u8>,
    cursor: usize,
    datagrams: Vec<(SocketAddr, usize)>,
}

impl Batch {
    pub fn spare(&mut self, needed: usize) -> &mut [u8] {
        let wanted = self.cursor + needed;

        if self.buffer.len() < wanted {
            self.buffer.resize(wanted, 0);
        }

        &mut self.buffer[self.cursor..]
    }

    pub fn commit(&mut self, destination: SocketAddr, len: usize) {
        self.datagrams.push((destination, len));
        self.cursor += len;
    }

    pub fn push(&mut self, destination: SocketAddr, payload: &[u8]) {
        self.spare(payload.len())[..payload.len()].copy_from_slice(payload);
        self.commit(destination, payload.len());
    }

    pub fn clear(&mut self) {
        self.cursor = 0;
        self.datagrams.clear();
    }

    fn groups(&self) -> Groups<'_> {
        Groups {
            buffer: &self.buffer[..self.cursor],
            datagrams: &self.datagrams,
        }
    }
}

struct Group<'a> {
    destination: SocketAddr,
    payload: &'a [u8],
    segment: usize,
    count: usize,
}

struct Groups<'a> {
    buffer: &'a [u8],
    datagrams: &'a [(SocketAddr, usize)],
}

impl<'a> Iterator for Groups<'a> {
    type Item = Group<'a>;

    fn next(&mut self) -> Option<Group<'a>> {
        let (&(destination, segment), rest) = self.datagrams.split_first()?;
        let mut count = 1;
        let mut bytes = segment;

        for &(next, len) in rest {
            if next != destination
                || len > segment
                || count == MAX_GSO_SEGMENTS
                || bytes + len > MAX_GSO_BYTES
            {
                break;
            }

            count += 1;
            bytes += len;

            if len < segment {
                break;
            }
        }

        let (payload, buffer) = self.buffer.split_at(bytes);
        self.buffer = buffer;
        self.datagrams = &self.datagrams[count..];

        Some(Group {
            destination,
            payload,
            segment,
            count,
        })
    }
}

pub struct Received {
    pub source: SocketAddr,
    pub len: usize,
    pub stride: usize,
}

pub fn control_buffer() -> Vec<u8> {
    nix::cmsg_space!(i32)
}

pub async fn recv(
    socket: &UdpSocket,
    buffer: &mut [u8],
    control: &mut [u8],
) -> io::Result<Received> {
    socket
        .async_io(Interest::READABLE, || {
            let mut iov = [IoSliceMut::new(buffer)];
            let message = recvmsg::<SockaddrStorage>(
                socket.as_raw_fd(),
                &mut iov,
                Some(control),
                MsgFlags::empty(),
            )?;
            let stride = offload::gro_stride(&message)
                .filter(|size| *size > 0)
                .unwrap_or(message.bytes);
            let source = message
                .address
                .as_ref()
                .and_then(socket_addr)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;

            Ok(Received {
                source,
                len: message.bytes,
                stride,
            })
        })
        .await
}

fn bind(address: SocketAddr, protect: Option<&dyn Protect>) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    if let Some(protect) = protect {
        protect.protect(socket.as_fd())?;
    }

    socket.set_recv_buffer_size(SOCKET_BUFFER)?;
    socket.set_send_buffer_size(SOCKET_BUFFER)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;

    let socket = UdpSocket::from_std(socket.into())?;

    offload::enable_gro(&socket);

    Ok(socket)
}

fn socket_addr(address: &SockaddrStorage) -> Option<SocketAddr> {
    address
        .as_sockaddr_in()
        .map(|v4| SocketAddr::V4(SocketAddrV4::from(*v4)))
        .or_else(|| {
            address
                .as_sockaddr_in6()
                .map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6)))
        })
}
