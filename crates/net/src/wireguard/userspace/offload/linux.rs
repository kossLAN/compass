use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::os::fd::AsRawFd as _;

use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, SockaddrStorage, getsockopt, sendmsg,
    setsockopt, sockopt,
};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tun_rs::{AsyncDevice, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use super::udp::MAX_DATAGRAM;

pub struct Tun {
    device: AsyncDevice,
    offload: bool,
}

pub struct Reads {
    original: Vec<u8>,
    segments: Vec<Vec<u8>>,
    sizes: Vec<usize>,
}

#[derive(Default)]
pub struct Writes {
    gro: GROTable,
}

impl Writes {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Tun {
    pub const fn plain(device: AsyncDevice) -> Self {
        Self {
            device,
            offload: false,
        }
    }

    pub const fn offload(device: AsyncDevice) -> Self {
        Self {
            device,
            offload: true,
        }
    }

    pub const fn header_len(&self) -> usize {
        if self.offload { VIRTIO_NET_HDR_LEN } else { 0 }
    }

    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        if !self.offload {
            return self.device.send(packet).await.map(drop);
        }

        let mut framed = vec![0; VIRTIO_NET_HDR_LEN];
        framed.extend_from_slice(packet);
        self.device.send(&framed).await.map(drop)
    }

    pub fn reads(&self, mtu: usize) -> Reads {
        let (original, batch) = if self.offload {
            (vec![0; VIRTIO_NET_HDR_LEN + MAX_DATAGRAM], IDEAL_BATCH_SIZE)
        } else {
            (Vec::new(), 1)
        };

        Reads {
            original,
            segments: vec![vec![0; mtu]; batch],
            sizes: vec![0; batch],
        }
    }

    pub async fn read<'a>(
        &self,
        reads: &'a mut Reads,
    ) -> io::Result<impl Iterator<Item = &'a [u8]>> {
        let count = if self.offload {
            self.device
                .recv_multiple(
                    &mut reads.original,
                    &mut reads.segments,
                    &mut reads.sizes,
                    0,
                )
                .await?
        } else {
            reads.sizes[0] = self.device.recv(&mut reads.segments[0]).await?;
            1
        };

        Ok(reads.segments[..count]
            .iter()
            .zip(&reads.sizes[..count])
            .map(|(segment, &size)| &segment[..size]))
    }

    pub async fn write(&self, writes: &mut Writes, packets: &mut [Vec<u8>]) -> io::Result<()> {
        if self.offload {
            return self
                .device
                .send_multiple(&mut writes.gro, packets, VIRTIO_NET_HDR_LEN)
                .await
                .map(drop);
        }

        for packet in packets {
            self.device.send(packet).await?;
        }

        Ok(())
    }
}

pub fn enable_gro(socket: &UdpSocket) {
    if let Err(error) = setsockopt(socket, sockopt::UdpGroSegment, &true) {
        tracing::debug!(%error, "UDP receive offload is unavailable");
    }
}

pub fn supports_gso(socket: &UdpSocket) -> bool {
    getsockopt(socket, sockopt::UdpGsoSegment).is_ok()
}

pub fn gro_stride(message: &RecvMsg<'_, '_, SockaddrStorage>) -> Option<usize> {
    message.cmsgs().ok()?.find_map(|cmsg| match cmsg {
        ControlMessageOwned::UdpGroSegments(size) => usize::try_from(size).ok(),
        _ => None,
    })
}

pub async fn send_segments(
    socket: &UdpSocket,
    destination: SocketAddr,
    payload: &[u8],
    segment: usize,
) -> io::Result<()> {
    let address = SockaddrStorage::from(destination);
    let segment = u16::try_from(segment).map_err(|_| io::ErrorKind::InvalidInput)?;

    socket
        .async_io(Interest::WRITABLE, || {
            sendmsg(
                socket.as_raw_fd(),
                &[IoSlice::new(payload)],
                &[ControlMessage::UdpGsoSegments(&segment)],
                MsgFlags::empty(),
                Some(&address),
            )
            .map(drop)
            .map_err(io::Error::from)
        })
        .await
}
