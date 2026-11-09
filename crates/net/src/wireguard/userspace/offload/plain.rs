use std::future;
use std::io;
use std::net::SocketAddr;

use nix::sys::socket::{RecvMsg, SockaddrStorage};
use tokio::net::UdpSocket;
use tun_rs::AsyncDevice;

pub struct Tun {
    device: AsyncDevice,
}

pub struct Reads {
    packet: Vec<u8>,
}

#[derive(Default)]
pub struct Writes;

impl Writes {
    pub const fn new() -> Self {
        Self
    }
}

impl Tun {
    pub const fn plain(device: AsyncDevice) -> Self {
        Self { device }
    }

    pub const fn header_len(&self) -> usize {
        0
    }

    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.device.send(packet).await.map(drop)
    }

    pub fn reads(&self, mtu: usize) -> Reads {
        Reads {
            packet: vec![0; mtu],
        }
    }

    pub async fn read<'a>(
        &self,
        reads: &'a mut Reads,
    ) -> io::Result<impl Iterator<Item = &'a [u8]>> {
        let len = self.device.recv(&mut reads.packet).await?;
        Ok(std::iter::once(&reads.packet[..len]))
    }

    pub async fn write(&self, _: &mut Writes, packets: &mut [Vec<u8>]) -> io::Result<()> {
        for packet in packets {
            self.device.send(packet).await?;
        }

        Ok(())
    }
}

pub const fn enable_gro(_: &UdpSocket) {}

pub const fn supports_gso(_: &UdpSocket) -> bool {
    false
}

pub const fn gro_stride(_: &RecvMsg<'_, '_, SockaddrStorage>) -> Option<usize> {
    None
}

pub fn send_segments(
    _: &UdpSocket,
    _: SocketAddr,
    _: &[u8],
    _: usize,
) -> impl Future<Output = io::Result<()>> {
    future::ready(Err(io::ErrorKind::Unsupported.into()))
}
