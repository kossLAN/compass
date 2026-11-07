use std::io;
use std::net::SocketAddr;
use std::sync::Weak;

use tokio::sync::{Mutex, mpsc};

use super::Shared;
use crate::stun::Datagram;

pub struct UserspaceStun {
    shared: Weak<Shared>,
    received: Mutex<mpsc::Receiver<Datagram>>,
}

impl UserspaceStun {
    pub(super) fn new(shared: Weak<Shared>, received: mpsc::Receiver<Datagram>) -> Self {
        Self {
            shared,
            received: Mutex::new(received),
        }
    }

    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let shared = self.shared.upgrade().ok_or_else(closed)?;
        shared.sockets.send_to(remote, payload).await
    }

    pub async fn recv(&self) -> io::Result<Datagram> {
        self.received.lock().await.recv().await.ok_or_else(closed)
    }
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "the userspace WireGuard device is gone",
    )
}
