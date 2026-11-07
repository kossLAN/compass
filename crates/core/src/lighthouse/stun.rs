use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::binding;

const MAX_DATAGRAM: usize = 2048;
const READ_RETRY: Duration = Duration::from_millis(100);
const EAFNOSUPPORT: i32 = 97;

pub fn bind(port: u16) -> io::Result<UdpSocket> {
    let socket = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(socket) => {
            socket.set_only_v6(false)?;
            socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
            socket
        },
        Err(error) if error.raw_os_error() == Some(EAFNOSUPPORT) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            socket
        },
        Err(error) => return Err(error),
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

pub async fn answer(socket: UdpSocket, cancel: CancellationToken) {
    let mut buffer = [0; MAX_DATAGRAM];

    loop {
        let (length, remote) = tokio::select! {
            () = cancel.cancelled() => break,
            received = socket.recv_from(&mut buffer) => match received {
                Ok(received) => received,
                Err(error) => {
                    tracing::warn!(%error, "failed to read STUN");
                    tokio::time::sleep(READ_RETRY).await;
                    continue;
                },
            },
        };

        let mapped = SocketAddr::new(remote.ip().to_canonical(), remote.port());

        if let Some(response) = binding::response(&buffer[..length], mapped)
            && let Err(error) = socket.send_to(&response, remote).await
        {
            tracing::debug!(%remote, %error, "failed to answer STUN");
        }
    }
}
