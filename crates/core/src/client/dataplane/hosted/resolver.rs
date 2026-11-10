use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd as _;
use std::sync::Arc;
use std::time::Duration;

use compass_proto::DNS_PORT;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::host::{Asker, Host};
use super::local::Local;
use crate::client::dns::{self, Reply};

const MAX_FORWARDS: usize = 64;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE: Duration = Duration::from_secs(60);
const MAX_MESSAGE: usize = u16::MAX as usize;

type Forwards = JoinSet<(Asker, Option<Vec<u8>>)>;

pub async fn serve(local: Arc<Local>, mut packets: mpsc::Receiver<Vec<u8>>) {
    let mut host: Option<Host> = None;
    let mut forwards = Forwards::new();

    loop {
        let delay = host.as_mut().and_then(Host::delay).unwrap_or(IDLE);

        tokio::select! {
            received = packets.recv() => {
                let Some(packet) = received else {
                    return;
                };
                let Some(resolver) = local.resolver() else {
                    continue;
                };

                if host.as_ref().is_some_and(|host| host.network() != resolver.network) {
                    host = None;
                }

                host.get_or_insert_with(|| Host::new(resolver.network)).receive(packet);
            },
            Some(forwarded) = forwards.join_next() => {
                if let (Ok((asker, response)), Some(host)) = (forwarded, &mut host) {
                    reply(host, asker, response);
                }
            },
            () = tokio::time::sleep(delay) => {},
        }

        if let Some(host) = &mut host {
            answer(&local, host, &mut forwards);

            for packet in host.transmit() {
                local.write(&packet).await;
            }
        }
    }
}

fn answer(local: &Arc<Local>, host: &mut Host, forwards: &mut Forwards) {
    loop {
        let queries = host.poll();

        if queries.is_empty() {
            return;
        }

        let Some(resolver) = local.resolver() else {
            return;
        };

        for (asker, query) in queries {
            match dns::answer(&resolver.zone, &query) {
                Some(Reply::Answer(response)) => host.respond(asker, &response),
                Some(Reply::Forward) if forwards.len() < MAX_FORWARDS => {
                    forwards.spawn(forward(Arc::clone(local), asker, query));
                },
                Some(Reply::Forward) | None => reply(host, asker, dns::failure(&query)),
            }
        }
    }
}

fn reply(host: &mut Host, asker: Asker, response: Option<Vec<u8>>) {
    match response {
        Some(response) => host.respond(asker, &response),
        None => host.reject(asker),
    }
}

async fn forward(local: Arc<Local>, asker: Asker, query: Vec<u8>) -> (Asker, Option<Vec<u8>>) {
    for server in local.dns_servers() {
        match tokio::time::timeout(FORWARD_TIMEOUT, ask(&local, asker, server, &query)).await {
            Ok(Ok(response)) if response.get(..2) == query.get(..2) => {
                return (asker, Some(response));
            },
            Ok(Ok(_)) => tracing::debug!(%server, "a resolver answered another query"),
            Ok(Err(error)) => tracing::debug!(%server, %error, "a resolver did not answer"),
            Err(_) => tracing::debug!(%server, "a resolver timed out"),
        }
    }

    (asker, dns::failure(&query))
}

async fn ask(local: &Local, asker: Asker, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    match asker {
        Asker::Udp(_) => ask_udp(local, server, query).await,
        Asker::Tcp(_) => ask_tcp(local, server, query).await,
    }
}

async fn ask_udp(local: &Local, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let unspecified = match server {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind((unspecified, 0)).await?;
    local.protect(socket.as_fd())?;
    socket.connect((server, DNS_PORT)).await?;
    socket.send(query).await?;

    let mut response = vec![0; MAX_MESSAGE];
    let len = socket.recv(&mut response).await?;
    response.truncate(len);
    Ok(response)
}

async fn ask_tcp(local: &Local, server: IpAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let framed = dns::frame(query).ok_or(io::ErrorKind::InvalidInput)?;
    let socket = match server {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    local.protect(socket.as_fd())?;
    let mut stream = socket.connect(SocketAddr::new(server, DNS_PORT)).await?;
    stream.write_all(&framed).await?;

    let mut response = vec![0; usize::from(stream.read_u16().await?)];
    stream.read_exact(&mut response).await?;
    Ok(response)
}
