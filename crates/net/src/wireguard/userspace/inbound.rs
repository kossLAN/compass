use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use bunnyhop_proto::PublicKey;
use tokio::net::UdpSocket;
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use super::table::{Peer, Table};
use super::udp::{self, Batch, MAX_DATAGRAM};
use super::{COOKIE_REPLY_LEN, Shared};
use crate::stun::is_stun;

pub async fn run(shared: Arc<Shared>, socket: Arc<UdpSocket>) -> io::Result<()> {
    let mut buffer = vec![0; MAX_DATAGRAM];
    let mut control = udp::control_buffer();
    let mut packets = Vec::with_capacity(IDEAL_BATCH_SIZE);
    let mut gro = GROTable::default();
    let mut batch = Batch::default();

    loop {
        let received = udp::recv(&socket, &mut buffer, &mut control).await?;

        if received.len == 0 {
            continue;
        }

        let datagrams = buffer[..received.len].chunks(received.stride);
        let count = receive(
            &shared,
            received.source,
            datagrams,
            &mut packets,
            &mut batch,
        );

        if count > 0
            && let Err(error) = shared
                .tun
                .send_multiple(&mut gro, &mut packets[..count], VIRTIO_NET_HDR_LEN)
                .await
        {
            tracing::debug!(%error, "failed to write packets to the TUN device");
        }

        shared.sockets.send(&batch).await;
        batch.clear();
    }
}

fn receive<'a>(
    shared: &Shared,
    source: SocketAddr,
    datagrams: impl Iterator<Item = &'a [u8]>,
    packets: &mut Vec<Vec<u8>>,
    batch: &mut Batch,
) -> usize {
    let table = shared.table.load();
    let mut count = 0;

    for datagram in datagrams {
        if is_stun(datagram) {
            shared.deliver_stun(source, datagram);
            continue;
        }

        let Some(peer) = route(shared, &table, source, datagram, batch) else {
            continue;
        };

        if packets.len() == count {
            packets.push(Vec::new());
        }

        let packet = &mut packets[count];
        packet.resize(VIRTIO_NET_HDR_LEN + datagram.len(), 0);
        let mut session = peer.session();

        let inner = match session.tunn.decapsulate(
            Some(source.ip()),
            datagram,
            &mut packet[VIRTIO_NET_HDR_LEN..],
        ) {
            TunnResult::Err(_) => continue,
            TunnResult::Done => None,
            TunnResult::WriteToNetwork(reply) => {
                batch.push(source, reply);
                drain(&mut session.tunn, source, batch);
                None
            },
            TunnResult::WriteToTunnelV4(inner, address) => Some((inner.len(), IpAddr::V4(address))),
            TunnResult::WriteToTunnelV6(inner, address) => Some((inner.len(), IpAddr::V6(address))),
        };

        session.endpoint = Some(source);

        if let Some((len, address)) = inner
            && table.routes_to(peer, address)
        {
            packet.truncate(VIRTIO_NET_HDR_LEN + len);
            count += 1;
        }
    }

    count
}

fn route<'t>(
    shared: &Shared,
    table: &'t Table,
    source: SocketAddr,
    datagram: &[u8],
    batch: &mut Batch,
) -> Option<&'t Arc<Peer>> {
    let packet = match shared.rate_limiter.verify_packet(
        Some(source.ip()),
        datagram,
        batch.spare(COOKIE_REPLY_LEN),
    ) {
        Ok(packet) => packet,
        Err(TunnResult::WriteToNetwork(cookie)) => {
            let len = cookie.len();
            batch.commit(source, len);
            return None;
        },
        Err(_) => return None,
    };

    match packet {
        Packet::HandshakeInit(init) => {
            let half = parse_handshake_anon(&shared.secret, &shared.public, &init).ok()?;
            table.by_key(&PublicKey::from_bytes(half.peer_static_public))
        },
        Packet::HandshakeResponse(response) => table.by_receiver(response.receiver_idx),
        Packet::PacketCookieReply(reply) => table.by_receiver(reply.receiver_idx),
        Packet::PacketData(data) => table.by_receiver(data.receiver_idx),
    }
}

fn drain(tunn: &mut Tunn, destination: SocketAddr, batch: &mut Batch) {
    while let TunnResult::WriteToNetwork(datagram) =
        tunn.decapsulate(None, &[], batch.spare(MAX_DATAGRAM))
    {
        let len = datagram.len();
        batch.commit(destination, len);
    }
}
