use std::io;
use std::sync::Arc;

use boringtun::noise::{Tunn, TunnResult};

use super::offload::Tun;
use super::table::Table;
use super::udp::Batch;
use super::{DATA_OVERHEAD, HANDSHAKE_INIT_LEN, Shared};

pub async fn run(shared: Arc<Shared>, tun: Arc<Tun>, mtu: usize) -> io::Result<()> {
    let mut reads = tun.reads(mtu);
    let mut batch = Batch::default();

    loop {
        let packets = match tun.read(&mut reads).await {
            Ok(packets) => packets,
            Err(error) if error.raw_os_error().is_none() => {
                tracing::debug!(%error, "dropped a malformed packet from the TUN device");
                continue;
            },
            Err(error) => return Err(error),
        };

        let table = shared.table.load();

        for packet in packets {
            if shared
                .intercept
                .as_ref()
                .is_some_and(|intercept| intercept.take(packet))
            {
                continue;
            }

            shared.filter.track(packet);
            encapsulate(&table, packet, &mut batch);
        }

        shared.sockets.send(&batch).await;
        batch.clear();
    }
}

fn encapsulate(table: &Table, packet: &[u8], batch: &mut Batch) {
    let Some(peer) = Tunn::dst_address(packet).and_then(|address| table.lookup(address)) else {
        return;
    };
    let mut session = peer.session();
    let Some(endpoint) = session.endpoint else {
        return;
    };
    let spare = batch.spare((packet.len() + DATA_OVERHEAD).max(HANDSHAKE_INIT_LEN));

    if let TunnResult::WriteToNetwork(datagram) = session.tunn.encapsulate(packet, spare) {
        let len = datagram.len();
        batch.commit(endpoint, len);
    }
}
