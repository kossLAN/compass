use std::io;
use std::sync::Arc;

use boringtun::noise::{Tunn, TunnResult};
use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use super::udp::{Batch, MAX_DATAGRAM};
use super::{DATA_OVERHEAD, HANDSHAKE_INIT_LEN, Shared};

pub async fn run(shared: Arc<Shared>, mtu: usize) -> io::Result<()> {
    let mut original = vec![0; VIRTIO_NET_HDR_LEN + MAX_DATAGRAM];
    let mut segments = vec![vec![0; mtu]; IDEAL_BATCH_SIZE];
    let mut sizes = vec![0; IDEAL_BATCH_SIZE];
    let mut batch = Batch::default();

    loop {
        let count = match shared
            .tun
            .recv_multiple(&mut original, &mut segments, &mut sizes, 0)
            .await
        {
            Ok(count) => count,
            Err(error) if error.raw_os_error().is_none() => {
                tracing::debug!(%error, "dropped a malformed packet from the TUN device");
                continue;
            },
            Err(error) => return Err(error),
        };

        encapsulate(&shared, &segments[..count], &sizes[..count], &mut batch);
        shared.sockets.send(&batch).await;
        batch.clear();
    }
}

fn encapsulate(shared: &Shared, segments: &[Vec<u8>], sizes: &[usize], batch: &mut Batch) {
    let table = shared.table.load();

    for (segment, &size) in segments.iter().zip(sizes) {
        let packet = &segment[..size];
        let Some(peer) = Tunn::dst_address(packet).and_then(|address| table.lookup(address)) else {
            continue;
        };
        let mut session = peer.session();
        let Some(endpoint) = session.endpoint else {
            continue;
        };
        let spare = batch.spare((size + DATA_OVERHEAD).max(HANDSHAKE_INIT_LEN));

        if let TunnResult::WriteToNetwork(datagram) = session.tunn.encapsulate(packet, spare) {
            let len = datagram.len();
            batch.commit(endpoint, len);
        }
    }
}
