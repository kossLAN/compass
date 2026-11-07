use std::collections::BTreeSet;

use crate::{DeviceState, PeerOp, PeerSpec};

pub fn plan_peers(desired: &[PeerSpec], actual: &DeviceState) -> Vec<PeerOp> {
    let upserts = desired.iter().filter_map(|spec| {
        let unchanged = actual.peers.get(&spec.key).is_some_and(|current| {
            let wanted: BTreeSet<_> = spec.allowed_ips.iter().collect();
            let present: BTreeSet<_> = current.allowed_ips.iter().collect();
            wanted == present
                && current.keepalive == spec.keepalive
                && spec
                    .endpoint
                    .is_none_or(|endpoint| current.endpoint == Some(endpoint))
        });
        (!unchanged).then(|| PeerOp::Upsert(spec.clone()))
    });

    let wanted: BTreeSet<_> = desired.iter().map(|spec| spec.key).collect();
    let removals = actual
        .peers
        .keys()
        .filter(|key| !wanted.contains(*key))
        .map(|key| PeerOp::Remove(*key));

    upserts.chain(removals).collect()
}
