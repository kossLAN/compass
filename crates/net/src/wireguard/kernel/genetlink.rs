use bunnyhop_proto::PrivateKey;
use futures_util::TryStreamExt as _;
use genetlink::GenetlinkHandle;
use ipnet::IpNet;
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};

use super::dump;
use crate::{DeviceState, ENODEV, NetError, PeerOp, PeerSpec};

const PEERS_PER_MESSAGE: usize = 32;

pub struct Genetlink {
    handle: GenetlinkHandle,
}

impl Genetlink {
    pub fn connect() -> Result<Self, NetError> {
        let (connection, handle, _) = genetlink::new_connection().map_err(NetError::Socket)?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    async fn request(
        &self,
        cmd: WireguardCmd,
        attributes: Vec<WireguardAttribute>,
        flags: u16,
    ) -> Result<Vec<WireguardMessage>, NetError> {
        let mut message = NetlinkMessage::from(GenlMessage::from_payload(WireguardMessage {
            cmd,
            attributes,
        }));
        message.header.flags = NLM_F_REQUEST | flags;

        let mut handle = self.handle.clone();
        let mut responses = handle.request(message).await.map_err(NetError::genetlink)?;
        let mut messages = Vec::new();

        while let Some(response) = responses
            .try_next()
            .await
            .map_err(|error| NetError::Protocol(error.to_string()))?
        {
            match response.payload {
                NetlinkPayload::InnerMessage(genl) => messages.push(genl.payload),
                NetlinkPayload::Error(error) if error.code.is_some() => {
                    return Err(NetError::Netlink(error.to_io()));
                },
                _ => {},
            }
        }

        Ok(messages)
    }

    pub async fn available(&self) -> bool {
        self.handle
            .resolve_family::<WireguardMessage>()
            .await
            .is_ok()
    }

    pub async fn get(&self, index: u32) -> Result<Option<DeviceState>, NetError> {
        let attributes = vec![WireguardAttribute::IfIndex(index)];

        match self
            .request(WireguardCmd::GetDevice, attributes, NLM_F_DUMP)
            .await
        {
            Ok(messages) => Ok(Some(dump::parse_device(messages))),
            Err(error) if error.is_os_error(ENODEV) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn configure(
        &self,
        index: u32,
        private_key: Option<&PrivateKey>,
        listen_port: Option<u16>,
        fwmark: Option<u32>,
    ) -> Result<(), NetError> {
        let mut attributes = vec![WireguardAttribute::IfIndex(index)];

        if let Some(key) = private_key {
            attributes.push(WireguardAttribute::PrivateKey(*key.to_bytes()));
        }

        if let Some(port) = listen_port {
            attributes.push(WireguardAttribute::ListenPort(port));
        }

        if let Some(mark) = fwmark {
            attributes.push(WireguardAttribute::Fwmark(mark));
        }

        self.set(attributes).await
    }

    pub async fn apply(&self, index: u32, ops: &[PeerOp]) -> Result<(), NetError> {
        for chunk in ops.chunks(PEERS_PER_MESSAGE) {
            self.set(vec![
                WireguardAttribute::IfIndex(index),
                WireguardAttribute::Peers(chunk.iter().map(peer_update).collect()),
            ])
            .await?;
        }

        Ok(())
    }

    async fn set(&self, attributes: Vec<WireguardAttribute>) -> Result<(), NetError> {
        self.request(WireguardCmd::SetDevice, attributes, NLM_F_ACK)
            .await
            .map(drop)
    }
}

fn peer_update(op: &PeerOp) -> WireguardPeer {
    match op {
        PeerOp::Upsert(spec) => upsert(spec),
        PeerOp::Remove(key) => WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey(key.to_bytes()),
            WireguardPeerAttribute::Flags(WireguardPeerFlags::RemoveMe),
        ]),
    }
}

fn upsert(spec: &PeerSpec) -> WireguardPeer {
    let mut attributes = vec![
        WireguardPeerAttribute::PublicKey(spec.key.to_bytes()),
        WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
        WireguardPeerAttribute::PersistentKeepalive(spec.keepalive),
        WireguardPeerAttribute::AllowedIps(spec.allowed_ips.iter().map(allowed_ip).collect()),
    ];

    if let Some(endpoint) = spec.endpoint {
        attributes.push(WireguardPeerAttribute::Endpoint(endpoint));
    }

    WireguardPeer(attributes)
}

fn allowed_ip(net: &IpNet) -> WireguardAllowedIp {
    let family = match net {
        IpNet::V4(_) => WireguardAddressFamily::Ipv4,
        IpNet::V6(_) => WireguardAddressFamily::Ipv6,
    };

    WireguardAllowedIp(vec![
        WireguardAllowedIpAttr::Family(family),
        WireguardAllowedIpAttr::IpAddr(net.addr()),
        WireguardAllowedIpAttr::Cidr(net.prefix_len()),
    ])
}
