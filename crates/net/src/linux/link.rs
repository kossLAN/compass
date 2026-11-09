use std::collections::BTreeMap;
use std::net::IpAddr;

use futures_util::TryStreamExt as _;
use ipnet::IpNet;
use rtnetlink::packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::{Handle, LinkUnspec};

use super::{EADDRNOTAVAIL, ENODEV, ignore_gone};
use crate::NetError;

#[derive(Debug, Clone)]
pub struct Link {
    pub index: u32,
    pub kind: Option<InfoKind>,
}

#[derive(Clone)]
pub struct Links {
    handle: Handle,
}

impl Links {
    pub fn connect() -> Result<Self, NetError> {
        let (connection, handle, _) = rtnetlink::new_connection().map_err(NetError::Socket)?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub const fn handle(&self) -> &Handle {
        &self.handle
    }

    pub async fn find(&self, name: &str) -> Result<Option<Link>, NetError> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();

        match links.try_next().await {
            Ok(message) => Ok(message.map(|message| Link {
                index: message.header.index,
                kind: kind(&message),
            })),
            Err(error) => match NetError::rtnetlink(error) {
                error if error.is_os_error(ENODEV) => Ok(None),
                error => Err(error),
            },
        }
    }

    pub async fn index(&self, name: &str) -> Result<u32, NetError> {
        self.find(name)
            .await?
            .map(|link| link.index)
            .ok_or_else(|| NetError::MissingDevice(name.to_owned()))
    }

    pub async fn add(&self, message: LinkMessage) -> Result<(), NetError> {
        self.handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(NetError::rtnetlink)
    }

    async fn bring_up(&self, index: u32, mtu: u16) -> Result<(), NetError> {
        let message = LinkUnspec::new_with_index(index)
            .mtu(u32::from(mtu))
            .up()
            .build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(NetError::rtnetlink)
    }

    pub async fn delete(&self, index: u32) -> Result<(), NetError> {
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(NetError::rtnetlink)
    }

    pub async fn delete_named(&self, name: &str) -> Result<(), NetError> {
        match self.find(name).await? {
            Some(link) => self.delete(link.index).await,
            None => Ok(()),
        }
    }

    pub async fn configure(
        &self,
        index: u32,
        mtu: u16,
        addresses: &[IpNet],
    ) -> Result<(), NetError> {
        self.bring_up(index, mtu).await?;
        self.sync_addresses(index, addresses).await
    }

    pub async fn names(&self) -> Result<BTreeMap<u32, String>, NetError> {
        let messages: Vec<LinkMessage> = self
            .handle
            .link()
            .get()
            .execute()
            .try_collect()
            .await
            .map_err(NetError::rtnetlink)?;
        Ok(messages
            .into_iter()
            .filter_map(|message| {
                let name = message
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        LinkAttribute::IfName(name) => Some(name.clone()),
                        _ => None,
                    })?;
                Some((message.header.index, name))
            })
            .collect())
    }

    pub async fn addresses(&self) -> Result<Vec<(u32, IpNet)>, NetError> {
        let messages = self.address_messages(None).await?;
        Ok(messages
            .iter()
            .filter_map(|m| {
                let net = address_of(m)?;
                is_stable(m, net.addr()).then_some((m.header.index, net))
            })
            .collect())
    }

    async fn sync_addresses(&self, index: u32, wanted: &[IpNet]) -> Result<(), NetError> {
        let current = self.address_messages(Some(index)).await?;
        let mut present = Vec::new();

        for message in current {
            let Some(net) = address_of(&message) else {
                continue;
            };

            if wanted.contains(&net) {
                present.push(net);
            } else if !is_link_local(net.addr()) {
                let deleted = self
                    .handle
                    .address()
                    .del(message)
                    .execute()
                    .await
                    .map_err(NetError::rtnetlink);
                ignore_gone(deleted, EADDRNOTAVAIL)?;
            }
        }

        for net in wanted.iter().filter(|net| !present.contains(net)) {
            let mut request = self
                .handle
                .address()
                .add(index, net.addr(), net.prefix_len());

            if net.addr().is_ipv6() {
                request
                    .message_mut()
                    .attributes
                    .push(AddressAttribute::Flags(AddressFlags::Nodad));
            }

            request.execute().await.map_err(NetError::rtnetlink)?;
        }

        Ok(())
    }

    async fn address_messages(&self, index: Option<u32>) -> Result<Vec<AddressMessage>, NetError> {
        let mut request = self.handle.address().get();

        if let Some(index) = index {
            request = request.set_link_index_filter(index);
        }

        request
            .execute()
            .try_collect()
            .await
            .map_err(NetError::rtnetlink)
    }
}

fn kind(message: &LinkMessage) -> Option<InfoKind> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|info| match info {
                LinkInfo::Kind(kind) => Some(kind.clone()),
                _ => None,
            }),
            _ => None,
        })
}

fn address_of(message: &AddressMessage) -> Option<IpNet> {
    let find = |local: bool| {
        message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(address) if local => Some(*address),
                AddressAttribute::Address(address) if !local => Some(*address),
                _ => None,
            })
    };
    let address = find(true).or_else(|| find(false))?;
    IpNet::new(address, message.header.prefix_len).ok()
}

fn is_stable(message: &AddressMessage, address: IpAddr) -> bool {
    let flags = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Flags(flags) => Some(*flags),
            _ => None,
        })
        .unwrap_or_else(AddressFlags::empty);
    let unusable = AddressFlags::Tentative | AddressFlags::Dadfailed | AddressFlags::Deprecated;
    let temporary = address.is_ipv6() && flags.contains(AddressFlags::Secondary);
    !flags.intersects(unusable) && !temporary
}

const fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}
