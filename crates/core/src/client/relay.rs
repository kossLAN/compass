use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use bytes::Bytes;
use compass_proto::{
    MAX_RELAY_FRAME, MAX_RELAY_PAYLOAD, NodeId, RELAY_KEEPALIVE, RELAY_TIMEOUT, RelayFrame,
};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const QUEUE: usize = 256;
const READ_RETRY: Duration = Duration::from_millis(100);

pub struct Relay {
    wireguard: SocketAddr,
    proxies: Mutex<HashMap<NodeId, Proxy>>,
    links: Mutex<HashMap<usize, Link>>,
    attached: AtomicU64,
}

struct Proxy {
    socket: Arc<UdpSocket>,
    address: SocketAddr,
    lighthouse: Option<usize>,
    task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Link {
    generation: u64,
    frames: mpsc::Sender<Bytes>,
}

struct Attachment<'a> {
    relay: &'a Relay,
    lighthouse: usize,
    generation: u64,
}

impl Drop for Attachment<'_> {
    fn drop(&mut self) {
        let mut links = lock(&self.relay.links);

        if links
            .get(&self.lighthouse)
            .is_some_and(|link| link.generation == self.generation)
        {
            links.remove(&self.lighthouse);
        }
    }
}

impl Relay {
    pub fn new(listen_port: u16) -> Arc<Self> {
        Arc::new(Self {
            wireguard: SocketAddr::from((Ipv4Addr::LOCALHOST, listen_port)),
            proxies: Mutex::default(),
            links: Mutex::default(),
            attached: AtomicU64::new(0),
        })
    }

    pub fn set_peers(self: &Arc<Self>, peers: &BTreeSet<NodeId>) {
        let mut proxies = lock(&self.proxies);
        proxies.retain(|peer, _| peers.contains(peer));

        for peer in peers {
            if proxies.contains_key(peer) {
                continue;
            }

            match self.open(*peer) {
                Ok(proxy) => {
                    proxies.insert(*peer, proxy);
                },
                Err(error) => tracing::warn!(%peer, %error, "failed to open a relay socket"),
            }
        }
    }

    fn open(self: &Arc<Self>, peer: NodeId) -> io::Result<Proxy> {
        let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let address = socket.local_addr()?;
        let task = tokio::spawn(forward(
            Arc::downgrade(self),
            peer,
            Arc::clone(&socket),
            self.wireguard,
        ));
        Ok(Proxy {
            socket,
            address,
            lighthouse: None,
            task,
        })
    }

    pub fn endpoints(&self) -> HashMap<NodeId, SocketAddr> {
        lock(&self.proxies)
            .iter()
            .map(|(peer, proxy)| (*peer, proxy.address))
            .collect()
    }

    pub fn set_routes(&self, routes: impl IntoIterator<Item = (NodeId, Option<usize>)>) {
        let mut proxies = lock(&self.proxies);

        for (peer, lighthouse) in routes {
            if let Some(proxy) = proxies.get_mut(&peer) {
                proxy.lighthouse = lighthouse;
            }
        }
    }

    pub fn connected(&self) -> BTreeSet<usize> {
        lock(&self.links).keys().copied().collect()
    }

    pub async fn run<S>(&self, lighthouse: usize, stream: S) -> io::Error
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_RELAY_FRAME)
            .new_codec();
        let mut connection = Framed::new(stream, codec);
        let (_attachment, mut outgoing) = self.attach(lighthouse);
        let mut keepalive = tokio::time::interval(RELAY_KEEPALIVE);
        let mut deadline = Instant::now() + RELAY_TIMEOUT;

        loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    return io::Error::new(io::ErrorKind::TimedOut, "the lighthouse stopped answering");
                },
                frame = outgoing.recv() => {
                    let Some(frame) = frame else {
                        return io::Error::other("another relay connection replaced this one");
                    };

                    if let Err(error) = connection.send(frame).await {
                        return error;
                    }
                },
                _ = keepalive.tick() => {
                    if let Err(error) = connection.send(RelayFrame::Keepalive.encode()).await {
                        return error;
                    }
                },
                received = connection.next() => {
                    let frame = match received {
                        Some(Ok(frame)) => frame,
                        Some(Err(error)) => return error,
                        None => {
                            return io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "the lighthouse closed the connection",
                            );
                        },
                    };

                    deadline = Instant::now() + RELAY_TIMEOUT;

                    match RelayFrame::decode(frame) {
                        Some(RelayFrame::Packet { peer, payload }) => self.deliver(peer, &payload),
                        Some(RelayFrame::Keepalive) => {},
                        None => {
                            return io::Error::new(
                                io::ErrorKind::InvalidData,
                                "the lighthouse sent an invalid frame",
                            );
                        },
                    }
                },
            }
        }
    }

    fn attach(&self, lighthouse: usize) -> (Attachment<'_>, mpsc::Receiver<Bytes>) {
        let generation = self.attached.fetch_add(1, Ordering::Relaxed);
        let (frames, receiver) = mpsc::channel(QUEUE);
        lock(&self.links).insert(lighthouse, Link { generation, frames });
        let attachment = Attachment {
            relay: self,
            lighthouse,
            generation,
        };
        (attachment, receiver)
    }

    fn send(&self, peer: NodeId, payload: Bytes) {
        let Some(lighthouse) = lock(&self.proxies)
            .get(&peer)
            .and_then(|proxy| proxy.lighthouse)
        else {
            return;
        };

        if let Some(link) = lock(&self.links).get(&lighthouse) {
            let _ = link
                .frames
                .try_send(RelayFrame::Packet { peer, payload }.encode());
        }
    }

    fn deliver(&self, peer: NodeId, payload: &[u8]) {
        let proxies = lock(&self.proxies);

        if let Some(proxy) = proxies.get(&peer)
            && let Err(error) = proxy.socket.try_send_to(payload, self.wireguard)
        {
            tracing::debug!(%peer, %error, "dropped a relayed packet");
        }
    }
}

async fn forward(relay: Weak<Relay>, peer: NodeId, socket: Arc<UdpSocket>, wireguard: SocketAddr) {
    let mut buffer = vec![0; MAX_RELAY_PAYLOAD];

    loop {
        let (length, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(%peer, %error, "failed to read from a relay socket");
                tokio::time::sleep(READ_RETRY).await;
                continue;
            },
        };

        if source != wireguard {
            continue;
        }

        let Some(relay) = relay.upgrade() else {
            return;
        };

        relay.send(peer, Bytes::copy_from_slice(&buffer[..length]));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
