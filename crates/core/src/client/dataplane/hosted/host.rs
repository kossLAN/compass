use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;
use std::time::Duration;

use bytes::BytesMut;
use compass_proto::DNS_PORT;
use ipnet::Ipv4Net;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{AnySocket as _, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use crate::client::dns;

const LARGEST_PACKET: usize = u16::MAX as usize;
const MAX_CONNECTIONS: usize = 16;
const UDP_QUEUE: usize = 64;
const TCP_RECEIVE: usize = 4096;
const TCP_SEND: usize = 2 + u16::MAX as usize;
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub enum Asker {
    Udp(IpEndpoint),
    Tcp(SocketHandle),
}

pub type Query = (Asker, Vec<u8>);

pub struct Host {
    network: Ipv4Net,
    interface: Interface,
    sockets: SocketSet<'static>,
    queues: Queues,
    udp: SocketHandle,
    streams: HashMap<SocketHandle, Stream>,
}

impl Host {
    pub fn new(network: Ipv4Net) -> Self {
        let mut queues = Queues::default();
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut queues,
            Instant::now(),
        );
        interface.update_ip_addrs(|addresses| {
            let cidr = IpCidr::new(IpAddress::Ipv4(network.network()), network.prefix_len());
            let _ = addresses.push(cidr);
        });

        let mut sockets = SocketSet::new(Vec::new());
        let mut udp = udp::Socket::new(udp_buffer(), udp_buffer());
        let _ = udp.bind(SocketAddrV4::new(network.network(), DNS_PORT));
        let udp = sockets.add(udp);

        let mut host = Self {
            network,
            interface,
            sockets,
            queues,
            udp,
            streams: HashMap::new(),
        };
        host.listen();
        host
    }

    pub const fn network(&self) -> Ipv4Net {
        self.network
    }

    pub fn receive(&mut self, packet: Vec<u8>) {
        self.queues.received.push_back(packet);
    }

    pub fn transmit(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.queues.sent)
    }

    pub fn delay(&mut self) -> Option<Duration> {
        self.interface
            .poll_delay(Instant::now(), &self.sockets)
            .map(Into::into)
    }

    pub fn poll(&mut self) -> Vec<Query> {
        self.interface
            .poll(Instant::now(), &mut self.queues, &mut self.sockets);

        let mut queries = Vec::new();
        self.read_datagrams(&mut queries);
        self.read_streams(&mut queries);

        if !self.listening() && self.streams.len() < MAX_CONNECTIONS {
            self.listen();
        }

        queries
    }

    pub fn respond(&mut self, asker: Asker, response: &[u8]) {
        match asker {
            Asker::Udp(endpoint) => {
                let socket = self.sockets.get_mut::<udp::Socket<'static>>(self.udp);
                let _ = socket.send_slice(response, endpoint);
            },
            Asker::Tcp(handle) => {
                let Some(stream) = self.streams.get_mut(&handle) else {
                    return;
                };
                let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
                stream.outstanding = stream.outstanding.saturating_sub(1);

                if let Some(framed) = dns::frame(response) {
                    let _ = socket.send_slice(&framed);
                }

                stream.close_when_answered(socket);
            },
        }
    }

    pub fn reject(&mut self, asker: Asker) {
        if let Asker::Tcp(handle) = asker
            && self.streams.contains_key(&handle)
        {
            self.sockets.get_mut::<tcp::Socket<'static>>(handle).abort();
        }
    }

    fn read_datagrams(&mut self, queries: &mut Vec<Query>) {
        let socket = self.sockets.get_mut::<udp::Socket<'static>>(self.udp);

        while let Ok((query, meta)) = socket.recv() {
            queries.push((Asker::Udp(meta.endpoint), query.to_vec()));
        }
    }

    fn read_streams(&mut self, queries: &mut Vec<Query>) {
        let mut closed = Vec::new();

        for (handle, socket) in self.sockets.iter_mut() {
            let Some(socket) = tcp::Socket::downcast_mut(socket) else {
                continue;
            };

            if socket.state() == tcp::State::Closed {
                closed.push(handle);
                continue;
            }

            let stream = self.streams.entry(handle).or_default();
            stream.read(socket);

            while let Some(query) = dns::unframe(&mut stream.received) {
                stream.outstanding += 1;
                queries.push((Asker::Tcp(handle), query));
            }

            stream.close_when_answered(socket);
        }

        for handle in closed {
            self.sockets.remove(handle);
            self.streams.remove(&handle);
        }
    }

    fn listening(&self) -> bool {
        self.sockets.iter().any(|(_, socket)| {
            tcp::Socket::downcast(socket).is_some_and(|socket| socket.state() == tcp::State::Listen)
        })
    }

    fn listen(&mut self) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECEIVE]),
            tcp::SocketBuffer::new(vec![0; TCP_SEND]),
        );
        socket.set_timeout(Some(IDLE_TIMEOUT.into()));

        if socket
            .listen(SocketAddrV4::new(self.network.network(), DNS_PORT))
            .is_ok()
        {
            let handle = self.sockets.add(socket);
            self.streams.insert(handle, Stream::default());
        }
    }
}

#[derive(Default)]
struct Stream {
    received: BytesMut,
    outstanding: usize,
}

impl Stream {
    fn read(&mut self, socket: &mut tcp::Socket<'_>) {
        while socket.can_recv() {
            let _ = socket.recv(|data| {
                self.received.extend_from_slice(data);
                (data.len(), ())
            });
        }
    }

    fn close_when_answered(&self, socket: &mut tcp::Socket<'_>) {
        if !socket.may_recv() && self.outstanding == 0 {
            socket.close();
        }
    }
}

#[derive(Default)]
struct Queues {
    received: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

struct Received(Vec<u8>);

struct Sent<'a>(&'a mut Vec<Vec<u8>>);

impl Device for Queues {
    type RxToken<'a> = Received;
    type TxToken<'a> = Sent<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Received, Sent<'_>)> {
        let packet = self.received.pop_front()?;
        Some((Received(packet), Sent(&mut self.sent)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Sent<'_>> {
        Some(Sent(&mut self.sent))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = LARGEST_PACKET;
        capabilities
    }
}

impl RxToken for Received {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for Sent<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push(packet);
        result
    }
}

fn udp_buffer() -> udp::PacketBuffer<'static> {
    udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_QUEUE],
        vec![0; LARGEST_PACKET],
    )
}
