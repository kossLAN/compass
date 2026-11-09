use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use compass_proto::{PacketRule, Proto};
use etherparse::{
    Icmpv4Slice, Icmpv4Type, Icmpv6Slice, Icmpv6Type, IpNumber, IpSlice, LaxIpSlice, TcpSlice,
    UdpSlice,
};

use crate::MeshRules;

const MAX_FLOWS: usize = 1 << 16;
const TCP_OPENING: Duration = Duration::from_secs(120);
const TCP_ESTABLISHED: Duration = Duration::from_secs(5 * 24 * 60 * 60);
const TCP_CLOSING: Duration = Duration::from_secs(60);
const UDP_UNREPLIED: Duration = Duration::from_secs(30);
const UDP_REPLIED: Duration = Duration::from_secs(120);
const OTHER: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Filter {
    rules: ArcSwapOption<Vec<MeshRules>>,
    flows: Mutex<Flows>,
}

impl Filter {
    pub fn set_rules(&self, rules: Vec<MeshRules>) {
        self.rules.store(Some(Arc::new(rules)));
    }

    pub fn track(&self, packet: &[u8]) {
        if self.rules.load().is_none() {
            return;
        }

        if let Some(Packet::Flow(endpoints, segment)) = classify(packet) {
            self.flows()
                .see(endpoints, segment, Origin::Local, Instant::now());
        }
    }

    pub fn admits(&self, packet: &[u8]) -> bool {
        let Some(rules) = self.rules.load_full() else {
            return true;
        };
        let now = Instant::now();
        let mut flows = self.flows();

        match classify(packet) {
            Some(Packet::Flow(endpoints, segment)) => {
                let key = endpoints.reversed();
                let reply = flows
                    .live(&key, now)
                    .is_some_and(|flow| flow.origin == Origin::Local);

                if !reply && !permitted(&rules, &endpoints) {
                    return false;
                }

                flows.see(key, segment, Origin::Remote, now);
                true
            },
            Some(Packet::Related(quoted)) => flows.live(&quoted, now).is_some(),
            Some(Packet::Fragment(endpoints)) => flows.connects(&endpoints.reversed(), now),
            None => false,
        }
    }

    pub fn expire(&self) {
        self.flows().expire(Instant::now());
    }

    fn flows(&self) -> MutexGuard<'_, Flows> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Endpoints {
    protocol: IpNumber,
    source: (IpAddr, u16),
    destination: (IpAddr, u16),
}

impl Endpoints {
    const fn reversed(self) -> Self {
        Self {
            protocol: self.protocol,
            source: self.destination,
            destination: self.source,
        }
    }

    const fn hosts(&self) -> (IpNumber, IpAddr, IpAddr) {
        (self.protocol, self.source.0, self.destination.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment {
    Open,
    Close,
    Data,
}

impl Segment {
    fn of(tcp: &TcpSlice<'_>) -> Self {
        if tcp.fin() || tcp.rst() {
            Self::Close
        } else if tcp.syn() && !tcp.ack() {
            Self::Open
        } else {
            Self::Data
        }
    }
}

struct Flow {
    protocol: IpNumber,
    origin: Origin,
    replied: bool,
    closing: bool,
    expires: Instant,
}

impl Flow {
    fn new(protocol: IpNumber, segment: Segment, origin: Origin, now: Instant) -> Self {
        let mut flow = Self {
            protocol,
            origin,
            replied: false,
            closing: false,
            expires: now,
        };
        flow.see(segment, origin, now);
        flow
    }

    fn see(&mut self, segment: Segment, from: Origin, now: Instant) {
        match segment {
            Segment::Open => self.closing = false,
            Segment::Close => self.closing = true,
            Segment::Data => {},
        }

        self.replied |= from != self.origin;
        self.expires = now + self.timeout();
    }

    const fn timeout(&self) -> Duration {
        match self.protocol {
            IpNumber::TCP if self.closing => TCP_CLOSING,
            IpNumber::TCP if self.replied => TCP_ESTABLISHED,
            IpNumber::TCP => TCP_OPENING,
            IpNumber::UDP if self.replied => UDP_REPLIED,
            IpNumber::UDP => UDP_UNREPLIED,
            _ => OTHER,
        }
    }

    fn live(&self, now: Instant) -> bool {
        self.expires > now
    }
}

#[derive(Default)]
struct Flows(HashMap<Endpoints, Flow>);

impl Flows {
    fn live(&mut self, key: &Endpoints, now: Instant) -> Option<&mut Flow> {
        self.0.get_mut(key).filter(|flow| flow.live(now))
    }

    fn see(&mut self, key: Endpoints, segment: Segment, from: Origin, now: Instant) {
        if let Some(flow) = self.live(&key, now) {
            flow.see(segment, from, now);
            return;
        }

        if self.0.len() >= MAX_FLOWS {
            self.expire(now);
        }

        if self.0.len() < MAX_FLOWS {
            self.0
                .insert(key, Flow::new(key.protocol, segment, from, now));
        }
    }

    fn connects(&self, key: &Endpoints, now: Instant) -> bool {
        self.0
            .iter()
            .any(|(endpoints, flow)| flow.live(now) && endpoints.hosts() == key.hosts())
    }

    fn expire(&mut self, now: Instant) {
        self.0.retain(|_, flow| flow.live(now));
    }
}

fn permitted(rules: &[MeshRules], endpoints: &Endpoints) -> bool {
    let (source, _) = endpoints.source;
    let (destination, port) = endpoints.destination;

    rules.iter().any(|mesh| {
        mesh.addresses.contains(&destination)
            && mesh.inbound.iter().any(|rule| {
                rule.src.iter().any(|net| net.contains(&source))
                    && rule_matches(rule, endpoints.protocol, port)
            })
    })
}

fn rule_matches(rule: &PacketRule, protocol: IpNumber, port: u16) -> bool {
    let proto = match protocol {
        IpNumber::TCP => Some(Proto::Tcp),
        IpNumber::UDP => Some(Proto::Udp),
        IpNumber::ICMP | IpNumber::IPV6_ICMP => Some(Proto::Icmp),
        _ => None,
    };
    let proto_listed =
        rule.protos.is_empty() || proto.is_some_and(|proto| rule.protos.contains(&proto));
    let port_listed = rule.ports.is_empty()
        || (matches!(proto, Some(Proto::Tcp | Proto::Udp))
            && rule
                .ports
                .iter()
                .any(|range| (range.start..=range.end).contains(&port)));

    proto_listed && port_listed
}

enum Packet {
    Flow(Endpoints, Segment),
    Related(Endpoints),
    Fragment(Endpoints),
}

enum Icmp<'a> {
    Echo(u16),
    Error(&'a [u8]),
    Other,
}

fn classify(packet: &[u8]) -> Option<Packet> {
    let ip = IpSlice::from_slice(packet).ok()?;
    let payload = ip.payload();
    let endpoints = |(source, destination): (u16, u16)| Endpoints {
        protocol: payload.ip_number,
        source: (ip.source_addr(), source),
        destination: (ip.destination_addr(), destination),
    };

    if payload.fragmented {
        return Some(Packet::Fragment(endpoints((0, 0))));
    }

    let (ports, segment) = match payload.ip_number {
        IpNumber::TCP => {
            let tcp = TcpSlice::from_slice(payload.payload).ok()?;
            (
                (tcp.source_port(), tcp.destination_port()),
                Segment::of(&tcp),
            )
        },
        IpNumber::UDP => {
            let udp = UdpSlice::from_slice(payload.payload).ok()?;
            ((udp.source_port(), udp.destination_port()), Segment::Data)
        },
        protocol @ (IpNumber::ICMP | IpNumber::IPV6_ICMP) => {
            match icmp(protocol, payload.payload)? {
                Icmp::Echo(id) => ((id, id), Segment::Data),
                Icmp::Error(original) => return quoted(original).map(Packet::Related),
                Icmp::Other => ((0, 0), Segment::Data),
            }
        },
        _ => ((0, 0), Segment::Data),
    };

    Some(Packet::Flow(endpoints(ports), segment))
}

fn icmp(protocol: IpNumber, message: &[u8]) -> Option<Icmp<'_>> {
    if protocol == IpNumber::ICMP {
        let icmp = Icmpv4Slice::from_slice(message).ok()?;

        return Some(match icmp.icmp_type() {
            Icmpv4Type::EchoRequest(echo) | Icmpv4Type::EchoReply(echo) => Icmp::Echo(echo.id),
            Icmpv4Type::DestinationUnreachable(_)
            | Icmpv4Type::TimeExceeded(_)
            | Icmpv4Type::ParameterProblem(_) => Icmp::Error(icmp.payload()),
            _ => Icmp::Other,
        });
    }

    let icmp = Icmpv6Slice::from_slice(message).ok()?;

    Some(match icmp.icmp_type() {
        Icmpv6Type::EchoRequest(echo) | Icmpv6Type::EchoReply(echo) => Icmp::Echo(echo.id),
        Icmpv6Type::DestinationUnreachable(_)
        | Icmpv6Type::PacketTooBig { .. }
        | Icmpv6Type::TimeExceeded(_)
        | Icmpv6Type::ParameterProblem(_) => Icmp::Error(icmp.payload()),
        _ => Icmp::Other,
    })
}

#[expect(
    clippy::big_endian_bytes,
    reason = "an ICMP error quotes only the first bytes of the transport header, which hold the ports in network order"
)]
fn quoted(original: &[u8]) -> Option<Endpoints> {
    let (ip, _) = LaxIpSlice::from_slice(original).ok()?;
    let payload = ip.payload();
    let header = payload.payload;
    let word = |at: usize| Some(u16::from_be_bytes([*header.get(at)?, *header.get(at + 1)?]));
    let (source_port, destination_port) = match payload.ip_number {
        IpNumber::TCP | IpNumber::UDP => (word(0)?, word(2)?),
        IpNumber::ICMP | IpNumber::IPV6_ICMP => (word(4)?, word(4)?),
        _ => (0, 0),
    };

    Some(Endpoints {
        protocol: payload.ip_number,
        source: (ip.source_addr(), source_port),
        destination: (ip.destination_addr(), destination_port),
    })
}
