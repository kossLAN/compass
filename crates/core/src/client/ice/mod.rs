mod candidate;
mod peer;
mod stun;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bunnyhop_net::{Datagram, Stun};
use bunnyhop_proto::{CandidateKind, IceCandidate, NodeId, PublicKey, SignalMessage};
use bytes::BytesMut;
use ipnet::IpNet;
use rtc_ice::crypto::RTCCryptoProvider;
use rtc_shared::{TransportContext, TransportMessage, TransportProtocol};
use sansio::Protocol as _;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use self::peer::PeerIce;
use self::stun::TransactionId;
use crate::binding;

const TRANSACTION_TTL: Duration = Duration::from_secs(30);
const IDLE_WAKEUP: Duration = Duration::from_secs(60);
const READ_RETRY: Duration = Duration::from_millis(100);
const PROBE_INTERVAL: Duration = Duration::from_secs(25);
const PROBE_FIRST_RETRY: Duration = Duration::from_secs(1);
const MAPPING_TTL: Duration = Duration::from_secs(90);

#[derive(Debug)]
pub enum IceEvent {
    Signal {
        to: NodeId,
        message: SignalMessage,
    },
    Direct {
        key: PublicKey,
        endpoint: SocketAddr,
    },
    Relayed {
        key: PublicKey,
    },
    Reflexive(Vec<SocketAddr>),
}

pub fn controls(own_key: &PublicKey, peer_key: &PublicKey) -> bool {
    own_key > peer_key
}

#[derive(Debug, Clone, Copy)]
pub struct IcePeer {
    pub id: NodeId,
    pub key: PublicKey,
    pub online: bool,
}

enum Command {
    Peers {
        peers: Vec<IcePeer>,
        prefixes: Vec<IpNet>,
    },
    Hubs(Vec<SocketAddr>),
    LocalNetworks(Vec<IpNet>),
    Signal(NodeId, SignalMessage),
}

pub struct IceHandle {
    commands: mpsc::UnboundedSender<Command>,
    task: JoinHandle<()>,
}

impl IceHandle {
    pub fn spawn(
        transport: Option<Stun>,
        port: u16,
        own_key: PublicKey,
        local_networks: Vec<IpNet>,
        events: mpsc::Sender<(u64, IceEvent)>,
        generation: u64,
    ) -> Self {
        let (commands, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let Some(transport) = transport else {
                tracing::error!("ICE is disabled; peers are only reached through a hub");
                return;
            };

            let crypto = match rtc_ice::crypto::default_provider() {
                Ok(crypto) => crypto,
                Err(error) => {
                    tracing::error!(%error, "ICE is disabled; peers are only reached through a hub");
                    return;
                },
            };

            let service = IceService {
                transport,
                port,
                own_key,
                crypto,
                local_networks,
                observed: Vec::new(),
                prefixes: None,
                peers: BTreeMap::new(),
                hubs: BTreeMap::new(),
                transactions: HashMap::new(),
                events,
                generation,
            };
            service.run(receiver).await;
        });
        Self { commands, task }
    }

    pub fn set_peers(&self, peers: Vec<IcePeer>, prefixes: Vec<IpNet>) {
        let _ = self.commands.send(Command::Peers { peers, prefixes });
    }

    pub fn set_hubs(&self, hubs: Vec<SocketAddr>) {
        let _ = self.commands.send(Command::Hubs(hubs));
    }

    pub fn set_local_networks(&self, networks: Vec<IpNet>) {
        let _ = self.commands.send(Command::LocalNetworks(networks));
    }

    pub fn signal(&self, from: NodeId, message: SignalMessage) {
        let _ = self.commands.send(Command::Signal(from, message));
    }
}

impl Drop for IceHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct IceService {
    transport: Stun,
    port: u16,
    own_key: PublicKey,
    crypto: Arc<dyn RTCCryptoProvider>,
    local_networks: Vec<IpNet>,
    observed: Vec<SocketAddr>,
    prefixes: Option<Vec<IpNet>>,
    peers: BTreeMap<NodeId, PeerIce>,
    hubs: BTreeMap<SocketAddr, HubProbe>,
    transactions: HashMap<TransactionId, (Transaction, Instant)>,
    events: mpsc::Sender<(u64, IceEvent)>,
    generation: u64,
}

#[derive(Debug, Clone, Copy)]
enum Transaction {
    Peer(NodeId),
    Hub(SocketAddr),
}

struct HubProbe {
    next: Instant,
    retry: Duration,
    mapped: Option<(SocketAddr, Instant)>,
}

impl IceService {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        loop {
            self.flush().await;
            let wakeup = self
                .peers
                .values_mut()
                .filter_map(PeerIce::next_deadline)
                .chain(self.hubs.values().map(|probe| probe.next))
                .min()
                .unwrap_or_else(|| Instant::now() + IDLE_WAKEUP);

            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.handle(command).await,
                    None => return,
                },
                received = self.transport.recv() => match received {
                    Ok(datagram) => self.receive(datagram).await,
                    Err(error) => {
                        tracing::warn!(%error, "failed to read STUN");
                        tokio::time::sleep(READ_RETRY).await;
                    },
                },
                () = tokio::time::sleep_until(wakeup.into()) => self.timeout().await,
            }
        }
    }

    async fn handle(&mut self, command: Command) {
        let now = Instant::now();

        match command {
            Command::Peers { peers, prefixes } => {
                self.prefixes = Some(prefixes);
                let mut removed = Vec::new();
                self.peers.retain(|id, state| {
                    let keep = peers.iter().any(|peer| peer.id == *id);

                    if !keep && state.path().is_some() {
                        removed.push(IceEvent::Relayed { key: state.key() });
                    }

                    keep
                });

                for peer in peers {
                    self.peers
                        .entry(peer.id)
                        .or_insert_with(|| PeerIce::new(peer.key, self.own_key))
                        .set_online(peer.online, now);
                }

                for event in removed {
                    self.emit(event).await;
                }
            },
            Command::Hubs(hubs) => {
                self.hubs.retain(|hub, _| hubs.contains(hub));

                for hub in hubs {
                    self.hubs.entry(hub).or_insert(HubProbe {
                        next: now,
                        retry: PROBE_FIRST_RETRY,
                        mapped: None,
                    });
                }

                self.update_observed(now).await;
            },
            Command::LocalNetworks(networks) => {
                if networks == self.local_networks {
                    return;
                }

                self.local_networks = networks;

                for probe in self.hubs.values_mut() {
                    probe.next = now;
                    probe.retry = PROBE_FIRST_RETRY;
                }

                let changes: Vec<IceEvent> = self
                    .peers
                    .values_mut()
                    .filter_map(|peer| peer.restart(now))
                    .collect();

                for event in changes {
                    self.emit(event).await;
                }
            },
            Command::Signal(from, message) => self.on_signal(from, &message, now).await,
        }
    }

    async fn on_signal(&mut self, from: NodeId, message: &SignalMessage, now: Instant) {
        let session = message.session();

        if let Err(error) = session.check() {
            tracing::debug!(%from, %error, "ignoring an invalid ICE signal");
            return;
        }

        let Some(prefixes) = &self.prefixes else {
            return;
        };

        let remote_candidates: Vec<IceCandidate> = session
            .candidates
            .iter()
            .filter(|candidate| candidate::usable(candidate, prefixes))
            .copied()
            .collect();
        let candidates = self.candidates();

        let Some(peer) = self.peers.get_mut(&from) else {
            tracing::debug!(%from, "ignoring an ICE signal from an unknown peer");
            return;
        };

        tracing::debug!(
            %from,
            session = session.id,
            candidates = remote_candidates.len(),
            offer = matches!(message, SignalMessage::Offer(_)),
            "ICE signal"
        );

        let (reply, change) = match peer.on_signal(
            message,
            &candidates,
            &remote_candidates,
            Arc::clone(&self.crypto),
            now,
        ) {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(%from, %error, "failed to start ICE");
                (None, peer.fail(now))
            },
        };

        if let Some(event) = change {
            self.emit(event).await;
        }

        if let Some(message) = reply {
            self.emit(IceEvent::Signal { to: from, message }).await;
        }
    }

    async fn receive(&mut self, datagram: Datagram) {
        let Some(header) = stun::parse(&datagram.payload) else {
            return;
        };

        let id = if header.request {
            header.receiver_ufrag().and_then(|ufrag| {
                self.peers
                    .iter()
                    .find(|(_, peer)| peer.ufrag() == ufrag)
                    .map(|(id, _)| *id)
            })
        } else {
            match self.transactions.remove(&header.transaction) {
                Some((Transaction::Peer(id), _)) => Some(id),
                Some((Transaction::Hub(hub), _)) => {
                    self.on_mapping(hub, &datagram.payload).await;
                    return;
                },
                None => None,
            }
        };

        let Some(agent) = id
            .and_then(|id| self.peers.get_mut(&id))
            .and_then(PeerIce::agent_mut)
        else {
            return;
        };

        let message = TransportMessage {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: datagram.local,
                peer_addr: datagram.remote,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(datagram.payload.as_slice()),
        };

        if let Err(error) = agent.handle_read(message) {
            tracing::debug!(remote = %datagram.remote, %error, "dropped a STUN message");
        }
    }

    async fn on_mapping(&mut self, hub: SocketAddr, response: &[u8]) {
        let Some(mapped) = binding::mapped_address(response) else {
            return;
        };

        let Some(probe) = self.hubs.get_mut(&hub) else {
            return;
        };

        let now = Instant::now();
        probe.mapped = Some((mapped, now));
        probe.next = now + PROBE_INTERVAL;
        probe.retry = PROBE_FIRST_RETRY;
        self.update_observed(now).await;
    }

    async fn probe_hubs(&mut self, now: Instant) {
        let mut requests = Vec::new();

        for (hub, probe) in &mut self.hubs {
            if probe.next > now {
                continue;
            }

            let mut transaction = [0; 12];
            getrandom::fill(&mut transaction).expect("the OS random number generator failed");
            self.transactions
                .insert(transaction, (Transaction::Hub(*hub), now));
            probe.next = now + probe.retry;
            probe.retry = (probe.retry * 2).min(PROBE_INTERVAL);
            requests.push((*hub, binding::request(transaction)));
        }

        for (hub, request) in requests {
            if let Err(error) = self.transport.send(hub, &request).await {
                tracing::debug!(%hub, %error, "failed to ask a hub for this node's mapping");
            }
        }

        self.update_observed(now).await;
    }

    async fn update_observed(&mut self, now: Instant) {
        let mut observed: Vec<SocketAddr> = self
            .hubs
            .values()
            .filter_map(|probe| probe.mapped)
            .filter(|(_, at)| now.saturating_duration_since(*at) < MAPPING_TTL)
            .map(|(mapped, _)| mapped)
            .collect();
        observed.sort_unstable();
        observed.dedup();

        if observed != self.observed {
            self.observed.clone_from(&observed);
            self.emit(IceEvent::Reflexive(observed)).await;
        }
    }

    async fn timeout(&mut self) {
        let now = Instant::now();
        self.probe_hubs(now).await;
        let candidates = self.candidates();
        let can_offer = candidates
            .iter()
            .any(|candidate| candidate.kind == CandidateKind::Host);
        let mut offers = Vec::new();

        for (id, peer) in &mut self.peers {
            if let Some(agent) = peer.agent_mut()
                && agent.poll_timeout().is_some_and(|at| at <= now)
                && let Err(error) = agent.handle_timeout(now)
            {
                tracing::debug!(peer = %id, %error, "ICE timeout handling failed");
            }

            if let Some(message) = peer.due_offer(now, &candidates)
                && can_offer
            {
                tracing::debug!(peer = %id, session = message.session().id, "sending an ICE offer");
                offers.push(IceEvent::Signal { to: *id, message });
            }
        }

        for offer in offers {
            self.emit(offer).await;
        }
    }

    async fn flush(&mut self) {
        let now = Instant::now();
        self.transactions
            .retain(|_, (_, at)| now.duration_since(*at) < TRANSACTION_TTL);
        let mut outgoing = Vec::new();
        let mut agent_events = Vec::new();

        for (id, peer) in &mut self.peers {
            let Some(agent) = peer.agent_mut() else {
                continue;
            };

            while let Some(transmit) = agent.poll_write() {
                if let Some(header) = stun::parse(&transmit.message)
                    && header.request
                {
                    self.transactions
                        .insert(header.transaction, (Transaction::Peer(*id), now));
                }

                outgoing.push((transmit.transport.peer_addr, transmit.message));
            }

            while let Some(tagged) = agent.poll_event() {
                agent_events.push((*id, tagged.event));
            }
        }

        for (remote, packet) in outgoing {
            if let Err(error) = self.transport.send(remote, &packet).await {
                tracing::debug!(%remote, %error, "failed to send STUN");
            }
        }

        for (id, event) in agent_events {
            if let Some(change) = self
                .peers
                .get_mut(&id)
                .and_then(|peer| peer.on_event(event, now))
            {
                self.emit(change).await;
            }
        }
    }

    fn candidates(&self) -> Vec<IceCandidate> {
        candidate::gather(&self.local_networks, self.port, &self.observed)
    }

    async fn emit(&self, event: IceEvent) {
        let _ = self.events.send((self.generation, event)).await;
    }
}
