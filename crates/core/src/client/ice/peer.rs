use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compass_proto::{CandidateKind, IceCandidate, IceSession, PublicKey, SignalMessage};
use rtc_ice::agent::agent_config::AgentConfig;
use rtc_ice::candidate::CandidateType;
use rtc_ice::crypto::RTCCryptoProvider;
use rtc_ice::mdns::MulticastDnsMode;
use rtc_ice::network_type::NetworkType;
use rtc_ice::state::ConnectionState;
use rtc_ice::{Agent, Event};
use rtc_shared::error::Error;
use sansio::Protocol as _;

use super::IceEvent;
use super::candidate::to_rtc;

const KEEPALIVE: Duration = Duration::from_secs(4);
const DISCONNECTED_TIMEOUT: Duration = Duration::from_secs(6);
const FAILED_TIMEOUT: Duration = Duration::from_secs(6);
const FIRST_RETRY: Duration = Duration::from_millis(800);
const MAX_RETRY: Duration = Duration::from_secs(60);
const UFRAG_LEN: usize = 16;
const PWD_LEN: usize = 32;

pub struct PeerIce {
    key: PublicKey,
    online: bool,
    controlling: bool,
    local: IceSession,
    remote_session: Option<u64>,
    agent: Option<Agent>,
    connected: bool,
    path: Option<SocketAddr>,
    next_offer: Option<Instant>,
    retry: Duration,
}

impl PeerIce {
    pub fn new(key: PublicKey, own_key: PublicKey) -> Self {
        Self {
            key,
            online: false,
            controlling: super::controls(&own_key, &key),
            local: new_session(),
            remote_session: None,
            agent: None,
            connected: false,
            path: None,
            next_offer: None,
            retry: FIRST_RETRY,
        }
    }

    pub const fn key(&self) -> PublicKey {
        self.key
    }

    pub const fn agent_mut(&mut self) -> Option<&mut Agent> {
        self.agent.as_mut()
    }

    pub fn ufrag(&self) -> &str {
        &self.local.ufrag
    }

    pub const fn path(&self) -> Option<SocketAddr> {
        self.path
    }

    pub fn set_online(&mut self, online: bool, now: Instant) {
        if online && !self.online && self.agent.is_none() {
            self.retry = FIRST_RETRY;
            self.next_offer = Some(now);
        }

        if !online && self.agent.is_none() {
            self.next_offer = None;
        }

        self.online = online;
    }

    pub fn next_deadline(&mut self) -> Option<Instant> {
        let agent = self.agent.as_mut().and_then(Agent::poll_timeout);
        agent.into_iter().chain(self.next_offer).min()
    }

    pub fn due_offer(
        &mut self,
        now: Instant,
        candidates: &[IceCandidate],
    ) -> Option<SignalMessage> {
        if !self.online || self.agent.is_some() || self.next_offer.is_none_or(|at| at > now) {
            return None;
        }

        self.next_offer = Some(now + self.retry);
        self.retry = (self.retry * 2).min(MAX_RETRY);
        Some(SignalMessage::Offer(self.session(candidates)))
    }

    pub fn on_signal(
        &mut self,
        message: &SignalMessage,
        candidates: &[IceCandidate],
        remote_candidates: &[IceCandidate],
        crypto: Arc<dyn RTCCryptoProvider>,
        now: Instant,
    ) -> Result<(Option<SignalMessage>, Option<IceEvent>), Error> {
        let remote = message.session();
        let mut change = None;

        if self.remote_session != Some(remote.id) {
            self.agent = None;
            self.connected = false;
            change = self.set_path(None);
            self.start(remote, candidates, remote_candidates, crypto, now)?;
        }

        let reply = matches!(message, SignalMessage::Offer(_))
            .then(|| SignalMessage::Answer(self.session(candidates)));
        Ok((reply, change))
    }

    pub fn on_event(&mut self, event: Event, now: Instant) -> Option<IceEvent> {
        if let Event::ConnectionStateChange(state) = &event {
            tracing::debug!(peer = %self.key, ?state, "ICE state");
        }

        match event {
            Event::ConnectionStateChange(
                ConnectionState::Connected | ConnectionState::Completed,
            ) => {
                self.connected = true;
                self.retry = FIRST_RETRY;
                let remote = self.agent.as_ref()?.get_selected_candidate_pair()?.1.addr();
                self.set_path(Some(remote))
            },
            Event::SelectedCandidatePairChange(_, remote) if self.connected => {
                self.set_path(Some(remote.addr()))
            },
            Event::ConnectionStateChange(
                ConnectionState::Disconnected | ConnectionState::Failed | ConnectionState::Closed,
            ) => self.fail(now),
            _ => None,
        }
    }

    pub fn fail(&mut self, now: Instant) -> Option<IceEvent> {
        self.agent = None;
        self.connected = false;
        self.remote_session = None;
        self.local = new_session();
        self.next_offer = self.online.then(|| now + self.retry);
        self.retry = (self.retry * 2).min(MAX_RETRY);
        self.set_path(None)
    }

    pub fn restart(&mut self, now: Instant) -> Option<IceEvent> {
        let change = self.fail(now);
        self.retry = FIRST_RETRY;
        self.next_offer = self.online.then_some(now);
        change
    }

    fn start(
        &mut self,
        remote: &IceSession,
        candidates: &[IceCandidate],
        remote_candidates: &[IceCandidate],
        crypto: Arc<dyn RTCCryptoProvider>,
        now: Instant,
    ) -> Result<(), Error> {
        let config = AgentConfig {
            local_ufrag: self.local.ufrag.clone(),
            local_pwd: self.local.pwd.clone(),
            multicast_dns_mode: MulticastDnsMode::Disabled,
            candidate_types: vec![CandidateType::Host, CandidateType::ServerReflexive],
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            keepalive_interval: Some(KEEPALIVE),
            disconnected_timeout: Some(DISCONNECTED_TIMEOUT),
            failed_timeout: Some(FAILED_TIMEOUT),
            ..AgentConfig::default()
        };
        let mut agent = Agent::new(now, Arc::new(config), crypto)?;

        for candidate in candidates
            .iter()
            .filter(|candidate| candidate.kind == CandidateKind::Host)
        {
            agent.add_local_candidate(to_rtc(candidate)?)?;
        }

        agent.start_connectivity_checks(
            now,
            self.controlling,
            remote.ufrag.clone(),
            remote.pwd.clone(),
        )?;

        for candidate in remote_candidates {
            agent.add_remote_candidate(to_rtc(candidate)?)?;
        }

        self.agent = Some(agent);
        self.remote_session = Some(remote.id);
        self.next_offer = None;
        Ok(())
    }

    fn session(&self, candidates: &[IceCandidate]) -> IceSession {
        IceSession {
            candidates: candidates.to_vec(),
            ..self.local.clone()
        }
    }

    fn set_path(&mut self, path: Option<SocketAddr>) -> Option<IceEvent> {
        if self.path == path {
            return None;
        }

        self.path = path;
        Some(match path {
            Some(endpoint) => IceEvent::Direct {
                key: self.key,
                endpoint,
            },
            None => IceEvent::Relayed { key: self.key },
        })
    }
}

fn new_session() -> IceSession {
    IceSession {
        id: getrandom::u64().expect("the OS random number generator failed"),
        ufrag: random_ice_chars(UFRAG_LEN),
        pwd: random_ice_chars(PWD_LEN),
        candidates: Vec::new(),
    }
}

fn random_ice_chars(len: usize) -> String {
    const ICE_CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = vec![0; len];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    bytes
        .iter()
        .map(|byte| char::from(ICE_CHARS[usize::from(byte & 0x3f)]))
        .collect()
}
