use std::net::SocketAddr;
use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

use crate::NodeId;

pub const MAX_CANDIDATES: usize = 32;
const UFRAG_LEN: RangeInclusive<usize> = 4..=256;
const PWD_LEN: RangeInclusive<usize> = 22..=256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignalError {
    #[error("ICE ufrag must be 4 to 256 and pwd 22 to 256 letters, digits, '+' or '/'")]
    Credentials,
    #[error("at most {MAX_CANDIDATES} ICE candidates are allowed")]
    Candidates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Host,
    ServerReflexive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    pub kind: CandidateKind,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceSession {
    pub id: u64,
    pub ufrag: String,
    pub pwd: String,
    pub candidates: Vec<IceCandidate>,
}

impl IceSession {
    pub fn check(&self) -> Result<(), SignalError> {
        let valid = |value: &str, len: RangeInclusive<usize>| {
            len.contains(&value.len())
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        };

        if !valid(&self.ufrag, UFRAG_LEN) || !valid(&self.pwd, PWD_LEN) {
            return Err(SignalError::Credentials);
        }

        if self.candidates.len() > MAX_CANDIDATES {
            return Err(SignalError::Candidates);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "session")]
pub enum SignalMessage {
    Offer(IceSession),
    Answer(IceSession),
}

impl SignalMessage {
    pub const fn session(&self) -> &IceSession {
        match self {
            Self::Offer(session) | Self::Answer(session) => session,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    pub to: NodeId,
    pub message: SignalMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalDelivery {
    pub from: NodeId,
    pub message: SignalMessage,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignalBatch {
    pub messages: Vec<SignalDelivery>,
}
