mod compile;
mod names;
mod policy;
mod selector;

use compass_proto::DnsError;

pub use compile::{Compiled, NodeAccess, Subject, compile};
pub use names::NamePattern;
pub use policy::{Policy, RuleConfig};
pub use selector::{Selector, Tag};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AclError {
    #[error("invalid selector \"{0}\": {1}")]
    InvalidSelector(String, &'static str),
    #[error("invalid group name \"{0}\"")]
    InvalidGroupName(String),
    #[error("group \"{group}\" contains \"{member}\"; groups may only contain users")]
    InvalidMember { group: String, member: String },
    #[error("group \"{0}\" is not defined in [groups]")]
    UnknownGroup(String),
    #[error("acl rule #{}: {reason}", index + 1)]
    InvalidRule { index: usize, reason: &'static str },
    #[error("acl rule #{}: {error}", index + 1)]
    InvalidName { index: usize, error: DnsError },
}
