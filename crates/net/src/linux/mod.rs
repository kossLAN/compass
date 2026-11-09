mod dataplane;
mod firewall;
mod kernel;
mod link;
mod resolvconf;
mod route;
mod rule;
mod sysctl;
mod wireguard;

pub use self::dataplane::Dataplane;
pub use self::firewall::{Firewall, NodeRules};
pub use self::kernel::KernelStun;
pub use self::wireguard::Wireguard;
use crate::NetError;

const PROTOCOL: u8 = 82;
const TABLE: &str = "compass";

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const ENODEV: i32 = 19;
const EADDRNOTAVAIL: i32 = 99;

impl NetError {
    fn is_os_error(&self, code: i32) -> bool {
        matches!(self, Self::Netlink(error) if error.raw_os_error() == Some(code))
    }

    fn genetlink(error: genetlink::GenetlinkError) -> Self {
        match error {
            genetlink::GenetlinkError::NetlinkError(error) => Self::Netlink(error),
            error => Self::Protocol(error.to_string()),
        }
    }

    fn rtnetlink(error: rtnetlink::Error) -> Self {
        match error {
            rtnetlink::Error::NetlinkError(message) => Self::Netlink(message.to_io()),
            error => Self::Protocol(error.to_string()),
        }
    }
}

fn ignore_gone(result: Result<(), NetError>, gone: i32) -> Result<(), NetError> {
    match result {
        Err(error) if error.is_os_error(gone) => Ok(()),
        result => result,
    }
}
