mod binding;
pub mod client;
#[cfg(feature = "linux")]
pub mod lighthouse;

#[cfg(feature = "linux")]
pub use self::client::LinuxPlatform;
pub use self::client::{
    Client, ClientSettings, HostedPlatform, LighthouseSettings, TunProvider, TunShape, Underlying,
};
#[cfg(feature = "linux")]
pub use self::lighthouse::Lighthouse;

#[cfg(feature = "linux")]
const FWMARK: u32 = 0x5254;
