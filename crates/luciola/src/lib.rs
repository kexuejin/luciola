//! # luciola
//!
//! Lightweight, resilient peer discovery & interface intelligence for the real-world LAN.

pub use luciola_ip as ip;

pub mod errors;
pub mod link;
pub mod pairing;
pub mod ports;
pub mod relay_crypto;
pub mod trust;
pub use luciola_net as net;
pub use luciola_proto as proto;
#[cfg(feature = "transfer")]
pub use luciola_transfer as transfer;

mod engine;
mod registry;

pub use engine::{DiscoveryConfig, DiscoveryEngine};
pub use registry::{PeerEvent, PeerRecord, PeerRegistry};

use thiserror::Error;

/// crate 级错误：绑定层把它映射成各自的错误回调/枚举。
#[derive(Error, Debug)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind error on port {0}: {1}")]
    BindFailed(u16, std::io::Error),
}
