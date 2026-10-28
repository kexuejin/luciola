//! # luciola-transfer
//!
//! Chunked file transfer data plane, transport-agnostic: frames ride any
//! reliable, ordered, message-oriented channel (in practice a
//! `luciola::link::secure::SecureStream`).
//!
//! Design invariants:
//! - the receiver writes every chunk at its **absolute offset** — arrival
//!   order is irrelevant, duplicates are idempotent, nothing is appended
//!   blindly;
//! - the receiver continuously reports the contiguous prefix
//!   (`acked_up_to`), so the sender can slide its window;
//! - after completion the receiver keeps a 30-second answer cache: a
//!   retransmitted tail chunk (its final ACK lost in flight) still gets the
//!   final ACK back, so the sender never hangs at 96–99%.

pub mod protocol;
pub mod receiver;
pub mod sender;

pub use protocol::{FileAck, FileChunk};
pub use receiver::{FileReceiver, ReceiverConfig};
pub use sender::{FileSender, SenderConfig};

#[derive(thiserror::Error, Debug)]
pub enum TransferError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame decode error: {0}")]
    Decode(String),
    #[error("transfer state error: {0}")]
    State(String),
    #[error("size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
}
