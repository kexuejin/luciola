//! luciola-tunnel — 在单条 SecureStream 上做 LAN TCP 复用与转发。
//!
//! 按 the tunnel plan（rev r4）实施：
//!
//! - Phase T1（本 crate 核心）：mux 模块 —— 12 字节帧头的 mux v1 协议、
//!   会话/通道状态机、MuxSession / MuxStream / OpenRequest。
//! - Phase T2：forward 模块 —— 本地端口转发与服务端 ACL 白名单。
//! - Phase T3：uniffi 控制面 TunnelLink（在 bindings 仓侧）。
//!
//! # 调度前提
//!
//! MuxSession::start 内部会 tokio::spawn reader/writer 任务，
//! start_local_forward / start_forward_endpoint 在调用处捕获 Handle ——
//! 全部必须在 tokio runtime 上下文中调用（spec §2.2/§2.3）。

pub mod forward;
pub mod mux;

pub use forward::{
    ForwardAcl, ForwardCounters, ForwardEndpointGuard, ForwardRule, ForwardStatus, LocalForwardConfig,
    LocalForwardGuard, start_forward_endpoint, start_local_forward,
};
pub use mux::{
    decode_frame, encode_frame, AckStatus, CloseReason, DialTarget, Frame, MuxConfig, MuxError,
    MuxSession, MuxStats, OpenRequest, Role, HEADER_LEN, MAX_DATA_FRAME, T_ACK, T_CLOSE, T_DATA,
    T_EOF, T_OPEN, T_PING, T_PONG, T_WINDOW,
};

/// 面向 forward/FFI 层（T2/T3）的错误类型。
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid forward rule: {0}")]
    InvalidRule(String),
    #[error("listen bind failed: {0}")]
    Bind(String),
    #[error("forward endpoint stopped: {0}")]
    Stopped(String),
    #[error(transparent)]
    Mux(#[from] MuxError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
