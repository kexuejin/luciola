//! luciola-tunnel — 在单条 SecureStream 上做 LAN TCP 复用与转发。
//!
//! 三个模块：
//!
//! - mux（本 crate 核心）：12 字节帧头的 mux v1 协议、会话/通道状态机、
//!   MuxSession / MuxStream / OpenRequest。
//! - forward：本地端口转发与服务端 ACL 白名单。
//! - tunnel_link：隧道链路控制面（cmd + supervisor 双线程，懒建立/退避重建/
//!   注册表恢复），uniffi 与 node 两个绑定层复用它。
//!
//! # 调度前提
//!
//! MuxSession::start 内部会 tokio::spawn reader/writer 任务，
//! start_local_forward / start_forward_endpoint 在调用处捕获 Handle ——
//! 全部必须在 tokio runtime 上下文中调用。

pub mod forward;
pub mod mux;
pub mod tunnel_link;

pub use forward::{
    start_forward_endpoint, start_local_forward, ForwardAcl, ForwardCounters, ForwardEndpointGuard,
    ForwardRule, ForwardStatus, LocalForwardConfig, LocalForwardGuard,
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
    /// 同步段：基址未注入（先 connect()/listen()）或推导不能。
    #[error("{0}")]
    NotConfigured(String),
    /// 同步段：角色与所调 API 不匹配（D8）。
    #[error("{0}")]
    RoleMismatch(String),
    /// 控制面线程对已退出（shutdown/Drop 之后仍被调用）。
    #[error("{0}")]
    Unavailable(String),
}

impl TunnelError {
    /// 同步错误 → 上报事件（state kind, detail），uniffi / node 双绑定共用
    /// 一处真相：`Bind` 产出 spec 规定的 `forward_bind_failed: ` 前缀。
    pub fn to_state(&self) -> (&'static str, String) {
        match self {
            TunnelError::Bind(m) => ("error", format!("forward_bind_failed: {m}")),
            other => ("error", other.to_string()),
        }
    }
}
