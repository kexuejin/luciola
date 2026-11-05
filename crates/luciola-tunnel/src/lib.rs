//! luciola-tunnel — 在单条 SecureStream 上做 LAN TCP/UDP 复用与转发。
//!
//! 三个模块：
//!
//! - mux（本 crate 核心）：12 字节帧头协议、会话/通道状态机、MuxSession /
//!   MuxStream / MuxDatagram / OpenRequest；v2 能力（PING/PONG keepalive、
//!   WINDOW 逐通道流控、双向 OPEN 即 remote forward、数据报通道、主机名目标、
//!   通道空闲回收）全部向后兼容 v1 线格式，详见 mux 模块文档。
//! - forward：本地/远程端口转发、UDP 转发与服务端 ACL 白名单（含解析钉扎）。
//! - tunnel_link：隧道链路控制面（cmd + supervisor 双线程，懒建立/退避重建/
//!   注册表恢复），uniffi 与 node 两个绑定层复用它。
//!
//! # 调度前提
//!
//! MuxSession::start 内部会 tokio::spawn reader/writer/keepalive/reaper 任务，
//! start_* / start_forward_endpoint 在调用处捕获 Handle ——
//! 全部必须在 tokio runtime 上下文中调用。

pub mod forward;
pub mod mux;
pub mod tunnel_link;

use luciola_proto::{ErrorCode, ErrorInfo};

pub use forward::{
    start_forward_endpoint, start_local_forward, start_remote_forward, start_udp_forward,
    ForwardAcl, ForwardCounters, ForwardEndpointGuard, ForwardRule, ForwardStatus,
    LocalForwardConfig, LocalForwardGuard, UdpForwardConfig, UdpForwardGuard,
};
pub use mux::{
    decode_frame, encode_frame, AckStatus, ChanMode, CloseReason, DialTarget, Frame, MuxConfig,
    MuxDatagram, MuxError, MuxSession, MuxStats, OpenRequest, Role, HEADER_LEN, MAX_DATA_FRAME,
    T_ACK, T_CLOSE, T_DATA, T_DOPEN, T_EOF, T_OPEN, T_PING, T_PONG, T_WINDOW,
};

/// 面向 forward/FFI 层（T2/T3）的错误类型。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// 保留该前缀是因为 TUNNEL_SPEC 与 `bind_conflict_reports_forward_bind_failed`
    /// 把它当契约；需要机器可读码时用 [`Self::error_info`]。
    pub fn to_state(&self) -> (&'static str, String) {
        match self {
            TunnelError::Bind(m) => ("error", format!("forward_bind_failed: {m}")),
            other => ("error", other.to_string()),
        }
    }

    /// Classify into the shared FFI taxonomy. `Mux` delegates to the wrapped
    /// [`MuxError`] instead of collapsing every mux failure into one code.
    pub fn error_info(&self) -> ErrorInfo {
        match self {
            TunnelError::Mux(e) => ErrorInfo::from(e),
            other => {
                let code = match other {
                    TunnelError::InvalidTarget(_) => ErrorCode::InvalidArgument,
                    TunnelError::InvalidRule(_) => ErrorCode::InvalidRule,
                    TunnelError::Bind(_) => ErrorCode::BindFailed,
                    TunnelError::Stopped(_) => ErrorCode::Stopped,
                    TunnelError::Io(_) => ErrorCode::IoError,
                    TunnelError::NotConfigured(_) => ErrorCode::NotConfigured,
                    TunnelError::RoleMismatch(_) => ErrorCode::RoleMismatch,
                    TunnelError::Unavailable(_) => ErrorCode::Unavailable,
                    TunnelError::Mux(_) => unreachable!("handled above"),
                };
                ErrorInfo::new(code, self.to_string())
            }
        }
    }
}

impl From<&MuxError> for ErrorInfo {
    fn from(e: &MuxError) -> Self {
        let code = match e {
            MuxError::SessionClosed | MuxError::ChannelClosed => ErrorCode::ChannelClosed,
            MuxError::OpenTimeout(_) => ErrorCode::Timeout,
            MuxError::Rejected { .. } => ErrorCode::ChannelClosed,
            MuxError::InvalidTarget(_) | MuxError::InvalidAckStatus(_) => {
                ErrorCode::InvalidArgument
            }
            MuxError::Protocol(_) => ErrorCode::ProtocolViolation,
            MuxError::ModeMismatch | MuxError::DatagramTooLarge(_) => ErrorCode::ProtocolViolation,
            MuxError::UnsupportedByPeer(_) => ErrorCode::CapabilityMismatch,
        };
        Self::new(code, e.to_string())
    }
}

impl From<&TunnelError> for ErrorInfo {
    fn from(e: &TunnelError) -> Self {
        e.error_info()
    }
}

#[cfg(test)]
mod error_taxonomy_tests {
    use super::*;

    #[test]
    fn tunnel_errors_keep_the_spec_prefix_and_gain_a_code() {
        let e = TunnelError::Bind("port in use".into());
        assert!(e.to_state().1.starts_with("forward_bind_failed: "));
        assert_eq!(e.error_info().code, ErrorCode::BindFailed);
    }

    #[test]
    fn mux_errors_are_not_all_collapsed() {
        let timeout = MuxError::OpenTimeout(std::time::Duration::from_secs(1));
        let bad_frame = MuxError::Protocol("bad magic".into());
        assert_eq!(ErrorInfo::from(&timeout).code, ErrorCode::Timeout);
        assert_eq!(
            ErrorInfo::from(&bad_frame).code,
            ErrorCode::ProtocolViolation
        );
    }
}
