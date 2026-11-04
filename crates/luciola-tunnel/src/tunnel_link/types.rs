use std::collections::BTreeMap;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::Duration;

use luciola::link::secure::SecureStream;

use crate::forward::{
    ForwardEndpointGuard, ForwardRule, ForwardStatus, LocalForwardGuard, UdpForwardGuard,
};
use crate::mux::{DialTarget, MuxSession};
use crate::TunnelError;

/// 首次重建退避（镜像 CLI serve：500ms 起步指数加倍）。
pub(crate) const BACKOFF_INIT: Duration = Duration::from_millis(500);
/// 重建退避上限。
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// keepalive 默认值（与 `MuxConfig::default()` 一致）：15s 间隔 / 45s 判死。
pub(crate) const KEEPALIVE_DEFAULT: (u64, u64) = (15_000, 45_000);

// ---------------------------------------------------------------- 对外类型

/// 上报通道：绑定层各实现一次（uniffi 包 `Arc<dyn SecureSessionListener>`，
/// node 包 `ThreadsafeFunction`）。**在 cmd / supervisor 线程上被调用**。
pub trait TunnelReporter: Send + Sync + 'static {
    /// `kind` ∈ {"error", "retrying"}，与 `SecureSessionListener::on_state` 同构。
    fn report(&self, kind: &str, detail: String);
}

/// 隧道链路基址：由 `connect()` / `listen()` 捕获（D8 角色模型）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelBase {
    /// 发起端（消息链路 Dial 侧）：隧道主动拨 `secure_port + 1`。
    Dial {
        addresses: Vec<String>,
        secure_port: u16,
        pinned_peer_public_key: Vec<u8>,
    },
    /// 服务端（消息链路 Listen 侧）：隧道监听 `secure_port + 1`。
    Listen {
        secure_port: u16,
        expected_peer: Option<Vec<u8>>,
    },
}

impl TunnelBase {
    /// 消息链路 secure 端口（tunnel_port 推导基准）。
    pub fn secure_port(&self) -> u16 {
        match self {
            TunnelBase::Dial { secure_port, .. } => *secure_port,
            TunnelBase::Listen { secure_port, .. } => *secure_port,
        }
    }

    /// 是否发起端角色。
    pub fn is_dial(&self) -> bool {
        matches!(self, TunnelBase::Dial { .. })
    }

    /// 解析 tunnel_port：显式覆盖（非 0）优先，否则 `secure_port + 1`。
    pub fn tunnel_port(&self, port_override: u16) -> Result<u16, TunnelError> {
        if port_override != 0 {
            return Ok(port_override);
        }
        let sp = self.secure_port();
        sp.checked_add(1).ok_or_else(|| {
            TunnelError::NotConfigured(
                "secure 端口为 65535，无法推导 tunnel_port；请 set_tunnel_port 显式指定".into(),
            )
        })
    }
}

/// stats 行类别（v2）：一条转发/端点注册在哪个面上。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardKind {
    /// Dial 侧本地 TCP 转发。
    Local,
    /// Dial 侧 UDP 转发（NAT 式映射）。
    UdpLocal,
    /// Dial 侧 remote endpoint（接受 Responder 发起的通道）。
    RemoteEndpoint,
    /// Listen 侧转发端点（拨入 ACL）。
    Endpoint,
    /// Listen 侧 remote forward（-R，向对端发起通道）。
    Remote,
}

impl ForwardKind {
    /// FFI/CLI 展示文本。
    pub fn as_str(&self) -> &'static str {
        match self {
            ForwardKind::Local => "local",
            ForwardKind::UdpLocal => "udp_local",
            ForwardKind::RemoteEndpoint => "remote_endpoint",
            ForwardKind::Endpoint => "endpoint",
            ForwardKind::Remote => "remote",
        }
    }
}

/// `forward_stats()` 的一行（DTO 由绑定层再包一层）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardStat {
    /// 链路已建立且本条转发的 Guard 存活。
    pub active: bool,
    /// 实际监听端口（listen_port=0 注册时为系统分配的实端口；端点行为 tunnel_port）。
    pub listen_port: u16,
    /// 本次 Guard 的活计数 + 拆除时折叠的历史累计（channels_open 不累计）。
    pub status: ForwardStatus,
    /// 条目类别。
    pub kind: ForwardKind,
}

// ---------------------------------------------------------------- 内部类型

pub(crate) type Reply = std_mpsc::Sender<Result<(), TunnelError>>;

pub(crate) enum Cmd {
    StartLocal {
        listen_port: u16,
        host: String,
        port: u16,
        reply: Reply,
    },
    StopLocal {
        listen_port: u16,
        reply: Reply,
    },
    StartUdp {
        listen_port: u16,
        host: String,
        port: u16,
        reply: Reply,
    },
    StopUdp {
        listen_port: u16,
        reply: Reply,
    },
    EnableEndpoint {
        rules: Vec<ForwardRule>,
        reply: Reply,
    },
    DisableEndpoint {
        reply: Reply,
    },
    StartRemote {
        listen_port: u16,
        host: String,
        port: u16,
        reply: Reply,
    },
    StopRemote {
        listen_port: u16,
        reply: Reply,
    },
    EnableRemoteEndpoint {
        rules: Vec<ForwardRule>,
        reply: Reply,
    },
    DisableRemoteEndpoint {
        reply: Reply,
    },
    SetTunnelPort {
        port: u16,
        reply: Reply,
    },
    SetKeepalive {
        interval_ms: u64,
        dead_after_ms: u64,
    },
    SetBase {
        base: TunnelBase,
        reporter: Arc<dyn TunnelReporter>,
    },
    Pause,
    Shutdown,
}

/// establish 的三种出口。
pub(crate) enum EstablishOutcome {
    Stream(Box<SecureStream>),
    /// 配置（基址/注册表/覆盖端口）变化 → 外层重新快照。
    Restart,
    Shutdown,
}

/// 注册表条目：目标 + 历史折叠计数（TCP 转发两类共用形状）。
pub(crate) struct ForwardReg {
    pub(crate) target: DialTarget,
    pub(crate) base: ForwardStatus,
}

/// 端点条目：规则 + 历史折叠计数。
pub(crate) struct EndpointReg {
    pub(crate) rules: Vec<ForwardRule>,
    pub(crate) base: ForwardStatus,
}

/// 注册表：**跨重建 / pause 存活**（上层意图的唯一真相）。
#[derive(Default)]
pub(crate) struct Registry {
    pub(crate) paused: bool,
    pub(crate) locals: BTreeMap<u16, ForwardReg>,
    pub(crate) udps: BTreeMap<u16, ForwardReg>,
    pub(crate) endpoint: Option<EndpointReg>,
    pub(crate) remotes: BTreeMap<u16, ForwardReg>,
    pub(crate) remote_endpoint: Option<EndpointReg>,
}

/// 活跃资源：仅 supervisor 线程写；stats 只读短锁。
#[derive(Default)]
pub(crate) struct Live {
    pub(crate) session: Option<Arc<MuxSession>>,
    /// 当前隧道链路端口（0 = 无链路）。
    pub(crate) link_port: u16,
    pub(crate) locals: BTreeMap<u16, (DialTarget, LocalForwardGuard)>,
    pub(crate) udps: BTreeMap<u16, (DialTarget, UdpForwardGuard)>,
    pub(crate) endpoint: Option<(Vec<ForwardRule>, ForwardEndpointGuard)>,
    pub(crate) remotes: BTreeMap<u16, (DialTarget, LocalForwardGuard)>,
    pub(crate) remote_endpoint: Option<(Vec<ForwardRule>, ForwardEndpointGuard)>,
    pub(crate) active: bool,
}

/// 一致性快照（registry + base + 覆盖端口）。
#[derive(Clone)]
pub(crate) struct Snap {
    pub(crate) paused: bool,
    pub(crate) base: Option<TunnelBase>,
    pub(crate) port_override: u16,
    pub(crate) locals: BTreeMap<u16, DialTarget>,
    pub(crate) udps: BTreeMap<u16, DialTarget>,
    pub(crate) endpoint: Option<Vec<ForwardRule>>,
    pub(crate) remotes: BTreeMap<u16, DialTarget>,
    pub(crate) remote_endpoint: Option<Vec<ForwardRule>>,
}

impl Snap {
    pub(crate) fn has_work(&self) -> bool {
        !self.locals.is_empty()
            || !self.udps.is_empty()
            || !self.remotes.is_empty()
            || self.endpoint.is_some()
            || self.remote_endpoint.is_some()
    }
}
