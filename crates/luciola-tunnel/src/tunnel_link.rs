//! 隧道链路控制面。
//!
//! `TunnelLink` 是**独立于消息链路**的第二套监督实例：两条专用 OS 线程
//! （命令线程 + supervisor 运行时线程）持有自己的 TCP 连接与 `MuxSession`，
//! 数据面（转发字节流）永不跨 FFI —— 逐帧回调在高吞吐下不可用，FFI 只暴露
//! 控制面。uniffi / node 两个绑定层复用本模块，各自的事件回调只需实现
//! `TunnelReporter` 做一层适配。
//!
//! ## 线程模型（回调重入防死锁）
//!
//! - **cmd 线程**（`luciola-tunnel-cmd`）：`std::sync::mpsc` 无界通道接收
//!   FFI 控制命令，oneshot 应答。命令处理中的端口探测用 `std::net`，
//!   从任何线程（含监听器回调内）同步调用控制面都不会死锁。
//! - **supervisor 线程**（`luciola-tunnel-link`）：`new_current_thread`
//!   runtime + `block_on`，负责 tunnel端口的拨号/监听/接受、退避重建、
//!   Guard 生命周期与计数折叠。所有阻塞点均 `select!` 关停信号。
//!
//! ## 关键语义（spec T3/T4）
//!
//! - **懒建立**：注册任一转发或启用端点后才拨/监听 tunnel_port
//!   （`secure 端口 + 1`，`TunnelLink::set_tunnel_port` 显式覆盖）。
//! - **断链自动重建**：MuxSession 死亡 → 折叠计数 → 退避重建 → 按注册表
//!   恢复全部转发/端点；上层只看到 `ForwardStat::active` 变化。
//! - **注册表与基址跨重建存活**：pause（消息链路断开）只拆除活跃转发，
//!   `set_base`（connect/listen）恢复。
//! - **五类注册条目**（v2）：`locals`（Dial 侧本地 TCP 转发）、`udps`（Dial 侧
//!   UDP 转发）、`remote_endpoint`（Dial 侧接受 remote forward 的 ACL）、
//!   `endpoint`（Listen 侧拨入 ACL）、`remotes`（Listen 侧 remote forward）。
//!   角色校验：前三者要求 Dial 基址，后两者要求 Listen 基址。
//! - **上报**：`TunnelReporter::report` 的 kind 与
//!   `SecureSessionListener::on_state` 同构（"error" | "retrying"）。
//!   隧道不产生 "connected"/"closed"（消息链路已覆盖），活跃度走 stats。
//!
//! 锁序（全模块统一，防死锁）：`registry` 先于 `live`；任何锁持有期间
//! **禁止 await、禁止调用 reporter**。

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;
use std::time::Duration;

use luciola::link::secure::SecureStream;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::sync::Notify;
use tracing::debug;

use crate::forward::{
    start_forward_endpoint, start_local_forward, start_remote_forward, start_udp_forward,
    ForwardAcl, ForwardEndpointGuard, ForwardRule, ForwardStatus, LocalForwardConfig,
    LocalForwardGuard, UdpForwardConfig, UdpForwardGuard,
};
use crate::mux::{DialTarget, MuxConfig, MuxSession, Role};
use crate::TunnelError;

/// 首次重建退避（镜像 CLI serve：500ms 起步指数加倍）。
const BACKOFF_INIT: Duration = Duration::from_millis(500);
/// 重建退避上限。
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// keepalive 默认值（与 `MuxConfig::default()` 一致）：15s 间隔 / 45s 判死。
const KEEPALIVE_DEFAULT: (u64, u64) = (15_000, 45_000);

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

type Reply = std_mpsc::Sender<Result<(), TunnelError>>;

enum Cmd {
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
enum EstablishOutcome {
    Stream(Box<SecureStream>),
    /// 配置（基址/注册表/覆盖端口）变化 → 外层重新快照。
    Restart,
    Shutdown,
}

/// 注册表条目：目标 + 历史折叠计数（TCP 转发两类共用形状）。
struct ForwardReg {
    target: DialTarget,
    base: ForwardStatus,
}

/// 端点条目：规则 + 历史折叠计数。
struct EndpointReg {
    rules: Vec<ForwardRule>,
    base: ForwardStatus,
}

/// 注册表：**跨重建 / pause 存活**（上层意图的唯一真相）。
#[derive(Default)]
struct Registry {
    paused: bool,
    locals: BTreeMap<u16, ForwardReg>,
    udps: BTreeMap<u16, ForwardReg>,
    endpoint: Option<EndpointReg>,
    remotes: BTreeMap<u16, ForwardReg>,
    remote_endpoint: Option<EndpointReg>,
}

/// 活跃资源：仅 supervisor 线程写；stats 只读短锁。
#[derive(Default)]
struct Live {
    session: Option<Arc<MuxSession>>,
    /// 当前隧道链路端口（0 = 无链路）。
    link_port: u16,
    locals: BTreeMap<u16, (DialTarget, LocalForwardGuard)>,
    udps: BTreeMap<u16, (DialTarget, UdpForwardGuard)>,
    endpoint: Option<(Vec<ForwardRule>, ForwardEndpointGuard)>,
    remotes: BTreeMap<u16, (DialTarget, LocalForwardGuard)>,
    remote_endpoint: Option<(Vec<ForwardRule>, ForwardEndpointGuard)>,
    active: bool,
}

/// 一致性快照（registry + base + 覆盖端口）。
#[derive(Clone)]
struct Snap {
    paused: bool,
    base: Option<TunnelBase>,
    port_override: u16,
    locals: BTreeMap<u16, DialTarget>,
    udps: BTreeMap<u16, DialTarget>,
    endpoint: Option<Vec<ForwardRule>>,
    remotes: BTreeMap<u16, DialTarget>,
    remote_endpoint: Option<Vec<ForwardRule>>,
}

impl Snap {
    fn has_work(&self) -> bool {
        !self.locals.is_empty()
            || !self.udps.is_empty()
            || !self.remotes.is_empty()
            || self.endpoint.is_some()
            || self.remote_endpoint.is_some()
    }
}

// ---------------------------------------------------------------- Shared

struct Shared {
    identity_seed: Vec<u8>,
    base: StdMutex<Option<TunnelBase>>,
    reporter: StdMutex<Option<Arc<dyn TunnelReporter>>>,
    port_override: AtomicU16,
    /// 隧道 mux keepalive 覆盖（interval_ms, dead_after_ms）；0 interval = 关闭。
    keepalive: StdMutex<(u64, u64)>,
    registry: StdMutex<Registry>,
    live: StdMutex<Live>,
    wake: Notify,
}

/// 停止命令的注册表/活跃表选择器（locals / udps / remotes 三张同构表共用）。
type RegTableSel<'a> = &'a dyn Fn(&mut Registry) -> &mut BTreeMap<u16, ForwardReg>;
type LiveTableSel<'a, T> = &'a dyn Fn(&Live) -> &BTreeMap<u16, (DialTarget, T)>;

impl Shared {
    fn snapshot(&self) -> Snap {
        let reg = self.registry.lock().unwrap();
        let base = self.base.lock().unwrap().clone();
        let port_override = self.port_override.load(Ordering::Relaxed);
        Snap {
            paused: reg.paused,
            base,
            port_override,
            locals: reg
                .locals
                .iter()
                .map(|(p, r)| (*p, r.target.clone()))
                .collect(),
            udps: reg
                .udps
                .iter()
                .map(|(p, r)| (*p, r.target.clone()))
                .collect(),
            endpoint: reg.endpoint.as_ref().map(|e| e.rules.clone()),
            remotes: reg
                .remotes
                .iter()
                .map(|(p, r)| (*p, r.target.clone()))
                .collect(),
            remote_endpoint: reg.remote_endpoint.as_ref().map(|e| e.rules.clone()),
        }
    }

    /// supervisor 用：把 keepalive 覆盖折进 MuxConfig。
    fn mux_config(&self) -> MuxConfig {
        let mut cfg = MuxConfig::default();
        let (interval_ms, dead_after_ms) = *self.keepalive.lock().unwrap();
        if interval_ms == 0 {
            cfg.keepalive_interval = None;
            cfg.keepalive_dead_after = None;
        } else {
            cfg.keepalive_interval = Some(Duration::from_millis(interval_ms));
            cfg.keepalive_dead_after = Some(Duration::from_millis(dead_after_ms.max(interval_ms)));
        }
        cfg
    }

    /// 无锁调用 reporter（锁内禁止上报）。
    fn report(&self, kind: &str, detail: String) {
        let r = self.reporter.lock().unwrap().clone();
        if let Some(r) = r {
            r.report(kind, detail);
        }
    }

    /// 通过 TunnelError 自带的 (kind, detail) 上报。
    fn report_err(&self, e: &TunnelError) {
        let (kind, detail) = e.to_state();
        self.report(kind, detail);
    }

    /// Dial 基址守卫（locals/udps/remote_endpoint 共用）。
    fn require_dial_base(&self, what: &str, alt: &str) -> Result<TunnelBase, TunnelError> {
        let base = self.base.lock().unwrap().clone().ok_or_else(|| {
            TunnelError::NotConfigured(format!(
                "隧道未配置：先 connect() 建立发起端会话，再注册{what}"
            ))
        })?;
        if !base.is_dial() {
            return Err(TunnelError::RoleMismatch(format!(
                "{what} 只能用于 connect()（发起端）会话；本会话是 listen()（服务端），请改用{alt}"
            )));
        }
        Ok(base)
    }

    /// Listen 基址守卫（endpoint/remotes 共用）。
    fn require_listen_base(&self, what: &str, alt: &str) -> Result<TunnelBase, TunnelError> {
        let base = self.base.lock().unwrap().clone().ok_or_else(|| {
            TunnelError::NotConfigured(format!(
                "隧道未配置：先 listen() 建立服务端会话，再启用{what}"
            ))
        })?;
        if base.is_dial() {
            return Err(TunnelError::RoleMismatch(format!(
                "{what} 只能用于 listen()（服务端）会话；本会话是 connect()（发起端），请改用{alt}"
            )));
        }
        Ok(base)
    }

    // ---- 命令处理（cmd 线程；探测用 std::net，无 runtime） ----

    fn cmd_start_local(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        let target = DialTarget::new(host, port);
        if !target.validate() {
            return Err(TunnelError::InvalidTarget(format!(
                "非法转发目标 {target}（端口 0 / 未指定 / 组播 / 广播地址或非法主机名均不允许）",
            )));
        }
        self.require_dial_base("本地转发", "enable_forward_endpoint")?;
        if listen_port != 0 {
            // D6 同步段探测：绑不上就立刻 false + on_state（不等 supervisor）。
            std::net::TcpListener::bind(("127.0.0.1", listen_port))
                .map_err(|e| TunnelError::Bind(format!("127.0.0.1:{listen_port}: {e}")))?;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.locals.get_mut(&listen_port) {
                // 同端口重复注册：只换目标，保留历史计数。
                Some(entry) => entry.target = target,
                None => {
                    reg.locals.insert(
                        listen_port,
                        ForwardReg {
                            target,
                            base: ForwardStatus::default(),
                        },
                    );
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_start_udp(&self, listen_port: u16, host: String, port: u16) -> Result<(), TunnelError> {
        let target = DialTarget::new(host, port);
        if !target.validate() {
            return Err(TunnelError::InvalidTarget(format!(
                "非法 UDP 转发目标 {target}",
            )));
        }
        self.require_dial_base("UDP 转发", "enable_forward_endpoint")?;
        if listen_port != 0 {
            std::net::UdpSocket::bind(("127.0.0.1", listen_port))
                .map_err(|e| TunnelError::Bind(format!("127.0.0.1:{listen_port} (udp): {e}")))?;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.udps.get_mut(&listen_port) {
                Some(entry) => entry.target = target,
                None => {
                    reg.udps.insert(
                        listen_port,
                        ForwardReg {
                            target,
                            base: ForwardStatus::default(),
                        },
                    );
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    /// 停止一个 TCP/UDP/remote 转发：先精确键，再回退按活链实测端口匹配
    /// （stats 展示的是实端口，stop 收到的值应与之一致）。`reg_table` 选择
    /// 注册表，`live_table` 选择对应活跃表（Guard 统一实现 [`ListenPort`]）。
    /// 锁序：registry 先于 live；本函数纯同步、不跨 await。
    fn cmd_stop_forward<T: ListenPort>(
        &self,
        reg_table: RegTableSel<'_>,
        live_table: LiveTableSel<'_, T>,
        what: &str,
        listen_port: u16,
    ) -> Result<(), TunnelError> {
        let removed = {
            let mut reg = self.registry.lock().unwrap();
            if reg_table(&mut reg).remove(&listen_port).is_some() {
                true
            } else {
                let hit = {
                    let live = self.live.lock().unwrap();
                    reg_table(&mut reg)
                        .keys()
                        .find(|&&k| {
                            k != listen_port
                                && live_table(&live)
                                    .get(&k)
                                    .is_some_and(|(_, g)| g.listen_port() == listen_port)
                        })
                        .copied()
                };
                hit.is_some_and(|k| reg_table(&mut reg).remove(&k).is_some())
            }
        };
        self.wake.notify_one();
        if removed {
            Ok(())
        } else {
            Err(TunnelError::Stopped(format!(
                "{what} {listen_port} 未在转发注册表中",
            )))
        }
    }

    fn cmd_enable_endpoint(&self, rules: Vec<ForwardRule>) -> Result<(), TunnelError> {
        let base = self.require_listen_base("转发端点", "start_local_forward")?;
        validate_rules(&rules)?;
        // tunnel_port 冲突同步探测（双栈：v4 必须干净；v6 缺失环境忽略）。
        let tp = base.tunnel_port(self.port_override.load(Ordering::Relaxed))?;
        std::net::TcpListener::bind(("0.0.0.0", tp))
            .map_err(|e| TunnelError::Bind(format!("0.0.0.0:{tp}: {e}")))?;
        if let Err(e) = std::net::TcpListener::bind(("[::]", tp)) {
            if e.kind() == ErrorKind::AddrInUse {
                return Err(TunnelError::Bind(format!("[::]:{tp}: {e}")));
            }
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.endpoint.as_mut() {
                // 重复启用：换规则、保留历史计数。
                Some(entry) => entry.rules = rules,
                None => {
                    reg.endpoint = Some(EndpointReg {
                        rules,
                        base: ForwardStatus::default(),
                    });
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_disable_endpoint(&self) -> Result<(), TunnelError> {
        self.registry.lock().unwrap().endpoint = None;
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_start_remote(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        let target = DialTarget::new(host, port);
        if !target.validate() {
            return Err(TunnelError::InvalidTarget(format!(
                "非法 remote forward 目标 {target}",
            )));
        }
        self.require_listen_base("remote forward", "enable_remote_endpoint")?;
        if listen_port != 0 {
            std::net::TcpListener::bind(("127.0.0.1", listen_port))
                .map_err(|e| TunnelError::Bind(format!("127.0.0.1:{listen_port}: {e}")))?;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.remotes.get_mut(&listen_port) {
                Some(entry) => entry.target = target,
                None => {
                    reg.remotes.insert(
                        listen_port,
                        ForwardReg {
                            target,
                            base: ForwardStatus::default(),
                        },
                    );
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_enable_remote_endpoint(&self, rules: Vec<ForwardRule>) -> Result<(), TunnelError> {
        self.require_dial_base("remote endpoint", "start_remote_forward")?;
        validate_rules(&rules)?;
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.remote_endpoint.as_mut() {
                Some(entry) => entry.rules = rules,
                None => {
                    reg.remote_endpoint = Some(EndpointReg {
                        rules,
                        base: ForwardStatus::default(),
                    });
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_disable_remote_endpoint(&self) -> Result<(), TunnelError> {
        self.registry.lock().unwrap().remote_endpoint = None;
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_set_tunnel_port(&self, port: u16) -> Result<(), TunnelError> {
        // 0 = 清除覆盖，恢复 secure_port + 1 推导。
        self.port_override.store(port, Ordering::Relaxed);
        self.wake.notify_one();
        Ok(())
    }

    fn cmd_set_base(&self, base: TunnelBase, reporter: Arc<dyn TunnelReporter>) {
        *self.reporter.lock().unwrap() = Some(reporter);
        *self.base.lock().unwrap() = Some(base);
        self.registry.lock().unwrap().paused = false;
        self.wake.notify_one();
    }

    fn cmd_pause(&self) {
        self.registry.lock().unwrap().paused = true;
        self.wake.notify_one();
    }

    // ---- supervisor 侧 ----

    /// 挂上新链路（active）并按注册表启动全部 Guard。
    async fn install(&self, session: Arc<MuxSession>, tunnel_port: u16) {
        {
            let mut live = self.live.lock().unwrap();
            live.session = Some(session.clone());
            live.link_port = tunnel_port;
            live.active = true;
        }
        self.apply_guards(&session).await;
    }

    /// 注册表 → 活跃 Guard 的增量同步（仅 supervisor；锁内无 await/上报）。
    async fn apply_guards(&self, session: &Arc<MuxSession>) {
        // 1) 需要停的：注册表已删（Stop）与目标变更（Restart，随后重启）。
        let (stop_ports, restart_ports) = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            let mut stop = Vec::new();
            let mut restart = Vec::new();
            for (port, (target, _)) in &live.locals {
                match reg.locals.get(port) {
                    None => stop.push(*port),
                    Some(r) if r.target != *target => restart.push(*port),
                    _ => {}
                }
            }
            for (port, (target, _)) in &live.udps {
                match reg.udps.get(port) {
                    None => stop.push(*port),
                    Some(r) if r.target != *target => restart.push(*port),
                    _ => {}
                }
            }
            for (port, (target, _)) in &live.remotes {
                match reg.remotes.get(port) {
                    None => stop.push(*port),
                    Some(r) if r.target != *target => restart.push(*port),
                    _ => {}
                }
            }
            (stop, restart)
        };
        for port in stop_ports.iter().chain(restart_ports.iter()) {
            let taken = self.live.lock().unwrap().locals.remove(port);
            if let Some((_, guard)) = taken {
                guard.stop().await;
                if restart_ports.contains(port) {
                    // 目标变更：历史计数折叠进仍在的注册表条目。
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(entry) = reg.locals.get_mut(port) {
                        fold(&mut entry.base, guard.status());
                    }
                }
            }
            let taken = self.live.lock().unwrap().udps.remove(port);
            if let Some((_, guard)) = taken {
                guard.stop().await;
                if restart_ports.contains(port) {
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(entry) = reg.udps.get_mut(port) {
                        fold(&mut entry.base, guard.status());
                    }
                }
            }
            let taken = self.live.lock().unwrap().remotes.remove(port);
            if let Some((_, guard)) = taken {
                guard.stop().await;
                if restart_ports.contains(port) {
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(entry) = reg.remotes.get_mut(port) {
                        fold(&mut entry.base, guard.status());
                    }
                }
            }
        }

        // 2) 需要启的：注册表有、live 没有（含刚被 Restart 停掉的）。
        let starts: Vec<(u16, DialTarget)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            reg.locals
                .iter()
                .filter(|(p, _)| !live.locals.contains_key(p))
                .map(|(p, r)| (*p, r.target.clone()))
                .collect()
        };
        for (port, target) in starts {
            match start_local_forward(
                session.clone(),
                LocalForwardConfig {
                    listen_port: port,
                    target: target.clone(),
                },
            ) {
                Ok(guard) => {
                    self.live
                        .lock()
                        .unwrap()
                        .locals
                        .insert(port, (target, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }
        let udp_starts: Vec<(u16, DialTarget)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            reg.udps
                .iter()
                .filter(|(p, _)| !live.udps.contains_key(p))
                .map(|(p, r)| (*p, r.target.clone()))
                .collect()
        };
        for (port, target) in udp_starts {
            match start_udp_forward(
                session.clone(),
                UdpForwardConfig {
                    listen_port: port,
                    target: target.clone(),
                },
            ) {
                Ok(guard) => {
                    self.live.lock().unwrap().udps.insert(port, (target, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }
        let remote_starts: Vec<(u16, DialTarget)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            reg.remotes
                .iter()
                .filter(|(p, _)| !live.remotes.contains_key(p))
                .map(|(p, r)| (*p, r.target.clone()))
                .collect()
        };
        for (port, target) in remote_starts {
            match start_remote_forward(
                session.clone(),
                LocalForwardConfig {
                    listen_port: port,
                    target: target.clone(),
                },
            ) {
                Ok(guard) => {
                    self.live
                        .lock()
                        .unwrap()
                        .remotes
                        .insert(port, (target, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }

        // 3) 两个端点（endpoint / remote_endpoint）：规则集变化则先停旧、折叠历史，再启新。
        for (want, which) in [
            (
                {
                    let reg = self.registry.lock().unwrap();
                    reg.endpoint.as_ref().map(|e| e.rules.clone())
                },
                EndpointSide::Endpoint,
            ),
            (
                {
                    let reg = self.registry.lock().unwrap();
                    reg.remote_endpoint.as_ref().map(|e| e.rules.clone())
                },
                EndpointSide::RemoteEndpoint,
            ),
        ] {
            self.sync_endpoint(session, want, which).await;
        }
    }

    /// 单个端点面（endpoint / remote_endpoint）的停旧-启新同步。
    async fn sync_endpoint(
        &self,
        session: &Arc<MuxSession>,
        want: Option<Vec<ForwardRule>>,
        which: EndpointSide,
    ) {
        let have = {
            let live = self.live.lock().unwrap();
            match which {
                EndpointSide::Endpoint => live.endpoint.as_ref().map(|e| e.0.clone()),
                EndpointSide::RemoteEndpoint => live.remote_endpoint.as_ref().map(|e| e.0.clone()),
            }
        };
        if want == have {
            return;
        }
        let taken = { self.live.lock().unwrap().take_for(which) };
        if let Some((old_rules, guard)) = taken {
            guard.stop().await;
            let mut reg = self.registry.lock().unwrap();
            let slot = match which {
                EndpointSide::Endpoint => reg.endpoint.as_mut(),
                EndpointSide::RemoteEndpoint => reg.remote_endpoint.as_mut(),
            };
            if let Some(entry) = slot {
                // 条目仍在（换规则场景）→ 折叠历史；已注销则自然丢弃。
                if want.is_some() || entry.rules == old_rules {
                    fold(&mut entry.base, guard.status());
                }
            }
        }
        if let Some(rules) = want {
            match start_forward_endpoint(session.clone(), ForwardAcl::new(rules.clone())) {
                Ok(guard) => {
                    self.live.lock().unwrap().set_for(which, (rules, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }
    }

    /// 拆除链路与全部活跃 Guard；计数折叠回注册表（channels_open 归零不累计）。
    async fn teardown(&self) {
        let (locals, udps, remotes, ep, rep, session) = {
            let mut live = self.live.lock().unwrap();
            live.active = false;
            live.link_port = 0;
            let locals = std::mem::take(&mut live.locals);
            let udps = std::mem::take(&mut live.udps);
            let remotes = std::mem::take(&mut live.remotes);
            let ep = live.endpoint.take();
            let rep = live.remote_endpoint.take();
            let session = live.session.take();
            (locals, udps, remotes, ep, rep, session)
        };
        if let Some(s) = session {
            s.shutdown();
        }
        // 先停（冻结计数）再折叠。
        for (_, guard) in locals.values() {
            guard.stop().await;
        }
        for (_, guard) in udps.values() {
            guard.stop().await;
        }
        for (_, guard) in remotes.values() {
            guard.stop().await;
        }
        if let Some((_, guard)) = &ep {
            guard.stop().await;
        }
        if let Some((_, guard)) = &rep {
            guard.stop().await;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            for (port, (_, guard)) in &locals {
                if let Some(entry) = reg.locals.get_mut(port) {
                    fold(&mut entry.base, guard.status());
                }
            }
            for (port, (_, guard)) in &udps {
                if let Some(entry) = reg.udps.get_mut(port) {
                    fold(&mut entry.base, guard.status());
                }
            }
            for (port, (_, guard)) in &remotes {
                if let Some(entry) = reg.remotes.get_mut(port) {
                    fold(&mut entry.base, guard.status());
                }
            }
            if let Some((_, guard)) = &ep {
                if let Some(entry) = reg.endpoint.as_mut() {
                    fold(&mut entry.base, guard.status());
                }
            }
            if let Some((_, guard)) = &rep {
                if let Some(entry) = reg.remote_endpoint.as_mut() {
                    fold(&mut entry.base, guard.status());
                }
            }
        }
    }

    /// 统计行（registry 先于 live；只读短锁；锁内不 await、不上报）。
    fn stats(&self) -> Vec<ForwardStat> {
        let mut rows = Vec::new();
        // 端点行（registry → live）：无注册端点时不产生行。
        let endpoint_rows: Vec<(ForwardKind, ForwardStatus, bool, u16)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            let mut rows = Vec::new();
            for (kind, entry, live_guard) in [
                (
                    ForwardKind::Endpoint,
                    reg.endpoint.as_ref(),
                    live.endpoint.as_ref().map(|(_, g)| g.status()),
                ),
                (
                    ForwardKind::RemoteEndpoint,
                    reg.remote_endpoint.as_ref(),
                    live.remote_endpoint.as_ref().map(|(_, g)| g.status()),
                ),
            ] {
                let Some(entry) = entry else { continue };
                let listen = if live.link_port != 0 {
                    live.link_port
                } else {
                    let base = self.base.lock().unwrap().clone();
                    let ov = self.port_override.load(Ordering::Relaxed);
                    // 无链路：报告按基址推导的「应然」端口（行仍可见，active=false）。
                    base.as_ref()
                        .and_then(|b| b.tunnel_port(ov).ok())
                        .unwrap_or(0)
                };
                rows.push((kind, entry.base, live_guard, live.active, listen));
            }
            rows.into_iter()
                .map(|(kind, base, live_s, active, listen)| {
                    (
                        kind,
                        match live_s {
                            Some(s) => merge(&base, &s),
                            None => base,
                        },
                        active,
                        listen,
                    )
                })
                .collect()
        };
        // 本地行（registry → live）。
        {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            for (port, entry) in &reg.locals {
                match live.locals.get(port) {
                    Some((_, guard)) => {
                        let listen = if *port == 0 {
                            guard.local_addr().port()
                        } else {
                            *port
                        };
                        rows.push(ForwardStat {
                            active: live.active,
                            listen_port: listen,
                            status: merge(&entry.base, &guard.status()),
                            kind: ForwardKind::Local,
                        });
                    }
                    None => rows.push(ForwardStat {
                        active: false,
                        listen_port: *port,
                        status: entry.base,
                        kind: ForwardKind::Local,
                    }),
                }
            }
            for (port, entry) in &reg.udps {
                match live.udps.get(port) {
                    Some((_, guard)) => {
                        let listen = if *port == 0 {
                            guard.local_addr().port()
                        } else {
                            *port
                        };
                        rows.push(ForwardStat {
                            active: live.active,
                            listen_port: listen,
                            status: merge(&entry.base, &guard.status()),
                            kind: ForwardKind::UdpLocal,
                        });
                    }
                    None => rows.push(ForwardStat {
                        active: false,
                        listen_port: *port,
                        status: entry.base,
                        kind: ForwardKind::UdpLocal,
                    }),
                }
            }
            for (port, entry) in &reg.remotes {
                match live.remotes.get(port) {
                    Some((_, guard)) => {
                        let listen = if *port == 0 {
                            guard.local_addr().port()
                        } else {
                            *port
                        };
                        rows.push(ForwardStat {
                            active: live.active,
                            listen_port: listen,
                            status: merge(&entry.base, &guard.status()),
                            kind: ForwardKind::Remote,
                        });
                    }
                    None => rows.push(ForwardStat {
                        active: false,
                        listen_port: *port,
                        status: entry.base,
                        kind: ForwardKind::Remote,
                    }),
                }
            }
        }
        for (kind, status, active, listen) in endpoint_rows {
            rows.push(ForwardStat {
                active,
                listen_port: listen,
                status,
                kind,
            });
        }
        rows
    }
}

#[derive(Clone, Copy)]
enum EndpointSide {
    Endpoint,
    RemoteEndpoint,
}

/// Guard 统一取实际监听端口（stop 回退匹配用）。
trait ListenPort {
    fn listen_port(&self) -> u16;
}

impl ListenPort for LocalForwardGuard {
    fn listen_port(&self) -> u16 {
        self.local_addr().port()
    }
}

impl ListenPort for UdpForwardGuard {
    fn listen_port(&self) -> u16 {
        self.local_addr().port()
    }
}

impl Live {
    fn take_for(
        &mut self,
        which: EndpointSide,
    ) -> Option<(Vec<ForwardRule>, ForwardEndpointGuard)> {
        match which {
            EndpointSide::Endpoint => self.endpoint.take(),
            EndpointSide::RemoteEndpoint => self.remote_endpoint.take(),
        }
    }

    fn set_for(&mut self, which: EndpointSide, v: (Vec<ForwardRule>, ForwardEndpointGuard)) {
        match which {
            EndpointSide::Endpoint => self.endpoint = Some(v),
            EndpointSide::RemoteEndpoint => self.remote_endpoint = Some(v),
        }
    }
}

/// 端点/转发规则公共校验：非空 + 起止端口正序。
fn validate_rules(rules: &[ForwardRule]) -> Result<(), TunnelError> {
    if rules.is_empty() {
        return Err(TunnelError::InvalidRule(
            "转发端点规则表为空：至少放行一条 (host, port_from..=port_to)".into(),
        ));
    }
    for r in rules {
        if r.port_from > r.port_to {
            return Err(TunnelError::InvalidRule(format!(
                "规则 {}:{}-{} 起止端口倒置",
                r.host, r.port_from, r.port_to
            )));
        }
    }
    Ok(())
}

/// 活计数叠加进历史基数（channels_open 不累计：拆除即归零）。
fn fold(base: &mut ForwardStatus, live: ForwardStatus) {
    base.channels_total = base.channels_total.saturating_add(live.channels_total);
    base.channels_open = 0;
    base.dial_denied = base.dial_denied.saturating_add(live.dial_denied);
    base.dial_failed = base.dial_failed.saturating_add(live.dial_failed);
}

/// 历史基数 + 活计数（读侧行）。
fn merge(base: &ForwardStatus, live: &ForwardStatus) -> ForwardStatus {
    ForwardStatus {
        channels_open: base.channels_open.saturating_add(live.channels_open),
        channels_total: base.channels_total.saturating_add(live.channels_total),
        dial_denied: base.dial_denied.saturating_add(live.dial_denied),
        dial_failed: base.dial_failed.saturating_add(live.dial_failed),
    }
}

// ---------------------------------------------------------------- 无活等待

/// 空转等待：true = 被唤醒（重新快照），false = 关停。
async fn idle_wait(shared: &Shared, stop: &mut tokio_mpsc::UnboundedReceiver<()>) -> bool {
    tokio::select! {
        _ = stop.recv() => false,
        _ = shared.wake.notified() => true,
    }
}

// ---------------------------------------------------------------- 建立隧道

/// 拨号 / 监听 + 握手，带指数退避重试；每个阻塞点都可被关停/重配打断。
/// 成功重置退避；建立期失败上报 kind="retrying"（前缀 tunnel_link_failed /
/// tunnel_bind_failed / tunnel_handshake_failed）。
async fn establish(
    shared: &Shared,
    base: &TunnelBase,
    tunnel_port: u16,
    stop: &mut tokio_mpsc::UnboundedReceiver<()>,
    backoff: &mut Duration,
) -> EstablishOutcome {
    match base {
        TunnelBase::Dial {
            addresses,
            pinned_peer_public_key,
            ..
        } => loop {
            let attempt = tokio::select! {
                r = tokio::time::timeout(
                    Duration::from_secs(10),
                    luciola::link::secure::connect_secure_raced(
                        addresses.clone(),
                        tunnel_port,
                        &shared.identity_seed,
                        pinned_peer_public_key,
                    ),
                ) => r,
                _ = stop.recv() => return EstablishOutcome::Shutdown,
                _ = shared.wake.notified() => return EstablishOutcome::Restart,
            };
            match attempt {
                Ok(Ok(s)) => {
                    *backoff = BACKOFF_INIT;
                    return EstablishOutcome::Stream(Box::new(s));
                }
                Ok(Err(e)) => {
                    shared.report(
                        "retrying",
                        format!("tunnel_link_failed: {e}; next attempt in {backoff:?}",),
                    );
                }
                Err(_) => {
                    shared.report(
                        "retrying",
                        format!(
                            "tunnel_link_failed: dial timed out (10s); next attempt in {backoff:?}",
                        ),
                    );
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(*backoff) => {}
                _ = stop.recv() => return EstablishOutcome::Shutdown,
                _ = shared.wake.notified() => return EstablishOutcome::Restart,
            }
            *backoff = (*backoff * 2).min(BACKOFF_MAX);
        },
        TunnelBase::Listen { expected_peer, .. } => {
            let listener = tokio::select! {
                r = luciola::link::bind_dual_stack_listener(tunnel_port) => match r {
                    Ok(l) => l,
                    Err(e) => {
                        shared.report(
                            "retrying",
                            format!(
                                "tunnel_bind_failed: {e}; next attempt in {backoff:?}",
                            ),
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(*backoff) => {}
                            _ = stop.recv() => return EstablishOutcome::Shutdown,
                            _ = shared.wake.notified() => return EstablishOutcome::Restart,
                        }
                        *backoff = (*backoff * 2).min(BACKOFF_MAX);
                        return EstablishOutcome::Restart;
                    }
                },
                _ = stop.recv() => return EstablishOutcome::Shutdown,
                // 重配（含 set_tunnel_port）→ listener 随作用域释放，外层重绑。
                _ = shared.wake.notified() => return EstablishOutcome::Restart,
            };
            loop {
                let attempt = tokio::select! {
                    r = luciola::link::secure::accept_secure(
                        &listener,
                        &shared.identity_seed,
                        expected_peer.as_deref(),
                    ) => r,
                    _ = stop.recv() => return EstablishOutcome::Shutdown,
                    _ = shared.wake.notified() => return EstablishOutcome::Restart,
                };
                match attempt {
                    Ok(s) => {
                        *backoff = BACKOFF_INIT;
                        return EstablishOutcome::Stream(Box::new(s));
                    }
                    Err(e) => {
                        // 握手失败不杀监听器（镜像消息链路）；短退避防畸形对端忙循环。
                        shared.report(
                            "retrying",
                            format!("tunnel_handshake_failed: {e}; next accept in {backoff:?}",),
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(*backoff) => {}
                            _ = stop.recv() => return EstablishOutcome::Shutdown,
                            _ = shared.wake.notified() => return EstablishOutcome::Restart,
                        }
                        *backoff = (*backoff * 2).min(BACKOFF_MAX);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- 主监督循环

async fn supervisor(shared: Arc<Shared>, mut stop: tokio_mpsc::UnboundedReceiver<()>) {
    let mut backoff = BACKOFF_INIT;
    loop {
        let snap = shared.snapshot();
        // 1) 无活可干（pause / 全部注销）：拆除后空转等待。
        if snap.paused || !snap.has_work() {
            shared.teardown().await;
            if !idle_wait(&shared, &mut stop).await {
                return;
            }
            continue;
        }
        // 2) 基址未注入：控制面同步段已用 NotConfigured 拒绝过；等 set_base。
        let base = match snap.base.clone() {
            Some(b) => b,
            None => {
                if !idle_wait(&shared, &mut stop).await {
                    return;
                }
                continue;
            }
        };
        let tunnel_port = match base.tunnel_port(snap.port_override) {
            Ok(p) => p,
            Err(e) => {
                shared.report_err(&e);
                if !idle_wait(&shared, &mut stop).await {
                    return;
                }
                continue;
            }
        };
        // 3) 建立隧道（懒：走到这里才有网络动作）。
        let stream = match establish(&shared, &base, tunnel_port, &mut stop, &mut backoff).await {
            EstablishOutcome::Stream(s) => *s,
            EstablishOutcome::Restart => continue,
            EstablishOutcome::Shutdown => return,
        };
        let role = if base.is_dial() {
            Role::Initiator
        } else {
            Role::Responder
        };
        let session = Arc::new(MuxSession::start(stream, role, shared.mux_config()));
        debug!(port = tunnel_port, "tunnel link established");
        shared.install(session.clone(), tunnel_port).await;

        // 4) 运行期：链路死亡 / 关停 / 配置变更。
        loop {
            tokio::select! {
                _ = session.wait_closed() => break,
                _ = stop.recv() => {
                    shared.teardown().await;
                    return;
                }
                _ = shared.wake.notified() => {
                    let now = shared.snapshot();
                    let now_port = now.base
                        .as_ref()
                        .and_then(|b| b.tunnel_port(now.port_override).ok());
                    let changed = now.paused
                        || !now.has_work()
                        || now.base.as_ref() != Some(&base)
                        || now_port != Some(tunnel_port);
                    if changed {
                        // pause / 改基址 / 改 tunnel_port / 全部注销 → 统一拆除重建。
                        break;
                    }
                    // 仅注册表增量（新增/换目标）→ 原链路上热更新。
                    shared.apply_guards(&session).await;
                }
            }
        }
        // 5) 链路死亡或配置变化：拆除（计数折叠）→ 退避 → 外层重建。
        shared.teardown().await;
        debug!("tunnel link torn down; backing off before rebuild");
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = stop.recv() => return,
            _ = shared.wake.notified() => {}
        }
    }
}

// ---------------------------------------------------------------- 命令线程

/// 执行一条命令并应答；返回 false = 停机。
fn handle_cmd(cmd: Cmd, shared: &Shared) -> bool {
    match cmd {
        Cmd::StartLocal {
            listen_port,
            host,
            port,
            reply,
        } => {
            let _ = reply.send(shared.cmd_start_local(listen_port, host, port));
            true
        }
        Cmd::StopLocal { listen_port, reply } => {
            let _ = reply.send(shared.cmd_stop_forward(
                &|reg| &mut reg.locals,
                &|live| &live.locals,
                "listen_port",
                listen_port,
            ));
            true
        }
        Cmd::StartUdp {
            listen_port,
            host,
            port,
            reply,
        } => {
            let _ = reply.send(shared.cmd_start_udp(listen_port, host, port));
            true
        }
        Cmd::StopUdp { listen_port, reply } => {
            let _ = reply.send(shared.cmd_stop_forward(
                &|reg| &mut reg.udps,
                &|live| &live.udps,
                "udp listen_port",
                listen_port,
            ));
            true
        }
        Cmd::EnableEndpoint { rules, reply } => {
            let _ = reply.send(shared.cmd_enable_endpoint(rules));
            true
        }
        Cmd::DisableEndpoint { reply } => {
            let _ = reply.send(shared.cmd_disable_endpoint());
            true
        }
        Cmd::StartRemote {
            listen_port,
            host,
            port,
            reply,
        } => {
            let _ = reply.send(shared.cmd_start_remote(listen_port, host, port));
            true
        }
        Cmd::StopRemote { listen_port, reply } => {
            let _ = reply.send(shared.cmd_stop_forward(
                &|reg| &mut reg.remotes,
                &|live| &live.remotes,
                "remote listen_port",
                listen_port,
            ));
            true
        }
        Cmd::EnableRemoteEndpoint { rules, reply } => {
            let _ = reply.send(shared.cmd_enable_remote_endpoint(rules));
            true
        }
        Cmd::DisableRemoteEndpoint { reply } => {
            let _ = reply.send(shared.cmd_disable_remote_endpoint());
            true
        }
        Cmd::SetTunnelPort { port, reply } => {
            let _ = reply.send(shared.cmd_set_tunnel_port(port));
            true
        }
        Cmd::SetKeepalive {
            interval_ms,
            dead_after_ms,
        } => {
            *shared.keepalive.lock().unwrap() = (interval_ms, dead_after_ms.max(interval_ms));
            true
        }
        Cmd::SetBase { base, reporter } => {
            shared.cmd_set_base(base, reporter);
            true
        }
        Cmd::Pause => {
            shared.cmd_pause();
            true
        }
        Cmd::Shutdown => false,
    }
}

fn cmd_loop(
    rx: std_mpsc::Receiver<Cmd>,
    shared: Arc<Shared>,
    stop: tokio_mpsc::UnboundedSender<()>,
) {
    while let Ok(cmd) = rx.recv() {
        if !handle_cmd(cmd, &shared) {
            break;
        }
    }
    // Shutdown 或发送端全部关闭（Drop）→ 通知 supervisor 退出。
    let _ = stop.send(());
}

fn supervisor_thread(shared: Arc<Shared>, stop: tokio_mpsc::UnboundedReceiver<()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("luciola-tunnel supervisor runtime 构建失败");
    rt.block_on(supervisor(shared, stop));
}

// ---------------------------------------------------------------- 对外入口

/// 隧道链路监督实例（T3）：构造即启动 cmd + supervisor 两条线程。
///
/// 生命周期镜像消息链路：`disconnect()`/`close()` → [`TunnelLink::pause`]，
/// `connect()`/`listen()` → [`TunnelLink::set_base`]，Drop 停线程并 join。
/// 同步方法可从任意线程（含监听器回调）调用，无死锁。
pub struct TunnelLink {
    shared: Arc<Shared>,
    cmd_tx: std_mpsc::Sender<Cmd>,
    cmd_thread: StdMutex<Option<JoinHandle<()>>>,
    sup_thread: StdMutex<Option<JoinHandle<()>>>,
}

impl TunnelLink {
    /// 启动控制面线程对（懒建立：注册前不占任何网络资源）。
    pub fn new(identity_seed: Vec<u8>) -> Arc<Self> {
        let shared = Arc::new(Shared {
            identity_seed,
            base: StdMutex::new(None),
            reporter: StdMutex::new(None),
            port_override: AtomicU16::new(0),
            keepalive: StdMutex::new(KEEPALIVE_DEFAULT),
            registry: StdMutex::new(Registry::default()),
            live: StdMutex::new(Live::default()),
            wake: Notify::new(),
        });
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
        let (stop_tx, stop_rx) = tokio_mpsc::unbounded_channel::<()>();
        let sup_shared = shared.clone();
        let sup_thread = std::thread::Builder::new()
            .name("luciola-tunnel-link".into())
            .spawn(move || supervisor_thread(sup_shared, stop_rx))
            .expect("spawn luciola-tunnel supervisor");
        let cmd_shared = shared.clone();
        let cmd_thread = std::thread::Builder::new()
            .name("luciola-tunnel-cmd".into())
            .spawn(move || cmd_loop(cmd_rx, cmd_shared, stop_tx))
            .expect("spawn luciola-tunnel cmd");
        Arc::new(Self {
            shared,
            cmd_tx,
            cmd_thread: StdMutex::new(Some(cmd_thread)),
            sup_thread: StdMutex::new(Some(sup_thread)),
        })
    }

    /// 同步回合：发命令、等应答（任何线程安全；回调内调用不死锁）。
    fn call(&self, build: impl FnOnce(Reply) -> Cmd) -> Result<(), TunnelError> {
        let (tx, rx) = std_mpsc::channel();
        self.cmd_tx
            .send(build(tx))
            .map_err(|_| TunnelError::Unavailable("隧道控制线程已退出".into()))?;
        rx.recv()
            .map_err(|_| TunnelError::Unavailable("隧道控制线程未应答（已退出）".into()))?
    }

    /// 注册本地转发（Dial 角色；listen_port=0 → 系统分配实端口）。
    /// `host` 为 IP 字面量或主机名（主机名由对端解析并按会话钉扎）。
    /// 校验/探测同步完成，返回时注册已生效；实际绑定由 supervisor 惰性完成。
    pub fn start_local_forward(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::StartLocal {
            listen_port,
            host,
            port,
            reply,
        })
    }

    /// 注销本地转发（停止 Guard + 折叠计数；未注册返回 Err）。
    pub fn stop_local_forward(&self, listen_port: u16) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::StopLocal { listen_port, reply })
    }

    /// 注册 UDP 转发（Dial 角色；v2 NAT 式映射，listen_port=0 → 系统分配）。
    /// 对端 endpoint 的 ACL 规则须 `udp: true` 放行该目标。
    pub fn start_udp_forward(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::StartUdp {
            listen_port,
            host,
            port,
            reply,
        })
    }

    /// 注销 UDP 转发。
    pub fn stop_udp_forward(&self, listen_port: u16) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::StopUdp { listen_port, reply })
    }

    /// 启用/替换转发端点 ACL（Listen 角色；规则非空且 from<=to；tunnel_port 双栈探测）。
    /// 规则主机为 IP 字面量或主机名；`udp: true` 的规则同时放行 DOPEN（UDP 拨号）。
    pub fn enable_forward_endpoint(&self, rules: Vec<ForwardRule>) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::EnableEndpoint { rules, reply })
    }

    /// 关闭转发端点（幂等）。
    pub fn disable_forward_endpoint(&self) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::DisableEndpoint { reply })
    }

    /// 注册 remote forward（Listen 角色；v2 `-R`）：本机 127.0.0.1:listen_port 的
    /// 每条入站连接经 mux 偶数通道转发到**对端机**上的 host:port。
    /// 对端须启用 remote endpoint ACL（`enable_remote_endpoint`）。
    pub fn start_remote_forward(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::StartRemote {
            listen_port,
            host,
            port,
            reply,
        })
    }

    /// 注销 remote forward。
    pub fn stop_remote_forward(&self, listen_port: u16) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::StopRemote { listen_port, reply })
    }

    /// 启用/替换 remote endpoint ACL（Dial 角色）：放行 Responder 发起的
    /// 通道（偶数）并拨本机目标。空表拒绝；默认（未启用）= 全拒。
    pub fn enable_remote_endpoint(&self, rules: Vec<ForwardRule>) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::EnableRemoteEndpoint { rules, reply })
    }

    /// 关闭 remote endpoint（幂等）。
    pub fn disable_remote_endpoint(&self) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::DisableRemoteEndpoint { reply })
    }

    /// 覆盖 tunnel_port（0 = 恢复 `secure 端口 + 1` 推导）；生效即重建链路。
    pub fn set_tunnel_port(&self, port: u16) -> Result<(), TunnelError> {
        self.call(|reply| Cmd::SetTunnelPort { port, reply })
    }

    /// 隧道 mux keepalive（v2）：interval_ms=0 关闭；改动随下一次链路重建生效。
    pub fn set_keepalive(&self, interval_ms: u64, dead_after_ms: u64) {
        let _ = self.cmd_tx.send(Cmd::SetKeepalive {
            interval_ms,
            dead_after_ms,
        });
    }

    /// 注入基址与上报器（connect/listen 后调用）：解除 pause 并按注册表恢复转发。
    pub fn set_base(&self, base: TunnelBase, reporter: Arc<dyn TunnelReporter>) {
        let _ = self.cmd_tx.send(Cmd::SetBase { base, reporter });
    }

    /// 暂停隧道链路（消息链路断开时调用）：拆除活跃转发，注册表/基址保留。
    pub fn pause(&self) {
        let _ = self.cmd_tx.send(Cmd::Pause);
    }

    /// 快照全部转发状态（历史折叠计数；无链路时 active=false；锁内只读短临界区）。
    pub fn stats(&self) -> Vec<ForwardStat> {
        self.shared.stats()
    }

    /// 主动停机（幂等；线程 join 由 Drop 完成）。
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown);
    }
}

impl Drop for TunnelLink {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown);
        // 防自 join：supervisor 回调里析构最后一个 Arc 时跳过本线程（runtime 随即回收）。
        let here = std::thread::current().id();
        let cmd = self.cmd_thread.lock().unwrap().take();
        let sup = self.sup_thread.lock().unwrap().take();
        for h in [cmd, sup].into_iter().flatten() {
            if h.thread().id() != here {
                let _ = h.join();
            }
        }
    }
}
