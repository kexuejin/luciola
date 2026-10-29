//! forward —— 端口转发与服务端 ACL 白名单。
//!
//! 四类转发面（v2）：
//!
//! - **LocalForward**（发起方）：监听 `127.0.0.1:<listen_port>`（只绑环回，
//!   不对外暴露：本地转发入口不鉴权，绑 `0.0.0.0` 等于向全 LAN 开放未加密隧道），每个入站 TCP 连接经 `MuxSession::open()` 建一条 mux 通道，
//!   与对端 `target` 双向拷贝。会话未建立/被拒时立即关闭本地连接（fail-fast，
//!   浏览器自行重试）。
//! - **ForwardEndpoint**（接受方）：`accept_open()` 循环，把每个 OPEN/DOPEN 请求
//!   派发到独立并发任务执行 ACL 检查（默认拒绝）、主机名解析（带会话级
//!   解析钉扎）与拨号（TCP 经 `link::dial`、UDP 走 connect 套接字，受
//!   `MuxConfig::dial_timeout` 限制），然后 grant + 双向拷贝/数据报中继。
//!   v2 起同一 Guard 也用于发起方接受 remote forward 的偶数通道（此时叫
//!   remote endpoint，注册在 tunnel_link 的对应注册表里）。
//! - **RemoteForward**（接受方/服务端侧发起，`-R` 等价物）：监听
//!   `127.0.0.1:<listen_port>`，每条入站连接经 `MuxSession::open()`（v2 中
//!   Responder 发出的偶数通道）转发到**对端机**上的 target。实现与
//!   LocalForward 同构，仅语义不同。
//! - **UdpForward**（发起方）：监听 `127.0.0.1:<listen_port>` 的 UDP 套接字，
//!   每个源地址 lazily 映射一条数据报通道（NAT 式会话映射），双向中继数据报；
//!   映射空闲超时（`MuxConfig::udp_idle_timeout`）自动回收。
//!
//! # 调度契约
//!
//! 所有 `start_*` 都在调用处捕获显式 `tokio::runtime::Handle`，Guard 内部
//! 所有任务（accept 循环与每连接子任务）一律经该 Handle 派发，不依赖任何
//! 隐式的调用方线程上下文（spec §2.3）。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::mux::{AckStatus, DialTarget, MuxSession, OpenRequest};
use crate::TunnelError;

// ---------------------------------------------------------------- 计数器

/// forward 层原子计数器（Guard 持有；T3 FFI status 直接读快照）。
///
/// - `channels_open`：当前正在进行双向拷贝/中继的通道数（派生量）。
/// - `channels_total`：生命周期内 grant 成功的通道累计数。
/// - `dial_denied`：被 ACL 白名单拒绝的 OPEN/DOPEN（从未发起拨号）。
/// - `dial_failed`：放行后拨号失败/超时/解析失败的 OPEN/DOPEN。
#[derive(Debug, Default)]
pub struct ForwardCounters {
    pub channels_open: AtomicU64,
    pub channels_total: AtomicU64,
    pub dial_denied: AtomicU64,
    pub dial_failed: AtomicU64,
}

impl ForwardCounters {
    /// 取一份普通值快照（FFI DTO / CLI status 用）。
    pub fn snapshot(&self) -> ForwardStatus {
        ForwardStatus {
            channels_open: self.channels_open.load(Ordering::SeqCst),
            channels_total: self.channels_total.load(Ordering::SeqCst),
            dial_denied: self.dial_denied.load(Ordering::SeqCst),
            dial_failed: self.dial_failed.load(Ordering::SeqCst),
        }
    }
}

/// `ForwardCounters` 的纯值快照（可直接进 uniffi DTO）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardStatus {
    pub channels_open: u64,
    pub channels_total: u64,
    pub dial_denied: u64,
    pub dial_failed: u64,
}

// ---------------------------------------------------------------- ACL

/// 一条白名单规则：主机（IP 字面量或主机名，小写规范化）+ 端口区间
/// （含端点，`port_from <= port_to`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRule {
    /// IP 字面量或主机名（构造时规范化为小写；匹配区分两类，互不跨匹配）。
    pub host: String,
    pub port_from: u16,
    pub port_to: u16,
    /// v2：true 时本规则同时放行 UDP 数据报拨号（DOPEN）；false 仅 TCP（v1 语义）。
    pub udp: bool,
}

impl ForwardRule {
    /// 解析 CLI/FFI 规则文本：
    ///
    /// - `127.0.0.1:8080` —— 单端口
    /// - `127.0.0.1:8000-8100` —— 端口区间
    /// - `[::1]:8080` / `[::1]:8000-8100` —— IPv6 必须带方括号
    /// - `nas.local:8080` —— 主机名（v2）
    pub fn parse(spec: &str) -> Result<Self, TunnelError> {
        let bad = || TunnelError::InvalidRule(spec.to_string());
        let (host_str, port_str) = if let Some(rest) = spec.strip_prefix('[') {
            let end = rest.find(']').ok_or_else(bad)?;
            let host = &rest[..end];
            let tail = rest[end + 1..].strip_prefix(':').ok_or_else(bad)?;
            (host, tail)
        } else {
            let idx = spec.rfind(':').ok_or_else(bad)?;
            (&spec[..idx], &spec[idx + 1..])
        };
        let host = normalize_rule_host_text(host_str).ok_or_else(bad)?;
        let (from, to) = match port_str.split_once('-') {
            Some((a, b)) => (
                a.parse::<u16>().map_err(|_| bad())?,
                b.parse::<u16>().map_err(|_| bad())?,
            ),
            None => {
                let p = port_str.parse::<u16>().map_err(|_| bad())?;
                (p, p)
            }
        };
        if from > to {
            return Err(TunnelError::InvalidRule(format!(
                "{spec} (port_from > port_to)"
            )));
        }
        Ok(Self {
            host,
            port_from: from,
            port_to: to,
            udp: false,
        })
    }

    fn ip_literal(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

/// 规则主机规范化（FFI/CLI 共用）：IP 字面量原样；主机名小写去尾点并做
/// 结构校验。非法 → None。
pub fn normalize_rule_host_text(host: &str) -> Option<String> {
    let t = DialTarget::new(host, 1);
    t.validate().then_some(t.host)
}

/// 服务端拨号白名单。**默认空表 = 全部拒绝**（deny-by-default，D7）。
#[derive(Debug, Clone, Default)]
pub struct ForwardAcl {
    pub rules: Vec<ForwardRule>,
}

impl ForwardAcl {
    pub fn new(rules: Vec<ForwardRule>) -> Self {
        Self { rules }
    }

    /// 是否放行。IP 经 `::ffff:v4` 映射标准化后按精确值比较；主机名按
    /// 小写精确比较。IP 规则与主机名目标互不匹配（不在 ACL 阶段解析——
    /// 对未放行目标做解析会泄漏解析行为，D5）。`datagram` 为 true 时仅
    /// `udp: true` 的规则可放行（v2 DOPEN）。
    pub fn allows(&self, target: &DialTarget, datagram: bool) -> bool {
        self.rules.iter().any(|r| {
            if datagram && !r.udp {
                return false;
            }
            if !(r.port_from..=r.port_to).contains(&target.port) {
                return false;
            }
            match (r.ip_literal(), target.ip_literal()) {
                (Some(rh), Some(th)) => normalize_ip(rh) == normalize_ip(th),
                (None, None) => r.host == target.host,
                _ => false,
            }
        })
    }
}

/// IPv4-mapped IPv6 → IPv4（`::ffff:10.0.0.1` 与 `10.0.0.1` 视为同一主机）。
fn normalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

// ---------------------------------------------------------------- Guard 公共件

/// 本地转发 Guard：持有监听端口与全部任务句柄。
///
/// `stop().await` 或 Drop 即终止 accept 循环（释放监听端口）与全部转发子任务。
/// TCP 本地转发与 remote forward（`-R`）共用此 Guard。
pub struct LocalForwardGuard {
    listen_addr: SocketAddr,
    accept: StdMutex<Option<JoinHandle<()>>>,
    children: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    /// 本转发的通道计数（生命周期与 Guard 相同；可在 stop 后继续读快照）。
    pub counters: Arc<ForwardCounters>,
}

impl LocalForwardGuard {
    /// 实际监听地址（listen_port=0 时用于取系统分配的端口）。
    pub fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 计数器快照。
    pub fn status(&self) -> ForwardStatus {
        self.counters.snapshot()
    }

    /// 停止 accept 循环并等待其退出（监听端口随即释放，可立即重新绑定），
    /// 同时中止全部转发子任务。幂等；与 Drop 兼容。
    pub async fn stop(&self) {
        let task = self.accept.lock().unwrap().take();
        if let Some(t) = task {
            t.abort();
            let _ = t.await; // accept 任务退出 → 监听 fd 释放 → 可安全重建同端口
        }
        let mut children = self.children.lock().unwrap();
        for t in children.drain(..) {
            t.abort();
        }
    }
}

impl Drop for LocalForwardGuard {
    fn drop(&mut self) {
        if let Some(t) = self.accept.lock().unwrap().take() {
            t.abort();
        }
        for t in self.children.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

/// 本地端口转发配置。监听失败/目标不合法由 `start_local_forward` 校验。
#[derive(Debug, Clone)]
pub struct LocalForwardConfig {
    /// 本地监听端口；0 = 系统分配，实际端口从 Guard 取（`local_addr()`）。
    pub listen_port: u16,
    /// 对端机上的目标地址（IP 字面量或主机名；主机名由对端解析并钉扎）。
    pub target: DialTarget,
}

/// TCP 转发（本地 forward 与 remote forward 共用实现）。
fn start_tcp_forward(
    session: Arc<MuxSession>,
    cfg: LocalForwardConfig,
) -> Result<LocalForwardGuard, TunnelError> {
    let handle = Handle::current();
    if !cfg.target.validate() {
        return Err(TunnelError::InvalidTarget(cfg.target.to_string()));
    }

    // D6：只绑 127.0.0.1，不对外暴露。
    let std_listener = std::net::TcpListener::bind(("127.0.0.1", cfg.listen_port))?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let listen_addr = listener.local_addr()?;

    let counters = Arc::new(ForwardCounters::default());
    let children: Arc<StdMutex<Vec<JoinHandle<()>>>> = Arc::new(StdMutex::new(Vec::new()));

    let accept_task = handle.spawn({
        let counters = counters.clone();
        let children = children.clone();
        let handle = handle.clone();
        async move {
            loop {
                match listener.accept().await {
                    Ok((mut conn, peer)) => {
                        // open() 首查会话存活：会话已死 → 立即关闭本地连接
                        // （fail-fast，浏览器自行重试），不进表、不发帧。
                        let session = session.clone();
                        let counters = counters.clone();
                        let children = children.clone();
                        let target = cfg.target.clone();
                        let task = handle.spawn(async move {
                            match session.open(target).await {
                                Ok(mut stream) => {
                                    counters.channels_total.fetch_add(1, Ordering::SeqCst);
                                    counters.channels_open.fetch_add(1, Ordering::SeqCst);
                                    if let Err(e) = copy_bidirectional(&mut stream, &mut conn).await {
                                        debug!("forward copy for {peer} ended: {e}");
                                    }
                                    counters.channels_open.fetch_sub(1, Ordering::SeqCst);
                                }
                                Err(e) => {
                                    // 会话未建立 / 被拒 / 超时：本地连接直接丢弃。
                                    debug!("local forward open for {peer} failed (fail-fast close): {e}");
                                }
                            }
                        });
                        let mut ch = children.lock().unwrap();
                        ch.retain(|t| !t.is_finished());
                        ch.push(task);
                    }
                    Err(e) => {
                        warn!("local forward accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    });

    Ok(LocalForwardGuard {
        listen_addr,
        accept: StdMutex::new(Some(accept_task)),
        children,
        counters,
    })
}

/// 启动本地端口转发（发起方；spec §2.3）。
///
/// 必须在 tokio runtime 上下文中调用（与 `MuxSession::start` 同一前提）：
/// 本函数在调用处捕获显式 `Handle`，此后所有任务经该 Handle 派发。
pub fn start_local_forward(
    session: Arc<MuxSession>,
    cfg: LocalForwardConfig,
) -> Result<LocalForwardGuard, TunnelError> {
    start_tcp_forward(session, cfg)
}

/// 启动 remote forward（v2，`-R` 等价物；接受方/服务端侧）：
/// 本机 `127.0.0.1:<listen_port>` 的每条入站连接经 mux 通道（Responder 发出的
/// 偶数通道）转发到**对端机**上的 `cfg.target`。对端须启用 remote endpoint
/// ACL（`start_forward_endpoint` 挂在 Initiator 会话上）放行该目标。
///
/// 通道复用与计数语义与 [`start_local_forward`] 完全一致。
pub fn start_remote_forward(
    session: Arc<MuxSession>,
    cfg: LocalForwardConfig,
) -> Result<LocalForwardGuard, TunnelError> {
    start_tcp_forward(session, cfg)
}

// ---------------------------------------------------------------- UdpForward

/// UDP 转发（发起方）配置：本地 UDP 监听 + 对端机上的目标。
#[derive(Debug, Clone)]
pub struct UdpForwardConfig {
    /// 本地 UDP 监听端口（只绑 127.0.0.1，D6）；0 = 系统分配。
    pub listen_port: u16,
    /// 对端机上的 UDP 目标。
    pub target: DialTarget,
}

/// UDP 转发 Guard。
pub struct UdpForwardGuard {
    listen_addr: SocketAddr,
    accept: StdMutex<Option<JoinHandle<()>>>,
    children: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    /// NAT 式映射表（src → 本地队列）；accept 任务维护，stop 时清空。
    mappings: Arc<StdMutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    pub counters: Arc<ForwardCounters>,
}

impl UdpForwardGuard {
    /// 实际监听地址（listen_port=0 时用于取系统分配的端口）。
    pub fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 计数器快照。
    pub fn status(&self) -> ForwardStatus {
        self.counters.snapshot()
    }

    /// 当前活跃的 NAT 式映射数。
    pub fn mappings(&self) -> usize {
        self.mappings.lock().unwrap().len()
    }

    /// 停止 accept 循环与全部映射子任务（本地端口随即释放）。幂等。
    pub async fn stop(&self) {
        let task = self.accept.lock().unwrap().take();
        if let Some(t) = task {
            t.abort();
            let _ = t.await;
        }
        let mut children = self.children.lock().unwrap();
        for t in children.drain(..) {
            t.abort();
        }
        self.mappings.lock().unwrap().clear();
    }
}

impl Drop for UdpForwardGuard {
    fn drop(&mut self) {
        if let Some(t) = self.accept.lock().unwrap().take() {
            t.abort();
        }
        for t in self.children.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

/// 启动 UDP 转发（发起方；v2 NAT 式会话映射）。必须在 tokio runtime 上下文中调用。
///
/// 每个源地址（ip:port）lazily 建一条数据报通道（`open_datagram`），映射空闲
/// 超过 `MuxConfig::udp_idle_timeout` 自动回收；accept 任务是本地套接字的唯一
/// 读者，按源地址分发到映射子任务（每映射一条有界队列，打满即丢——UDP 语义）。
pub fn start_udp_forward(
    session: Arc<MuxSession>,
    cfg: UdpForwardConfig,
) -> Result<UdpForwardGuard, TunnelError> {
    let handle = Handle::current();
    if !cfg.target.validate() {
        return Err(TunnelError::InvalidTarget(cfg.target.to_string()));
    }

    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", cfg.listen_port))?;
    std_sock.set_nonblocking(true)?;
    let sock = Arc::new(UdpSocket::from_std(std_sock)?);
    let listen_addr = sock.local_addr()?;

    let counters = Arc::new(ForwardCounters::default());
    let children: Arc<StdMutex<Vec<JoinHandle<()>>>> = Arc::new(StdMutex::new(Vec::new()));
    let mappings: Arc<StdMutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(StdMutex::new(HashMap::new()));

    let accept_task = handle.spawn({
        let counters = counters.clone();
        let children = children.clone();
        let mappings = mappings.clone();
        let handle = handle.clone();
        let session = session.clone();
        let target = cfg.target.clone();
        async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("udp forward recv error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let datagram = buf[..n].to_vec();
                // 命中已有映射 → 直投队列（满即丢，UDP 语义）；
                // 未命中 → 开新数据报通道 + 起映射子任务。
                let tx = mappings.lock().unwrap().get(&src).cloned();
                match tx {
                    Some(tx) => {
                        let _ = tx.try_send(datagram);
                    }
                    None => {
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(32);
                        mappings.lock().unwrap().insert(src, tx.clone());
                        let task = handle.spawn({
                            let counters = counters.clone();
                            let mappings = mappings.clone();
                            let sock = sock.clone();
                            let session = session.clone();
                            let target = target.clone();
                            let idle = session.config().udp_idle_timeout;
                            async move {
                                udp_mapping_task(session, target, sock, src, rx, idle, counters)
                                    .await;
                                mappings.lock().unwrap().remove(&src);
                            }
                        });
                        let mut ch = children.lock().unwrap();
                        ch.retain(|t| !t.is_finished());
                        ch.push(task);
                        // 首个数据报不能丢：队列刚建、必然有空位。
                        let _ = tx.try_send(datagram);
                    }
                }
            }
        }
    });

    Ok(UdpForwardGuard {
        listen_addr,
        accept: StdMutex::new(Some(accept_task)),
        children,
        mappings,
        counters,
    })
}

/// 单个 NAT 式映射：本地队列 → 数据报通道；通道 → 本地套接字回源。
/// 空闲超时（收不到任何一方向流量）自动拆通道并退出（映射随 Guard 表清理）。
async fn udp_mapping_task(
    session: Arc<MuxSession>,
    target: DialTarget,
    sock: Arc<UdpSocket>,
    src: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    idle: Option<Duration>,
    counters: Arc<ForwardCounters>,
) {
    let mut ch = match session.open_datagram(target).await {
        Ok(ch) => {
            // 计数与 TCP 路径一致：通道建立成功才计入 total/open。
            counters.channels_total.fetch_add(1, Ordering::SeqCst);
            counters.channels_open.fetch_add(1, Ordering::SeqCst);
            ch
        }
        Err(e) => {
            debug!("udp forward open_datagram for {src} failed: {e}");
            return;
        }
    };
    let idle = idle.unwrap_or(Duration::from_secs(60));
    loop {
        tokio::select! {
            out = ch.recv_datagram() => match out {
                Some(bytes) => {
                    if sock.send_to(&bytes, src).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            up = rx.recv() => match up {
                Some(bytes) => {
                    if ch.send_datagram(&bytes).await.is_err() {
                        break;
                    }
                }
                None => break, // accept 任务终止（Guard stop）
            },
            _ = tokio::time::sleep(idle) => {
                // select 每轮重新计时：任一方向有流量即续期；整轮无事件才超时回收。
                break;
            }
        }
    }
    counters.channels_open.fetch_sub(1, Ordering::SeqCst);
    drop(ch); // Drop 补发 CLOSE(0)
}

// ---------------------------------------------------------------- ForwardEndpoint

/// 服务端转发端点 Guard：`accept_open` 循环 + 每请求并发任务。
///
/// `stop().await` 或 Drop 即终止循环并中止在途子任务。
pub struct ForwardEndpointGuard {
    accept: StdMutex<Option<JoinHandle<()>>>,
    children: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    /// 端点计数（生命周期与 Guard 相同）。
    pub counters: Arc<ForwardCounters>,
}

impl ForwardEndpointGuard {
    /// 计数器快照。
    pub fn status(&self) -> ForwardStatus {
        self.counters.snapshot()
    }

    /// 停止 accept 循环（等待退出）并中止在途子任务。幂等。
    pub async fn stop(&self) {
        let task = self.accept.lock().unwrap().take();
        if let Some(t) = task {
            t.abort();
            let _ = t.await;
        }
        let mut children = self.children.lock().unwrap();
        for t in children.drain(..) {
            t.abort();
        }
    }
}

impl Drop for ForwardEndpointGuard {
    fn drop(&mut self) {
        if let Some(t) = self.accept.lock().unwrap().take() {
            t.abort();
        }
        for t in self.children.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

/// 启动服务端转发端点（spec §2.3）。必须在 tokio runtime 上下文中调用。
///
/// 每个 OPEN/DOPEN 请求都在**独立并发任务**里处理（严禁在主循环串行 await
/// ACL/拨号）。v2：挂在 Initiator 会话上即为 remote endpoint（接受 Responder
/// 发起的偶数通道，需对端 v2）；ACL 默认拒绝，主机名规则跨会话做解析钉扎。
pub fn start_forward_endpoint(
    session: Arc<MuxSession>,
    acl: ForwardAcl,
) -> Result<ForwardEndpointGuard, TunnelError> {
    let handle = Handle::current();
    let counters = Arc::new(ForwardCounters::default());
    let children: Arc<StdMutex<Vec<JoinHandle<()>>>> = Arc::new(StdMutex::new(Vec::new()));
    let state = Arc::new(EndpointState {
        acl,
        counters: counters.clone(),
        resolve_cache: StdMutex::new(HashMap::new()),
        dial_timeout: session.config().dial_timeout,
    });

    let accept_task = handle.spawn({
        let state = state.clone();
        let children = children.clone();
        let handle = handle.clone();
        async move {
            loop {
                let req = match session.accept_open().await {
                    Ok(req) => req,
                    Err(e) => {
                        debug!("forward endpoint accept loop ended: {e}");
                        break;
                    }
                };
                let state = state.clone();
                let children = children.clone();
                let task = handle.spawn(async move {
                    serve_one(req, state).await;
                });
                let mut ch = children.lock().unwrap();
                ch.retain(|t| !t.is_finished());
                ch.push(task);
            }
        }
    });

    Ok(ForwardEndpointGuard {
        accept: StdMutex::new(Some(accept_task)),
        children,
        counters,
    })
}

/// 端点运行态：ACL + 解析钉扎缓存（v2 防 rebinding：同一 Guard 生命周期内，
/// 同一主机名只解析一次，后续拨号复用钉扎结果）。
struct EndpointState {
    acl: ForwardAcl,
    counters: Arc<ForwardCounters>,
    resolve_cache: StdMutex<HashMap<String, IpAddr>>,
    dial_timeout: Duration,
}

/// 处理一个 OPEN/DOPEN 请求：ACL（默认拒绝）→ 解析钉扎 → 拨号（dial_timeout 上限）
/// → grant → 双向拷贝 / 数据报中继。
async fn serve_one(req: OpenRequest, state: Arc<EndpointState>) {
    let target = req.target.clone();
    let datagram = req.datagram;

    // ① 目标合法性（防御纵深；mux 解析阶段已挡大部分非法目标）。
    if !target.validate() {
        let _ = req.deny(AckStatus::BAD_TARGET, None).await;
        return;
    }

    // ② ACL：默认拒绝。拒绝时**永不拨号、永不解析**，也不向 initiator 附带策略细节。
    if !state.acl.allows(&target, datagram) {
        state.counters.dial_denied.fetch_add(1, Ordering::SeqCst);
        let _ = req.deny(AckStatus::ACL_DENIED, None).await;
        return;
    }

    // ③ 解析钉扎：IP 字面量直接用；主机名在同一端点生命周期内只解析一次。
    let ip = match target.ip_literal() {
        Some(ip) => ip,
        None => {
            match resolve_pinned(&state.resolve_cache, &target.host, state.dial_timeout).await {
                Ok(ip) => ip,
                Err(e) => {
                    state.counters.dial_failed.fetch_add(1, Ordering::SeqCst);
                    let _ = req
                        .deny(AckStatus::DIAL_FAILED, Some(format!("resolve failed: {e}")))
                        .await;
                    return;
                }
            }
        }
    };

    if datagram {
        serve_datagram(req, state, ip, target.port).await;
    } else {
        serve_stream(req, state, ip, target.port).await;
    }
}

/// 流式通道：TCP 拨号 → grant → copy_bidirectional。
async fn serve_stream(req: OpenRequest, state: Arc<EndpointState>, ip: IpAddr, port: u16) {
    // ④ 并发拨号（link::dial 内含 IPv4/IPv6/host 统一路径与链路本地 scope 处理；
    //    受 dial_timeout 上限，与 initiator 的 open_timeout 对齐）。
    let ip_str = ip.to_string();
    let dial = luciola::link::dial(&ip_str, port);
    let mut upstream: TcpStream = match tokio::time::timeout(state.dial_timeout, dial).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            state.counters.dial_failed.fetch_add(1, Ordering::SeqCst);
            let _ = req
                .deny(AckStatus::DIAL_FAILED, Some(format!("dial failed: {e}")))
                .await;
            return;
        }
        Err(_) => {
            state.counters.dial_failed.fetch_add(1, Ordering::SeqCst);
            let _ = req
                .deny(
                    AckStatus::DIAL_FAILED,
                    Some(format!("dial timeout after {:?}", state.dial_timeout)),
                )
                .await;
            return;
        }
    };

    // ⑤ grant → 双向拷贝。grant 失败（会话已死）→ 丢弃 upstream（fd 随之关闭，无泄漏）。
    match req.grant().await {
        Ok(mut stream) => {
            state.counters.channels_total.fetch_add(1, Ordering::SeqCst);
            state.counters.channels_open.fetch_add(1, Ordering::SeqCst);
            if let Err(e) = copy_bidirectional(&mut stream, &mut upstream).await {
                debug!("endpoint copy ended: {e}");
            }
            state.counters.channels_open.fetch_sub(1, Ordering::SeqCst);
        }
        Err(e) => {
            debug!("grant after dial failed: {e}");
        }
    }
}

/// 数据报通道（v2 UDP 会话映射）：UDP connect 套接字 → grant_datagram → 双向中继。
/// 每个通道一个独立 UDP 套接字（connect 固定对端，天然过滤非目标源）。
async fn serve_datagram(req: OpenRequest, state: Arc<EndpointState>, ip: IpAddr, port: u16) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            state.counters.dial_failed.fetch_add(1, Ordering::SeqCst);
            let _ = req
                .deny(
                    AckStatus::DIAL_FAILED,
                    Some(format!("udp bind failed: {e}")),
                )
                .await;
            return;
        }
    };
    if let Err(e) = sock.connect((ip, port)).await {
        state.counters.dial_failed.fetch_add(1, Ordering::SeqCst);
        let _ = req
            .deny(
                AckStatus::DIAL_FAILED,
                Some(format!("udp connect failed: {e}")),
            )
            .await;
        return;
    }

    match req.grant_datagram().await {
        Ok(mut ch) => {
            state.counters.channels_total.fetch_add(1, Ordering::SeqCst);
            state.counters.channels_open.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    out = ch.recv_datagram() => match out {
                        Some(bytes) => {
                            if sock.send(&bytes).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                    r = sock.recv(&mut buf) => match r {
                        Ok(n) => {
                            if ch.send_datagram(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
            state.counters.channels_open.fetch_sub(1, Ordering::SeqCst);
        }
        Err(e) => {
            debug!("grant_datagram after dial failed: {e}");
        }
    }
}

/// 会话级解析钉扎：首次解析并缓存，后续复用（v2 防 rebinding——同一会话内
/// 同一主机名的目标永不漂移）。解析受 dial_timeout 上限。多地址结果中
/// 优先取 IPv4（局域网工具的普遍偏好；v6-only 主机仍取 v6）。
async fn resolve_pinned(
    cache: &StdMutex<HashMap<String, IpAddr>>,
    host: &str,
    dial_timeout: Duration,
) -> Result<IpAddr, String> {
    if let Some(ip) = cache.lock().unwrap().get(host) {
        return Ok(*ip);
    }
    let lookup = async {
        match tokio::net::lookup_host((host, 0u16)).await {
            Ok(addrs) => {
                let mut first = None;
                let mut v4 = None;
                for sa in addrs {
                    let ip = sa.ip();
                    if first.is_none() {
                        first = Some(ip);
                    }
                    if v4.is_none() && ip.is_ipv4() {
                        v4 = Some(ip);
                    }
                }
                v4.or(first)
                    .ok_or_else(|| format!("no addresses for {host}"))
            }
            Err(e) => Err(format!("{e}")),
        }
    };
    let ip = match tokio::time::timeout(dial_timeout, lookup).await {
        Ok(r) => r?,
        Err(_) => return Err(format!("resolve timeout after {dial_timeout:?}")),
    };
    cache.lock().unwrap().insert(host.to_string(), ip);
    Ok(ip)
}

// ---------------------------------------------------------------- 单元测试（ACL）

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(spec: &str) -> ForwardRule {
        ForwardRule::parse(spec).unwrap()
    }

    #[test]
    fn acl_ip_exact_and_port_range() {
        let acl = ForwardAcl::new(vec![rule("127.0.0.1:8000-8100")]);
        assert!(acl.allows(&DialTarget::new("127.0.0.1", 8080), false));
        assert!(acl.allows(&DialTarget::new("127.0.0.1", 8000), false));
        assert!(acl.allows(&DialTarget::new("127.0.0.1", 8100), false));
        assert!(!acl.allows(&DialTarget::new("127.0.0.1", 8101), false));
        assert!(!acl.allows(&DialTarget::new("127.0.0.2", 8080), false));
        // mapped-v4 标准化
        assert!(acl.allows(&DialTarget::new("::ffff:127.0.0.1", 8080), false));
    }

    #[test]
    fn acl_ipv6_bracket_spec() {
        let acl = ForwardAcl::new(vec![rule("[::1]:8080")]);
        assert!(acl.allows(&DialTarget::new("::1", 8080), false));
        assert!(!acl.allows(&DialTarget::new("::2", 8080), false));
    }

    #[test]
    fn acl_hostname_rules() {
        let acl = ForwardAcl::new(vec![rule("NAS.local:80")]);
        assert!(acl.allows(&DialTarget::new("nas.local", 80), false));
        assert!(acl.allows(&DialTarget::new("NAS.LOCAL.", 80), false)); // 规范化
        assert!(!acl.allows(&DialTarget::new("nas.local", 81), false));
        assert!(!acl.allows(&DialTarget::new("nas.other", 80), false));
        // 主机名规则不匹配 IP 目标，IP 规则不匹配主机名目标（互不跨匹配）
        let ip_acl = ForwardAcl::new(vec![rule("127.0.0.1:80")]);
        assert!(!ip_acl.allows(&DialTarget::new("nas.local", 80), false));
        assert!(!acl.allows(&DialTarget::new("127.0.0.1", 80), false));
    }

    #[test]
    fn acl_udp_gate() {
        let mut r = rule("127.0.0.1:5353");
        assert!(!r.udp);
        let tcp_only = ForwardAcl::new(vec![r.clone()]);
        assert!(tcp_only.allows(&DialTarget::new("127.0.0.1", 5353), false));
        assert!(!tcp_only.allows(&DialTarget::new("127.0.0.1", 5353), true));
        r.udp = true;
        let udp_ok = ForwardAcl::new(vec![r]);
        assert!(udp_ok.allows(&DialTarget::new("127.0.0.1", 5353), true));
        assert!(udp_ok.allows(&DialTarget::new("127.0.0.1", 5353), false));
    }

    #[test]
    fn rule_parse_rejects_bad_hosts() {
        assert!(ForwardRule::parse("1.2.3.999:80").is_err()); // 纯数字串
        assert!(ForwardRule::parse("nas local:80").is_err()); // 空白
        assert!(ForwardRule::parse("127.0.0.1:9000-8000").is_err()); // 倒置
        assert!(ForwardRule::parse("127.0.0.1").is_err()); // 无端口
        assert!(ForwardRule::parse("nas.local:80").is_ok());
    }
}
