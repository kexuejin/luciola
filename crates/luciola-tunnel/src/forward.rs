//! T2 forward —— 本地端口转发与服务端 ACL 白名单（the tunnel plan §2.3）。
//!
//! 两端分工：
//!
//! - **LocalForward**（initiator 侧）：监听 `127.0.0.1:<listen_port>`（D6：只绑环回，
//!   不对外暴露），每个入站 TCP 连接经 `MuxSession::open()` 建一条 mux 通道，
//!   与对端 `target` 双向拷贝。会话未建立/被拒时立即关闭本地连接（fail-fast，
//!   浏览器自行重试）。
//! - **ForwardEndpoint**（responder 侧）：`accept_open()` 循环，把每个 OPEN 请求
//!   派发到独立并发任务执行 ACL 检查（默认拒绝）与 `link::dial`（受
//!   `MuxConfig::dial_timeout` 限制），然后 `grant()` + 双向拷贝。
//!
//! # 调度契约
//!
//! 两个 `start_*` 都在调用处捕获显式 `tokio::runtime::Handle`，Guard 内部
//! 所有任务（accept 循环与每连接子任务）一律经该 Handle 派发，不依赖任何
//! 隐式的调用方线程上下文（spec §2.3）。

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::mux::{AckStatus, DialTarget, MuxSession, OpenRequest};
use crate::TunnelError;

// ---------------------------------------------------------------- 计数器

/// forward 层原子计数器（Guard 持有；T3 FFI status 直接读快照）。
///
/// - `channels_open`：当前正在进行双向拷贝的通道数（派生量）。
/// - `channels_total`：生命周期内 grant 成功的通道累计数。
/// - `dial_denied`：被 ACL 白名单拒绝的 OPEN（从未发起拨号）。
/// - `dial_failed`：放行后拨号失败/超时的 OPEN。
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

/// 一条白名单规则：精确主机 + 端口区间（含端点，`port_from <= port_to`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardRule {
    pub host: IpAddr,
    pub port_from: u16,
    pub port_to: u16,
}

impl ForwardRule {
    /// 解析 CLI/FFI 规则文本：
    ///
    /// - `127.0.0.1:8080` —— 单端口
    /// - `127.0.0.1:8000-8100` —— 端口区间
    /// - `[::1]:8080` / `[::1]:8000-8100` —— IPv6 必须带方括号
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
        let host: IpAddr = host_str.parse().map_err(|_| bad())?;
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
            return Err(TunnelError::InvalidRule(format!("{spec} (port_from > port_to)")));
        }
        Ok(Self { host, port_from: from, port_to: to })
    }
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

    /// 是否放行。IP 经 `::ffff:v4` 映射标准化后按精确值比较（spec §2.3）。
    pub fn allows(&self, target: &DialTarget) -> bool {
        let host = normalize_ip(target.host);
        self.rules
            .iter()
            .any(|r| normalize_ip(r.host) == host && (r.port_from..=r.port_to).contains(&target.port))
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

// ---------------------------------------------------------------- LocalForward

/// 本地端口转发配置。监听失败/目标不合法由 `start_local_forward` 校验。
#[derive(Debug, Clone)]
pub struct LocalForwardConfig {
    /// 本地监听端口；0 = 系统分配，实际端口从 Guard 取（`local_addr()`）。
    pub listen_port: u16,
    /// 对端（responder 机上）的目标地址。
    pub target: DialTarget,
}

/// 本地转发 Guard：持有监听端口与全部任务句柄。
///
/// `stop().await` 或 Drop 即终止 accept 循环（释放监听端口）与全部转发子任务。
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

/// 启动本地端口转发（initiator 侧；spec §2.3）。
///
/// 必须在 tokio runtime 上下文中调用（与 `MuxSession::start` 同一前提）：
/// 本函数在调用处捕获显式 `Handle`，此后所有任务经该 Handle 派发。
pub fn start_local_forward(
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
                        let target = cfg.target;
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

/// 启动服务端转发端点（responder 侧；spec §2.3）。必须在 tokio runtime 上下文中调用。
///
/// 每个 OPEN 请求都在**独立并发任务**里处理（严禁在主循环串行 await ACL/拨号）。
pub fn start_forward_endpoint(
    session: Arc<MuxSession>,
    acl: ForwardAcl,
) -> Result<ForwardEndpointGuard, TunnelError> {
    let handle = Handle::current();
    let counters = Arc::new(ForwardCounters::default());
    let children: Arc<StdMutex<Vec<JoinHandle<()>>>> = Arc::new(StdMutex::new(Vec::new()));

    let accept_task = handle.spawn({
        let counters = counters.clone();
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
                let acl = acl.clone();
                let counters = counters.clone();
                let children = children.clone();
                let dial_timeout = session.config().dial_timeout;
                let task = handle.spawn(async move {
                    serve_one(req, acl, counters, dial_timeout).await;
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

/// 处理一个 OPEN 请求：ACL（默认拒绝）→ 拨号（dial_timeout 上限）→ grant → 双向拷贝。
async fn serve_one(req: OpenRequest, acl: ForwardAcl, counters: Arc<ForwardCounters>, dial_timeout: Duration) {
    let target = req.target;

    // ① 目标合法性（防御纵深；mux 解析阶段已挡大部分非法目标）。
    if !target.validate() {
        let _ = req.deny(AckStatus::BAD_TARGET, None).await;
        return;
    }

    // ② ACL：默认拒绝。拒绝时**永不拨号**，也不向 initiator 附带策略细节。
    if !acl.allows(&target) {
        counters.dial_denied.fetch_add(1, Ordering::SeqCst);
        let _ = req.deny(AckStatus::ACL_DENIED, None).await;
        return;
    }

    // ③ 并发拨号（link::dial 内含 IPv4/IPv6/host 统一路径与链路本地 scope 处理；
    //    受 dial_timeout 上限，与 initiator 的 open_timeout 对齐）。
    let dial_host = target.host.to_string();
    let dial = luciola::link::dial(&dial_host, target.port);
    let mut upstream: TcpStream = match tokio::time::timeout(dial_timeout, dial).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            counters.dial_failed.fetch_add(1, Ordering::SeqCst);
            let _ = req.deny(AckStatus::DIAL_FAILED, Some(format!("dial failed: {e}"))).await;
            return;
        }
        Err(_) => {
            counters.dial_failed.fetch_add(1, Ordering::SeqCst);
            let _ = req
                .deny(AckStatus::DIAL_FAILED, Some(format!("dial timeout after {dial_timeout:?}")))
                .await;
            return;
        }
    };

    // ④ grant → 双向拷贝。grant 失败（会话已死）→ 丢弃 upstream（fd 随之关闭，无泄漏）。
    match req.grant().await {
        Ok(mut stream) => {
            counters.channels_total.fetch_add(1, Ordering::SeqCst);
            counters.channels_open.fetch_add(1, Ordering::SeqCst);
            if let Err(e) = copy_bidirectional(&mut stream, &mut upstream).await {
                debug!("endpoint copy ended: {e}");
            }
            counters.channels_open.fetch_sub(1, Ordering::SeqCst);
        }
        Err(e) => {
            debug!("grant after dial failed: {e}");
        }
    }
}
