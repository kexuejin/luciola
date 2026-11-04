use std::sync::atomic::AtomicU16;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;

use tokio::sync::mpsc as tokio_mpsc;
use tokio::sync::Notify;

use crate::forward::ForwardRule;
use crate::TunnelError;

use super::*;

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
