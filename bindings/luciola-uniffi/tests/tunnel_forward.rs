//! T3 uniffi 控制面集成测试：两条 SecureSession（Dial + Listen）上的
//! 本地转发 / 端点 ACL / 同步失败契约 / stop 与 disconnect 语义。
//!
//! 事件断言同时钉住两条铁律：
//! - happy path 零 error（建立期失败只允许 retrying）；
//! - 隧道绝不上报 connected/closed —— Dial 监听器全程只见消息链路那一次。

use luciola_uniffi::{ForwardRuleDto, SecureSession, SecureSessionListener};
use std::io::{Read as _, Write as _};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- 基础设施

/// 一条 (state, detail) 事件记录。
type Events = Vec<(String, Option<String>)>;

/// 记录全部事件的测试监听器（Arc 共享存储）。
#[derive(Clone)]
struct TestListener(Arc<Mutex<Events>>);

impl TestListener {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(Mutex::new(Vec::new()))))
    }
    fn box_clone(&self) -> Box<TestListener> {
        Box::new(self.clone())
    }
    fn events(&self) -> Events {
        self.0.lock().unwrap().clone()
    }
    fn count(&self, state: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, _)| s == state)
            .count()
    }
    fn has_detail_prefix(&self, state: &str, prefix: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|(s, d)| s == state && d.as_deref().is_some_and(|d| d.starts_with(prefix)))
    }
}

impl SecureSessionListener for TestListener {
    fn on_state(&self, state: String, detail: Option<String>) {
        self.0.lock().unwrap().push((state, detail));
    }

    fn on_message(
        &self,
        _message: Vec<u8>,
        _peer_fingerprint: String,
        _remote_addr: Option<String>,
    ) {
    }
}

fn wait_until(pred: impl Fn() -> bool, ms: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
    loop {
        if pred() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 单个空闲端口。
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 连续空闲端口对 (p, p+1)：tunnel 默认端口 = secure + 1。
fn free_port_pair() -> (u16, u16) {
    loop {
        let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = a.local_addr().unwrap().port();
        if p == u16::MAX {
            continue;
        }
        let ok = std::net::TcpListener::bind(("127.0.0.1", p + 1)).is_ok()
            && std::net::TcpListener::bind(("::1", p + 1)).is_ok()
            && std::net::TcpListener::bind(("::1", p)).is_ok();
        drop(a);
        if ok {
            return (p, p + 1);
        }
    }
}

/// 本机回显服务：模拟「对端内网」的 TCP 目标。
fn spawn_echo() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// 经本地转发端口做一次回环；成功返回 true。
fn tcp_roundtrip(port: u16, payload: &[u8]) -> bool {
    let addr: std::net::SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2))
    else {
        return false;
    };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(5)));
    if s.write_all(payload).is_err() {
        return false;
    }
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).is_ok() && buf == payload
}

/// 一对就绪的消息链路：Listen(TOFU) + Dial(pin 对端公钥)。
struct Pair {
    dial: Arc<SecureSession>,
    listen: Arc<SecureSession>,
    dial_ev: Arc<TestListener>,
    listen_ev: Arc<TestListener>,
}

fn setup_pair() -> Pair {
    let (secure_port, _tunnel_port) = free_port_pair();
    let listen_identity = luciola::trust::identity_from_seed(&[2u8; 32]);

    let listen_session = Arc::new(SecureSession::new(vec![2u8; 32]));
    let listen_ev = TestListener::new();
    listen_session
        .clone()
        .listen(secure_port, None, listen_ev.box_clone());

    let dial_session = Arc::new(SecureSession::new(vec![1u8; 32]));
    let dial_ev = TestListener::new();
    dial_session.clone().connect(
        vec!["127.0.0.1".into()],
        secure_port,
        listen_identity.public_key,
        true,
        dial_ev.box_clone(),
    );

    let up = wait_until(|| dial_session.is_connected(), 20_000);
    assert!(up, "消息链路未建立: {:?}", dial_ev.events());
    Pair {
        dial: dial_session,
        listen: listen_session,
        dial_ev,
        listen_ev,
    }
}

// ---------------------------------------------------------------- 用例

/// e2e：本地转发经隧道回环 + 状态行 + 事件铁律。
#[test]
fn local_forward_e2e_roundtrip_and_stats() {
    let p = setup_pair();
    let upstream = spawn_echo();
    let l = free_port();

    // 懒建立契约（spec §T3 实现要点 3）：Responder 未注册端点时状态表为空、
    // 不绑定 tunnel_port —— 两端各自有工作才建链。
    assert!(p.listen.forward_stats().is_empty());

    // Responder 先启用端点（允许拨本机上游），其 tunnel_port 开始 accept。
    assert!(
        p.listen.enable_forward_endpoint(vec![ForwardRuleDto {
            host: "127.0.0.1".into(),
            port_from: 1,
            port_to: u16::MAX,
        }]),
        "启用转发端点应成功: {:?}",
        p.listen_ev.events(),
    );

    assert!(
        p.dial.start_local_forward(l, "127.0.0.1".into(), upstream),
        "注册本地转发应成功: {:?}",
        p.dial_ev.events(),
    );

    // 惰性建立（隧道 + Guard 绑定）→ 轮询到真正能通。
    let ok = wait_until(|| tcp_roundtrip(l, b"luciola-t3-e2e"), 30_000);
    assert!(
        ok,
        "经隧道的 TCP 回环应成功: stats={:?} ev={:?}",
        p.dial.forward_stats(),
        p.dial_ev.events(),
    );

    // 状态行：active + 实端口 + 累计。
    let stats = p.dial.forward_stats();
    let row = stats
        .iter()
        .find(|s| s.listen_port == l)
        .unwrap_or_else(|| panic!("stats 应含 listen_port={l} 行: {stats:?}"));
    assert!(row.active, "行应 active: {row:?}");
    assert!(row.channels_total >= 1, "channels_total≥1: {row:?}");
    assert_eq!(row.dial_denied, 0, "未配 ACL 不应有拒绝: {row:?}");

    // 铁律 1：happy path 零 error。
    assert_eq!(
        p.dial_ev.count("error"),
        0,
        "happy path 不该有 error: {:?}",
        p.dial_ev.events(),
    );
    // 铁律 2：隧道不上报 connected/closed（只有消息链路那一次 connected）。
    assert_eq!(
        p.dial_ev.count("connected"),
        1,
        "隧道不得上报 connected: {:?}",
        p.dial_ev.events(),
    );
    assert_eq!(
        p.dial_ev.count("closed"),
        0,
        "隧道不得上报 closed: {:?}",
        p.dial_ev.events(),
    );
    // Listen 侧端点行存在且真实计过通道。
    assert!(
        p.listen
            .forward_stats()
            .iter()
            .any(|s| s.channels_total >= 1),
        "Listen 端点行应计通道: {:?}",
        p.listen.forward_stats(),
    );
}

/// 端口冲突：同步 false + `forward_bind_failed: ` 事件，注册表不被污染。
#[test]
fn bind_conflict_reports_forward_bind_failed() {
    let p = setup_pair();
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied = holder.local_addr().unwrap().port();

    let r = p.dial.start_local_forward(occupied, "127.0.0.1".into(), 9);
    assert!(!r, "被占端口应同步失败");
    assert!(
        p.dial_ev
            .has_detail_prefix("error", "forward_bind_failed: "),
        "应上报 forward_bind_failed: {:?}",
        p.dial_ev.events(),
    );
    // 失败不入表。
    assert!(p
        .dial
        .forward_stats()
        .iter()
        .all(|s| s.listen_port != occupied));
}

/// 端点 ACL：空规则同步拒绝；拒绝规则只计数、不建通道。
#[test]
fn endpoint_acl_denies_counted_not_forwarded() {
    let p = setup_pair();
    let upstream = spawn_echo();

    // 空规则 → 同步拒绝 + 错误经 on_state 上报。
    let r = p.listen.enable_forward_endpoint(vec![]);
    assert!(!r, "空规则应被拒");
    assert!(
        p.listen_ev
            .has_detail_prefix("error", "invalid forward rule"),
        "空规则错误应上报: {:?}",
        p.listen_ev.events(),
    );

    // 永不匹配的规则（对端只会拨 127.0.0.1）→ 接受。
    let deny = ForwardRuleDto {
        host: "10.99.99.99".into(),
        port_from: 1,
        port_to: u16::MAX,
    };
    assert!(
        p.listen.enable_forward_endpoint(vec![deny]),
        "有效规则应被接受: {:?}",
        p.listen_ev.events(),
    );

    // Dial 侧注册本地转发；客户端连上即触发 T_OPEN → 被 ACL 拒绝。
    let l = free_port();
    assert!(p.dial.start_local_forward(l, "127.0.0.1".into(), upstream));
    let addr: std::net::SocketAddr = format!("127.0.0.1:{l}").parse().unwrap();
    let bound = wait_until(
        || std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_ok(),
        30_000,
    );
    assert!(bound, "本地监听未就绪");
    // 再来一次明确的尝试（被拒即断）。
    if let Ok(mut s) =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2))
    {
        let _ = s.write_all(b"x");
    }

    // Listen 端点行：dial_denied ≥ 1 且从未建立通道。
    let denied = wait_until(
        || {
            p.listen
                .forward_stats()
                .iter()
                .any(|r| r.dial_denied >= 1 && r.channels_total == 0)
        },
        30_000,
    );
    assert!(
        denied,
        "ACL 拒绝应计数且不建通道: {:?}",
        p.listen.forward_stats(),
    );
}

/// 角色错配 / 未配置 / 非法目标：同步 false + on_state，不产生注册。
#[test]
fn wrong_role_no_base_and_invalid_target_rejected_synchronously() {
    let p = setup_pair();

    // Dial 角色调端点 API → RoleMismatch。
    let before = p.dial_ev.count("error");
    let r = p.dial.enable_forward_endpoint(vec![ForwardRuleDto {
        host: "10.0.0.1".into(),
        port_from: 1,
        port_to: 2,
    }]);
    assert!(!r, "Dial 角色不该能启用端点");
    assert_eq!(
        p.dial_ev.count("error"),
        before + 1,
        "同步错误必须上报 on_state: {:?}",
        p.dial_ev.events(),
    );

    // Listen 角色调本地转发 → RoleMismatch。
    let before = p.listen_ev.count("error");
    let r = p
        .listen
        .start_local_forward(free_port(), "127.0.0.1".into(), 9);
    assert!(!r, "Listen 角色不该能注册本地转发");
    assert_eq!(p.listen_ev.count("error"), before + 1);

    // 未 connect/listen 的会话 → NotConfigured。
    let fresh = Arc::new(SecureSession::new(vec![3u8; 32]));
    assert!(
        !fresh.start_local_forward(free_port(), "127.0.0.1".into(), 1234),
        "未配置基址不该能注册",
    );

    // 非法目标 host → InvalidTarget。
    let before = p.dial_ev.count("error");
    let r = p
        .dial
        .start_local_forward(free_port(), "not-an-ip".into(), 9);
    assert!(!r);
    assert_eq!(p.dial_ev.count("error"), before + 1);
    assert!(p.dial_ev.has_detail_prefix("error", "invalid target"));

    // 端口区间倒置 → InvalidRule。
    let r = p.listen.enable_forward_endpoint(vec![ForwardRuleDto {
        host: "10.0.0.1".into(),
        port_from: 90,
        port_to: 80,
    }]);
    assert!(!r, "起止端口倒置应被拒");
}

/// stop 释放端口（幂等第二次失败）；disconnect → 暂停：active=false、
/// 注册表保留、本地端口拒绝连接。
#[test]
fn stop_releases_port_and_disconnect_pauses_tunnel() {
    let p = setup_pair();
    let upstream = spawn_echo();
    let l = free_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{l}").parse().unwrap();

    // Responder 先启用端点（懒建立：两端各自有工作才建链）。
    assert!(
        p.listen.enable_forward_endpoint(vec![ForwardRuleDto {
            host: "127.0.0.1".into(),
            port_from: 1,
            port_to: u16::MAX,
        }]),
        "启用转发端点应成功: {:?}",
        p.listen_ev.events(),
    );
    assert!(p.dial.start_local_forward(l, "127.0.0.1".into(), upstream));
    assert!(
        wait_until(|| tcp_roundtrip(l, b"before-stop"), 30_000),
        "转发应先可用: {:?}",
        p.dial.forward_stats(),
    );

    assert!(p.dial.stop_local_forward(l), "首次 stop 应成功");
    assert!(!p.dial.stop_local_forward(l), "重复 stop 应失败");
    let released = wait_until(
        || std::net::TcpListener::bind(("127.0.0.1", l)).is_ok(),
        15_000,
    );
    assert!(released, "stop 后端口应释放");

    // 重新注册，再断开消息链路 → 隧道暂停。
    assert!(p.dial.start_local_forward(l, "127.0.0.1".into(), upstream));
    assert!(
        wait_until(|| tcp_roundtrip(l, b"before-disconnect"), 30_000),
        "重注册后应恢复: {:?}",
        p.dial.forward_stats(),
    );

    p.dial.disconnect();
    let paused = wait_until(
        || {
            p.dial
                .forward_stats()
                .iter()
                .find(|s| s.listen_port == l)
                .is_some_and(|s| !s.active)
        },
        15_000,
    );
    assert!(
        paused,
        "disconnect 后行应保留且 inactive: {:?}",
        p.dial.forward_stats(),
    );
    let refused = wait_until(
        || std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_err(),
        15_000,
    );
    assert!(refused, "暂停后本地端口应拒绝连接");
}
