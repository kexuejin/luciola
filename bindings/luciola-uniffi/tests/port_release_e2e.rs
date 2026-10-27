//! 消费方仓库 `jvmAcceptanceTest` 端口释放断言在 Rust/uniffi 层的复现:
//! `SecureSession.listen(P)` → 连接 → 传数据 → `stop()` → 一个**不带
//! SO_REUSEADDR** 的裸 bind 必须能在 5 秒内重新占用 P。
//! (验收探针就是 Kotlin 的 `ServerSocket(port)`。)

use luciola_uniffi::{generate_device_identity, SecureSession, SecureSessionListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct NopListener;

impl SecureSessionListener for NopListener {
    fn on_state(&self, _state: String, _detail: Option<String>) {}
    fn on_message(
        &self,
        _message: Vec<u8>,
        _peer_fingerprint: String,
        _remote_addr: Option<String>,
    ) {
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_port_rebindable_after_stop() {
    // freePort() 等价:bind :0 拿到端口号后立即释放。
    let port = {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let server_id = generate_device_identity();
    let client_id = generate_device_identity();

    let server = Arc::new(SecureSession::new(server_id.seed.clone()));
    server.clone().listen(port, None, Box::new(NopListener));

    let client = Arc::new(SecureSession::new(client_id.seed.clone()));
    client.clone().connect(
        vec!["127.0.0.1".to_string()],
        port,
        server_id.public_key.clone(),
        false,
        Box::new(NopListener),
    );

    // 等握手 + 走一帧真实流量(建立连接的内核状态与验收一致)。
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client.is_connected() {
        assert!(Instant::now() < deadline, "handshake never completed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    while !server.send(vec![7u8; 4096]) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // stop():与验收里 transport.stop() 走的是同一条 FFI 路径 ——
    // **先关监听会话、再关外拨会话**(SecureChannelTransport.stop 的顺序)。
    server.clone().disconnect();
    client.clone().disconnect();

    // 探针:不带 SO_REUSEADDR 的裸 bind,5 秒窗口(与 Kotlin 测试同参数)。
    let started = Instant::now();
    loop {
        match std::net::TcpListener::bind(("0.0.0.0", port)) {
            Ok(l) => {
                drop(l);
                println!("rebind OK after {:?}", started.elapsed());
                return;
            }
            Err(e) if started.elapsed() < Duration::from_secs(5) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = e;
            }
            Err(e) => panic!("probe bind never succeeded: {e}"),
        }
    }
}
