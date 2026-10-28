//! Consumer-side acceptance assertion, reproduced at the Rust layer: after
//! `stop()`, the listening port must be reclaimable by a plain bind **without
//! SO_REUSEADDR** (the consumer probe is a JVM `ServerSocket(port)`).
//!
//! 对照组:旧实现(裸 `TcpListener::bind(("0.0.0.0", p))`)与新实现
//! ([`bind_dual_stack_listener`],带 SO_REUSEADDR 的双栈)各跑一遍。

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn transfer_then_probe<F, Fut>(make_listener: F)
where
    F: Fn(u16) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<tokio::net::TcpListener>>,
{
    // 1) 监听(端口 0 → 内核分配,与 freePort() 语义一致)
    let listener = make_listener(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // 2) 一条真实连接 + 一帧数据(让内核留一条已建立连接)
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(&buf[..n]).await.unwrap();
        // 主动方先落盘回显,再由调用方 drop —— 模拟 stop() 时引擎侧持有 socket
        tokio::time::sleep(Duration::from_millis(50)).await;
        sock
    });
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    client.read_exact(&mut echo).await.unwrap();

    // 3) 服务端先关(引擎 stop() 的方向),客户端随后关 —— 与验收里的关闭次序一致
    let server_sock = server.await.unwrap();
    drop(server_sock);
    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4) 探针:不带 SO_REUSEADDR 的裸 bind,5 秒窗口(与 Kotlin 测试同参数)
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

#[tokio::test]
async fn plain_v4_listener_port_rebindable() {
    transfer_then_probe(|p| tokio::net::TcpListener::bind(("0.0.0.0", p))).await;
}

#[tokio::test]
async fn dual_stack_listener_port_rebindable() {
    transfer_then_probe(luciola::link::bind_dual_stack_listener).await;
}
