//! the tunnel plan §3 T2 验收：forward 层端到端（真实 SecureStream + 本地 TCP 回环）。
//!
//! 场景对应 spec 验收清单：
//! 1. 8 并发连接大流量交错传输；
//! 2. 一个通道处于停顿（未打满自身队列）期间，不阻塞其他通道的 OPEN 与数据；
//! 3. ACL 拒绝 → dial_denied+1 且**不发生拨号**，initiator 收 OPEN_ACK(1)；
//! 4. 上游拨号失败 → dial_failed+1 且 initiator 收 OPEN_ACK(2)；
//! 5. 会话断开 → 本地连接 fail-fast 关闭、双端 wait_closed、端点自然退出。
//!
//! 全部监听临时端口；同机自检时"转发监听端口 ≠ 上游目标端口"。

mod common;
use common::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use luciola_tunnel::{
    CloseReason, DialTarget, ForwardAcl, ForwardRule, LocalForwardConfig, MuxError,
    start_forward_endpoint, start_local_forward,
};

// ---------------------------------------------------------------- 本机上游

/// 本机 echo 上游：读到什么写回什么。返回 (地址, 任务句柄)。
async fn spawn_echo_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let h = tokio::spawn(async move {
        loop {
            let (mut conn, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, h)
}

/// 计数上游：接受即计数，连接保持打开但不服务。用于断言"从未被拨号"。
async fn spawn_counting_upstream() -> (SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind counting");
    let addr = listener.local_addr().expect("counting addr");
    let accepts = Arc::new(AtomicU64::new(0));
    let c = accepts.clone();
    tokio::spawn(async move {
        let mut held: Vec<TcpStream> = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            c.fetch_add(1, Ordering::SeqCst);
            held.push(conn); // 持有句柄：连接保持打开
        }
    });
    (addr, accepts)
}

/// 黑洞上游：接受但永不读写（上游应用停顿）。
async fn spawn_blackhole_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind blackhole");
    let addr = listener.local_addr().expect("blackhole addr");
    tokio::spawn(async move {
        let mut held: Vec<TcpStream> = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            held.push(conn);
        }
    });
    addr
}

/// 取一个"必然没人监听"的地址：先绑定取端口再立即释放（放最后创建，最小化重用竞态）。
fn dead_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind for dead port");
    let addr = l.local_addr().expect("dead addr");
    drop(l);
    addr
}

// ---------------------------------------------------------------- 断言工具

/// 经本地转发做一次完整回环：写 chunks×chunk 并读回逐字节比对。
async fn roundtrip(local: SocketAddr, chunks: usize, chunk: Vec<u8>) {
    let (mut rd, mut wr) = TcpStream::connect(local)
        .await
        .expect("connect local forward")
        .into_split();
    let expect = chunk.clone();
    let writer = tokio::spawn(async move {
        for _ in 0..chunks {
            wr.write_all(&chunk).await.expect("local write");
        }
        let _ = wr.shutdown().await;
    });
    let mut buf = vec![0u8; expect.len()];
    for _ in 0..chunks {
        rd.read_exact(&mut buf).await.expect("read back");
        assert_eq!(buf, expect, "echoed bytes differ");
    }
    writer.await.expect("writer task");
}

/// 轮询等待条件成立（计数收敛用）。
async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..300 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met within 6s");
}

fn rule_for(addr: SocketAddr) -> ForwardRule {
    ForwardRule { host: addr.ip(), port_from: addr.port(), port_to: addr.port() }
}

// ---------------------------------------------------------------- 验收用例

/// 8 并发连接、60KB 非对齐块 ×8/连接（≈480KB/连接）交错传输，字节级比对。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_concurrent_connections_large_interleaved_transfer() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (up_addr, up) = spawn_echo_upstream().await;
        let (i, r) = mux_pair().await;
        let (i, r) = (Arc::new(i), Arc::new(r));

        let endpoint = start_forward_endpoint(r, ForwardAcl::new(vec![rule_for(up_addr)]))
            .expect("endpoint");
        let fwd = start_local_forward(
            i,
            LocalForwardConfig { listen_port: 0, target: DialTarget::new(up_addr.ip(), up_addr.port()) },
        )
        .expect("local forward");
        let local = fwd.local_addr();

        let chunk: Vec<u8> = (0..60_000).map(|k| (k % 251) as u8).collect(); // 60KB，非对齐触发部分写
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let chunk = chunk.clone();
            tasks.push(tokio::spawn(async move {
                roundtrip(local, 8, chunk).await;
            }));
        }
        for t in tasks {
            t.await.expect("conn task");
        }

        let st = endpoint.status();
        assert_eq!(st.channels_total, 8, "8 条通道各开一次");
        assert_eq!(st.dial_denied, 0);
        assert_eq!(st.dial_failed, 0);
        wait_until(|| fwd.status().channels_open == 0).await;
        assert_eq!(fwd.status().channels_total, 8);

        fwd.stop().await;
        endpoint.stop().await;
        up.abort();
    })
    .await
    .expect("test timed out");
}

/// A 通道上游黑洞（自身队列未打满、处于停顿）期间：B 通道 OPEN 与数据完全不受影响，
/// A 不被误切断（stall 只在自身队列打满时触发）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_channel_does_not_block_others() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let bh_addr = spawn_blackhole_upstream().await;
        let (echo_addr, echo) = spawn_echo_upstream().await;

        let (i, r) = mux_pair().await;
        let (i, r) = (Arc::new(i), Arc::new(r));
        let acl = ForwardAcl::new(vec![rule_for(bh_addr), rule_for(echo_addr)]);
        let endpoint = start_forward_endpoint(r, acl).expect("endpoint");

        let fwd_bh = start_local_forward(
            i.clone(),
            LocalForwardConfig { listen_port: 0, target: DialTarget::new(bh_addr.ip(), bh_addr.port()) },
        )
        .expect("fwd blackhole");
        let fwd_echo = start_local_forward(
            i.clone(),
            LocalForwardConfig { listen_port: 0, target: DialTarget::new(echo_addr.ip(), echo_addr.port()) },
        )
        .expect("fwd echo");

        // A：连黑洞并写入 200KB（远低于队列上限 256×64KiB），上游永不读 → 通道停顿但不打满队列。
        let mut a = TcpStream::connect(fwd_bh.local_addr()).await.expect("connect A");
        let a_task = tokio::spawn(async move {
            let buf = vec![0xA5u8; 50_000];
            for _ in 0..4 {
                if a.write_all(&buf).await.is_err() {
                    break;
                }
            }
            a // 写完保留句柄：A 连接保持打开
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // B：A 停顿期间做两轮完整回环（OPEN + 数据）。
        let chunk: Vec<u8> = (0..40_000).map(|k| (k % 199) as u8).collect();
        roundtrip(fwd_echo.local_addr(), 4, chunk.clone()).await;
        roundtrip(fwd_echo.local_addr(), 4, chunk).await;

        // A 未被切断（自身队列未打满 → stall 计时器不启动），通道仍打开。
        let st = endpoint.status();
        assert_eq!(st.dial_denied, 0, "两目标都在白名单内");
        assert_eq!(st.dial_failed, 0);
        assert_eq!(fwd_bh.status().channels_open, 1, "A 通道仍在");
        assert_eq!(fwd_echo.status().channels_total, 2, "B 两条通道");
        let mut peek = [0u8; 4];
        match a_task.await.expect("A task").try_read(&mut peek) {
            Ok(0) => panic!("A 被误切断（stall cut 不应在队列未打满时触发）"),
            Ok(n) => panic!("A 意外读到 {n} 字节"),
            Err(_) => {} // WouldBlock = 存活
        }

        fwd_bh.stop().await;
        fwd_echo.stop().await;
        endpoint.stop().await;
        echo.abort();
    })
    .await
    .expect("test timed out");
}

/// ACL 拒绝（默认拒绝空表 / 白名单不含目标）：OPEN_ACK(1)、dial_denied+1、
/// 上游 accept 计数为 0（从未拨号）、会话与本地转发 fail-fast 语义均成立。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_deny_counts_and_never_dials() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (forbidden_addr, forbidden_accepts) = spawn_counting_upstream().await;
        let (echo_addr, echo) = spawn_echo_upstream().await;

        let (i, r) = mux_pair().await;
        let (i, r) = (Arc::new(i), Arc::new(r));
        // 白名单只放行 echo；forbidden 不在表内。
        let endpoint = start_forward_endpoint(r, ForwardAcl::new(vec![rule_for(echo_addr)]))
            .expect("endpoint");

        // ① 直接 OPEN forbidden：initiator 收到明确的 OPEN_ACK(1)。
        let err = match i.open(DialTarget::new(forbidden_addr.ip(), forbidden_addr.port())).await {
            Err(e) => e,
            Ok(_) => panic!("open forbidden must be rejected"),
        };
        match &err {
            MuxError::Rejected { status, .. } => assert_eq!(*status, 1, "ACL_DENIED status"),
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(endpoint.status().dial_denied, 1);
        assert_eq!(endpoint.status().dial_failed, 0);
        assert_eq!(
            forbidden_accepts.load(Ordering::SeqCst),
            0,
            "ACL 拒绝时绝不拨号"
        );

        // ② 经本地转发 fail-fast：本地连接立即关闭（不挂死、不透传数据）。
        let fwd = start_local_forward(
            i.clone(),
            LocalForwardConfig {
                listen_port: 0,
                target: DialTarget::new(forbidden_addr.ip(), forbidden_addr.port()),
            },
        )
        .expect("fwd forbidden");
        let mut c = TcpStream::connect(fwd.local_addr()).await.expect("connect");
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("fail-fast close timed out")
            .expect("read after fail-fast");
        assert_eq!(n, 0, "open 被拒 → 本地连接立即关闭");
        assert_eq!(endpoint.status().dial_denied, 2, "第二条同样计入拒绝");

        // ③ 会话仍健康：允许目标照常工作。
        let fwd_echo = start_local_forward(
            i.clone(),
            LocalForwardConfig { listen_port: 0, target: DialTarget::new(echo_addr.ip(), echo_addr.port()) },
        )
        .expect("fwd echo");
        roundtrip(fwd_echo.local_addr(), 2, vec![7u8; 30_000]).await;
        assert!(i.is_alive() && endpoint.status().dial_failed == 0);

        fwd.stop().await;
        fwd_echo.stop().await;
        endpoint.stop().await;
        echo.abort();
    })
    .await
    .expect("test timed out");
}

/// 上游拨号失败（端口无人监听）：dial_failed+1、initiator 收 OPEN_ACK(2) 且带 detail。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dial_failure_counts_and_acks_2() {
    tokio::time::timeout(Duration::from_secs(30), async {
        // 先建会话/上游，再取死端口，最小化端口重用竞态。
        let (i, r) = mux_pair().await;
        let (echo_addr, echo) = spawn_echo_upstream().await;
        let dead = dead_addr();

        let (i, r) = (Arc::new(i), Arc::new(r));
        let endpoint = start_forward_endpoint(
            r.clone(),
            ForwardAcl::new(vec![rule_for(dead), rule_for(echo_addr)]),
        )
        .expect("endpoint");

        let err = match i.open(DialTarget::new(dead.ip(), dead.port())).await {
            Err(e) => e,
            Ok(_) => panic!("open dead port must fail"),
        };
        match &err {
            MuxError::Rejected { status, detail } => {
                assert_eq!(*status, 2, "DIAL_FAILED status");
                let detail = detail.as_deref().expect("dial failed detail");
                assert!(detail.contains("dial failed"), "detail 应说明拨号失败: {detail}");
            }
            other => panic!("expected Rejected(2), got {other:?}"),
        }

        let st = endpoint.status();
        assert_eq!(st.dial_failed, 1);
        assert_eq!(st.dial_denied, 0, "目标在白名单内 → 不是拒绝");
        assert!(i.is_alive() && r.is_alive(), "拨号失败不杀会话");

        endpoint.stop().await;
        echo.abort();
    })
    .await
    .expect("test timed out");
}

/// 会话断开：本地新连接 fail-fast 关闭；双端 wait_closed 返回 SESSION_SHUTDOWN；
/// responder 标记 peer_closed（对端线帧 CLOSE(3)）；端点 accept 循环自然退出。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_disconnect_fails_fast_and_stops_forward() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (echo_addr, echo) = spawn_echo_upstream().await;
        let (i, r) = mux_pair().await;
        let (i, r) = (Arc::new(i), Arc::new(r));

        let endpoint = start_forward_endpoint(r.clone(), ForwardAcl::new(vec![rule_for(echo_addr)]))
            .expect("endpoint");
        let fwd = start_local_forward(
            i.clone(),
            LocalForwardConfig { listen_port: 0, target: DialTarget::new(echo_addr.ip(), echo_addr.port()) },
        )
        .expect("fwd");

        // 先证明链路可用。
        roundtrip(fwd.local_addr(), 2, vec![3u8; 20_000]).await;

        // initiator 主动 shutdown → 线上 CLOSE(SESSION_SHUTDOWN) 到 responder。
        i.shutdown();

        // 本地 fail-fast：新连接立刻被关闭（会话未建立路径）。
        let mut c = TcpStream::connect(fwd.local_addr()).await.expect("connect after shutdown");
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("fail-fast close timed out")
            .expect("read after shutdown");
        assert_eq!(n, 0, "会话断开 → 本地连接立即关闭");

        // 双端 wait_closed；responder 经对端线帧标记。
        let reason_i = tokio::time::timeout(Duration::from_secs(3), i.wait_closed())
            .await
            .expect("initiator wait_closed");
        assert_eq!(reason_i, CloseReason::SESSION_SHUTDOWN);
        let reason_r = tokio::time::timeout(Duration::from_secs(3), r.wait_closed())
            .await
            .expect("responder wait_closed");
        assert_eq!(reason_r, CloseReason::SESSION_SHUTDOWN);
        assert!(r.peer_closed(), "responder 应标记对端线帧关闭");

        fwd.stop().await;
        endpoint.stop().await;
        echo.abort();
    })
    .await
    .expect("test timed out");
}
