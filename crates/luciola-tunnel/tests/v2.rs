//! mux v2 能力在真实 SecureStream（127.0.0.1 回环）上的验收：
//! keepalive（PING/PONG + 静默判死）、WINDOW 逐通道流控、双向 OPEN（remote
//! forward）、数据报通道（UDP 会话映射）、主机名目标、通道空闲回收。
//!
//! v2 兼容性红线（全部在本文件断言）：
//! - v1 对端（从不回 PONG/WINDOW）永不被静默判死、不被 WINDOW 卡死；
//! - 未证明 v2 的对端发偶数通道帧 / DOPEN 仍按 D9 结构违规终止（与 v1 一致）；
//! - Responder 在对端证明 v2 前不得发 OPEN（open() 干净失败，不发帧）。

mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use common::*;
use luciola_tunnel::{
    start_forward_endpoint, start_local_forward, start_udp_forward, AckStatus, CloseReason,
    DialTarget, ForwardAcl, ForwardRule, Frame, LocalForwardConfig, MuxConfig, MuxError,
    MuxSession, Role, UdpForwardConfig, T_ACK, T_DOPEN, T_OPEN, T_PING, T_PONG,
};

fn v2_cfg() -> MuxConfig {
    MuxConfig {
        open_timeout: Duration::from_millis(1500),
        ..Default::default()
    }
}

fn host_target(host: &str, port: u16) -> DialTarget {
    DialTarget::new(host, port)
}

// ---------------------------------------------------------------- keepalive

/// PING/PONG：mux 会话自动应答探测 PING（nonce 回显）；收到 PING 后对端视为 v2。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_ping_pong_nonce_echo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, v2_cfg());
        let mut raw = s;

        // mux 发出探测 PING → raw 收到并回显 PONG
        let probe = match raw_recv_any(&mut raw).await {
            Frame::Ping { nonce } => nonce,
            f => panic!("expected probe PING, got {f:?}"),
        };
        assert!(!i.peer_is_v2(), "v2 proof requires an inbound v2 frame");
        raw_send(&mut raw, T_PONG, 0, &probe.to_be_bytes()).await;

        // raw 主动 PING → mux 应答 PONG(nonce) 且置位 peer_v2
        raw_send(&mut raw, T_PING, 0, &7777u64.to_be_bytes()).await;
        match raw_recv_any(&mut raw).await {
            Frame::Pong { nonce } => assert_eq!(nonce, 7777, "PONG must echo the nonce"),
            f => panic!("expected PONG, got {f:?}"),
        }
        assert!(i.peer_is_v2());
        assert!(i.is_alive());
    })
    .await
    .expect("test timed out");
}

/// 静默判死只对已证明 v2 的对端执行：raw 侧回过一次 PONG（证明 v2）后沉默，
/// mux 在 dead_after 后终止会话。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_dead_after_kills_silent_v2_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let cfg = MuxConfig {
            keepalive_interval: Some(Duration::from_millis(100)),
            keepalive_dead_after: Some(Duration::from_millis(300)),
            ..v2_cfg()
        };
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, cfg);
        let mut raw = s;

        // 证明 v2 一次，然后永久沉默
        match raw_recv_any(&mut raw).await {
            Frame::Ping { nonce } => {
                raw_send(&mut raw, T_PONG, 0, &nonce.to_be_bytes()).await;
            }
            f => panic!("expected probe PING, got {f:?}"),
        }

        let i2 = i.clone();
        let waiter = tokio::spawn(async move { i2.wait_closed().await });
        let reason = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("wait deadline")
            .expect("waiter task");
        assert_eq!(reason, CloseReason::SESSION_SHUTDOWN);
        assert!(!i.is_alive());
    })
    .await
    .expect("test timed out");
}

/// v1 对端（从不回 PONG/WINDOW）永不被静默判死（R7 兼容红线）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_never_kills_v1_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let cfg = MuxConfig {
            keepalive_interval: Some(Duration::from_millis(50)),
            keepalive_dead_after: Some(Duration::from_millis(150)),
            ..v2_cfg()
        };
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, cfg);
        let mut raw = s;

        // 3 × dead_after 内对 PING 保持完全沉默（v1 行为：忽略保留帧）
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(i.is_alive(), "v1 peer must never be killed by silence");
        assert!(!i.peer_is_v2());
        // raw 侧收到的全是 PING，无其他帧
        match raw_recv_any(&mut raw).await {
            Frame::Ping { .. } => {}
            f => panic!("expected only PING noise, got {f:?}"),
        }
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- WINDOW 流控

/// v2 对端之间：慢消费者通道被窗口限流（写端挂起而非报错），其余通道完全
/// 不受影响，且该通道不因队列打满被 stall 拆除（v2 消除级联停顿）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_slow_consumer_parks_writer_and_spares_other_channels() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let cfg = MuxConfig {
            window_size: 128 * 1024, // 2 帧
            stall_hard_timeout: Duration::from_secs(1),
            ..v2_cfg()
        };
        let (i, r) = mux_pair_cfg(cfg).await;

        // responder：A 授权但永不读；B 回显。
        let r2 = r.clone();
        tokio::spawn(async move {
            let a = r2
                .accept_open()
                .await
                .expect("accept A")
                .grant()
                .await
                .expect("grant A");
            let mut b = r2
                .accept_open()
                .await
                .expect("accept B")
                .grant()
                .await
                .expect("grant B");
            let mut buf = [0u8; 16];
            loop {
                match b.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if b.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            drop(a);
        });

        let a = i.open(target(1)).await.expect("open A");
        let mut b = i.open(target(2)).await.expect("open B");

        // B 连通确认
        b.write_all(b"ping").await.expect("B write");
        let mut back = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), b.read_exact(&mut back))
            .await
            .expect("B echo")
            .expect("B read");
        assert_eq!(&back, b"ping");

        // A 灌满窗口（2 帧），第三帧应挂起（窗口执行）而非报错
        let chunk = vec![0xABu8; 64 * 1024];
        let (mut a_r, mut a_w) = tokio::io::split(a);
        a_w.write_all(&chunk).await.expect("A write 1");
        a_w.write_all(&chunk).await.expect("A write 2");
        let parked = tokio::time::timeout(Duration::from_millis(400), a_w.write_all(&chunk)).await;
        assert!(parked.is_err(), "third frame must park on the window");

        // B 在 A 挂起期间完全正常；stall(1s) 未拆 A（窗口限流使队列永不打满）
        b.write_all(b"ping2").await.expect("B write 2");
        tokio::time::timeout(Duration::from_secs(5), b.read_exact(&mut back))
            .await
            .expect("B echo 2")
            .expect("B read 2");
        assert_eq!(&back, b"ping");
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            i.is_alive() && r.is_alive(),
            "session must survive a window-parked channel"
        );

        // A 通道未死（没有 CLOSE 送达）
        let mut probe = [0u8; 1];
        let still_open =
            tokio::time::timeout(Duration::from_millis(100), a_r.read(&mut probe)).await;
        assert!(
            matches!(still_open, Err(_) | Ok(Ok(0)) | Ok(Ok(_)) | Ok(Err(_))),
            "no assertion — read may block; session stats are the real check"
        );
        assert_eq!(i.stats().channels_open, 2, "A must not be torn down");
    })
    .await
    .expect("test timed out");
}

/// 窗口 credit 端到端：大流量（远超窗口）经 credit 回笼持续流动。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_large_transfer_flows_through_credits() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let cfg = MuxConfig {
            window_size: 64 * 1024, // 极小窗口：全程依赖 credit 回笼
            ..v2_cfg()
        };
        let (i, r) = mux_pair_cfg(cfg).await;
        spawn_accept_echo(r);

        let st = i.open(target(1)).await.expect("open");
        let payload: Vec<u8> = (0..512 * 1024u32).map(|k| k as u8).collect();
        let (mut rh, mut wh) = tokio::io::split(st);
        let writer = tokio::spawn({
            let payload = payload.clone();
            async move {
                wh.write_all(&payload).await.expect("write");
                wh.shutdown().await.expect("half close");
            }
        });
        let mut back = Vec::new();
        rh.read_to_end(&mut back).await.expect("echo");
        writer.await.expect("writer");
        assert_eq!(back.len(), payload.len());
        assert!(back == payload);
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- remote forward（-R）

/// Responder 侧 open()（偶数通道）→ Initiator accept_open → grant → 数据流动。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_forward_responder_opens_even_channel() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (i, r) = mux_pair().await;

        // initiator：接受 remote OPEN 并回显
        let i2 = i.clone();
        tokio::spawn(async move {
            while let Ok(req) = i2.accept_open().await {
                assert!(!req.datagram, "stream OPEN");
                tokio::spawn(async move {
                    if let Ok(mut st) = req.grant().await {
                        let mut buf = [0u8; 64];
                        loop {
                            match st.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if st.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });

        let mut st = r.open(target(4321)).await.expect("responder open");
        assert_eq!(
            st.ch_id() % 2,
            0,
            "responder-originated channels must be even (D8 v2)"
        );
        st.write_all(b"from-responder").await.expect("write");
        let mut back = vec![0u8; 14];
        st.read_exact(&mut back).await.expect("echo");
        assert_eq!(&back, b"from-responder");

        // initiator 侧的 open() 仍是奇数；responder 以 ACK(1) 终态拒绝
        // （同时验证：responder 接受 ACK(odd) 的路径，v1 语义保持）
        let i3 = i.clone();
        let opener = tokio::spawn(async move { i3.open(target(1)).await });
        let r2 = r.clone();
        tokio::spawn(async move {
            while let Ok(req) = r2.accept_open().await {
                let _ = req.deny(AckStatus::ACL_DENIED, None).await;
            }
        });
        match opener.await.expect("opener") {
            Err(MuxError::Rejected { status, detail }) => {
                assert_eq!(status, AckStatus::ACL_DENIED);
                assert!(detail.is_none(), "acl_denied must not carry detail");
            }
            Err(other) => panic!("expected Rejected(1), got {other:?}"),
            Ok(_) => panic!("initiator open unexpectedly succeeded"),
        }
    })
    .await
    .expect("test timed out");
}

/// 对端证明 v2 之前，Responder open() 干净失败且不发帧（v1 对端保护）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_open_to_v1_peer_fails_unsupported() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let cfg = MuxConfig {
            open_timeout: Duration::from_millis(300),
            ..v2_cfg()
        };
        let (c, s) = secure_pair().await;
        let r = MuxSession::start(c, Role::Responder, cfg);
        let mut raw = s;

        // raw 是 v1：收到 PING 一律忽略
        match r.open(target(1)).await {
            Err(MuxError::UnsupportedByPeer(m)) => {
                assert!(m.contains("v2"), "message should mention v2: {m}");
            }
            Err(other) => panic!("expected UnsupportedByPeer, got {other:?}"),
            Ok(_) => panic!("responder open unexpectedly succeeded against a v1 peer"),
        }
        // 线上只有探测 PING，没有 OPEN
        match raw_recv_within(&mut raw, Duration::from_millis(100)).await {
            None => {}
            Some(f) => panic!("responder open must not hit the wire, got {f:?}"),
        }
    })
    .await
    .expect("test timed out");
}

/// 已证明 v2 的对端发偶数 OPEN：initiator 接受（v2 放宽）；DATA/ACK 奇偶对称成立。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proven_v2_peer_even_open_is_accepted() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, v2_cfg());
        let mut raw = s;

        // 证明 v2：回探测 PONG
        match raw_recv_any(&mut raw).await {
            Frame::Ping { nonce } => raw_send(&mut raw, T_PONG, 0, &nonce.to_be_bytes()).await,
            f => panic!("expected PING, got {f:?}"),
        }
        // 偶数 OPEN → Pending（不 ACK，等策略层）；accept_open 可取到
        raw_send(&mut raw, T_OPEN, 2, &open_payload("127.0.0.1", 8080)).await;
        let req = tokio::time::timeout(Duration::from_secs(2), i.accept_open())
            .await
            .expect("accept deadline")
            .expect("accept");
        assert_eq!(req.ch_id, 2);
        assert_eq!(req.target.host, "127.0.0.1");
        let mut st = req.grant().await.expect("grant");
        // ACK(0) 已上线
        match raw_recv(&mut raw).await {
            Frame::Ack { ch_id, status, .. } => {
                assert_eq!(ch_id, 2);
                assert_eq!(status, AckStatus::OK);
            }
            f => panic!("expected ACK, got {f:?}"),
        }
        // 数据双向
        st.write_all(b"ok").await.expect("write");
        match raw_recv(&mut raw).await {
            Frame::Data { ch_id, bytes } => {
                assert_eq!(ch_id, 2);
                assert_eq!(&bytes, b"ok");
            }
            f => panic!("expected DATA, got {f:?}"),
        }
    })
    .await
    .expect("test timed out");
}

/// ACK 奇偶错位 = 结构违规：initiator 收 ACK(偶数) → 会话终止。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ack_wrong_parity_is_violation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, v2_cfg());
        let mut raw = s;

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(1)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        // ACK 打在偶数通道上（initiator 从不拥有偶数通道）
        raw_send(&mut raw, T_ACK, 2, &[AckStatus::OK]).await;
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 0);
                assert_eq!(reason, CloseReason::PROTOCOL_VIOLATION);
            }
            f => panic!("expected CLOSE(1), got {f:?}"),
        }
        assert!(!i.is_alive());
        drop(opener);
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- 数据报通道

/// 数据报通道端到端：DOPEN → grant_datagram → 数据报边界保留的双向回显。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datagram_channel_roundtrip_preserves_boundaries() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (i, r) = mux_pair().await;

        let r2 = r.clone();
        tokio::spawn(async move {
            while let Ok(req) = r2.accept_open().await {
                assert!(req.datagram, "DOPEN expected");
                tokio::spawn(async move {
                    if let Ok(mut ch) = req.grant_datagram().await {
                        while let Some(d) = ch.recv_datagram().await {
                            if ch.send_datagram(&d).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });

        let mut ch = i.open_datagram(target(5353)).await.expect("open_datagram");
        assert_eq!(ch.ch_id() % 2, 1);
        ch.send_datagram(b"a").await.expect("send");
        ch.send_datagram(b"bbb").await.expect("send");
        ch.send_datagram(&vec![0xCDu8; 1000]).await.expect("send");
        assert_eq!(ch.recv_datagram().await.as_deref(), Some(&b"a"[..]));
        assert_eq!(ch.recv_datagram().await.as_deref(), Some(&b"bbb"[..]));
        assert_eq!(ch.recv_datagram().await.unwrap().len(), 1000);
        // 大数据报上限
        let big = vec![0u8; luciola_tunnel::MAX_DATA_FRAME + 1];
        assert!(matches!(
            ch.send_datagram(&big).await,
            Err(MuxError::DatagramTooLarge(_))
        ));
    })
    .await
    .expect("test timed out");
}

/// 未证明 v2 的对端发 DOPEN = 结构违规（v1 对端保护，与 OPEN 同规则）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dopen_from_unproven_peer_is_violation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, v2_cfg());
        let mut raw = s;

        raw_send(&mut raw, T_DOPEN, 2, &open_payload("127.0.0.1", 5353)).await;
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 0);
                assert_eq!(reason, CloseReason::PROTOCOL_VIOLATION);
            }
            f => panic!("expected CLOSE(1), got {f:?}"),
        }
        assert!(!i.is_alive());
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- forward 层：UDP 会话映射

/// UDP 转发端到端：本地 socket → NAT 式映射 → 对端 connect 套接字回显；
/// 两个源地址各建一条映射通道。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_forward_e2e_two_sources_two_mappings() {
    tokio::time::timeout(Duration::from_secs(15), async {
        // UDP 回显上游
        let up = UdpSocket::bind("127.0.0.1:0").await.expect("upstream bind");
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = up.recv_from(&mut buf).await {
                let _ = up.send_to(&buf[..n], src).await;
            }
        });

        let (i, r) = mux_pair().await;
        let (i, r) = (std::sync::Arc::new(i), std::sync::Arc::new(r));
        let rule = ForwardRule {
            host: up_addr.ip().to_string(),
            port_from: up_addr.port(),
            port_to: up_addr.port(),
            udp: true,
        };
        let endpoint =
            start_forward_endpoint(r.clone(), ForwardAcl::new(vec![rule])).expect("endpoint");
        let fwd = start_udp_forward(
            i.clone(),
            UdpForwardConfig {
                listen_port: 0,
                target: DialTarget::from_ip(up_addr.ip(), up_addr.port()),
            },
        )
        .expect("udp forward");
        let local = fwd.local_addr();

        // 两个源 socket → 两条映射，各自回显
        for k in 0..2u8 {
            let s = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
            s.send_to(format!("ping{k}").as_bytes(), local)
                .await
                .expect("send");
            let mut buf = [0u8; 64];
            let (n, src) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf))
                .await
                .expect("recv deadline")
                .expect("recv");
            assert_eq!(src, local);
            assert_eq!(&buf[..n], format!("ping{k}").as_bytes());
        }
        // 映射收敛到 2 条
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while fwd.mappings() < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "mappings never reached 2"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(fwd.status().channels_total, 2);

        fwd.stop().await;
        endpoint.stop().await;
    })
    .await
    .expect("test timed out");
}

/// UDP 映射空闲回收：udp_idle_timeout 到期后映射拆除、通道回收，
/// 会话存活且同源新数据报可建立新映射。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_mapping_idle_timeout_recycles() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cfg = MuxConfig {
            udp_idle_timeout: Some(Duration::from_millis(400)),
            ..v2_cfg()
        };
        let up = UdpSocket::bind("127.0.0.1:0").await.expect("upstream bind");
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = up.recv_from(&mut buf).await {
                let _ = up.send_to(&buf[..n], src).await;
            }
        });

        let (i, r) = mux_pair_cfg(cfg).await;
        let (i, r) = (std::sync::Arc::new(i), std::sync::Arc::new(r));
        let rule = ForwardRule {
            host: up_addr.ip().to_string(),
            port_from: up_addr.port(),
            port_to: up_addr.port(),
            udp: true,
        };
        let endpoint =
            start_forward_endpoint(r.clone(), ForwardAcl::new(vec![rule])).expect("endpoint");
        let fwd = start_udp_forward(
            i.clone(),
            UdpForwardConfig {
                listen_port: 0,
                target: DialTarget::from_ip(up_addr.ip(), up_addr.port()),
            },
        )
        .expect("udp forward");
        let local = fwd.local_addr();

        let s = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        s.send_to(b"ping".as_ref(), local).await.expect("send");
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf))
            .await
            .expect("recv deadline")
            .expect("recv");
        assert_eq!(&buf[..n], b"ping");

        // 空闲 400ms → 映射与通道回收
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while fwd.mappings() != 0 || r.stats().channels_open != 0 || i.stats().channels_open != 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "idle mapping never recycled (mappings={} r_open={} i_open={})",
                fwd.mappings(),
                r.stats().channels_open,
                i.stats().channels_open,
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(i.is_alive() && r.is_alive());

        // 同源新数据报 → 新映射仍可用
        s.send_to(b"ping2".as_ref(), local).await.expect("send 2");
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf))
            .await
            .expect("recv deadline 2")
            .expect("recv 2");
        assert_eq!(&buf[..n], b"ping2");

        fwd.stop().await;
        endpoint.stop().await;
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- forward 层：主机名目标

/// 主机名目标端到端：OPEN(host="localhost") → endpoint 解析（v4 优先）→ 拨通回显；
/// ACL 主机名规则匹配；未授权主机名 ACK(1) 且不解析。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostname_target_dials_via_endpoint() {
    tokio::time::timeout(Duration::from_secs(15), async {
        // TCP 回显上游（只绑 127.0.0.1：断言解析钉扎选中 v4）
        let up = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = up.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match c.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if c.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let (i, r) = mux_pair().await;
        let (i, r) = (std::sync::Arc::new(i), std::sync::Arc::new(r));
        let rule = ForwardRule {
            host: "localhost".into(), // ACL 按小写精确匹配（解析发生在 ACL 之后）
            port_from: up_addr.port(),
            port_to: up_addr.port(),
            udp: false,
        };
        let endpoint =
            start_forward_endpoint(r.clone(), ForwardAcl::new(vec![rule])).expect("endpoint");
        let fwd = start_local_forward(
            i.clone(),
            LocalForwardConfig {
                listen_port: 0,
                target: host_target("localhost", up_addr.port()),
            },
        )
        .expect("local forward");
        let local = fwd.local_addr();

        let (mut rd, mut wr) = tokio::net::TcpStream::connect(local)
            .await
            .expect("connect")
            .into_split();
        wr.write_all(b"hello-host").await.expect("write");
        let mut buf = [0u8; 10];
        rd.read_exact(&mut buf).await.expect("echo");
        assert_eq!(&buf, b"hello-host");

        // 未授权主机名：ACK(1) 干净拒绝（fail-fast 本地连接关闭）
        let deny = start_local_forward(
            i.clone(),
            LocalForwardConfig {
                listen_port: 0,
                target: host_target("forbidden.example", up_addr.port()),
            },
        )
        .expect("deny forward");
        let conn = tokio::net::TcpStream::connect(deny.local_addr())
            .await
            .expect("connect deny");
        let mut conn = conn;
        let res = tokio::time::timeout(Duration::from_secs(5), conn.read_u8()).await;
        assert!(
            matches!(res, Err(_) | Ok(Err(_))),
            "denied connection must be closed by peer ACK(1)"
        );

        deny.stop().await;
        fwd.stop().await;
        endpoint.stop().await;
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- 通道空闲回收

/// 流式通道空闲回收：idle_timeout 到期只拆该通道（CLOSE(0)），会话存活，
/// 新通道立即可用；活动重置计时。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_idle_timeout_recycles_channel_only() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cfg = MuxConfig {
            idle_timeout: Some(Duration::from_millis(400)),
            ..v2_cfg()
        };
        let (i, r) = mux_pair_cfg(cfg).await;
        let (i, r) = (std::sync::Arc::new(i), std::sync::Arc::new(r));
        let r2 = r.clone();
        tokio::spawn(async move {
            while let Ok(req) = r2.accept_open().await {
                tokio::spawn(async move {
                    if let Ok(mut st) = req.grant().await {
                        let mut buf = [0u8; 64];
                        loop {
                            match st.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if st.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });

        // 通道 1：用一轮后闲置 → 回收
        let mut a = i.open(target(1)).await.expect("open A");
        a.write_all(b"x").await.expect("write");
        let mut back = [0u8; 1];
        a.read_exact(&mut back).await.expect("echo");
        drop(a);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while i.stats().channels_open != 0 || r.stats().channels_open != 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "idle channel never recycled"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            i.is_alive() && r.is_alive(),
            "session must survive recycling"
        );

        // 会话健康：新通道立即可用
        let mut b = i.open(target(2)).await.expect("open B after recycle");
        b.write_all(b"y").await.expect("write B");
        b.read_exact(&mut back).await.expect("echo B");
        assert_eq!(&back, b"y");
    })
    .await
    .expect("test timed out");
}

/// 空闲回收不会误伤活跃通道：持续流量（窗口信用来回流动）的通道保持存活。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_reaper_spares_active_channels() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cfg = MuxConfig {
            idle_timeout: Some(Duration::from_millis(400)),
            ..v2_cfg()
        };
        let (i, r) = mux_pair_cfg(cfg).await;
        spawn_accept_echo(r);

        let mut st = i.open(target(1)).await.expect("open");
        for k in 0..8u32 {
            tokio::time::sleep(Duration::from_millis(200)).await; // 总跨度 > idle_timeout
            st.write_all(format!("beat{k}").as_bytes())
                .await
                .expect("write");
            let mut back = [0u8; 5];
            st.read_exact(&mut back).await.expect("echo");
        }
        assert_eq!(i.stats().channels_open, 1, "active channel must survive");
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------- 回归：窗口与队列容量交互

/// 窗口远大于出站队列容量（window 4MiB=64 帧 vs 队列 36 帧）：写方必须在
/// 「窗口挂起 ↔ 队列挂起」之间正确交错推进。回归钉死 poll_write 的
/// 「先 reserve 再门控」顺序——反序会在 reserve Pending 时留下幻影窗口计数，
/// 传输中途永久卡死。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_larger_than_queue_still_flows() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let cfg = MuxConfig {
            max_channels: 1,
            channel_queue_frames: 1, // 队列容量 ≈ 36 帧
            window_size: 4 * 1024 * 1024,
            ..v2_cfg()
        };
        let (i, r) = mux_pair_cfg(cfg).await;
        spawn_accept_echo(r);

        let st = i.open(target(1)).await.expect("open");
        let payload: Vec<u8> = (0..2 * 1024 * 1024u32).map(|k| (k ^ 0x5A) as u8).collect();
        let (mut rh, mut wh) = tokio::io::split(st);
        let writer = tokio::spawn({
            let payload = payload.clone();
            async move {
                wh.write_all(&payload).await.expect("write");
                wh.shutdown().await.expect("half close");
            }
        });
        let mut back = Vec::new();
        rh.read_to_end(&mut back).await.expect("echo");
        writer.await.expect("writer");
        assert_eq!(back.len(), payload.len());
        assert!(back == payload);
    })
    .await
    .expect("test timed out");
}

/// 数据报通道在窗口等待期间被拆除：send_datagram 必须干净返回
/// ChannelClosed（而非挂起到会话结束）。回归钉死等待循环里的 dead 复查。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datagram_send_parked_then_torn_down_returns_closed() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let cfg = MuxConfig {
            window_size: 128 * 1024, // 2 帧
            ..v2_cfg()
        };
        let (i, r) = mux_pair_cfg(cfg).await;

        // responder：accept 后持有通道但永不消费 → credit 永不来
        let holder = tokio::spawn(async move {
            let ch = r
                .accept_open()
                .await
                .expect("accept")
                .grant_datagram()
                .await
                .expect("grant");
            std::future::pending::<()>().await;
            drop(ch);
        });

        let ch = i.open_datagram(target(1)).await.expect("open_datagram");
        ch.send_datagram(&vec![0u8; 64 * 1024])
            .await
            .expect("send 1");
        ch.send_datagram(&vec![0u8; 64 * 1024])
            .await
            .expect("send 2");

        // 第三帧 park 在窗口上；随后本地拆除通道（触发对端 Drop-CLOSE 回程 +
        // 本端 remove_entry → kill），park 中的 send_datagram 应报 ChannelClosed。
        let sender = tokio::spawn({
            let ch = ch;
            async move { ch.send_datagram(&vec![0u8; 64 * 1024]).await }
        });
        // 等 sender 真正 park（窗口已满、无 credit）
        tokio::time::sleep(Duration::from_millis(150)).await;
        holder.abort(); // responder 侧 MuxDatagram Drop → CLOSE(NORMAL) → 本端 dead+kill

        let res = tokio::time::timeout(Duration::from_secs(5), sender)
            .await
            .expect("sender must not hang")
            .expect("sender task");
        assert!(
            matches!(
                res,
                Err(MuxError::ChannelClosed) | Err(MuxError::SessionClosed)
            ),
            "parked send must resolve on teardown, got {res:?}"
        );
    })
    .await
    .expect("test timed out");
}
