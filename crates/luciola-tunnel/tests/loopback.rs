//! mux v1 在真实 SecureStream（127.0.0.1 回环）上的行为。
//!
//! 约定：initiator = connect_secure 一侧，responder = accept_secure 一侧；
//! "raw" 指测试自己收发帧、不跑 mux 的一侧，用于观测线协议与注入违规帧。
//! 共享 harness（SecureStream/mux 配对、raw 帧收发、OPEN payload 等）在
//! tests/common/mod.rs，与 forward_e2e.rs 共用。

mod common;
use common::*;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use luciola_tunnel::{
    AckStatus, CloseReason, DialTarget, Frame, MuxConfig, MuxError, MuxSession, Role, T_ACK,
    T_DATA, T_OPEN,
};

// ---------------------------------------------------------------- T1 验收用例

/// 多通道并发交错：ch 1/3/5/7（D8 奇数分配）、64KiB 以上部分写、200KB×4 完整性。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_channel_interleaved_transfer() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (i, r) = mux_pair().await;
        spawn_accept_echo(r);

        let mut handles = Vec::new();
        for k in 0u32..4 {
            let i = i.clone();
            handles.push(tokio::spawn(async move {
                let st = i.open(target(9000 + k as u16)).await.expect("open");
                let ch = st.ch_id();
                let payload: Vec<u8> = (0..200_000u32)
                    .map(|j| ((j >> 3) as u8) ^ (k as u8))
                    .collect();
                let (mut rh, mut wh) = tokio::io::split(st);
                let writer = tokio::spawn({
                    let payload = payload.clone();
                    async move {
                        wh.write_all(&payload).await.expect("write");
                        wh.shutdown().await.expect("half close");
                    }
                });
                let mut back = Vec::new();
                rh.read_to_end(&mut back).await.expect("read echo");
                writer.await.expect("writer task");
                assert_eq!(back.len(), payload.len(), "ch {ch} length mismatch");
                assert!(back == payload, "ch {ch} content mismatch");
                ch
            }));
        }

        let mut chs = Vec::new();
        for h in handles {
            chs.push(h.await.expect("channel task"));
        }
        chs.sort_unstable();
        assert_eq!(
            chs,
            vec![1, 3, 5, 7],
            "initiator must allocate odd, monotonous ch ids"
        );
        assert_eq!(i.stats().channels_total, 4);
        assert!(i.is_alive());
    })
    .await
    .expect("test timed out");
}

/// 半关闭独立性：本端 shutdown 写方向后仍可读对端数据（EOF 单向）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_close_is_bidirectional_independent() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (i, r) = mux_pair().await;
        let r2 = r.clone();
        let responder = tokio::spawn(async move {
            let st = r2
                .accept_open()
                .await
                .expect("accept")
                .grant()
                .await
                .expect("grant");
            let (mut rh, mut wh) = tokio::io::split(st);
            let mut got = Vec::new();
            rh.read_to_end(&mut got).await.expect("read until peer EOF");
            wh.write_all(b"B-hello")
                .await
                .expect("write after peer EOF");
            wh.shutdown().await.expect("half close");
            got
        });

        let mut st = i.open(target(1)).await.expect("open");
        st.write_all(b"A-hello").await.expect("write");
        st.shutdown().await.expect("half close");
        let mut back = Vec::new();
        st.read_to_end(&mut back)
            .await
            .expect("still readable after half close");
        assert_eq!(&back, b"B-hello");
        assert_eq!(responder.await.expect("responder task"), &b"A-hello"[..]);
        assert!(i.is_alive() && r.is_alive());
    })
    .await
    .expect("test timed out");
}

/// deny(1)：无 detail、终态 ACK 后不补 CLOSE，会话继续可用（通道级终态不杀会话）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_rejects_open_then_session_recovers() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (i, r) = mux_pair().await;
        let r2 = r.clone();
        let responder = tokio::spawn(async move {
            let first = r2.accept_open().await.expect("accept 1");
            assert_eq!(first.ch_id, 1);
            first.deny(AckStatus::ACL_DENIED, None).await.expect("deny");
            let second = r2.accept_open().await.expect("accept 2");
            let mut st = second.grant().await.expect("grant");
            let mut buf = [0u8; 4];
            st.read_exact(&mut buf).await.expect("read");
            buf
        });

        match i.open(target(1)).await {
            Err(MuxError::Rejected { status, detail }) => {
                assert_eq!(status, AckStatus::ACL_DENIED);
                assert!(detail.is_none(), "ACL_DENIED must not carry a detail");
            }
            other => panic!("expected Rejected, got {:?}", other.map(|s| s.ch_id())),
        }
        assert!(i.is_alive());

        let mut st = i.open(target(2)).await.expect("second open");
        st.write_all(b"ping").await.expect("write");
        let got = responder.await.expect("responder task");
        assert_eq!(&got, b"ping");
        assert_eq!(i.stats().channels_total, 2);
    })
    .await
    .expect("test timed out");
}

/// 线上观测：终态 ACK（raw 回 ACK(1)）之后不得出现 CLOSE；会话继续握手 + shutdown 发 CLOSE(3,0)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_ack_no_close_then_shutdown_emits_session_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(9)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        raw_send(&mut raw, T_ACK, 1, &[AckStatus::ACL_DENIED]).await;
        match opener.await.expect("opener task") {
            Err(MuxError::Rejected { status, .. }) => assert_eq!(status, AckStatus::ACL_DENIED),
            other => panic!("expected Rejected, got {:?}", other.map(|s| s.ch_id())),
        }
        assert!(
            raw_recv_within(&mut raw, Duration::from_millis(400))
                .await
                .is_none(),
            "a terminal ACK must never be followed by a CLOSE"
        );

        // 会话仍活着：第二条通道正常握手 + 数据可达
        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(9)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 3),
            f => panic!("expected OPEN ch3, got {f:?}"),
        }
        raw_send(&mut raw, T_ACK, 3, &[AckStatus::OK]).await;
        let mut st = opener.await.expect("opener task").expect("second open");
        st.write_all(b"ok").await.expect("write");
        match raw_recv(&mut raw).await {
            Frame::Data { ch_id, bytes } => {
                assert_eq!(ch_id, 3);
                assert_eq!(&bytes, b"ok");
            }
            f => panic!("expected DATA, got {f:?}"),
        }

        // 会话级关闭：CLOSE(reason=3, ch 0)
        i.shutdown();
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 0);
                assert_eq!(reason, CloseReason::SESSION_SHUTDOWN);
            }
            f => panic!("expected session CLOSE, got {f:?}"),
        }
        assert!(!i.is_alive());
        assert!(matches!(
            i.open(target(9)).await,
            Err(MuxError::SessionClosed)
        ));
    })
    .await
    .expect("test timed out");
}

/// responder 线上 deny(2, detail) 后 grant 下一条：ACK detail 保留、无补发 CLOSE。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_deny_detail_then_grant_follows() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let mut raw = c;
        let r = MuxSession::start(s, Role::Responder, fast_cfg());
        let r2 = r.clone();
        let responder = tokio::spawn(async move {
            let req = r2.accept_open().await.expect("accept 1");
            assert_eq!(req.target.port, 3080);
            req.deny(AckStatus::DIAL_FAILED, Some("connection refused".into()))
                .await
                .expect("deny");
            let req = r2.accept_open().await.expect("accept 2");
            let mut st = req.grant().await.expect("grant");
            let mut buf = [0u8; 2];
            st.read_exact(&mut buf).await.expect("read");
            buf
        });

        raw_send(&mut raw, T_OPEN, 1, &open_payload("127.0.0.1", 3080)).await;
        match raw_recv(&mut raw).await {
            Frame::Ack {
                ch_id,
                status,
                detail,
            } => {
                assert_eq!(ch_id, 1);
                assert_eq!(status, AckStatus::DIAL_FAILED);
                assert_eq!(detail.as_deref(), Some("connection refused"));
            }
            f => panic!("expected ACK, got {f:?}"),
        }
        assert!(
            raw_recv_within(&mut raw, Duration::from_millis(400))
                .await
                .is_none(),
            "deny is terminal at channel level: no CLOSE"
        );

        raw_send(&mut raw, T_OPEN, 3, &open_payload("127.0.0.1", 3081)).await;
        match raw_recv(&mut raw).await {
            Frame::Ack { ch_id, status, .. } => {
                assert_eq!(ch_id, 3);
                assert_eq!(status, AckStatus::OK);
            }
            f => panic!("expected ACK(0), got {f:?}"),
        }
        raw_send(&mut raw, T_DATA, 3, b"yo").await;
        let got = responder.await.expect("responder task");
        assert_eq!(&got, b"yo");
        assert!(r.is_alive());
    })
    .await
    .expect("test timed out");
}

/// open 超时：对端不回 ACK -> OpenTimeout + 线上 CLOSE(upstream_reset, ch 1)，会话不死。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_timeout_sends_close_upstream_reset() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let cfg = MuxConfig {
            open_timeout: Duration::from_millis(400),
            ..Default::default()
        };
        let i = MuxSession::start(c, Role::Initiator, cfg);
        let mut raw = s;

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(1)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        // 故意不回 ACK，等 open 超时
        let res = tokio::time::timeout(Duration::from_secs(3), opener)
            .await
            .expect("opener deadline")
            .expect("opener task");
        match res {
            Err(MuxError::OpenTimeout(_)) => {}
            other => panic!("expected OpenTimeout, got {:?}", other.map(|s| s.ch_id())),
        }
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 1, "timeout CLOSE must target the timed-out channel");
                assert_eq!(reason, CloseReason::UPSTREAM_RESET);
            }
            f => panic!("expected CLOSE, got {f:?}"),
        }
        assert!(i.is_alive());

        // 会话继续可用
        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(2)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 3),
            f => panic!("expected OPEN ch3, got {f:?}"),
        }
        raw_send(&mut raw, T_ACK, 3, &[AckStatus::OK]).await;
        assert!(opener.await.expect("opener task").is_ok());
    })
    .await
    .expect("test timed out");
}

/// responder 通道数超限：两条 Pending 后第三条 OPEN -> ACK(3)，会话存活。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_channel_limit_acks_3() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let mut raw = c;
        let cfg = MuxConfig {
            max_channels: 2,
            ..fast_cfg()
        };
        let r = MuxSession::start(s, Role::Responder, cfg);

        raw_send(&mut raw, T_OPEN, 1, &open_payload("127.0.0.1", 3080)).await;
        assert!(
            raw_recv_within(&mut raw, Duration::from_millis(150))
                .await
                .is_none(),
            "pending OPEN must not be ACKed before grant/deny"
        );
        raw_send(&mut raw, T_OPEN, 3, &open_payload("127.0.0.1", 3081)).await;
        assert!(raw_recv_within(&mut raw, Duration::from_millis(150))
            .await
            .is_none());

        raw_send(&mut raw, T_OPEN, 5, &open_payload("127.0.0.1", 3082)).await;
        match raw_recv(&mut raw).await {
            Frame::Ack { ch_id, status, .. } => {
                assert_eq!(ch_id, 5);
                assert_eq!(status, AckStatus::CHANNEL_LIMIT);
            }
            f => panic!("expected ACK(3), got {f:?}"),
        }
        assert!(r.is_alive());
    })
    .await
    .expect("test timed out");
}

/// initiator 本地通道上限：max_channels=1 时第二条 open 在本地被拒，且不发帧。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initiator_local_channel_limit_rejected_3() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let cfg = MuxConfig {
            max_channels: 1,
            ..fast_cfg()
        };
        let i = MuxSession::start(c, Role::Initiator, cfg);
        let mut raw = s;

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(1)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        raw_send(&mut raw, T_ACK, 1, &[AckStatus::OK]).await;
        let _held = opener.await.expect("opener task").expect("first open");

        match i.open(target(2)).await {
            Err(MuxError::Rejected { status, detail }) => {
                assert_eq!(status, AckStatus::CHANNEL_LIMIT);
                assert!(detail.unwrap_or_default().contains("limit"));
            }
            other => panic!(
                "expected local Rejected(3), got {:?}",
                other.map(|s| s.ch_id())
            ),
        }
        assert!(
            raw_recv_within(&mut raw, Duration::from_millis(200))
                .await
                .is_none(),
            "local limit rejection must not put any frame on the wire"
        );
    })
    .await
    .expect("test timed out");
}

/// DATA 打在 Pending（未 ACK）通道上 = 结构性违规：CLOSE(1, ch 0)、会话终止。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_before_ack_is_violation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(1)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        // 不回 ACK，直接发 DATA
        raw_send(&mut raw, T_DATA, 1, b"premature").await;
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 0, "session-level CLOSE");
                assert_eq!(reason, CloseReason::PROTOCOL_VIOLATION);
            }
            f => panic!("expected session CLOSE(1), got {f:?}"),
        }
        match opener.await.expect("opener task") {
            Err(MuxError::SessionClosed) => {}
            other => panic!("expected SessionClosed, got {:?}", other.map(|s| s.ch_id())),
        }
        assert!(!i.is_alive());
    })
    .await
    .expect("test timed out");
}

/// 未知通道的 DATA：回 CLOSE(0, ch)（仅删通道），会话与后续通道不受影响。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_channel_data_gets_close_and_session_survives() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        raw_send(&mut raw, T_DATA, 9, b"ghost").await;
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 9, "unknown-channel CLOSE targets that channel");
                assert_eq!(reason, CloseReason::NORMAL);
            }
            f => panic!("expected CLOSE(ch 9, 0), got {f:?}"),
        }
        assert!(i.is_alive());

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(1)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        raw_send(&mut raw, T_ACK, 1, &[AckStatus::OK]).await;
        let mut st = opener
            .await
            .expect("opener task")
            .expect("open after unknown DATA");
        st.write_all(b"hi").await.expect("write");
        match raw_recv(&mut raw).await {
            Frame::Data { ch_id, bytes } => {
                assert_eq!(ch_id, 1);
                assert_eq!(&bytes, b"hi");
            }
            f => panic!("expected DATA, got {f:?}"),
        }
    })
    .await
    .expect("test timed out");
}

/// 偶数 ch_id 的通道帧 = 结构性违规（D8/D9）：CLOSE(1, ch 0)，会话终止。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn even_channel_id_open_is_violation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        raw_send(&mut raw, T_OPEN, 2, &open_payload("127.0.0.1", 3080)).await;
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 0);
                assert_eq!(reason, CloseReason::PROTOCOL_VIOLATION);
            }
            f => panic!("expected session CLOSE(1), got {f:?}"),
        }
        assert!(!i.is_alive());
        assert!(matches!(
            i.open(target(1)).await,
            Err(MuxError::SessionClosed)
        ));
    })
    .await
    .expect("test timed out");
}

/// 坏 magic = 结构性违规：会话以 CLOSE(1, ch 0) 终止。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_magic_kills_session() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        raw_send_bytes(&mut raw, b"ZZZZZZZZZZZZZZZZZZ").await;
        match raw_recv(&mut raw).await {
            Frame::Close { ch_id, reason } => {
                assert_eq!(ch_id, 0);
                assert_eq!(reason, CloseReason::PROTOCOL_VIOLATION);
            }
            f => panic!("expected session CLOSE(1), got {f:?}"),
        }
        assert!(!i.is_alive());
    })
    .await
    .expect("test timed out");
}

/// shutdown()：双端 accept_open/open -> SessionClosed，既有 stream 报错（timeout 包裹）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_terminates_both_sides() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (i, r) = mux_pair().await;
        let r2 = r.clone();
        let responder = tokio::spawn(async move {
            let mut st = r2
                .accept_open()
                .await
                .expect("accept")
                .grant()
                .await
                .expect("grant");
            let mut buf = [0u8; 8];
            match st.read(&mut buf).await {
                Err(_) => {}
                Ok(n) => panic!("stream must error after session shutdown, read {n} bytes"),
            }
            r2.is_alive()
        });

        let mut st = i.open(target(1)).await.expect("open");
        i.shutdown();
        assert!(!i.is_alive());
        assert!(matches!(
            i.open(target(1)).await,
            Err(MuxError::SessionClosed)
        ));

        // 对端在途 CLOSE 到达前 accept_open 挂起，终止后立即返回 SessionClosed
        match tokio::time::timeout(Duration::from_secs(3), r.accept_open()).await {
            Ok(Err(MuxError::SessionClosed)) => {}
            other => panic!("expected SessionClosed, got {other:?}"),
        }
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), r.open(target(1))).await,
            Ok(Err(MuxError::SessionClosed))
        ));

        let mut buf = [0u8; 4];
        let read_res = tokio::time::timeout(Duration::from_secs(3), st.read(&mut buf))
            .await
            .expect("read deadline");
        assert!(
            read_res.is_err(),
            "initiator stream must error after shutdown"
        );

        let responder_alive = responder.await.expect("responder task");
        assert!(!responder_alive, "responder session must die on CLOSE(3)");
        assert!(!r.is_alive());
    })
    .await
    .expect("test timed out");
}

/// 底层 FIN（对端进程消失等价场景）：读侧 recv 失败 -> 会话终止、open 拒绝。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn underlying_fin_terminates_session() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        let opener = {
            let i = i.clone();
            tokio::spawn(async move { i.open(target(1)).await })
        };
        match raw_recv(&mut raw).await {
            Frame::Open { ch_id, .. } => assert_eq!(ch_id, 1),
            f => panic!("expected OPEN, got {f:?}"),
        }
        raw_send(&mut raw, T_ACK, 1, &[AckStatus::OK]).await;
        let mut st = opener.await.expect("opener task").expect("open");
        raw_send(&mut raw, T_DATA, 1, b"hello").await;
        let mut buf = [0u8; 5];
        st.read_exact(&mut buf).await.expect("read data");
        assert_eq!(&buf, b"hello");

        drop(raw); // TCP FIN
        let read_res = tokio::time::timeout(Duration::from_secs(3), st.read(&mut buf))
            .await
            .expect("read deadline");
        assert!(read_res.is_err(), "stream must error when the link dies");

        tokio::time::timeout(Duration::from_secs(3), async {
            while i.is_alive() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session must die after underlying FIN");
        assert!(matches!(
            i.open(target(1)).await,
            Err(MuxError::SessionClosed)
        ));
    })
    .await
    .expect("test timed out");
}

/// §1.4 级联停顿硬超时：只拆 stall 的通道（CLOSE(2)），会话与另一条通道继续流动。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stall_cut_off_tears_channel_not_session() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let cfg = MuxConfig {
            channel_queue_frames: 1,
            stall_hard_timeout: Duration::from_millis(300),
            open_timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, cfg.clone());
        let r = MuxSession::start(s, Role::Responder, cfg);

        let r2 = r.clone();
        // responder：A 授权但永不读；B 持续回显。任务不 join（测试尾部由 runtime 回收）。
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
            let _a_held_unread = a;
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
            drop(_a_held_unread);
        });

        let a = i.open(target(1)).await.expect("open A");
        let mut b = i.open(target(2)).await.expect("open B");

        // B 先确认连通（此时 A 尚未洪泛）
        b.write_all(b"ping").await.expect("B write");
        let mut back = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), b.read_exact(&mut back))
            .await
            .expect("B echo deadline")
            .expect("B echo read");
        assert_eq!(&back, b"ping");

        // A 洪泛：64KiB/帧，直到写端报错（通道被 stall 拆掉）
        let (mut a_r, mut a_w) = tokio::io::split(a);
        let flood = tokio::spawn(async move {
            let chunk = vec![0xABu8; 64 * 1024];
            let mut n = 0u32;
            loop {
                match a_w.write_all(&chunk).await {
                    Err(_) => break n,
                    Ok(()) => {
                        n += 1;
                        assert!(n <= 500, "flood write never errored");
                    }
                }
            }
        });
        let iters = tokio::time::timeout(Duration::from_secs(15), flood)
            .await
            .expect("flood deadline")
            .expect("flood task");
        assert!(iters <= 500);

        // A 读端也报错（close/队列关闭任一路径）
        let mut tmp = [0u8; 8];
        assert!(a_r.read(&mut tmp).await.is_err());

        // 会话活着；A 被拆、B 仍在（两侧一致）
        assert!(i.is_alive() && r.is_alive());
        tokio::time::timeout(Duration::from_secs(3), async {
            while r.stats().channels_open != 1 || i.stats().channels_open != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("channel A torn down, B alive on both sides");

        // B 在 stall 拆除后仍然恢复流动
        b.write_all(b"ping2").await.expect("B write after stall");
        tokio::time::timeout(Duration::from_secs(5), b.read_exact(&mut back))
            .await
            .expect("B echo deadline 2")
            .expect("B echo read 2");
        assert_eq!(&back, b"ping");
    })
    .await
    .expect("test timed out");
}

/// 本地 invalid target：解析阶段直接拒绝，不发任何帧。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_target_rejected_locally_without_wire() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let i = MuxSession::start(c, Role::Initiator, fast_cfg());
        let mut raw = s;

        assert!(matches!(
            i.open(DialTarget::from_ip(ip("0.0.0.0"), 80)).await,
            Err(MuxError::InvalidTarget(_))
        ));
        assert!(matches!(
            i.open(DialTarget::from_ip(ip("224.0.0.1"), 80)).await,
            Err(MuxError::InvalidTarget(_))
        ));
        assert!(matches!(
            i.open(DialTarget::from_ip(ip("255.255.255.255"), 80)).await,
            Err(MuxError::InvalidTarget(_))
        ));
        assert!(matches!(
            i.open(target(0)).await,
            Err(MuxError::InvalidTarget(_))
        ));
        assert!(
            raw_recv_within(&mut raw, Duration::from_millis(250))
                .await
                .is_none(),
            "local invalid-target rejection must not put frames on the wire"
        );
        assert!(i.is_alive());
    })
    .await
    .expect("test timed out");
}

/// responder 线上 bad target：非法主机名 / unspecified / 广播 / 组播 / 重复 ch_id
/// -> OPEN_ACK(4)，会话存活。（v2：合法主机名在 mux 层是合法目标，交给策略层
/// 解析；只有结构非法的才在此层 ACK(4)。）
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_bad_target_and_duplicate_acks_4() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (c, s) = secure_pair().await;
        let mut raw = c;
        let r = MuxSession::start(s, Role::Responder, fast_cfg());

        for (ch, host) in [
            (1u32, "1.2.3.999"), // 纯数字串，IP/主机名都不是
            (3, "0.0.0.0"),
            (5, "255.255.255.255"),
            (7, "224.0.0.1"),
        ] {
            raw_send(&mut raw, T_OPEN, ch, &open_payload(host, 80)).await;
            match raw_recv(&mut raw).await {
                Frame::Ack {
                    ch_id,
                    status,
                    detail,
                } => {
                    assert_eq!(ch_id, ch);
                    assert_eq!(status, AckStatus::BAD_TARGET);
                    assert!(detail.is_some(), "bad target must carry a detail");
                }
                f => panic!("expected ACK(4) for {host}, got {f:?}"),
            }
        }

        // 合法 OPEN 停在 Pending；重复 ch_id -> ACK(4)
        raw_send(&mut raw, T_OPEN, 9, &open_payload("127.0.0.1", 3080)).await;
        assert!(raw_recv_within(&mut raw, Duration::from_millis(150))
            .await
            .is_none());
        raw_send(&mut raw, T_OPEN, 9, &open_payload("127.0.0.1", 3081)).await;
        match raw_recv(&mut raw).await {
            Frame::Ack {
                ch_id,
                status,
                detail,
            } => {
                assert_eq!(ch_id, 9);
                assert_eq!(status, AckStatus::BAD_TARGET);
                assert!(detail.unwrap_or_default().contains("duplicate"));
            }
            f => panic!("expected duplicate ACK(4), got {f:?}"),
        }
        assert!(r.is_alive());
    })
    .await
    .expect("test timed out");
}
