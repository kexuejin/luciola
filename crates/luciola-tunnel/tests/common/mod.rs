//! 集成测试共享 harness（loopback.rs 与 forward_e2e.rs 共用）。
//!
//! 约定（见 loopback.rs 文件头）：initiator = connect_secure 一侧、responder =
//! accept_secure 一侧；"raw" 指测试自己收发帧、不跑 mux 的一侧。
//! 所有监听一律临时端口（127.0.0.1:0），不依赖固定端口。
#![allow(dead_code)] // 每个测试二进制只用到子集

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use luciola::link::secure::{accept_secure, connect_secure, SecureStream};
use luciola::trust::identity_from_seed;
use luciola_tunnel::{decode_frame, encode_frame, DialTarget, Frame, MuxConfig, MuxSession, Role};

pub const SEED_I: [u8; 32] = [7u8; 32];
pub const SEED_R: [u8; 32] = [9u8; 32];

/// 建立一对互 pin 的 SecureStream：(initiator 侧, responder 侧)。
pub async fn secure_pair() -> (SecureStream, SecureStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let pin_r = identity_from_seed(&SEED_R).public_key;
    let pin_i = identity_from_seed(&SEED_I).public_key;
    let server =
        tokio::spawn(async move { accept_secure(&listener, &SEED_R, Some(&pin_i[..])).await });
    let client = connect_secure(&addr.ip().to_string(), addr.port(), &SEED_I, &pin_r[..])
        .await
        .expect("handshake");
    let server = server
        .await
        .expect("accept task")
        .expect("accept handshake");
    (client, server)
}

pub fn fast_cfg() -> MuxConfig {
    MuxConfig {
        open_timeout: Duration::from_millis(1500),
        ..Default::default()
    }
}

pub async fn mux_pair_cfg(cfg: MuxConfig) -> (MuxSession, MuxSession) {
    let (c, s) = secure_pair().await;
    (
        MuxSession::start(c, Role::Initiator, cfg.clone()),
        MuxSession::start(s, Role::Responder, cfg),
    )
}

pub async fn mux_pair() -> (MuxSession, MuxSession) {
    mux_pair_cfg(fast_cfg()).await
}

pub fn target(port: u16) -> DialTarget {
    DialTarget::from_ip("127.0.0.1".parse::<IpAddr>().expect("ip"), port)
}

pub fn ip(host: &str) -> IpAddr {
    host.parse::<IpAddr>().expect("ip")
}

// ---------------------------------------------------------------- raw 侧帧收发

/// 收下一帧（含 keepalive 噪声）。v2 会话会周期性发 PING——协议语义测试
/// 基本都该用 [`raw_recv`]（自动跳过），只有 keepalive 测试用本函数。
pub async fn raw_recv_any(stream: &mut SecureStream) -> Frame {
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.recv(&mut buf))
        .await
        .expect("raw recv timed out")
        .expect("raw recv failed");
    decode_frame(&buf).expect("undecodable frame")
}

fn is_keepalive_noise(f: &Frame) -> bool {
    matches!(f, Frame::Ping { .. } | Frame::Pong { .. })
}

pub async fn raw_send(stream: &mut SecureStream, ftype: u8, ch_id: u32, payload: &[u8]) {
    stream
        .send(&encode_frame(ftype, ch_id, payload))
        .await
        .expect("raw send failed");
}

pub async fn raw_send_bytes(stream: &mut SecureStream, bytes: &[u8]) {
    stream.send(bytes).await.expect("raw send failed");
}

/// 收下一个协议帧（跳过 PING/PONG keepalive 噪声）。
pub async fn raw_recv(stream: &mut SecureStream) -> Frame {
    loop {
        let f = raw_recv_any(stream).await;
        if !is_keepalive_noise(&f) {
            return f;
        }
    }
}

/// 限时等一个协议帧：None = 窗口内没有非 keepalive 帧（用于"不该有帧"的断言）。
pub async fn raw_recv_within(stream: &mut SecureStream, wait: Duration) -> Option<Frame> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut buf = Vec::new();
        match tokio::time::timeout(left, stream.recv(&mut buf)).await {
            Err(_) => return None,
            Ok(Err(e)) => panic!("raw peer closed connection unexpectedly: {e}"),
            Ok(Ok(())) => {
                let frame = decode_frame(&buf).expect("undecodable frame");
                if !is_keepalive_noise(&frame) {
                    return Some(frame);
                }
            }
        }
    }
}

/// OPEN payload：[host_len u8][host utf8][port u16be]。
pub fn open_payload(host: &str, port: u16) -> Vec<u8> {
    let h = host.as_bytes();
    let mut p = Vec::with_capacity(3 + h.len());
    p.push(h.len() as u8);
    p.extend_from_slice(h);
    p.extend_from_slice(&port.to_be_bytes());
    p
}

/// responder：accept -> grant -> 流式回显（读到什么写回什么），EOF 后收尾。
pub fn spawn_accept_echo(r: MuxSession) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(req) = r.accept_open().await {
            tokio::spawn(async move {
                if let Ok(mut st) = req.grant().await {
                    let mut buf = vec![0u8; 64 * 1024];
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
                    let _ = st.shutdown().await;
                }
            });
        }
    })
}
