//! 真实 Worker 端到端：两个引擎经 `wrangler dev` 跑起来的 Worker + Durable
//! Object 完成 rendezvous、鉴权、转发和加密握手。
//!
//! 覆盖单元/回环测不到的部分：
//! 1. **真实的 Ed25519 边缘鉴权**（workerd 里的 WebCrypto，而不是测试里手写的
//!    forwarder）；
//! 2. **Durable Object 的 pre-join 缓冲**——先到的 peer 的 candidate 帧被存起来
//!    再按序投递给第二个 peer，否则 rendezvous 死锁；
//! 3. **`x-luciola-epoch` 握手响应头**由真实 Worker 发出，客户端能读到；
//! 4. relay 数据面在真实 DO 上转发。
//!
//! 需要外部进程，所以默认跳过。跑法：
//!
//! ```bash
//! cd deploy/cloudflare-signaling && npx wrangler dev --port 8787 --local
//! LUCIOLA_WAN_WORKER=ws://127.0.0.1:8787/ws cargo test -p luciola \
//!   --test wan_local_worker -- --nocapture
//! ```

use luciola::pairing::derive_rendezvous_room_id_flexible;
use luciola::proto::RelayConfig;
use luciola::wan::{connect_wan, current_epoch, WanConfig};
use std::time::Duration;
use zeroize::Zeroizing;

/// 端点来自环境变量；没有就跳过（与 `realnic_e2e` 的"不依赖环境"纪律一致）。
fn worker_endpoint() -> Option<String> {
    let endpoint = std::env::var("LUCIOLA_WAN_WORKER").ok()?;
    if endpoint.trim().is_empty() {
        return None;
    }
    Some(endpoint)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_meet_through_a_local_worker() {
    let Some(endpoint) = worker_endpoint() else {
        eprintln!("skip: set LUCIOLA_WAN_WORKER to a local wrangler dev endpoint");
        return;
    };

    let id_a = luciola::trust::generate_identity();
    let id_b = luciola::trust::generate_identity();
    let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
    let seed_b: [u8; 32] = id_b.seed.clone().try_into().unwrap();
    let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
    let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();

    let psk = Zeroizing::new(b"local-worker-e2e-psk".to_vec());
    let epoch = current_epoch();
    let room = derive_rendezvous_room_id_flexible(&pk_a, &pk_b, Some(psk.as_slice()), Some(epoch));
    assert_eq!(room.len(), 32, "room must be 32 hex chars: {room:?}");

    let base = || WanConfig {
        signaling_endpoint: endpoint.clone(),
        room: room.clone(),
        // Pin the epoch: this test is about the Worker path, not realignment.
        epoch,
        psk: psk.clone(),
        relay: RelayConfig {
            allow_wan_signaling: true,
            allow_relay: true,
            connection_timeout_ms: 5_000,
            ..RelayConfig::default()
        },
        punch_timeout: Duration::from_secs(10),
        // No UDP punching: a relay-only run keeps this test about the Worker.
        enable_hole_punching: false,
        ..WanConfig::default()
    };
    let mut cfg_a = base();
    cfg_a.identity_seed = seed_a;
    cfg_a.my_public_key = pk_a;
    cfg_a.peer_public_key = pk_b;
    let mut cfg_b = base();
    cfg_b.identity_seed = seed_b;
    cfg_b.my_public_key = pk_b;
    cfg_b.peer_public_key = pk_a;

    let (a, b) = tokio::try_join!(
        tokio::time::timeout(Duration::from_secs(20), connect_wan(cfg_a)),
        tokio::time::timeout(Duration::from_secs(20), connect_wan(cfg_b)),
    )
    .expect("connect_wan must finish inside the timeout");
    let (mut a, mut b) = (a.expect("peer A"), b.expect("peer B"));

    assert_eq!(a.channel_type(), luciola::ChannelType::RelayForwarded);
    assert_eq!(b.channel_type(), luciola::ChannelType::RelayForwarded);
    // The pinned peer must be the one we actually talked to, not a bystander.
    assert_eq!(a.peer_public_key, id_b.public_key);
    assert_eq!(b.peer_public_key, id_a.public_key);

    // Larger than one relay frame, so chunking and the DO's 32 KiB cap both run.
    let payload = vec![0x5au8; 96 * 1024];
    a.send(&payload).await.expect("send");
    let mut got = Vec::new();
    b.recv(&mut got).await.expect("recv");
    assert_eq!(got.len(), payload.len(), "relay must deliver every byte");
    assert_eq!(got, payload, "relay must deliver the exact bytes");

    b.send(b"ack-through-the-worker").await.unwrap();
    got.clear();
    a.recv(&mut got).await.unwrap();
    assert_eq!(got, b"ack-through-the-worker");
}

/// `/health` 必须报出 Worker 自己服务的 epoch，且与客户端一致（允许 ±1 窗口）。
///
/// 这条断言是 epoch 对齐的前提：如果 Worker 的时钟和客户端差出超过一个窗口，
/// 客户端 realign 之后仍然会被 `validateParams` 拒绝。
#[tokio::test]
async fn worker_health_reports_an_epoch_within_one_window() {
    let Some(endpoint) = worker_endpoint() else {
        eprintln!("skip: set LUCIOLA_WAN_WORKER to a local wrangler dev endpoint");
        return;
    };
    // ws://host:port/ws -> host:port, and only loopback http is attempted:
    // this test exists to check a local `wrangler dev`, not to be an HTTP client.
    let authority = endpoint
        .trim_end_matches("/ws")
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .to_string();
    if authority.contains('/') {
        eprintln!("skip: {endpoint} is not a bare host:port endpoint");
        return;
    }

    let Ok(mut stream) = tokio::net::TcpStream::connect(&authority).await else {
        eprintln!("skip: {authority} unreachable");
        return;
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!("GET /health HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw);

    let (head, body) = text.split_once("\r\n\r\n").expect("HTTP response");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "health must answer 200, got: {}",
        head.lines().next().unwrap_or_default()
    );
    let json: serde_json::Value = serde_json::from_str(body).expect("health must be JSON");
    assert_eq!(json["ok"], true, "health payload: {body}");
    let worker_epoch = json["epoch"].as_u64().expect("epoch must be a number");
    let local = current_epoch();
    let skew = worker_epoch.abs_diff(local);
    assert!(
        skew <= 1,
        "worker epoch {worker_epoch} is {skew} windows from local {local}; \
         realignment cannot help beyond ±1"
    );
}
