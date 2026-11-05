//! `luciola-cli transfer send|recv` —— 给 luciola-transfer 状态机一个真实
//! 生产驱动（此前该 crate 只有测试驱动，README/CHANGELOG 明确标注过）。
//!
//! 传输模型（与 transfer 的 50 MiB E2E 同一模式）：SecureStream 是**面向
//! 消息**的，一帧一消息，无需额外长度前缀。发送方先发 `FileIntro`（接收方
//! 需要提前知道 total_size 才能 `FileReceiver::create`），然后双任务并发泵
//! 两个方向——窗口超过内核 socket 缓冲后，串行驱动必然死锁（E2E 注释里
//! 记录过）。安全姿态沿用 forward：**pin 缺省 = 拒绝连接，无 TOFU**。
//!
//! 接收方对发送方报来的文件名只取 basename：防止 `../../.ssh/...` 之类
//! 的路径穿越写到 --out 目录之外。

use std::time::Duration;

use luciola::link::secure::SecureStream;
use luciola_transfer::protocol::{is_chunk_frame, is_intro_frame, FileAck, FileChunk, FileIntro};
use luciola_transfer::{FileReceiver, FileSender, ReceiverConfig};

/// 发送方驱动：intro → 滑窗 → 消费 ACK → 超时重传，直到 done 或通道死亡。
/// 进度按 acked 前缀打到 stderr（stdout 留给最终摘要）。
pub async fn run_send(
    mut stream: SecureStream,
    mut tx: FileSender,
    file_name: &str,
) -> Result<FileSender, String> {
    let intro = FileIntro {
        transfer_id: tx.transfer_id().to_string(),
        file_name: sanitize_name(file_name),
        total_size: tx.total_size(),
    };
    let total = tx.total_size();
    stream
        .send(&intro.encode())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf: Vec<u8> = Vec::new();
    let mut last_reported = 0u64;
    loop {
        if tx.is_done() {
            return Ok(tx);
        }
        for chunk in tx.fill_window().await.map_err(|e| e.to_string())? {
            stream
                .send(&chunk.encode())
                .await
                .map_err(|e| e.to_string())?;
        }
        tokio::select! {
            // SecureStream::recv 可取消安全（半读帧留在内部缓冲）——E2E 验证过的模式
            frame = stream.recv(&mut buf) => match frame {
                Ok(()) if !is_chunk_frame(&buf) => {
                    let ack = FileAck::decode(&buf).map_err(|e| e.to_string())?;
                    tx.on_ack(ack.acked_up_to);
                    report_progress(total, tx.acked_up_to(), &mut last_reported);
                }
                Ok(()) => {} // 收到 chunk = 对端驱动 bug；忽略等下一帧
                Err(e) => return Err(format!("channel closed at {} / {} bytes: {e}", tx.acked_up_to(), total)),
            },
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        for chunk in tx.expired_in_flight().await.map_err(|e| e.to_string())? {
            stream
                .send(&chunk.encode())
                .await
                .map_err(|e| e.to_string())?;
        }
    }
}

/// 接收方驱动：等 intro → 建 receiver → 按绝对偏移写盘 → 回 ACK 前缀；
/// 完成后从应答缓存服务重传，发送方静默 `quiet` 即返回。
pub async fn run_recv(
    mut stream: SecureStream,
    dest_dir: &std::path::Path,
    quiet: Duration,
) -> Result<FileReceiver, String> {
    let mut buf: Vec<u8> = Vec::new();
    stream.recv(&mut buf).await.map_err(|e| e.to_string())?;
    let intro = if is_intro_frame(&buf) {
        FileIntro::decode(&buf).map_err(|e| e.to_string())?
    } else {
        return Err("peer's first message was not a transfer intro".into());
    };
    // 只取 basename：对端报什么名字都写不进 --out 之外。
    let safe_name = std::path::Path::new(&intro.file_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("received.bin");
    let dest = dest_dir.join(safe_name);

    let mut rx = FileReceiver::create(
        &intro.transfer_id,
        &dest,
        intro.total_size,
        ReceiverConfig::default(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let total = rx.total_size();
    let mut last_reported = 0u64;

    loop {
        if rx.is_complete() {
            // 应答缓存模式：对端静默即收工（E2E 同款）。
            match tokio::time::timeout(quiet, stream.recv(&mut buf)).await {
                Ok(Ok(())) => { /* 落到下面的分派 */ }
                _ => return Ok(rx),
            }
        } else {
            stream.recv(&mut buf).await.map_err(|e| {
                format!(
                    "peer closed before transfer complete ({} / {} bytes): {e}",
                    rx.acked_up_to(),
                    total
                )
            })?;
        }
        if !is_chunk_frame(&buf) {
            continue;
        }
        let chunk = FileChunk::decode(&buf).map_err(|e| e.to_string())?;
        let acked = rx.on_chunk(&chunk).await.map_err(|e| e.to_string())?;
        report_progress(total, acked, &mut last_reported);
        stream
            .send(
                &FileAck {
                    transfer_id: chunk.transfer_id.clone(),
                    acked_up_to: acked,
                }
                .encode(),
            )
            .await
            .map_err(|e| e.to_string())?;
    }
}

/// 每 ≥5% 或首帧打一行进度到 stderr。
fn report_progress(total: u64, acked: u64, last_reported: &mut u64) {
    let pct = if total == 0 { 100 } else { acked * 100 / total };
    let last_pct = if total == 0 {
        100
    } else {
        *last_reported * 100 / total
    };
    if pct >= last_pct + 5 || (*last_reported == 0 && acked > 0) {
        eprintln!("  ⏳ {}/{} bytes ({}%)", acked, total, pct);
        *last_reported = acked;
    }
}

/// 传输 ID：文件名 + 大小 + 毫秒时间戳，够用来区分同会话内的多次传输。
pub(crate) fn make_transfer_id(file_name: &str, total_size: u64) -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{}-{}-{ms}", sanitize_name(file_name), total_size)
}

fn sanitize_name(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string()
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::{make_transfer_id, run_recv, run_send, sanitize_name, FileSender};
    use luciola::link::secure::{accept_secure, SecureStream};
    use luciola::trust::generate_identity;
    use luciola_transfer::protocol::FileIntro;
    use luciola_transfer::SenderConfig;
    use std::sync::Arc;
    use std::time::Duration;

    /// 测试同款回环：真实 X25519+Ed25519 握手 + loopback TCP。
    async fn secure_pair() -> (SecureStream, SecureStream) {
        let a = generate_identity();
        let b = generate_identity();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server: tokio::task::JoinHandle<SecureStream> = tokio::spawn(async move {
            accept_secure(&listener, &seed_b, Some(&key_a))
                .await
                .unwrap()
        });
        let client =
            luciola::link::secure::connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
                .await
                .expect("client handshake");
        let server = server.await.expect("server task");
        (client, server)
    }

    #[test]
    fn sanitize_name_strips_directories() {
        assert_eq!(sanitize_name("../../.ssh/id_ed25519"), "id_ed25519");
        assert_eq!(sanitize_name("normal.bin"), "normal.bin");
        assert_eq!(sanitize_name("/abs/path/file"), "file");
    }

    #[test]
    fn transfer_id_is_stable_per_file_shape() {
        let a = make_transfer_id("a.bin", 100);
        assert!(a.starts_with("a.bin-100-"), "{a}");
    }

    /// 端到端：512 KiB 经真实 SecureStream 落盘，字节完全一致。
    /// 收发各一个任务并发泵（串行会在窗口 > socket 缓冲时死锁，E2E 记录过）。
    #[tokio::test(flavor = "multi_thread")]
    async fn send_recv_roundtrip_over_real_secure_stream() {
        let dir = std::env::temp_dir().join(format!("luciola-cli-transfer-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("hello.bin");
        let out = dir.join("out");
        tokio::fs::create_dir_all(&out).await.unwrap();

        let payload: Arc<Vec<u8>> = Arc::new((0..512 * 1024u32).map(|i| (i % 251) as u8).collect());
        tokio::fs::write(&src, payload.as_slice()).await.unwrap();

        let (client, server) = secure_pair().await;
        let id = make_transfer_id("hello.bin", payload.len() as u64);
        let tx = FileSender::open(
            &id,
            &src,
            SenderConfig {
                chunk_size: 64 * 1024,
                window: 8,
                retransmit_after: Duration::from_millis(200),
            },
        )
        .await
        .unwrap();

        // intro 里带文件名，接收方按它落盘（basename 已消毒）。
        let sender = tokio::spawn(async move {
            let tx = run_send(client, tx, "hello.bin")
                .await
                .expect("send driver");
            tx
        });
        let out2 = out.clone();
        let receiver =
            tokio::spawn(async move { run_recv(server, &out2, Duration::from_millis(500)).await });

        let _tx = sender.await.unwrap();
        let rx = receiver.await.unwrap().expect("recv driver");
        assert!(rx.is_complete());
        assert_eq!(rx.acked_up_to(), payload.len() as u64);
        let dest = out.join("hello.bin");
        let got = tokio::fs::read(&dest).await.unwrap();
        assert_eq!(got.len(), payload.len(), "byte count must match");
        assert_eq!(got, *payload, "bytes must match");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    /// 路径穿越防线:恶意发送方报 `../../evil.txt`,落盘必须只在 --out 下,
    /// 且父目录不出现文件。
    #[tokio::test(flavor = "multi_thread")]
    async fn receiver_never_escapes_the_out_dir() {
        use luciola_transfer::protocol::FileChunk;
        let dir = std::env::temp_dir().join(format!("luciola-cli-xform-{}", std::process::id()));
        let out = dir.join("out");
        tokio::fs::create_dir_all(&out).await.unwrap();
        let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
        let total = payload.len() as u64;

        let (mut evil, server) = secure_pair().await;
        let id = format!("xform-{}", std::process::id());
        let evil_intro = FileIntro {
            transfer_id: id.clone(),
            file_name: "../../evil.txt".into(),
            total_size: total,
        };
        let chunk = FileChunk {
            transfer_id: id,
            offset: 0,
            total_size: total,
            payload: payload.clone(),
        };

        let out2 = out.clone();
        let receiver =
            tokio::spawn(async move { run_recv(server, &out2, Duration::from_millis(400)).await });
        // 恶意"发送方":手写 intro + 单 chunk(ACK 由 socket 缓冲吸收,量极小)。
        evil.send(&evil_intro.encode()).await.unwrap();
        evil.send(&chunk.encode()).await.unwrap();

        let rx = receiver.await.unwrap().expect("recv driver must complete");
        assert!(
            rx.is_complete(),
            "traversal-targeted transfer must still complete"
        );
        let landed = out.join("evil.txt");
        assert!(
            tokio::fs::metadata(&landed).await.is_ok(),
            "file must land at the sanitized basename inside --out"
        );
        assert_eq!(tokio::fs::read(&landed).await.unwrap(), payload);
        assert!(
            tokio::fs::metadata(dir.join("evil.txt")).await.is_err(),
            "no file may escape --out via ../"
        );
        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
