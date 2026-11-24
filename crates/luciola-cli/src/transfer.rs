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

/// Decide whether this transfer may proceed on the channel it will actually use.
///
/// A progressive connection starts on the relay and migrates to a direct path
/// shortly afterwards. Judging the relay quota on that transient hop rejects a
/// 200 MiB file that is about to travel over a free path, so a file that only
/// fails on the relay waits, bounded, for the migration to land first. A
/// connection that cannot migrate is judged immediately — the quota still
/// exists, it is just not applied to a hop the data never crosses.
async fn admit(stream: &mut SecureStream, tx: &FileSender) -> Result<(), String> {
    luciola_transfer::admit_transfer(stream, tx)
        .await
        .map_err(|e| e.to_string())
}

/// 发送方驱动：intro → 滑窗 → 消费 ACK → 超时重传，直到 done 或通道死亡。
/// 进度按 acked 前缀打到 stderr（stdout 留给最终摘要）。
pub async fn run_send(
    mut stream: SecureStream,
    mut tx: FileSender,
    file_name: &str,
) -> Result<FileSender, String> {
    // Enforce the relay quota *before* the first byte leaves the device. A
    // relay is a billed third-party path; without this check SenderConfig's
    // limit would exist in the type but never be applied by the real driver.
    admit(&mut stream, &tx).await?;

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
    let mut last_channel_type = stream.channel_type();
    eprintln!("[INFO] Active channel: {}", last_channel_type.as_str());

    if total == 0 {
        // Wait briefly for the receiver's zero-byte ACK (or clean EOF) before
        // closing the stream so `FileIntro` is never dropped in flight.
        if let Ok(Ok(())) =
            tokio::time::timeout(Duration::from_secs(2), stream.recv(&mut buf)).await
        {
            if !is_chunk_frame(&buf) {
                let _ = FileAck::decode(&buf);
            }
        }
        let _ = stream.shutdown().await;
        return Ok(tx);
    }

    let mut pending_chunks: std::collections::VecDeque<FileChunk> =
        std::collections::VecDeque::new();
    loop {
        let current_channel = stream.channel_type();
        if current_channel != last_channel_type {
            eprintln!(
                "[INFO] Channel upgraded: {} -> {}!",
                last_channel_type.as_str(),
                current_channel.as_str()
            );
            last_channel_type = current_channel;
        }

        if tx.is_done() {
            let _ = stream.shutdown().await;
            return Ok(tx);
        }
        if pending_chunks.is_empty() {
            for chunk in tx.fill_window().await.map_err(|e| e.to_string())? {
                pending_chunks.push_back(chunk);
            }
        }
        // Write at most one chunk per loop turn before polling ACKs so a slow
        // WAN link never deadlocks by filling the send buffer without draining.
        if let Some(chunk) = pending_chunks.pop_front() {
            stream
                .send(&chunk.encode())
                .await
                .map_err(|e| e.to_string())?;
            if !pending_chunks.is_empty() {
                tokio::select! {
                    biased;
                    frame = stream.recv(&mut buf) => {
                        handle_cli_ack(&mut tx, &mut pending_chunks, &buf, frame, total, &mut last_reported)?;
                    }
                    _ = tokio::task::yield_now() => {}
                }
                continue;
            }
        }
        tokio::select! {
            // SecureStream::recv 可取消安全（半读帧留在内部缓冲）——E2E 验证过的模式
            frame = stream.recv(&mut buf) => {
                handle_cli_ack(&mut tx, &mut pending_chunks, &buf, frame, total, &mut last_reported)?;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        for chunk in tx.expired_in_flight().await.map_err(|e| e.to_string())? {
            pending_chunks.push_back(chunk);
        }
    }
}

fn handle_cli_ack(
    tx: &mut FileSender,
    pending_chunks: &mut std::collections::VecDeque<FileChunk>,
    buf: &[u8],
    frame: Result<(), luciola::link::secure::LinkError>,
    total: u64,
    last_reported: &mut u64,
) -> Result<(), String> {
    match frame {
        Ok(()) if !is_chunk_frame(buf) => {
            let ack = FileAck::decode(buf).map_err(|e| e.to_string())?;
            if ack.transfer_id != tx.transfer_id() {
                return Ok(());
            }
            if ack.resume {
                eprintln!(
                    "[INFO] Remote peer requested resume: skipping {}/{} bytes ({:.1}%)",
                    ack.acked_up_to,
                    total,
                    (ack.acked_up_to as f64 / total.max(1) as f64) * 100.0
                );
            }
            tx.on_ack(ack.acked_up_to);
            let acked = tx.acked_up_to();
            pending_chunks.retain(|c| c.offset + c.payload.len() as u64 > acked);
            report_progress(total, acked, last_reported);
            Ok(())
        }
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "channel closed at {} / {} bytes: {e}",
            tx.acked_up_to(),
            total
        )),
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
    // Cross-platform basename sanitization: blocks `/`, `\`, NTFS ADS `:`, and
    // Windows reserved device names (`CON`, `NUL`, etc.).
    let safe_name = sanitize_name(&intro.file_name);
    let dest = dest_dir.join(safe_name);

    let cfg = ReceiverConfig::default();
    let answer_cache_ttl = cfg.answer_cache_ttl;
    let mut rx = FileReceiver::create(&intro.transfer_id, &dest, intro.total_size, cfg)
        .await
        .map_err(|e| e.to_string())?;
    let total = rx.total_size();
    let mut last_reported = 0u64;

    if total == 0 {
        let zero_ack = FileAck {
            transfer_id: rx.transfer_id().to_string(),
            acked_up_to: 0,
            resume: false,
        };
        let _ = stream.send(&zero_ack.encode()).await;
    } else if rx.acked_up_to() > 0 {
        eprintln!(
            "[INFO] Resuming transfer from checkpoint: {}/{} bytes ({:.1}%) already on disk",
            rx.acked_up_to(),
            total,
            (rx.acked_up_to() as f64 / total.max(1) as f64) * 100.0
        );
        let resume_ack = FileAck {
            transfer_id: rx.transfer_id().to_string(),
            acked_up_to: rx.acked_up_to(),
            resume: true,
        };
        stream
            .send(&resume_ack.encode())
            .await
            .map_err(|e| e.to_string())?;
        last_reported = rx.acked_up_to();
    }

    let max_drain = quiet.saturating_mul(4).min(answer_cache_ttl);
    let mut drain_deadline: Option<tokio::time::Instant> = None;

    loop {
        let already_complete = rx.is_complete();
        if already_complete {
            let deadline =
                *drain_deadline.get_or_insert_with(|| tokio::time::Instant::now() + max_drain);
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(rx);
            }
            let wait = quiet.min(remaining);
            // 应答缓存模式：对端静默或达到总上限即收工（E2E 同款）。
            match tokio::time::timeout(wait, stream.recv(&mut buf)).await {
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
        let chunk = match FileChunk::decode(&buf) {
            Ok(c) => c,
            Err(_) if already_complete => return Ok(rx),
            Err(e) => return Err(e.to_string()),
        };
        let acked = match rx.on_chunk(&chunk).await {
            Ok(a) => a,
            Err(_) if already_complete => return Ok(rx),
            Err(e) => return Err(e.to_string()),
        };
        report_progress(total, acked, &mut last_reported);
        let ack = FileAck {
            transfer_id: chunk.transfer_id.clone(),
            acked_up_to: acked,
            resume: false,
        };
        if let Err(e) = stream.send(&ack.encode()).await {
            // The sender can hang up the moment its final ACK is in hand. A
            // failed write *after* completion means the answer was already
            // delivered — reporting it as a transfer failure would turn a
            // successful download into a non-zero exit.
            if rx.is_complete() {
                return Ok(rx);
            }
            return Err(e.to_string());
        }
    }
}

/// 每 ≥5% 或首帧打一行进度到 stderr。
fn report_progress(total: u64, acked: u64, last_reported: &mut u64) {
    let pct = (acked * 100).checked_div(total).unwrap_or(100);
    let last_pct = (*last_reported * 100).checked_div(total).unwrap_or(100);
    if pct >= last_pct + 5 || (*last_reported == 0 && acked > 0) {
        eprintln!("  ⏳ {}/{} bytes ({}%)", acked, total, pct);
        *last_reported = acked;
    }
}

/// 传输 ID：文件名 + 大小 + 文件修改时间（若无则取当前时间）。
/// 基于真实文件的属性生成稳定的传输 ID，使得传输意外中断后重新发起时
/// 能够命中已存在的断点（.luciola-meta / .luciola-part），实现跨进程断点续传。
pub(crate) fn make_transfer_id(file_name: &str, total_size: u64) -> String {
    luciola_transfer::make_transfer_id(std::path::Path::new(file_name), total_size)
}

fn sanitize_name(name: &str) -> String {
    luciola_transfer::sanitize_file_name(name)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::{admit, make_transfer_id, run_recv, run_send, sanitize_name, FileSender};
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

    /// A 120 MiB transfer must not be rejected on the relay hop it is about to
    /// leave. The file is sparse: only its length matters here.
    #[tokio::test(flavor = "multi_thread")]
    async fn large_transfer_is_admitted_once_the_channel_migrates() {
        use luciola_proto::ChannelType;
        use std::sync::atomic::{AtomicU8, Ordering};

        let dir =
            std::env::temp_dir().join(format!("luciola-cli-quota-migrate-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("big.bin");
        let file = tokio::fs::File::create(&src).await.unwrap();
        file.set_len(120 * 1024 * 1024).await.unwrap();
        drop(file);

        let (mut client, _server) = secure_pair().await;
        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        client.set_channel_tracker(tracker.clone());
        assert!(client.may_migrate());

        let tx = FileSender::open("big", &src, SenderConfig::default())
            .await
            .unwrap();
        // Over the 100 MiB relay quota: this is exactly the case that used to
        // be refused before the punch had a chance to succeed.
        assert!(tx
            .check_channel_policy(ChannelType::RelayForwarded)
            .is_err());

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            tracker.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
        });
        admit(&mut client, &tx)
            .await
            .expect("a migrating connection must not be judged on its transient relay hop");

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    /// Negative control: the quota still applies to a connection that really is
    /// relay-only. Otherwise "fix" would just mean "delete the limit".
    #[tokio::test(flavor = "multi_thread")]
    async fn large_transfer_over_a_pure_relay_is_still_refused() {
        use luciola_proto::ChannelType;

        let dir = std::env::temp_dir().join(format!("luciola-cli-quota2-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("big.bin");
        let file = tokio::fs::File::create(&src).await.unwrap();
        file.set_len(120 * 1024 * 1024).await.unwrap();
        drop(file);

        let (mut client, _server) = secure_pair().await;
        client.set_channel_type(ChannelType::RelayForwarded);
        assert!(!client.may_migrate());

        let tx = FileSender::open("big", &src, SenderConfig::default())
            .await
            .unwrap();
        let err = admit(&mut client, &tx).await.unwrap_err();
        assert!(err.contains("exceeds limit"), "{err}");

        tokio::fs::remove_dir_all(&dir).await.ok();
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
                ..Default::default()
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

    /// Relay 配额必须在 intro 之前生效：被拒时链路上不能出现任何数据帧。
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_quota_is_enforced_before_the_first_frame() {
        let dir = std::env::temp_dir().join(format!("luciola-cli-quota-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("big.bin");
        tokio::fs::write(&src, vec![0u8; 4096]).await.unwrap();

        let (mut client, mut server) = secure_pair().await;
        client.set_channel_type(luciola_proto::ChannelType::RelayForwarded);
        let tx = FileSender::open(
            "quota-check",
            &src,
            SenderConfig {
                relay_max_bytes: Some(1024),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let err = match run_send(client, tx, "big.bin").await {
            Ok(_) => panic!("relay quota must deny an oversized file"),
            Err(e) => e,
        };
        assert!(err.contains("exceeds limit"), "{err}");

        let mut buf = Vec::new();
        let received = tokio::time::timeout(Duration::from_secs(1), server.recv(&mut buf)).await;
        assert!(
            !matches!(received, Ok(Ok(()))),
            "no intro frame may be sent before the channel quota check"
        );
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
