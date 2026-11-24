//! Transport-agnostic production driver for [`FileSender`] and [`FileReceiver`].
//!
//! Keeps `luciola-transfer` free of a circular crate dependency on `luciola`
//! while sharing one tested wire driver across `luciola-cli`, `luciola-uniffi`,
//! and `luciola-node`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use luciola_proto::ChannelType;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::protocol::{is_chunk_frame, is_intro_frame, FileAck, FileChunk, FileIntro};
use crate::{FileReceiver, FileSender, ReceiverConfig, SenderConfig, TransferError};

/// Minimal message-oriented ordered transport required by the transfer driver.
///
/// `luciola` implements this trait for `SecureStream` when its `transfer`
/// feature is enabled; unit tests can implement it over in-memory channels.
pub trait TransferTransport: Send {
    /// Send one complete wire frame.
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<(), TransferError>> + Send + 'a;

    /// Receive the next complete wire frame into `buf` (clearing previous contents).
    ///
    /// # Cancel safety
    ///
    /// Implementations **must** be cancellation-safe for `tokio::select!`:
    /// dropping the returned future before completion must not lose or corrupt
    /// partially read bytes from the underlying stream. (`SecureStream::recv`
    /// upholds this via its internal read buffer.)
    fn recv_frame<'a>(
        &'a mut self,
        buf: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<(), TransferError>> + Send + 'a;

    /// Gracefully flush and half-close the outbound transport once a transfer finishes.
    /// Defaults to a no-op for transports that do not distinguish half-close from drop.
    fn shutdown<'a>(&'a mut self) -> impl Future<Output = Result<(), TransferError>> + Send + 'a {
        async { Ok(()) }
    }

    /// Current active transport plane (LAN, hole-punched direct, or encrypted relay).
    fn channel_type(&self) -> ChannelType;

    /// Whether a progressive connection may still upgrade from relay to direct.
    fn may_migrate(&self) -> bool {
        false
    }

    /// Wait up to `timeout` for a progressive channel's routing decision to settle.
    fn wait_channel_settle<'a>(
        &'a mut self,
        timeout: Duration,
    ) -> impl Future<Output = ChannelType> + Send + 'a {
        let _ = timeout;
        let current = self.channel_type();
        async move { current }
    }
}

/// Progress snapshot emitted by [`send_file_over_transport`] and [`recv_file_over_transport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProgress {
    /// Stable identifier for this transfer (used for checkpoint matching).
    pub transfer_id: String,
    /// Contiguous acknowledged bytes so far.
    pub bytes_done: u64,
    /// Total expected bytes.
    pub total_bytes: u64,
    /// Transport plane currently carrying the transfer.
    pub channel_type: ChannelType,
    /// True when this progress update reflects a resumed checkpoint skip.
    pub resumed: bool,
}

/// Final verified receipt returned upon successful transfer completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReceipt {
    /// Stable identifier for this transfer.
    pub transfer_id: String,
    /// Sanitized basename of the transferred file.
    pub file_name: String,
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Lowercase hex SHA-256 of the complete file.
    pub sha256_hex: String,
    /// Destination path on disk (populated on receiver; `None` on sender).
    pub saved_path: Option<PathBuf>,
    /// Final transport plane active when the transfer completed.
    pub channel_type: ChannelType,
}

fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Strip directory components (both `/` and `\`), control/forbidden characters,
/// NTFS alternate data stream separators, and Windows reserved device names so a
/// peer-supplied name can never escape or misbehave inside the target directory.
pub fn sanitize_file_name(name: &str) -> String {
    let last_segment = name
        .split(['/', '\\'])
        .rfind(|s| !s.is_empty())
        .unwrap_or("");
    let cleaned: String = last_segment
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_end_matches([' ', '.']);
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "file".to_string();
    }
    if is_windows_reserved_name(trimmed) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Build a deterministic transfer ID (strictly `<= 255` UTF-8 bytes to fit the
/// wire `u8` length prefix) from file basename, size, and mtime so retries
/// after a drop match the receiver's persisted `.luciola-meta` checkpoint.
pub fn make_transfer_id(file_path: &Path, total_size: u64) -> String {
    let mtime = std::fs::metadata(file_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis());
    let stamp = mtime.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    });
    let base = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let clean = sanitize_file_name(base);
    let suffix = format!("-{total_size}-{stamp}");
    if clean.len() + suffix.len() <= u8::MAX as usize {
        return format!("{clean}{suffix}");
    }
    // Truncate long basenames (e.g. >77 CJK chars) on a UTF-8 boundary and mix
    // in a short hash of the full basename to avoid collisions.
    let digest: [u8; 32] = Sha256::digest(clean.as_bytes()).into();
    let tag = &hex_digest(&digest)[..12];
    let tagged_suffix = format!("-{tag}{suffix}");
    let max_prefix = (u8::MAX as usize).saturating_sub(tagged_suffix.len());
    let mut end = max_prefix.min(clean.len());
    while end > 0 && !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{tagged_suffix}", &clean[..end])
}

/// Decide whether `tx` may proceed on the channel `transport` will actually use.
///
/// Mirrors `DECISIONS.md`: a progressive connection that only exceeds the relay
/// quota waits for hole punching to settle (bounded at 30 s) before judging.
pub async fn admit_transfer<T: TransferTransport>(
    transport: &mut T,
    tx: &FileSender,
) -> Result<(), TransferError> {
    let mut channel = transport.channel_type();
    if tx.check_channel_policy(channel).is_err() && transport.may_migrate() {
        channel = transport.wait_channel_settle(Duration::from_secs(30)).await;
    }
    tx.check_channel_policy(channel)
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn is_cancelled(cancel: &watch::Receiver<bool>) -> bool {
    *cancel.borrow()
}

/// Resolves only when `cancel` actually transitions to `true`. If all senders
/// are dropped while the value is still `false`, this pends forever instead of
/// spuriously cancelling an active transfer.
async fn wait_cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Send one file over `transport` with sliding-window pipelining, resume
/// support, relay-quota admission, progress callbacks, and cooperative cancel.
pub async fn send_file_over_transport<T, F>(
    mut transport: T,
    file_path: &Path,
    file_name: Option<&str>,
    transfer_id: Option<&str>,
    cfg: SenderConfig,
    mut cancel: watch::Receiver<bool>,
    mut on_progress: F,
) -> Result<TransferReceipt, TransferError>
where
    T: TransferTransport,
    F: FnMut(TransferProgress) + Send,
{
    if is_cancelled(&cancel) {
        return Err(TransferError::Cancelled);
    }

    let clean_name = sanitize_file_name(
        file_name
            .or_else(|| file_path.file_name().and_then(|n| n.to_str()))
            .unwrap_or("file"),
    );
    let preliminary_size = tokio::fs::metadata(file_path).await?.len();
    let tid = transfer_id
        .map(str::to_string)
        .unwrap_or_else(|| make_transfer_id(file_path, preliminary_size));

    let mut tx = FileSender::open(&tid, file_path, cfg).await?;
    let total_size = tx.total_size();
    admit_transfer(&mut transport, &tx).await?;

    let intro = FileIntro {
        transfer_id: tid.clone(),
        file_name: clean_name.clone(),
        total_size,
    };
    transport.send_frame(&intro.encode()).await?;

    let mut buf = Vec::new();
    if total_size == 0 {
        // Wait for the receiver's zero-byte ACK (or clean peer EOF from an older
        // receiver) before closing the transport so `FileIntro` is never cut off
        // in flight.
        tokio::select! {
            _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
            res = tokio::time::timeout(Duration::from_secs(2), transport.recv_frame(&mut buf)) => {
                if let Ok(Ok(())) = res {
                    if !is_chunk_frame(&buf) {
                        let _ = FileAck::decode(&buf);
                    }
                }
            }
        }
        on_progress(TransferProgress {
            transfer_id: tid.clone(),
            bytes_done: 0,
            total_bytes: 0,
            channel_type: transport.channel_type(),
            resumed: false,
        });
        let digest = tx.sha256().await?;
        let channel_type = transport.channel_type();
        let _ = transport.shutdown().await;
        return Ok(TransferReceipt {
            transfer_id: tid,
            file_name: clean_name,
            total_bytes: 0,
            sha256_hex: hex_digest(&digest),
            saved_path: None,
            channel_type,
        });
    }

    let mut pending_chunks: std::collections::VecDeque<FileChunk> =
        std::collections::VecDeque::new();

    loop {
        if is_cancelled(&cancel) {
            return Err(TransferError::Cancelled);
        }
        if tx.is_done() {
            let digest = tx.sha256().await?;
            let channel_type = transport.channel_type();
            let _ = transport.shutdown().await;
            return Ok(TransferReceipt {
                transfer_id: tid,
                file_name: clean_name,
                total_bytes: total_size,
                sha256_hex: hex_digest(&digest),
                saved_path: None,
                channel_type,
            });
        }

        if pending_chunks.is_empty() {
            for chunk in tx.fill_window().await? {
                pending_chunks.push_back(chunk);
            }
        }

        // Send at most one chunk per loop turn before polling ACKs/cancel so a
        // slow WAN link cannot fill the send buffer and starve ACK draining.
        if let Some(chunk) = pending_chunks.pop_front() {
            let wire = chunk.encode();
            tokio::select! {
                res = transport.send_frame(&wire) => res?,
                _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
            }
            // If more chunks are queued in the window, quickly poll for an
            // already-arrived ACK without blocking for 100 ms.
            if !pending_chunks.is_empty() {
                tokio::select! {
                    biased;
                    _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
                    frame = transport.recv_frame(&mut buf) => {
                        handle_sender_frame(&mut tx, &mut pending_chunks, &buf, frame, &tid, total_size, transport.channel_type(), &mut on_progress)?;
                    }
                    _ = tokio::task::yield_now() => {}
                }
                continue;
            }
        }

        tokio::select! {
            _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
            frame = transport.recv_frame(&mut buf) => {
                handle_sender_frame(&mut tx, &mut pending_chunks, &buf, frame, &tid, total_size, transport.channel_type(), &mut on_progress)?;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }

        for chunk in tx.expired_in_flight().await? {
            pending_chunks.push_back(chunk);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_sender_frame<F>(
    tx: &mut FileSender,
    pending_chunks: &mut std::collections::VecDeque<FileChunk>,
    buf: &[u8],
    frame: Result<(), TransferError>,
    tid: &str,
    total_size: u64,
    channel_type: ChannelType,
    on_progress: &mut F,
) -> Result<(), TransferError>
where
    F: FnMut(TransferProgress),
{
    frame?;
    if !is_chunk_frame(buf) {
        let ack = FileAck::decode(buf)?;
        if ack.transfer_id != tid {
            return Ok(());
        }
        tx.on_ack(ack.acked_up_to);
        let acked = tx.acked_up_to();
        pending_chunks.retain(|c| c.offset + c.payload.len() as u64 > acked);
        on_progress(TransferProgress {
            transfer_id: tid.to_string(),
            bytes_done: acked,
            total_bytes: total_size,
            channel_type,
            resumed: ack.resume,
        });
    }
    Ok(())
}

/// Receive one file over `transport` into `dest_dir` with absolute-offset
/// writes, checkpoint resume, answer-cache quiet drain, SHA-256 verification,
/// and cooperative cancel.
pub async fn recv_file_over_transport<T, F>(
    mut transport: T,
    dest_dir: &Path,
    cfg: ReceiverConfig,
    quiet: Duration,
    mut cancel: watch::Receiver<bool>,
    mut on_progress: F,
) -> Result<TransferReceipt, TransferError>
where
    T: TransferTransport,
    F: FnMut(TransferProgress) + Send,
{
    if is_cancelled(&cancel) {
        return Err(TransferError::Cancelled);
    }

    let mut buf = Vec::new();
    tokio::select! {
        res = transport.recv_frame(&mut buf) => res?,
        _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
    }

    let intro = if is_intro_frame(&buf) {
        FileIntro::decode(&buf)?
    } else {
        return Err(TransferError::Decode(
            "peer's first message was not a transfer intro".into(),
        ));
    };

    let safe_name = sanitize_file_name(&intro.file_name);
    let dest = dest_dir.join(&safe_name);
    let answer_cache_ttl = cfg.answer_cache_ttl;
    let mut rx = FileReceiver::create(&intro.transfer_id, &dest, intro.total_size, cfg).await?;
    let total = rx.total_size();

    if total == 0 {
        let zero_ack = FileAck {
            transfer_id: rx.transfer_id().to_string(),
            acked_up_to: 0,
            resume: false,
        };
        let _ = transport.send_frame(&zero_ack.encode()).await;
        on_progress(TransferProgress {
            transfer_id: intro.transfer_id.clone(),
            bytes_done: 0,
            total_bytes: 0,
            channel_type: transport.channel_type(),
            resumed: false,
        });
    } else if rx.acked_up_to() > 0 {
        let resume_ack = FileAck {
            transfer_id: rx.transfer_id().to_string(),
            acked_up_to: rx.acked_up_to(),
            resume: true,
        };
        transport.send_frame(&resume_ack.encode()).await?;
        on_progress(TransferProgress {
            transfer_id: intro.transfer_id.clone(),
            bytes_done: rx.acked_up_to(),
            total_bytes: total,
            channel_type: transport.channel_type(),
            resumed: true,
        });
    }

    // Hard upper bound on post-complete quiet draining so a peer continuously
    // sending frames cannot defer `finalize()` indefinitely or outlive
    // `answer_cache_ttl`.
    let max_drain = quiet.saturating_mul(4).min(answer_cache_ttl);
    let mut drain_deadline: Option<tokio::time::Instant> = None;

    loop {
        if is_cancelled(&cancel) {
            return Err(TransferError::Cancelled);
        }
        let already_complete = rx.is_complete();
        if already_complete {
            let deadline =
                *drain_deadline.get_or_insert_with(|| tokio::time::Instant::now() + max_drain);
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let wait = quiet.min(remaining);
            let received = tokio::select! {
                _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
                res = tokio::time::timeout(wait, transport.recv_frame(&mut buf)) => {
                    match res {
                        Ok(Ok(())) => Some(()),
                        _ => None,
                    }
                }
            };
            if received.is_none() {
                break;
            }
        } else {
            tokio::select! {
                _ = wait_cancelled(&mut cancel) => return Err(TransferError::Cancelled),
                res = transport.recv_frame(&mut buf) => res?,
            }
        }

        if !is_chunk_frame(&buf) {
            continue;
        }
        let chunk = match FileChunk::decode(&buf) {
            Ok(c) => c,
            Err(_) if already_complete => break,
            Err(err) => return Err(err),
        };
        let acked = match rx.on_chunk(&chunk).await {
            Ok(a) => a,
            Err(_) if already_complete => break,
            Err(err) => return Err(err),
        };
        on_progress(TransferProgress {
            transfer_id: intro.transfer_id.clone(),
            bytes_done: acked,
            total_bytes: total,
            channel_type: transport.channel_type(),
            resumed: false,
        });
        let ack = FileAck {
            transfer_id: chunk.transfer_id,
            acked_up_to: acked,
            resume: false,
        };
        if let Err(err) = transport.send_frame(&ack.encode()).await {
            if rx.is_complete() {
                break;
            }
            return Err(err);
        }
    }

    let channel_type = transport.channel_type();
    let saved_path = rx.dest().to_path_buf();
    let digest = rx.finalize().await?;
    Ok(TransferReceipt {
        transfer_id: intro.transfer_id,
        file_name: safe_name,
        total_bytes: total,
        sha256_hex: hex_digest(&digest),
        saved_path: Some(saved_path),
        channel_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    struct MemTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
        kind: ChannelType,
    }

    fn mem_pair(kind: ChannelType) -> (MemTransport, MemTransport) {
        let (a_tx, b_rx) = mpsc::channel(64);
        let (b_tx, a_rx) = mpsc::channel(64);
        (
            MemTransport {
                tx: a_tx,
                rx: a_rx,
                kind,
            },
            MemTransport {
                tx: b_tx,
                rx: b_rx,
                kind,
            },
        )
    }

    impl TransferTransport for MemTransport {
        async fn send_frame(&mut self, bytes: &[u8]) -> Result<(), TransferError> {
            self.tx
                .send(bytes.to_vec())
                .await
                .map_err(|_| TransferError::State("transport closed".into()))
        }

        async fn recv_frame(&mut self, buf: &mut Vec<u8>) -> Result<(), TransferError> {
            match self.rx.recv().await {
                Some(data) => {
                    buf.clear();
                    buf.extend_from_slice(&data);
                    Ok(())
                }
                None => Err(TransferError::State("transport eof".into())),
            }
        }

        fn channel_type(&self) -> ChannelType {
            self.kind
        }
    }

    #[tokio::test]
    async fn driver_roundtrips_file_and_verifies_sha256() {
        let dir = std::env::temp_dir().join(format!(
            "luciola_driver_ok_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let src_dir = dir.join("src");
        let dst_dir = dir.join("dst");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        tokio::fs::create_dir_all(&dst_dir).await.unwrap();

        let src = src_dir.join("sample.bin");
        let payload: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
        tokio::fs::write(&src, &payload).await.unwrap();

        let (ta, tb) = mem_pair(ChannelType::LanDirect);
        let (_cancel_tx, cancel_rx_a) = watch::channel(false);
        let cancel_rx_b = cancel_rx_a.clone();

        let dst_dir_clone = dst_dir.clone();
        let recv_task = tokio::spawn(async move {
            recv_file_over_transport(
                tb,
                &dst_dir_clone,
                ReceiverConfig::default(),
                Duration::from_millis(50),
                cancel_rx_b,
                |_| {},
            )
            .await
        });

        let mut progress_seen = 0u64;
        let send_receipt = send_file_over_transport(
            ta,
            &src,
            Some("../../evil/sample.bin"),
            None,
            SenderConfig::default(),
            cancel_rx_a,
            |p| progress_seen = p.bytes_done,
        )
        .await
        .expect("send ok");

        let recv_receipt = recv_task.await.unwrap().expect("recv ok");
        assert_eq!(send_receipt.sha256_hex, recv_receipt.sha256_hex);
        assert_eq!(recv_receipt.file_name, "sample.bin");
        assert_eq!(recv_receipt.saved_path.unwrap(), dst_dir.join("sample.bin"));
        assert_eq!(progress_seen, payload.len() as u64);

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn driver_honors_cancel_signal() {
        let dir = std::env::temp_dir().join(format!(
            "luciola_driver_cancel_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("c.bin");
        tokio::fs::write(&src, vec![7u8; 4096]).await.unwrap();

        let (ta, _tb) = mem_pair(ChannelType::LanDirect);
        let (cancel_tx, cancel_rx) = watch::channel(true);
        drop(cancel_tx);

        let err = send_file_over_transport(
            ta,
            &src,
            None,
            None,
            SenderConfig::default(),
            cancel_rx,
            |_| {},
        )
        .await
        .expect_err("cancelled transfer must error");
        assert!(matches!(err, TransferError::Cancelled), "{err}");

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[test]
    fn sanitize_file_name_handles_cross_platform_hazards() {
        assert_eq!(sanitize_file_name("../../evil/sample.bin"), "sample.bin");
        assert_eq!(sanitize_file_name(r"..\..\evil.txt"), "evil.txt");
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("CON .txt"), "_CON .txt");
        assert_eq!(sanitize_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_file_name("COM1.log"), "_COM1.log");
        assert_eq!(sanitize_file_name("data.txt:ads"), "data.txt_ads");
        assert_eq!(sanitize_file_name("bad\x00name\n.bin"), "bad_name_.bin");
        assert_eq!(sanitize_file_name("trailing. "), "trailing");
        assert_eq!(sanitize_file_name(".."), "file");
        assert_eq!(sanitize_file_name(""), "file");

        // Long UTF-8 basename (100 CJK chars = 300 bytes) must stay <= 255 bytes
        // on a valid UTF-8 boundary so wire `u8` length prefixes never wrap.
        let long_name = format!("{}.bin", "文".repeat(100));
        let tid = make_transfer_id(Path::new(&long_name), 123456);
        assert!(
            tid.len() <= u8::MAX as usize,
            "transfer_id exceeded 255 bytes: {}",
            tid.len()
        );
    }

    #[tokio::test]
    async fn driver_roundtrips_zero_byte_file_without_race() {
        let dir = std::env::temp_dir().join(format!(
            "luciola_driver_zero_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let src_dir = dir.join("src");
        let dst_dir = dir.join("dst");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        tokio::fs::create_dir_all(&dst_dir).await.unwrap();

        let src = src_dir.join("empty.txt");
        tokio::fs::write(&src, b"").await.unwrap();

        let (ta, tb) = mem_pair(ChannelType::LanDirect);
        let (_cancel_tx, cancel_rx_a) = watch::channel(false);
        let cancel_rx_b = cancel_rx_a.clone();
        let dst_clone = dst_dir.clone();
        let recv_task = tokio::spawn(async move {
            recv_file_over_transport(
                tb,
                &dst_clone,
                ReceiverConfig::default(),
                Duration::from_millis(50),
                cancel_rx_b,
                |_| {},
            )
            .await
        });

        let send_receipt = send_file_over_transport(
            ta,
            &src,
            None,
            None,
            SenderConfig::default(),
            cancel_rx_a,
            |_| {},
        )
        .await
        .expect("0-byte send ok");
        let recv_receipt = recv_task.await.unwrap().expect("0-byte recv ok");

        assert_eq!(send_receipt.total_bytes, 0);
        assert_eq!(recv_receipt.total_bytes, 0);
        assert_eq!(send_receipt.sha256_hex, recv_receipt.sha256_hex);
        assert!(dst_dir.join("empty.txt").exists());

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn receiver_drain_bounds_hostile_post_complete_frame_flood() {
        let dir = std::env::temp_dir().join(format!(
            "luciola_driver_flood_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let (mut ta, tb) = mem_pair(ChannelType::LanDirect);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let dir_clone = dir.clone();
        let recv_task = tokio::spawn(async move {
            recv_file_over_transport(
                tb,
                &dir_clone,
                ReceiverConfig::default(),
                Duration::from_millis(40),
                cancel_rx,
                |_| {},
            )
            .await
        });

        // Send a 0-byte intro, then continuously spam non-chunk frames faster than `quiet`.
        let intro = FileIntro {
            transfer_id: "flood-0".into(),
            file_name: "flood.bin".into(),
            total_size: 0,
        };
        ta.send_frame(&intro.encode()).await.unwrap();
        let flooder = tokio::spawn(async move {
            for _ in 0..100 {
                if ta.send_frame(b"spam").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let receipt = tokio::time::timeout(Duration::from_secs(2), recv_task)
            .await
            .expect("drain must terminate within bounded deadline")
            .unwrap()
            .expect("recv finalize ok");
        assert_eq!(receipt.total_bytes, 0);
        flooder.abort();
        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
