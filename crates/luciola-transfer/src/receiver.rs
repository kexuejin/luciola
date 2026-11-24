//! Receiving side: absolute-offset writes, contiguous-prefix ACK, SHA-256
//! receipt, and the 30-second post-completion answer cache.

use crate::checkpoint::{self, TransferMeta};
use crate::protocol::FileChunk;
use crate::TransferError;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

/// Target number of checkpoint writes for one transfer.
///
/// The interval is derived from the chunk count, not fixed: a ten-chunk file
/// checkpoints every chunk (a 2-byte bitmap), while a 3200-chunk file
/// checkpoints 64 times instead of 3200. Writing the whole bitmap per chunk is
/// O(n^2) I/O; writing it before the data is flushed can record bytes that a
/// power loss erases. Bounding the write count fixes the first, the fsync
/// ordering fixes the second.
const CHECKPOINT_WRITES_TARGET: u32 = 64;

/// Default safety ceiling on an accepted inbound file size (16 GiB).
/// Callers needing larger transfers can raise or clear [`ReceiverConfig::max_file_size`].
pub const DEFAULT_MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// Tunables for [`FileReceiver`].
#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// How long after completion a retransmitted tail chunk still earns the
    /// final ACK back (guards the sender against a lost last ACK).
    pub answer_cache_ttl: Duration,
    /// Optional ceiling on `total_size` accepted by [`FileReceiver::create`].
    /// Guards against a hostile intro forcing huge disk preallocation or bitmap RAM.
    pub max_file_size: Option<u64>,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            answer_cache_ttl: Duration::from_secs(30),
            max_file_size: Some(DEFAULT_MAX_FILE_SIZE),
        }
    }
}

#[derive(Debug)]
struct Interval {
    start: u64,
    end: u64,
}

/// Stateful receiver for ONE file transfer. Single-task by design: `on_chunk`
/// takes `&mut self`, so the owning driver is the only writer.
pub struct FileReceiver {
    transfer_id: String,
    total_size: u64,
    dest: std::path::PathBuf,
    part_path: std::path::PathBuf,
    meta_path: std::path::PathBuf,
    /// Open write handle to `part_path`; closed and dropped before atomic rename
    /// to `dest` so Windows volumes never hit `ERROR_SHARING_VIOLATION`.
    file: Option<File>,
    /// Merged, sorted received intervals. `[0, acked)` is always fully
    /// covered by the first interval when it starts at 0.
    intervals: Vec<Interval>,
    completed_at: Option<Instant>,
    config: ReceiverConfig,
    meta: TransferMeta,
    chunks_since_checkpoint: u32,
}

impl FileReceiver {
    /// Create destination file (or resume from `.luciola-meta` checkpoint) and prepare for `total_size`.
    pub async fn create(
        transfer_id: &str,
        dest: impl Into<std::path::PathBuf>,
        total_size: u64,
        config: ReceiverConfig,
    ) -> Result<Self, TransferError> {
        if let Some(limit) = config.max_file_size {
            if total_size > limit {
                return Err(TransferError::State(format!(
                    "declared file size ({total_size} bytes) exceeds receiver limit ({limit} bytes)"
                )));
            }
        }
        let max_bitmap_bytes =
            (checkpoint::MAX_CHUNK_COUNT as u64) * (checkpoint::DEFAULT_CHUNK_SIZE as u64);
        if total_size > max_bitmap_bytes {
            return Err(TransferError::State(format!(
                "declared file size ({total_size} bytes) exceeds checkpoint bitmap capacity ({max_bitmap_bytes} bytes)"
            )));
        }
        let dest = dest.into();
        let part_path = checkpoint::part_path_for(&dest);
        let meta_path = checkpoint::meta_path_for(&dest);

        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let mut resumed_meta: Option<TransferMeta> = None;
        if meta_path.exists() && part_path.exists() {
            let part_len = tokio::fs::metadata(&part_path).await.ok().map(|m| m.len());
            if part_len == Some(total_size) {
                if let Ok(data) = tokio::fs::read(&meta_path).await {
                    if let Some(meta) = TransferMeta::decode(&data, transfer_id) {
                        if meta.total_bytes == total_size {
                            resumed_meta = Some(meta);
                        }
                    }
                }
            }
        }

        let (file, meta, intervals) = if let Some(meta) = resumed_meta {
            let file = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&part_path)
                .await?;
            let contiguous = meta.contiguous_bytes();
            let intervals = if contiguous > 0 {
                vec![Interval {
                    start: 0,
                    end: contiguous,
                }]
            } else {
                Vec::new()
            };
            tracing::info!(
                transfer = %transfer_id,
                contiguous,
                "resumed transfer from persistent checkpoint"
            );
            (file, meta, intervals)
        } else {
            let file = File::create(&part_path).await?;
            file.set_len(total_size).await?;
            let meta = TransferMeta::new(transfer_id, total_size, checkpoint::DEFAULT_CHUNK_SIZE);
            let meta_bytes = meta.encode();
            let _ = tokio::fs::write(&meta_path, meta_bytes).await;
            (file, meta, Vec::new())
        };

        let mut rx = Self {
            transfer_id: transfer_id.to_string(),
            total_size,
            dest,
            part_path,
            meta_path,
            file: Some(file),
            intervals,
            completed_at: None,
            config,
            meta,
            chunks_since_checkpoint: 0,
        };
        // Zero-byte files and 100%-resumed checkpoints are already complete
        // without receiving any further chunks: flush, close the write handle,
        // and commit the atomic rename now so `dest` exists on disk.
        if rx.is_complete() {
            rx.commit_rename().await?;
        }
        Ok(rx)
    }

    async fn commit_rename(&mut self) -> Result<(), TransferError> {
        if let Some(file) = self.file.take() {
            file.sync_data().await?;
            drop(file);
        }
        self.chunks_since_checkpoint = 0;
        tokio::fs::rename(&self.part_path, &self.dest).await?;
        let _ = tokio::fs::remove_file(&self.meta_path).await;
        self.completed_at = Some(Instant::now());
        Ok(())
    }

    /// Identifier of the transfer being received.
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Declared total size in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Contiguous prefix written so far.
    ///
    /// Not necessarily on disk yet: the checkpoint is persisted in batches (see
    /// [`CHECKPOINT_WRITES_TARGET`]) and only after a data fsync, so a crash can
    /// cost a re-send but never resume past bytes that were not written.
    pub fn acked_up_to(&self) -> u64 {
        match self.intervals.first() {
            Some(i) if i.start == 0 => i.end,
            _ => 0,
        }
    }

    /// Whether the whole file has been written and acked.
    pub fn is_complete(&self) -> bool {
        self.acked_up_to() >= self.total_size
    }

    /// Write one chunk at its ABSOLUTE offset.
    ///
    /// Duplicates and out-of-order arrivals are fine: the write is
    /// idempotent and the interval map re-merges. Returns the (possibly
    /// unchanged) contiguous prefix — the caller turns it into a `FileAck`.
    /// After completion this answers from the 30 s cache instead of writing.
    pub async fn on_chunk(&mut self, chunk: &FileChunk) -> Result<u64, TransferError> {
        if chunk.transfer_id != self.transfer_id {
            return Err(TransferError::State(format!(
                "chunk for transfer '{}' reached receiver of '{}'",
                chunk.transfer_id, self.transfer_id
            )));
        }

        // Completed: only the answer cache is left to serve.
        if let Some(at) = self.completed_at {
            if at.elapsed() <= self.config.answer_cache_ttl {
                return Ok(self.total_size);
            }
            return Err(TransferError::State(
                "transfer complete but answer cache expired".into(),
            ));
        }

        let end = chunk
            .offset
            .checked_add(chunk.payload.len() as u64)
            .ok_or_else(|| TransferError::Decode("offset overflow".into()))?;
        if end > self.total_size {
            return Err(TransferError::State(format!(
                "chunk [{}, {}) exceeds total size {}",
                chunk.offset, end, self.total_size
            )));
        }

        if !chunk.payload.is_empty() {
            let file = self.file.as_mut().ok_or_else(|| {
                TransferError::State("receiver file handle already closed".into())
            })?;
            file.seek(std::io::SeekFrom::Start(chunk.offset)).await?;
            file.write_all(&chunk.payload).await?;
        }

        self.insert_interval(chunk.offset, end);
        self.meta.mark_range(chunk.offset, chunk.payload.len());

        // Batched, and only after the bytes it describes are on disk.
        self.chunks_since_checkpoint += 1;
        let interval = (self.meta.chunk_count / CHECKPOINT_WRITES_TARGET).max(1);
        if self.chunks_since_checkpoint >= interval {
            self.persist_checkpoint().await?;
        }

        if self.is_complete() {
            // Durability point: sync and close write handle before atomic rename
            // so Windows volumes never fail with sharing violations.
            self.commit_rename().await?;
            tracing::info!(
                transfer = %self.transfer_id,
                size = self.total_size,
                "transfer complete; answer cache open"
            );
        }
        Ok(self.acked_up_to())
    }

    /// Flush data, then the bitmap that describes it.
    ///
    /// Order matters: a checkpoint written before the fsync can claim chunks
    /// that a power loss will erase, and a resumed transfer would then skip
    /// them, leaving a hole that no checksum covers.
    async fn persist_checkpoint(&mut self) -> Result<(), TransferError> {
        if let Some(file) = self.file.as_ref() {
            file.sync_data().await?;
        }
        let _ = tokio::fs::write(&self.meta_path, self.meta.encode()).await;
        self.chunks_since_checkpoint = 0;
        Ok(())
    }

    /// Read the finished file back and compute its SHA-256.
    ///
    /// Only valid after [`Self::is_complete`] — the answer cache may serve
    /// ACKs, but the receipt is computed once, here.
    pub async fn finalize(self) -> Result<[u8; 32], TransferError> {
        if !self.is_complete() {
            return Err(TransferError::State("finalize before completion".into()));
        }
        let mut file = File::open(&self.dest).await?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().into())
    }

    /// Destination path this receiver writes to.
    pub fn dest(&self) -> &std::path::Path {
        &self.dest
    }

    fn insert_interval(&mut self, start: u64, end: u64) {
        if start == end {
            return;
        }
        let mut merged: Vec<Interval> = Vec::with_capacity(self.intervals.len() + 1);
        let mut cur = Interval { start, end };
        for i in std::mem::take(&mut self.intervals) {
            if i.end < cur.start {
                merged.push(i);
            } else if cur.end < i.start {
                merged.push(cur);
                cur = i;
            } else {
                // Overlap/adjacent: merge into cur.
                cur.start = cur.start.min(i.start);
                cur.end = cur.end.max(i.end);
            }
        }
        merged.push(cur);
        self.intervals = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FileChunk;

    fn chunk(offset: u64, payload: &[u8]) -> FileChunk {
        FileChunk {
            transfer_id: "t".into(),
            offset,
            total_size: 16,
            payload: payload.to_vec(),
        }
    }

    #[tokio::test]
    async fn writes_at_absolute_offset_not_append_order() {
        let dir = std::env::temp_dir().join(format!("luciola-tr-{}-{}", std::process::id(), "t1"));
        let dest = dir.join("offset.bin");
        let mut rx = FileReceiver::create("t", &dest, 16, ReceiverConfig::default())
            .await
            .unwrap();

        // Reverse order: tail half first, head half second.
        assert_eq!(rx.on_chunk(&chunk(8, &[0xAA; 8])).await.unwrap(), 0);
        assert!(!rx.is_complete());
        assert_eq!(rx.on_chunk(&chunk(0, &[0xBB; 8])).await.unwrap(), 16);
        assert!(rx.is_complete());

        let bytes = tokio::fs::read(&dest).await.unwrap();
        assert_eq!(&bytes[..8], &[0xBB; 8]);
        assert_eq!(&bytes[8..], &[0xAA; 8]);
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn duplicate_chunks_are_idempotent() {
        let dir = std::env::temp_dir().join(format!("luciola-tr-{}-{}", std::process::id(), "t2"));
        let dest = dir.join("dup.bin");
        let mut rx = FileReceiver::create("t", &dest, 8, ReceiverConfig::default())
            .await
            .unwrap();
        for _ in 0..3 {
            assert_eq!(rx.on_chunk(&chunk(0, &[1u8; 4])).await.unwrap(), 4);
        }
        assert_eq!(rx.on_chunk(&chunk(4, &[2u8; 4])).await.unwrap(), 8);
        assert!(rx.is_complete());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn answer_cache_serves_retransmits_after_completion() {
        let dir = std::env::temp_dir().join(format!("luciola-tr-{}-{}", std::process::id(), "t3"));
        let dest = dir.join("cache.bin");
        let cfg = ReceiverConfig {
            answer_cache_ttl: Duration::from_secs(30),
            ..Default::default()
        };
        let mut rx = FileReceiver::create("t", &dest, 8, cfg).await.unwrap();
        rx.on_chunk(&chunk(0, &[9u8; 8])).await.unwrap();
        assert!(rx.is_complete());

        // A lost-final-ACK retransmit arrives after completion: still answered.
        let ack = rx.on_chunk(&chunk(0, &[9u8; 8])).await.unwrap();
        assert_eq!(ack, 8);
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn out_of_bounds_chunk_rejected() {
        let dir = std::env::temp_dir().join(format!("luciola-tr-{}-{}", std::process::id(), "t4"));
        let dest = dir.join("oob.bin");
        let mut rx = FileReceiver::create("t", &dest, 8, ReceiverConfig::default())
            .await
            .unwrap();
        assert!(rx.on_chunk(&chunk(4, &[0u8; 8])).await.is_err());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn interval_merging() {
        let dir = std::env::temp_dir().join(format!("luciola-tr-{}-{}", std::process::id(), "t5"));
        let dest = dir.join("intervals.bin");
        let mut rx = FileReceiver::create("t", &dest, 100, ReceiverConfig::default())
            .await
            .unwrap();
        rx.insert_interval(10, 20);
        rx.insert_interval(30, 40);
        // Covered so far: [10, 40) — does not start at 0, so no prefix credit.
        assert_eq!(rx.acked_up_to(), 0);
        rx.insert_interval(20, 30); // bridges the gap -> [10, 40)
        assert_eq!(rx.acked_up_to(), 0);
        rx.insert_interval(0, 10); // -> [0, 40)
        assert_eq!(rx.acked_up_to(), 40);
        rx.insert_interval(40, 100);
        assert!(rx.is_complete());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn resuming_transfer_from_interrupted_checkpoint_skips_completed_chunks() {
        let dir = std::env::temp_dir().join(format!("luciola-tr-resume-{}", std::process::id()));
        let dest = dir.join("resume_test.bin");
        let total = 640 * 1024u64; // 640 KiB
        let full_payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();

        // 1. Initial receiver receives first half (320 KiB)
        {
            let mut rx1 =
                FileReceiver::create("test_resumable", &dest, total, ReceiverConfig::default())
                    .await
                    .unwrap();
            for i in 0..5 {
                let offset = i * 64 * 1024;
                let c = FileChunk {
                    transfer_id: "test_resumable".into(),
                    offset,
                    total_size: total,
                    payload: full_payload[offset as usize..(offset as usize + 64 * 1024)].to_vec(),
                };
                rx1.on_chunk(&c).await.unwrap();
            }
            assert_eq!(rx1.acked_up_to(), 320 * 1024);
            assert!(!rx1.is_complete());
            // rx1 is dropped here without completion, simulating process crash
        }

        // Verify .part and .meta files exist on disk
        let part_file = checkpoint::part_path_for(&dest);
        let meta_file = checkpoint::meta_path_for(&dest);
        assert!(part_file.exists(), ".part file must exist after crash");
        assert!(meta_file.exists(), ".meta file must exist after crash");
        assert!(
            !dest.exists(),
            "destination file must not exist prematurely"
        );

        // 2. Second receiver resumes the same transfer
        {
            let mut rx2 =
                FileReceiver::create("test_resumable", &dest, total, ReceiverConfig::default())
                    .await
                    .unwrap();
            // Restored acked_up_to should immediately be 320 KiB
            assert_eq!(rx2.acked_up_to(), 320 * 1024);
            assert!(!rx2.is_complete());

            // Receive remaining half (320 KiB to 640 KiB)
            for i in 5..10 {
                let offset = i * 64 * 1024;
                let c = FileChunk {
                    transfer_id: "test_resumable".into(),
                    offset,
                    total_size: total,
                    payload: full_payload[offset as usize..(offset as usize + 64 * 1024)].to_vec(),
                };
                rx2.on_chunk(&c).await.unwrap();
            }
            assert!(rx2.is_complete());
            assert_eq!(rx2.acked_up_to(), total);

            let receipt = rx2.finalize().await.unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&full_payload);
            let expected_receipt: [u8; 32] = hasher.finalize().into();
            assert_eq!(receipt, expected_receipt);
        }

        // Verify final destination file exists and temp files are cleaned up
        assert!(
            dest.exists(),
            "final destination file must exist after completion"
        );
        assert!(!part_file.exists(), ".part file must be cleaned up");
        assert!(!meta_file.exists(), ".meta file must be cleaned up");

        let written_bytes = tokio::fs::read(&dest).await.unwrap();
        assert_eq!(written_bytes, full_payload);

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn create_rejects_file_size_exceeding_receiver_limit() {
        let dir = std::env::temp_dir().join(format!(
            "luciola_xfer_limit_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dest = dir.join("huge.bin");
        let cfg = ReceiverConfig {
            max_file_size: Some(1024),
            ..Default::default()
        };
        let Err(err) = FileReceiver::create("huge_id", &dest, 2048, cfg).await else {
            panic!("oversized file must be rejected before disk allocation");
        };
        assert!(err.to_string().contains("exceeds receiver limit"), "{err}");
        assert!(!checkpoint::part_path_for(&dest).exists());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
