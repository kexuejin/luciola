//! Receiving side: absolute-offset writes, contiguous-prefix ACK, SHA-256
//! receipt, and the 30-second post-completion answer cache.

use crate::protocol::FileChunk;
use crate::TransferError;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// How long after completion a retransmitted tail chunk still earns the
    /// final ACK back (guards the sender against a lost last ACK).
    pub answer_cache_ttl: Duration,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            answer_cache_ttl: Duration::from_secs(30),
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
    file: File,
    /// Merged, sorted received intervals. `[0, acked)` is always fully
    /// covered by the first interval when it starts at 0.
    intervals: Vec<Interval>,
    completed_at: Option<Instant>,
    config: ReceiverConfig,
}

impl FileReceiver {
    /// Create (truncate) the destination file and prepare for `total_size`.
    pub async fn create(
        transfer_id: &str,
        dest: impl Into<std::path::PathBuf>,
        total_size: u64,
        config: ReceiverConfig,
    ) -> Result<Self, TransferError> {
        let dest = dest.into();
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let file = File::create(&dest).await?;
        file.set_len(total_size).await?;
        Ok(Self {
            transfer_id: transfer_id.to_string(),
            total_size,
            dest,
            file,
            intervals: Vec::new(),
            completed_at: None,
            config,
        })
    }

    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Contiguous prefix durably written so far.
    pub fn acked_up_to(&self) -> u64 {
        match self.intervals.first() {
            Some(i) if i.start == 0 => i.end,
            _ => 0,
        }
    }

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
            self.file
                .seek(std::io::SeekFrom::Start(chunk.offset))
                .await?;
            self.file.write_all(&chunk.payload).await?;
        }

        self.insert_interval(chunk.offset, end);
        if self.is_complete() {
            // Durability point: the final ACK may now be credited honestly.
            self.file.sync_data().await?;
            self.completed_at = Some(Instant::now());
            tracing::info!(
                transfer = %self.transfer_id,
                size = self.total_size,
                "transfer complete; answer cache open"
            );
        }
        Ok(self.acked_up_to())
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
}
