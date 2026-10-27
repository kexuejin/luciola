//! Sending side: sliding window over absolute-offset chunks, ACK-driven
//! progress, timeout-based retransmit of unacknowledged chunks.

use crate::protocol::FileChunk;
use crate::TransferError;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::AsyncSeekExt;

#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Payload bytes per chunk.
    pub chunk_size: usize,
    /// Max chunks in flight before an ACK frees a slot.
    pub window: usize,
    /// Re-send in-flight chunks with no ACK covering them for this long.
    pub retransmit_after: Duration,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            chunk_size: 256 * 1024,
            window: 8,
            retransmit_after: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
struct InFlight {
    offset: u64,
    len: usize,
    sent_at: Instant,
}

/// Stateful sender for ONE file. Single-task by design (`&mut self`).
pub struct FileSender {
    transfer_id: String,
    file: File,
    total_size: u64,
    next_offset: u64,
    acked_up_to: u64,
    in_flight: Vec<InFlight>,
    config: SenderConfig,
}

impl FileSender {
    pub async fn open(
        transfer_id: impl Into<String>,
        src: impl AsRef<std::path::Path>,
        config: SenderConfig,
    ) -> Result<Self, TransferError> {
        let path = src.as_ref();
        let total_size = tokio::fs::metadata(path).await?.len();
        let file = File::open(path).await?;
        Ok(Self {
            transfer_id: transfer_id.into(),
            file,
            total_size,
            next_offset: 0,
            acked_up_to: 0,
            in_flight: Vec::new(),
            config,
        })
    }

    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn acked_up_to(&self) -> u64 {
        self.acked_up_to
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// All bytes acked — transfer finished from the sender's view.
    pub fn is_done(&self) -> bool {
        self.acked_up_to >= self.total_size
    }

    /// Fraction acked, in `[0, 1]` (0-size files are done immediately).
    pub fn progress(&self) -> f64 {
        if self.total_size == 0 {
            return 1.0;
        }
        (self.acked_up_to as f64) / (self.total_size as f64)
    }

    /// Fill the window: read up to `window - in_flight` chunks from disk.
    pub async fn fill_window(&mut self) -> Result<Vec<FileChunk>, TransferError> {
        let mut out = Vec::new();
        while self.in_flight.len() < self.config.window && self.next_offset < self.total_size {
            let offset = self.next_offset;
            let len = (self.total_size - offset).min(self.config.chunk_size as u64) as usize;
            let payload = self.read_at(offset, len).await?;
            self.in_flight.push(InFlight {
                offset,
                len,
                sent_at: Instant::now(),
            });
            self.next_offset += len as u64;
            out.push(FileChunk {
                transfer_id: self.transfer_id.clone(),
                offset,
                total_size: self.total_size,
                payload,
            });
        }
        Ok(out)
    }

    /// Advance on an ACK. Regressing ACKs are ignored.
    pub fn on_ack(&mut self, acked_up_to: u64) {
        if acked_up_to <= self.acked_up_to {
            return;
        }
        self.acked_up_to = acked_up_to;
        self.in_flight
            .retain(|f| f.offset + f.len as u64 > acked_up_to);
    }

    /// In-flight chunks unacknowledged for longer than `retransmit_after`
    /// (their clock restarts). Returns them for immediate re-send.
    pub async fn expired_in_flight(&mut self) -> Result<Vec<FileChunk>, TransferError> {
        let cutoff = self.config.retransmit_after;
        let expired: Vec<InFlight> = self
            .in_flight
            .iter()
            .filter(|f| f.sent_at.elapsed() >= cutoff)
            .cloned()
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for f in expired {
            let payload = self.read_at(f.offset, f.len).await?;
            if let Some(entry) = self
                .in_flight
                .iter_mut()
                .find(|e| e.offset == f.offset && e.len == f.len)
            {
                entry.sent_at = Instant::now();
            }
            out.push(FileChunk {
                transfer_id: self.transfer_id.clone(),
                offset: f.offset,
                total_size: self.total_size,
                payload,
            });
        }
        Ok(out)
    }

    async fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, TransferError> {
        self.file.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; len];
        tokio::io::AsyncReadExt::read_exact(&mut self.file, &mut buf).await?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_src(bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("luciola-tx-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join(format!("src-{}", bytes.len()));
        tokio::fs::write(&p, bytes).await.unwrap();
        p
    }

    #[tokio::test]
    async fn window_slides_on_ack() {
        let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let src = make_src(&data).await;
        let cfg = SenderConfig {
            chunk_size: 1024,
            window: 2,
            retransmit_after: Duration::from_millis(200),
        };
        let mut tx = FileSender::open("t", &src, cfg).await.unwrap();

        let first = tx.fill_window().await.unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].offset, 0);
        assert_eq!(first[1].offset, 1024);
        // Window full: nothing more until ACK.
        assert!(tx.fill_window().await.unwrap().is_empty());

        tx.on_ack(1024); // first chunk acked
        let next = tx.fill_window().await.unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].offset, 2048);

        // Regressing ACK ignored.
        tx.on_ack(512);
        assert_eq!(tx.acked_up_to(), 1024);
        tokio::fs::remove_file(&src).await.ok();
    }

    #[tokio::test]
    async fn retransmit_expires_unacked_chunks() {
        let src = make_src(&[0u8; 2048]).await;
        let cfg = SenderConfig {
            chunk_size: 1024,
            window: 4,
            retransmit_after: Duration::from_millis(50),
        };
        let mut tx = FileSender::open("t", &src, cfg).await.unwrap();
        let first = tx.fill_window().await.unwrap();
        assert_eq!(first.len(), 2);

        tokio::time::sleep(Duration::from_millis(80)).await;
        let resent = tx.expired_in_flight().await.unwrap();
        assert_eq!(resent.len(), 2);
        assert_eq!(resent[0].offset, 0);
        assert_eq!(resent[1].offset, 1024);
        // Clocks restarted: nothing expires immediately after.
        assert!(tx.expired_in_flight().await.unwrap().is_empty());

        // Acking everything clears in-flight and finishes the transfer.
        tx.on_ack(2048);
        assert!(tx.is_done());
        assert!(tx.fill_window().await.unwrap().is_empty());
        tokio::fs::remove_file(&src).await.ok();
    }

    #[tokio::test]
    async fn zero_byte_file_is_done_immediately() {
        let src = make_src(&[]).await;
        let mut tx = FileSender::open("empty", &src, SenderConfig::default())
            .await
            .unwrap();
        assert!(tx.is_done());
        assert_eq!(tx.progress(), 1.0);
        assert!(tx.fill_window().await.unwrap().is_empty());
        tokio::fs::remove_file(&src).await.ok();
    }

    #[tokio::test]
    async fn ack_math_matches_chunk_layout() {
        // Documented invariant the driver relies on: chunks fully below the
        // ack prefix leave in-flight on on_ack.
        let src = make_src(&[0u8; 10]).await;
        let mut tx = FileSender::open("t", &src, SenderConfig::default())
            .await
            .unwrap();
        let chunks = tx.fill_window().await.unwrap();
        assert_eq!(chunks.len(), 1);
        tx.on_ack(10);
        assert!(tx.in_flight.is_empty());
        tokio::fs::remove_file(&src).await.ok();
    }
}
