//! Persistent file transfer checkpoints (`.luciola-meta` and `.luciola-part`).
//!
//! Implements Phase 2 of the Luciola WAN Traversal Roadmap (NectarLink Pattern):
//! Binary header (64 bytes):
//! - `0x00..0x08`: magic `[u8; 8]` = `b"LUCMETA1"`
//! - `0x08..0x28`: transfer identity hash `[u8; 32]` = SHA-256(transfer_id)
//! - `0x28..0x30`: total file length `u64` (LE)
//! - `0x30..0x34`: chunk size `u32` (LE)
//! - `0x34..0x38`: chunk count `u32` (LE)
//! - `0x38..0x3C`: CRC-32 checksum over the first 56 bytes `u32` (LE)
//! - `0x3C..0x40`: reserved 4 bytes `[0u8; 4]`
//!
//! Followed by the chunk bitmap data: `chunk_count.div_ceil(8)` bytes.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Magic prefix for Luciola checkpoint metadata file.
pub const MAGIC_META: &[u8; 8] = b"LUCMETA1";
/// Default chunk size for bitmap resolution (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
/// Upper bound on checkpoint bitmap allocation (1 MiB = 8,388,608 chunks =
/// 512 GiB at the default 64 KiB chunk size). Prevents a hostile or corrupted
/// metadata header / intro size from forcing unbounded heap allocation.
pub const MAX_BITMAP_BYTES: usize = 1024 * 1024;
/// Maximum number of chunks representable within [`MAX_BITMAP_BYTES`].
pub const MAX_CHUNK_COUNT: u32 = (MAX_BITMAP_BYTES as u32) * 8;

/// Pure Rust IEEE 802.3 CRC-32 (polynomial `0xEDB88320`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Checkpoint metadata describing in-flight transfer state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferMeta {
    /// Associated transfer identifier.
    pub transfer_id: String,
    /// Total expected file size in bytes.
    pub total_bytes: u64,
    /// Chunk size in bytes per bitmap bit.
    pub chunk_size: u32,
    /// Total number of chunks covering the file.
    pub chunk_count: u32,
    /// Bitset marking completed chunks (1 = completed and written).
    pub bitmap: Vec<u8>,
}

impl TransferMeta {
    /// Create fresh checkpoint metadata for a new transfer.
    pub fn new(transfer_id: &str, total_bytes: u64, chunk_size: u32) -> Self {
        let chunk_size = chunk_size.max(1024);
        let chunk_count = if total_bytes == 0 {
            0
        } else {
            total_bytes.div_ceil(chunk_size as u64) as u32
        };
        let bitmap_len = chunk_count.div_ceil(8) as usize;
        Self {
            transfer_id: transfer_id.to_string(),
            total_bytes,
            chunk_size,
            chunk_count,
            bitmap: vec![0u8; bitmap_len],
        }
    }

    /// Mark a chunk index as completed and verified on disk.
    pub fn mark_chunk(&mut self, chunk_idx: u32) {
        if chunk_idx < self.chunk_count {
            let byte_idx = (chunk_idx / 8) as usize;
            let bit_idx = (chunk_idx % 8) as u8;
            self.bitmap[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Mark a byte range `[offset, offset + len)` as completed.
    ///
    /// Only chunks the range **fully** covers are marked. The bitmap is what a
    /// resumed transfer trusts, so a half-written chunk marked complete is a
    /// hole that survives a crash — the resume path would skip right over it.
    /// The final chunk is the one exception: it is complete as soon as the
    /// range reaches `total_bytes`, however short it is.
    pub fn mark_range(&mut self, offset: u64, len: usize) {
        if len == 0 || self.chunk_size == 0 {
            return;
        }
        let size = self.chunk_size as u64;
        let end = offset.saturating_add(len as u64);
        // First chunk whose whole extent starts at or after `offset`.
        let first_covered = offset.div_ceil(size);
        // Chunks ending at or before `end`.
        let last_exclusive = end / size;
        for c in first_covered..last_exclusive.min(self.chunk_count as u64) {
            self.mark_chunk(c as u32);
        }
        // Final chunk may be shorter than `chunk_size`, so it is complete only
        // when the range covers it from its start boundary all the way to EOF.
        if end >= self.total_bytes && self.chunk_count > 0 {
            let last_chunk_start = (self.chunk_count as u64 - 1) * size;
            if offset <= last_chunk_start {
                self.mark_chunk(self.chunk_count - 1);
            }
        }
    }

    /// Check if a specific chunk index has been marked complete.
    pub fn is_chunk_completed(&self, chunk_idx: u32) -> bool {
        if chunk_idx >= self.chunk_count {
            return false;
        }
        let byte_idx = (chunk_idx / 8) as usize;
        let bit_idx = (chunk_idx % 8) as u8;
        (self.bitmap[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Return the contiguous completed byte prefix from offset 0.
    pub fn contiguous_bytes(&self) -> u64 {
        let mut count = 0u64;
        for i in 0..self.chunk_count {
            if self.is_chunk_completed(i) {
                let this_chunk = if (i + 1) == self.chunk_count {
                    self.total_bytes - (i as u64 * self.chunk_size as u64)
                } else {
                    self.chunk_size as u64
                };
                count += this_chunk;
            } else {
                break;
            }
        }
        count
    }

    /// Serialize into the binary `.luciola-meta` file format with CRC-32 integrity.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.bitmap.len());
        buf.extend_from_slice(MAGIC_META);
        let id_hash = sha256_digest(self.transfer_id.as_bytes());
        buf.extend_from_slice(&id_hash);
        buf.extend_from_slice(&self.total_bytes.to_le_bytes());
        buf.extend_from_slice(&self.chunk_size.to_le_bytes());
        buf.extend_from_slice(&self.chunk_count.to_le_bytes());
        let crc = crc32(&buf[0..56]);
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]); // reserved
        buf.extend_from_slice(&self.bitmap);
        buf
    }

    /// Decode and validate checksum, magic, and transfer identity.
    pub fn decode(buf: &[u8], expected_transfer_id: &str) -> Option<Self> {
        if buf.len() < 64 || &buf[0..8] != MAGIC_META {
            return None;
        }
        let stored_crc = u32::from_le_bytes(buf[56..60].try_into().ok()?);
        let computed_crc = crc32(&buf[0..56]);
        if stored_crc != computed_crc {
            return None;
        }
        let stored_hash: [u8; 32] = buf[8..40].try_into().ok()?;
        let expected_hash = sha256_digest(expected_transfer_id.as_bytes());
        if stored_hash != expected_hash {
            return None;
        }
        let total_bytes = u64::from_le_bytes(buf[40..48].try_into().ok()?);
        let chunk_size = u32::from_le_bytes(buf[48..52].try_into().ok()?);
        let chunk_count = u32::from_le_bytes(buf[52..56].try_into().ok()?);
        if chunk_size < 1024 || chunk_count > MAX_CHUNK_COUNT {
            return None;
        }
        let expected_chunks = if total_bytes == 0 {
            0u64
        } else {
            total_bytes.div_ceil(chunk_size as u64)
        };
        if expected_chunks != chunk_count as u64 {
            return None;
        }
        let expected_bitmap_len = chunk_count.div_ceil(8) as usize;
        if expected_bitmap_len > MAX_BITMAP_BYTES || buf.len() < 64 + expected_bitmap_len {
            return None;
        }
        let bitmap = buf[64..64 + expected_bitmap_len].to_vec();
        Some(Self {
            transfer_id: expected_transfer_id.to_string(),
            total_bytes,
            chunk_size,
            chunk_count,
            bitmap,
        })
    }
}

/// Compute the `.luciola-part` temporary in-progress file path for `dest`.
pub fn part_path_for(dest: &Path) -> PathBuf {
    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    dest.with_file_name(format!("{file_name}.luciola-part"))
}

/// Compute the `.luciola-meta` checkpoint metadata path for `dest`.
pub fn meta_path_for(dest: &Path) -> PathBuf {
    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    dest.with_file_name(format!("{file_name}.luciola-meta"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_test_vector() {
        // Standard check: CRC-32 of b"123456789" is 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// A partially written chunk must not be recorded as done: resume would
    /// skip it and silently leave a hole in the file.
    #[test]
    fn mark_range_only_marks_fully_covered_chunks() {
        let chunk = 64 * 1024u64;
        let mut meta = TransferMeta::new("t", 4 * chunk, 64 * 1024);
        assert_eq!(meta.chunk_count, 4);

        // Half of chunk 1.
        meta.mark_range(chunk + 1024, 1024);
        assert!(
            !meta.is_chunk_completed(1),
            "a partial chunk is not complete"
        );
        assert_eq!(meta.contiguous_bytes(), 0);

        // All of chunk 1 plus a sliver of chunk 2.
        meta.mark_range(chunk, 64 * 1024 + 10);
        assert!(meta.is_chunk_completed(1));
        assert!(!meta.is_chunk_completed(2), "the sliver must not count");

        // Two whole chunks in one write.
        meta.mark_range(0, (2 * chunk) as usize);
        assert!(meta.is_chunk_completed(0));
        assert!(meta.is_chunk_completed(1));
        assert!(!meta.is_chunk_completed(2));
    }

    /// The short tail chunk counts once the range covers it from its chunk
    /// start boundary to EOF (partial tail writes must NOT mark it complete).
    #[test]
    fn reaching_eof_marks_the_short_tail_chunk() {
        let chunk = 64 * 1024u64;
        let total = 3 * chunk + 100;
        let mut meta = TransferMeta::new("t", total, 64 * 1024);
        assert_eq!(meta.chunk_count, 4);
        meta.mark_range(0, (3 * chunk) as usize);
        assert!(!meta.is_chunk_completed(3));
        // Partial tail write (last 50 bytes only) must NOT mark chunk 3 complete.
        meta.mark_range(3 * chunk + 50, 50);
        assert!(
            !meta.is_chunk_completed(3),
            "partial tail write leaving gap at start of final chunk must not mark it complete"
        );
        // Full coverage of final chunk from its start boundary to EOF marks it complete.
        meta.mark_range(3 * chunk, 100);
        assert!(meta.is_chunk_completed(3));
        assert_eq!(meta.contiguous_bytes(), total);
    }

    #[test]
    fn meta_encode_decode_roundtrip() {
        let mut meta = TransferMeta::new("xfer_123", 200 * 1024 * 1024, 64 * 1024);
        assert_eq!(meta.chunk_count, 3200);
        meta.mark_chunk(0);
        meta.mark_chunk(1);
        meta.mark_chunk(2);
        assert_eq!(meta.contiguous_bytes(), 3 * 64 * 1024);

        let encoded = meta.encode();
        assert_eq!(encoded.len(), 64 + 400);

        let decoded = TransferMeta::decode(&encoded, "xfer_123").expect("decode");
        assert_eq!(decoded.contiguous_bytes(), 3 * 64 * 1024);
        assert_eq!(decoded.total_bytes, 200 * 1024 * 1024);
        assert!(decoded.is_chunk_completed(0));
        assert!(decoded.is_chunk_completed(1));
        assert!(decoded.is_chunk_completed(2));
        assert!(!decoded.is_chunk_completed(3));

        // Wrong transfer id must be rejected
        assert!(TransferMeta::decode(&encoded, "wrong_id").is_none());

        // Corrupted CRC must be rejected
        let mut corrupted = encoded.clone();
        corrupted[10] ^= 0xFF;
        assert!(TransferMeta::decode(&corrupted, "xfer_123").is_none());
    }

    #[test]
    fn decode_rejects_oversized_or_mismatched_bitmap_header() {
        // Craft a syntactically valid CRC header claiming an excessive chunk_count.
        let mut header = Vec::with_capacity(64);
        header.extend_from_slice(MAGIC_META);
        header.extend_from_slice(&sha256_digest(b"evil"));
        header.extend_from_slice(&(1024u64).to_le_bytes()); // total_bytes
        header.extend_from_slice(&(DEFAULT_CHUNK_SIZE).to_le_bytes()); // chunk_size
        header.extend_from_slice(&(MAX_CHUNK_COUNT + 1).to_le_bytes()); // bogus chunk_count
        let crc = crc32(&header[0..56]);
        header.extend_from_slice(&crc.to_le_bytes());
        header.extend_from_slice(&[0u8; 4]);
        assert!(TransferMeta::decode(&header, "evil").is_none());
    }
}
