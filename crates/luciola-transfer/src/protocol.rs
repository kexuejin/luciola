//! Wire frames: `FileChunk` (data) and `FileAck` (contiguous-prefix credit).
//!
//! Each frame is fully self-describing so a whole frame fits inside exactly
//! one encrypted-channel message:
//!
//! ```text
//! chunk: 'T''C' | id_len:u8 | id | offset:u64be | total_size:u64be | payload_len:u32be | payload
//! ack:   'T''A' | id_len:u8 | id | acked_up_to:u64be
//! ```

pub const MAGIC_CHUNK: [u8; 2] = [0x54, 0x43]; // 'T', 'C' (Transfer Chunk)
pub const MAGIC_ACK: [u8; 2] = [0x54, 0x41]; // 'T', 'A' (Transfer Ack)

/// One piece of the file, positioned absolutely. `payload` may be empty
/// (keepalive-style re-ack request is expressed as a 0-length chunk at 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunk {
    pub transfer_id: String,
    pub offset: u64,
    pub total_size: u64,
    pub payload: Vec<u8>,
}

/// Contiguous-prefix credit: every byte in `[0, acked_up_to)` is durably on
/// disk at the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAck {
    pub transfer_id: String,
    pub acked_up_to: u64,
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], crate::TransferError> {
        if self.pos + n > self.buf.len() {
            return Err(crate::TransferError::Decode("frame truncated".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, crate::TransferError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, crate::TransferError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, crate::TransferError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn id(&mut self) -> Result<String, crate::TransferError> {
        let len = self.u8()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| crate::TransferError::Decode("transfer_id not UTF-8".into()))
    }
}

impl FileChunk {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 1 + self.transfer_id.len() + 20 + self.payload.len());
        buf.extend_from_slice(&MAGIC_CHUNK);
        buf.push(self.transfer_id.len() as u8);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        put_u64(&mut buf, self.offset);
        put_u64(&mut buf, self.total_size);
        put_u32(&mut buf, self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, crate::TransferError> {
        let mut r = Reader { buf, pos: 0 };
        let magic = r.take(2)?;
        if magic != MAGIC_CHUNK {
            return Err(crate::TransferError::Decode("bad chunk magic".into()));
        }
        let transfer_id = r.id()?;
        let offset = r.u64()?;
        let total_size = r.u64()?;
        let payload_len = r.u32()? as usize;
        let payload = r.take(payload_len)?.to_vec();
        Ok(Self {
            transfer_id,
            offset,
            total_size,
            payload,
        })
    }
}

impl FileAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 1 + self.transfer_id.len() + 8);
        buf.extend_from_slice(&MAGIC_ACK);
        buf.push(self.transfer_id.len() as u8);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        put_u64(&mut buf, self.acked_up_to);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, crate::TransferError> {
        let mut r = Reader { buf, pos: 0 };
        let magic = r.take(2)?;
        if magic != MAGIC_ACK {
            return Err(crate::TransferError::Decode("bad ack magic".into()));
        }
        let transfer_id = r.id()?;
        let acked_up_to = r.u64()?;
        Ok(Self {
            transfer_id,
            acked_up_to,
        })
    }
}

/// Distinguish a frame kind without fully decoding (receiver loop dispatch).
pub fn is_chunk_frame(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[..2] == MAGIC_CHUNK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrips_all_fields() {
        let chunk = FileChunk {
            transfer_id: "t-12345".into(),
            offset: 1 << 33,
            total_size: 52_428_800,
            payload: vec![7u8; 4096],
        };
        let back = FileChunk::decode(&chunk.encode()).unwrap();
        assert_eq!(back, chunk);
    }

    #[test]
    fn empty_payload_chunk_roundtrips() {
        let chunk = FileChunk {
            transfer_id: "x".into(),
            offset: 0,
            total_size: 0,
            payload: vec![],
        };
        assert_eq!(FileChunk::decode(&chunk.encode()).unwrap(), chunk);
    }

    #[test]
    fn ack_roundtrips() {
        let ack = FileAck {
            transfer_id: "t-1".into(),
            acked_up_to: u64::MAX,
        };
        assert_eq!(FileAck::decode(&ack.encode()).unwrap(), ack);
    }

    #[test]
    fn truncated_frames_are_rejected() {
        let chunk = FileChunk {
            transfer_id: "t".into(),
            offset: 1,
            total_size: 2,
            payload: vec![0; 16],
        };
        let mut bytes = chunk.encode();
        for cut in [2, 5, 12, 25] {
            assert!(FileChunk::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        bytes[0] = 0x00; // corrupt magic
        assert!(FileChunk::decode(&bytes).is_err());
    }

    #[test]
    fn kind_dispatch() {
        let chunk = FileChunk {
            transfer_id: "t".into(),
            offset: 0,
            total_size: 1,
            payload: vec![1],
        };
        let ack = FileAck {
            transfer_id: "t".into(),
            acked_up_to: 1,
        };
        assert!(is_chunk_frame(&chunk.encode()));
        assert!(!is_chunk_frame(&ack.encode()));
    }
}
