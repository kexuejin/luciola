//! Wire frames: `FileChunk` (data) and `FileAck` (contiguous-prefix credit).
//!
//! Each frame is fully self-describing so a whole frame fits inside exactly
//! one encrypted-channel message:
//!
//! ```text
//! intro: 'T''I' | id_len:u8 | id | name_len:u16be | name | total_size:u64be
//! chunk: 'T''C' | id_len:u8 | id | offset:u64be | total_size:u64be | payload_len:u32be | payload
//! ack:   'T''A' | id_len:u8 | id | acked_up_to:u64be
//! ```
//!
//! `FileIntro` is the first message on the wire: it names the transfer and the
//! file so the receiving side can construct its [`crate::FileReceiver`] before
//! the first chunk lands (receiver-side `total_size` is required upfront).

/// Magic prefix of a data chunk frame (`'T','C'`).
pub const MAGIC_CHUNK: [u8; 2] = [0x54, 0x43]; // 'T', 'C' (Transfer Chunk)
/// Magic prefix of an acknowledgement frame (`'T','A'`).
pub const MAGIC_ACK: [u8; 2] = [0x54, 0x41]; // 'T', 'A' (Transfer Ack)
/// Magic prefix of the intro frame (`'T','I'`).
pub const MAGIC_INTRO: [u8; 2] = [0x54, 0x49]; // 'T', 'I' (Transfer Intro)

/// One piece of the file, positioned absolutely. `payload` may be empty
/// (keepalive-style re-ack request is expressed as a 0-length chunk at 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunk {
    /// Transfer this chunk belongs to.
    pub transfer_id: String,
    /// Absolute byte offset of `payload` inside the file.
    pub offset: u64,
    /// Total file size declared by the sender.
    pub total_size: u64,
    /// Bytes at `offset`; may be empty for a zero-length marker.
    pub payload: Vec<u8>,
}

/// Contiguous-prefix credit: every byte in `[0, acked_up_to)` is durably on
/// disk at the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAck {
    /// Transfer this acknowledgement belongs to.
    pub transfer_id: String,
    /// Exclusive end of the contiguous prefix durably written.
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
    /// Encode this chunk into its self-describing wire frame.
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

    /// Decode a chunk frame; truncated frames and bad magic are rejected.
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
    /// Encode this acknowledgement into its wire frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 1 + self.transfer_id.len() + 8);
        buf.extend_from_slice(&MAGIC_ACK);
        buf.push(self.transfer_id.len() as u8);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        put_u64(&mut buf, self.acked_up_to);
        buf
    }

    /// Decode an acknowledgement frame; bad magic is rejected.
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

/// Wire intro: names the transfer and the file before the first chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIntro {
    /// Transfer this intro opens.
    pub transfer_id: String,
    /// Peer-supplied file name (the receiver must keep only its basename).
    pub file_name: String,
    /// Total file size the receiver must pre-allocate.
    pub total_size: u64,
}

impl FileIntro {
    /// Encode this intro into its wire frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(2 + 1 + self.transfer_id.len() + 2 + self.file_name.len() + 8);
        buf.extend_from_slice(&MAGIC_INTRO);
        buf.push(self.transfer_id.len() as u8);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.extend_from_slice(&(self.file_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.file_name.as_bytes());
        put_u64(&mut buf, self.total_size);
        buf
    }

    /// Decode an intro frame; truncated frames and bad magic are rejected.
    pub fn decode(buf: &[u8]) -> Result<Self, crate::TransferError> {
        let mut r = Reader { buf, pos: 0 };
        let magic = r.take(2)?;
        if magic != MAGIC_INTRO {
            return Err(crate::TransferError::Decode("bad intro magic".into()));
        }
        let transfer_id = r.id()?;
        let name_len = r.u16()? as usize;
        let file_name = String::from_utf8(r.take(name_len)?.to_vec())
            .map_err(|_| crate::TransferError::Decode("file name not UTF-8".into()))?;
        let total_size = r.u64()?;
        Ok(Self {
            transfer_id,
            file_name,
            total_size,
        })
    }
}

impl Reader<'_> {
    fn u16(&mut self) -> Result<u16, crate::TransferError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Distinguish a frame kind without fully decoding (receiver loop dispatch).
pub fn is_chunk_frame(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[..2] == MAGIC_CHUNK
}

/// True when the buffer starts with the intro magic.
pub fn is_intro_frame(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == MAGIC_INTRO[0] && buf[1] == MAGIC_INTRO[1]
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

    #[test]
    fn intro_roundtrip() {
        let intro = FileIntro {
            transfer_id: "t-1".into(),
            file_name: "report 最终版.pdf".into(),
            total_size: 12_345_678,
        };
        let decoded = FileIntro::decode(&intro.encode()).unwrap();
        assert_eq!(decoded, intro);
        assert!(is_intro_frame(&intro.encode()));
        assert!(!is_intro_frame(
            &FileAck {
                transfer_id: "t".into(),
                acked_up_to: 1
            }
            .encode()
        ));
    }

    #[test]
    fn intro_rejects_truncation_and_bad_magic() {
        let mut buf = FileIntro {
            transfer_id: "t".into(),
            file_name: "x".into(),
            total_size: 1,
        }
        .encode();
        assert!(FileIntro::decode(&buf[..buf.len() - 1]).is_err());
        buf[1] = b'X';
        assert!(FileIntro::decode(&buf).is_err());
    }
}
