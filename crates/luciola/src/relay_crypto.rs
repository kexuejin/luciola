//! Session-key agreement and per-frame AEAD for the luciola-relay wire
//! protocol (`frame_aead_v3`).
//!
//! The relay session keeps its own JSON handshake (identity + features), then
//! upgrades to an encrypted channel when BOTH peers advertise `frame_aead_v3`:
//!
//! 1. Each side generates a fresh X25519 ephemeral key pair and puts the
//!    public key in its handshake frame.
//! 2. The handshake signature string grows to
//!    `"{timestamp_ms}:{node_id}:{ephemeral_public_key_hex}"`, so the
//!    ephemeral key is authenticated — a MITM cannot swap it without failing
//!    the Ed25519 check. Handshakes without the field keep the legacy
//!    `"{timestamp_ms}:{node_id}"` string and stay on plaintext frames.
//! 3. Both sides hash the two raw handshake byte strings (exactly the bytes
//!    each side put on the wire — JSON key order differs per implementation,
//!    but each side sees the same bytes) in initiator-first order with u32
//!    big-endian length prefixes. That digest is the transcript.
//! 4. `HKDF-SHA256(ikm = X25519(eph_i, eph_r), salt = transcript_hash,
//!    info = "LUCIOLA_RELAY_V3 session keys" || fp_i || fp_r)` yields 64
//!    bytes: the initiator transmits with the first 32, the responder with
//!    the last 32.
//! 5. Every frame after the handshake is sealed with AES-256-GCM:
//!    AAD = the raw 12-byte frame header as transmitted, payload = the
//!    ciphertext (`plaintext + 16-byte tag`), nonce = `00000000 || u64be(seq)`
//!    where `seq` is the header's own sequence field. A receiver that
//!    enforces strictly increasing `seq` per direction therefore also gets
//!    replay protection for free.
//!
//! Forward secrecy: the long-term Ed25519 keys only sign; the traffic keys
//! die with the ephemeral X25519 secrets when the session ends.
//!
//! These functions are the canonical Rust implementation. The uniffi bindings
//! re-export them for the Android app, iOS re-implements them on CryptoKit,
//! and `core/tests/fixtures/wire/cases.json` pins all three to the same
//! vectors.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

/// Domain-separation prefix for the HKDF `info` field.
pub const SESSION_INFO_CONTEXT: &[u8] = b"LUCIOLA_RELAY_V3 session keys";
pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;
pub const EPHEMERAL_KEY_LEN: usize = 32;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RelayCryptoError {
    #[error("ephemeral key must be {0} bytes")]
    BadKeyLength(usize),
    #[error("X25519 exchange produced a degenerate (low-order) shared secret")]
    DegenerateSharedSecret,
    #[error("AEAD decryption failed: frame was tampered with or the key is wrong")]
    AeadOpenFailed,
}

/// Lowercase hex — the encoding used inside the signed handshake string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fresh X25519 ephemeral key pair for one session: `(secret, public)`.
pub fn ephemeral_keypair() -> ([u8; EPHEMERAL_KEY_LEN], [u8; EPHEMERAL_KEY_LEN]) {
    let mut secret = [0u8; EPHEMERAL_KEY_LEN];
    OsRng.fill_bytes(&mut secret);
    let public = ephemeral_public(&secret);
    (secret, public)
}

/// Public key belonging to a (serialized) ephemeral secret. Exposed so the
/// bindings can rebuild a public key from persisted test material.
pub fn ephemeral_public(secret: &[u8; EPHEMERAL_KEY_LEN]) -> [u8; EPHEMERAL_KEY_LEN] {
    *XPublicKey::from(&StaticSecret::from(*secret)).as_bytes()
}

/// The byte string an Ed25519 handshake signature covers.
///
/// `ephemeral_public` is `None` for legacy (plaintext, pre-`frame_aead_v3`)
/// peers, whose string stays `"{timestamp_ms}:{node_id}"`.
pub fn signed_handshake_payload(
    timestamp_ms: u64,
    node_id: &str,
    ephemeral_public: Option<&[u8; EPHEMERAL_KEY_LEN]>,
) -> String {
    match ephemeral_public {
        Some(eph) => format!("{}:{}:{}", timestamp_ms, node_id, hex(eph)),
        None => format!("{}:{}", timestamp_ms, node_id),
    }
}

/// SHA-256 over both raw handshake byte strings, initiator first, each
/// length-prefixed with a u32 big-endian. Both roles compute the same digest
/// because both know which side spoke first.
pub fn transcript_hash(initiator_handshake: &[u8], responder_handshake: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((initiator_handshake.len() as u32).to_be_bytes());
    hasher.update(initiator_handshake);
    hasher.update((responder_handshake.len() as u32).to_be_bytes());
    hasher.update(responder_handshake);
    hasher.finalize().into()
}

/// Raw HKDF-SHA256 expand step, exported for the cross-language vectors.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .expect("requested HKDF output length is valid");
    okm
}

/// Derive the two directional traffic keys.
///
/// Returns `(send_key, recv_key)` from the caller's perspective: the
/// initiator sends with the first HKDF block, the responder with the second.
pub fn session_keys(
    ephemeral_secret: &[u8; EPHEMERAL_KEY_LEN],
    peer_ephemeral_public: &[u8; EPHEMERAL_KEY_LEN],
    transcript: &[u8; 32],
    initiator_fingerprint: &str,
    responder_fingerprint: &str,
    is_initiator: bool,
) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_KEY_LEN]), RelayCryptoError> {
    let shared = StaticSecret::from(*ephemeral_secret)
        .diffie_hellman(&XPublicKey::from(*peer_ephemeral_public));
    if !shared.was_contributory() {
        return Err(RelayCryptoError::DegenerateSharedSecret);
    }

    let mut info = Vec::with_capacity(
        SESSION_INFO_CONTEXT.len() + initiator_fingerprint.len() + responder_fingerprint.len(),
    );
    info.extend_from_slice(SESSION_INFO_CONTEXT);
    info.extend_from_slice(initiator_fingerprint.as_bytes());
    info.extend_from_slice(responder_fingerprint.as_bytes());

    let okm = hkdf_sha256(shared.as_bytes(), transcript, &info, 2 * AEAD_KEY_LEN);

    let mut send = [0u8; AEAD_KEY_LEN];
    let mut recv = [0u8; AEAD_KEY_LEN];
    if is_initiator {
        send.copy_from_slice(&okm[..AEAD_KEY_LEN]);
        recv.copy_from_slice(&okm[AEAD_KEY_LEN..]);
    } else {
        send.copy_from_slice(&okm[AEAD_KEY_LEN..]);
        recv.copy_from_slice(&okm[..AEAD_KEY_LEN]);
    }
    Ok((send, recv))
}

/// 96-bit GCM nonce for a frame: 4 zero bytes + the frame's sequence number.
pub fn frame_nonce(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// AES-256-GCM over `plaintext` with an explicit 12-byte nonce. The vector
/// tests need a caller-chosen nonce (the NIST vectors use their own IVs);
/// production code goes through [`aead_seal`], which derives the nonce from
/// the frame sequence.
pub fn aead_seal_raw(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(
            &aes_gcm::Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption with a valid 32-byte key cannot fail")
}

/// AES-256-GCM open with an explicit 12-byte nonce.
pub fn aead_open_raw(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, RelayCryptoError> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(RelayCryptoError::AeadOpenFailed);
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            &aes_gcm::Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| RelayCryptoError::AeadOpenFailed)
}

/// Seal one frame payload. `aad` is the raw 12-byte frame header as it goes
/// on the wire; the ciphertext embeds the 16-byte GCM tag.
pub fn aead_seal(
    key: &[u8; AEAD_KEY_LEN],
    seq: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    aead_seal_raw(key, &frame_nonce(seq), aad, plaintext)
}

/// Open one frame payload. Fails on tampering or a key/seq mismatch.
pub fn aead_open(
    key: &[u8; AEAD_KEY_LEN],
    seq: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, RelayCryptoError> {
    aead_open_raw(key, &frame_nonce(seq), aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1 Diffie-Hellman test vector.
    #[test]
    fn x25519_matches_rfc_7748() {
        let alice_sk = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_pk = ephemeral_public(&alice_sk);
        assert_eq!(
            hex(&alice_pk),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );

        let bob_sk = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pk = ephemeral_public(&bob_sk);
        assert_eq!(
            hex(&bob_pk),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );

        let (_, a_recv) = session_keys(
            &alice_sk,
            &bob_pk,
            &[0u8; 32],
            "fp_i",
            "fp_r",
            true,
        )
        .unwrap();
        let (b_send, _) = session_keys(
            &bob_sk,
            &alice_pk,
            &[0u8; 32],
            "fp_i",
            "fp_r",
            false,
        )
        .unwrap();
        assert_eq!(a_recv, b_send, "initiator recv key must equal responder send key");
    }

    /// RFC 5869 Test Case 1 (SHA-256).
    #[test]
    fn hkdf_matches_rfc_5869() {
        let okm = hkdf_sha256(
            &[0x0b; 22],
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            ],
            &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
            42,
        );
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// NIST GCM specification, Test Case 14 (AES-256).
    #[test]
    fn aead_matches_nist_gcm_vector() {
        let mut key = [0u8; 32];
        key.copy_from_slice(&[
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ]);
        // The NIST vector uses its own 12-byte IV; call the primitive directly.
        let cipher = Aes256Gcm::new((&key).into());
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext: &[u8] = &[
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let aad: &[u8] = &[
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let ct = cipher
            .encrypt(&aes_gcm::Nonce::from(iv), Payload { msg: plaintext, aad })
            .unwrap();
        assert_eq!(
            hex(&ct),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad2df7cd675b4f09163b41ebf980a7f638"
        );
    }

    #[test]
    fn aead_round_trip_and_tamper_detection() {
        let key = [7u8; 32];
        let header = [0x4Cu8, 0x52, 0, 0x10, 0, 0, 0, 4, 0, 0, 0, 9];
        let sealed = aead_seal(&key, 9, &header, b"fire");
        assert_eq!(sealed.len(), 4 + AEAD_TAG_LEN);
        assert_eq!(aead_open(&key, 9, &header, &sealed).unwrap(), b"fire");

        // Wrong seq = wrong nonce = failure.
        assert!(aead_open(&key, 10, &header, &sealed).is_err());
        // Flipped payload bit = tampering.
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(aead_open(&key, 9, &header, &tampered).is_err());
        // Flipped header bit (AAD) = tampering.
        let mut other_header = header;
        other_header[11] ^= 1;
        assert!(aead_open(&key, 9, &other_header, &sealed).is_err());
    }

    #[test]
    fn signature_string_binds_the_ephemeral_key() {
        let eph = [0xABu8; 32];
        assert_eq!(
            signed_handshake_payload(1729840000000, "relay_test01", Some(&eph)),
            format!("1729840000000:relay_test01:{}", hex(&eph))
        );
        assert_eq!(
            signed_handshake_payload(1729840000000, "relay_test01", None),
            "1729840000000:relay_test01"
        );
    }

    #[test]
    fn a_low_order_peer_key_is_rejected() {
        let sk = [1u8; 32];
        // The all-zero public key is a low-order point.
        let degenerate = [0u8; 32];
        assert_eq!(
            session_keys(&sk, &degenerate, &[0u8; 32], "i", "r", true),
            Err(RelayCryptoError::DegenerateSharedSecret)
        );
    }

    #[test]
    fn generated_keypairs_round_trip() {
        let (secret, public) = ephemeral_keypair();
        assert_eq!(ephemeral_public(&secret), public);
    }
}

