//! Encrypted rendezvous signalling over WSS.
//!
//! The Worker is a **blind forwarder**: it validates the room shape and the
//! Ed25519 handshake signature, then relays opaque frames between at most two
//! peers. Candidate and relay payloads are sealed *before* they leave the
//! device with AES-256-GCM under a key derived from the pairing PSK, so the
//! signalling service never sees endpoint addresses, file names or any
//! transfer data — only the room id, the public keys and online times it needs
//! for routing.
//!
//! Frame envelope (JSON, the only part the Worker can read):
//! `{"v":1,"t":"candidate|route|relay","s":<seq>,"ct":"<hex ciphertext>"}`
//! `candidate` carries endpoint addresses, `route` carries the agreed data
//! plane, and `relay` carries the fallback byte stream. All three kinds are
//! sealed with the same key, so the Worker sees none of their contents.
//!
//! AAD binds room, epoch, sequence and frame kind; the sequence is strictly
//! increasing per direction, which gives replay protection for free. An empty
//! `relay` payload is the ordered EOF marker, not an empty data frame.

use super::bridge::{bridge_pair, StreamBridge};
use super::WanError;
use crate::relay_crypto::{aead_open_raw, aead_seal_raw, frame_nonce, hkdf_sha256, AEAD_KEY_LEN};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

/// Domain-separation context for the signalling traffic key.
const SIGNAL_INFO: &[u8] = b"LUCIOLA_WAN_SIGNAL_V1";
/// Prefix of the string the Worker verifies with our Ed25519 identity key.
pub(crate) const AUTH_PREFIX: &str = "LUCIOLA_WAN_AUTH";
/// Largest encrypted frame accepted from the signalling plane.
pub(crate) const MAX_SIGNAL_FRAME: usize = 16 * 1024;
/// Relay writes are chunked so that hex-encoded ciphertext plus the JSON
/// envelope stays under the `MAX_SIGNAL_FRAME * 2` receive cap.
pub(crate) const RELAY_CHUNK: usize = MAX_SIGNAL_FRAME - 512;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Serialize, Deserialize)]
struct WireFrame {
    v: u8,
    t: String,
    s: u64,
    ct: String,
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Derive the 32-byte signalling traffic key from the pairing PSK.
///
/// Both peers compute the same key: public keys are sorted before being mixed
/// into HKDF `info`, so the derivation is commutative.
pub(crate) fn signaling_key(
    psk: &[u8],
    room: &str,
    my_pk: &[u8],
    peer_pk: &[u8],
) -> [u8; AEAD_KEY_LEN] {
    let (first, second) = if my_pk <= peer_pk {
        (my_pk, peer_pk)
    } else {
        (peer_pk, my_pk)
    };
    let mut info = SIGNAL_INFO.to_vec();
    info.extend_from_slice(first);
    info.extend_from_slice(second);
    let okm = Zeroizing::new(hkdf_sha256(psk, room.as_bytes(), &info, AEAD_KEY_LEN));
    let mut key = [0u8; AEAD_KEY_LEN];
    key.copy_from_slice(&okm);
    key
}

fn aad(room: &str, epoch: u64, seq: u64, kind: &str) -> Vec<u8> {
    format!("{room}:{epoch}:{seq}:{kind}").into_bytes()
}

/// The exact string the Worker verifies with our Ed25519 key. Keep this in
/// sync with `deploy/cloudflare-signaling/src/auth.js::authPayload`; a test
/// below pins the format so the two sides cannot drift silently.
fn auth_payload(room: &str, epoch: u64, nonce_hex: &str, peer_hex: &str) -> String {
    format!("{AUTH_PREFIX}:{room}:{epoch}:{nonce_hex}:{peer_hex}")
}

pub(crate) fn seal(
    key: &[u8; AEAD_KEY_LEN],
    room: &str,
    epoch: u64,
    seq: u64,
    kind: &str,
    plaintext: &[u8],
) -> Result<String, WanError> {
    if plaintext.len() > MAX_SIGNAL_FRAME {
        return Err(WanError::Signaling("candidate frame too large".into()));
    }
    let ct = aead_seal_raw(
        key,
        &frame_nonce(seq),
        &aad(room, epoch, seq, kind),
        plaintext,
    );
    serde_json::to_string(&WireFrame {
        v: 1,
        t: kind.to_string(),
        s: seq,
        ct: to_hex(&ct),
    })
    .map_err(|e| WanError::Signaling(format!("frame encode: {e}")))
}

pub(crate) fn open(
    key: &[u8; AEAD_KEY_LEN],
    room: &str,
    epoch: u64,
    last_seq: &mut u64,
    wire: &[u8],
) -> Result<Option<(String, Vec<u8>)>, WanError> {
    if wire.len() > MAX_SIGNAL_FRAME * 2 {
        return Err(WanError::Signaling("signalling frame too large".into()));
    }
    let frame: WireFrame = match serde_json::from_slice(wire) {
        Ok(f) => f,
        // The Durable Object sends unencrypted control notices; they carry no
        // secret and are not part of the encrypted sequence space.
        Err(_) => return Ok(None),
    };
    if frame.v != 1 {
        return Err(WanError::Signaling("unsupported frame version".into()));
    }
    // Strictly increasing per direction = replay rejection.
    if frame.s <= *last_seq {
        return Err(WanError::Signaling("replayed signalling frame".into()));
    }
    let ct =
        from_hex(&frame.ct).ok_or_else(|| WanError::Signaling("bad ciphertext encoding".into()))?;
    let plaintext = aead_open_raw(
        key,
        &frame_nonce(frame.s),
        &aad(room, epoch, frame.s, &frame.t),
        &ct,
    )
    .map_err(|_| WanError::Signaling("candidate frame failed authentication".into()))?;
    *last_seq = frame.s;
    Ok(Some((frame.t, plaintext)))
}

/// Authenticated, encrypted rendezvous connection.
pub(crate) struct SignalingClient {
    pub(crate) sink: SplitSink<WsStream, Message>,
    pub(crate) stream: SplitStream<WsStream>,
    pub(crate) key: [u8; AEAD_KEY_LEN],
    pub(crate) room: String,
    pub(crate) epoch: u64,
    pub(crate) send_seq: u64,
    pub(crate) recv_seq: u64,
}

/// Parameters for opening a rendezvous connection.
pub(crate) struct SignalParams<'a> {
    /// `wss://` endpoint (plain `ws://` is allowed for loopback tests only).
    pub(crate) endpoint: &'a str,
    /// 32-character hex room id derived from the pairing PSK.
    pub(crate) room: &'a str,
    /// 10-minute epoch window shared with the Worker's replay window.
    pub(crate) epoch: u64,
    /// 32-byte local Ed25519 identity seed.
    pub(crate) identity_seed: &'a [u8; 32],
    /// Our 32-byte Ed25519 public key.
    pub(crate) my_pk: &'a [u8],
    /// The pinned peer's 32-byte Ed25519 public key.
    pub(crate) peer_pk: &'a [u8],
    /// Pairing PSK (never sent to the Worker).
    pub(crate) psk: &'a [u8],
    /// Connection timeout.
    pub(crate) timeout: Duration,
}

impl SignalingClient {
    /// Connect to the rendezvous Worker and authenticate with Ed25519.
    pub(crate) async fn connect(p: SignalParams<'_>) -> Result<Self, WanError> {
        // The Worker accepts canonical lowercase hex only; reject anything
        // else here so a caller never gets a confusing 400 from the edge.
        let canonical_room = p.room.len() == 32
            && p.room
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !canonical_room {
            return Err(WanError::InvalidConfig(
                "room must be 32 lowercase hex characters".into(),
            ));
        }
        if p.psk.is_empty() {
            return Err(WanError::InvalidConfig("pairing PSK is required".into()));
        }
        if p.my_pk.len() != 32 || p.peer_pk.len() != 32 {
            return Err(WanError::InvalidConfig(
                "public keys must be 32 bytes".into(),
            ));
        }
        if !(p.endpoint.starts_with("wss://")
            || p.endpoint.starts_with("ws://127.0.0.1")
            || p.endpoint.starts_with("ws://localhost")
            || p.endpoint.starts_with("ws://[::1]"))
        {
            return Err(WanError::InvalidConfig(
                "signalling endpoint must use wss:// (plain ws is loopback-only)".into(),
            ));
        }

        let signing = SigningKey::from_bytes(p.identity_seed);
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let my_hex = to_hex(p.my_pk);
        // The signature is bound to the same public key we present in `peer`,
        // so a captured signature cannot be replayed under a different key.
        let nonce_hex = to_hex(&nonce);
        let payload = auth_payload(p.room, p.epoch, &nonce_hex, &my_hex);
        let signature = signing.sign(payload.as_bytes());
        let separator = if p.endpoint.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{}room={}&peer={}&nonce={}&epoch={}&sig={}",
            p.endpoint,
            separator,
            p.room,
            my_hex,
            nonce_hex,
            p.epoch,
            to_hex(&signature.to_bytes())
        );

        let (ws, _) = tokio::time::timeout(p.timeout, connect_async(url))
            .await
            .map_err(|_| WanError::Signaling("rendezvous connect timed out".into()))?
            .map_err(|e| WanError::Signaling(format!("websocket handshake: {e}")))?;
        let (sink, stream) = ws.split();
        Ok(Self {
            sink,
            stream,
            key: signaling_key(p.psk, p.room, p.my_pk, p.peer_pk),
            room: p.room.to_string(),
            epoch: p.epoch,
            send_seq: 0,
            recv_seq: 0,
        })
    }

    /// Send one encrypted application frame.
    pub(crate) async fn send(&mut self, kind: &str, plaintext: &[u8]) -> Result<(), WanError> {
        self.send_seq += 1;
        let wire = seal(
            &self.key,
            &self.room,
            self.epoch,
            self.send_seq,
            kind,
            plaintext,
        )?;
        self.sink
            .send(Message::Binary(wire.into_bytes().into()))
            .await
            .map_err(|e| WanError::Signaling(format!("websocket send: {e}")))
    }

    /// Receive the next encrypted frame. Plaintext control notices from the
    /// Durable Object are consumed internally.
    pub(crate) async fn recv(&mut self) -> Result<Option<(String, Vec<u8>)>, WanError> {
        loop {
            match self.stream.next().await {
                None => return Ok(None),
                Some(Err(e)) => {
                    return Err(WanError::Signaling(format!("websocket receive: {e}")));
                }
                Some(Ok(Message::Binary(bytes))) => {
                    if let Some(frame) = open(
                        &self.key,
                        &self.room,
                        self.epoch,
                        &mut self.recv_seq,
                        &bytes,
                    )? {
                        return Ok(Some(frame));
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Some(frame) = open(
                        &self.key,
                        &self.room,
                        self.epoch,
                        &mut self.recv_seq,
                        text.as_bytes(),
                    )? {
                        return Ok(Some(frame));
                    }
                }
                Some(Ok(_)) => {} // ping/pong/close handled by tungstenite
            }
        }
    }

    /// Turn the WSS connection into an ordered byte stream for relay fallback.
    ///
    /// WebSocket is already reliable and ordered, so no ARQ is needed here;
    /// only framing, encryption, chunking and credit release are. An empty
    /// relay frame is an explicit EOF marker: because the WebSocket preserves
    /// order, all preceding data has already been delivered when it arrives.
    pub(crate) fn into_relay(self) -> StreamBridge {
        let (bridge, mut ends) = bridge_pair();
        let Self {
            mut sink,
            mut stream,
            key,
            room,
            epoch,
            mut send_seq,
            mut recv_seq,
        } = self;
        tokio::spawn(async move {
            let mut outbound_done = false;
            loop {
                tokio::select! {
                    // A dropped or shut-down writer must not spin on `None`,
                    // and must not kill the read half before the peer's EOF.
                    outbound = ends.outbound_rx.recv(), if !outbound_done => {
                        match outbound {
                            None => {
                                outbound_done = true;
                                send_seq += 1;
                                let wire = match seal(&key, &room, epoch, send_seq, "relay", &[]) {
                                    Ok(w) => w,
                                    Err(_) => break,
                                };
                                if sink.send(Message::Binary(wire.into_bytes().into())).await.is_err() {
                                    break;
                                }
                            }
                            Some(bytes) if bytes.is_empty() => {
                                outbound_done = true;
                                send_seq += 1;
                                let wire = match seal(&key, &room, epoch, send_seq, "relay", &[]) {
                                    Ok(w) => w,
                                    Err(_) => break,
                                };
                                if sink.send(Message::Binary(wire.into_bytes().into())).await.is_err() {
                                    break;
                                }
                            }
                            Some(bytes) => {
                                let mut sent_all = true;
                                for chunk in bytes.chunks(RELAY_CHUNK) {
                                    send_seq += 1;
                                    let wire = match seal(&key, &room, epoch, send_seq, "relay", chunk) {
                                        Ok(w) => w,
                                        Err(_) => { sent_all = false; break; }
                                    };
                                    if sink.send(Message::Binary(wire.into_bytes().into())).await.is_err() {
                                        sent_all = false;
                                        break;
                                    }
                                }
                                if !sent_all {
                                    break;
                                }
                                ends.flow.release(bytes.len());
                            }
                        }
                    }
                    incoming = stream.next() => {
                        let (kind, pt) = match incoming {
                            Some(Ok(Message::Binary(bytes))) => {
                                match open(&key, &room, epoch, &mut recv_seq, &bytes) {
                                    Ok(Some(frame)) => frame,
                                    Ok(None) => continue,
                                    Err(_) => break,
                                }
                            }
                            Some(Ok(Message::Text(text))) => {
                                match open(&key, &room, epoch, &mut recv_seq, text.as_bytes()) {
                                    Ok(Some(frame)) => frame,
                                    Ok(None) => continue,
                                    Err(_) => break,
                                }
                            }
                            Some(Ok(_)) => continue,
                            Some(Err(_)) | None => break,
                        };
                        if kind != "relay" {
                            continue;
                        }
                        if pt.is_empty() {
                            // Ordered EOF marker: everything before it has
                            // already been pushed into the inbound channel.
                            break;
                        }
                        if ends.inbound_tx.send(pt).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        bridge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "00112233445566778899aabbccddeeff";
    const EPOCH: u64 = 2_980_000;

    #[test]
    fn auth_payload_matches_the_worker_verifier() {
        assert_eq!(
            auth_payload(ROOM, EPOCH, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "abab"),
            format!("LUCIOLA_WAN_AUTH:{ROOM}:{EPOCH}:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd:abab")
        );
    }

    #[test]
    fn hex_roundtrip_and_validation() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }

    #[test]
    fn signaling_key_is_commutative_and_psk_bound() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(
            signaling_key(b"psk", ROOM, &a, &b),
            signaling_key(b"psk", ROOM, &b, &a)
        );
        assert_ne!(
            signaling_key(b"psk", ROOM, &a, &b),
            signaling_key(b"other-psk", ROOM, &a, &b)
        );
    }

    #[test]
    fn frames_are_authenticated_replay_resistant_and_aad_bound() {
        let key = signaling_key(b"psk", ROOM, &[1u8; 32], &[2u8; 32]);
        let wire = seal(
            &key,
            ROOM,
            EPOCH,
            1,
            "candidate",
            b"{\"srflx\":\"1.2.3.4:5\"}",
        )
        .unwrap();
        let mut last = 0;
        let (kind, pt) = open(&key, ROOM, EPOCH, &mut last, wire.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(kind, "candidate");
        assert_eq!(pt, b"{\"srflx\":\"1.2.3.4:5\"}");
        assert_eq!(last, 1);

        // Replay of the same frame is rejected.
        assert!(open(&key, ROOM, EPOCH, &mut last, wire.as_bytes()).is_err());
        // Wrong epoch (AAD) is rejected even with a fresh sequence.
        let wire2 = seal(&key, ROOM, EPOCH, 2, "candidate", b"x").unwrap();
        let mut last2 = 0;
        assert!(open(&key, ROOM, EPOCH + 1, &mut last2, wire2.as_bytes()).is_err());
        // Frame kind is bound by the AAD.
        let wire3 = seal(&key, ROOM, EPOCH, 2, "relay", b"x").unwrap();
        let forged: WireFrame = serde_json::from_str(&wire3).unwrap();
        let mut tampered = forged;
        tampered.t = "candidate".into();
        let mut last3 = 0;
        assert!(open(
            &key,
            ROOM,
            EPOCH,
            &mut last3,
            serde_json::to_string(&tampered).unwrap().as_bytes()
        )
        .is_err());
    }

    #[test]
    fn control_notices_are_not_treated_as_encrypted_frames() {
        let key = signaling_key(b"psk", ROOM, &[1u8; 32], &[2u8; 32]);
        let mut last = 0;
        assert_eq!(
            open(
                &key,
                ROOM,
                EPOCH,
                &mut last,
                br#"{"type":"peer_online","peer":"ab"}"#
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn oversized_plaintext_is_refused() {
        let key = signaling_key(b"psk", ROOM, &[1u8; 32], &[2u8; 32]);
        let big = vec![0u8; MAX_SIGNAL_FRAME + 1];
        assert!(seal(&key, ROOM, EPOCH, 1, "candidate", &big).is_err());
    }

    #[test]
    fn relay_chunk_fits_the_receive_cap_and_roundtrips() {
        let key = signaling_key(b"psk", ROOM, &[1u8; 32], &[2u8; 32]);
        let chunk = vec![7u8; RELAY_CHUNK];
        let wire = seal(&key, ROOM, EPOCH, 1, "relay", &chunk).unwrap();
        assert!(
            wire.len() <= MAX_SIGNAL_FRAME * 2,
            "hex-encoded wire frame must fit the receive cap: {}",
            wire.len()
        );
        let mut last = 0;
        let (kind, plaintext) = open(&key, ROOM, EPOCH, &mut last, wire.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(kind, "relay");
        assert_eq!(plaintext, chunk);
    }

    #[test]
    fn empty_relay_frame_is_a_valid_eof_marker() {
        let key = signaling_key(b"psk", ROOM, &[1u8; 32], &[2u8; 32]);
        let wire = seal(&key, ROOM, EPOCH, 9, "relay", &[]).unwrap();
        let mut last = 0;
        let (kind, plaintext) = open(&key, ROOM, EPOCH, &mut last, wire.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(kind, "relay");
        assert!(plaintext.is_empty());
    }
}
