//! Canonical pairing payload (`luciola://pair?...`) — one format across all
//! products, replacing the per-demo hand-rolled builders/parsers.
//!
//! v2 fields: `name` (URL-encoded), `product`, `port` (TCP service port),
//! `addrs` (comma-separated candidate addresses), `fp` (the host's
//! `sha256:<hex>` identity fingerprint, so pairing carries the trust anchor),
//! `pin` (optional 6-digit comparison pin), `pk` (base64 Ed25519 public key —
//! the pin target). Plain `http://host:port` payloads are accepted as
//! single-address, no-fingerprint (legacy) pairings.

use crate::trust;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};

/// Parsed `luciola://pair` payload (or a legacy `http://host:port` URI).
#[derive(Debug, Clone, PartialEq)]
pub struct PairingPayload {
    /// Display name of the host device.
    pub name: String,
    /// Product label, when the host advertises one.
    pub product: Option<String>,
    /// TCP service port to dial.
    pub port: u16,
    /// Candidate addresses for the host, best first.
    pub addrs: Vec<String>,
    /// Host identity fingerprint (`sha256:<hex>`) — bind trust on this.
    pub fingerprint: Option<String>,
    /// Host Ed25519 public key (base64) — the pin target for SecureChannel.
    pub public_key: Option<String>,
    /// Optional 6-digit on-screen comparison pin.
    pub pin: Option<String>,
    /// Optional high-entropy pre-shared secret for WAN rendezvous room derivation.
    ///
    /// This is **secret key material**: the v3 pairing URI (and any QR code
    /// carrying it) contains it in plaintext. It is hashed with SHA-256 before
    /// use; do not display, log or persist it as ordinary metadata. A missing
    /// PSK yields no rendezvous room (see `derive_rendezvous_room_id_flexible`).
    pub psk: Option<String>,
}

fn encode(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

fn decode(s: &str) -> Option<String> {
    percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

/// Build the canonical pairing URI (v2 without PSK).
pub fn build_pairing_uri(
    name: &str,
    product: Option<&str>,
    port: u16,
    addrs: &[String],
    fingerprint: Option<&str>,
    public_key: Option<&str>,
    pin: Option<&str>,
) -> String {
    build_pairing_uri_v3(
        name,
        product,
        port,
        addrs,
        fingerprint,
        public_key,
        pin,
        None,
    )
}

/// Build the canonical pairing URI (v3 with optional PSK for WAN rendezvous).
#[allow(clippy::too_many_arguments)]
pub fn build_pairing_uri_v3(
    name: &str,
    product: Option<&str>,
    port: u16,
    addrs: &[String],
    fingerprint: Option<&str>,
    public_key: Option<&str>,
    pin: Option<&str>,
    psk: Option<&str>,
) -> String {
    let mut q = format!("luciola://pair?name={}", encode(name));
    if let Some(p) = product {
        q.push_str(&format!("&product={}", encode(p)));
    }
    q.push_str(&format!("&port={}", port));
    if !addrs.is_empty() {
        q.push_str("&addrs=");
        q.push_str(
            &addrs
                .iter()
                .map(|a| encode(a))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(fp) = fingerprint {
        q.push_str(&format!("&fp={}", encode(fp)));
    }
    if let Some(pk) = public_key {
        q.push_str(&format!("&pk={}", encode(pk)));
    }
    if let Some(pin) = pin {
        q.push_str(&format!("&pin={}", encode(pin)));
    }
    if let Some(psk) = psk {
        q.push_str(&format!("&psk={}", encode(psk)));
    }
    q
}

/// Parse a pairing URI. Accepts `luciola://pair?...` (v1 without fp/pin, v2
/// with) and plain `http(s)://host:port` (single address, no fingerprint).
pub fn parse_pairing_uri(uri: &str) -> Option<PairingPayload> {
    if let Some(rest) = uri.strip_prefix("luciola://pair") {
        let query = rest.strip_prefix('?')?;
        let mut name = None;
        let mut product = None;
        let mut port = None;
        let mut addrs: Vec<String> = Vec::new();
        let mut fingerprint = None;
        let mut public_key = None;
        let mut pin = None;
        let mut psk = None;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=')?;
            let v = decode(v)?;
            match k {
                "name" => name = Some(v),
                "product" => product = Some(v),
                "port" => port = v.parse().ok(),
                "addrs" => {
                    addrs = v.split(',').filter_map(decode).collect();
                }
                "fp" => fingerprint = Some(v),
                "pk" => public_key = Some(v),
                "pin" => pin = Some(v),
                "psk" => psk = Some(v),
                _ => {}
            }
        }
        let port = port?;
        let name = name.unwrap_or_else(|| "Peer".to_string());
        if addrs.is_empty() {
            return None;
        }
        return Some(PairingPayload {
            name,
            product,
            port,
            addrs,
            fingerprint,
            public_key,
            pin,
            psk,
        });
    }
    // Legacy plain HTTP form: http://host:port or http://[v6]:port/path
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))?;
    let rest = rest.split('/').next()?;
    let (host, port_str) = if let Some(stripped) = rest.strip_prefix('[') {
        let (h, r) = stripped.split_once(']')?;
        (h.to_string(), r.strip_prefix(':')?)
    } else {
        let (h, p) = rest.rsplit_once(':')?;
        (h.to_string(), p)
    };
    let port: u16 = port_str.parse().ok()?;
    Some(PairingPayload {
        name: "Peer".into(),
        product: None,
        port,
        addrs: vec![host.to_string()],
        fingerprint: None,
        public_key: None,
        pin: None,
        psk: None,
    })
}

/// Convenience: fingerprint for a public key (same as `trust::fingerprint`).
pub fn fingerprint_of(public_key: &[u8]) -> String {
    trust::fingerprint(public_key)
}

/// Deterministically derives a 32-character hex rendezvous room ID from two peers' public keys,
/// a pre-shared key (PSK), and a time epoch.
///
/// Both peers sort their public keys lexicographically to guarantee identical room generation,
/// preventing third parties from discovering or predicting the rendezvous room without the PSK.
/// Callers MUST supply a real PSK: an all-zero key makes the room predictable from public keys.
pub fn derive_rendezvous_room_id(
    my_pk: &[u8; 32],
    peer_pk: &[u8; 32],
    psk: &[u8; 32],
    epoch: u64,
) -> String {
    let (lo, hi) = if my_pk < peer_pk {
        (my_pk, peer_pk)
    } else {
        (peer_pk, my_pk)
    };

    let mut ikm = Vec::with_capacity(25 + 32 + 32 + 8);
    ikm.extend_from_slice(b"LUCIOLA_WAN_RENDEZVOUS_V2");
    ikm.extend_from_slice(lo);
    ikm.extend_from_slice(hi);
    ikm.extend_from_slice(&epoch.to_be_bytes());

    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(psk), &ikm);

    let mut hex_str = String::with_capacity(32);
    for b in &prk[..16] {
        use std::fmt::Write;
        let _ = write!(hex_str, "{:02x}", b);
    }
    hex_str
}

/// Flexible helper to derive a deterministic 32-character hex rendezvous room ID from arbitrary byte slices or strings.
///
/// Keys not exactly 32 bytes in length are normalized via SHA-256.
/// If `epoch` is `None`, defaults to the current 10-minute epoch window (`unix_seconds / 600`).
///
/// A PSK is **required**: without one this returns an empty string rather than
/// deriving a room from an all-zero key, which any third party could predict
/// from the two public keys. The signalling service rejects an empty room ID.
pub fn derive_rendezvous_room_id_flexible(
    my_pk: &[u8],
    peer_pk: &[u8],
    psk: Option<&[u8]>,
    epoch: Option<u64>,
) -> String {
    use sha2::Digest;
    use zeroize::Zeroizing;

    // Fail closed instead of silently substituting a zero key (§10).
    let Some(psk_bytes) = psk else {
        return String::new();
    };
    let psk_arr: [u8; 32] = if psk_bytes.len() == 32 {
        psk_bytes.try_into().unwrap()
    } else {
        sha2::Sha256::digest(psk_bytes).into()
    };
    let psk_32 = Zeroizing::new(psk_arr);

    let my_key_32: [u8; 32] = if my_pk.len() == 32 {
        my_pk.try_into().unwrap()
    } else {
        sha2::Sha256::digest(my_pk).into()
    };

    let peer_key_32: [u8; 32] = if peer_pk.len() == 32 {
        peer_pk.try_into().unwrap()
    } else {
        sha2::Sha256::digest(peer_pk).into()
    };

    let current_epoch = epoch.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 600)
            .unwrap_or(0)
    });

    derive_rendezvous_room_id(&my_key_32, &peer_key_32, &psk_32, current_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_unicode_and_fingerprint() {
        let uri = build_pairing_uri(
            "ke的Mac mini",
            Some("luciola-clipboard"),
            3000,
            &["192.168.2.82".into(), "2408::1".into()],
            Some("sha256:abcd1234"),
            Some("dGVzdGtleQ=="),
            Some("309051"),
        );
        let p = parse_pairing_uri(&uri).unwrap();
        assert_eq!(p.name, "ke的Mac mini");
        assert_eq!(p.product.as_deref(), Some("luciola-clipboard"));
        assert_eq!(p.port, 3000);
        assert_eq!(p.addrs, vec!["192.168.2.82", "2408::1"]);
        assert_eq!(p.fingerprint.as_deref(), Some("sha256:abcd1234"));
        assert_eq!(p.public_key.as_deref(), Some("dGVzdGtleQ=="));
        assert_eq!(p.pin.as_deref(), Some("309051"));
    }

    #[test]
    fn legacy_v1_without_fp_parses() {
        let p = parse_pairing_uri("luciola://pair?name=Mac&port=8080&addrs=192.168.1.5").unwrap();
        assert_eq!(p.name, "Mac");
        assert_eq!(p.fingerprint, None);
        assert_eq!(p.addrs, vec!["192.168.1.5"]);
    }

    #[test]
    fn plain_http_uri_parses_as_single_address() {
        let p = parse_pairing_uri("http://192.168.2.82:3100").unwrap();
        assert_eq!(p.addrs, vec!["192.168.2.82"]);
        assert_eq!(p.port, 3100);
        assert_eq!(p.fingerprint, None);
        let v6 = parse_pairing_uri("http://[2408:8248::1]:8080/path").unwrap();
        assert_eq!(v6.addrs, vec!["2408:8248::1"]);
        assert_eq!(v6.port, 8080);
    }

    #[test]
    fn missing_addrs_rejected() {
        assert!(parse_pairing_uri("luciola://pair?name=X&port=80").is_none());
        assert!(parse_pairing_uri("weird://nope").is_none());
    }

    #[test]
    fn v3_pairing_with_psk_roundtrip() {
        let uri = build_pairing_uri_v3(
            "Phone",
            Some("app"),
            9000,
            &["192.168.1.100".into()],
            Some("sha256:11223344"),
            Some("pk_base64_here"),
            Some("123456"),
            Some("cHNrX2Jhc2U2NF8zMmJ5dGVzX2tleV9leGFtcGxl"),
        );
        let p = parse_pairing_uri(&uri).unwrap();
        assert_eq!(p.name, "Phone");
        assert_eq!(
            p.psk.as_deref(),
            Some("cHNrX2Jhc2U2NF8zMmJ5dGVzX2tleV9leGFtcGxl")
        );
    }

    #[test]
    fn missing_psk_yields_no_rendezvous_room() {
        // A zero-key fallback would make the room predictable from public keys.
        assert_eq!(
            derive_rendezvous_room_id_flexible(&[1u8; 32], &[2u8; 32], None, Some(1000)),
            ""
        );
        assert_eq!(
            derive_rendezvous_room_id_flexible(&[1u8; 32], &[2u8; 32], Some(b"psk"), Some(1000))
                .len(),
            32
        );
    }

    #[test]
    fn deterministic_rendezvous_room_id() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let psk = [42u8; 32];
        let epoch = 1000;

        let room_a = derive_rendezvous_room_id(&pk_a, &pk_b, &psk, epoch);
        let room_b = derive_rendezvous_room_id(&pk_b, &pk_a, &psk, epoch);

        assert_eq!(
            room_a, room_b,
            "Room IDs derived from either peer must match symmetrically"
        );
        assert_eq!(
            room_a.len(),
            32,
            "Room ID must be 32 hex characters (16 bytes)"
        );

        // Different epoch must yield different room
        let room_next_epoch = derive_rendezvous_room_id(&pk_a, &pk_b, &psk, epoch + 1);
        assert_ne!(room_a, room_next_epoch);

        // Different PSK must yield different room
        let mut psk_diff = psk;
        psk_diff[0] ^= 1;
        let room_diff_psk = derive_rendezvous_room_id(&pk_a, &pk_b, &psk_diff, epoch);
        assert_ne!(room_a, room_diff_psk);
    }
}
