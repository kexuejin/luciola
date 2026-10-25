//! Canonical pairing payload (`luciola://pair?...`) — one format across all
//! products, replacing the per-demo hand-rolled builders/parsers.
//!
//! v2 fields: `name` (URL-encoded), `product`, `port` (TCP service port),
//! `addrs` (comma-separated candidate addresses), `fp` (the host's
//! `sha256:<hex>` identity fingerprint, so pairing carries the trust anchor),
//! `pin` (optional 6-digit comparison pin). Plain `http://host:port` payloads
//! are accepted as single-address, no-fingerprint (legacy) pairings.

use crate::trust;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};

#[derive(Debug, Clone, PartialEq)]
pub struct PairingPayload {
    pub name: String,
    pub product: Option<String>,
    pub port: u16,
    pub addrs: Vec<String>,
    /// Host identity fingerprint (`sha256:<hex>`) — bind trust on this.
    pub fingerprint: Option<String>,
    /// Optional 6-digit on-screen comparison pin.
    pub pin: Option<String>,
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

/// Build the canonical pairing URI.
pub fn build_pairing_uri(
    name: &str,
    product: Option<&str>,
    port: u16,
    addrs: &[String],
    fingerprint: Option<&str>,
    pin: Option<&str>,
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
    if let Some(pin) = pin {
        q.push_str(&format!("&pin={}", encode(pin)));
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
        let mut pin = None;
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
                "pin" => pin = Some(v),
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
            pin,
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
        pin: None,
    })
}

/// Convenience: fingerprint for a public key (same as `trust::fingerprint`).
pub fn fingerprint_of(public_key: &[u8]) -> String {
    trust::fingerprint(public_key)
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
            Some("309051"),
        );
        let p = parse_pairing_uri(&uri).unwrap();
        assert_eq!(p.name, "ke的Mac mini");
        assert_eq!(p.product.as_deref(), Some("luciola-clipboard"));
        assert_eq!(p.port, 3000);
        assert_eq!(p.addrs, vec!["192.168.2.82", "2408::1"]);
        assert_eq!(p.fingerprint.as_deref(), Some("sha256:abcd1234"));
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
}
