//! Native HTTP `CONNECT` proxy support for the WSS rendezvous connection.
//!
//! `tokio_tungstenite::connect_async()` always calls
//! `TcpStream::connect("{host}:{port}")` itself, so it cannot be pointed at a
//! proxy. This module does the two things that helper cannot: pick a proxy and
//! open the TCP stream (optionally through `CONNECT`), then hands that stream to
//! `client_async_tls_with_config()` so TLS, the WebSocket upgrade and SNI stay
//! exactly the same as a direct connection.
//!
//! Only plain `http://` CONNECT proxies are supported. An `https://` or
//! `socks5://` proxy URL is a hard configuration error rather than a silent
//! fallback, because ignoring it would reintroduce the "curl works, the client
//! times out" failure this code exists to fix.
//!
//! Threat model: the proxy sees the rendezvous hostname and connection timing,
//! but the upgrade is authenticated with Ed25519, the transport is TLS, and
//! every signalling frame is AES-256-GCM sealed end to end. A hostile proxy can
//! stall or drop the connection; it cannot read or forge signalling payloads.
//! Proxy credentials are kept in `Zeroizing` storage and are never logged.

use super::WanError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http::Uri;
use zeroize::Zeroizing;

/// Upper bound on a proxy's CONNECT response headers. A proxy that streams
/// more than this without terminating the header block is malformed (and must
/// not be allowed to make us allocate without bound).
const MAX_CONNECT_HEADERS: usize = 8 * 1024;

/// One resolved proxy endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProxyTarget {
    /// Proxy hostname or IP, without brackets.
    pub(super) host: String,
    pub(super) port: u16,
    /// Raw `user:password` from the proxy URL, sent as HTTP Basic credentials.
    pub(super) credentials: Option<Zeroizing<String>>,
}

fn invalid(detail: impl Into<String>) -> WanError {
    WanError::InvalidConfig(detail.into())
}

fn strip_brackets(host: &str) -> &str {
    if host.len() > 2 && host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

/// Split an authority into `(bare_host, port)`, defaulting to port 80.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        if host.is_empty() {
            return None;
        }
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => p.parse::<u16>().ok()?,
            None => 80,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            // A colon that is not followed by a valid port is a malformed
            // authority, not a hostname with a default port. Silently treating
            // `host:notaport` as a host would send the tunnel to nowhere.
            if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((host.to_string(), port.parse::<u16>().ok()?))
        }
        None => Some((authority.to_string(), 80)),
    }
}

/// Parse a proxy URL such as `http://user:pass@127.0.0.1:8080` or
/// `127.0.0.1:8080`. A scheme other than `http` is rejected explicitly.
pub(super) fn parse_proxy_url(value: &str) -> Result<ProxyTarget, WanError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid("proxy URL is empty"));
    }
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, value),
    };
    if let Some(scheme) = scheme {
        if !scheme.eq_ignore_ascii_case("http") {
            return Err(invalid(format!(
                "unsupported proxy scheme {scheme:?}; only http:// CONNECT proxies are supported"
            )));
        }
    }
    // Anything after the authority (path/query/fragment) is meaningless for
    // CONNECT and would otherwise corrupt the host parse.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };
    let (host, port) = split_authority(hostport)
        .ok_or_else(|| invalid(format!("invalid proxy authority in {value:?}")))?;
    // Credentials are used verbatim as the HTTP Basic `user:password` pair;
    // percent-encoded characters are intentionally not decoded here.
    let credentials = userinfo
        .filter(|u| !u.is_empty())
        .map(|u| Zeroizing::new(u.to_string()));
    Ok(ProxyTarget {
        host,
        port,
        credentials,
    })
}

/// Extract `(host, port)` from the WebSocket request URI. This mirrors
/// `tokio_tungstenite`'s own `domain()` + port resolution so direct and
/// proxied connections address the same endpoint.
pub(super) fn uri_authority(uri: &Uri) -> Result<(String, u16), WanError> {
    let raw = uri
        .host()
        .ok_or_else(|| invalid("signalling endpoint has no host"))?;
    let default_port = match uri.scheme_str() {
        Some("wss") => 443,
        Some("ws") => 80,
        _ => return Err(invalid("signalling endpoint must use ws:// or wss://")),
    };
    Ok((
        strip_brackets(raw).to_string(),
        uri.port_u16().unwrap_or(default_port),
    ))
}

/// The request-target form used in `CONNECT` and its `Host` header.
fn connect_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Loopback endpoints must never be sent through a proxy: local `wrangler dev`
/// and the in-process test Worker listen on 127.0.0.1, and a proxy resolves
/// that address on its own host.
fn is_loopback(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost") || host == "::1" || host.starts_with("127.")
}

/// Match one `NO_PROXY` / `no_proxy` entry against the target host.
fn no_proxy_entry_matches(entry: &str, host: &str, port: u16) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }
    if entry == "*" {
        return true;
    }
    let (name, wanted_port) = match entry.rsplit_once(':') {
        Some((name, digits))
            if !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (!name.contains(':') || (name.starts_with('[') && name.ends_with(']'))) =>
        {
            match digits.parse::<u16>() {
                Ok(p) => (name, Some(p)),
                Err(_) => (entry, None),
            }
        }
        _ => (entry, None),
    };
    if wanted_port.is_some_and(|p| p != port) {
        return false;
    }
    let name = strip_brackets(name)
        .trim_start_matches('.')
        .to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    host == name || host.ends_with(&format!(".{name}"))
}

fn no_proxy_matches(list: &str, host: &str, port: u16) -> bool {
    list.split(',')
        .any(|entry| no_proxy_entry_matches(entry, host, port))
}

/// Decide whether to tunnel the signalling connection.
///
/// `explicit` comes from `WanConfig::proxy`:
///   * `Some("")`  — disable proxying outright, ignoring the environment;
///   * `Some(url)` — force that proxy, ignoring environment and `NO_PROXY`;
///   * `None`      — honour the standard proxy environment variables.
///
/// `env` is injected so resolution stays a pure, environment-independent
/// function that unit tests can drive without mutating process globals.
pub(super) fn resolve_proxy<F>(
    uri: &Uri,
    explicit: Option<&str>,
    env: F,
) -> Result<Option<ProxyTarget>, WanError>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = explicit {
        if value.trim().is_empty() {
            return Ok(None);
        }
        return parse_proxy_url(value).map(Some);
    }

    let (host, port) = uri_authority(uri)?;
    if is_loopback(&host) {
        return Ok(None);
    }
    if no_proxy_matches(
        &env("NO_PROXY")
            .or_else(|| env("no_proxy"))
            .unwrap_or_default(),
        &host,
        port,
    ) {
        return Ok(None);
    }
    // Scheme-specific variables win over the catch-all; uppercase wins over
    // lowercase so the precedence is deterministic across platforms.
    let keys: &[&str] = if uri.scheme_str() == Some("wss") {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };
    for key in keys {
        if let Some(value) = env(key) {
            if value.trim().is_empty() {
                continue;
            }
            return parse_proxy_url(&value).map(Some);
        }
    }
    Ok(None)
}

/// Minimal RFC 4648 base64 encoder for HTTP Basic credentials. Keeping this
/// local avoids pulling a whole new dependency into the core crate for one
/// header.
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Open a TCP stream to the rendezvous host through an HTTP CONNECT proxy.
///
/// The response is read one byte at a time so nothing belonging to the TLS
/// handshake is swallowed past the `\r\n\r\n` terminator.
pub(super) async fn connect_via_proxy(
    proxy: &ProxyTarget,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, WanError> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|e| {
            WanError::Signaling(format!(
                "proxy connect {}:{} failed: {e}",
                proxy.host, proxy.port
            ))
        })?;
    let authority = connect_authority(target_host, target_port);
    let mut request = Zeroizing::new(format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    ));
    if let Some(credentials) = &proxy.credentials {
        let encoded = Zeroizing::new(base64(credentials.as_bytes()));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encoded);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| WanError::Signaling(format!("proxy CONNECT write failed: {e}")))?;
    drop(request);

    let mut headers = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if headers.len() >= MAX_CONNECT_HEADERS {
            return Err(WanError::Signaling(
                "proxy CONNECT response headers too large".into(),
            ));
        }
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|e| WanError::Signaling(format!("proxy CONNECT read failed: {e}")))?;
        if read == 0 {
            return Err(WanError::Signaling(
                "proxy closed before completing the CONNECT response".into(),
            ));
        }
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") || headers.ends_with(b"\n\n") {
            break;
        }
    }
    let status_line = String::from_utf8_lossy(&headers)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(WanError::Signaling(format!(
            "proxy CONNECT rejected: {status_line}"
        )));
    }
    Ok(stream)
}

/// Open the signalling TCP stream, directly or through a proxy.
///
/// This deliberately has no internal deadline: the caller wraps TCP connect,
/// CONNECT, the TLS handshake and the WebSocket upgrade in one timeout, so a
/// proxy that accepts TCP but never answers cannot double the budget.
pub(super) async fn open_socket(
    proxy: Option<&ProxyTarget>,
    host: &str,
    port: u16,
) -> Result<TcpStream, WanError> {
    match proxy {
        Some(p) => connect_via_proxy(p, host, port).await,
        None => TcpStream::connect((host, port))
            .await
            .map_err(|e| WanError::Signaling(format!("rendezvous connect failed: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(value: &str) -> Uri {
        value.parse().unwrap()
    }

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn parses_proxy_urls() {
        let p = parse_proxy_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.credentials, None);

        // Bare authority defaults to port 80.
        let p = parse_proxy_url("proxy.internal").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy.internal", 80));

        // A trailing path must not leak into the host.
        let p = parse_proxy_url("http://proxy.internal:3128/tunnel?x=1").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy.internal", 3128));

        // Credentials are preserved verbatim and never logged by the resolver.
        let p = parse_proxy_url("http://user:p%40ss@proxy.internal:3128").unwrap();
        assert_eq!(
            p.credentials.as_deref().map(|s| s.as_str()),
            Some("user:p%40ss")
        );

        // IPv6 literal.
        let p = parse_proxy_url("http://[::1]:8080").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("::1", 8080));
    }

    #[test]
    fn rejects_unsupported_or_malformed_proxy_urls() {
        assert!(parse_proxy_url("").is_err());
        assert!(parse_proxy_url("socks5://127.0.0.1:1080").is_err());
        assert!(parse_proxy_url("https://proxy.internal").is_err());
        assert!(parse_proxy_url("http://").is_err());
        assert!(parse_proxy_url("http://proxy.internal:notaport").is_err());
    }

    #[test]
    fn uri_authority_uses_scheme_default_ports_and_strips_ipv6_brackets() {
        assert_eq!(
            uri_authority(&uri("wss://hub.example/ws?room=a")).unwrap(),
            ("hub.example".into(), 443)
        );
        assert_eq!(
            uri_authority(&uri("ws://127.0.0.1:8787/ws")).unwrap(),
            ("127.0.0.1".into(), 8787)
        );
        assert_eq!(
            uri_authority(&uri("ws://[::1]:8787/ws")).unwrap(),
            ("::1".into(), 8787)
        );
        assert!(uri_authority(&uri("/ws")).is_err());
    }

    #[test]
    fn connect_authority_brackets_ipv6_only() {
        assert_eq!(connect_authority("hub.example", 443), "hub.example:443");
        assert_eq!(connect_authority("::1", 443), "[::1]:443");
    }

    #[test]
    fn no_proxy_matches_suffixes_ports_and_wildcards() {
        assert!(no_proxy_matches("*", "hub.example", 443));
        assert!(no_proxy_matches("example.com", "example.com", 443));
        assert!(no_proxy_matches(".example.com", "a.b.example.com", 443));
        assert!(!no_proxy_matches("example.com", "notexample.com", 443));
        assert!(no_proxy_matches("example.com:443", "example.com", 443));
        assert!(!no_proxy_matches("example.com:443", "example.com", 80));
        assert!(no_proxy_matches(
            "localhost, .internal",
            "hub.internal",
            443
        ));
        assert!(!no_proxy_matches("", "hub.example", 443));
        assert!(no_proxy_matches("[::1]:8080", "::1", 8080));
    }

    #[test]
    fn env_resolution_prefers_scheme_specific_then_catch_all() {
        let u = uri("wss://hub.example/ws");
        let env = env_from(&[
            ("ALL_PROXY", "http://fallback:3128"),
            ("HTTPS_PROXY", "http://secure:8080"),
        ]);
        let p = resolve_proxy(&u, None, env).unwrap().unwrap();
        assert_eq!((p.host.as_str(), p.port), ("secure", 8080));

        let env = env_from(&[("ALL_PROXY", "http://fallback:3128")]);
        let p = resolve_proxy(&u, None, env).unwrap().unwrap();
        assert_eq!((p.host.as_str(), p.port), ("fallback", 3128));

        let env = env_from(&[("HTTP_PROXY", "http://plain:8080")]);
        assert!(resolve_proxy(&u, None, env).unwrap().is_none());
    }

    #[test]
    fn loopback_and_no_proxy_bypass_the_environment() {
        let env = env_from(&[("HTTPS_PROXY", "http://secure:8080")]);
        assert!(resolve_proxy(&uri("ws://127.0.0.1:8787/ws"), None, env)
            .unwrap()
            .is_none());
        let env = env_from(&[("HTTPS_PROXY", "http://secure:8080")]);
        assert!(resolve_proxy(&uri("wss://localhost/ws"), None, env)
            .unwrap()
            .is_none());
        let env = env_from(&[
            ("HTTPS_PROXY", "http://secure:8080"),
            ("NO_PROXY", ".example.com"),
        ]);
        assert!(resolve_proxy(&uri("wss://hub.example.com/ws"), None, env)
            .unwrap()
            .is_none());
    }

    #[test]
    fn explicit_config_is_authoritative() {
        let u = uri("wss://hub.example/ws");
        // Empty string disables the environment proxy.
        let env = env_from(&[("HTTPS_PROXY", "http://secure:8080")]);
        assert!(resolve_proxy(&u, Some(""), env).unwrap().is_none());
        // A forced proxy wins over NO_PROXY and loopback.
        let env = env_from(&[("NO_PROXY", "*")]);
        let p = resolve_proxy(&uri("ws://127.0.0.1:8787/ws"), Some("http://forced:9"), env)
            .unwrap()
            .unwrap();
        assert_eq!((p.host.as_str(), p.port), ("forced", 9));
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    }
}
