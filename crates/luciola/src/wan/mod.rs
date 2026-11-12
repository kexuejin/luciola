//! WAN connection orchestration: signalling → candidate exchange → UDP hole
//! punching → secure channel, with an explicit opt-in relay fallback.
//!
//! This is the **Rust core tier** (see AGENTS.md §11). LAN discovery, the
//! bindgen-generated KMP/Swift surfaces and the Node surface are unchanged;
//! a host that wants WAN calls [`connect_wan`] and receives an ordinary
//! [`SecureStream`] whose [`SecureStream::channel_type`] reports the route
//! that was actually established.
//!
//! Deny-by-default: nothing leaves the LAN unless
//! `RelayConfig::allow_wan_signaling` is `true`, and relay fallback needs
//! `RelayConfig::allow_relay` on top of that. Pairing trust, pinned keys and
//! the handshake are unchanged.

mod bridge;
mod signaling;
mod udp;

use crate::link::secure::{
    secure_handshake_client, secure_handshake_client_with_remote, secure_handshake_server,
    secure_handshake_server_with_remote, SecureStream,
};
use luciola_proto::{ChannelType, RelayConfig, TraversalCandidates};
use signaling::{SignalParams, SignalingClient};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of one rendezvous epoch window, in seconds (10 minutes).
pub const RENDEZVOUS_EPOCH_SECONDS: u64 = 600;

/// Errors raised while establishing a WAN channel.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum WanError {
    /// The embedder did not opt in to third-party signalling / relay.
    #[error("wan connection denied by policy: {0}")]
    PolicyDenied(String),
    /// An operating-system I/O failure on the UDP or WebSocket socket.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Signalling transport, authentication or framing failure.
    #[error("signalling error: {0}")]
    Signaling(String),
    /// No direct route and no permitted relay.
    #[error("no wan route: {0}")]
    NoRoute(String),
    /// The authenticated secure handshake failed on the chosen transport.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// Configuration was missing or inconsistent.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Everything a host must supply to establish one WAN channel.
///
/// `identity_seed`, `my_public_key` and `peer_public_key` are the same pinned
/// identities the LAN `SecureStream` uses. `psk` is the high-entropy secret
/// from the v3 pairing URI; it never leaves the device and is zeroized on
/// drop.
pub struct WanConfig {
    /// `wss://` rendezvous endpoint (plain `ws://` is loopback-only, for tests).
    pub signaling_endpoint: String,
    /// 32-character hex room id from `pairing::derive_rendezvous_room_id`.
    /// Both peers must use the same room **and** the same epoch.
    pub room: String,
    /// Rendezvous epoch window; `0` means [`current_epoch`].
    pub epoch: u64,
    /// Pairing PSK used to derive the signalling encryption key.
    pub psk: Zeroizing<Vec<u8>>,
    /// Local 32-byte Ed25519 identity seed.
    pub identity_seed: [u8; 32],
    /// Local 32-byte Ed25519 public key.
    pub my_public_key: [u8; 32],
    /// Pinned peer 32-byte Ed25519 public key (deny-by-default, never TOFU).
    pub peer_public_key: [u8; 32],
    /// WAN policy; both opt-in flags are `false` by default.
    pub relay: RelayConfig,
    /// Optional single STUN server override.
    pub stun_server: Option<String>,
    /// How long to wait for the peer's candidates and for hole punching.
    pub punch_timeout: Duration,
    /// Set to `false` to skip UDP hole punching entirely (relay-only). This
    /// also skips the public STUN query, which is useful on platforms without
    /// UDP egress or when a third-party STUN contact is undesirable.
    pub enable_hole_punching: bool,
    /// Local LAN TCP port advertised in candidates (diagnostic metadata).
    pub tcp_port: u16,
}

impl Default for WanConfig {
    /// A deny-by-default placeholder; hosts must fill in endpoint, room, PSK
    /// and identities before calling [`connect_wan`].
    fn default() -> Self {
        Self {
            signaling_endpoint: String::new(),
            room: String::new(),
            epoch: 0,
            psk: Zeroizing::new(Vec::new()),
            identity_seed: [0u8; 32],
            my_public_key: [0u8; 32],
            peer_public_key: [0u8; 32],
            relay: RelayConfig::default(),
            stun_server: None,
            punch_timeout: Duration::from_secs(5),
            enable_hole_punching: true,
            tcp_port: 0,
        }
    }
}

/// Current 10-minute rendezvous epoch (`unix_seconds / 600`).
pub fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / RENDEZVOUS_EPOCH_SECONDS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WanRole {
    Initiator,
    Responder,
}

/// Deterministic roles: the smaller public key initiates. Both peers compute
/// the same answer, so they can never both dial or both listen.
fn role_for(my_pk: &[u8], peer_pk: &[u8]) -> WanRole {
    if my_pk <= peer_pk {
        WanRole::Initiator
    } else {
        WanRole::Responder
    }
}

/// One peer's view of the transport race. Exchanged over the encrypted
/// signalling plane so both sides commit to the **same** data plane.
#[derive(serde::Serialize, serde::Deserialize)]
struct RouteDecision {
    direct: bool,
    relay: bool,
}

/// Establish a WAN secure channel.
///
/// Order of attempts: encrypted candidate exchange over WSS → simultaneous UDP
/// hole punching on the STUN socket → (only if both peers agree and both allow
/// it) an end-to-end encrypted relay over the same WebSocket. Returns a normal
/// `SecureStream` whose `channel_type` is `HolePunchedDirect` or
/// `RelayForwarded`. A failed race never claims a relay that was not actually
/// established.
pub async fn connect_wan(config: WanConfig) -> Result<SecureStream, WanError> {
    if !config.relay.allow_wan_signaling {
        return Err(WanError::PolicyDenied(
            "allow_wan_signaling is false; WAN signalling is opt-in".into(),
        ));
    }
    let epoch = if config.epoch == 0 {
        current_epoch()
    } else {
        config.epoch
    };

    // Validate and authenticate first: an invalid endpoint or missing PSK
    // must not cause a public STUN query (or any third-party contact).
    let mut signal = SignalingClient::connect(SignalParams {
        endpoint: &config.signaling_endpoint,
        room: &config.room,
        epoch,
        identity_seed: &config.identity_seed,
        my_pk: &config.my_public_key,
        peer_pk: &config.peer_public_key,
        psk: &config.psk,
        timeout: Duration::from_millis(config.relay.connection_timeout_ms.max(500)),
    })
    .await?;

    let my_hex = signaling::to_hex(&config.my_public_key);
    // One socket for STUN, punching and the data plane — do not rebind. When
    // punching is disabled we skip the public STUN query entirely.
    let session = if config.enable_hole_punching {
        Some(
            crate::traversal::gather_traversal_session(
                &my_hex,
                config.tcp_port,
                config.stun_server.as_deref(),
            )
            .await?,
        )
    } else {
        None
    };
    let local_candidates = match &session {
        Some(s) => s.candidates.clone(),
        None => TraversalCandidates {
            public_key: my_hex.clone(),
            lan_ipv4: Vec::new(),
            ipv6_gua: Vec::new(),
            srflx: None,
            tcp_port: config.tcp_port,
            udp_port: 0,
        },
    };
    let local_wire = serde_json::to_vec(&local_candidates)
        .map_err(|e| WanError::Signaling(format!("candidate encode: {e}")))?;
    signal.send("candidate", &local_wire).await?;

    let peer_candidates: TraversalCandidates = loop {
        let received = tokio::time::timeout(config.punch_timeout, signal.recv())
            .await
            .map_err(|_| WanError::NoRoute("timed out waiting for peer candidates".into()))??;
        match received {
            Some((kind, plaintext)) if kind == "candidate" => {
                break serde_json::from_slice(&plaintext)
                    .map_err(|e| WanError::Signaling(format!("peer candidates malformed: {e}")))?;
            }
            Some(_) => continue,
            None => return Err(WanError::Signaling("rendezvous closed early".into())),
        }
    };

    // The candidate frame must come from the pinned peer, not from a third
    // party that happened to learn an unguessable room id.
    let expected_hex = signaling::to_hex(&config.peer_public_key);
    if !peer_candidates
        .public_key
        .eq_ignore_ascii_case(&expected_hex)
    {
        return Err(WanError::Signaling(
            "candidate frame identity does not match the pinned peer".into(),
        ));
    }

    // Try UDP hole punching on the very socket that produced srflx.
    let mut punched: Option<(Arc<tokio::net::UdpSocket>, SocketAddr)> = None;
    if let Some(session) = &session {
        let socket = session.socket();
        let local_is_v4 = socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
        let targets: Vec<SocketAddr> = crate::traversal::peer_udp_targets(&peer_candidates)
            .into_iter()
            .filter(|a| a.is_ipv4() == local_is_v4)
            .collect();
        if !targets.is_empty() {
            if let Ok(peer_addr) = udp::punch(&socket, &targets, config.punch_timeout).await {
                punched = Some((socket, peer_addr));
            }
        }
    }
    let local_direct = punched.is_some();

    // Publish our decision and wait for the peer's. Without this agreement one
    // side could succeed at punching while the other timed out and silently
    // fell back to relay, leaving the two handshakes on different transports.
    let decision = RouteDecision {
        direct: local_direct,
        relay: config.relay.allow_relay,
    };
    let wire = serde_json::to_vec(&decision)
        .map_err(|e| WanError::Signaling(format!("route encode: {e}")))?;
    signal.send("route", &wire).await?;
    let peer_decision: RouteDecision = loop {
        let received = tokio::time::timeout(config.punch_timeout, signal.recv())
            .await
            .map_err(|_| WanError::NoRoute("timed out waiting for peer route decision".into()))??;
        match received {
            Some((kind, plaintext)) if kind == "route" => {
                break serde_json::from_slice(&plaintext)
                    .map_err(|e| WanError::Signaling(format!("peer route malformed: {e}")))?;
            }
            Some(_) => continue,
            None => return Err(WanError::Signaling("rendezvous closed early".into())),
        }
    };

    let use_direct = local_direct && peer_decision.direct;
    let use_relay = !use_direct && config.relay.allow_relay && peer_decision.relay;
    let role = role_for(&config.my_public_key, &config.peer_public_key);

    if use_direct {
        let (socket, peer_addr) = punched.expect("checked by local_direct");
        let transport = udp::start_stream(socket, peer_addr);
        let mut stream = match role {
            WanRole::Initiator => {
                secure_handshake_client_with_remote(
                    transport,
                    peer_addr,
                    &config.identity_seed,
                    &config.peer_public_key,
                )
                .await
            }
            WanRole::Responder => {
                secure_handshake_server_with_remote(
                    transport,
                    peer_addr,
                    &config.identity_seed,
                    Some(&config.peer_public_key),
                )
                .await
            }
        }
        .map_err(|e| WanError::Handshake(e.to_string()))?;
        stream.set_channel_type(ChannelType::HolePunchedDirect);
        return Ok(stream);
    }

    if !use_relay {
        return Err(WanError::NoRoute(
            "no agreed WAN route: hole punching unavailable and relay not permitted by both peers"
                .into(),
        ));
    }

    // Relay fallback: WebSocket is ordered/reliable, so the bridge needs no
    // ARQ. Payloads stay end-to-end encrypted under the signalling key.
    let transport = signal.into_relay();
    let mut stream = match role {
        WanRole::Initiator => {
            secure_handshake_client(transport, &config.identity_seed, &config.peer_public_key).await
        }
        WanRole::Responder => {
            secure_handshake_server(
                transport,
                &config.identity_seed,
                Some(&config.peer_public_key),
            )
            .await
        }
    }
    .map_err(|e| WanError::Handshake(e.to_string()))?;
    stream.set_channel_type(ChannelType::RelayForwarded);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_config_is_denied_before_any_network_activity() {
        assert!(matches!(
            connect_wan(WanConfig::default()).await,
            Err(WanError::PolicyDenied(_))
        ));
    }

    #[tokio::test]
    async fn opting_into_signaling_only_still_requires_a_valid_endpoint() {
        let mut cfg = WanConfig::default();
        cfg.relay.allow_wan_signaling = true;
        cfg.signaling_endpoint = "http://not-a-websocket.example".into();
        cfg.room = "00112233445566778899aabbccddeeff".into();
        cfg.psk = Zeroizing::new(b"psk".to_vec());
        // Endpoint validation happens before any DNS or socket work.
        assert!(matches!(
            connect_wan(cfg).await,
            Err(WanError::InvalidConfig(_))
        ));
    }

    #[test]
    fn roles_are_opposite_and_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(role_for(&a, &b), WanRole::Initiator);
        assert_eq!(role_for(&b, &a), WanRole::Responder);
    }

    #[test]
    fn epoch_is_a_ten_minute_window() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(current_epoch(), now / 600);
    }

    /// Two peers meet on a local blind-forwarding WebSocket (the same shape as
    /// the Cloudflare Durable Object), skip hole punching, agree on the relay
    /// route, then run the real authenticated secure handshake and exchange
    /// data over the encrypted relay. No public network is contacted.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_fallback_establishes_a_working_secure_channel() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let forwarder = tokio::spawn(async move {
            let (s1, _) = listener.accept().await.unwrap();
            let ws1 = accept_async(s1).await.unwrap();
            let (s2, _) = listener.accept().await.unwrap();
            let ws2 = accept_async(s2).await.unwrap();
            let (mut w1, mut r1) = ws1.split();
            let (mut w2, mut r2) = ws2.split();
            let a = tokio::spawn(async move {
                while let Some(Ok(msg)) = r1.next().await {
                    if w2.send(msg).await.is_err() {
                        break;
                    }
                }
            });
            let b = tokio::spawn(async move {
                while let Some(Ok(msg)) = r2.next().await {
                    if w1.send(msg).await.is_err() {
                        break;
                    }
                }
            });
            let _ = tokio::join!(a, b);
        });

        let id_a = crate::trust::generate_identity();
        let id_b = crate::trust::generate_identity();
        let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
        let seed_b: [u8; 32] = id_b.seed.clone().try_into().unwrap();
        let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
        let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();

        let base = |endpoint: String| WanConfig {
            signaling_endpoint: endpoint,
            room: "00112233445566778899aabbccddeeff".into(),
            epoch: 42,
            psk: Zeroizing::new(b"relay-e2e-psk".to_vec()),
            relay: RelayConfig {
                allow_wan_signaling: true,
                allow_relay: true,
                connection_timeout_ms: 3000,
                ..RelayConfig::default()
            },
            punch_timeout: Duration::from_secs(5),
            enable_hole_punching: false,
            ..WanConfig::default()
        };
        let endpoint = format!("ws://127.0.0.1:{port}/ws");
        let mut cfg_a = base(endpoint.clone());
        cfg_a.identity_seed = seed_a;
        cfg_a.my_public_key = pk_a;
        cfg_a.peer_public_key = pk_b;
        let mut cfg_b = base(endpoint);
        cfg_b.identity_seed = seed_b;
        cfg_b.my_public_key = pk_b;
        cfg_b.peer_public_key = pk_a;

        let (a, b) = tokio::try_join!(
            tokio::time::timeout(Duration::from_secs(10), connect_wan(cfg_a)),
            tokio::time::timeout(Duration::from_secs(10), connect_wan(cfg_b)),
        )
        .unwrap();
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.channel_type(), ChannelType::RelayForwarded);
        assert_eq!(b.channel_type(), ChannelType::RelayForwarded);
        assert_eq!(a.peer_public_key, id_b.public_key);
        assert_eq!(b.peer_public_key, id_a.public_key);

        // Larger than one relay frame: exercises the chunking path.
        let payload = vec![0x5au8; 64 * 1024];
        a.send(&payload).await.unwrap();
        let mut got = Vec::new();
        b.recv(&mut got).await.unwrap();
        assert_eq!(got, payload);
        b.send(b"ack").await.unwrap();
        got.clear();
        a.recv(&mut got).await.unwrap();
        assert_eq!(got, b"ack");

        forwarder.abort();
    }
}
