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

mod adaptive;
mod arq;
mod bridge;
mod proxy;
pub mod route;
mod signaling;
mod udp;

pub use route::{connect_with_policy, ConnectPolicyError, LanDialConfig, RoutePolicy};

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
#[derive(Clone)]
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
    /// Set to `true` to enable zero-wait progressive connection: start streaming
    /// immediately over the relay channel while hole punching races in the
    /// background, seamlessly migrating to direct once punched.
    pub progressive: bool,
    /// Optional HTTP `CONNECT` proxy for the signalling connection.
    ///
    /// `None` (the default) honours `HTTPS_PROXY` / `https_proxy` for `wss://`
    /// and `HTTP_PROXY` / `http_proxy` for `ws://`, with `ALL_PROXY` /
    /// `all_proxy` as a fallback; `NO_PROXY` / `no_proxy` and loopback hosts
    /// bypass it. `Some("")` disables proxying entirely, and `Some(url)` forces
    /// that one proxy regardless of the environment. Only plain `http://`
    /// proxies are supported. Explicit proxy configuration is Rust-core/CLI
    /// only; binding surfaces rely on the environment.
    pub proxy: Option<String>,
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
            progressive: false,
            proxy: None,
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

/// Open one authenticated rendezvous connection.
///
/// Extracted so the epoch realignment path below can reconnect with the same
/// parameters after re-deriving the room, without duplicating the timeout and
/// identity wiring.
async fn open_signaling(
    config: &WanConfig,
    room: &str,
    epoch: u64,
) -> Result<SignalingClient, WanError> {
    SignalingClient::connect(SignalParams {
        endpoint: &config.signaling_endpoint,
        room,
        epoch,
        identity_seed: &config.identity_seed,
        my_pk: &config.my_public_key,
        peer_pk: &config.peer_public_key,
        psk: &config.psk,
        timeout: Duration::from_millis(config.relay.connection_timeout_ms.max(500)),
        proxy: config.proxy.as_deref(),
    })
    .await
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
    let mut config = config;
    let epoch_pinned = config.epoch != 0;
    let mut epoch = if epoch_pinned {
        config.epoch
    } else {
        current_epoch()
    };
    let mut room = config.room.clone();

    // Validate and authenticate first: an invalid endpoint or missing PSK
    // must not cause a public STUN query (or any third-party contact).
    let mut signal = open_signaling(&config, &room, epoch).await?;

    // Room ids are derived from the epoch, so two peers on opposite sides of a
    // 10-minute boundary would wait in different rooms and never meet. When the
    // caller left the epoch to us, adopt the Worker's epoch and re-derive the
    // room once, so both sides land in the room the server is actually serving.
    //
    // Two cases deliberately keep the local epoch:
    //   * the caller pinned an epoch — the boundary decision is theirs;
    //   * the caller hand-wrote the room (it does not match what the local
    //     epoch derives) — re-deriving would move us somewhere the peer is not
    //     listening.
    // An older Worker sends no header at all, which is the pre-alignment
    // behaviour.
    if !epoch_pinned {
        if let Some(server_epoch) = signal.server_epoch {
            if server_epoch != epoch {
                let derive = |at: u64| {
                    crate::pairing::derive_rendezvous_room_id_flexible(
                        &config.my_public_key,
                        &config.peer_public_key,
                        Some(config.psk.as_slice()),
                        Some(at),
                    )
                };
                let aligned = if room == derive(epoch) {
                    derive(server_epoch)
                } else {
                    String::new()
                };
                if !aligned.is_empty() {
                    tracing::debug!(
                        local_epoch = epoch,
                        server_epoch,
                        "realigning rendezvous room to the signalling server's epoch"
                    );
                    room = aligned;
                    epoch = server_epoch;
                    signal = open_signaling(&config, &room, epoch).await?;
                    config.room = room.clone();
                    config.epoch = epoch;
                }
            }
        }
    }

    if config.progressive && config.relay.allow_relay {
        let role = role_for(&config.my_public_key, &config.peer_public_key);
        let prog = adaptive::start_progressive_relay(signal, Arc::new(config.clone()));
        let mut stream = match role {
            WanRole::Initiator => {
                secure_handshake_client(
                    prog.bridge,
                    &config.identity_seed,
                    Some(&config.peer_public_key),
                )
                .await
            }
            WanRole::Responder => {
                secure_handshake_server(
                    prog.bridge,
                    &config.identity_seed,
                    Some(&config.peer_public_key),
                )
                .await
            }
        }
        .map_err(|e| WanError::Handshake(e.to_string()))?;
        stream.set_channel_type(ChannelType::RelayForwarded);
        stream.set_channel_tracker(prog.tracker);
        stream.set_migration_gate(prog.punching_done);
        return Ok(stream);
    }

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
            nat_type: 0,
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
                    Some(&config.peer_public_key),
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
            secure_handshake_client(
                transport,
                &config.identity_seed,
                Some(&config.peer_public_key),
            )
            .await
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
#[allow(clippy::result_large_err)]
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

    /// Progressive WAN connection starts streaming immediately over the relay
    /// channel with zero wait, without blocking on candidate gathering.
    #[tokio::test(flavor = "multi_thread")]
    async fn progressive_relay_starts_immediately_and_transfers() {
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
            room: "112233445566778899aabbccddeeff00".into(),
            epoch: 42,
            psk: Zeroizing::new(b"progressive-psk".to_vec()),
            relay: RelayConfig {
                allow_wan_signaling: true,
                allow_relay: true,
                connection_timeout_ms: 3000,
                ..RelayConfig::default()
            },
            punch_timeout: Duration::from_millis(500),
            enable_hole_punching: false,
            progressive: true,
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

        let start = std::time::Instant::now();
        let (a, b) = tokio::try_join!(
            tokio::time::timeout(Duration::from_secs(5), connect_wan(cfg_a)),
            tokio::time::timeout(Duration::from_secs(5), connect_wan(cfg_b)),
        )
        .unwrap();
        let elapsed = start.elapsed();
        // Zero-wait bootstrap: connected in under 200 ms on loopback
        assert!(
            elapsed < Duration::from_millis(500),
            "connection took {:?}",
            elapsed
        );

        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.channel_type(), ChannelType::RelayForwarded);
        assert_eq!(b.channel_type(), ChannelType::RelayForwarded);

        let payload = vec![0x42u8; 32 * 1024];
        a.send(&payload).await.unwrap();
        let mut got = Vec::new();
        b.recv(&mut got).await.unwrap();
        assert_eq!(got, payload);

        forwarder.abort();
    }

    /// Room-keyed blind forwarder shaped like the Cloudflare Durable Object: a
    /// connection only ever sees peers that joined the same room, and every
    /// handshake response advertises `server_epoch`.
    ///
    /// Returns the task handle plus a log of the room each handshake asked for,
    /// so a test can see whether a peer redialled in a different room.
    fn epoch_advertising_worker(
        listener: tokio::net::TcpListener,
        server_epoch: u64,
    ) -> (
        tokio::task::JoinHandle<()>,
        Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use futures_util::{SinkExt, StreamExt};
        use std::collections::HashMap;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let handle = tokio::spawn(async move {
            let mut waiting: HashMap<
                String,
                tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
            > = HashMap::new();
            while let Ok((stream, _)) = listener.accept().await {
                let mut room = String::new();
                let ws = match accept_hdr_async(stream, |req: &Request, mut resp: Response| {
                    room = req
                        .uri()
                        .query()
                        .unwrap_or_default()
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("room="))
                        .unwrap_or_default()
                        .to_string();
                    resp.headers_mut()
                        .append("x-luciola-epoch", server_epoch.to_string().parse().unwrap());
                    Ok(resp)
                })
                .await
                {
                    Ok(ws) => ws,
                    Err(_) => continue,
                };
                log.lock().unwrap().push(room.clone());
                match waiting.remove(&room) {
                    Some(other) => {
                        tokio::spawn(async move {
                            let (mut w1, mut r1) = ws.split();
                            let (mut w2, mut r2) = other.split();
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
                    }
                    None => {
                        waiting.insert(room, ws);
                    }
                }
            }
        });
        (handle, seen)
    }

    /// Two peers straddling a 10-minute boundary must still meet.
    ///
    /// The room id embeds the epoch, so without realignment each peer waits in
    /// a room the other never joins. The Worker advertises its own epoch; a
    /// client that left the window to the engine re-derives the room at the
    /// server's epoch and redials once, so both sides land where the server is
    /// actually serving.
    #[tokio::test(flavor = "multi_thread")]
    async fn epoch_realignment_lands_both_peers_in_the_server_room() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let local_epoch = current_epoch();
        // One window behind: exactly the case a peer that just crossed the
        // boundary would hit.
        let server_epoch = local_epoch.saturating_sub(1);
        let (worker, seen) = epoch_advertising_worker(listener, server_epoch);

        let id_a = crate::trust::generate_identity();
        let id_b = crate::trust::generate_identity();
        let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
        let seed_b: [u8; 32] = id_b.seed.clone().try_into().unwrap();
        let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
        let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();
        let psk = Zeroizing::new(b"epoch-realign-psk".to_vec());

        let room_at = |epoch: u64| {
            crate::pairing::derive_rendezvous_room_id_flexible(
                &pk_a,
                &pk_b,
                Some(psk.as_slice()),
                Some(epoch),
            )
        };
        let local_room = room_at(local_epoch);
        let server_room = room_at(server_epoch);
        assert_ne!(
            local_room, server_room,
            "the epoch must actually change the room for this test to mean anything"
        );

        let endpoint = format!("ws://127.0.0.1:{port}/ws");
        let base = || WanConfig {
            signaling_endpoint: endpoint.clone(),
            room: local_room.clone(),
            // The caller did not pin a window, so the engine may realign.
            epoch: 0,
            psk: psk.clone(),
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
        let mut cfg_a = base();
        cfg_a.identity_seed = seed_a;
        cfg_a.my_public_key = pk_a;
        cfg_a.peer_public_key = pk_b;
        let mut cfg_b = base();
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
        a.send(b"across the boundary").await.unwrap();
        let mut got = Vec::new();
        b.recv(&mut got).await.unwrap();
        assert_eq!(got, b"across the boundary");

        let rooms = seen.lock().unwrap().clone();
        assert!(
            rooms.contains(&local_room),
            "the first dial must use the local epoch: {rooms:?}"
        );
        assert!(
            rooms.contains(&server_room),
            "the realigned dial must use the server epoch: {rooms:?}"
        );
        worker.abort();
    }

    /// A caller that pins the epoch owns the boundary decision: the engine must
    /// not silently move it into the server's window.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pinned_epoch_is_not_realigned() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pinned_epoch = current_epoch().saturating_sub(1);
        // The server advertises a *different* window, so any realignment would
        // be visible in the handshake log.
        let (worker, seen) = epoch_advertising_worker(listener, pinned_epoch.saturating_sub(1));

        let id_a = crate::trust::generate_identity();
        let id_b = crate::trust::generate_identity();
        let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
        let seed_b: [u8; 32] = id_b.seed.clone().try_into().unwrap();
        let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
        let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();
        let psk = Zeroizing::new(b"pinned-epoch-psk".to_vec());
        let pinned_room = crate::pairing::derive_rendezvous_room_id_flexible(
            &pk_a,
            &pk_b,
            Some(psk.as_slice()),
            Some(pinned_epoch),
        );

        let endpoint = format!("ws://127.0.0.1:{port}/ws");
        let base = || WanConfig {
            signaling_endpoint: endpoint.clone(),
            room: pinned_room.clone(),
            epoch: pinned_epoch,
            psk: psk.clone(),
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
        let mut cfg_a = base();
        cfg_a.identity_seed = seed_a;
        cfg_a.my_public_key = pk_a;
        cfg_a.peer_public_key = pk_b;
        let mut cfg_b = base();
        cfg_b.identity_seed = seed_b;
        cfg_b.my_public_key = pk_b;
        cfg_b.peer_public_key = pk_a;

        let (a, b) = tokio::try_join!(
            tokio::time::timeout(Duration::from_secs(10), connect_wan(cfg_a)),
            tokio::time::timeout(Duration::from_secs(10), connect_wan(cfg_b)),
        )
        .unwrap();
        assert!(a.is_ok() && b.is_ok());

        let rooms = seen.lock().unwrap().clone();
        assert_eq!(
            rooms.len(),
            2,
            "a pinned epoch must dial exactly once per peer: {rooms:?}"
        );
        assert!(
            rooms.iter().all(|r| *r == pinned_room),
            "a pinned epoch must not be moved to the server window: {rooms:?}"
        );
        worker.abort();
    }
}
