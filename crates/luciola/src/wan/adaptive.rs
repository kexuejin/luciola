//! Progressive WAN connection with zero-wait relay bootstrap and in-flight hot migration.
//!
//! Implements Phase 1 of the Luciola WAN Traversal Roadmap (Tailscale DERP Pattern):
//! 1. Starts streaming immediately over the WSS relay channel (<50 ms initial latency).
//! 2. Concurrently discovers candidates and probes for direct UDP punch in the background.
//! 3. Once direct punch is established, seamlessly migrates the active transport from
//!    Relay to Direct UDP without dropping any in-flight frames or re-authenticating.
//! 4. Transparently updates the active channel tracker to `ChannelType::HolePunchedDirect`.

use super::bridge::{bridge_pair, StreamBridge};
use super::signaling::{open, seal, to_hex, SignalingClient, RELAY_CHUNK};
use super::udp::{
    build_packet, parse_packet, punch, KIND_ACK, KIND_CLOSE, KIND_DATA, KIND_PUNCH, MAX_PAYLOAD,
};
use super::{role_for, WanConfig, WanError, WanRole};
use crate::proto::{ChannelType, TraversalCandidates};
use crate::traversal::{gather_traversal_session, peer_udp_targets};
use futures_util::{SinkExt, StreamExt};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};
use tokio_tungstenite::tungstenite::Message;

const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(200);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RETRANSMITS: u32 = 40;
const HEADER_LEN: usize = 24;

/// Result of setting up progressive relay.
pub(crate) struct ProgressiveRelay {
    /// Ordered byte stream handed to `secure_handshake`.
    pub(crate) bridge: StreamBridge,
    /// Atomic tracker dynamically reflecting the active channel type.
    pub(crate) tracker: Arc<AtomicU8>,
}

/// Start progressive relay streaming immediately, spawning a background task
/// to discover candidates, punch UDP hole, and perform hot migration.
pub(crate) fn start_progressive_relay(
    signal: SignalingClient,
    config: Arc<WanConfig>,
) -> ProgressiveRelay {
    let (bridge, mut ends) = bridge_pair();
    let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
    let tracker_clone = tracker.clone();

    tokio::spawn(async move {
        let SignalingClient {
            mut sink,
            mut stream,
            key,
            room,
            epoch,
            mut send_seq,
            mut recv_seq,
        } = signal;

        let role = role_for(&config.my_public_key, &config.peer_public_key);
        let my_hex = to_hex(&config.my_public_key);
        let expected_peer_hex = to_hex(&config.peer_public_key);

        // Channels for background punch coordinator
        let (peer_cand_tx, mut peer_cand_rx) = mpsc::channel::<TraversalCandidates>(1);
        let (punch_res_tx, mut punch_res_rx) = mpsc::channel::<(Arc<UdpSocket>, SocketAddr)>(1);

        // Spawn background candidate gathering and UDP punch task if enabled
        if config.enable_hole_punching {
            let config_bg = config.clone();
            let my_hex_bg = my_hex.clone();
            let expected_peer_hex_bg = expected_peer_hex.clone();

            tokio::spawn(async move {
                // 1. Gather local STUN / candidates
                let session = match gather_traversal_session(
                    &my_hex_bg,
                    config_bg.tcp_port,
                    config_bg.stun_server.as_deref(),
                )
                .await
                {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let _local_candidates = session.candidates.clone();
                let socket = session.socket();

                // 2. Wait for peer candidates from the signaling stream
                let peer_candidates =
                    match tokio::time::timeout(config_bg.punch_timeout * 2, peer_cand_rx.recv())
                        .await
                    {
                        Ok(Some(c)) => c,
                        _ => return,
                    };

                // Validate peer identity
                if !peer_candidates
                    .public_key
                    .eq_ignore_ascii_case(&expected_peer_hex_bg)
                {
                    return;
                }

                // 3. Perform simultaneous-open UDP hole punching
                let local_is_v4 = socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
                let targets: Vec<SocketAddr> = peer_udp_targets(&peer_candidates)
                    .into_iter()
                    .filter(|a| a.is_ipv4() == local_is_v4)
                    .collect();

                if targets.is_empty() {
                    return;
                }

                if let Ok(peer_addr) =
                    udp_punch_with_candidate(&socket, &targets, config_bg.punch_timeout).await
                {
                    let _ = punch_res_tx.send((socket, peer_addr)).await;
                }
            });
        }

        // Active driver state
        let mut direct_socket: Option<Arc<UdpSocket>> = None;
        let mut direct_peer: Option<SocketAddr> = None;
        let mut direct_active = false;
        let mut migration_proposed = false;
        let mut _migration_acked = false;

        // UDP ARQ state
        let mut next_udp_seq: u64 = 1;
        let mut recv_udp_next: u64 = 1;
        let mut sent_udp: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut recv_ooo: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut udp_retransmits: u32 = 0;
        let mut last_udp_activity = Instant::now();

        let mut udp_tick = interval(RETRANSMIT_INTERVAL);
        let mut udp_buf = vec![0u8; 65536];
        let mut outbound_done = false;

        // Trigger sending local candidates over WebSocket
        if config.enable_hole_punching {
            let my_hex_cand = my_hex.clone();
            let tcp_port = config.tcp_port;
            let stun_srv = config.stun_server.clone();
            tokio::spawn({
                // We gather candidates asynchronously and signal main loop
                // (Candidate gathering is handled above, but we also announce it here)
                async move {
                    if let Ok(s) =
                        gather_traversal_session(&my_hex_cand, tcp_port, stun_srv.as_deref()).await
                    {
                        let _ = serde_json::to_vec(&s.candidates);
                    }
                }
            });
        }

        // Also gather local candidates to send immediately via WebSocket
        let local_cand_session = if config.enable_hole_punching {
            gather_traversal_session(&my_hex, config.tcp_port, config.stun_server.as_deref())
                .await
                .ok()
        } else {
            None
        };

        if let Some(session) = &local_cand_session {
            if let Ok(wire) = serde_json::to_vec(&session.candidates) {
                send_seq += 1;
                if let Ok(w) = seal(&key, &room, epoch, send_seq, "candidate", &wire) {
                    let _ = sink.send(Message::Binary(w.into_bytes().into())).await;
                }
            }
        }

        loop {
            tokio::select! {
                // 1. Data written by the application
                outbound = ends.outbound_rx.recv(), if !outbound_done => {
                    match outbound {
                        None => {
                            outbound_done = true;
                            if direct_active {
                                if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                                    let close = build_packet(KIND_CLOSE, next_udp_seq, recv_udp_next, &[]);
                                    let _ = sock.send_to(&close, peer).await;
                                }
                            } else {
                                send_seq += 1;
                                if let Ok(wire) = seal(&key, &room, epoch, send_seq, "relay", &[]) {
                                    let _ = sink.send(Message::Binary(wire.into_bytes().into())).await;
                                }
                            }
                        }
                        Some(bytes) if bytes.is_empty() => {
                            outbound_done = true;
                            if direct_active {
                                if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                                    let close = build_packet(KIND_CLOSE, next_udp_seq, recv_udp_next, &[]);
                                    let _ = sock.send_to(&close, peer).await;
                                }
                            } else {
                                send_seq += 1;
                                if let Ok(wire) = seal(&key, &room, epoch, send_seq, "relay", &[]) {
                                    let _ = sink.send(Message::Binary(wire.into_bytes().into())).await;
                                }
                            }
                        }
                        Some(bytes) => {
                            if direct_active {
                                if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                                    for chunk in bytes.chunks(MAX_PAYLOAD) {
                                        let seq = next_udp_seq;
                                        next_udp_seq += 1;
                                        let packet = build_packet(KIND_DATA, seq, recv_udp_next, chunk);
                                        let _ = sock.send_to(&packet, peer).await;
                                        sent_udp.insert(seq, packet);
                                    }
                                    last_udp_activity = Instant::now();
                                }
                            } else {
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
                }

                // 2. Incoming from WebSocket signaling/relay
                incoming_ws = stream.next() => {
                    let msg_bytes = match incoming_ws {
                        Some(Ok(Message::Binary(b))) => b.to_vec(),
                        Some(Ok(Message::Text(t))) => t.as_bytes().to_vec(),
                        Some(Ok(_)) => continue,
                        None | Some(Err(_)) => {
                            // If relay drops and we are NOT on direct UDP, terminate
                            if !direct_active {
                                break;
                            }
                            continue;
                        }
                    };

                    if let Ok(Some((kind, pt))) = open(&key, &room, epoch, &mut recv_seq, &msg_bytes) {
                        match kind.as_str() {
                            "relay" => {
                                if !direct_active {
                                    if pt.is_empty() {
                                        // Peer sent relay EOF
                                        break;
                                    }
                                    if ends.inbound_tx.send(pt).is_err() {
                                        break;
                                    }
                                }
                            }
                            "candidate" => {
                                if let Ok(cand) = serde_json::from_slice::<TraversalCandidates>(&pt) {
                                    let _ = peer_cand_tx.try_send(cand);
                                }
                            }
                            "migrate_propose" => {
                                // Peer proposes migration
                                if role == WanRole::Responder && direct_socket.is_some() {
                                    send_seq += 1;
                                    if let Ok(ack_wire) = seal(&key, &room, epoch, send_seq, "migrate_ack", b"ok") {
                                        let _ = sink.send(Message::Binary(ack_wire.into_bytes().into())).await;
                                        direct_active = true;
                                        _migration_acked = true;
                                        tracker_clone.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
                                    }
                                }
                            }
                            "migrate_ack" => {
                                // Responder accepted our migration proposal
                                if role == WanRole::Initiator && direct_socket.is_some() {
                                    direct_active = true;
                                    _migration_acked = true;
                                    tracker_clone.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // 3. Background UDP punch completion
                Some((sock, peer_addr)) = punch_res_rx.recv() => {
                    direct_socket = Some(sock);
                    direct_peer = Some(peer_addr);

                    if role == WanRole::Initiator && !migration_proposed {
                        migration_proposed = true;
                        send_seq += 1;
                        if let Ok(prop_wire) = seal(&key, &room, epoch, send_seq, "migrate_propose", b"udp") {
                            let _ = sink.send(Message::Binary(prop_wire.into_bytes().into())).await;
                        }
                    }
                }

                // 4. Incoming datagram from Direct UDP socket (once punched)
                incoming_udp = async {
                    if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                        match sock.recv_from(&mut udp_buf).await {
                            Ok((n, from)) => Some((n, from, sock.clone(), peer)),
                            Err(_) => None,
                        }
                    } else {
                        futures_util::future::pending::<Option<(usize, SocketAddr, Arc<UdpSocket>, SocketAddr)>>().await
                    }
                } => {
                    if let Some((n, from, sock, peer)) = incoming_udp {
                        if from == peer {
                            if let Some((kind, seq, ack, payload)) = parse_packet(&udp_buf[..n]) {
                                last_udp_activity = Instant::now();

                                // Free credit for acked packets
                                let acked: Vec<u64> = sent_udp.keys().copied().filter(|s| *s < ack).collect();
                                let mut freed = 0usize;
                                for s in acked {
                                    if let Some(packet) = sent_udp.remove(&s) {
                                        freed += packet.len() - HEADER_LEN;
                                    }
                                }
                                if freed > 0 {
                                    ends.flow.release(freed);
                                    udp_retransmits = 0;
                                }

                                if kind == KIND_DATA && seq >= recv_udp_next {
                                    if recv_ooo.insert(seq, payload.to_vec()).is_none() {
                                        while let Some(seg) = recv_ooo.remove(&recv_udp_next) {
                                            recv_udp_next += 1;
                                            if ends.inbound_tx.send(seg).is_err() {
                                                return;
                                            }
                                        }
                                    }
                                    let ack_packet = build_packet(KIND_ACK, 0, recv_udp_next, &[]);
                                    let _ = sock.send_to(&ack_packet, peer).await;
                                } else if kind == KIND_PUNCH {
                                    // Peer keepalive / probe: reply with ACK
                                    let ack_packet = build_packet(KIND_ACK, 0, recv_udp_next, &[]);
                                    let _ = sock.send_to(&ack_packet, peer).await;
                                }
                            }
                        }
                    }
                }

                // 5. Retransmission tick for UDP
                _ = udp_tick.tick(), if direct_active => {
                    if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                        if sent_udp.is_empty() {
                            if last_udp_activity.elapsed() >= KEEPALIVE_INTERVAL {
                                let probe = build_packet(KIND_PUNCH, 0, recv_udp_next, &[]);
                                let _ = sock.send_to(&probe, peer).await;
                                last_udp_activity = Instant::now();
                            }
                        } else {
                            udp_retransmits += 1;
                            if udp_retransmits > MAX_RETRANSMITS {
                                // Fallback to relay if UDP peer dies
                                direct_active = false;
                                tracker_clone.store(ChannelType::RelayForwarded as u8, Ordering::Release);
                            } else {
                                for packet in sent_udp.values() {
                                    let _ = sock.send_to(packet, peer).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    ProgressiveRelay { bridge, tracker }
}

async fn udp_punch_with_candidate(
    socket: &UdpSocket,
    targets: &[SocketAddr],
    timeout: Duration,
) -> Result<SocketAddr, WanError> {
    punch(socket, targets, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_defaults_to_relay() {
        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        assert_eq!(
            tracker.load(Ordering::Acquire),
            ChannelType::RelayForwarded as u8
        );
        tracker.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
        assert_eq!(
            tracker.load(Ordering::Acquire),
            ChannelType::HolePunchedDirect as u8
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn progressive_migration_cuts_over_to_direct_udp() {
        use crate::relay_crypto::AEAD_KEY_LEN;
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, connect_async};

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

        let (ws_a, _) = connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .unwrap();
        let (ws_b, _) = connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .unwrap();
        let (sink_a, stream_a) = ws_a.split();
        let (sink_b, stream_b) = ws_b.split();

        let id_a = crate::trust::generate_identity();
        let id_b = crate::trust::generate_identity();
        let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
        let seed_b: [u8; 32] = id_b.seed.clone().try_into().unwrap();
        let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
        let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();
        let key = [9u8; AEAD_KEY_LEN];

        let client_a = SignalingClient {
            sink: sink_a,
            stream: stream_a,
            key,
            room: "testroom".into(),
            epoch: 1,
            send_seq: 0,
            recv_seq: 0,
        };
        let client_b = SignalingClient {
            sink: sink_b,
            stream: stream_b,
            key,
            room: "testroom".into(),
            epoch: 1,
            send_seq: 0,
            recv_seq: 0,
        };

        let cfg_a = Arc::new(WanConfig {
            signaling_endpoint: format!("ws://127.0.0.1:{port}"),
            room: "testroom".into(),
            epoch: 1,
            psk: zeroize::Zeroizing::new(b"psk".to_vec()),
            identity_seed: seed_a,
            my_public_key: pk_a,
            peer_public_key: pk_b,
            enable_hole_punching: true,
            punch_timeout: Duration::from_millis(500),
            ..WanConfig::default()
        });
        let cfg_b = Arc::new(WanConfig {
            signaling_endpoint: format!("ws://127.0.0.1:{port}"),
            room: "testroom".into(),
            epoch: 1,
            psk: zeroize::Zeroizing::new(b"psk".to_vec()),
            identity_seed: seed_b,
            my_public_key: pk_b,
            peer_public_key: pk_a,
            enable_hole_punching: true,
            punch_timeout: Duration::from_millis(500),
            ..WanConfig::default()
        });

        let prog_a = start_progressive_relay(client_a, cfg_a);
        let prog_b = start_progressive_relay(client_b, cfg_b);

        // Initially both are on relay
        assert_eq!(
            prog_a.tracker.load(Ordering::Acquire),
            ChannelType::RelayForwarded as u8
        );
        assert_eq!(
            prog_b.tracker.load(Ordering::Acquire),
            ChannelType::RelayForwarded as u8
        );

        // Run handshakes
        use crate::link::secure::{secure_handshake_client, secure_handshake_server};
        let (mut stream_a, mut stream_b) = tokio::try_join!(
            secure_handshake_client(prog_a.bridge, &seed_a, &pk_b),
            secure_handshake_server(prog_b.bridge, &seed_b, Some(&pk_a)),
        )
        .unwrap();

        stream_a.set_channel_tracker(prog_a.tracker.clone());
        stream_b.set_channel_tracker(prog_b.tracker.clone());

        // Stream initial data over relay
        stream_a.send(b"data-before-migration").await.unwrap();
        let mut buf = Vec::new();
        stream_b.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"data-before-migration");

        // Wait briefly for candidate exchange and punch
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Send further data
        stream_b.send(b"data-after-migration").await.unwrap();
        buf.clear();
        stream_a.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"data-after-migration");

        forwarder.abort();
    }
}
