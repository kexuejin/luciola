//! Progressive WAN connection: zero-wait relay bootstrap and in-flight migration.
//!
//! The relay carries application bytes from the first millisecond; a background
//! task gathers candidates and tries to punch a direct UDP path. Once punched,
//! the active transport migrates from relay to direct **without losing a byte**.
//!
//! # Why migration needs a barrier
//!
//! The relay is an ordered WebSocket, the direct path is an ARQ over UDP. They
//! are two independent sequence spaces, so a naive "switch when punching
//! succeeds" races: frames already queued on the WebSocket get dropped while
//! newer bytes flow over UDP, and the encrypted byte stream silently loses a
//! hole in the middle. The barrier below is what makes the switch exact:
//!
//! ```text
//! initiator                                     responder
//!   stop relay writes
//!   send PROPOSE  ──────── (ordered WS) ───────▶  stop relay writes
//!   park app writes                               switch to UDP
//!   ...                                           send ACK
//!   switch to UDP   ◀───── (ordered WS) ────────
//! ```
//!
//! Because the WebSocket preserves order, PROPOSE can only arrive after every
//! relay frame the initiator sent before it, and ACK only after every relay
//! frame the responder sent. So each side knows exactly when the peer's relay
//! stream is finished, and may start ignoring relay frames at that point.
//!
//! Also invariant: **one** UDP socket. The candidates advertised to the peer
//! and the socket used for punching and for the data plane are the same object;
//! a second socket would have a different NAT mapping and the peer would punch
//! a hole nobody is listening on.

use super::arq::AimdWindow;
use super::bridge::{bridge_pair, BridgeEnds, StreamBridge};
use super::signaling::{seal, to_hex, SignalingClient, RELAY_CHUNK};
use super::udp::{
    build_packet, parse_packet, punch, ACK_EVERY, DUP_ACK_FAST_RETRANSMIT, KIND_ACK, KIND_CLOSE,
    KIND_DATA, KIND_PUNCH, MAX_OOO_PACKETS, MAX_PAYLOAD,
};
use super::{role_for, WanConfig, WanRole};
use crate::proto::{ChannelType, TraversalCandidates};
use crate::relay_crypto::AEAD_KEY_LEN;
use crate::traversal::{
    decide_traversal_strategy, gather_traversal_session, peer_udp_targets, NatClassification,
    TraversalDecision,
};
use futures_util::{SinkExt, StreamExt};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};
use tokio_tungstenite::tungstenite::Message;

const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(200);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
/// Retransmission rounds before the direct path is declared dead. With the
/// exponential backoff below this is roughly half a minute, not 8 seconds of
/// blind full-window floods.
const MAX_RETRANSMIT_ROUNDS: u32 = 8;
/// Longest a migration may park the writer waiting for the peer's ACK.
const MIGRATION_ACK_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle cap after local half-close so a disappeared peer never leaks the driver.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(300);
const HEADER_LEN: usize = 24;

/// Paces relay writes to stay inside the signalling server's message budget.
///
/// The rendezvous server rate-limits each socket (256 messages/second in
/// `deploy/cloudflare-signaling`) and *closes* the socket on overflow rather
/// than throttling — an unpaced sender streaming at LAN speed dies mid-transfer
/// within about one second of credit. Every frame from this peer (relay chunks,
/// candidates, migration control) shares that one budget, so the sustained rate
/// keeps a margin under the limit and the burst stays small enough that even a
/// server window straddling ours never observes more than the budget allows.
struct RelayPacer {
    tokens: f64,
    last: Instant,
}

impl RelayPacer {
    /// Sustained frames/second. 224 + 16 burst = 240 observable in any
    /// one-second window, under the server's 256 with headroom for control
    /// frames sent outside the pacer.
    const RATE_PER_SEC: f64 = 224.0;
    /// Small startup burst for handshake + candidate frames.
    const BURST: f64 = 16.0;

    fn new() -> Self {
        Self {
            tokens: Self::BURST,
            last: Instant::now(),
        }
    }

    /// Consume one token, sleeping for the deficit when the bucket is empty.
    async fn wait(&mut self) {
        loop {
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + dt * Self::RATE_PER_SEC).min(Self::BURST);
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            let deficit = (1.0 - self.tokens) / Self::RATE_PER_SEC;
            tokio::time::sleep(Duration::from_secs_f64(deficit)).await;
        }
    }
}

/// Loop diagnostics for one progressive driver.
///
/// `ticks` counts event-loop iterations. It exists so the regression test can
/// tell "the driver went idle" from "the driver is spinning on a closed
/// channel", which is invisible from the outside.
#[derive(Default)]
pub(crate) struct DriverStats {
    pub(crate) ticks: AtomicU64,
}

/// Result of setting up progressive relay.
pub(crate) struct ProgressiveRelay {
    /// Ordered byte stream handed to `secure_handshake`.
    pub(crate) bridge: StreamBridge,
    /// Atomic tracker dynamically reflecting the active channel type.
    pub(crate) tracker: Arc<AtomicU8>,
    /// Set once hole punching has *resolved* (succeeded or given up). Lets a
    /// caller wait for the real routing decision instead of burning a fixed
    /// timeout on a connection that is still punching (see `set_migration_gate`).
    pub(crate) punching_done: Arc<AtomicBool>,
    /// Loop diagnostics; not read in production.
    #[allow(dead_code)]
    pub(crate) stats: Arc<DriverStats>,
}

/// Start progressive relay streaming immediately, spawning a background task
/// to discover candidates, punch a UDP hole, and migrate the live stream.
pub(crate) fn start_progressive_relay(
    signal: SignalingClient,
    config: Arc<WanConfig>,
) -> ProgressiveRelay {
    let (bridge, ends) = bridge_pair();
    let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
    let stats = Arc::new(DriverStats::default());
    let punching_done = Arc::new(AtomicBool::new(false));

    let (cand_tx, cand_rx) = mpsc::channel::<TraversalCandidates>(1);
    let (peer_cand_tx, peer_cand_rx) = mpsc::channel::<TraversalCandidates>(4);
    let (punch_tx, punch_rx) = mpsc::channel::<(Arc<UdpSocket>, SocketAddr)>(1);

    if config.enable_hole_punching {
        tokio::spawn(discover_and_punch(
            config.clone(),
            to_hex(&config.peer_public_key),
            cand_tx,
            peer_cand_rx,
            punch_tx,
            punching_done.clone(),
        ));
    } else {
        // Nothing to wait for: this connection will never leave the relay.
        punching_done.store(true, Ordering::Release);
    }

    tokio::spawn(run_progressive(
        signal,
        config,
        ends,
        tracker.clone(),
        punching_done.clone(),
        stats.clone(),
        cand_rx,
        peer_cand_tx,
        punch_rx,
    ));

    ProgressiveRelay {
        bridge,
        tracker,
        punching_done,
        stats,
    }
}

/// Guarantees `punching_done` is set on every failure/early-exit branch, while
/// allowing a successful punch to hand off ownership to `run_progressive` so
/// `wait_channel_settle` does not observe `punching_done == true` before
/// `migrate_propose`/`migrate_ack` actually updates `tracker`.
struct PunchDoneGuard(Option<Arc<AtomicBool>>);

impl PunchDoneGuard {
    fn new(flag: Arc<AtomicBool>) -> Self {
        Self(Some(flag))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for PunchDoneGuard {
    fn drop(&mut self) {
        if let Some(flag) = &self.0 {
            flag.store(true, Ordering::Release);
        }
    }
}

/// Gather candidates once and punch on the very socket that produced them.
///
/// This runs off the driver loop so the relay can start forwarding immediately;
/// the candidates are handed back to the driver (the only writer on the
/// WebSocket) for advertising. `punching_done` is set on every return path via
/// the guard so a caller can wait for the real routing decision.
async fn discover_and_punch(
    config: Arc<WanConfig>,
    expected_peer_hex: String,
    cand_tx: mpsc::Sender<TraversalCandidates>,
    mut peer_cand_rx: mpsc::Receiver<TraversalCandidates>,
    punch_tx: mpsc::Sender<(Arc<UdpSocket>, SocketAddr)>,
    punching_done: Arc<AtomicBool>,
) {
    let mut done = PunchDoneGuard::new(punching_done);
    let my_hex = to_hex(&config.my_public_key);
    let session =
        match gather_traversal_session(&my_hex, config.tcp_port, config.stun_server.as_deref())
            .await
        {
            Ok(session) => session,
            Err(err) => {
                tracing::debug!("candidate gathering failed: {err}");
                return;
            }
        };
    let socket = session.socket();
    let local = session.candidates.clone();

    // Advertised `udp_port`/`srflx` come from this socket, and so will every
    // punch probe and every data frame below.
    if cand_tx.send(local.clone()).await.is_err() {
        return;
    }

    let peer = match tokio::time::timeout(config.punch_timeout * 2, peer_cand_rx.recv()).await {
        Ok(Some(peer)) => peer,
        _ => return,
    };
    if !peer.public_key.eq_ignore_ascii_case(&expected_peer_hex) {
        tracing::warn!("peer candidate frame did not match the pinned identity");
        return;
    }

    let strategy = decide_traversal_strategy(
        NatClassification::from_u8(local.nat_type),
        NatClassification::from_u8(peer.nat_type),
        !local.ipv6_gua.is_empty() && !peer.ipv6_gua.is_empty(),
    );
    if matches!(strategy, TraversalDecision::DirectRelayImmediate) {
        tracing::info!("both peers are behind symmetric NAT; keeping the relay path");
        return;
    }

    let local_is_v4 = socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
    let targets: Vec<SocketAddr> = peer_udp_targets(&peer)
        .into_iter()
        .filter(|a| a.is_ipv4() == local_is_v4)
        .collect();
    if targets.is_empty() {
        return;
    }

    // A symmetric NAT can still be punched asymmetrically; only the matrix's
    // explicit "0% chance" verdict above is allowed to skip the attempt.
    match punch(&socket, &targets, config.punch_timeout).await {
        Ok(peer_addr) => {
            // Which candidate won matters: a LAN target and a cellular
            // srflx address can differ by two orders of magnitude in
            // throughput, and this is the only place that knows.
            tracing::info!("punched a direct UDP path to {peer_addr}");
            if punch_tx.send((socket, peer_addr)).await.is_ok() {
                // Hand off `punching_done` completion to `run_progressive` so
                // it flips only after the WS migration barrier updates `tracker`.
                done.disarm();
            }
        }
        Err(err) => tracing::debug!("udp punch failed: {err}"),
    }
}

/// Encrypt one signalling frame and write it. Returns `false` if the WebSocket
/// is gone, which is fatal for the driver.
async fn send_frame<S>(
    sink: &mut S,
    key: &[u8; AEAD_KEY_LEN],
    room: &str,
    epoch: u64,
    seq: &mut u64,
    kind: &str,
    plaintext: &[u8],
) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    *seq += 1;
    let Ok(wire) = seal(key, room, epoch, *seq, kind, plaintext) else {
        return false;
    };
    sink.send(Message::Binary(wire.into_bytes().into()))
        .await
        .is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn run_progressive(
    signal: SignalingClient,
    config: Arc<WanConfig>,
    mut ends: BridgeEnds,
    tracker: Arc<AtomicU8>,
    punching_done: Arc<AtomicBool>,
    stats: Arc<DriverStats>,
    mut cand_rx: mpsc::Receiver<TraversalCandidates>,
    peer_cand_tx: mpsc::Sender<TraversalCandidates>,
    mut punch_res_rx: mpsc::Receiver<(Arc<UdpSocket>, SocketAddr)>,
) {
    let _driver_done = PunchDoneGuard::new(punching_done.clone());
    let SignalingClient {
        mut sink,
        mut stream,
        key,
        room,
        epoch,
        mut send_seq,
        mut recv_seq,
        server_epoch: _,
    } = signal;
    let role = role_for(&config.my_public_key, &config.peer_public_key);

    // Relay write/read are separate flags: a half-closed migration keeps the
    // other direction alive.
    let mut relay_write_open = true;
    let mut direct_write = false;
    let mut direct_read = false;
    let mut awaiting_ack: Option<Instant> = None;
    let mut migration_aborted = false;
    let mut ws_open = true;
    let mut candidates_open = true;
    let mut outbound_done = false;
    let mut local_closed_at: Option<Instant> = None;
    let mut last_close_sent: Option<Instant> = None;
    let mut peer_eof = false;
    let mut peer_final: Option<u64> = None;
    // Dropping `inbound_tx` surfaces clean EOF to the local reader on half-close
    // without terminating our write direction.
    let mut inbound_tx = Some(ends.inbound_tx);

    let mut direct_socket: Option<Arc<UdpSocket>> = None;
    let mut direct_peer: Option<SocketAddr> = None;

    let mut next_udp_seq: u64 = 1;
    let mut recv_udp_next: u64 = 1;
    let mut sent_udp: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut recv_ooo: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut retransmit_rounds: u32 = 0;
    let mut retransmit_every: u32 = 1;
    let mut backoff_ticks: u32 = 0;
    let mut last_peer_udp_rx = Instant::now();
    let mut last_keepalive_tx = Instant::now();
    let mut last_ack_seen: u64 = 0;
    let mut dup_acks: u32 = 0;
    let mut inorder_since_ack: u32 = 0;
    // AIMD governs the direct path only: the relay leg releases credit the
    // moment the sink accepts, so it needs the full ceiling and must not be
    // throttled by a window that exists to protect the UDP link.
    let mut aimd = AimdWindow::new();

    let mut udp_tick = interval(RETRANSMIT_INTERVAL);
    udp_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut udp_buf = vec![0u8; 65536];
    let mut relay_pace = RelayPacer::new();

    loop {
        stats.ticks.fetch_add(1, Ordering::Relaxed);

        if direct_write {
            // Wait until every direct DATA packet is ACKed AND either the peer
            // finished every packet up to its `KIND_CLOSE` marker or the idle
            // close deadline elapsed with no peer packets.
            if outbound_done && sent_udp.is_empty() {
                let idle = local_closed_at.is_some_and(|t| t.elapsed() >= CLOSE_TIMEOUT)
                    && last_peer_udp_rx.elapsed() >= CLOSE_TIMEOUT;
                if peer_eof || idle {
                    break;
                }
            }
        } else if outbound_done && (peer_eof || !ws_open) {
            break;
        }

        tokio::select! {
            // Application writes. Parked (`!awaiting_ack`) for the duration of
            // one migration round trip so that no relay frame can follow the
            // PROPOSE that closes the relay stream.
            outbound = ends.outbound_rx.recv(), if !outbound_done && awaiting_ack.is_none() => {
                match outbound {
                    None => {
                        outbound_done = true;
                        local_closed_at = Some(Instant::now());
                        if direct_write {
                            if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                                let close = build_packet(KIND_CLOSE, next_udp_seq, recv_udp_next, &[]);
                                let _ = sock.send_to(&close, peer).await;
                                last_close_sent = Some(Instant::now());
                            }
                        } else if relay_write_open
                            && !send_frame(
                                &mut sink,
                                &key,
                                &room,
                                epoch,
                                &mut send_seq,
                                "relay",
                                &[],
                            )
                            .await
                        {
                            break;
                        }
                    }
                    Some(bytes) if bytes.is_empty() => {
                        outbound_done = true;
                        local_closed_at = Some(Instant::now());
                        if direct_write {
                            if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                                let close = build_packet(KIND_CLOSE, next_udp_seq, recv_udp_next, &[]);
                                let _ = sock.send_to(&close, peer).await;
                                last_close_sent = Some(Instant::now());
                            }
                        } else if relay_write_open
                            && !send_frame(
                                &mut sink,
                                &key,
                                &room,
                                epoch,
                                &mut send_seq,
                                "relay",
                                &[],
                            )
                            .await
                        {
                            break;
                        }
                    }
                    Some(bytes) => {
                        if direct_write {
                            if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                                for chunk in bytes.chunks(MAX_PAYLOAD) {
                                    let seq = next_udp_seq;
                                    next_udp_seq += 1;
                                    let packet = build_packet(KIND_DATA, seq, recv_udp_next, chunk);
                                    let _ = sock.send_to(&packet, peer).await;
                                    sent_udp.insert(seq, packet);
                                }
                                last_keepalive_tx = Instant::now();
                            }
                        } else if relay_write_open {
                            let mut ok = true;
                            for chunk in bytes.chunks(RELAY_CHUNK) {
                                relay_pace.wait().await;
                                if !send_frame(&mut sink, &key, &room, epoch, &mut send_seq, "relay", chunk).await {
                                    ok = false;
                                    break;
                                }
                            }
                            if !ok {
                                // Release even on the failure path: the writer
                                // may still poll once more before observing
                                // the channel close, and parked credit it can
                                // never spend turns a clean error into a hang.
                                ends.flow.release(bytes.len());
                                break;
                            }
                            ends.flow.release(bytes.len());
                        }
                    }
                }
            }

            // Signalling and relay frames from the peer.
            incoming_ws = stream.next(), if ws_open => {
                let raw = match incoming_ws {
                    Some(Ok(Message::Binary(b))) => b.to_vec(),
                    Some(Ok(Message::Text(t))) => t.as_bytes().to_vec(),
                    Some(Ok(_)) => continue,
                    // Do NOT `continue` here: a terminated stream reports `None`
                    // again immediately, which would spin this loop at 100% CPU.
                    None | Some(Err(_)) => {
                        ws_open = false;
                        continue;
                    }
                };
                match super::signaling::open(&key, &room, epoch, &mut recv_seq, &raw) {
                    Ok(Some((kind, pt))) => match kind.as_str() {
                        "relay" => {
                            if pt.is_empty() {
                                peer_eof = true;
                                inbound_tx = None;
                                continue;
                            }
                            // After the barrier the peer has no relay frames
                            // left; anything arriving now would be a duplicate.
                            if !direct_read {
                                if let Some(tx) = inbound_tx.as_ref() {
                                    if tx.send(pt).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        "candidate" => {
                            if let Ok(cand) = serde_json::from_slice::<TraversalCandidates>(&pt) {
                                let _ = peer_cand_tx.try_send(cand);
                            }
                        }
                        "migrate_propose" => {
                            if role != WanRole::Responder {
                                continue;
                            }
                            match (&direct_socket, direct_peer) {
                                (Some(_), Some(_)) => {
                                    // Our own relay stream is finished as of the
                                    // last frame we wrote, i.e. right now.
                                    relay_write_open = false;
                                    direct_write = true;
                                    direct_read = true;
                                    if !send_frame(&mut sink, &key, &room, epoch, &mut send_seq, "migrate_ack", &[]).await {
                                        break;
                                    }
                                    tracker.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
                                    punching_done.store(true, Ordering::Release);
                                }
                                _ => {
                                    // Punching failed on this side: tell the
                                    // initiator to keep the relay instead of
                                    // waiting for an ACK that cannot come.
                                    if !send_frame(&mut sink, &key, &room, epoch, &mut send_seq, "migrate_reject", &[]).await {
                                        break;
                                    }
                                    punching_done.store(true, Ordering::Release);
                                }
                            }
                        }
                        "migrate_ack" => {
                            if role != WanRole::Initiator || migration_aborted || awaiting_ack.is_none() {
                                continue;
                            }
                            awaiting_ack = None;
                            direct_write = true;
                            direct_read = true;
                            tracker.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
                            punching_done.store(true, Ordering::Release);
                        }
                        "migrate_reject" => {
                            if role != WanRole::Initiator {
                                continue;
                            }
                            awaiting_ack = None;
                            relay_write_open = true;
                            punching_done.store(true, Ordering::Release);
                            tracing::info!("peer declined migration; staying on the relay");
                        }
                        _ => {}
                    },
                    Ok(None) => {}
                    Err(err) => {
                        tracing::debug!("signalling frame rejected: {err}");
                        ws_open = false;
                    }
                }
            }

            // Candidates gathered by the background task, advertised once.
            cand = cand_rx.recv(), if candidates_open => {
                match cand {
                    Some(local) => {
                        let Ok(wire) = serde_json::to_vec(&local) else { continue };
                        if !send_frame(&mut sink, &key, &room, epoch, &mut send_seq, "candidate", &wire).await {
                            break;
                        }
                    }
                    None => candidates_open = false,
                }
            }

            // A direct path became available.
            Some((sock, peer_addr)) = punch_res_rx.recv() => {
                direct_socket = Some(sock);
                direct_peer = Some(peer_addr);
                if role == WanRole::Initiator && awaiting_ack.is_none() && !direct_write {
                    // Close the relay write side *before* proposing: the
                    // WebSocket order is the barrier the peer relies on.
                    relay_write_open = false;
                    awaiting_ack = Some(Instant::now());
                    if !send_frame(&mut sink, &key, &room, epoch, &mut send_seq, "migrate_propose", &[]).await {
                        break;
                    }
                }
            }

            incoming_udp = async {
                if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                    match sock.recv_from(&mut udp_buf).await {
                        Ok((n, from)) => Some((n, from, sock.clone(), peer)),
                        Err(_) => None,
                    }
                } else {
                    futures_util::future::pending::<Option<(usize, SocketAddr, Arc<UdpSocket>, SocketAddr)>>().await
                }
            }, if direct_read => {
                if let Some((n, from, sock, peer)) = incoming_udp {
                    if from == peer {
                        let parsed = parse_packet(&udp_buf[..n]);
                        if let Some((kind, seq, ack, payload)) = parsed {
                            last_peer_udp_rx = Instant::now();

                            let acked: Vec<u64> = sent_udp.keys().copied().filter(|s| *s < ack).collect();
                            let mut freed = 0usize;
                            for s in acked {
                                if let Some(packet) = sent_udp.remove(&s) {
                                    freed += packet.len() - HEADER_LEN;
                                }
                            }
                            if freed > 0 {
                                ends.flow.release(freed);
                                aimd.on_progress(freed);
                                ends.flow.set_cap(aimd.value());
                                retransmit_rounds = 0;
                                retransmit_every = 1;
                                backoff_ticks = 0;
                            }

                            // Fast retransmit: repeated ACKs at the same
                            // cumulative position mean the packet at that
                            // offset was lost. Resending just the hole now
                            // beats waiting for the backoff timer to re-flood
                            // the entire in-flight window.
                            if ack > last_ack_seen {
                                last_ack_seen = ack;
                                dup_acks = 0;
                            } else if ack == last_ack_seen {
                                dup_acks += 1;
                                if dup_acks >= DUP_ACK_FAST_RETRANSMIT {
                                    dup_acks = 0;
                                    aimd.on_loss();
                                    ends.flow.set_cap(aimd.value());
                                    if let Some(packet) = sent_udp.get(&ack) {
                                        let _ = sock.send_to(packet, peer).await;
                                    }
                                }
                            }

                            if kind == KIND_DATA {
                                // Decide the cadence before the insert mutates
                                // the state: a retransmission or an
                                // out-of-order arrival answers at once, a
                                // clean in-order packet shares one ACK per
                                // [`ACK_EVERY`] packets.
                                let ack_now = seq != recv_udp_next || !recv_ooo.is_empty();
                                let within_ooo_bound = seq >= recv_udp_next
                                    && seq < recv_udp_next.saturating_add(MAX_OOO_PACKETS as u64)
                                    && (seq == recv_udp_next || recv_ooo.len() < MAX_OOO_PACKETS);
                                if within_ooo_bound && !recv_ooo.contains_key(&seq) {
                                    recv_ooo.insert(seq, payload.to_vec());
                                    while let Some(seg) = recv_ooo.remove(&recv_udp_next) {
                                        recv_udp_next += 1;
                                        if let Some(tx) = inbound_tx.as_ref() {
                                            if tx.send(seg).is_err() {
                                                return;
                                            }
                                        }
                                    }
                                    if peer_final.is_some_and(|f| recv_udp_next >= f) {
                                        peer_eof = true;
                                        inbound_tx = None;
                                    }
                                }
                                if !ack_now {
                                    inorder_since_ack += 1;
                                    if inorder_since_ack < ACK_EVERY {
                                        continue;
                                    }
                                }
                                inorder_since_ack = 0;
                                // Batched or immediate, every DATA decision
                                // ends in one ACK at the current position.
                                let ack_packet = build_packet(KIND_ACK, 0, recv_udp_next, &[]);
                                let _ = sock.send_to(&ack_packet, peer).await;
                            } else if kind == KIND_PUNCH {
                                let ack_packet = build_packet(KIND_ACK, 0, recv_udp_next, &[]);
                                let _ = sock.send_to(&ack_packet, peer).await;
                            } else if kind == KIND_CLOSE {
                                // `seq` carries the sender's final DATA sequence
                                // (exclusive). Wait until `recv_udp_next >= seq`
                                // before surfacing EOF so a CLOSE overtaking a
                                // reordered tail DATA packet never truncates it.
                                peer_final = Some(peer_final.map_or(seq, |prev| prev.max(seq)));
                                if peer_final.is_some_and(|f| recv_udp_next >= f) {
                                    peer_eof = true;
                                    inbound_tx = None;
                                }
                                let ack_packet = build_packet(KIND_ACK, 0, recv_udp_next, &[]);
                                let _ = sock.send_to(&ack_packet, peer).await;
                            }
                        }
                    }
                }
            }

            _ = udp_tick.tick(), if direct_write || awaiting_ack.is_some() => {
                // A migration that never gets its ACK must not park the writer
                // forever: fall back to the relay we never stopped listening on.
                if let Some(since) = awaiting_ack {
                    if since.elapsed() >= MIGRATION_ACK_TIMEOUT {
                        awaiting_ack = None;
                        migration_aborted = true;
                        relay_write_open = true;
                        punching_done.store(true, Ordering::Release);
                        tracing::warn!("migration ACK timed out; resuming the relay");
                        continue;
                    }
                }
                if !direct_write {
                    continue;
                }
                if let (Some(sock), Some(peer)) = (&direct_socket, direct_peer) {
                    // Re-advertise KIND_CLOSE periodically after local write close
                    // (matching `wan::udp`) instead of inserting it into `sent_udp`.
                    if outbound_done
                        && last_close_sent.is_none_or(|t| t.elapsed() >= KEEPALIVE_INTERVAL)
                    {
                        let close = build_packet(KIND_CLOSE, next_udp_seq, recv_udp_next, &[]);
                        let _ = sock.send_to(&close, peer).await;
                        last_close_sent = Some(Instant::now());
                    }
                    if sent_udp.is_empty() {
                        if last_peer_udp_rx.elapsed() >= KEEPALIVE_INTERVAL
                            && last_keepalive_tx.elapsed() >= KEEPALIVE_INTERVAL
                        {
                            let probe = build_packet(KIND_PUNCH, 0, recv_udp_next, &[]);
                            let _ = sock.send_to(&probe, peer).await;
                            last_keepalive_tx = Instant::now();
                        }
                    } else {
                        // Exponential backoff: flooding a 4 MiB window every
                        // 200 ms makes a congested link worse, not better.
                        backoff_ticks += 1;
                        if backoff_ticks.is_multiple_of(retransmit_every) {
                            retransmit_rounds += 1;
                            if retransmit_rounds > MAX_RETRANSMIT_ROUNDS {
                                // There is no safe way back to the relay (the
                                // peer already stopped listening on it), so fail
                                // loudly instead of truncating the stream.
                                tracing::warn!("direct UDP path stopped acknowledging data");
                                break;
                            }
                            for packet in sent_udp.values() {
                                let _ = sock.send_to(packet, peer).await;
                            }
                            aimd.on_loss();
                            ends.flow.set_cap(aimd.value());
                            retransmit_every = (retransmit_every * 2).min(64);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::secure::{secure_handshake_client, secure_handshake_server, SecureStream};
    use futures_util::stream::{SplitSink, SplitStream};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream, WebSocketStream};

    type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    const ROOM: &str = "00112233445566778899aabbccddeeff";
    const EPOCH: u64 = 42;

    /// One second of frames at the sustained rate + the full burst must take
    /// at least one wall-clock second: that is what keeps a server window —
    /// even one straddling the client's — under its 256 msg/s budget. Only a
    /// lower bound is asserted so a loaded machine cannot flake the test.
    #[tokio::test]
    async fn relay_pacer_stays_under_the_server_budget() {
        let mut pacer = RelayPacer::new();
        let frames = RelayPacer::RATE_PER_SEC as usize + RelayPacer::BURST as usize;
        let start = std::time::Instant::now();
        for _ in 0..frames {
            pacer.wait().await;
        }
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "{} frames left the pacer in {:?}; the budget allows ~1s",
            frames,
            start.elapsed()
        );
    }

    /// Blind forwarder with exactly two clients, mirroring the Durable Object.
    async fn forwarder() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (s1, _) = listener.accept().await.unwrap();
            let ws1 = accept_async(s1).await.unwrap();
            let (s2, _) = listener.accept().await.unwrap();
            let ws2 = accept_async(s2).await.unwrap();
            let (mut w1, mut r1) = ws1.split();
            let (mut w2, mut r2) = ws2.split();
            // Both pumps live in one task on purpose: when either peer goes
            // away the whole connection must collapse, otherwise a driver would
            // keep a half-open socket that never reports EOF.
            loop {
                tokio::select! {
                    m = r1.next() => match m {
                        Some(Ok(m)) => { if w2.send(m).await.is_err() { break } }
                        _ => break,
                    },
                    m = r2.next() => match m {
                        Some(Ok(m)) => { if w1.send(m).await.is_err() { break } }
                        _ => break,
                    },
                }
            }
        });
        (port, task)
    }

    async fn ws_side(port: u16) -> Ws {
        let (ws, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
            .await
            .unwrap();
        ws
    }

    fn client_from(ws: Ws, key: [u8; AEAD_KEY_LEN]) -> SignalingClient {
        let (sink, stream) = ws.split();
        SignalingClient {
            sink,
            stream,
            key: zeroize::Zeroizing::new(key),
            room: ROOM.to_string(),
            epoch: EPOCH,
            send_seq: 0,
            recv_seq: 0,
            server_epoch: None,
        }
    }

    /// Minimal RFC 5389 responder that echoes the source endpoint, so
    /// `probe_nat_behavior` short-circuits to "open internet" in microseconds
    /// instead of waiting out a public STUN timeout.
    async fn spawn_echo_stun() -> SocketAddr {
        use crate::stun::{BINDING_RESPONSE, STUN_MAGIC_COOKIE};
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                if n < 20 {
                    continue;
                }
                let tid: [u8; 12] = buf[8..20].try_into().unwrap();
                let mut body = Vec::new();
                body.extend_from_slice(&0x0020u16.to_be_bytes());
                body.extend_from_slice(&8u16.to_be_bytes());
                body.push(0);
                body.push(0x01);
                let xport = from.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                body.extend_from_slice(&xport.to_be_bytes());
                let ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                    std::net::IpAddr::V6(_) => 0x7f00_0001,
                };
                body.extend_from_slice(&(ip ^ STUN_MAGIC_COOKIE).to_be_bytes());
                let mut resp = Vec::new();
                resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
                resp.extend_from_slice(&(body.len() as u16).to_be_bytes());
                resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                resp.extend_from_slice(&tid);
                resp.extend_from_slice(&body);
                let _ = sock.send_to(&resp, from).await;
            }
        });
        addr
    }

    fn base_config(port: u16) -> WanConfig {
        WanConfig {
            signaling_endpoint: format!("ws://127.0.0.1:{port}/ws"),
            room: ROOM.to_string(),
            epoch: EPOCH,
            psk: zeroize::Zeroizing::new(b"adaptive-psk".to_vec()),
            enable_hole_punching: false,
            punch_timeout: Duration::from_millis(600),
            ..WanConfig::default()
        }
    }

    /// The advertised candidate must describe the socket that actually punches.
    /// A second socket has a different NAT mapping, so the peer would punch a
    /// hole nobody is reading from.
    #[tokio::test(flavor = "multi_thread")]
    async fn progressive_advertises_the_socket_it_punches_from() {
        let (port, fwd) = forwarder().await;
        let stun = spawn_echo_stun().await;

        let id_a = crate::trust::generate_identity();
        let id_b = crate::trust::generate_identity();
        let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
        let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
        let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();
        let key =
            super::super::signaling::signaling_key(b"adaptive-psk".as_ref(), ROOM, &pk_a, &pk_b);

        let mut cfg = base_config(port);
        cfg.identity_seed = seed_a;
        cfg.my_public_key = pk_a;
        cfg.peer_public_key = pk_b;
        cfg.enable_hole_punching = true;
        cfg.stun_server = Some(stun.to_string());

        let driver_ws = ws_side(port).await;
        let prog = start_progressive_relay(client_from(driver_ws, key), Arc::new(cfg));

        // Peer advertises an observer socket the driver is expected to punch.
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observer_port = observer.local_addr().unwrap().port();
        let peer_ws = ws_side(port).await;
        let (mut peer_sink, mut peer_stream): (SplitSink<Ws, Message>, SplitStream<Ws>) =
            peer_ws.split();

        let peer_cand = TraversalCandidates {
            public_key: to_hex(&pk_b),
            lan_ipv4: Vec::new(),
            ipv6_gua: Vec::new(),
            srflx: Some(format!("127.0.0.1:{observer_port}")),
            tcp_port: 0,
            udp_port: observer_port,
            nat_type: 1,
        };
        let mut peer_seq = 0u64;
        assert!(
            send_frame(
                &mut peer_sink,
                &key,
                ROOM,
                EPOCH,
                &mut peer_seq,
                "candidate",
                &serde_json::to_vec(&peer_cand).unwrap(),
            )
            .await
        );

        // The driver's own candidate frame tells us what it advertised.
        let mut last = 0u64;
        let local = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = peer_stream.next().await.unwrap().unwrap();
                let bytes = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    _ => continue,
                };
                if let Ok(Some((kind, pt))) =
                    super::super::signaling::open(&key, ROOM, EPOCH, &mut last, &bytes)
                {
                    if kind == "candidate" {
                        break serde_json::from_slice::<TraversalCandidates>(&pt).unwrap();
                    }
                }
            }
        })
        .await
        .expect("driver must advertise its candidates");

        let mut buf = [0u8; 2048];
        let (_, from) = tokio::time::timeout(Duration::from_secs(5), observer.recv_from(&mut buf))
            .await
            .expect("driver must punch the advertised endpoint")
            .unwrap();

        assert_eq!(
            from.port(),
            local.udp_port,
            "advertised udp_port must be the port probes come from"
        );
        let advertised_srflx_port: u16 = local
            .srflx
            .as_deref()
            .expect("echo STUN must have produced a srflx")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(advertised_srflx_port, from.port());
        let _ = prog;
        fwd.abort();
    }

    /// After the barrier no relay frame may follow: the peer stops accepting
    /// the relay at that point, so anything later is a hole in the stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn migration_closes_the_relay_before_proposing() {
        let (port, fwd) = forwarder().await;
        let key = [7u8; AEAD_KEY_LEN];
        let mut cfg = base_config(port);
        cfg.my_public_key = [1u8; 32]; // smaller key -> initiator
        cfg.peer_public_key = [2u8; 32];

        let driver = client_from(ws_side(port).await, key);
        let (bridge, ends) = bridge_pair();
        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        let stats = Arc::new(DriverStats::default());
        let (cand_tx, cand_rx) = mpsc::channel::<TraversalCandidates>(1);
        drop(cand_tx);
        let (peer_cand_tx, _peer_cand_rx) = mpsc::channel::<TraversalCandidates>(4);
        let (punch_tx, punch_rx) = mpsc::channel::<(Arc<UdpSocket>, SocketAddr)>(1);

        let driver_task = tokio::spawn(run_progressive(
            driver,
            Arc::new(cfg),
            ends,
            tracker.clone(),
            Arc::new(AtomicBool::new(false)),
            stats,
            cand_rx,
            peer_cand_tx,
            punch_rx,
        ));

        let (mut sink_p, mut stream_p): (SplitSink<Ws, Message>, SplitStream<Ws>) =
            ws_side(port).await.split();
        let mut peer_seq = 0u64;

        let mut writer_bridge = bridge;
        let writer = tokio::spawn(async move {
            let mut written = 0usize;
            for _ in 0..200 {
                if writer_bridge.write_all(&[0xABu8; 1024]).await.is_err() {
                    break;
                }
                written += 1024;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = writer_bridge.shutdown().await;
            written
        });

        tokio::time::sleep(Duration::from_millis(120)).await;
        let punch_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let drain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        punch_tx
            .send((punch_socket.clone(), drain.local_addr().unwrap()))
            .await
            .unwrap();

        let mut last = 0u64;
        let mut kinds: Vec<String> = Vec::new();
        let mut relay_bytes = 0usize;
        let deadline = Instant::now() + Duration::from_millis(1200);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(Some(Ok(msg))) = tokio::time::timeout(remaining, stream_p.next()).await else {
                break;
            };
            let bytes = match msg {
                Message::Binary(b) => b.to_vec(),
                Message::Text(t) => t.as_bytes().to_vec(),
                _ => continue,
            };
            if let Ok(Some((kind, pt))) =
                super::super::signaling::open(&key, ROOM, EPOCH, &mut last, &bytes)
            {
                if kind == "relay" {
                    relay_bytes += pt.len();
                }
                if kind == "migrate_propose" {
                    // A real peer needs a round trip to answer; holding the ACK
                    // back is what exposes a migration that keeps writing relay
                    // frames in the meantime.
                    tokio::time::sleep(Duration::from_millis(120)).await;
                    assert!(
                        send_frame(
                            &mut sink_p,
                            &key,
                            ROOM,
                            EPOCH,
                            &mut peer_seq,
                            "migrate_ack",
                            &[],
                        )
                        .await
                    );
                }
                kinds.push(kind);
            }
        }
        // The responder side of the direct path: ACK every DATA packet at the
        // cumulative position so the sender's AIMD window keeps opening (a
        // silent drain would park the writer the moment a loss halves the
        // window below its outstanding bytes — correct production behavior
        // this test must not trip over), and count each sequence once.
        let drain_task = tokio::spawn(async move {
            let mut udp_unique: BTreeMap<u64, usize> = BTreeMap::new();
            let mut ubuf = [0u8; 2048];
            // The progressive driver numbers DATA from 1 (unlike udp::drive's
            // 0-based space); the responder must expect the same first seq or
            // its cumulative ACK never advances past zero.
            let mut recv_next: u64 = 1;
            let mut recv_ooo: BTreeMap<u64, usize> = BTreeMap::new();
            let mut final_pos: Option<u64> = None;
            loop {
                let idle = Duration::from_millis(1500);
                let Ok(Ok((n, from))) =
                    tokio::time::timeout(idle, drain.recv_from(&mut ubuf)).await
                else {
                    break;
                };
                let Some((kind, seq, _, payload)) = parse_packet(&ubuf[..n]) else {
                    continue;
                };
                match kind {
                    KIND_DATA => {
                        if seq >= recv_next {
                            recv_ooo.insert(seq, payload.len());
                            while let Some(len) = recv_ooo.remove(&recv_next) {
                                udp_unique.insert(recv_next, len);
                                recv_next += 1;
                            }
                        }
                        let pos = final_pos.map_or(recv_next, |f| recv_next.max(f));
                        let ack = build_packet(KIND_ACK, 0, pos, &[]);
                        let _ = drain.send_to(&ack, from).await;
                    }
                    // The close marker carries the sender's final DATA
                    // sequence; acknowledging one past it releases the marker
                    // from the sender's retransmit set.
                    KIND_CLOSE => {
                        final_pos = Some(final_pos.map_or(seq, |f| f.max(seq)) + 1);
                        let ack = build_packet(KIND_ACK, 0, final_pos.unwrap_or(recv_next), &[]);
                        let _ = drain.send_to(&ack, from).await;
                    }
                    _ => {}
                }
            }
            udp_unique
        });
        let written = writer.await.unwrap();

        // Everything that left the application must come out exactly once, on
        // one transport or the other. A migration that silently drops the
        // window between PROPOSE and ACK shows up here as missing bytes.
        let udp_unique = drain_task.await.unwrap();
        let udp_bytes: usize = udp_unique.values().sum();
        assert_eq!(
            relay_bytes + udp_bytes,
            written,
            "bytes were lost across the migration (relay {relay_bytes} + udp {udp_bytes} != written {written})"
        );

        let propose = kinds
            .iter()
            .position(|k| k == "migrate_propose")
            .expect("the driver must propose migration");
        assert!(
            kinds[..propose].iter().any(|k| k == "relay"),
            "the relay must carry the early bytes: {kinds:?}"
        );
        assert!(
            kinds[propose + 1..].iter().all(|k| k != "relay"),
            "relay frames after the barrier would be dropped by the peer: {kinds:?}"
        );
        driver_task.abort();
        fwd.abort();
    }

    /// A terminated signalling stream reports `None` forever. The driver must
    /// go idle, not spin on that branch at 100% CPU.
    #[tokio::test(flavor = "multi_thread")]
    async fn dead_signalling_does_not_spin_the_driver() {
        let (port, fwd) = forwarder().await;
        let key = [9u8; AEAD_KEY_LEN];
        let mut cfg = base_config(port);
        cfg.my_public_key = [1u8; 32];
        cfg.peer_public_key = [2u8; 32];

        let driver = client_from(ws_side(port).await, key);
        let (bridge, ends) = bridge_pair();
        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        let stats = Arc::new(DriverStats::default());
        let (_cand_tx, cand_rx) = mpsc::channel::<TraversalCandidates>(1);
        let (peer_cand_tx, _peer_cand_rx) = mpsc::channel::<TraversalCandidates>(4);
        let (punch_tx, punch_rx) = mpsc::channel::<(Arc<UdpSocket>, SocketAddr)>(1);

        let driver_task = tokio::spawn(run_progressive(
            driver,
            Arc::new(cfg),
            ends,
            tracker.clone(),
            Arc::new(AtomicBool::new(false)),
            stats.clone(),
            cand_rx,
            peer_cand_tx,
            punch_rx,
        ));

        let (mut sink_p, mut stream_p): (SplitSink<Ws, Message>, SplitStream<Ws>) =
            ws_side(port).await.split();
        let mut peer_seq = 0u64;
        let mut last = 0u64;

        // Drive the connection into the migrated state.
        let punch_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let drain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        punch_tx
            .send((punch_socket.clone(), drain.local_addr().unwrap()))
            .await
            .unwrap();
        let mut bridge_keep = bridge;
        bridge_keep.write_all(b"before-migration").await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "migration never happened");
            let Ok(Some(Ok(msg))) = tokio::time::timeout(remaining, stream_p.next()).await else {
                continue;
            };
            let bytes = match msg {
                Message::Binary(b) => b.to_vec(),
                Message::Text(t) => t.as_bytes().to_vec(),
                _ => continue,
            };
            if let Ok(Some((kind, _))) =
                super::super::signaling::open(&key, ROOM, EPOCH, &mut last, &bytes)
            {
                if kind == "migrate_propose" {
                    send_frame(
                        &mut sink_p,
                        &key,
                        ROOM,
                        EPOCH,
                        &mut peer_seq,
                        "migrate_ack",
                        &[],
                    )
                    .await;
                    break;
                }
            }
        }
        // The ACK is in flight: wait for the driver to adopt the direct path.
        let deadline = Instant::now() + Duration::from_secs(2);
        while tracker.load(Ordering::Acquire) != ChannelType::HolePunchedDirect as u8 {
            assert!(Instant::now() < deadline, "migration never completed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Kill the signalling transport, then sample the loop budget from a
        // plain OS thread: if the driver really spins it starves the async
        // runtime, and an async observer would hang instead of failing.
        drop(sink_p);
        drop(stream_p);
        let sampled = stats.clone();
        let delta = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let before = sampled.ticks.load(Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(300));
            let after = sampled.ticks.load(Ordering::Relaxed);
            after.saturating_sub(before)
        })
        .join()
        .unwrap();
        assert!(
            delta < 200,
            "driver loop ran {delta} times in 300 ms of silence; it is spinning"
        );

        driver_task.abort();
        fwd.abort();
        let _ = bridge_keep;
    }

    /// End to end: stream over relay, migrate, keep streaming.
    #[tokio::test(flavor = "multi_thread")]
    async fn progressive_migration_cuts_over_to_direct_udp() {
        let (port, fwd) = forwarder().await;
        let id_a = crate::trust::generate_identity();
        let id_b = crate::trust::generate_identity();
        let seed_a: [u8; 32] = id_a.seed.clone().try_into().unwrap();
        let seed_b: [u8; 32] = id_b.seed.clone().try_into().unwrap();
        let pk_a: [u8; 32] = id_a.public_key.clone().try_into().unwrap();
        let pk_b: [u8; 32] = id_b.public_key.clone().try_into().unwrap();
        let key = [9u8; AEAD_KEY_LEN];

        let mut cfg_a = base_config(port);
        cfg_a.identity_seed = seed_a;
        cfg_a.my_public_key = pk_a;
        cfg_a.peer_public_key = pk_b;
        cfg_a.enable_hole_punching = true;
        let mut cfg_b = base_config(port);
        cfg_b.identity_seed = seed_b;
        cfg_b.my_public_key = pk_b;
        cfg_b.peer_public_key = pk_a;
        cfg_b.enable_hole_punching = true;

        let prog_a =
            start_progressive_relay(client_from(ws_side(port).await, key), Arc::new(cfg_a));
        let prog_b =
            start_progressive_relay(client_from(ws_side(port).await, key), Arc::new(cfg_b));

        let (mut stream_a, mut stream_b): (SecureStream, SecureStream) = tokio::try_join!(
            secure_handshake_client(prog_a.bridge, &seed_a, Some(&pk_b)),
            secure_handshake_server(prog_b.bridge, &seed_b, Some(&pk_a)),
        )
        .unwrap();

        stream_a.send(b"data-before-migration").await.unwrap();
        let mut buf = Vec::new();
        stream_b.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"data-before-migration");

        tokio::time::sleep(Duration::from_millis(400)).await;

        stream_b.send(b"data-after-migration").await.unwrap();
        buf.clear();
        stream_a.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"data-after-migration");

        fwd.abort();
    }

    /// P0 regression: a migrated driver must actually terminate.
    ///
    /// The migrated driver sends `KIND_CLOSE` over the direct UDP path, but the
    /// inline UDP loop used to ignore `KIND_CLOSE`, so `peer_eof` was never set
    /// and the termination condition (`outbound_done && peer_eof`) could never
    /// be met — every successful migration leaked a background driver task for
    /// the life of the process. This drives one driver through migration + data
    /// + close against a minimal fake peer and asserts the driver task joins.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrated_driver_terminates_after_close() {
        use crate::proto::ChannelType;

        let (port, fwd) = forwarder().await;
        let key = [13u8; AEAD_KEY_LEN];
        let mut cfg = base_config(port);
        cfg.my_public_key = [1u8; 32]; // initiator (<= peer) so it proposes
        cfg.peer_public_key = [2u8; 32];

        let driver_ws = ws_side(port).await;
        let driver = client_from(driver_ws, key);
        let (bridge, ends) = bridge_pair();
        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        let stats = Arc::new(DriverStats::default());
        let (_cand_tx, cand_rx) = mpsc::channel::<TraversalCandidates>(1);
        let (peer_cand_tx, _peer_cand_rx) = mpsc::channel::<TraversalCandidates>(4);
        let (punch_tx, punch_rx) = mpsc::channel::<(Arc<UdpSocket>, SocketAddr)>(1);

        let driver_task = tokio::spawn(run_progressive(
            driver,
            Arc::new(cfg),
            ends,
            tracker.clone(),
            Arc::new(AtomicBool::new(false)),
            stats,
            cand_rx,
            peer_cand_tx,
            punch_rx,
        ));

        // Fake peer: acknowledges migration and bounces a CLOSE back over UDP.
        let peer_ws = ws_side(port).await;
        let (mut peer_sink, mut peer_stream) = peer_ws.split();
        let mut peer_seq = 0u64;
        let mut last = 0u64;
        let peer_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_udp_addr = peer_udp.local_addr().unwrap();
        let ws_peer = tokio::spawn(async move {
            loop {
                let Ok(Some(Ok(msg))) =
                    tokio::time::timeout(Duration::from_secs(3), peer_stream.next()).await
                else {
                    break;
                };
                let bytes = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    _ => continue,
                };
                if let Ok(Some((kind, _))) =
                    super::super::signaling::open(&key, ROOM, EPOCH, &mut last, &bytes)
                {
                    if kind == "migrate_propose" {
                        let _ = send_frame(
                            &mut peer_sink,
                            &key,
                            ROOM,
                            EPOCH,
                            &mut peer_seq,
                            "migrate_ack",
                            &[],
                        )
                        .await;
                    }
                }
            }
        });
        let udp_peer = tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                let Ok((n, from)) = peer_udp.recv_from(&mut buf).await else {
                    break;
                };
                if let Some((kind, seq, _, _)) = parse_packet(&buf[..n]) {
                    if kind == KIND_CLOSE {
                        let close = build_packet(KIND_CLOSE, 1, seq, &[]);
                        let _ = peer_udp.send_to(&close, from).await;
                    } else if kind == KIND_DATA {
                        let ack = build_packet(KIND_ACK, 0, seq + 1, &[]);
                        let _ = peer_udp.send_to(&ack, from).await;
                    }
                }
            }
        });

        // Hand the driver its punched socket pointed at the fake peer.
        let sock_driver = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let _ = punch_tx.send((sock_driver.clone(), peer_udp_addr)).await;

        // Wait for migration to land so the close travels over the direct path.
        let deadline = Instant::now() + Duration::from_secs(3);
        while tracker.load(Ordering::Acquire) != ChannelType::HolePunchedDirect as u8 {
            assert!(Instant::now() < deadline, "migration never completed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Drive some data, then close the application stream.
        let mut bridge = bridge;
        bridge
            .write_all(b"payload-over-the-direct-path")
            .await
            .unwrap();
        bridge.shutdown().await.unwrap();

        // The driver must terminate once it has both finished its own writes
        // and learned the peer finished (KIND_CLOSE over UDP). A leaked driver
        // makes this join time out, which is exactly the P0 symptom.
        let finished = tokio::time::timeout(Duration::from_secs(5), driver_task)
            .await
            .expect("migrated driver must terminate after close (P0 leak)");
        let _ = (finished, ws_peer, udp_peer);
        fwd.abort();
    }

    /// Regression for audit question #3: if the responder dies or drops
    /// `migrate_ack` after `migrate_propose`, `MIGRATION_ACK_TIMEOUT` must
    /// still fire while `direct_write` is false and resume relay writes
    /// instead of parking the writer forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn migration_ack_timeout_resumes_relay_when_responder_silent() {
        let (port, fwd) = forwarder().await;
        let key = [0x66u8; AEAD_KEY_LEN];
        let mut cfg = base_config(port);
        cfg.my_public_key = [1u8; 32]; // initiator so it sends migrate_propose
        cfg.peer_public_key = [2u8; 32];

        let driver_ws = ws_side(port).await;
        let driver = client_from(driver_ws, key);
        let (mut bridge, ends) = bridge_pair();
        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        let stats = Arc::new(DriverStats::default());
        let (_cand_tx, cand_rx) = mpsc::channel::<TraversalCandidates>(1);
        let (peer_cand_tx, _peer_cand_rx) = mpsc::channel::<TraversalCandidates>(4);
        let (punch_tx, punch_rx) = mpsc::channel::<(Arc<UdpSocket>, SocketAddr)>(1);

        let driver_task = tokio::spawn(run_progressive(
            driver,
            Arc::new(cfg),
            ends,
            tracker.clone(),
            Arc::new(AtomicBool::new(false)),
            stats,
            cand_rx,
            peer_cand_tx,
            punch_rx,
        ));

        let peer_ws = ws_side(port).await;
        let (_peer_sink, mut peer_stream) = peer_ws.split();

        let peer_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_driver = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let _ = punch_tx
            .send((sock_driver, peer_udp.local_addr().unwrap()))
            .await;

        // Wait until the initiator emits `migrate_propose` on the relay, and
        // deliberately never send `migrate_ack`.
        let mut saw_propose = false;
        let mut last = 0u64;
        let propose_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < propose_deadline {
            if let Ok(Some(Ok(msg))) =
                tokio::time::timeout(Duration::from_millis(200), peer_stream.next()).await
            {
                let bytes = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    _ => continue,
                };
                if let Ok(Some((kind, _))) =
                    super::super::signaling::open(&key, ROOM, EPOCH, &mut last, &bytes)
                {
                    if kind == "migrate_propose" {
                        saw_propose = true;
                        break;
                    }
                }
            }
        }
        assert!(saw_propose, "initiator must send migrate_propose");

        // Queue application bytes while `awaiting_ack` is active; they must
        // flow over the relay once MIGRATION_ACK_TIMEOUT (5s) elapses.
        bridge.write_all(b"after-ack-timeout").await.unwrap();
        let mut saw_relay_after_timeout = false;
        let resume_deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < resume_deadline {
            if let Ok(Some(Ok(msg))) =
                tokio::time::timeout(Duration::from_millis(500), peer_stream.next()).await
            {
                let bytes = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    _ => continue,
                };
                if let Ok(Some((kind, payload))) =
                    super::super::signaling::open(&key, ROOM, EPOCH, &mut last, &bytes)
                {
                    if kind == "relay" && payload == b"after-ack-timeout" {
                        saw_relay_after_timeout = true;
                        break;
                    }
                }
            }
        }
        assert!(
            saw_relay_after_timeout,
            "initiator must resume relay writes after MIGRATION_ACK_TIMEOUT"
        );
        assert_eq!(
            tracker.load(Ordering::Acquire),
            ChannelType::RelayForwarded as u8
        );

        driver_task.abort();
        fwd.abort();
    }
}
