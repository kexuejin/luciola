//! Reliable, ordered UDP byte stream + UDP hole punching.
//!
//! UDP hole punching creates a **UDP-only** NAT mapping, while the existing
//! secure channel was TCP-bound. A naive swap to datagrams would break the
//! AES-256-GCM strictly increasing counter nonce (reordered datagrams would
//! fail authentication). This module keeps the crypto untouched by exposing
//! the datagram path as an *ordered byte stream* via a small ARQ:
//!
//! ```text
//! DATA  : [magic][kind][len][seq][ack][payload]   seq = packet sequence
//! ACK   : [magic][kind][ 0 ][ 0 ][ack]            ack = next expected seq
//! CLOSE : [magic][kind][ 0 ][final_seq][ack]
//! ```
//!
//! Cumulative ACKs, an out-of-order packet buffer and a retransmission timer
//! give exactly-once, in-order delivery. Because packets are never re-chunked,
//! overlapping byte ranges cannot occur. `StreamBridge` adds credit-based
//! backpressure so an unresponsive peer cannot grow an unbounded send queue.
//!
//! `CLOSE` carries the sender's final DATA sequence; it is a *marker*, not an
//! immediate EOF. A receiver keeps ACKing and delivering until `recv_next`
//! reaches that sequence, otherwise a CLOSE that overtakes a reordered DATA
//! packet silently truncates the tail of the stream.
//!
//! The **same socket** used for the STUN Binding query is reused for punching
//! and then for this data plane; dropping it (or binding a second one) would
//! invalidate the server-reflexive mapping the peer was told to dial.

use super::bridge::{bridge_pair, StreamBridge};
use super::WanError;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{interval, Instant};

const MAGIC: &[u8; 4] = b"LUD1";
const HEADER_LEN: usize = 24;
/// Stay below the 1280-byte IPv6 minimum MTU with room for encapsulation.
pub(crate) const MAX_PAYLOAD: usize = 1200;
const MAX_DATAGRAM: usize = HEADER_LEN + MAX_PAYLOAD;

pub(crate) const KIND_DATA: u8 = 1;
pub(crate) const KIND_ACK: u8 = 2;
pub(crate) const KIND_PUNCH: u8 = 3;
pub(crate) const KIND_CLOSE: u8 = 4;

const PUNCH_INTERVAL: Duration = Duration::from_millis(50);
const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(200);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RETRANSMITS: u32 = 40;
/// Bound the lifetime of a half-closed driver whose peer never answers.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(300);

/// Build one datagram. `ack` is the sender's cumulative receive position.
pub(crate) fn build_packet(kind: u8, seq: u64, ack: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse one datagram, rejecting anything truncated, mis-magicked or with a
/// length field that runs past the received bytes.
pub(crate) fn parse_packet(buf: &[u8]) -> Option<(u8, u64, u64, &[u8])> {
    if buf.len() < HEADER_LEN || &buf[0..4] != MAGIC {
        return None;
    }
    let kind = buf[4];
    let len = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if HEADER_LEN + len > buf.len() || len > MAX_PAYLOAD {
        return None;
    }
    let seq = u64::from_be_bytes(buf[8..16].try_into().ok()?);
    let ack = u64::from_be_bytes(buf[16..24].try_into().ok()?);
    Some((kind, seq, ack, &buf[HEADER_LEN..HEADER_LEN + len]))
}

/// Simultaneous-open UDP hole punching.
///
/// Sends keepalive/keep-open probes to every peer candidate until one answers.
/// The source address of the first valid peer datagram becomes the data-plane
/// peer: it is the actual NAT-mapped endpoint, which may differ from the
/// advertised candidate (e.g. a port-dependent mapping).
pub(crate) async fn punch(
    socket: &UdpSocket,
    targets: &[SocketAddr],
    timeout: Duration,
) -> Result<SocketAddr, WanError> {
    if targets.is_empty() {
        return Err(WanError::NoRoute("no peer UDP candidates".into()));
    }
    tokio::time::timeout(timeout, punch_inner(socket, targets))
        .await
        .map_err(|_| WanError::NoRoute("UDP hole punching timed out".into()))?
}

async fn punch_inner(socket: &UdpSocket, targets: &[SocketAddr]) -> Result<SocketAddr, WanError> {
    let mut tick = interval(PUNCH_INTERVAL);
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let probe = build_packet(KIND_PUNCH, 0, 0, &[]);
                for target in targets {
                    let _ = socket.send_to(&probe, target).await;
                }
            }
            res = socket.recv_from(&mut buf) => {
                let (n, from) = res.map_err(WanError::Io)?;
                if let Some((kind, _, _, _)) = parse_packet(&buf[..n]) {
                    if matches!(kind, KIND_PUNCH | KIND_DATA | KIND_ACK) {
                        // Answer so the peer can finish its own punch even if
                        // its probe reached us before ours reached it.
                        let probe = build_packet(KIND_PUNCH, 0, 0, &[]);
                        let _ = socket.send_to(&probe, from).await;
                        return Ok(from);
                    }
                }
            }
        }
    }
}

/// Start the ARQ driver over a punched socket and return the ordered stream.
pub(crate) fn start_stream(socket: Arc<UdpSocket>, peer: SocketAddr) -> StreamBridge {
    let (bridge, ends) = bridge_pair();
    tokio::spawn(async move {
        if let Err(err) = drive(socket, peer, ends).await {
            tracing::debug!("udp arq driver stopped: {err}");
        }
    });
    bridge
}

async fn drive(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut ends: super::bridge::BridgeEnds,
) -> io::Result<()> {
    let mut sent: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut next_seq: u64 = 0;
    let mut recv_next: u64 = 0;
    let mut recv_ooo: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut retransmits: u32 = 0;
    let mut last_activity = Instant::now();
    let mut tick = interval(RETRANSMIT_INTERVAL);
    let mut buf = [0u8; MAX_DATAGRAM];
    // Half-close state. CLOSE carries the sender's final DATA sequence in its
    // `seq` field: the receiver must keep delivering (and ACKing) until every
    // packet before that marker has arrived in order. Breaking on CLOSE alone
    // truncates the tail whenever the marker overtakes a reordered DATA packet.
    let mut local_write_closed = false;
    let mut local_closed_at: Option<Instant> = None;
    let mut last_close_sent: Option<Instant> = None;
    let mut outbound_done = false;
    let mut peer_final: Option<u64> = None;

    loop {
        // Both directions must be finished before the driver may drop the
        // inbound channel (which would surface as EOF to the secure channel).
        // A peer that disappears instead of closing is bounded by the idle cap.
        if local_write_closed && sent.is_empty() {
            let peer_done = peer_final.is_some_and(|final_seq| recv_next >= final_seq);
            let idle = local_closed_at.is_some_and(|t| t.elapsed() >= CLOSE_TIMEOUT)
                && last_activity.elapsed() >= CLOSE_TIMEOUT;
            if peer_done || idle {
                break;
            }
        }
        tokio::select! {
            // Once the application drops its writer, `recv()` would return
            // `None` forever; disable the branch instead of spinning or, worse,
            // breaking and abandoning still-unacknowledged retransmissions.
            outbound = ends.outbound_rx.recv(), if !outbound_done => {
                match outbound {
                    None => {
                        outbound_done = true;
                        local_write_closed = true;
                        local_closed_at = Some(Instant::now());
                    }
                    Some(bytes) if bytes.is_empty() => {
                        local_write_closed = true;
                        local_closed_at = Some(Instant::now());
                        let close = build_packet(KIND_CLOSE, next_seq, recv_next, &[]);
                        let _ = socket.send_to(&close, peer).await;
                        last_close_sent = Some(Instant::now());
                    }
                    Some(bytes) => {
                        for chunk in bytes.chunks(MAX_PAYLOAD) {
                            let seq = next_seq;
                            next_seq += 1;
                            let packet = build_packet(KIND_DATA, seq, recv_next, chunk);
                            socket.send_to(&packet, peer).await?;
                            sent.insert(seq, packet);
                        }
                        last_activity = Instant::now();
                    }
                }
            }
            incoming = socket.recv_from(&mut buf) => {
                let (n, from) = incoming?;
                if from != peer {
                    // STUN responses / probes from other candidates: ignore.
                    continue;
                }
                let Some((kind, seq, ack, payload)) = parse_packet(&buf[..n]) else {
                    continue;
                };
                last_activity = Instant::now();
                if kind == KIND_CLOSE {
                    // Do NOT break here: the marker can overtake DATA packets.
                    peer_final = Some(peer_final.map_or(seq, |f| f.max(seq)));
                }

                // Piggyback ACK: free credit for every packet now covered.
                let acked: Vec<u64> = sent.keys().copied().filter(|s| *s < ack).collect();
                let mut freed = 0usize;
                for s in acked {
                    if let Some(packet) = sent.remove(&s) {
                        freed += packet.len() - HEADER_LEN;
                    }
                }
                if freed > 0 {
                    ends.flow.release(freed);
                    retransmits = 0;
                    last_activity = Instant::now();
                }

                if kind == KIND_DATA && seq >= recv_next {
                    if recv_ooo.insert(seq, payload.to_vec()).is_none() {
                        while let Some(seg) = recv_ooo.remove(&recv_next) {
                            recv_next += 1;
                            if ends.inbound_tx.send(seg).is_err() {
                                return Ok(());
                            }
                        }
                    }
                    // Always ACK: a lost ACK would otherwise stall the sender
                    // until its retransmission timer fired.
                    let ack_packet = build_packet(KIND_ACK, 0, recv_next, &[]);
                    socket.send_to(&ack_packet, peer).await?;
                    last_activity = Instant::now();
                }
            }
            _ = tick.tick() => {
                // CLOSE is a UDP datagram and can be lost. Re-advertise it (and
                // our cumulative ACK position) while we wait for the peer's own
                // CLOSE, so a single lost marker cannot wedge the half-close.
                if local_write_closed
                    && last_close_sent.is_none_or(|t| t.elapsed() >= KEEPALIVE_INTERVAL)
                {
                    let close = build_packet(KIND_CLOSE, next_seq, recv_next, &[]);
                    socket.send_to(&close, peer).await?;
                    last_close_sent = Some(Instant::now());
                }
                if sent.is_empty() {
                    if last_activity.elapsed() >= KEEPALIVE_INTERVAL {
                        let probe = build_packet(KIND_PUNCH, 0, recv_next, &[]);
                        socket.send_to(&probe, peer).await?;
                        last_activity = Instant::now();
                    }
                } else {
                    retransmits += 1;
                    if retransmits > MAX_RETRANSMITS {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "peer stopped acknowledging UDP data",
                        ));
                    }
                    for packet in sent.values() {
                        socket.send_to(packet, peer).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::secure::{
        secure_handshake_client_with_remote, secure_handshake_server_with_remote,
    };
    use crate::trust::generate_identity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn packet_codec_roundtrips_and_rejects_truncation() {
        let packet = build_packet(KIND_DATA, 42, 17, b"payload");
        let (kind, seq, ack, payload) = parse_packet(&packet).unwrap();
        assert_eq!(
            (kind, seq, ack, payload),
            (KIND_DATA, 42, 17, &b"payload"[..])
        );
        assert!(parse_packet(&packet[..10]).is_none());
        let mut bad_magic = packet.clone();
        bad_magic[0] ^= 1;
        assert!(parse_packet(&bad_magic).is_none());
        let mut bad_len = packet.clone();
        bad_len[7] = 0xff;
        assert!(parse_packet(&bad_len).is_none());
    }

    /// Two ARQ drivers connected through a lossy, reordering UDP proxy.
    /// The byte stream must still be exact and in order.
    #[tokio::test(flavor = "multi_thread")]
    async fn arq_recovers_loss_and_reorder() {
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a_addr = sock_a.local_addr().unwrap();
        let b_addr = sock_b.local_addr().unwrap();
        let pa = proxy_a.local_addr().unwrap();
        let pb = proxy_b.local_addr().unwrap();

        let proxy = tokio::spawn({
            let proxy_a = proxy_a.clone();
            let proxy_b = proxy_b.clone();
            async move {
                let mut ba = [0u8; MAX_DATAGRAM];
                let mut bb = [0u8; MAX_DATAGRAM];
                let mut held: Option<(Vec<u8>, SocketAddr)> = None;
                let mut seen = 0u32;
                let mut tick = interval(Duration::from_millis(30));
                loop {
                    tokio::select! {
                        r = proxy_a.recv_from(&mut ba) => {
                            let Ok((n, _)) = r else { break };
                            forward((&proxy_a, &proxy_b), (a_addr, b_addr), b_addr,
                                    &ba[..n], &mut held, &mut seen).await;
                        }
                        r = proxy_b.recv_from(&mut bb) => {
                            let Ok((n, _)) = r else { break };
                            forward((&proxy_a, &proxy_b), (a_addr, b_addr), a_addr,
                                    &bb[..n], &mut held, &mut seen).await;
                        }
                        _ = tick.tick() => {
                            if let Some((pkt, dest)) = held.take() {
                                let sink = sink_for((&proxy_a, &proxy_b), (a_addr, b_addr), dest);
                                let _ = sink.send_to(&pkt, dest).await;
                            }
                        }
                    }
                }
            }
        });

        let mut a = start_stream(sock_a, pa);
        let mut b = start_stream(sock_b, pb);

        let total = 256 * 1024usize;
        let expected: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let expected_clone = expected.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&expected_clone).await.unwrap();
            a.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; total];
            b.read_exact(&mut got).await.unwrap();
            got
        });
        let got = tokio::time::timeout(Duration::from_secs(20), reader)
            .await
            .expect("ARQ must recover within 20s")
            .unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected, "byte stream must be exact and ordered");
        proxy.abort();
    }

    type Sinks<'a> = (&'a UdpSocket, &'a UdpSocket);

    fn sink_for<'a>(
        sinks: Sinks<'a>,
        addrs: (SocketAddr, SocketAddr),
        dest: SocketAddr,
    ) -> &'a UdpSocket {
        if dest == addrs.0 {
            sinks.0
        } else {
            sinks.1
        }
    }

    async fn forward(
        sinks: Sinks<'_>,
        addrs: (SocketAddr, SocketAddr),
        dest: SocketAddr,
        pkt: &[u8],
        held: &mut Option<(Vec<u8>, SocketAddr)>,
        seen: &mut u32,
    ) {
        let is_data = parse_packet(pkt).map(|p| p.0 == KIND_DATA).unwrap_or(false);
        *seen += 1;
        if is_data && seen.is_multiple_of(13) {
            return; // drop ~8% of DATA packets
        }
        if is_data && held.is_none() && seen.is_multiple_of(3) {
            *held = Some((pkt.to_vec(), dest)); // delay one packet -> reorder
            return;
        }
        let _ = sink_for(sinks, addrs, dest).send_to(pkt, dest).await;
        if let Some((delayed, delayed_dest)) = held.take() {
            let _ = sink_for(sinks, addrs, delayed_dest)
                .send_to(&delayed, delayed_dest)
                .await;
        }
    }

    /// The secure channel (handshake + AES-256-GCM counter frames) must run
    /// unchanged over the UDP byte stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn secure_channel_runs_over_udp_byte_stream() {
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a_addr = sock_a.local_addr().unwrap();
        let b_addr = sock_b.local_addr().unwrap();

        let a_stream = start_stream(sock_a, b_addr);
        let b_stream = start_stream(sock_b, a_addr);

        let id_a = generate_identity();
        let id_b = generate_identity();
        let seed_b = id_b.seed.clone();
        let key_a = id_a.public_key.clone();
        let server = tokio::spawn(async move {
            secure_handshake_server_with_remote(b_stream, a_addr, &seed_b, Some(&key_a)).await
        });
        let mut client = tokio::time::timeout(
            Duration::from_secs(10),
            secure_handshake_client_with_remote(a_stream, b_addr, &id_a.seed, &id_b.public_key),
        )
        .await
        .expect("handshake over UDP must not hang")
        .unwrap();
        let mut server = server.await.unwrap().unwrap();

        assert_eq!(client.peer_public_key, id_b.public_key);
        client.send(b"over udp").await.unwrap();
        let mut buf = Vec::new();
        server.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"over udp");
        server.send(b"ack").await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"ack");
    }
}
