//! WAN NAT traversal: candidate gathering, ranking and UDP target selection.
//!
//! The single most important invariant lives here: **one UDP socket** is used
//! for STUN discovery, hole punching and the data plane. A server-reflexive
//! address is only valid for the exact local binding that produced it; binding
//! a second socket (or dropping the first) invalidates the mapping the peer
//! was told to dial.

use crate::link::{race_connect, RaceConfig, RaceOutcome};
use luciola_proto::{ChannelType, TraversalCandidates};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

/// Errors from candidate racing.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TraversalError {
    /// No candidate could be reached, and no relay was established.
    #[error("no reachable candidate and no relay connection was established")]
    NoRoute,
}

/// Local candidates plus the **live** UDP socket that produced `srflx`.
///
/// Keep this session alive for the whole WAN connection attempt: dropping the
/// socket releases the NAT mapping.
pub struct TraversalSession {
    /// Candidates to exchange with the peer through the signalling plane.
    pub candidates: TraversalCandidates,
    socket: Arc<UdpSocket>,
}

impl TraversalSession {
    /// The socket that must be reused for punching and the data plane.
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Local UDP port behind the advertised reflexive candidate.
    pub fn udp_port(&self) -> u16 {
        self.candidates.udp_port
    }
}

/// Gather local candidates while retaining the STUN socket for punching.
///
/// `stun_server` overrides the built-in public STUN list. SRFLX carries its
/// full `ip:port`; callers must not strip the port.
pub async fn gather_traversal_session(
    public_key: &str,
    tcp_port: u16,
    stun_server: Option<&str>,
) -> std::io::Result<TraversalSession> {
    let mut lan_ipv4 = Vec::new();
    let mut ipv6_gua = Vec::new();
    for addr in luciola_net::NetworkDetector::local_candidate_addresses() {
        if addr.contains(':') {
            if let Some(scope) = luciola_ip::get_ipv6_scope(&addr) {
                if matches!(scope, luciola_ip::Ipv6Scope::Global) {
                    ipv6_gua.push(addr);
                }
            }
        } else {
            lan_ipv4.push(addr);
        }
    }

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let udp_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);

    let servers: Vec<&str> = match stun_server {
        Some(s) => vec![s],
        None => crate::stun::DEFAULT_STUN_SERVERS.to_vec(),
    };
    let srflx = match tokio::time::timeout(
        Duration::from_millis(1500),
        crate::stun::query_public_address(&socket, &servers),
    )
    .await
    {
        Ok(Ok(addr)) => Some(addr.to_string()),
        _ => None,
    };

    Ok(TraversalSession {
        candidates: TraversalCandidates {
            public_key: public_key.to_string(),
            lan_ipv4,
            ipv6_gua,
            srflx,
            tcp_port,
            udp_port,
        },
        socket,
    })
}

/// Diagnostic-only variant: gathers candidates but **drops** the STUN socket.
///
/// WAN callers must use [`gather_traversal_session`] instead; the `srflx`
/// candidate returned here is not usable for punching because its mapping is
/// released when this function returns.
pub async fn gather_traversal_candidates(
    public_key: &str,
    tcp_port: u16,
    stun_server: Option<&str>,
) -> TraversalCandidates {
    match gather_traversal_session(public_key, tcp_port, stun_server).await {
        Ok(session) => session.candidates,
        Err(_) => TraversalCandidates {
            public_key: public_key.to_string(),
            lan_ipv4: Vec::new(),
            ipv6_gua: Vec::new(),
            srflx: None,
            tcp_port,
            udp_port: 0,
        },
    }
}

/// Full UDP endpoints to punch, in priority order. Unlike
/// [`prioritize_peer_candidates`] this **keeps the srflx port**, which is the
/// NAT-mapped port the peer actually listens on.
pub fn peer_udp_targets(candidates: &TraversalCandidates) -> Vec<SocketAddr> {
    let mut targets: Vec<SocketAddr> = Vec::new();

    // 1. IPv6 global unicast: end-to-end, no port mapping.
    for v6 in &candidates.ipv6_gua {
        if let Ok(addr) = format!("[{v6}]:{}", candidates.udp_port).parse() {
            targets.push(addr);
        }
    }
    // 2. LAN IPv4 (peers may still share a subnet even across WAN pairing).
    for v4 in &candidates.lan_ipv4 {
        if let Ok(addr) = format!("{v4}:{}", candidates.udp_port).parse() {
            targets.push(addr);
        }
    }
    // 3. Server-reflexive endpoint, with its mapped port intact.
    if let Some(ref srflx) = candidates.srflx {
        if let Ok(addr) = srflx.parse() {
            if !targets.contains(&addr) {
                targets.push(addr);
            }
        }
    }
    targets
}

/// TCP host candidates for LAN Happy Eyeballs (no ports; `race_connect`
/// appends the secure TCP port itself).
pub fn prioritize_peer_candidates(candidates: &TraversalCandidates) -> Vec<String> {
    let mut targets = Vec::new();
    for v6 in &candidates.ipv6_gua {
        targets.push(format!("[{v6}]"));
    }
    for v4 in &candidates.lan_ipv4 {
        targets.push(v4.clone());
    }
    if let Some(ref srflx) = candidates.srflx {
        let host = match srflx.rsplit_once(':') {
            Some((h, _)) => h.trim_matches('[').trim_matches(']'),
            None => srflx.as_str(),
        };
        let shaped = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        if !targets.contains(&shaped) {
            targets.push(shaped);
        }
    }
    targets
}

/// Race LAN TCP candidates and classify the winner.
///
/// A failed race is an **error**, never `RelayForwarded`: that channel type is
/// only legitimate once a relay connection has actually been established.
pub async fn race_lan_candidates(
    candidates: &TraversalCandidates,
    config: RaceConfig,
) -> Result<(RaceOutcome, ChannelType), TraversalError> {
    let prioritized = prioritize_peer_candidates(candidates);
    let outcome = race_connect(prioritized, candidates.tcp_port, config).await;
    let Some(winner) = outcome.winner.as_ref() else {
        return Err(TraversalError::NoRoute);
    };
    let clean = winner.trim_matches('[').trim_matches(']');
    let channel_type = if candidates.lan_ipv4.iter().any(|v| v == clean) {
        ChannelType::LanDirect
    } else {
        // IPv6 GUA or a reflexive endpoint reached directly.
        ChannelType::HolePunchedDirect
    };
    Ok((outcome, channel_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TraversalCandidates {
        TraversalCandidates {
            public_key: "abc123".into(),
            lan_ipv4: vec!["192.168.1.50".into(), "10.0.0.5".into()],
            ipv6_gua: vec!["2408:8248::1".into()],
            srflx: Some("203.0.113.10:45678".into()),
            tcp_port: 17879,
            udp_port: 43210,
        }
    }

    #[test]
    fn udp_targets_keep_the_reflexive_port() {
        let targets = peer_udp_targets(&sample());
        assert_eq!(
            targets,
            vec![
                "[2408:8248::1]:43210".parse().unwrap(),
                "192.168.1.50:43210".parse().unwrap(),
                "10.0.0.5:43210".parse().unwrap(),
                "203.0.113.10:45678".parse().unwrap(),
            ]
        );
        // The classic bug: srflx port must not collapse onto the TCP/UDP port.
        assert_eq!(targets.last().unwrap().port(), 45678);
    }

    #[test]
    fn tcp_host_priority_orders_ipv6_first() {
        assert_eq!(
            prioritize_peer_candidates(&sample()),
            vec![
                "[2408:8248::1]".to_string(),
                "192.168.1.50".to_string(),
                "10.0.0.5".to_string(),
                "203.0.113.10".to_string(),
            ]
        );
    }

    #[test]
    fn malformed_srflx_is_ignored_not_panicking() {
        let mut cand = sample();
        cand.srflx = Some("not-an-address".into());
        assert_eq!(peer_udp_targets(&cand).len(), 3);
    }
}
