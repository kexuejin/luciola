//! Link establishment: turn a discovered peer's candidate addresses into a
//! working connection path.
//!
//! Discovery answers "who is out there"; this module answers "which of their
//! addresses actually works right now". [`race_connect`] dials every candidate
//! concurrently with a small inter-attempt delay (RFC 8305 / Happy Eyeballs
//! style): the first successful TCP connect wins, everything still in flight
//! is cancelled. Callers then open their own connection on the winning
//! address (keeping sockets out of the FFI boundary).
//!
//! [`default_candidates`] centralizes the selection policy shared by the
//! demos: first three IPv4 candidates plus the first IPv6 GUA.

use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

/// Per-channel outcome of a [`race_connect`] run.
#[derive(Debug, Clone, PartialEq)]
pub struct DialChannelOutcome {
    pub address: String,
    pub status: DialStatus,
    /// Round-trip connect latency of the winning channel, in milliseconds.
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialStatus {
    Won,
    Cancelled,
    Timeout,
}

/// Overall race outcome: the winning address (if any) plus per-channel detail.
#[derive(Debug, Clone, PartialEq)]
pub struct RaceOutcome {
    pub winner: Option<String>,
    pub rtt_ms: Option<f64>,
    pub channels: Vec<DialChannelOutcome>,
}

/// Tuning for [`race_connect`].
#[derive(Debug, Clone)]
pub struct RaceConfig {
    /// Per-attempt TCP connect timeout.
    pub attempt_timeout: Duration,
    /// Delay before dialing the (n+1)-th candidate.
    pub stagger: Duration,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_millis(1500),
            stagger: Duration::from_millis(40),
        }
    }
}

/// Selection policy for which of a peer's addresses to race: first 3 IPv4
/// (discovery already orders them by NIC score) plus the first IPv6 GUA.
///
/// Addresses are bare (no brackets); IPv6 literals dial fine through
/// `ToSocketAddrs` on `(&str, u16)`.
pub fn default_candidates(addresses: &[String]) -> Vec<String> {
    let mut ipv4 = addresses.iter().filter(|a| !a.contains(':'));
    let ipv6 = addresses.iter().filter(|a| a.contains(':')).next().cloned();
    let mut out: Vec<String> = ipv4.by_ref().take(3).cloned().collect();
    if let Some(v6) = ipv6 {
        out.push(v6);
    }
    out
}

/// Race TCP dials across `addresses` on `port`; first connect wins.
///
/// The candidate sockets are dropped (closed) immediately — this function
/// measures and selects, the caller connects on the winner.
pub async fn race_connect(addresses: Vec<String>, port: u16, config: RaceConfig) -> RaceOutcome {
    // Dedupe preserving order.
    let mut seen = std::collections::HashSet::new();
    let channels: Vec<String> = addresses
        .into_iter()
        .filter(|a| seen.insert(a.clone()))
        .collect();

    let mut set = JoinSet::new();
    for (i, address) in channels.iter().enumerate() {
        let address = address.clone();
        let timeout = config.attempt_timeout;
        let stagger = config.stagger;
        set.spawn(async move {
            tokio::time::sleep(stagger * i as u32).await;
            let start = Instant::now();
            let connected =
                tokio::time::timeout(timeout, TcpStream::connect((address.as_str(), port)))
                    .await
                    .map(|s| s.is_ok())
                    .unwrap_or(false);
            (address, connected, start.elapsed().as_secs_f64() * 1000.0)
        });
    }

    let mut results: Vec<(String, bool, f64)> = Vec::with_capacity(channels.len());
    while let Some(joined) = set.join_next().await {
        if let Ok(triple) = joined {
            let won = triple.1;
            results.push(triple);
            if won {
                // Happy Eyeballs: the race is decided; cancel stragglers.
                set.abort_all();
                break;
            }
        }
    }
    // Channels whose tasks never completed were aborted after the win.
    let mut collected: Vec<DialChannelOutcome> = Vec::with_capacity(channels.len());
    let mut winner: Option<(String, f64)> = None;
    for address in &channels {
        if let Some(pos) = results.iter().position(|r| &r.0 == address) {
            let (_, connected, rtt) = results.remove(pos);
            if connected && winner.is_none() {
                winner = Some((address.clone(), rtt));
                collected.push(DialChannelOutcome {
                    address: address.clone(),
                    status: DialStatus::Won,
                    rtt_ms: Some(rtt),
                });
            } else if connected {
                // Connected after the winner was chosen.
                collected.push(DialChannelOutcome {
                    address: address.clone(),
                    status: DialStatus::Cancelled,
                    rtt_ms: None,
                });
            } else {
                collected.push(DialChannelOutcome {
                    address: address.clone(),
                    status: DialStatus::Timeout,
                    rtt_ms: None,
                });
            }
        } else {
            collected.push(DialChannelOutcome {
                address: address.clone(),
                status: DialStatus::Cancelled,
                rtt_ms: None,
            });
        }
    }

    RaceOutcome {
        winner: winner.as_ref().map(|(a, _)| a.clone()),
        rtt_ms: winner.map(|(_, rtt)| rtt),
        channels: collected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn race_prefers_live_listener_over_dead_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = listener.local_addr().unwrap().port();
        // A port with no listener on loopback: connect fails fast (refused).
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = probe.local_addr().unwrap().port();
        drop(probe);

        let outcome = race_connect(
            vec![
                "127.0.0.1".to_string(),
                "127.0.0.1".to_string(), // duplicate must not double-dial
            ],
            live_port,
            RaceConfig::default(),
        )
        .await;

        assert_eq!(outcome.winner.as_deref(), Some("127.0.0.1"));
        assert!(outcome.rtt_ms.unwrap() >= 0.0);
        assert_eq!(outcome.channels.len(), 1);
        assert_eq!(outcome.channels[0].status, DialStatus::Won);

        let all_dead = race_connect(
            vec!["127.0.0.1".to_string()],
            dead_port,
            RaceConfig {
                attempt_timeout: Duration::from_millis(300),
                stagger: Duration::from_millis(10),
            },
        )
        .await;
        assert!(all_dead.winner.is_none());
        assert_eq!(all_dead.channels[0].status, DialStatus::Timeout);
    }

    #[test]
    fn default_candidates_policy() {
        let addrs: Vec<String> = ["192.168.2.82", "10.0.0.5", "172.17.0.1", "100.64.1.2", "2408::1", "2408::2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            default_candidates(&addrs),
            vec!["192.168.2.82", "10.0.0.5", "172.17.0.1", "2408::1"]
        );
    }
}
