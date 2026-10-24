//! # luciola
//!
//! Lightweight, resilient peer discovery & interface intelligence for the real-world LAN.

pub use luciola_ip as ip;
pub use luciola_net as net;
pub use luciola_proto as proto;

use luciola_net::NetworkDetector;
use luciola_proto::{
    AliveDedupTracker, Codec, Envelope, JitterScheduler, MsgType, Profile,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, warn};

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind error on port {0}: {1}")]
    BindFailed(u16, std::io::Error),
}

/// A discovered peer node record in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub node_id: String,
    pub name: String,
    pub profile_rev: u32,
    pub ip: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub online: bool,
    pub last_seen: Instant,
    pub device: Option<luciola_proto::DeviceMeta>,
}

/// Discovery events emitted by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Found(PeerRecord),
    Updated(PeerRecord),
    Lost(String),
}

/// Peer registry maintaining active network nodes.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    peers: HashMap<String, PeerRecord>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Update or register a peer upon packet reception.
    pub fn touch(
        &mut self,
        node_id: &str,
        ip: &str,
        udp_port: u16,
        profile: Option<&Profile>,
    ) -> (Option<PeerRecord>, bool) {
        let now = Instant::now();
        let _is_new = !self.peers.contains_key(node_id);

        if let Some(existing) = self.peers.get_mut(node_id) {
            let was_offline = !existing.online;
            existing.last_seen = now;
            existing.online = true;
            existing.ip = ip.to_string();
            existing.udp_port = udp_port;

            if let Some(p) = profile {
                if p.profile_rev >= existing.profile_rev {
                    existing.name = p.name.clone();
                    existing.profile_rev = p.profile_rev;
                    existing.tcp_port = p.tcp_port;
                    existing.device = p.device.clone();
                }
            }

            let record = existing.clone();
            (Some(record), was_offline)
        } else if let Some(p) = profile {
            let record = PeerRecord {
                node_id: node_id.to_string(),
                name: p.name.clone(),
                profile_rev: p.profile_rev,
                ip: ip.to_string(),
                udp_port,
                tcp_port: p.tcp_port,
                online: true,
                last_seen: now,
                device: p.device.clone(),
            };
            self.peers.insert(node_id.to_string(), record.clone());
            (Some(record), true)
        } else {
            (None, false)
        }
    }

    /// Mark peer offline immediately (e.g. on receiving `exit`).
    pub fn mark_offline(&mut self, node_id: &str) -> Option<PeerRecord> {
        if let Some(peer) = self.peers.get_mut(node_id) {
            if peer.online {
                peer.online = false;
                return Some(peer.clone());
            }
        }
        None
    }

    /// Sweep peers that haven't sent a presence heartbeat within `offline_after`.
    pub fn sweep(&mut self, offline_after: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut offline_ids = Vec::new();
        for (id, peer) in self.peers.iter_mut() {
            if peer.online && now.duration_since(peer.last_seen) > offline_after {
                peer.online = false;
                offline_ids.push(id.clone());
            }
        }
        offline_ids
    }

    pub fn online_peers(&self) -> Vec<PeerRecord> {
        self.peers.values().filter(|p| p.online).cloned().collect()
    }

    pub fn profile_rev_of(&self, node_id: &str) -> Option<u32> {
        self.peers.get(node_id).map(|p| p.profile_rev)
    }
}

/// Configuration options for the discovery engine.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub self_profile: Profile,
    pub listen_port: u16,
    pub broadcast_port: u16,
    pub presence_interval: Duration,
    pub offline_after: Duration,
    pub manual_peers: Vec<(String, u16)>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            self_profile: Profile {
                node_id: "anonymous".to_string(),
                name: "Luciola Node".to_string(),
                profile_rev: 1,
                addresses: Vec::new(),
                udp_port: 17878,
                tcp_port: 17879,
                device: Some(luciola_net::DeviceDetector::detect()),
            },
            listen_port: 17878,
            broadcast_port: 17878,
            presence_interval: Duration::from_secs(5),
            offline_after: Duration::from_secs(90),
            manual_peers: Vec::new(),
        }
    }
}

/// Main async engine for peer discovery.
pub struct DiscoveryEngine {
    config: DiscoveryConfig,
    registry: Arc<RwLock<PeerRegistry>>,
    event_tx: broadcast::Sender<PeerEvent>,
    socket: Arc<RwLock<Arc<UdpSocket>>>,
}

impl DiscoveryEngine {
    /// Bind UDP socket and initialize discovery engine.
    pub async fn bind(config: DiscoveryConfig) -> Result<Arc<Self>, CoreError> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
        let std_socket = match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(_e) => {
                // Try fallback to random port if default is occupied
                let fallback_addr = SocketAddr::from(([0, 0, 0, 0], 0));
                std::net::UdpSocket::bind(fallback_addr)
                    .map_err(|e2| CoreError::BindFailed(config.listen_port, e2))?
            }
        };

        std_socket.set_broadcast(true)?;
        std_socket.set_nonblocking(true)?;

        let socket = Arc::new(RwLock::new(Arc::new(UdpSocket::from_std(std_socket)?)));
        let registry = Arc::new(RwLock::new(PeerRegistry::new()));
        let (event_tx, _) = broadcast::channel(128);

        let engine = Arc::new(Self {
            config,
            registry,
            event_tx,
            socket,
        });

        Ok(engine)
    }

    /// Retrieve currently bound local UDP port.
    pub async fn local_port(&self) -> Result<u16, std::io::Error> {
        let sock = self.socket.read().await;
        sock.local_addr().map(|a| a.port())
    }

    /// Self-healing mechanism: Rebind and rebuild the UDP socket if network changed or stalled.
    pub async fn restart_socket(&self) -> Result<(), CoreError> {
        tracing::warn!("Network stalled or socket died, rebuilding UDP discovery socket...");
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.config.listen_port));
        let std_socket = match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(_) => {
                let fallback_addr = SocketAddr::from(([0, 0, 0, 0], 0));
                std::net::UdpSocket::bind(fallback_addr)
                    .map_err(|e| CoreError::BindFailed(self.config.listen_port, e))?
            }
        };

        std_socket.set_broadcast(true)?;
        std_socket.set_nonblocking(true)?;
        let new_socket = Arc::new(UdpSocket::from_std(std_socket)?);

        let mut sock_guard = self.socket.write().await;
        *sock_guard = new_socket;
        tracing::info!("UDP discovery socket successfully rebuilt!");
        Ok(())
    }

    /// Subscribe to real-time peer discovery events.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.event_tx.subscribe()
    }

    /// Get a snapshot of currently online peers.
    pub async fn online_peers(&self) -> Vec<PeerRecord> {
        self.registry.read().await.online_peers()
    }

    /// Send broadcast entry to announce this node's presence.
    pub async fn announce(&self) {
        let envelope = Codec::make_entry(&self.config.self_profile, None);
        self.send_to_all_targets(&envelope).await;
    }

    /// Send exit broadcast before shutting down.
    pub async fn announce_exit(&self) {
        let envelope = Codec::make_exit(&self.config.self_profile.node_id);
        self.send_to_all_targets(&envelope).await;
    }

    /// Start background background loops: receiving, presence, and sweeping.
    pub fn spawn(self: Arc<Self>) {
        let engine_rx = self.clone();
        tokio::spawn(async move {
            engine_rx.receive_loop().await;
        });

        let engine_presence = self.clone();
        tokio::spawn(async move {
            engine_presence.presence_loop().await;
        });

        let engine_sweep = self.clone();
        tokio::spawn(async move {
            engine_sweep.sweep_loop().await;
        });
    }

    /// Compute broadcast targets:
    /// - Limited broadcast: `255.255.255.255`
    /// - Per-NIC Subnet broadcasts (e.g. `192.168.2.255`)
    /// - Manual configured peers
    /// - Known online peers
    async fn compute_targets(&self) -> Vec<(String, u16)> {
        let mut targets = vec![("255.255.255.255".to_string(), self.config.broadcast_port)];

        // Subnet broadcasts bypassing TUN proxy interception
        for bcast in NetworkDetector::subnet_broadcast_addresses() {
            if bcast != "255.255.255.255" {
                targets.push((bcast, self.config.broadcast_port));
            }
        }

        // Manual peers
        for (host, port) in &self.config.manual_peers {
            targets.push((host.clone(), *port));
        }

        // Known online peers
        for peer in self.registry.read().await.online_peers() {
            targets.push((peer.ip, peer.udp_port));
        }

        targets
    }

    async fn send_to_all_targets(&self, envelope: &Envelope) -> usize {
        let bytes = match Codec::encode(envelope) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to encode envelope: {}", e);
                return 0;
            }
        };

        let mut sent = 0;
        let active_socket = self.socket.read().await.clone();
        for (host, port) in self.compute_targets().await {
            let target = format!("{}:{}", host, port);
            if let Ok(addr) = target.parse::<SocketAddr>() {
                if active_socket.send_to(&bytes, addr).await.is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    }

    async fn receive_loop(&self) {
        let mut buf = [0u8; 65535];
        let mut dedup_tracker = AliveDedupTracker::new(Duration::from_millis(3000));
        let jitter = JitterScheduler::default();

        loop {
            let active_socket = self.socket.read().await.clone();
            match active_socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    let bytes = &buf[..len];
                    if let Ok(envelope) = Codec::decode(bytes) {
                        self.handle_envelope(envelope, peer_addr, &mut dedup_tracker, &jitter).await;
                    }
                }
                Err(e) => {
                    warn!("UDP receive error: {}", e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    async fn handle_envelope(
        &self,
        envelope: Envelope,
        peer_addr: SocketAddr,
        dedup_tracker: &mut AliveDedupTracker,
        jitter: &JitterScheduler,
    ) {
        // Ignore self packets
        if envelope.from == self.config.self_profile.node_id {
            return;
        }

        let msg_type = match envelope.msg_type() {
            Some(t) => t,
            None => return,
        };

        let peer_ip = peer_addr.ip().to_string();
        let peer_port = peer_addr.port();

        match msg_type {
            MsgType::Entry => {
                let profile = envelope.extract_profile();
                let (record, changed) = self.registry.write().await.touch(
                    &envelope.from,
                    &peer_ip,
                    peer_port,
                    profile.as_ref(),
                );

                if let Some(r) = record {
                    if changed {
                        let _ = self.event_tx.send(PeerEvent::Found(r));
                    }
                }

                // Schedule reply with alive
                let probe_id = envelope.extract_probe_id();
                let directed = probe_id.is_some();
                if dedup_tracker.should_reply(&envelope.from, directed) {
                    let online_count = self.registry.read().await.online_peers().len();
                    let delay = jitter.calculate_delay(online_count, directed);
                    let socket = self.socket.read().await.clone();
                    let self_profile = self.config.self_profile.clone();

                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let alive = Codec::make_alive(&self_profile, probe_id.as_deref());
                        if let Ok(bytes) = Codec::encode(&alive) {
                            let _ = socket.send_to(&bytes, peer_addr).await;
                        }
                    });
                }
            }
            MsgType::Alive => {
                let profile = envelope.extract_profile();
                let (record, changed) = self.registry.write().await.touch(
                    &envelope.from,
                    &peer_ip,
                    peer_port,
                    profile.as_ref(),
                );

                if let Some(r) = record {
                    if changed {
                        let _ = self.event_tx.send(PeerEvent::Found(r));
                    } else {
                        let _ = self.event_tx.send(PeerEvent::Updated(r));
                    }
                }
            }
            MsgType::Presence => {
                let their_rev = envelope.extract_presence_rev().unwrap_or(0);
                let (record, changed) = self.registry.write().await.touch(
                    &envelope.from,
                    &peer_ip,
                    peer_port,
                    None,
                );

                if let Some(r) = record {
                    if changed {
                        let _ = self.event_tx.send(PeerEvent::Found(r));
                    }
                }

                // If profile version mismatch, send directed entry to retrieve full profile
                let known_rev = self.registry.read().await.profile_rev_of(&envelope.from).unwrap_or(0);
                if known_rev != their_rev {
                    let entry = Codec::make_entry(&self.config.self_profile, Some("refresh"));
                    if let Ok(bytes) = Codec::encode(&entry) {
                        let socket = self.socket.read().await.clone();
                        let _ = socket.send_to(&bytes, peer_addr).await;
                    }
                }
            }
            MsgType::Exit => {
                if let Some(_) = self.registry.write().await.mark_offline(&envelope.from) {
                    let _ = self.event_tx.send(PeerEvent::Lost(envelope.from));
                }
            }
        }
    }

    async fn presence_loop(&self) {
        let mut seq = 0u32;
        let mut dead_rounds = 0u32;
        const STALLED_ROUNDS_BEFORE_RESTART: u32 = 2;

        loop {
            tokio::time::sleep(self.config.presence_interval).await;
            let presence = Codec::make_presence(
                &self.config.self_profile.node_id,
                seq,
                self.config.self_profile.profile_rev,
            );
            seq = seq.wrapping_add(1);
            let sent = self.send_to_all_targets(&presence).await;

            // Self-healing: if 0 packets could be delivered to kernel for 2 consecutive rounds,
            // assume socket is broken/stalled and rebuild it.
            if sent == 0 {
                dead_rounds += 1;
                if dead_rounds >= STALLED_ROUNDS_BEFORE_RESTART {
                    dead_rounds = 0;
                    let _ = self.restart_socket().await;
                }
            } else {
                dead_rounds = 0;
            }
        }
    }

    async fn sweep_loop(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let lost_ids = self.registry.write().await.sweep(self.config.offline_after);
            for id in lost_ids {
                let _ = self.event_tx.send(PeerEvent::Lost(id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_two_nodes_loopback_discovery() {
        // Node A
        let profile_a = Profile {
            node_id: "node_A".to_string(),
            name: "Alpha".to_string(),
            profile_rev: 1,
            addresses: vec!["127.0.0.1".to_string()],
            udp_port: 0,
            tcp_port: 8081,
            device: None,
        };
        let mut config_a = DiscoveryConfig::default();
        config_a.self_profile = profile_a;
        config_a.listen_port = 0; // OS assigns port
        let engine_a = DiscoveryEngine::bind(config_a).await.expect("bind A");

        // Node B
        let profile_b = Profile {
            node_id: "node_B".to_string(),
            name: "Beta".to_string(),
            profile_rev: 1,
            addresses: vec!["127.0.0.1".to_string()],
            udp_port: 0,
            tcp_port: 8082,
            device: None,
        };
        let mut config_b = DiscoveryConfig::default();
        config_b.self_profile = profile_b;
        config_b.listen_port = 0; // OS assigns port
        let port_a = engine_a.local_port().await.unwrap();
        config_b.manual_peers = vec![("127.0.0.1".to_string(), port_a)];
        let engine_b = DiscoveryEngine::bind(config_b).await.expect("bind B");

        let mut sub_a = engine_a.subscribe();
        let mut sub_b = engine_b.subscribe();

        engine_a.clone().spawn();
        engine_b.clone().spawn();

        // Node B announces to Node A
        engine_b.announce().await;

        // Verify Node A discovered Node B
        let event_a = tokio::time::timeout(Duration::from_secs(3), sub_a.recv()).await;
        assert!(event_a.is_ok(), "Node A should discover Node B within 3s");
        if let Ok(Ok(PeerEvent::Found(p))) = event_a {
            assert_eq!(p.node_id, "node_B");
            assert_eq!(p.name, "Beta");
        }

        // Verify Node B discovered Node A (via Alive reply)
        let event_b = tokio::time::timeout(Duration::from_secs(3), sub_b.recv()).await;
        assert!(event_b.is_ok(), "Node B should discover Node A within 3s");
        if let Ok(Ok(PeerEvent::Found(p))) = event_b {
            assert_eq!(p.node_id, "node_A");
            assert_eq!(p.name, "Alpha");
        }

        // Node B announces exit -> Node A immediately marks offline
        engine_b.announce_exit().await;
        let lost_event = tokio::time::timeout(Duration::from_secs(3), sub_a.recv()).await;
        assert!(lost_event.is_ok(), "Node A should receive Lost event for Node B");
        if let Ok(Ok(PeerEvent::Lost(id))) = lost_event {
            assert_eq!(id, "node_B");
        }
    }
}
