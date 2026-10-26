//! # luciola
//!
//! Lightweight, resilient peer discovery & interface intelligence for the real-world LAN.

pub use luciola_ip as ip;

pub mod link;
pub mod pairing;
pub mod trust;
pub use luciola_net as net;
pub use luciola_proto as proto;

use luciola_net::NetworkDetector;
use luciola_proto::{AliveDedupTracker, Codec, Envelope, JitterScheduler, MsgType, Profile};
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
    /// Stable per-device grouping id (display-grade).
    pub device_id: Option<String>,
    /// Product label running on the peer.
    pub product: Option<String>,
    /// Opaque application payload carried alongside discovery (mDNS-TXT style).
    pub extra: Option<String>,
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

/// How suitable an address is for dialling: lower is better.
///
/// IPv4 first, then global IPv6, then link-local (which needs a scope id and
/// only works on one link). Anything unparsable sorts last.
fn address_rank(ip: &str) -> u8 {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => 0,
        Ok(std::net::IpAddr::V6(v6)) => {
            let o = v6.octets();
            if (u16::from_be_bytes([o[0], o[1]]) & 0xffc0) == 0xfe80 {
                2
            } else {
                1
            }
        }
        Err(_) => 3,
    }
}

/// Whether a freshly seen address should replace the one already recorded.
///
/// Stable while the peer stays online, but a peer that comes back after a gap
/// may legitimately have moved networks, and an address of the same rank is
/// never swapped out — that is what caused mid-session flicker.
fn should_take_new_address(was_offline: bool, current_ip: &str, candidate: &str) -> bool {
    if was_offline || current_ip.is_empty() || current_ip == candidate {
        return true;
    }
    address_rank(candidate) < address_rank(current_ip)
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
            // Keep the best address we have seen while the peer stays online
            // instead of the newest one. Both families arrive continuously on a
            // multi-homed host (IPv4 subnet broadcast plus the ff02::1 group),
            // and last-write-wins made the record flicker between interfaces
            // mid-session — measured 1 run in 6 switching between
            // 10.233.138.167 and fe80::1027:fbf:772:d1f7, while any dial that
            // lands in that window gets the other family.
            //
            // A peer that reappears after a gap is allowed to move (it may have
            // changed networks), so an offline -> online transition always
            // takes the new address.
            let take_new_address = should_take_new_address(was_offline, &existing.ip, ip);
            if take_new_address {
                existing.ip = ip.to_string();
                existing.udp_port = udp_port;
            }

            if let Some(p) = profile {
                if p.profile_rev >= existing.profile_rev {
                    existing.name = p.name.clone();
                    existing.profile_rev = p.profile_rev;
                    existing.tcp_port = p.tcp_port;
                    existing.device = p.device.clone();
                    existing.device_id = p.device_id.clone();
                    existing.product = p.product.clone();
                    existing.extra = p.extra.clone();
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
                device_id: p.device_id.clone(),
                product: p.product.clone(),
                extra: p.extra.clone(),
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
        let meta = luciola_net::DeviceDetector::detect();
        let default_name = meta
            .hostname
            .clone()
            .unwrap_or_else(|| "Luciola Node".to_string());
        let device_id = meta.device_id.clone();
        Self {
            self_profile: Profile {
                node_id: "anonymous".to_string(),
                name: default_name,
                profile_rev: 1,
                addresses: Vec::new(),
                udp_port: 17878,
                tcp_port: 17879,
                device: Some(meta),
                device_id,
                product: None,
                extra: None,
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
    /// Optional IPv6-only socket on the same port: enables IPv6 discovery
    /// (ff02::1 link-local multicast + v6 unicast) alongside the v4 socket.
    config: DiscoveryConfig,
    registry: Arc<RwLock<PeerRegistry>>,
    event_tx: broadcast::Sender<PeerEvent>,
    socket: Arc<RwLock<Arc<UdpSocket>>>,
    socket_v6: Arc<RwLock<Option<Arc<UdpSocket>>>>,
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
        let port = socket.read().await.local_addr().map(|a| a.port())?;
        let socket_v6 = Arc::new(RwLock::new(bind_v6_socket(port)));
        let registry = Arc::new(RwLock::new(PeerRegistry::new()));
        let (event_tx, _) = broadcast::channel(128);

        let engine = Arc::new(Self {
            config,
            registry,
            event_tx,
            socket,
            socket_v6,
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

        let port = new_socket.local_addr().map(|a| a.port())?;
        let mut sock_guard = self.socket.write().await;
        *sock_guard = new_socket;
        drop(sock_guard);
        *self.socket_v6.write().await = bind_v6_socket(port);
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
    async fn compute_targets(&self) -> Vec<SocketAddr> {
        let mut targets: Vec<SocketAddr> = Vec::new();
        let push_parsed = |targets: &mut Vec<SocketAddr>, host: &str, port: u16| {
            let text = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            if let Ok(addr) = text.parse::<SocketAddr>() {
                targets.push(addr);
            }
        };

        push_parsed(&mut targets, "255.255.255.255", self.config.broadcast_port);
        // Subnet broadcasts bypassing TUN proxy interception
        for bcast in NetworkDetector::subnet_broadcast_addresses() {
            if bcast != "255.255.255.255" {
                push_parsed(&mut targets, &bcast, self.config.broadcast_port);
            }
        }
        // IPv6 link-local multicast on every physical interface.
        for idx in luciola_net::multicast_scope_interfaces() {
            let mut a =
                SocketAddr::from(([0xff02, 0, 0, 0, 0, 0, 0, 1], self.config.broadcast_port));
            if let SocketAddr::V6(v6) = &mut a {
                v6.set_scope_id(idx);
            }
            targets.push(a);
        }

        // Manual peers
        for (host, port) in &self.config.manual_peers {
            push_parsed(&mut targets, host, *port);
        }

        // Known online peers
        for peer in self.registry.read().await.online_peers() {
            push_parsed(&mut targets, &peer.ip, peer.udp_port);
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
        for addr in self.compute_targets().await {
            // send_via caps each dial at 300ms (a settling interface can leave
            // send_to pending forever) and picks the family-matching socket.
            if self.send_via(addr, &bytes).await {
                sent += 1;
            }
        }
        sent
    }

    async fn receive_loop(&self) {
        let mut buf = [0u8; 65535];
        let mut dedup_tracker = AliveDedupTracker::new(Duration::from_millis(3000));
        let jitter = JitterScheduler::default();

        let mut buf6 = [0u8; 65535];
        loop {
            let v4 = self.socket.read().await.clone();
            let v6 = self.socket_v6.read().await.clone();
            // Separate buffers: select polls both sockets concurrently.
            let received = match v6 {
                Some(v6sock) => tokio::select! {
                    r = v6sock.recv_from(&mut buf6) => Some((r, v6sock)),
                    r = v4.recv_from(&mut buf) => Some((r, v4)),
                },
                None => Some((v4.recv_from(&mut buf).await, v4)),
            };
            let Some((result, receiving_socket)) = received else {
                continue;
            };
            match result {
                Ok((len, peer_addr)) => {
                    let bytes: &[u8] = if receiving_socket
                        .local_addr()
                        .map(|a| a.is_ipv6())
                        .unwrap_or(false)
                    {
                        &buf6[..len]
                    } else {
                        &buf[..len]
                    };
                    if let Ok(envelope) = Codec::decode(bytes) {
                        self.handle_envelope(
                            envelope,
                            peer_addr,
                            receiving_socket,
                            &mut dedup_tracker,
                            &jitter,
                        )
                        .await;
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
        receiving_socket: Arc<UdpSocket>,
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
                    let socket = receiving_socket;
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
                let (record, changed) =
                    self.registry
                        .write()
                        .await
                        .touch(&envelope.from, &peer_ip, peer_port, None);

                if let Some(r) = record {
                    if changed {
                        let _ = self.event_tx.send(PeerEvent::Found(r));
                    }
                }

                // If profile version mismatch, send directed entry to retrieve full profile
                let known_rev = self
                    .registry
                    .read()
                    .await
                    .profile_rev_of(&envelope.from)
                    .unwrap_or(0);
                if known_rev != their_rev {
                    let entry = Codec::make_entry(&self.config.self_profile, Some("refresh"));
                    if let Ok(bytes) = Codec::encode(&entry) {
                        let _ = receiving_socket.send_to(&bytes, peer_addr).await;
                    }
                }
            }
            MsgType::Exit => {
                if self
                    .registry
                    .write()
                    .await
                    .mark_offline(&envelope.from)
                    .is_some()
                {
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

/// Bind an IPv6-only UDP socket on `port` (0 = same fallback as v4), join
/// ff02::1 on every physical interface, and set multicast loopback on.
fn bind_v6_socket(port: u16) -> Option<Arc<UdpSocket>> {
    use socket2::{Domain, Protocol, Socket as Sock, Type};
    let sock = Sock::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    // V6ONLY: keep the v4 socket authoritative for v4 traffic.
    sock.set_only_v6(true).ok()?;
    if sock
        .bind(&format!("[::]:{port}").parse::<SocketAddr>().ok()?.into())
        .is_err()
    {
        return None;
    }
    sock.set_nonblocking(true).ok()?;
    let std_socket: std::net::UdpSocket = sock.into();
    let any = std::net::Ipv6Addr::from([0xff02, 0, 0, 0, 0, 0, 0, 1]);
    for idx in luciola_net::multicast_scope_interfaces() {
        if let Err(e) = std_socket.join_multicast_v6(&any, idx) {
            tracing::warn!("ff02::1 join failed on if_index {idx}: {e}");
        }
    }
    UdpSocket::from_std(std_socket).ok().map(Arc::new)
}

impl DiscoveryEngine {
    /// Pick the socket matching the address family (v6 unicast/multicast
    /// MUST leave via the v6-only socket).
    async fn socket_for(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        if addr.is_ipv4() {
            Some(self.socket.read().await.clone())
        } else {
            self.socket_v6.read().await.clone()
        }
    }

    async fn send_via(&self, addr: SocketAddr, bytes: &[u8]) -> bool {
        match self.socket_for(addr).await {
            Some(sock) => matches!(
                tokio::time::timeout(Duration::from_millis(300), sock.send_to(bytes, addr)).await,
                Ok(Ok(_))
            ),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{address_rank, should_take_new_address};

    #[test]
    fn address_rank_orders_v4_before_global_v6_before_link_local() {
        assert!(address_rank("192.168.2.82") < address_rank("2408:8248:2020::1"));
        assert!(address_rank("2408:8248:2020::1") < address_rank("fe80::1027:fbf:772:d1f7"));
        assert!(address_rank("fe80::1") < address_rank("not-an-address"));
    }

    #[test]
    fn a_live_peer_keeps_its_address_instead_of_flapping() {
        // The measured failure: the record switched from an IPv4 address to a
        // link-local one mid-session and back.
        assert!(!should_take_new_address(false, "10.233.138.167", "fe80::1027:fbf:772:d1f7"));
        assert!(!should_take_new_address(false, "192.168.2.82", "10.233.138.167"));
    }

    #[test]
    fn a_better_address_still_wins_while_online() {
        assert!(should_take_new_address(false, "fe80::1", "192.168.2.82"));
    }

    #[test]
    fn a_peer_that_returns_after_a_gap_may_have_moved() {
        assert!(should_take_new_address(true, "192.168.2.82", "10.9.9.9"));
        assert!(should_take_new_address(false, "", "fe80::1"));
        // Same address: refresh the ports without touching the address.
        assert!(should_take_new_address(false, "192.168.2.82", "192.168.2.82"));
    }

    use super::*;

    #[tokio::test]
    async fn two_nodes_discover_over_ipv6_loopback() {
        // Node A (v4 ephemeral; v6 socket binds the same numeric port)
        let profile_a = Profile {
            node_id: "v6_A".to_string(),
            name: "Alpha6".to_string(),
            profile_rev: 1,
            addresses: vec!["::1".to_string()],
            udp_port: 0,
            tcp_port: 9081,
            device: None,
            device_id: None,
            product: None,
            extra: None,
        };
        let config_a = DiscoveryConfig {
            self_profile: profile_a,
            listen_port: 0,
            ..Default::default()
        };
        let engine_a = DiscoveryEngine::bind(config_a).await.expect("bind A");
        let port_a = engine_a.local_port().await.unwrap();

        // Node B dials A over pure IPv6 via a manual peer.
        let profile_b = Profile {
            node_id: "v6_B".to_string(),
            name: "Beta6".to_string(),
            profile_rev: 1,
            addresses: vec!["::1".to_string()],
            udp_port: port_a,
            tcp_port: 9082,
            device: None,
            device_id: None,
            product: None,
            extra: None,
        };
        let config_b = DiscoveryConfig {
            self_profile: profile_b,
            listen_port: 0,
            manual_peers: vec![("::1".to_string(), port_a)],
            ..Default::default()
        };
        let engine_b = DiscoveryEngine::bind(config_b).await.expect("bind B");

        let mut sub_a = engine_a.subscribe();
        let mut sub_b = engine_b.subscribe();
        engine_a.clone().spawn();
        engine_b.clone().spawn();
        engine_a.announce().await;
        engine_b.announce().await;

        // A discovers B (B's v6 entry reaches A's v6 socket; A replies v6).
        let found_b = tokio::time::timeout(Duration::from_secs(5), sub_a.recv()).await;
        assert!(
            matches!(found_b, Ok(Ok(PeerEvent::Found(ref p))) if p.node_id == "v6_B"),
            "A must discover B over IPv6"
        );
        // B discovers A from the alive reply.
        let found_a = tokio::time::timeout(Duration::from_secs(5), sub_b.recv()).await;
        assert!(
            matches!(found_a, Ok(Ok(PeerEvent::Found(ref p))) if p.node_id == "v6_A"),
            "B must discover A over IPv6"
        );
        engine_a.announce_exit().await;
        engine_b.announce_exit().await;
    }

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
            device_id: None,
            product: None,
            extra: None,
        };
        let config_a = DiscoveryConfig {
            self_profile: profile_a,
            listen_port: 0, // OS assigns port
            ..Default::default()
        };
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
            device_id: None,
            product: None,
            extra: None,
        };
        let port_a = engine_a.local_port().await.unwrap();
        let config_b = DiscoveryConfig {
            self_profile: profile_b,
            listen_port: 0, // OS assigns port
            manual_peers: vec![("127.0.0.1".to_string(), port_a)],
            ..Default::default()
        };
        let engine_b = DiscoveryEngine::bind(config_b).await.expect("bind B");

        let mut sub_a = engine_a.subscribe();
        let mut sub_b = engine_b.subscribe();

        engine_a.clone().spawn();
        engine_b.clone().spawn();

        // Node B announces to Node A
        engine_b.announce().await;

        // Tests must not depend on the machine they run on: a real phone on
        // this LAN also announces, so wait for the peer this test created
        // instead of asserting whatever arrives first (that used to fail with
        // node_id "uniffi_79235686" — the phone — when the suite ran while the
        // product was running).
        let event_a = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(PeerEvent::Found(p)) = sub_a.recv().await {
                    if p.node_id == "node_B" {
                        return p;
                    }
                }
            }
        })
        .await;
        let found_b = event_a.expect("Node A should discover Node B within 3s");
        assert_eq!(found_b.name, "Beta");

        // Verify Node B discovered Node A (via Alive reply)
        let event_b = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(PeerEvent::Found(p)) = sub_b.recv().await {
                    if p.node_id == "node_A" {
                        return p;
                    }
                }
            }
        })
        .await;
        let found_a = event_b.expect("Node B should discover Node A within 3s");
        assert_eq!(found_a.name, "Alpha");

        // Node B announces exit -> Node A immediately marks offline
        engine_b.announce_exit().await;
        let lost_event = tokio::time::timeout(Duration::from_secs(3), sub_a.recv()).await;
        assert!(
            lost_event.is_ok(),
            "Node A should receive Lost event for Node B"
        );
        if let Ok(Ok(PeerEvent::Lost(id))) = lost_event {
            assert_eq!(id, "node_B");
        }
    }
}
