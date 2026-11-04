//! # luciola
//!
//! Lightweight, resilient peer discovery & interface intelligence for the real-world LAN.

pub use luciola_ip as ip;

pub mod link;
pub mod pairing;
pub mod ports;
pub mod relay_crypto;
pub mod trust;
pub use luciola_net as net;
pub use luciola_proto as proto;
#[cfg(feature = "transfer")]
pub use luciola_transfer as transfer;

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
    /// Ed25519 identity public key advertised by the peer (see `trust`).
    pub public_key: Option<Vec<u8>>,
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

/// 离线超过这个时长的表项会被彻底移除：peers 表只增不删会让长驻进程的
/// 内存随历史邻居数无界增长（sweep 只置 offline）。1 小时后同一 node_id
/// 几乎不可能原样回归，真回来了 presence 会重新插入。
const PEER_EVICT_AFTER: Duration = Duration::from_secs(3600);

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
                    existing.public_key = p.public_key.clone();
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
                public_key: p.public_key.clone(),
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

    /// Sweep peers that haven't sent a presence heartbeat within `offline_after`,
    /// and evict entries whose peer has been gone for longer than
    /// [`PEER_EVICT_AFTER`] (the table would otherwise grow without bound for
    /// the lifetime of a long-running engine). Eviction never fires while a
    /// peer is still within the offline window: the threshold is clamped to
    /// at least twice `offline_after`.
    pub fn sweep(&mut self, offline_after: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut offline_ids = Vec::new();
        for (id, peer) in self.peers.iter_mut() {
            if peer.online && now.duration_since(peer.last_seen) > offline_after {
                peer.online = false;
                offline_ids.push(id.clone());
            }
        }
        let evict_after = PEER_EVICT_AFTER.max(offline_after.saturating_mul(2));
        let evicted: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > evict_after)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &evicted {
            tracing::debug!("evicting peer {id} from the registry (gone > {evict_after:?})");
            self.peers.remove(id);
        }
        offline_ids
    }

    pub fn online_peers(&self) -> Vec<PeerRecord> {
        self.peers.values().filter(|p| p.online).cloned().collect()
    }

    pub fn profile_rev_of(&self, node_id: &str) -> Option<u32> {
        self.peers.get(node_id).map(|p| p.profile_rev)
    }

    /// Product label last advertised by this peer (for the product allow-list).
    pub fn product_of(&self, node_id: &str) -> Option<String> {
        self.peers.get(node_id).and_then(|p| p.product.clone())
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
    /// When the requested `listen_port` is taken, bind an ephemeral port
    /// instead of failing. Off by default.
    ///
    /// A silent fallback is how two products end up sharing one broadcast
    /// mesh: the loser still announces to the well-known port, the winner
    /// hears it, the two exchange profiles and then dial each other's channel
    /// ports — measured on 2026-11-02 with Firefly and Tidings in the same
    /// `17878/17879` range. Callers that really must stay up without the
    /// well-known port opt in here and surface `local_port()` (announce and
    /// receive then use different ports, so discovery is degraded).
    pub allow_ephemeral_fallback: bool,
    /// Optional allow-list of Profile.product values.
    ///
    /// None (default) accepts every product — the historical open mesh.
    /// Some(list) ignores beacons from any other product, which keeps two
    /// products that share a link from appearing in each other's peer table
    /// and then dialling each other's channel port (the 2026-11-02
    /// Firefly/Tidings cross-dial). Beacons without a product label are
    /// ignored too: an allow-list that admits unknowns is not a list.
    pub product_filter: Option<Vec<String>>,
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
                public_key: None,
            },
            listen_port: 17878,
            broadcast_port: 17878,
            presence_interval: Duration::from_secs(5),
            offline_after: Duration::from_secs(90),
            manual_peers: Vec::new(),
            allow_ephemeral_fallback: false,
            product_filter: None,
        }
    }
}

impl DiscoveryConfig {
    /// Whether this engine accepts a beacon that carries `product`.
    ///
    /// No filter means the historical open mesh. With a filter, a beacon
    /// without a product label is rejected: accepting unknowns would defeat
    /// the isolation the filter exists for.
    pub fn accepts_product(&self, product: Option<&str>) -> bool {
        match &self.product_filter {
            None => true,
            Some(allowed) => product.is_some_and(|p| allowed.iter().any(|a| a == p)),
        }
    }
}

/// Bind the discovery UDP socket, honouring the explicit fallback policy.
///
/// Off by default: a silent fallback is how two processes end up sharing one
/// broadcast mesh (the loser keeps announcing into the winner's port). The
/// caller sees `CoreError::BindFailed` instead, so the host can show a real
/// "port occupied" error and pick another product port.
fn bind_discovery_udp(
    listen_port: u16,
    allow_ephemeral_fallback: bool,
) -> Result<std::net::UdpSocket, CoreError> {
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    match std::net::UdpSocket::bind(bind_addr) {
        Ok(socket) => Ok(socket),
        Err(err) if allow_ephemeral_fallback => {
            warn!(
                "discovery port {listen_port} is unavailable ({err}); continuing on an ephemeral                  port because allow_ephemeral_fallback is set — broadcast discovery is degraded                  and this node will keep announcing into whichever process owns {listen_port}"
            );
            std::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
                .map_err(|fallback_err| CoreError::BindFailed(listen_port, fallback_err))
        }
        Err(err) => Err(CoreError::BindFailed(listen_port, err)),
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
        let std_socket = bind_discovery_udp(config.listen_port, config.allow_ephemeral_fallback)?;

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
        let std_socket = bind_discovery_udp(
            self.config.listen_port,
            self.config.allow_ephemeral_fallback,
        )?;

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
        // Handles are dropped: the loops run for the lifetime of the engine,
        // which is what the FFI/platform embedders assume (each stops the
        // engine by shutting down its own runtime). Rust embedders that need
        // to cancel the loops use [`DiscoveryEngine::spawn_tracked`].
        let _ = self.spawn_tracked();
    }

    /// Like [`DiscoveryEngine::spawn`], but returns the JoinHandles of the
    /// three engine loops so a Rust embedder can cancel them (`abort()`).
    /// This is the first-class escape hatch the binding layers get for free
    /// from owning their runtimes.
    pub fn spawn_tracked(self: Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        let engine_rx = self.clone();
        let rx = tokio::spawn(async move {
            engine_rx.receive_loop().await;
        });

        let engine_presence = self.clone();
        let presence = tokio::spawn(async move {
            engine_presence.presence_loop().await;
        });

        let engine_sweep = self;
        let sweep = tokio::spawn(async move {
            engine_sweep.sweep_loop().await;
        });

        vec![rx, presence, sweep]
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
                if !self
                    .config
                    .accepts_product(profile.as_ref().and_then(|p| p.product.as_deref()))
                {
                    return;
                }
                let (record, changed) = self.registry.write().await.touch(
                    &envelope.from,
                    &peer_ip,
                    peer_port,
                    profile.as_ref(),
                );

                if let Some(r) = record {
                    if changed && self.event_tx.send(PeerEvent::Found(r)).is_err() {
                        tracing::debug!("no discovery event subscribers; PeerEvent::Found dropped");
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
                            if let Err(e) = socket.send_to(&bytes, peer_addr).await {
                                tracing::debug!("presence probe to {peer_addr} failed: {e}");
                            }
                        }
                    });
                }
            }
            MsgType::Alive => {
                let profile = envelope.extract_profile();
                if !self
                    .config
                    .accepts_product(profile.as_ref().and_then(|p| p.product.as_deref()))
                {
                    return;
                }
                let (record, changed) = self.registry.write().await.touch(
                    &envelope.from,
                    &peer_ip,
                    peer_port,
                    profile.as_ref(),
                );

                if let Some(r) = record {
                    if changed {
                        if self.event_tx.send(PeerEvent::Found(r)).is_err() {
                            tracing::debug!(
                                "no discovery event subscribers; PeerEvent::Found dropped"
                            );
                        }
                    } else if self.event_tx.send(PeerEvent::Updated(r)).is_err() {
                        tracing::debug!(
                            "no discovery event subscribers; PeerEvent::Updated dropped"
                        );
                    }
                }
            }
            MsgType::Presence => {
                // Presence carries no profile; use the product learned from
                // the last entry/alive for this node.
                let known_product = self.registry.read().await.product_of(&envelope.from);
                if !self.config.accepts_product(known_product.as_deref()) {
                    return;
                }
                let their_rev = envelope.extract_presence_rev().unwrap_or(0);
                let (record, changed) =
                    self.registry
                        .write()
                        .await
                        .touch(&envelope.from, &peer_ip, peer_port, None);

                if let Some(r) = record {
                    if changed && self.event_tx.send(PeerEvent::Found(r)).is_err() {
                        tracing::debug!("no discovery event subscribers; PeerEvent::Found dropped");
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
                        if let Err(e) = receiving_socket.send_to(&bytes, peer_addr).await {
                            tracing::debug!("profile refresh to {peer_addr} failed: {e}");
                        }
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
                    && self.event_tx.send(PeerEvent::Lost(envelope.from)).is_err()
                {
                    tracing::debug!("no discovery event subscribers; PeerEvent::Lost dropped");
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
                    if let Err(e) = self.restart_socket().await {
                        error!("discovery socket restart failed: {e}; discovery is down until the next successful restart");
                    }
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
                if self.event_tx.send(PeerEvent::Lost(id)).is_err() {
                    tracing::debug!("no discovery event subscribers; PeerEvent::Lost dropped");
                }
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
    use super::PeerRegistry;
    use super::{address_rank, should_take_new_address};
    use crate::proto::Profile;
    use std::time::{Duration, Instant};

    fn minimal_profile(node_id: &str) -> Profile {
        Profile {
            node_id: node_id.to_string(),
            name: node_id.to_string(),
            profile_rev: 1,
            addresses: vec![],
            udp_port: 1,
            tcp_port: 1,
            device: None,
            device_id: None,
            product: None,
            extra: None,
            public_key: None,
        }
    }

    #[test]
    fn sweep_evicts_entries_gone_longer_than_the_eviction_ttl() {
        let mut reg = PeerRegistry::new();
        reg.touch("gone", "10.0.0.1", 1, Some(&minimal_profile("gone")));
        reg.touch("fresh", "10.0.0.2", 1, Some(&minimal_profile("fresh")));
        // "gone" 在 2 小时前最后一次心跳：先被判 offline，随后被逐出。
        let cutoff = Instant::now() - Duration::from_secs(2 * 3600);
        reg.peers.get_mut("gone").unwrap().last_seen = cutoff;
        let offline = reg.sweep(Duration::from_secs(90));
        assert_eq!(offline, vec!["gone".to_string()]);
        assert!(reg.peers.contains_key("fresh"), "live peer must survive");
        assert!(
            !reg.peers.contains_key("gone"),
            "stale entry must be evicted"
        );
    }

    #[test]
    fn sweep_never_evicts_inside_the_offline_window_even_when_it_is_huge() {
        let mut reg = PeerRegistry::new();
        reg.touch("slow", "10.0.0.3", 1, Some(&minimal_profile("slow")));
        let cutoff = Instant::now() - Duration::from_secs(2 * 3600);
        reg.peers.get_mut("slow").unwrap().last_seen = cutoff;
        // offline_after = 3h：2h 未心跳仍算在线，逐出阈值被钳到 ≥ 2×offline_after，
        // 该表项必须原样保留。
        let offline = reg.sweep(Duration::from_secs(3 * 3600));
        assert!(offline.is_empty());
        assert!(reg.peers.contains_key("slow"));
    }

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
        assert!(!should_take_new_address(
            false,
            "10.233.138.167",
            "fe80::1027:fbf:772:d1f7"
        ));
        assert!(!should_take_new_address(
            false,
            "192.168.2.82",
            "10.233.138.167"
        ));
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
        assert!(should_take_new_address(
            false,
            "192.168.2.82",
            "192.168.2.82"
        ));
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
            public_key: None,
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
            public_key: None,
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
            public_key: None,
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
            public_key: None,
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

    #[tokio::test]
    async fn product_filter_keeps_other_products_out_of_the_peer_table() {
        // Two products that end up on the same discovery port (shared agent,
        // same machine, a legacy deployment) must not see each other: each
        // would otherwise treat the other as a peer and dial the channel port
        // from its profile — the 2026-11-02 Firefly/Tidings cross-dial.
        fn profile(node_id: &str, product: &str) -> Profile {
            Profile {
                node_id: node_id.to_string(),
                name: node_id.to_string(),
                profile_rev: 1,
                addresses: vec!["127.0.0.1".to_string()],
                udp_port: 0,
                tcp_port: 0,
                device: None,
                device_id: None,
                product: Some(product.to_string()),
                extra: None,
                public_key: None,
            }
        }

        let observer = DiscoveryEngine::bind(DiscoveryConfig {
            self_profile: profile("filter_A", "alpha"),
            listen_port: 0,
            product_filter: Some(vec!["alpha".to_string()]),
            ..Default::default()
        })
        .await
        .expect("bind observer");
        let observer_port = observer.local_port().await.expect("observer port");

        let dial = |node: &str, product: &str| DiscoveryConfig {
            self_profile: profile(node, product),
            listen_port: 0,
            manual_peers: vec![("127.0.0.1".to_string(), observer_port)],
            ..Default::default()
        };
        let other_product = DiscoveryEngine::bind(dial("filter_B", "beta"))
            .await
            .expect("bind beta");
        let same_product = DiscoveryEngine::bind(dial("filter_C", "alpha"))
            .await
            .expect("bind alpha");

        let mut events = observer.subscribe();
        observer.clone().spawn();
        other_product.clone().spawn();
        same_product.clone().spawn();

        other_product.announce().await;
        same_product.announce().await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut saw_alpha = false;
        let mut saw_beta = false;
        while tokio::time::Instant::now() < deadline && !saw_alpha {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Ok(PeerEvent::Found(peer))) => {
                    if peer.node_id == "filter_B" {
                        saw_beta = true;
                    }
                    if peer.node_id == "filter_C" {
                        saw_alpha = true;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => {}
            }
        }
        assert!(saw_alpha, "the allowed product must still be discovered");
        assert!(
            !saw_beta,
            "a filtered-out product must never enter the peer table"
        );

        observer.announce_exit().await;
        other_product.announce_exit().await;
        same_product.announce_exit().await;
    }
}
