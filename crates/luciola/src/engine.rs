//! 发现引擎与配置（lib.rs 的执行体部分；对外类型经 lib 重导出）。

use luciola_net::NetworkDetector;
use luciola_proto::{AliveDedupTracker, Codec, Envelope, JitterScheduler, MsgType, Profile};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, warn};

use crate::registry::{PeerEvent, PeerRecord, PeerRegistry};
use crate::CoreError;

/// Configuration options for the discovery engine.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// This node's advertised profile.
    pub self_profile: Profile,
    /// UDP port to listen on for discovery traffic.
    pub listen_port: u16,
    /// UDP port to broadcast to (usually equal to `listen_port`).
    pub broadcast_port: u16,
    /// How often an `alive` presence frame is broadcast.
    pub presence_interval: Duration,
    /// Silence after which a peer is marked offline.
    pub offline_after: Duration,
    /// Explicit `(host, port)` peers for cross-subnet or loopback setups.
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
    use super::{DiscoveryConfig, DiscoveryEngine};
    use crate::proto::Profile;
    use crate::registry::PeerEvent;
    use std::time::Duration;

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
