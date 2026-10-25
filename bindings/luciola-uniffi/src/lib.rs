uniffi::setup_scaffolding!();

use luciola_ip::{is_lan_address as ip_is_lan, is_proxy_tun_address};
use luciola_net::{is_physical_interface_name, is_virtual_interface_name, NetworkDetector};
use qrcode::render::unicode;
use qrcode::QrCode;

/// Device form factor classification.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Mobile,
    Tablet,
    Laptop,
    Desktop,
    Server,
    Wsl,
    Unknown,
}

/// A manually configured peer for cross-subnet / VPN / localhost setups.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ManualPeer {
    pub host: String,
    pub port: u16,
}

/// Device hardware and OS metadata.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DeviceMeta {
    pub device_type: DeviceType,
    pub icon: String,
    pub os: String,
    pub arch: String,
    pub model: Option<String>,
    pub device_id: Option<String>,
}

/// A discovered peer node in the local network.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub node_id: String,
    pub name: String,
    pub ip: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub device: Option<DeviceMeta>,
    /// Stable per-device grouping id (display-grade).
    pub device_id: Option<String>,
    /// Product label running on the peer.
    pub product: Option<String>,
}

/// Detect the current machine's hardware profile, OS, architecture, and form factor.
#[uniffi::export]
pub fn get_device_meta() -> DeviceMeta {
    let meta = luciola_net::DeviceDetector::detect();
    let device_id = meta.device_id.clone();
    let dtype = match meta.device_type {
        luciola_proto::DeviceType::Mobile => DeviceType::Mobile,
        luciola_proto::DeviceType::Tablet => DeviceType::Tablet,
        luciola_proto::DeviceType::Laptop => DeviceType::Laptop,
        luciola_proto::DeviceType::Desktop => DeviceType::Desktop,
        luciola_proto::DeviceType::Server => DeviceType::Server,
        luciola_proto::DeviceType::Wsl => DeviceType::Wsl,
        luciola_proto::DeviceType::Unknown => DeviceType::Unknown,
    };
    DeviceMeta {
        device_type: dtype,
        icon: meta.device_type.icon().to_string(),
        os: meta.os,
        arch: meta.arch,
        model: meta.model,
        device_id,
    }
}

/// Select the best local IPv4 address for QR code / LAN access.
#[uniffi::export]
pub fn select_lan_ip() -> Option<String> {
    NetworkDetector::local_candidate_addresses()
        .into_iter()
        .find(|ip| luciola_ip::is_ipv4(ip))
}

/// Retrieve clean local candidate IP addresses (high-scoring IPv4 and domestic IPv6 GUA/ULA).
#[uniffi::export]
pub fn local_candidate_addresses() -> Vec<String> {
    NetworkDetector::local_candidate_addresses()
}

/// Retrieve per-NIC subnet broadcast addresses (e.g. `192.168.2.255`).
///
/// These addresses bypass Clash / Sing-box TUN mode (0.0.0.0/1) route capture.
#[uniffi::export]
pub fn subnet_broadcast_addresses() -> Vec<String> {
    NetworkDetector::subnet_broadcast_addresses()
}

/// Retrieve all local addresses including VPN/tunnels (for unicast overlay sync).
#[uniffi::export]
pub fn advertised_addresses() -> Vec<String> {
    NetworkDetector::advertised_addresses()
}

/// Check if a peer address is in the same local network:
/// Returns true if either RFC private IPv4/IPv6 OR domestic broadband /64 GUA matching.
#[uniffi::export]
pub fn is_lan_peer(peer_address: String, local_addresses: Vec<String>) -> bool {
    let locals: Vec<&str> = local_addresses.iter().map(|s| s.as_str()).collect();
    ip_is_lan(&peer_address, &locals)
}

/// Check if an IP address belongs to a proxy software TUN virtual network (198.18.0.0/15).
#[uniffi::export]
pub fn is_tun_virtual_ip(address: String) -> bool {
    is_proxy_tun_address(&address)
}

/// Check if an interface name corresponds to a virtual adapter (utun, feth, tailscale, docker, etc.).
#[uniffi::export]
pub fn is_virtual_nic(name: String) -> bool {
    is_virtual_interface_name(&name)
}

/// Check if an interface name looks like a real physical network interface (Wi-Fi, Ethernet).
#[uniffi::export]
pub fn is_physical_nic(name: String) -> bool {
    is_physical_interface_name(&name)
}

/// Render a compact terminal QR code for a given URL or text content.
///
/// In dark terminals, swaps dark and light colors so that white background border
/// and black QR modules are rendered correctly for optical scanning.
#[uniffi::export]
pub fn render_qr_ascii(content: String) -> Option<String> {
    let code = QrCode::new(content.as_bytes()).ok()?;
    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    Some(string)
}

// ---------------------------------------------------------------------------
// Discovery engine exports
// ---------------------------------------------------------------------------

use luciola::{DiscoveryConfig, DiscoveryEngine, PeerEvent};
use std::sync::Mutex;
use tokio::sync::oneshot;

/// Callbacks from the discovery engine. Products must implement all four;
/// `on_peer_updated` fires on profile/address changes, `on_peer_lost` when a
/// peer exits or ages out (update your peer table), `on_error` reports
/// fatal setup problems (e.g. discovery port occupied by another product).
#[uniffi::export(callback_interface)]
pub trait OnPeerDiscovered: Send + Sync {
    fn on_peer_discovered(&self, peer: DiscoveredPeer);
    fn on_peer_updated(&self, peer: DiscoveredPeer);
    fn on_peer_lost(&self, node_id: String);
    fn on_error(&self, code: String, message: String);
}

/// Active P2P discovery session backed by the Luciola UDP broadcast engine.
///
/// The engine announces this device's presence (`entry`), replies to probes
/// (`alive`), keeps a periodic heartbeat (`presence`), and reports every newly
/// discovered LAN peer through the `OnPeerDiscovered` callback.
///
/// Supervision is built in so hosts do not re-implement it per platform:
/// - `node_id` is stable for the session's lifetime — engine restarts keep the
///   same identity and remote registries do not see a "new" device.
/// - `start` retries the UDP bind so a restart racing the old socket's release
///   does not silently fall back to an ephemeral port.
/// - `restart()` rebuilds the engine with the same listener (hosts call this on
///   network changes); `seconds_since_idle()` feeds host-side watchdogs.
#[derive(uniffi::Object)]
pub struct DiscoverySession {
    name: Mutex<String>,
    port: Mutex<u16>,
    product: Mutex<Option<String>>,
    node_id: Mutex<String>,
    manual_peers: Mutex<Vec<ManualPeer>>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    listener: Mutex<Option<std::sync::Arc<dyn OnPeerDiscovered>>>,
    last_activity: std::sync::Arc<Mutex<std::time::SystemTime>>,
    bound: std::sync::Arc<Mutex<bool>>,
}

fn map_device_meta(meta: luciola_proto::DeviceMeta) -> DeviceMeta {
    let device_type = match meta.device_type {
        luciola_proto::DeviceType::Mobile => DeviceType::Mobile,
        luciola_proto::DeviceType::Tablet => DeviceType::Tablet,
        luciola_proto::DeviceType::Laptop => DeviceType::Laptop,
        luciola_proto::DeviceType::Desktop => DeviceType::Desktop,
        luciola_proto::DeviceType::Server => DeviceType::Server,
        luciola_proto::DeviceType::Wsl => DeviceType::Wsl,
        luciola_proto::DeviceType::Unknown => DeviceType::Unknown,
    };
    DeviceMeta {
        device_type,
        icon: meta.device_type.icon().to_string(),
        os: meta.os,
        arch: meta.arch,
        model: meta.model,
        device_id: meta.device_id,
    }
}

#[uniffi::export]
impl DiscoverySession {
    /// Create a session announcing `name` on the given UDP discovery port.
    ///
    /// `manualPeers` are unicast-only targets (host:port is the UDP discovery
    /// port) for peers that broadcasts cannot reach: cross-subnet hosts, VPN
    /// overlays (Tailscale/ZeroTier), or localhost debugging.
    #[uniffi::constructor]
    pub fn new(
        name: String,
        port: u16,
        manual_peers: Option<Vec<ManualPeer>>,
        product: Option<String>,
    ) -> Self {
        Self {
            name: Mutex::new(name),
            port: Mutex::new(port),
            product: Mutex::new(product),
            manual_peers: Mutex::new(manual_peers.unwrap_or_default()),
            node_id: Mutex::new(format!("uniffi_{:x}", rand::random::<u32>())),
            shutdown_tx: Mutex::new(None),
            listener: Mutex::new(None),
            last_activity: std::sync::Arc::new(Mutex::new(std::time::SystemTime::now())),
            bound: std::sync::Arc::new(Mutex::new(false)),
        }
    }

    /// Replace the manual peer list; takes effect on the next `restart()`.
    pub fn set_manual_peers(&self, peers: Vec<ManualPeer>) {
        *self.manual_peers.lock().unwrap() = peers;
    }

    /// This session's stable engine node id. Companion sockets (sweeps, unicast
    /// reconciliation on the host side) should present the SAME identity so
    /// remote devices see ONE node, not a duplicate peer.
    pub fn node_id(&self) -> String {
        self.node_id.lock().unwrap().clone()
    }

    /// Whether the last engine start actually bound the requested discovery
    /// port. False means the port was occupied and never freed within the
    /// retry window — the UI should not claim "online".
    pub fn is_bound(&self) -> bool {
        *self.bound.lock().unwrap()
    }

    /// Seconds since the last peer discovery (or session start). Host watchdogs
    /// treat a long idle on a networked device as "engine stalled".
    pub fn seconds_since_idle(&self) -> f64 {
        let last = *self.last_activity.lock().unwrap();
        match last.elapsed() {
            Ok(d) => d.as_secs_f64(),
            Err(_) => f64::MAX,
        }
    }

    /// Start the engine on a dedicated background thread.
    pub fn start(self: std::sync::Arc<Self>, listener: Box<dyn OnPeerDiscovered>) {
        let listener: std::sync::Arc<dyn OnPeerDiscovered> = listener.into();
        *self.listener.lock().unwrap() = Some(listener.clone());
        self.spawn_engine(listener);
    }

    /// Stop the engine (announcing `exit` to neighbors) and rebuild it with the
    /// same listener and identity. Hosts call this when the network set changes;
    /// the internal bind-retry tolerates the old socket still releasing.
    pub fn restart(self: std::sync::Arc<Self>) {
        self.stop();
        if let Some(listener) = self.listener.lock().unwrap().clone() {
            self.spawn_engine(listener);
        }
    }

    /// Stop the session and broadcast `exit` to neighbors.
    pub fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
}

// Private engine plumbing — a plain impl block so the UniFFI macro never sees it.
impl DiscoverySession {
    fn spawn_engine(&self, listener: std::sync::Arc<dyn OnPeerDiscovered>) {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

        let name = self.name.lock().unwrap().clone();
        let port = *self.port.lock().unwrap();
        let node_id = self.node_id.lock().unwrap().clone();
        let product = self.product.lock().unwrap().clone();
        let manual_peers: Vec<(String, u16)> = self
            .manual_peers
            .lock()
            .unwrap()
            .iter()
            .map(|p| (p.host.clone(), p.port))
            .collect();
        let last_activity = std::sync::Arc::clone(&self.last_activity);
        let bound = std::sync::Arc::clone(&self.bound);
        *bound.lock().unwrap() = false;

        std::thread::Builder::new()
            .name("luciola-uniffi-engine".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(async move {
                    let detected = luciola_net::DeviceDetector::detect();
                    let profile = luciola::proto::Profile {
                        node_id,
                        name,
                        profile_rev: 1,
                        addresses: NetworkDetector::local_candidate_addresses(),
                        udp_port: port,
                        tcp_port: port.wrapping_add(1),
                        device_id: detected.device_id.clone(),
                        product,
                        device: Some(detected),
                    };
                    let config = DiscoveryConfig {
                        self_profile: profile,
                        listen_port: port,
                        broadcast_port: port,
                        manual_peers,
                        ..Default::default()
                    };

                    // A restart may race the previous socket releasing the port;
                    // retry instead of silently falling back to an ephemeral
                    // port where broadcast discovery cannot work.
                    let mut engine = None;
                    // 5s total: a restart must out-wait the previous engine
                    // thread's socket teardown (exit announce + drop) or the
                    // session silently ends up on an ephemeral port.
                    for _ in 0..25 {
                        match DiscoveryEngine::bind(config.clone()).await {
                            Ok(e) => {
                                *bound.lock().unwrap() = true;
                                engine = Some(e);
                                break;
                            }
                            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
                        }
                    }
                    let Some(engine) = engine else {
                        *bound.lock().unwrap() = false;
                        listener.on_error(
                            "bind_failed".into(),
                            format!("discovery port {} occupied by another process", port),
                        );
                        return;
                    };
                    let mut events = engine.subscribe();
                    engine.clone().spawn();
                    engine.announce().await;

                    loop {
                        // Match on recv() result explicitly: a broadcast
                        // RecvError (Lagged/Closed) must NOT disable this
                        // select branch permanently, or the engine loop
                        // silently stops processing packets.
                        let event = tokio::select! {
                            _ = &mut shutdown_rx => {
                                engine.announce_exit().await;
                                break;
                            }
                            event = events.recv() => match event {
                                Ok(ev) => ev,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            },
                        };
                        *last_activity.lock().unwrap() = std::time::SystemTime::now();
                        let record = |p: luciola::PeerRecord| DiscoveredPeer {
                            node_id: p.node_id,
                            name: p.name,
                            ip: p.ip,
                            udp_port: p.udp_port,
                            tcp_port: p.tcp_port,
                            device: p.device.map(map_device_meta),
                            device_id: p.device_id,
                            product: p.product,
                        };
                        match event {
                            PeerEvent::Found(p) => listener.on_peer_discovered(record(p)),
                            PeerEvent::Updated(p) => listener.on_peer_updated(record(p)),
                            PeerEvent::Lost(id) => listener.on_peer_lost(id),
                        }
                    }
                });
            })
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Link racing (Happy Eyeballs) exports
// ---------------------------------------------------------------------------

/// Per-channel dial outcome.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct DialChannel {
    pub address: String,
    pub status: DialStatus,
    pub rtt_ms: Option<f64>,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialStatus {
    Won,
    Cancelled,
    Timeout,
}

/// Overall race outcome: winning address plus per-channel detail.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct RaceOutcome {
    pub winner: Option<String>,
    pub rtt_ms: Option<f64>,
    pub channels: Vec<DialChannel>,
}

fn map_race_outcome(o: luciola::link::RaceOutcome) -> RaceOutcome {
    RaceOutcome {
        winner: o.winner,
        rtt_ms: o.rtt_ms,
        channels: o
            .channels
            .into_iter()
            .map(|c| DialChannel {
                address: c.address,
                status: match c.status {
                    luciola::link::DialStatus::Won => DialStatus::Won,
                    luciola::link::DialStatus::Cancelled => DialStatus::Cancelled,
                    luciola::link::DialStatus::Timeout => DialStatus::Timeout,
                },
                rtt_ms: c.rtt_ms,
            })
            .collect(),
    }
}

/// Selection policy shared with the demos: first 3 IPv4 candidates plus the
/// first IPv6 GUA. Feed the result into [race_connect].
#[uniffi::export]
pub fn default_race_candidates(addresses: Vec<String>) -> Vec<String> {
    luciola::link::default_candidates(&addresses)
}

/// Race TCP dials across `addresses` on `port` (Happy Eyeballs): the first
/// connect wins, the rest are cancelled. Blocking; call off the UI thread.
#[uniffi::export]
pub fn race_connect(
    addresses: Vec<String>,
    port: u16,
    attempt_timeout_ms: Option<u64>,
    stagger_ms: Option<u64>,
) -> RaceOutcome {
    let mut config = luciola::link::RaceConfig::default();
    if let Some(t) = attempt_timeout_ms {
        config.attempt_timeout = std::time::Duration::from_millis(t);
    }
    if let Some(t) = stagger_ms {
        config.stagger = std::time::Duration::from_millis(t);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build race runtime");
    rt.block_on(luciola::link::race_connect(addresses, port, config))
        .pipe(map_race_outcome)
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}
impl<T> Pipe for T {}

// ---------------------------------------------------------------------------
// Trust & pairing exports
// ---------------------------------------------------------------------------

/// How much a paired device may do without per-action confirmation.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustLevel {
    /// Own devices: silent/background push allowed.
    Full,
    /// Paired but restricted: per-action confirmation required.
    Partial,
}

/// A paired device entry.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TrustedDeviceInfo {
    pub device_id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub level: TrustLevel,
    pub pinned_at_ms: u64,
}

/// A generated or restored device identity. Keep `seed` secret.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct DeviceIdentityInfo {
    pub seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub short_pin: String,
}

/// Persisted trust list. Serialize with [TrustStore::to_json] and store the
/// bytes in the product's secret storage; unpaired peers are simply absent
/// (default posture: deny).
#[derive(uniffi::Object)]
pub struct TrustStore {
    inner: std::sync::Mutex<luciola::trust::TrustStore>,
}

#[uniffi::export]
impl TrustStore {
    #[uniffi::constructor]
    pub fn new(from_json: Option<String>) -> Self {
        let inner = from_json
            .and_then(|j| luciola::trust::TrustStore::from_json(&j).ok())
            .unwrap_or_default();
        Self {
            inner: std::sync::Mutex::new(inner),
        }
    }

    /// Pair or re-pair a device (replaces the entry with the same public key).
    pub fn trust_device(&self, device: TrustedDeviceInfo) {
        self.inner
            .lock()
            .unwrap()
            .trust_device(luciola::trust::TrustedDevice {
                device_id: device.device_id,
                name: device.name,
                public_key: device.public_key,
                fingerprint: device.fingerprint,
                level: match device.level {
                    TrustLevel::Full => luciola::trust::TrustLevel::Full,
                    TrustLevel::Partial => luciola::trust::TrustLevel::Partial,
                },
                pinned_at_ms: device.pinned_at_ms,
            });
    }

    /// Trust level for a public key; absent = unpaired.
    pub fn level_of(&self, public_key: Vec<u8>) -> Option<TrustLevel> {
        self.inner
            .lock()
            .unwrap()
            .level_of(&public_key)
            .map(|l| match l {
                luciola::trust::TrustLevel::Full => TrustLevel::Full,
                luciola::trust::TrustLevel::Partial => TrustLevel::Partial,
            })
    }

    /// Remove a paired device by fingerprint.
    pub fn remove(&self, fingerprint: String) -> bool {
        self.inner.lock().unwrap().remove(&fingerprint)
    }

    pub fn entries(&self) -> Vec<TrustedDeviceInfo> {
        self.inner
            .lock()
            .unwrap()
            .entries()
            .iter()
            .map(|d| TrustedDeviceInfo {
                device_id: d.device_id.clone(),
                name: d.name.clone(),
                public_key: d.public_key.clone(),
                fingerprint: d.fingerprint.clone(),
                level: match d.level {
                    luciola::trust::TrustLevel::Full => TrustLevel::Full,
                    luciola::trust::TrustLevel::Partial => TrustLevel::Partial,
                },
                pinned_at_ms: d.pinned_at_ms,
            })
            .collect()
    }

    /// JSON serialization for persistence.
    pub fn to_json(&self) -> String {
        self.inner.lock().unwrap().to_json().unwrap_or_default()
    }
}

/// Generate a fresh device identity (Ed25519). Keep the seed secret.
#[uniffi::export]
pub fn generate_device_identity() -> DeviceIdentityInfo {
    let id = luciola::trust::generate_identity();
    DeviceIdentityInfo {
        seed: id.seed,
        public_key: id.public_key,
        fingerprint: id.fingerprint,
        short_pin: id.short_pin,
    }
}

/// Restore an identity from a persisted 32-byte seed.
#[uniffi::export]
pub fn identity_from_seed(seed: Vec<u8>) -> DeviceIdentityInfo {
    let id = luciola::trust::identity_from_seed(&seed);
    DeviceIdentityInfo {
        seed: id.seed,
        public_key: id.public_key,
        fingerprint: id.fingerprint,
        short_pin: id.short_pin,
    }
}

/// `sha256:<hex>` fingerprint of an Ed25519 public key.
#[uniffi::export]
pub fn identity_fingerprint(public_key: Vec<u8>) -> String {
    luciola::trust::fingerprint(&public_key)
}

/// 6-digit on-screen comparison pin for pairing.
#[uniffi::export]
pub fn identity_short_pin(public_key: Vec<u8>) -> String {
    luciola::trust::short_pin(&public_key)
}

/// Symmetrical 6-digit on-screen comparison pin between two devices during pairing.
#[uniffi::export]
pub fn comparison_pin(local_pk: Vec<u8>, remote_pk: Vec<u8>) -> String {
    luciola::trust::comparison_pin(&local_pk, &remote_pk)
}

/// Sign a message with a persisted seed.
#[uniffi::export]
pub fn sign_message(seed: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    luciola::trust::sign(&seed, &message)
}

/// Verify a signature against an Ed25519 public key.
#[uniffi::export]
pub fn verify_message(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    luciola::trust::verify(&public_key, &message, &signature)
}

// ---------------------------------------------------------------------------
// Secure link session exports
// ---------------------------------------------------------------------------

use luciola::link::secure::{accept_secure, connect_secure_raced};
use tokio::sync::mpsc;

/// Events from a [SecureSession]: state transitions and decrypted messages.
#[uniffi::export(callback_interface)]
pub trait SecureSessionListener: Send + Sync {
    /// `state`: "connected" | "closed" | "error"; `detail` carries the peer
    /// fingerprint on connect and the error message on failure.
    fn on_state(&self, state: String, detail: Option<String>);
    fn on_message(&self, message: Vec<u8>);
}

#[derive(Clone)]
enum LinkRole {
    Dial(Vec<String>, u16, Vec<u8>, bool),
    Listen(u16, Option<Vec<u8>>),
}

const KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(15);
const RECONNECT_MIN: std::time::Duration = std::time::Duration::from_secs(1);
const RECONNECT_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// Link health counters for UI/diagnostics.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct LinkStats {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub connections_established: u64,
    pub reconnect_attempts: u64,
}

/// One authenticated encrypted channel (see `luciola::link::secure`).
/// Message-oriented for FFI friendliness: `send` queues an encrypted frame;
/// received frames are decrypted and delivered through the listener.
#[derive(uniffi::Object)]
pub struct SecureSession {
    identity_seed: Vec<u8>,
    outbound_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stats: std::sync::Arc<LinkStatsCounters>,
}

#[derive(Default)]
struct LinkStatsCounters {
    frames_sent: std::sync::atomic::AtomicU64,
    frames_received: std::sync::atomic::AtomicU64,
    connections: std::sync::atomic::AtomicU64,
    reconnects: std::sync::atomic::AtomicU64,
}

#[uniffi::export]
impl SecureSession {
    #[uniffi::constructor]
    pub fn new(identity_seed: Vec<u8>) -> Self {
        Self {
            identity_seed,
            outbound_tx: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
            connected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            stats: std::sync::Arc::new(LinkStatsCounters::default()),
        }
    }

    /// Link health counters (sent/received frames, connections, retries).
    pub fn stats(&self) -> LinkStats {
        let s = &self.stats;
        LinkStats {
            frames_sent: s.frames_sent.load(std::sync::atomic::Ordering::Relaxed),
            frames_received: s.frames_received.load(std::sync::atomic::Ordering::Relaxed),
            connections_established: s.connections.load(std::sync::atomic::Ordering::Relaxed),
            reconnect_attempts: s.reconnects.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Race-dial every candidate address (Happy Eyeballs) and run the
    /// authenticated handshake on the winning socket, with a PINNED peer key.
    ///
    /// With `auto_reconnect` the session re-dials with exponential backoff
    /// (1s..30s) whenever the channel drops, until `disconnect()`.
    pub fn connect(
        self: std::sync::Arc<Self>,
        addresses: Vec<String>,
        port: u16,
        pinned_peer_public_key: Vec<u8>,
        auto_reconnect: bool,
        listener: Box<dyn SecureSessionListener>,
    ) {
        self.spawn_link(
            LinkRole::Dial(addresses, port, pinned_peer_public_key, auto_reconnect),
            listener,
        );
    }

    /// Accept connections in a LOOP (one at a time). `expected_peer`: pin the
    /// peer key, or None to accept any identity (TOFU — check the reported
    /// fingerprint). The listener re-arms after each channel closes.
    pub fn listen(
        self: std::sync::Arc<Self>,
        port: u16,
        expected_peer: Option<Vec<u8>>,
        listener: Box<dyn SecureSessionListener>,
    ) {
        self.spawn_link(LinkRole::Listen(port, expected_peer), listener);
    }

    /// Queue an encrypted frame. False when not connected OR the outbound
    /// queue is full (peer stalled) — back off and retry.
    pub fn send(&self, message: Vec<u8>) -> bool {
        if !self.connected.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        match self.outbound_tx.lock().unwrap().as_ref() {
            Some(tx) => tx.try_send(message).is_ok(),
            None => false,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Close the channel; the peer sees the socket close. (Named
    /// `disconnect` because the generated Disposable interface already owns
    /// `close`.)
    pub fn disconnect(&self) {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        *self.outbound_tx.lock().unwrap() = None;
        self.connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SecureSession {
    fn spawn_link(&self, role: LinkRole, listener: Box<dyn SecureSessionListener>) {
        use luciola::link::secure::SecureStream;
        use tokio::io::AsyncWriteExt as _;

        self.disconnect();
        let listener: std::sync::Arc<dyn SecureSessionListener> = listener.into();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);
        // Bounded outbound queue: a stalled peer must not grow our memory.
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
        *self.outbound_tx.lock().unwrap() = Some(out_tx);
        let connected = self.connected.clone();
        let seed = self.identity_seed.clone();
        let stats = self.stats.clone();

        std::thread::Builder::new()
            .name("luciola-secure-link".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                let mut shutdown = shutdown_rx;

                rt.block_on(async move {
                    let mut out_rx = out_rx;
                    let mut backoff = RECONNECT_MIN;

                    'outer: loop {
                        // Establish the channel.
                        let stream: SecureStream = match role.clone() {
                            LinkRole::Dial(addresses, port, pinned, auto) => {
                                match connect_secure_raced(addresses, port, &seed, &pinned).await {
                                    Ok(s) => {
                                        backoff = RECONNECT_MIN;
                                        s
                                    }
                                    Err(e) => {
                                        connected.store(false, std::sync::atomic::Ordering::SeqCst);
                                        if !auto {
                                            listener.on_state("error".into(), Some(e.to_string()));
                                            return;
                                        }
                                        stats.reconnects.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        listener.on_state("retrying".into(), Some(format!(
                                            "{}; next attempt in {:?}",
                                            e, backoff
                                        )));
                                        tokio::select! {
                                            _ = tokio::time::sleep(backoff) => {}
                                            _ = &mut shutdown => break 'outer,
                                        }
                                        backoff = std::cmp::min(backoff * 2, RECONNECT_MAX);
                                        continue 'outer;
                                    }
                                }
                            }
                            LinkRole::Listen(port, expected) => {
                                let l = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
                                    Ok(l) => l,
                                    Err(e) => {
                                        listener.on_state("error".into(), Some(e.to_string()));
                                        return;
                                    }
                                };
                                match accept_secure(&l, &seed, expected.as_deref()).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        // A failed handshake (wrong initiator)
                                        // must not kill the listener; keep accepting.
                                        listener.on_state("retrying".into(), Some(e.to_string()));
                                        continue 'outer;
                                    }
                                }
                            }
                        };
                        let mut stream = stream;
                        stats.connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        connected.store(true, std::sync::atomic::Ordering::SeqCst);
                        listener.on_state("connected".into(), Some(stream.peer_fingerprint()));

                        // Pump both directions; keepalive pings when idle.
                        let mut keepalive = tokio::time::interval(KEEPALIVE_IDLE);
                        keepalive.reset();
                        let mut awaiting_pong = false;
                        loop {
                            let mut buf: Vec<u8> = Vec::new();
                            tokio::select! {
                                _ = &mut shutdown => {
                                    let _ = stream.socket_mut().shutdown().await;
                                    break 'outer;
                                }
                                _ = keepalive.tick() => {
                                    if awaiting_pong {
                                        // Peer silent for 2 intervals: dead.
                                        break;
                                    }
                                    if stream.send(&[]).await.is_err() {
                                        break;
                                    }
                                    awaiting_pong = true;
                                }
                                msg = out_rx.recv() => match msg {
                                    Some(m) => {
                                        keepalive.reset();
                                        awaiting_pong = false;
                                        if stream.send(&m).await.is_ok() {
                                            stats.frames_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        } else {
                                            break;
                                        }
                                    }
                                    None => break 'outer,
                                },
                                frame = stream.recv(&mut buf) => {
                                    keepalive.reset();
                                    awaiting_pong = false;
                                    if frame.is_err() {
                                        break;
                                    }
                                    if !buf.is_empty() {
                                        stats.frames_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        listener.on_message(buf.clone());
                                    }
                                }
                            }
                        }
                        connected.store(false, std::sync::atomic::Ordering::SeqCst);
                        listener.on_state("closed".into(), None);
                        // Loop back: dial again (if auto) / accept next (listener).
                        if let LinkRole::Dial(_, _, _, false) = role {
                            break 'outer;
                        }
                    }
                });
            })
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Pairing payload exports (luciola://pair v2)
// ---------------------------------------------------------------------------

/// Canonical pairing payload. `fingerprint` is the host's identity
/// fingerprint — bind trust on it; `pin` is the optional 6-digit compare.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct PairingInfo {
    pub name: String,
    pub product: Option<String>,
    pub port: u16,
    pub addrs: Vec<String>,
    pub fingerprint: Option<String>,
    pub pin: Option<String>,
}

#[uniffi::export]
pub fn build_pairing_uri(
    name: String,
    product: Option<String>,
    port: u16,
    addrs: Vec<String>,
    fingerprint: Option<String>,
    pin: Option<String>,
) -> String {
    luciola::pairing::build_pairing_uri(
        &name,
        product.as_deref(),
        port,
        &addrs,
        fingerprint.as_deref(),
        pin.as_deref(),
    )
}

#[uniffi::export]
pub fn parse_pairing_uri(uri: String) -> Option<PairingInfo> {
    luciola::pairing::parse_pairing_uri(&uri).map(|p| PairingInfo {
        name: p.name,
        product: p.product,
        port: p.port,
        addrs: p.addrs,
        fingerprint: p.fingerprint,
        pin: p.pin,
    })
}
