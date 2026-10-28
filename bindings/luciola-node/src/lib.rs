#[macro_use]
extern crate napi_derive;

use luciola_ip::{is_lan_address as ip_is_lan, is_proxy_tun_address};
use luciola_net::{is_physical_interface_name, is_virtual_interface_name, NetworkDetector};
use luciola_tunnel::tunnel_link::{TunnelBase, TunnelLink, TunnelReporter};
use luciola_tunnel::{ForwardRule, TunnelError};

/// Select the best local IPv4 address for QR code / LAN access.
///
/// Filters out virtual adapters (Docker, VMware, Tailscale, Radmin),
/// avoids Windows ICS mobile hotspot (192.168.137.x), and selects
/// true physical Wi-Fi or Ethernet interfaces.
#[napi]
pub fn select_lan_ip() -> Option<String> {
    NetworkDetector::local_candidate_addresses()
        .into_iter()
        .find(|ip| luciola_ip::is_ipv4(ip))
}

/// Retrieve clean local candidate IP addresses (high-scoring IPv4 and domestic IPv6 GUA/ULA).
#[napi]
pub fn local_candidate_addresses() -> Vec<String> {
    NetworkDetector::local_candidate_addresses()
}

/// Retrieve per-NIC subnet broadcast addresses (e.g. `192.168.2.255`).
///
/// These addresses have direct /24 routes, bypassing Clash / Sing-box TUN mode (0.0.0.0/1)
/// route capture that swallows standard `255.255.255.255` broadcasts.
#[napi]
pub fn subnet_broadcast_addresses() -> Vec<String> {
    NetworkDetector::subnet_broadcast_addresses()
}

/// Retrieve all local addresses including VPN/tunnels (for unicast overlay sync).
#[napi]
pub fn advertised_addresses() -> Vec<String> {
    NetworkDetector::advertised_addresses()
}

/// Check if a peer address is in the same local network:
/// Returns true if either RFC private IPv4/IPv6 OR domestic broadband /64 GUA matching.
#[napi]
pub fn is_lan_peer(peer_address: String, local_addresses: Vec<String>) -> bool {
    let locals: Vec<&str> = local_addresses.iter().map(|s| s.as_str()).collect();
    ip_is_lan(&peer_address, &locals)
}

/// Check if an IP address belongs to a proxy software TUN virtual network (198.18.0.0/15).
#[napi]
pub fn is_tun_virtual_ip(address: String) -> bool {
    is_proxy_tun_address(&address)
}

/// Check if an interface name corresponds to a virtual adapter (utun, feth, tailscale, docker, etc.).
#[napi]
pub fn is_virtual_nic(name: String) -> bool {
    is_virtual_interface_name(&name)
}

/// Check if an interface name looks like a real physical network interface (Wi-Fi, Ethernet).
#[napi]
pub fn is_physical_nic(name: String) -> bool {
    is_physical_interface_name(&name)
}

/// Render a standard vector SVG QR code string for HTML/Web/Mobile display.
#[napi]
pub fn render_qr_svg(content: String) -> Option<String> {
    use qrcode::QrCode;
    let code = QrCode::new(content.as_bytes()).ok()?;
    let svg = code.render::<qrcode::render::svg::Color>().build();
    Some(svg)
}

/// Render a UTF-8 compact terminal QR code with proper dark terminal optical contrast.
#[napi]
pub fn render_qr_ascii(content: String) -> Option<String> {
    use qrcode::render::unicode;
    use qrcode::QrCode;
    let code = QrCode::new(content.as_bytes()).ok()?;
    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    Some(string)
}

/// Device hardware and platform identity.
#[napi(object)]
#[derive(Clone)]
pub struct JsDeviceMeta {
    pub device_type: String,
    pub icon: String,
    pub os: String,
    pub arch: String,
    pub model: Option<String>,
    pub hostname: Option<String>,
    pub device_id: Option<String>,
}

/// Detect the current local device hardware profile, OS, and form factor.
#[napi]
pub fn get_device_meta() -> JsDeviceMeta {
    let meta = luciola_net::DeviceDetector::detect();
    JsDeviceMeta {
        device_type: meta.device_type.as_str().to_string(),
        icon: meta.device_type.icon().to_string(),
        os: meta.os,
        arch: meta.arch,
        model: meta.model,
        hostname: meta.hostname,
        device_id: meta.device_id,
    }
}

/// Manually configured peer for cross-subnet / VPN / localhost setups.
#[napi(object)]
pub struct JsManualPeer {
    pub host: String,
    pub port: u32,
}

/// Discovered peer record returned to JavaScript.
#[napi(object)]
pub struct JsPeerRecord {
    pub node_id: String,
    pub name: String,
    pub ip: String,
    pub udp_port: u32,
    pub tcp_port: u32,
    pub device: Option<JsDeviceMeta>,
    pub device_id: Option<String>,
    pub product: Option<String>,
    pub extra: Option<String>,
}

use napi::bindgen_prelude::*;
use napi::threadsafe_function::{
    ErrorStrategy, ThreadSafeCallContext, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
use tokio::sync::oneshot;

fn make_peer_obj(env: &napi::Env, p: &JsPeerRecord) -> napi::Result<napi::JsObject> {
    let mut peer = env.create_object()?;
    peer.set_named_property("nodeId", &p.node_id)?;
    peer.set_named_property("name", &p.name)?;
    peer.set_named_property("ip", &p.ip)?;
    peer.set_named_property("udpPort", p.udp_port)?;
    peer.set_named_property("tcpPort", p.tcp_port)?;
    if let Some(ref v) = p.device_id {
        peer.set_named_property("deviceId", v)?;
    }
    if let Some(ref v) = p.product {
        peer.set_named_property("product", v)?;
    }
    if let Some(ref v) = p.extra {
        peer.set_named_property("extra", v)?;
    }
    if let Some(ref d) = p.device {
        let mut dev = env.create_object()?;
        dev.set_named_property("deviceType", &d.device_type)?;
        dev.set_named_property("icon", &d.icon)?;
        dev.set_named_property("os", &d.os)?;
        dev.set_named_property("arch", &d.arch)?;
        if let Some(ref m) = d.model {
            dev.set_named_property("model", m)?;
        }
        if let Some(ref h) = d.hostname {
            dev.set_named_property("hostname", h)?;
        }
        if let Some(ref di) = d.device_id {
            dev.set_named_property("deviceId", di)?;
        }
        peer.set_named_property("device", dev)?;
    }
    Ok(peer)
}

/// Active P2P discovery session in Node.js.
///
/// Discovers other Luciola/downstream nodes across the local network and emits real-time events.
#[napi]
pub struct DiscoverySession {
    name: String,
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    node_id: std::sync::Mutex<Option<String>>,
    manual_peers: std::sync::Mutex<Vec<(String, u16)>>,
    product: Option<String>,
    device_id: Option<String>,
    extra: Option<String>,
    tcp_port: Option<u16>,
    public_key: Option<Vec<u8>>,
}

#[napi]
impl DiscoverySession {
    #[napi(constructor)]
    // napi 构造器的可选参数即公共 JS API，参数表由调用方约定（clippy 9/7）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: Option<String>,
        port: Option<u32>,
        manual_peers: Option<Vec<JsManualPeer>>,
        product: Option<String>,
        device_id: Option<String>,
        extra: Option<String>,
        node_id: Option<String>,
        tcp_port: Option<u32>,
        public_key: Option<Buffer>,
    ) -> Self {
        Self {
            name: name.unwrap_or_else(|| "NodeJS Peer".to_string()),
            port: port.unwrap_or(17878) as u16,
            shutdown_tx: None,
            node_id: std::sync::Mutex::new(node_id),
            manual_peers: std::sync::Mutex::new(
                manual_peers
                    .unwrap_or_default()
                    .into_iter()
                    .map(|p| (p.host, p.port as u16))
                    .collect(),
            ),
            product,
            device_id,
            extra,
            tcp_port: tcp_port.map(|p| p as u16),
            public_key: public_key.map(|b| b.to_vec()),
        }
    }

    /// This session's engine node id (available after `start`), so companion
    /// sockets (sweeps, unicast reconciliation) can present the SAME identity
    /// instead of appearing as a duplicate peer on remote devices.
    #[napi]
    pub fn node_id(&self) -> Option<String> {
        self.node_id.lock().unwrap().clone()
    }

    /// Start discovery session and listen for discovered peers via callback.
    #[napi]
    pub fn start(&mut self, _env: Env, callback: JsFunction) -> Result<()> {
        #[allow(dead_code)]
        enum DiscoveryEvent {
            Found(JsPeerRecord),
            Updated(JsPeerRecord),
            Lost(String),
            Error(String, String),
        }
        let tsfn: ThreadsafeFunction<DiscoveryEvent, ErrorStrategy::Fatal> = callback
            .create_threadsafe_function(0, |ctx: ThreadSafeCallContext<DiscoveryEvent>| {
                let mut obj = ctx.env.create_object()?;
                let event = ctx.value;
                match event {
                    DiscoveryEvent::Found(p) => {
                        obj.set_named_property("type", "found")?;
                        let peer = make_peer_obj(&ctx.env, &p)?;
                        obj.set_named_property("peer", peer)?;
                    }
                    DiscoveryEvent::Updated(p) => {
                        obj.set_named_property("type", "updated")?;
                        let peer = make_peer_obj(&ctx.env, &p)?;
                        obj.set_named_property("peer", peer)?;
                    }
                    DiscoveryEvent::Lost(id) => {
                        obj.set_named_property("type", "lost")?;
                        obj.set_named_property("nodeId", id)?;
                    }
                    DiscoveryEvent::Error(code, m) => {
                        obj.set_named_property("type", "error")?;
                        obj.set_named_property("message", format!("{code}: {m}"))?;
                    }
                }
                Ok(vec![obj])
            })?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let name = self.name.clone();
        let port = self.port;
        let node_id = self
            .node_id
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| format!("node_{:x}", rand::random::<u32>()));
        let manual_peers = self.manual_peers.lock().unwrap().clone();
        let detected = luciola_net::DeviceDetector::detect();
        let device_id = self.device_id.clone().or(detected.device_id.clone());
        let product = self.product.clone();
        let extra = self.extra.clone();
        let tcp_port = self.tcp_port;
        let public_key = self.public_key.clone();
        *self.node_id.lock().unwrap() = Some(node_id.clone());

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(_) => return,
            };

            rt.block_on(async move {
                let profile = luciola::proto::Profile {
                    node_id: node_id.clone(),
                    name,
                    profile_rev: 1,
                    addresses: luciola::net::NetworkDetector::local_candidate_addresses(),
                    udp_port: port,
                    tcp_port: tcp_port.unwrap_or(port + 1),
                    device: Some(detected),
                    device_id,
                    product,
                    extra,
                    public_key,
                };

                let config = luciola::DiscoveryConfig {
                    self_profile: profile,
                    listen_port: port,
                    broadcast_port: port,
                    manual_peers,
                    ..Default::default()
                };

                if let Ok(engine) = luciola::DiscoveryEngine::bind(config).await {
                    let mut events = engine.subscribe();
                    engine.clone().spawn();
                    engine.announce().await;

                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => {
                                engine.announce_exit().await;
                                break;
                            }
                            Ok(event) = events.recv() => {
                                let conv = |p: luciola::PeerRecord| {
                                    let device = p.device.map(|d| JsDeviceMeta {
                                        device_type: d.device_type.as_str().to_string(),
                                        icon: d.device_type.icon().to_string(),
                                        os: d.os,
                                        arch: d.arch,
                                        model: d.model,
                                        hostname: d.hostname,
                                        device_id: d.device_id,
                                    });
                                    JsPeerRecord {
                                        node_id: p.node_id,
                                        name: p.name,
                                        ip: p.ip,
                                        udp_port: p.udp_port as u32,
                                        tcp_port: p.tcp_port as u32,
                                        device,
                                        device_id: p.device_id,
                                        product: p.product,
                                        extra: p.extra,
                                    }
                                };
                                match event {
                                    luciola::PeerEvent::Found(p) => {
                                        tsfn.call(DiscoveryEvent::Found(conv(p)), ThreadsafeFunctionCallMode::NonBlocking);
                                    }
                                    luciola::PeerEvent::Updated(p) => {
                                        tsfn.call(DiscoveryEvent::Updated(conv(p)), ThreadsafeFunctionCallMode::NonBlocking);
                                    }
                                    luciola::PeerEvent::Lost(id) => {
                                        tsfn.call(DiscoveryEvent::Lost(id), ThreadsafeFunctionCallMode::NonBlocking);
                                    }
                                }
                            }
                        }
                    }
                }
            });
        });

        Ok(())
    }

    /// Stop discovery session and broadcast exit to neighbors.
    #[napi]
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Per-channel dial outcome of a Happy Eyeballs race.
#[napi(object)]
pub struct JsDialChannel {
    pub address: String,
    pub status: String,
    pub rtt_ms: Option<f64>,
}

/// Overall race outcome: winning address plus per-channel detail.
#[napi(object)]
pub struct JsRaceOutcome {
    pub winner: Option<String>,
    pub rtt_ms: Option<f64>,
    pub channels: Vec<JsDialChannel>,
}

/// Selection policy shared with the demos: first 3 IPv4 candidates plus the
/// first IPv6 GUA. Feed the result into `happyEyeballsRace`.
#[napi]
pub fn default_race_candidates(addresses: Vec<String>) -> Vec<String> {
    luciola::link::default_candidates(&addresses)
}

/// Race TCP dials across `addresses` on `port` (Happy Eyeballs): the first
/// connect wins, the rest are cancelled. Returns a Promise.
#[napi]
pub async fn happy_eyeballs_race(
    addresses: Vec<String>,
    port: u16,
    attempt_timeout_ms: Option<u32>,
    stagger_ms: Option<u32>,
) -> JsRaceOutcome {
    let mut config = luciola::link::RaceConfig::default();
    if let Some(t) = attempt_timeout_ms {
        config.attempt_timeout = std::time::Duration::from_millis(t as u64);
    }
    if let Some(t) = stagger_ms {
        config.stagger = std::time::Duration::from_millis(t as u64);
    }
    let outcome = luciola::link::race_connect(addresses, port, config).await;
    JsRaceOutcome {
        winner: outcome.winner,
        rtt_ms: outcome.rtt_ms,
        channels: outcome
            .channels
            .into_iter()
            .map(|c| JsDialChannel {
                address: c.address,
                status: match c.status {
                    luciola::link::DialStatus::Won => "won".to_string(),
                    luciola::link::DialStatus::Cancelled => "cancelled".to_string(),
                    luciola::link::DialStatus::Timeout => "timeout".to_string(),
                },
                rtt_ms: c.rtt_ms,
            })
            .collect(),
    }
}

/// A generated or restored device identity. Keep `seed` secret.
#[napi(object)]
pub struct JsDeviceIdentity {
    pub seed: Buffer,
    pub public_key: Buffer,
    pub fingerprint: String,
    pub short_pin: String,
}

/// Generate a fresh Ed25519 device identity for pairing/trust.
#[napi]
pub fn generate_device_identity() -> JsDeviceIdentity {
    let id = luciola::trust::generate_identity();
    JsDeviceIdentity {
        seed: id.seed.into(),
        public_key: id.public_key.into(),
        fingerprint: id.fingerprint,
        short_pin: id.short_pin,
    }
}

/// Restore an identity from a persisted 32-byte seed.
#[napi]
pub fn identity_from_seed(seed: Buffer) -> JsDeviceIdentity {
    let id = luciola::trust::identity_from_seed(&seed);
    JsDeviceIdentity {
        seed: id.seed.into(),
        public_key: id.public_key.into(),
        fingerprint: id.fingerprint,
        short_pin: id.short_pin,
    }
}

/// `sha256:<hex>` fingerprint of an Ed25519 public key.
#[napi]
pub fn identity_fingerprint(public_key: Buffer) -> String {
    luciola::trust::fingerprint(&public_key)
}

/// 6-digit on-screen comparison pin for pairing.
#[napi]
pub fn identity_short_pin(public_key: Buffer) -> String {
    luciola::trust::short_pin(&public_key)
}

/// Sign a message with a persisted seed.
#[napi]
pub fn sign_message(seed: Buffer, message: Buffer) -> Buffer {
    luciola::trust::sign(&seed, &message).into()
}

/// Verify a signature against an Ed25519 public key.
#[napi]
pub fn verify_message(public_key: Buffer, message: Buffer, signature: Buffer) -> bool {
    luciola::trust::verify(&public_key, &message, &signature)
}

/// T3：隧道事件 → 已注册 onEvent 回调（NonBlocking：不阻塞隧道命令/监督线程）。
struct NodeReporter {
    tsfn: ThreadsafeFunction<ChannelEvent, ErrorStrategy::Fatal>,
}

impl TunnelReporter for NodeReporter {
    fn report(&self, kind: &str, detail: String) {
        self.tsfn.call(
            (Some(kind.to_string()), Some(detail), None),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
    }
}

/// One authenticated encrypted channel (luciola::link::secure).
/// Message-oriented: `send` queues an encrypted frame; decrypted inbound
/// frames are delivered through the callback as `{ state, detail, message }`.
#[napi]
pub struct SecureChannel {
    identity_seed: Vec<u8>,
    outbound_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
    shutdown_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    frames_sent: std::sync::Arc<std::sync::atomic::AtomicU64>,
    frames_received: std::sync::Arc<std::sync::atomic::AtomicU64>,
    connections_established: std::sync::Arc<std::sync::atomic::AtomicU64>,
    reconnect_attempts: std::sync::Arc<std::sync::atomic::AtomicU64>,
    timings: std::sync::Arc<LinkTimings>,
    /// T3：独立隧道监督实例（数据面不经过 JS，与消息链路并行）。
    tunnel: std::sync::Arc<TunnelLink>,
    /// T3：已注册 onEvent；隧道 error/retrying 经它同步上报。
    tunnel_event: std::sync::Mutex<Option<ThreadsafeFunction<ChannelEvent, ErrorStrategy::Fatal>>>,
}

/// Link health counters.
#[napi(object)]
pub struct JsLinkStats {
    pub frames_sent: i64,
    pub frames_received: i64,
    pub connections_established: i64,
    pub reconnect_attempts: i64,
}

/// T3 转发 ACL 规则（主机必须是 IP 字面量，与 uniffi ForwardRuleDto 同构）。
#[napi(object)]
pub struct JsForwardRule {
    pub host: String,
    pub port_from: u16,
    pub port_to: u16,
}

/// T3 转发状态行（计数沿用 JS 侧 i64 惯例，与 uniffi ForwardStatusDto 同义）。
#[napi(object)]
pub struct JsForwardStatus {
    pub active: bool,
    pub listen_port: u16,
    pub channels_open: i64,
    pub channels_total: i64,
    pub dial_denied: i64,
    pub dial_failed: i64,
}

#[derive(Clone)]
enum ChannelRole {
    Dial(Vec<String>, u16, Vec<u8>, bool),
    Listen(u16, Option<Vec<u8>>),
}

/// JS 事件载荷 (state, detail, message)——spawn_link 的 tsfn 与 T3 隧道上报共用。
type ChannelEvent = (Option<String>, Option<String>, Option<Vec<u8>>);

/// Retry/keepalive timings, adjustable before/after connect.
struct LinkTimings {
    reconnect_min_ms: std::sync::atomic::AtomicU64,
    reconnect_max_ms: std::sync::atomic::AtomicU64,
    jitter_pct: std::sync::atomic::AtomicU64,
    keepalive_ms: std::sync::atomic::AtomicU64,
    dead_after_ms: std::sync::atomic::AtomicU64,
}

impl LinkTimings {
    fn backoff(&self, base: std::time::Duration) -> std::time::Duration {
        let jitter = self.jitter_pct.load(std::sync::atomic::Ordering::Relaxed) as f64 / 100.0;
        let factor = 1.0 + jitter * (2.0 * (rand::random::<f64>() - 0.5));
        let max = self
            .reconnect_max_ms
            .load(std::sync::atomic::Ordering::Relaxed) as f64;
        std::time::Duration::from_millis(((base.as_millis() as f64 * factor).min(max)) as u64)
    }
}

impl Default for LinkTimings {
    fn default() -> Self {
        let v = |x: u64| std::sync::atomic::AtomicU64::new(x);
        Self {
            reconnect_min_ms: v(1_000),
            reconnect_max_ms: v(60_000),
            jitter_pct: v(20),
            keepalive_ms: v(15_000),
            dead_after_ms: v(30_000),
        }
    }
}

#[napi]
impl SecureChannel {
    #[napi(constructor)]
    pub fn new(identity_seed: Buffer) -> Self {
        Self {
            identity_seed: identity_seed.to_vec(),
            outbound_tx: std::sync::Mutex::new(None),
            shutdown_tx: std::sync::Mutex::new(None),
            connected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            frames_sent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            frames_received: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            connections_established: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reconnect_attempts: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            timings: std::sync::Arc::new(LinkTimings::default()),
            tunnel: TunnelLink::new(identity_seed.to_vec()),
            tunnel_event: std::sync::Mutex::new(None),
        }
    }

    /// Retry policy for auto-reconnect: 2x exponential from minMs to maxMs,
    /// each delay jittered +-jitterPct percent.
    #[napi]
    pub fn set_retry_policy(&self, min_ms: f64, max_ms: f64, jitter_pct: f64) {
        let t = &self.timings;
        let (mn, mx, j) = (min_ms as u64, max_ms as u64, jitter_pct as u64);
        t.reconnect_min_ms
            .store(mn, std::sync::atomic::Ordering::Relaxed);
        t.reconnect_max_ms
            .store(mx.max(mn), std::sync::atomic::Ordering::Relaxed);
        t.jitter_pct
            .store(j.min(90), std::sync::atomic::Ordering::Relaxed);
    }

    /// Keepalive cadence: ping after intervalMs idle; dead after deadAfterMs
    /// of silence. Raise both under Android Doze.
    #[napi]
    pub fn set_keepalive(&self, interval_ms: f64, dead_after_ms: f64) {
        let t = &self.timings;
        let (i, d) = (interval_ms as u64, dead_after_ms as u64);
        t.keepalive_ms
            .store(i, std::sync::atomic::Ordering::Relaxed);
        t.dead_after_ms
            .store(d.max(i), std::sync::atomic::Ordering::Relaxed);
    }

    /// Link health counters (sent/received frames, connections, retries).
    #[napi]
    pub fn stats(&self) -> JsLinkStats {
        JsLinkStats {
            frames_sent: self.frames_sent.load(std::sync::atomic::Ordering::Relaxed) as i64,
            frames_received: self
                .frames_received
                .load(std::sync::atomic::Ordering::Relaxed) as i64,
            connections_established: self
                .connections_established
                .load(std::sync::atomic::Ordering::Relaxed)
                as i64,
            reconnect_attempts: self
                .reconnect_attempts
                .load(std::sync::atomic::Ordering::Relaxed) as i64,
        }
    }

    /// Dial with a PINNED peer public key. Events: state = "connected" |
    /// "closed" | "error"; message = decrypted frame bytes.
    #[napi(
        ts_args_type = "addresses: string[], port: number, pinnedPeerPublicKey: Buffer, autoReconnect: boolean, onEvent: (event: { state?: string, detail?: string, message?: Buffer }) => void"
    )]
    pub fn connect(
        &self,
        addresses: Vec<String>,
        port: u16,
        pinned_peer_public_key: Buffer,
        auto_reconnect: bool,
        on_event: JsFunction,
    ) -> Result<()> {
        self.spawn_link(
            ChannelRole::Dial(
                addresses,
                port,
                pinned_peer_public_key.to_vec(),
                auto_reconnect,
            ),
            on_event,
        )
    }

    /// Accept ONE connection; `expectedPeerPublicKey` pins the peer or
    /// null/undefined for TOFU (check the reported fingerprint).
    #[napi(
        ts_args_type = "port: number, expectedPeerPublicKey: Buffer | null | undefined, onEvent: (event: { state?: string, detail?: string, message?: Buffer }) => void"
    )]
    pub fn listen(
        &self,
        port: u16,
        expected_peer_public_key: Option<Buffer>,
        on_event: JsFunction,
    ) -> Result<()> {
        self.spawn_link(
            ChannelRole::Listen(port, expected_peer_public_key.map(|b| b.to_vec())),
            on_event,
        )
    }

    /// Queue an encrypted frame; false when not connected.
    #[napi]
    pub fn send(&self, message: Buffer) -> bool {
        if !self.connected.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        match self.outbound_tx.lock().unwrap().as_ref() {
            Some(tx) => tx.try_send(message.to_vec()).is_ok(),
            None => false,
        }
    }

    #[napi]
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[napi]
    pub fn close(&self) {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        *self.outbound_tx.lock().unwrap() = None;
        self.connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // T3：消息链路关闭 → 暂停隧道（注册表保留，重连后自动恢复）。
        self.tunnel.pause();
    }

    /// T3 本地转发（发起端）：本机 127.0.0.1:listenPort → 经隧道 → target。
    /// 端口冲突等同步失败：返回 false 并经 onEvent 报 "error"
    ///（detail 前缀 forward_bind_failed: ）。
    #[napi]
    pub fn start_local_forward(&self, listen_port: u16, host: String, port: u16) -> bool {
        let ip: std::net::IpAddr = match host.parse() {
            Ok(ip) => ip,
            Err(_) => {
                return self.tunnel_result(Err(TunnelError::InvalidTarget(format!(
                    "非法转发目标 {host}:{port}，必须是 IP 字面量"
                ))));
            }
        };
        self.tunnel_result(self.tunnel.start_local_forward(listen_port, ip, port))
    }

    /// T3 停止一个本地转发并释放端口；再次停止同一端口返回 false。
    #[napi]
    pub fn stop_local_forward(&self, listen_port: u16) -> bool {
        self.tunnel_result(self.tunnel.stop_local_forward(listen_port))
    }

    /// T3 端点（响应端）：在 tunnel_port 上 accept，按 rules 做拨入 ACL。
    /// 空 rules = 全拒绝；返回 false 并经 onEvent 报 "error"（前缀
    /// invalid forward rule: / forward_bind_failed: ）。
    #[napi]
    pub fn enable_forward_endpoint(&self, rules: Vec<JsForwardRule>) -> bool {
        let mut parsed = Vec::with_capacity(rules.len());
        for r in &rules {
            match r.host.parse::<std::net::IpAddr>() {
                Ok(host) => parsed.push(ForwardRule {
                    host,
                    port_from: r.port_from,
                    port_to: r.port_to,
                }),
                Err(_) => {
                    return self.tunnel_result(Err(TunnelError::InvalidRule(format!(
                        "规则主机不是合法 IP：{}:{}-{}",
                        r.host, r.port_from, r.port_to
                    ))));
                }
            }
        }
        self.tunnel_result(self.tunnel.enable_forward_endpoint(parsed))
    }

    /// T3 撤下端点（隧道保持，仅停 accept 与转发）。
    #[napi]
    pub fn disable_forward_endpoint(&self) -> bool {
        self.tunnel_result(self.tunnel.disable_forward_endpoint())
    }

    /// T3 隧道端口覆盖（0 = 默认 securePort+1）。停机状态同步生效，
    /// 运行中随下一次隧道重建生效。
    #[napi]
    pub fn set_tunnel_port(&self, port: u16) -> bool {
        self.tunnel_result(self.tunnel.set_tunnel_port(port))
    }

    /// T3 状态表：每个本地转发/端点一行（active = 已绑定）。
    #[napi]
    pub fn forward_stats(&self) -> Vec<JsForwardStatus> {
        self.tunnel
            .stats()
            .into_iter()
            .map(|s| JsForwardStatus {
                active: s.active,
                listen_port: s.listen_port,
                channels_open: s.status.channels_open as i64,
                channels_total: s.status.channels_total as i64,
                dial_denied: s.status.dial_denied as i64,
                dial_failed: s.status.dial_failed as i64,
            })
            .collect()
    }
}

impl SecureChannel {
    /// T3 同步控制面结果：Ok → true；Err → 转 (state, detail) 经 onEvent 上报
    /// "error" 后返回 false（不静默失败；onEvent 未注册时仅返回 false）。
    fn tunnel_result(&self, r: std::result::Result<(), TunnelError>) -> bool {
        match r {
            Ok(()) => true,
            Err(e) => {
                let (kind, detail) = e.to_state();
                if let Some(tsfn) = self.tunnel_event.lock().unwrap().as_ref() {
                    tsfn.call(
                        (Some(kind.to_string()), Some(detail), None),
                        ThreadsafeFunctionCallMode::NonBlocking,
                    );
                }
                false
            }
        }
    }

    fn spawn_link(&self, role: ChannelRole, on_event: JsFunction) -> Result<()> {
        use napi::threadsafe_function::{
            ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode,
        };
        use tokio::io::AsyncWriteExt as _;

        let tsfn: ThreadsafeFunction<ChannelEvent, ErrorStrategy::Fatal> = on_event
            .create_threadsafe_function(0, |ctx| {
                let mut obj = ctx.env.create_object()?;
                let (state, detail, message): &(Option<String>, Option<String>, Option<Vec<u8>>) =
                    &ctx.value;
                if let Some(s) = state {
                    obj.set_named_property("state", s)?;
                }
                if let Some(d) = detail {
                    obj.set_named_property("detail", d)?;
                }
                if let Some(m) = message {
                    let buf = ctx.env.create_buffer_copy(m.as_slice())?;
                    obj.set_named_property("message", buf.into_raw())?;
                }
                Ok(vec![obj])
            })?;

        self.close();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);
        // Bounded outbound queue: a stalled peer must not grow our memory.
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        *self.outbound_tx.lock().unwrap() = Some(out_tx);
        // T3：把消息链路的角色翻成隧道基址。close() 已先发 Pause，随后 SetBase 在
        // 同一条命令队列里 FIFO 生效；onEvent 的 tsfn 同时作为隧道 error/retrying
        // 的上报通道（数据面仍走独立线程，不经 JS）。
        let tunnel_base = match &role {
            ChannelRole::Dial(addresses, port, pinned, _auto) => TunnelBase::Dial {
                addresses: addresses.clone(),
                secure_port: *port,
                pinned_peer_public_key: pinned.clone(),
            },
            ChannelRole::Listen(port, expected) => TunnelBase::Listen {
                secure_port: *port,
                expected_peer: expected.clone(),
            },
        };
        *self.tunnel_event.lock().unwrap() = Some(tsfn.clone());
        self.tunnel.set_base(
            tunnel_base,
            std::sync::Arc::new(NodeReporter { tsfn: tsfn.clone() }),
        );
        let connected = self.connected.clone();
        let seed = self.identity_seed.clone();
        let timings = self.timings.clone();
        let (frames_sent, frames_received) =
            (self.frames_sent.clone(), self.frames_received.clone());
        let (connections_established, reconnect_attempts) = (
            self.connections_established.clone(),
            self.reconnect_attempts.clone(),
        );

        std::thread::Builder::new()
            .name("luciola-node-secure-link".to_string())
            .spawn(move || {
                use luciola::link::secure::{accept_secure, connect_secure_raced};
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
                    let min = std::time::Duration::from_millis(
                        timings.reconnect_min_ms.load(std::sync::atomic::Ordering::Relaxed));
                    let mut backoff = min;

                    'outer: loop {
                        let stream = match role.clone() {
                            ChannelRole::Dial(addresses, port, pinned, auto) => {
                                match connect_secure_raced(addresses, port, &seed, &pinned).await {
                                    Ok(s) => {
                                        backoff = min;
                                        s
                                    }
                                    Err(e) => {
                                        connected.store(false, std::sync::atomic::Ordering::SeqCst);
                                        if !auto {
                                            tsfn.call((Some("error".to_string()), Some(e.to_string()), None), ThreadsafeFunctionCallMode::NonBlocking);
                                            return;
                                        }
                                        reconnect_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        let jittered = timings.backoff(backoff);
                                        tsfn.call((Some("retrying".to_string()), Some(format!("{}; next attempt in {:?}", e, jittered)), None), ThreadsafeFunctionCallMode::NonBlocking);
                                        tokio::select! {
                                            _ = tokio::time::sleep(jittered) => {}
                                            _ = &mut shutdown => break 'outer,
                                        }
                                        let cap = std::time::Duration::from_millis(
                                            timings.reconnect_max_ms.load(std::sync::atomic::Ordering::Relaxed));
                                        backoff = std::cmp::min(backoff * 2, cap.max(min));
                                        continue 'outer;
                                    }
                                }
                            }
                            ChannelRole::Listen(port, expected) => {
                                // bind 与 accept 都必须可被 shutdown 打断(理由同
                                // luciola-uniffi 同名循环:僵尸 accept 会攥住端口)。
                                let l = tokio::select! {
                                    l = luciola::link::bind_dual_stack_listener(port) => match l {
                                        Ok(l) => l,
                                        Err(e) => {
                                            tsfn.call((Some("error".to_string()), Some(e.to_string()), None), ThreadsafeFunctionCallMode::NonBlocking);
                                            return;
                                        }
                                    },
                                    _ = &mut shutdown => break 'outer,
                                };
                                let accepted = tokio::select! {
                                    r = accept_secure(&l, &seed, expected.as_deref()) => match r {
                                        Ok(s) => s,
                                        Err(e) => {
                                            // Handshake failures (wrong initiator) keep the listener alive.
                                            tsfn.call((Some("retrying".to_string()), Some(e.to_string()), None), ThreadsafeFunctionCallMode::NonBlocking);
                                            continue 'outer;
                                        }
                                    },
                                    _ = &mut shutdown => break 'outer,
                                };
                                accepted
                            }
                        };
                        let mut stream = stream;
                        connections_established.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        connected.store(true, std::sync::atomic::Ordering::SeqCst);
                        tsfn.call((Some("connected".to_string()), Some(stream.peer_fingerprint()), None), ThreadsafeFunctionCallMode::NonBlocking);

                        let mut keepalive = tokio::time::interval(std::time::Duration::from_millis(
                            timings.keepalive_ms.load(std::sync::atomic::Ordering::Relaxed)));
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
                                            frames_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                                        frames_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        tsfn.call((None, None, Some(buf.clone())), ThreadsafeFunctionCallMode::NonBlocking);
                                    }
                                }
                            }
                        }
                        connected.store(false, std::sync::atomic::Ordering::SeqCst);
                        tsfn.call((Some("closed".to_string()), None, None), ThreadsafeFunctionCallMode::NonBlocking);
                        if let ChannelRole::Dial(_, _, _, false) = role {
                            break 'outer;
                        }
                    }
                });
            })
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(())
    }
}

/// Canonical pairing payload (`luciola://pair` v2). `fingerprint` is the
/// host's identity fingerprint — bind trust on it.
#[napi(object)]
pub struct JsPairingInfo {
    pub name: String,
    pub product: Option<String>,
    pub port: u16,
    pub addrs: Vec<String>,
    pub fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub pin: Option<String>,
}

/// Build the canonical pairing URI (URL-encoded).
#[napi]
pub fn build_pairing_uri(
    name: String,
    product: Option<String>,
    port: u16,
    addrs: Vec<String>,
    fingerprint: Option<String>,
    public_key: Option<String>,
    pin: Option<String>,
) -> String {
    luciola::pairing::build_pairing_uri(
        &name,
        product.as_deref(),
        port,
        &addrs,
        fingerprint.as_deref(),
        public_key.as_deref(),
        pin.as_deref(),
    )
}

/// Parse a pairing URI (`luciola://pair?...` v1/v2 or plain `http://host:port`).
#[napi]
pub fn parse_pairing_uri(uri: String) -> Option<JsPairingInfo> {
    luciola::pairing::parse_pairing_uri(&uri).map(|p| JsPairingInfo {
        name: p.name,
        product: p.product,
        port: p.port,
        addrs: p.addrs,
        fingerprint: p.fingerprint,
        public_key: p.public_key,
        pin: p.pin,
    })
}
