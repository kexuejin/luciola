//! Node.js (N-API) bindings: discovery, secure channels, port forwarding,
//! pairing and the shared error taxonomy.
//!
//! Every `#[napi]` item is part of the published `index.d.ts` contract; keep
//! the TypeScript declarations in sync (see AGENTS.md §3).
//!
//! `missing_docs` is deliberately **not** denied crate-wide: `#[napi]` on a
//! class generates undocumented wrapper functions we do not own, so the lint
//! would fail on macro output. Every hand-written item here is documented.

#[macro_use]
extern crate napi_derive;

use luciola_ip::{is_lan_address as ip_is_lan, is_proxy_tun_address};
use luciola_net::{is_physical_interface_name, is_virtual_interface_name, NetworkDetector};
use luciola_proto::{ErrorCode, ErrorInfo};
use luciola_tunnel::tunnel_link::{TunnelBase, TunnelLink, TunnelReporter};
use luciola_tunnel::{ForwardRule, TunnelError};

/// The closed set of stable wire codes delivered by `error` events.
///
/// A host can validate its `switch` at startup, and detect a newer engine by
/// diffing this list against the codes it knows.
#[napi]
pub fn get_error_codes() -> Vec<String> {
    ErrorCode::ALL
        .iter()
        .map(|c| c.as_str().to_string())
        .collect()
}

/// Normalise a callback detail (`"<code>: <message>"`, including the legacy
/// tunnel prefixes) into a structured record. Useful for hosts handling
/// `onEvent` details emitted by older peers.
#[napi(object)]
pub struct JsErrorInfo {
    /// Stable snake_case wire code; unknown codes are reported as `"unknown"`.
    pub code: String,
    /// The original human-readable detail, without a code prefix.
    pub message: String,
    /// Whether retrying the operation may succeed.
    pub retryable: bool,
}

/// Classify an `onEvent` detail string. Unknown text is preserved in
/// `message` with `code = "unknown"`.
#[napi]
pub fn classify_error(detail: String) -> JsErrorInfo {
    let info = ErrorInfo::parse_detail(&detail);
    let retryable = info.retryable();
    JsErrorInfo {
        code: info.code_str().to_string(),
        message: info.message,
        retryable,
    }
}

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
    /// Form factor: mobile / tablet / laptop / desktop / server / wsl / unknown.
    pub device_type: String,
    /// Emoji icon for peer-list UIs.
    pub icon: String,
    /// Operating-system name.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Hardware model string, when available.
    pub model: Option<String>,
    /// Host name, when available.
    pub hostname: Option<String>,
    /// Stable per-device grouping id (display-grade).
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
    /// Peer host (IP literal or hostname).
    pub host: String,
    /// Peer UDP discovery port.
    pub port: u32,
}

/// Discovered peer record returned to JavaScript.
#[napi(object)]
pub struct JsPeerRecord {
    /// Stable node identity.
    pub node_id: String,
    /// Human-readable device name.
    pub name: String,
    /// Address the peer was last heard from.
    pub ip: String,
    /// Peer's UDP discovery port.
    pub udp_port: u32,
    /// Peer's secure-channel TCP port.
    pub tcp_port: u32,
    /// Optional hardware metadata.
    pub device: Option<JsDeviceMeta>,
    /// Stable per-device grouping id (display-grade).
    pub device_id: Option<String>,
    /// Product label running on the peer.
    pub product: Option<String>,
    /// Opaque application payload carried alongside discovery.
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
    product_filter: std::sync::Mutex<Option<Vec<String>>>,
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
    /// Create a discovery session. All arguments are optional; `port` defaults
    /// to 17878, `name` to "NodeJS Peer".
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
            product_filter: std::sync::Mutex::new(None),
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

    /// Restrict discovery to these `product` labels (the `product` field of a
    /// peer profile). `null`/`undefined` or an empty array accepts every
    /// product. Takes effect on the next `start()` call.
    ///
    /// Use it when several luciola products share one discovery port or one
    /// machine: without a filter each product sees the others as peers and
    /// dials the channel port advertised in their profiles.
    #[napi]
    pub fn set_product_filter(&self, products: Option<Vec<String>>) {
        *self.product_filter.lock().unwrap() = products.filter(|list| !list.is_empty());
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
                        let info = ErrorInfo::new(ErrorCode::from_code(&code), m);
                        obj.set_named_property("type", "error")?;
                        obj.set_named_property("code", info.code_str())?;
                        obj.set_named_property("message", &info.message)?;
                        obj.set_named_property("retryable", info.retryable())?;
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
        let product_filter = self.product_filter.lock().unwrap().clone();
        // DeviceDetector::detect() shells out to system commands (Command::output)
        // and must not run on the N-API main thread: start() is synchronous and a
        // slow `system_profiler`/`ipconfig` would freeze the JS event loop. It runs
        // on a blocking thread inside the engine task below.
        let device_id = self.device_id.clone();
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
                let detected = tokio::task::spawn_blocking(luciola_net::DeviceDetector::detect)
                    .await
                    .unwrap_or_else(|_| luciola::proto::DeviceMeta {
                        device_type: luciola::proto::DeviceType::Unknown,
                        os: std::env::consts::OS.to_string(),
                        arch: std::env::consts::ARCH.to_string(),
                        model: None,
                        hostname: None,
                        device_id: None,
                    });
                let device_id = device_id.or(detected.device_id.clone());
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
                    product_filter,
                    ..Default::default()
                };

                let engine = match luciola::DiscoveryEngine::bind(config).await {
                    Ok(candidate) => {
                        let actual = candidate.local_port().await.unwrap_or(0);
                        if port != 0 && actual != port {
                            // Only reachable with an explicit fallback opt-in;
                            // the documented JS contract is "bind_failed when
                            // the port is occupied", never a silent move.
                            tsfn.call(
                                DiscoveryEvent::Error(
                                    ErrorCode::BindFailed.as_str().to_string(),
                                    format!("discovery port {port} landed on {actual}"),
                                ),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                            return;
                        }
                        candidate
                    }
                    Err(e) => {
                        let info = ErrorInfo::from(&e);
                        tsfn.call(
                            DiscoveryEvent::Error(info.code_str().to_string(), info.message),
                            ThreadsafeFunctionCallMode::NonBlocking,
                        );
                        return;
                    }
                };

                let mut events = engine.subscribe();
                engine.clone().spawn();
                engine.announce().await;

                loop {
                    // Match on recv() result explicitly: a broadcast RecvError
                    // (Lagged/Closed) must NOT disable this select branch
                    // permanently, or the engine loop silently stops delivering
                    // events to JS (same fix as the uniffi binding).
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
                            tsfn.call(
                                DiscoveryEvent::Found(conv(p)),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                        luciola::PeerEvent::Updated(p) => {
                            tsfn.call(
                                DiscoveryEvent::Updated(conv(p)),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                        luciola::PeerEvent::Lost(id) => {
                            tsfn.call(
                                DiscoveryEvent::Lost(id),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
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
    /// Address this channel dialled.
    pub address: String,
    /// `won` / `cancelled` / `timeout`.
    pub status: String,
    /// Connect latency in milliseconds, when the attempt succeeded.
    pub rtt_ms: Option<f64>,
}

/// Overall race outcome: winning address plus per-channel detail.
#[napi(object)]
pub struct JsRaceOutcome {
    /// Address that won the race, if any.
    pub winner: Option<String>,
    /// Connect latency of the winner, in milliseconds.
    pub rtt_ms: Option<f64>,
    /// Per-candidate outcome, in input order.
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
    /// 32-byte Ed25519 seed — keep it secret.
    pub seed: Buffer,
    /// Ed25519 public key derived from `seed`.
    pub public_key: Buffer,
    /// `sha256:<hex>` fingerprint of `public_key`.
    pub fingerprint: String,
    /// 6-digit on-screen comparison pin.
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
/// tsfn 放在 Mutex<Option<_>> 里：close() 必须能掐断隧道对回调的最后一条持有
/// 路径——一个被引用的 ThreadsafeFunction 会钉住 JS 事件循环，进程因此永不退出。
struct NodeReporter {
    tsfn: std::sync::Mutex<Option<ThreadsafeFunction<ChannelEvent, ErrorStrategy::Fatal>>>,
}

impl TunnelReporter for NodeReporter {
    fn report(&self, kind: &str, detail: String) {
        // 先把句柄 clone 出锁再调用：锁内禁止上报，也不能持锁跨 N-API 调用。
        let tsfn = self.tsfn.lock().unwrap().clone();
        if let Some(tsfn) = tsfn {
            tsfn.call(
                (Some(kind.to_string()), Some(detail), None),
                ThreadsafeFunctionCallMode::NonBlocking,
            );
        }
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
    frames_enqueued: std::sync::Arc<std::sync::atomic::AtomicU64>,
    frames_dequeued: std::sync::Arc<std::sync::atomic::AtomicU64>,
    timings: std::sync::Arc<LinkTimings>,
    /// T3：独立隧道监督实例（数据面不经过 JS，与消息链路并行）。
    tunnel: std::sync::Arc<TunnelLink>,
    /// T3：已注册 onEvent；隧道 error/retrying 经它同步上报。
    tunnel_event: std::sync::Mutex<Option<ThreadsafeFunction<ChannelEvent, ErrorStrategy::Fatal>>>,
    /// T3：交给隧道的 reporter（close() 经它释放隧道持有的 tsfn 克隆）。
    tunnel_reporter: std::sync::Mutex<Option<std::sync::Arc<NodeReporter>>>,
    /// Monotonic generation counter so an exiting old link/WAN pump cannot
    /// clobber `connected` or emit a stale `"closed"` after a newer link or
    /// `attach_wan_channel` has taken over.
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Serializes `close()`, `spawn_link()`, and `attach_wan_channel()`.
    lifecycle: std::sync::Mutex<()>,
}

/// Upper bound (24 h) on keepalive/retry timers so `Instant::now() + period`
/// can never overflow platform instant arithmetic.
const MAX_LINK_TIMER_MS: u64 = 86_400_000;

fn parse_timer_ms(value: f64, field: &str) -> Result<u64> {
    if !value.is_finite() || value < 0.0 {
        return Err(Error::new(
            napi::Status::InvalidArg,
            format!("{field} must be a non-negative finite number"),
        ));
    }
    Ok((value.min(MAX_LINK_TIMER_MS as f64)) as u64)
}

/// Link health counters (same six fields as the uniffi `LinkStats`).
#[napi(object)]
pub struct JsLinkStats {
    /// Frames written to the socket.
    pub frames_sent: i64,
    /// Frames read from the socket.
    pub frames_received: i64,
    /// Successful connections established (including reconnects).
    pub connections_established: i64,
    /// Reconnect attempts started after a drop.
    pub reconnect_attempts: i64,
    /// Frames accepted into the outbound queue.
    pub frames_enqueued: i64,
    /// Frames taken from the outbound queue by the link loop.
    pub frames_dequeued: i64,
}

/// T3/T4 转发 ACL 规则（主机为 IP 字面量或主机名，与 uniffi ForwardRuleDto 同构）。
#[napi(object)]
pub struct JsForwardRule {
    /// IP literal or hostname (normalised to lowercase).
    pub host: String,
    /// Inclusive lower port bound.
    pub port_from: u16,
    /// Inclusive upper port bound.
    pub port_to: u16,
    /// v2：true = 本规则同时放行 UDP 数据报拨号（DOPEN）；false 仅 TCP（v1 语义）。
    pub udp: bool,
}

/// T3/T4 转发状态行（计数沿用 JS 侧 i64 惯例，与 uniffi ForwardStatusDto 同义）。
/// `kind` ∈ {"local", "udp_local", "remote_endpoint", "endpoint", "remote"}。
#[napi(object)]
pub struct JsForwardStatus {
    /// Whether the forward / endpoint is currently bound.
    pub active: bool,
    /// Port actually bound (system-assigned when 0 was requested).
    pub listen_port: u16,
    /// Channels currently relaying bytes.
    pub channels_open: i64,
    /// Channels granted since registration.
    pub channels_total: i64,
    /// OPEN / DOPEN rejected by the ACL.
    pub dial_denied: i64,
    /// Allowed dials that failed or timed out.
    pub dial_failed: i64,
    /// Row kind: local / udp_local / remote_endpoint / endpoint / remote.
    pub kind: String,
}

#[derive(Clone)]
enum ChannelRole {
    /// `pinned = None` → 发起侧 TOFU（`connect_secure_raced_tofu`）。
    Dial(Vec<String>, u16, Option<Vec<u8>>, bool),
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
    /// Create a channel bound to a 32-byte Ed25519 identity seed.
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
            frames_enqueued: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            frames_dequeued: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            timings: std::sync::Arc::new(LinkTimings::default()),
            tunnel: TunnelLink::new(identity_seed.to_vec()),
            tunnel_event: std::sync::Mutex::new(None),
            tunnel_reporter: std::sync::Mutex::new(None),
            generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            lifecycle: std::sync::Mutex::new(()),
        }
    }

    /// Retry policy for auto-reconnect: 2x exponential from minMs to maxMs,
    /// each delay jittered +-jitterPct percent.
    #[napi]
    pub fn set_retry_policy(&self, min_ms: f64, max_ms: f64, jitter_pct: f64) -> Result<()> {
        let t = &self.timings;
        let mn = parse_timer_ms(min_ms, "minMs")?;
        let mx = parse_timer_ms(max_ms, "maxMs")?;
        if !jitter_pct.is_finite() || jitter_pct < 0.0 {
            return Err(Error::new(
                napi::Status::InvalidArg,
                "jitterPct must be a non-negative finite number",
            ));
        }
        let j = (jitter_pct.min(90.0)) as u64;
        t.reconnect_min_ms
            .store(mn, std::sync::atomic::Ordering::Relaxed);
        t.reconnect_max_ms
            .store(mx.max(mn), std::sync::atomic::Ordering::Relaxed);
        t.jitter_pct.store(j, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Keepalive cadence: ping after intervalMs idle; dead after deadAfterMs
    /// of silence. Raise both under Android Doze.
    #[napi]
    pub fn set_keepalive(&self, interval_ms: f64, dead_after_ms: f64) -> Result<()> {
        let t = &self.timings;
        let i = parse_timer_ms(interval_ms, "intervalMs")?;
        let d = parse_timer_ms(dead_after_ms, "deadAfterMs")?;
        t.keepalive_ms
            .store(i, std::sync::atomic::Ordering::Relaxed);
        t.dead_after_ms
            .store(d.max(i), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Link health counters (sent/received frames, connections, retries,
    /// outbound queue in/out — same set as the uniffi `LinkStats`).
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
            frames_enqueued: self
                .frames_enqueued
                .load(std::sync::atomic::Ordering::Relaxed) as i64,
            frames_dequeued: self
                .frames_dequeued
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
        pinned_peer_public_key: Option<Buffer>,
        auto_reconnect: bool,
        on_event: JsFunction,
    ) -> Result<()> {
        self.spawn_link(
            ChannelRole::Dial(
                addresses,
                port,
                pinned_peer_public_key.map(|b| b.to_vec()),
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

    /// Take ownership of an established [`WanChannel`] and drive its
    /// [`luciola::link::secure::SecureStream`] through this channel's existing
    /// `send` / `onEvent` / `stats` / `close` surface. Stops any prior LAN link.
    #[napi(
        ts_args_type = "channel: WanChannel, onEvent: (event: { state?: string, detail?: string, message?: Buffer }) => void"
    )]
    pub fn attach_wan_channel(&self, channel: &WanChannel, on_event: JsFunction) -> Result<()> {
        use napi::threadsafe_function::{
            ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode,
        };

        let mut stream = channel
            .take_stream()?
            .ok_or_else(|| Error::from_reason("WanChannel already attached or shut down"))?;

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
                    if matches!(state.as_deref(), Some("error") | Some("retrying")) {
                        let info = ErrorInfo::parse_detail(d);
                        let mut err = ctx.env.create_object()?;
                        err.set_named_property("code", info.code_str())?;
                        err.set_named_property("message", &info.message)?;
                        err.set_named_property("retryable", info.retryable())?;
                        obj.set_named_property("error", err)?;
                    }
                }
                if let Some(m) = message {
                    let buf = ctx.env.create_buffer_copy(m.as_slice())?;
                    obj.set_named_property("message", buf.into_raw())?;
                }
                Ok(vec![obj])
            })?;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let fp = stream.peer_fingerprint();

        let my_gen = {
            let _life = self.lifecycle.lock().unwrap();
            self.close_locked();
            let g = self
                .generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);
            *self.outbound_tx.lock().unwrap() = Some(out_tx);
            self.connections_established
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.connected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            g
        };

        let connected = self.connected.clone();
        let frames_sent = self.frames_sent.clone();
        let frames_received = self.frames_received.clone();
        let frames_dequeued = self.frames_dequeued.clone();
        let timings = self.timings.clone();
        let generation = self.generation.clone();

        tsfn.call(
            (Some("connected".to_string()), Some(fp), None),
            ThreadsafeFunctionCallMode::NonBlocking,
        );

        napi::tokio::spawn(async move {
            let ka_ms = timings
                .keepalive_ms
                .load(std::sync::atomic::Ordering::Relaxed);
            let mut keepalive = (ka_ms > 0).then(|| {
                let mut iv = tokio::time::interval(std::time::Duration::from_millis(ka_ms));
                iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                iv.reset();
                iv
            });
            let mut awaiting_pong = false;
            loop {
                let mut buf = Vec::new();
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        let _ = stream.shutdown().await;
                        break;
                    }
                    _ = async {
                        if let Some(ref mut iv) = keepalive {
                            iv.tick().await;
                        }
                    }, if keepalive.is_some() => {
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
                            frames_dequeued.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if let Some(ref mut iv) = keepalive {
                                iv.reset();
                            }
                            awaiting_pong = false;
                            if stream.send(&m).await.is_ok() {
                                frames_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            } else {
                                break;
                            }
                        }
                        None => break,
                    },
                    frame = stream.recv(&mut buf) => {
                        if let Some(ref mut iv) = keepalive {
                            iv.reset();
                        }
                        awaiting_pong = false;
                        if frame.is_err() {
                            break;
                        }
                        if !buf.is_empty() {
                            frames_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tsfn.call(
                                (None, None, Some(buf)),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                    }
                }
            }
            if generation.load(std::sync::atomic::Ordering::SeqCst) == my_gen {
                connected.store(false, std::sync::atomic::Ordering::SeqCst);
                tsfn.call(
                    (Some("closed".to_string()), None, None),
                    ThreadsafeFunctionCallMode::NonBlocking,
                );
            }
        });

        Ok(())
    }

    /// Queue an encrypted frame; false when not connected.
    #[napi]
    pub fn send(&self, message: Buffer) -> bool {
        if !self.connected.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        match self.outbound_tx.lock().unwrap().as_ref() {
            Some(tx) => {
                let ok = tx.try_send(message.to_vec()).is_ok();
                if ok {
                    self.frames_enqueued
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ok
            }
            None => false,
        }
    }

    #[napi]
    /// Whether the channel currently holds an authenticated connection.
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[napi]
    /// Close the channel, stop reconnecting and pause the tunnel.
    pub fn close(&self) {
        let _life = self.lifecycle.lock().unwrap();
        self.close_locked();
    }

    /// T3 本地转发（发起端）：本机 127.0.0.1:listenPort → 经隧道 → target。
    /// 端口冲突等同步失败：返回 false 并经 onEvent 报 "error"
    ///（detail 前缀 forward_bind_failed: ）。
    #[napi]
    /// `host` 为 IP 字面量或主机名（v2：主机名由对端解析并按会话钉扎）。
    pub fn start_local_forward(&self, listen_port: u16, host: String, port: u16) -> bool {
        self.tunnel_result(self.tunnel.start_local_forward(listen_port, host, port))
    }

    /// T4 UDP 转发（发起端，NAT 式会话映射）：本机 127.0.0.1:listenPort 的每个
    /// 源地址映射一条数据报通道到对端 host:port；对端 ACL 规则须 udp=true 放行。
    #[napi]
    pub fn start_udp_forward(&self, listen_port: u16, host: String, port: u16) -> bool {
        self.tunnel_result(self.tunnel.start_udp_forward(listen_port, host, port))
    }

    /// T4 注销 UDP 转发。未注册返回 false。
    #[napi]
    pub fn stop_udp_forward(&self, listen_port: u16) -> bool {
        self.tunnel_result(self.tunnel.stop_udp_forward(listen_port))
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
    /// 规则主机为 IP 字面量或主机名；`udp=true` 的规则同时放行 DOPEN（UDP 拨号）。
    pub fn enable_forward_endpoint(&self, rules: Vec<JsForwardRule>) -> bool {
        match parse_rule_objs(rules) {
            Ok(parsed) => self.tunnel_result(self.tunnel.enable_forward_endpoint(parsed)),
            Err(e) => self.tunnel_result(Err(e)),
        }
    }

    /// T4 remote endpoint ACL（发起端）：放行响应端 remote forward（-R）拨入的
    /// 本机目标；未启用 = 默认拒绝。
    #[napi]
    pub fn enable_remote_endpoint(&self, rules: Vec<JsForwardRule>) -> bool {
        match parse_rule_objs(rules) {
            Ok(parsed) => self.tunnel_result(self.tunnel.enable_remote_endpoint(parsed)),
            Err(e) => self.tunnel_result(Err(e)),
        }
    }

    /// T4 关闭 remote endpoint（幂等）。
    #[napi]
    pub fn disable_remote_endpoint(&self) -> bool {
        self.tunnel_result(self.tunnel.disable_remote_endpoint())
    }

    /// T4 remote forward（响应端，`-R`）：本机 127.0.0.1:listenPort 的每条入站
    /// 连接经隧道（偶数通道）转发到对端机上的 host:port；对端须启用
    /// remote endpoint 放行目标。
    #[napi]
    pub fn start_remote_forward(&self, listen_port: u16, host: String, port: u16) -> bool {
        self.tunnel_result(self.tunnel.start_remote_forward(listen_port, host, port))
    }

    /// T4 注销 remote forward。未注册返回 false。
    #[napi]
    pub fn stop_remote_forward(&self, listen_port: u16) -> bool {
        self.tunnel_result(self.tunnel.stop_remote_forward(listen_port))
    }

    /// T4 隧道 mux keepalive：intervalMs=0 关闭；随下一次隧道链路重建生效。
    #[napi]
    pub fn set_tunnel_keepalive(&self, interval_ms: f64, dead_after_ms: f64) -> Result<()> {
        let i = parse_timer_ms(interval_ms, "intervalMs")?;
        let d = parse_timer_ms(dead_after_ms, "deadAfterMs")?;
        self.tunnel.set_keepalive(i, d);
        Ok(())
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
                kind: s.kind.as_str().to_string(),
            })
            .collect()
    }
}

/// DTO → 核心规则：主机为 IP 字面量或合法主机名（v2），端口区间正序。
fn parse_rule_objs(objs: Vec<JsForwardRule>) -> std::result::Result<Vec<ForwardRule>, TunnelError> {
    let mut parsed = Vec::with_capacity(objs.len());
    for r in objs {
        if r.port_from == 0 || r.port_from > r.port_to {
            return Err(TunnelError::InvalidRule(format!(
                "非法端口区间：{}:{}-{}",
                r.host, r.port_from, r.port_to
            )));
        }
        let host = luciola_tunnel::forward::normalize_rule_host_text(&r.host).ok_or_else(|| {
            TunnelError::InvalidRule(format!(
                "规则主机既不是合法 IP 也不是合法主机名：{}:{}-{}",
                r.host, r.port_from, r.port_to
            ))
        })?;
        parsed.push(ForwardRule {
            host,
            port_from: r.port_from,
            port_to: r.port_to,
            udp: r.udp,
        });
    }
    Ok(parsed)
}

impl SecureChannel {
    fn close_locked(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        *self.outbound_tx.lock().unwrap() = None;
        // 释放事件回调的全部持有路径：链路线程退出时丢弃自己的克隆，隧道的两条
        // （tunnel_event 与 NodeReporter）在这里掐断。少放掉一个，被引用的
        // ThreadsafeFunction 就会把 JS 事件循环钉住——contract 测试曾因此在打印
        // "✅ passed" 之后永不退出。
        *self.tunnel_event.lock().unwrap() = None;
        if let Some(rep) = self.tunnel_reporter.lock().unwrap().take() {
            *rep.tsfn.lock().unwrap() = None;
        }
        self.connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // T3：消息链路关闭 → 暂停隧道（注册表保留，重连后自动恢复）。
        self.tunnel.pause();
    }
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
                    // Error / retry details carry a `"<code>: <message>"`
                    // prefix. Surface it as a structured companion instead of
                    // forcing every host to parse the prose. `connected` uses
                    // `detail` for the fingerprint, so only these two states
                    // get an `error` object.
                    if matches!(state.as_deref(), Some("error") | Some("retrying")) {
                        let info = ErrorInfo::parse_detail(d);
                        let mut err = ctx.env.create_object()?;
                        err.set_named_property("code", info.code_str())?;
                        err.set_named_property("message", &info.message)?;
                        err.set_named_property("retryable", info.retryable())?;
                        obj.set_named_property("error", err)?;
                    }
                }
                if let Some(m) = message {
                    let buf = ctx.env.create_buffer_copy(m.as_slice())?;
                    obj.set_named_property("message", buf.into_raw())?;
                }
                Ok(vec![obj])
            })?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        // Bounded outbound queue: a stalled peer must not grow our memory.
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let my_gen = {
            let _life = self.lifecycle.lock().unwrap();
            self.close_locked();
            let g = self
                .generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);
            *self.outbound_tx.lock().unwrap() = Some(out_tx);
            // T3：把消息链路的角色翻成隧道基址。close_locked() 已先发 Pause，随后 SetBase 在
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
            let reporter = std::sync::Arc::new(NodeReporter {
                tsfn: std::sync::Mutex::new(Some(tsfn.clone())),
            });
            *self.tunnel_reporter.lock().unwrap() = Some(reporter.clone());
            self.tunnel.set_base(tunnel_base, reporter);
            g
        };
        let connected = self.connected.clone();
        let seed = self.identity_seed.clone();
        let timings = self.timings.clone();
        let (frames_sent, frames_received) =
            (self.frames_sent.clone(), self.frames_received.clone());
        let (connections_established, reconnect_attempts) = (
            self.connections_established.clone(),
            self.reconnect_attempts.clone(),
        );
        let frames_dequeued = self.frames_dequeued.clone();
        let generation = self.generation.clone();

        std::thread::Builder::new()
            .name("luciola-node-secure-link".to_string())
            .spawn(move || {
                use luciola::link::secure::{accept_secure, connect_secure_raced, connect_secure_raced_tofu};
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
                        if generation.load(std::sync::atomic::Ordering::SeqCst) != my_gen {
                            break 'outer;
                        }
                        let stream = match role.clone() {
                            ChannelRole::Dial(addresses, port, pinned, auto) => {
                                let attempt = tokio::select! {
                                    _ = &mut shutdown => break 'outer,
                                    r = async {
                                        match pinned.as_deref() {
                                            Some(k) => connect_secure_raced(addresses.clone(), port, &seed, k).await,
                                            None => connect_secure_raced_tofu(addresses.clone(), port, &seed).await,
                                        }
                                    } => r,
                                };
                                if generation.load(std::sync::atomic::Ordering::SeqCst) != my_gen {
                                    if let Ok(mut s) = attempt {
                                        let _ = s.shutdown().await;
                                    }
                                    break 'outer;
                                }
                                match attempt {
                                    Ok(s) => {
                                        backoff = min;
                                        s
                                    }
                                    Err(e) => {
                                        connected.store(false, std::sync::atomic::Ordering::SeqCst);
                                        if !auto {
                                            let info = ErrorInfo::from(&e);
                                            tsfn.call((Some("error".to_string()), Some(info.wire_detail()), None), ThreadsafeFunctionCallMode::NonBlocking);
                                            return;
                                        }
                                        reconnect_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        let jittered = timings.backoff(backoff);
                                        let info = ErrorInfo::from(&e);
                                        tsfn.call((Some("retrying".to_string()), Some(format!("{}; next attempt in {:?}", info.wire_detail(), jittered)), None), ThreadsafeFunctionCallMode::NonBlocking);
                                        tokio::select! {
                                            _ = tokio::time::sleep(jittered) => {}
                                            _ = &mut shutdown => break 'outer,
                                        }
                                        let cap = std::time::Duration::from_millis(
                                            timings.reconnect_max_ms.load(std::sync::atomic::Ordering::Relaxed));
                                        backoff = std::cmp::min(backoff.saturating_mul(2), cap.max(min));
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
                                            if generation.load(std::sync::atomic::Ordering::SeqCst) == my_gen {
                                                let info = ErrorInfo::new(ErrorCode::BindFailed, e.to_string());
                                                tsfn.call((Some("error".to_string()), Some(info.wire_detail()), None), ThreadsafeFunctionCallMode::NonBlocking);
                                            }
                                            return;
                                        }
                                    },
                                    _ = &mut shutdown => break 'outer,
                                };
                                let accepted = tokio::select! {
                                    r = accept_secure(&l, &seed, expected.as_deref()) => match r {
                                        Ok(s) => s,
                                        Err(e) => {
                                            if generation.load(std::sync::atomic::Ordering::SeqCst) != my_gen {
                                                break 'outer;
                                            }
                                            // Handshake failures (wrong initiator) keep the listener alive.
                                            let info = ErrorInfo::from(&e);
                                            tsfn.call((Some("retrying".to_string()), Some(info.wire_detail()), None), ThreadsafeFunctionCallMode::NonBlocking);
                                            continue 'outer;
                                        }
                                    },
                                    _ = &mut shutdown => break 'outer,
                                };
                                accepted
                            }
                        };
                        let mut stream = stream;
                        if generation.load(std::sync::atomic::Ordering::SeqCst) != my_gen {
                            let _ = stream.shutdown().await;
                            break 'outer;
                        }
                        connections_established.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        connected.store(true, std::sync::atomic::Ordering::SeqCst);
                        tsfn.call((Some("connected".to_string()), Some(stream.peer_fingerprint()), None), ThreadsafeFunctionCallMode::NonBlocking);

                        let ka_ms = timings
                            .keepalive_ms
                            .load(std::sync::atomic::Ordering::Relaxed);
                        let mut keepalive = (ka_ms > 0).then(|| {
                            let mut iv = tokio::time::interval(std::time::Duration::from_millis(ka_ms));
                            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                            iv.reset();
                            iv
                        });
                        let mut awaiting_pong = false;
                        loop {
                            let mut buf: Vec<u8> = Vec::new();
                            tokio::select! {
                                _ = &mut shutdown => {
                                    let _ = stream.shutdown().await;
                                    break 'outer;
                                }
                                _ = async {
                                    if let Some(ref mut iv) = keepalive {
                                        iv.tick().await;
                                    }
                                }, if keepalive.is_some() => {
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
                                        frames_dequeued.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        if let Some(ref mut iv) = keepalive {
                                            iv.reset();
                                        }
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
                                    if let Some(ref mut iv) = keepalive {
                                        iv.reset();
                                    }
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
                        if generation.load(std::sync::atomic::Ordering::SeqCst) == my_gen {
                            connected.store(false, std::sync::atomic::Ordering::SeqCst);
                            tsfn.call((Some("closed".to_string()), None, None), ThreadsafeFunctionCallMode::NonBlocking);
                        } else {
                            break 'outer;
                        }
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
    /// Display name of the host device.
    pub name: String,
    /// Product label, when the host advertises one.
    pub product: Option<String>,
    /// TCP service port to dial.
    pub port: u16,
    /// Candidate addresses for the host, best first.
    pub addrs: Vec<String>,
    /// Host identity fingerprint (`sha256:<hex>`) — bind trust on it.
    pub fingerprint: Option<String>,
    /// Host Ed25519 public key (base64) — the pin target.
    pub public_key: Option<String>,
    /// Optional 6-digit on-screen comparison pin.
    pub pin: Option<String>,
    /// Optional pre-shared key for WAN rendezvous room derivation.
    pub psk: Option<String>,
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

/// Build a v3 pairing URI (carrying optional PSK for WAN rendezvous).
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn build_pairing_uri_v3(
    name: String,
    product: Option<String>,
    port: u16,
    addrs: Vec<String>,
    fingerprint: Option<String>,
    public_key: Option<String>,
    pin: Option<String>,
    psk: Option<String>,
) -> String {
    luciola::pairing::build_pairing_uri_v3(
        &name,
        product.as_deref(),
        port,
        &addrs,
        fingerprint.as_deref(),
        public_key.as_deref(),
        pin.as_deref(),
        psk.as_deref(),
    )
}

/// Parse a pairing URI (`luciola://pair?...` v1/v2/v3 or plain `http://host:port`).
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
        psk: p.psk,
    })
}

/// Derive deterministic Cloudflare Worker rendezvous room ID from two public keys and optional PSK.
#[napi]
pub fn derive_rendezvous_room_id(
    my_pk: String,
    peer_pk: String,
    psk: Option<String>,
    epoch: Option<i64>,
) -> String {
    let epoch_u64 = epoch.and_then(|e| if e >= 0 { Some(e as u64) } else { None });
    luciola::pairing::derive_rendezvous_room_id_flexible(
        my_pk.as_bytes(),
        peer_pk.as_bytes(),
        psk.as_deref().map(|s| s.as_bytes()),
        epoch_u64,
    )
}

/// 平台日志出口的一条日志：引擎内 tracing 以 (level, message) 送达 JS 回调。
#[napi(object)]
pub struct JsLogEvent {
    /// Tracing level (`trace` / `debug` / `info` / `warn` / `error`).
    pub level: String,
    /// Rendered log message.
    pub message: String,
}

/// 安装（或清除）平台日志出口。进程内全局 tracing subscriber 只能安装一次：
/// 首次调用尝试安装桥接 subscriber；宿主已自带 subscriber 时安装失败并被
/// 忽略（日志归宿主处理，有意让位）。回调内不要再调用会打日志的引擎 API。
#[napi]
pub fn set_log_sink(callback: Option<JsFunction>) -> Result<()> {
    let tsfn: Option<ThreadsafeFunction<JsLogEvent, ErrorStrategy::Fatal>> = match callback {
        Some(cb) => Some(cb.create_threadsafe_function(
            0,
            |ctx: ThreadSafeCallContext<JsLogEvent>| {
                Ok(vec![
                    ctx.env.create_string(&ctx.value.level)?.into_unknown(),
                    ctx.env.create_string(&ctx.value.message)?.into_unknown(),
                ])
            },
        )?),
        None => None,
    };
    *LOG_SINK_TSFN.lock().unwrap() = tsfn;
    LOG_SUBSCRIBER_ONCE.call_once(|| {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(NodeSinkBridge)
            .try_init();
    });
    Ok(())
}

static LOG_SINK_TSFN: std::sync::Mutex<
    Option<ThreadsafeFunction<JsLogEvent, ErrorStrategy::Fatal>>,
> = std::sync::Mutex::new(None);
static LOG_SUBSCRIBER_ONCE: std::sync::Once = std::sync::Once::new();

struct NodeSinkBridge;

struct NodeMessageVisitor(String);

impl tracing::field::Visit for NodeMessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = write!(self.0, "{}={:?}", field.name(), value);
    }
}

impl<S> tracing_subscriber::Layer<S> for NodeSinkBridge
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = event.metadata().level().to_string();
        let mut visitor = NodeMessageVisitor(String::new());
        event.record(&mut visitor);
        let tsfn = LOG_SINK_TSFN.lock().unwrap().clone();
        if let Some(tsfn) = tsfn {
            tsfn.call(
                JsLogEvent {
                    level,
                    message: visitor.0,
                },
                ThreadsafeFunctionCallMode::NonBlocking,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// WAN traversal
// ---------------------------------------------------------------------------

use zeroize::Zeroizing;

/// Relay and signalling policy for one WAN channel. Both flags default to
/// `false`, so a host must opt in to third-party signalling explicitly.
#[napi(object)]
pub struct JsWanRelayConfig {
    /// Permit an end-to-end encrypted relay when a direct path fails.
    pub allow_relay: bool,
    /// Permit third-party signalling (public keys, public IPs and online times
    /// leave the LAN).
    pub allow_wan_signaling: bool,
    /// Reserved for dedicated relay endpoints; the current engine reuses the
    /// already-authenticated signalling WebSocket.
    pub relay_endpoints: Vec<String>,
    /// WebSocket connect timeout in milliseconds (clamped to a 500 ms floor).
    pub connection_timeout_ms: u32,
}

/// Everything a host supplies to establish one WAN channel.
#[napi(object)]
pub struct JsWanConfig {
    /// `wss://` rendezvous endpoint (`ws://` is accepted for loopback tests).
    pub signaling_endpoint: String,
    /// 32-character hex room id from `wanDeriveRoomId`.
    pub room: String,
    /// Rendezvous epoch; `0` means the current epoch.
    pub epoch: u32,
    /// Pairing PSK (secret; zeroized inside the engine).
    pub psk: Buffer,
    /// Local 32-byte Ed25519 identity seed.
    pub identity_seed: Buffer,
    /// Local 32-byte Ed25519 public key.
    pub my_public_key: Buffer,
    /// Pinned peer 32-byte Ed25519 public key (never TOFU).
    pub peer_public_key: Buffer,
    /// Relay and signalling policy.
    pub relay: JsWanRelayConfig,
    /// Optional single STUN server override.
    pub stun_server: Option<String>,
    /// Candidate/punch budget in milliseconds; omitted or `0` uses 5000 ms.
    pub punch_timeout_ms: Option<u32>,
    /// Skip UDP punching (and the public STUN query). Defaults to `true`.
    pub enable_hole_punching: Option<bool>,
    /// Local LAN TCP port advertised in candidates. Defaults to `0`.
    pub tcp_port: Option<u32>,
    /// Start streaming over the relay immediately and migrate later.
    /// Defaults to `false`.
    pub progressive: Option<bool>,
}

impl JsWanConfig {
    fn into_core(self) -> Result<luciola::wan::WanConfig> {
        if self.signaling_endpoint.is_empty() {
            return Err(Error::from_reason("signalingEndpoint must not be empty"));
        }
        if self.room.is_empty() {
            return Err(Error::from_reason(
                "room must not be empty; derive it with wanDeriveRoomId",
            ));
        }
        if self.psk.is_empty() {
            return Err(Error::from_reason("psk must not be empty"));
        }
        let identity_seed = require_key(&self.identity_seed, "identitySeed")?;
        let my_public_key = require_key(&self.my_public_key, "myPublicKey")?;
        let peer_public_key = require_key(&self.peer_public_key, "peerPublicKey")?;
        let tcp_port = u16::try_from(self.tcp_port.unwrap_or(0))
            .map_err(|_| Error::from_reason("tcpPort must fit in u16"))?;
        let punch_timeout_ms = u64::from(self.punch_timeout_ms.unwrap_or(0));
        Ok(luciola::wan::WanConfig {
            signaling_endpoint: self.signaling_endpoint,
            room: self.room,
            epoch: u64::from(self.epoch),
            psk: Zeroizing::new(self.psk.to_vec()),
            identity_seed,
            my_public_key,
            peer_public_key,
            relay: luciola_proto::RelayConfig {
                allow_relay: self.relay.allow_relay,
                allow_wan_signaling: self.relay.allow_wan_signaling,
                relay_endpoints: self.relay.relay_endpoints,
                connection_timeout_ms: u64::from(self.relay.connection_timeout_ms),
            },
            stun_server: self.stun_server,
            punch_timeout: std::time::Duration::from_millis(if punch_timeout_ms == 0 {
                5_000
            } else {
                punch_timeout_ms
            }),
            enable_hole_punching: self.enable_hole_punching.unwrap_or(true),
            tcp_port,
            progressive: self.progressive.unwrap_or(false),
            // Explicit proxy configuration is Rust-core/CLI only. Node callers
            // use the process environment (HTTPS_PROXY / NO_PROXY).
            proxy: None,
        })
    }
}

fn require_key(bytes: &[u8], field: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| Error::from_reason(format!("{field} must be exactly 32 bytes")))
}

/// An established WAN channel.
///
/// `connectWan` returns a Promise; the channel reports the data plane it
/// actually uses and must be shut down when the host is done with it.
#[napi]
pub struct WanChannel {
    inner: std::sync::Mutex<Option<luciola::link::secure::SecureStream>>,
}

impl WanChannel {
    fn take_stream(&self) -> Result<Option<luciola::link::secure::SecureStream>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN channel lock poisoned"))?;
        Ok(guard.take())
    }
}

#[napi]
impl WanChannel {
    /// The data plane this channel actually uses: `lan_direct`,
    /// `hole_punched_direct`, `relay_forwarded`, `usb_adb_direct`, or
    /// `unknown` after shutdown.
    #[napi]
    pub fn channel_type(&self) -> String {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .map(|stream| stream.channel_type().as_str().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// The peer's socket endpoint, when the transport exposes one.
    #[napi]
    pub fn remote_addr(&self) -> Option<String> {
        self.inner.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .and_then(|stream| stream.remote_addr())
                .map(|addr| addr.to_string())
        })
    }

    /// Close the channel. Idempotent; a second call is a no-op.
    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        let stream = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN channel lock poisoned"))?
            .take();
        if let Some(mut stream) = stream {
            stream
                .shutdown()
                .await
                .map_err(|err| Error::from_reason(err.to_string()))?;
        }
        Ok(())
    }
}

/// Establish a WAN secure channel. Returns a Promise.
///
/// Order of attempts: encrypted candidate exchange over WSS, simultaneous UDP
/// hole punching on the same socket, then an end-to-end encrypted relay over
/// the signalling WebSocket only when both peers allow it and agree on the
/// route.
#[napi]
pub async fn connect_wan(config: JsWanConfig) -> Result<WanChannel> {
    let core = config.into_core()?;
    let stream = luciola::wan::connect_wan(core)
        .await
        .map_err(|err| Error::from_reason(err.to_string()))?;
    Ok(WanChannel {
        inner: std::sync::Mutex::new(Some(stream)),
    })
}

/// The current 10-minute rendezvous epoch (`unix_seconds / 600`).
#[napi]
pub fn wan_current_epoch() -> u32 {
    luciola::wan::current_epoch() as u32
}

/// Derive the room id both peers must use for `epoch`.
///
/// The PSK is required: without one the engine returns an empty room id rather
/// than deriving a room any third party could predict from the public keys.
#[napi]
pub fn wan_derive_room_id(
    my_public_key: Buffer,
    peer_public_key: Buffer,
    psk: Buffer,
    epoch: u32,
) -> Result<String> {
    let my = require_key(&my_public_key, "myPublicKey")?;
    let peer = require_key(&peer_public_key, "peerPublicKey")?;
    if psk.is_empty() {
        return Err(Error::from_reason("psk must not be empty"));
    }
    let room = luciola::pairing::derive_rendezvous_room_id_flexible(
        &my,
        &peer,
        Some(&psk[..]),
        Some(u64::from(epoch)),
    );
    if room.is_empty() {
        return Err(Error::from_reason("room derivation failed; check the PSK"));
    }
    Ok(room)
}

/// LAN dial configuration for [`connect_with_policy`] (pinned peer identity required; no TOFU).
#[napi(object)]
pub struct JsLanDialConfig {
    /// Candidate LAN IPv4 / IPv6 addresses.
    pub addresses: Vec<String>,
    /// Peer's secure TCP port (`1..=65535`).
    pub port: u32,
    /// Local 32-byte Ed25519 identity seed (zeroized after validation).
    pub identity_seed: Buffer,
    /// Pinned 32-byte Ed25519 peer public key (mandatory; no TOFU).
    pub peer_public_key: Buffer,
}

impl JsLanDialConfig {
    fn into_core(self) -> Result<luciola::wan::route::LanDialConfig> {
        let mut seed_vec = self.identity_seed.to_vec();
        let port = match u16::try_from(self.port) {
            Ok(p) if p > 0 => p,
            _ => {
                zeroize::Zeroize::zeroize(&mut seed_vec);
                return Err(Error::new(
                    napi::Status::InvalidArg,
                    format!("lan.port {} is out of 1..=65535 range", self.port),
                ));
            }
        };
        let seed_res = require_key(&seed_vec, "lan.identitySeed");
        zeroize::Zeroize::zeroize(&mut seed_vec);
        let identity_seed = zeroize::Zeroizing::new(seed_res?);
        let peer_public_key = require_key(&self.peer_public_key, "lan.peerPublicKey")?;
        Ok(luciola::wan::route::LanDialConfig {
            addresses: self.addresses,
            port,
            identity_seed,
            peer_public_key,
        })
    }
}

/// Establish an authenticated channel according to `policy`:
/// `'lan_only'`, `'lan_then_wan'`, or `'wan_only'`.
///
/// Under `'lan_then_wan'`, `lanBudgetMs == 0` or `undefined` uses a 1500 ms default budget,
/// and security failures (pin mismatch / tamper) fail immediately without falling back to WAN.
#[napi]
pub async fn connect_with_policy(
    policy: String,
    lan_budget_ms: Option<f64>,
    lan: Option<JsLanDialConfig>,
    wan: Option<JsWanConfig>,
) -> Result<WanChannel> {
    let budget_ms = match lan_budget_ms {
        Some(ms) => {
            if !ms.is_finite() || ms < 0.0 || ms > (u64::MAX as f64) {
                return Err(Error::new(
                    napi::Status::InvalidArg,
                    "lanBudgetMs must be a non-negative finite number",
                ));
            }
            ms as u64
        }
        None => 0,
    };

    let core_policy = match policy.as_str() {
        "lan_only" => luciola::wan::route::RoutePolicy::LanOnly,
        "lan_then_wan" => luciola::wan::route::RoutePolicy::LanThenWan {
            lan_budget: std::time::Duration::from_millis(if budget_ms == 0 {
                1_500
            } else {
                budget_ms
            }),
        },
        "wan_only" => luciola::wan::route::RoutePolicy::WanOnly,
        other => {
            return Err(Error::new(
                napi::Status::InvalidArg,
                format!(
                    "unknown route policy '{other}'; expected 'lan_only', 'lan_then_wan', or 'wan_only'"
                ),
            ));
        }
    };

    let lan_core = match core_policy {
        luciola::wan::route::RoutePolicy::WanOnly => {
            if let Some(mut unused) = lan {
                zeroize::Zeroize::zeroize(unused.identity_seed.as_mut());
            }
            None
        }
        _ => lan.map(JsLanDialConfig::into_core).transpose()?,
    };
    let wan_core = match core_policy {
        luciola::wan::route::RoutePolicy::LanOnly => {
            if let Some(mut unused) = wan {
                zeroize::Zeroize::zeroize(unused.psk.as_mut());
                zeroize::Zeroize::zeroize(unused.identity_seed.as_mut());
            }
            None
        }
        _ => wan.map(JsWanConfig::into_core).transpose()?,
    };

    let stream = luciola::wan::route::connect_with_policy(core_policy, lan_core, wan_core)
        .await
        .map_err(|err| Error::from_reason(err.to_string()))?;
    Ok(WanChannel {
        inner: std::sync::Mutex::new(Some(stream)),
    })
}

// ---------------------------------------------------------------------------
// File transfer & standalone WAN tunnel exports (WP1.2 / WP1.3)
// ---------------------------------------------------------------------------

/// Progress update emitted during a file transfer.
#[napi(object)]
#[derive(Clone)]
pub struct JsTransferProgress {
    /// Stable transfer identifier used for checkpoint matching.
    pub transfer_id: String,
    /// Contiguous acknowledged bytes so far.
    pub bytes_done: f64,
    /// Total expected file size in bytes.
    pub total_bytes: f64,
    /// Active transport plane (`lan_direct`, `hole_punched_direct`, `relay_forwarded`, `usb_adb_direct`).
    pub channel_type: String,
    /// True when this update reports a resumed checkpoint skip.
    pub resumed: bool,
}

/// Cooperative cancellation handle shared with any `transfer*` call.
#[napi]
pub struct TransferCancelHandle {
    tx: std::sync::Mutex<tokio::sync::watch::Sender<bool>>,
    rx: tokio::sync::watch::Receiver<bool>,
}

impl TransferCancelHandle {
    fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.rx.clone()
    }
}

#[napi]
impl TransferCancelHandle {
    /// Create a fresh non-cancelled handle.
    #[napi(constructor)]
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        Self {
            tx: std::sync::Mutex::new(tx),
            rx,
        }
    }

    /// Signal cancellation to any transfer observing this handle.
    #[napi]
    pub fn cancel(&self) {
        if let Ok(guard) = self.tx.lock() {
            let _ = guard.send(true);
        }
    }

    /// Whether [`Self::cancel`] has been called.
    #[napi]
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }
}

impl Default for TransferCancelHandle {
    fn default() -> Self {
        Self::new()
    }
}

fn to_js_progress(p: luciola_transfer::TransferProgress) -> JsTransferProgress {
    JsTransferProgress {
        transfer_id: p.transfer_id,
        bytes_done: p.bytes_done as f64,
        total_bytes: p.total_bytes as f64,
        channel_type: p.channel_type.as_str().to_string(),
        resumed: p.resumed,
    }
}

fn build_progress_tsfn(
    cb: napi::JsFunction,
) -> Result<
    napi::threadsafe_function::ThreadsafeFunction<
        JsTransferProgress,
        napi::threadsafe_function::ErrorStrategy::Fatal,
    >,
> {
    cb.create_threadsafe_function(0, |ctx| {
        let p: &JsTransferProgress = &ctx.value;
        let mut obj = ctx.env.create_object()?;
        obj.set_named_property("transferId", &p.transfer_id)?;
        obj.set_named_property("bytesDone", p.bytes_done)?;
        obj.set_named_property("totalBytes", p.total_bytes)?;
        obj.set_named_property("channelType", &p.channel_type)?;
        obj.set_named_property("resumed", p.resumed)?;
        Ok(vec![obj])
    })
}

/// Verified final receipt returned by Node file transfer functions.
#[napi(object)]
pub struct JsTransferReceipt {
    pub transfer_id: String,
    pub file_name: String,
    pub total_bytes: f64,
    pub sha256_hex: String,
    pub saved_path: Option<String>,
    pub channel_type: String,
}

fn to_js_receipt(r: luciola_transfer::TransferReceipt) -> JsTransferReceipt {
    JsTransferReceipt {
        transfer_id: r.transfer_id,
        file_name: r.file_name,
        total_bytes: r.total_bytes as f64,
        sha256_hex: r.sha256_hex,
        saved_path: r.saved_path.map(|p| p.to_string_lossy().into_owned()),
        channel_type: r.channel_type.as_str().to_string(),
    }
}

/// Send one file over a pin-verified LAN connection (no TOFU).
#[napi(ts_return_type = "Promise<JsTransferReceipt>")]
#[allow(clippy::too_many_arguments)]
pub fn transfer_send_lan(
    env: Env,
    identity_seed: Buffer,
    addresses: Vec<String>,
    port: u16,
    pinned_peer_public_key: Buffer,
    file_path: String,
    #[napi(ts_arg_type = "((progress: JsTransferProgress) => void) | undefined | null")]
    on_progress: Option<JsFunction>,
    cancel: Option<&TransferCancelHandle>,
) -> Result<napi::JsObject> {
    let tsfn = on_progress.map(build_progress_tsfn).transpose()?;
    let cancel_rx = cancel
        .map(|h| h.subscribe())
        .unwrap_or_else(|| tokio::sync::watch::channel(false).1);
    let mut seed_vec = identity_seed.to_vec();
    let peer_vec = pinned_peer_public_key.to_vec();

    env.execute_tokio_future(
        async move {
            let seed_res = require_key(&seed_vec, "identitySeed");
            zeroize::Zeroize::zeroize(&mut seed_vec);
            let seed = zeroize::Zeroizing::new(seed_res?);
            let peer_pk = require_key(&peer_vec, "pinnedPeerPublicKey")?;
            if addresses.is_empty() {
                return Err(Error::from_reason("addresses must not be empty"));
            }
            let mut dial_cancel = cancel_rx.clone();
            let stream = tokio::select! {
                _ = async {
                    loop {
                        if *dial_cancel.borrow() {
                            break;
                        }
                        if dial_cancel.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                } => {
                    return Err(Error::from_reason("transfer cancelled"));
                }
                res = luciola::link::secure::connect_secure_raced(addresses, port, seed.as_slice(), &peer_pk) => {
                    res.map_err(|e| Error::from_reason(e.to_string()))?
                }
            };
            let receipt = luciola::transfer_driver::send_file_over_stream(
                stream,
                std::path::Path::new(&file_path),
                None,
                None,
                luciola_transfer::SenderConfig::default(),
                cancel_rx,
                |p| {
                    if let Some(ref cb) = tsfn {
                        cb.call(
                            to_js_progress(p),
                            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok(to_js_receipt(receipt))
        },
        |_env, receipt| Ok(receipt),
    )
}

/// Accept one pin-verified LAN file transfer into `destDir` (no TOFU).
#[napi(ts_return_type = "Promise<JsTransferReceipt>")]
pub fn transfer_recv_lan(
    env: Env,
    identity_seed: Buffer,
    listen_port: u16,
    accept_peer_public_key: Buffer,
    dest_dir: String,
    #[napi(ts_arg_type = "((progress: JsTransferProgress) => void) | undefined | null")]
    on_progress: Option<JsFunction>,
    cancel: Option<&TransferCancelHandle>,
) -> Result<napi::JsObject> {
    let tsfn = on_progress.map(build_progress_tsfn).transpose()?;
    let cancel_rx = cancel
        .map(|h| h.subscribe())
        .unwrap_or_else(|| tokio::sync::watch::channel(false).1);
    let mut seed_vec = identity_seed.to_vec();
    let peer_vec = accept_peer_public_key.to_vec();

    env.execute_tokio_future(
        async move {
            let seed_res = require_key(&seed_vec, "identitySeed");
            zeroize::Zeroize::zeroize(&mut seed_vec);
            let seed = zeroize::Zeroizing::new(seed_res?);
            let peer_pk = require_key(&peer_vec, "acceptPeerPublicKey")?;
            let tcp_listener = luciola::link::bind_dual_stack_listener(listen_port)
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?;
            let mut accept_cancel = cancel_rx.clone();
            let stream = tokio::select! {
                _ = async {
                    loop {
                        if *accept_cancel.borrow() {
                            break;
                        }
                        if accept_cancel.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                } => {
                    return Err(Error::from_reason("transfer cancelled"));
                }
                res = luciola::link::secure::accept_secure(&tcp_listener, seed.as_slice(), Some(&peer_pk)) => {
                    res.map_err(|e| Error::from_reason(e.to_string()))?
                }
            };
            let receipt = luciola::transfer_driver::recv_file_over_stream(
                stream,
                std::path::Path::new(&dest_dir),
                luciola_transfer::ReceiverConfig::default(),
                std::time::Duration::from_millis(500),
                cancel_rx,
                |p| {
                    if let Some(ref cb) = tsfn {
                        cb.call(
                            to_js_progress(p),
                            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok(to_js_receipt(receipt))
        },
        |_env, receipt| Ok(receipt),
    )
}

/// Send one file over an established [`WanChannel`] (consumes the channel).
#[napi(ts_return_type = "Promise<JsTransferReceipt>")]
pub fn transfer_send_wan(
    env: Env,
    channel: &WanChannel,
    file_path: String,
    max_relay_bytes: Option<f64>,
    #[napi(ts_arg_type = "((progress: JsTransferProgress) => void) | undefined | null")]
    on_progress: Option<JsFunction>,
    cancel: Option<&TransferCancelHandle>,
) -> Result<napi::JsObject> {
    let tsfn = on_progress.map(build_progress_tsfn).transpose()?;
    let cancel_rx = cancel
        .map(|h| h.subscribe())
        .unwrap_or_else(|| tokio::sync::watch::channel(false).1);

    let cfg_res: Result<luciola_transfer::SenderConfig> = (|| {
        let mut cfg = luciola_transfer::SenderConfig::default();
        if let Some(limit) = max_relay_bytes {
            if !limit.is_finite()
                || limit < 0.0
                || limit.fract() != 0.0
                || limit > 9_007_199_254_740_991.0
            {
                return Err(Error::new(
                    napi::Status::InvalidArg,
                    "maxRelayBytes must be a non-negative safe integer",
                ));
            }
            cfg.relay_max_bytes = Some(limit as u64);
        }
        Ok(cfg)
    })();

    let stream_res = if cfg_res.is_ok() {
        Some(channel.take_stream().and_then(|opt| {
            opt.ok_or_else(|| Error::from_reason("WanChannel already consumed or shut down"))
        }))
    } else {
        None
    };

    env.execute_tokio_future(
        async move {
            let cfg = cfg_res?;
            let stream = stream_res.expect("stream taken when cfg_res is Ok")?;
            let receipt = luciola::transfer_driver::send_file_over_stream(
                stream,
                std::path::Path::new(&file_path),
                None,
                None,
                cfg,
                cancel_rx,
                |p| {
                    if let Some(ref cb) = tsfn {
                        cb.call(
                            to_js_progress(p),
                            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok(to_js_receipt(receipt))
        },
        |_env, receipt| Ok(receipt),
    )
}

/// Receive one file over an established [`WanChannel`] (consumes the channel).
#[napi(ts_return_type = "Promise<JsTransferReceipt>")]
pub fn transfer_recv_wan(
    env: Env,
    channel: &WanChannel,
    dest_dir: String,
    #[napi(ts_arg_type = "((progress: JsTransferProgress) => void) | undefined | null")]
    on_progress: Option<JsFunction>,
    cancel: Option<&TransferCancelHandle>,
) -> Result<napi::JsObject> {
    let tsfn = on_progress.map(build_progress_tsfn).transpose()?;
    let cancel_rx = cancel
        .map(|h| h.subscribe())
        .unwrap_or_else(|| tokio::sync::watch::channel(false).1);
    let stream_res = channel.take_stream().and_then(|opt| {
        opt.ok_or_else(|| Error::from_reason("WanChannel already consumed or shut down"))
    });

    env.execute_tokio_future(
        async move {
            let stream = stream_res?;
            let receipt = luciola::transfer_driver::recv_file_over_stream(
                stream,
                std::path::Path::new(&dest_dir),
                luciola_transfer::ReceiverConfig::default(),
                std::time::Duration::from_millis(500),
                cancel_rx,
                |p| {
                    if let Some(ref cb) = tsfn {
                        cb.call(
                            to_js_progress(p),
                            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok(to_js_receipt(receipt))
        },
        |_env, receipt| Ok(receipt),
    )
}

/// Multiplexed TCP/UDP port-forwarding session running over one [`WanChannel`].
#[napi]
pub struct WanTunnelSession {
    inner: std::sync::Mutex<Option<std::sync::Arc<luciola_tunnel::DirectTunnelSession>>>,
}

#[napi]
impl WanTunnelSession {
    /// Consume `channel` and start a direct mux tunnel session inside the Tokio runtime.
    #[napi(factory)]
    pub async fn from_wan_channel(channel: &WanChannel, is_initiator: bool) -> Result<Self> {
        let stream = channel
            .take_stream()?
            .ok_or_else(|| Error::from_reason("WanChannel already consumed or shut down"))?;
        let role = if is_initiator {
            luciola_tunnel::Role::Initiator
        } else {
            luciola_tunnel::Role::Responder
        };
        let session = std::sync::Arc::new(luciola_tunnel::DirectTunnelSession::start(
            stream,
            role,
            luciola_tunnel::MuxConfig::default(),
        ));
        Ok(Self {
            inner: std::sync::Mutex::new(Some(session)),
        })
    }

    #[napi]
    pub async fn start_local_forward(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<u16> {
        let target = luciola_tunnel::DialTarget::new(&host, port);
        if !target.validate() {
            return Err(Error::from_reason(format!(
                "invalid forward target: {host}:{port}"
            )));
        }
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .clone()
            .ok_or_else(|| Error::from_reason("WanTunnelSession has been shut down"))?;
        session
            .start_local_forward(listen_port, target)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn stop_local_forward(&self, listen_port: u16) -> Result<bool> {
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .clone();
        match session {
            Some(s) => Ok(s.stop_local_forward(listen_port).await),
            None => Ok(false),
        }
    }

    #[napi]
    pub async fn start_udp_forward(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<u16> {
        let target = luciola_tunnel::DialTarget::new(&host, port);
        if !target.validate() {
            return Err(Error::from_reason(format!(
                "invalid forward target: {host}:{port}"
            )));
        }
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .clone()
            .ok_or_else(|| Error::from_reason("WanTunnelSession has been shut down"))?;
        session
            .start_udp_forward(listen_port, target)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn stop_udp_forward(&self, listen_port: u16) -> Result<bool> {
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .clone();
        match session {
            Some(s) => Ok(s.stop_udp_forward(listen_port).await),
            None => Ok(false),
        }
    }

    #[napi]
    pub async fn enable_forward_endpoint(&self, rules: Vec<JsForwardRule>) -> Result<()> {
        let parsed = parse_rule_objs(rules).map_err(|e| Error::from_reason(e.to_string()))?;
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .clone()
            .ok_or_else(|| Error::from_reason("WanTunnelSession has been shut down"))?;
        session
            .enable_forward_endpoint(parsed)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn disable_forward_endpoint(&self) -> Result<()> {
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .clone();
        if let Some(s) = session {
            s.disable_forward_endpoint().await;
        }
        Ok(())
    }

    #[napi]
    pub fn is_alive(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.is_alive()))
            .unwrap_or(false)
    }

    #[napi]
    pub fn channel_type(&self) -> String {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.channel_type().as_str().to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[napi]
    pub fn stats(&self) -> Vec<JsForwardStatus> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(session) = guard.as_ref() else {
            return Vec::new();
        };
        session
            .stats()
            .into_iter()
            .map(|s| JsForwardStatus {
                active: s.active,
                listen_port: s.listen_port,
                channels_open: s.status.channels_open as i64,
                channels_total: s.status.channels_total as i64,
                dial_denied: s.status.dial_denied as i64,
                dial_failed: s.status.dial_failed as i64,
                kind: s.kind.as_str().to_string(),
            })
            .collect()
    }

    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        let session = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("WAN tunnel lock poisoned"))?
            .take();
        if let Some(s) = session {
            s.shutdown().await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Single-port multi-peer authenticated server (`SecureHub`)
// ---------------------------------------------------------------------------

/// Metadata for a peer currently connected to [`SecureHub`].
#[napi(object)]
pub struct JsHubPeerInfo {
    /// Verified `sha256:<hex>` fingerprint of the peer's Ed25519 identity key.
    pub fingerprint: String,
    /// Raw 32-byte Ed25519 public key of the peer.
    pub public_key: Buffer,
    /// Peer's TCP socket address (`ip:port`).
    pub remote_addr: String,
}

/// Lifecycle or message event delivered by [`SecureHub`].
#[napi(object)]
pub struct JsHubEvent {
    /// `'peer_connected' | 'message' | 'peer_disconnected' | 'peer_rejected'`
    #[napi(js_name = "type")]
    pub kind: String,
    /// Connected peer metadata (`'peer_connected'`).
    pub peer: Option<JsHubPeerInfo>,
    /// Peer fingerprint (`'peer_connected' | 'message' | 'peer_disconnected'`).
    pub fingerprint: Option<String>,
    /// Peer socket endpoint (`'peer_connected' | 'message' | 'peer_rejected'`).
    pub remote_addr: Option<String>,
    /// Decrypted payload (`'message'`).
    pub payload: Option<Buffer>,
    /// Rejection reason (`'peer_rejected'`).
    pub reason: Option<String>,
}

fn to_js_hub_event(ev: luciola::link::hub::HubEvent) -> JsHubEvent {
    match ev {
        luciola::link::hub::HubEvent::PeerConnected(info) => {
            let remote = info.remote_addr.to_string();
            let fp = info.fingerprint;
            JsHubEvent {
                kind: "peer_connected".to_string(),
                peer: Some(JsHubPeerInfo {
                    fingerprint: fp.clone(),
                    public_key: Buffer::from(info.public_key),
                    remote_addr: remote.clone(),
                }),
                fingerprint: Some(fp),
                remote_addr: Some(remote),
                payload: None,
                reason: None,
            }
        }
        luciola::link::hub::HubEvent::Message {
            fingerprint,
            remote_addr,
            payload,
        } => JsHubEvent {
            kind: "message".to_string(),
            peer: None,
            fingerprint: Some(fingerprint),
            remote_addr: Some(remote_addr.to_string()),
            payload: Some(Buffer::from(payload)),
            reason: None,
        },
        luciola::link::hub::HubEvent::PeerDisconnected { fingerprint } => JsHubEvent {
            kind: "peer_disconnected".to_string(),
            peer: None,
            fingerprint: Some(fingerprint),
            remote_addr: None,
            payload: None,
            reason: None,
        },
        luciola::link::hub::HubEvent::PeerRejected {
            remote_addr,
            reason,
        } => JsHubEvent {
            kind: "peer_rejected".to_string(),
            peer: None,
            fingerprint: None,
            remote_addr: Some(remote_addr.to_string()),
            payload: None,
            reason: Some(reason),
        },
    }
}

/// Concurrent multi-peer authenticated TCP server on a single dual-stack port.
///
/// Peer keys are checked against an explicit allowlist **before** the server signs
/// handshake message 2 (deny by default).
#[napi]
pub struct SecureHub {
    inner: std::sync::Mutex<Option<luciola::link::hub::SecureHub>>,
    local_addr: std::net::SocketAddr,
    allowlist: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
    stop_tx: std::sync::Mutex<tokio::sync::watch::Sender<bool>>,
}

#[napi]
impl SecureHub {
    /// Bind `port` (`0` = OS ephemeral) and start accepting concurrent peers.
    ///
    /// `allowedPeerPublicKeys` seeds the pre-sign allowlist (each entry must be 32 bytes;
    /// an empty array starts in deny-all mode until [`Self::add_allowed_peer`] is called).
    #[napi(factory)]
    pub async fn start(
        port: u16,
        identity_seed: Buffer,
        allowed_peer_public_keys: Vec<Buffer>,
        #[napi(ts_arg_type = "(event: JsHubEvent) => void")]
        on_event: napi::threadsafe_function::ThreadsafeFunction<
            JsHubEvent,
            napi::threadsafe_function::ErrorStrategy::Fatal,
        >,
    ) -> Result<Self> {
        let mut seed_vec = identity_seed.to_vec();
        let pk_vecs: Vec<Vec<u8>> = allowed_peer_public_keys
            .into_iter()
            .map(|b| b.to_vec())
            .collect();

        if let Err(err) = require_key(&seed_vec, "identitySeed") {
            zeroize::Zeroize::zeroize(&mut seed_vec);
            return Err(err);
        }
        let mut set = std::collections::HashSet::with_capacity(pk_vecs.len());
        for (idx, pk) in pk_vecs.iter().enumerate() {
            match require_key(pk, &format!("allowedPeerPublicKeys[{idx}]")) {
                Ok(arr) => {
                    set.insert(arr);
                }
                Err(err) => {
                    zeroize::Zeroize::zeroize(&mut seed_vec);
                    return Err(err);
                }
            }
        }
        let allowlist = std::sync::Arc::new(std::sync::RwLock::new(set));
        let allow_for_hub = allowlist.clone();
        let seed_for_hub = std::mem::take(&mut seed_vec);

        let (hub, mut event_rx) =
            luciola::link::hub::SecureHub::start(port, seed_for_hub, move |pk| {
                let Ok(arr): std::result::Result<[u8; 32], _> = pk.try_into() else {
                    return false;
                };
                allow_for_hub
                    .read()
                    .map(|peers| peers.contains(&arr))
                    .unwrap_or(false)
            })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let local_addr = hub.local_addr();
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let tsfn = on_event;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            while let Ok(Some(ev)) = tokio::time::timeout(
                                std::time::Duration::from_millis(50),
                                event_rx.recv(),
                            )
                            .await
                            {
                                tsfn.call(
                                    to_js_hub_event(ev),
                                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                                );
                            }
                            break;
                        }
                    }
                    maybe_ev = event_rx.recv() => {
                        match maybe_ev {
                            Some(ev) => {
                                tsfn.call(
                                    to_js_hub_event(ev),
                                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                                );
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            inner: std::sync::Mutex::new(Some(hub)),
            local_addr,
            allowlist,
            stop_tx: std::sync::Mutex::new(stop_tx),
        })
    }

    /// Actual listening TCP port (useful when started with `port === 0`).
    #[napi]
    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Actual listening socket address (`ip:port`).
    #[napi]
    pub fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    /// Add a 32-byte Ed25519 peer public key to the pre-sign allowlist.
    #[napi]
    pub fn add_allowed_peer(&self, public_key: Buffer) -> Result<bool> {
        let arr = require_key(&public_key, "publicKey")?;
        let mut guard = self
            .allowlist
            .write()
            .map_err(|_| Error::from_reason("hub allowlist lock poisoned"))?;
        Ok(guard.insert(arr))
    }

    /// Remove a 32-byte Ed25519 peer public key from the pre-sign allowlist.
    #[napi]
    pub fn remove_allowed_peer(&self, public_key: Buffer) -> Result<bool> {
        let arr = require_key(&public_key, "publicKey")?;
        let mut guard = self
            .allowlist
            .write()
            .map_err(|_| Error::from_reason("hub allowlist lock poisoned"))?;
        Ok(guard.remove(&arr))
    }

    /// Snapshot of currently connected peers.
    #[napi]
    pub fn connected_peers(&self) -> Vec<JsHubPeerInfo> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(ref hub) = *guard else {
            return Vec::new();
        };
        hub.connected_peers()
            .into_iter()
            .map(|p| JsHubPeerInfo {
                fingerprint: p.fingerprint,
                public_key: Buffer::from(p.public_key),
                remote_addr: p.remote_addr.to_string(),
            })
            .collect()
    }

    /// Queue an encrypted frame for one connected peer (`false` if disconnected or backpressured).
    #[napi]
    pub fn send_to(&self, fingerprint: String, payload: Buffer) -> bool {
        let Ok(guard) = self.inner.lock() else {
            return false;
        };
        guard
            .as_ref()
            .is_some_and(|hub| hub.send_to(&fingerprint, payload.to_vec()))
    }

    /// Broadcast an encrypted frame to every connected peer.
    /// Returns fingerprints whose outbound queue rejected the frame.
    #[napi]
    pub fn broadcast(&self, payload: Buffer) -> Vec<String> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        match guard.as_ref() {
            Some(hub) => hub.broadcast(&payload),
            None => Vec::new(),
        }
    }

    /// Disconnect one connected peer by fingerprint and emit `peer_disconnected`.
    #[napi]
    pub fn kick(&self, fingerprint: String) -> bool {
        let Ok(guard) = self.inner.lock() else {
            return false;
        };
        guard.as_ref().is_some_and(|hub| hub.kick(&fingerprint))
    }

    /// Stop accepting new peers, disconnect every active peer, and release the event callback.
    #[napi]
    pub fn stop(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(hub) = guard.take() {
                hub.stop();
            }
        }
        if let Ok(guard) = self.stop_tx.lock() {
            let _ = guard.send(true);
        }
    }
}

impl Drop for SecureHub {
    fn drop(&mut self) {
        self.stop();
    }
}
