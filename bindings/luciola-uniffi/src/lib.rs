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

/// Device hardware and OS metadata.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DeviceMeta {
    pub device_type: DeviceType,
    pub icon: String,
    pub os: String,
    pub arch: String,
    pub model: Option<String>,
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
}

/// Detect the current machine's hardware profile, OS, architecture, and form factor.
#[uniffi::export]
pub fn get_device_meta() -> DeviceMeta {
    let meta = luciola_net::DeviceDetector::detect();
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

/// Callback invoked from a background engine thread whenever a new peer is discovered.
#[uniffi::export(callback_interface)]
pub trait OnPeerDiscovered: Send + Sync {
    fn on_peer_discovered(&self, peer: DiscoveredPeer);
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
    node_id: Mutex<String>,
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
    }
}

#[uniffi::export]
impl DiscoverySession {
    /// Create a session announcing `name` on the given UDP discovery port.
    #[uniffi::constructor]
    pub fn new(name: String, port: u16) -> Self {
        Self {
            name: Mutex::new(name),
            port: Mutex::new(port),
            node_id: Mutex::new(format!("uniffi_{:x}", rand::random::<u32>())),
            shutdown_tx: Mutex::new(None),
            listener: Mutex::new(None),
            last_activity: std::sync::Arc::new(Mutex::new(std::time::SystemTime::now())),
            bound: std::sync::Arc::new(Mutex::new(false)),
        }
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
                    let profile = luciola::proto::Profile {
                        node_id,
                        name,
                        profile_rev: 1,
                        addresses: NetworkDetector::local_candidate_addresses(),
                        udp_port: port,
                        tcp_port: port.wrapping_add(1),
                        device: Some(luciola_net::DeviceDetector::detect()),
                    };
                    let mut config = DiscoveryConfig::default();
                    config.self_profile = profile;
                    config.listen_port = port;
                    config.broadcast_port = port;

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
                        if let PeerEvent::Found(p) = event {
                            *last_activity.lock().unwrap() = std::time::SystemTime::now();
                            listener.on_peer_discovered(DiscoveredPeer {
                                node_id: p.node_id,
                                name: p.name,
                                ip: p.ip,
                                udp_port: p.udp_port,
                                tcp_port: p.tcp_port,
                                device: p.device.map(map_device_meta),
                            });
                        }
                    }
                });
            })
            .ok();
    }

}
