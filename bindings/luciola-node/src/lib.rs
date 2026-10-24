#[macro_use]
extern crate napi_derive;

use luciola_ip::{is_lan_address as ip_is_lan, is_proxy_tun_address};
use luciola_net::{is_physical_interface_name, is_virtual_interface_name, NetworkDetector};

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
    }
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
}

use napi::bindgen_prelude::*;
use napi::threadsafe_function::{
    ErrorStrategy, ThreadSafeCallContext, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
use tokio::sync::oneshot;

/// Active P2P discovery session in Node.js.
///
/// Discovers other Luciola/downstream nodes across the local network and emits real-time events.
#[napi]
pub struct DiscoverySession {
    name: String,
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    node_id: std::sync::Mutex<Option<String>>,
}

#[napi]
impl DiscoverySession {
    #[napi(constructor)]
    pub fn new(name: Option<String>, port: Option<u32>) -> Self {
        Self {
            name: name.unwrap_or_else(|| "NodeJS Peer".to_string()),
            port: port.unwrap_or(17878) as u16,
            shutdown_tx: None,
            node_id: std::sync::Mutex::new(None),
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
        let tsfn: ThreadsafeFunction<JsPeerRecord, ErrorStrategy::Fatal> = callback
            .create_threadsafe_function(0, |ctx: ThreadSafeCallContext<JsPeerRecord>| {
                let mut obj = ctx.env.create_object()?;
                obj.set_named_property("nodeId", &ctx.value.node_id)?;
                obj.set_named_property("name", &ctx.value.name)?;
                obj.set_named_property("ip", &ctx.value.ip)?;
                obj.set_named_property("udpPort", ctx.value.udp_port)?;
                obj.set_named_property("tcpPort", ctx.value.tcp_port)?;
                if let Some(ref d) = ctx.value.device {
                    let mut dev = ctx.env.create_object()?;
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
                    obj.set_named_property("device", dev)?;
                }
                Ok(vec![obj])
            })?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let name = self.name.clone();
        let port = self.port;
        let node_id = format!("node_{:x}", rand::random::<u32>());
        *self.node_id.lock().unwrap() = Some(node_id.clone());

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
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
                    tcp_port: port + 1,
                    device: Some(luciola_net::DeviceDetector::detect()),
                };

                let mut config = luciola::DiscoveryConfig::default();
                config.self_profile = profile;
                config.listen_port = port;
                config.broadcast_port = port;

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
                                if let luciola::PeerEvent::Found(p) = event {
                                    let device = p.device.map(|d| JsDeviceMeta {
                                        device_type: d.device_type.as_str().to_string(),
                                        icon: d.device_type.icon().to_string(),
                                        os: d.os,
                                        arch: d.arch,
                                        model: d.model,
                                        hostname: d.hostname,
                                    });
                                    let record = JsPeerRecord {
                                        node_id: p.node_id,
                                        name: p.name,
                                        ip: p.ip,
                                        udp_port: p.udp_port as u32,
                                        tcp_port: p.tcp_port as u32,
                                        device,
                                    };
                                    tsfn.call(record, ThreadsafeFunctionCallMode::NonBlocking);
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
