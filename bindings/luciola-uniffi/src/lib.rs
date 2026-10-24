uniffi::setup_scaffolding!();

use luciola_ip::{is_lan_address as ip_is_lan, is_proxy_tun_address};
use luciola_net::{is_physical_interface_name, is_virtual_interface_name, NetworkDetector};
use qrcode::render::unicode;
use qrcode::QrCode;

/// A discovered peer node in the local network.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub node_id: String,
    pub name: String,
    pub ip: String,
    pub udp_port: u16,
    pub tcp_port: u16,
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
#[uniffi::export]
pub fn render_qr_ascii(content: String) -> Option<String> {
    let code = QrCode::new(content.as_bytes()).ok()?;
    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build();
    Some(string)
}
