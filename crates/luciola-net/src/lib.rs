//! # luciola-net
//!
//! System network interface intelligence:
//! - Physical vs virtual network interface detection and scoring
//! - Subnet Broadcast calculation (anti-TUN interception)
//! - WSL2 host physical IP resolution
//! - Dual-pool candidate address selection (LAN vs Advertised)

use std::net::Ipv4Addr;
use luciola_ip::{get_ipv6_scope, is_private_or_local, is_proxy_tun_address, Ipv6Scope};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("failed to query system network interfaces: {0}")]
    QueryFailed(String),
}

/// Check if interface name corresponds to a virtual, tunnel, or emulator interface.
///
/// Filters out:
/// - macOS / Linux utun / tun / tap / feth
/// - Tailscale / ZeroTier / EasyTier / WireGuard
/// - Docker / veth / bridge
/// - VMware / VirtualBox / WSL virtual adapters
/// - Windows Internet Connection Sharing (ICS) mobile hotspot (`本地连接*`)
pub fn is_virtual_interface_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();

    // Windows ICS / hotspot virtual adapter: e.g. "本地连接* 12"
    if lower.starts_with("本地连接*") || lower.contains("wifidirect") || lower.contains("hostednetwork") {
        return true;
    }

    let virtual_patterns = [
        "utun", "tun", "tap", "feth", "tailscale", "zerotier", "easytier", "et_",
        "docker", "veth", "virbr", "radmin", "vmware", "virtualbox", "vbox",
        "wsl", "teredo", "hamachi", "bluetooth", "bridge",
    ];

    virtual_patterns.iter().any(|&pattern| lower.contains(pattern))
}

/// Check if interface name looks like a real physical network interface
/// (Wi-Fi, Ethernet, WLAN).
pub fn is_physical_interface_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_virtual_interface_name(name) {
        return false;
    }

    let physical_prefixes = [
        "wlan", "wi-fi", "wifi", "wireless", "ethernet", "eth", "en", "wlp",
        "以太网", "有线", "无线",
    ];

    if lower.starts_with("本地连接") && !lower.starts_with("本地连接*") {
        return true;
    }

    physical_prefixes.iter().any(|&prefix| lower.starts_with(prefix))
}

/// Detect if the current environment is running inside Windows Subsystem for Linux (WSL).
pub fn detect_wsl() -> bool {
    // 1. Check WSL environment variables
    if std::env::var("WSL_DISTRO_NAME").is_ok() || std::env::var("WSL_INTEROP").is_ok() {
        return true;
    }

    // 2. Inspect /proc/version if on Linux
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let v_lower = version.to_ascii_lowercase();
        if v_lower.contains("microsoft") || v_lower.contains("wsl") {
            return true;
        }
    }

    false
}

/// Calculate the subnet broadcast address for an IPv4 address and netmask.
///
/// Skips:
/// - /31 and /32 point-to-point subnets where broadcast equals the address
/// - Subnets where calculated broadcast equals the address itself
pub fn calculate_subnet_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Option<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(netmask);

    // /31 (255.255.255.254) and /32 (255.255.255.255)
    if mask_u32 >= 0xFFFF_FFFE {
        return None;
    }

    let broadcast_u32 = ip_u32 | (!mask_u32);
    let broadcast_ip = Ipv4Addr::from(broadcast_u32);

    if broadcast_ip == ip || broadcast_ip.is_loopback() {
        return None;
    }

    Some(broadcast_ip)
}

/// Scored candidate address for local peering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredAddress {
    pub ip: String,
    pub interface_name: String,
    pub score: i32,
    pub is_ipv6: bool,
}

/// Inspect and retrieve system network interfaces with Luciola intelligence.
pub struct NetworkDetector;

impl NetworkDetector {
    /// Retrieve all network interfaces from system.
    pub fn get_interfaces() -> Result<Vec<NetworkInterface>, NetError> {
        NetworkInterface::show().map_err(|e| NetError::QueryFailed(e.to_string()))
    }

    /// Calculate targeted subnet broadcast addresses for all physical and virtual interfaces.
    ///
    /// ## Why this defeats proxy TUN mode:
    ///
    /// When proxy tools (Clash, Sing-box) enable TUN mode, they install `0.0.0.0/1` and `128.0.0.0/1`
    /// routes. The limited broadcast `255.255.255.255` has no specific route entry, falling into
    /// the default route (captured by the TUN proxy, dropping all LAN broadcasts).
    ///
    /// In contrast, `192.168.2.255` matches the direct `/24` connected route (prefix length 24 is
    /// much more specific than `/1`), forcing the OS kernel to route packets directly out of the
    /// physical Wi-Fi/Ethernet NIC.
    pub fn subnet_broadcast_addresses() -> Vec<String> {
        let mut broadcasts = Vec::new();
        let interfaces = match Self::get_interfaces() {
            Ok(itfs) => itfs,
            Err(_) => return broadcasts,
        };

        for itf in interfaces {
            for addr in itf.addr {
                if let Addr::V4(v4) = addr {
                    let ip = v4.ip;
                    if ip.is_loopback() || is_proxy_tun_address(&ip.to_string()) {
                        continue;
                    }

                    // Prefer existing broadcast if given by OS, otherwise calculate from netmask
                    let bcast = v4.broadcast.or_else(|| {
                        v4.netmask.and_then(|mask| calculate_subnet_broadcast(ip, mask))
                    });

                    if let Some(b) = bcast {
                        if !b.is_loopback() && b != ip && b != Ipv4Addr::new(255, 255, 255, 255) {
                            let s = b.to_string();
                            if !broadcasts.contains(&s) {
                                broadcasts.push(s);
                            }
                        }
                    }
                }
            }
        }

        broadcasts
    }

    /// Local candidate addresses:
    /// Prioritizes clean, physical LAN IPv4 addresses (sorted by score) and valid IPv6 (ULA & GUA).
    ///
    /// Filters out virtual/tunnel adapters (`utun`, `tailscale`) to avoid false LAN targets,
    /// falling back to virtual interfaces only if no physical IP is available.
    pub fn local_candidate_addresses() -> Vec<String> {
        let interfaces = match Self::get_interfaces() {
            Ok(itfs) => itfs,
            Err(_) => return Vec::new(),
        };

        let mut scored_v4: Vec<ScoredAddress> = Vec::new();
        let mut v6_addrs: Vec<String> = Vec::new();

        for itf in &interfaces {
            let is_virt = is_virtual_interface_name(&itf.name);
            let is_phys = is_physical_interface_name(&itf.name);

            for addr in &itf.addr {
                match addr {
                    Addr::V4(v4) => {
                        let ip = v4.ip;
                        let s = ip.to_string();
                        if ip.is_loopback() || ip.is_link_local() || is_proxy_tun_address(&s) {
                            continue;
                        }

                        let mut score = 0;
                        if is_private_or_local(&s) {
                            score += 100;
                        }
                        if is_phys {
                            score += 20;
                        } else if is_virt {
                            score -= 50;
                        }

                        // Demote Windows ICS mobile hotspot adapter (192.168.137.x)
                        if s.starts_with("192.168.137.") {
                            score -= 80;
                        }

                        scored_v4.push(ScoredAddress {
                            ip: s,
                            interface_name: itf.name.clone(),
                            score,
                            is_ipv6: false,
                        });
                    }
                    Addr::V6(v6) => {
                        let ip = v6.ip;
                        let s = ip.to_string();
                        // macOS JDK scope `%scope` stripping
                        let clean = s.split('%').next().unwrap_or(&s).trim();
                        if let Some(scope) = get_ipv6_scope(clean) {
                            if matches!(scope, Ipv6Scope::Global | Ipv6Scope::UniqueLocal) {
                                if !is_virt && !v6_addrs.contains(&clean.to_string()) {
                                    v6_addrs.push(clean.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort IPv4 by score desc
        scored_v4.sort_by(|a, b| b.score.cmp(&a.score));

        // Result: high-scoring IPv4 first, then IPv6 candidates
        let mut candidates: Vec<String> = scored_v4.into_iter().map(|a| a.ip).collect();
        candidates.extend(v6_addrs);
        candidates.dedup();
        candidates
    }

    /// Advertised addresses:
    /// All local addresses including VPN/tunnel interfaces (Tailscale, ZeroTier)
    /// for unicast state synchronization.
    pub fn advertised_addresses() -> Vec<String> {
        let interfaces = match Self::get_interfaces() {
            Ok(itfs) => itfs,
            Err(_) => return Vec::new(),
        };

        let mut addrs = Vec::new();
        for itf in interfaces {
            for addr in itf.addr {
                match addr {
                    Addr::V4(v4) => {
                        let s = v4.ip.to_string();
                        if !v4.ip.is_loopback() && !is_proxy_tun_address(&s) && !addrs.contains(&s) {
                            addrs.push(s);
                        }
                    }
                    Addr::V6(v6) => {
                        let s = v6.ip.to_string();
                        let clean = s.split('%').next().unwrap_or(&s).trim().to_string();
                        if let Some(scope) = get_ipv6_scope(&clean) {
                            if matches!(scope, Ipv6Scope::Global | Ipv6Scope::UniqueLocal) && !addrs.contains(&clean) {
                                addrs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_virtual_interface_name() {
        assert!(is_virtual_interface_name("utun5"));
        assert!(is_virtual_interface_name("feth2730"));
        assert!(is_virtual_interface_name("tailscale0"));
        assert!(is_virtual_interface_name("tun0"));
        assert!(is_virtual_interface_name("UTUN5"));
        assert!(is_virtual_interface_name("docker0"));
        assert!(is_virtual_interface_name("veth1234"));
        assert!(is_virtual_interface_name("本地连接* 12"));

        assert!(!is_virtual_interface_name("en0"));
        assert!(!is_virtual_interface_name("wlan0"));
        assert!(!is_virtual_interface_name("eth0"));
        assert!(!is_virtual_interface_name("本地连接"));
    }

    #[test]
    fn test_calculate_subnet_broadcast() {
        // Standard /24
        let ip = Ipv4Addr::new(192, 168, 2, 82);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert_eq!(
            calculate_subnet_broadcast(ip, mask),
            Some(Ipv4Addr::new(192, 168, 2, 255))
        );

        // /16
        let ip2 = Ipv4Addr::new(10, 20, 30, 40);
        let mask2 = Ipv4Addr::new(255, 255, 0, 0);
        assert_eq!(
            calculate_subnet_broadcast(ip2, mask2),
            Some(Ipv4Addr::new(10, 20, 255, 255))
        );

        // Point-to-point /32: no broadcast
        let p2p = Ipv4Addr::new(198, 18, 0, 1);
        let mask_32 = Ipv4Addr::new(255, 255, 255, 255);
        assert_eq!(calculate_subnet_broadcast(p2p, mask_32), None);
    }

    #[test]
    fn test_live_network_detector_runs_without_panic() {
        let broadcasts = NetworkDetector::subnet_broadcast_addresses();
        let local_candidates = NetworkDetector::local_candidate_addresses();
        let advertised = NetworkDetector::advertised_addresses();

        // Should return cleanly on any dev machine
        println!("Broadcasts: {:?}", broadcasts);
        println!("Candidates: {:?}", local_candidates);
        println!("Advertised: {:?}", advertised);
    }
}
