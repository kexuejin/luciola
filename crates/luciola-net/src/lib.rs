//! # luciola-net
//!
//! System network interface intelligence:
//! - Physical vs virtual network interface detection and scoring
//! - Subnet Broadcast calculation (anti-TUN interception)
//! - WSL2 host physical IP resolution
//! - Dual-pool candidate address selection (LAN vs Advertised)

use std::net::Ipv4Addr;
use luciola_ip::{get_ipv6_scope, is_private_or_local, is_proxy_tun_address, Ipv6Scope};
use luciola_proto::{DeviceMeta, DeviceType};
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
    if lower.contains("本地连接*") || lower.contains("wifidirect") || lower.contains("hostednetwork") {
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

/// Parse Windows `ipconfig.exe` text output to extract physical Wi-Fi/Ethernet IPv4 addresses.
///
/// Handles both English (`IPv4 Address. . . : 192.168.1.10`)
/// and Chinese (`IPv4 地址 . . . . . . . . . . . : 192.168.1.10`).
/// Automatically filters out virtual adapter blocks (vEthernet, WSL, Docker, VMware, VPN, `本地连接*`).
pub fn parse_ipconfig_output(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let mut current_block_is_virtual = false;

    for line in text.lines() {
        let trimmed = line.trim();
        // Interface header lines usually start at column 0 without leading spaces and end with ':'
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            current_block_is_virtual = is_virtual_interface_name(trimmed);
        }

        if !current_block_is_virtual && (trimmed.contains("IPv4") || trimmed.contains("IP Address")) {
            if let Some(idx) = trimmed.rfind(':') {
                let candidate_ip = trimmed[idx + 1..].trim();
                let clean_ip = candidate_ip.split_whitespace().next().unwrap_or(candidate_ip);
                if luciola_ip::is_ipv4(clean_ip) && !clean_ip.starts_with("127.") && !clean_ip.starts_with("169.254.") {
                    let s = clean_ip.to_string();
                    if !ips.contains(&s) {
                        ips.push(s);
                    }
                }
            }
        }
    }

    ips
}

/// In WSL2 environments, query the Windows host's physical Wi-Fi/Ethernet IP via `ipconfig.exe`.
pub fn resolve_wsl_host_ips() -> Vec<String> {
    if !detect_wsl() {
        return Vec::new();
    }

    if let Ok(output) = std::process::Command::new("ipconfig.exe").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            return parse_ipconfig_output(&text);
        }
    }

    Vec::new()
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

        // In WSL2, prepend the Windows host's physical Wi-Fi IP
        for host_ip in resolve_wsl_host_ips() {
            if !candidates.contains(&host_ip) {
                candidates.insert(0, host_ip);
            }
        }

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

/// Automatically inspect and classify the local machine's device hardware profile.
pub struct DeviceDetector;

impl DeviceDetector {
    /// Detect the current machine's device metadata:
    /// - form factor (Laptop, Desktop, Mobile, WSL, etc.)
    /// - operating system family (macOS, Windows, Linux, Android, iOS)
    /// - architecture (x86_64, aarch64, etc.)
    /// - hardware model (e.g. `MacBookPro18,1`)
    pub fn detect() -> DeviceMeta {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        if detect_wsl() {
            return DeviceMeta {
                device_type: DeviceType::Wsl,
                os: "Linux (WSL)".to_string(),
                arch,
                model: Some("WSL2 Virtual Machine".to_string()),
                hostname: Self::friendly_computer_name(),
                device_id: Some(Self::stable_device_id()),
            };
        }

        let (device_type, model) = match os.as_str() {
            "macos" => {
                let raw_model = Self::macos_model();
                let friendly_model = raw_model.as_deref().map(Self::humanize_macos_model);
                let dtype = if let Some(ref m) = raw_model {
                    if m.contains("MacBook") || m.starts_with("Mac14,2") || m.starts_with("Mac15,2") {
                        DeviceType::Laptop
                    } else if m.contains("Macmini") || m.contains("iMac") || m.contains("MacPro") || m.contains("MacStudio") || m.starts_with("Mac16,") {
                        DeviceType::Desktop
                    } else {
                        DeviceType::Desktop
                    }
                } else {
                    DeviceType::Desktop
                };
                (dtype, friendly_model)
            }
            "linux" => {
                let model = Self::linux_model();
                let dtype = Self::linux_device_type();
                (dtype, model)
            }
            "windows" => (DeviceType::Desktop, None),
            "android" => (DeviceType::Mobile, None),
            "ios" => (DeviceType::Mobile, None),
            _ => (DeviceType::Unknown, None),
        };

        let hostname = Self::friendly_computer_name();

        DeviceMeta {
            device_type,
            os,
            arch,
            model,
            hostname,
            device_id: Some(Self::stable_device_id()),
        }
    }

    /// Stable, per-device grouping id (FNV-1a over machine identity).
    ///
    /// Display-grade only: it lets remote UIs group multiple products on one
    /// physical device. It is NOT a security identity — trust decisions must
    /// use paired public keys (see `luciola::trust`).
    pub fn stable_device_id() -> String {
        let mut basis = String::new();
        if let Some(h) = Self::friendly_computer_name() {
            basis.push_str(&h);
        }
        basis.push('|');
        basis.push_str(std::env::consts::OS);
        basis.push('|');
        basis.push_str(std::env::consts::ARCH);
        if let Some(m) = Self::macos_model() {
            basis.push('|');
            basis.push_str(&m);
        }
        // FNV-1a 64-bit: tiny, dependency-free, stable across runs/versions.
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in basis.as_bytes() {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("dev_{hash:016x}")
    }

    /// Retrieve the friendly device nickname / computer name (e.g. "ke的Mac mini").
    pub fn friendly_computer_name() -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("scutil").arg("--get").arg("ComputerName").output() {
                if output.status.success() {
                    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("hostname").output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }

        std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty())
    }

    /// Map raw Apple Model Identifiers (e.g. `Mac16,11`, `MacBookPro18,1`) to friendly product names.
    fn humanize_macos_model(raw: &str) -> String {
        if raw.starts_with("MacBookPro") {
            "MacBook Pro".to_string()
        } else if raw.starts_with("MacBookAir") || raw.starts_with("Mac14,2") || raw.starts_with("Mac15,2") {
            "MacBook Air".to_string()
        } else if raw.starts_with("MacBook") {
            "MacBook".to_string()
        } else if raw.starts_with("Macmini") || raw == "Mac16,10" || raw == "Mac16,11" || raw == "Mac14,3" || raw == "Mac14,12" {
            "Mac mini".to_string()
        } else if raw.starts_with("iMac") || raw == "Mac15,4" || raw == "Mac15,5" {
            "iMac".to_string()
        } else if raw.starts_with("MacStudio") || raw == "Mac14,13" || raw == "Mac14,14" {
            "Mac Studio".to_string()
        } else if raw.starts_with("MacPro") || raw == "Mac14,8" {
            "Mac Pro".to_string()
        } else if raw.starts_with("Mac16,") {
            "Mac (M4)".to_string()
        } else if raw.starts_with("Mac15,") {
            "Mac (M3)".to_string()
        } else if raw.starts_with("Mac14,") {
            "Mac (M2)".to_string()
        } else {
            raw.to_string()
        }
    }

    /// Retrieve macOS hardware model via `sysctl -n hw.model`
    fn macos_model() -> Option<String> {
        let output = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.model")
            .output()
            .ok()?;
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
        None
    }

    /// Retrieve Linux hardware model from `/sys/class/dmi/id/product_name`
    fn linux_model() -> Option<String> {
        std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Infer Linux device form factor from chassis type
    fn linux_device_type() -> DeviceType {
        if let Ok(chassis) = std::fs::read_to_string("/sys/class/dmi/id/chassis_type") {
            if let Ok(code) = chassis.trim().parse::<u32>() {
                return match code {
                    8 | 9 | 10 | 11 | 14 | 30 | 31 | 32 => DeviceType::Laptop,
                    3 | 4 | 6 | 7 => DeviceType::Desktop,
                    23 | 28 | 29 => DeviceType::Server,
                    _ => DeviceType::Unknown,
                };
            }
        }
        DeviceType::Unknown
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
    fn test_parse_ipconfig_output_chinese_and_english() {
        let sample_output = r#"
Windows IP 配置

以太网适配器 vEthernet (WSL):
   连接特定的 DNS 后缀 . . . . . . . :
   IPv4 地址 . . . . . . . . . . . . : 172.26.112.1
   子网掩码  . . . . . . . . . . . . : 255.255.240.0

无线局域网适配器 WLAN:
   连接特定的 DNS 后缀 . . . . . . . : lan
   IPv4 地址 . . . . . . . . . . . . : 192.168.2.100 (首选项)
   子网掩码  . . . . . . . . . . . . : 255.255.255.0

未知适配器 本地连接* 12:
   IPv4 地址 . . . . . . . . . . . . : 192.168.137.1
"#;

        let parsed = parse_ipconfig_output(sample_output);
        assert_eq!(parsed, vec!["192.168.2.100"]);
    }

    #[test]
    fn test_device_detector_detects_current_machine() {
        let meta = DeviceDetector::detect();
        println!("Detected Device Meta: {:?}", meta);
        assert!(!meta.os.is_empty());
        assert!(!meta.arch.is_empty());
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
