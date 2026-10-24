//! # luciola-ip
//!
//! Pure, zero-dependency algorithms for IP address taxonomy, RFC 4291/4193 IPv6 scoping,
//! domestic broadband GUA local prefix matching, and proxy TUN virtual IP detection.

use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv6 address scope classification according to RFC 4291 and RFC 4193.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv6Scope {
    /// 2000::/3 Global Unicast Address (GUA)
    Global,
    /// fc00::/7 Unique Local Address (ULA)
    UniqueLocal,
    /// fe80::/10 Link-Local Unicast Address
    LinkLocal,
    /// ::1 Loopback Address
    Loopback,
    /// Unspecified, multicast, IPv4-mapped, or reserved
    Other,
}

/// Strip enclosing square brackets, e.g. "[240e:...]" -> "240e:...".
pub fn unbracket(host: &str) -> &str {
    let trimmed = host.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
        &trimmed[1..trimmed.len() - 1].trim()
    } else {
        trimmed
    }
}

/// Wrap IPv6 in brackets if not already wrapped; leave IPv4 and hostnames intact.
pub fn bracket_if_ipv6(host: &str) -> String {
    let clean = host.trim();
    if clean.starts_with('[') && clean.ends_with(']') {
        return clean.to_string();
    }
    if is_ipv6(clean) {
        format!("[{clean}]")
    } else {
        clean.to_string()
    }
}

/// Strip scope id if present (e.g. "fe80::1%en0" -> "fe80::1").
pub fn strip_scope_id(host: &str) -> &str {
    let unbracketed = unbracket(host);
    match unbracketed.find('%') {
        Some(idx) => &unbracketed[..idx],
        None => unbracketed,
    }
}

/// Check if string is a valid IPv4 address.
pub fn is_ipv4(host: &str) -> bool {
    unbracket(host).trim().parse::<Ipv4Addr>().is_ok()
}

/// Check if string is a valid IPv6 address (strips optional brackets and scope id).
pub fn is_ipv6(host: &str) -> bool {
    let clean = strip_scope_id(host);
    clean.parse::<Ipv6Addr>().is_ok()
}

/// Parse IPv6 string to raw 16-byte array.
pub fn parse_ipv6_bytes(host: &str) -> Option<[u8; 16]> {
    let clean = strip_scope_id(host);
    clean.parse::<Ipv6Addr>().ok().map(|ip| ip.octets())
}

/// Classify IPv6 address scope.
pub fn get_ipv6_scope(host: &str) -> Option<Ipv6Scope> {
    let unbracketed = unbracket(host);
    if unbracketed.contains('%') {
        return Some(Ipv6Scope::LinkLocal);
    }
    let bytes = parse_ipv6_bytes(unbracketed)?;
    Some(classify_ipv6_bytes(&bytes))
}

fn classify_ipv6_bytes(bytes: &[u8; 16]) -> Ipv6Scope {
    // ::1 loopback
    if bytes[..15].iter().all(|&b| b == 0) && bytes[15] == 1 {
        return Ipv6Scope::Loopback;
    }

    let b0 = bytes[0];
    let b1 = bytes[1];

    // fe80::/10 (Link-Local): 1111 1110 10xx xxxx
    if b0 == 0xFE && (b1 & 0xC0) == 0x80 {
        return Ipv6Scope::LinkLocal;
    }

    // fc00::/7 (ULA): 1111 110x
    if (b0 & 0xFE) == 0xFC {
        return Ipv6Scope::UniqueLocal;
    }

    // 2000::/3 (GUA): 001x xxxx
    if (b0 & 0xE0) == 0x20 {
        return Ipv6Scope::Global;
    }

    Ipv6Scope::Other
}

/// Check if address is a public GUA IPv6 without local scope suffix.
pub fn is_public_gua_ipv6(host: &str) -> bool {
    let unbracketed = unbracket(host);
    if unbracketed.contains('%') {
        return false;
    }
    match get_ipv6_scope(unbracketed) {
        Some(Ipv6Scope::Global) => true,
        _ => false,
    }
}

/// Check if two IPv6 addresses share the same prefix (default 64 bits).
///
/// This handles domestic broadband ISPs issuing /64 subnets where multiple devices
/// have different host identifiers but belong to the exact same physical home LAN.
pub fn same_ipv6_prefix(a: &str, b: &str, prefix_bits: usize) -> bool {
    let bytes_a = match parse_ipv6_bytes(a) {
        Some(bytes) => bytes,
        None => return false,
    };
    let bytes_b = match parse_ipv6_bytes(b) {
        Some(bytes) => bytes,
        None => return false,
    };

    let full_bytes = prefix_bits / 8;
    for i in 0..full_bytes {
        if bytes_a[i] != bytes_b[i] {
            return false;
        }
    }

    let rem_bits = prefix_bits % 8;
    if rem_bits > 0 {
        let mask = (!0u8) << (8 - rem_bits);
        if (bytes_a[full_bytes] & mask) != (bytes_b[full_bytes] & mask) {
            return false;
        }
    }

    true
}

/// Check if two host strings refer to the same host (case-insensitive, bracket-insensitive,
/// and /64 prefix compatible for IPv6 privacy extensions).
pub fn is_same_host(a: &str, b: &str) -> bool {
    let clean_a = unbracket(a).trim();
    let clean_b = unbracket(b).trim();
    if clean_a.is_empty() || clean_b.is_empty() {
        return false;
    }
    if clean_a.eq_ignore_ascii_case(clean_b) {
        return true;
    }
    if is_ipv6(clean_a) && is_ipv6(clean_b) {
        return same_ipv6_prefix(clean_a, clean_b, 64);
    }
    false
}

/// Check whether the address is standard private or local-link (RFC1918 / Loopback / ULA / Link-Local).
pub fn is_private_or_local(host: &str) -> bool {
    let clean = unbracket(host).trim();
    if clean.is_empty() {
        return false;
    }
    if clean.contains('%') {
        return true;
    }

    if let Ok(ipv4) = clean.parse::<Ipv4Addr>() {
        let octets = ipv4.octets();
        let a = octets[0];
        let b = octets[1];
        return a == 127
            || a == 10
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 169 && b == 254);
    }

    if let Some(scope) = get_ipv6_scope(clean) {
        return matches!(
            scope,
            Ipv6Scope::Loopback | Ipv6Scope::LinkLocal | Ipv6Scope::UniqueLocal
        );
    }

    false
}

/// Check whether an address belongs to a proxy software TUN virtual network (RFC 2544 `198.18.0.0/15`).
///
/// When proxy tools (Clash, Sing-box) enable TUN mode, they assign a virtual address in `198.18.x.x`
/// and route `0.0.0.0/1` + `128.0.0.0/1`. Advertising this address to peers causes connection failure.
pub fn is_proxy_tun_address(host: &str) -> bool {
    let clean = unbracket(host).trim();
    if let Ok(ipv4) = clean.parse::<Ipv4Addr>() {
        let octets = ipv4.octets();
        return octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
    }
    false
}

/// High-accuracy LAN peer determination.
///
/// Returns true if either:
/// 1. The address is RFC private/local (`is_private_or_local`); OR
/// 2. The peer IPv6 address shares the same `/64` prefix with any of the local interface addresses.
///
/// This correctly recognizes Chinese broadband LANs issuing public GUA (e.g. `2408:8248:...::/64`)
/// as local LAN without exposing them to false WAN security drop.
pub fn is_lan_address(peer_address: &str, local_addresses: &[&str]) -> bool {
    if is_private_or_local(peer_address) {
        return true;
    }
    let peer = unbracket(peer_address).trim();
    if !is_ipv6(peer) {
        return false;
    }

    local_addresses.iter().any(|&local| {
        let local_clean = unbracket(local).trim();
        is_ipv6(local_clean) && same_ipv6_prefix(peer, local_clean, 64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unbracket_and_bracket() {
        assert_eq!(unbracket("[240e:1234::1]"), "240e:1234::1");
        assert_eq!(unbracket("192.168.1.1"), "192.168.1.1");
        assert_eq!(bracket_if_ipv6("240e:1234::1"), "[240e:1234::1]");
        assert_eq!(bracket_if_ipv6("[240e:1234::1]"), "[240e:1234::1]");
        assert_eq!(bracket_if_ipv6("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn test_ipv6_scope_classification() {
        assert_eq!(get_ipv6_scope("::1"), Some(Ipv6Scope::Loopback));
        assert_eq!(get_ipv6_scope("fe80::1"), Some(Ipv6Scope::LinkLocal));
        assert_eq!(get_ipv6_scope("fe80::1%en0"), Some(Ipv6Scope::LinkLocal));
        assert_eq!(get_ipv6_scope("fc00::1"), Some(Ipv6Scope::UniqueLocal));
        assert_eq!(get_ipv6_scope("fd12:3456::1"), Some(Ipv6Scope::UniqueLocal));
        assert_eq!(get_ipv6_scope("2408:8248::1"), Some(Ipv6Scope::Global));
        assert_eq!(get_ipv6_scope("2001:da8::1"), Some(Ipv6Scope::Global));
    }

    #[test]
    fn test_same_ipv6_prefix() {
        let a = "2408:8248:2020:cb44:1111:2222:3333:4444";
        let b = "2408:8248:2020:cb44:aaaa:bbbb:cccc:dddd";
        let c = "2408:8248:2020:cb45:aaaa:bbbb:cccc:dddd";
        assert!(same_ipv6_prefix(a, b, 64));
        assert!(!same_ipv6_prefix(a, c, 64));
    }

    #[test]
    fn test_is_private_or_local() {
        assert!(is_private_or_local("127.0.0.1"));
        assert!(is_private_or_local("192.168.1.50"));
        assert!(is_private_or_local("10.0.0.1"));
        assert!(is_private_or_local("172.20.1.1"));
        assert!(is_private_or_local("169.254.1.1"));
        assert!(is_private_or_local("::1"));
        assert!(is_private_or_local("fe80::dead:beef"));
        assert!(is_private_or_local("fd00::1"));

        assert!(!is_private_or_local("8.8.8.8"));
        assert!(!is_private_or_local("1.1.1.1"));
        assert!(!is_private_or_local("2408:8248::1"));
    }

    #[test]
    fn test_is_proxy_tun_address() {
        assert!(is_proxy_tun_address("198.18.0.1"));
        assert!(is_proxy_tun_address("198.19.255.254"));
        assert!(!is_proxy_tun_address("198.20.0.1"));
        assert!(!is_proxy_tun_address("192.168.1.1"));
    }

    #[test]
    fn test_is_lan_address_with_broadband_gua() {
        let local_addrs = vec!["192.168.1.100", "2408:8248:2020:cb44:1:2:3:4"];
        // Private IPv4 peer
        assert!(is_lan_address("192.168.1.105", &local_addrs));
        // Peer in same IPv6 /64 prefix (Chinese domestic broadband LAN)
        assert!(is_lan_address(
            "2408:8248:2020:cb44:5:6:7:8",
            &local_addrs
        ));
        // Peer outside /64 prefix
        assert!(!is_lan_address(
            "2408:8248:2020:cb45:5:6:7:8",
            &local_addrs
        ));
        // Random public IPv4
        assert!(!is_lan_address("114.114.114.114", &local_addrs));
    }
}
