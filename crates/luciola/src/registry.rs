//! 发现对端注册表：peer 表、offline 判定与无界增长防护。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::proto::Profile;

/// A discovered peer node record in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub node_id: String,
    pub name: String,
    pub profile_rev: u32,
    pub ip: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub online: bool,
    pub last_seen: Instant,
    pub device: Option<luciola_proto::DeviceMeta>,
    /// Stable per-device grouping id (display-grade).
    pub device_id: Option<String>,
    /// Product label running on the peer.
    pub product: Option<String>,
    /// Opaque application payload carried alongside discovery (mDNS-TXT style).
    pub extra: Option<String>,
    /// Ed25519 identity public key advertised by the peer (see `trust`).
    pub public_key: Option<Vec<u8>>,
}

/// Discovery events emitted by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Found(PeerRecord),
    Updated(PeerRecord),
    Lost(String),
}

/// Peer registry maintaining active network nodes.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    peers: HashMap<String, PeerRecord>,
}

/// 离线超过这个时长的表项会被彻底移除：peers 表只增不删会让长驻进程的
/// 内存随历史邻居数无界增长（sweep 只置 offline）。1 小时后同一 node_id
/// 几乎不可能原样回归，真回来了 presence 会重新插入。
const PEER_EVICT_AFTER: Duration = Duration::from_secs(3600);

/// How suitable an address is for dialling: lower is better.
///
/// IPv4 first, then global IPv6, then link-local (which needs a scope id and
/// only works on one link). Anything unparsable sorts last.
pub(crate) fn address_rank(ip: &str) -> u8 {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => 0,
        Ok(std::net::IpAddr::V6(v6)) => {
            let o = v6.octets();
            if (u16::from_be_bytes([o[0], o[1]]) & 0xffc0) == 0xfe80 {
                2
            } else {
                1
            }
        }
        Err(_) => 3,
    }
}

/// Whether a freshly seen address should replace the one already recorded.
///
/// Stable while the peer stays online, but a peer that comes back after a gap
/// may legitimately have moved networks, and an address of the same rank is
/// never swapped out — that is what caused mid-session flicker.
pub(crate) fn should_take_new_address(
    was_offline: bool,
    current_ip: &str,
    candidate: &str,
) -> bool {
    if was_offline || current_ip.is_empty() || current_ip == candidate {
        return true;
    }
    address_rank(candidate) < address_rank(current_ip)
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Update or register a peer upon packet reception.
    pub fn touch(
        &mut self,
        node_id: &str,
        ip: &str,
        udp_port: u16,
        profile: Option<&Profile>,
    ) -> (Option<PeerRecord>, bool) {
        let now = Instant::now();
        let _is_new = !self.peers.contains_key(node_id);

        if let Some(existing) = self.peers.get_mut(node_id) {
            let was_offline = !existing.online;
            existing.last_seen = now;
            existing.online = true;
            // Keep the best address we have seen while the peer stays online
            // instead of the newest one. Both families arrive continuously on a
            // multi-homed host (IPv4 subnet broadcast plus the ff02::1 group),
            // and last-write-wins made the record flicker between interfaces
            // mid-session — measured 1 run in 6 switching between
            // 10.233.138.167 and fe80::1027:fbf:772:d1f7, while any dial that
            // lands in that window gets the other family.
            //
            // A peer that reappears after a gap is allowed to move (it may have
            // changed networks), so an offline -> online transition always
            // takes the new address.
            let take_new_address = should_take_new_address(was_offline, &existing.ip, ip);
            if take_new_address {
                existing.ip = ip.to_string();
                existing.udp_port = udp_port;
            }

            if let Some(p) = profile {
                if p.profile_rev >= existing.profile_rev {
                    existing.name = p.name.clone();
                    existing.profile_rev = p.profile_rev;
                    existing.tcp_port = p.tcp_port;
                    existing.device = p.device.clone();
                    existing.device_id = p.device_id.clone();
                    existing.product = p.product.clone();
                    existing.extra = p.extra.clone();
                    existing.public_key = p.public_key.clone();
                }
            }

            let record = existing.clone();
            (Some(record), was_offline)
        } else if let Some(p) = profile {
            let record = PeerRecord {
                node_id: node_id.to_string(),
                name: p.name.clone(),
                profile_rev: p.profile_rev,
                ip: ip.to_string(),
                udp_port,
                tcp_port: p.tcp_port,
                online: true,
                last_seen: now,
                device: p.device.clone(),
                device_id: p.device_id.clone(),
                product: p.product.clone(),
                extra: p.extra.clone(),
                public_key: p.public_key.clone(),
            };
            self.peers.insert(node_id.to_string(), record.clone());
            (Some(record), true)
        } else {
            (None, false)
        }
    }

    /// Mark peer offline immediately (e.g. on receiving `exit`).
    pub fn mark_offline(&mut self, node_id: &str) -> Option<PeerRecord> {
        if let Some(peer) = self.peers.get_mut(node_id) {
            if peer.online {
                peer.online = false;
                return Some(peer.clone());
            }
        }
        None
    }

    /// Sweep peers that haven't sent a presence heartbeat within `offline_after`,
    /// and evict entries whose peer has been gone for longer than
    /// [`PEER_EVICT_AFTER`] (the table would otherwise grow without bound for
    /// the lifetime of a long-running engine). Eviction never fires while a
    /// peer is still within the offline window: the threshold is clamped to
    /// at least twice `offline_after`.
    pub fn sweep(&mut self, offline_after: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut offline_ids = Vec::new();
        for (id, peer) in self.peers.iter_mut() {
            if peer.online && now.duration_since(peer.last_seen) > offline_after {
                peer.online = false;
                offline_ids.push(id.clone());
            }
        }
        let evict_after = PEER_EVICT_AFTER.max(offline_after.saturating_mul(2));
        let evicted: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > evict_after)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &evicted {
            tracing::debug!("evicting peer {id} from the registry (gone > {evict_after:?})");
            self.peers.remove(id);
        }
        offline_ids
    }

    pub fn online_peers(&self) -> Vec<PeerRecord> {
        self.peers.values().filter(|p| p.online).cloned().collect()
    }

    pub fn profile_rev_of(&self, node_id: &str) -> Option<u32> {
        self.peers.get(node_id).map(|p| p.profile_rev)
    }

    /// Product label last advertised by this peer (for the product allow-list).
    pub fn product_of(&self, node_id: &str) -> Option<String> {
        self.peers.get(node_id).and_then(|p| p.product.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::PeerRegistry;
    use super::{address_rank, should_take_new_address};
    use crate::proto::Profile;
    use std::time::{Duration, Instant};

    fn minimal_profile(node_id: &str) -> Profile {
        Profile {
            node_id: node_id.to_string(),
            name: node_id.to_string(),
            profile_rev: 1,
            addresses: vec![],
            udp_port: 1,
            tcp_port: 1,
            device: None,
            device_id: None,
            product: None,
            extra: None,
            public_key: None,
        }
    }

    #[test]
    fn sweep_evicts_entries_gone_longer_than_the_eviction_ttl() {
        let mut reg = PeerRegistry::new();
        reg.touch("gone", "10.0.0.1", 1, Some(&minimal_profile("gone")));
        reg.touch("fresh", "10.0.0.2", 1, Some(&minimal_profile("fresh")));
        // "gone" 在 2 小时前最后一次心跳：先被判 offline，随后被逐出。
        let cutoff = Instant::now() - Duration::from_secs(2 * 3600);
        reg.peers.get_mut("gone").unwrap().last_seen = cutoff;
        let offline = reg.sweep(Duration::from_secs(90));
        assert_eq!(offline, vec!["gone".to_string()]);
        assert!(reg.peers.contains_key("fresh"), "live peer must survive");
        assert!(
            !reg.peers.contains_key("gone"),
            "stale entry must be evicted"
        );
    }

    #[test]
    fn sweep_never_evicts_inside_the_offline_window_even_when_it_is_huge() {
        let mut reg = PeerRegistry::new();
        reg.touch("slow", "10.0.0.3", 1, Some(&minimal_profile("slow")));
        let cutoff = Instant::now() - Duration::from_secs(2 * 3600);
        reg.peers.get_mut("slow").unwrap().last_seen = cutoff;
        // offline_after = 3h：2h 未心跳仍算在线，逐出阈值被钳到 ≥ 2×offline_after，
        // 该表项必须原样保留。
        let offline = reg.sweep(Duration::from_secs(3 * 3600));
        assert!(offline.is_empty());
        assert!(reg.peers.contains_key("slow"));
    }

    #[test]
    fn address_rank_orders_v4_before_global_v6_before_link_local() {
        assert!(address_rank("192.168.2.82") < address_rank("2408:8248:2020::1"));
        assert!(address_rank("2408:8248:2020::1") < address_rank("fe80::1027:fbf:772:d1f7"));
        assert!(address_rank("fe80::1") < address_rank("not-an-address"));
    }

    #[test]
    fn a_live_peer_keeps_its_address_instead_of_flapping() {
        // The measured failure: the record switched from an IPv4 address to a
        // link-local one mid-session and back.
        assert!(!should_take_new_address(
            false,
            "10.233.138.167",
            "fe80::1027:fbf:772:d1f7"
        ));
        assert!(!should_take_new_address(
            false,
            "192.168.2.82",
            "10.233.138.167"
        ));
    }

    #[test]
    fn a_better_address_still_wins_while_online() {
        assert!(should_take_new_address(false, "fe80::1", "192.168.2.82"));
    }

    #[test]
    fn a_peer_that_returns_after_a_gap_may_have_moved() {
        assert!(should_take_new_address(true, "192.168.2.82", "10.9.9.9"));
        assert!(should_take_new_address(false, "", "fe80::1"));
        // Same address: refresh the ports without touching the address.
        assert!(should_take_new_address(
            false,
            "192.168.2.82",
            "192.168.2.82"
        ));
    }
}
