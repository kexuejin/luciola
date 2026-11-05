//! Port-plan rules and preflight checks for hosts that run several luciola
//! products on one machine.
//!
//! A luciola port is a **product-level global constant**, not a per-process
//! value: discovery is one shared UDP mesh per port, and the secure channel is
//! a per-process TCP listener. Two products on one machine therefore either
//! keep different numbers (two meshes) or collide — and a collision used to be
//! silent (ephemeral fallback), which let both sides join one mesh and dial
//! each other's channel ports. The docs/PORTS.md document is the authority for
//! the actual allocations; this module is the executable part of it.
//!
//! Rules enforced here:
//! - two products must not claim the same (protocol, port) pair; a claim marked
//!   legacy only warns, so a known overlap can be migrated instead of blocking
//!   the whole fleet;
//! - inside one plan the same number may appear once per protocol (discovery
//!   UDP and channel TCP may share 17878), but twice in the same protocol is
//!   an error;
//! - probe() reports whether this machine currently has the ports open.
//!
//! New products take an unallocated 16-port block (the default BLOCK_SIZE);
//! the existing well-known numbers are grandfathered in the registry.

use serde::{Deserialize, Serialize};

/// Default size of a per-product port block.
pub const BLOCK_SIZE: u16 = 16;
/// Tunnel port derived from the secure-channel port (channel + 1).
pub const TUNNEL_OFFSET: u16 = 1;
/// Screen/secondary data-plane port derived from discovery (discovery + 10).
pub const SCREEN_OFFSET: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
        }
    }
}

/// One product's port allocation. A missing channel means the product has no
/// inbound secure listener (e.g. a dial-only helper).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortPlan {
    pub product: String,
    pub discovery_udp: u16,
    #[serde(default)]
    pub channel_tcp: Option<u16>,
    /// Additional TCP ports owned by this product (screen channel, desktop
    /// wire listener, ...).
    #[serde(default)]
    pub extra_tcp: Vec<u16>,
    /// TCP ports still bound by older releases. Overlaps involving a legacy
    /// claim are warnings: they are known and must be migrated, not papered
    /// over.
    #[serde(default)]
    pub legacy_tcp: Vec<u16>,
}

/// A single (protocol, port) claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortClaim {
    pub protocol: Protocol,
    pub port: u16,
    pub legacy: bool,
}

impl PortPlan {
    pub fn new(product: impl Into<String>, discovery_udp: u16, channel_tcp: Option<u16>) -> Self {
        Self {
            product: product.into(),
            discovery_udp,
            channel_tcp,
            extra_tcp: Vec::new(),
            legacy_tcp: Vec::new(),
        }
    }

    /// Tunnel port this plan implies (channel + 1), if it has a channel.
    pub fn tunnel_port(&self) -> Option<u16> {
        self.channel_tcp
            .map(|port| port.saturating_add(TUNNEL_OFFSET))
    }

    /// Secondary data-plane port derived from discovery (discovery + 10).
    pub fn screen_port(&self) -> u16 {
        self.discovery_udp.saturating_add(SCREEN_OFFSET)
    }

    /// Every claim this plan makes, in a stable order. Port 0 means "system
    /// assigned" and is never a claim.
    pub fn claims(&self) -> Vec<PortClaim> {
        let mut claims = Vec::new();
        if self.discovery_udp != 0 {
            claims.push(PortClaim {
                protocol: Protocol::Udp,
                port: self.discovery_udp,
                legacy: false,
            });
        }
        if let Some(channel) = self.channel_tcp.filter(|port| *port != 0) {
            claims.push(PortClaim {
                protocol: Protocol::Tcp,
                port: channel,
                legacy: false,
            });
        }
        for port in &self.extra_tcp {
            if *port != 0 {
                claims.push(PortClaim {
                    protocol: Protocol::Tcp,
                    port: *port,
                    legacy: false,
                });
            }
        }
        for port in &self.legacy_tcp {
            if *port != 0 {
                claims.push(PortClaim {
                    protocol: Protocol::Tcp,
                    port: *port,
                    legacy: true,
                });
            }
        }
        claims
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Blocks the plan: two live claims want the same socket.
    Error,
    /// Reported but does not fail: a legacy number that must be migrated.
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortConflict {
    pub severity: Severity,
    pub protocol: Protocol,
    pub port: u16,
    pub products: Vec<String>,
    pub message: String,
}

/// One machine-local probe result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProbe {
    pub product: String,
    pub protocol: Protocol,
    pub port: u16,
    pub in_use: bool,
}

/// Detect cross-product and intra-product port conflicts.
///
/// Two products claiming the same (protocol, port) is an error unless one of
/// the claims is legacy (then it is a warning with the migration hint). The
/// same number may appear once per protocol inside one plan (UDP discovery and
/// TCP channel are different namespaces) but not twice in the same protocol.
pub fn conflicts(plans: &[PortPlan]) -> Vec<PortConflict> {
    use std::collections::HashMap;

    let mut out = Vec::new();
    let mut groups: HashMap<(Protocol, u16), Vec<(String, bool)>> = HashMap::new();

    for plan in plans {
        let mut seen: Vec<(Protocol, u16)> = Vec::new();
        for claim in plan.claims() {
            if seen.contains(&(claim.protocol, claim.port)) {
                out.push(PortConflict {
                    severity: Severity::Error,
                    protocol: claim.protocol,
                    port: claim.port,
                    products: vec![plan.product.clone()],
                    message: format!(
                        "{} declares {} port {} more than once",
                        plan.product,
                        claim.protocol.as_str(),
                        claim.port
                    ),
                });
                continue;
            }
            seen.push((claim.protocol, claim.port));
            groups
                .entry((claim.protocol, claim.port))
                .or_default()
                .push((plan.product.clone(), claim.legacy));
        }
    }

    for ((protocol, port), mut claims) in groups {
        claims.sort_by(|a, b| a.0.cmp(&b.0));
        claims.dedup_by(|a, b| a.0 == b.0);
        if claims.len() < 2 {
            continue;
        }
        let legacy = claims.iter().any(|(_, is_legacy)| *is_legacy);
        let products: Vec<String> = claims.iter().map(|(product, _)| product.clone()).collect();
        out.push(PortConflict {
            severity: if legacy {
                Severity::Warning
            } else {
                Severity::Error
            },
            protocol,
            port,
            products: products.clone(),
            message: format!(
                "{} port {} is claimed by both {} ({})",
                protocol.as_str(),
                port,
                products.join(" and "),
                if legacy {
                    "known legacy overlap — drop the legacy number after migration"
                } else {
                    "both are live claims — move one product to its own block"
                }
            ),
        });
    }

    out.sort_by(|a, b| {
        (a.protocol.as_str(), a.port, a.severity.as_str()).cmp(&(
            b.protocol.as_str(),
            b.port,
            b.severity.as_str(),
        ))
    });
    out
}

/// Try to bind every claimed port on this machine. An occupied port is not a
/// conflict by itself (the owning process may simply be running); it tells the
/// host which plan is not reachable right now.
pub fn probe(plans: &[PortPlan]) -> Vec<PortProbe> {
    let mut seen: Vec<(Protocol, u16)> = Vec::new();
    let mut out = Vec::new();
    for plan in plans {
        for claim in plan.claims() {
            if seen.contains(&(claim.protocol, claim.port)) {
                continue;
            }
            seen.push((claim.protocol, claim.port));
            let in_use = match claim.protocol {
                Protocol::Udp => std::net::UdpSocket::bind(("0.0.0.0", claim.port)).is_err(),
                Protocol::Tcp => std::net::TcpListener::bind(("0.0.0.0", claim.port)).is_err(),
            };
            out.push(PortProbe {
                product: plan.product.clone(),
                protocol: claim.protocol,
                port: claim.port,
                in_use,
            });
        }
    }
    out
}

/// The machine-readable half of docs/PORTS.md: the single authority for the
/// fleet's allocations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortRegistry {
    pub version: u32,
    #[serde(default = "default_block_size")]
    pub block_size: u16,
    #[serde(default)]
    pub note: Option<String>,
    pub products: Vec<PortPlan>,
}

fn default_block_size() -> u16 {
    BLOCK_SIZE
}

/// Errors raised while loading or saving the port registry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortRegistryError {
    #[error("invalid port registry JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("registry version {0} is not supported (expected 1)")]
    UnsupportedVersion(u32),
}

impl PortRegistry {
    pub fn from_json(json: &str) -> Result<Self, PortRegistryError> {
        let registry: Self = serde_json::from_str(json)?;
        if registry.version != 1 {
            return Err(PortRegistryError::UnsupportedVersion(registry.version));
        }
        Ok(registry)
    }

    pub fn conflicts(&self) -> Vec<PortConflict> {
        conflicts(&self.products)
    }

    pub fn errors(&self) -> Vec<PortConflict> {
        self.conflicts()
            .into_iter()
            .filter(|c| c.severity == Severity::Error)
            .collect()
    }

    pub fn probe(&self) -> Vec<PortProbe> {
        probe(&self.products)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(product: &str, udp: u16, tcp: Option<u16>) -> PortPlan {
        PortPlan::new(product, udp, tcp)
    }

    #[test]
    fn two_live_products_on_the_same_tcp_port_is_an_error() {
        let mut a = plan("a", 18000, Some(18001));
        a.extra_tcp.push(18002);
        let b = plan("b", 18010, Some(18001));
        let found = conflicts(&[a, b]);
        let hit = found
            .iter()
            .find(|c| c.protocol == Protocol::Tcp && c.port == 18001)
            .expect("conflict on tcp/18001");
        assert_eq!(hit.severity, Severity::Error);
        assert_eq!(hit.products, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn a_legacy_overlap_only_warns() {
        let mut a = plan("a", 18000, Some(18001));
        a.legacy_tcp.push(18002);
        let b = plan("b", 18010, Some(18002));
        let found = conflicts(&[a, b]);
        let hit = found
            .iter()
            .find(|c| c.protocol == Protocol::Tcp && c.port == 18002)
            .expect("legacy conflict reported");
        assert_eq!(hit.severity, Severity::Warning);
    }

    #[test]
    fn udp_and_tcp_may_share_a_number_in_one_product() {
        // Discovery is UDP and the secure channel is TCP: 17878 on both is the
        // documented "same number, different protocol" layout.
        let found = conflicts(&[plan("a", 17878, Some(17878))]);
        assert!(found.is_empty(), "unexpected conflicts: {found:?}");
    }

    #[test]
    fn a_number_declared_twice_in_one_protocol_is_an_error() {
        let mut a = plan("a", 18000, Some(18001));
        a.extra_tcp.push(18001);
        let found = conflicts(&[a]);
        assert!(found.iter().any(|c| c.severity == Severity::Error
            && c.protocol == Protocol::Tcp
            && c.port == 18001));
    }

    #[test]
    fn zero_means_system_assigned_and_is_not_a_claim() {
        let claims = PortPlan::new("dial-only", 0, None).claims();
        assert!(claims.is_empty());
    }

    #[test]
    fn probe_reports_a_held_port_as_in_use() {
        // The probe binds the wildcard address, which is what a product
        // listener does; a loopback-only holder can coexist with that on some
        // platforms (macOS) and would make this test lie.
        let tcp_holder = std::net::TcpListener::bind("0.0.0.0:0").expect("tcp holder");
        let tcp_port = tcp_holder.local_addr().expect("addr").port();
        let udp_holder = std::net::UdpSocket::bind("0.0.0.0:0").expect("udp holder");
        let udp_port = udp_holder.local_addr().expect("addr").port();

        let probed = probe(&[PortPlan::new("a", udp_port, Some(tcp_port))]);
        assert!(
            probed
                .iter()
                .any(|p| p.protocol == Protocol::Tcp && p.port == tcp_port && p.in_use),
            "held tcp port must report in_use: {probed:?}"
        );
        assert!(
            probed
                .iter()
                .any(|p| p.protocol == Protocol::Udp && p.port == udp_port && p.in_use),
            "held udp port must report in_use: {probed:?}"
        );
    }

    #[test]
    fn registry_json_round_trip_and_version_check() {
        let json = r#"{
            "version": 1,
            "block_size": 16,
            "products": [
                {"product": "a", "discovery_udp": 18000, "channel_tcp": 18001},
                {"product": "b", "discovery_udp": 18010, "channel_tcp": 18011,
                 "extra_tcp": [18012], "legacy_tcp": [18001]}
            ]
        }"#;
        let registry = PortRegistry::from_json(json).expect("valid registry");
        assert_eq!(registry.products.len(), 2);
        assert!(
            registry.errors().is_empty(),
            "only a legacy warning expected"
        );
        assert!(registry
            .conflicts()
            .iter()
            .any(|c| c.severity == Severity::Warning && c.port == 18001));

        let bad = PortRegistry::from_json(r#"{"version": 9, "products": []}"#);
        assert!(matches!(bad, Err(PortRegistryError::UnsupportedVersion(9))));
    }
}
