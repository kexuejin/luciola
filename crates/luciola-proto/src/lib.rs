//! # luciola-proto
//!
//! Zero-IO protocol state machine for Luciola P2P discovery:
//! - Frame envelopes (`entry`, `alive`, `presence`, `exit`)
//! - Strict codec and payload parsing
//! - Jitter delay calculation (anti-broadcast storm)
//! - Alive reply deduplication window tracker
//! - The shared FFI error taxonomy ([`ErrorCode`], [`ErrorInfo`])

#![deny(missing_docs)]

/// The shared FFI error taxonomy.
pub mod error;
pub use error::{ErrorCode, ErrorInfo};

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors raised while encoding or decoding a wire envelope.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ProtoError {
    /// JSON serialisation or deserialisation failed.
    #[error("json serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The envelope was structurally invalid (missing or malformed fields).
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
}

/// Device form factor classification (used for UI icons and hardware context).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Phone.
    Mobile,
    /// Tablet.
    Tablet,
    /// Portable computer.
    Laptop,
    /// Desktop computer.
    Desktop,
    /// Headless server.
    Server,
    /// Windows Subsystem for Linux guest.
    Wsl,
    /// Form factor could not be determined.
    Unknown,
}

impl DeviceType {
    /// Emoji icon used by peer-list UIs.
    pub fn icon(&self) -> &'static str {
        match self {
            DeviceType::Mobile => "📱",
            DeviceType::Tablet => "📱",
            DeviceType::Laptop => "💻",
            DeviceType::Desktop => "🖥️",
            DeviceType::Server => "🗄️",
            DeviceType::Wsl => "🐧",
            DeviceType::Unknown => "🌐",
        }
    }

    /// Stable lowercase wire name (also the serde representation).
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Mobile => "mobile",
            DeviceType::Tablet => "tablet",
            DeviceType::Laptop => "laptop",
            DeviceType::Desktop => "desktop",
            DeviceType::Server => "server",
            DeviceType::Wsl => "wsl",
            DeviceType::Unknown => "unknown",
        }
    }
}

/// Lightweight device metadata broadcast to peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMeta {
    /// Form factor of the device.
    pub device_type: DeviceType,
    /// Operating-system name, e.g. `macOS` or `Android`.
    pub os: String,
    /// CPU architecture, e.g. `aarch64`.
    pub arch: String,
    /// Hardware model string, when the platform exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Human-readable host name, when the platform exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Stable per-device grouping id (display-grade, not a security identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// Node presence profile exchanged across the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable node identity for this session.
    pub node_id: String,
    /// Human-readable device name shown in peer lists.
    pub name: String,
    /// Monotonic revision; peers keep the highest revision they see.
    pub profile_rev: u32,
    /// Addresses the peer can be dialled on, best first.
    pub addresses: Vec<String>,
    /// UDP discovery port.
    pub udp_port: u16,
    /// Secure-channel TCP port advertised to peers.
    pub tcp_port: u16,
    /// Optional hardware metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceMeta>,
    /// Stable per-device grouping id (display-grade, not a security identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Product label, e.g. "luciola-clipboard" — lets remote UIs group
    /// multiple products running on the same physical device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Opaque application payload (mDNS-TXT style): the engine never parses
    /// it; hosts ride their own richer profile JSON here so a luciola
    /// discovery mesh can replace an app-specific discovery protocol
    /// without losing app fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
    /// Ed25519 identity public key (32 bytes, see `luciola::trust`).
    ///
    /// Optional with serde default + skip on None so v1 frames without the
    /// field keep decoding losslessly in BOTH directions (an old peer simply
    /// never sees the key on the wire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,
}

/// Message types in the Luciola discovery protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    /// Announcement broadcast when a node starts.
    Entry,
    /// Reply to a probe, carrying the full profile.
    Alive,
    /// Lightweight liveness update carrying a profile revision.
    Presence,
    /// Best-effort goodbye broadcast on shutdown.
    Exit,
}

impl MsgType {
    /// Lowercase wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            MsgType::Entry => "entry",
            MsgType::Alive => "alive",
            MsgType::Presence => "presence",
            MsgType::Exit => "exit",
        }
    }

    /// Parse a lowercase wire name; unknown names yield `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "entry" => Some(MsgType::Entry),
            "alive" => Some(MsgType::Alive),
            "presence" => Some(MsgType::Presence),
            "exit" => Some(MsgType::Exit),
            _ => None,
        }
    }
}

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Wire envelope carrying discovery datagrams.
///
/// `v` is optional on the wire for backward compatibility: frames from
/// pre-versioning nodes decode as [PROTOCOL_VERSION] (old serde structs also
/// ignore the unknown field, so both directions interop).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Wire protocol version; absent means the current version.
    #[serde(default = "current_version")]
    pub v: u32,
    /// Unique frame id (`<from>:<timestamp-ms>`).
    pub id: String,
    /// Message kind; see [`MsgType`].
    pub kind: String,
    /// Sender node id.
    pub from: String,
    /// Sender wall-clock timestamp in milliseconds since the Unix epoch.
    pub ts: u64,
    /// Message-type-specific JSON payload.
    pub payload: serde_json::Value,
}

fn current_version() -> u32 {
    PROTOCOL_VERSION
}

impl Envelope {
    /// Build an envelope stamped with the current time and protocol version.
    pub fn new(kind: MsgType, from: String, payload: serde_json::Value) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let id = format!("{}:{}", from, ts);
        Self {
            v: PROTOCOL_VERSION,
            id,
            kind: kind.as_str().to_string(),
            from,
            ts,
            payload,
        }
    }

    /// Parse [`Self::kind`] into a [`MsgType`].
    pub fn msg_type(&self) -> Option<MsgType> {
        MsgType::parse(&self.kind)
    }

    /// Decode the embedded [`Profile`] from an `entry` / `alive` payload.
    pub fn extract_profile(&self) -> Option<Profile> {
        let obj = self.payload.as_object()?;
        let profile_val = obj.get("profile")?;
        serde_json::from_value(profile_val.clone()).ok()
    }

    /// Read the `profileRev` field from a `presence` payload.
    pub fn extract_presence_rev(&self) -> Option<u32> {
        let obj = self.payload.as_object()?;
        let rev_val = obj.get("profileRev")?;
        rev_val.as_u64().map(|v| v as u32)
    }

    /// Read the optional `probeId` correlation id.
    pub fn extract_probe_id(&self) -> Option<String> {
        let obj = self.payload.as_object()?;
        let probe = obj.get("probeId")?;
        probe.as_str().map(|s| s.to_string())
    }
}

/// Codec for encoding and decoding protocol frames.
pub struct Codec;

impl Codec {
    /// Serialise an envelope to JSON bytes.
    pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, ProtoError> {
        serde_json::to_vec(envelope).map_err(ProtoError::Serialization)
    }

    /// Parse an envelope from JSON bytes.
    pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtoError> {
        serde_json::from_slice(bytes).map_err(ProtoError::Serialization)
    }

    /// Build an `entry` frame announcing `profile`.
    pub fn make_entry(profile: &Profile, probe_id: Option<&str>) -> Envelope {
        let mut map = serde_json::Map::new();
        map.insert(
            "profile".to_string(),
            serde_json::to_value(profile).unwrap_or_default(),
        );
        if let Some(probe) = probe_id {
            map.insert(
                "probeId".to_string(),
                serde_json::Value::String(probe.to_string()),
            );
        }
        Envelope::new(
            MsgType::Entry,
            profile.node_id.clone(),
            serde_json::Value::Object(map),
        )
    }

    /// Build an `alive` reply carrying `profile`.
    pub fn make_alive(profile: &Profile, probe_id: Option<&str>) -> Envelope {
        let mut map = serde_json::Map::new();
        map.insert(
            "profile".to_string(),
            serde_json::to_value(profile).unwrap_or_default(),
        );
        if let Some(probe) = probe_id {
            map.insert(
                "probeId".to_string(),
                serde_json::Value::String(probe.to_string()),
            );
        }
        Envelope::new(
            MsgType::Alive,
            profile.node_id.clone(),
            serde_json::Value::Object(map),
        )
    }

    /// Build a `presence` frame with a sequence number and profile revision.
    pub fn make_presence(node_id: &str, seq: u32, profile_rev: u32) -> Envelope {
        let mut map = serde_json::Map::new();
        map.insert("seq".to_string(), serde_json::Value::from(seq));
        map.insert(
            "profileRev".to_string(),
            serde_json::Value::from(profile_rev),
        );
        Envelope::new(
            MsgType::Presence,
            node_id.to_string(),
            serde_json::Value::Object(map),
        )
    }

    /// Build an `exit` frame for `node_id`.
    pub fn make_exit(node_id: &str) -> Envelope {
        Envelope::new(MsgType::Exit, node_id.to_string(), serde_json::json!({}))
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn legacy_frame_without_version_decodes_as_v1() {
        let legacy = r#"{"id":"a:1","kind":"presence","from":"a","ts":1,"payload":{}}"#;
        let env = Codec::decode(legacy.as_bytes()).expect("legacy decodes");
        assert_eq!(env.v, PROTOCOL_VERSION);
    }

    #[test]
    fn extra_payload_roundtrips_and_old_frames_absent() {
        let env = Envelope::new(
            MsgType::Entry,
            "host".into(),
            serde_json::json!({"profile": {"node_id":"n","name":"ke","profile_rev":2,"addresses":["192.168.1.5"],"udp_port":17878,"tcp_port":1}}),
        );
        let bytes = Codec::encode(&env).unwrap();
        let p = Codec::decode(&bytes).unwrap().extract_profile().unwrap();
        assert!(p.extra.is_none()); // legacy frame: absent stays absent

        let mut p2 = p.clone();
        let payload = r#"{"app":"demo","avatar":7}"#;
        p2.extra = Some(payload.to_string());
        let env2 = Envelope::new(
            MsgType::Alive,
            "host".into(),
            serde_json::json!({"profile": p2}),
        );
        let back = Codec::decode(&Codec::encode(&env2).unwrap()).unwrap();
        assert_eq!(
            back.extract_profile().unwrap().extra.as_deref(),
            Some(payload)
        );
    }

    #[test]
    fn versioned_frame_roundtrips() {
        let env = Envelope::new(MsgType::Entry, "n".into(), serde_json::json!({}));
        let bytes = Codec::encode(&env).unwrap();
        let back = Codec::decode(&bytes).unwrap();
        assert_eq!(back.v, PROTOCOL_VERSION);
        assert_eq!(back, env);
    }
}

/// Jitter calculator preventing broadcast reply storm when multiple nodes discover each other.
pub struct JitterScheduler {
    /// Base delay in milliseconds for an undirected reply.
    pub base_ms: u64,
    /// Upper bound of the jitter window, in milliseconds.
    pub max_ms: u64,
    /// Fixed delay in milliseconds for a directed (unicast) reply.
    pub directed_reply_ms: u64,
}

impl Default for JitterScheduler {
    fn default() -> Self {
        Self {
            base_ms: 200,
            max_ms: 1_200,
            directed_reply_ms: 50,
        }
    }
}

impl JitterScheduler {
    /// Calculate delay before sending an `alive` reply.
    pub fn calculate_delay(&self, online_count: usize, directed: bool) -> Duration {
        if directed {
            return Duration::from_millis(self.directed_reply_ms);
        }
        let window = (self.base_ms + (online_count as u64 / 100) * 1_000).min(self.max_ms);
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(0..=window.max(1));
        Duration::from_millis(jitter)
    }
}

/// Alive response deduplication tracker to prevent repeated replies within a short time window.
pub struct AliveDedupTracker {
    dedup_window: Duration,
    last_replies: HashMap<String, Instant>,
}

impl AliveDedupTracker {
    /// Create a tracker with the given deduplication window.
    pub fn new(dedup_window: Duration) -> Self {
        Self {
            dedup_window,
            last_replies: HashMap::new(),
        }
    }

    /// Check if we should reply to the given nodeId.
    /// Returns true if this is the first reply or if the dedup window has elapsed.
    pub fn should_reply(&mut self, node_id: &str, directed: bool) -> bool {
        if directed {
            return true;
        }
        let now = Instant::now();
        if let Some(&last_at) = self.last_replies.get(node_id) {
            if now.duration_since(last_at) < self.dedup_window {
                return false;
            }
        }
        self.last_replies.insert(node_id.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_encode_decode() {
        let profile = Profile {
            node_id: "node_abc123".to_string(),
            name: "MacBook Pro".to_string(),
            profile_rev: 1,
            addresses: vec!["192.168.1.10".to_string()],
            udp_port: 17878,
            tcp_port: 17879,
            extra: None,
            device: Some(DeviceMeta {
                device_type: DeviceType::Laptop,
                os: "macOS".to_string(),
                arch: "aarch64".to_string(),
                model: Some("MacBookPro18,1".to_string()),
                hostname: Some("Alex's Laptop".to_string()),
                device_id: Some("dev_123".to_string()),
            }),
            device_id: Some("dev_123".to_string()),
            product: Some("my-app".to_string()),
            public_key: None,
        };

        let env = Codec::make_entry(&profile, Some("probe_1"));
        let bytes = Codec::encode(&env).expect("must encode");
        let decoded = Codec::decode(&bytes).expect("must decode");

        assert_eq!(decoded.kind, "entry");
        assert_eq!(decoded.from, "node_abc123");
        assert_eq!(decoded.extract_probe_id(), Some("probe_1".to_string()));

        let recovered_profile = decoded.extract_profile().expect("must extract profile");
        assert_eq!(recovered_profile, profile);
    }

    #[test]
    fn test_dedup_tracker() {
        let mut tracker = AliveDedupTracker::new(Duration::from_millis(100));
        assert!(tracker.should_reply("node1", false));
        // Immediately calling again within 100ms should be rejected
        assert!(!tracker.should_reply("node1", false));
        // Directed reply is never rejected
        assert!(tracker.should_reply("node1", true));
    }

    /// Level-1 acceptance: a v1 discovery frame WITHOUT `public_key` (existing
    /// deployed peers) must keep decoding losslessly.
    #[test]
    fn legacy_v1_profile_without_public_key_decodes() {
        let legacy = serde_json::json!({
            "node_id": "node_old",
            "name": "Old Peer",
            "profile_rev": 1,
            "addresses": ["192.168.1.10"],
            "udp_port": 17878,
            "tcp_port": 17879,
        });
        let p: Profile = serde_json::from_value(legacy).expect("legacy profile decodes");
        assert!(p.public_key.is_none());
    }

    /// Level-1 acceptance: a profile carrying a 32-byte Ed25519 key must
    /// round-trip byte-exact through the codec.
    #[test]
    fn profile_with_public_key_roundtrips() {
        let key: Vec<u8> = (0..32).map(|i| (i * 7 + 3) as u8).collect();
        let mut p = Profile {
            node_id: "node_k".to_string(),
            name: "Keyed Peer".to_string(),
            profile_rev: 2,
            addresses: vec!["192.168.1.11".to_string()],
            udp_port: 17878,
            tcp_port: 17879,
            device: None,
            device_id: None,
            product: None,
            extra: None,
            public_key: Some(key.clone()),
        };
        let env = Codec::make_entry(&p, None);
        let back = Codec::decode(&Codec::encode(&env).unwrap())
            .unwrap()
            .extract_profile()
            .expect("extract");
        assert_eq!(back.public_key, Some(key));

        // Toggling back to None keeps the field off the wire.
        p.public_key = None;
        let env2 = Codec::make_alive(&p, None);
        let back2 = Codec::decode(&Codec::encode(&env2).unwrap())
            .unwrap()
            .extract_profile()
            .unwrap();
        assert!(back2.public_key.is_none());
    }

    /// Level-1 acceptance: `public_key: None` must be fully ABSENT from the
    /// serialized JSON (old peers must never see the key name at all).
    #[test]
    fn none_public_key_is_omitted_from_wire() {
        let p = Profile {
            node_id: "node_n".to_string(),
            name: "Bare Peer".to_string(),
            profile_rev: 1,
            addresses: vec![],
            udp_port: 1,
            tcp_port: 2,
            device: None,
            device_id: None,
            product: None,
            extra: None,
            public_key: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(!s.contains("public_key"), "wire JSON leaked key name: {s}");
    }
}
