//! # luciola-proto
//!
//! Zero-IO protocol state machine for Luciola P2P discovery:
//! - Frame envelopes (`entry`, `alive`, `presence`, `exit`)
//! - Strict codec and payload parsing
//! - Jitter delay calculation (anti-broadcast storm)
//! - Alive reply deduplication window tracker

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("json serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
}

/// Device form factor classification (used for UI icons and hardware context).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Mobile,
    Tablet,
    Laptop,
    Desktop,
    Server,
    Wsl,
    Unknown,
}

impl DeviceType {
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
    pub device_type: DeviceType,
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Node presence profile exchanged across the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub node_id: String,
    pub name: String,
    pub profile_rev: u32,
    pub addresses: Vec<String>,
    pub udp_port: u16,
    pub tcp_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceMeta>,
}

/// Message types in the Luciola discovery protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    Entry,
    Alive,
    Presence,
    Exit,
}

impl MsgType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MsgType::Entry => "entry",
            MsgType::Alive => "alive",
            MsgType::Presence => "presence",
            MsgType::Exit => "exit",
        }
    }

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

/// Wire envelope carrying discovery datagrams.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub ts: u64,
    pub payload: serde_json::Value,
}

impl Envelope {
    pub fn new(kind: MsgType, from: String, payload: serde_json::Value) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let id = format!("{}:{}", from, ts);
        Self {
            id,
            kind: kind.as_str().to_string(),
            from,
            ts,
            payload,
        }
    }

    pub fn msg_type(&self) -> Option<MsgType> {
        MsgType::parse(&self.kind)
    }

    pub fn extract_profile(&self) -> Option<Profile> {
        let obj = self.payload.as_object()?;
        let profile_val = obj.get("profile")?;
        serde_json::from_value(profile_val.clone()).ok()
    }

    pub fn extract_presence_rev(&self) -> Option<u32> {
        let obj = self.payload.as_object()?;
        let rev_val = obj.get("profileRev")?;
        rev_val.as_u64().map(|v| v as u32)
    }

    pub fn extract_probe_id(&self) -> Option<String> {
        let obj = self.payload.as_object()?;
        let probe = obj.get("probeId")?;
        probe.as_str().map(|s| s.to_string())
    }
}

/// Codec for encoding and decoding protocol frames.
pub struct Codec;

impl Codec {
    pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, ProtoError> {
        serde_json::to_vec(envelope).map_err(ProtoError::Serialization)
    }

    pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtoError> {
        serde_json::from_slice(bytes).map_err(ProtoError::Serialization)
    }

    pub fn make_entry(profile: &Profile, probe_id: Option<&str>) -> Envelope {
        let mut map = serde_json::Map::new();
        map.insert(
            "profile".to_string(),
            serde_json::to_value(profile).unwrap_or_default(),
        );
        if let Some(probe) = probe_id {
            map.insert("probeId".to_string(), serde_json::Value::String(probe.to_string()));
        }
        Envelope::new(MsgType::Entry, profile.node_id.clone(), serde_json::Value::Object(map))
    }

    pub fn make_alive(profile: &Profile, probe_id: Option<&str>) -> Envelope {
        let mut map = serde_json::Map::new();
        map.insert(
            "profile".to_string(),
            serde_json::to_value(profile).unwrap_or_default(),
        );
        if let Some(probe) = probe_id {
            map.insert("probeId".to_string(), serde_json::Value::String(probe.to_string()));
        }
        Envelope::new(MsgType::Alive, profile.node_id.clone(), serde_json::Value::Object(map))
    }

    pub fn make_presence(node_id: &str, seq: u32, profile_rev: u32) -> Envelope {
        let mut map = serde_json::Map::new();
        map.insert("seq".to_string(), serde_json::Value::from(seq));
        map.insert("profileRev".to_string(), serde_json::Value::from(profile_rev));
        Envelope::new(MsgType::Presence, node_id.to_string(), serde_json::Value::Object(map))
    }

    pub fn make_exit(node_id: &str) -> Envelope {
        Envelope::new(MsgType::Exit, node_id.to_string(), serde_json::json!({}))
    }
}

/// Jitter calculator preventing broadcast reply storm when multiple nodes discover each other.
pub struct JitterScheduler {
    pub base_ms: u64,
    pub max_ms: u64,
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
            device: Some(DeviceMeta {
                device_type: DeviceType::Laptop,
                os: "macOS".to_string(),
                arch: "aarch64".to_string(),
                model: Some("MacBookPro18,1".to_string()),
            }),
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
}
