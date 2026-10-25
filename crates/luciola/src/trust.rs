//! Trust & pairing primitives shared by every luciola product.
//!
//! Discovery is open by design (seeing a device on the LAN is not sensitive);
//! data planes are not. Products that push or accept content — clipboard sync,
//! file transfer — must default to trusted peers only. This module provides the
//! common building blocks so each product does not reinvent them:
//!
//! - [`DeviceIdentity`]: a per-device Ed25519 keypair. The public key IS the
//!   security identity (unlike the display-grade `device_id` on profiles).
//! - [`fingerprint`] / [`short_pin`]: human-comparable forms of a public key —
//!   the full fingerprint for QR payloads and logs, the 6-digit pin for
//!   on-screen numeric comparison during pairing.
//! - [`TrustStore`]: the persisted list of paired devices with a
//!   [`TrustLevel`]. `Full` = one's own devices (silent push allowed),
//!   `Partial` = visible, per-action confirmation required. Unpaired peers
//!   simply do not appear in the store — the default posture is deny.
//!
//! Persistence is the embedder's job: [`TrustStore`] serializes to JSON bytes
//! (`to_json`/`from_json`); store them wherever the product keeps secrets.
//! Signing/verification over the transport (handshakes, TLS-like link auth)
//! is deliberately NOT here — it belongs to the link layer that consumes
//! these primitives.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How much a paired device is allowed to do without per-action confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// One's own devices: silent/background push allowed.
    Full,
    /// Paired but not fully trusted: discovery + explicit per-action consent.
    Partial,
}

/// A paired device entry in the [`TrustStore`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// Display-grade grouping id of the peer device.
    pub device_id: String,
    /// Human-readable name at pairing time.
    pub name: String,
    /// Ed25519 public key (32 bytes) — the security identity.
    pub public_key: Vec<u8>,
    /// Cached `sha256:` fingerprint of [TrustedDevice::public_key].
    pub fingerprint: String,
    pub level: TrustLevel,
    /// When the device was pinned (epoch milliseconds).
    pub pinned_at_ms: u64,
}

/// In-memory trust list; serialize with `to_json` and persist in the
/// product's secret storage.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrustStore {
    devices: Vec<TrustedDevice>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pair (or re-pair) a device; replaces any previous entry for the same
    /// public key.
    pub fn trust_device(&mut self, device: TrustedDevice) {
        self.devices.retain(|d| d.public_key != device.public_key);
        self.devices.push(device);
    }

    /// Trust level for a public key, if paired.
    pub fn level_of(&self, public_key: &[u8]) -> Option<TrustLevel> {
        self.devices
            .iter()
            .find(|d| d.public_key == public_key)
            .map(|d| d.level)
    }

    /// Remove a paired device by fingerprint.
    pub fn remove(&mut self, fingerprint: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.fingerprint != fingerprint);
        before != self.devices.len()
    }

    pub fn entries(&self) -> &[TrustedDevice] {
        &self.devices
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

/// A freshly generated (or restored) device identity.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceIdentity {
    /// Ed25519 seed (32 bytes). Persist as a secret.
    pub seed: Vec<u8>,
    /// Ed25519 public key (32 bytes). This is the security identity.
    pub public_key: Vec<u8>,
    /// `sha256:<hex>` of the public key, for QR payloads and logs.
    pub fingerprint: String,
    /// 6-digit pin for on-screen numeric comparison while pairing.
    pub short_pin: String,
}

/// Generate a new device identity.
pub fn generate_identity() -> DeviceIdentity {
    identity_from_seed(&SigningKey::generate(&mut rand::thread_rng()).to_bytes())
}

/// Restore an identity from a persisted 32-byte seed.
pub fn identity_from_seed(seed: &[u8]) -> DeviceIdentity {
    let signing = SigningKey::from_bytes(seed.try_into().expect("seed must be 32 bytes"));
    let public_key = signing.verifying_key().as_bytes().to_vec();
    DeviceIdentity {
        seed: seed.to_vec(),
        public_key: public_key.clone(),
        fingerprint: fingerprint(&public_key),
        short_pin: short_pin(&public_key),
    }
}

/// `sha256:<hex>` fingerprint of an Ed25519 public key.
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    format!("sha256:{}", hex(&digest))
}

/// 6-digit comparison pin derived from the public key: both sides display it
/// during pairing; a mismatch means MITM.
pub fn short_pin(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

/// Sign a message with a persisted seed.
pub fn sign(seed: &[u8], message: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(seed.try_into().expect("seed must be 32 bytes"));
    signing.sign(message).to_bytes().to_vec()
}

/// Verify a signature against an Ed25519 public key.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key.try_into().expect("key must be 32 bytes"))
    else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip_and_signing() {
        let id = generate_identity();
        assert_eq!(id.seed.len(), 32);
        assert_eq!(id.public_key.len(), 32);
        assert!(id.fingerprint.starts_with("sha256:"));
        assert_eq!(id.short_pin.len(), 6);
        assert!(id.short_pin.chars().all(|c| c.is_ascii_digit()));

        // restore from seed reproduces the same identity
        let restored = identity_from_seed(&id.seed);
        assert_eq!(restored.public_key, id.public_key);
        assert_eq!(restored.fingerprint, id.fingerprint);

        let sig = sign(&id.seed, b"hello");
        assert!(verify(&id.public_key, b"hello", &sig));
        assert!(!verify(&id.public_key, b"tampered", &sig));

        let other = generate_identity();
        assert!(!verify(&other.public_key, b"hello", &sig));
    }

    #[test]
    fn trust_store_levels_and_roundtrip() {
        let mut store = TrustStore::new();
        let a = generate_identity();
        let b = generate_identity();
        assert_eq!(store.level_of(&a.public_key), None); // unpaired = deny

        store.trust_device(TrustedDevice {
            device_id: "dev_aaa".into(),
            name: "My MacBook".into(),
            public_key: a.public_key.clone(),
            fingerprint: a.fingerprint.clone(),
            level: TrustLevel::Full,
            pinned_at_ms: 42,
        });
        store.trust_device(TrustedDevice {
            device_id: "dev_bbb".into(),
            name: "Office printer kiosk".into(),
            public_key: b.public_key.clone(),
            fingerprint: b.fingerprint.clone(),
            level: TrustLevel::Partial,
            pinned_at_ms: 43,
        });
        assert_eq!(store.level_of(&a.public_key), Some(TrustLevel::Full));
        assert_eq!(store.level_of(&b.public_key), Some(TrustLevel::Partial));

        let json = store.to_json().unwrap();
        let restored = TrustStore::from_json(&json).unwrap();
        assert_eq!(restored, store);

        assert!(store.remove(&a.fingerprint));
        assert_eq!(store.level_of(&a.public_key), None);
        assert!(!store.remove(&a.fingerprint));
    }

    #[test]
    fn pin_is_stable_and_keyed() {
        let id = generate_identity();
        assert_eq!(short_pin(&id.public_key), short_pin(&id.public_key));
        let other = generate_identity();
        assert_ne!(id.short_pin, other.short_pin);
    }
}
