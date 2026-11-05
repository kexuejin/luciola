//! One error taxonomy for every binding surface.
//!
//! The engine has nine `thiserror` enums (37 `Display` templates). Before this
//! module existed, each FFI boundary flattened an error into a free-form
//! string, so a host could not tell "the peer presented the wrong key" from
//! "the socket broke" without parsing human prose. The Node surface was worse:
//! it concatenated the code into `message` and dropped the code entirely.
//!
//! [`ErrorCode`] is the closed, stable set of machine-readable codes. Every
//! crate maps its own error enum into an [`ErrorInfo`] via `From`, so there is
//! exactly one place to look when a code is added or renamed. Codes are part
//! of the FFI contract: they may be appended to, never renamed or removed
//! without a breaking release.

/// Stable, machine-readable error codes shared by the Rust core, uniffi
/// (KMP / Swift) and Node bindings.
///
/// Codes are `snake_case` strings on the wire. `#[non_exhaustive]` is
/// deliberate: hosts must treat an unrecognised code as [`ErrorCode::Unknown`]
/// rather than failing to compile against a newer engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// An operating-system I/O failure on a socket or file.
    IoError,
    /// A listener could not bind the requested port (often already occupied).
    BindFailed,
    /// The authenticated handshake failed before a channel was established.
    HandshakeFailed,
    /// The peer presented a key that does not match the pinned identity.
    UntrustedPeer,
    /// AEAD verification failed: a frame was tampered with or the key is wrong.
    TamperingDetected,
    /// The caller supplied a malformed argument (host, key length, envelope…).
    InvalidArgument,
    /// A port-forward rule was rejected during validation.
    InvalidRule,
    /// A wire frame, JSON document or registry file could not be decoded.
    DecodeError,
    /// The operation is not valid in the current state.
    StateError,
    /// A transfer's byte count disagreed with the declared size.
    SizeMismatch,
    /// An open, handshake or dial exceeded its deadline.
    Timeout,
    /// The channel or mux session closed while an operation was in flight.
    ChannelClosed,
    /// A tunnel base address was needed before `connect()` / `listen()`.
    NotConfigured,
    /// A tunnel API was called on the wrong link role.
    RoleMismatch,
    /// The tunnel control-plane task has exited (usually after shutdown).
    Unavailable,
    /// A forward endpoint was stopped.
    Stopped,
    /// A registry or protocol version is not supported.
    UnsupportedVersion,
    /// The peer violated the wire protocol (bad status, mode, frame size…).
    ProtocolViolation,
    /// The peer did not prove a required capability (e.g. mux v2).
    CapabilityMismatch,
    /// Enumerating the machine's network interfaces failed.
    NetworkQueryFailed,
    /// No mapping exists (or a newer engine emitted a code this host does not
    /// know). Hosts should fall back to the human-readable message.
    Unknown,
}

impl ErrorCode {
    /// Every code in the contract, in a stable order. Used by the FFI
    /// `errorCodes()` / `getErrorCodes()` exports and by the unit test that
    /// guards against duplicate or unparseable codes.
    pub const ALL: &'static [Self] = &[
        Self::IoError,
        Self::BindFailed,
        Self::HandshakeFailed,
        Self::UntrustedPeer,
        Self::TamperingDetected,
        Self::InvalidArgument,
        Self::InvalidRule,
        Self::DecodeError,
        Self::StateError,
        Self::SizeMismatch,
        Self::Timeout,
        Self::ChannelClosed,
        Self::NotConfigured,
        Self::RoleMismatch,
        Self::Unavailable,
        Self::Stopped,
        Self::UnsupportedVersion,
        Self::ProtocolViolation,
        Self::CapabilityMismatch,
        Self::NetworkQueryFailed,
        Self::Unknown,
    ];

    /// The wire representation. Never localise, never derive from `Debug`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IoError => "io_error",
            Self::BindFailed => "bind_failed",
            Self::HandshakeFailed => "handshake_failed",
            Self::UntrustedPeer => "untrusted_peer",
            Self::TamperingDetected => "tampering_detected",
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidRule => "invalid_rule",
            Self::DecodeError => "decode_error",
            Self::StateError => "state_error",
            Self::SizeMismatch => "size_mismatch",
            Self::Timeout => "timeout",
            Self::ChannelClosed => "channel_closed",
            Self::NotConfigured => "not_configured",
            Self::RoleMismatch => "role_mismatch",
            Self::Unavailable => "unavailable",
            Self::Stopped => "stopped",
            Self::UnsupportedVersion => "unsupported_version",
            Self::ProtocolViolation => "protocol_violation",
            Self::CapabilityMismatch => "capability_mismatch",
            Self::NetworkQueryFailed => "network_query_failed",
            Self::Unknown => "unknown",
        }
    }

    /// Whether a host should retry the failed operation. This is a hint, not
    /// a guarantee: an untrusted peer will stay untrusted no matter how often
    /// the caller retries, while a busy port or a dropped socket often clears.
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::IoError
                | Self::BindFailed
                | Self::HandshakeFailed
                | Self::Timeout
                | Self::ChannelClosed
                | Self::Unavailable
                | Self::Stopped
                | Self::NetworkQueryFailed
        )
    }

    /// Parse a wire code. Unknown strings become [`ErrorCode::Unknown`], so an
    /// older host confronted with a newer engine degrades instead of crashing.
    ///
    /// The four legacy prefixes are pinned by TUNNEL_SPEC and by consumer
    /// tests on both FFI surfaces; accepting them here keeps those strings on
    /// the wire while still giving hosts a canonical code.
    pub fn from_code(s: &str) -> Self {
        match s {
            "forward_bind_failed" | "tunnel_bind_failed" => Self::BindFailed,
            "tunnel_link_failed" => Self::IoError,
            "tunnel_handshake_failed" => Self::HandshakeFailed,
            _ => Self::ALL
                .iter()
                .copied()
                .find(|c| c.as_str() == s)
                .unwrap_or(Self::Unknown),
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A classified error: a stable code plus the original human-readable detail.
///
/// `Display` templates remain the human channel; the code is the machine
/// channel. Nothing is lost by classifying — `message` is exactly
/// `error.to_string()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorInfo {
    /// Stable machine-readable classification.
    pub code: ErrorCode,
    /// The original human-readable detail, exactly as the source error rendered it.
    pub message: String,
}

impl ErrorInfo {
    /// Pair a code with a human-readable message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The wire representation of [`Self::code`].
    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// Whether a host should retry the failed operation.
    pub fn retryable(&self) -> bool {
        self.code.retryable()
    }

    /// Legacy string callbacks (`on_error(code, message)` and
    /// `on_state("error", detail)`) receive exactly this prefix form. Keeping
    /// it in one helper stops the two FFI surfaces from drifting apart.
    pub fn wire_detail(&self) -> String {
        format!("{}: {}", self.code_str(), self.message)
    }

    /// Inverse of [`Self::wire_detail`]: recover the code from a
    /// `"<code>: <message>"` detail emitted by the tunnel control plane or an
    /// older peer. Unrecognised prefixes keep the whole string as the message
    /// and report [`ErrorCode::Unknown`] — nothing is silently discarded.
    pub fn parse_detail(detail: &str) -> Self {
        if let Some((head, rest)) = detail.split_once(": ") {
            let code = ErrorCode::from_code(head);
            if code != ErrorCode::Unknown {
                return Self::new(code, rest.to_string());
            }
        }
        Self::new(ErrorCode::Unknown, detail.to_string())
    }
}

impl From<&crate::ProtoError> for ErrorInfo {
    fn from(e: &crate::ProtoError) -> Self {
        let code = match e {
            crate::ProtoError::Serialization(_) => ErrorCode::DecodeError,
            crate::ProtoError::InvalidEnvelope(_) => ErrorCode::DecodeError,
        };
        Self::new(code, e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_code_is_unique_parseable_and_listed() {
        let strings: Vec<_> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        let unique: HashSet<_> = strings.iter().copied().collect();
        assert_eq!(unique.len(), strings.len(), "duplicate wire code");
        for (i, s) in strings.iter().enumerate() {
            assert!(!s.is_empty(), "empty code at index {i}");
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "code must be snake_case: {s}"
            );
            assert_eq!(ErrorCode::from_code(s).as_str(), *s, "no round trip: {s}");
        }
    }

    #[test]
    fn unknown_codes_degrade_instead_of_panicking() {
        assert_eq!(ErrorCode::from_code("future_thing"), ErrorCode::Unknown);
        assert_eq!(ErrorCode::from_code(""), ErrorCode::Unknown);
    }

    #[test]
    fn legacy_tunnel_prefixes_map_to_canonical_codes() {
        assert_eq!(
            ErrorCode::from_code("forward_bind_failed"),
            ErrorCode::BindFailed
        );
        assert_eq!(
            ErrorCode::from_code("tunnel_bind_failed"),
            ErrorCode::BindFailed
        );
        assert_eq!(
            ErrorCode::from_code("tunnel_handshake_failed"),
            ErrorCode::HandshakeFailed
        );
        assert_eq!(
            ErrorCode::from_code("tunnel_link_failed"),
            ErrorCode::IoError
        );
    }

    #[test]
    fn parse_detail_roundtrips_and_preserves_unknown_text() {
        let original = ErrorInfo::new(ErrorCode::UntrustedPeer, "peer key mismatch");
        let parsed = ErrorInfo::parse_detail(&original.wire_detail());
        assert_eq!(parsed, original);

        let legacy = ErrorInfo::parse_detail("forward_bind_failed: port in use");
        assert_eq!(legacy.code, ErrorCode::BindFailed);
        assert_eq!(legacy.message, "port in use");

        let freeform = ErrorInfo::parse_detail("something the host must still see");
        assert_eq!(freeform.code, ErrorCode::Unknown);
        assert_eq!(freeform.message, "something the host must still see");
    }

    #[test]
    fn wire_detail_keeps_code_and_message() {
        let info = ErrorInfo::new(ErrorCode::UntrustedPeer, "peer key mismatch");
        assert_eq!(info.code_str(), "untrusted_peer");
        assert!(!info.retryable());
        assert_eq!(
            info.wire_detail(),
            "untrusted_peer: peer key mismatch".to_string()
        );
    }

    #[test]
    fn proto_errors_are_classified() {
        let e = crate::ProtoError::InvalidEnvelope("bad v".into());
        let info = ErrorInfo::from(&e);
        assert_eq!(info.code, ErrorCode::DecodeError);
        assert_eq!(info.message, e.to_string());
    }
}
