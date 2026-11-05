//! Classification of the engine's own errors into the shared FFI taxonomy.
//!
//! Every `Display` template in this crate has exactly one [`ErrorCode`]. The
//! binding layers call `ErrorInfo::from(&err)` instead of inventing their own
//! strings, so a host sees the same code on Android, iOS, Swift and Node.

use luciola_proto::{ErrorCode, ErrorInfo};

impl From<&crate::CoreError> for ErrorInfo {
    fn from(e: &crate::CoreError) -> Self {
        let code = match e {
            crate::CoreError::Io(_) => ErrorCode::IoError,
            crate::CoreError::BindFailed(_, _) => ErrorCode::BindFailed,
        };
        Self::new(code, e.to_string())
    }
}

impl From<&crate::link::secure::LinkError> for ErrorInfo {
    fn from(e: &crate::link::secure::LinkError) -> Self {
        let code = match e {
            crate::link::secure::LinkError::Io(_) => ErrorCode::IoError,
            crate::link::secure::LinkError::Handshake(_) => ErrorCode::HandshakeFailed,
            crate::link::secure::LinkError::UntrustedPeer => ErrorCode::UntrustedPeer,
            crate::link::secure::LinkError::Tamper(_) => ErrorCode::TamperingDetected,
        };
        Self::new(code, e.to_string())
    }
}

impl From<&crate::relay_crypto::RelayCryptoError> for ErrorInfo {
    fn from(e: &crate::relay_crypto::RelayCryptoError) -> Self {
        let code = match e {
            crate::relay_crypto::RelayCryptoError::BadKeyLength(_) => ErrorCode::InvalidArgument,
            crate::relay_crypto::RelayCryptoError::DegenerateSharedSecret => {
                ErrorCode::HandshakeFailed
            }
            crate::relay_crypto::RelayCryptoError::AeadOpenFailed => ErrorCode::TamperingDetected,
        };
        Self::new(code, e.to_string())
    }
}

impl From<&crate::ports::PortRegistryError> for ErrorInfo {
    fn from(e: &crate::ports::PortRegistryError) -> Self {
        let code = match e {
            crate::ports::PortRegistryError::Json(_) => ErrorCode::DecodeError,
            crate::ports::PortRegistryError::UnsupportedVersion(_) => ErrorCode::UnsupportedVersion,
        };
        Self::new(code, e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_mismatch_is_not_retryable() {
        let info = ErrorInfo::from(&crate::link::secure::LinkError::UntrustedPeer);
        assert_eq!(info.code, ErrorCode::UntrustedPeer);
        assert!(!info.retryable(), "a wrong key will never become right");
        assert!(info.message.contains("untrusted"));
    }

    #[test]
    fn io_and_bind_are_distinguished_and_retryable() {
        let io = ErrorInfo::from(&crate::CoreError::Io(std::io::Error::other("socket broke")));
        let bind = ErrorInfo::from(&crate::CoreError::BindFailed(
            17878,
            std::io::Error::other("in use"),
        ));
        assert_eq!(io.code, ErrorCode::IoError);
        assert_eq!(bind.code, ErrorCode::BindFailed);
        assert!(io.retryable() && bind.retryable());
        assert_ne!(io.code_str(), bind.code_str());
    }

    #[test]
    fn every_variant_maps_to_a_known_code() {
        let infos = vec![
            ErrorInfo::from(&crate::CoreError::Io(std::io::Error::other("x"))),
            ErrorInfo::from(&crate::link::secure::LinkError::Handshake("h".into())),
            ErrorInfo::from(&crate::link::secure::LinkError::Tamper("t".into())),
            ErrorInfo::from(&crate::relay_crypto::RelayCryptoError::AeadOpenFailed),
            ErrorInfo::from(&crate::relay_crypto::RelayCryptoError::BadKeyLength(1)),
            ErrorInfo::from(&crate::ports::PortRegistryError::UnsupportedVersion(9)),
        ];
        for info in infos {
            assert_ne!(info.code, ErrorCode::Unknown);
            assert_eq!(
                ErrorCode::from_code(info.code_str()),
                info.code,
                "{} must round-trip",
                info.code_str()
            );
        }
    }
}
