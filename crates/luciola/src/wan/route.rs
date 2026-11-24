//! Explicit route selection (`LanOnly` / `LanThenWan` / `WanOnly`).
//!
//! Covers initial connection establishment only — never silently downgrades an
//! already-established direct connection (see `docs/DECISIONS.md`) and always
//! reports the true transport plane via [`SecureStream::channel_type`].

use std::fmt;
use std::time::Duration;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::link::secure::{connect_secure_raced, LinkError, SecureStream};
use crate::wan::{connect_wan, WanConfig, WanError};

/// Route policy for [`connect_with_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePolicy {
    /// Dial LAN candidates only; never contact signalling/relay.
    LanOnly,
    /// Race LAN candidates for up to `lan_budget`, then fall back to WAN on failure.
    LanThenWan {
        /// Maximum time spent trying LAN before starting WAN rendezvous.
        lan_budget: Duration,
    },
    /// Skip LAN and dial WAN directly.
    WanOnly,
}

/// LAN dial parameters for [`connect_with_policy`].
#[derive(Clone)]
pub struct LanDialConfig {
    /// Candidate LAN IPv4 / IPv6 addresses.
    pub addresses: Vec<String>,
    /// Peer's secure TCP port.
    pub port: u16,
    /// Local 32-byte Ed25519 identity seed (zeroized on drop; redacted in `Debug`).
    pub identity_seed: Zeroizing<[u8; 32]>,
    /// Pinned 32-byte Ed25519 peer public key (mandatory; no TOFU).
    pub peer_public_key: [u8; 32],
}

impl fmt::Debug for LanDialConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanDialConfig")
            .field("addresses", &self.addresses)
            .field("port", &self.port)
            .field("identity_seed", &"[REDACTED]")
            .field("peer_public_key", &self.peer_public_key)
            .finish()
    }
}

/// Errors returned by [`connect_with_policy`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConnectPolicyError {
    /// Required configuration for the chosen route policy was not supplied.
    #[error("missing route configuration: {0}")]
    MissingConfig(&'static str),
    /// LAN dial failed (or exceeded `lan_budget`).
    #[error("lan connect failed: {0}")]
    Lan(String),
    /// WAN rendezvous failed.
    #[error("wan connect failed: {0}")]
    Wan(#[from] WanError),
    /// Both LAN and WAN attempts failed under [`RoutePolicy::LanThenWan`].
    #[error("lan failed ({lan}); wan failed ({wan})")]
    BothFailed {
        /// Reason the LAN attempt failed.
        lan: String,
        /// Reason the WAN attempt failed.
        wan: WanError,
    },
}

struct LanAttemptError {
    message: String,
    /// True for authentication / identity / tamper failures that must NOT fall
    /// back to WAN (security errors are terminal, not connectivity failures).
    security_fatal: bool,
}

fn is_security_link_error(err: &LinkError) -> bool {
    matches!(err, LinkError::UntrustedPeer | LinkError::Tamper(_))
}

async fn try_lan(
    lan: &LanDialConfig,
    budget: Option<Duration>,
) -> Result<SecureStream, LanAttemptError> {
    if lan.addresses.is_empty() {
        return Err(LanAttemptError {
            message: "no LAN candidate addresses".into(),
            security_fatal: false,
        });
    }
    let fut = connect_secure_raced(
        lan.addresses.clone(),
        lan.port,
        lan.identity_seed.as_slice(),
        &lan.peer_public_key,
    );
    match budget {
        Some(limit) => match tokio::time::timeout(limit, fut).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(LanAttemptError {
                security_fatal: is_security_link_error(&e),
                message: e.to_string(),
            }),
            Err(_) => Err(LanAttemptError {
                message: format!("LAN dial timed out after {limit:?}"),
                security_fatal: false,
            }),
        },
        None => fut.await.map_err(|e| LanAttemptError {
            security_fatal: is_security_link_error(&e),
            message: e.to_string(),
        }),
    }
}

/// Establish a [`SecureStream`] according to `policy`.
///
/// The returned stream always reports its true [`crate::ChannelType`] (`LanDirect`,
/// `HolePunchedDirect`, or `RelayForwarded`).
pub async fn connect_with_policy(
    policy: RoutePolicy,
    lan: Option<LanDialConfig>,
    wan: Option<WanConfig>,
) -> Result<SecureStream, ConnectPolicyError> {
    match policy {
        RoutePolicy::LanOnly => {
            let lan = lan.ok_or(ConnectPolicyError::MissingConfig("lan"))?;
            try_lan(&lan, None)
                .await
                .map_err(|e| ConnectPolicyError::Lan(e.message))
        }
        RoutePolicy::WanOnly => {
            let wan = wan.ok_or(ConnectPolicyError::MissingConfig("wan"))?;
            connect_wan(wan).await.map_err(ConnectPolicyError::Wan)
        }
        RoutePolicy::LanThenWan { lan_budget } => {
            let lan_err = match lan {
                Some(ref cfg) => match try_lan(cfg, Some(lan_budget)).await {
                    Ok(stream) => return Ok(stream),
                    Err(err) if err.security_fatal => {
                        return Err(ConnectPolicyError::Lan(err.message));
                    }
                    Err(err) => err.message,
                },
                None => "no LAN config supplied".into(),
            };
            let wan = wan.ok_or(ConnectPolicyError::Lan(lan_err.clone()))?;
            connect_wan(wan)
                .await
                .map_err(|wan_err| ConnectPolicyError::BothFailed {
                    lan: lan_err,
                    wan: wan_err,
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::secure::accept_secure;
    use crate::trust::generate_identity;
    use luciola_proto::ChannelType;
    use tokio::net::TcpListener;

    #[tokio::test(flavor = "multi_thread")]
    async fn lan_then_wan_returns_honest_lan_channel_when_lan_succeeds() {
        let a = generate_identity();
        let b = generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let pk_a = a.public_key.clone();
        let srv = tokio::spawn(async move {
            accept_secure(&listener, &seed_b, Some(&pk_a))
                .await
                .unwrap()
        });

        let stream = connect_with_policy(
            RoutePolicy::LanThenWan {
                lan_budget: Duration::from_secs(2),
            },
            Some(LanDialConfig {
                addresses: vec!["127.0.0.1".into()],
                port,
                identity_seed: Zeroizing::new(a.seed.clone().try_into().unwrap()),
                peer_public_key: b.public_key.clone().try_into().unwrap(),
            }),
            None,
        )
        .await
        .expect("LAN succeeds without needing WAN");

        assert_eq!(stream.channel_type(), ChannelType::LanDirect);
        let _ = srv.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lan_then_wan_falls_through_to_wan_and_respects_policy_deny() {
        let a = generate_identity();
        let b = generate_identity();
        // Bind then drop to obtain an unreachable local port.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let Err(err) = connect_with_policy(
            RoutePolicy::LanThenWan {
                lan_budget: Duration::from_millis(200),
            },
            Some(LanDialConfig {
                addresses: vec!["127.0.0.1".into()],
                port: dead_port,
                identity_seed: Zeroizing::new(a.seed.clone().try_into().unwrap()),
                peer_public_key: b.public_key.clone().try_into().unwrap(),
            }),
            // Default WanConfig has allow_wan_signaling=false (deny by default).
            Some(WanConfig::default()),
        )
        .await
        else {
            panic!("must fail when LAN fails and WAN is denied by policy");
        };

        assert!(
            matches!(
                err,
                ConnectPolicyError::BothFailed {
                    wan: WanError::PolicyDenied(_),
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lan_then_wan_does_not_fallback_to_wan_on_pin_mismatch() {
        let a = generate_identity();
        let b = generate_identity();
        let wrong_peer = generate_identity();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let srv = tokio::spawn(async move {
            let _ = accept_secure(&listener, &seed_b, None).await;
        });

        let Err(err) = connect_with_policy(
            RoutePolicy::LanThenWan {
                lan_budget: Duration::from_secs(2),
            },
            Some(LanDialConfig {
                addresses: vec!["127.0.0.1".into()],
                port,
                identity_seed: Zeroizing::new(a.seed.clone().try_into().unwrap()),
                // Expect `wrong_peer` while `b` is actually listening -> UntrustedPeer.
                peer_public_key: wrong_peer.public_key.clone().try_into().unwrap(),
            }),
            Some(WanConfig::default()),
        )
        .await
        else {
            panic!("pin mismatch must fail");
        };

        assert!(
            matches!(err, ConnectPolicyError::Lan(_)),
            "security error on LAN must NOT fall back to WAN; got {err:?}"
        );
        let _ = srv.await;
    }
}
