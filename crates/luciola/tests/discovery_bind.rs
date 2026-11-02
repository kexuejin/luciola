//! Regression: an occupied discovery port must fail loudly by default.
//!
//! Why: the old silent fallback let the loser of a port race keep announcing
//! into the winner's well-known port. On 2026-11-02 that made Firefly and
//! Tidings exchange profiles and dial each other's channel ports, and the
//! single-slot inbound listener starved the legitimate peer. A port conflict
//! is now an explicit `BindFailed`, and a fallback is an opt-in the caller can
//! see (it must surface `local_port()`).
//!
//! Both tests bind port 0 for the holder, so they do not depend on fixed ports
//! or on whatever else is listening on the dev machine.

use luciola::{CoreError, DiscoveryConfig, DiscoveryEngine};

fn occupied_udp_port() -> (std::net::UdpSocket, u16) {
    let holder = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind holder");
    let port = holder.local_addr().expect("holder addr").port();
    (holder, port)
}

fn config_for(port: u16) -> DiscoveryConfig {
    DiscoveryConfig {
        listen_port: port,
        broadcast_port: port,
        ..Default::default()
    }
}

#[tokio::test]
async fn occupied_port_fails_loudly_by_default() {
    let (_holder, port) = occupied_udp_port();

    match DiscoveryEngine::bind(config_for(port)).await {
        Ok(engine) => panic!(
            "expected BindFailed, got an engine bound to {:?}",
            engine.local_port().await
        ),
        Err(CoreError::BindFailed(reported, _)) => assert_eq!(
            reported, port,
            "the error must name the requested port, not the fallback"
        ),
        Err(other) => panic!("expected BindFailed, got {other}"),
    }
}

#[tokio::test]
async fn fallback_is_explicit_and_reports_the_actual_port() {
    let (_holder, port) = occupied_udp_port();
    let mut config = config_for(port);
    config.allow_ephemeral_fallback = true;

    let engine = DiscoveryEngine::bind(config)
        .await
        .expect("explicit fallback must bind");
    let actual = engine.local_port().await.expect("bound port");
    assert_ne!(
        actual, port,
        "fallback must not report the occupied port as its own"
    );
}
