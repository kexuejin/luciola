//! Regression (2026-11-02): an occupied discovery port must surface as
//! `bind_failed` with `is_bound() == false` — never as a session that claims
//! to be online while it quietly sits on an ephemeral port.
//!
//! Before this, `DiscoveryEngine::bind` swallowed the conflict and the uniffi
//! retry loop was dead code, so `is_bound()` always returned true.

use luciola_uniffi::{DiscoveredPeer, DiscoverySession, OnPeerDiscovered};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<(String, String)>>>);

impl OnPeerDiscovered for Recorder {
    fn on_peer_discovered(&self, _peer: DiscoveredPeer) {}
    fn on_peer_updated(&self, _peer: DiscoveredPeer) {}
    fn on_peer_lost(&self, _node_id: String) {}
    fn on_error(&self, code: String, message: String) {
        self.0.lock().unwrap().push((code, message));
    }
}

#[test]
fn occupied_discovery_port_reports_bind_failed_and_is_not_bound() {
    let holder = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind holder");
    let port = holder.local_addr().expect("holder addr").port();

    let session = Arc::new(DiscoverySession::new(
        "port-conflict-test".to_string(),
        port,
        None,
        Some("test".to_string()),
        None,
        None,
        None,
        None,
    ));
    let recorder = Recorder::default();
    session.clone().start(Box::new(recorder.clone()));

    // The retry window is 25 * 200 ms; give it headroom.
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline && recorder.0.lock().unwrap().is_empty() {
        std::thread::sleep(Duration::from_millis(50));
    }

    let errors = recorder.0.lock().unwrap().clone();
    assert!(
        errors.iter().any(|(code, _)| code == "bind_failed"),
        "expected bind_failed, got {errors:?}"
    );
    assert!(
        !session.is_bound(),
        "is_bound() must agree with the failed bind"
    );
    session.stop();
}
