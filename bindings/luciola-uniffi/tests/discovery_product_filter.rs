//! FFI regression: the product allow-list must be wired from the uniffi setter
//! into the engine config, so an FFI host (KMP/Swift) can keep another
//! product's peers out of its table without touching Rust code.

use luciola_uniffi::{DiscoveredPeer, DiscoverySession, ManualPeer, OnPeerDiscovered};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<DiscoveredPeer>>>);

impl OnPeerDiscovered for Recorder {
    fn on_peer_discovered(&self, peer: DiscoveredPeer) {
        self.0.lock().unwrap().push(peer);
    }
    fn on_peer_updated(&self, _peer: DiscoveredPeer) {}
    fn on_peer_lost(&self, _node_id: String) {}
    fn on_error(&self, _code: String, _message: String) {}
}

mod support;

use support::free_udp_port;

fn session(
    name: &str,
    port: u16,
    manual_peers: Option<Vec<ManualPeer>>,
    product: &str,
    node_id: &str,
) -> Arc<DiscoverySession> {
    Arc::new(DiscoverySession::new(
        name.to_string(),
        port,
        manual_peers,
        Some(product.to_string()),
        None,
        Some(node_id.to_string()),
        None,
        None,
    ))
}

fn wait_until(pred: impl Fn() -> bool, ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    pred()
}

#[test]
fn product_filter_keeps_other_products_out_of_the_ffi_peer_table() {
    let port = free_udp_port();

    let observer = session("observer", port, None, "alpha", "ffi_obs");
    observer
        .clone()
        .set_product_filter(Some(vec!["alpha".to_string()]));
    let observed = Recorder::default();
    observer.clone().start(Box::new(observed.clone()));
    // Let the bind land before the peers announce.
    std::thread::sleep(Duration::from_millis(150));

    let dial = |node: &str, product: &str| {
        session(
            node,
            0,
            Some(vec![ManualPeer {
                host: "127.0.0.1".to_string(),
                port,
            }]),
            product,
            node,
        )
    };
    let beta = dial("ffi_beta", "beta");
    let alpha = dial("ffi_alpha", "alpha");

    let noop = Recorder::default();
    beta.clone().start(Box::new(noop.clone()));
    alpha.clone().start(Box::new(noop));

    assert!(
        wait_until(
            || observed
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|p| p.node_id == "ffi_alpha"),
            4_000
        ),
        "the allowed product must still be discovered through the FFI setter"
    );

    // Give the filtered product a generous window to (wrongly) appear.
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        !observed
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.node_id == "ffi_beta"),
        "a filtered-out product must never reach the FFI callback"
    );

    observer.stop();
    beta.stop();
    alpha.stop();
}
