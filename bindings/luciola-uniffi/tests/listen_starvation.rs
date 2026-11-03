//! Regression (2026-11-02): the single inbound accept slot must not be held
//! forever by a foreign/silent connection.
//!
//! Field failure: Firefly dialled the Tidings port with its own wire format,
//! the server's handshake blocked waiting for a first flight that never came,
//! and the legitimate peer queued in the kernel backlog was starved until the
//! foreign process exited (then the backlog flushed and messages poured in).

use luciola_uniffi::{SecureSession, SecureSessionListener};
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type EventLog = Arc<Mutex<Vec<(String, Option<String>)>>>;

#[derive(Clone, Default)]
struct Events(EventLog);

impl Events {
    fn has(&self, state: &str) -> bool {
        self.0.lock().unwrap().iter().any(|(s, _)| s == state)
    }
    fn dump(&self) -> Vec<(String, Option<String>)> {
        self.0.lock().unwrap().clone()
    }
}

impl SecureSessionListener for Events {
    fn on_state(&self, state: String, detail: Option<String>) {
        self.0.lock().unwrap().push((state, detail));
    }
    fn on_message(
        &self,
        _message: Vec<u8>,
        _peer_fingerprint: String,
        _remote_addr: Option<String>,
    ) {
    }
}

mod support;
use support::free_tcp_port;

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
fn silent_foreign_client_does_not_starve_the_legitimate_peer() {
    let port = free_tcp_port();
    let a = luciola::trust::generate_identity();
    let b = luciola::trust::generate_identity();

    // Listener (TOFU: the peer pin is learned from the handshake).
    let server = Arc::new(SecureSession::new(b.seed.clone()));
    let server_events = Events::default();
    server
        .clone()
        .listen(port, None, Box::new(server_events.clone()));

    // A foreign client that connects and sends a short, non-handshake
    // prefix: exactly what a different wire format looks like on the wire.
    let silent = (|| {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                stream.write_all(&[0u8; 10]).unwrap();
                stream.flush().unwrap();
                return stream;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("listener never bound on port {port}");
    })();

    // The legitimate peer dials while the slot is occupied. With no handshake
    // timeout it would sit in the backlog forever.
    let dialer = Arc::new(SecureSession::new(a.seed.clone()));
    let dial_events = Events::default();
    dialer.clone().connect(
        vec!["127.0.0.1".to_string()],
        port,
        b.public_key.clone(),
        true,
        Box::new(dial_events.clone()),
    );

    let connected = wait_until(|| dial_events.has("connected"), 20_000);
    assert!(
        connected,
        "legitimate peer starved; events: {:?}",
        dial_events.dump()
    );
    // dialer 的 connected 与 server 的 on_state("connected") 由两端各自的
    // accept/dial 任务分别上报，先后没有保证：server 侧要等 accept 任务跑完
    // 握手收尾才回调，负载高（windows-latest）时会晚于 dialer 那次即时断言，
    // 于是"合法对端其实已被接受"也会判红。这里同样等它入队——属性不变：
    // 合法对端最终必须被接受（10s 预算内）。
    let accepted = wait_until(|| server_events.has("connected"), 10_000);
    assert!(
        accepted,
        "server never accepted the legitimate peer; events: {:?}",
        server_events.dump()
    );

    dialer.disconnect();
    server.disconnect();
    drop(silent);
}
