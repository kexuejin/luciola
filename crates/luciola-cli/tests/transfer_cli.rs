//! Process-level coverage for `luciola-cli transfer`.
//!
//! The unit tests in `src/transfer.rs` drive `run_send` / `run_recv` directly.
//! Those cannot catch a broken command wiring: a wrong clap subcommand, a pin
//! swapped between the two roles, a listener that never binds, or a receiver
//! that forgets to finalize. This suite spawns the real binary twice over a
//! loopback TCP socket, exactly as two machines would run it.
//!
//! Port 0 is used on the receiving side and the assigned port is read back
//! from the CLI's listening line — no fixed port, so parallel CI jobs and a
//! leftover listener on a dev box cannot make the suite flaky.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn identity_hex(seed: &[u8; 32]) -> (String, String) {
    let id = luciola::trust::identity_from_seed(seed);
    (hex(seed), hex(&id.public_key))
}

/// Wait for a child without letting a stuck peer hang the whole suite.
fn wait_with_timeout(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("wait_with_output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("transfer process did not exit within {timeout:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Drain the receiver's stdout for its whole lifetime.
///
/// The listening line is needed immediately to learn the ephemeral port, but
/// the read end must stay open until the process exits: Rust's `println!`
/// panics on EPIPE, so closing stdout after the first line would kill the
/// receiver mid-transfer and the sender would report a misleading
/// "Broken pipe". The first line is delivered on its own channel; the rest
/// accumulates and is returned at EOF for diagnostics.
struct StdoutDrain {
    first_line: mpsc::Receiver<String>,
    full: mpsc::Receiver<String>,
}

fn drain_stdout(stdout: std::process::ChildStdout) -> StdoutDrain {
    let (first_tx, first_line) = mpsc::channel();
    let (full_tx, full) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut all = String::new();
        let mut sent_first = false;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if !sent_first {
                        let _ = first_tx.send(line.clone());
                        sent_first = true;
                    }
                    all.push_str(&line);
                }
            }
        }
        if !sent_first {
            let _ = first_tx.send(String::new());
        }
        let _ = full_tx.send(all);
    });
    StdoutDrain { first_line, full }
}

fn listening_line(drain: &StdoutDrain) -> String {
    drain
        .first_line
        .recv_timeout(Duration::from_secs(15))
        .expect("receiver never printed its listening line")
}

fn listening_port(line: &str) -> u16 {
    let addr = line
        .split("Listening on ")
        .nth(1)
        .unwrap_or_else(|| panic!("unexpected listening line: {line:?}"))
        .split_whitespace()
        .next()
        .expect("missing socket address");
    addr.rsplit(':')
        .next()
        .expect("missing port")
        .parse()
        .unwrap_or_else(|e| panic!("cannot parse port from {addr:?}: {e}"))
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "luciola-cli-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn send_recv_over_two_cli_processes() {
    let bin = env!("CARGO_BIN_EXE_luciola-cli");
    let dir = temp_dir("e2e");
    let src = dir.join("payload.bin");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");

    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &payload).expect("write payload");

    let (seed_a, pk_a) = identity_hex(&[0x11; 32]);
    let (seed_b, pk_b) = identity_hex(&[0x22; 32]);

    let mut recv = Command::new(bin)
        .args([
            "transfer",
            "recv",
            "--port",
            "0",
            "--seed",
            &seed_b,
            "--accept-pin",
            &pk_a,
            "--out",
            out.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn receiver");
    let drain = drain_stdout(recv.stdout.take().expect("receiver stdout"));
    let port = listening_port(&listening_line(&drain));

    let send = Command::new(bin)
        .args([
            "transfer",
            "send",
            "--file",
            src.to_str().unwrap(),
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--seed",
            &seed_a,
            "--pin-peer",
            &pk_b,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sender");

    let send_out = wait_with_timeout(send, Duration::from_secs(30));
    let recv_out = wait_with_timeout(recv, Duration::from_secs(45));
    let recv_stdout = drain.full.recv().unwrap_or_default();
    let diagnostics = format!(
        "--- sender stdout ---\n{}\n--- sender stderr ---\n{}\n--- receiver stdout ---\n{recv_stdout}\n--- receiver stderr ---\n{}",
        String::from_utf8_lossy(&send_out.stdout),
        String::from_utf8_lossy(&send_out.stderr),
        String::from_utf8_lossy(&recv_out.stderr),
    );
    assert!(send_out.status.success(), "sender failed:\n{diagnostics}");
    assert!(recv_out.status.success(), "receiver failed:\n{diagnostics}");

    let landed = out.join("payload.bin");
    assert!(
        landed.exists(),
        "file must land at the basename inside --out"
    );
    assert_eq!(
        std::fs::read(&landed).expect("read received file"),
        payload,
        "received bytes must match exactly"
    );
    assert!(
        recv_stdout.contains("SHA-256"),
        "receiver must report a verified checksum; got: {recv_stdout}"
    );
    assert!(
        recv_stdout.contains("262144 bytes"),
        "receiver must report the verified byte count; got: {recv_stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Deny-by-default: a sender pinned to the wrong peer key must be rejected,
/// and the receiver must not write a file. Guards against a regression where
/// `--accept-pin` was accidentally treated as advisory.
#[test]
fn wrong_pin_is_rejected_and_no_file_is_written() {
    let bin = env!("CARGO_BIN_EXE_luciola-cli");
    let dir = temp_dir("wrong-pin");
    let src = dir.join("secret.bin");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");
    std::fs::write(&src, b"do not land").expect("write payload");

    let (seed_a, pk_a) = identity_hex(&[0x33; 32]);
    let (seed_b, _pk_b) = identity_hex(&[0x44; 32]);
    let (_seed_c, wrong_pin) = identity_hex(&[0x55; 32]);

    let mut recv = Command::new(bin)
        .args([
            "transfer",
            "recv",
            "--port",
            "0",
            "--seed",
            &seed_b,
            "--accept-pin",
            &pk_a,
            "--out",
            out.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn receiver");
    let drain = drain_stdout(recv.stdout.take().expect("receiver stdout"));
    let port = listening_port(&listening_line(&drain));

    let send = Command::new(bin)
        .args([
            "transfer",
            "send",
            "--file",
            src.to_str().unwrap(),
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--seed",
            &seed_a,
            "--pin-peer",
            &wrong_pin,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sender");

    let send_out = wait_with_timeout(send, Duration::from_secs(30));
    let recv_out = wait_with_timeout(recv, Duration::from_secs(30));
    assert!(
        !send_out.status.success(),
        "a sender pinned to the wrong key must fail"
    );
    assert!(
        !recv_out.status.success(),
        "receiver must reject the mismatched peer"
    );
    assert!(
        std::fs::read_dir(&out)
            .expect("read out dir")
            .next()
            .is_none(),
        "no file may be written for a rejected handshake"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// `transfer pin` is the documented way to derive the value peers paste into
/// `--pin-peer` / `--accept-pin`; keep its output tied to the real identity.
#[test]
fn pin_command_prints_the_identity_public_key() {
    let (seed, expected_pk) = identity_hex(&[0x66; 32]);
    let out = Command::new(env!("CARGO_BIN_EXE_luciola-cli"))
        .args(["transfer", "pin", "--seed", &seed])
        .output()
        .expect("run transfer pin");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("public_key={expected_pk}")),
        "unexpected pin output: {stdout}"
    );
}
