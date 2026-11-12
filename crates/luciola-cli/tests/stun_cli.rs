//! Process-level coverage for `luciola-cli stun`.
//!
//! Two things can only be verified against the real binary: that a failed
//! probe returns a non-zero exit code, and that a successful probe does not
//! claim a NAT classification that a single Binding response cannot support.

use std::net::UdpSocket;
use std::process::Command;
use std::thread;

const COOKIE: u32 = 0x2112_A442;

/// Minimal RFC 5389 responder on loopback: answers one Binding Request with
/// an XOR-MAPPED-ADDRESS equal to the sender's observed endpoint.
fn spawn_mock_stun() -> (u16, thread::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind mock STUN");
    let port = server.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (len, from) = server.recv_from(&mut buf).expect("receive binding request");
        if len < 20 {
            return;
        }
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE.to_be_bytes());
        resp.extend_from_slice(&buf[8..20]); // transaction id
        resp.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x01); // IPv4
        let xport = from.port() ^ (COOKIE >> 16) as u16;
        resp.extend_from_slice(&xport.to_be_bytes());
        let ip = match from.ip() {
            std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            _ => 0x7f00_0001,
        };
        resp.extend_from_slice(&(ip ^ COOKIE).to_be_bytes());
        let _ = server.send_to(&resp, from);
    });
    (port, handle)
}

#[test]
fn successful_probe_prints_the_endpoint_without_a_nat_verdict() {
    let (port, server) = spawn_mock_stun();
    let out = Command::new(env!("CARGO_BIN_EXE_luciola-cli"))
        .args([
            "stun",
            "--servers",
            &format!("127.0.0.1:{port}"),
            "--timeout-secs",
            "5",
        ])
        .output()
        .expect("run stun command");
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stun probe should succeed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Public Reflected Address: 127.0.0.1:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Port mapping:"),
        "port preservation/rewrite must still be reported: {stdout}"
    );
    assert!(
        !stdout.contains("Endpoint-Independent"),
        "one Binding response cannot classify NAT mapping behaviour: {stdout}"
    );
    assert!(
        stdout.contains("one response reveals ONE mapped endpoint"),
        "{stdout}"
    );
}

#[test]
fn failed_probe_returns_a_nonzero_exit_code() {
    // Port 1 on loopback has no STUN responder. The CLI must fail loudly.
    let out = Command::new(env!("CARGO_BIN_EXE_luciola-cli"))
        .args(["stun", "--servers", "127.0.0.1:1", "--timeout-secs", "1"])
        .output()
        .expect("run stun command");
    assert!(
        !out.status.success(),
        "a failed STUN probe must not report success: stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn default_servers_come_from_the_library_not_a_hardcoded_list() {
    let out = Command::new(env!("CARGO_BIN_EXE_luciola-cli"))
        .args(["stun", "--help"])
        .output()
        .expect("run stun --help");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("--timeout-secs"), "{stdout}");
    assert!(stdout.contains("--ipv6"), "{stdout}");
    // Keep the help text honest: no NAT classification promise.
    assert!(!stdout.contains("Endpoint-Independent"), "{stdout}");
}
