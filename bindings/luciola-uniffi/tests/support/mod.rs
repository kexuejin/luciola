//! Shared helpers for the uniffi integration test binaries.
//!
//! # Why ports come from a fixed band
//!
//! These tests need a *known* port before the code under test binds it (the
//! tunnel port is derived as `secure + 1`, and a "port is released after
//! `stop`" assertion needs the same number twice), so §6's "bind port 0 and
//! read the assigned port" is not available everywhere. The next best thing is
//! to hand out ports that **no OS can auto-assign**: Linux allocates ephemeral
//! ports from 32768, macOS and Windows from 49152, so [`PORT_BAND_START`],
//! [`PORT_BAND_END`]) is safe on all three.
//!
//! That is not pedantry — asking the kernel via `bind(0.0.0.0:0)` is a real red
//! CI: everything it returns sits in the ephemeral range, which is also where
//! every outgoing connection takes its source port. Windows answers
//! `bind(0.0.0.0:p)` with WSAEADDRINUSE (10048) while *any* other socket merely
//! uses `p` as a source port, and the `#[test]`s run in parallel threads, so a
//! probed port was regularly stolen between the probe and the real bind:
//!
//! ```text
//! forward_bind_failed: 0.0.0.0:50259: Only one usage of each socket address ... (os error 10048)
//! ```
//!
//! Reservation is process-wide and neighbour-inclusive because the tunnel port
//! is `secure + 1` and both listeners bind wildcard addresses; the rotating
//! cursor keeps parallel tests on non-adjacent blocks.
#![allow(dead_code)] // each test binary uses a subset

use std::collections::HashSet;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};

/// Port band owned by the uniffi test binaries (below every OS ephemeral range).
pub const PORT_BAND_START: u16 = 20_000;
pub const PORT_BAND_END: u16 = 30_000;
const BAND_LEN: u16 = PORT_BAND_END - PORT_BAND_START;

fn reserved_ports() -> &'static Mutex<HashSet<u16>> {
    static PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn tcp_wildcard_free(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
        && std::net::TcpListener::bind(("::", port)).is_ok()
}

fn udp_wildcard_free(port: u16) -> bool {
    std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
        && std::net::UdpSocket::bind(("::", port)).is_ok()
}

/// Reserve `p-span..=p+span` and return `p`.
///
/// A block is accepted only when every port in it is un-reserved (process-wide)
/// and free on both wildcard addresses; `None` means the band is exhausted,
/// which the callers treat as a hard test-infrastructure failure instead of
/// looping forever.
fn reserve_block(span: u16, free: impl Fn(u16) -> bool) -> Option<u16> {
    static CURSOR: AtomicU16 = AtomicU16::new(0);
    let mut reserved = reserved_ports().lock().unwrap();
    for _ in 0..BAND_LEN {
        let offset = CURSOR.fetch_add(span + 1, Ordering::Relaxed) % BAND_LEN;
        let p = PORT_BAND_START + offset;
        // Keep the whole neighbour block inside the band: just outside it the OS
        // may hand those ports to an outgoing connection at any moment.
        if p < PORT_BAND_START + span || p + span >= PORT_BAND_END {
            continue;
        }
        if (p - span..=p + span).any(|port| reserved.contains(&port) || !free(port)) {
            continue;
        }
        for port in (p - span)..=(p + span) {
            reserved.insert(port);
        }
        return Some(p);
    }
    None
}

/// A TCP port whose ±1 neighbours are free as well.
pub fn free_tcp_port() -> u16 {
    reserve_block(1, tcp_wildcard_free)
        .expect("no free port block left in the test band 20000-30000")
}

/// A TCP port pair `(p, p + 1)`: the tunnel port defaults to `secure + 1`.
pub fn free_tcp_port_pair() -> (u16, u16) {
    let p = reserve_block(2, tcp_wildcard_free)
        .expect("no free port block left in the test band 20000-30000");
    (p, p + 1)
}

/// A UDP port whose ±1 neighbours are free as well.
pub fn free_udp_port() -> u16 {
    reserve_block(1, udp_wildcard_free)
        .expect("no free port block left in the test band 20000-30000")
}
