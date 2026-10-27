//! Level-2 acceptance: real socket behavior (no mock sockets).
//!
//! - dual-stack listener serves IPv4 AND IPv6 on the same port
//! - `dial` handles v4, `::1`, `[::1]`, and link-local scope injection
//! - Happy Eyeballs race picks the live address fast

use luciola::link::{bind_dual_stack_listener, dial, race_connect, RaceConfig};
use network_interface::NetworkInterfaceConfig;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Both a v4 client (127.0.0.1) and a v6 client ([::1]) must be accepted by
/// the SAME listener, with concurrent 10 KiB bidirectional exchanges.
#[tokio::test]
async fn dual_stack_listener_accepts_v4_and_v6() {
    let listener = bind_dual_stack_listener(0).await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let is_dual = listener.local_addr().unwrap().is_ipv6();

    let server = tokio::spawn(async move {
        let mut conns = Vec::new();
        for _ in 0..2 {
            conns.push(listener.accept().await.expect("accept").0);
        }
        for s in conns.iter_mut() {
            let mut buf = vec![0u8; 10 * 1024];
            s.read_exact(&mut buf).await.expect("server read");
            s.write_all(&buf).await.expect("server echo");
        }
    });

    let v4 = tokio::spawn(async move {
        let mut s = dial("127.0.0.1", port).await.expect("v4 dial");
        let payload: Vec<u8> = (0..10 * 1024).map(|i| (i % 251) as u8).collect();
        s.write_all(&payload).await.unwrap();
        let mut buf = vec![0u8; 10 * 1024];
        s.read_exact(&mut buf).await.unwrap();
        buf
    });
    let v6 = tokio::spawn(async move {
        let mut s = dial("::1", port).await.expect("v6 dial");
        let payload: Vec<u8> = (0..10 * 1024).map(|i| (i % 253) as u8).collect();
        s.write_all(&payload).await.unwrap();
        let mut buf = vec![0u8; 10 * 1024];
        s.read_exact(&mut buf).await.unwrap();
        buf
    });

    let (r4, r6) = tokio::join!(v4, v6);
    let r4 = r4.unwrap();
    let r6 = r6.unwrap();
    assert_eq!(r4[0], 0);
    assert_eq!(r4[10 * 1024 - 1], ((10 * 1024 - 1) % 251) as u8);
    assert_eq!(r6[0], 0);
    assert_eq!(r6[10 * 1024 - 1], ((10 * 1024 - 1) % 253) as u8);
    server.await.unwrap();

    // If the platform had to fall back to IPv4-only, the v6 path above would
    // have failed the dial already; reaching here on a dual-stack-capable
    // machine proves both families were served by one socket.
    assert!(
        is_dual || std::env::var("LUCIOLA_ALLOW_V4_FALLBACK").is_ok(),
        "listener fell back to IPv4-only; dual stack unavailable"
    );
}

#[tokio::test]
async fn dial_handles_loopback_forms() {
    let listener = bind_dual_stack_listener(0).await.expect("bind");
    let port = listener.local_addr().unwrap().port();

    for target in ["127.0.0.1", "::1", "[::1]"] {
        let s = dial(target, port)
            .await
            .unwrap_or_else(|e| panic!("dial {target} failed: {e}"));
        drop(s);
    }
}

/// Link-local scope injection: dial the local machine's own link-local
/// address (with and without an explicit %scope) against a local listener.
/// Skips silently where no link-local NIC exists (bare CI containers).
#[tokio::test]
async fn dial_injects_link_local_scope() {
    let listener = bind_dual_stack_listener(0).await.expect("bind");
    let port = listener.local_addr().unwrap().port();

    let mut target: Option<(std::net::Ipv6Addr, u32, String)> = None;
    for iface in network_interface::NetworkInterface::show()
        .into_iter()
        .flatten()
    {
        // scope_id_for only resolves physical NICs; pick a target it can own.
        if luciola_net::is_virtual_interface_name(&iface.name) {
            continue;
        }
        for addr in iface.addr {
            if let network_interface::Addr::V6(v6) = addr {
                if luciola_net::is_link_local_ipv6(&v6.ip) {
                    target = Some((v6.ip, iface.index, iface.name.clone()));
                    break;
                }
            }
        }
        if target.is_some() {
            break;
        }
    }

    let Some((ip, index, name)) = target else {
        eprintln!("no local IPv6 link-local address; skipping scope test");
        return;
    };

    let bare = ip.to_string();
    let with_name = format!("{bare}%{name}");
    let with_index = format!("{bare}%{index}");

    // Self-dial over link-local completes in milliseconds when healthy; a
    // 5 s cap keeps a transient NDP/interface blip from stalling the suite
    // for the full OS-level TCP timeout (~75 s on macOS).
    for t in [with_name, with_index, bare] {
        let s = tokio::time::timeout(Duration::from_secs(5), dial(&t, port))
            .await
            .unwrap_or_else(|_| panic!("dial {t} timed out (link-local self-dial must be fast)"))
            .unwrap_or_else(|e| panic!("dial {t} failed: {e}"));
        drop(s);
    }
}

/// Happy Eyeballs: unreachable TEST-NET candidates mixed with a live loopback
/// must resolve quickly (no serializing behind dead timeouts, no deadlock).
///
/// On TUN-proxied machines (Clash/Sing-box) even TEST-NET addresses "connect"
/// instantly through the proxy, so the winner may legitimately be a TEST-NET
/// address there; the invariants we hold everywhere are: exactly one Won, and
/// the race decided far below the per-attempt timeout budget.
#[tokio::test]
async fn race_connect_survives_unreachable_candidates() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_port = listener.local_addr().unwrap().port();

    let started = Instant::now();
    let outcome = race_connect(
        vec![
            "192.0.2.1".to_string(),   // TEST-NET-1, routed to nowhere (or TUN proxy)
            "2001:db8::1".to_string(), // doc range, routed to nowhere
            "127.0.0.1".to_string(),   // live
        ],
        live_port,
        RaceConfig::default(),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        outcome.winner.is_some(),
        "race must produce a winner, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "race must not serialize behind dead candidates, took {elapsed:?}"
    );
    let won: Vec<_> = outcome
        .channels
        .iter()
        .filter(|c| c.status == luciola::link::DialStatus::Won)
        .collect();
    assert_eq!(won.len(), 1);
    if outcome.winner.as_deref() != Some("127.0.0.1") {
        eprintln!(
            "note: TUN/proxy environment accepted TEST-NET first (winner {:?})",
            outcome.winner
        );
    }
}
