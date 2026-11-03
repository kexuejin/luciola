//! TEMPORARY Windows diagnostic probe — deleted before the fix lands.
//!
//! Not part of the suite: run explicitly with
//!   cargo test -p luciola-tunnel --test zz_probe -- --nocapture --test-threads=1
//! Every probe prints a timeline to stderr so a Windows runner tells us WHICH
//! step differs (connect refused timing, ACK delivery, or head-of-line stall).

mod common;
use common::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use luciola_tunnel::{
    start_forward_endpoint, start_local_forward, DialTarget, ForwardAcl, ForwardRule,
    LocalForwardConfig, MuxConfig,
};

fn dead_addr() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind for dead port");
    let addr = l.local_addr().expect("dead addr");
    drop(l);
    addr
}

fn rule_for(addr: std::net::SocketAddr) -> ForwardRule {
    ForwardRule {
        host: addr.ip().to_string(),
        port_from: addr.port(),
        port_to: addr.port(),
        udp: false,
    }
}

async fn spawn_echo_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let h = tokio::spawn(async move {
        loop {
            let (mut conn, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, h)
}

async fn spawn_blackhole_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind blackhole");
    let addr = listener.local_addr().expect("blackhole addr");
    tokio::spawn(async move {
        let mut held: Vec<TcpStream> = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            held.push(conn);
        }
    });
    addr
}

/// probe 1/2: raw connect to a just-closed loopback port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p1_dead_port_connect_timing() {
    println!("=== P1 tokio TcpStream::connect to a just-closed loopback port ===");
    for i in 0..3 {
        let addr = dead_addr();
        let t = Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await;
        let desc = match &r {
            Err(_) => "TIMEOUT after 10s".to_string(),
            Ok(Ok(_)) => "CONNECTED (unexpected)".to_string(),
            Ok(Err(e)) => format!("err kind={:?} display={}", e.kind(), e),
        };
        println!("P1 #{i} addr={addr} -> {desc} elapsed={:?}", t.elapsed());
    }

    println!("=== P2 luciola::link::dial to the same kind of port ===");
    for i in 0..2 {
        let addr = dead_addr();
        let t = Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            luciola::link::dial("127.0.0.1", addr.port()),
        )
        .await;
        let desc = match &r {
            Err(_) => "TIMEOUT after 10s".to_string(),
            Ok(Ok(_)) => "CONNECTED (unexpected)".to_string(),
            Ok(Err(e)) => format!("err kind={:?} display={}", e.kind(), e),
        };
        println!("P2 #{i} port={} -> {desc} elapsed={:?}", addr.port(), t.elapsed());
    }

    println!("=== P2b blocking std::net::TcpStream::connect (same port kind) ===");
    for i in 0..2 {
        let addr = dead_addr();
        let t = Instant::now();
        let join = tokio::task::spawn_blocking(move || {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        });
        let r = join.await.expect("blocking join");
        let desc = match &r {
            Ok(_) => "CONNECTED (unexpected)".to_string(),
            Err(e) => format!("err kind={:?} display={}", e.kind(), e),
        };
        println!("P2b #{i} port={} -> {desc} elapsed={:?}", addr.port(), t.elapsed());
    }
}

/// probe 3: the real failing scenario, but with a generous open_timeout so we
/// see whether the peer's ACK arrives at all and when the dial actually fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_mux_open_dead_port() {
    println!("=== P3 mux open() to a dead port through a real ForwardEndpoint ===");
    let cfg = MuxConfig {
        open_timeout: Duration::from_secs(8),
        ..Default::default()
    };
    let (i, r) = mux_pair_cfg(cfg.clone()).await;
    let (i, r) = (Arc::new(i), Arc::new(r));
    let dead = dead_addr();
    let endpoint =
        start_forward_endpoint(r.clone(), ForwardAcl::new(vec![rule_for(dead)])).expect("endpoint");

    let t = Instant::now();
    let res = i.open(DialTarget::from_ip(dead.ip(), dead.port())).await;
    println!(
        "P3 open(dead {dead}) -> {:?} elapsed={:?} endpoint_status={:?}",
        res.as_ref().map(|s| s.ch_id()).map_err(|e| e.to_string()),
        t.elapsed(),
        endpoint.status()
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    println!(
        "P3 after +6s: endpoint_status={:?} session_alive={} stats={:?}",
        endpoint.status(),
        i.is_alive(),
        i.stats()
    );
    endpoint.stop().await;
}

/// probe 4: baseline — the same open() path to a LIVE upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p4_mux_open_live_port() {
    println!("=== P4 baseline mux open() to a live upstream ===");
    let cfg = MuxConfig {
        open_timeout: Duration::from_secs(8),
        ..Default::default()
    };
    let (i, r) = mux_pair_cfg(cfg).await;
    let (i, r) = (Arc::new(i), Arc::new(r));
    let (echo_addr, echo) = spawn_echo_upstream().await;
    let endpoint =
        start_forward_endpoint(r.clone(), ForwardAcl::new(vec![rule_for(echo_addr)])).expect("endpoint");
    for k in 0..3 {
        let t = Instant::now();
        let res = i.open(DialTarget::from_ip(echo_addr.ip(), echo_addr.port())).await;
        println!(
            "P4 #{k} open(live) -> {:?} elapsed={:?}",
            res.as_ref().map(|s| s.ch_id()).map_err(|e| e.to_string()),
            t.elapsed()
        );
        drop(res);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    endpoint.stop().await;
    echo.abort();
}

/// probe 5: the stalled-channel scenario, instrumented so a Windows run shows
/// which side stops first (local open timeout vs. mid-transfer reset).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p5_stalled_channel_timeline() {
    println!("=== P5 stalled-channel timeline ===");
    let bh_addr = spawn_blackhole_upstream().await;
    let (echo_addr, echo) = spawn_echo_upstream().await;
    let (i, r) = mux_pair().await;
    let (i, r) = (Arc::new(i), Arc::new(r));
    let acl = ForwardAcl::new(vec![rule_for(bh_addr), rule_for(echo_addr)]);
    let endpoint = start_forward_endpoint(r, acl).expect("endpoint");

    let fwd_bh = start_local_forward(
        i.clone(),
        LocalForwardConfig {
            listen_port: 0,
            target: DialTarget::from_ip(bh_addr.ip(), bh_addr.port()),
        },
    )
    .expect("fwd blackhole");
    let fwd_echo = start_local_forward(
        i.clone(),
        LocalForwardConfig {
            listen_port: 0,
            target: DialTarget::from_ip(echo_addr.ip(), echo_addr.port()),
        },
    )
    .expect("fwd echo");

    let written = Arc::new(AtomicU64::new(0));
    let mut a = TcpStream::connect(fwd_bh.local_addr())
        .await
        .expect("connect A");
    let w = written.clone();
    let a_task = tokio::spawn(async move {
        let buf = vec![0xA5u8; 50_000];
        for _ in 0..4 {
            if a.write_all(&buf).await.is_err() {
                break;
            }
            w.fetch_add(buf.len() as u64, Ordering::SeqCst);
        }
        a
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    println!(
        "P5 after A burst: A_written={} endpoint={:?} fwd_bh={:?} fwd_echo={:?}",
        written.load(Ordering::SeqCst),
        endpoint.status(),
        fwd_bh.status(),
        fwd_echo.status()
    );

    for round in 0..2 {
        let t = Instant::now();
        let chunk: Vec<u8> = (0..40_000).map(|k| (k % 199) as u8).collect();
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            roundtrip_probe(fwd_echo.local_addr(), 4, chunk),
        )
        .await;
        match outcome {
            Ok(Ok(())) => println!("P5 roundtrip #{round} OK elapsed={:?}", t.elapsed()),
            Ok(Err(e)) => println!("P5 roundtrip #{round} FAILED {e} elapsed={:?}", t.elapsed()),
            Err(_) => println!("P5 roundtrip #{round} TIMEOUT after {:?}", t.elapsed()),
        }
        println!(
            "P5   state: A_written={} endpoint={:?} fwd_bh={:?} fwd_echo={:?} echo_stats={:?} alive={}",
            written.load(Ordering::SeqCst),
            endpoint.status(),
            fwd_bh.status(),
            fwd_echo.status(),
            i.stats(),
            i.is_alive()
        );
    }

    fwd_bh.stop().await;
    fwd_echo.stop().await;
    endpoint.stop().await;
    echo.abort();
    let _ = a_task.await;
}

async fn roundtrip_probe(
    local: std::net::SocketAddr,
    chunks: usize,
    chunk: Vec<u8>,
) -> Result<(), String> {
    let (mut rd, mut wr) = TcpStream::connect(local)
        .await
        .map_err(|e| format!("connect: {e}"))?
        .into_split();
    let expect = chunk.clone();
    let writer = tokio::spawn(async move {
        for _ in 0..chunks {
            wr.write_all(&chunk).await.map_err(|e| format!("write: {e}"))?;
        }
        let _ = wr.shutdown().await;
        Ok::<(), String>(())
    });
    let mut buf = vec![0u8; expect.len()];
    for k in 0..chunks {
        rd.read_exact(&mut buf)
            .await
            .map_err(|e| format!("read #{k}: {e:?}"))?;
        if buf != expect {
            return Err(format!("bytes differ at #{k}"));
        }
    }
    let _ = writer.await;
    Ok(())
}
