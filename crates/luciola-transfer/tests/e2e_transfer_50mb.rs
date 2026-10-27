//! Level-3 acceptance: real data-plane E2E over a REAL `SecureSession`
//! (X25519 + Ed25519 handshake, AES-256-GCM frames) with REAL disk I/O.
//!
//! Both protocol roles run as CONCURRENT tasks on the real duplex channel —
//! a sequential driver would deadlock once one window (megabytes) exceeds the
//! kernel socket buffer, which is itself the reason production callers must
//! pump both directions concurrently.
//!
//! 1. 50 MiB pseudo-random file, sliding-window streaming: exact byte count,
//!    SHA-256 identical, memory flat by construction (chunk-bounded buffers —
//!    the sender reads `chunk_size` at a time, the receiver writes `chunk_size`
//!    at a time; nothing in this path ever holds the whole file).
//! 2. Out-of-order arrival: chunks delivered reversed must land byte-exact
//!    via absolute-offset writes.
//! 3. Final-ACK loss: the receiver's first final ACK is dropped; the sender
//!    must recover through the retransmit path + the receiver's 30 s answer
//!    cache instead of hanging at 96–99%.

use luciola::link::secure::{accept_secure, connect_secure, SecureStream};
use luciola_transfer::protocol::{is_chunk_frame, FileAck, FileChunk};
use luciola_transfer::{FileReceiver, FileSender, ReceiverConfig, SenderConfig};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const MIB: usize = 1024 * 1024;

fn temp_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("luciola-e2e-{}-{}", std::process::id(), tag))
}

/// Deterministic pseudo-random file (xorshift64), written in 1 MiB blocks so
/// the generator itself never holds the whole image either. Returns SHA-256.
async fn write_pseudo_random(path: &std::path::Path, len: usize) -> [u8; 32] {
    let mut file = tokio::fs::File::create(path).await.unwrap();
    let mut hasher = Sha256::new();
    let mut state: u64 = 0x243F_6A88_85A3_08D3;
    let block_size = 1 * MIB;
    let mut written = 0usize;
    while written < len {
        let n = (len - written).min(block_size);
        let mut block = vec![0u8; n];
        for b in block.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state >> 24) as u8;
        }
        hasher.update(&block);
        file.write_all(&block).await.unwrap();
        written += n;
    }
    file.sync_data().await.unwrap();
    hasher.finalize().into()
}

/// Real handshake over loopback; returns (client, server) streams.
async fn secure_pair() -> (SecureStream, SecureStream) {
    let a = luciola::trust::generate_identity();
    let b = luciola::trust::generate_identity();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seed_b = b.seed.clone();
    let key_a = a.public_key.clone();
    let server = tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
    let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
        .await
        .expect("client handshake");
    let server = server.await.unwrap().expect("server handshake");
    (client, server)
}

/// SENDER role: slide the window, consume ACKs, retransmit on expiry.
/// Returns the final FileSender state (acked prefix / done).
async fn run_sender(mut client: SecureStream, mut tx: FileSender, tick: Duration) -> FileSender {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if tx.is_done() {
            return tx;
        }
        for chunk in tx.fill_window().await.unwrap() {
            client.send(&chunk.encode()).await.unwrap();
        }
        // Wait for the next ACK or the retransmit tick — whichever first.
        // ACKs always arrive (the server acks every chunk it writes) except
        // when one was dropped: the tick then rescues the window.
        //
        // `SecureStream::recv` is cancellation-safe (half-read frames stay in
        // its internal buffer), so select! is the intended pattern here.
        tokio::select! {
            frame = client.recv(&mut buf) => match frame {
                Ok(()) if !is_chunk_frame(&buf) => {
                    let ack = FileAck::decode(&buf).unwrap();
                    tx.on_ack(ack.acked_up_to);
                }
                Ok(()) => {} // a chunk on this side would be a driver bug
                Err(_) => return tx, // channel died; asserts below will fail
            },
            _ = tokio::time::sleep(tick) => {}
        }
        for chunk in tx.expired_in_flight().await.unwrap() {
            client.send(&chunk.encode()).await.unwrap();
        }
    }
}

/// RECEIVER role: write chunks at absolute offsets, ACK the contiguous
/// prefix; after completion serve retransmits from the answer cache until
/// the sender stops talking for `quiet` (then exit).
async fn run_receiver(
    mut server: SecureStream,
    mut rx: FileReceiver,
    quiet: Duration,
    drop_first_final_ack: bool,
) -> FileReceiver {
    let mut final_dropped = false;
    loop {
        let mut buf = Vec::new();
        if rx.is_complete() {
            // Answer-cache mode: exit when the sender went quiet.
            match tokio::time::timeout(quiet, server.recv(&mut buf)).await {
                Ok(Ok(())) => { /* serve below */ }
                _ => return rx,
            }
        } else {
            server.recv(&mut buf).await.unwrap();
        }
        if !is_chunk_frame(&buf) {
            continue;
        }
        let chunk = FileChunk::decode(&buf).unwrap();
        let acked = rx.on_chunk(&chunk).await.unwrap();
        let is_final = acked >= rx.total_size();
        if is_final && drop_first_final_ack && !final_dropped {
            final_dropped = true; // simulate the lost last ACK
            continue;
        }
        server
            .send(
                &FileAck {
                    transfer_id: chunk.transfer_id.clone(),
                    acked_up_to: acked,
                }
                .encode(),
            )
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_50mb_over_real_secure_session() {
    let dir = temp_root("50mb");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let src = dir.join("source.bin");
    let dest = dir.join("received.bin");

    const SIZE: usize = 50 * MIB; // 52,428,800 bytes
    let started = std::time::Instant::now();
    let source_sha = write_pseudo_random(&src, SIZE).await;
    let gen_done = started.elapsed();

    let (client, server) = secure_pair().await;

    let tx = FileSender::open(
        "e2e-50m",
        &src,
        SenderConfig {
            chunk_size: 256 * 1024,
            window: 8,
            retransmit_after: Duration::from_secs(2),
        },
    )
    .await
    .unwrap();
    assert_eq!(tx.total_size(), SIZE as u64);

    let rx = FileReceiver::create("e2e-50m", &dest, SIZE as u64, ReceiverConfig::default())
        .await
        .unwrap();

    let sender = tokio::spawn(run_sender(client, tx, Duration::from_millis(100)));
    let receiver = tokio::spawn(run_receiver(server, rx, Duration::from_millis(500), false));

    let tx = sender.await.unwrap();
    let rx = receiver.await.unwrap();
    let transfer_done = started.elapsed() - gen_done;

    assert!(tx.is_done());
    assert_eq!(tx.acked_up_to(), SIZE as u64, "every byte must be credited");
    assert_eq!(tx.in_flight_count(), 0);
    assert!(rx.is_complete());
    assert_eq!(
        tokio::fs::metadata(&dest).await.unwrap().len(),
        52_428_800u64,
        "received file must be exactly 50 MiB"
    );
    let rx_sha = rx.finalize().await.unwrap();
    assert_eq!(rx_sha, source_sha, "SHA-256 must match the source file");
    println!(
        "50 MiB over real secure channel: gen {:?}, transfer {:?}",
        gen_done, transfer_done
    );

    tokio::fs::remove_dir_all(&dir).await.ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn out_of_order_arrival_lands_byte_exact() {
    let dir = temp_root("ooo");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let src = dir.join("source.bin");
    let dest = dir.join("received.bin");

    const SIZE: usize = MIB; // 16 chunks of 64 KiB
    const CHUNK: usize = 64 * 1024;
    let source_sha = write_pseudo_random(&src, SIZE).await;

    let (mut client, mut server) = secure_pair().await;

    let mut tx = FileSender::open(
        "e2e-ooo",
        &src,
        SenderConfig {
            chunk_size: CHUNK,
            window: SIZE / CHUNK, // whole file in flight at once
            retransmit_after: Duration::from_secs(5),
        },
    )
    .await
    .unwrap();
    let mut rx = FileReceiver::create("e2e-ooo", &dest, SIZE as u64, ReceiverConfig::default())
        .await
        .unwrap();

    // Ship every chunk in REVERSE order (Block N-1 .. Block 0), one at a
    // time so the duplex channel never fills while nobody drains it.
    let mut chunks = tx.fill_window().await.unwrap();
    chunks.reverse();
    for chunk in &chunks {
        client.send(&chunk.encode()).await.unwrap();
        let mut buf = Vec::new();
        server.recv(&mut buf).await.unwrap();
        let got = FileChunk::decode(&buf).unwrap();
        let acked = rx.on_chunk(&got).await.unwrap();
        // The contiguous prefix only jumps when Block 0 (sent last) lands.
        if got.offset == 0 {
            assert_eq!(acked, SIZE as u64, "tail block completes the prefix");
        } else {
            assert_eq!(acked, 0, "no prefix credit before block 0 arrives");
        }
    }
    assert!(rx.is_complete(), "reversed chunks must still complete");

    // One final ack closes the sender out.
    server
        .send(
            &FileAck {
                transfer_id: "e2e-ooo".into(),
                acked_up_to: SIZE as u64,
            }
            .encode(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    client.recv(&mut buf).await.unwrap();
    tx.on_ack(FileAck::decode(&buf).unwrap().acked_up_to);
    assert!(tx.is_done());

    let rx_sha = rx.finalize().await.unwrap();
    assert_eq!(rx_sha, source_sha, "byte-exact after out-of-order arrival");
    tokio::fs::remove_dir_all(&dir).await.ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn final_ack_loss_recovers_via_answer_cache() {
    let dir = temp_root("ackloss");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let src = dir.join("source.bin");
    let dest = dir.join("received.bin");

    const SIZE: usize = 256 * 1024; // 4 chunks of 64 KiB
    const CHUNK: usize = 64 * 1024;
    let source_sha = write_pseudo_random(&src, SIZE).await;

    let (client, server) = secure_pair().await;

    let tx = FileSender::open(
        "e2e-ackloss",
        &src,
        SenderConfig {
            chunk_size: CHUNK,
            window: 8,
            retransmit_after: Duration::from_millis(120),
        },
    )
    .await
    .unwrap();
    let rx = FileReceiver::create("e2e-ackloss", &dest, SIZE as u64, ReceiverConfig::default())
        .await
        .unwrap();

    let started = std::time::Instant::now();
    let sender = tokio::spawn(run_sender(client, tx, Duration::from_millis(40)));
    let receiver = tokio::spawn(run_receiver(server, rx, Duration::from_millis(500), true));
    let tx = sender.await.unwrap();
    let rx = receiver.await.unwrap();
    let elapsed = started.elapsed();

    assert!(rx.is_complete());
    assert!(tx.is_done(), "sender must not hang at 96-99%");
    assert_eq!(tx.acked_up_to(), SIZE as u64);
    // The first final ACK was dropped, so progress MUST have taken the
    // retransmit path (> retransmit_after), then finished promptly.
    assert!(
        elapsed >= Duration::from_millis(120),
        "recovery must have gone through the retransmit path, took {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(10), "recovery must be prompt");

    let rx_sha = rx.finalize().await.unwrap();
    assert_eq!(rx_sha, source_sha);
    tokio::fs::remove_dir_all(&dir).await.ok();
}
