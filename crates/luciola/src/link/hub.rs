//! Single-port multi-peer authenticated hub (`SecureHub`).
//!
//! Leaves the existing single-slot [`crate::link::secure`] / FFI `SecureSession`
//! contract untouched while giving multi-device hosts (desktop relays, agent
//! hubs, LAN broadcast rooms) one dual-stack listener that serves N concurrent
//! trusted peers indexed by their verified Ed25519 fingerprint.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch, Semaphore};
use zeroize::Zeroizing;

use crate::link::bind_dual_stack_listener;
use crate::link::secure::secure_handshake_server_with_policy;

/// Bounded per-peer outbound queue so one stalled device never blocks others.
const PEER_OUTBOUND_QUEUE: usize = 64;
/// Handshake deadline for each inbound TCP connection.
const HUB_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum concurrent unauthenticated handshakes in flight (DoS bound).
const MAX_CONCURRENT_HANDSHAKES: usize = 64;
/// Maximum simultaneous authenticated peers tracked by one hub.
const MAX_CONNECTED_PEERS: usize = 256;
/// Upper bound on a single encrypted frame write so a zero-window peer cannot wedge a task.
const PEER_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Information about a peer currently connected to [`SecureHub`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubPeerInfo {
    /// Verified `sha256:<hex>` fingerprint of the peer's Ed25519 identity key.
    pub fingerprint: String,
    /// Raw 32-byte Ed25519 public key of the peer.
    pub public_key: Vec<u8>,
    /// Peer's TCP socket address.
    pub remote_addr: SocketAddr,
}

/// Events emitted by [`SecureHub`] to the host application.
#[derive(Debug, Clone)]
pub enum HubEvent {
    /// A peer completed the authenticated handshake and passed the trust check.
    PeerConnected(HubPeerInfo),
    /// A decrypted application frame arrived from a connected peer.
    Message {
        /// Verified sender fingerprint.
        fingerprint: String,
        /// Sender TCP socket address.
        remote_addr: SocketAddr,
        /// Decrypted payload bytes.
        payload: Vec<u8>,
    },
    /// A peer disconnected or was kicked.
    PeerDisconnected {
        /// Fingerprint of the disconnected peer.
        fingerprint: String,
    },
    /// An inbound connection was rejected by the trust gate or failed handshake.
    PeerRejected {
        /// Remote TCP socket address.
        remote_addr: SocketAddr,
        /// Human-readable reason.
        reason: String,
    },
}

struct PeerSlot {
    info: HubPeerInfo,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    kick_tx: watch::Sender<bool>,
}

struct HubState {
    stopped: bool,
    peers: HashMap<String, PeerSlot>,
}

/// Concurrent multi-peer authenticated TCP server on a single dual-stack port.
pub struct SecureHub {
    local_addr: SocketAddr,
    state: Arc<Mutex<HubState>>,
    event_tx: mpsc::Sender<HubEvent>,
    shutdown_tx: watch::Sender<bool>,
}

impl SecureHub {
    /// Bind `port` (`0` = OS ephemeral) and start accepting concurrent peers.
    ///
    /// `allow_peer` is evaluated against the initiator's 32-byte Ed25519 public
    /// key **before** the hub signs handshake message 2, upholding `SECURITY.md`
    /// pre-sign pin enforcement (untrusted peers learn neither our key nor any
    /// signature; deny by default).
    pub async fn start<F>(
        port: u16,
        identity_seed: Vec<u8>,
        allow_peer: F,
    ) -> std::io::Result<(Self, mpsc::Receiver<HubEvent>)>
    where
        F: Fn(&[u8]) -> bool + Send + Sync + 'static,
    {
        let listener = bind_dual_stack_listener(port).await?;
        let local_addr = listener.local_addr()?;
        let state: Arc<Mutex<HubState>> = Arc::new(Mutex::new(HubState {
            stopped: false,
            peers: HashMap::new(),
        }));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (event_tx, event_rx) = mpsc::channel(256);
        let allow_peer = Arc::new(allow_peer);
        let identity_seed = Arc::new(Zeroizing::new(identity_seed));
        let handshake_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES));

        let accept_state = state.clone();
        let accept_shutdown = shutdown_tx.clone();
        let accept_events = event_tx.clone();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                    res = listener.accept() => match res {
                        Ok(pair) => pair,
                        Err(err) => {
                            tracing::debug!("secure hub accept error: {err}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    }
                };

                let (socket, remote_addr) = accepted;
                let Ok(permit) = handshake_slots.clone().try_acquire_owned() else {
                    drop(socket);
                    let _ = accept_events.try_send(HubEvent::PeerRejected {
                        remote_addr,
                        reason: "handshake concurrency limit reached".into(),
                    });
                    continue;
                };
                let _ = socket.set_nodelay(true);
                let seed = identity_seed.clone();
                let allow = allow_peer.clone();
                let hub_state = accept_state.clone();
                let events = accept_events.clone();
                let mut hub_shutdown = accept_shutdown.subscribe();

                tokio::spawn(async move {
                    if *hub_shutdown.borrow() {
                        drop(permit);
                        return;
                    }
                    let allow_for_hs = allow.clone();
                    let hs = tokio::select! {
                        _ = hub_shutdown.changed() => {
                            if *hub_shutdown.borrow() {
                                drop(permit);
                                return;
                            }
                            drop(permit);
                            return;
                        }
                        r = tokio::time::timeout(
                            HUB_HANDSHAKE_TIMEOUT,
                            secure_handshake_server_with_policy(
                                socket,
                                remote_addr,
                                &seed,
                                move |pk| allow_for_hs(pk),
                            ),
                        ) => r,
                    };
                    // Release handshake concurrency permit immediately once handshake completes.
                    drop(permit);

                    let mut stream = match hs {
                        Ok(Ok(s)) => s,
                        Ok(Err(err)) => {
                            let _ = events.try_send(HubEvent::PeerRejected {
                                remote_addr,
                                reason: err.to_string(),
                            });
                            return;
                        }
                        Err(_) => {
                            let _ = events.try_send(HubEvent::PeerRejected {
                                remote_addr,
                                reason: "handshake timeout".into(),
                            });
                            return;
                        }
                    };

                    let fp = stream.peer_fingerprint();
                    let info = HubPeerInfo {
                        fingerprint: fp.clone(),
                        public_key: stream.peer_public_key.clone(),
                        remote_addr,
                    };
                    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_QUEUE);
                    let (kick_tx, mut kick_rx) = watch::channel(false);

                    // Enforce shutdown state and max peer capacity under the same lock
                    // so `hub.stop()` can never race past an insert and leak a slot.
                    let insert_res = {
                        let mut guard = hub_state.lock().unwrap();
                        if guard.stopped {
                            Err(None)
                        } else if !guard.peers.contains_key(&fp)
                            && guard.peers.len() >= MAX_CONNECTED_PEERS
                        {
                            Err(Some("max connected peers reached"))
                        } else {
                            Ok(guard.peers.insert(
                                fp.clone(),
                                PeerSlot {
                                    info: info.clone(),
                                    outbound_tx: out_tx.clone(),
                                    kick_tx: kick_tx.clone(),
                                },
                            ))
                        }
                    };
                    let replaced = match insert_res {
                        Ok(old) => old,
                        Err(reason) => {
                            let _ = stream.shutdown().await;
                            if let Some(msg) = reason {
                                let _ = events.try_send(HubEvent::PeerRejected {
                                    remote_addr,
                                    reason: msg.into(),
                                });
                            }
                            return;
                        }
                    };
                    if let Some(old) = replaced {
                        let _ = old.kick_tx.send(true);
                    }

                    let announced = tokio::select! {
                        r = events.send(HubEvent::PeerConnected(info)) => r.is_ok(),
                        _ = hub_shutdown.changed() => false,
                        _ = kick_rx.changed() => false,
                    };

                    if announced && !*hub_shutdown.borrow() && !*kick_rx.borrow() {
                        let mut buf = Vec::new();
                        loop {
                            tokio::select! {
                                _ = hub_shutdown.changed() => {
                                    if *hub_shutdown.borrow() {
                                        let _ = stream.shutdown().await;
                                        break;
                                    }
                                }
                                _ = kick_rx.changed() => {
                                    if *kick_rx.borrow() {
                                        let _ = stream.shutdown().await;
                                        break;
                                    }
                                }
                                msg = out_rx.recv() => match msg {
                                    Some(bytes) => {
                                        let sent = tokio::select! {
                                            r = tokio::time::timeout(PEER_WRITE_TIMEOUT, stream.send(&bytes)) => {
                                                matches!(r, Ok(Ok(())))
                                            }
                                            _ = hub_shutdown.changed() => false,
                                            _ = kick_rx.changed() => false,
                                        };
                                        if !sent {
                                            let _ = stream.shutdown().await;
                                            break;
                                        }
                                    }
                                    None => break,
                                },
                                frame = stream.recv(&mut buf) => match frame {
                                    Ok(()) => {
                                        if !buf.is_empty() {
                                            let delivered = tokio::select! {
                                                r = events.send(HubEvent::Message {
                                                    fingerprint: fp.clone(),
                                                    remote_addr,
                                                    payload: buf.clone(),
                                                }) => r.is_ok(),
                                                _ = hub_shutdown.changed() => false,
                                                _ = kick_rx.changed() => false,
                                            };
                                            if !delivered {
                                                break;
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    } else {
                        let _ = stream.shutdown().await;
                    }

                    // Remove only if this task still owns the current slot for `fp`.
                    let removed_self = {
                        let mut guard = hub_state.lock().unwrap();
                        let same_slot = guard
                            .peers
                            .get(&fp)
                            .is_some_and(|slot| slot.outbound_tx.same_channel(&out_tx));
                        if same_slot {
                            guard.peers.remove(&fp);
                            true
                        } else {
                            false
                        }
                    };
                    if removed_self {
                        let _ = events.try_send(HubEvent::PeerDisconnected { fingerprint: fp });
                    }
                });
            }
        });

        Ok((
            Self {
                local_addr,
                state,
                event_tx,
                shutdown_tx,
            },
            event_rx,
        ))
    }

    /// Actual listening socket address (useful when started with port `0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Snapshot of currently connected peers.
    pub fn connected_peers(&self) -> Vec<HubPeerInfo> {
        self.state
            .lock()
            .unwrap()
            .peers
            .values()
            .map(|slot| slot.info.clone())
            .collect()
    }

    /// Queue a frame for one connected peer (`false` if disconnected or backpressured).
    pub fn send_to(&self, fingerprint: &str, payload: Vec<u8>) -> bool {
        let tx = self
            .state
            .lock()
            .unwrap()
            .peers
            .get(fingerprint)
            .map(|slot| slot.outbound_tx.clone());
        tx.is_some_and(|ch| ch.try_send(payload).is_ok())
    }

    /// Broadcast a frame to every connected peer. Returns fingerprints whose
    /// send queue rejected the frame (backpressured or closing).
    pub fn broadcast(&self, payload: &[u8]) -> Vec<String> {
        let targets: Vec<(String, mpsc::Sender<Vec<u8>>)> = self
            .state
            .lock()
            .unwrap()
            .peers
            .iter()
            .map(|(fp, slot)| (fp.clone(), slot.outbound_tx.clone()))
            .collect();
        let mut failed = Vec::new();
        for (fp, tx) in targets {
            if tx.try_send(payload.to_vec()).is_err() {
                failed.push(fp);
            }
        }
        failed
    }

    /// Disconnect one connected peer by fingerprint and emit [`HubEvent::PeerDisconnected`].
    pub fn kick(&self, fingerprint: &str) -> bool {
        let slot = self.state.lock().unwrap().peers.remove(fingerprint);
        if let Some(s) = slot {
            let _ = s.kick_tx.send(true);
            let _ = self.event_tx.try_send(HubEvent::PeerDisconnected {
                fingerprint: fingerprint.to_string(),
            });
            true
        } else {
            false
        }
    }

    /// Stop accepting new peers and disconnect every active peer.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let slots: Vec<PeerSlot> = {
            let mut guard = self.state.lock().unwrap();
            guard.stopped = true;
            guard.peers.drain().map(|(_, s)| s).collect()
        };
        for s in slots {
            let _ = s.kick_tx.send(true);
        }
    }
}

impl Drop for SecureHub {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::secure::connect_secure;
    use crate::trust::{fingerprint, generate_identity};
    use std::collections::HashSet;

    #[tokio::test(flavor = "multi_thread")]
    async fn hub_serves_multiple_trusted_peers_and_rejects_untrusted() {
        let hub_id = generate_identity();
        let peer_a = generate_identity();
        let peer_b = generate_identity();
        let peer_c = generate_identity();
        let stranger = generate_identity();

        let allowed: HashSet<Vec<u8>> = [
            peer_a.public_key.clone(),
            peer_b.public_key.clone(),
            peer_c.public_key.clone(),
        ]
        .into_iter()
        .collect();

        let (hub, mut events) =
            SecureHub::start(0, hub_id.seed.clone(), move |pk| allowed.contains(pk))
                .await
                .expect("hub start");
        let port = hub.local_addr().port();

        let mut sa = connect_secure("127.0.0.1", port, &peer_a.seed, &hub_id.public_key)
            .await
            .unwrap();
        let mut sb = connect_secure("127.0.0.1", port, &peer_b.seed, &hub_id.public_key)
            .await
            .unwrap();
        let mut sc = connect_secure("127.0.0.1", port, &peer_c.seed, &hub_id.public_key)
            .await
            .unwrap();

        // Untrusted peer is rejected BEFORE message 2 is signed (pre-sign pin invariant).
        let bad = connect_secure("127.0.0.1", port, &stranger.seed, &hub_id.public_key).await;
        assert!(
            bad.is_err(),
            "untrusted peer must be dropped during handshake before signature"
        );

        // Wait until all 3 trusted peers are registered.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while hub.connected_peers().len() < 3 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Targeted send to peer B only.
        let fp_b = fingerprint(&peer_b.public_key);
        assert!(hub.send_to(&fp_b, b"only-for-b".to_vec()));
        let mut got_b = Vec::new();
        sb.recv(&mut got_b).await.unwrap();
        assert_eq!(&got_b, b"only-for-b");

        // Broadcast reaches all 3 peers simultaneously.
        let failed = hub.broadcast(b"hello-all");
        assert!(failed.is_empty(), "broadcast failed: {failed:?}");
        for s in [&mut sa, &mut sb, &mut sc] {
            let mut got = Vec::new();
            s.recv(&mut got).await.unwrap();
            assert_eq!(&got, b"hello-all");
        }

        // Inbound message from peer A reaches hub event channel with verified fingerprint.
        sa.send(b"from-a").await.unwrap();
        let fp_a = fingerprint(&peer_a.public_key);
        let mut saw_from_a = false;
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(2), events.recv()).await {
            if let HubEvent::Message {
                fingerprint,
                payload,
                ..
            } = ev
            {
                if fingerprint == fp_a && payload == b"from-a" {
                    saw_from_a = true;
                    break;
                }
            }
        }
        assert!(saw_from_a);

        // Kicking peer C drops its slot.
        let fp_c = fingerprint(&peer_c.public_key);
        assert!(hub.kick(&fp_c));
        hub.stop();
    }
}
