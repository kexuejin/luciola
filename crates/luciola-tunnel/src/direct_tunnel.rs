//! Direct-stream tunnel session (`DirectTunnelSession`).
//!
//! Unlike [`crate::tunnel_link::TunnelLink`], which owns the D8 dual-port LAN
//! model (`secure_port + 1`), `DirectTunnelSession` wraps **one already
//! established `SecureStream`** (for example from `luciola::wan::connect_wan`
//! or a single direct TCP link) and runs [`MuxSession`] + the existing TCP/UDP
//! forward guards directly over it without touching the LAN D8 contract.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use luciola::link::secure::SecureStream;
use luciola_proto::ChannelType;

use crate::forward::{
    start_forward_endpoint, start_local_forward, start_remote_forward, start_udp_forward,
    ForwardAcl, ForwardEndpointGuard, ForwardRule, LocalForwardConfig, LocalForwardGuard,
    UdpForwardConfig, UdpForwardGuard,
};
use crate::mux::{DialTarget, MuxConfig, MuxSession, Role};
use crate::tunnel_link::{ForwardKind, ForwardStat};
use crate::TunnelError;

struct DirectTunnelState {
    closed: bool,
    local_tcp: BTreeMap<u16, LocalForwardGuard>,
    local_udp: BTreeMap<u16, UdpForwardGuard>,
    remote_tcp: BTreeMap<u16, LocalForwardGuard>,
    endpoint: Option<ForwardEndpointGuard>,
}

/// Port-forwarding session running over one pre-established [`SecureStream`].
pub struct DirectTunnelSession {
    mux: Arc<MuxSession>,
    channel_type: ChannelType,
    state: Mutex<DirectTunnelState>,
    /// Serializes async endpoint replacement/disable calls so two concurrent
    /// callers cannot spawn overlapping `ForwardEndpointGuard`s on the same mux.
    endpoint_op: tokio::sync::Mutex<()>,
}

impl DirectTunnelSession {
    /// Start a multiplexed tunnel over `stream`. Must be called inside a Tokio runtime.
    pub fn start(stream: SecureStream, role: Role, cfg: MuxConfig) -> Self {
        let channel_type = stream.channel_type();
        let mux = Arc::new(MuxSession::start(stream, role, cfg));
        Self {
            mux,
            channel_type,
            state: Mutex::new(DirectTunnelState {
                closed: false,
                local_tcp: BTreeMap::new(),
                local_udp: BTreeMap::new(),
                remote_tcp: BTreeMap::new(),
                endpoint: None,
            }),
            endpoint_op: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether the underlying [`MuxSession`] is still alive.
    pub fn is_alive(&self) -> bool {
        self.mux.is_alive()
    }

    /// Underlying transport plane recorded when the stream was attached.
    pub fn channel_type(&self) -> ChannelType {
        self.channel_type
    }

    /// Access the underlying [`MuxSession`] directly.
    pub fn mux(&self) -> &Arc<MuxSession> {
        &self.mux
    }

    /// Bind `127.0.0.1:listen_port` locally (`0` = OS ephemeral) and forward TCP
    /// connections over the mux to `target` on the peer. Returns the actual bound port.
    pub fn start_local_forward(
        &self,
        listen_port: u16,
        target: DialTarget,
    ) -> Result<u16, TunnelError> {
        if self.state.lock().unwrap().closed {
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        let cfg = LocalForwardConfig {
            listen_port,
            target,
        };
        let guard = start_local_forward(self.mux.clone(), cfg)?;
        let actual_port = guard.local_addr().port();
        let mut state = self.state.lock().unwrap();
        if state.closed {
            drop(guard);
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        state.local_tcp.insert(actual_port, guard);
        Ok(actual_port)
    }

    /// Stop a local TCP forward previously started on `listen_port`.
    pub async fn stop_local_forward(&self, listen_port: u16) -> bool {
        let guard = self.state.lock().unwrap().local_tcp.remove(&listen_port);
        if let Some(g) = guard {
            g.stop().await;
            true
        } else {
            false
        }
    }

    /// Bind `127.0.0.1:listen_port` locally for UDP forwarding over mux v2 datagrams.
    pub fn start_udp_forward(
        &self,
        listen_port: u16,
        target: DialTarget,
    ) -> Result<u16, TunnelError> {
        if self.state.lock().unwrap().closed {
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        let cfg = UdpForwardConfig {
            listen_port,
            target,
        };
        let guard = start_udp_forward(self.mux.clone(), cfg)?;
        let actual_port = guard.local_addr().port();
        let mut state = self.state.lock().unwrap();
        if state.closed {
            drop(guard);
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        state.local_udp.insert(actual_port, guard);
        Ok(actual_port)
    }

    /// Stop a local UDP forward previously started on `listen_port`.
    pub async fn stop_udp_forward(&self, listen_port: u16) -> bool {
        let guard = self.state.lock().unwrap().local_udp.remove(&listen_port);
        if let Some(g) = guard {
            g.stop().await;
            true
        } else {
            false
        }
    }

    /// Bind `127.0.0.1:listen_port` on the responder side and forward back (`-R`)
    /// to `target` on the peer.
    pub fn start_remote_forward(
        &self,
        listen_port: u16,
        target: DialTarget,
    ) -> Result<u16, TunnelError> {
        if self.state.lock().unwrap().closed {
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        let cfg = LocalForwardConfig {
            listen_port,
            target,
        };
        let guard = start_remote_forward(self.mux.clone(), cfg)?;
        let actual_port = guard.local_addr().port();
        let mut state = self.state.lock().unwrap();
        if state.closed {
            drop(guard);
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        state.remote_tcp.insert(actual_port, guard);
        Ok(actual_port)
    }

    /// Stop a remote TCP forward previously started on `listen_port`.
    pub async fn stop_remote_forward(&self, listen_port: u16) -> bool {
        let guard = self.state.lock().unwrap().remote_tcp.remove(&listen_port);
        if let Some(g) = guard {
            g.stop().await;
            true
        } else {
            false
        }
    }

    /// Enable or replace the inbound ACL forward endpoint (`--allow`).
    pub async fn enable_forward_endpoint(
        &self,
        rules: Vec<ForwardRule>,
    ) -> Result<(), TunnelError> {
        if rules.is_empty() {
            return Err(TunnelError::InvalidRule(
                "at least one forward rule is required".into(),
            ));
        }
        for r in &rules {
            if r.port_from == 0 || r.port_from > r.port_to {
                return Err(TunnelError::InvalidRule(format!(
                    "invalid port range: {}-{}",
                    r.port_from, r.port_to
                )));
            }
        }
        let _op_guard = self.endpoint_op.lock().await;
        let prev = {
            let mut s = self.state.lock().unwrap();
            if s.closed {
                return Err(TunnelError::Stopped(
                    "DirectTunnelSession has been shut down".into(),
                ));
            }
            s.endpoint.take()
        };
        if let Some(old) = prev {
            old.stop().await;
        }
        let guard = start_forward_endpoint(self.mux.clone(), ForwardAcl::new(rules))?;
        let closed = {
            let mut s = self.state.lock().unwrap();
            if s.closed {
                true
            } else {
                s.endpoint = Some(guard);
                false
            }
        };
        if closed {
            return Err(TunnelError::Stopped(
                "DirectTunnelSession has been shut down".into(),
            ));
        }
        Ok(())
    }

    /// Disable the inbound ACL forward endpoint.
    pub async fn disable_forward_endpoint(&self) {
        let _op_guard = self.endpoint_op.lock().await;
        let prev = self.state.lock().unwrap().endpoint.take();
        if let Some(old) = prev {
            old.stop().await;
        }
    }

    /// Snapshot active forward statistics.
    pub fn stats(&self) -> Vec<ForwardStat> {
        let alive = self.mux.is_alive();
        let state = self.state.lock().unwrap();
        let mut out = Vec::new();
        for (&port, g) in &state.local_tcp {
            out.push(ForwardStat {
                active: alive,
                listen_port: port,
                status: g.status(),
                kind: ForwardKind::Local,
            });
        }
        for (&port, g) in &state.local_udp {
            out.push(ForwardStat {
                active: alive,
                listen_port: port,
                status: g.status(),
                kind: ForwardKind::UdpLocal,
            });
        }
        for (&port, g) in &state.remote_tcp {
            out.push(ForwardStat {
                active: alive,
                listen_port: port,
                status: g.status(),
                kind: ForwardKind::Remote,
            });
        }
        if let Some(ep) = &state.endpoint {
            out.push(ForwardStat {
                active: alive,
                listen_port: 0,
                status: ep.status(),
                kind: ForwardKind::Endpoint,
            });
        }
        out
    }

    /// Tear down all active forwards and shut down the underlying [`MuxSession`].
    pub async fn shutdown(&self) {
        let (locals, udps, remotes, ep) = {
            let mut s = self.state.lock().unwrap();
            s.closed = true;
            (
                std::mem::take(&mut s.local_tcp),
                std::mem::take(&mut s.local_udp),
                std::mem::take(&mut s.remote_tcp),
                s.endpoint.take(),
            )
        };
        for (_, g) in locals {
            g.stop().await;
        }
        for (_, g) in udps {
            g.stop().await;
        }
        for (_, g) in remotes {
            g.stop().await;
        }
        if let Some(ep) = ep {
            ep.stop().await;
        }
        self.mux.shutdown();
    }
}

impl Drop for DirectTunnelSession {
    fn drop(&mut self) {
        if let Ok(mut s) = self.state.lock() {
            s.closed = true;
            s.local_tcp.clear();
            s.local_udp.clear();
            s.remote_tcp.clear();
            s.endpoint = None;
        }
        self.mux.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luciola::link::secure::{accept_secure, connect_secure};
    use luciola::trust::generate_identity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn secure_pair() -> (SecureStream, SecureStream) {
        let a = generate_identity();
        let b = generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server = tokio::spawn(async move {
            accept_secure(&listener, &seed_b, Some(&key_a))
                .await
                .unwrap()
        });
        let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .unwrap();
        (client, server.await.unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_tunnel_forwards_allowed_tcp_and_rejects_disallowed_port() {
        // Spin up a tiny echo service on the responder side.
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let (client_stream, server_stream) = secure_pair().await;
        let initiator =
            DirectTunnelSession::start(client_stream, Role::Initiator, MuxConfig::default());
        let responder =
            DirectTunnelSession::start(server_stream, Role::Responder, MuxConfig::default());

        // Allow only `echo_port`.
        let rule = ForwardRule::parse(&format!("127.0.0.1:{echo_port}")).unwrap();
        responder.enable_forward_endpoint(vec![rule]).await.unwrap();

        let bound_port = initiator
            .start_local_forward(0, DialTarget::new("127.0.0.1", echo_port))
            .unwrap();

        // Allowed port roundtrips cleanly.
        let mut conn = TcpStream::connect(("127.0.0.1", bound_port)).await.unwrap();
        conn.write_all(b"ping-direct-tunnel").await.unwrap();
        let mut reply = [0u8; 18];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping-direct-tunnel");

        // Disallowed port is refused by ACL (connection closes with 0 bytes).
        let blocked_port = initiator
            .start_local_forward(
                0,
                DialTarget::new("127.0.0.1", echo_port.wrapping_add(1).max(1025)),
            )
            .unwrap();
        let mut blocked = TcpStream::connect(("127.0.0.1", blocked_port))
            .await
            .unwrap();
        let mut probe = [0u8; 8];
        let n = blocked.read(&mut probe).await.unwrap_or(0);
        assert_eq!(n, 0, "disallowed target must be closed by ACL");

        assert!(initiator.is_alive());
        assert!(!initiator.stats().is_empty());

        initiator.shutdown().await;
        responder.shutdown().await;
        echo_task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_tunnel_rejects_forwards_after_shutdown_and_drop_closes_mux() {
        let (client_stream, server_stream) = secure_pair().await;
        let initiator =
            DirectTunnelSession::start(client_stream, Role::Initiator, MuxConfig::default());
        let responder =
            DirectTunnelSession::start(server_stream, Role::Responder, MuxConfig::default());

        let initiator_mux = initiator.mux().clone();
        initiator.shutdown().await;
        assert!(!initiator_mux.is_alive());
        let err = initiator
            .start_local_forward(0, DialTarget::new("127.0.0.1", 8080))
            .expect_err("start_local_forward after shutdown must fail");
        assert!(matches!(err, TunnelError::Stopped(_)), "{err}");

        let responder_mux = responder.mux().clone();
        assert!(responder_mux.is_alive());
        drop(responder);
        assert!(
            !responder_mux.is_alive(),
            "dropping DirectTunnelSession must shut down underlying mux"
        );
    }
}
