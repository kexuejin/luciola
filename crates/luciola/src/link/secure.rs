//! Authenticated encrypted channels — the "door" for the trust primitives in
//! [`crate::trust`].
//!
//! The channel is **transport-agnostic**: the socket is a boxed
//! [`AsyncRead`] + [`AsyncWrite`] byte stream. LAN peers still use TCP; WAN
//! peers use a reliable-ordered UDP stream (the `wan::udp` ARQ adapter) or a
//! WebSocket relay adapter. Every transport must deliver bytes **in order**:
//! the AES-256-GCM frame nonce is a strictly increasing counter, so a datagram
//! transport that exposed reordering directly would break authentication.
//!
//! Handshake (SIGMA-like, 1.5 round trips, all RustCrypto primitives):
//!
//! ```text
//! I -> R : eph_pub_i (32)  nonce_i (16)  pub_i (32)
//! R -> I : eph_pub_r (32)  nonce_r (16)  sig_r (64)      // sig over transcript
//! I -> R : sig_i (64)
//! key    : HKDF-SHA256(X25519(eph_i, eph_r), salt = nonce_i||nonce_r,
//!                      info = ctx || fp_i || fp_r)
//! frames : [u32 ct_len][AES-256-GCM(ct, nonce = counter)]
//! ```
//!
//! Both signatures cover the full transcript (ephemeral keys, nonces, both
//! identity fingerprints), which binds the session to both identities and
//! prevents unknown-key-share. The initiator always dials with a PINNED peer
//! key (`deny by default`); a listener may capture the peer key on first use
//! (`expected_peer = None`) and hand it to the embedder for TOFU pinning.
//!
//! Replay defense: per-direction strictly increasing frame counters feed the
//! GCM nonce; duplicate or regressing counters abort the stream.

use crate::trust;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

const PROTOCOL_CONTEXT: &[u8] = b"luciola-link-v1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const PUB_LEN: usize = 32;
const SIG_LEN: usize = 64;
/// Largest plaintext frame accepted (guards against length-field DoS).
pub const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// An ordered, full-duplex byte stream usable as a secure-channel transport.
///
/// This is the **only** contract `SecureStream` puts on its transport. TCP,
/// the reliable UDP adapter and the WebSocket relay adapter all implement it.
/// Deliberately a single non-auto supertrait so it is object-safe; `Send` is
/// required because bindings move channels between runtimes.
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Object-safe wrapper that keeps the concrete transport behind `SecureStream`.
///
/// Implementing `AsyncRead`/`AsyncWrite` explicitly (rather than relying on
/// tokio's `Box<T>` blanket impl) makes the object-safety requirement visible
/// at the type boundary and keeps `poll_*` forwarding cancellation-safe.
pub struct ErasedStream {
    inner: Box<dyn ByteStream>,
    remote: Option<SocketAddr>,
}

impl ErasedStream {
    /// Wrap any ordered byte stream, recording its remote endpoint for
    /// diagnostics (the WAN adapters know it even without a TCP socket).
    pub fn new<S>(socket: S, remote: Option<SocketAddr>) -> Self
    where
        S: ByteStream + 'static,
    {
        Self {
            inner: Box::new(socket),
            remote,
        }
    }

    /// Remote endpoint, when the transport has one.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote
    }

    /// Replace the recorded remote endpoint (used after hole punching resolves
    /// the peer's reflexive address).
    pub fn set_remote_addr(&mut self, remote: SocketAddr) {
        self.remote = Some(remote);
    }
}

impl AsyncRead for ErasedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ErasedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

/// How long the LISTENING side waits for the initiator's first flight.
///
/// Without this a client that connects and then sends nothing (a different
/// protocol, a stuck build, a scanner) held the accept slot forever: the
/// listener serves one session at a time, so the legitimate peer queued in
/// the kernel backlog never got in (2026-11-02, Firefly dialling a Tidings
/// port with its own wire format). Five seconds is far above a LAN handshake
/// and short enough that the next peer gets the slot.
pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long the DIALING side waits for the responder's flight.
///
/// Longer than `DEFAULT_HANDSHAKE_TIMEOUT` on purpose: a dialer may sit in the
/// listener's backlog while the listener is recycling a stale session, so it
/// must out-wait the server-side timeout instead of giving up at the same
/// instant (that would turn a recoverable queue into a reconnect storm).
pub const DEFAULT_DIAL_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// single read chunk (each read is a cancellation point)
const READ_CHUNK: usize = 64 * 1024;

/// Errors raised while establishing or reading an authenticated secure link.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum LinkError {
    /// An operating-system I/O failure on the underlying socket.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The authenticated handshake failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// The peer presented a key that does not match the pinned identity.
    #[error("peer key mismatch (untrusted device)")]
    UntrustedPeer,
    /// AEAD verification failed: a frame was tampered with or the key is wrong.
    #[error("tampering detected: {0}")]
    Tamper(String),
}

fn transcript(
    eph_i: &[u8],
    eph_r: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    fp_i: &str,
    fp_r: &str,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(200);
    t.extend_from_slice(PROTOCOL_CONTEXT);
    t.extend_from_slice(eph_i);
    t.extend_from_slice(eph_r);
    t.extend_from_slice(nonce_i);
    t.extend_from_slice(nonce_r);
    t.extend_from_slice(fp_i.as_bytes());
    t.extend_from_slice(fp_r.as_bytes());
    t
}

fn derive_keys(
    shared: &[u8; 32],
    nonce_i: &[u8],
    nonce_r: &[u8],
    fp_i: &str,
    fp_r: &str,
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let salt = [nonce_i, nonce_r].concat();
    let mut info = Vec::new();
    info.extend_from_slice(PROTOCOL_CONTEXT);
    info.extend_from_slice(fp_i.as_bytes());
    info.extend_from_slice(fp_r.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 2 * KEY_LEN];
    hk.expand(&info, &mut okm).expect("okm length is fixed");
    let mut send = [0u8; KEY_LEN];
    let mut recv = [0u8; KEY_LEN];
    send.copy_from_slice(&okm[..KEY_LEN]);
    recv.copy_from_slice(&okm[KEY_LEN..]);
    use zeroize::Zeroize;
    okm.zeroize();
    (send, recv)
}

/// An established, mutually authenticated, encrypted channel.
pub struct SecureStream {
    socket: ErasedStream,
    send_cipher: Aes256Gcm,
    recv_cipher: Aes256Gcm,
    send_counter: AtomicU64,
    recv_counter: u64,
    /// 已从 socket 读出、尚未解出完整帧的字节（半帧状态）。
    ///
    /// 必须留在结构体里而不是局部变量：调用方在 `tokio::select!` 里 poll `recv`，
    /// 别的分支先完成就会 drop 这个 future —— 状态放在局部变量里就丢了。
    in_buf: Vec<u8>,
    /// Peer's Ed25519 public key, verified during the handshake.
    pub peer_public_key: Vec<u8>,
    channel_type: crate::proto::ChannelType,
    channel_tracker: Option<Arc<AtomicU8>>,
    /// Set once hole punching has resolved (succeeded or given up). When
    /// present, `wait_channel_settle` stops waiting the instant the routing
    /// decision is final instead of burning its whole timeout.
    migration_gate: Option<Arc<AtomicBool>>,
}

impl SecureStream {
    /// Returns the underlying transport channel type.
    pub fn channel_type(&self) -> crate::proto::ChannelType {
        if let Some(ref tracker) = self.channel_tracker {
            // Decode through the enum so inserting a variant cannot silently
            // relabel an existing code.
            if let Some(live) = crate::proto::ChannelType::from_u8(tracker.load(Ordering::Acquire))
            {
                return live;
            }
        }
        self.channel_type
    }

    /// Sets the underlying transport channel type.
    pub fn set_channel_type(&mut self, channel: crate::proto::ChannelType) {
        self.channel_type = channel;
    }

    /// Attach an atomic channel tracker so that dynamic transport migrations
    /// update the reported channel type in real time.
    pub fn set_channel_tracker(&mut self, tracker: Arc<AtomicU8>) {
        self.channel_tracker = Some(tracker);
    }

    /// Attach the "punching resolved" flag set by the progressive driver once
    /// hole punching has definitively succeeded or failed. Without it,
    /// `wait_channel_settle` can only wait out its timeout; with it, a caller
    /// learns the final route the moment the decision is made (see
    /// [`SecureStream::wait_channel_settle`]).
    pub fn set_migration_gate(&mut self, gate: Arc<AtomicBool>) {
        self.migration_gate = Some(gate);
    }

    /// Whether the transport can still change underneath this stream.
    ///
    /// True for a progressive WAN connection, which starts on the relay and
    /// may migrate to a direct path a few hundred milliseconds later.
    pub fn may_migrate(&self) -> bool {
        self.channel_tracker.is_some()
    }

    /// Wait, bounded, for the channel type to settle.
    ///
    /// Any decision taken on `channel_type` — quota, UI, telemetry — should be
    /// taken on the value the connection actually settles on. Returns as soon
    /// as the tracker changes, or the current value once `timeout` elapses (a
    /// progressive connection whose punch fails stays on the relay, and that is
    /// a legitimate final answer).
    ///
    /// Takes `&mut self` on purpose: the transport is `Box<dyn ByteStream>`,
    /// which is `Send` but not `Sync`, so a future holding `&self` cannot be
    /// spawned. `&mut` keeps the method usable from inside a spawned driver.
    pub async fn wait_channel_settle(&mut self, timeout: Duration) -> crate::proto::ChannelType {
        let Some(tracker) = self.channel_tracker.clone() else {
            return self.channel_type();
        };
        let initial = tracker.load(Ordering::Acquire);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tracker.load(Ordering::Acquire) != initial {
                break;
            }
            // The routing decision is final the instant punching resolves: a
            // connection that failed to punch stays on the relay, and one that
            // succeeded has already flipped the tracker. Returning here instead
            // of on the deadline is what keeps a slow-but-successful hard-NAT
            // punch from being misjudged on its transient relay hop.
            if let Some(gate) = &self.migration_gate {
                if gate.load(Ordering::Acquire) {
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.channel_type()
    }

    /// Send one encrypted frame.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), LinkError> {
        let counter = self.send_counter.fetch_add(1, Ordering::SeqCst);
        write_frame(&mut self.socket, &self.send_cipher, counter, plaintext).await
    }

    /// Receive one encrypted frame.
    ///
    /// # 取消安全（这是本函数存在的关键原因）
    ///
    /// 调用方在 `tokio::select!` 里 poll 这个 future，**任何别的分支先完成都会把它
    /// 直接 drop**。原来的实现用两次 `read_exact`（先 4 字节长度、再密文），而
    /// `read_exact` 不是取消安全的：它内部循环读，被 drop 时**已经读出来的字节就丢了**。
    ///
    /// 后果（2026-10-27 实测，50MB 通道验收）：下一次 `recv` 会把密文的头 4 字节当成
    /// 长度前缀 → 长度越界 / GCM 认证失败 → 连接 `break` → 重连；
    /// 应用层看到的是"JVM 侧 send() 成功 11776 次，Rust 真正发出只有 941 帧"。
    ///
    /// 现在改成：**只在自己累积的缓冲上解析**，读用单次 `read()`（取消安全：要么
    /// 完成、要么一个字节都没消费），半帧状态留在 `in_buf` 里，下次接着解析。
    pub async fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), LinkError> {
        self.recv_counter = read_frame(
            &mut self.socket,
            &self.recv_cipher,
            self.recv_counter,
            &mut self.in_buf,
            buf,
        )
        .await?;
        Ok(())
    }

    /// `sha256:<hex>` fingerprint of the peer's Ed25519 identity key.
    pub fn peer_fingerprint(&self) -> String {
        trust::fingerprint(&self.peer_public_key)
    }

    /// Remote endpoint of the underlying transport, when known.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.socket.remote_addr()
    }

    /// Record the remote endpoint (WAN adapters resolve it during punching).
    pub fn set_remote_addr(&mut self, remote: SocketAddr) {
        self.socket.set_remote_addr(remote);
    }

    /// Graceful shutdown of the outbound direction (supervisor disconnect).
    pub async fn shutdown(&mut self) -> io::Result<()> {
        AsyncWriteExt::shutdown(&mut self.socket).await
    }

    /// Wrap an already-established ordered byte stream in the secure frame
    /// codec. Used by the WAN orchestration after a transport is punched or a
    /// relay bridge is opened; cryptographic state comes from the handshake.
    pub fn from_erased_parts(
        socket: ErasedStream,
        send_cipher: Aes256Gcm,
        recv_cipher: Aes256Gcm,
        peer_public_key: Vec<u8>,
        channel_type: crate::proto::ChannelType,
    ) -> Self {
        Self {
            socket,
            send_cipher,
            recv_cipher,
            send_counter: AtomicU64::new(0),
            recv_counter: 0,
            in_buf: Vec::new(),
            peer_public_key,
            channel_type,
            channel_tracker: None,
            migration_gate: None,
        }
    }

    /// 拆成独立的读/写半句柄，供全双工任务各自持有（如 mux 的 reader/writer 任务）。
    ///
    /// 读半句柄保留取消安全的 `in_buf` 半帧状态；写半句柄的计数器从原子量转成
    /// 独享所有权——拆分后每个方向只有一个任务触碰，不再需要原子。
    pub fn into_split(self) -> (SecureRecvHalf, SecureSendHalf) {
        let (read_half, write_half) = tokio::io::split(self.socket);
        (
            SecureRecvHalf {
                read_half,
                recv_cipher: self.recv_cipher,
                recv_counter: self.recv_counter,
                in_buf: self.in_buf,
                peer_public_key: self.peer_public_key.clone(),
            },
            SecureSendHalf {
                write_half,
                send_cipher: self.send_cipher,
                send_counter: self.send_counter.load(Ordering::SeqCst),
                peer_public_key: self.peer_public_key,
            },
        )
    }
}

/// The receive half of a split [`SecureStream`].
pub struct SecureRecvHalf {
    read_half: tokio::io::ReadHalf<ErasedStream>,
    recv_cipher: Aes256Gcm,
    recv_counter: u64,
    in_buf: Vec<u8>,
    peer_public_key: Vec<u8>,
}

impl SecureRecvHalf {
    /// Receive one encrypted frame — same cancellation-safety contract as
    /// [`SecureStream::recv`]（半帧状态留在 `in_buf`，见其文档）。
    pub async fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), LinkError> {
        self.recv_counter = read_frame(
            &mut self.read_half,
            &self.recv_cipher,
            self.recv_counter,
            &mut self.in_buf,
            buf,
        )
        .await?;
        Ok(())
    }

    /// `sha256:<hex>` fingerprint of the peer's Ed25519 identity key.
    pub fn peer_fingerprint(&self) -> String {
        trust::fingerprint(&self.peer_public_key)
    }
}

/// The send half of a split [`SecureStream`].
pub struct SecureSendHalf {
    write_half: tokio::io::WriteHalf<ErasedStream>,
    send_cipher: Aes256Gcm,
    send_counter: u64,
    peer_public_key: Vec<u8>,
}

impl SecureSendHalf {
    /// Send one encrypted frame.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), LinkError> {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);
        if counter == u64::MAX {
            return Err(LinkError::Tamper("send counter exhausted".into()));
        }
        write_frame(&mut self.write_half, &self.send_cipher, counter, plaintext).await
    }

    /// Graceful FIN on the write direction (read half keeps receiving).
    pub async fn shutdown(&mut self) -> io::Result<()> {
        AsyncWriteExt::shutdown(&mut self.write_half).await
    }

    /// `sha256:<hex>` fingerprint of the peer's Ed25519 identity key.
    pub fn peer_fingerprint(&self) -> String {
        trust::fingerprint(&self.peer_public_key)
    }
}

/// Encrypt one frame and write it as `[u32 ct_len][ct]`.
///
/// Shared by [`SecureStream`] and the `into_split` halves — the two `write_all`
/// calls stay together so the wire format is identical everywhere.
async fn write_frame<W>(
    sink: &mut W,
    cipher: &Aes256Gcm,
    counter: u64,
    plaintext: &[u8],
) -> Result<(), LinkError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if counter == u64::MAX {
        return Err(LinkError::Tamper("send counter exhausted".into()));
    }
    let nonce = aes_gcm::Nonce::from(counter_nonce(counter));
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| LinkError::Tamper("encrypt failed".into()))?;
    let len = (ct.len() as u32).to_be_bytes();
    use tokio::io::AsyncWriteExt;
    sink.write_all(&len).await?;
    sink.write_all(&ct).await?;
    Ok(())
}

/// Cancellation-safe receive of one frame; returns the updated receive counter.
///
/// 解析只在本函数累积的 `in_buf` 上进行（见 [`SecureStream::recv`] 文档）：
/// 被取消时半帧状态不丢，下次调用接着解析。
async fn read_frame<R>(
    source: &mut R,
    cipher: &Aes256Gcm,
    recv_counter: u64,
    in_buf: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<u64, LinkError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut counter = recv_counter;
    loop {
        // 1) 缓冲里够一帧就解一帧（纯内存，没有 await 点，不会被取消）。
        if in_buf.len() >= 4 {
            let ct_len = u32::from_be_bytes([in_buf[0], in_buf[1], in_buf[2], in_buf[3]]) as usize;
            if ct_len < 16 || ct_len > MAX_FRAME_LEN as usize + 16 {
                return Err(LinkError::Tamper("frame length out of bounds".into()));
            }
            if in_buf.len() >= 4 + ct_len {
                if counter == u64::MAX {
                    return Err(LinkError::Tamper("recv counter exhausted".into()));
                }
                let nonce = aes_gcm::Nonce::from(counter_nonce(counter));
                let pt = cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: &in_buf[4..4 + ct_len],
                            aad: &[],
                        },
                    )
                    .map_err(|_| LinkError::Tamper("frame failed authentication".into()))?;
                in_buf.drain(..4 + ct_len);
                counter += 1;
                out.clear();
                out.extend_from_slice(&pt);
                return Ok(counter);
            }
        }
        // 2) 不够就再读一批。单次 read 是取消安全的。
        let mut tmp = vec![0u8; READ_CHUNK];
        let n = source.read(&mut tmp).await?;
        if n == 0 {
            return Err(LinkError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed the connection",
            )));
        }
        in_buf.extend_from_slice(&tmp[..n]);
    }
}

fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Dial a peer with a PINNED public key (deny-by-default posture).
pub async fn connect_secure(
    address: &str,
    port: u16,
    identity_seed: &[u8],
    pinned_peer_public_key: &[u8],
) -> Result<SecureStream, LinkError> {
    let socket = crate::link::dial(address, port).await?;
    handshake_client_timed(
        socket,
        identity_seed,
        Some(pinned_peer_public_key),
        DEFAULT_DIAL_HANDSHAKE_TIMEOUT,
    )
    .await
}

/// 发起侧 TOFU：不钉对端公钥，从握手消息 2 里**学习**它（`pub_r`），照常验签。
///
/// 安全语义与监听侧的 `expected_peer = None` 相同：首连学到什么信什么 —— 首连路径上的
/// 中间人防不住（TOFU 的定义），但签名仍绑定整个 transcript，路径上的篡改会当场失败。
/// 「手填地址、什么码都没有」的配对走这里；学到 key 后由调用方落盘钉存。
pub async fn connect_secure_tofu(
    address: &str,
    port: u16,
    identity_seed: &[u8],
) -> Result<SecureStream, LinkError> {
    let socket = crate::link::dial(address, port).await?;
    handshake_client_timed(socket, identity_seed, None, DEFAULT_DIAL_HANDSHAKE_TIMEOUT).await
}

/// [`connect_secure_raced`] 的 TOFU 变体：多个候选地址竞速，胜者握手时不带钉住 key。
pub async fn connect_secure_raced_tofu(
    addresses: Vec<String>,
    port: u16,
    identity_seed: &[u8],
) -> Result<SecureStream, LinkError> {
    use crate::link::race_stream;
    let Some((socket, _addr, _rtt)) = race_stream(addresses, port, Default::default()).await else {
        return Err(LinkError::Handshake(
            "no candidate address reachable".into(),
        ));
    };
    handshake_client_timed(socket, identity_seed, None, DEFAULT_DIAL_HANDSHAKE_TIMEOUT).await
}

/// Race-dial every candidate address (Happy Eyeballs) and run the client
/// handshake on the winning socket — no gap between racing and connecting.
pub async fn connect_secure_raced(
    addresses: Vec<String>,
    port: u16,
    identity_seed: &[u8],
    pinned_peer_public_key: &[u8],
) -> Result<SecureStream, LinkError> {
    use crate::link::race_stream;
    let Some((socket, _addr, _rtt)) = race_stream(addresses, port, Default::default()).await else {
        return Err(LinkError::Handshake(
            "no candidate address reachable".into(),
        ));
    };
    handshake_client_timed(
        socket,
        identity_seed,
        Some(pinned_peer_public_key),
        DEFAULT_DIAL_HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Client handshake bounded by a timeout: drops the socket on expiry, so a
/// dialer waiting behind a busy listener fails visibly and retries instead of
/// hanging as "connecting" forever.
pub async fn handshake_client_timed(
    socket: TcpStream,
    identity_seed: &[u8],
    pinned_peer_public_key: Option<&[u8]>,
    handshake_timeout: std::time::Duration,
) -> Result<SecureStream, LinkError> {
    // 关掉 Nagle。`send` 是「4 字节长度 + 密文」两次 write_all：第一段是个小包，
    // 开着 Nagle 会被攒着等 ACK（对端延迟 ACK 时单帧多出几十毫秒）。加密信道上
    // 我们自己已经按整帧写，没有需要 Nagle 去合的小包。
    // 注：回环实测（release 引擎、10fps×100KiB）关与不关都是 p95≈6ms —— 这条是
    // 防御性的正确做法，不是某个具体数字的修复。
    if let Err(e) = socket.set_nodelay(true) {
        tracing::debug!("set_nodelay failed: {e}");
    }
    let remote = socket.peer_addr().ok();
    let erased = ErasedStream::new(socket, remote);
    match tokio::time::timeout(
        handshake_timeout,
        handshake_client_inner(erased, identity_seed, pinned_peer_public_key),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(LinkError::Handshake(format!(
            "handshake timed out after {handshake_timeout:?}"
        ))),
    }
}

/// Client side of the handshake over an ALREADY-CONNECTED ordered byte stream.
///
/// WAN callers pass a reliable UDP adapter or a relay bridge here; the
/// cryptographic transcript is identical to the TCP path.
pub async fn secure_handshake_client<S>(
    socket: S,
    identity_seed: &[u8],
    pinned_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError>
where
    S: ByteStream + 'static,
{
    handshake_client_inner(
        ErasedStream::new(socket, None),
        identity_seed,
        pinned_peer_public_key,
    )
    .await
}

/// Build a client handshake over a transport whose remote endpoint is already
/// known (used by `connect_wan` after hole punching).
pub async fn secure_handshake_client_with_remote<S>(
    socket: S,
    remote: SocketAddr,
    identity_seed: &[u8],
    pinned_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError>
where
    S: ByteStream + 'static,
{
    handshake_client_inner(
        ErasedStream::new(socket, Some(remote)),
        identity_seed,
        pinned_peer_public_key,
    )
    .await
}

async fn handshake_client_inner(
    mut socket: ErasedStream,
    identity_seed: &[u8],
    pinned_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError> {
    let signing = SigningKey::from_bytes(
        identity_seed
            .try_into()
            .map_err(|_| LinkError::Handshake("seed must be 32 bytes".into()))?,
    );

    // I -> R
    let eph_i_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_i = XPublicKey::from(&eph_i_secret).as_bytes().to_vec();
    let mut nonce_i = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_i);
    socket.write_all(&eph_i).await?;
    socket.write_all(&nonce_i).await?;
    socket.write_all(signing.verifying_key().as_bytes()).await?;

    // R -> I：`eph_r || nonce_r || pub_r || sig_r`。pub_r 在消息 2 里（见服务端注释），
    // 发起侧要么**核对**它（钉住过），要么**学习**它（TOFU，`None`）。
    let mut eph_r = [0u8; PUB_LEN];
    socket.read_exact(&mut eph_r).await?;
    let mut nonce_r = [0u8; NONCE_LEN];
    socket.read_exact(&mut nonce_r).await?;
    let mut pub_r = [0u8; PUB_LEN];
    socket.read_exact(&mut pub_r).await?;
    let mut sig_r = [0u8; SIG_LEN];
    socket.read_exact(&mut sig_r).await?;

    let peer_key: [u8; PUB_LEN] = match pinned_peer_public_key {
        Some(pinned) => {
            let pinned: [u8; PUB_LEN] = pinned
                .try_into()
                .map_err(|_| LinkError::Handshake("peer key must be 32 bytes".into()))?;
            // 钉住过的对端必须报出同一把 key：pub_r 与钉住值不一致 = 冒名，立刻断。
            if pub_r != pinned {
                return Err(LinkError::UntrustedPeer);
            }
            pinned
        }
        // TOFU：首连学到什么信什么（中间人防不住是 TOFU 的定义）；签名仍照常验，
        // transcript 绑定保证了这条 key 确实握有对应私钥。
        None => pub_r,
    };

    let fp_i = trust::fingerprint(signing.verifying_key().as_bytes());
    let fp_r = trust::fingerprint(&peer_key);
    let ts = transcript(&eph_i, &eph_r, &nonce_i, &nonce_r, &fp_i, &fp_r);
    let verifier = VerifyingKey::from_bytes(&peer_key)
        .map_err(|_| LinkError::Handshake("bad pinned key".into()))?;
    verifier
        .verify(&ts, &ed25519_dalek::Signature::from_bytes(&sig_r))
        .map_err(|_| LinkError::UntrustedPeer)?;

    // I -> R (signature)
    let sig_i = signing.sign(&ts);
    socket.write_all(&sig_i.to_bytes()).await?;

    let shared = eph_i_secret.diffie_hellman(&XPublicKey::from(eph_r));
    let (send, recv) = derive_keys(shared.as_bytes(), &nonce_i, &nonce_r, &fp_i, &fp_r);
    Ok(SecureStream {
        socket,
        send_cipher: Aes256Gcm::new_from_slice(&send).expect("key length"),
        recv_cipher: Aes256Gcm::new_from_slice(&recv).expect("key length"),
        send_counter: AtomicU64::new(0),
        recv_counter: 0,
        in_buf: Vec::new(),
        peer_public_key: peer_key.to_vec(),
        channel_type: crate::proto::ChannelType::LanDirect,
        channel_tracker: None,
        migration_gate: None,
    })
}

/// Accept one connection on `listener` and bound the handshake by
/// [`DEFAULT_HANDSHAKE_TIMEOUT`].
///
/// `expected_peer`: `Some(key)` pins the peer (both sides pre-paired);
/// `None` accepts any identity and returns it for TOFU pinning by the caller.
///
/// The timeout is what keeps a silent or foreign client from occupying the
/// single accept slot forever; see [`DEFAULT_HANDSHAKE_TIMEOUT`] for the
/// measured failure (2026-11-02).
pub async fn accept_secure(
    listener: &TcpListener,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError> {
    accept_secure_with_timeout(
        listener,
        identity_seed,
        expected_peer_public_key,
        DEFAULT_HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Accept one connection on `listener` with an explicit handshake timeout
/// (tests and hosts with slower links use this; production uses
/// [`accept_secure`]).
pub async fn accept_secure_with_timeout(
    listener: &TcpListener,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
    handshake_timeout: std::time::Duration,
) -> Result<SecureStream, LinkError> {
    let (socket, remote) = listener.accept().await?;
    // 与客户端同一条：关掉 Nagle（原因见 `handshake_client_timed`）。
    // 服务端这条同样重要：画面与文件的回程都从这里出去。
    if let Err(e) = socket.set_nodelay(true) {
        tracing::debug!("set_nodelay failed: {e}");
    }
    let erased = ErasedStream::new(socket, Some(remote));
    match tokio::time::timeout(
        handshake_timeout,
        handshake_server_inner(erased, identity_seed, expected_peer_public_key),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(LinkError::Handshake(format!(
            "handshake timed out after {handshake_timeout:?}"
        ))),
    }
}

/// Server side of the handshake over an ALREADY-CONNECTED ordered byte stream.
///
/// WAN callers pass a reliable UDP adapter or a relay bridge here.
pub async fn secure_handshake_server<S>(
    socket: S,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError>
where
    S: ByteStream + 'static,
{
    handshake_server_inner(
        ErasedStream::new(socket, None),
        identity_seed,
        expected_peer_public_key,
    )
    .await
}

/// Build a server handshake over a transport whose remote endpoint is already
/// known (used by `accept_wan` after hole punching).
pub async fn secure_handshake_server_with_remote<S>(
    socket: S,
    remote: SocketAddr,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError>
where
    S: ByteStream + 'static,
{
    handshake_server_inner(
        ErasedStream::new(socket, Some(remote)),
        identity_seed,
        expected_peer_public_key,
    )
    .await
}

/// Same as [`secure_handshake_server_with_remote`], evaluating `allow_peer`
/// against the initiator's 32-byte Ed25519 public key **before** signing
/// message 2 so untrusted peers never receive a server signature or identity key.
pub async fn secure_handshake_server_with_policy<S, F>(
    socket: S,
    remote: SocketAddr,
    identity_seed: &[u8],
    allow_peer: F,
) -> Result<SecureStream, LinkError>
where
    S: ByteStream + 'static,
    F: FnOnce(&[u8]) -> bool,
{
    handshake_server_inner_with_policy(
        ErasedStream::new(socket, Some(remote)),
        identity_seed,
        allow_peer,
    )
    .await
}

async fn handshake_server_inner(
    socket: ErasedStream,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError> {
    let pinned = expected_peer_public_key
        .map(|k| {
            <[u8; PUB_LEN]>::try_from(k)
                .map_err(|_| LinkError::Handshake("peer key must be 32 bytes".into()))
        })
        .transpose()?;
    handshake_server_inner_with_policy(socket, identity_seed, move |pub_i| match pinned {
        Some(p) => p == pub_i,
        None => true,
    })
    .await
}

async fn handshake_server_inner_with_policy<F>(
    mut socket: ErasedStream,
    identity_seed: &[u8],
    allow_peer: F,
) -> Result<SecureStream, LinkError>
where
    F: FnOnce(&[u8]) -> bool,
{
    let signing = SigningKey::from_bytes(
        identity_seed
            .try_into()
            .map_err(|_| LinkError::Handshake("seed must be 32 bytes".into()))?,
    );

    // I -> R (ephemeral key, nonce, identity public key)
    let mut eph_i = [0u8; PUB_LEN];
    socket.read_exact(&mut eph_i).await?;
    let mut nonce_i = [0u8; NONCE_LEN];
    socket.read_exact(&mut nonce_i).await?;
    let mut pub_i = [0u8; PUB_LEN];
    socket.read_exact(&mut pub_i).await?;

    // Pin/policy check BEFORE signing anything: an unexpected initiator gets
    // the connection dropped without ever learning our public key or signature.
    if !allow_peer(&pub_i) {
        return Err(LinkError::UntrustedPeer);
    }

    // R -> I
    let eph_r_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_r = XPublicKey::from(&eph_r_secret).as_bytes().to_vec();
    let mut nonce_r = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_r);
    let peer_key = pub_i;

    let fp_r = trust::fingerprint(signing.verifying_key().as_bytes());
    let fp_i = trust::fingerprint(&peer_key);
    let ts = transcript(&eph_i, &eph_r, &nonce_i, &nonce_r, &fp_i, &fp_r);
    let sig_r = signing.sign(&ts);
    socket.write_all(&eph_r).await?;
    socket.write_all(&nonce_r).await?;
    // **消息 2 携带身份公钥**：发起侧没有钉住对端时（TOFU 首连），它没有第二条途径
    // 拿到 pub_r —— 旧格式 `eph_r || nonce_r || sig_r` 里 sig_r 只能对着「预先钉住的
    // key」验，这正是「手填地址、什么码都没有」被挡住的根因。多出的 32 字节对旧客户端
    // 是干净的失败（把它读成 sig_r 的一部分，签名验证不过），两端同版发布，可接受。
    socket.write_all(signing.verifying_key().as_bytes()).await?;
    socket.write_all(&sig_r.to_bytes()).await?;

    // I -> R (signature over the same transcript, proving key possession)
    let mut sig_i = [0u8; SIG_LEN];
    socket.read_exact(&mut sig_i).await?;
    let verifier = VerifyingKey::from_bytes(&peer_key)
        .map_err(|_| LinkError::Handshake("bad peer key".into()))?;
    verifier
        .verify(&ts, &ed25519_dalek::Signature::from_bytes(&sig_i))
        .map_err(|_| LinkError::UntrustedPeer)?;

    let shared = eph_r_secret.diffie_hellman(&XPublicKey::from(eph_i));
    let (recv, send) = derive_keys(shared.as_bytes(), &nonce_i, &nonce_r, &fp_i, &fp_r);
    Ok(SecureStream {
        socket,
        send_cipher: Aes256Gcm::new_from_slice(&send).expect("key length"),
        recv_cipher: Aes256Gcm::new_from_slice(&recv).expect("key length"),
        send_counter: AtomicU64::new(0),
        recv_counter: 0,
        in_buf: Vec::new(),
        peer_public_key: peer_key.to_vec(),
        channel_type: crate::proto::ChannelType::LanDirect,
        channel_tracker: None,
        migration_gate: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_authenticated_channel() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key).await;
        let mut client = client.expect("client handshake");
        let mut server = server.await.unwrap().expect("server handshake");

        assert_eq!(client.peer_public_key, b.public_key);
        assert_eq!(server.peer_public_key, a.public_key);

        client.send(b"clipboard: hello").await.unwrap();
        let mut buf = Vec::new();
        server.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"clipboard: hello");

        server.send(b"clipboard: ack").await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"clipboard: ack");
    }

    /// TOFU：发起侧不带 pinned key，从消息 2 学到对端身份公钥并完成互信握手。
    /// 「手填地址、什么码都没有」正是这条路（对应的监听侧形态是 `expected_peer = None`）。
    #[tokio::test]
    async fn tofu_connect_learns_peer_key() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let server = tokio::spawn(async move {
            accept_secure(&listener, &seed_b, None).await // 监听侧同样不钉：TOFU 捕获发起方
        });
        let mut client = connect_secure_tofu("127.0.0.1", port, &a.seed)
            .await
            .expect("tofu client handshake");
        let mut server = server.await.unwrap().expect("tofu server handshake");

        // 发起方学到的是响应方的真实身份 key
        assert_eq!(client.peer_public_key, b.public_key);
        assert_eq!(server.peer_public_key, a.public_key);

        client.send(b"tofu: hello").await.unwrap();
        let mut buf = Vec::new();
        server.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"tofu: hello");
    }

    /// 钉住过的对端报出**另一把**身份 key：pub_r 与钉住值不一致必须当场断（冒名）。
    /// 这是消息 2 携带 pub_r 换来的新校验 —— 旧格式里发起方无从发现对端换 key。
    #[tokio::test]
    async fn pinned_mismatch_detected_from_message2() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let attacker = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // 冒名者顶在服务端：它的签名对它自己的 fp 有效，但消息 2 里报出的 pub_r
        // 与客户端钉住的 b 不一致 —— 新格式让发起方在验签前就能当场识破。
        let seed_attacker = attacker.seed.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_attacker, None).await });
        let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key).await;
        assert!(
            matches!(client, Err(LinkError::UntrustedPeer)),
            "对端报出的 pub_r 与钉住 key 不一致必须失败：{:?}",
            client.map(|_| ()).map_err(|e| e.to_string()),
        );
        let _ = server.await;
    }

    /// `wait_channel_settle` must return as soon as the tracker moves, and
    /// must not block a caller whose connection will never migrate.
    #[tokio::test]
    async fn wait_channel_settle_follows_a_migration() {
        use crate::proto::ChannelType;
        use std::sync::atomic::AtomicU8;

        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let mut client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .expect("client handshake");
        let _server = server.await.unwrap().expect("server handshake");

        let tracker = Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8));
        client.set_channel_tracker(tracker.clone());
        assert!(client.may_migrate());
        assert_eq!(client.channel_type(), ChannelType::RelayForwarded);

        let mover = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            tracker.store(ChannelType::HolePunchedDirect as u8, Ordering::Release);
        });
        let started = std::time::Instant::now();
        let settled = client.wait_channel_settle(Duration::from_secs(2)).await;
        assert_eq!(settled, ChannelType::HolePunchedDirect);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "must return when the tracker moves, not on the deadline"
        );
        mover.await.unwrap();
    }

    #[tokio::test]
    async fn wait_channel_settle_gives_up_when_nothing_migrates() {
        use crate::proto::ChannelType;
        use std::sync::atomic::AtomicU8;

        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let mut client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .expect("client handshake");
        let _server = server.await.unwrap().expect("server handshake");

        client.set_channel_tracker(Arc::new(AtomicU8::new(ChannelType::RelayForwarded as u8)));
        let started = std::time::Instant::now();
        let settled = client.wait_channel_settle(Duration::from_millis(150)).await;
        assert_eq!(settled, ChannelType::RelayForwarded);
        assert!(started.elapsed() >= Duration::from_millis(140));
    }

    #[tokio::test]
    async fn wrong_pinned_key_is_rejected() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let attacker = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server pins A; the attacker dials with its own key. The attacker's
        // local handshake may complete (it cannot be refused before it
        // identifies itself), but the SERVER aborts on the bad signature and
        // the channel is unusable.
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        // The pinned responder drops the connection before signing anything;
        // the attacker's handshake fails reading the responder's flight.
        let client = connect_secure("127.0.0.1", port, &attacker.seed, &b.public_key).await;
        assert!(client.is_err(), "attacker handshake must fail");
        assert!(
            server.await.unwrap().is_err(),
            "server rejects the attacker"
        );
    }

    #[tokio::test]
    async fn out_of_order_counter_is_rejected() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let mut client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .unwrap();
        let mut server = server.await.unwrap().unwrap();

        client.send(b"frame-0").await.unwrap();
        let mut buf = Vec::new();
        server.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"frame-0");

        // Force the receiver to expect counter=1 while the next frame is
        // encrypted under counter=1 -> wait: force counter=2 so the GCM nonce
        // mismatches, standing in for any replay/reorder/tamper.
        server.recv_counter = 2;
        client.send(b"frame-1").await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), server.recv(&mut buf))
            .await
            .expect("recv must not hang");
        assert!(matches!(result, Err(LinkError::Tamper(_))));
    }

    #[tokio::test]
    async fn eof_after_peer_close_is_error() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .unwrap();
        let mut server = server.await.unwrap().unwrap();
        drop(client); // close the socket
        let mut buf = Vec::new();
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), server.recv(&mut buf))
            .await
            .expect("recv on closed socket must not hang");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tofu_capture_returns_peer_key() {
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let seed_b = b.seed.clone();
        let server = tokio::spawn(async move { accept_secure(&listener, &seed_b, None).await });
        let mut client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .unwrap();
        let server = server.await.unwrap().expect("tofu handshake");
        assert_eq!(
            server.peer_public_key, a.public_key,
            "TOFU captures peer key"
        );
        client.send(b"hi").await.unwrap();
    }

    /// Phase T0 验收：拆分后的两半在并发收发 10MB 数据下无死锁且解密正常。
    #[tokio::test]
    async fn split_halves_concurrent_10mb_both_directions() {
        const TOTAL: usize = 10 * 1024 * 1024;
        const CHUNK: usize = 64 * 1024;

        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .unwrap();
        let server = server.await.unwrap().expect("server handshake");

        let (mut a_recv, mut a_send) = client.into_split();
        let (mut b_recv, mut b_send) = server.into_split();

        // 双向并发：a→b 与 b→a 同时推 10MB（chunk 内容 = 序号低字节，接收端校验）。
        let send_a = tokio::spawn(async move {
            for seq in 0..(TOTAL / CHUNK) {
                let chunk = vec![seq as u8; CHUNK];
                a_send.send(&chunk).await.expect("a→b send");
            }
            a_send.shutdown().await.ok();
        });
        let send_b = tokio::spawn(async move {
            for seq in 0..(TOTAL / CHUNK) {
                let chunk = vec![seq.wrapping_add(0x80) as u8; CHUNK];
                b_send.send(&chunk).await.expect("b→a send");
            }
            b_send.shutdown().await.ok();
        });

        // 校验逻辑：每个 chunk 的字节都等于其序号（低 8 位）。
        let recv_a = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut got = 0usize;
            while got < TOTAL {
                b_recv.recv(&mut buf).await.expect("a→b recv");
                let expect = (got / CHUNK) as u8;
                assert!(buf.iter().all(|&x| x == expect), "a→b chunk byte mismatch");
                got += buf.len();
            }
            assert_eq!(got, TOTAL, "a→b total");
        });
        let recv_b = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut got = 0usize;
            while got < TOTAL {
                a_recv.recv(&mut buf).await.expect("b→a recv");
                let expect = ((got / CHUNK) + 0x80) as u8;
                assert!(buf.iter().all(|&x| x == expect), "b→a chunk byte mismatch");
                got += buf.len();
            }
            assert_eq!(got, TOTAL, "b→a total");
        });

        let (r1, r2, s1, s2) = tokio::join!(recv_a, recv_b, send_a, send_b);
        r1.unwrap();
        r2.unwrap();
        s1.unwrap();
        s2.unwrap();
    }

    #[tokio::test]
    async fn a_silent_client_cannot_hold_the_accept_slot() {
        // Measured failure (2026-11-02): a foreign app dialled the Tidings
        // port with its own wire format, its first bytes never formed a valid
        // flight, and the single accept loop waited forever. The legitimate
        // peer queued in the backlog was starved until the foreign process
        // exited.
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let silent = tokio::spawn(async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            drop(stream);
        });
        // Give the silent connection time to be queued.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let seed_b = b.seed.clone();
        let key_a = a.public_key.clone();
        let first = accept_secure_with_timeout(
            &listener,
            &seed_b,
            Some(&key_a),
            std::time::Duration::from_millis(200),
        )
        .await;
        assert!(
            matches!(first, Err(LinkError::Handshake(_))),
            "a client that never sends a flight must time out"
        );

        // The same listener still serves the next (legitimate) connection.
        let server =
            tokio::spawn(async move { accept_secure(&listener, &seed_b, Some(&key_a)).await });
        let client = connect_secure("127.0.0.1", port, &a.seed, &b.public_key)
            .await
            .expect("legitimate peer after the silent one");
        let server = server.await.unwrap().expect("server handshake");
        assert_eq!(client.peer_public_key, b.public_key);
        assert_eq!(server.peer_public_key, a.public_key);

        silent.abort();
    }

    #[tokio::test]
    async fn a_dialer_does_not_hang_on_a_listener_that_never_answers() {
        // The other half of the starvation: a dialer queued behind a busy
        // listener used to wait forever and report nothing at all.
        let a = trust::generate_identity();
        let b = trust::generate_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            drop(stream);
        });

        let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let started = std::time::Instant::now();
        let result = handshake_client_timed(
            socket,
            &a.seed,
            Some(&b.public_key),
            std::time::Duration::from_millis(200),
        )
        .await;
        assert!(
            matches!(result, Err(LinkError::Handshake(_))),
            "a dialer must fail instead of hanging"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the dialer timed out far too late: {:?}",
            started.elapsed()
        );

        hold.abort();
    }
}
