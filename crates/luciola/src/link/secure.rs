//! Authenticated encrypted channels over TCP — the "door" for the trust
//! primitives in [`crate::trust`].
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
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

const PROTOCOL_CONTEXT: &[u8] = b"luciola-link-v1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const PUB_LEN: usize = 32;
const SIG_LEN: usize = 64;
/// Largest plaintext frame accepted (guards against length-field DoS).
pub const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// single read chunk (each read is a cancellation point)
const READ_CHUNK: usize = 64 * 1024;

#[derive(Error, Debug)]
pub enum LinkError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("peer key mismatch (untrusted device)")]
    UntrustedPeer,
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
    socket: TcpStream,
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
}

impl SecureStream {
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

    pub fn peer_fingerprint(&self) -> String {
        trust::fingerprint(&self.peer_public_key)
    }

    /// Direct socket access (used by supervisors for graceful shutdown).
    pub fn socket_mut(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    /// 拆成独立的读/写半句柄，供全双工任务各自持有（如 mux 的 reader/writer 任务）。
    ///
    /// 读半句柄保留取消安全的 `in_buf` 半帧状态；写半句柄的计数器从原子量转成
    /// 独享所有权——拆分后每个方向只有一个任务触碰，不再需要原子。
    pub fn into_split(self) -> (SecureRecvHalf, SecureSendHalf) {
        let (read_half, write_half) = self.socket.into_split();
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
    read_half: tokio::net::tcp::OwnedReadHalf,
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

    pub fn peer_fingerprint(&self) -> String {
        trust::fingerprint(&self.peer_public_key)
    }
}

/// The send half of a split [`SecureStream`].
pub struct SecureSendHalf {
    write_half: tokio::net::tcp::OwnedWriteHalf,
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
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.write_half.shutdown().await
    }

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
    secure_handshake_client(socket, identity_seed, pinned_peer_public_key).await
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
    secure_handshake_client(socket, identity_seed, pinned_peer_public_key).await
}

/// Client side of the handshake over an ALREADY-CONNECTED socket.
pub async fn secure_handshake_client(
    mut socket: TcpStream,
    identity_seed: &[u8],
    pinned_peer_public_key: &[u8],
) -> Result<SecureStream, LinkError> {
    // 关掉 Nagle。`send` 是「4 字节长度 + 密文」两次 write_all：第一段是个小包，
    // 开着 Nagle 会被攒着等 ACK（对端延迟 ACK 时单帧多出几十毫秒）。加密信道上
    // 我们自己已经按整帧写，没有需要 Nagle 去合的小包。
    // 注：回环实测（release 引擎、10fps×100KiB）关与不关都是 p95≈6ms —— 这条是
    // 防御性的正确做法，不是某个具体数字的修复。
    let _ = socket.set_nodelay(true);
    let signing = SigningKey::from_bytes(
        identity_seed
            .try_into()
            .map_err(|_| LinkError::Handshake("seed must be 32 bytes".into()))?,
    );
    let peer_key: [u8; PUB_LEN] = pinned_peer_public_key
        .try_into()
        .map_err(|_| LinkError::Handshake("peer key must be 32 bytes".into()))?;

    // I -> R
    let eph_i_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_i = XPublicKey::from(&eph_i_secret).as_bytes().to_vec();
    let mut nonce_i = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_i);
    socket.write_all(&eph_i).await?;
    socket.write_all(&nonce_i).await?;
    socket.write_all(signing.verifying_key().as_bytes()).await?;

    // R -> I
    let mut eph_r = [0u8; PUB_LEN];
    socket.read_exact(&mut eph_r).await?;
    let mut nonce_r = [0u8; NONCE_LEN];
    socket.read_exact(&mut nonce_r).await?;
    let mut sig_r = [0u8; SIG_LEN];
    socket.read_exact(&mut sig_r).await?;

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
    })
}

/// Accept one connection on `listener`.
///
/// `expected_peer`: `Some(key)` pins the peer (both sides pre-paired);
/// `None` accepts any identity and returns it for TOFU pinning by the caller.
pub async fn accept_secure(
    listener: &TcpListener,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError> {
    let (socket, _) = listener.accept().await?;
    secure_handshake_server(socket, identity_seed, expected_peer_public_key).await
}

/// Server side of the handshake over an ALREADY-ACCEPTED socket.
pub async fn secure_handshake_server(
    mut socket: TcpStream,
    identity_seed: &[u8],
    expected_peer_public_key: Option<&[u8]>,
) -> Result<SecureStream, LinkError> {
    // 与客户端同一条：关掉 Nagle（原因见 `secure_handshake_client`）。
    // 服务端这条同样重要：画面与文件的回程都从这里出去。
    let _ = socket.set_nodelay(true);
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

    // R -> I
    let eph_r_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_r = XPublicKey::from(&eph_r_secret).as_bytes().to_vec();
    let mut nonce_r = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_r);

    // Pin check BEFORE signing anything: an unexpected initiator gets the
    // connection dropped without ever learning our signature.
    let pinned = expected_peer_public_key
        .map(|k| {
            <[u8; PUB_LEN]>::try_from(k)
                .map_err(|_| LinkError::Handshake("peer key must be 32 bytes".into()))
        })
        .transpose()?;
    if let Some(p) = pinned {
        if p != pub_i {
            return Err(LinkError::UntrustedPeer);
        }
    }
    let peer_key = pub_i;

    let fp_r = trust::fingerprint(signing.verifying_key().as_bytes());
    let fp_i = trust::fingerprint(&peer_key);
    let ts = transcript(&eph_i, &eph_r, &nonce_i, &nonce_r, &fp_i, &fp_r);
    let sig_r = signing.sign(&ts);
    socket.write_all(&eph_r).await?;
    socket.write_all(&nonce_r).await?;
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
}
