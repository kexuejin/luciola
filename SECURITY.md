# Security Policy

## Cryptographic constructions

- **Device identity**: Ed25519 (ed25519-dalek). Public key = security identity.
- **Fingerprints / pins**: SHA-256 of the public key (`sha256:<hex>` full form;
  6-digit decimal pin derived from the digest for on-screen comparison).
- **Secure channel handshake** (luciola::link::secure): SIGMA-style —
  X25519 ephemeral ECDH, both sides sign the full transcript (ephemeral keys,
  nonces, both identity fingerprints) with their Ed25519 identity keys,
  HKDF-SHA256 derives per-direction keys, AES-256-GCM frames with strictly
  increasing counter nonces (tamper + replay rejection). Responder pins are
  checked BEFORE any signature leaves (unknown initiators learn nothing).
- **Discovery frames are NOT authenticated** by design (open discovery);
  products must treat profile fields as untrusted display data and gate all
  data-plane access behind the trust store + secure channel.

## Status: pre-audit

The handshake is built from vetted primitives (RustCrypto: ed25519-dalek,
x25519-dalek, sha2, hkdf, aes-gcm) in a standard construction, but it is a
**custom protocol composition that has not been externally audited**.
Before shipping products that carry secrets:

1. Commission an external review of `crates/luciola/src/link/secure.rs`
   (~300 lines) and `crates/luciola/src/trust.rs`.
2. If the review flags structural issues, the fallback is a swap to a vetted
   Noise framework implementation behind the same API — the surface
   (`connect_secure` / `accept_secure` / `SecureStream`) was kept small on
   purpose.

## Key material hygiene

- Identity seeds (32 bytes) are returned to the embedder — persist them in
  Keychain / Keystore / a locked keyfile (see docs/INTEGRATION.md).
- Ephemeral X25519 secrets and HKDF output are zeroized on drop; signing keys
  zeroize via ed25519-dalek's `zeroize` feature.

## Tunnel data plane posture (luciola-tunnel)

The mux rides on top of `SecureStream` and adds no cryptography of its own; its
security claims are access-control ones, and they are deny-by-default:

- Forward-endpoint ACLs are empty-by-default (every OPEN rejected, never dialed,
  never resolved); ACL denial leaks no policy detail (`OPEN_ACK(1)` carries no
  detail). Remote-forward endpoints on the initiator side must be enabled
  explicitly (`enable_remote_endpoint`) — inbound opens are rejected otherwise.
- Local and remote-forward listeners bind loopback only (`127.0.0.1`).
- Hostname dial targets are resolved **after** the ACL passes and pinned per
  session (anti-rebinding: one lookup per hostname per endpoint lifetime); IP
  ACL rules and hostname targets never cross-match.
- The mux v2 features (WINDOW flow control, remote forward, datagram channels)
  are gated on v2-peer proof (inbound PING/PONG/WINDOW); a v1 peer sees them
  as ignored reserved frames or clean terminal rejections, never as a change
  of its trust surface.

## Reporting

Email the repository owner; do not open public issues for vulnerabilities.
