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
  The handshake runs over any ordered byte stream (`ByteStream`): originally
  TCP, now also a reliable ordered UDP ARQ or an ordered WebSocket relay.
  Ordering is a security requirement — see the WAN section below.
- **Discovery frames are NOT authenticated** by design (open discovery);
  products must treat profile fields as untrusted display data and gate all
  data-plane access behind the trust store + secure channel.

## Denial-of-service posture

- Secure-channel handshake reads are time-bounded: 5 s on the listening side
  (`DEFAULT_HANDSHAKE_TIMEOUT`) and 10 s on the dialling side
  (`DEFAULT_DIAL_HANDSHAKE_TIMEOUT`). A client that opens a TCP connection and
  sends nothing is dropped and the accept slot is released; without the bound,
  any host able to reach the port could deny service to the legitimate peer
  (measured 2026-11-02: a foreign app held the single slot until it exited).
- Discovery is unauthenticated by design, and a requested port that cannot be
  bound is a hard error rather than a silent move to an ephemeral port: the
  loser of a port race no longer announces into the winner's socket, which had
  let two products join one broadcast mesh and dial each other.

## Status: pre-audit

The handshake is built from vetted primitives (RustCrypto: ed25519-dalek,
x25519-dalek, sha2, hkdf, aes-gcm) in a standard construction, but it is a
**custom protocol composition that has not been externally audited**.
Before shipping products that carry secrets:

1. Commission an external review of `crates/luciola/src/link/secure.rs`
   (~300 lines) and `crates/luciola/src/trust.rs`.
2. Include the WAN composition in the same review:
   `crates/luciola/src/wan/` (ARQ, encrypted signalling frames, route
   agreement), `crates/luciola/src/pairing.rs` (room derivation),
   `crates/luciola/src/relay_crypto.rs`, and
   `deploy/cloudflare-signaling/src/` (Ed25519 auth, replay and rate limits).
   None of this code has been externally audited or field-tested across real
   NATs. The deployed staging Worker has been exercised end to end (see the
   verification layer below), which is a runtime check, not a field test.
3. If the review flags structural issues, the fallback is a swap to a vetted
   Noise framework implementation behind the same API — the surface
   (`connect_secure` / `accept_secure` / `SecureStream`) was kept small on
   purpose.

## Key material hygiene

- Identity seeds (32 bytes) are returned to the embedder — persist them in
  Keychain / Keystore / a locked keyfile (see docs/INTEGRATION.md).
- Ephemeral X25519 secrets and HKDF output are zeroized on drop; signing keys
  zeroize via ed25519-dalek's `zeroize` feature.

## WAN signalling and traversal (0.11.0-local.1, local validation only)

The 0.11.0 line adds STUN candidate discovery, a third-party rendezvous
Worker (`deploy/cloudflare-signaling`) and a `luciola::wan::connect_wan`
orchestrator. This is **Rust core tier only**: the KMP, Swift and Node binding
surfaces do not expose WAN establishment. This section describes the *new*
threat model, which is materially different from the LAN-only one.

- **Metadata leaves the LAN.** A public STUN server and the signalling Worker
  can observe public keys, public IP addresses, room identifiers and online
  times. Discovery was already open; this is a new, cloud-side observer. Room
  IDs are HKDF-SHA256 outputs keyed by the pairing PSK plus both public keys
  and a 10-minute epoch, so they are unguessable without the PSK, but they are
  not anonymous. `WanConfig::enable_hole_punching = false` skips the public
  STUN query entirely for relay-only validation. RFC 5780 behaviour discovery
  (`luciola stun --probe-nat`, alias `--probe-nat-behavior`) sends additional
  CHANGE-REQUEST queries to alternate addresses, so the STUN operator can
  also learn mapping and filtering behaviour — run it only as an explicit
  diagnostic, and never treat a timed-out probe as a classification.
- **Candidate, route and relay payloads are end-to-end encrypted.** The
  Worker only reads a JSON envelope (`v`, `t`, `s`, `ct`); the ciphertext is
  AES-256-GCM under an HKDF-SHA256 key derived from the PSK, room and sorted
  public keys. AAD binds room, epoch, sequence and frame kind, and the
  sequence is strictly increasing per direction (replay protection). The
  service therefore never sees endpoint addresses, route decisions or file
  bytes. **Do not** add plaintext fields to the signalling envelope — the
  privacy claim depends on every non-routing field living inside `ct`.
- **Worker authentication and abuse limits.** The Worker verifies an Ed25519
  signature over `LUCIOLA_WAN_AUTH:${room}:${epoch}:${nonce}:${peer}` where
  `peer` is the presenting public key, checks a bounded 600 s epoch window,
  rejects reused nonces via Durable Object storage, caps join and message
  rates, and closes frames over `MAX_MESSAGE_BYTES` (32 KiB). Rooms are
  limited to two distinct peers. These are DoS/abuse controls, **not** an
  authorization grant: the pinned peer identity is still checked by the
  `SecureStream` handshake, and a candidate frame whose identity does not
  match the pinned key is rejected by `connect_wan`.
- **Deny-by-default is unchanged.** `RelayConfig::default()` has
  `allow_relay = false` and `allow_wan_signaling = false`; `connect_wan`
  returns `PolicyDenied` before any DNS, socket or STUN work. Both peers must
  also agree on the chosen data plane via an encrypted `RouteDecision`, so a
  failed punch can never silently diverge into a relay on one side only. The
  CLI send path enforces `FileSender::check_channel_policy` (default relay cap
  100 MiB) *before* the first frame. Unpaired peers are still denied and
  `Partial` trust still requires per-action confirmation. LAN discovery and
  the existing TCP `SecureStream` path are unaffected.
- **Ordered delivery is a security invariant, not an optimisation.**
  `SecureStream` uses AES-256-GCM with strictly increasing counter nonces and
  therefore requires an ordered byte stream. UDP hole punching provides
  datagrams, so `wan::udp` puts a reliable ordered ARQ layer underneath the
  channel, and the signalling relay uses an ordered WebSocket. Feeding raw,
  reordered datagrams directly into `SecureStream` would break nonce
  uniqueness. The STUN query, the punch and the data plane all share **one**
  UDP socket — rebinding invalidates the NAT mapping and the srflx candidate.
- **Rendezvous PSK hygiene.** Room IDs are keyed by the pairing PSK; without
  a PSK no room is derived (an all-zero key would make the room predictable).
  The PSK travels in the v3 pairing URI / QR code as plaintext secret
  material: treat that channel as secret, never log it, and do not display it
  as ordinary metadata. Derived keys and the normalized PSK are `Zeroizing`.
  Both peers must rendezvous in the same 10-minute epoch. The room id embeds
  the epoch, so a peer on the far side of a boundary lands in an **unrelated
  room** rather than arriving early or late. The Durable Object returns the
  epoch it is serving in the `x-luciola-epoch` upgrade header, and a client
  that did not pin an epoch re-derives its room at that value and redials
  **once**. This is room selection, not a widened authentication window: the
  Worker still rejects any signature whose epoch is more than one window from
  its own clock, and a client that pinned `WanConfig::epoch` (or supplied a
  hand-written room) is never moved. The header carries no key material — the
  request URL already states the client's own epoch — so it adds nothing to
  what the signalling service observes.
- **USB ADB is a physical-bus path, not a new trust boundary.**
  `ChannelType::UsbAdbDirect` still runs the same pinned `SecureStream`
  handshake; the transport is an `adb forward` created on the sending side
  only and removed on exit. Its security rests on the developer's ADB
  authorization for the attached device — an unauthorized host cannot open
  the forward. A failed `adb forward` is a hard error, so a same-machine run
  cannot silently masquerade as a USB transfer.
- **Background presence widens the exposure window, not the trust boundary.**
  The Android demo's `connectedDevice` foreground service keeps the discovery
  socket open while the app is not in the foreground, so the device answers
  `alive` probes — and is therefore discoverable on the LAN — for longer than a
  foreground-only app. It adds no frame type, key or peer-admission rule:
  pairing, key pinning and the `SecureStream` handshake are unchanged, and the
  engine still speaks only the same public discovery envelopes. iOS has no
  equivalent and stays foreground-only plus opportunistic refresh, which is the
  honest ceiling without a push server.
- **Resumable-transfer sidecars are local files, not secrets.**
  `<file>.luciola-part` and `<file>.luciola-meta` live beside the destination
  and carry the transfer hash, file length and a chunk bitmap — no identity
  seed, PSK or session key. The bitmap is written only after `sync_data` of
  the bytes it describes, so a crash cannot resume past an unchecksummed
  hole; finalize is an atomic rename and the destination is not overwritten
  before completion.
- **Congestion control is not a cryptographic change.** The AIMD in-flight
  window in `wan::arq` schedules how many ARQ bytes may be outstanding; it
  changes no frame format, cipher suite, pinning default or nonce rule. It is
  nevertheless additional custom, unaudited code, like the migration
  protocol and the checkpoint format.
- **No deployed service ships with this build.** `deploy/cloudflare-signaling`
  ships source + `wrangler.toml`; a deployment is a separate, explicit step.
  The **staging** environment was deployed to the Cloudflare runtime on
  2026-11-13 and is the only deployed environment exercised so far;
  **production is not deployed**. Sustained relay traffic is a billed
  third-party path (Worker/Durable Object messages and duration); "zero idle
  cost" covers idle hibernated WebSockets and STUN signalling, **not** bulk
  relay throughput. There is no public TURN relay.
- **Verification layer (AGENTS.md §12).** Proven at the unit / loopback
  layer: the full local gate on 2026-11-13 (Rust fmt / clippy / 26 test
  binaries, KMP compiles for four targets, Node build plus three test files,
  Worker 9/9), an encrypted relay handshake carrying 64 KiB over a local
  blind-forwarding WebSocket, a real `SecureStream` handshake over the UDP ARQ
  byte stream, and ARQ recovery under a lossy/reordering proxy. The progressive
  migration, RFC 5780 classification, checkpoint resume, AIMD window, ADB path
  and epoch realignment have unit / process-test / loopback coverage only.
  Proven on the **deployed staging** Cloudflare runtime: `/health` reports a
  versioned build whose epoch agrees with the client's;
  `scripts/probe-signaling.py` observed a real signed `101` upgrade carrying
  `x-luciola-epoch`; and `crates/luciola/tests/wan_local_worker.rs` ran two
  Rust peers through the deployed Durable Object (edge Ed25519 verification,
  pre-join buffering, a 96 KiB relay transfer) via
  `scripts/wan-proxy-tunnel.py`, which recorded ~198 KiB to and ~199 KiB from
  the Worker. That is a relay-only, single-host run through a proxy bridge —
  no hole punching and no real NAT were involved. What is
  **not** proven: no real-NAT / carrier-grade-NAT field test, no production
  deployment or test, no cross-platform WAN smoke, no physical-device ADB
  transfer, no real-device background run on either mobile platform (Android's
  foreground service has only been compiled and linted; iOS `BGAppRefreshTask`
  and silent push need a signed build and a server), and no external audit.
  Treat WAN as unvalidated on real networks until those runs happen.

The handshake, cipher suites, pinning defaults and secure-channel frame size
limit are **unchanged**. The ARQ protocol, signalling frame composition,
migration protocol, checkpoint format, AIMD window, epoch realignment and
Worker auth path are
**additional custom, unaudited code** — see the extended review checklist
below.

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
