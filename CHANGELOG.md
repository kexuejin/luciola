# Changelog

All notable changes to **Luciola (萤火)** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — sections
are `Added` / `Changed` / `Fixed` / `Removed`, plus a explicit `Breaking` marker where a
consumer must change code. Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the project is `0.x`, a
breaking change lands in a **minor** bump; from `1.0.0` breaking changes require a major.

Entries are newest-first. Short hashes in parentheses are the commits that carry the
change, taken from the repository history; where one change needed several commits the
primary one is cited.

> **Published-versus-repo version note.** The repository is at **0.8.2** (workspace
> `Cargo.toml`, path-dep requirements, KMP `version`, npm `version`) and **0.8.2 is not
> published yet**. The registries carry the **0.8.0** line, verified 2026-10-29 after
> publishing: crates.io carries **0.8.0** for `luciola-ip`/`luciola-proto`/`luciola-net`/
> `luciola`/`luciola-transfer`/`luciola-tunnel`/`luciola-cli`; Maven Central carries
> **`io.github.kexuejin:luciola:0.8.0`** (AAR with the embedded arm64 `.so`, JVM jar,
> iOS klibs); `@luciola/core` **remains unpublished on npm** — for Node, build
> `bindings/luciola-node` from source.
>
> A consumer that needs 0.8.2 before it is published must pin the **git commit**, not a
> version number: `{ git = "https://github.com/kexuejin/luciola", rev = "<sha>" }`.
> Naming an unpublished version in a dependency is how a consumer repo ends up with
> `path = "../../luciola/..."` and stops being buildable from a clean clone.

---

## [Unreleased] — relay session crypto for luciola-relay 0.3.0

### Added

- `crates/luciola/src/relay_crypto.rs` — canonical implementation of the
  luciola-relay `frame_aead_v3` session crypto: X25519 ephemeral key agreement
  (RFC 7748 vectors), HKDF-SHA256 key schedule bound to the relay handshake
  transcript, and per-frame AES-256-GCM with `nonce = 0000… ‖ u64be(seq)` and
  the raw 12-byte frame header as AAD. iOS re-implements the same steps on
  CryptoKit; all three implementations are pinned by
  `luciola-relay/core/tests/fixtures/wire/cases.json` (cross-language vectors).
- `bindings/luciola-uniffi` exports for the above (`relay_ephemeral_keypair`,
  `relay_session_keys`, `relay_aead_seal/open`, `relay_hkdf_sha256`,
  `relay_transcript_hash`, `relay_signed_handshake_payload`), plus the
  regenerated KMP bindings (gobley) so Android consumes the canonical Rust code.

### Changed

- `x25519-dalek` now enables the `static_secrets` feature (the relay key
  schedule must rebuild a secret from serialized bytes for the vector tests).
- KMP binding version bumped to **0.8.2** (0.8.1 was republished with new
  bindings; the bump forces Gradle to see the change). The AAR was rebuilt and
  published to mavenLocal; the xcframework was rebuilt with the same surface.

---

## [0.8.0] - 2026-10-29

Tunnel v2 (the full T4 scope, wire-compatible with v1 peers). Published on
2026-10-29 and verified: crates.io carries all seven crates at **0.8.0**;
Maven Central carries **`io.github.kexuejin:luciola:0.8.0`** plus the platform
companions (`luciola-android`/`luciola-jvm`/`luciola-iosarm64`/
`luciola-iossimulatorarm64`); `@luciola/core` (npm) remains unpublished.
Breaking for KMP/Node consumers: see the markers below.

### Added — tunnel v2 (the full T4 scope, wire-compatible with v1 peers)

- **Tunnel link keepalive** (`luciola-tunnel` mux) — probe + periodic `PING(nonce)`
  frames answered by `PONG` automatically; receiving any PING/PONG/WINDOW proves the
  peer is v2 (`peer_is_v2()`). A proven-v2 peer silent beyond `keepalive_dead_after`
  (default 45s) terminates the session so the supervisor rebuilds it; a v1 peer is
  **never** killed by silence (R7 boundary kept). Adjustable via the new
  `set_tunnel_keepalive(intervalMs, deadAfterMs)` on uniffi/Node (0 disables).
- **Per-channel WINDOW flow control** (yamux-style credits, frame type `0x08`) — the
  receiver reports consumed bytes at `window_size/2` thresholds (credits take the
  reliable deferred-ctrl path; losing one would deadlock the sender), the sender
  parks `poll_write`/`send_datagram` when `window_size` (default 256 KiB, sanitized
  to ≥ `max_data_frame`) is outstanding. Enforcement starts only after the peer
  proves v2; v1 peers keep the v1 behavior (bounded queues + `stall_hard_timeout`),
  which for v2 peers eliminates the §1.4 cross-channel stall.
- **Remote forward (`-R`)** — the mux Responder may now open channels (even IDs,
  D8's v2 relaxation), gated on `peer_v2` proof (an unproven peer sending even
  frames is still a D9 violation, so mixed-version stays a clean failure). Control
  plane: `start_remote_forward`/`stop_remote_forward` (Listen side: bind
  `127.0.0.1:<listen>`, forward each connection through the tunnel to the peer's
  target) and `enable_remote_endpoint`/`disable_remote_endpoint` (Dial side: ACL
  for inbound remote opens, **deny-by-default**).
- **UDP session mapping** — new datagram channels (`T_DOPEN 0x09`, payload identical
  to OPEN; each DATA frame carries exactly one UDP datagram, boundaries preserved;
  zero-length datagrams are not representable on the wire and are dropped silently)
  and `start_udp_forward`/`stop_udp_forward` (Dial side: NAT-style mapping, one
  channel per source address, idle-recycled). Endpoint ACL rules gain `udp: bool` —
  `true` admits UDP dials too, `false` is TCP-only (v1 semantics).
- **Hostname dial targets** — `DialTarget.host` is now `String` (IP literal or
  RFC-1123-style hostname; the OPEN host field was already UTF-8 text, so the wire
  is unchanged). Structural validation stays in the mux core (bad_target for
  garbage); resolution happens on the dialing side with **session-scoped pinning**
  (one lookup per hostname per endpoint, anti-rebinding; IPv4 preferred among
  results). ACL rules accept hostnames, matched case-insensitively; IP rules and
  hostname targets never cross-match (no resolution before authorization).
- **Channel idle recycling** — `MuxConfig.idle_timeout` (stream channels, default
  off — an idle SSH-like stream must not die) and `udp_idle_timeout` (datagram
  channels, default 60s — NAT mappings must expire). The reaper tears down only
  Active channels (`CLOSE(normal)`; the peer's read side sees EOF), the session
  and all other channels keep flowing.
- **CLI** — `forward serve --remote-forward LISTEN=TARGET` / `--allow-udp`,
  `forward dial --remote-allow` / `--udp LISTEN=TARGET`; `--target`/`--allow`
  accept hostnames.
- **`ForwardStatusDto.kind`** (uniffi/Node `kind`) — each stats row is labeled
  `"local" | "udp_local" | "remote_endpoint" | "endpoint" | "remote"`. KMP/Swift
  bindings regenerated in the same change; the artifact version stays at the
  unpublished 0.7.0, so no registry-facing bump.

**Breaking (0.x, minor):** `ForwardRuleDto`/`JsForwardRule` gained a required
`udp` field and `ForwardStatusDto`/`JsForwardStatus` a required `kind` field;
`DialTarget.host` changed from `IpAddr` to `String` (use `DialTarget::from_ip`);
`MuxError::WrongRole` was removed (Responder-side `open()` is now valid) and
`ModeMismatch`/`DatagramTooLarge`/`UnsupportedByPeer` added. The tunnel wire
format stays `ver=0x01` and is interoperable in both directions with the 0.7.0 v1
peers (with the documented remote-forward/UDP capability gaps).

### Added — KMP iOS runtime verification (tests + build hardening)

- **`iosTest` source set** (`bindings/luciola-kmp/src/iosTest/`) — the first tests
  that *execute* the Kotlin/Native iOS path instead of merely compiling it:
  binding smoke via cinterop against `libluciola_uniffi.a`, `IosNetworkMonitor`
  over Network.framework, tunnel control-plane contracts (role/invalid-target/
  empty-rules rejections, `setTunnelPort`/`setTunnelKeepalive`), and a full
  loopback e2e (message link → tunnel → local TCP forward → byte-exact echo).
  Run with `./gradlew :luciola:iosSimulatorArm64Test` (requires the
  `aarch64-apple-ios-sim` static lib and an Xcode simulator). 4/4 passing.
- **Build hardening** — the native test binary never linked the current
  `libluciola_uniffi.a`: Gradle's up-to-date check does not track the static lib
  (opaque linker flags; the cinterop klib only sees headers), so after a Rust
  rebuild the tests silently ran the old engine — the same "old .so in the
  artifact" trap AGENTS.md §3 warns about, now on the test side. The `.a` files
  are registered as inputs of the iOS test link tasks; a stale-link failure mode
  (misaligned record ABI → `junk data left in buffer` /恒 false) is documented in
  `build.gradle.kts`.

### Added — platform entry points

- **`DesktopDiscoveryController`** (jvmMain) — the desktop convenience shell
  mirroring `AndroidDiscoveryController`: injects the already-present
  `DesktopNetworkMonitor` (interface polling) and a JVM scheduler into the
  cross-platform `DiscoveryController` in commonMain, with an optional injected
  `Executor` for callback marshalling. Compile-verified for the JVM target.
- **`IosNetworkMonitor`** (iosMain) — a `NetworkMonitorPort` over Network.framework's
  path monitor via the C `nw_path_monitor_*` API (the ObjC `NWPathMonitor` class is
  Swift-only and unreachable from Kotlin/Native cinterop). The first path update is
  swallowed as a baseline, matching `AndroidNetworkMonitor`. Compiles for
  iosArm64/iosSimulatorArm64 (CI `kmp-ios` job) and now **runtime-verified on the
  iOS simulator** (`iosSimulatorArm64Test` boots the monitor and asserts a live
  path report); a physical-device run is still outstanding.

### Changed (repository) — landed in this unreleased batch

- The README install sections document the three integration tiers (Android /
  desktop JVM / iOS) instead of an Android-only snippet, and carry the verified
  published-versus-repo version note plus a CI badge.
- `AGENTS.md` records the working rules this repository's incidents produced: the
  CI-parity gate, binding-regeneration discipline, the four version homes, the
  portability red line, verification claims that name their layer.
- CI's Node job also runs `bindings/luciola-node/test/forward.test.mjs` now.

### Fixed (repository)

- **`scripts/publish-crates.sh` publishes `luciola-transfer` and `luciola-tunnel`** —
  both were missing from its ordered list, so they could never reach crates.io even
  when the rest did.

### Known state to fix before the next release

- **Registry lag** as described at the top of this file: everything from **0.4.3 through
  0.7.0** below exists only in this repository.
- **Version drift across the four version homes** must be re-checked at release time:
  the workspace version in `Cargo.toml`, the per-crate path-dependency version
  requirements, the KMP artifact version, and the npm package version all have to
  agree; a path-dep requirement the workspace version cannot satisfy aborts
  `cargo publish` at the very last step.

---

## [0.7.0] — 2026-10-28

Encrypted **port forwarding and TCP multiplexing** over an authenticated channel: a phone
browser can talk to `127.0.0.1` (a secure context) and reach a web service on a desktop
or NAS through one encrypted link.

### Added

- `luciola-tunnel` crate: **mux v1** TCP multiplexing over a single `SecureStream`, plus
  **local port forwarding** (the `ssh -L` equivalent) and a **deny-by-default forwarding
  ACL** on the responder side (`56dbed8`).
- `SecureStream::into_split()` returning independent `SecureRecvHalf` /
  `SecureSendHalf`, so one task can pump a forwarded stream while another reads (`029fd31`).
  Framing state is shared between `SecureStream` and the halves; the two `write_all`
  paths are documented as needing to stay in step.
- Tunnel control plane on the FFI surface, accepted on all binding layers — Kotlin, Swift
  and Node can open and close forwards (`fcc170b`).
- CLI `luciola-cli forward serve|dial|pin` (`56dbed8`): `--tunnel-port`, `--seed`,
  `--pin-peer`, `--allow <host:port>`; `forward pin --seed <hex>` derives the public key
  and the on-screen comparison PIN. The peer pin is **mandatory** — absent a pin the
  responder denies, there is no TOFU on the forwarding path.
- Node surface: `SecureChannel#enableForwardEndpoint(rules)` (responder ACL) and
  `SecureChannel#startLocalForward(listenPort, host, port)` (initiator bind), declared in
  `index.d.ts` (`fcc170b`).
- Supervision runs on an **independent link** from the data channels, with cascading
  stall protection, so a wedged forwarded stream cannot starve the keepalive that would
  otherwise detect it.

### Fixed

- macOS: AirDrop / peer-to-peer interfaces (`awdl`, `llw`, `anpi`) are excluded from
  physical-NIC candidates (`b597871`). They present as real hardware, and selecting one
  advertised an address no peer could ever route to. Unit tests assert all three prefixes
  classify as virtual.

---

## [0.6.0] — 2026-10-28

**Keyed beacons**: the identity a device advertises in discovery is now the identity its
secure channel presents. The chunked file-transfer data plane also landed, as its own crate.

### Added

- `Profile` and `PeerRecord` carry an optional **Ed25519 public key** (`6cc8272`),
  serde-compatible **in both directions** with pre-key peers: an old frame without the
  field still decodes, and a new frame still decodes on an old peer. The
  legacy-direction regression test is `legacy_v1_profile_without_public_key_decodes`.
- `DiscoverySession` exposes `node_id`, `tcp_port` and `public_key` so the host can pin
  exactly what its beacon announces (`2de7cf3`), with the KMP adapter passing them
  through (`080a081`).
- `luciola-transfer`: sliding-window chunked transfers with **absolute-offset writes**
  (out-of-order safe), **contiguous-prefix ACKs**, timeout retransmit, and a 30-second
  post-completion answer cache that removes the "stuck at 99% because the last ACK was
  lost" failure (`5712d0e`). Re-exported from `luciola` behind the default `transfer`
  feature; its E2E tests drive a real `SecureStream` (50 MiB, SHA-256 verified) through a
  dev-dependency on `luciola` that is circular on purpose.
- IPv6 link-local **scope-id resolution**, one unified `dial()` that injects the scope
  automatically, and a single dual-stack listener serving IPv4 and IPv6 inbound (`4f85d58`).

### Breaking

- **`on_message` gained a third parameter** — `(message, peer_fingerprint, remote_addr)`
  with `remote_addr: Option<String>` (`2de7cf3`). Every listener implementation on the
  Rust, Kotlin and Swift surfaces must be updated; it is a build error, not a runtime
  break. Callers that need to attribute a message to a peer address now get it without a
  side-channel.

### Fixed

- **Zombie accept on shutdown**: bind and accept are shutdown-interruptible, so `stop()`
  tears the listener down instead of leaving a task parked in `accept` holding the port
  (`2de7cf3`); covered by `bindings/luciola-uniffi/tests/port_release_e2e.rs`.

---

## [0.5.1] — 2026-10-27

### Changed

- `UniffiEngineAdapter` and `LuciolaFacade` **moved into commonMain** (`9720c31`). The
  adapter carries no `android.*` dependency, so it is now the engine port for JVM **and**
  iOS; the supervision core, watchdog policy and UI models compile once for all three
  targets.

## [0.5.0] — 2026-10-27

Kotlin/Native bindings that work on iOS — **one generated binding set for all three
targets**, instead of a JVM-only set plus a separate hand-maintained Swift path.

### Added

- `uniffi` pinned to **0.29.4** with bindings generated by
  **gobley-uniffi-bindgen 0.3.7** (`8312a0c`), emitting five source sets
  (commonMain / jvmMain / androidMain / nativeMain / cinterop headers): JVM and Android via
  JNA, Native via cinterop against the C FFI, all from one uniffi metadata blob
  (`4efdbcd`).
- `scripts/generate-kmp-bindings.sh` is self-checking: it fails if `nativeMain` is
  missing, or if `nativeMain` contains no `kotlinx.cinterop` — that combination compiles
  and then silently leaves iOS with nothing usable.

### Changed

- The gobley config is **flat**: writing it in uniffi's usual `[bindings.kotlin]` section
  style yields only commonMain and no error (`8312a0c`).
- Generated output under `build/` is git-ignored; native artifacts never enter history
  (`b7d8e4b`).
- `uniffi = "=0.29.4"` in `bindings/luciola-uniffi/Cargo.toml` is coupled to
  gobley-uniffi-bindgen 0.3.7, which depends on exactly that `uniffi_bindgen`. Bumping one
  without the other fails at bindgen time on a metadata mismatch.

---

## [0.4.6] — 2026-10-27

Bindings regenerated so the 0.4.4–0.4.6 Rust-side work actually reaches the shipped
artifacts (a Rust fix without a regeneration leaves desktop fixed and phones unchanged,
silently).

### Added

- `frames_enqueued` / `frames_dequeued` exported on the secure-channel stats snapshot
  (`a18fa48`). With only "the send returned OK", that claim and "the frame left the
  process" were indistinguishable — the exact gap that made field reports about stalled
  channels unresolvable.
- Android: **ARMv8 hardware AES** for aarch64 (`8eb009d`) — needs the `aes_armv8` cfg
  *and* `-C target-feature=+aes,+sha2`, because the crate's runtime detection covers
  Linux/macOS but Android is its own `target_os`. Omitting either is not an error but a
  silent slowdown: measured on a real device at ~24 ms per frame encrypted vs ~2 ms on the
  cleartext path at 49 KiB/frame.

### Fixed

- `recv` on a secure channel is **cancellation-safe**, and a frame whose write failed is
  no longer silently dropped (`cde2f6b`). Cancelling a receive mid-frame desynced the
  frame reader for the rest of the connection.

### Changed

- **Nagle disabled** on secure channels (`6f5e556`) — the writer already emits complete
  framed buffers, so kernel small-write coalescing only added latency.

## [0.4.5] — 2026-10-26

### Added

- Both platform artifacts became independently verifiable (`505f5c8`):
  `scripts/publish-maven-local.sh` builds and embeds the Rust `.so` before publishing, and
  `bindings/luciola-swift/build-xcframework.sh` produces the iOS framework from source.
  The AAR refuses to publish without the embedded native library (`verifyNativeLib` in the
  KMP build script), because an AAR without it is a runtime crash for the consumer.

### Fixed

- **The peer registry keeps the best address, not the newest one, while a peer is online**
  (`73caef2`). A weaker re-announce (for example a link-local address arriving after a
  routable GUA) overwrote the good one, turning a discoverable peer into an undialable one.

### Changed

- Android `minSdk` **26 → 24** (`ec15499`). The Android side of the library needs only
  JNA and standard sockets, so 26 was raising a consumer app's whole install floor to API
  26 for no reason.

## [0.4.4] — 2026-10-26

- Version bump carried with the `minSdk` change above (`ec15499`).

## [0.4.3] — 2026-10-25

### Added

- `UniffiEngineAdapter.dial(host, port)` — **directed unicast re-announce** (`d0a1b43`).
  On networks where the router does not forward client-to-client multicast, a host can
  point discovery at a known address instead of waiting for a broadcast that will not come.

## [0.4.2] — 2026-10-25

The last version actually on Maven Central.

### Added

- **QR v2 pairing payload carries the host's Ed25519 public key** (base64 `pk`) across the
  Rust core, the Kotlin surface and the Node surface (`e1694e6`). A scanned QR now
  establishes identity, not merely an address: what the pairee pins is the key the pairer
  will present on the secure channel.
- **Opaque `Profile.extra`** in the wire protocol — an mDNS-TXT-style free-form field for
  application payloads, so products can advertise app-specific state without inventing a
  second discovery protocol (`321d5b9`).
- `PeerUiModel.extra` — the field reaches the Kotlin UI layer intact (`321d5b9`), is
  handed to `DiscoverySession` by the adapter (`321d5b9`), and the bindings are
  regenerated to match (`321d5b9`). The gap was found by a consumer app's compile, not
  by this repository's own gates: the Rust and Kotlin surfaces disagreed and only the
  consumer noticed.

> 0.4.0 and 0.4.1 exist on Maven Central, but the commits in between do not annotate which
> change rode which number, so they are not itemized separately here. Treat `extra` and its
> propagation as the 0.4.0–0.4.2 line of work.

---

## [0.3.1] — 2026-10-25 — highest version on crates.io

### Fixed

- The unix-socket discovery agent is gated off Windows (`e1289ab`). CI builds on
  ubuntu/macos/windows and the agent used `AF_UNIX` unconditionally.
- `ff02::1` is joined only on interfaces that actually carry IPv6, with network-monitor
  diagnostics alongside (`8f0cd9d`); joining on a non-IPv6 interface failed the whole
  multicast setup on dual-stack machines that had one IPv6-less adapter.

### Changed

- Published under open-source-safe coordinates — `io.github.kexuejin:luciola` (`4282c65`),
  versioned path-dependency requirements so `cargo publish` resolves (`eddb790`), and
  publication to Maven Central through the Central Portal API (`dcc76af`).
- `rustfmt` + `clippy -D warnings` adopted as the CI gate (`ad61c4d`).

## [0.3.0] — 2026-10-25

The first release-shape version: the Rust core plus all three binding surfaces working
against each other.

### Added

- **Happy Eyeballs path racing** as a core primitive (`3d289e9`): staggered concurrent
  dials across every candidate subnet (IPv4 and IPv6 GUA), first connect wins, and the
  encrypted handshake runs **on the winning socket** so there is no race-then-dial gap.
- **Authenticated encrypted channels**, `link::secure` (`3d00895`): SIGMA-style
  handshake (X25519 ephemeral ECDH + Ed25519 transcript signatures + HKDF-SHA256 +
  AES-256-GCM with strictly increasing counters), responder pins checked before any
  signature leaves, deny-by-default with TOFU capture, auto-reconnect with backoff,
  keepalive dead-peer detection, bounded queues. The composition is **pre-audit** — see
  [`SECURITY.md`](SECURITY.md).
- **Trust and pairing primitives** with device-grouping fields (`69badd7`): Ed25519
  identities, `sha256:` fingerprints, 6-digit comparison PINs, and a leveled trust store
  (Full = own devices, Partial = per-action confirm, unpaired = deny).
- **Dual-stack discovery with IPv6 link-local multicast** (`e50ad9c`): RFC 4291/4193
  scope taxonomy plus `/64` prefix matching that treats ISP-assigned GUA addresses as
  same-LAN.
- `manualPeers` exported for cross-subnet, VPN and localhost dialing (`52a02dd`).
- **Supervision built into the bindings** (`a3805de`): stable node identity across engine
  restarts, `bind_failed` events for same-machine multi-product port conflicts, watchdog
  plus debounced network-change rebuilds, Android `MulticastLock` handling.
- Kotlin Multiplatform library `luciola-kmp` — Android AAR + JVM + iOS klib (`da2d28d`);
  Swift bindings regenerated with an iOS xcframework (`9dcbe2c`); Android radar demo (`2a11ab5`).
- `luciola-cli agent` — a per-device discovery daemon streaming events over a unix socket,
  so several products on one machine share one set of sockets (`b5cc1ff`).
- Configurable retry/keepalive policies on the link layer (`f154a0f`), with an
  integration guide for a consumer app moving onto them.
- Link diagnostics, broader network watching, and binding compile gates in CI (`d1e6878`).

### Security

- Identity seeds, ephemeral X25519 secrets and HKDF output are `zeroize`d on drop, and the
  pre-audit status is documented rather than implied (`545857e`).

### Changed

- Native artifacts kept out of git; `scripts/publish-maven-local.sh` becomes the single
  source of truth for producing them (`b5ccb61`).

---

## 0.2.x and earlier — 2026-10-24 (never published under these numbers)

The initial workspace shape, before any registry release.

- Initial Rust workspace (`28acf91`); crate hierarchy standardized around the root
  `luciola` crate with TypeScript types for the Node surface (`5fd22dc`).
- Node.js N-API bindings (`40c85ac`), with `DiscoverySession`, WSL2 passthrough
  resolution of the Windows host's real IP, and dead-socket self-healing (`275cba0`).
- Terminal QR-code rendering, UniFFI scaffolding with the first Kotlin and Swift bindings
  (`e7b9759`), and hardware device profiling (device type, OS, arch, model) plumbed
  through core, CLI, Node and UniFFI (`67a6b46`).
- Human-readable device model and hostname, QR dark-contrast fix, and a multi-subnet
  universal pairing payload (`d910c5b`).
- Zero-dependency web radar demo driven by `@luciola/core` (`fead6b1`).
- Private project references removed from examples and docs at the point of open-sourcing
  (`bd8c55a`).

---

## Release tagging

No git tags exist in this repository's history yet, so the version headings above are
dates plus numbers read from the history and the build files, not tag references, and
there are deliberately no compare links at the foot of this file: every such link would
point at a tag that does not exist. Add `[0.7.0]: <compare url>`-style definitions only
once matching tags are pushed. When tagging starts, use `v0.7.0`-style names matching the
published artifact version, and never document a version as installable without checking
that the registry actually carries it.
