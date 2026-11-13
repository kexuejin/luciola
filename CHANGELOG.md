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

> **Published-versus-repo version note.** The repository is at **0.11.0-local.1**,
> a **local-only validation build** (workspace `Cargo.toml`, path-dep
> requirements, KMP `version`, npm `version`). That version is on **no registry**:
> it exists only in `~/.m2` via `scripts/publish-maven-local.sh` so downstream
> products can validate the WAN API before a public release. The install
> snippets in the README still name 0.10.0, the last verified public release;
> do not copy `0.11.0-local.1` into a consumer that cannot see `mavenLocal()`.
> Release state, checked 2026-11-05 against the registries rather than assumed:
>
> - **crates.io — 0.10.0 published and verified.** `luciola`, `luciola-ip`,
>   `luciola-proto`, `luciola-net`, `luciola-transfer`, `luciola-tunnel`,
>   `luciola-cli` all answer `0.10.0` from the registry API.
> - **Maven Central — 0.10.0 published and verified.** The deployment reached
>   `PUBLISHED` on the Central Portal; repo1 serves the root Gradle module
>   metadata (`io.github.kexuejin:luciola:0.10.0`), the `luciola-android` AAR,
>   `luciola-jvm`, and the `luciola-iosarm64` / `luciola-iossimulatorarm64`
>   klibs.
> - **iOS — 0.10.0 published.** `LuciolaUniFFI-0.10.0.zip` (28,882,594 bytes,
>   xcframework for device and simulator, `luciola_uniffi.swift`, FFI headers)
>   plus its `.sha256` (`3b95e3f6…cebf75`) are release assets on tag `v0.10.0`.
> - `@luciola/core` **remains unpublished on npm** — for Node, build
>   `bindings/luciola-node` from source.
>
> A consumer that needs an engine change that is not released yet must pin the **git
> commit**, not a version number: `{ git = "https://github.com/kexuejin/luciola", rev =
> "<sha>" }`. Naming an unpublished version in a dependency is how a consumer repo ends
> up with `path = "../../luciola/..."` and stops being buildable from a clean clone.

## [Unreleased] — 0.11.0-local.1 (local validation build, republished 2026-11-13)

Published to **mavenLocal only** under one unchanged local coordinate. crates.io,
Maven Central, npm, the git tag and `origin/main` are all untouched; the public
registries remain at 0.10.0 until downstream products finish validation. The
local artifact was **republished four times on 2026-11-13**: first after the
WAN stability fixes, resumable transfers, USB transport and the AIMD window;
at 11:34 after the WAN channel API reached the uniffi/Node surfaces and the
epoch realignment, mobile background and deployed-Worker verification work
landed; at 12:16 after native HTTP CONNECT proxy support and the rustls
crypto-provider fix; and at 12:21, the final republish, after the unit-level
TLS-provider regression guard. The coordinate is deliberately unchanged, so a
consumer that resolved `0.11.0-local.1` before any of those republishes may
still hold an older engine in its Gradle cache — refresh dependencies
(`--refresh-dependencies`) before concluding a fix is absent from the AAR. The
current AAR embeds an arm64 `.so` with sha256
`ea41c96867534a2f8e062b11a4340a07109fa8f57b88570c264a47b6e357aed2`. The
Android arm64 native library was rebuilt for this republish. The iOS
`LuciolaUniFFI.xcframework` was subsequently rebuilt for `aarch64-apple-ios`
and `aarch64-apple-ios-sim` with the new `ring` dependency and now links into
`examples/ios-demo` for the arm64 simulator, and was then installed and
launched on that simulator — the app runs with its Rust engine bound, so this
is a simulator runtime result for launch and engine bind, not a device run. See
*Verification layer and remaining limits*.

### Added (Rust core tier — local validation only)

- `luciola::wan`: `connect_wan`, `WanConfig`, `WanError` and `current_epoch`.
  Encrypted WSS rendezvous, candidate exchange, UDP hole punching, a reliable
  **ordered** UDP data plane (ARQ), and an end-to-end encrypted relay fallback
  over the same WebSocket. Both sides commit to one data plane via an encrypted
  `RouteDecision`; the returned `SecureStream` reports
  `HolePunchedDirect` or `RelayForwarded` in `channel_type()`.
- `SecureStream` transport abstraction: `ByteStream` / `ErasedStream` let the
  unchanged handshake run over TCP, the UDP ARQ or an ordered WebSocket.
  `socket_mut()` is replaced by `shutdown()` / `remote_addr()`; `into_split()`
  now splits the erased stream. Existing LAN TCP callers are source-compatible.
- `luciola::stun`: RFC 5389 Binding client (IPv4/IPv6 XOR-MAPPED-ADDRESS,
  Binding Error Response, strict length/padding checks, 5 s query deadline)
  and a `luciola-cli stun` probe with `--timeout-secs`, `--probe-nat` and
  `--json`, shared default servers
  and a non-zero exit code on failure. The probe no longer claims a NAT
  mapping-behaviour classification that one Binding response cannot support.
- `luciola::traversal`: `TraversalSession` keeps **one** UDP socket for STUN,
  punching and the data plane; `peer_udp_targets` preserves the reflexive port.
  UDP bind failure returns `io::Result` rather than panicking, and a failed
  candidate race returns `NoRoute` rather than falsely reporting a relay.
- `luciola::pairing`: v3 pairing URI carrying an optional PSK, and deterministic
  HKDF-SHA256 rendezvous room derivation.
- `luciola-proto`: `ChannelType`, `RelayConfig`, `TraversalCandidates` (with
  `udp_port`) and the `quota_exceeded` error code.
- `deploy/cloudflare-signaling`: Worker + Durable Object rendezvous service
  with `src/auth.js` and an `npm test` suite. Ed25519 edge verification is
  aligned with the Rust client, with bounded epoch windows, nonce replay
  protection, join/message rate limits, a 32 KiB frame cap, hibernation and
  blind forwarding of opaque encrypted frames.
- **Deployed-Worker verification tooling**: `scripts/deploy-signaling.sh`
  accepts a minimally scoped `CLOUDFLARE_API_TOKEN` (verified against the token
  endpoint rather than `wrangler whoami`, which a scoped token cannot satisfy),
  `scripts/probe-signaling.py` asserts a real signed `101` upgrade carries
  `x-luciola-epoch` matching `/health`, and `scripts/wan-proxy-tunnel.py`
  bridges a loopback `ws://` client to a deployed `wss://` Worker through
  `HTTPS_PROXY` when local DNS is hijacked. `wan_local_worker.rs` gained a
  configurable connect timeout and now skips its plaintext `/health` assertion
  for `wss://` endpoints.
- **Native HTTP CONNECT proxy support** (`wan::proxy`): `connect_wan` can now
  reach a deployed `wss://` Worker through `HTTPS_PROXY` / `https_proxy`
  (`ALL_PROXY` / `all_proxy` fallback), respecting `NO_PROXY` / `no_proxy` and
  always bypassing loopback. `WanConfig::proxy` forces one proxy (`Some("")`
  disables proxying); that explicit field is Rust-core/CLI only, the binding
  surfaces use the environment. CONNECT supports Basic credentials, bounds the
  response headers and rejects non-200 replies with the status. TLS, SNI and the
  Ed25519-authenticated upgrade are unchanged — the proxy sees the hostname and
  timing, never a signalling payload. `scripts/wan-proxy-tunnel.py` is retained
  for diagnostics but is no longer required. In-process tests cover proxy URL
  parsing, `NO_PROXY` matching, a real fake CONNECT proxy with Basic auth, a
  rejected 407 tunnel and loopback bypass.
- All three binding surfaces regenerated (KMP, Swift, Node) and verified
  byte-identical to a fresh bindgen run.
- **Progressive WAN connection with hot migration** (`wan::adaptive`): a
  zero-wait relay stream starts immediately over the signalling WebSocket
  while candidates are gathered and punched in the background;
  `migrate_propose` / `migrate_ack` cut the authenticated stream over to the
  direct UDP path, and `SecureStream::channel_type` tracks the active plane
  through an `AtomicU8`. `luciola-cli transfer send` / `recv --progressive`
  drive it. A dead direct path fails the stream rather than silently falling
  back to a relay nobody drains (see `docs/DECISIONS.md`).
- **RFC 5780 NAT behaviour discovery**: `stun::probe_nat_behavior` handles
  CHANGE-REQUEST, RESPONSE-ORIGIN and OTHER-ADDRESS across multiple servers;
  `NatClassification` and `decide_traversal_strategy` pick the route, and two
  symmetric-NAT peers bypass punching entirely instead of waiting out a
  doomed timeout. `luciola-cli stun --probe-nat` (alias
  `--probe-nat-behavior`) exposes the diagnostic.
- **Resumable transfers**: `TransferMeta` (`LUCMETA1` header, CRC-32, SHA-256,
  chunk bitmap) plus `<file>.luciola-meta` / `<file>.luciola-part` sidecars in
  `luciola-transfer`. The receiver advertises its contiguous resume offset,
  the sender fast-forwards on the resume `FileAck`, and the CLI derives a
  stable transfer ID from file mtime and length. Bitmap writes are batched
  and only follow `sync_data` of the bytes they describe.
- **USB ADB direct transport**: `ChannelType::UsbAdbDirect` and
  `--adb-device <serial>` on `transfer send` / `recv`. The sender runs
  `adb forward tcp:P tcp:P` and removes it on exit; the receiver sets up
  nothing. It is a physical-bus path, still over the same `SecureStream`
  handshake.
- **AIMD congestion window** (`wan::arq`): `AimdWindow` is shared by both UDP
  ARQ drivers. The in-flight budget starts small, grows with acknowledged
  bytes and halves on a loss signal, enforced through the bridge's flow
  credit cap so the writer and the driver obey the same ceiling.
- **Signalling Worker**: pre-join frames are buffered opaquely in Durable
  Object storage (bounded at 32 frames) and replayed when the second peer
  joins, so an initiator is no longer stranded without the peer's candidates;
  relay writes are paced by `RelayPacer` against a 256 messages/second budget.
- `luciola-proto`: `ChannelType::from_u8` replaces a hardcoded byte
  discriminator. `docs/DECISIONS.md` gains six entries covering migration
  failure, checkpoint ordering, ADB setup, post-migration EOF, quota
  admission and server-epoch alignment.
- **Real-NAT operator runbook.** `docs/field-test-record.md` now spells out how
  to produce one matrix row: two machines on two access networks, an offline
  preflight, the shared 32-hex room / PSK / seed / pin values, receiver-first
  ordering, the 600-second epoch constraint, why proxy environment variables
  must be cleared on field machines (otherwise relay bytes egress through the
  proxy instead of the NAT under test), and what to capture beyond the JSON
  record (relay usage, carrier, `NoRoute`). It contains no
  results — the matrix is still empty.
- **Production deployment plan.** `deploy/cloudflare-signaling/README.md` now
  carries a *not-executed* checklist: decisions due before the first production
  deploy (the `/health` version tag, a fresh Durable Object namespace, billing,
  no public release), offline preflight, scoped credentials, three separate
  post-deploy verification layers and rollback. `scripts/deploy-signaling.sh`
  gains `--dry-run` (print the exact wrangler command without contacting
  Cloudflare) and `--self-test` (offline argument regression checks).
  **Production is still not deployed.**
- **`transfer send` / `recv --punch-timeout-secs`.** `connect_wan` waits 5 s
  for the peer's candidates and then exits, which is fine for an automated test
  that starts both sides together and hostile to a two-person field run. The
  wait is now a CLI flag (default unchanged at 5). The field harness passes 60.
- **The NAT matrix record now says which path won.** `transfer.channel` carries
  the sender's `[INFO] Active channel:` value and `transfer.upgraded_to` the
  post-upgrade channel, so a row distinguishes a punched path from a relayed
  one. The harness used to discard the sender's output entirely, which forced
  the operator to retype `channel_type` from a terminal — a relay-only row and
  a punched row were otherwise identical.

### Fixed

- `SecureStream`'s AES-GCM strictly-increasing counter nonce is no longer
  exposed to UDP reordering: the ARQ layer delivers ordered bytes. UDP
  half-close now retransmits `CLOSE`, waits for the peer's final sequence and
  has a bounded idle timeout instead of hanging or truncating the tail.
- Relay writes are chunked under the receive cap and use an explicit ordered
  EOF marker; route decisions can no longer diverge between the two peers.
- `FileSender::check_channel_policy` is now called by the real CLI send path
  before the first intro frame, so the relay byte cap is actually enforced.
- `SECURITY.md`, `RelayConfig` docs and the Worker README no longer describe
  the WAN data plane as absent/unwired.
- Verification claims now name their layer: `SECURITY.md`, `CHANGELOG.md`,
  `docs/audit-scope.md` and both READMEs distinguish the deployed **staging**
  Worker from an undeployed production, and no longer say the WAN channel API
  is absent from the uniffi/Node surfaces. The real-NAT, real-device and audit
  caveats stay in place.
- The Rust client can now actually complete a `wss://` handshake.
  `tokio-tungstenite` enables rustls with `default-features = false` and no
  crypto provider, so `ClientConfig::builder()` panicked on the first TLS
  connection; every earlier WAN test used plain `ws://` loopback or terminated
  TLS inside `scripts/wan-proxy-tunnel.py`. `wan::signaling` installs the
  `ring` provider once (keeping an embedder-installed provider if present), and
  `rustls` is an explicit workspace dependency with that feature. This was
  exposed by removing the bridge, not by the proxy code itself.
- Aliyun Gradle mirrors are opt-in **fallbacks**
  (`-PluciolaUseAliyunMirrors=true`), placed after `mavenCentral()` / `google()`
  so official registries always resolve first and can never be shadowed in a
  published build; `AGENTS.md` documents the constrained-network flag and
  `node_modules/` is gitignored.
- **One UDP socket for the whole traversal session.** STUN, hole punching and
  the data plane now share a single socket and the advertised srflx candidate
  keeps its reflexive port; the earlier path gathered candidates three times
  and advertised a mapping it had already dropped.
- **Migration is barrier-aligned and terminates.** Both peers stop writing the
  relay at the same point; a closed signalling WebSocket no longer leaves the
  connection loop spinning; post-migration `KIND_CLOSE` datagrams set
  `peer_eof` and are retransmitted like data, so a successful migration no
  longer leaks a driver task. Regression tests cover both the close path and
  a direct path that dies.
- **STUN no longer invents a verdict on failure.** Timeouts and ignored
  CHANGE-REQUESTs report `Unknown` instead of `EndpointIndependent`,
  OTHER-ADDRESS is preserved verbatim, and a classification is issued only
  when both mapping and filtering dimensions are known.
- **UDP ARQ**: duplicate DATA always produces an ACK, retransmits use
  exponential RTO backoff, and relay half-close splits inbound/outbound so an
  EOF cannot kill the write side.
- **Checkpoint integrity**: only fully covered chunks are marked, the bitmap
  is written in batches (~64 per transfer) and never before `sync_data` of the
  bytes it describes, so a power loss cannot leave an unchecksummed hole on
  resume.
- **Relay quota admission waits for the routing verdict**, not a fixed 1.5 s
  window: `punching_done` is raised on every `discover_and_punch` return path
  and `SecureStream::wait_channel_settle` releases the wait. A slow but
  successful punch of a large file is admitted on its merits; a relay-bound
  connection is still refused promptly.
- **ADB setup fails loudly**: a failed `adb forward` is fatal, the receiving
  side no longer runs a conflicting `adb reverse`, and the forward is removed
  on exit (including via a Drop guard).
- Worker Durable Object forwarding is guarded against closed sockets, and the
  CLI/transfer suites no longer share a temp directory between parallel
  tests. Two pre-existing transfer flakes (a shared quota directory and a
  post-completion final-ACK write error) are fixed.
- `ChannelType::from_u8` replaces hardcoded byte discrimination and `to_hex`
  no longer allocates.
- `scripts/publish-maven-local.sh` now forwards `HTTPS_PROXY` to the Gradle
  JVM, accepts `LUCIOLA_USE_ALIYUN_MIRRORS=1` and
  `LUCIOLA_SKIP_LINT_ANNOTATIONS=1` for constrained networks, and verifies
  the AAR's arm64 `.so` sha256 against the freshly built jniLibs copy.
- **Epoch drift no longer strands two peers in different rooms.** The room id
  is HKDF-derived from the PSK, both public keys *and* the epoch, so peers on
  opposite sides of a 10-minute boundary were not merely early/late — they were
  in unrelated rooms and could never meet, and the Worker's `epoch ± 1`
  admission window did not help because each side is routed by its own epoch.
  The Durable Object now returns `x-luciola-epoch` on the `101` upgrade and
  `connect_wan` re-derives the room at the server's epoch and redials once, but
  only when the caller left `WanConfig::epoch` at `0` and the supplied room is
  the one the local epoch would derive. A pinned epoch or a hand-written room
  is left alone. Regression tests cover both the realignment and the
  pinned-epoch guard.
- **Android demo keeps presence in the background.** The engine moved out of
  `MainActivity` into `LuciolaPresenceService`, a `connectedDevice` foreground
  service (`START_STICKY`), with the UI rendering a process-wide `PresenceBus`.
  `connectedDevice` rather than `dataSync` because Android 15+ caps `dataSync`
  at 6 h per 24 h; its prerequisite is satisfied by the
  `CHANGE_WIFI_MULTICAST_STATE` the app already declares. Adds
  `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE` and
  `POST_NOTIFICATIONS` (runtime on API 33+). A failed engine bind stops the
  service instead of leaving a notification that claims it is running.
- **iOS demo declares what iOS will actually give it.** `BackgroundPresence`
  registers a `BGAppRefreshTask` before launch completes and re-submits it
  before doing any work, `AppDelegate` handles APNs registration and silent
  pushes, and the engine is stopped when the granted budget expires. Presence
  on iOS remains **foreground plus opportunistic refresh** — there is no
  foreground-service equivalent, and the `voip`/`audio` background modes that
  would fake one are rejected on review. `project.yml` gains a partial
  `Info.plist` with `UIBackgroundModes` and `BGTaskSchedulerPermittedIdentifiers`.
- **`LuciolaUniFFI.xcframework` rebuilt.** The checked-in Swift bindings had
  gained the WAN surface while the prebuilt static library was still the
  0.10.0 binary, so the iOS demo failed to compile on the missing
  `uniffi_luciola_uniffi_checksum_*_connect_wan` symbols. The xcframework is a
  gitignored build artifact; `bindings/luciola-swift/build-xcframework.sh`
  reproduces it and the demo now builds against it.
- **`docs/audit-scope.md` — the audit package.** What an external reviewer
  should read, in order, with the twelve invariants the code claims, the test
  that asserts each one, the questions worth answering explicitly (ARQ re-seal
  behaviour, unbounded-memory paths, the migration barrier when a side dies
  mid-handshake, epoch-header spoofing) and an explicit list of the evidence
  that does **not** exist. It states plainly that it is a package, not evidence
  that a review happened.
- **Field-test tooling for the real-NAT matrix.** `luciola-cli stun
  --probe-nat --json` emits one JSON object (stdout is then nothing but JSON),
  with the readable mapping/filtering labels, the IPv6 candidates, the current
  epoch and a one-sided `prediction` — explicitly not a verdict about the peer,
  which a single-sided RFC 5780 probe cannot know.
  `scripts/field-nat-matrix.sh` records one JSON line per network profile:
  environment, the probe, the signalling Worker's `/health` (so clock skew is
  visible) and, when given WAN arguments, one real transfer. Secrets are passed
  to the CLI and never written to the record. `docs/field-test-record.md`
  documents the 2×2 matrix that a real run needs, and says plainly that the
  script records one side per run and cannot distinguish "migrated to direct"
  from "stayed on the relay".
- **Worker: `/health`, a staging environment and a deploy script.** `/health`
  reports liveness plus the epoch the deployment is serving (public metadata —
  it is derivable from the wall clock and the client already sends its own), so
  a deploy script and the field tooling can prove which build is live and that
  its clock agrees. `wrangler.toml` gains `[env.staging]` with a separate
  Worker name and its own Durable Object namespace, so a staging deploy cannot
  serve production rooms. `scripts/deploy-signaling.sh` runs the Worker tests,
  checks wrangler is authenticated, deploys (staging by default, production only
  with `--production`) and then verifies `/health` — a deploy that succeeds
  while the Worker does not answer is reported as a failure.
- **The real Worker is now exercised, not just a stand-in.** `wrangler dev` runs
  the Worker and Durable Object under workerd, and
  `crates/luciola/tests/wan_local_worker.rs` points the Rust client at it:
  signed upgrade, edge Ed25519 verification, pre-join buffering, encrypted
  handshake and a 96 KiB relay transfer all run against the actual
  implementation. It skips itself unless `LUCIOLA_WAN_WORKER` is set, so CI
  needs no Worker.
- **`scripts/field-nat-matrix.sh` no longer reports a healthy Worker as
  unreachable.** `--send` requires `--worker` to be the `wss://…/ws` signalling
  URL, but the `/health` probe fed that value straight to `curl`, which has no
  `ws://` / `wss://` support and was also pointed at `/ws/health` instead of
  the root. The harness now normalises the endpoint to `https://…/health` for
  liveness while passing the original URL to `--signaling`. Verified against
  the deployed staging Worker: a `wss://` `--worker` now records
  `worker.ok = true` with the live epoch and version.
- **The field harness is self-testable and its peer pin is checked.**
  `--self-test` asserts the URL conversion, scheme rejection and loopback
  `ws://` handling offline — no build, no network call, no field log.
  `--peer-seed` used to be required but ignored; it is now optional and, when
  supplied, derives the peer public key with `luciola-cli transfer pin` and
  aborts early on a `--pin` mismatch instead of failing opaquely
  mid-handshake. `-h` no longer depends on a fixed line range. On macOS bash
  3.2, expanding the empty `"${EXTRA[@]}"` used for the optional
  `--progressive` flag made `set -u` abort every non-progressive `--send` run
  before the transfer even started; the expansion is now guarded, and both the
  plain and `--progressive` send paths were exercised end to end against an
  unreachable loopback endpoint.
- **`scripts/deploy-signaling.sh --production` can now run at all.** Production
  is the top-level wrangler environment, so its `DEPLOY_ARGS` array is empty;
  on macOS bash 3.2 the unguarded `"${DEPLOY_ARGS[@]}"` aborted with
  `unbound variable` under `set -u` before `wrangler` even started. Staging
  always passed `--env staging`, so the defect was invisible in every prior
  deploy. The expansion is now guarded and `--self-test` asserts both
  environments' exact commands. `-h` no longer uses a fixed line range.
- **The deploy tool version is now honest.** `deploy/cloudflare-signaling/package.json`
  declared `wrangler ^3.100.0` while `4.161.0` was installed (`npm ls` reported
  `invalid`), and there is no `package-lock.json`. It is now pinned to the exact
  installed version, the only reproducibility anchor in the absence of a lockfile.
- The deploy script header and Worker README no longer claim the script never
  *reads* `CLOUDFLARE_API_TOKEN`: it reads the environment variable and sends
  it in an `Authorization` header. The corrected claim is that the token is
  never written to disk, logged or printed.

### Changed

- `RelayConfig::default()` is now deny-by-default (`allow_relay` and
  `allow_wan_signaling` both `false`) in line with SECURITY.md.
- A missing PSK no longer silently becomes an all-zero HKDF key:
  `derive_rendezvous_room_id_flexible` returns an empty room ID instead.
- `SECURITY.md` now documents the implemented signalling/data planes, the
  cloud-side observer, encrypted frame guarantees, Worker abuse controls and
  the extended pre-audit review checklist.
- Both UDP ARQ drivers now share one `AimdWindow` policy, and the bridge flow
  credit cap is the enforcement point instead of a second driver queue.

### Verification layer and remaining limits

Verified locally on **2026-11-13**, after the fixes above: `cargo fmt --all
-- --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all-targets --all-features` (26 test binaries, 0 failures), KMP
compiles for Android / JVM / iosArm64 / iosSimulatorArm64, `cargo build -p
luciola-node` plus `bindings/luciola-node/test.js`,
`bindings/luciola-node/test/forward.test.mjs` and
`bindings/luciola-node/test/contract.test.mjs`, and the Worker
`node --test test/*.test.js` suite (9/9). KMP (five source sets) and Swift
(two files) bindings were regenerated from the current Rust core — this batch
**does** extend the uniffi surface with the WAN types (`WanConfig`,
`WanChannel`, `connectWan`, `wanCurrentEpoch`, `wanDeriveRoomId`), and the
regenerated sources are byte-identical to the checked-in copies. The mavenLocal
AAR in this coordinate is rebuilt with a fresh arm64 `.so`; compare its sha256
against the freshly built jniLibs copy before treating the package as current.

Mobile demos: `:app:compileDebugKotlin`, `:app:assembleDebug` and
`:app:lintDebug` pass for `examples/android-demo`, the merged manifest carries
the three background permissions plus
`foregroundServiceType="connectedDevice"`, and `xcodebuild` builds
`examples/ios-demo` for the iPhone 17 Pro simulator with zero errors against a
freshly rebuilt `LuciolaUniFFI.xcframework`.

The `ring` crypto-provider fix needed a fresh iOS binary, so on 2026-11-13
`bindings/luciola-swift/build-xcframework.sh` rebuilt both slices from the
current core (`aarch64-apple-ios` and `aarch64-apple-ios-sim`, each now
compiling `ring v0.17.14` / `rustls v0.23.46`). Static-lib sha256: device
`9f4a7965730ca0e5f4a716cf2e997524549be3266967c206a67b9679531bbb98`, simulator
`b58701c760d771b7fbafdf90504ddd9e8ceb9e2847f2e74a4306ebbd5d32d23f`;
ring/rustls object members went from 22 to 38 per slice. Disassembling the
rebuilt library shows `uniffi_luciola_uniffi_checksum_func_connect_wan`
returning `30765` (`mov w0, #0x782d; ret`), exactly the value the checked-in
`bindings/luciola-swift/luciola_uniffi.swift` asserts — a static ABI check, not
a runtime contract run. `xcodebuild` links `examples/ios-demo` against it for
the arm64 iPhone 17 Pro simulator (**BUILD SUCCEEDED**); a generic `iOS Simulator`
destination fails because the framework deliberately ships no x86_64 slice.
The linker emits 22 warnings that `ring` assembly objects were built for
iOS-simulator 26.2 while the demo targets 16.0.

The demo was then **launched**, not just linked: `xcrun simctl install` plus
`launch` on the booted iPhone 17 Pro simulator, with the process staying up and
holding `UDP *:17880`. The running app shows `引擎在线`, which
`DiscoveryModel` derives from `session.isBound()` after a 2.5 s settle, together
with 7 candidate addresses and the subnet broadcast `192.168.2.255` — values
computed by the Rust core (`luciola-net`) inside the simulator process. That
turns the iOS layer from compile/link into a **runtime** result for launch,
engine bind and interface enumeration. Still unverified on iOS: peer discovery
inside the simulator (Mac broadcast frames are not looped back, and two engines
cannot share a host because the discovery socket binds exclusively),
`BGAppRefreshTask` firing and silent-push delivery.

The field harness was exercised against the deployed staging Worker with a
`wss://` `--worker` URL: `/health` returned `ok=true`,
`version=0.11.0-local.1-staging`, epoch `2990907`, and the offline
`--self-test` plus the `--peer-seed` mismatch path both behaved as specified.
That is a harness check, **not** a field row.

The **operator CLI path** — the commands in `docs/field-test-record.md`, not
the Rust test harness — was then run against the deployed staging Worker over
this host's `HTTPS_PROXY` (its `*.workers.dev` resolver is hijacked, so `wss://`
needs the native CONNECT path). Three runs of 1 MiB with both peers on one
host: `transfer.channel=hole_punched_direct` in 5 s; `relay_forwarded` upgraded
to `hole_punched_direct` in 6 s under `--progressive`; and one harness-recorded
row carrying `channel=relay_forwarded, upgraded_to=hole_punched_direct`. Every
received file matched the sender's sha256
(`4e0bbbc8c755d51b8eb23ec9b322f528da0c1dea38433391b605016557c7f32d`). The
progressive run logged the winning candidate as `192.168.2.82` — a **LAN**
address. That is why one host cannot produce a matrix row: the "direct" path
resolved inside the local subnet and never crossed a NAT, so the row would
report a punch that says nothing about NAT traversal.

The production deploy work was checked **offline only**, on macOS bash 3.2:
`bash -n scripts/deploy-signaling.sh`, `--self-test` (4 assertions),
`--dry-run --production` and `--dry-run --staging` printing the exact wrangler
commands, `-h`, and `--check` against an unreachable loopback endpoint.
No Cloudflare call, no deploy, no configuration change on any live service and
no push/tag/public publish was made. Production remains undeployed.

Earlier loopback integration tests still cover a 64 KiB encrypted relay
transfer over a local blind-forwarding WebSocket, a real secure handshake
over the UDP ARQ stream, ARQ loss/reorder recovery, and STUN CLI process
tests. The new work — RFC 5780 classification, progressive migration,
resumable checkpoints, the AIMD window, the ADB path and epoch realignment —
is covered at the **unit / process-test / loopback layer only**, not on a real
NAT or a physical device in this gate. The epoch tests use a room-keyed local
forwarder that advertises a server epoch one window behind the clients, so the
redial path is exercised without a deployed Worker.

The Worker itself is exercised for real against `wrangler dev` (workerd + a
local Durable Object): `crates/luciola/tests/wan_local_worker.rs` drives two
Rust clients through the signed upgrade, edge Ed25519 verification, pre-join
buffering, the encrypted handshake and a 96 KiB relay transfer, and asserts
`/health` reports an epoch within one window.

On the **deployed staging** Cloudflare runtime (2026-11-13): `/health` reported
`0.11.0-local.1-staging` with an epoch matching the client's,
`scripts/probe-signaling.py` observed a signed `101` upgrade carrying
`x-luciola-epoch`, and `wan_local_worker.rs` ran two Rust peers through the
deployed Durable Object via `scripts/wan-proxy-tunnel.py` (edge Ed25519
verification, pre-join buffering, 96 KiB relay transfer). The bridge recorded
~198 KiB to and ~199 KiB from the Worker. That run was relay-only, single-host
and proxied because this host's `*.workers.dev` DNS is hijacked — it exercises
the deployed signalling path, **not** hole punching or a real NAT. Production
is not deployed.

**Not** verified: no real-NAT / carrier-grade-NAT field test (the field harness
has only a `local-smoke` record from this host, no paired two-network rows;
`docs/field-test-record.md` now has an operator runbook and the harness has an
offline `--self-test`, but neither is a run), no
production deployment or test (the Worker README has a deployment plan and the
deploy script has offline `--self-test` / `--dry-run`, but neither is a
deploy), no real-device background verification on either mobile platform (Android: Doze,
OEM battery managers, the notification permission prompt; iOS:
`BGAppRefreshTask` scheduling and silent-push delivery, which need a signed
build with an `aps-environment` entitlement and a server holding the APNs key),
and no external audit of the ARQ, signalling frame composition, migration
protocol, checkpoint format or Worker auth path. WAN remains
unvalidated on real networks — this is why the build is mavenLocal-only.

## [0.10.0] — 2026-11-05

### Breaking

- **Rust API:** every public error enum is now `#[non_exhaustive]`:
  `ProtoError`, `NetError`, `CoreError`, `LinkError`, `RelayCryptoError`,
  `PortRegistryError`, `TransferError`, `TunnelError`, `MuxError`.
  Downstream code that matched one of these exhaustively must add a `_ =>`
  arm. This is the point of the 0.10 window: a new error variant can ship in
  a patch release without breaking a consumer's build. The FFI surfaces are
  unaffected — they already project onto the stable `ErrorCode` table, whose
  unknown codes degrade to `unknown`.

### Added

- **`luciola-cli transfer send|recv|pin`**: the first production driver for the
  `luciola-transfer` state machine. A new `FileIntro` wire frame names the
  transfer and file so the receiver can size its state before the first chunk;
  `run_send` / `run_recv` pump both directions over a real `SecureStream`
  (serial driving deadlocks once the window exceeds the socket buffer). Pins
  are mandatory on both sides — deny-by-default, no TOFU. The receiver keeps
  only the basename of the peer-supplied file name, so a malicious
  `../../…` cannot escape `--out`, and prints a SHA-256 receipt at completion.
- Process-level CLI tests: a real two-process loopback transfer (ephemeral
  port read back from the listening line), a wrong-pin rejection that asserts
  no file is written, and a `transfer pin` identity check. The unit tests in
  `src/transfer.rs` cover a 512 KiB round trip and the path-traversal guard.
- **One structured error taxonomy across every surface.** `luciola_proto`
  gains `ErrorCode` (21 stable `snake_case` codes, `#[non_exhaustive]`) and
  `ErrorInfo` (code + original message + `retryable` hint). Each crate maps
  its own error enum via `From<&Err> for ErrorInfo`, so Android, iOS, Swift
  and Node report the same code for the same failure. `wire_detail()` keeps
  the legacy `"<code>: <message>"` string form and `parse_detail()` inverts
  it, mapping the TUNNEL_SPEC prefixes (`forward_bind_failed:`,
  `tunnel_bind_failed:`, `tunnel_link_failed:`, `tunnel_handshake_failed:`)
  onto canonical codes without changing the wire strings.
- **uniffi**: `ErrorInfoDto { code, message, retryable }`, `errorCodes()` and
  `classifyError(codeOrDetail, message?)`. Additive — existing listener
  signatures are untouched.
- **Node**: `getErrorCodes()` and `classifyError(detail)`; discovery `error`
  events now carry `code` / `message` / `retryable`; `SecureChannel` `error`
  and `retrying` events carry a nested `error` object alongside the legacy
  `detail` string. `index.d.ts`, the runtime contract test and the TypeScript
  consumer check cover all of it.
- KMP facade helpers `luciolaErrorCodes()` and `luciolaClassifyError()`.

### Changed

- **The public Rust API is documented and the gap is now enforced.** All 411
  `missing_docs` warnings are gone: `#![deny(missing_docs)]` is enabled in
  `luciola-proto`, `luciola-net`, `luciola-transfer`, `luciola-tunnel`,
  `luciola` and `luciola-uniffi`. Documentation comments flow into the
  generated Kotlin/Swift bindings, and — because uniffi folds docs into its
  metadata checksum — both binding surfaces were regenerated. The Node surface
  is fully documented too, but cannot deny the lint crate-wide: `#[napi]` on a
  class generates undocumented wrapper functions, so the lint would fail on
  macro output.
- **Node discovery `error` events (behaviour change).** `message` is now the
  human detail without a code prefix; the code moved to its own field. A host
  that parsed the old flattened `"<code>: <message>"` string must switch on
  `code` instead. The Node package is still unpublished on npm, and the other
  two surfaces keep their existing string callbacks unchanged.
- README / README.zh-CN now describe the transfer CLI instead of the
  "Rust-core only, no CLI command" downgrade note. The crate remains without
  a KMP / Swift / Node surface.

## [0.9.3] — 2026-11-05

### Fixed

- **PONG/ACK replies no longer stall the shared mux read task** (`e61029a`).
  `send_ctrl` awaited `send()` on the single shared outbound FIFO — with the
  queue full, that backpressured `reader_loop` and serialised every channel's
  OPEN/ACK/DATA handling (the outbound twin of the 0.9.1 inbound-stall fix).
  PONG/ACK are must-not-lose frames and now ride the same `defer_ctrl` path as
  WINDOW/EOF/CLOSE; the local TUNNEL_SPEC §1.4 was synced to the single-FIFO
  reality.
- **Device detection no longer freezes hosts** (`cc638d4`). The Node binding
  ran the subprocess-based `DeviceDetector::detect()` synchronously on the
  N-API main thread inside `start()`; the uniffi binding ran it on its
  current-thread runtime's only worker. Both now run it via `spawn_blocking`.
- Silent failures on the discovery and link paths are visible
  (`5668236`): a failed discovery-socket restart logs at error level (after it
  discovery is down with zero output — previously unreportable), listener
  socket-option failures warn, presence-probe/profile-refresh wire failures
  and broadcast events dropped for lack of subscribers log at debug.

### Added

- **Platform log sink on both FFI surfaces** (`2ae363e`): uniffi
  `set_log_sink(LogSink)` and Node `setLogSink(cb)` deliver engine tracing
  logs as `(level, message)` to the host. Additive API; per AGENTS.md §3 the
  KMP and Swift bindings were regenerated in the same change and the iOS
  staticlibs/xcframework rebuilt. The process-wide subscriber yields to a
  host-owned one by design.
- `DiscoveryEngine::spawn_tracked()` (`5cf197f`): the additive first-class
  stop story for Rust embedders — the JoinHandles of the three engine loops.
- Peer-registry eviction (`5cf197f`): entries whose peer has been silent for
  over an hour (clamped to ≥ 2× `offline_after`) are removed — the table used
  to grow without bound on long-running engines.
- MSRV declared: `rust-version = "1.88"` workspace-wide, verified on a pinned
  toolchain (1.87 cannot resolve the dependency tree), and gated in CI
  (`e33de51`).
- tokio features narrowed per crate instead of workspace-wide `full`
  (`9bb70b9`).
- CLI input-parsing unit tests, and a real EOF assertion replacing a
  matches-everything tautology in the window-park survival test (`5722ba2`).

### Changed

- God modules split into focused files (`322f340`): `mux.rs` 2431 lines →
  6 files, `tunnel_link.rs` 1642 → 5, core `lib.rs` → `engine.rs` +
  `registry.rs`. Pure refactor, public API re-exported unchanged; the two
  hand-written FFI surfaces stay whole deliberately.
- `luciola-transfer` is explicitly documented as a Rust-core building block —
  no CLI command or FFI surface yet, its own tests are the only driver
  (`d1c04d2`).

## [0.9.2] — 2026-11-05

### Fixed

- **Tunnel datagram writers can no longer hang forever on a torn-down channel**
  (`d6f85fb`). `send_datagram`'s window-wait loop checked the channel-dead flag
  before registering its `Notify::notified()` future, and `kill()` uses
  `notify_waiters()`, which stores no permit — a teardown landing between the
  check and the registration lost the wakeup and parked the writer until
  session end. The wait now registers the `notified()` future *before* any
  state check, so a `kill()` either wakes the task or is already visible in
  the dead flag. The credit path (`notify_one`) was always permit-preserving
  and is unchanged.
- **Node `DiscoverySession` event stream no longer silently dies** (`69390b8`).
  The engine loop patterned on `Ok(event) = events.recv()`; a broadcast
  `RecvError` (a `Lagged` burst is enough) disabled the select branch and the
  session stayed alive delivering nothing. Lag now continues, a closed channel
  exits. The CLI beacon's neighbor watcher had the same `while let Ok` shape
  and got the same fix (`24bbd2b`).
- **Node `index.d.ts` matches the native surface** (`0c7f8e1`). `JsPeerRecord`
  documents `extra`, the `DiscoverySession` constructor documents all nine
  parameters, `JsPairingInfo` documents `publicKey`, and `buildPairingUri`
  documents its real seven-parameter shape — a caller following the old
  declaration passed a PIN into the `publicKey` slot. `stats()` now exposes
  `framesEnqueued`/`framesDequeued`, the same six counters as the uniffi
  `LinkStats`.
- **iOS demo compiles against the generated bindings again** (`5d4c47a`): the
  demo still called the four-argument `DiscoverySession` convenience init.

### Added

- **Node runtime and type-level contract gates** (`f61d9ba`).
  `test/contract.test.mjs` pins the pairing-URI slot placement, the
  nine-argument constructor (an advertised `extra` must arrive on peer
  objects) and the exact six-field `stats()` shape; `npm run typecheck`
  compiles a documented-call-shape consumer against `index.d.ts`. The smoke
  test now also asserts the pin/publicKey roundtrip.
- **CI contract gates** (`96cfe16`). The Node job runs on Ubuntu as well as
  macOS and runs the contract test plus the type check; the KMP job runs
  `:luciola:jvmTest` against a freshly built host library (previously it only
  compiled Kotlin); a new job build-checks the iOS demo — the gate that would
  have caught the demo drift above.

### Changed

- Documentation: CONTRIBUTING.md's stale "CI runs `test.js` only" note, the
  integration handbook's pairing snippet (same PIN-slot trap), and the
  android-demo dev-wiring comment now describe the current state
  (`0331063`, `b889261`).

## [0.9.1] — 2026-11-03

### Fixed

- **Tunnel multiplexing (`luciola-tunnel`):** a channel whose consumer stops
  reading no longer stalls the entire session. The shared read task used to
  await that channel's bounded inbound queue, so one blocked channel serialised
  every other channel's OPEN/ACK/DATA and could make an unrelated `open()` time
  out (observed on Windows first, where socket buffers are smaller). Frames now
  pass through a per-channel staging queue with a byte budget
  (`window_size` + one frame); the bounded queue and the section 1.4 stall
  cut-off moved into that channel's own forwarder. Public API unchanged; a v2
  peer that honours its window never reaches the budget.
- **CI could not answer "is Windows green?"** The Rust matrix cancelled sibling
  OS jobs when one failed, so a macOS flake hid the Windows result. The matrix
  now runs every leg; Windows-only test defects (2.0 s loopback dial refusal vs
  a 1.5 s test timeout, test ports taken from the OS ephemeral range,
  assert-immediately-after-dialer-event) are fixed in the tests, and the macOS
  transfer E2E treats a peer close as end-of-input instead of panicking.
- `LICENSE-APACHE` is the complete Apache-2.0 text. The previous file stopped
  inside section 3, which made GitHub report "Other" instead of the dual
  MIT/Apache-2.0 license every crate declares.

### Changed

- crates.io metadata: every crate now declares `keywords`, `categories`,
  `homepage` and `documentation`, so the crates can be found through registry
  facets and lib.rs category pages (these take effect on this release).
- Documentation: README install snippets name 0.9.1, the iOS simulator test
  command is runnable from a fresh clone, and the KMP binding README describes
  the iOS cinterop targets and JNA dependency accurately.

## [0.9.0] — 2026-11-03

### Changed

- **Breaking (Rust API):** `DiscoveryEngine::bind` no longer falls back to an
  ephemeral port when the requested discovery port is occupied; it returns
  `CoreError::BindFailed`. The silent fallback kept announcing into the
  well-known port, so two products joined one broadcast mesh and dialled each
  other's channel ports. Hosts that must stay up without the port opt into
  `DiscoveryConfig::allow_ephemeral_fallback` explicitly and surface
  `local_port()`. The FFI surfaces now report `bind_failed` and
  `isBound() == false` after the documented 5 s retry (the retry was dead code
  while `bind` swallowed the conflict); Node emits `{type:"error"}`.
- Handshakes are time-bounded (5 s on the listener, 10 s on the dialler). The
  single accept slot is still one session at a time, but a client that
  connects and sends nothing can no longer hold it forever, and a dialler
  queued behind a busy listener fails visibly and reconnects instead of
  hanging as "connecting" indefinitely.
- `DiscoveryConfig::product_filter` (Rust) and `luciola-cli agent --product`
  let a host ignore beacons from other products sharing one discovery port.

### Added

- **FFI product isolation:** `DiscoverySession.setProductFilter([...])` (uniffi →
  KMP / Swift) and `setProductFilter(products?)` (Node) wire
  `DiscoveryConfig::product_filter` through the FFI, so a host can ignore beacons
  from other luciola products without filtering in app code. KMP and Swift
  bindings were regenerated (gobley 0.3.7 / uniffi 0.29.4); an old binding paired
  with the new library fails loudly on checksum mismatch.
- `luciola::ports` — port-plan rules (16-port blocks, `tunnel = channel + 1`,
  `screen = discovery + 10`), cross-product conflict detection (legacy
  overlaps warn, live overlaps fail) and a machine probe.
- `docs/PORTS.md` + `docs/ports.json` — the single authority for multi-product
  port allocations, plus `luciola-cli ports --registry <file> [--probe]
  [--json]` to validate it (exit code 1 on a live conflict, warnings for known
  legacy overlaps).
- Regression tests: occupied discovery port -> `BindFailed`; FFI
  `bind_failed` / `is_bound == false`; a silent foreign client times out and
  the listener still serves the legitimate peer; product filter keeps other
  products out of the peer table.

### Fixed

- `SecureSession::listen` keeps its TCP listener for the whole session instead
  of dropping it after each accept. The listener used to disappear within a
  second of accepting, so peers dialling while a channel was live were refused
  and a peer restart wedged both sides (2026-11-02 field evidence: every frame
  became no-ack after the first burst).

---

## [0.8.2] — 2026-10-30

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

### Fixed

- The Swift bindings were never regenerated for the eight `relay_*` exports
  (the KMP bindings were, in `04af23a`). The shipped xcframework therefore
  exposed symbols the Swift layer had no declaration for — invisible at link
  time because nothing referenced them, which is the shape of failure this
  repository keeps paying for. Regenerated (`8f7b9ce`); the change is purely
  additive (a `FfiConverterUInt32` and the eight functions).
- `scripts/publish-central.sh` wiped its staging directory with `rm -rf`, which
  tripped bulk-delete guards and, more importantly, hid why the wipe mattered:
  a leftover `0.8.0` in the bundle makes the upload fail on "already published".
  It now moves the directory aside instead (`b3b176b`).

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
