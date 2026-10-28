# Contributing to Luciola (萤火)

Thank you for taking an interest. Luciola is a Rust core plus first-class bindings
(Kotlin Multiplatform for Android/JVM/iOS, Swift, Node.js). Because "one core, every
platform" is the central promise, most of the rules below exist to keep the Rust core
and the binding layers from drifting apart.

By contributing you agree that your contributions are licensed under, at the
maintainer's option, MIT or Apache-2.0 (see [`LICENSE-MIT`](LICENSE-MIT),
[`LICENSE-APACHE`](LICENSE-APACHE), and the workspace `license = "MIT OR Apache-2.0"`
field in [`Cargo.toml`](Cargo.toml)).

> **Security issues are not feature requests.** Please do not open a public issue for a
> vulnerability, and do not disclose one in a PR. Follow the reporting channel and the
> pre-audit disclosure in [SECURITY.md](SECURITY.md); this document will not repeat that
> policy.

---

## 1. Environment

| Tool | Version | Needed for |
| :--- | :--- | :--- |
| Rust (stable) | latest stable, with `rustfmt` + `clippy` | every crate, all four gates |
| JDK | 21 (Temurin in CI) | KMP + Android Gradle builds |
| Android SDK | `platforms;android-36` (`compileSdk = 36`) | `:luciola:compileAndroidMain` |
| Xcode + Kotlin/Native | current macOS toolchain | iOS klib targets, Swift bindings |
| Node.js | 22 | `@luciola/core` smoke test |
| `cargo-ndk` | optional | building `libluciola_uniffi.so` for the AAR |
| `gobley-uniffi-bindgen` | **0.3.7, pinned** | regenerating the KMP bindings |

`gobley-uniffi-bindgen` is version-coupled to the Rust side:

```bash
cargo install --bin gobley-uniffi-bindgen gobley-uniffi-bindgen@0.3.7
```

`0.3.7` depends on `uniffi_bindgen = 0.29.4`, which is exactly why
`bindings/luciola-uniffi/Cargo.toml` pins `uniffi = "=0.29.4"`. A patch-level mismatch
does not fail loudly — it reads incompatible UDL metadata, or (with a malformed gobley
config) silently emits only `commonMain` and no other source set.

---

## 2. Reproducing CI locally

These are the four gate groups from [`.github/workflows/ci.yml`](.github/workflows/ci.yml),
run in the order CI runs them. Anything failing here will fail the PR.

**1) Rust — fmt, lint, tests (three OSes in CI: ubuntu / macos / windows):**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

**2) KMP, Android + JVM targets** (the Gradle project lives in the demo app, which
`include(":luciola")` points at `bindings/luciola-kmp` — so run it from there):

```bash
cd examples/android-demo
./gradlew :luciola:compileAndroidMain :luciola:compileKotlinJvm --no-daemon
```

**3) KMP, iOS targets** (macOS runner; Kotlin/Native cross-compile):

```bash
cd examples/android-demo
./gradlew :luciola:compileKotlinIosArm64 :luciola:compileKotlinIosSimulatorArm64 --no-daemon
```

**4) Node.js bindings smoke test:**

```bash
cargo build -p luciola-node
node bindings/luciola-node/test.js
node bindings/luciola-node/test/forward.test.mjs
```

CI's Node job runs `test.js` only; `test/forward.test.mjs` is a **local** gate today, so
run it yourself whenever you touch the tunnel or the Node forwarding surface.

CI runs the Rust gate on Windows too. Anything Unix-specific has to be gated (see the
history of `fix(cli): gate the unix-socket agent off Windows`); do not assume a
POSIX-only API is portable without a `#[cfg(unix)]` boundary and a Windows fallback.

---

## 3. Repository layout

Workspace members are declared in [`Cargo.toml`](Cargo.toml).

### Core crates (`crates/`)

- **`luciola-ip`** — pure algorithms, zero dependencies: RFC 4291/4193 IPv6 scope
  taxonomy, `/64` GUA same-LAN matching, `198.18.0.0/15` proxy-TUN filtering. No I/O,
  no `tokio`; keep it that way.
- **`luciola-net`** — network-interface intelligence: physical/virtual NIC scoring,
  WSL2 host passthrough, per-NIC subnet-directed broadcast calculation, device metadata.
- **`luciola-proto`** — the wire protocol: versioned envelopes, jitter scheduling,
  revision sync and dedup state machine. Deliberately zero-I/O so the state machine is
  testable without a socket. Wire-format compatibility is a contract — see §6.
- **`luciola`** — the `tokio` engine: dual-stack discovery, Happy Eyeballs path racing,
  authenticated encrypted channels (`link::secure`), trust store and pairing primitives.
  Re-exports `luciola-transfer` behind the default `transfer` feature.
- **`luciola-transfer`** — chunked file-transfer data plane: absolute-offset writes
  (out-of-order safe), contiguous-prefix ACKs, timeout retransmit, completion answer
  cache. Its dev-dependency on `luciola` is circular on purpose so the E2E tests drive
  real `SecureStream`s.
- **`luciola-tunnel`** — TCP multiplexing (mux v1) and local port forwarding over a
  `SecureStream` (deny-by-default forwarding ACL on the responder side).
- **`luciola-cli`** — `ip` / `scan` / `beacon` / `agent` / `forward`.

### Bindings (`bindings/`)

- **`luciola-uniffi`** (Rust, `publish = false`) — the UniFFI surface:
  `DiscoverySession`, secure channels, pairing, identity helpers. This is the single
  source of truth for the Kotlin and Swift APIs. Changing it is a breaking change for
  three platforms at once.
- **`luciola-kmp`** (Gradle, `io.github.kexuejin:luciola`) — Kotlin Multiplatform
  library: Android AAR (with the Rust `.so` embedded), desktop JVM, iOS klib. Contains
  `UniffiEngineAdapter`, `LuciolaFacade`, `DiscoveryController`, `PeerUiModel`, and the
  `DiscoveryEnginePort` / `NetworkMonitorPort` seams.
- **`luciola-swift`** — generated Swift bindings + `LuciolaUniFFI.xcframework`.
- **`luciola-node`** (Rust N-API, `@luciola/core`) — Node.js/Electron bindings.
- `examples/` — `android-demo` (the Gradle root the CI KMP gates run in), `ios-demo`,
  `web-radar-demo`.
- `scripts/` — `generate-kmp-bindings.sh`, `publish-crates.sh`,
  `publish-maven-local.sh`, `publish-central.sh`.
- `docs/` — `INTEGRATION.md` (the operational handbook), plus migration notes.

---

## 4. Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <subject>

<body: what changed, and why — including how the failure looked>
```

**Types:** `feat`, `fix`, `perf`, `refactor`, `build`, `docs`, `test`, `ci`, `chore`.
Never write a public commit message that describes an exploitable flaw before the fix is
merged — coordinate through SECURITY.md instead.

**Scopes** name the crate or subsystem: `ip`, `net`, `proto`, `link`, `engine`,
`registry`, `pairing`, `transfer`, `tunnel`, `cli`, `stats`, `kmp`, `ffi`, `swift`,
`node`, `android`, `demo`, `docs`, `ci`, `build`, `release`.

Rules:

- **One logical change per commit.** A behaviour change and its test belong together;
  an unrelated cleanup does not.
- **Never write local release state into a subject.** No `mavenLocal`, no version
  numbers in titles, no "regenerate bindings" as a standalone commit. A regeneration is a
  *build artifact of* the commit that changed the Rust API (§7) — fold it in. A version
  bump belongs in a `build(release):` or `chore(release):` commit, never in the feature
  commit. Likewise, fold `style: rustfmt` into the commit whose formatting it fixed; a
  free-standing formatter commit means the gate was skipped on the way in.
- Scope when the change belongs to one crate or subsystem; leave the scope off only for
  genuinely repo-wide commits (`docs:`, `ci:`, `build:`).
- Prefer the imperative mood, and state the symptom in the body when the commit is a
  fix: *"writes no longer silently drop frames when the send fails"*, not *"fix send"*.
- Do not reference a private product, machine path, or account name in a commit message,
  body, or code comment. History is public and rewriting it later is expensive.

If a PR is a mess of local history, we squash-merge with a message you provide.

---

## 5. Code style

- `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings` are
  **hard gates**, not suggestions. Warnings are errors; `#[allow(...)]` needs a comment
  saying why.
- **Comments and KDoc are in English.** The public reading surface — commit messages,
  README and README twin, `docs/`, doc comments on public Rust items, and KDoc on public
  Kotlin API — is English without exception. Some existing Rust and Gradle comments are in
  Chinese where they record hard-won failure detail; they are tolerated as history and
  welcome a translation, but do not add new local-language comments to a public surface.
  Everywhere English and another language compete, English wins — this is a cross-language,
  cross-continent codebase.
- Comments record **why** and **the observed failure mode**, not what the next line
  does. Good: *"the `-libraryPath` flag must go through `extraOpts`, not
  `compilerOpts` — the latter only reaches clang, and the symptom is 'Could not find
  libluciola_uniffi.a binary in neither of []'."* Bad: a changelog of things that were
  fixed and now work. Do not check in a success log.
- Cryptographic material: anything derived from a seed is `zeroize`d on drop
  (established by `security: zeroize key material`). Key material never enters a log, an
  error string, a test fixture, or a commit message.
- Prefer `tracing` over `println!` in library code; the CLI is the only place that
  prints for a human.

---

## 6. Portability red lines

These are real incidents this project has paid for. Each one is a review-rejection, not
a style preference.

1. **No machine-private absolute paths anywhere, not even as a fallback.** A path like
   `/Volumes/...` or `/Users/...`, a username, or a home-relative SDK location baked
   into a build file works silently on the author's laptop and breaks every clone and
   every CI runner. Native-artifact roots resolve in this order:

   1. an explicit override — a Gradle `-P<name>=` property, `LUCIOLA_TARGET_DIR`, or
      `CARGO_TARGET_DIR`;
   2. `cargo metadata --format-version 1 --no-deps` → `target_directory`, because a
      shared `[build] target-dir` in `~/.cargo/config.toml` redirects the output
      directory, so `./target` is **not** a safe assumption;
   3. a relative in-repo fallback (`<repo>/target`).

   Follow the existing implementations: `nativeRoot()` in
   `bindings/luciola-kmp/build.gradle.kts`, `cargoTargetDirectory()` in
   `bindings/luciola-node/index.js`, and the header of `scripts/generate-kmp-bindings.sh`.

   **Why this is a red line and not a preference:** such a default sat in the KMP build
   script and in the Node loader for months. On any other machine the iOS cinterop
   silently received an empty library path — `Could not find
   'libluciola_uniffi.a' binary in neither of []` — and the Node bindings loaded only if
   the developer happened to own that volume.
2. **Tests must not depend on the environment they did not create.** No test may require
   a real NIC with real traffic, a fixed public port, a specific VPN overlay, or a peer
   device that happens to be online. Pure logic goes in unit tests; socket-level tests
   bind port `0` and read back the assigned port; loopback and in-process pairs are the
   default. A test that genuinely needs hardware or a live LAN must detect the absence
   and **skip gracefully** with a printed reason, not fail.
3. **Wire-format compatibility is a contract.** Discovery envelopes are versioned
   (`luciola-proto`). New profile fields are added as `Option`s with serde defaults so an
   old peer still decodes a new frame and a new peer still decodes an old one, and both
   directions get a named test (`legacy_v1_profile_without_public_key_decodes` is the
   template). A silently breaking frame is the worst possible bug here: peers degrade to
   "no discovery", not to an error.
4. **Windows is a CI target.** Any Unix socket, `AF_PACKET`, signal, or `/proc` path
   needs a `#[cfg(unix)]` boundary plus a documented Windows behavior.
5. **Native build artifacts never enter git.** `.so` / `.dylib` / `.a` / `.node` /
   `.xcframework` contents are produced by scripts, not committed; generated binding
   output under `build/` is ignored.

---

## 7. Platform boundary — Rust core vs. binding layer

**Belongs in Rust:** discovery, NIC intelligence and scoring, IPv6 scope math, path
racing, the secure handshake and framing, the trust store, pairing payload construction,
chunked transfer, mux and forwarding. If it is hard, subtle, or security-relevant, it is
Rust, exactly once.

**Belongs in a binding:** threading and dispatch to the UI/main thread, lifecycle
(foreground service, `MulticastLock`, app-freeer survival), platform key storage
(Keychain / Keystore), platform permission prompts, and idiomatic error/callback shapes.
Nothing that changes protocol behavior.

**The rule:** *after changing the Rust interface under `bindings/luciola-uniffi`,
regenerate the bindings and bump the KMP version in the same change.*

```bash
./scripts/generate-kmp-bindings.sh          # writes build/kmp-bindings by default
# copy the generated source sets into bindings/luciola-kmp/src/uniffiKmp/, then:
cd examples/android-demo
./gradlew :luciola:compileAndroidMain :luciola:compileKotlinJvm --no-daemon
```

The generator script is itself a gate: it fails if `nativeMain` is missing, or if
`nativeMain` contains no `kotlinx.cinterop` (which means iOS silently cannot use the
output).

The other two surfaces regenerate differently, and both must move with the Rust change:

```bash
# Swift: regenerate into bindings/luciola-swift/
cargo run -p luciola-uniffi --bin uniffi-bindgen -- generate --language swift

# Node: no generator — hand-edit bindings/luciola-node/src/lib.rs and index.d.ts
#       to match, then run the §2 Node gate.
```

Then bump the KMP `version` in `bindings/luciola-kmp/build.gradle.kts) in the same change
and state the new version in the commit **body** — not the subject (§4).

Why this is a rule and not a tip: a desktop-side fix that was never regenerated into the
Kotlin bindings shipped as "fixed on desktop, still broken on the phone, and nothing
errored." The compiler cannot catch this, because the stale Kotlin file still compiles
against the old signature. The Rust surface, the generated bindings, and the KMP
`version` must move together in one change, and the CHANGELOG entry is written once for
the pair.

---

## 8. Pull request flow

1. Branch from `main`. Keep the diff to one logical change where you can.
2. Run all four gate groups from §2 and report the results in the PR description, or
   state which you could not run and why (e.g. "no Xcode on this machine" — iOS targets
   are then verified by CI and by a reviewer).
3. Add or update a [CHANGELOG.md](CHANGELOG.md) entry under **Unreleased** for anything a
   consumer of the library would notice: a new API, a changed default, a fixed symptom, a
   wire-format addition. Pure refactors, test-only changes, and CI plumbing do not need
   one.
4. **Breaking changes** use a `feat:`/`fix:` subject with `!` before the colon
   (`feat(ffi)!: on_message gains the remote address`) and a `BREAKING CHANGE:` footer
   naming the old and new signature and the migration. Version bump follows semver:
   breaking → minor while `0.x`, major at `1.0.0`. A UniFFI signature change is breaking
   for Kotlin, Swift **and** the generated bindings at once — say so explicitly in the PR.
5. Update [`docs/INTEGRATION.md`](docs/INTEGRATION.md) when the operational contract
   changes (ports, threading, lifecycle, pairing payloads), and both READMEs when a
   headline feature lands; they are kept in sync by hand.
6. A reviewer checks the §6 red lines and the §7 binding-regeneration rule specifically;
   those are the two things most likely to pass CI and still be wrong.

### What makes a good contribution here

A bug report or PR that came from running the thing on a hostile network — a proxy in TUN
mode, an IPv6-only broadband connection, a hotel AP that drops multicast, a phone the OS
froze — is worth more than a hundred lines of refactoring. Every hazard-table row in the
README exists because somebody lived it. If your change makes a documented real failure
go away, say which one.
