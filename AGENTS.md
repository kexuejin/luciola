# AGENTS.md — working rules for this repository

Orienting notes for humans and AI agents working in luciola. Every rule below
corresponds to a defect that actually happened in this repository and got caught
late. Read the **Why** lines before deciding a rule is pedantry.

luciola is **one Rust core with three binding surfaces** (KMP, Swift, Node). The
binding layers are where the real incidents happen: a Rust-side fix does not reach a
phone until the bindings are regenerated *and republished*.

---

## 1. Repository map

```
crates/
  luciola-ip/        RFC scope taxonomy, /64 GUA same-LAN matching, TUN range filter (no_std)
  luciola-net/       NIC scoring, virtual-adapter filtering, subnet-directed broadcasts
  luciola-proto/     wire protocol: versioned envelopes, Profile/PeerRecord, jitter + dedup state machine
  luciola/           tokio engine: dual-stack discovery, Happy Eyeballs racing, SecureStream, trust store
  luciola-transfer/  chunked file transfer data plane (feature-gated as "transfer" in luciola)
  luciola-tunnel/    mux v1 + local port forwarding over a SecureStream
  luciola-cli/       ip / scan / beacon / agent / forward
bindings/
  luciola-kmp/       KMP library: Android AAR + JVM + iOS klib
  luciola-uniffi/    the Rust uniffi crate — every generated binding comes from here
  luciola-swift/     committed Swift bindings + build-xcframework.sh
  luciola-node/      N-API bindings (@luciola/core)
examples/
  android-demo/      KMP/Compose app; also the Gradle entry point CI uses for the library
  ios-demo/          SwiftUI app over the uniffi Swift bindings
  web-radar-demo/    zero-dependency radar page
docs/INTEGRATION.md  integration handbook (ports, foreground service, trust UX, troubleshooting)
scripts/             binding generation + publishing (see §3, §9)
```

The Rust workspace version lives in the root `Cargo.toml` under
`[workspace.package]`; every crate uses `version.workspace = true`.

## 2. Local gate = CI gate. Run it before proposing anything.

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features

cd examples/android-demo
./gradlew :luciola:compileAndroidMain :luciola:compileKotlinJvm --no-daemon
./gradlew :luciola:compileKotlinIosArm64 :luciola:compileKotlinIosSimulatorArm64 --no-daemon

cargo build -p luciola-node
node bindings/luciola-node/test.js
node bindings/luciola-node/test/forward.test.mjs
```

**Why:** the rustfmt check is the *first* CI step, and it was red across 11 files on
a batch whose individual commits each "passed locally", because formatting got run
per-feature and never re-checked over the whole set before it was pushed. Run the
check; never assume the formatter ran.

Clippy is `-D warnings` for **all targets and all features**: `--all-features`
is what pulls the transfer and tunnel codepaths into the lint at all.

## 3. After changing any Rust API, regenerate the bindings in the same change

Rust types are the source of truth for three FFI surfaces. When a `luciola-uniffi`
signature changes (new method argument, new record field, listener arity change):

- **KMP:** run `./scripts/generate-kmp-bindings.sh`, then copy the generated
  source sets into `bindings/luciola-kmp/src/uniffiKmp/`. The script self-checks
  that the generated `nativeMain` really uses `kotlinx.cinterop` — if it does
  not, iOS is broken and the failure is silent downstream.
- **Swift:** `cargo run -p luciola-uniffi --bin uniffi-bindgen -- generate
  --language swift`, into `bindings/luciola-swift/`.
- **Node:** hand-edit `bindings/luciola-node/src/lib.rs` plus `index.d.ts`.
- **Bump the KMP version** in `bindings/luciola-kmp/build.gradle.kts` in the same
  change, and state that version in the commit **body**, not the subject (§7).

**Why:** uniffi embeds metadata checksums, and the AAR/klib ship a *prebuilt* native
library. A Rust fix that is not republished gives you a desktop that works and a
phone that silently runs the old engine, with no error anywhere. Do not try to prove
"the new engine is in the artifact" with `strings | grep some_fn` — small
functions get inlined, so old and new artifacts both show zero hits. Prove it by
version plus build timestamp, or by sha256 of
`lib/arm64-v8a/libluciola_uniffi.so` inside the APK versus the AAR just built.

`uniffi` is pinned `=0.29.4` in `bindings/luciola-uniffi/Cargo.toml`
because gobley-uniffi-bindgen 0.3.7 depends on exactly that `uniffi_bindgen`.
Bumping one without the other fails at bindgen time with a metadata mismatch.

## 4. Version numbers have four homes and must agree

| Where | File |
| :-- | :-- |
| Rust crates | root `Cargo.toml` → `[workspace.package] version` |
| path-dep requirements | each crate: `luciola-* = { path = "..", version = "X" }` |
| KMP artifact | `bindings/luciola-kmp/build.gradle.kts` → `version` |
| npm package | `bindings/luciola-node/package.json` → `version` |

Path-dependency version strings are **compatibility requirements**, not decoration:
they must be satisfiable by the workspace version, or `cargo publish` fails at the
very end of a release. Grep for stale ones when bumping:

```
grep -rn 'version = "' crates/*/Cargo.toml bindings/*/Cargo.toml | grep -v workspace
```

**Why:** this repository shipped a README advertising 0.7.0 while the workspace said
0.3.2, path deps demanded 0.3.1, and the registry maxima were 0.3.1 (crates.io) and
0.4.2 (Maven Central). Anyone copying the install snippet gets an unresolvable
dependency.

**Never document a version as installable without checking that it exists:**

```
curl -s https://repo1.maven.org/maven2/io/github/kexuejin/luciola/maven-metadata.xml
curl -s -H 'User-Agent: docs-check' https://crates.io/api/v1/crates/luciola | head -c 200
```

If the version is not published, say so and point at the local path
(`mavenLocal()` plus `scripts/publish-maven-local.sh`) instead of implying
availability.

## 5. Portability red line: no machine-specific defaults

Nothing in the tree — code, scripts, docs, examples — may hardcode a personal
absolute path (`/Volumes/...`, `/Users/...`, a username, a home-relative SDK
location) as a default. Native artifact roots resolve in this order:

1. an explicit override (Gradle `-P` property, `LUCIOLA_TARGET_DIR`,
   `CARGO_TARGET_DIR`);
2. `cargo metadata --format-version 1 --no-deps` → `target_directory`, because a
   shared `[build] target-dir` in `~/.cargo/config.toml` redirects the output
   directory — so `./target` is **not** a safe assumption;
3. a relative in-repo fallback (`<repo>/target`).

Follow the existing implementations: `nativeRoot()` in
`bindings/luciola-kmp/build.gradle.kts`, `cargoTargetDirectory()` in
`bindings/luciola-node/index.js`, and the header of
`scripts/generate-kmp-bindings.sh`.

**Why:** the KMP build script and the Node loader each shipped such a default for
months. On any other machine the iOS cinterop silently received an empty library path
("Could not find 'libluciola_uniffi.a' binary in neither of []"), and the Node
bindings loaded only if the developer happened to own that volume.

## 6. Tests must not depend on the environment

- Bind port `0` and read the assigned port. Never a fixed port: a leftover
  listener on a dev box makes the suite flaky, and CI runs jobs in parallel.
- Anything needing a real NIC or real peers must **skip gracefully** when the
  environment lacks it — see the `real_ipv4()` guard in
  `crates/luciola/tests/realnic_e2e.rs`.
- Never let a live device on the network participate in a discovery test.

**Why:** "the test passed" and "the test could not run" were previously
indistinguishable in reports. A guard that prints a skip line and returns is the
minimum; a missing environment is not a failure of the code under test.

- **Two tests are load-sensitive on a busy dev box**: `two_nodes_discover_over_ipv6_loopback`
  (5 s discovery timeouts) and `final_ack_loss_recovers_via_answer_cache` (transfer
  timing). Each failed once in multi-suite runs on a machine that was also compiling,
  and passed every unloaded rerun. Treat a failure of either **on an idle machine, or
  twice in a row**, as a real regression — not a flake.

Generalisation: **a gate must distinguish "not verified" from "verified broken."**
When a check depends on an external artifact (remote sitemap, service, CDN),
unreachable must be a non-blocking warning while reachable-but-mismatched is an error
that blocks. Give such logic an offline reverse self-test (inject unreachable ⇒
warning only; inject reachable-but-missing ⇒ still fails).

## 7. Commit and history discipline

- Conventional Commits: `feat|fix|perf|refactor|build|docs|test|ci|chore(scope): ...`
  in **English**, one logical change per commit.
- **Local release state does not belong in a subject.** No `mavenLocal`, no version
  tags in titles, and no standalone "regenerate bindings" commit — a regeneration
  belongs in the commit that changed the Rust API (§3). Same for
  `style: rustfmt` commits: fold the formatting into the commit it belongs to.
- Chinese is fine in code comments where it carries hard-won detail; subjects, README,
  docs and public KDoc are English (`README.zh-CN.md` is the maintained twin).
- If a commit touches a public API, its body states the artifact version and whether
  that version was actually published.

**Why:** 23 unpushed commits had to be rewritten before publication because subjects
such as `chore(release): 0.4.6 —— regenerate Kotlin bindings` and
`fix(kmp): ... (0.4.2 mavenLocal)` described a developer's local state rather than a
change to the software. Rewriting history that is already public costs forks and
stargazers; doing it once privately is cheap.

Never embed another project's private paths or internal product names in this
repository's docs. The internal planning spec that used to live here referenced
sibling repositories and per-machine workspace paths, which is why it was dropped on
publication.

## 8. Platform entry points — docs must not imply "Android only"

The KMP library's real cross-platform entry point is **`DiscoveryController`** in
`commonMain`: it owns the peer table, debounced rebuilds on network change, and the
watchdog, and it takes three injected ports (`DiscoveryEnginePort`,
`NetworkMonitorPort`, `TaskScheduler`).

- `AndroidDiscoveryController` (androidMain) is a thin **convenience shell** over
  it, needed because Android injects `AndroidNetworkMonitor` plus a main-`Handler`
  scheduler and marshals callbacks to the main thread.
- `UniffiEngineAdapter` lives in `commonMain` and has **no** `android.*`
  dependency — it is the engine port for JVM *and* iOS (Kotlin/Native via cinterop).
- JVM ships `DesktopNetworkMonitor` and `DesktopDiscoveryController`; iOS ships
  `IosNetworkMonitor` (Network.framework's path monitor via the C
  `nw_path_monitor_*` API — the ObjC `NWPathMonitor` class is Swift-only and not
  reachable from Kotlin/Native cinterop; do not "simplify" the implementation by
  trying to import it).
- Swift integrators can skip Kotlin entirely and use `bindings/luciola-swift`
  (`DiscoverySession`, `SecureSession`, `TrustStore`) — which is what
  `examples/ios-demo` does.

When documenting a capability, say which tier it lives in: Rust core, uniffi binding
surface, or platform shell. Anything reachable only through
`AndroidDiscoveryController` is an Android feature, and labelling it "KMP" is wrong.

**Why:** the README's "Android / KMP products" section showed
`AndroidDiscoveryController(...)` and nothing else, which read as "this library is
for Android". iOS and desktop readers could not tell they were looking at a platform
shell rather than the API they should target.

## 9. Release checklist

1. Bump all four version homes (§4) and grep for stale path-dep requirements.
2. Regenerate every binding surface (§3); confirm the generated nativeMain uses cinterop.
3. Run the full local gate (§2).
4. `scripts/publish-crates.sh`, then `scripts/publish-central.sh`; use
   `scripts/publish-maven-local.sh` for local consumers.
5. Verify the artifact is readable from the registry afterwards (§4 curl checks), then
   update README/CHANGELOG to the **verified** number, not the intended one.

Two rules the release path has already broken once — both repaired in-tree; keep them
repaired:
- A new workspace crate must be added to the workspace **and** to the ordered list in
  `scripts/publish-crates.sh` in the same commit. `luciola-transfer` and
  `luciola-tunnel` were missing from that list once and shipped unpublished; the list
  now reads `luciola-ip luciola-proto luciola-net luciola-transfer luciola
  luciola-tunnel luciola-cli` — transfer **before** luciola, because luciola's
  optional dep with an exact version req must already exist on the registry when
  luciola publishes (transfer's dep on luciola is dev-only and stripped, so this
  direction is the only publishable one; the old order is why crates.io sat at
  0.3.1 across several in-tree releases).
- The CI Node job must run **both** `bindings/luciola-node/test.js` and
  `bindings/luciola-node/test/forward.test.mjs`; forwarding regressions used to be
  unguarded in CI because only the smoke test was wired in.

Publishing credentials live **outside** the repo (`~/.luciola/central.env`,
`~/.luciola/signing-key.asc`; `.gitignore` keeps `release.env` out). Never
inline a token into a command line, a commit, or a log.

## 10. Security posture is a documented claim, not a vibe

`SECURITY.md` records the cryptographic inventory and states that the protocol
composition is **pre-audit** (custom SIGMA-style handshake: X25519 + Ed25519
transcript signatures + HKDF + AES-256-GCM). For agents that means:

- Do not silently alter handshake structure, cipher suites, pinning defaults, or the
  frame size limit without updating `SECURITY.md` in the same change.
- Keep the deny-by-default posture: discovery is open, **data planes are not**.
  Unpaired peers are denied; `Partial` trust requires per-action confirmation.
- Key material is zeroized; any new secret path gets the same treatment.
- Report vulnerabilities through `SECURITY.md`, not a public issue carrying details.

**Why:** an "audited-grade security" sentence next to an unaudited custom protocol is
the worst combination for a library in this position, and a docs-only edit can
introduce it by accident.

## 11. Every command and path in docs must exist

Docs here are example-driven. Before adding a snippet, run it or `ls` it. A comment
in `build.gradle.kts` pointed at `scripts/build-ios-natives.sh`, a script that
does not exist; a reader would have gone hunting for a nonexistent build step. When
you rename or delete a script, grep the tree for references:

```
grep -rn 'scripts/<name>' --include='*.md' --include='*.kts' --include='*.rs' .
```

## 12. Verification claims must name their layer

Report precisely what was proven: unit test green / compiles for target X / verified
on a real device. A Kotlin/Native iOS class that compiles into a klib has **not** been
runtime-verified unless a device or simulator run happened. A local
`cargo test` passing does not mean a published artifact carries the fix (§3).

**Why:** a real-device test here once reported "phone to desktop 3/3 success" while
the automation was tapping real UI buttons and triggering manual sends — the feature
did not work at all. Instrument the code path before believing a green-looking run.
