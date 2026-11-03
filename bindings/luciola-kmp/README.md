# luciola-kmp

Kotlin Multiplatform library over the Luciola Rust core (`luciola-uniffi`):
peer discovery, supervision (watchdog / network self-healing), Happy Eyeballs
path racing, trust & pairing primitives, and authenticated encrypted channels.

Package: `io.github.kexuejin:luciola` (Kotlin package `io.github.kexuejin.luciola`).

## Targets

- **androidLibrary** (AGP KMP plugin) — ships `libluciola_uniffi.so`
  (arm64-v8a) inside the AAR; JNA comes in as a runtime dependency of
  the published POM.
- **jvm** — same uniffi bindings over JNA (desktop/CLI; load the
  `luciola_uniffi` native library for your platform first).
- **iosArm64 / iosSimulatorArm64** — the same uniffi bindings over
  cinterop (`src/uniffiKmp/nativeMain`, linked against
  `libluciola_uniffi.a`): discovery, supervision, trust, tunnel control
  plane and the secure channel, with native `iosTest` coverage that the
  simulator runs in-process. The Swift bindings
  (`bindings/luciola-swift`) are an alternative path that skips Kotlin.
  Physical iOS devices are **not** runtime-verified (simulator only).

## Consume

Published on Maven Central:

```kotlin
implementation("io.github.kexuejin:luciola:0.9.1")
```

## Consume (local Maven)

```kotlin
// settings.gradle.kts
dependencyResolutionManagement { repositories { mavenLocal(); ... } }

// build.gradle.kts
implementation("io.github.kexuejin:luciola:0.9.1")
```

KMP consumers resolve per-target variants automatically via Gradle module
metadata. Consumers must use Kotlin 2.2.x.

## Publish locally

One command from the repo root — builds the Rust core for Android and
publishes to `~/.m2` (native binaries are never committed to git):

```bash
scripts/publish-maven-local.sh
```

Publishing without the freshly built `.so` fails fast (`verifyNativeLib`
task guards every publish task).
