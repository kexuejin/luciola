# luciola-kmp

Kotlin Multiplatform library over the Luciola Rust core (`luciola-uniffi`):
peer discovery, supervision (watchdog / network self-healing), Happy Eyeballs
path racing, trust & pairing primitives, and authenticated encrypted channels.

Package: `io.github.kexuejin:luciola` (Kotlin package `io.github.kexuejin.luciola`).

## Targets

- **androidLibrary** (AGP KMP plugin) — ships `libluciola_uniffi.so`
  (arm64-v8a) inside the AAR; JNA included.
- **jvm** — same uniffi bindings over JNA (desktop/CLI; load the
  `luciola_uniffi` native library for your platform first).
- **iosArm64 / iosSimulatorArm64** — commonMain supervision core only; the
  engine calls on iOS go through the Swift bindings
  (`bindings/luciola-swift`), implementing the same surface.

## Consume

Published on Maven Central:

```kotlin
implementation("io.github.kexuejin:luciola:0.3.0")
```

## Consume (local Maven)

```kotlin
// settings.gradle.kts
dependencyResolutionManagement { repositories { mavenLocal(); ... } }

// build.gradle.kts
implementation("io.github.kexuejin:luciola:0.3.0")
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
