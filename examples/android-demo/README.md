# Luciola Android Demo (真机移动端)

A minimal Jetpack Compose app that runs the **real Luciola engine on a phone** (Rust core via UniFFI → arm64 `.so`), counterpart to the [web-radar-demo](../web-radar-demo) desktop console.

## Features

- **Real UDP discovery on-device**: the Rust engine binds `0.0.0.0:17878`, announces `entry`, replies `alive`, keeps `presence` heartbeats, and reports newly discovered LAN peers to Compose through a UniFFI callback.
- **QR pairing + Happy Eyeballs racing**: scan the desktop console's `luciola://pair?...` QR code (zxing-embedded, no GMS needed — works on China ROMs), then the app dials every candidate subnet concurrently with 40 ms staggering; first TCP connect wins and its RTT is shown.
- **Android networking done right**: acquires a `WifiManager.MulticastLock` (Wi-Fi drivers filter broadcast frames without it) and passes `Build.MODEL` as the node name.

## Layout

The mobile logic lives in the **KMP library** (`bindings/luciola-kmp`), not in
this app — the app depends on it as a Gradle module and only owns UI:

```
bindings/luciola-kmp/                         # multiplatform library
├── src/commonMain/kotlin/dev/luciola/kmp/    # DiscoveryController core
│   │                                         # (watchdog, debounced restarts,
│   │                                         #  peer table) — compiles to
│   │                                         #  Android/JVM/iOS (Kotlin/Native)
│   └── ... ports: DiscoveryEnginePort, NetworkMonitorPort
├── src/jvmShared/kotlin/dev/luciola/kmp/     # uniffi Kotlin adapter + facade
├── src/androidMain/kotlin/dev/luciola/kmp/   # MulticastLock, NetworkCallback,
│   │                                         # main-thread wiring
└── src/uniffiJvm/kotlin/uniffi/...           # generated bindings (JNA)

android-demo/
├── app/src/main/java/com/luciola/radar/MainActivity.kt   # Compose UI + HE race
└── app/src/main/jniLibs/arm64-v8a/libluciola_uniffi.so   # Rust core (cargo-ndk)
```

Supervision capabilities ship **in the library** (no per-integration rework):
MulticastLock acquisition, ConnectivityManager watching, watchdog with bounded
consecutive rebuilds, debounced restarts, and the port-release wait before
rebinding 17878. iOS gets the same primitives from Rust
(`restart()`, `secondsSinceIdle()`, `isBound()`) plus its own
`NWPathMonitor` glue in `examples/ios-demo`.

## Build & Run

Prereqs: Android SDK + NDK, `cargo-ndk`, Rust target `aarch64-linux-android`.

```bash
# 1. Rust core → Android .so (regenerate Kotlin bindings after changing the API)
cargo ndk -t arm64-v8a -o <out> build --release -p luciola-uniffi
# 2. APK
cd examples/android-demo && ./gradlew assembleDebug
# 3. Install on a device with USB debugging
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Then open the desktop console (`node server.js` in `web-radar-demo`) on the same LAN — the phone appears on the desktop radar within seconds, and desktop nodes show up under "附近发现的电脑 / 节点" on the phone.

## Real-World Notes

- **Discovery port 17878 is contested.** On the dev machine in this session, a production peer node held UDP 17878 on **both** the Mac and the phone; the engine silently falls back to an ephemeral port and broadcast-based discovery degrades. Force-stopping that app (or overriding `DISCOVERY_PORT` on the desktop demo) restores the full broadcast mesh.
- The engine's `entry`/`alive`/`presence` envelopes work unchanged across ZeroTier virtual networks (observed live: the phone answered from its `172.26.x` ZeroTier address).
