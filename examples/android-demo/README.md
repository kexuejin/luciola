# Luciola Android Demo (真机移动端)

A minimal Jetpack Compose app that runs the **real Luciola engine on a phone** (Rust core via UniFFI → arm64 `.so`), counterpart to the [web-radar-demo](../web-radar-demo) desktop console.

## Features

- **Real UDP discovery on-device**: the Rust engine binds `0.0.0.0:17878`, announces `entry`, replies `alive`, keeps `presence` heartbeats, and reports newly discovered LAN peers to Compose through a UniFFI callback.
- **Background presence (foreground service)**: the engine lives in
  `LuciolaPresenceService`, not in the Activity, so the phone keeps answering
  `alive` probes with the screen off or the task swiped away. See
  [Background presence](#background-presence) for why the type is
  `connectedDevice` and what it costs.
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

## Background presence

The engine used to be owned by `MainActivity`, so closing the task silently
removed the phone from every peer's radar. It now lives in
`LuciolaPresenceService`, a foreground service, and the UI renders
`PresenceBus` (a process-wide snapshot-state object) instead of holding a
controller.

**Service type: `connectedDevice`, not `dataSync`.** `dataSync` is the obvious
choice for a socket, but Android 15+ caps `dataSync` foreground services at
**6 hours per 24-hour period** and then calls `onTimeout` — worse than useless
for a presence socket. `connectedDevice` has no such cap and matches the intent
(maintaining a network link to an external device). Its prerequisite is any one
of `BLUETOOTH_*`, `CHANGE_NETWORK_STATE`, `CHANGE_WIFI_STATE`,
`CHANGE_WIFI_MULTICAST_STATE`, `NFC`, `TRANSMIT_IR` or `UWB_RANGING`; this app
already declares `CHANGE_WIFI_MULTICAST_STATE` for the `MulticastLock`, so no
extra prerequisite was needed.

Permissions added to the manifest:

| Permission | Why |
| :-- | :-- |
| `FOREGROUND_SERVICE` | required for any foreground service |
| `FOREGROUND_SERVICE_CONNECTED_DEVICE` | required for the `connectedDevice` type on targetSdk 34+ |
| `POST_NOTIFICATIONS` | runtime permission on API 33+; denying it only hides the ongoing notification, the service still runs |

`START_STICKY` means a reclaimed process is recreated with a null intent and
re-announces. If the engine fails to bind, the service reports it and stops
rather than leaving a notification that claims it is running.

Verified in this environment: `:app:compileDebugKotlin`, `:app:assembleDebug`
and `:app:lintDebug` all pass, and the merged manifest carries the three
permissions plus `android:foregroundServiceType="connectedDevice"`. **Not**
verified here: behaviour on a real device with the screen off (Doze, OEM
battery managers such as MIUI/EMUI, and the notification permission prompt) —
that needs hardware.

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
