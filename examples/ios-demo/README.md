# Luciola iOS Demo (SwiftUI + UniFFI Swift bindings)

Real Luciola engine on iOS via the uniffi **Swift** bindings. The supervision
primitives (stable identity, in-place restart, bind retry, idle tracking) live
in Rust, so this integration stays thin: NWPathMonitor drives `restart()`, a
small watchdog uses `secondsSinceIdle()`, and `isBound()` reflects whether the
discovery port was actually acquired.

## Layout

```
ios-demo/
├── LuciolaRadar/
│   ├── LuciolaRadarApp.swift      # entry point
│   ├── ContentView.swift          # discovery list UI
│   └── DiscoveryModel.swift       # engine + NWPathMonitor + watchdog
├── project.yml                    # xcodegen project definition
└── README.md
```

The Rust side lives in `bindings/luciola-swift`:

```
bindings/luciola-swift/
├── luciola_uniffi.swift            # generated Swift bindings (uniffi-bindgen)
├── luciola_uniffiFFI.h/.modulemap  # C FFI header
└── LuciolaUniFFI.xcframework       # ios-arm64 + ios-arm64-simulator static libs
```

## Build & Run

Prereqs: Xcode, `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`,
[xcodegen](https://github.com/yonaskolb/XcodeGen).

```bash
# 1. Rust static libs (run from the repo root)
cargo build --release -p luciola-uniffi --target aarch64-apple-ios
cargo build --release -p luciola-uniffi --target aarch64-apple-ios-sim

# 2. Regenerate Swift bindings after changing the Rust API.
#    Ask cargo for the target directory — it is not always ./target.
TD=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
cargo run -p luciola-uniffi --bin uniffi-bindgen -- generate \
  --library "$TD/debug/libluciola_uniffi.dylib" \
  --language swift --out-dir /tmp/uo-sw
cp /tmp/uo-sw/luciola_uniffi.swift /tmp/uo-sw/luciola_uniffiFFI.h \
   /tmp/uo-sw/luciola_uniffiFFI.modulemap ../../bindings/luciola-swift/

# 3. Rebuild the xcframework (both slices + shared FFI headers)
./bindings/luciola-swift/build-xcframework.sh

# 4. Generate the Xcode project and build for the simulator
cd examples/ios-demo
xcodegen generate
xcodebuild -project LuciolaRadar.xcodeproj -scheme LuciolaRadar \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

Run on the same LAN as the desktop web console (`examples/web-radar-demo`) —
peers appear on both ends within seconds.

## Notes

- The demo binds the discovery port **17880** because the standard 17878 was
  occupied by a production peer node on the dev machine; change the `port:`
  argument in `ContentView.start(...)` if yours is free.
- **Simulator caveat**: the simulator shares the Mac's network stack, so
  LAN broadcast frames sent by the Mac are not looped back to it. Discovery
  between the simulator and the desktop works via the server's *unicast
  reconciliation* (peers already in the registry are dialed directly). Real
  devices discover each other through normal broadcast.
- Scanning the desktop QR code is not wired yet — use VisionKit
  (`DataScannerViewController`) or any QR scanner and feed the decoded
  `luciola://pair?...` URI into a Happy-Eyeballs dialer like the Android demo's.
