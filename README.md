# Luciola (萤火) — Resilient LAN Peer Discovery & Secure Local Connections

**A Rust-powered local-network engine for real-world conditions**: discover peers on a LAN, race the best connection path, and move data over authenticated encrypted channels — even behind Clash/Sing-box TUN VPNs, on China-broadband IPv6-only setups, across ZeroTier/Tailscale overlays, and through routers that break multicast.

Luciola is the foundation layer for **local-first apps** — LAN clipboard sync, direct file transfer, screen sharing, local AI companions — so every product doesn't reinvent (and mis-debug) LAN networking. One Rust core, first-class bindings for **Kotlin Multiplatform (Android/JVM), iOS/Swift, and Node.js/Electron**.

> Why not mDNS/Bonjour/Zeroconf? Enterprise & hotel Wi-Fi drop multicast; proxy TUN modes swallow broadcasts; mobile OSes freeze background listeners. Luciola is designed around exactly these failures — see [Why Luciola](#why-luciola-real-world-networks).

---

## Feature Highlights

- 🛡️ **Survives proxy TUN interception** — Clash / Sing-box enhanced mode hijacks `0.0.0.0/1` and swallows limited broadcasts. Luciola computes per-NIC **subnet-directed broadcasts** (`192.168.2.255`) whose `/24` direct routes can't be captured.
- 🌐 **IPv6 done for real broadband** — RFC 4291/4193 scope taxonomy plus `/64` prefix matching that treats ISP-assigned GUAs (2408:…, China Telecom/Unicom/Mobile) as same-LAN; dual-stack engine with `ff02::1` link-local multicast and IPv6-only discovery.
- 🎯 **Interface intelligence** — scores physical NICs and filters Docker/VMware/Tailscale/Radmin/Windows-ICS (`192.168.137.x`) virtual adapters; WSL2 passthrough resolves the Windows host's real IP; QR codes are always dialable.
- ⚡ **Happy Eyeballs path racing** — staggered concurrent dials across every candidate subnet (IPv4 + IPv6 GUA); first connect wins, and the secure handshake runs on the winning socket (no race-then-dial gap).
- 🔐 **Trust & pairing primitives** — Ed25519 device identities, `sha256:` fingerprints, 6-digit comparison PINs, and a **leveled trust store** (Full = own devices / silent push, Partial = per-action confirm, unpaired = deny). Built for clipboard-sync-grade privacy: *discovery is open, data planes are not*.
- 🔒 **Authenticated encrypted channels** — SIGMA-style handshake (X25519 + Ed25519 transcript signatures + HKDF + AES-256-GCM, replay-proof counters), deny-by-default pinning, TOFU capture, auto-reconnect with backoff, keepalive dead-peer detection, bounded queues.
- 🧭 **Supervision built in** — stable node identity across engine restarts, port-conflict detection (`bind_failed` events for same-device multi-product setups), watchdog + debounced network-change rebuilds, Android `MulticastLock` handling.
- 🔌 **One core, every platform** — Rust core; **KMP library** (`io.github.kexuejin:luciola-kmp`, ships the arm64 `.so` in the AAR), Swift bindings + xcframework for iOS, Node.js N-API (`@luciola/core`), plus a desktop **agent** (`luciola-cli agent`) that funnels discovery to multiple same-machine products over a unix socket.

## Why Luciola (real-world networks)

| Real-world hazard | mDNS / Bonjour | Naive scripts | **Luciola** |
| :--- | :--- | :--- | :--- |
| Enterprise / hotel / campus Wi-Fi (multicast dropped) | dead | — | subnet-directed broadcast + unicast reconciliation |
| Clash / Sing-box TUN mode (`0.0.0.0/1`) | silently dead | ignored | per-NIC `/24` broadcasts bypass the capture |
| China broadband IPv6 (GUA-only LAN) | treated as public WAN | IPv4-only | `/64` same-prefix matching + IPv6 discovery/dial |
| WSL2 / Docker / Tailscale virtual NICs | — | picks the wrong IP | NIC scoring + WSL2 host passthrough |
| Router blocks STA→STA multicast | flaky mDNS | — | manualPeers unicast fallback (documented after live testing) |
| Android Doze / app freezer | listeners die | PC-only thinking | watchdog, network-change rebuilds, foreground-service playbook |
| Multiple products on one device | port fights | — | `device_id` grouping, per-product ports, desktop agent |

## Quick Start

### CLI (diagnose your LAN in one command)

```bash
cargo run -p luciola-cli -- ip      # NIC diagnostics, TUN detection, candidate IPs, QR
cargo run -p luciola-cli -- scan    # live peer radar
cargo run -p luciola-cli -- beacon --name "My Laptop" --qr
cargo run -p luciola-cli -- agent   # per-device discovery daemon (unix-socket event stream)
```

### Android / KMP products

```kotlin
// settings.gradle.kts
dependencyResolutionManagement { repositories { mavenLocal(); google(); mavenCentral() } }

implementation("io.github.kexuejin:luciola:0.3.0")

val controller = AndroidDiscoveryController(
    context = this,
    sessionName = Build.MODEL,
    product = "my-clipboard-app",
    onPeersChanged = { peers -> /* PeerUiModel list, main thread */ },
    onEngineError = { code, msg -> /* surface bind_failed etc. */ },
)
controller.start()
```

### Node.js / Electron

```js
const luciola = require('@luciola/core');

const ip = luciola.selectLanIp();               // best dialable LAN IP (TUN/WSL/ICS-aware)
const broadcasts = luciola.subnetBroadcastAddresses(); // anti-TUN targets

const session = new luciola.DiscoverySession('My App', 17878, null, 'my-app');
session.start((ev) => {  // found | updated | lost | error
  if (ev.type === 'found') console.log('peer:', ev.peer.name, ev.peer.ip);
});

// encrypted channel with a paired peer
const id = luciola.generateDeviceIdentity();     // persist the seed securely!
const channel = new luciola.SecureChannel(id.seed);
channel.connect(['192.168.2.82'], 3000, pinnedPeerKey, true, (ev) => {
  if (ev.message) console.log('decrypted:', ev.message);
});
```

### Demos

- **Web radar console** ([examples/web-radar-demo](examples/web-radar-demo)) — live peer radar, real wire-protocol beacons, pairing QR with fingerprint + PIN.
- **Android app** ([examples/android-demo](examples/android-demo)) — KMP-based Compose app, QR scan + Happy Eyeballs racing, verified on real devices across Wi-Fi/ZeroTier.
- **iOS app** ([examples/ios-demo](examples/ios-demo)) — SwiftUI over uniffi Swift bindings, verified in the simulator.

## Documentation

- 📖 **[Integration handbook](docs/INTEGRATION.md)** — ports, Android foreground service & freezer behavior, trust/pairing UX, secure-channel states, troubleshooting table (every row from live testing).
- 🔐 **[Security policy](SECURITY.md)** — cryptographic inventory, pre-audit status, review checklist.
- 📦 **Publishing** — `scripts/publish-maven-local.sh` builds the Rust core and publishes the KMP library; native artifacts never enter git.

## Architecture

```
luciola/
├── crates/
│   ├── luciola-ip/       # RFC scopes, /64 GUA matching, 198.18.0.0/15 TUN filter (no_std)
│   ├── luciola-net/      # NIC scoring, WSL2 passthrough, subnet broadcasts, device meta
│   ├── luciola-proto/    # wire protocol: versioned envelopes, jitter/dedup state machine
│   ├── luciola/          # tokio engine: dual-stack discovery, link racing,
│   │                     #   secure channels, trust & pairing primitives
│   └── luciola-cli/      # ip / scan / beacon / agent
└── bindings/
    ├── luciola-kmp/      # Kotlin Multiplatform library (Android AAR + JVM + iOS klib)
    ├── luciola-swift/    # Swift bindings + xcframework
    └── luciola-node/     # @luciola/core (N-API)
```

## Project Goals

1. **Make LAN peer networking boring** for app developers: discovery, best-path connection, and trusted encrypted channels as one dependency.
2. **Work where real users are** — VPN TUN modes, ISP IPv6, virtualized NICs, budget routers, battery-constrained phones. Every hazard in the table above is covered by a test or a documented live verification.
3. **One core, every platform** — a single Rust implementation of the hard parts; thin, idiomatic bindings instead of N divergent reimplementations.
4. **Security honest by default** — open discovery, deny-by-default data planes, pre-audit status disclosed (see [SECURITY.md](SECURITY.md)).

## Suggested repo topics

`rust` `lan` `discovery` `peer-to-peer` `p2p` `kotlin-multiplatform` `kmp` `android` `ios` `nodejs` `ipv6` `happy-eyeballs` `local-first` `zeroconf-alternative` `mdns-alternative` `clipboard-sync` `file-transfer` `vpn-tun` `clash`

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) — pick either. GPL projects may depend on Luciola safely.

---

**中文文档** · [README.zh-CN.md](README.zh-CN.md)
