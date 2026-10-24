# Luciola (萤火)

<p align="center">
  <strong>Lightweight, resilient peer discovery & interface intelligence for the real-world LAN.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#why-luciola">Why Luciola</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#verification">Verification</a> •
  <a href="README.zh-CN.md">中文文档</a>
</p>

---

## Features

- 🌐 **Real-World IPv6 Done Right**: Native RFC 4291/4193 scope taxonomy, plus intelligent `/64` prefix matching recognizing domestic ISP GUA as local LAN.
- 🛡️ **Anti-TUN / Anti-Proxy Defense**: Outsmarts proxy TUN modes (Clash, Sing-box) where `0.0.0.0/1` swallows standard `255.255.255.255` broadcasts. Luciola computes targeted **Subnet Broadcasts** (`x.x.x.255`) whose `/24` direct routes cannot be hijacked.
- 🎯 **Physical vs Virtual Interface Intelligence**: High-accuracy interface scoring that filters out Docker, VMware, Radmin, and Windows ICS hotspot (`192.168.137.x`), while preserving WSL2 host-IP passthrough.
- ⚡ **Zero-Overhead Peer Protocol**: Lightweight UDP gossip (`entry`, `alive`, `presence`, `exit`) with jitter-delay storm protection, deduplication, and revision-driven state synchronization.
- 🔌 **Universal Multi-Language Ecosystem**: Core in Rust with first-class Node.js (`napi-rs`), Android/JVM, and iOS/macOS (`uniffi`) bindings.

---

## Why Luciola?

| Real-World Challenge | Traditional mDNS / Naive Scripts | Luciola |
| :--- | :--- | :--- |
| **Enterprise / Campus Wi-Fi** | Drops multicast packets (`224.0.0.251`) | Uses resilient Subnet Broadcast + directed UDP fallbacks |
| **Broadband IPv6 (GUA)** | Mistaken as public WAN, dropping plaintext/local links | Detects same `/64` prefix as local LAN peer |
| **Clash / Sing-box TUN Mode** | All `255.255.255.255` traffic silently swallowed | Computes per-NIC `/24` subnet broadcasts to bypass TUN |
| **WSL2 Environment** | Exposes unreachable internal NAT `172.x` IP to mobile | Detects WSL and resolves Windows host physical IP |
| **Battery / Doze Mode** | Android kills mDNS listeners | Mobile-aware lifecycle hooks and backoff loops |

---

## Quick Start (CLI)

Install or run via Cargo:

```bash
# Scan local peers in your network
cargo run -p luciola-cli -- scan

# Broadcast your presence
cargo run -p luciola-cli -- beacon --name "My Laptop"
```

---

## Architecture

```
luciola/
├── crates/
│   ├── luciola-ip/       # RFC scopes, /64 GUA detection, 198.18.0.0/15 TUN filter
│   ├── luciola-net/      # Physical NIC scoring, WSL2 passthrough, Subnet Broadcasts
│   ├── luciola-proto/    # Zero-I/O protocol state machine, jitter & deduplication
│   ├── luciola-core/     # Async Tokio discovery engine with self-healing sockets
│   └── luciola-cli/      # Command-line inspection & debugging tool
```

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
