# Upgrade guide

Breaking changes and behavioural shifts between published versions, from the
consumer's point of view. For what each release added, see [CHANGELOG.md](../CHANGELOG.md).

## 0.6.0

1. **SecureSessionListener.on_message takes three arguments.**
   `onMessage(message, peerFingerprint, remoteAddr)` — the last two are the sender
   fingerprint the engine verified during the handshake and the real socket origin
   of the frame. Every implementation (Kotlin / Swift / Node) must update its
   signature. Attribute inbound binary frames to these two values; **do not** infer
   ownership from session state machines anymore.
2. **DiscoverySession::new gained four optional parameters** after `extra`:
   `nodeId / tcpPort / publicKey`. Hosts should pin the beacon identity to their own
   zero-trust store: beacon identity = channel identity, and peers get a dialable
   port plus a trustworthy key straight from the discovery layer.
3. **Beacon `Profile` now carries `public_key: Option<Vec<u8>>`.** Serde-compatible
   in both directions — beacons from older builds still parse.
4. **Zombie accept fixed.** The `listen()` loop's bind/accept is now interruptible by
   shutdown, so `stop()` releases the listening port immediately. Code that relied on
   the old behaviour (port lingering after stop) needs a self-check.
5. **New crate `luciola-transfer`** (chunked file-transfer data plane), re-exported
   from `luciola` behind the `transfer` feature. Existing app-side transfer managers
   are unaffected.

KMP: `UniffiEngineAdapter` mirrors the new `nodeId / tcpPort / publicKey` constructor
arguments (nullable, defaults preserve the old behaviour). **Swift bindings must be
regenerated** (`cargo run -p luciola-uniffi --bin uniffi-bindgen -- generate
--language swift`): the uniffi metadata checksum rejects an old binding paired with
a new dylib, so the mismatch fails loudly rather than silently.

## Behaviour worth knowing when replacing a hand-rolled LAN stack

A product migrating off its own UDP/TCP transport layer typically deletes these,
because the engine already covers them:

| Was hand-rolled | Now provided by |
| :-- | :-- |
| peer registry + event fan-out | `DiscoveryController` peer table with found/updated/lost ageing |
| UDP socket + bind/retry logic | Rust dual-stack engine (per-family routing, send timeouts, EPIPE self-heal) |
| network change watching | `NetworkMonitorPort` + debounced rebuild + watchdog |
| ad-hoc TLS/SPKI pinning | `SecureChannel` / TrustStore (Ed25519 pins, fail-closed) |
| cross-subnet raw dialer | `race_connect` + pairing-payload addresses + `manualPeers` |
| length-prefixed TCP framing | built-in channel frames (≤ 8 MiB) |
| mDNS helper service type | subnet-directed broadcasts + `manualPeers` |

Notes from live migrations:

- **First message costs one handshake RTT** (plain UDP used to send immediately).
  On a LAN this is inaudible; on an overlay network it is one extra round trip.
- **Keepalive and Android Doze:** slow `setKeepalive` when idle (e.g. 45000/90000 ms)
  and drive it from `PowerManager.isDeviceIdleMode`. Screen-off is *not* a good signal —
  NAT entries usually stay alive while the screen is off.
- **Retry semantics** map onto `setRetryPolicy(1000, 60000, 20)`; keep the app-side ACK
  and backoff logic untouched, and watch `stats().reconnectAttempts` after a network
  recovery to confirm the backlog drains.
- **Trust stores do not convert.** If the old scheme pinned P-256/SPKI fingerprints,
  there is no automatic translation to Ed25519: existing pairs must re-pair (re-scan).
- **Frame limit is 8 MiB**, so keep chunk sizes below it.
- **GPL apps may depend on luciola:** luciola is MIT OR Apache-2.0, which is safe in
  that direction.
