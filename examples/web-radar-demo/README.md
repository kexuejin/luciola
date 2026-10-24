# Luciola Web Radar Demo (桌面中控台)

A zero-dependency real-time web dashboard implementing the desktop half of the dual-end prototype, powered by the real `@luciola/core` native engine. The mobile end is the **real Android app** in [../android-demo](../android-demo) — it appears here over actual UDP discovery.

## Features

- **🖥️ Desktop Radar Console**: real device identity, physical NIC candidates, rotating radar with live peer blips, and an authentic vector QR code rendered by the native engine.
- **📱 Real phone peers**: phones running the Luciola Android app (or any `luciola-cli beacon`) show up live on the radar with their hardware metadata.
- **⚡ Happy Eyeballs race demo**: one click dials every candidate subnet concurrently (real TCP connects, staggered like RFC 8305) and shows which channel won with its measured RTT — exactly what a phone does when it scans the QR code.
- **📡 Real Wire Protocol**: the server crafts genuine Luciola `entry` envelopes (same JSON codec as `luciola-proto`) and sends them as **subnet-directed broadcasts** (`192.168.2.255` style) that bypass Clash/Sing-box TUN `0.0.0.0/1` capture, plus **unicast reconciliation** to peers whose engine fell back to a random port. Alive replies measure true RTT.
- **🔄 Live Updates over SSE**: peers joining/leaving, beacon broadcasts, and race results stream to both ends in real time.
- **🧹 Self-Aging Registry**: peers that stop answering sweeps go offline automatically (the engine's `Found`-only events alone cannot track liveness).

## How to Run

```bash
cd examples/web-radar-demo
node server.js
```

Then open `http://localhost:3000` in your browser.

To see real peers appear on the radar, run another Luciola node on the LAN or in a separate terminal:

```bash
cargo run -p luciola-cli -- beacon --name "My-Other-Device"
```

### Configuration

| Env var | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `3000` | HTTP server port (embedded in the pairing QR). |
| `DISCOVERY_PORT` | `17878` | UDP discovery port. Override when another app (e.g. a production peer node) already occupies 17878 — the engine silently falls back to a random port on bind failure, which breaks broadcast-based discovery. |

## API Overview

| Endpoint | Description |
| :--- | :--- |
| `GET /api/status` | Local device meta, candidate addresses, subnet broadcasts, pairing URI, current peers. |
| `GET /api/events` | SSE stream: `peer_found`, `peer_expired`, `beacon_sent`, `race_done`. |
| `GET /api/qr.svg?url=` | Native SVG QR code (`renderQrSvg`). |
| `POST /api/beacon` | Broadcast real `entry` heartbeats (subnet-directed + unicast reconciliation). Body `{"target": "ip"}` sends a directed unicast beacon and returns RTT. |
| `POST /api/ping` | Measure true RTT to a peer (`entry` → `alive` round trip on its actual listening port). |
| `POST /api/race` | Happy Eyeballs race across the primary IPv4 subnets + first IPv6 GUA. |
| `POST /api/peers/inject` | Inject a simulated mobile peer (used by the "scan to pair" demo flow). |
