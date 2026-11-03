# Luciola Web Radar Demo (桌面中控台)

A zero-dependency real-time web dashboard powered by the real `@luciola/core` native engine. The mobile end is the **real Android app** in [../android-demo](../android-demo) — it appears here over actual UDP discovery.

The page works in two modes, and it is deliberate about which one you are looking at:

| Mode | What you see | How it is triggered |
| :--- | :--- | :--- |
| **Live** (local engine) | real peers, real RTT, engine-rendered pairing QR, SSE event stream | `GET /api/status` returns valid JSON from `server.js` |
| **Static preview** | **clearly labelled sample data** — fabricated peers on IETF documentation addresses, no QR, actions disabled | GitHub Pages, `file://`, or `?demo=1` (anywhere `/api/*` is unreachable) |

The static preview never pretends to have discovered a peer: it shows a banner, a `SAMPLE` chip on every device card, a sample-only event log, and it sends no probe packets at all.

## Features

- **🖥️ Desktop Radar Console**: real device identity, physical NIC candidates, rotating radar with live peer blips, and an authentic vector QR code rendered by the native engine.
- **📱 Real phone peers**: phones running the Luciola Android app (or any `luciola-cli beacon`) show up live on the radar with their hardware metadata.
- **⚡ Happy Eyeballs race demo**: one click dials every candidate subnet concurrently (real TCP connects, staggered like RFC 8305) and shows which channel won with its measured RTT.
- **📡 Real Wire Protocol**: the server crafts genuine Luciola `entry` envelopes (same JSON codec as `luciola-proto`) and sends them as **subnet-directed broadcasts** (`192.168.2.255` style) that bypass Clash/Sing-box TUN `0.0.0.0/1` capture, plus **unicast reconciliation** to pre-0.9.0 peers (or hosts that explicitly enabled ephemeral-port fallback). Alive replies measure true RTT.
- **🔄 Live Updates over SSE**: peers joining/leaving, beacon broadcasts, and race results stream to both ends in real time.
- **🌐 zh / EN**: the page ships both languages inline (no CDN, no fonts): it follows `navigator.language` and accepts `?lang=zh` / `?lang=en`.
- **🧹 Self-Aging Registry**: peers that stop answering sweeps go offline automatically (the engine's `Found`-only events alone cannot track liveness).

## Run it live

```bash
# from the repository root — the demo loads the native Node addon
cargo build -p luciola-node

cd examples/web-radar-demo
node server.js
```

Then open `http://localhost:3000`. Node 18+ is required (`bindings/luciola-node/package.json` `engines`).

To see real peers appear on the radar, run another Luciola node on the LAN or in a separate terminal:

```bash
cargo run -p luciola-cli -- beacon --name "My-Other-Device"
```

### Configuration

| Env var | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `3000` | HTTP server port (embedded in the pairing QR). |
| `DISCOVERY_PORT` | `17878` | UDP discovery port. Override when another Luciola app already occupies 17878: since 0.9.0 the engine returns `BindFailed` instead of silently falling back to a random port, which would break broadcast-based discovery. |

## Static preview / GitHub Pages

`.github/workflows/pages.yml` publishes **only** `index.html` to <https://kexuejin.github.io/luciola/>. There is no Node process and no engine on Pages, so the page detects the missing `/api/status` and switches to the labelled static preview. It is self-contained on purpose: the Pages workflow fails if `index.html` references an external `http(s)` asset, because a CDN turns the demo into a blank screen on a slow or offline network.

- Force the preview locally: <http://localhost:3000/?demo=1> or open `index.html` from the filesystem.
- Force a language: `?lang=en` / `?lang=zh` (default follows the browser locale).

## API Overview

| Endpoint | Description |
| :--- | :--- |
| `GET /api/status` | Local device meta, candidate addresses, subnet broadcasts, pairing URI, current peers. Its absence is exactly what flips the UI into static preview. |
| `GET /api/events` | SSE stream: `peer_found`, `peer_expired`, `beacon_sent`, `race_done`. |
| `GET /api/qr.svg?url=` | Native SVG QR code (`renderQrSvg`). |
| `POST /api/beacon` | Broadcast real `entry` heartbeats (subnet-directed + unicast reconciliation). Body `{"target": "ip"}` sends a directed unicast beacon and returns RTT. |
| `POST /api/ping` | Measure true RTT to a peer (`entry` → `alive` round trip on its actual listening port). |
| `POST /api/race` | Happy Eyeballs race across the primary IPv4 subnets + first IPv6 GUA. |
| `POST /api/peers/inject` | Inject a simulated mobile peer (used by the "scan to pair" demo flow). |
