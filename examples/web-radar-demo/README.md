# Luciola Web Radar Demo

A zero-dependency real-time web dashboard demonstrating the capabilities of `@luciola/core`.

## Features
- **Visual LAN Radar**: Real-time rotating radar sweeping the local subnet (`192.168.2.0/24`).
- **Dynamic Peer Cards**: Shows peer device type icon (`💻`, `📱`, `🗄️`), OS, CPU architecture, IP, and UDP port.
- **Server-Sent Events (SSE)**: Instant real-time updates as nodes join or leave the LAN.
- **Mobile QR Connect**: Shows direct IP and dynamic QR code for instant mobile pairing.
- **Anti-TUN Verification**: Displays physical subnet broadcast routes that bypass Clash/Sing-box TUN proxy hijacking.

## How to Run

```bash
cd examples/web-radar-demo
node server.js
```

Then open `http://localhost:3000` in your browser.

To see peers appear on the radar in real time, run another Luciola node on the LAN or in a separate terminal:
```bash
cargo run -p luciola-cli -- beacon --name "My-Other-Device"
```
