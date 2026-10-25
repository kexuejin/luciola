const http = require('http');
const fs = require('fs');
const path = require('path');
const dgram = require('dgram');
const net = require('net');
const luciola = require('../../bindings/luciola-node/index.js');

const PORT = Number(process.env.PORT) || 3000;
// Discovery UDP port. Overridable when another app (e.g. a production peer
// node) already occupies 17878 — the engine silently falls back to a random
// port on bind failure, which would silently break broadcast-based discovery.
const DISCOVERY_PORT = Number(process.env.DISCOVERY_PORT) || 17878;
const PEER_STALE_MS = 90_000;
const SWEEP_INTERVAL_MS = 25_000;

// ---------------------------------------------------------------------------
// Local identity (real, from @luciola/core native engine)
// ---------------------------------------------------------------------------
const localDevice = luciola.getDeviceMeta();
const lanIp = luciola.selectLanIp();
const candidates = luciola.localCandidateAddresses();
const subnetBroadcasts = luciola.subnetBroadcastAddresses();
const advertised = luciola.advertisedAddresses();

const sessionName = localDevice.hostname || localDevice.model || 'Luciola-Web-Radar';
const pairingUri = `luciola://pair?name=${encodeURIComponent(sessionName)}&port=${PORT}&addrs=${candidates.join(',')}`;
const httpUrl = lanIp ? `http://${lanIp}:${PORT}` : `http://localhost:${PORT}`;

console.log('✨ [Luciola Web Demo] Initializing discovery engine...');
console.log(`💻 Local Hardware Identity: ${localDevice.icon} ${localDevice.deviceType} | ${localDevice.os} (${localDevice.arch}) | Model: ${localDevice.model || 'N/A'}`);
console.log(`🌐 Best LAN IP: ${lanIp}`);
console.log(`🛡️ Anti-TUN Subnet Broadcasts: ${subnetBroadcasts.join(', ')}`);

// ---------------------------------------------------------------------------
// Peer registry + SSE fan-out
// ---------------------------------------------------------------------------
const peers = new Map();
const sseClients = new Set();

function broadcastSSE(type, data) {
  const payload = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  for (const client of sseClients) {
    client.write(payload);
  }
}

const DEVICE_ICONS = {
  mobile: '📱', tablet: '📱', laptop: '💻',
  desktop: '🖥️', server: '🗄️', wsl: '🐧', unknown: '🌐',
};

function normalizeDevice(device) {
  if (!device) return undefined;
  const type = device.deviceType || device.device_type || 'unknown';
  return {
    deviceType: type,
    icon: device.icon || DEVICE_ICONS[type] || '🌐',
    os: device.os || 'unknown',
    arch: device.arch || 'unknown',
    model: device.model || device.hostname || '',
    hostname: device.hostname || '',
  };
}

function upsertPeer(record, source) {
  const prev = peers.get(record.nodeId);
  const merged = {
    ...prev,
    ...record,
    device: normalizeDevice(record.device) || (prev && prev.device),
    source: prev ? prev.source : source,
    rttMs: prev ? prev.rttMs : undefined,
    lastSeen: Date.now(),
  };
  peers.set(record.nodeId, merged);
  broadcastSSE('peer_found', { peer: merged });
  return merged;
}

// Periodic aging: peers that stopped answering sweeps go offline.
setInterval(() => {
  const now = Date.now();
  for (const [nodeId, peer] of peers.entries()) {
    if (now - peer.lastSeen > PEER_STALE_MS) {
      peers.delete(nodeId);
      broadcastSSE('peer_expired', { nodeId });
    }
  }
}, 5000);

// ---------------------------------------------------------------------------
// Luciola engine session (instant Found events on the official UDP port)
// ---------------------------------------------------------------------------
const session = new luciola.DiscoverySession(sessionName, DISCOVERY_PORT, null, 'web-radar-demo');
session.start((peer) => {
  if (peer.nodeId === selfNodeId) return; // our own sweeper envelopes echoed back
  console.log(`👋 [Engine Found] ${peer.name} (${peer.nodeId}) @ ${peer.ip}:${peer.udpPort}`);
  upsertPeer(peer, 'engine');
});
const selfNodeId = session.nodeId() || `web_${Math.random().toString(16).slice(2, 10)}`;

// ---------------------------------------------------------------------------
// Wire-protocol sweeper: crafts REAL `entry` envelopes (serde_json, same codec
// as luciola-proto) and sends them as subnet-directed broadcasts. Alive replies
// refresh liveness so the dashboard never drops online peers (fixes Found-only
// aging), and unicast pings measure true RTT (entry -> alive round trip).
// ---------------------------------------------------------------------------
// probeId -> { replies: [{envelope, rinfo}] }; alive replies matched per probe.
const pendingProbes = new Map();

let sweeper = createSweeper();

// A send to a port nobody listens on (engine fell back) yields an ICMP
// unreachable that puts the macOS dgram socket into a permanent error state
// (every later send fails with EPIPE). Rebuild the socket on errors instead.
let sweeperRebuilding = false;
function createSweeper() {
  const s = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  s.on('error', (err) => {
    console.error('🛑 [Sweeper socket]', err.message);
    if (!sweeperRebuilding) {
      sweeperRebuilding = true;
      try { s.close(); } catch (_e) { /* already closed */ }
      setTimeout(() => {
        sweeper = createSweeper();
        sweeperRebuilding = false;
        console.log('🔄 [Sweeper socket] rebuilt');
      }, 100);
    }
  });
  s.on('message', onSweeperMessage);
  s.bind(() => s.setBroadcast(true));
  return s;
}

function rebuildSweeper() {
  if (sweeperRebuilding) return;
  sweeperRebuilding = true;
  try { sweeper.close(); } catch (_e) { /* already closed */ }
  setTimeout(() => {
    sweeper = createSweeper();
    sweeperRebuilding = false;
    console.log('🔄 [Sweeper socket] rebuilt');
  }, 100);
}

function onSweeperMessage(buf, rinfo) {
  let envelope;
  try {
    envelope = JSON.parse(buf.toString('utf8'));
  } catch (_e) {
    console.log(`🛰️ [Sweeper RX] non-JSON datagram from ${rinfo.address}:${rinfo.port} (${buf.length}B)`);
    return;
  }
  console.log(`🛰️ [Sweeper RX] kind=${envelope.kind} from=${envelope.from} @ ${rinfo.address}:${rinfo.port}`);
  const kind = envelope.kind;
  const profile = envelope.payload && envelope.payload.profile;
  if (profile && profile.node_id && profile.node_id !== selfNodeId) {
    // Skip our own engine's alive reply (same hostname, answering from a local
    // interface) — otherwise the dashboard lists this machine as its own peer.
    const isSelfEngine = profile.name === sessionName && candidates.includes(rinfo.address);
    if (!isSelfEngine) {
      upsertPeer({
        nodeId: profile.node_id,
        name: profile.name,
        ip: rinfo.address,
        // The alive reply's source port is the peer engine's ACTUAL listening
        // socket (its configured port may have fallen back when occupied).
        udpPort: rinfo.port,
        tcpPort: profile.tcp_port,
        device: profile.device,
      }, 'sweep');
    }
  }
  if (kind === 'alive' || kind === 'presence') {
    const probeId = envelope.payload && envelope.payload.probeId;
    if (probeId && pendingProbes.has(probeId)) {
      const track = pendingProbes.get(probeId);
      if (track.replies.length === 0) {
        track.firstReplyMs = Number(process.hrtime.bigint() - track.startedAt) / 1e6;
      }
      track.replies.push({ envelope, rinfo });
    }
  }
}

function sweepProfile() {
  return {
    // Same identity as the engine session so remote devices see ONE node
    // from this machine, not a duplicate "· Web" peer.
    node_id: selfNodeId,
    name: sessionName,
    profile_rev: 1,
    addresses: candidates,
    udp_port: DISCOVERY_PORT,
    tcp_port: PORT,
    device: {
      device_type: localDevice.deviceType,
      os: localDevice.os,
      arch: localDevice.arch,
      model: localDevice.model || undefined,
      hostname: localDevice.hostname || undefined,
    },
  };
}

function craftEnvelope(kind, payload) {
  const ts = Date.now();
  return Buffer.from(JSON.stringify({
    id: `${selfNodeId}:${ts}:${Math.random().toString(16).slice(2, 6)}`,
    kind,
    from: selfNodeId,
    ts,
    payload,
  }));
}

function sendEnvelope(buf, address, port = DISCOVERY_PORT) {
  return sendEnvelopeOnce(buf, address, port).then((ok) => {
    // macOS caches one ICMP error per socket: a send to an unreachable
    // destination makes the NEXT send (any target) fail with EPIPE. A single
    // retry consumes it, so one dead target cannot poison the sweep.
    if (ok) return true;
    return sendEnvelopeOnce(buf, address, port);
  });
}

function sendEnvelopeOnce(buf, address, port) {
  return new Promise((resolve) => {
    sweeper.send(buf, port, address, (err) => {
      if (err && (err.code === 'EPIPE' || err.code === 'ECONNREFUSED')) {
        // The ICMP error is sticky on this socket — rebuild it and retry once
        // on the fresh socket (a clean socket dials the same target fine).
        console.error(`🛑 [Sweeper TX] ${address}:${port} -> ${err.message} (rebuilding socket)`);
        rebuildSweeper();
        setTimeout(() => {
          sweeper.send(buf, port, address, (err2) => {
            if (err2) console.error(`🛑 [Sweeper TX retry] ${address}:${port} -> ${err2.message}`);
            resolve(!err2);
          });
        }, 150);
        return;
      }
      if (err) console.error(`🛑 [Sweeper TX] ${address}:${port} -> ${err.message}`);
      resolve(!err);
    });
  });
}

// Send a real `entry` envelope to one address; collect alive replies for `waitMs`.
async function probeAddress(address, { port = DISCOVERY_PORT, waitMs = 1600, probeId = null } = {}) {
  const id = probeId || `probe_${Date.now()}_${Math.random().toString(16).slice(2, 6)}`;
  const buf = craftEnvelope('entry', { profile: sweepProfile(), probeId: id });
  const track = { replies: [], startedAt: process.hrtime.bigint(), firstReplyMs: null };
  pendingProbes.set(id, track);
  await sendEnvelope(buf, address, port);
  await new Promise((r) => setTimeout(r, waitMs));
  pendingProbes.delete(id);
  return {
    address,
    probeId: id,
    rttMs: track.firstReplyMs,
    replies: track.replies,
  };
}

async function broadcastBeacon(probeIdPrefix = 'manual') {
  const targets = [...new Set([...subnetBroadcasts, '255.255.255.255'])];
  const probeId = `${probeIdPrefix}_${Date.now()}`;
  const buf = craftEnvelope('entry', { profile: sweepProfile(), probeId });
  const results = [];
  for (const target of targets) {
    const ok = await sendEnvelope(buf, target);
    results.push({ target, sent: ok });
  }
  // Unicast reconciliation: peers whose engine fell back to a random port
  // (discovery port occupied by another process) never hear broadcasts, so
  // also dial every known peer directly on its actual listening port.
  for (const peer of peers.values()) {
    if (!peer.udpPort) continue;
    const ok = await sendEnvelope(buf, peer.ip, peer.udpPort);
    results.push({ target: `${peer.ip}:${peer.udpPort}`, sent: ok, unicast: true });
  }
  broadcastSSE('beacon_sent', { targets: results.filter(r => r.sent).map(r => r.target), probeId });
  const sentCount = results.filter(r => r.sent).length;
  console.log(`📡 [Beacon] entry envelopes sent via ${sentCount}/${results.length} targets (broadcast + unicast reconciliation)`);
  return results;
}

// Background sweep keeps liveness fresh using real subnet-directed broadcasts.
setInterval(() => {
  broadcastBeacon('sweep').catch(() => {});
}, SWEEP_INTERVAL_MS);

// ---------------------------------------------------------------------------
// Happy Eyeballs race: TCP-dial every candidate address concurrently
// (staggered like RFC 8305 / Happy Eyeballs), first connect wins.
// ---------------------------------------------------------------------------
function happyEyeballsRace(targetPort = PORT) {
  // Same channel selection as the UI scanner panel: primary 3 IPv4 + first IPv6 GUA.
  const ipv4 = candidates.filter(c => !c.includes(':')).slice(0, 3);
  const ipv6 = candidates.filter(c => c.includes(':')).slice(0, 1);
  const channels = [
    ...ipv4.map((addr, i) => ({ addr, label: i === 0 ? '主网卡 (Wi-Fi/Ethernet)' : '备用网卡' })),
    ...ipv6.map(addr => ({ addr, label: 'IPv6 GUA' })),
  ];
  if (channels.length === 0) return Promise.resolve({ channels: [], winner: null });

  return new Promise((resolve) => {
    const results = channels.map((ch) => ({ ...ch, status: 'pending', rttMs: null }));
    const sockets = new Set();
    let winner = null;
    let settledCount = 0;
    let finished = false;

    const finishOne = () => {
      settledCount++;
      if (finished) return;
      if (settledCount >= results.length || winner) {
        finished = true;
        for (const s of sockets) s.destroy();
        for (const ch of results) {
          if (ch.status === 'pending') ch.status = winner ? 'cancelled' : 'timeout';
        }
        resolve({
          channels: results.map(({ addr, label, status, rttMs }) => ({ addr, label, status, rttMs })),
          winner,
        });
      }
    };

    results.forEach((ch, i) => {
      setTimeout(() => {
        if (finished) { ch.status = 'cancelled'; finishOne(); return; }
        const start = process.hrtime.bigint();
        const sock = net.connect({ host: ch.addr, port: targetPort });
        sockets.add(sock);
        sock.setTimeout(1500);
        sock.on('connect', () => {
          if (winner) {
            ch.status = 'cancelled';
          } else {
            winner = ch.addr;
            ch.status = 'won';
            ch.rttMs = Math.round((Number(process.hrtime.bigint() - start) / 1e6) * 10) / 10;
          }
          finishOne();
        });
        const fail = () => {
          if (ch.status === 'pending') { ch.status = 'timeout'; finishOne(); }
        };
        sock.on('error', fail);
        sock.on('timeout', () => { sock.destroy(); fail(); });
      }, i * 40); // Happy Eyeballs inter-attempt delay
    });
  });
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const htmlPath = path.join(__dirname, 'index.html');

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/') {
    fs.readFile(htmlPath, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Failed to load index.html: ' + err.message);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  if (url.pathname === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      localDevice,
      lanIp,
      candidates,
      subnetBroadcasts,
      advertised,
      pairingUri,
      httpUrl,
      discoveryPort: DISCOVERY_PORT,
      selfNodeId,
      peers: Array.from(peers.values()),
    }));
    return;
  }

  if (url.pathname === '/api/peers/inject' && req.method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      const record = {
        nodeId: payload.nodeId || `sim_${Date.now().toString(16)}`,
        name: payload.name || 'Redmi-K60-Pro',
        ip: payload.ip || '192.168.2.144',
        udpPort: payload.udpPort || DISCOVERY_PORT,
        tcpPort: payload.tcpPort || 8080,
        device: payload.device || {
          deviceType: 'mobile',
          icon: '📱',
          os: 'android',
          arch: 'aarch64',
          model: 'Redmi K60 Pro',
          hostname: 'Redmi-K60-Pro',
        },
      };
      const merged = upsertPeer(record, 'simulated');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, record: merged }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  if (url.pathname === '/api/beacon' && req.method === 'POST') {
    try {
      const body = await readJsonBody(req);
      if (body.target) {
        // Directed unicast beacon to one peer (real entry envelope), dialed on
        // the peer's actual listening port when known.
        const known = [...peers.values()].find(p => String(p.ip) === body.target);
        const port = (known && known.udpPort) || DISCOVERY_PORT;
        const probe = await probeAddress(body.target, { port, waitMs: 1500, probeId: `direct_${Date.now()}` });
        const rttMs = probe.rttMs !== null ? Math.round(probe.rttMs * 10) / 10 : null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, mode: 'directed', target: body.target, rttMs, replies: probe.replies.length }));
      } else {
        const results = await broadcastBeacon('manual');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, mode: 'broadcast', targets: results }));
      }
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  if (url.pathname === '/api/ping' && req.method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const peer = peers.get(body.nodeId);
      if (!peer) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'peer not found' }));
        return;
      }
      const probe = await probeAddress(peer.ip, { port: peer.udpPort, waitMs: 1500, probeId: `ping_${Date.now()}` });
      const rttMs = probe.rttMs !== null ? Math.round(probe.rttMs * 10) / 10 : null;
      if (rttMs !== null) {
        peer.rttMs = rttMs;
        peers.set(peer.nodeId, peer);
        broadcastSSE('peer_found', { peer });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, nodeId: peer.nodeId, rttMs }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  if (url.pathname === '/api/race' && req.method === 'POST') {
    try {
      await readJsonBody(req);
    } catch (_e) { /* empty body allowed */ }
    const race = await happyEyeballsRace(PORT);
    broadcastSSE('race_done', { winner: race.winner });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, ...race }));
    return;
  }

  if (url.pathname === '/api/qr.svg') {
    const targetUrl = url.searchParams.get('url') || httpUrl;
    const svg = luciola.renderQrSvg(targetUrl);
    if (svg) {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8' });
      res.end(svg);
    } else {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Failed to render QR');
    }
    return;
  }

  if (url.pathname === '/api/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.write(': connected\n\n');
    sseClients.add(res);
    req.on('close', () => {
      sseClients.delete(res);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 [Luciola Web Radar Demo] running at:`);
  console.log(`👉 Local:   http://localhost:${PORT}`);
  if (lanIp) {
    console.log(`👉 Network: ${httpUrl}`);
  }
  console.log('Press Ctrl+C to stop.');
});

process.on('SIGINT', () => {
  console.log('\n👋 Stopping Luciola session...');
  session.stop();
  sweeper.close();
  server.close(() => {
    process.exit(0);
  });
});
