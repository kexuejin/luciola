const http = require('http');
const fs = require('fs');
const path = require('path');
const luciola = require('../../bindings/luciola-node/index.js');

const PORT = process.env.PORT || 3000;
const peers = new Map();
const sseClients = new Set();

// Initialize Luciola discovery engine in Node.js
const localDevice = luciola.getDeviceMeta();
const lanIp = luciola.selectLanIp();
const subnetBroadcasts = luciola.subnetBroadcastAddresses();
const candidates = luciola.localCandidateAddresses();

console.log('✨ [Luciola Web Demo] Initializing discovery engine...');
console.log(`💻 Local Hardware Identity: ${localDevice.icon} ${localDevice.deviceType} | ${localDevice.os} (${localDevice.arch}) | Model: ${localDevice.model || 'N/A'}`);
console.log(`🌐 Best LAN IP: ${lanIp}`);
console.log(`🛡️ Anti-TUN Subnet Broadcasts: ${subnetBroadcasts.join(', ')}`);

const session = new luciola.DiscoverySession('Luciola-Web-Radar', 17878);
session.start((peer) => {
  console.log(`👋 [Luciola Discovered Peer] ${peer.name} (${peer.nodeId}) @ ${peer.ip}:${peer.udpPort}`);
  const record = {
    ...peer,
    lastSeen: Date.now(),
  };
  peers.set(peer.nodeId, record);

  // Broadcast to all connected web clients via SSE
  const eventData = JSON.stringify({ type: 'peer_found', peer: record });
  for (const client of sseClients) {
    client.write(`data: ${eventData}\n\n`);
  }
});

// Periodic peer aging (mark offline if not seen for 90s)
setInterval(() => {
  const now = Date.now();
  for (const [nodeId, peer] of peers.entries()) {
    if (now - peer.lastSeen > 90_000) {
      peers.delete(nodeId);
      const eventData = JSON.stringify({ type: 'peer_expired', nodeId });
      for (const client of sseClients) {
        client.write(`data: ${eventData}\n\n`);
      }
    }
  }
}, 5000);

const htmlPath = path.join(__dirname, 'index.html');

const server = http.createServer((req, res) => {
  // CORS headers
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
      peers: Array.from(peers.values()),
    }));
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
    console.log(`👉 Network: http://${lanIp}:${PORT}`);
  }
  console.log('Press Ctrl+C to stop.');
});

process.on('SIGINT', () => {
  console.log('\n👋 Stopping Luciola session...');
  session.stop();
  server.close(() => {
    process.exit(0);
  });
});
