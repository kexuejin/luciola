import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const luciola = require('../index.js');

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
    srv.on('error', reject);
  });
}

// Minimal RFC 6455 loopback room relay so WAN surfaces (`WanTunnelSession`,
// `attachWanChannel`, `transferSendWan`) run end-to-end offline with no
// external Worker or network dependency.
function encodeWsFrame(opcode, payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

async function startMockSignalingServer() {
  const rooms = new Map();
  const sockets = new Set();

  const server = http.createServer((_req, res) => {
    res.writeHead(404);
    res.end();
  });

  server.on('upgrade', (req, socket) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const room = url.searchParams.get('room') || 'default';
    const key = req.headers['sec-websocket-key'];
    const accept = crypto
      .createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );

    sockets.add(socket);
    if (!rooms.has(room)) rooms.set(room, []);
    const peers = rooms.get(room);
    const peer = { socket, queue: [] };
    peers.push(peer);

    // Flush frames queued by an earlier peer in the same room.
    for (const other of peers) {
      if (other !== peer && other.queue.length > 0) {
        for (const frame of other.queue.splice(0)) {
          if (!socket.destroyed) socket.write(frame);
        }
      }
    }

    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const opcode = buf[0] & 0x0f;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let offset = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          len = Number(buf.readBigUInt64BE(2));
          offset = 10;
        }
        const maskLen = masked ? 4 : 0;
        if (buf.length < offset + maskLen + len) return;
        const mask = masked ? buf.subarray(offset, offset + 4) : null;
        offset += maskLen;
        const payload = Buffer.from(buf.subarray(offset, offset + len));
        buf = buf.subarray(offset + len);
        if (mask) {
          for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
        }
        if (opcode === 0x8) {
          socket.end();
          return;
        }
        if (opcode === 0x9) {
          if (!socket.destroyed) socket.write(encodeWsFrame(0x0a, payload));
          continue;
        }
        if (opcode === 0x1 || opcode === 0x2) {
          const out = encodeWsFrame(opcode, payload);
          const others = (rooms.get(room) || []).filter((p) => p !== peer);
          if (others.length === 0) {
            peer.queue.push(out);
          } else {
            for (const o of others) {
              if (!o.socket.destroyed) o.socket.write(out);
            }
          }
        }
      }
    });

    socket.on('close', () => {
      sockets.delete(socket);
      const list = rooms.get(room);
      if (list) {
        const idx = list.indexOf(peer);
        if (idx >= 0) list.splice(idx, 1);
      }
    });
    socket.on('error', () => {});
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    endpoint: `ws://127.0.0.1:${port}/ws`,
    close: async () => {
      for (const s of sockets) s.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

async function connectLoopbackWanPair(endpoint) {
  const alice = luciola.generateDeviceIdentity();
  const bob = luciola.generateDeviceIdentity();
  const psk = crypto.randomBytes(32);
  const epoch = luciola.wanCurrentEpoch();
  const room = luciola.wanDeriveRoomId(alice.publicKey, bob.publicKey, psk, epoch);

  const mkCfg = (selfId, peerId) => ({
    signalingEndpoint: endpoint,
    room,
    epoch,
    psk,
    identitySeed: selfId.seed,
    myPublicKey: selfId.publicKey,
    peerPublicKey: peerId.publicKey,
    relay: {
      allowRelay: true,
      allowWanSignaling: true,
      relayEndpoints: [],
      connectionTimeoutMs: 3000,
    },
    enableHolePunching: false,
    punchTimeoutMs: 500,
    progressive: false,
  });

  const [chA, chB] = await Promise.all([
    luciola.connectWan(mkCfg(alice, bob)),
    luciola.connectWan(mkCfg(bob, alice)),
  ]);
  return { alice, bob, chA, chB };
}

test('Node binding exposes WAN data-plane, transfer, and WanTunnelSession surfaces', () => {
  assert.equal(typeof luciola.SecureChannel.prototype.attachWanChannel, 'function');
  assert.equal(typeof luciola.transferSendLan, 'function');
  assert.equal(typeof luciola.transferRecvLan, 'function');
  assert.equal(typeof luciola.transferSendWan, 'function');
  assert.equal(typeof luciola.transferRecvWan, 'function');
  assert.equal(typeof luciola.WanTunnelSession.fromWanChannel, 'function');
  assert.equal(typeof luciola.WanTunnelSession.prototype.startUdpForward, 'function');
  assert.equal(typeof luciola.WanTunnelSession.prototype.stopUdpForward, 'function');
  assert.equal(typeof luciola.WanTunnelSession.prototype.disableForwardEndpoint, 'function');
});

test('transferSendLan and transferRecvLan roundtrip file with verified SHA-256 and pinned keys', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'luciola-node-xfer-'));
  const srcDir = path.join(dir, 'src');
  const dstDir = path.join(dir, 'dst');
  fs.mkdirSync(srcDir);
  fs.mkdirSync(dstDir);

  const srcFile = path.join(srcDir, 'hello.bin');
  const payload = Buffer.alloc(128 * 1024, 0x5a);
  fs.writeFileSync(srcFile, payload);

  const alice = luciola.generateDeviceIdentity();
  const bob = luciola.generateDeviceIdentity();
  const port = await freePort();

  const recvPromise = luciola.transferRecvLan(bob.seed, port, alice.publicKey, dstDir);
  // Give the dual-stack listener a moment to bind before dialing.
  await new Promise((r) => setTimeout(r, 80));
  const sendReceipt = await luciola.transferSendLan(
    alice.seed,
    ['127.0.0.1'],
    port,
    bob.publicKey,
    srcFile,
  );
  const recvReceipt = await recvPromise;

  assert.equal(sendReceipt.sha256Hex, recvReceipt.sha256Hex);
  assert.equal(recvReceipt.totalBytes, payload.length);
  assert.equal(recvReceipt.fileName, 'hello.bin');
  assert.equal(recvReceipt.channelType, 'lan_direct');
  assert.ok(fs.existsSync(path.join(dstDir, 'hello.bin')));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('transferSendLan rejects non-32-byte pinned key (no TOFU shortcut)', async () => {
  const alice = luciola.generateDeviceIdentity();
  await assert.rejects(
    luciola.transferSendLan(alice.seed, ['127.0.0.1'], 12345, Buffer.alloc(0), '/nonexistent'),
    /32 bytes/,
  );
});

test('WanTunnelSession.fromWanChannel + startLocalForward run inside Tokio runtime and roundtrip TCP', async () => {
  const sig = await startMockSignalingServer();
  const echoServer = net.createServer((sock) => sock.pipe(sock));
  await new Promise((resolve) => echoServer.listen(0, '127.0.0.1', resolve));
  const echoPort = echoServer.address().port;

  try {
    const { chA, chB } = await connectLoopbackWanPair(sig.endpoint);
    const initiator = await luciola.WanTunnelSession.fromWanChannel(chA, true);
    const responder = await luciola.WanTunnelSession.fromWanChannel(chB, false);

    assert.equal(initiator.isAlive(), true);
    assert.equal(initiator.channelType(), 'relay_forwarded');

    await responder.enableForwardEndpoint([
      { host: '127.0.0.1', portFrom: echoPort, portTo: echoPort, udp: true },
    ]);
    const localPort = await initiator.startLocalForward(0, '127.0.0.1', echoPort);
    assert.ok(localPort > 0);

    const echoed = await new Promise((resolve, reject) => {
      const sock = net.connect(localPort, '127.0.0.1', () => {
        sock.write(Buffer.from('hello-wan-tunnel'));
      });
      sock.once('data', (d) => {
        sock.end();
        resolve(d.toString('utf8'));
      });
      sock.once('error', reject);
    });
    assert.equal(echoed, 'hello-wan-tunnel');

    const udpPort = await initiator.startUdpForward(0, '127.0.0.1', echoPort);
    assert.ok(udpPort > 0);
    assert.equal(await initiator.stopUdpForward(udpPort), true);
    assert.equal(await initiator.stopLocalForward(localPort), true);
    await responder.disableForwardEndpoint();

    await initiator.shutdown();
    await responder.shutdown();
    assert.equal(initiator.isAlive(), false);
  } finally {
    await new Promise((resolve) => echoServer.close(resolve));
    await sig.close();
  }
});

test('transferSendWan rejects non-finite, negative, fractional, or unsafe maxRelayBytes', async () => {
  const sig = await startMockSignalingServer();
  try {
    const { chA, chB } = await connectLoopbackWanPair(sig.endpoint);
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, Number.MAX_SAFE_INTEGER + 2]) {
      await assert.rejects(
        luciola.transferSendWan(chA, '/nonexistent', bad),
        /non-negative safe integer/,
      );
    }
    await chA.shutdown();
    await chB.shutdown();
  } finally {
    await sig.close();
  }
});

test('SecureChannel.attachWanChannel handles keepalive=0 without panicking', async () => {
  const sig = await startMockSignalingServer();
  try {
    const { alice, bob, chA, chB } = await connectLoopbackWanPair(sig.endpoint);
    const scA = new luciola.SecureChannel(alice.seed);
    const scB = new luciola.SecureChannel(bob.seed);
    scA.setKeepalive(0, 0);
    scB.setKeepalive(0, 0);

    let receivedResolve;
    const received = new Promise((resolve) => {
      receivedResolve = resolve;
    });
    scA.attachWanChannel(chA, () => {});
    scB.attachWanChannel(chB, (ev) => {
      if (ev.message) receivedResolve(ev.message.toString('utf8'));
    });

    assert.equal(scA.send(Buffer.from('ping-ka0')), true);
    const got = await Promise.race([
      received,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000)),
    ]);
    assert.equal(got, 'ping-ka0');

    scA.close();
    scB.close();
  } finally {
    await sig.close();
  }
});

test('SecureChannel timer setters reject non-finite or negative values', () => {
  const id = luciola.generateDeviceIdentity();
  const sc = new luciola.SecureChannel(id.seed);
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1]) {
    assert.throws(() => sc.setKeepalive(bad, 1000), /non-negative finite/);
    assert.throws(() => sc.setRetryPolicy(bad, 1000, 10), /non-negative finite/);
    assert.throws(() => sc.setTunnelKeepalive(bad, 1000), /non-negative finite/);
  }
  sc.close();
});

test('transferSendLan/transferRecvLan deliver onProgress and honour TransferCancelHandle', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'luciola-node-prog-'));
  const srcDir = path.join(dir, 'src');
  const dstDir = path.join(dir, 'dst');
  fs.mkdirSync(srcDir);
  fs.mkdirSync(dstDir);

  const srcFile = path.join(srcDir, 'progress.bin');
  const payload = Buffer.alloc(192 * 1024, 0x3c);
  fs.writeFileSync(srcFile, payload);

  const alice = luciola.generateDeviceIdentity();
  const bob = luciola.generateDeviceIdentity();
  const port = await freePort();

  const sendProgress = [];
  const recvProgress = [];
  const recvPromise = luciola.transferRecvLan(
    bob.seed,
    port,
    alice.publicKey,
    dstDir,
    (p) => recvProgress.push(p),
  );
  await new Promise((r) => setTimeout(r, 80));
  const sendReceipt = await luciola.transferSendLan(
    alice.seed,
    ['127.0.0.1'],
    port,
    bob.publicKey,
    srcFile,
    (p) => sendProgress.push(p),
  );
  const recvReceipt = await recvPromise;
  assert.equal(sendReceipt.sha256Hex, recvReceipt.sha256Hex);

  // Give queued non-blocking TSFN callbacks one tick to flush.
  await new Promise((r) => setTimeout(r, 40));
  assert.ok(sendProgress.length > 0, 'sender onProgress must fire');
  assert.ok(recvProgress.length > 0, 'receiver onProgress must fire');
  assert.equal(sendProgress.at(-1).bytesDone, payload.length);
  assert.equal(recvProgress.at(-1).bytesDone, payload.length);

  // Pre-cancelled TransferCancelHandle aborts accept/dial promptly.
  const cancel = new luciola.TransferCancelHandle();
  assert.equal(cancel.isCancelled(), false);
  cancel.cancel();
  assert.equal(cancel.isCancelled(), true);
  await assert.rejects(
    luciola.transferRecvLan(bob.seed, 0, alice.publicKey, dstDir, null, cancel),
    /cancelled/i,
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test('SecureHub and connectWithPolicy support multi-peer messaging, pre-sign gate, and pin-mismatch stop', async () => {
  const hubId = luciola.generateDeviceIdentity();
  const alice = luciola.generateDeviceIdentity();
  const bob = luciola.generateDeviceIdentity();
  const wrongPeer = luciola.generateDeviceIdentity();

  const hubEvents = [];
  const hub = await luciola.SecureHub.start(0, hubId.seed, [alice.publicKey], (ev) => {
    hubEvents.push(ev);
  });
  const port = hub.localPort();
  assert.ok(port > 0);

  try {
    // 1. Unallowed peer (bob) is rejected pre-sign.
    await assert.rejects(
      luciola.connectWithPolicy('lan_only', 0, {
        addresses: ['127.0.0.1'],
        port,
        identitySeed: bob.seed,
        peerPublicKey: hubId.publicKey,
      }),
    );

    const waitEvent = async (pred, label) => {
      const end = Date.now() + 3000;
      while (Date.now() < end) {
        const hit = hubEvents.find(pred);
        if (hit) return hit;
        await new Promise((r) => setTimeout(r, 20));
      }
      throw new Error(`timed out waiting for ${label}`);
    };
    await waitEvent((e) => e.type === 'peer_rejected', 'peer_rejected');

    // 2. Pin mismatch under lan_then_wan fails immediately with untrusted peer (no WAN fallback).
    await assert.rejects(
      luciola.connectWithPolicy(
        'lan_then_wan',
        1000,
        {
          addresses: ['127.0.0.1'],
          port,
          identitySeed: alice.seed,
          peerPublicKey: wrongPeer.publicKey,
        },
        null,
      ),
      /untrusted/i,
    );

    // 3. Dynamically allow bob and connect both peers concurrently.
    assert.equal(hub.addAllowedPeer(bob.publicKey), true);
    assert.equal(hub.addAllowedPeer(bob.publicKey), false);

    const chAlice = await luciola.connectWithPolicy(
      'lan_then_wan',
      1500,
      {
        addresses: ['127.0.0.1'],
        port,
        identitySeed: alice.seed,
        peerPublicKey: hubId.publicKey,
      },
      null,
    );
    assert.equal(chAlice.channelType(), 'lan_direct');

    const chBob = await luciola.connectWithPolicy('lan_only', 0, {
      addresses: ['127.0.0.1'],
      port,
      identitySeed: bob.seed,
      peerPublicKey: hubId.publicKey,
    });
    assert.equal(chBob.channelType(), 'lan_direct');

    const aliceInbox = [];
    const bobInbox = [];
    const scAlice = new luciola.SecureChannel(alice.seed);
    const scBob = new luciola.SecureChannel(bob.seed);
    scAlice.attachWanChannel(chAlice, (ev) => {
      if (ev.message) aliceInbox.push(ev.message.toString('utf8'));
    });
    scBob.attachWanChannel(chBob, (ev) => {
      if (ev.message) bobInbox.push(ev.message.toString('utf8'));
    });

    const end = Date.now() + 3000;
    while (hub.connectedPeers().length < 2 && Date.now() < end) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(hub.connectedPeers().length, 2);

    // Alice -> Hub
    assert.equal(scAlice.send(Buffer.from('hello-hub')), true);
    const msgEv = await waitEvent((e) => e.type === 'message', 'hub message');
    assert.equal(msgEv.fingerprint, alice.fingerprint);
    assert.equal(msgEv.payload.toString('utf8'), 'hello-hub');

    // Hub -> Alice unicast + broadcast
    assert.equal(hub.sendTo(alice.fingerprint, Buffer.from('direct-alice')), true);
    assert.deepEqual(hub.broadcast(Buffer.from('all-peers')), []);

    const rxEnd = Date.now() + 3000;
    while ((aliceInbox.length < 2 || bobInbox.length < 1) && Date.now() < rxEnd) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.deepEqual(aliceInbox, ['direct-alice', 'all-peers']);
    assert.deepEqual(bobInbox, ['all-peers']);

    assert.equal(hub.removeAllowedPeer(bob.publicKey), true);
    assert.equal(hub.kick(bob.fingerprint), true);
    await waitEvent(
      (e) => e.type === 'peer_disconnected' && e.fingerprint === bob.fingerprint,
      'bob disconnected',
    );

    scAlice.close();
    scBob.close();
  } finally {
    hub.stop();
  }
});
