// CI smoke test for @luciola/core — deterministic, exit code reflects success.
const assert = require('assert');
const luciola = require('./index.js');

async function main() {
  // Static probes
  assert.ok(luciola.localCandidateAddresses().length > 0, 'candidates');
  assert.ok(luciola.isVirtualNic('utun5') && !luciola.isPhysicalNic('utun5'), 'nic classify');
  assert.ok(luciola.renderQrSvg('http://x').includes('<svg'), 'qr svg');
  assert.match(luciola.getDeviceMeta().os, /\w+/, 'device meta');

  // Trust primitives
  const id = luciola.generateDeviceIdentity();
  assert.match(id.fingerprint, /^sha256:/, 'fingerprint format');
  assert.match(id.shortPin, /^\d{6}$/, 'pin format');
  const sig = luciola.signMessage(id.seed, Buffer.from('m'));
  assert.ok(luciola.verifyMessage(id.publicKey, Buffer.from('m'), sig), 'verify ok');
  assert.ok(!luciola.verifyMessage(id.publicKey, Buffer.from('x'), sig), 'verify tamper');
  assert.strictEqual(luciola.identityFromSeed(id.seed).fingerprint, id.fingerprint, 'seed restore');

  // WAN Traversal / Pairing v3 & Room derivation
  const uriV3 = luciola.buildPairingUriV3(
    'NodeClient',
    'luciola-test',
    18999,
    ['192.168.1.100'],
    id.fingerprint,
    id.publicKey.toString('base64'),
    '123456',
    'secret_psk_key_123'
  );
  assert.ok(uriV3.includes('psk='), 'uri v3 carries psk');
  const parsedV3 = luciola.parsePairingUri(uriV3);
  assert.strictEqual(parsedV3.psk, 'secret_psk_key_123', 'parsed v3 psk match');
  assert.strictEqual(parsedV3.name, 'NodeClient', 'parsed v3 name match');

  const roomId1 = luciola.deriveRendezvousRoomId('pk_a', 'pk_b', 'secret_psk', 100);
  const roomId2 = luciola.deriveRendezvousRoomId('pk_b', 'pk_a', 'secret_psk', 100);
  assert.strictEqual(roomId1, roomId2, 'rendezvous room derivation is commutative');
  assert.strictEqual(roomId1.length, 32, 'rendezvous room is 32-char hex');

  const errorCodes = luciola.getErrorCodes();
  assert.ok(errorCodes.includes('quota_exceeded'), 'quota_exceeded in errorCodes');

  // Discovery product filter (FFI surface): a host must be able to ignore
  // peers of another luciola product sharing the same discovery port.
  const dgram = require('node:dgram');
  const freeUdpPort = () =>
    new Promise((resolve, reject) => {
      const sock = dgram.createSocket('udp4');
      sock.once('error', reject);
      sock.bind(0, '0.0.0.0', () => {
        const p = sock.address().port;
        sock.close(() => resolve(p));
      });
    });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (pred, ms) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (pred()) return true;
      await sleep(50);
    }
    return pred();
  };
  const discoveryPort = await freeUdpPort();
  const observed = [];
  const observer = new luciola.DiscoverySession('observer', discoveryPort, null, 'alpha');
  assert.strictEqual(typeof observer.setProductFilter, 'function', 'setProductFilter exists');
  observer.setProductFilter(['alpha']);
  observer.start((ev) => {
    if (ev.type === 'found' && ev.peer) observed.push(ev.peer);
  });
  await sleep(200);
  const dialPeer = (name, product) => {
    const s = new luciola.DiscoverySession(name, 0, [{ host: '127.0.0.1', port: discoveryPort }], product);
    s.start(() => {});
    return s;
  };
  const betaPeer = dialPeer('beta-peer', 'beta');
  const alphaPeer = dialPeer('alpha-peer', 'alpha');
  assert.ok(
    await waitFor(() => observed.some((p) => p.product === 'alpha'), 4000),
    'the allowed product must still be discovered',
  );
  await sleep(600);
  assert.ok(
    !observed.some((p) => p.product === 'beta'),
    'a filtered-out product must never reach the callback',
  );
  observer.stop();
  betaPeer.stop();
  alphaPeer.stop();

  // Pairing payload v2 — publicKey has its own slot between fingerprint and
  // pin; passing the PIN without the null placeholder used to land it in the
  // publicKey slot, and the old assertions never checked pin so it passed.
  const uri = luciola.buildPairingUri('Mac 的', 'p1', 3000, ['192.168.1.2', '2408::1'], id.fingerprint, null, '123456');
  const parsed = luciola.parsePairingUri(uri);
  assert.strictEqual(parsed.name, 'Mac 的');
  assert.strictEqual(parsed.fingerprint, id.fingerprint);
  assert.deepStrictEqual(parsed.addrs, ['192.168.1.2', '2408::1']);
  assert.strictEqual(parsed.pin, '123456', 'pin must land in the pin slot');
  assert.ok(!parsed.publicKey, 'publicKey must stay absent when not given');
  const publicKeyB64 = id.publicKey.toString('base64');
  const parsedPk = luciola.parsePairingUri(
    luciola.buildPairingUri('Mac 的', 'p1', 3000, ['192.168.1.2'], id.fingerprint, publicKeyB64, '654321'),
  );
  assert.strictEqual(parsedPk.publicKey, publicKeyB64, 'publicKey must roundtrip as base64');
  assert.strictEqual(parsedPk.pin, '654321');
  assert.strictEqual(luciola.parsePairingUri('http://10.0.0.5:8080').port, 8080);

  // Race + secure channel loopback with stats
  const a = luciola.generateDeviceIdentity();
  const b = luciola.generateDeviceIdentity();
  const server = new luciola.SecureChannel(b.seed);
  await new Promise((res) => {
    let gotHello = false;
    server.listen(0, null, (ev) => {
      if (ev.state === 'connected') {
        gotHello = true;
        server.send(Buffer.from('hi'));
      }
    });
    // port 0 unsupported by listen (bind 0.0.0.0:0) — use a fixed port instead
    server.close(); res();
  });

  const PORT = 18801;
  const server2 = new luciola.SecureChannel(b.seed);
  server2.listen(PORT, null, (ev) => {
    if (ev.state === 'connected') server2.send(Buffer.from('hello'));
  });
  await new Promise((res) => setTimeout(res, 200));
  const client = new luciola.SecureChannel(a.seed);
  await new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('secure connect timeout')), 5000);
    client.connect(['127.0.0.1'], PORT, b.publicKey, false, (ev) => {
      if (ev.state === 'connected') client.send(Buffer.from('ping'));
      if (ev.message && ev.message.toString() === 'hello') {
        clearTimeout(t);
        setTimeout(() => {
          const s = client.stats();
          assert.ok(s.framesSent >= 1 && s.framesReceived >= 1 && s.connectionsEstablished === 1, 'stats');
          assert.strictEqual(typeof s.framesEnqueued, 'number', 'queue counters exist');
          assert.ok(s.framesEnqueued >= 1, 'queued frames must be counted');
          client.close(); server2.close();
          res();
        }, 200);
      }
    });
  });

  console.log('✅ node smoke passed');
}

main().then(() => process.exit(0)).catch((e) => { console.error('❌', e.message); process.exit(1); });
