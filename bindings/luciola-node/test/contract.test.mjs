// Runtime contract test: the native surface must match what index.d.ts
// documents. Guards the drift class where a hand-edited binding grows a
// field or parameter and the .d.ts — or a caller's argument order —
// silently lags behind (test.js once passed a PIN into the publicKey
// slot and only passed because the assertions never looked at pin).
import { createRequire } from 'node:module';
import assert from 'node:assert';
import dgram from 'node:dgram';

const require = createRequire(import.meta.url);
const luciola = require('../index.js');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freeUdpPort = () =>
  new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.once('error', reject);
    sock.bind(0, '0.0.0.0', () => {
      const p = sock.address().port;
      sock.close(() => resolve(p));
    });
  });
const waitFor = async (pred, ms) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return true;
    await sleep(50);
  }
  return pred();
};

// 1) buildPairingUri: seven documented args, publicKey sits between
//    fingerprint and pin. The URI carries the key as a base64 string.
const id = luciola.generateDeviceIdentity();
const publicKeyB64 = id.publicKey.toString('base64');
const uri = luciola.buildPairingUri(
  'host', 'prod', 3000, ['192.168.1.2'], id.fingerprint, publicKeyB64, '123456',
);
const info = luciola.parsePairingUri(uri);
assert.strictEqual(info.pin, '123456', 'pin must land in the pin slot');
assert.strictEqual(info.publicKey, publicKeyB64, 'publicKey must land in the publicKey slot');

const uriNoPk = luciola.buildPairingUri(
  'host', 'prod', 3000, ['192.168.1.2'], id.fingerprint, null, '654321',
);
const infoNoPk = luciola.parsePairingUri(uriNoPk);
assert.strictEqual(infoNoPk.pin, '654321', 'null placeholder: pin must land in the pin slot');
assert.ok(!infoNoPk.publicKey, 'publicKey must stay absent');

// 2) stats(): exactly the six documented fields, numeric, zero on a
//    fresh channel (same set as the uniffi LinkStats).
const ch = new luciola.SecureChannel(id.seed);
const s = ch.stats();
assert.deepStrictEqual(
  Object.keys(s).sort(),
  [
    'connectionsEstablished',
    'framesDequeued',
    'framesEnqueued',
    'framesReceived',
    'framesSent',
    'reconnectAttempts',
  ],
  'stats() must expose exactly the documented six fields',
);
for (const v of Object.values(s)) {
  assert.strictEqual(typeof v, 'number', 'stat values must be numbers');
}
ch.close();

// 3) DiscoverySession: the documented 9-arg constructor is accepted, and
//    an advertised `extra` must arrive on the peer object.
const port = await freeUdpPort();
const seen = [];
const observer = new luciola.DiscoverySession('contract-observer', port, null, 'contract');
observer.setProductFilter(['contract']);
observer.start((ev) => {
  if (ev.type === 'found' && ev.peer) seen.push(ev.peer);
});
await sleep(200);
const dialer = new luciola.DiscoverySession(
  'contract-dialer', 0, [{ host: '127.0.0.1', port }], 'contract',
  null, 'extra-payload', null, 0, null,
);
dialer.start(() => {});
assert.ok(
  await waitFor(() => seen.some((p) => p.extra === 'extra-payload'), 4000),
  'peer objects must carry the advertised extra field',
);
observer.stop();
dialer.stop();

console.log('✅ node contract test passed');
