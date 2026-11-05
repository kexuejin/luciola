// Runtime contract test: the native surface must match what index.d.ts
// documents. Guards the drift class where a hand-edited binding grows a
// field or parameter and the .d.ts — or a caller's argument order —
// silently lags behind (test.js once passed a PIN into the publicKey
// slot and only passed because the assertions never looked at pin).
import { createRequire } from 'node:module';
import assert from 'node:assert';
import dgram from 'node:dgram';
import net from 'node:net';

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

// 4) Error contract: one shared taxonomy for Rust / uniffi / Node.
const codes = luciola.getErrorCodes();
assert.ok(Array.isArray(codes) && codes.length > 0, 'getErrorCodes must return a list');
assert.strictEqual(new Set(codes).size, codes.length, 'error codes must be unique');
for (const c of codes) {
  assert.match(c, /^[a-z][a-z0-9_]*$/, `error code must be snake_case: ${c}`);
}
for (const required of ['bind_failed', 'untrusted_peer', 'unknown']) {
  assert.ok(codes.includes(required), `error codes must include ${required}`);
}

// classifyError normalises the canonical form AND the legacy tunnel prefixes
// that TUNNEL_SPEC still puts on the wire.
const bindErr = luciola.classifyError('forward_bind_failed: port 3020 in use');
assert.strictEqual(bindErr.code, 'bind_failed', 'legacy prefix must map to bind_failed');
assert.strictEqual(bindErr.message, 'port 3020 in use', 'the code prefix must be stripped once');
assert.strictEqual(bindErr.retryable, true, 'a busy port is retryable');

const pinErr = luciola.classifyError('untrusted_peer: peer key mismatch');
assert.strictEqual(pinErr.code, 'untrusted_peer');
assert.strictEqual(pinErr.retryable, false, 'a wrong pin must never be advertised as retryable');

const freeform = luciola.classifyError('a free-form message from an older peer');
assert.strictEqual(freeform.code, 'unknown', 'unrecognised text degrades to unknown');
assert.strictEqual(
  freeform.message,
  'a free-form message from an older peer',
  'unknown text must be preserved, never dropped',
);

// 5) SecureChannel error events carry the structured companion, and it must
//    agree with classifyError(detail). Dialing a closed loopback port fails
//    deterministically (connection refused), so there is no timeout race.
const freeTcpPort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
const deadPort = await freeTcpPort();
const errChannel = new luciola.SecureChannel(id.seed);
let linkEvent = null;
errChannel.connect(['127.0.0.1'], deadPort, id.publicKey, false, (ev) => {
  if (ev.state === 'error' && !linkEvent) linkEvent = ev;
});
assert.ok(await waitFor(() => linkEvent !== null, 5000), 'dialing a closed port must emit error');
assert.strictEqual(typeof linkEvent.detail, 'string', 'detail stays for backward compatibility');
const parsed = luciola.classifyError(linkEvent.detail);
assert.ok(linkEvent.error, 'error/retrying events must carry the structured error object');
assert.strictEqual(linkEvent.error.code, parsed.code, 'error.code must agree with classifyError(detail)');
assert.strictEqual(linkEvent.error.message, parsed.message, 'error.message must agree with classifyError(detail)');
assert.strictEqual(linkEvent.error.retryable, parsed.retryable, 'error.retryable must agree with classifyError(detail)');
assert.ok(
  linkEvent.detail.startsWith(`${linkEvent.error.code}: `),
  'detail must keep exactly one "<code>: " prefix',
);
errChannel.close();

console.log('✅ node contract test passed');
