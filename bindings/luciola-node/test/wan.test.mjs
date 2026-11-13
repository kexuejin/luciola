// End-to-end test for the Node WAN surface (`connectWan` / `WanChannel`).
//
// The two-peer case needs a deployed signalling Worker and outbound WSS, so it
// is skipped unless explicitly enabled:
//
//   LUCIOLA_WAN_E2E=1 \
//   LUCIOLA_WAN_ENDPOINT=wss://luciola-signaling-staging.<account>.workers.dev/ws \
//   node --test test/wan.test.mjs
//
// The room is derived with `wanDeriveRoomId` rather than shared out of band, so
// both peers agree on it from their own keys, and `connect_wan`'s server-epoch
// realignment stays active because the room equals `derive(epoch)`.
//
// Note what this can and cannot prove: `WanChannel` exposes `channelType()`,
// `remoteAddr()` and `shutdown()` only — no read/write — so the assertion is
// that both sides established and *agreed on a route*, not that bytes moved.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { randomBytes, createPrivateKey, createPublicKey } from 'node:crypto';

const require = createRequire(import.meta.url);
const luciola = require('../index.js');

const E2E = process.env.LUCIOLA_WAN_E2E === '1';
const ENDPOINT = process.env.LUCIOLA_WAN_ENDPOINT || '';
const ROLE = process.argv.find((arg) => arg.startsWith('--role='))?.slice('--role='.length);

// PKCS#8 prefix for a raw Ed25519 seed. Verified against `luciola-cli transfer
// pin --seed`: both produce the same 32-byte public key.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function publicKeyFromSeed(seed) {
  const key = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' });
  return Buffer.from(spki.subarray(spki.length - 32));
}

function wanConfig({ seed, myPublicKey, peerPublicKey, psk, room }) {
  return {
    signalingEndpoint: ENDPOINT,
    room,
    epoch: 0,
    psk,
    identitySeed: seed,
    myPublicKey,
    peerPublicKey,
    relay: {
      allowRelay: true,
      allowWanSignaling: true,
      relayEndpoints: [],
      connectionTimeoutMs: 3000,
    },
    punchTimeoutMs: 60_000,
    progressive: false,
  };
}

// ---------------------------------------------------------------------------
// Receiver role: this file re-executes itself in a child process.
// ---------------------------------------------------------------------------

if (ROLE === 'receiver') {
  const seed = Buffer.from(process.env.LUCIOLA_E2E_SEED, 'hex');
  const peerSeed = Buffer.from(process.env.LUCIOLA_E2E_PEER_SEED, 'hex');
  const psk = Buffer.from(process.env.LUCIOLA_E2E_PSK, 'hex');
  const room = process.env.LUCIOLA_E2E_ROOM;
  const myPublicKey = publicKeyFromSeed(seed);
  const peerPublicKey = publicKeyFromSeed(peerSeed);

  const channel = await luciola.connectWan(
    wanConfig({ seed, myPublicKey, peerPublicKey, psk, room }),
  );
  process.stdout.write(
    `${JSON.stringify({
      ready: true,
      channel: channel.channelType(),
      remote: channel.remoteAddr(),
    })}\n`,
  );

  // Hold the channel until the driver says stop, so both peers are alive in
  // the same rendezvous window.
  await new Promise((resolve) => process.stdin.once('data', resolve));
  await channel.shutdown();
  process.stdout.write(`${JSON.stringify({ after: channel.channelType() })}\n`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

test('connectWan rejects a missing room before touching the network', async () => {
  const seed = randomBytes(32);
  await assert.rejects(
    luciola.connectWan({
      signalingEndpoint: 'ws://127.0.0.1:1/ws',
      room: '',
      epoch: 0,
      psk: Buffer.from('test-psk'),
      identitySeed: seed,
      myPublicKey: publicKeyFromSeed(seed),
      peerPublicKey: publicKeyFromSeed(randomBytes(32)),
      relay: {
        allowRelay: false,
        allowWanSignaling: false,
        relayEndpoints: [],
        connectionTimeoutMs: 3000,
      },
    }),
    /room must not be empty/,
  );
});

test(
  'two Node peers meet over WAN and agree on one channel',
  { skip: E2E && ENDPOINT ? false : 'set LUCIOLA_WAN_E2E=1 and LUCIOLA_WAN_ENDPOINT' },
  async () => {
    const seedA = randomBytes(32);
    const seedB = randomBytes(32);
    const psk = randomBytes(32);
    const pubA = publicKeyFromSeed(seedA);
    const pubB = publicKeyFromSeed(seedB);
    const room = luciola.wanDeriveRoomId(pubA, pubB, psk, luciola.wanCurrentEpoch());

    assert.match(room, /^[0-9a-f]{32}$/, 'derived room must be 32 lowercase hex');

    const child = spawn(process.execPath, [import.meta.filename, '--role=receiver'], {
      env: {
        ...process.env,
        LUCIOLA_E2E_SEED: seedB.toString('hex'),
        LUCIOLA_E2E_PEER_SEED: seedA.toString('hex'),
        LUCIOLA_E2E_PSK: psk.toString('hex'),
        LUCIOLA_E2E_ROOM: room,
      },
      stdio: ['pipe', 'pipe', 'inherit'],
    });

    const lines = [];
    let pending = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      pending += chunk;
      let index;
      while ((index = pending.indexOf('\n')) >= 0) {
        lines.push(pending.slice(0, index));
        pending = pending.slice(index + 1);
      }
    });

    const waitForLine = async (timeoutMs) => {
      const deadline = Date.now() + timeoutMs;
      while (lines.length === 0) {
        if (Date.now() > deadline) throw new Error('receiver did not report ready in time');
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return JSON.parse(lines.shift());
    };

    try {
      // `connectWan` blocks until the peer's candidates arrive, so the receiver
      // cannot report "ready" before the sender dials — waiting for it first is
      // a deadlock that looks like a NAT timeout. Give it a moment to reach the
      // rendezvous, then dial concurrently.
      await new Promise((resolve) => setTimeout(resolve, 500));

      const channel = await luciola.connectWan(
        wanConfig({ seed: seedA, myPublicKey: pubA, peerPublicKey: pubB, psk, room }),
      );
      const ready = await waitForLine(30_000);
      assert.equal(ready.ready, true);
      const senderChannel = channel.channelType();
      assert.ok(
        ['lan_direct', 'hole_punched_direct', 'relay_forwarded', 'usb_adb_direct'].includes(
          senderChannel,
        ),
        `unexpected channel type: ${senderChannel}`,
      );
      // The engine publishes its route decision and waits for the peer's, so
      // both ends must land on the same plane.
      assert.equal(senderChannel, ready.channel, 'both peers must agree on the channel');

      await channel.shutdown();
      assert.equal(channel.channelType(), 'unknown', 'shutdown must clear the channel type');

      child.stdin.write('stop\n');
      const final = await waitForLine(15_000);
      assert.equal(final.after, 'unknown', 'receiver shutdown must clear its channel type');
    } finally {
      child.stdin.end();
      child.kill();
    }
  },
);
