import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  AUTH_PREFIX,
  authPayload,
  currentEpoch,
  EPOCH_SECONDS,
  frameSize,
  hexToBytes,
  MAX_JOINS_PER_MINUTE,
  MAX_MESSAGE_BYTES,
  MAX_MESSAGES_PER_SECOND,
  nextJoinBudget,
  nextMessageBudget,
  ROOM_TTL_MS,
  validateParams,
  verifyEd25519,
} from "../src/auth.js";

const NOW = 1_800_000_000_000;
const EPOCH = String(currentEpoch(NOW));
const ROOM = "00112233445566778899aabbccddeeff";
const PEER = "ab".repeat(32);
const NONCE = "cd".repeat(16);
const SIG = "ef".repeat(64);

function params(overrides = {}) {
  return new URLSearchParams({
    room: ROOM,
    peer: PEER,
    nonce: NONCE,
    epoch: EPOCH,
    sig: SIG,
    ...overrides,
  });
}

test("epoch matches the Rust 10-minute window", () => {
  assert.equal(EPOCH_SECONDS, 600);
  assert.equal(currentEpoch(NOW), Math.floor(NOW / 1000 / 600));
});

test("auth payload is bound to room, epoch, nonce and the presenting key", () => {
  const bytes = authPayload({ room: ROOM, epoch: EPOCH, nonce: NONCE, peer: PEER });
  assert.equal(
    new TextDecoder().decode(bytes),
    `${AUTH_PREFIX}:${ROOM}:${EPOCH}:${NONCE}:${PEER}`,
  );
});

test("well-formed query is accepted", () => {
  const result = validateParams(params(), NOW);
  assert.equal(result.ok, true);
  assert.deepEqual(result.value, {
    room: ROOM,
    peer: PEER,
    nonce: NONCE,
    epoch: EPOCH,
    sig: SIG,
  });
});

test("malformed shapes are rejected before any crypto", () => {
  const cases = [
    { room: "short" },
    { room: ROOM.toUpperCase() },
    { peer: "ab" },
    { nonce: "cd" },
    { sig: "ef" },
    { epoch: "not-a-number" },
    { epoch: `0${EPOCH}` },
    { epoch: `00${EPOCH}` },
    { epoch: "999999999999999999999999" },
  ];
  for (const bad of cases) {
    const result = validateParams(params(bad), NOW);
    assert.equal(result.ok, false, `expected rejection for ${JSON.stringify(bad)}`);
    assert.equal(result.status, 400);
  }
});

test("epoch outside the current +/-1 window is rejected", () => {
  for (const delta of [-3, -2, 2, 3]) {
    const epoch = String(currentEpoch(NOW) + delta);
    assert.equal(validateParams(params({ epoch }), NOW).ok, false);
  }
  for (const delta of [-1, 0, 1]) {
    const epoch = String(currentEpoch(NOW) + delta);
    assert.equal(validateParams(params({ epoch }), NOW).ok, true);
  }
});

test("hex decoding is strict", () => {
  assert.equal(hexToBytes("00abff").length, 3);
  assert.equal(hexToBytes("abc"), null);
  assert.equal(hexToBytes("zz"), null);
  assert.equal(hexToBytes(42), null);
});

test("Ed25519 verification accepts a genuine signature and fails closed on tampering", async () => {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", publicKey));
  const peerHex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
  const payload = authPayload({ room: ROOM, epoch: EPOCH, nonce: NONCE, peer: peerHex });
  const signature = new Uint8Array(
    await webcrypto.subtle.sign({ name: "Ed25519" }, privateKey, payload),
  );
  const sigHex = [...signature].map((b) => b.toString(16).padStart(2, "0")).join("");

  assert.equal(await verifyEd25519(peerHex, payload, sigHex, webcrypto.subtle), true);

  // Same signature, different room / epoch / nonce / peer in the payload.
  const otherRoom = "ff".repeat(16);
  const otherPayload = authPayload({ room: otherRoom, epoch: EPOCH, nonce: NONCE, peer: peerHex });
  assert.equal(await verifyEd25519(peerHex, otherPayload, sigHex, webcrypto.subtle), false);
  assert.equal(await verifyEd25519(peerHex, payload, "00" + sigHex.slice(2), webcrypto.subtle), false);
  assert.equal(await verifyEd25519(peerHex, payload, "abcd", webcrypto.subtle), false);
  assert.equal(await verifyEd25519("ab".repeat(32), payload, sigHex, webcrypto.subtle), false);
  // Default path uses the runtime's global WebCrypto (Workers / Node 22).
  assert.equal(await verifyEd25519(peerHex, payload, sigHex), true);
});

test("frame size covers text, ArrayBuffer and typed arrays", () => {
  assert.equal(frameSize("abcd"), 4);
  assert.equal(frameSize("é"), 2);
  assert.equal(frameSize(new ArrayBuffer(17)), 17);
  assert.equal(frameSize(new Uint8Array(9)), 9);
  assert.equal(frameSize(null), 0);
  assert.ok(MAX_MESSAGE_BYTES >= 32 * 1024);
});

test("message and join budgets roll over with their time window", () => {
  const second = Math.floor(NOW / 1000);
  let att = { windowSec: second, windowCount: 0 };
  for (let i = 0; i < MAX_MESSAGES_PER_SECOND; i++) {
    const budget = nextMessageBudget(att, NOW);
    assert.equal(budget.allowed, true);
    att = { ...att, ...budget };
  }
  assert.equal(nextMessageBudget(att, NOW).allowed, false);
  assert.equal(nextMessageBudget(att, NOW + 1000).allowed, true);

  let state = null;
  for (let i = 0; i < MAX_JOINS_PER_MINUTE; i++) {
    const join = nextJoinBudget(state, NOW);
    assert.equal(join.allowed, true);
    state = { minute: join.minute, count: join.count };
  }
  assert.equal(nextJoinBudget(state, NOW).allowed, false);
  assert.equal(nextJoinBudget(state, NOW + 60_000).allowed, true);
});

test("room TTL outlives the full epoch +/-1 acceptance window", () => {
  assert.ok(
    ROOM_TTL_MS > 3 * EPOCH_SECONDS * 1000,
    `ROOM_TTL_MS (${ROOM_TTL_MS}) must exceed 3 * EPOCH_SECONDS (${3 * EPOCH_SECONDS * 1000}) so replay keys cannot expire while a signed URL is still valid`,
  );
});
