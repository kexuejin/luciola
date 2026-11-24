// Pure, dependency-free helpers for the rendezvous Worker.
//
// Kept free of `cloudflare:workers` imports so the authentication and input
// validation rules can be exercised with plain `node --test`. The Worker and
// the Durable Object both consume these exact functions — there is only one
// definition of "valid request".

export const AUTH_PREFIX = "LUCIOLA_WAN_AUTH";
export const EPOCH_SECONDS = 600;
/** Matches the Rust client's MAX_SIGNAL_FRAME * 2 (hex-encoded ciphertext). */
export const MAX_MESSAGE_BYTES = 32 * 1024;
export const MAX_JOINS_PER_MINUTE = 20;
export const MAX_MESSAGES_PER_SECOND = 256;
/**
 * Room storage TTL must exceed the full `epoch +/- 1` admission window
 * (`3 * EPOCH_SECONDS = 30 min`) so the Durable Object alarm cannot wipe the
 * `nonce:*` replay store while a captured signed URL is still within window.
 */
export const ROOM_TTL_MS = 35 * 60 * 1000;

const ROOM_RE = /^[0-9a-f]{32}$/;
const PEER_RE = /^[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const SIG_RE = /^[0-9a-f]{128}$/;
const EPOCH_RE = /^(?:0|[1-9]\d{0,19})$/;

/** Current 10-minute rendezvous epoch; must match Rust `current_epoch()`. */
export function currentEpoch(nowMs = Date.now()) {
  return Math.floor(nowMs / 1000 / EPOCH_SECONDS);
}

/**
 * The exact bytes the Rust client signs. Binding `peer` into the payload means
 * a captured signature cannot be replayed under a different public key, and
 * binding `room`/`epoch` means it cannot be replayed into another room.
 */
export function authPayload({ room, epoch, nonce, peer }) {
  return new TextEncoder().encode(
    `${AUTH_PREFIX}:${room}:${epoch}:${nonce}:${peer}`,
  );
}

/** Strict hex decode; returns null for odd length or non-hex characters. */
export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    return null;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Validate every query parameter before any signature check or Durable Object
 * invocation. `epoch` is confined to the current +/-1 window so an attacker
 * cannot create unbounded Durable Objects by inventing epoch values.
 */
export function validateParams(params, nowMs = Date.now()) {
  const room = params.get("room");
  const peer = params.get("peer");
  const nonce = params.get("nonce");
  const epoch = params.get("epoch");
  const sig = params.get("sig");

  const bad = (message) => ({ ok: false, status: 400, message });
  if (!room || !peer || !nonce || !epoch || !sig) {
    return bad("missing required query parameters: room, peer, nonce, epoch, sig");
  }
  if (!ROOM_RE.test(room)) return bad("room must be 32 lowercase hex chars");
  if (!PEER_RE.test(peer)) return bad("peer must be 64 lowercase hex chars (32-byte Ed25519 key)");
  if (!NONCE_RE.test(nonce)) return bad("nonce must be 32 lowercase hex chars (16 random bytes)");
  if (!SIG_RE.test(sig)) return bad("sig must be 128 lowercase hex chars (64-byte Ed25519 signature)");
  if (!EPOCH_RE.test(epoch)) return bad("epoch must be a decimal integer");

  const epochNum = Number(epoch);
  if (!Number.isSafeInteger(epochNum)) return bad("epoch is out of range");
  if (Math.abs(epochNum - currentEpoch(nowMs)) > 1) {
    return bad("epoch outside the accepted window");
  }
  return { ok: true, value: { room, peer, nonce, epoch, sig } };
}

/**
 * Verify Ed25519 with standard WebCrypto first. The legacy `NODE-ED25519`
 * name is only a fallback for Node-based test runners, not a weaker check.
 * Any failure (unsupported algorithm, bad key, bad signature) fails closed.
 */
export async function verifyEd25519(publicKeyHex, dataBytes, signatureHex, subtle) {
  try {
    const cryptoSubtle = subtle ?? globalThis.crypto?.subtle;
    if (!cryptoSubtle) return false;
    const keyBytes = hexToBytes(publicKeyHex);
    const sigBytes = hexToBytes(signatureHex);
    if (!keyBytes || keyBytes.length !== 32 || !sigBytes || sigBytes.length !== 64) {
      return false;
    }

    let key;
    let algorithm;
    try {
      algorithm = { name: "Ed25519" };
      key = await cryptoSubtle.importKey("raw", keyBytes, algorithm, false, ["verify"]);
    } catch {
      algorithm = { name: "NODE-ED25519", namedCurve: "NODE-ED25519" };
      key = await cryptoSubtle.importKey("raw", keyBytes, algorithm, false, ["verify"]);
    }
    return await cryptoSubtle.verify(algorithm, key, sigBytes, dataBytes);
  } catch {
    return false;
  }
}

/** Byte length of a WebSocket message (text, ArrayBuffer or typed array). */
export function frameSize(message) {
  if (typeof message === "string") return new TextEncoder().encode(message).length;
  if (message instanceof ArrayBuffer) return message.byteLength;
  if (ArrayBuffer.isView(message)) return message.byteLength;
  return 0;
}

/** Per-second message budget for a hibernatable WebSocket attachment. */
export function nextMessageBudget(attachment, nowMs = Date.now()) {
  const second = Math.floor(nowMs / 1000);
  const count =
    attachment && attachment.windowSec === second
      ? (attachment.windowCount ?? 0) + 1
      : 1;
  return {
    windowSec: second,
    windowCount: count,
    allowed: count <= MAX_MESSAGES_PER_SECOND,
  };
}

/** Per-minute join budget persisted in Durable Object storage. */
export function nextJoinBudget(state, nowMs = Date.now()) {
  const minute = Math.floor(nowMs / 60_000);
  const count = state && state.minute === minute ? (state.count ?? 0) + 1 : 1;
  return { minute, count, allowed: count <= MAX_JOINS_PER_MINUTE };
}
