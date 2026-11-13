import { DurableObject } from "cloudflare:workers";
import {
  authPayload,
  currentEpoch,
  EPOCH_SECONDS,
  frameSize,
  MAX_MESSAGE_BYTES,
  nextJoinBudget,
  nextMessageBudget,
  ROOM_TTL_MS,
  validateParams,
  verifyEd25519,
} from "./auth.js";

/**
 * Frames that arrive while the room holds fewer than two sockets are stored
 * under this prefix (one storage key per frame, zero-padded sequence for
 * ordered replay) and delivered to the second peer on join.
 *
 * Without this, the first peer's handshake and candidate frames are forwarded
 * to nobody and lost: the responder then waits for a handshake that was sent
 * before it existed, and the initiator waits for a reply that never comes —
 * the rendezvous deadlocks, and hole punching can never even start because
 * neither side holds the other's candidates.
 */
const PENDING_PREFIX = "pend:";
const PENDING_SEQ_KEY = "pendSeq";
/** Storage bound for an unpaired socket; the client needs a handful of frames. */
const PENDING_MAX = 32;

/**
 * Cloudflare Worker for Luciola WAN rendezvous signalling.
 *
 * The Worker is a blind forwarder: it authenticates the Ed25519 handshake and
 * enforces shape / epoch / rate limits, but never sees candidate addresses or
 * transfer data — those are AES-256-GCM sealed under a PSK-derived key before
 * they leave the device.
 *
 * Trust model: room ids are HKDF-derived from the pairing PSK (unguessable),
 * every frame is authenticated end-to-end, and the Durable Object admits at
 * most two distinct peers. The signalling service therefore learns only the
 * room id, public keys and online times.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Liveness, plus which epoch this deployment is serving. Deliberately
    // tiny: the epoch is public metadata (it is derivable from the wall clock)
    // and nothing else about the deployment is exposed. The field-test and
    // deploy scripts use this to confirm they are talking to the Worker they
    // just deployed, and to check that its clock agrees with the client's.
    if (url.pathname === "/health") {
      const now = Date.now();
      return Response.json(
        {
          ok: true,
          service: "luciola-signaling",
          epoch: currentEpoch(now),
          epoch_seconds: EPOCH_SECONDS,
          version: env.LUCIOLA_SIGNALING_VERSION ?? "dev",
        },
        { headers: { "cache-control": "no-store" } },
      );
    }

    if (url.pathname !== "/ws") {
      return new Response("Luciola WAN Rendezvous Hub Active\n", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    const upgradeHeader = request.headers.get("Upgrade");
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket Upgrade header", { status: 426 });
    }

    const checked = validateParams(url.searchParams);
    if (!checked.ok) {
      return new Response(checked.message, { status: checked.status });
    }
    const { room, peer, nonce, epoch, sig } = checked.value;

    // Verify at the edge before invoking the Durable Object, so unauthenticated
    // traffic cannot create billable DO work. The signed payload includes the
    // room, the epoch, a fresh nonce and the presenting public key.
    const payload = authPayload({ room, epoch, nonce, peer });
    if (!(await verifyEd25519(peer, payload, sig))) {
      return new Response("Unauthorized: invalid Ed25519 signature", { status: 401 });
    }

    // `epoch` was validated against the current +/-1 window, so the name space
    // of Durable Objects an attacker can create is bounded.
    const doId = env.RENDEZVOUS.idFromName(`${room}:${epoch}`);
    return env.RENDEZVOUS.get(doId).fetch(request);
  },
};

/**
 * Forward a frame without letting one dead peer take the handler down.
 *
 * `getWebSockets()` keeps returning a socket that has just closed, so a bare
 * `send` throws inside the event handler and the whole message is lost for the
 * *other* peer too.
 */
function sendSafely(socket, payload) {
  if (!socket || socket.readyState !== 1) return false;
  try {
    socket.send(payload);
    return true;
  } catch {
    return false;
  }
}

/**
 * RendezvousRoom Durable Object: hibernatable two-peer blind forwarding.
 */
export class RendezvousRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const p = new URL(request.url).searchParams;
    const peer = p.get("peer");
    const epoch = p.get("epoch");
    const nonce = p.get("nonce");
    if (!peer || !epoch || !nonce) {
      return new Response("Missing authenticated query parameters", { status: 400 });
    }

    const now = Date.now();

    // Rate limit room joins so a valid key pair cannot spin up unbounded DO
    // work or churn connections for someone else's room.
    const join = nextJoinBudget(await this.ctx.storage.get("joinRate"), now);
    if (!join.allowed) {
      return new Response("Rate limited", { status: 429 });
    }
    await this.ctx.storage.put("joinRate", {
      minute: join.minute,
      count: join.count,
    });

    // Replay protection: a captured URL (valid signature, still inside the
    // epoch window) must not be usable a second time in this room.
    const replayKey = `nonce:${peer}:${nonce}`;
    if ((await this.ctx.storage.get(replayKey)) !== undefined) {
      return new Response("Unauthorized: nonce already used", { status: 401 });
    }
    await this.ctx.storage.put(replayKey, now);

    const sockets = this.ctx.getWebSockets();
    if (sockets.length >= 2) {
      return new Response("Room is full (max 2 peers)", { status: 409 });
    }
    for (const ws of sockets) {
      const att = ws.deserializeAttachment();
      if (att && att.peer === peer) {
        return new Response("Duplicate peer connection rejected", { status: 409 });
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({
      peer,
      epoch: Number(epoch),
      joinedAt: now,
      windowSec: Math.floor(now / 1000),
      windowCount: 0,
    });

    // Deliver everything the first peer sent before this join (handshake,
    // candidates), in original order, then drop the buffer. The frames were
    // forwarded to nobody at the time they arrived.
    const pending = await this.ctx.storage.list({ prefix: PENDING_PREFIX });
    if (pending.size > 0) {
      for (const message of pending.values()) {
        sendSafely(server, message);
      }
      await this.ctx.storage.delete([...pending.keys()]);
      await this.ctx.storage.delete(PENDING_SEQ_KEY);
    }

    const allSockets = this.ctx.getWebSockets();
    if (allSockets.length === 2) {
      for (const s of allSockets) {
        const other = allSockets.find((x) => x !== s);
        const otherPeer = other?.deserializeAttachment()?.peer || "";
        sendSafely(s, JSON.stringify({ type: "peer_online", peer: otherPeer }));
      }
    }

    // Bound room lifetime: expired rooms and their replay/rate state are wiped.
    await this.ctx.storage.setAlarm(now + ROOM_TTL_MS);

    // Tell the client which epoch this deployment is serving. Room ids embed
    // the epoch, so a peer whose clock sits on the other side of a boundary
    // would otherwise wait in a room nobody else joins. The value is public
    // metadata (the request URL already carries the client's own epoch) and
    // carries no key material.
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "x-luciola-epoch": String(currentEpoch(now)) },
    });
  }

  async webSocketMessage(ws, message) {
    // Cap before forwarding: a peer must not be able to push unbounded bytes
    // through the relay. 32 KiB matches the Rust client's receive cap.
    if (frameSize(message) > MAX_MESSAGE_BYTES) {
      ws.close(1009, "frame too large");
      return;
    }

    const att = ws.deserializeAttachment() ?? {};
    const budget = nextMessageBudget(att, Date.now());
    if (!budget.allowed) {
      ws.close(1008, "message rate limit exceeded");
      return;
    }
    ws.serializeAttachment({
      ...att,
      windowSec: budget.windowSec,
      windowCount: budget.windowCount,
    });

    // No second socket yet: keep the frame for replay instead of dropping it
    // on the floor. Still rate-limited and size-capped above, and bounded in
    // count so an unpaired socket cannot grow storage unboundedly.
    if (this.ctx.getWebSockets().length < 2) {
      const seq = ((await this.ctx.storage.get(PENDING_SEQ_KEY)) ?? 0) + 1;
      if (seq > PENDING_MAX) {
        ws.close(1013, "too many frames before the peer joined");
        return;
      }
      await this.ctx.storage.put(PENDING_SEQ_KEY, seq);
      await this.ctx.storage.put(`${PENDING_PREFIX}${String(seq).padStart(12, "0")}`, message);
      return;
    }

    // Opaque blind forwarding: never parse candidate or relay frames.
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws) {
        sendSafely(other, message);
      }
    }
  }

  async webSocketClose(ws) {
    const peer = ws.deserializeAttachment()?.peer || "unknown";
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws) {
        sendSafely(other, JSON.stringify({ type: "peer_offline", peer }));
      }
    }
    // A room that emptied before the second peer ever joined has nobody left
    // to replay its buffered frames to; a rejoining peer re-sends its own
    // handshake under a fresh nonce, so stale frames would only confuse it.
    const remaining = this.ctx.getWebSockets().filter((s) => s !== ws);
    if (remaining.length === 0) {
      const stale = await this.ctx.storage.list({ prefix: PENDING_PREFIX });
      if (stale.size > 0) {
        await this.ctx.storage.delete([...stale.keys()]);
        await this.ctx.storage.delete(PENDING_SEQ_KEY);
      }
    }
  }

  async webSocketError(ws) {
    ws.close(1011, "WebSocket error");
  }

  async alarm() {
    for (const ws of this.ctx.getWebSockets()) {
      ws.close(1000, "Room session expired");
    }
    await this.ctx.storage.deleteAll();
  }
}
