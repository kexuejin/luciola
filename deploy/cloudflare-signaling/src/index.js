import { DurableObject } from "cloudflare:workers";
import {
  authPayload,
  frameSize,
  MAX_MESSAGE_BYTES,
  nextJoinBudget,
  nextMessageBudget,
  ROOM_TTL_MS,
  validateParams,
  verifyEd25519,
} from "./auth.js";

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

    const allSockets = this.ctx.getWebSockets();
    if (allSockets.length === 2) {
      for (const s of allSockets) {
        const other = allSockets.find((x) => x !== s);
        const otherPeer = other?.deserializeAttachment()?.peer || "";
        s.send(JSON.stringify({ type: "peer_online", peer: otherPeer }));
      }
    }

    // Bound room lifetime: expired rooms and their replay/rate state are wiped.
    await this.ctx.storage.setAlarm(now + ROOM_TTL_MS);

    return new Response(null, { status: 101, webSocket: client });
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

    // Opaque blind forwarding: never parse candidate or relay frames.
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws) {
        other.send(message);
      }
    }
  }

  async webSocketClose(ws) {
    const peer = ws.deserializeAttachment()?.peer || "unknown";
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws) {
        other.send(JSON.stringify({ type: "peer_offline", peer }));
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
