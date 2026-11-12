# Luciola WAN Rendezvous Signaling Service

A Cloudflare Worker + Durable Object rendezvous hub for the `luciola::wan`
Rust core. It uses the Hibernation API so idle rooms cost no duration charges.
This directory ships **source and config, not a deployed public endpoint**.

## What the service does

- **Deterministic routing** — a validated `room:epoch` pair names one Durable
  Object via `env.RENDEZVOUS.idFromName`. The `room` itself is derived by the
  client (`pairing::derive_rendezvous_room_id`) as an HKDF-SHA256 output keyed
  by the pairing PSK, both public keys and a 10-minute epoch; the Worker only
  checks that it is 32 lowercase hex characters.
- **Ed25519 edge verification** — every upgrade request is signed with the
  presenting identity key over exactly
  `LUCIOLA_WAN_AUTH:${room}:${epoch}:${nonce}:${peer}`, the same bytes the
  Rust client signs (`crates/luciola/src/wan/signaling.rs`). Standard WebCrypto
  `{ name: "Ed25519" }` is tried first; the legacy `NODE-ED25519` algorithm is
  a fallback only, and any verification failure is a closed 401.
- **Bounded abuse surface** — all validation lives in `src/auth.js`: strict
  lowercase-hex shapes for `room` / `peer` / `nonce` / `sig`, an epoch window
  of the current ±1 600-second epoch, and a 32 KiB frame cap
  (`MAX_MESSAGE_BYTES`, matching the Rust client's hex-encoded frame budget).
  The Durable Object rejects reused nonces via storage keys
  `nonce:${peer}:${nonce}`, limits joins to 20/minute and messages to
  256/second, and cleans up with an alarm after 15 minutes of room TTL.
- **Blind forwarding of opaque ciphertext** — the Worker reads only the JSON
  envelope `{"v":1,"t":"candidate|route|relay","s":<seq>,"ct":"<hex>"}`.
  Candidate addresses, route decisions and relay bytes are AES-256-GCM sealed
  before they leave the device under an HKDF-SHA256 key derived from the
  pairing PSK. The service never sees endpoint addresses or file data. Do not
  add plaintext fields to that envelope.
- **Strict 2-peer limit** — one room accepts two distinct peers, rejects
  duplicates, and emits `peer_online` / `peer_offline` control notices.
- **Hibernation API** — idle WebSockets do not incur duration charges. This is
  an *idle* property only: sustained relay traffic is still a billed
  third-party path (see `SECURITY.md`).

## Layout

| Path | Role |
| :-- | :-- |
| `src/index.js` | Worker fetch handler and `RendezvousRoom` Durable Object |
| `src/auth.js` | Pure, dependency-free validation/verification helpers |
| `test/auth.test.js` | `node --test` suite for the helpers |
| `wrangler.toml` | `RENDEZVOUS` binding and the SQLite-backed DO migration |

## Quick start

```bash
npm install          # install wrangler (devDependency)
npm test             # node --test test/*.test.js — no Cloudflare account needed
npm run dev          # wrangler dev (local)
npm run deploy       # wrangler deploy (requires your own Cloudflare account)
```

`npm test` runs plain Node tests against `src/auth.js`; it deliberately imports
nothing from `cloudflare:workers`, so the authentication rules can be checked
without a Worker runtime.

## Client alignment

The Worker's `authPayload()` in `src/auth.js` must stay byte-for-byte identical
to the Rust client's `auth_payload()` in
`crates/luciola/src/wan/signaling.rs`. Both sides are covered by tests
(`test/auth.test.js` and `wan::signaling::tests`). Changing one without the
other turns every legitimate join into a 401. The 600-second epoch definition
must also stay in sync with `luciola::wan::current_epoch()`.

Deployment status: **not deployed as part of the 0.11.0-local.1 local Maven
validation build**. See `SECURITY.md` for the threat model and the list of
WAN validations that are still outstanding.
