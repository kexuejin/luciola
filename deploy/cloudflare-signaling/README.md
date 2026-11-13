# Luciola WAN Rendezvous Signaling Service

A Cloudflare Worker + Durable Object rendezvous hub for the `luciola::wan`
Rust core. It uses the Hibernation API so idle rooms cost no duration charges.
This directory ships **source and config**; a deployment is a separate step
(`scripts/deploy-signaling.sh`) and is never part of a published library
artifact.

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
- **Pre-join frames are buffered, not dropped** — while a room holds fewer
  than two sockets there is no forward target, so the first peer's frames
  (handshake, candidates) are stored opaquely in Durable Object storage —
  bounded at 32 frames, still ciphertext — and replayed in order to the second
  peer on join. Without this the rendezvous deadlocks whenever the initiator
  joins first, and neither side can hole-punch because neither holds the
  other's candidates. A room that empties again discards the buffer.
- **Relay budget is 256 messages/second and overflow closes the socket** —
  clients must pace relay writes (the Rust driver's `RelayPacer` sustains
  ~224 frames/s with a 16-frame burst, keeping every server-observable
  one-second window under the budget). Raising the limit trades against the
  bounded-abuse posture; client pacing is the contract, not server headroom.
- **Strict 2-peer limit** — one room accepts two distinct peers, rejects
  duplicates, and emits `peer_online` / `peer_offline` control notices.
- **The `101` upgrade reports the epoch being served** — the Durable Object
  returns `x-luciola-epoch: <unix_seconds / 600>`. Because the room id embeds
  the epoch, two peers on opposite sides of a 10-minute boundary would wait in
  unrelated rooms; a Rust client that left `WanConfig::epoch` at `0` re-derives
  its room at this value and redials once. The header is public metadata (the
  request URL already carries the client's epoch) and carries no key material.
  It does **not** widen authentication: `validateParams` still rejects any
  signature more than one window from the Worker's clock.
- **Hibernation API** — idle WebSockets do not incur duration charges. This is
  an *idle* property only: sustained relay traffic is still a billed
  third-party path (see `SECURITY.md`).

## Layout

| Path | Role |
| :-- | :-- |
| `src/index.js` | Worker fetch handler and `RendezvousRoom` Durable Object |
| `src/auth.js` | Pure, dependency-free validation/verification helpers |
| `test/auth.test.js` | `node --test` suite for the helpers |
| `wrangler.toml` | `RENDEZVOUS` binding, the SQLite-backed DO migration, staging env |
| `../../scripts/deploy-signaling.sh` | deploy + `/health` verification, staging by default |
| `../../scripts/probe-signaling.py` | prove a deployed Worker returns the epoch header on a `101` |
| `../../scripts/wan-proxy-tunnel.py` | loopback `ws://` bridge to a deployed `wss://` Worker through `HTTPS_PROXY` |

## Endpoints

| Path | Response |
| :-- | :-- |
| `/ws` | the rendezvous WebSocket (Ed25519-signed upgrade) |
| `/health` | `{"ok":true,"service":"luciola-signaling","epoch":<n>,"epoch_seconds":600,"version":"<var>"}` |
| anything else | `Luciola WAN Rendezvous Hub Active` (plain text) |

`/health` deliberately exposes nothing but liveness and the epoch this
deployment is serving. The epoch is public metadata — it is derivable from the
wall clock and the client already puts its own in the request URL — and it is
what a deploy script and the field-test tooling need in order to prove they are
talking to the build they just shipped, with a clock that agrees.

## Quick start

```bash
npm install          # install wrangler (devDependency)
npm test             # node --test test/*.test.js — no Cloudflare account needed
npm run dev          # wrangler dev (local, real Durable Object via workerd)
```

`npm test` runs plain Node tests against `src/auth.js`; it deliberately imports
nothing from `cloudflare:workers`, so the authentication rules can be checked
without a Worker runtime.

### Running the real Worker end to end

`wrangler dev` runs the Worker **and** the Durable Object locally under workerd,
so the Rust client can be pointed at it and the whole path — signed upgrade,
edge verification, pre-join buffering, relay forwarding — is exercised for real
rather than against a hand-rolled forwarder:

```bash
# terminal 1
cd deploy/cloudflare-signaling && npx wrangler dev --port 8787 --local

# terminal 2
LUCIOLA_WAN_WORKER=ws://127.0.0.1:8787/ws \
  cargo test -p luciola --test wan_local_worker -- --nocapture
```

`crates/luciola/tests/wan_local_worker.rs` skips itself when
`LUCIOLA_WAN_WORKER` is unset, so CI does not need a Worker. It covers two
peers meeting through the Worker, a 96 KiB relay transfer, and `/health`
reporting an epoch within one window of the client's. `ws://` is accepted by the
client for loopback only; a deployed Worker must be `wss://`.

### Verifying a deployment

A deployed endpoint needs two separate observations. `scripts/probe-signaling.py`
signs a real upgrade request with an ephemeral Ed25519 key and asserts the
`101` carries `x-luciola-epoch` matching `/health`:

```bash
scripts/probe-signaling.py https://luciola-signaling-staging.<account>.workers.dev
```

For the two-peer test, point `LUCIOLA_WAN_WORKER` at the `wss://` endpoint and
raise the timeout for the public TLS handshake plus Durable Object cold start:

```bash
LUCIOLA_WAN_WORKER=wss://luciola-signaling-staging.<account>.workers.dev/ws \
  LUCIOLA_WAN_CONNECT_TIMEOUT_MS=30000 \
  cargo test -p luciola --test wan_local_worker -- --nocapture
```

`connect_wan` has native HTTP CONNECT proxy support, so a `wss://` endpoint
reaches the Worker directly even on hosts whose `*.workers.dev` DNS is
hijacked. For `wss://` it reads `HTTPS_PROXY` / `https_proxy` (falling back to
`ALL_PROXY` / `all_proxy`), honours `NO_PROXY` / `no_proxy`, and always bypasses
loopback so a local `wrangler dev` endpoint is never tunnelled. TLS terminates
in the Rust client with the Worker's real hostname as SNI; the proxy only moves
opaque bytes and sees the hostname, not the signalling payload. Your existing
`HTTPS_PROXY` is enough — no bridge process is needed.

To verify the proxy is actually in use, run the same command with
`NO_PROXY=<worker-host>` as a control. On a hijacked resolver the forced direct
path fails with `rendezvous connect timed out`, while the proxied run completes.

Rust-core / CLI callers can override the environment with `WanConfig::proxy`:
`Some("http://127.0.0.1:8080")` forces one proxy and `Some("")` disables
proxying entirely. The uniffi (KMP/Swift) and Node surfaces do not expose that
field; they use the environment. Only plain `http://` CONNECT proxies are
supported — an `https://` or `socks5://` proxy URL is a configuration error, not
a silent fallback. Proxy credentials in `http://user:pass@host:port` are sent as
Basic auth, held in zeroizing storage and never logged. Proxying applies only
to the signalling WebSocket's TCP connection — STUN queries and UDP hole
punching still use the host's own UDP path and are unaffected by `HTTPS_PROXY`.

`scripts/wan-proxy-tunnel.py` remains in-tree as a diagnostic loopback bridge:
it listens on loopback, tunnels through the proxy with the correct TLS SNI,
rewrites only the `Host` header and pumps bytes. It changes no code under test,
but is no longer required for a deployed run:

```bash
# terminal 1: prints the OS-assigned loopback port
HTTPS_PROXY=http://127.0.0.1:8080 \
  python3 scripts/wan-proxy-tunnel.py \
    https://luciola-signaling-staging.<account>.workers.dev

# terminal 2: use the ws:// endpoint printed above
LUCIOLA_WAN_WORKER=ws://127.0.0.1:<port>/ws \
  LUCIOLA_WAN_CONNECT_TIMEOUT_MS=30000 \
  cargo test -p luciola --test wan_local_worker -- --nocapture
```

## Deploying

```bash
scripts/deploy-signaling.sh                  # staging
scripts/deploy-signaling.sh --production     # production, explicit
scripts/deploy-signaling.sh --check https://…/ # verify an existing deployment
```

The script runs the Worker tests, verifies authentication, deploys, and then
asks the deployment's own `/health` which epoch it serves — a deploy that
succeeds while the Worker does not answer is reported as a failure. With
`CLOUDFLARE_API_TOKEN` set it verifies the token against Cloudflare's token
endpoint instead of running `wrangler whoami`, because a minimally scoped deploy
token deliberately lacks the account/user read scopes `whoami` requires;
otherwise it falls back to the stored `wrangler login`. It never reads, writes or
prints a token. Staging is a separate Worker name with its own Durable Object
namespace (`[env.staging]` in `wrangler.toml`), so a staging deploy cannot serve
production rooms.

## Client alignment

The Worker's `authPayload()` in `src/auth.js` must stay byte-for-byte identical
to the Rust client's `auth_payload()` in
`crates/luciola/src/wan/signaling.rs`. Both sides are covered by tests
(`test/auth.test.js` and `wan::signaling::tests`). Changing one without the
other turns every legitimate join into a 401. The 600-second epoch definition
must also stay in sync with `luciola::wan::current_epoch()`.

Deployment status: the **staging** environment was deployed and verified on
2026-11-13 (`/health`, a real signed `101` upgrade with `x-luciola-epoch`, and
the two-peer 96 KiB relay test against the deployed Durable Object).
**Production is not deployed.** No deployed service ships with the
`0.11.0-local.1` local Maven validation build, and a staging run is not a
real-NAT/CGNAT field test. See `SECURITY.md` for the threat model and the list
of WAN validations that are still outstanding.
