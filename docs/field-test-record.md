# Field test record — real NAT / CGNAT matrix

The one thing this repository cannot do for you. Hole-punching claims in
`CHANGELOG.md` and `SECURITY.md` stay qualified with "unit / loopback layer
only" until the runs below exist, because hole punching either works through a
real carrier NAT or it does not, and no amount of loopback testing — nor a
relay-only run against a deployed signalling Worker — answers that. Native
HTTP CONNECT proxy support only changes how the client reaches the signalling
endpoint over TCP; it says nothing about UDP hole punching or NAT behaviour,
and a proxied staging run is still a single-host relay-only run. The
deployed staging verification is recorded separately by layer in those files.

## What to collect

One record per **(network profile, side)** pair. A matrix row needs two peers on
*different* access networks, so a minimal useful matrix is a 2×2:

| # | Side A | Side B | What it proves |
| :-- | :-- | :-- | :-- |
| 1 | home Wi-Fi (cone NAT) | home Wi-Fi (same NAT) | the baseline: punch succeeds, no relay bytes |
| 2 | home Wi-Fi | 4G/5G hotspot | the normal case: two different NATs, punch should succeed |
| 3 | home Wi-Fi | 4G/5G hotspot, CGNAT | the hard case: symmetric/CGNAT side, punch may fail and the relay must carry it |
| 4 | corporate Wi-Fi (blocked UDP) | 4G/5G hotspot | `NoRoute` must be reported honestly, not a fake relay |

Add a row per additional profile you care about (IPv6-only, VPN, hotel captive
portal, dual-stack). The point is coverage of *failure* modes as much as success.

## Operator runbook — one matrix row

One row is **two machines on two different access networks, measured in the
same 600-second epoch**. Work through this on both machines; the harness records
only one side per invocation. Use throwaway identities and a throwaway PSK:
seeds, pins and the PSK are passed as command-line arguments (visible in the
process table and shell history) and are never written into the record.

**0. Preflight — once per session, on each machine.**

```bash
# Offline, no build and no network: proves the Worker URL normalisation.
scripts/field-nat-matrix.sh --self-test

# Proves this deployment answers a real signed upgrade and reports its epoch.
scripts/probe-signaling.py https://luciola-signaling-staging.<account>.workers.dev
```

Remove `HTTPS_PROXY` / `https_proxy` / `ALL_PROXY` / `all_proxy` from both field
machines, or add the Worker hostname to `NO_PROXY`. With a proxy set, the
signalling WebSocket — and therefore every relayed byte — exits through the
proxy's network instead of the access network under test, so the row measures
the proxy rather than the NAT. Proxying never affects STUN or UDP hole punching;
those always use the host's own UDP path. A development host whose
`*.workers.dev` resolver is hijacked needs the proxy just to reach the Worker
and therefore **cannot produce a valid matrix row** — that configuration is a
smoke test only.

**1. Agree the shared values before either side starts.**

| Value | Source / constraint |
| :-- | :-- |
| `$WORKER` | `wss://luciola-signaling-staging.<account>.workers.dev/ws`, identical on both sides |
| `$ROOM` | exactly **32 lowercase hex characters** — `ROOM_RE = /^[0-9a-f]{32}$/` in `deploy/cloudflare-signaling/src/auth.js`; anything else gets a `400` before the Durable Object is touched (a bad signature gets a `401`). Identical on both sides |
| `$PSK` | a throwaway shared secret, identical on both sides |
| `$SEED_A`, `$SEED_B` | one 32-byte hex identity seed per machine |
| `$PIN_A`, `$PIN_B` | `luciola-cli transfer pin --seed "$SEED_A"` (and B); take the `public_key=` line |

Build the CLI on both machines and derive the pins once:

```bash
cargo build -q -p luciola-cli
CLI="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/luciola-cli"
"$CLI" transfer pin --seed "$SEED_A"      # -> public_key=… (PIN_A)
"$CLI" transfer pin --seed "$SEED_B"      # -> public_key=… (PIN_B)
```

Fetch `/health` on both sides and note its `epoch`. Room routing is
`room:epoch`, so peers that cross a 10-minute boundary join unrelated Durable
Objects; if the epochs differ, wait for the next window and restart the row. Do
not reuse a `$ROOM` across rows.

**2. Start the receiver first (machine B).** `connect_wan` waits for a peer
rather than failing instantly, and the Worker buffers up to 32 early frames for
the second joiner, but starting the sender into an empty room burns the
rendezvous timeout and risks crossing an epoch boundary. Have B listening
before A dials.

```bash
RECV_DIR=$(mktemp -d)
"$CLI" transfer recv \
  --seed "$SEED_B" --accept-pin "$PIN_A" \
  --room "$ROOM" --signaling "$WORKER" --psk "$PSK" \
  --out "$RECV_DIR"
```

**3. Run the sender side through the harness (machine A).**

```bash
PROBE_FILE=$(mktemp)
dd if=/dev/urandom of="$PROBE_FILE" bs=1048576 count=1 2>/dev/null

LUCIOLA_SEED="$SEED_A" \
LUCIOLA_FIELD_NOTES="side A: home Wi-Fi; side B: 4G CGNAT; <carrier>; no VPN" \
scripts/field-nat-matrix.sh \
  --label home-wifi-vs-4g-cgnat-A \
  --worker "$WORKER" \
  --send "$PROBE_FILE" \
  --peer-seed "$SEED_B" --pin "$PIN_B" \
  --room "$ROOM" --psk "$PSK"
```

`--peer-seed` is optional; when supplied the harness derives the peer's public
key and aborts before the transfer if it disagrees with `--pin`, which is the
value actually passed to the CLI as `--pin-peer`. Add `--progressive` to
exercise the zero-wait relay with a background direct upgrade.

`--worker` may be the `wss://…/ws` signalling URL itself: the harness
normalises it to `https://…/health` for the liveness probe (curl has no
`wss://` support) and passes the original URL to `--signaling`. An earlier
version fed the `wss://` URL straight to curl and recorded
`{"error":"unreachable"}` for a healthy Worker; `--self-test` guards that path.

**4. Record side B as well.** Run the harness on B with `--label …-B` and the
same `$ROOM` / `$PSK` (a reverse-direction `--send` is optional). Set
`LUCIOLA_FIELD_LOG` to a shared path if you want both records in one file. Both
labels go in one summary row; a single record is a half-row and proves nothing
about NAT.

**5. Capture what the JSON cannot.** `transfer.result` is one success/failure
and does not say whether the peers punched or stayed on the relay. Copy
`channel_type` from the client log into the notes, along with whether relay
bytes flowed, elapsed time, and any `NoRoute` report. A row that proves "1 MiB
arrived once" proves exactly that.

**6. Repeat for rows 1–4** in the table above, then follow *Filling in the
summary*. Until then the "no real-NAT / carrier-grade-NAT field test" caveat
stays in `CHANGELOG.md`, `SECURITY.md` and both READMEs.

## Running one record

```bash
# Always: environment + RFC 5780 behaviour. Works with a single machine.
scripts/field-nat-matrix.sh --label home-wifi

# With a deployed Worker: also records its epoch so clock skew is visible.
scripts/field-nat-matrix.sh --label 4g-cgnat \
  --worker https://luciola-signaling-staging.<account>.workers.dev

# With a real transfer: the row that actually decides "does WAN work".
# A receiver must already be running on the second machine (runbook step 2).
scripts/field-nat-matrix.sh --label 4g-cgnat \
  --worker wss://luciola-signaling-staging.<account>.workers.dev/ws \
  --send /tmp/probe.bin \
  --seed "$MY_SEED" --peer-seed "$PEER_SEED" \
  --pin "$PEER_PIN" --room "$ROOM" --psk "$PSK"
```

`--worker` accepts either form. For the `wss://…/ws` form the liveness probe is
normalised to `https://…/health` while the original URL is passed to
`--signaling`; `--self-test` checks that conversion offline.

The script appends one JSON line per run to `$LUCIOLA_FIELD_LOG`
(`field-records.jsonl` by default) and prints it. Set
`LUCIOLA_FIELD_NOTES="..."` to attach context (which SIM, which VPN, whether the
carrier is known to CGNAT).

Seeds and PSKs are passed to the CLI and never written to the record.

## What the record contains

```json
{
  "schema": "luciola.field-record/1",
  "recorded_at": "2026-11-13T02:27:44+00:00",
  "label": "local-smoke",
  "host": "…",
  "os": "Darwin_25.6.0_arm64",
  "interface": "en1",
  "nat": { "classification": "Unknown", "mapping": "…", "filtering": "…",
           "reflexive_addr": "…", "prediction": "…", "epoch": 2990894 },
  "worker": { "ok": true, "epoch": 2990894, "version": "…" },
  "transfer": { "result": "ok", "bytes": 1048576, "elapsed_s": 3 },
  "notes": ""
}
```

`nat.prediction` is a prediction for **that side only** — a one-sided RFC 5780
probe cannot know the peer's NAT. `Unknown` is a legitimate, expected outcome
when the STUN server does not offer a second address for the filtering test;
it must not be read as "cone".

## Filling in the summary

After the runs, summarise in `docs/field-test-results.md` (create it when you
have real data — do not pre-fill it with guesses). A `local-smoke` record taken
on the development host is useful for checking the harness, but it is **not** a
matrix row: it has one side, no paired second peer on another access network,
and `transfer` is `null`. Do not put it in the summary table or use it to lift
the real-NAT caveat.

| Profile | mapping | filtering | classification | punch outcome | relay used | notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |

Then, and only then, remove the "no real-NAT / carrier-grade-NAT field test"
caveat from `CHANGELOG.md`, `SECURITY.md` and the READMEs — naming the runs that
back the claim, per `AGENTS.md` §12.

## Known limits of this harness

- It records **one side per run**. Pairing two machines is manual: run it on
  both, with matching `--room`/`--psk`, and put both labels in the summary row.
- `transfer.result` is a single success/failure. It does not distinguish
  "punched and migrated" from "stayed on the relay" — read `channel_type` from a
  client log if that distinction matters for the row.
- Nothing here measures throughput or stability over time. A row that only
  proves "1 MiB arrived once" is exactly that and no more.
