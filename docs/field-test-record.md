# Field test record — real NAT / CGNAT matrix

The one thing this repository cannot do for you. Hole-punching claims in
`CHANGELOG.md` and `SECURITY.md` stay qualified with "unit / loopback layer
only" until the runs below exist, because hole punching either works through a
real carrier NAT or it does not, and no amount of loopback testing — nor a
relay-only run against a deployed signalling Worker — answers that. The
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

## Running one record

```bash
# Always: environment + RFC 5780 behaviour. Works with a single machine.
scripts/field-nat-matrix.sh --label home-wifi

# With a deployed Worker: also records its epoch so clock skew is visible.
scripts/field-nat-matrix.sh --label 4g-cgnat \
  --worker https://luciola-signaling-staging.<acct>.workers.dev

# With a real transfer: the row that actually decides "does WAN work".
scripts/field-nat-matrix.sh --label 4g-cgnat \
  --worker wss://luciola-signaling-staging.<acct>.workers.dev/ws \
  --send /tmp/probe.bin \
  --seed "$MY_SEED" --peer-seed "$PEER_SEED" \
  --pin "$PEER_PIN" --room "$ROOM" --psk "$PSK"
```

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
