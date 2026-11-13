#!/usr/bin/env bash
# Collect one field-test record per network profile.
#
# A real NAT/CGNAT matrix cannot be scripted end to end: it needs two machines
# on different access networks, and the operator is the one who switches Wi-Fi /
# hotspot / VPN between runs. This script does the part that *can* be automated
# — capture the environment, probe RFC 5780 behaviour, check the signalling
# Worker's epoch, and (optionally) run one real transfer — and appends a single
# JSON line per run so the matrix is a machine-readable file rather than prose.
#
# Usage:
#   scripts/field-nat-matrix.sh --self-test
#   scripts/field-nat-matrix.sh --label home-wifi
#   scripts/field-nat-matrix.sh --label 4g-cgnat \
#       --worker https://luciola-signaling-staging.<account>.workers.dev
#   scripts/field-nat-matrix.sh --label hotel-wifi \
#       --worker wss://luciola-signaling-staging.<account>.workers.dev/ws \
#       --send /tmp/probe.bin --peer-seed "$PEER_SEED" --pin "$PEER_PIN" \
#       --room "$ROOM" --psk "$PSK"
#
# --worker accepts either an https:// base URL or the wss:// signalling URL
# that --send passes to --signaling. The /health probe normalises it: curl
# cannot speak ws:// or wss://, and /health is at the root, not under /ws.
#
# Output: one JSON object per line on stdout, and appended to
# $LUCIOLA_FIELD_LOG (default: field-records.jsonl in the repo root).
#
# Everything printed here is metadata the operator already has. Secrets (seed,
# PSK) are passed on the command line to the CLI but never written to the record.
set -euo pipefail

cd "$(dirname "$0")/.."

# The signalling URL and the health URL are different things. curl has no
# ws:// or wss:// support at all, and /health is served at the root while the
# WebSocket lives at /ws. Feeding --worker straight to curl used to record
# {"error":"unreachable"} for a perfectly healthy deployed Worker whenever an
# operator used the wss:// form that --send requires.
health_url() {
  local url="$1" scheme rest authority
  case "$url" in
    *://*) scheme="${url%%://*}"; rest="${url#*://}" ;;
    *) echo "worker URL needs a scheme (https:// or wss://): $url" >&2; return 1 ;;
  esac
  authority="${rest%%/*}"          # drop /ws and anything after it
  [ -n "$authority" ] || { echo "empty worker host: $url" >&2; return 1; }
  case "$scheme" in
    wss) scheme=https ;;
    ws) scheme=http ;;
    https|http) ;;
    *) echo "unsupported worker scheme: $scheme" >&2; return 1 ;;
  esac
  printf '%s://%s/health\n' "$scheme" "$authority"
}

# Offline reverse self-test: no network, no CLI build, no field log. Run this
# before a field session so a URL-normalisation regression cannot masquerade
# as "the Worker is down" in the matrix.
run_self_test() {
  local failed=0
  expect() {
    local want="$1" input="$2" got
    got=$(health_url "$input") || { echo "FAIL: $input was rejected" >&2; failed=1; return; }
    if [ "$got" != "$want" ]; then
      echo "FAIL: health_url($input) = $got; expected $want" >&2
      failed=1
    else
      echo "ok: $input -> $got"
    fi
  }
  expect 'https://host.example/health' 'wss://host.example/ws'
  expect 'https://host.example/health' 'wss://host.example/ws/'
  expect 'https://host.example/health' 'https://host.example'
  expect 'https://host.example/health' 'https://host.example/'
  expect 'http://127.0.0.1:8787/health' 'ws://127.0.0.1:8787/ws'
  expect 'http://127.0.0.1:8787/health' 'http://127.0.0.1:8787'
  if health_url 'socks5://host.example/ws' >/dev/null 2>&1; then
    echo 'FAIL: unsupported scheme was accepted' >&2; failed=1
  else
    echo 'ok: unsupported scheme rejected'
  fi
  if health_url 'host.example' >/dev/null 2>&1; then
    echo 'FAIL: schemeless URL was accepted' >&2; failed=1
  else
    echo 'ok: schemeless URL rejected'
  fi
  return "$failed"
}

LABEL=""
WORKER=""
SEND_FILE=""
PEER_SEED=""
PIN=""
ROOM=""
PSK=""
SEED="${LUCIOLA_SEED:-}"
OUT="${LUCIOLA_FIELD_LOG:-field-records.jsonl}"
TIMEOUT_SECS=8
PROGRESSIVE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --label) LABEL="$2"; shift 2 ;;
    --worker) WORKER="$2"; shift 2 ;;
    --send) SEND_FILE="$2"; shift 2 ;;
    --peer-seed) PEER_SEED="$2"; shift 2 ;;
    --pin) PIN="$2"; shift 2 ;;
    --room) ROOM="$2"; shift 2 ;;
    --psk) PSK="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --timeout-secs) TIMEOUT_SECS="$2"; shift 2 ;;
    --progressive) PROGRESSIVE=1; shift ;;
    --self-test) run_self_test || exit 1; exit 0 ;;
    -h|--help) awk 'NR == 1 {next} /^set -euo pipefail$/ {exit} {print}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$LABEL" ] || { echo "--label is required (e.g. home-wifi, 4g-cgnat)" >&2; exit 2; }

# Build the CLI once; a debug binary is fine here (this measures the network,
# not the engine).
echo "==> building luciola-cli" >&2
cargo build -q -p luciola-cli
CLI="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/luciola-cli"
[ -x "$CLI" ] || { echo "expected the CLI at $CLI (cargo installs it as luciola-cli)" >&2; exit 1; }

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

# --- environment ------------------------------------------------------------

HOST=$(hostname -s 2>/dev/null || echo unknown)
OS=$(uname -srm | tr ' ' '_')

# The interface carrying the default route: that is the one a field run is
# actually testing. Absent on some hosts, which is itself worth recording.
IFACE=$(route -n get default 2>/dev/null | sed -n 's/.*interface: //p' || true)
if [ -z "$IFACE" ] && command -v ip >/dev/null; then
  IFACE=$(ip route show default 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)
fi

# --- NAT probe --------------------------------------------------------------

echo "==> probing RFC 5780 behaviour (label=$LABEL)" >&2
PROBE=$("$CLI" stun --probe-nat --json --timeout-secs "$TIMEOUT_SECS" 2>/dev/null) || {
  PROBE='{"error":"nat probe failed"}'
}

# --- signalling Worker ------------------------------------------------------

WORKER_JSON="null"
if [ -n "$WORKER" ]; then
  HEALTH_URL=$(health_url "$WORKER") || exit 1
  echo "==> checking $HEALTH_URL" >&2
  WORKER_JSON=$(curl -fsS --max-time 10 "$HEALTH_URL" 2>/dev/null || echo '{"error":"unreachable"}')
fi

# --- optional real transfer -------------------------------------------------

TRANSFER_JSON="null"
if [ -n "$SEND_FILE" ]; then
  [ -f "$SEND_FILE" ] || { echo "no such file: $SEND_FILE" >&2; exit 1; }
  [ -n "$PIN" ] || { echo "--send needs --pin" >&2; exit 1; }
  [ -n "$ROOM" ] || { echo "--send needs --room" >&2; exit 1; }
  [ -n "$PSK" ] || { echo "--send needs --psk" >&2; exit 1; }
  [ -n "$SEED" ] || { echo "--send needs --seed (or LUCIOLA_SEED)" >&2; exit 1; }
  [ -n "$WORKER" ] || { echo "--send needs --worker (the wss:// endpoint)" >&2; exit 1; }
  # --peer-seed is optional. It used to be required but ignored, which is worse
  # than absent: the operator thought the peer identity had been checked. Now
  # it derives the peer public key and fails early on a pin mismatch instead of
  # letting the handshake fail opaquely halfway through a field session.
  if [ -n "$PEER_SEED" ]; then
    if ! DERIVED_PIN=$("$CLI" transfer pin --seed "$PEER_SEED" \
        | sed -n 's/^public_key=//p'); then
      echo "could not derive a pin from --peer-seed" >&2
      exit 1
    fi
    [ -n "$DERIVED_PIN" ] || { echo "could not derive a pin from --peer-seed" >&2; exit 1; }
    [ "$DERIVED_PIN" = "$PIN" ] || {
      echo "--pin does not match the public key derived from --peer-seed" >&2
      exit 1
    }
  fi
  echo "==> WAN transfer of $SEND_FILE" >&2
  EXTRA=()
  if [ "$PROGRESSIVE" = "1" ]; then
    EXTRA+=(--progressive)
  fi
  START=$(date +%s)
  if "$CLI" transfer send \
      --file "$SEND_FILE" \
      --seed "$SEED" \
      --pin-peer "$PIN" \
      --room "$ROOM" \
      --signaling "$WORKER" \
      --psk "$PSK" \
      ${EXTRA[@]+"${EXTRA[@]}"} >/dev/null 2>&1; then
    RESULT='"ok"'
  else
    RESULT='"failed"'
  fi
  ELAPSED=$(( $(date +%s) - START ))
  TRANSFER_JSON=$(printf '{"result":%s,"bytes":%s,"elapsed_s":%s}' \
    "$RESULT" "$(wc -c < "$SEND_FILE" | tr -d ' ')" "$ELAPSED")
fi

# --- record -----------------------------------------------------------------

RECORD=$(python3 - "$LABEL" "$HOST" "$OS" "$IFACE" "$PROBE" "$WORKER_JSON" "$TRANSFER_JSON" <<'PY'
import datetime, json, os, sys

label, host, osname, iface, probe, worker, transfer = sys.argv[1:8]

def load(raw, what):
    try:
        return json.loads(raw)
    except Exception:
        return {"error": f"{what} was not valid JSON"}

record = {
    "schema": "luciola.field-record/1",
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "label": label,
    "host": host,
    "os": osname,
    "interface": iface or None,
    "nat": load(probe, "nat probe"),
    "worker": load(worker, "worker health"),
    "transfer": load(transfer, "transfer"),
    "notes": os.environ.get("LUCIOLA_FIELD_NOTES", ""),
}
print(json.dumps(record, ensure_ascii=False))
PY
)

# One line per run: stdout for a human, the log for the matrix.
printf '%s\n' "$RECORD" | tee -a "$OUT"
echo "==> appended to $OUT" >&2
