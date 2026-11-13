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
#   scripts/field-nat-matrix.sh --label home-wifi
#   scripts/field-nat-matrix.sh --label 4g-cgnat --worker https://…workers.dev
#   scripts/field-nat-matrix.sh --label hotel-wifi \
#       --worker https://…workers.dev \
#       --send /tmp/probe.bin --peer-seed "$PEER_SEED" --pin "$PEER_PIN" \
#       --room "$ROOM" --psk "$PSK"
#
# Output: one JSON object per line on stdout, and appended to
# $LUCIOLA_FIELD_LOG (default: field-records.jsonl in the repo root).
#
# Everything printed here is metadata the operator already has. Secrets (seed,
# PSK) are passed on the command line to the CLI but never written to the record.
set -euo pipefail

cd "$(dirname "$0")/.."

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
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
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
  echo "==> checking $WORKER/health" >&2
  WORKER_JSON=$(curl -fsS --max-time 10 "${WORKER%/}/health" 2>/dev/null || echo '{"error":"unreachable"}')
fi

# --- optional real transfer -------------------------------------------------

TRANSFER_JSON="null"
if [ -n "$SEND_FILE" ]; then
  [ -f "$SEND_FILE" ] || { echo "no such file: $SEND_FILE" >&2; exit 1; }
  [ -n "$PEER_SEED" ] || { echo "--send needs --peer-seed" >&2; exit 1; }
  [ -n "$PIN" ] || { echo "--send needs --pin" >&2; exit 1; }
  [ -n "$ROOM" ] || { echo "--send needs --room" >&2; exit 1; }
  [ -n "$PSK" ] || { echo "--send needs --psk" >&2; exit 1; }
  [ -n "$SEED" ] || { echo "--send needs --seed (or LUCIOLA_SEED)" >&2; exit 1; }
  [ -n "$WORKER" ] || { echo "--send needs --worker (the wss:// endpoint)" >&2; exit 1; }
  echo "==> WAN transfer of $SEND_FILE" >&2
  EXTRA=()
  [ "$PROGRESSIVE" = "1" ] && EXTRA+=(--progressive)
  START=$(date +%s)
  if "$CLI" transfer send \
      --file "$SEND_FILE" \
      --seed "$SEED" \
      --pin-peer "$PIN" \
      --room "$ROOM" \
      --signaling "$WORKER" \
      --psk "$PSK" \
      "${EXTRA[@]}" >/dev/null 2>&1; then
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
