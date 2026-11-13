#!/usr/bin/env bash
# Deploy the Luciola rendezvous Worker to Cloudflare.
#
# Staging is the default; production requires --production explicitly. The
# script never pushes, tags or publishes anything else.
#
# "It deployed" and "it is answering" are treated as two separate, observed
# facts: after `wrangler deploy` the script asks the deployment's own /health
# endpoint which epoch it serves, and prints it. A deploy that succeeds but
# whose Worker is not answering is a failure here, not a success.
#
# Usage:
#   scripts/deploy-signaling.sh                     # deploy staging
#   scripts/deploy-signaling.sh --production        # deploy production
#   scripts/deploy-signaling.sh --check URL         # only verify a deployment
#
# Requires: node + npx, and wrangler authenticated either with
# `wrangler login` or CLOUDFLARE_API_TOKEN in the environment. This script
# never reads, writes or prints a token.
set -euo pipefail

cd "$(dirname "$0")/.."
WORKER_DIR="deploy/cloudflare-signaling"

ENV_NAME="staging"
CHECK_ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --production) ENV_NAME="production"; shift ;;
    --staging) ENV_NAME="staging"; shift ;;
    --check)
      [ $# -ge 2 ] || { echo "--check needs a URL" >&2; exit 2; }
      CHECK_ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -d "$WORKER_DIR" ] || { echo "missing $WORKER_DIR" >&2; exit 1; }
command -v node >/dev/null || { echo "node is required" >&2; exit 1; }

# --- health check -----------------------------------------------------------

verify_health() {
  local base="${1%/}"
  local body
  body=$(curl -fsS --max-time 10 "$base/health") || {
    echo "FAIL: $base/health did not answer" >&2
    return 1
  }
  case "$body" in
    *'"ok":true'*) ;;
    *) echo "FAIL: unexpected /health payload: $body" >&2; return 1 ;;
  esac
  # Report the epoch the Worker is serving: it is what clients align to, and a
  # Worker whose clock is wrong breaks rendezvous even when the code is right.
  local epoch
  epoch=$(printf '%s' "$body" | sed -n 's/.*"epoch":\([0-9]*\).*/\1/p')
  echo "OK: $base/health  epoch=$epoch"
  echo "    $body"
}

if [ -n "$CHECK_ONLY" ]; then
  verify_health "$CHECK_ONLY"
  exit 0
fi

# --- preflight --------------------------------------------------------------

echo "==> [1/4] Worker unit tests"
( cd "$WORKER_DIR" && node --test )

echo "==> [2/4] wrangler authentication"
if ! ( cd "$WORKER_DIR" && npx --no-install wrangler whoami >/dev/null 2>&1 ); then
  echo "FAIL: wrangler is not authenticated." >&2
  echo "      Run 'npx wrangler login' in $WORKER_DIR, or export" >&2
  echo "      CLOUDFLARE_API_TOKEN (and CLOUDFLARE_ACCOUNT_ID)." >&2
  exit 1
fi
echo "OK: wrangler is authenticated"

# --- deploy -----------------------------------------------------------------

if [ "$ENV_NAME" = "production" ]; then
  echo "==> [3/4] Deploying PRODUCTION (luciola-signaling)"
  DEPLOY_ARGS=()
else
  echo "==> [3/4] Deploying staging (luciola-signaling-staging)"
  DEPLOY_ARGS=(--env staging)
fi
( cd "$WORKER_DIR" && npx --no-install wrangler deploy "${DEPLOY_ARGS[@]}" )

# --- verify -----------------------------------------------------------------

echo "==> [4/4] Verifying the deployment"
if [ -n "${LUCIOLA_WAN_URL:-}" ]; then
  verify_health "$LUCIOLA_WAN_URL"
else
  echo "SKIP: set LUCIOLA_WAN_URL to the deployed https:// URL to verify /health."
  echo "      Example: LUCIOLA_WAN_URL=https://luciola-signaling-staging.<acct>.workers.dev \\"
  echo "               scripts/deploy-signaling.sh --check \$LUCIOLA_WAN_URL"
  echo "      The URL is the 'Deployed ... triggers' line above; it is not parsed"
  echo "      from wrangler's output because that format is not stable."
fi

cat <<'EOF'

Next steps that this script does not do (deliberately):
  * put the URL into a client: WanConfig.signaling_endpoint must be wss://,
    plain ws:// is accepted for loopback only;
  * a real NAT/CGNAT field run: scripts/field-nat-matrix.sh (separate step);
  * public release: the registries stay at the last released version until
    sibling products validate the local package.
EOF
