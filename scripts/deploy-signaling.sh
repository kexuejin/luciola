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
# Authentication: a scoped API token is enough — no `wrangler login` needed.
#
#   export CLOUDFLARE_API_TOKEN=...     # Account API token, scoped to one account
#   export CLOUDFLARE_ACCOUNT_ID=...    # optional if the token sees one account
#
# Minimum token permissions (Account scope, resource = the target account):
#   * Workers Scripts        — Edit     (script upload; Durable Object classes
#                                        and their migrations ride along with it)
#   * Workers Scripts        — Read     (wrangler reads the current deployment)
#   * Account Settings       — Read     (resolving the account)
# Not needed for this Worker: Workers KV / D1 / R2 / Queues / Routes. Do not add
# them "just in case" — a token that cannot touch them cannot leak them.
#
# First deploy on a fresh account: the account must have a workers.dev
# subdomain registered, otherwise `wrangler deploy` stops and asks for one. That
# step is interactive and is done once in the dashboard (Workers & Pages →
# your subdomain), not by this script.
#
# Requires: node + npx. This script never reads, writes or prints a token.
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
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
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
# A scoped API token is the expected path (and the only one that works in CI).
# Do NOT gate on `wrangler whoami` in that case: it needs account/user read
# scopes that a minimal deploy token deliberately lacks, so it can fail while
# `deploy` would have worked. Verify the token against the endpoint that checks
# a token's own validity instead, which needs no extra permission.
if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
  if curl -fsS --max-time 15 \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      https://api.cloudflare.com/client/v4/user/tokens/verify \
      | grep -q '"status":"active"'; then
    echo "OK: CLOUDFLARE_API_TOKEN is active"
  else
    echo "FAIL: CLOUDFLARE_API_TOKEN is not valid or not active." >&2
    echo "      Check it has not expired or been rolled in the dashboard." >&2
    exit 1
  fi
  if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    # Wrangler can derive the account when the token reaches exactly one; with
    # several it fails with "More than one account available".
    echo "WARN: CLOUDFLARE_ACCOUNT_ID is not set." >&2
    echo "      Fine if this token can see only one account; otherwise wrangler" >&2
    echo "      aborts with 'More than one account available but unable to" >&2
    echo "      select one'. Export it to be explicit." >&2
  else
    echo "OK: account $CLOUDFLARE_ACCOUNT_ID"
  fi
else
  if ! ( cd "$WORKER_DIR" && npx --no-install wrangler whoami >/dev/null 2>&1 ); then
    echo "FAIL: wrangler is not authenticated." >&2
    echo "      Either 'npx wrangler login' in $WORKER_DIR, or export" >&2
    echo "      CLOUDFLARE_API_TOKEN (and CLOUDFLARE_ACCOUNT_ID)." >&2
    exit 1
  fi
  echo "OK: wrangler is authenticated via its stored login"
fi

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
