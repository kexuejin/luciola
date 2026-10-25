#!/usr/bin/env bash
# Publish luciola (KMP) to Maven Central via the Central Portal API.
# Credentials live OUTSIDE the repo: ~/.luciola/central.env and
# ~/.luciola/signing-key.asc (see scripts/publish-maven-local.sh for the
# mavenLocal variant).
set -euo pipefail
cd "$(dirname "$0")/.."

source "$HOME/.luciola/central.env"
: "${CENTRAL_USER:?set CENTRAL_USER}"; : "${CENTRAL_TOKEN:?set CENTRAL_TOKEN}"
[ -f "$HOME/.luciola/signing-key.asc" ] || { echo "missing ~/.luciola/signing-key.asc" >&2; exit 1; }

echo "==> [1/4] Signed publish to staging dir..."
ESC_KEY=$(awk '{printf "%s\\n", $0}' "$HOME/.luciola/signing-key.asc")
(cd examples/android-demo && ./gradlew :luciola:publishAllPublicationsToLocalRepository \
  --no-daemon -q -PsigningKey="$ESC_KEY" -PsigningPassword="")

STAGE=bindings/luciola-kmp/build/repoLocal
BUNDLE=/tmp/luciola-central-bundle.zip
echo "==> [2/4] Bundling $(find "$STAGE" -type f | wc -l | tr -d ' ') files..."
rm -f "$BUNDLE"
(cd "$STAGE" && zip -qr "$BUNDLE" io)

echo "==> [3/4] Uploading to Central Portal..."
AUTH=$(printf '%s:%s' "$CENTRAL_USER" "$CENTRAL_TOKEN" | base64)
HTTP=$(curl -s -o /tmp/central-upload-resp.txt -w '%{http_code}' \
  -X POST "https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC" \
  -H "Authorization: Bearer $AUTH" -F "bundle=@$BUNDLE")
echo "HTTP $HTTP"; cat /tmp/central-upload-resp.txt; echo
[ "$HTTP" = "201" ] || { echo "upload failed" >&2; exit 1; }
ID=$(tr -d '"' </tmp/central-upload-resp.txt)

echo "==> [4/4] Polling deployment $ID..."
for i in $(seq 1 60); do
  sleep 5
  STATUS=$(curl -s -H "Authorization: Bearer $AUTH" \
    "https://central.sonatype.com/api/v1/publisher/status?id=$ID")
  STATE=$(echo "$STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("deploymentState","?"))' 2>/dev/null || echo "?")
  echo "  [$((i*5))s] $STATE"
  case "$STATE" in
    PUBLISHED) echo "PUBLISHED ✅"; exit 0 ;;
    FAILED) echo "$STATUS" | python3 -m json.tool 2>/dev/null | head -40; exit 1 ;;
  esac
done
echo "timed out waiting; check the portal UI" >&2; exit 1
