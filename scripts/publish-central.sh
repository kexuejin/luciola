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
rm -rf bindings/luciola-kmp/build/repoLocal   # only the new version may enter the bundle
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
# `GET /publisher/status?id=` answers HTTP 500 for **every** id, including ids
# that do not exist — so the original poll loop could only ever end in "timed
# out waiting", exit 1, even though the upload had been accepted and the release
# was already on its way. The deployment LIST endpoint does work, so read the
# state out of it and match on the id we were handed.
for i in $(seq 1 120); do
  sleep 5
  STATE=$(curl -s -H "Authorization: Bearer $AUTH" \
    "https://central.sonatype.com/api/v1/publisher/deployments" \
    | python3 -c '
import json, sys
want = sys.argv[1]
for d in json.load(sys.stdin).get("deployments", []):
    if d.get("deploymentId") == want:
        print(d.get("deploymentState", "?"))
        break
else:
    print("?")
' "$ID" 2>/dev/null || echo "?")
  echo "  [$((i*5))s] $STATE"
  case "$STATE" in
    PUBLISHED) echo "PUBLISHED"; exit 0 ;;
    FAILED) echo "deployment $ID FAILED — inspect https://central.sonatype.com/publishing/deployments" >&2; exit 1 ;;
  esac
done
echo "timed out after 600s (last state: $STATE)." >&2
echo "The upload WAS accepted (id $ID); repo1 can lag the portal by several minutes." >&2
echo "Check https://central.sonatype.com/publishing/deployments before retrying — a" >&2
echo "retry of an already-accepted version is rejected as a duplicate." >&2
exit 1
