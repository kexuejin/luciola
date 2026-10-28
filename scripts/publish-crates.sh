#!/usr/bin/env bash
# Publish the luciola crates to crates.io in dependency order.
# Prereq: cargo login (token from https://crates.io/settings/tokens)
set -euo pipefail
cd "$(dirname "$0")/.."

# Dependency order. A new workspace crate must be added HERE as well, or it
# silently never reaches crates.io (luciola-transfer and luciola-tunnel were missing
# from this list and shipped unpublished).
for crate in luciola-ip luciola-proto luciola-net luciola luciola-transfer luciola-tunnel luciola-cli; do
  echo "==> publishing $crate"
  cargo publish -p "$crate" --allow-dirty
  # let the registry index propagate between dependent publishes
  sleep 25
done
echo "Done. https://crates.io/crates/luciola"
