#!/usr/bin/env bash
# Publish the luciola crates to crates.io in dependency order.
# Prereq: cargo login (token from https://crates.io/settings/tokens)
set -euo pipefail
cd "$(dirname "$0")/.."

for crate in luciola-ip luciola-proto luciola-net luciola luciola-cli; do
  echo "==> publishing $crate"
  cargo publish -p "$crate" --allow-dirty
  # let the registry index propagate between dependent publishes
  sleep 25
done
echo "Done. https://crates.io/crates/luciola"
