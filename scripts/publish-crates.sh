#!/usr/bin/env bash
# Publish the luciola crates to crates.io in dependency order.
# Prereq: cargo login (token from https://crates.io/settings/tokens)
set -euo pipefail
cd "$(dirname "$0")/.."

# Dependency order. A new workspace crate must be added HERE as well, or it
# silently never reaches crates.io (luciola-transfer and luciola-tunnel were missing
# from this list and shipped unpublished).
#
# luciola-transfer MUST precede luciola: luciola carries it as an optional
# dependency with an exact version req, and `cargo publish` resolves optional
# deps against the registry — a same-version transfer must already exist there.
# (transfer's own dep on luciola is a dev-only path dep, stripped on publish,
# so the cycle is publishable in exactly this direction. The previous order
# made every fresh version release fail at `cargo publish -p luciola`, which
# is why crates.io sat at 0.3.1 while the tree moved on.)
for crate in luciola-ip luciola-proto luciola-net luciola-transfer luciola luciola-tunnel luciola-cli; do
  echo "==> publishing $crate"
  cargo publish -p "$crate" --allow-dirty
  # let the registry index propagate between dependent publishes
  sleep 25
done
echo "Done. https://crates.io/crates/luciola"
