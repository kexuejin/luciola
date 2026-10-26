#!/usr/bin/env bash
# Build LuciolaUniFFI.xcframework from the current crates/ HEAD.
#
# The xcframework is a build artifact (gitignored), so every consumer — the iOS
# app in my-app, and any demo — needs one command that reproduces it.
# Without this, "the desktop is fixed but iOS still runs the old engine" is
# invisible: the binary simply is not in the repository to diff.
#
# Two details that cost a debugging round:
#   - the module map must be named module.modulemap inside Headers/, otherwise
#     the generated Swift cannot see RustBuffer/ForeignBytes/RustCallStatus;
#   - the simulator slice is aarch64-apple-ios-sim (Apple Silicon), not an x86
#     slice; add -x86_64 variants only if you also need Intel simulators.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root
SWIFT_DIR="bindings/luciola-swift"
OUT="$SWIFT_DIR/LuciolaUniFFI.xcframework"
HDRS=$(mktemp -d)
trap 'rm -rf "$HDRS"' EXIT

echo "==> [1/3] Building luciola-uniffi for ios-arm64 and ios-arm64-simulator..."
cargo build --release -p luciola-uniffi --target aarch64-apple-ios
cargo build --release -p luciola-uniffi --target aarch64-apple-ios-sim

# Ask cargo where artifacts land: this workspace overrides CARGO_TARGET_DIR,
# so assuming ./target silently produced "missing libluciola_uniffi.a".
TARGET_DIR=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
DEV_LIB="$TARGET_DIR/aarch64-apple-ios/release/libluciola_uniffi.a"
SIM_LIB="$TARGET_DIR/aarch64-apple-ios-sim/release/libluciola_uniffi.a"
[ -f "$DEV_LIB" ] || { echo "missing $DEV_LIB" >&2; exit 1; }
[ -f "$SIM_LIB" ] || { echo "missing $SIM_LIB" >&2; exit 1; }

echo "==> [2/3] Assembling headers (module map must be module.modulemap)..."
cp "$SWIFT_DIR/luciola_uniffiFFI.h" "$HDRS/"
cp "$SWIFT_DIR/luciola_uniffiFFI.modulemap" "$HDRS/module.modulemap"

echo "==> [3/3] Creating $OUT ..."
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$DEV_LIB" -headers "$HDRS" \
  -library "$SIM_LIB" -headers "$HDRS" \
  -output "$OUT" >/dev/null

echo "OK: $OUT"
echo "Consumers link it statically (embed: false); regenerate the Swift bindings"
echo "separately when the FFI surface changes (uniffi-bindgen swift)."
