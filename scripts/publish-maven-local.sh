#!/usr/bin/env bash
# Build the Rust core for Android and publish luciola-kmp to the local Maven
# repository (~/.m2). Native binaries are NEVER committed — this script is the
# single source of truth for producing them.
set -euo pipefail
cd "$(dirname "$0")/.."

KMP=bindings/luciola-kmp
SO_DIR="$KMP/src/androidMain/jniLibs/arm64-v8a"

echo "==> [1/3] Building Rust core for Android (arm64-v8a, release)..."
if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "cargo-ndk not found. Install with: cargo install cargo-ndk" >&2
  exit 1
fi
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
cargo ndk -t arm64-v8a -o "$KMP/src/androidMain/jniLibs" build --release -p luciola-uniffi
test -f "$SO_DIR/libluciola_uniffi.so" || { echo ".so missing after build" >&2; exit 1; }

echo "==> [2/3] Publishing luciola-kmp to mavenLocal..."
(cd examples/android-demo && ./gradlew :luciola:publishToMavenLocal --no-daemon -q)

echo "==> [3/3] Verifying the published AAR embeds the native lib..."
AAR=$(ls -t ~/.m2/repository/io/github/kexuejin/luciola-android/*/luciola-kmp-android-*.aar | head -1)
if ! unzip -l "$AAR" | grep -q "jni/arm64-v8a/libluciola_uniffi.so"; then
  echo "Published AAR does NOT contain the native lib: $AAR" >&2
  exit 1
fi
echo "OK: $AAR contains jni/arm64-v8a/libluciola_uniffi.so"
echo "Done. Consumers: implementation(\"io.github.kexuejin:luciola:<version>\") + mavenLocal()"
