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
# **AES-GCM 硬件加速**：aes crate 在 aarch64 上要显式打开 aes_armv8 cfg 才会用
# ARMv8 的 AES 指令；而它的「运行时自动检测」只覆盖 Linux/macOS —— Android 是
# target_os=android，落在「其他平台」那一档，必须再用 RUSTFLAGS 把 aes 目标特性
# 打开。不开的后果不是报错而是**静默变慢**：真机实测投屏每帧发送耗时 24ms，
# 而明文通路只有 2ms —— 那 22ms 基本就是纯软 AES 的代价（49KiB/帧）。
RUSTFLAGS="${RUSTFLAGS:-} --cfg aes_armv8 -C target-feature=+aes,+sha2" \
  cargo ndk -t arm64-v8a -o "$KMP/src/androidMain/jniLibs" build --release -p luciola-uniffi
test -f "$SO_DIR/libluciola_uniffi.so" || { echo ".so missing after build" >&2; exit 1; }

PUBLISH_TASK=":luciola:publishToMavenLocal"
EXTRA_ARGS=()
# `set -u` above means an unset CENTRAL_URL aborted the publish before it even
# started; every optional override has to be defaulted, not merely tested.
if [ -n "${CENTRAL_URL:-}" ]; then
  PUBLISH_TASK=":luciola:publishAllPublicationsToCentralRepository"
  EXTRA_ARGS=(-PcentralUrl="$CENTRAL_URL" -PcentralUser="${CENTRAL_USER:-}" -PcentralToken="${CENTRAL_TOKEN:-}")
fi
echo "==> [2/3] Publishing luciola ($PUBLISH_TASK)..."
# bash 3.2 (the one macOS ships) treats "${EMPTY[@]}" as unbound under set -u;
# the +form expands to nothing when the array is empty.
(cd examples/android-demo && ./gradlew "$PUBLISH_TASK" --no-daemon -q ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})

echo "==> [3/3] Verifying the published AAR embeds the native lib..."
# The artifact is luciola-android-<version>.aar; the previous glob
# (luciola-kmp-android-*.aar) never matched anything, so this check silently
# "failed open" and reported success without verifying.
VERSION=$(grep -m1 '^version = ' "$KMP/build.gradle.kts" | sed 's/.*"\(.*\)".*/\1/')
AAR="$HOME/.m2/repository/io/github/kexuejin/luciola-android/$VERSION/luciola-android-$VERSION.aar"
if [ ! -f "$AAR" ]; then
  echo "Publish produced no artifact at $AAR" >&2
  exit 1
fi
if ! unzip -l "$AAR" | grep -q "jni/arm64-v8a/libluciola_uniffi.so"; then
  echo "Published AAR does NOT contain the native lib: $AAR" >&2
  exit 1
fi
echo "OK: $AAR contains jni/arm64-v8a/libluciola_uniffi.so"
echo "Done (mavenLocal). Consumers: implementation(\"io.github.kexuejin:luciola-android:$VERSION\")"
echo "Remote (Central) when ready: set CENTRAL_URL/CENTRAL_USER/CENTRAL_TOKEN env + GPG"
echo "  signingKey/signingPassword gradle properties, then rerun this script."
