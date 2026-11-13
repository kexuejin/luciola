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

# Constrained networks: the Gradle JVM does not inherit HTTPS_PROXY by itself,
# and dl.google.com can terminate the TLS handshake while resolving the lint
# tool that `publishToMavenLocal` pulls in. Every escape below is opt-in or
# environment-driven — no machine-specific value is hardcoded (AGENTS.md §5).
#   LUCIOLA_USE_ALIYUN_MIRRORS=1     add the Aliyun fallback repositories
#   LUCIOLA_SKIP_LINT_ANNOTATIONS=1  skip the lint annotation extractor when
#                                    the lint tool cannot be resolved at all
#   LUCIOLA_NO_GRADLE_PROXY=1        do not forward HTTPS_PROXY to Gradle
if [ "${LUCIOLA_USE_ALIYUN_MIRRORS:-}" = "1" ]; then
  EXTRA_ARGS+=(-PluciolaUseAliyunMirrors=true)
fi
if [ "${LUCIOLA_SKIP_LINT_ANNOTATIONS:-}" = "1" ]; then
  EXTRA_ARGS+=(-x :luciola:extractAndroidMainAnnotations)
fi
PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
PROXY="${PROXY%/}"
case "$PROXY" in
  http://*)
    if [ -z "${LUCIOLA_NO_GRADLE_PROXY:-}" ]; then
      HOSTPORT="${PROXY#http://}"
      PROXY_HOST="${HOSTPORT%%:*}"
      PROXY_PORT="${HOSTPORT##*:}"
      case "$PROXY_PORT" in
        ''|*[!0-9]*) echo "Ignoring malformed HTTPS_PROXY port: $PROXY" >&2 ;;
        *)
          EXTRA_ARGS+=(-Dhttps.proxyHost="$PROXY_HOST" -Dhttps.proxyPort="$PROXY_PORT"
                       -Dhttp.proxyHost="$PROXY_HOST" -Dhttp.proxyPort="$PROXY_PORT")
          ;;
      esac
    fi
    ;;
esac
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
# A version string alone does not prove the artifact carries the engine that was
# just built (AGENTS.md §3). Compare the packaged .so with the jniLibs copy.
TMP_SO=$(mktemp)
trap 'rm -f "$TMP_SO"' EXIT
unzip -p "$AAR" jni/arm64-v8a/libluciola_uniffi.so > "$TMP_SO"
if command -v shasum >/dev/null 2>&1; then
  AAR_SHA=$(shasum -a 256 "$TMP_SO" | awk '{print $1}')
  SO_SHA=$(shasum -a 256 "$SO_DIR/libluciola_uniffi.so" | awk '{print $1}')
else
  AAR_SHA=$(sha256sum "$TMP_SO" | awk '{print $1}')
  SO_SHA=$(sha256sum "$SO_DIR/libluciola_uniffi.so" | awk '{print $1}')
fi
if [ "$AAR_SHA" != "$SO_SHA" ]; then
  echo "AAR .so does not match the freshly built jniLibs copy" >&2
  echo "  aar:     $AAR_SHA" >&2
  echo "  jniLibs: $SO_SHA" >&2
  exit 1
fi
echo "OK: $AAR contains jni/arm64-v8a/libluciola_uniffi.so (sha256 $SO_SHA)"
echo "Done (mavenLocal). Consumers: implementation(\"io.github.kexuejin:luciola-android:$VERSION\")"
echo "Remote (Central) when ready: set CENTRAL_URL/CENTRAL_USER/CENTRAL_TOKEN env + GPG"
echo "  signingKey/signingPassword gradle properties, then rerun this script."
