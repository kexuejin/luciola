#!/usr/bin/env bash
# 生成 Kotlin Multiplatform 的 uniffi 绑定（含 nativeMain / cinterop 头）。
#
# 为什么需要这个脚本（2026-10-27 实测）：
#   uniffi 0.29.x 自带的 uniffi-bindgen --language kotlin 只产 JVM/JNA 绑定
#   （生成的 .kt 里是 import com.sun.jna.* 与 java.nio.ByteBuffer；
#   grep kotlinx.cinterop 命中 0）。上游默认工具链产不出 iOS 能用的 Kotlin。
#
#   用 gobley 的 KMP 后端可以产出五个源集：
#     commonMain/            公共 API
#     jvmMain/               JVM 实现
#     androidMain/           Android 实现
#     nativeMain/            Kotlin/Native 实现（cinterop 调 C FFI）
#     nativeInterop/.../h    cinterop 头
#
# 版本必须对齐：
#   gobley-uniffi-bindgen 0.3.7 精确依赖 uniffi_bindgen = 0.29.4，
#   所以 bindings/luciola-uniffi/Cargo.toml 里 uniffi 被 pin 成 =0.29.4。
#   差一个小版本就可能读到不兼容的元数据。
#
# 配置是扁平的（踩过）：
#   gobley 的 new_config 直接对根 toml 反序列化，不能写成 uniffi 惯例的
#   [bindings.kotlin] 段。写错的表现是「只生成 commonMain，其余源集静默缺失」。
#
# 用法：./scripts/generate-kmp-bindings.sh [输出目录，默认 build/kmp-bindings]
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-build/kmp-bindings}"
# 目标目录不一定是 ./target：共享的 [build] target-dir 会把它重定向到别处，
# 所以问 cargo 本人；CARGO_TARGET_DIR / LUCIOLA_TARGET_DIR 可覆盖。
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
  CARGO_TARGET_DIR="${LUCIOLA_TARGET_DIR:-}"
fi
if [ -z "$CARGO_TARGET_DIR" ]; then
  CARGO_TARGET_DIR=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
fi
if [ -z "$CARGO_TARGET_DIR" ]; then
  CARGO_TARGET_DIR="$(pwd)/target"
fi
export CARGO_TARGET_DIR
CDYLIB="$CARGO_TARGET_DIR/release/libluciola_uniffi.dylib"
CONFIG="bindings/luciola-kmp/gobley-uniffi.toml"

if ! command -v gobley-uniffi-bindgen >/dev/null 2>&1; then
  echo "gobley-uniffi-bindgen not found. Install with:" >&2
  echo "  cargo install --bin gobley-uniffi-bindgen gobley-uniffi-bindgen@0.3.7" >&2
  exit 1
fi

echo "==> [1/2] Building Rust cdylib (release)..."
CARGO_TARGET_DIR="$CARGO_TARGET_DIR" cargo build --release -p luciola-uniffi
test -f "$CDYLIB" || { echo "cdylib missing: $CDYLIB" >&2; exit 1; }

echo "==> [2/2] Generating Kotlin Multiplatform bindings -> $OUT"
rm -rf "$OUT"
gobley-uniffi-bindgen --library --crate luciola_uniffi \
  --config "$CONFIG" \
  --out-dir "$OUT" \
  "$CDYLIB"

# 判据：nativeMain 必须真的生成、且用 cinterop —— 否则 iOS 还是用不上。
NATIVE="$OUT/nativeMain/kotlin/uniffi/luciola_uniffi/luciola_uniffi.native.kt"
COMMON="$OUT/commonMain/kotlin/uniffi/luciola_uniffi/luciola_uniffi.common.kt"
HEADER="$OUT/nativeInterop/cinterop/headers/luciola_uniffi/luciola_uniffi.h"
for f in "$COMMON" "$NATIVE" "$HEADER"; do
  test -f "$f" || { echo "missing generated file: $f" >&2; exit 1; }
done
grep -q 'kotlinx.cinterop' "$NATIVE" \
  || { echo "nativeMain does not use cinterop — iOS would not work" >&2; exit 1; }

echo "OK: $(find "$OUT" -type f | wc -l | tr -d ' ') files under $OUT"
