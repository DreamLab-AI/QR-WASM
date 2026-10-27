#!/usr/bin/env bash
# Builds every size-ladder rung into fixtures/ and records the toolchain.
# Stable rungs build offline; nightly rungs need network for build-std's own deps.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/fixtures"; mkdir -p "$out"; cd "$here"
NIGHTLY="${NIGHTLY:-$(dirname "$(which -a rustc | while read -r r; do "$r" --version | grep -q nightly && echo "$r" && break; done)")}"
WO=(wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals
    --enable-reference-types --enable-multivalue --strip-debug --strip-producers)
# clang 21 rejects libsecp256k1's implicit memmove under the bundled wasm sysroot; compiler_builtins provides it.
export CFLAGS_wasm32_unknown_unknown="-Wno-error=implicit-function-declaration"
artifact=qrwasm_minimal_pod.wasm
stable() { local name=$1; shift
  cargo build --quiet --offline --release --target wasm32-unknown-unknown "$@"
  "${WO[@]}" "target/wasm32-unknown-unknown/release/$artifact" -o "$out/$name.wasm"; }
nightly() { local name=$1; shift
  RUSTC="$NIGHTLY/rustc" RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" "$NIGHTLY/cargo" build --quiet --release \
    --target wasm32-unknown-unknown --target-dir target/nightly -Zbuild-std=std,panic_abort "$@"
  "${WO[@]}" "target/nightly/wasm32-unknown-unknown/release/$artifact" -o "$out/$name.wasm"; }
stable  A1-pod-k256
stable  A2-pod-k256-bump            --features bump
stable  A3-pod-secp-bump            --no-default-features --features libsecp256k1,pod,bump
stable  B2-verify-k256-bump         --no-default-features --features k256,bump
stable  B4-verify-secp-bump         --no-default-features --features libsecp256k1,bump
nightly C1-verify-k256-bump-ia      --no-default-features --features k256,bump
nightly C2-pod-k256-bump-ia         --features bump
{ rustc --version; "$NIGHTLY/rustc" --version; wasm-opt --version; echo "nightly RUSTFLAGS: -Zunstable-options -Cpanic=immediate-abort"; } > "$out/TOOLCHAIN"
ls -l "$out"
