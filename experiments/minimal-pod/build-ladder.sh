#!/usr/bin/env bash
# Builds every size-ladder rung into fixtures/ and records the toolchain.
# Stable rungs build offline; nightly rungs need network once for build-std.
# Rungs of the earlier serde_json design (A1–C2) are kept at commit 958d601.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/fixtures"; mkdir -p "$out"; cd "$here"
first_nightly() { which -a rustc | while read -r r; do "$r" --version | grep -q nightly && dirname "$r" && break; done; }
NIGHTLY="${NIGHTLY:-$(first_nightly)}"
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
    --target wasm32-unknown-unknown --target-dir target/nightly -Zbuild-std=core,alloc "$@"
  "${WO[@]}" "target/nightly/wasm32-unknown-unknown/release/$artifact" -o "$out/$name.wasm"; }
rm -f "$out"/*.wasm
stable  P1-pod-k256
stable  P2-pod-k256-bump            --features bump
nightly P3-pod-k256-bump-ia         --features bump
stable  P4-pod-secp-bump            --no-default-features --features libsecp256k1,pod,bump
stable  V1-verify-k256              --no-default-features --features k256
stable  V2-verify-k256-bump         --no-default-features --features k256,bump
nightly V3-verify-k256-bump-ia      --no-default-features --features k256,bump
stable  V4-verify-secp-bump         --no-default-features --features libsecp256k1,bump
{ rustc --version; "$NIGHTLY/rustc" --version; wasm-opt --version; echo "nightly: -Zbuild-std=core,alloc -Zunstable-options -Cpanic=immediate-abort"; } > "$out/TOOLCHAIN"
ls -l "$out"
