#!/usr/bin/env bash
# Rebuilds the committed Rust fixtures. The benchmark reads the committed files,
# so a toolchain bump shows up as a reviewable diff rather than a moving gate.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/fixtures"
mkdir -p "$out"
cd "$here/rust-module"
build() { cargo build --quiet --release --target wasm32-unknown-unknown "$@"; }
build
cp target/wasm32-unknown-unknown/release/qrwasm_bench_module.wasm "$out/base45-oz.wasm"
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-reference-types --enable-multivalue --strip-debug --strip-producers "$out/base45-oz.wasm" -o "$out/base45-oz-wasmopt.wasm"
build --features fmt
cp target/wasm32-unknown-unknown/release/qrwasm_bench_module.wasm "$out/base45-fmt-oz.wasm"
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-reference-types --enable-multivalue --strip-debug --strip-producers "$out/base45-fmt-oz.wasm" -o "$out/base45-fmt-oz-wasmopt.wasm"
{ rustc --version; wasm-opt --version; } > "$out/TOOLCHAIN"
ls -l "$out"
