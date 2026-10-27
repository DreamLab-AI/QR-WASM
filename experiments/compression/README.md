# Compression, capacity and envelope gate

`bench.mjs` measures the committed WebAssembly fixtures against [envelope v1](../../docs/spec/qr-object-v1.md) and exits non-zero if any of its 71 checks fails. The spec's acceptance criteria (§9) are checks here.

```
npm ci            # qrcode 1.5.4 is a runtime dependency because this estate's npm omits dev deps
node bench.mjs    # add --write to refresh results.json
```

- `fixtures/`: the Rust-built modules, committed so a toolchain bump shows up as a diff. Rebuild them with `./build-fixtures.sh`; `fixtures/TOOLCHAIN` records the versions.
- `rust-module/`: the source of those fixtures (an RFC 9285 base45 codec, plus a `fmt` feature for a larger build).
- `results.json`: the measured capacities, compression ratios and frame counts that the docs quote.

What it checks: QR capacity at level L against the ISO table, base45 (RFC 9285) and radix-43 codecs, envelope round-trips, decoder rejection rules (bombs, tampering, truncation), framing, and frame-count criteria for each transport.
