# Minimal did:nostr pod in WebAssembly

A size probe answering "how many QR codes does a minimal Nostr-owned Solid-style pod take in a browser?" The answer, and how it got there, is in [docs/findings.md](../../docs/findings.md) §1–§2.

- `src/lib.rs`: the pod as one pure function. It takes a request and the stored state, and returns a response and at most one write. It enforces LDP rules, NIP-98 auth and the owner check, and verifies BIP-340 with k256 (or libsecp256k1, for comparison). `no_std`.
- `shell.mjs`: the browser side. It parses the NIP-98 header natively and passes the fields; the module re-derives the NIP-01 serialisation and verifies over it, so shell tampering is rejected.
- `fixtures/`: every size-ladder rung, built by `./build-ladder.sh` (nightly rungs need network once for `build-std`).
- `vectors/`: the 19 BIP-340 vectors (bitcoin/bips `5aadddb`) and 26 signed NIP-98 / LDP cases. `nip98.json` is generated deterministically by `tests/vectors.rs`.

```
cargo test --offline        # vectors natively; WRITE_VECTORS=1 regenerates nip98.json
node test.mjs               # every rung through shell.mjs; --write refreshes results.json
```

In a browser, serve this directory over HTTP and run `(await import('/browser.mjs')).replay()`. `probe()` checks browser capabilities and needs a secure context. The last results (Chrome 151) are in `browser-results.json`.

The test keys are the fixed scalars `[1;32]` and `[2;32]`, for vectors only.
