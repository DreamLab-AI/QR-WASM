# QR-WASM

Experimental QR-transported modular WebAssembly computing environment.

**Status:** Research prototype. Earlier conversational experiments reported tiny manually constructed WASM modules, order-independent imports/exports and SHA-256 envelopes. Their original binary archives are **not available in this session** and have not been recovered; the repository contains a new, reproducible source-based baseline instead. Do not interpret historical results as independently reverified here.

## Research direction
- QR objects transport code, data, dependencies and integrity metadata.
- Browser WebAssembly imports/exports enable progressive linking.
- Use QR level L (minimum standardized error correction); standard QR has no zero-ECC mode.
- Content hashes prove integrity, **not provenance or trust**.
- Future optional Nostr adapter: NIP-01 event hashes, BIP-340 Schnorr/secp256k1 verification; no private keys in QR code or source control.
- Browser scanner, sandboxing, capability permissions, identity delegation, Rust WASM size benchmarks and mobile camera testing are open work.

## Current work
- [docs/findings.md](docs/findings.md): measured results (QR counts for a minimal did:nostr pod, size ladder, Tiny Little Office comparison, solid-pod-rs integration).
- [docs/spec/qr-object-v1.md](docs/spec/qr-object-v1.md): envelope v1 with full SHA-256 IDs, framing, transports, pod mapping, threat model.
- [docs/adr/](docs/adr/): decisions 0001–0003.

## Reproduce
- `node experiments/dynamic-linking/test.mjs`: builds two tiny WASM binaries directly and tests linking in both arrival orders.
- `cd experiments/compression && npm ci && node bench.mjs`: the compression, capacity and envelope gate.
- `cd experiments/minimal-pod && cargo test --offline && node test.mjs`: the pod's BIP-340 and NIP-98 vectors.

## Tiny Little Office reference
See [references/tiny-little-office.md](references/tiny-little-office.md). Upstream is MIT licensed; referenced via URL rather than copying or silently vendoring its source.

## Security
Never execute arbitrary QR-delivered WASM with privileged host imports. Validate full digests, enforce explicit import allowlists, budgets and publisher policy. QR scanning and URL fragments can leak through browser history, screenshots and link sharing.
