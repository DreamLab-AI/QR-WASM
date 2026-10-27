# QR-WASM

Experimental QR-transported modular WebAssembly computing environment.

**Status:** Research prototype. Envelope v1 is specified and gated, and a minimal did:nostr pod has been built and measured: 1 bootstrap QR code plus 19 version-25 codes (or 8 at version 40), with every size verified against published test vectors in Rust, Node and Chrome. Earlier conversational experiments were never recovered; every number in this repository comes from a script here.

## Research direction
- QR objects transport code, data, dependencies and integrity metadata.
- Browser WebAssembly imports/exports enable progressive linking.
- Use QR level L (minimum standardized error correction); standard QR has no zero-ECC mode.
- Content hashes prove integrity, **not provenance or trust**.
- Future optional Nostr adapter: NIP-01 event hashes, BIP-340 Schnorr/secp256k1 verification; no private keys in QR code or source control.
- Phone camera testing, the service-worker shell, sandboxing, typed imports and parser fuzzing are open work (see "Resume here").

## Current work
- [docs/findings.md](docs/findings.md): measured results (QR counts for a minimal did:nostr pod, size ladder, Tiny Little Office comparison, solid-pod-rs integration).
- [docs/spec/qr-object-v1.md](docs/spec/qr-object-v1.md): envelope v1 with full SHA-256 IDs, framing, transports, pod mapping, threat model.
- [docs/adr/](docs/adr/): decisions 0001–0003.

## Resume here
Work is on branch `mission/qr-object-v1`. Open decisions and next steps are in [docs/findings.md](docs/findings.md) §5:
1. Phone camera test of `url43` and binary symbols (blocks making `url43` the default).
2. A real service-worker shell with IndexedDB around `experiments/minimal-pod/shell.mjs`.
3. Operator decision: offer Ed25519 did:key, which WebCrypto verifies natively and would remove the 30 KB verifier.
4. Recommendations for solid-pod-rs (content-addressed container, conditional requests, NIP-01 escaping): not yet raised there.
5. Fuzz the envelope, frame and wire parsers.

## Reproduce
- `node experiments/dynamic-linking/test.mjs`: builds two tiny WASM binaries directly and tests linking in both arrival orders.
- `cd experiments/compression && npm ci && node bench.mjs`: the compression, capacity and envelope gate.
- `cd experiments/minimal-pod && cargo test --offline && node test.mjs`: the pod's BIP-340 and NIP-98 vectors.

Each experiment has its own README.

## Tiny Little Office reference
See [references/tiny-little-office.md](references/tiny-little-office.md). Upstream is MIT licensed; referenced via URL rather than copying or silently vendoring its source.

## Security
Never execute arbitrary QR-delivered WASM with privileged host imports. Validate full digests, enforce explicit import allowlists, budgets and publisher policy. QR scanning and URL fragments can leak through browser history, screenshots and link sharing.
