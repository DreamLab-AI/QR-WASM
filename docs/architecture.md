# QR-WASM architecture notes

## Object format
The conversational prototype used a 46-byte envelope with 4-byte truncated object and dependency IDs. It is **superseded** by [envelope v1](spec/qr-object-v1.md): a 43-byte header carrying the full SHA-256 of the uncompressed payload, plus 32 bytes per dependency, and 39-byte frame headers that also carry the full ID ([ADR-0001](adr/0001-envelope-and-compression.md)).

## Layers and status

| # | Layer | Status (2026-10-27) |
|---|---|---|
| 1 | QR transport, framing, error handling | Specified (spec §4–§5): `binary`, `base45`, `url43` transports; shuffled and duplicate frames handled; gated by `experiments/compression/bench.mjs` |
| 2 | Content-addressed store, chunk assembly | Specified (spec §2–§3, §6): object ID = SHA-256 of the uncompressed bytes, which equals the solid-pod-rs ETag |
| 3 | Dependency graph, typed imports and exports | Partly done: dependencies by full ID; exactly-one-provider rule from `experiments/dynamic-linking`. Typed resolution still open |
| 4 | WASM execution policy | Requirements only (spec §8): host-import allowlist, bounded memory and time |
| 5 | Identity adapters | Done for Nostr ([ADR-0002](adr/0002-identity-via-estate-crates.md)): BIP-340 via k256, NIP-98 writes, NIP-94 provenance; verified against published vectors |
| 6 | Browser UI, offline caching | Shell prototype (`experiments/minimal-pod/shell.mjs`); service-worker and IndexedDB wiring still open |

## Gaps

Closed by this round of work (see [findings](findings.md)):
- ~~Nostr BIP-340 verification in compiled Rust WASM, measured QR footprint~~: 30.5 KB verifier, 48.7 KB full pod, 1 + 19 v25-L codes.
- ~~NIP-01 event canonicalisation and signatures~~: implemented to the spec text; an escaping difference in `solid-pod-rs-nostr` is reported, not fixed.
- ~~Threat model for malicious QR input~~: spec §8.
- ~~Browser-native crypto versus shipped crypto~~: measured in Chrome 151. Ed25519 is native, secp256k1 is not.

Still open:
- Typed import resolution and namespace-aware provider selection.
- Phone camera decoding of raw binary and upper-case `url43` QR codes.
- Fuzz tests for the envelope, frame and wire parsers.
- NIP-19 encoding, NIP-26 delegation, NIP-46 remote signing.
- Hierarchical deterministic derivation needs a separately specified key standard; never infer inheritance rights from possession of a public key.

## Historical experiment caveat
Previous experiments were reported in conversation but their generated artifacts were not accessible when this repository was initialised. Every number now in the repository comes from a script here.
