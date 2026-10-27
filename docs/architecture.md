# QR-WASM architecture notes

## Object format
The conversational prototype used a 46-byte envelope with 4-byte truncated object and dependency IDs. It is **superseded** by [envelope v1](spec/qr-object-v1.md): a 43-byte header carrying the full SHA-256 of the uncompressed payload, plus 32 bytes per dependency, and 39-byte frame headers that also carry the full ID ([ADR-0001](adr/0001-envelope-and-compression.md)).

## Layers and status

| # | Layer | Status (2026-10-27) |
|---|---|---|
| 1 | QR transport, framing, error handling | Specified (spec §4–§5): `binary`, `base45`, `url43` transports; shuffled and duplicate frames handled; gated by `experiments/compression/bench.mjs` |
| 2 | Content-addressed store, chunk assembly | Specified (spec §2–§3, §6): object ID = SHA-256 of the uncompressed bytes, which equals the solid-pod-rs ETag. Sealed blobs (`experiments/sealed-launcher`) add a BEP 52 root, so any untrusted source (cache, web seed, swarm) can serve them |
| 3 | Dependency graph, typed imports and exports | Partly done: dependencies by full ID; exactly-one-provider rule from `experiments/dynamic-linking`. Typed resolution still open |
| 4 | WASM execution policy | Partly done: the launcher enforces an import allowlist (empty for the pod), re-hashes on every cold start and asks for consent before running. Pod output is contained on the launcher origin but not yet isolated on its own origin. Memory and time bounds are still open |
| 5 | Identity adapters | Done for Nostr ([ADR-0002](adr/0002-identity-via-estate-crates.md)): BIP-340 via k256, NIP-98 writes, NIP-94 provenance; verified against published vectors |
| 6 | Browser UI, offline caching | Done for draft 0 (`experiments/sealed-launcher`): launcher page, service worker, IndexedDB, verified blob cache, NIP-46 pairing; 15/15 in Chrome 151 |

## Gaps

Closed by this round of work (see [findings](findings.md)):
- ~~Nostr BIP-340 verification in compiled Rust WASM, measured QR footprint~~: 30.5 KB verifier, 48.7 KB full pod, 1 + 19 v25-L codes.
- ~~NIP-01 event canonicalisation and signatures~~: implemented to the spec text; an escaping difference in `solid-pod-rs-nostr` is reported, not fixed.
- ~~Threat model for malicious QR input~~: spec §8.
- ~~Browser-native crypto versus shipped crypto~~: measured in Chrome 151. Ed25519 is native, secp256k1 is not.
- ~~Service-worker shell and IndexedDB~~, ~~NIP-46 remote signing~~: built in the sealed launcher, with consent, containment and cold-start re-verification.
- ~~Confidentiality~~: sealed app codes (COSE_Encrypt0, A256GCM) keep hosts and seeders from learning what is being run.

Still open:
- Typed import resolution and namespace-aware provider selection.
- Phone camera decoding of raw binary and upper-case `url43` QR codes.
- Fuzz tests for the envelope, frame and wire parsers.
- NIP-19 encoding; a production NIP-46 signer (only a test signer exists).
- Torrent transport (WebTorrent is BitTorrent v1 only), mesh links between ephemeral nodes.
- Serving pod output from its own origin, and an object-ID allowlist pages cannot change.
- Hierarchical deterministic derivation needs a separately specified key standard; never infer inheritance rights from possession of a public key.

## Historical experiment caveat
Previous experiments were reported in conversation but their generated artifacts were not accessible when this repository was initialised. Every number now in the repository comes from a script here.
