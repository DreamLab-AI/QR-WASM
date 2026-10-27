# QR-WASM architecture notes

## Object format candidate
The conversational prototype used a 46-byte envelope: 2-byte magic, 1-byte version, 1-byte type, 4-byte truncated object ID, 4-byte dependency ID, 2-byte payload length, 32-byte SHA-256, then payload. This is **not a production format**: 32-bit IDs can collide, dependency resolution is limited and no publisher signature is included.

## Layers
1. QR transport (static printed or animated sequences), framing, error handling.
2. Content-addressed object store with full digest and chunk assembly.
3. Dependency graph and typed imports/exports, including collision/ambiguity handling.
4. WASM execution policy: bounded memory/fuel, capability-gated host functions.
5. Optional identity adapters: Nostr/BIP-340, DID methods, other signature schemes.
6. Browser UI and offline caching.

## Gaps
- Typed import resolution and namespace-aware provider selection.
- Nostr BIP-340 verification in compiled Rust WASM, measured QR footprint.
- NIP-01 event canonicalization and signatures, NIP-19 encoding, optional delegation (NIP-26), NIP-46 remote signing.
- Hierarchical deterministic derivation needs a separately specified key standard; never infer inheritance rights from possession of a public key.
- Browser camera decoding of raw binary QR, including ordering and duplicate handling.
- Threat model and fuzz tests for malicious QR input.
- Browser-native crypto versus shipped crypto-module size tradeoffs.

## Historical experiment caveat
Previous experiments were reported in conversation but their generated artifacts were not accessible when this repository was initialized. The code here is a new baseline, not a complete archive of those binaries.
