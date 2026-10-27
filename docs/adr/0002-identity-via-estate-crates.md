# ADR-0002: Identity and provenance go through standard Nostr, did:key and estate crypto

- Status: accepted (research draft)
- Date: 2026-10-27
- Spec: [`docs/spec/qr-object-v1.md`](../spec/qr-object-v1.md) §6–§8
- Evidence: `experiments/minimal-pod/` (`tests/vectors.rs`, `test.mjs`, `browser-results.json`); `cargo test -p solid-pod-rs-nostr` passed (7 + 8 + 2 tests)

## Context

Layer 5 of [`docs/architecture.md`](../architecture.md) needs publisher identity and provenance. The estate already has three relevant pieces:

- `solid-pod-rs-nostr`: k256 BIP-340 verification at `crates/solid-pod-rs-nostr/src/relay.rs:63-88`, and the NIP-01 ID at `:48-58`.
- `solid-pod-rs-didkey`: Ed25519, P-256 and secp256k1 multicodecs at `src/pubkey.rs:16-24`.
- NIP-98 HTTP auth: server-side at `crates/solid-pod-rs-server/src/lib.rs:636`, core at `crates/solid-pod-rs/src/auth/nip98.rs:65`.

The global rules forbid hand-rolled cryptography and bespoke token formats.

## Decision

1. **Signatures are BIP-340 Schnorr over secp256k1, verified with k256 0.13.** That is the crate `solid-pod-rs-nostr` uses. In the browser it is compiled into the module with `default-features = false, features = ["schnorr"]`, with `precomputed-tables` confirmed off.
   - It passes all 19 BIP-340 test vectors (bitcoin/bips `5aadddb`, `bip-0340/test-vectors.csv`) natively, in Node, and in Chrome 151.
   - QR-WASM contains no Schnorr, field or hash code of its own.
2. **Provenance is a standard NIP-94 kind-1063 event**: `["x", <object ID hex>]` and `["m", "application/wasm"]`.
   - Online, it is fetched from a relay or from the pod.
   - Offline, it travels as a kind-`0x04` QR object of 373 bytes, which fits one v15-L symbol.
3. **Writes to a pod use NIP-98.** The QR-WASM pod module checks:
   - kind 27235;
   - created_at within ±60 s;
   - the `u` and `method` tags;
   - the `payload` tag equals SHA-256 of the body;
   - the NIP-01 ID;
   - the BIP-340 signature;
   - the owner.

   26 signed vectors cover each rule.
4. **did:key for a Nostr publisher** is `did:key` with multicodec `0xe7` over `0x02 ‖ x-only pubkey`, because BIP-340 keys imply an even Y. It is an identifier, not a proof. `solid-pod-rs-didkey` verifies ES256K JWTs (ECDSA), not BIP-340, so it is not used for event signatures.
5. **The shell parses and the module verifies.** The browser shell decodes and parses the NIP-98 header natively (`Uint8Array.fromBase64`, `JSON.parse`) and passes the fields to the module. The module rebuilds the NIP-01 serialisation from exactly those fields and verifies over it.
   - A shell that changes a field is rejected. This was tested by deliberately breaking the shell's `content` field: the vector failed, then passed again once restored.

## Measured alternatives

| Option | Result | Verdict |
|---|---|---|
| libsecp256k1 (`secp256k1` 0.31, `lowmemory`) instead of k256 | Verifier 55,155 B against 33,121 B; its tables sit in the data section | Rejected on size |
| Packed 104-byte provenance trailer (key, timestamp, signature; rest rebuilt from a template) | Saves about 270 B against the 373-byte standard event | Rejected: a bespoke format that no Nostr tool can read |
| Depend on `solid-pod-rs-nostr` directly in the browser module | Its `Event` pulls in serde_json and std; the A1 rung (serde_json in wasm) was 109 KB | Rejected for the browser; same primitive used instead |
| Ed25519 did:key, verified with WebCrypto | Chrome 151 verifies RFC 8032 test 1 natively; secp256k1 is `NotSupportedError` | **Not adopted: did:nostr and NIP-98 require secp256k1.** This is an operator decision; it would remove the verifier entirely (see findings §5) |

## Consequences

- **NIP-01 escaping is a real cross-implementation risk.** NIP-01 (nips `0b54c4d`, `01.md:44-55`) escapes seven characters and requires "all other characters … verbatim". serde_json, and therefore `solid-pod-rs-nostr` `relay.rs:48-58`, and `JSON.stringify` both write other C0 controls as `\u00XX`.
  - The QR-WASM module follows the spec text. A vector pins both behaviours: the NIP-01 form is accepted, the `\u0001` form rejected.
  - Mismatches fail closed, but the estate should choose one rule (findings §4).
- No private keys appear in QR objects, fragments or source. The test keys are the fixed scalars `[1;32]` and `[2;32]`, used only in `tests/vectors.rs`.
