# QR-WASM research findings: TLO, size limits and estate integration

Date: 2026-10-27 · Branch `mission/qr-object-v1` · Every number here comes from a script in this repository; nothing is carried over from the unrecovered earlier experiments.

**Sources pinned:**
- Tiny Little Office (TLO) `399d217`
- bitcoin/bips `5aadddb` (BIP-340 vectors)
- nostr-protocol/nips `0b54c4d`
- solid-pod-rs `a4a86f6` (read-only)

**Decisions:** [ADR-0001](adr/0001-envelope-and-compression.md), [ADR-0002](adr/0002-identity-via-estate-crates.md), [ADR-0003](adr/0003-link-tlo-not-vendor.md). **Format:** [qr-object-v1](spec/qr-object-v1.md).

## 1. How many QR codes for a minimal did:nostr Solid pod in a browser?

The Service Worker spec registers only `http`/`https` scripts ([Register](https://w3c.github.io/ServiceWorker/) step "If scriptURL's scheme is not one of…"). So **one bootstrap QR code linking to an origin is always needed**, and the shell itself never arrives by QR. What comes after that depends on what the origin is trusted to serve:

| Origin serves | QR codes | Notes |
|---|---|---|
| A pod-specific shell, verifier included | **1** | The origin already holds the policy, so sending the verifier by QR adds nothing |
| A generic QR-WASM loader only (the project's model) | **1 + 19** at v25-L binary, or 1 + 8 at v40-L | Pod rung P2: 48,303 B wasm, 22,415 B deflate-raw, 22,458 B envelope |
| The same, as camera-openable `url43` links | 1 + 20 at v25, 1 + 9 at v40 | Mixed-segment URLs (§3) |
| The same, built on nightly | 1 + 18 at v25, 1 + 8 at v40 | Rung P3: 46,607 B |

All of these rungs pass:
- 19 BIP-340 vectors;
- 26 signed NIP-98 / LDP vectors (`experiments/minimal-pod/vectors/`);
- the same set run twice on one instance, plus 1 MiB request and response bodies.

They pass natively (`cargo test`), in Node through the JS shell (`node test.mjs`), and in Chrome 151 through the same shell (`browser-results.json`).

## 2. Size ladder (what made it smaller)

Each step changes one variable, except A → P, which moves JSON parsing to the shell *and* switches to `no_std` in the same step. P1–P4 and V1–V4 are verified; A1–C2 are the earlier serde_json design, built at commit `958d601`, superseded and never put through the vectors.

| Rung | Change | wasm (wasm-opt -Oz) | deflate | v25 frames |
|---|---|---:|---:|---:|
| A1 | std, serde_json + base64 inside wasm | 109,450 | 50,654 | 42 |
| A2 | + bump allocator | 100,670 | 47,182 | 39 |
| C2 | + nightly immediate-abort | 79,321 | 38,013 | 31 |
| P1 | `no_std`; shell does `JSON.parse` and base64; module rebuilds NIP-01 | 55,164 | 25,324 | 21 |
| **P2** | + bump allocator, no `core::fmt` (stable) | **48,303** | **22,415** | **19** |
| P3 | + nightly `build-std` immediate-abort | 46,607 | 21,563 | 18 |
| P4 | P2 using libsecp256k1 `lowmemory` | 75,672 | 46,608 | 38 |
| V3 | BIP-340 verifier alone (lower bound for any Nostr pod) | 30,264 | 13,801 | 12 |

The levers, largest first:

1. **Use the browser instead of shipping code, together with `no_std`.** A1 → P1 is 50% smaller (109,450 → 55,164). Moving JSON parsing and base64 to the shell is safe because the module verifies the signature over the very fields it acts on.
2. **Per-request bump allocator.** 6.9 KB on `no_std` (P1 → P2 minus the `core::fmt` change), 8.8 KB on std (A1 → A2). It is sound because the module is a pure function and `reset()` runs before each request.
3. **Removing `core::fmt`.** 5.0 KB, by writing decimals and joining strings by hand.
4. **Nightly immediate-abort panics.** 21 KB on the std design (A2 → C2), but only 1.7 KB once `no_std` with a trapping panic handler is in place (P2 → P3). Stable `no_std` gets most of the gain without nightly.

Pure-Rust k256 beats libsecp256k1 by about 22 KB.

What is left: the verifier (k256 field and scalar arithmetic) is about 30 KB of the 48 KB, and the pod logic plus SHA-256 and hex are about 18 KB.

## 3. Findings: TLO ideas scored against QR-WASM

| # | Idea | Source | Verdict | Why |
|---|---|---|---|---|
| T1 | Keep the shortest of several packings | TLO `src/kit/core/codec.ts:122-130` | **Improves (adopted)** | Hand-built modules grow under deflate (43 → 43, 62 → 63); per-object choice fixes that |
| T2 | Cap inflated output | TLO `codec.ts:133` | **Improves (adopted, stricter)** | Stop at the declared length, not 4 MiB; gated by the bomb check |
| T3 | Raw deflate via fflate, not CompressionStream | TLO `codec.ts:21-25` | Neutral | TLO needs dictionaries; QR-WASM does not, and native `DecompressionStream('deflate-raw')` costs 0 bytes |
| T4 | Frozen preset dictionary | TLO `codec.ts:92-117` | Worse for WASM | 3.7% gain (10,346 → 9,966) using a cached module as the dictionary; no native support |
| T5 | base64url in byte mode, whole URL | TLO `src/kit/draw/qr.ts:1-6` | **Worse than ours** | `url43` mixed segments need 11 frames against 15 at v10 and match binary at v25 and v40 (bench) |
| T6 | Single v40 cap of 2,953 B | TLO `qr.ts:6`, `src/kit/share/limits.ts:78-79` | Worse for WASM | Modules need multi-symbol framing at scannable versions |
| T7 | App shell cached by a service worker; state only in the fragment | TLO `src/sw.ts:1-17`, `docs/threat-model.md:57-58` | **Improves (adopted)** | It is the bootstrap model in §1 |
| T8 | `~` instead of `-`, `+` every 300 characters | TLO `codec.ts:9-12, 39-49` | Neutral | Matters for links pasted into chat, not QR to camera |
| T9 | Privacy: history and sync keep fragments | TLO `docs/threat-model.md:121-125` | **Improves (adopted)** | Spec §8 |
| T10 | Password-sealed payloads (HKDF + AES-GCM via WebCrypto) | TLO `src/kit/share/crypt.ts:14` | Out of scope | QR-WASM objects are public; noted for a future confidential-data kind |
| Q1 | 32-bit truncated IDs (our prototype) | `docs/architecture.md` (before) | Replaced | Full 32-byte IDs: +29 B per envelope, 3.1% of a v25 frame header |
| Q2 | Brotli | [Compression Standard](https://compression.spec.whatwg.org/) | Deferred | 11–17% smaller, but Chrome 151 has no `DecompressionStream('brotli')` |

Browser capabilities measured in Chrome 151 (`experiments/minimal-pod/browser-results.json`):

| Capability | Result |
|---|---|
| `DecompressionStream`: deflate-raw / brotli / zstd | ✅ / ❌ / ❌ |
| `Uint8Array.fromBase64` | ✅ |
| Ed25519 in WebCrypto (RFC 8032 test 1) | ✅ |
| secp256k1 in WebCrypto | ❌ |
| JSPI | ✅ |
| `BarcodeDetector` (Linux desktop) | ❌ |
| OPFS | ✅ |
| 43-character alphabet in `location.hash` | ✅ |

## 4. Estate integration: where a QR object fits

| Role | Estate piece (solid-pod-rs `a4a86f6`) | Fit today | Gap, as a recommendation only (no edits made) |
|---|---|---|---|
| Content-addressed resource | `Storage` trait, `crates/solid-pod-rs/src/storage/mod.rs:73`; ETag = `hex(sha256(body))`, `storage/fs.rs:107-109` | `PUT /qr/sha256/<hex>.wasm`: ETag equals the object ID | The pod does not check that path and digest match; recommend an opt-in content-addressed container that rejects mismatches (one compare, since the ETag is already computed) |
| Immutability | Conditional requests not enforced, `CLOSEOUT-JSS-DEEPDIVE.md:66` (P1-a) | Clients must verify digests themselves | Fixing P1-a makes `If-None-Match: *` give write-once objects |
| MIME | `mime_guess` via `crates/solid-pod-rs/src/ldp.rs:427-457` → `application/wasm` for `.wasm` | Works with `WebAssembly.compileStreaming` | — |
| Publisher write auth | NIP-98 `crates/solid-pod-rs-server/src/lib.rs:636`, identity `did:nostr:<pk>` at `:662` | The same key signs the upload and the provenance | — |
| Provenance verification | `Event::verify`, `crates/solid-pod-rs-nostr/src/relay.rs:63-88` (k256) | Server side: verify NIP-94 kind-1063 events | `canonical_id` (`relay.rs:48-58`) uses serde_json escaping (`\u00XX` for C0 controls); NIP-01 `01.md:44-55` says verbatim. Pick one rule estate-wide and add the escaping vector from `experiments/minimal-pod/tests/vectors.rs` |
| In-browser verification | — | QR-WASM ships its own k256 build (no_std) | Extracting a `no_std` NIP-01 canonical + verify core from `solid-pod-rs-nostr` would let pod and browser share one implementation |
| Publisher did:key | `solid-pod-rs-didkey` multicodec `0xe7`, `src/pubkey.rs:21`; `jws_alg` gives ES256K at `:67-73` | `did:key` over `0x02 ‖ x` names a Nostr publisher | did:key verification is JWT/ECDSA, not BIP-340; use it only as an identifier |
| IdP | `solid-pod-rs-idp` router not mounted (`CLOSEOUT-JSS-DEEPDIVE.md` P0-2) | Not needed for QR objects | — |

`cargo test -p solid-pod-rs-nostr` passed (7 + 8 + 2 tests). It was built with its target directory in the scratchpad, so solid-pod-rs was not touched.

## 5. Next steps

1. **Phone camera test** (blocks the `url43` default): print v15, v20 and v25 `url43` and `binary` symbols, and scan them with Android and iOS camera apps and with `BarcodeDetector` on Android and macOS. Record whether upper-case links open, whether fragments are kept, and frames per second.
2. **Write a real service-worker shell** around `experiments/minimal-pod/shell.mjs`: IndexedDB storage and a fetch handler, tested in the sidecar Chrome. Consider JSPI (available in Chrome 151) so the module can read storage directly.
3. **Content-addressed container and conditional requests in solid-pod-rs**, per §4. This needs an owner decision and edits in that repository.
4. **Settle NIP-01 escaping estate-wide** (§4), with a shared vector.
5. **Fuzz** the envelope, frame and wire parsers (`cargo fuzz` on `read_fields`, `parse_request` and a Rust port of `decodeObject`).
6. **Operator decision: offer Ed25519 did:key as an alternative identity.** WebCrypto verifies it natively, which removes the 30 KB verifier: the pod would be roughly 18 KB of logic, about 8 v25 frames, but this is not measured. did:nostr and NIP-98 remain secp256k1-only.
7. **Fountain-coded animated sequences** (RFC 6330) once scan rates are known.

## 6. Unknowns

- Camera-app handling of upper-case mixed-segment URLs and of byte-mode binary (spec §10).
- Brotli in `DecompressionStream`, and `Uint8Array.fromBase64`, in Firefox and Safari. Only Chrome 151 was tested.
- Real scan throughput and reliable QR versions at a given print size.
- Exactly how much an Ed25519 pod rung would save (step 6, unmeasured).
- Whether the solid-pod-rs maintainers accept a content-addressed container.

## Reproduce

```
node experiments/dynamic-linking/test.mjs
cd experiments/compression && npm ci && node bench.mjs            # 71 checks
cd experiments/minimal-pod && cargo test --offline                # BIP-340 + NIP-98 natively
node experiments/minimal-pod/test.mjs                             # every rung through the JS shell
experiments/minimal-pod/build-ladder.sh                           # rebuild rungs (nightly needs network)
```
