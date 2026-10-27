# ADR-0001: Envelope v1, compression and transports

- Status: accepted (research draft)
- Date: 2026-10-27
- Spec: [`docs/spec/qr-object-v1.md`](../spec/qr-object-v1.md) §2–§5
- Evidence: `experiments/compression/bench.mjs` → `results.json` (71 checks); `experiments/minimal-pod/results.json`; `experiments/minimal-pod/browser-results.json`

## Context

The prototype envelope in [`docs/architecture.md`](../architecture.md) was 46 bytes, with 32-bit truncated object and dependency IDs. With 32-bit IDs, collisions are expected after about 2¹⁶ objects, and an attacker can find a colliding module in about 2³² hashes.

QR-WASM objects travel as QR symbols at error-correction level L. The probed capacities match the ISO/IEC 18004 table: 271 / 520 / 1,273 / 2,953 bytes at v10 / v15 / v25 / v40. Every header byte is paid for in every symbol.

## Decision

1. **Full SHA-256 everywhere.**
   - The object ID is the 32-byte SHA-256 of the *uncompressed* payload, so the ID does not depend on codec or transport. It equals the Solid pod's ETag (ADR-0002) and the NIP-94 `x` tag.
   - Dependencies are listed by full ID.
   - Every frame header carries the full ID.
   - Fixed envelope: 43 bytes, plus 32 per dependency. Frame header: 39 bytes.
2. **Codecs.**
   - The encoder chooses the smallest of `none` and `deflate-raw` for each object. Every decoder must support both.
   - `brotli` (`0x02`) is reserved but not emitted in v1.
3. **Bounded decompression.**
   - The decoder stops at the declared uncompressed length, with a 1 MiB ceiling.
   - It then checks the length and the digest.
4. **Transports.**
   - `binary` (byte mode) for apps that pass bytes through intact.
   - `url43` for camera-openable links: an alphanumeric origin, a byte-mode `#`, then a radix-43 payload in alphanumeric mode.
   - `base45` (alphanumeric) is kept for scanners that return text only.
   - Plain base64url in byte mode (`url`) is measured but not recommended.

## Measurements behind the decision

**Compression on the fixtures (bytes):**

| Fixture | Raw | deflate-raw | brotli |
|---|---:|---:|---:|
| hand-built `provider` / `consumer` | 43 / 62 | 43 / 63 | 40 / 60 |
| Rust `base45-oz-wasmopt` | 775 | 503 | 493 |
| Rust `base45-fmt-oz-wasmopt` | 19,837 | 10,346 | 9,155 |
| minimal pod P2 (`experiments/minimal-pod`) | 48,678 | 22,573 | 18,842 |

**Why deflate-raw and not brotli:**
- Modules under about 64 bytes grow under deflate, so per-object selection with `none` as a candidate is required. This is the same shortest-of-candidates rule TLO's `packDoc` uses (`src/kit/core/codec.ts:122`, TLO `399d217`).
- Brotli is 11–17% smaller on the larger modules: it would save 3 of 19 v25 frames for the pod.
- But Chrome 151 rejects `new DecompressionStream('brotli')` and `'zstd'`, while `deflate-raw` is native. Shipping a brotli decoder would cost more than it saves. Brotli is revisited when Firefox, Safari and Chrome all ship it.
- A preset dictionary, which is TLO's frozen-dictionary idea (`codec.ts:92-117`), was measured using a module the receiver already holds: 10,346 → 9,966 bytes, 3.7% smaller. `DecompressionStream` has no dictionary option, so this would also mean shipping an inflater. Rejected.

**Transport density** (frames at v10 / v15 / v25 / v40, from `results.json`):

| Object | `binary` | `url` (base64url) | `url43` |
|---|---|---|---|
| incompressible 2 KiB + 1 dependency | 10 / 5 / 2 / 1 | 15 / 7 / 3 / 1 | 11 / 5 / 2 / 1 |
| `base45-fmt-oz-wasmopt` | 45 / 22 / 9 / 4 | 71 / 32 / 12 / 5 | 52 / 24 / 9 / 4 |

**Header cost:**
- The 39-byte frame header is 14% of a v10 symbol, 7.5% of v15, 3.1% of v25 and 1.3% of v40.
- Shortening it would mean a truncated frame tag, which the no-truncated-IDs rule forbids.
- Shaving 2–3 bytes off the envelope saves under 0.3% at v25 and is not worth changing the format for.

## Consequences

- An object ID is a cache key, a pod path, an ETag and a provenance subject all at once, with no mapping table.
- The digest can only be checked after decompression. Decoder rule 4 (stop at the declared length) is what keeps that safe, and it is gated by the *decompression bomb* check.
- Mixed-segment `url43` symbols depend on upper-case links surviving phone camera apps. That has not been tested yet (spec §10).
- `url43` is designed for QR to camera, not for links pasted into chat. Its alphabet contains `-`, which TLO avoids because chat apps break lines there (`codec.ts:9-12`). Text sharing should use TLO-style base64url with `~`.

## Alternatives rejected

| Option | Why |
|---|---|
| Keep 32-bit IDs, or use 64-bit frame tags | Collisions and forgeries are cheap; violates the mission rule |
| Digest the compressed bytes | The ID would change with codec or level; it would no longer match pod ETags or NIP-94 `x` |
| Brotli mandatory | Not native in Chrome 151's `DecompressionStream` |
| Base45 inside URLs | Space and `%` are mangled by URL percent-decoding, and `#` is outside the alphanumeric set |
| Byte-mode base64url URLs (TLO's QR path, `src/kit/draw/qr.ts:1-6`) | About 1.5× the frames of `url43` at v10 |
