# ADR-0003: Tiny Little Office is linked and cited, not vendored

- Status: accepted
- Date: 2026-10-27
- Upstream: https://github.com/aboard-io/tinylittleoffice at `399d21771dbfbe06e383992f03f523b24a999ad2` (2026-10-22), MIT, "Copyright (c) 2026 Paul Ford"

## Context

TLO stores whole documents in URL fragments and draws QR codes for them. Several of its ideas apply to QR-WASM. Its codebase is changing quickly; the pinned HEAD is a few days old.

## Decision

- QR-WASM copies no TLO source. Ideas are cited as `path:line` at the pinned commit and reimplemented where they are adopted.
- If TLO source is ever needed in-tree, it is pinned to an exact commit, keeps the MIT licence and notices, and records every modification. That is the rule in [`references/tiny-little-office.md`](../../references/tiny-little-office.md).
- TLO's QR encoder (`src/kit/draw/qr.ts`, 9,347 bytes of source) is not taken, even though QR-WASM will need one. A shell that renders QR codes uses a maintained encoder pinned like `qrcode` 1.5.4 in `experiments/compression`.

## What QR-WASM takes from TLO (as ideas)

| TLO idea | Where (`399d217`) | Adopted as |
|---|---|---|
| Try each packing and keep the shortest | `src/kit/core/codec.ts:122-130` | Per-object codec choice with `none` as a candidate (ADR-0001) |
| Cap on inflated size as a bomb guard | `codec.ts:133` (`MAX_DOC_BYTES`) | Decoder rule 4, stopping at the declared length, which is stricter than a fixed cap |
| App code cached separately from state; the document never reaches the worker | `src/sw.ts:1-17`, `docs/threat-model.md:57-58` | Origin-served shell plus QR-delivered modules (findings §3) |
| History and sync leak fragments | `docs/threat-model.md:121-125` | Spec §8 threat model |
| One link-format version in the fragment (`#/v1/…`) | `src/kit/core/route.ts:26-30` | `#V1/` in `url43` |

## What QR-WASM does better or differently

| TLO choice | QR-WASM | Why |
|---|---|---|
| Whole URL in byte mode, base64url payload (`qr.ts:1-6`) | `url43` mixed segments | About 1.5× fewer frames at v10, and the same as binary at v25 and v40 |
| A single version-40 symbol cap (`qr.ts:6`, `limits.ts:78-79`) | Framing across many symbols, sized for scannable versions | WASM modules exceed 2,953 bytes |
| Preset deflate dictionary (`codec.ts:92-117`) | Not adopted | 3.7% gain on WASM; `DecompressionStream` has no dictionary support |
| `~` in place of `-` for chat line-wrapping (`codec.ts:9-12`) | Not needed for QR symbols | Applies only to links shared as text |
