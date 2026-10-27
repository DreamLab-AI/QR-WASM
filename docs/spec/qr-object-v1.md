# QR object format, version 1

Status: draft. Decisions are recorded in [ADR-0001](../adr/0001-envelope-and-compression.md), [ADR-0002](../adr/0002-identity-via-estate-crates.md) and [ADR-0003](../adr/0003-link-tlo-not-vendor.md). Every number below comes from `experiments/compression/bench.mjs`, which writes `experiments/compression/results.json` (Node 22.23.3, zlib 1.3.1, rustc 1.99.1, wasm-opt 132, `qrcode` 1.5.4). The acceptance criteria in §9 are checks in that script, so the gate fails if the spec and the measurements disagree.

## 1. Scope

A *QR object* is a WebAssembly module, data blob or provenance record carried in one or more QR symbols at error-correction level L. Version 1 defines:

- the binary envelope (§2);
- object identity and dependencies (§3);
- framing across several symbols (§4);
- three transports (§5);
- the mapping onto a Solid pod (§6);
- provenance (§7).

It replaces the 46-byte prototype envelope in [`docs/architecture.md`](../architecture.md). That envelope truncated object and dependency IDs to 32 bits, so collisions are expected after about 2¹⁶ objects.

Not in v1:

- typed import resolution beyond "exactly one provider per import", which is today's `experiments/dynamic-linking/test.mjs` rule;
- the execution policy (fuel, memory, host-import allowlist), except as threat-model requirements (§8);
- fountain-coded animated sequences.

## 2. Envelope

All integers are big-endian.

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 2 | magic | ASCII `QW` |
| 2 | 1 | version | `0x01` |
| 3 | 1 | kind | `0x01` WASM module, `0x02` opaque data, `0x04` provenance record (§7); others reserved |
| 4 | 1 | codec | `0x00` none, `0x01` deflate-raw (RFC 1951), `0x02` brotli (RFC 7932, optional, §2.2) |
| 5 | 1 | flags | must be `0x00` in v1 |
| 6 | 4 | length | length of the *uncompressed* payload in bytes |
| 10 | 32 | digest | SHA-256 of the *uncompressed* payload: the object ID |
| 42 | 1 | ndeps | number of dependency digests, 0–255 |
| 43 | 32·ndeps | deps | full SHA-256 object IDs this object needs |
| 43+32·ndeps | rest | body | the payload after `codec` |

The fixed header is 43 bytes. Each dependency adds 32 bytes. With one dependency the header is 75 bytes, against 46 in the prototype. The 29 extra bytes buy full-strength IDs.

### 2.1 Codec selection

The encoder compresses with every codec it is allowed to emit and keeps the smallest body. `none` is always a candidate, so the envelope is never larger than `43 + 32·ndeps + length`. The measurements show this choice matters:

| Fixture | Raw | deflate-raw | brotli | Chosen |
|---|---:|---:|---:|---|
| `provider` (hand-built) | 43 | 43 | 40 | none |
| `consumer` (hand-built) | 62 | 63 | 60 | none |
| `base45-oz-wasmopt` (Rust, `opt-level=z`, `wasm-opt -Oz`) | 775 | 503 | 493 | deflate-raw |
| `base45-fmt-oz-wasmopt` (same, plus `core::fmt`) | 19,837 | 10,346 | 9,155 | deflate-raw |

### 2.2 Why deflate-raw is mandatory and brotli optional

- Every v1 decoder must support `none` and `deflate-raw`.
- Brotli is about 2% smaller on the 775-byte module and 11.5% smaller on the 19.8 KB one. That saves one frame out of nine at v25 (§4), so it is worth keeping. But although the [Compression Standard](https://compression.spec.whatwg.org/) now lists `"brotli"`, Chrome 151 rejects `new DecompressionStream('brotli')` with a TypeError (`experiments/minimal-pod/browser-results.json`). A decoder would have to ship brotli itself, which costs more than the frame it saves.
- An encoder may emit `0x02` only when it knows the receiver's decoder supports it, for example because a cached runtime declares it. A decoder that sees an unsupported codec rejects the object and does not guess.

### 2.3 Decoder rules

A decoder must reject the envelope in any of these cases:

1. Magic ≠ `QW`, version ≠ 1, or flags ≠ 0.
2. `length` > 1 MiB (1,048,576). This is the v1 ceiling and may be configured lower, never higher.
3. The input ends before the body starts.
4. Decompression would produce more than `length` bytes. The decoder stops at `length`; it does not decompress fully and then check.
5. The decompressed length ≠ `length`.
6. SHA-256 of the decompressed payload ≠ `digest`.

The digest covers the uncompressed bytes, so verification cannot happen before decompression. Rule 4 is what makes that safe: a 64 KiB zero-filled module, deflated and relabelled with `length = 100`, fails without allocating more than 100 bytes. That is check *decoder rejects a decompression bomb*.

## 3. Identity and dependencies

- The object ID is the 32-byte SHA-256 of the uncompressed payload. It does not depend on the codec or the transport.
- It is written as 64 lowercase hex characters wherever text is needed. That is the same form the pod uses for ETags (§6) and NIP-94 uses for `x` tags (§7).
- Dependencies are listed by full object ID. A loader instantiates a module once every dependency is present and each of its imports has exactly one provider, which is the rule the dynamic-linking experiment already uses.
- A digest proves the bytes are intact. It says nothing about who published them; that is §7's job.

## 4. Framing

An envelope that fits in one symbol is sent bare: the symbol's data starts with `QW`. Otherwise the envelope is cut into frames, and each frame is one symbol:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic, ASCII `QF` |
| 2 | 1 | version `0x01` |
| 3 | 2 | index, 0-based |
| 5 | 2 | total, 1–65,535 |
| 7 | 32 | object ID (equal to the envelope's `digest`) |
| 39 | rest | envelope bytes `[index·per, (index+1)·per)` |

The frame header is 39 bytes. It carries the full object ID, which costs 3.1% of a v25 symbol, so two objects scanned at the same time can never be mixed up. The receiver:

- drops exact duplicates;
- rejects a frame whose index, total or object ID disagrees with the frames already held;
- assembles the envelope only once all `total` frames are present;
- checks that the decoded envelope's digest equals the frame's object ID.

The order frames arrive in does not matter.

## 5. Transports

| Transport | QR mode | Symbol content | Per-symbol envelope bytes at v25-L |
|---|---|---|---|
| `binary` (preferred) | byte | frame bytes as they are | 1,273 − 39 = 1,234 |
| `base45` | alphanumeric | RFC 9285 base45 of the frame | ⌊1,853 / 3⌋·2 + 1 − 39 = 1,196 |
| `url` | byte | `https://<origin>/#v1/` + base64url (RFC 4648 §5) of the frame | ⌊(1,273 − 23)·3/4⌋ − 39 = 898 |
| `url43` (preferred for camera links) | alphanumeric + byte + alphanumeric | `HTTPS://<ORIGIN>/` · `#` · `V1/` + radix-43 of the frame | 1,215 − 39 = 1,176 (probed) |

`binary` packs the most per symbol. The open question is whether browser and phone scanners return its bytes intact (§10).

`base45` exists for scanners that only return text. It takes the same number of frames as `binary`, or one more, for every fixture measured.

`url` is what a phone camera opens with no app installed, which is how TLO works. At v10 it needs about 1.5–1.6 times as many frames as `binary` (15 against 10 for the 2 KiB case, 71 against 45 for the 19.8 KB module). Base45 cannot be used inside a URL: `#` is not in the QR alphanumeric set, and base45's space and `%` are mangled by URL percent-decoding.

`url43` gets around this with three QR segments:

1. an alphanumeric segment for the upper-case origin (scheme and host are case-insensitive);
2. a one-character byte segment for `#`;
3. an alphanumeric segment holding `V1/` and the frame in *radix 43*.

Radix 43 is base45 without space and `%`. Its alphabet is `0-9 A-Z $ * + - . / :`, which the [WHATWG URL](https://url.spec.whatwg.org/) fragment percent-encode set leaves untouched. Two bytes become three characters (43³ ≥ 2¹⁶, and a lone final byte takes two), the same density as base45.

The shell reads the payload from `location.hash`. It must never parse the fragment as form data, where `+` would become a space. Chrome 151 returned all 43 characters unchanged (`experiments/minimal-pod/browser-results.json`).

`url43` needs the same number of frames as `binary` at v25 and v40, and one to seven more at v10 and v15.

Frames needed, with one dependency (from `results.json`):

| Object | Envelope | binary v15 / v25 / v40 | base45 v15 / v25 / v40 | url v15 / v25 / v40 |
|---|---:|---|---|---|
| incompressible 2,048 B | 2,123 | 5 / 2 / 1 | 5 / 2 / 1 | 7 / 3 / 1 |
| `base45-oz-wasmopt` | 578 | 2 / 1 / 1 | 2 / 1 / 1 | 2 / 1 / 1 |
| `base45-fmt-oz-wasmopt` | 10,421 | 22 / 9 / 4 | 23 / 9 / 4 | 32 / 12 / 5 |

With `url43` the three rows are 5 / 2 / 1, 2 / 1 / 1 and 24 / 9 / 4.

## 6. Mapping onto a Solid pod

The estate's pod server is solid-pod-rs (read-only for this work). An object lives at

```
<pod>/qr/sha256/<hex>.wasm         Content-Type: application/wasm   body: uncompressed module
<pod>/qr/sha256/<hex>.nip94.json   Content-Type: application/json  body: the provenance event (§7)
```

- The body is stored uncompressed, so the pod's ETag, which solid-pod-rs computes as `hex(sha256(body))` (`crates/solid-pod-rs/src/storage/fs.rs:107-109`), equals the object ID. A client checks the ETag against the path before using it, and checks the body's digest after downloading.
- The `.wasm` suffix makes `mime_guess` (used by `crates/solid-pod-rs/src/ldp.rs:427-457`) report `application/wasm`. Browsers need that type for `WebAssembly.compileStreaming`.
- Writes are authenticated with NIP-98, which the server already verifies (`crates/solid-pod-rs-server/src/lib.rs:636`, identity `did:nostr:<pk>` at `:662`). The key that signs the upload can be the one that signs the provenance event.
- The pod does not check that the path matches the content, and it does not yet enforce conditional requests (`CLOSEOUT-JSS-DEEPDIVE.md:66`). Until both are in place, the client is what makes the path content-addressed, by checking the digest. `docs/findings.md` §4 recommends adding both to solid-pod-rs.

## 7. Provenance

Provenance is a standard [NIP-94](https://github.com/nostr-protocol/nips/blob/master/94.md) file-metadata event: kind `1063`, `["x", <hex object ID>]`, `["m", "application/wasm"]`, empty `content`. Nothing bespoke is involved.

It reaches a verifier in one of two ways:

- **Online:** from a relay, or from the pod's `.nip94.json` resource.
- **Offline:** as a separate QR object of kind `0x04`. Its payload is the event's UTF-8 JSON, and its single dependency is the attested object's ID.

The minimal event is 442 bytes. As a kind `0x04` object with one dependency, deflate-raw is chosen (hex compresses to about 4 bits per character), and the envelope is 373 bytes. That fits one bare v15-L symbol (capacity 520). A packed 104-byte form (public key, timestamp, signature, with the rest rebuilt from a template) was measured and rejected in ADR-0002.

A verifier:

1. recomputes the NIP-01 event ID;
2. verifies the BIP-340 signature;
3. checks that the `x` tag equals the object ID;
4. applies its publisher policy to the public key.

Steps 1 and 2 use `solid_pod_rs_nostr::relay::Event::verify` (`crates/solid-pod-rs-nostr/src/relay.rs:63-88`, k256 Schnorr). The did:key of a publisher, when needed, is `did:key` with multicodec `0xe7` (secp256k1, `crates/solid-pod-rs-didkey/src/pubkey.rs:21`) over the compressed point `0x02 ‖ pubkey`. BIP-340's x-only keys always imply an even Y coordinate, which is why the prefix is `0x02`.

## 8. Threat model

| Threat | Requirement |
|---|---|
| Malicious QR input: oversized length, decompression bomb, truncated or overlong fields | §2.3 rules 1–6. Parsers are fuzzed before any release (§10). |
| Frame confusion: two objects scanned at once, or a replayed frame | The frame carries the full object ID; conflicting duplicates are rejected (§4). |
| Code that is intact but hostile | A digest proves integrity, not trust. Execution requires a publisher-policy decision (§7) or explicit user consent. |
| Privileged host imports | A loader exposes only an allowlist of host functions per kind and policy. It never passes through `env.*` wholesale. Any unresolved or ambiguous import refuses instantiation. |
| Resource exhaustion at run time | Memory, table size and execution time are bounded by the loader. The mechanism is out of scope for v1. |
| Leakage through URL fragments | A `url` symbol puts the whole object in the address bar. Browsers keep it in history and sync it, and it appears in screenshots and shared links. TLO's threat model makes the same point (`docs/threat-model.md:121-125` at TLO `399d217`). For plain v1 objects: use `binary` or `base45` for anything not meant to be public, and never put keys in a fragment. The sealed bootstrap (README, draft 0) is the one deliberate exception: its app code carries a content key in the fragment, and the launcher removes it from the URL and history entry before doing anything else (verified in the Chrome e2e gate). |
| Leakage through QR images | A printed or photographed plain v1 symbol is the object; plain objects are public by design and have no confidentiality layer. A sealed **app code** is a bearer capability: whoever holds it can decrypt and run that app. |
| Lost or photographed home code | The home code grants signing requests within the remote signer's policy (kind 27235, `u` under `home`). Treat it like a house key: revoke it at the signer and print a new one if lost. Its secret is single-use and binds the first client that pairs, so a copy made after pairing cannot pair again. It never contains a private key. |
| Trusted launcher origin | The launcher page reads the app code's key, so its origin is trusted with every app opened through it. Mitigations: keep the launcher small and auditable, install it as a PWA, and offer it from more than one origin. |
| Forged provenance | Only BIP-340 verification through the estate crate counts (ADR-0002). A did:key string or a `did:nostr` claim on its own is never treated as proof. |

## 9. Acceptance criteria

Each criterion below is a check in `experiments/compression/bench.mjs` (check names in italics). The gate passes only when all of them pass.

1. Probed QR capacity at level L equals the cited ISO/IEC 18004 table for versions 10, 15, 20, 25, 30 and 40 in byte and alphanumeric mode. At v40-L that is 2,953 bytes and 4,296 characters. *QR capacity probe matches cited ISO/IEC 18004 table (level L).*
2. An incompressible 2,048-byte module with one dependency fits in ≤ 2 binary frames at v25-L, 5 at v15-L, and 1 at v40-L. It fits in ≤ 2 base45 frames and ≤ 3 URL frames at v25-L. Every frame encodes at its stated version. *spec §9 frame-count acceptance criteria hold*, and the *frames encode at vN-L* checks.
3. The envelope is never larger than codec `none` would make it, and modules under 64 bytes choose `none`. *codec selection never inflates…*, and *tiny modules do not benefit…*.
4. Each fixture round-trips through envelope and framing, including frames shuffled and duplicated. *envelope round-trips every fixture*, *frames reassemble shuffled and duplicated*.
5. The decoder rejects a decompression bomb, a declared length over the ceiling, a tampered payload, truncated input, a wrong version, a frame from another object, and missing frames. These are the five *decoder rejects…* and *reassembly rejects…* checks.
6. Base45 matches the RFC 9285 examples, and the Rust-built fixture's base45 output equals the JS codec's. *base45 matches RFC 9285…*, *Rust base45 fixture agrees…*.
7. A minimal provenance object (kind `0x04`, 442-byte NIP-94 event with pseudo-random hex, one dependency: 373 bytes after deflate) fits one bare v15-L binary symbol. *provenance object (kind 0x04) fits one bare v15-L binary symbol.*
8. The `url43` transport round-trips radix 43, rejects overflow, and fits the incompressible 2,048-byte module in 2 frames at v25-L and 11 at v10-L. Every frame encodes at its stated version. *base43 round-trips…*; `url43@v10` and `url43@v25` in the frame-count criteria.

## 10. Unknowns

- **Byte-mode integrity through scanners.** `BarcodeDetector.rawValue` is a `DOMString`, and some decoders guess a charset for byte-mode data. It is not known which browser and phone scanners return arbitrary bytes unchanged. Until a camera test exists, `base45` is the safe text-only fallback.
- **Brotli in `DecompressionStream` outside Chrome.** Chrome 151 does not support it. Firefox and Safari have not been tested.
- **Camera apps and upper-case links.** It is not known whether phone camera apps open an upper-case `HTTPS://` link and keep the fragment intact. `BarcodeDetector` is missing from Chrome 151 on Linux desktop; Android and macOS have not been tested.
- **Real scan reliability.** How many frames per second a phone can read, and which versions it can read reliably at a given print size, has not been measured.
- **A pre-shared deflate dictionary.** Priming deflate with a module the receiver already has took the 19.8 KB fixture from 10,346 to 9,966 bytes, 3.7% smaller. `DecompressionStream` has no dictionary option, so this would mean shipping an inflater. Not adopted.
- **Fuzzing the §2.3 and §4 parsers.** Not yet done.
- **Fountain codes for animated sequences** (for example RaptorQ, RFC 6330), which would make frame loss harmless.
