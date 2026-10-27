# QR-WASM

Experimental QR-transported modular WebAssembly computing environment.

**Status:** research prototype on branch `mission/qr-object-v1`.
- Envelope v1 is specified and gated.
- A minimal did:nostr pod is built and measured: it needs 1 bootstrap QR code plus 19 version-25 codes (or 8 at version 40).
- The **sealed single-QR bootstrap** below is the current design, being implemented in `experiments/sealed-launcher/`.
- Every number in this repository comes from a script here. Earlier conversational results were never recovered.

## Sealed single-QR bootstrap (draft 0)

One small public **app code** boots an ephemeral browser node that runs a content-addressed, encrypted WebAssembly app. That app is the did:nostr pod. A second, private **home code** binds the node to its owner's main pod through a NIP-46 remote signer. Neither code holds a private key.

### Codes

| Code | Content | Size | QR (level L) |
|---|---|---|---|
| App code | `HTTPS://<LAUNCHER>/#` + radix-43 of the sealed pointer (spec §5 `url43`) | 103 B pointer | v5 binary, v6 as a camera link *(measured at 105 B)* |
| Home code | `https://<launcher>/#bunker://<signer-pubkey>?relay=<wss-url>&secret=<s>&home=<pod-url>` (NIP-46 plus `home`) | ~150 B | byte mode, about v7–v8 *(estimate)* |

The app code is public and works for any user. The home code is personal: whoever holds it can request signatures within the signer's policy.

### Sealed pointer (app code payload)

All integers are big-endian.

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 2 | magic | ASCII `QS` |
| 2 | 1 | version | `0x01` |
| 3 | 4 | blob length | byte length of the sealed blob |
| 7 | 32 | blob root | BEP 52 `pieces root` of the blob: SHA-256 merkle tree over 16 KiB blocks |
| 39 | 32 | content key | AES-256-GCM key, random per blob, **never derived from the content** |
| 71 | 32 | object ID | SHA-256 of the uncompressed payload (spec §3): envelope v1 `digest` |

The torrent identity is derived and not carried. The info dictionary is
`{file tree: {m: {"": {length, pieces root}}}, meta version: 2, name: "m", piece length: 16384}`,
and the v2 infohash is the SHA-256 of its bencoding. This reconstruction matches libtorrent 2.0.15 for files of 1 B, 775 B, 16,384 B, 16,385 B and 19,837 B. For blobs of at most 16 KiB, `pieces root` = SHA-256 of the blob.

### Sealed blob

- `COSE_Encrypt0` (RFC 9052, CBOR tag 16), with protected header `{1: 3}` (A256GCM) and unprotected header `{5: <12-byte IV>}`. The AAD is the RFC 9052 `Enc_structure` `["Encrypt0", protected, h'']`.
- Plaintext = `u32 n` ‖ envelope v1 (`n` bytes) ‖ zero padding to the size bucket: 16 KiB·2^k, at most 1 MiB + 4. The bucket hides the exact module size. It does not hide the size class.

### Launcher decode rules

Reject at the first failure. Nothing runs until rule 7 passes.

1. The fragment parses as a sealed pointer: magic, version, length ≤ 1 MiB + 4 KiB.
2. Fetch the blob from any source: local cache, then home web seed (HTTP + CORS), then BitTorrent swarm. **Sources are untrusted.**
3. The blob length and BEP 52 merkle root match the pointer.
4. COSE strict parse: tag 16, alg = A256GCM only, IV 12 bytes. AES-GCM decrypts with the pointer key under the `Enc_structure` AAD.
5. The padding frame is valid: `n` ≤ plaintext length − 4, and every pad byte is 0.
6. Envelope v1 decoder rules (spec §2.3): bounded decompression, length, then digest.
7. Envelope `digest` = pointer object ID. This is the key-commitment check: AES-GCM is not key-committing.
8. `kind` = `0x01`, and the module's imports are a subset of the launcher allowlist (empty for the pod).

### Runtime

- **Page (launcher):** parses the codes, fetches, verifies and unseals. It holds the NIP-46 client and, later, the WebTorrent client. Workers have no `RTCPeerConnection`; this was measured in Chrome 151.
- **Service worker:** receives the verified module bytes from the page, instantiates the pod (`experiments/minimal-pod`, policy entirely inside the hashed module), and serves same-origin `/pod/*`. State lives in IndexedDB. The node is **ephemeral**: it lives while its tab does.
- **Home pod** (the owner's main Solid server): web seed for blobs, NIP-98 write target and source of truth. The ephemeral node pushes writes home as NIP-98 `PUT`s signed through NIP-46 `sign_event`.
- **Pairing:** scan the home code → `connect(signer, secret)` with a fresh NIP-46 client keypair → `get_public_key` = pod owner. Store `{relay, signer, home, owner, client key}` in IndexedDB.
- **Signer policy:** sign only kind 27235 events whose `u` tag starts with `home`. The `secret` is single-use and binds the first client that connects.

### Trust and leakage

| Party | Learns or can do |
|---|---|
| Launcher origin | **Trusted.** It reads the fragment key. Mitigations: small auditable launcher, installed as a PWA, multiple origins |
| Blob sources (seeders, web seed, tracker, network) | Infohash, size bucket and peer IPs; never plaintext. A swapped blob fails rule 3 or 4 |
| Holder of the app code | Decrypts and runs the app. It's a bearer capability |
| Holder of the home code | Requests signatures within the signer policy until revoked at the signer. It's a bearer credential, not a key |
| Swarm observer holding the app code | IPs of everyone fetching that app. Use web seed only where this matters |

### Out of scope for draft 0

- Mesh links between ephemeral nodes.
- JavaScriptSolidServer plugins over torrent.
- Solid-OIDC, WAC/ACP and PATCH; the pod does LDP plus NIP-98 with a single owner.
- Phone camera behaviour (untested).

## Research direction
- QR objects transport code, data, dependencies and integrity metadata.
- Browser WebAssembly imports and exports enable progressive linking.
- Use QR level L, the minimum standardised error correction; standard QR has no zero-ECC mode.
- Content hashes prove integrity, **not provenance or trust**.
- Never put private keys in a QR code or in source control.

## Current work
- [docs/findings.md](docs/findings.md): measured results (QR counts for a minimal did:nostr pod, size ladder, Tiny Little Office comparison, solid-pod-rs integration).
- [docs/spec/qr-object-v1.md](docs/spec/qr-object-v1.md): envelope v1 with full SHA-256 IDs, framing, transports, pod mapping, threat model.
- [docs/adr/](docs/adr/): decisions 0001–0003.

## Resume here
1. Implement draft 0: `experiments/sealed-launcher/` (in progress).
2. Phone camera test of `url43` and of the home code.
3. WebTorrent v2 (BEP 52) support in browsers: unverified.
4. Recommendations for solid-pod-rs: CORS and range requests for the web seed, a content-addressed container, conditional requests, NIP-01 escaping. Not yet raised there.
5. Fuzz the pointer, COSE, envelope, frame and wire parsers.

## Reproduce
- `node experiments/dynamic-linking/test.mjs`: builds two tiny WASM binaries directly and tests linking in both arrival orders.
- `cd experiments/compression && npm ci && node bench.mjs`: the compression, capacity and envelope gate.
- `cd experiments/minimal-pod && cargo test --offline && node test.mjs`: the pod's BIP-340 and NIP-98 vectors.

Each experiment has its own README.

## Tiny Little Office reference
See [references/tiny-little-office.md](references/tiny-little-office.md). Upstream is MIT licensed; referenced via URL rather than copying or silently vendoring its source.

## Security
- Never execute arbitrary QR-delivered WASM with privileged host imports.
- Validate full digests, and enforce explicit import allowlists, budgets and publisher policy.
- QR scanning and URL fragments can leak through browser history, screenshots and link sharing.
- Both codes are bearer secrets.
