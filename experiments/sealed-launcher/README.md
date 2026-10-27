# Sealed launcher (draft 0)

This experiment implements the "Sealed single-QR bootstrap" in the [top-level README](../../README.md). A public **app code** boots the did:nostr pod (`../minimal-pod`, rung P2) as an encrypted, content-addressed blob into a browser service worker. A private **home code** pairs the node with a NIP-46 remote signer and the owner's home pod.

## Layout

| Path | What |
|---|---|
| `sealer/` | Rust CLI `qrw-seal`, built on `coset` 0.3.8 and `aes-gcm` 0.10.3 with `OsRng` keys and IVs. It writes envelope v1 → padded plaintext → `COSE_Encrypt0` and prints the `QS` pointer and app link. It also contains an independent BEP 52 / BEP 3 implementation |
| `web/lib/` | Isomorphic launcher libraries on WebCrypto: `pointer`, `base43`, `bep52`, `cose` (strict A256GCM profile), `envelope` (bounded inflate), `unseal` (rules 3–8), `codes` (fragment parsing, home scope), `podstore`, `idb` |
| `web/launcher.mjs`, `web/sw.mjs`, `web/index.html` | The launcher page, and the service worker that runs the pod at `/pod/*` |
| `test/harness/` | NIP-01 relay (verifies signatures), test NIP-46 signer with the draft-0 policy, home pod (the same P2 module in Node, CORS, web seed) and static launcher server |
| `test/*.test.mjs` | Unit gates (`npm test`) |
| `test/e2e.mjs` | Chrome gate over raw CDP |
| `vectors/` | `bep52-libtorrent.json` (libtorrent 2.0.15), `cose-wg.json` (cose-wg/Examples `53c9d63`, public domain), `sealed.json` (16 launcher cases), `qr-measured.json`. NIP-44 vectors are fetched at test time and checked against the checksum NIP-44 publishes |

## Run

```sh
npm ci && npm run build                 # nostr-tools bundle for the browser (web/vendor/, gitignored)
(cd sealer && cargo test && cargo build --release)
npm test                                # unit gates (46 checks)
node test/e2e.mjs                       # Chrome gate; needs docker access to the browsercontainer sidecar
WRITE_VECTORS=1 cargo test              # in sealer/: regenerate vectors/sealed.json
```

To regenerate the libtorrent vectors, run `python -I tools/libtorrent-vectors.py <workdir> > vectors/bep52-libtorrent.json` with libtorrent 2.0.15 from pip.

The e2e driver serves ports 8800 (launcher), 8801 (home pod) and 8802 (relay) on this host, and forwards them onto the sidecar's `localhost` with `socat`, which it removes on exit. `localhost` is a secure context, and service workers and WebCrypto require one.

## What the gates prove

| Gate | Result |
|---|---|
| BEP 52 root, v2 infohash from (length, root) alone, v1 infohash | match libtorrent for 9 sizes, in both JS and Rust |
| Strict COSE profile | accepts cose-wg `AES-GCM-ENC-03` byte for byte; rejects `ENC-01` and `ENC-04` by profile, and decrypts or fails them correctly in the core |
| Launcher rules | 16 sealed vectors. The 2 valid cases decode, match the digest and compile; each negative fails at its intended rule: swapped or truncated blob (3); wrong key, flipped byte, A128GCM, 11-byte IV, trailing byte (4); bad padding (5); decompression bomb, digest mismatch (6); another object (7); module with imports, opaque data (8). coset agrees on every case that reaches rule 4 |
| Sealer | buckets are exact powers of two × 16 KiB; sealing twice gives a fresh key, IV and root |
| QR round trip (jsQR) | app code **v6** (104 B pointer), **v7** with the v1 locator, home code **v9** (215 B) |
| NIP-44 | all 8 official v2 vector groups (nostr-tools), plus the extended-prefix boundary table from NIP-44 itself. The key schedule is checked by recomputing the HMAC and ChaCha20 decryption with Node's crypto, because nostr-tools does not export it |
| Signer (test harness) | scope = parsed origin + path prefix (10 refusal cases); secret single-use; unbound client refused; owner = user key ≠ bunker key; `get_public_key` after session restore without reconnect |
| Chrome 151 e2e | 12/12 steps (`e2e-results.json`): pair; boot from web seed; signed write-through; LDP listing; unsigned and forged writes refused; policy refusals; cold worker restart with data intact; **a module corrupted in IndexedDB refused on cold start before compiling**; cache re-boot; wrong key → rule 4 **with no new boot, instantiation or boot-record change**; unseeded → rule 2; home code single-use |

Five checks were mutation-tested, each broken once and then restored: rule 7, the pad check, the signer scope check, the worker's persistence and the worker's re-hash. Each break turned exactly the matching case red. The other checks are covered by their vectors but were not mutation-tested.

## Findings from building it

- **The NIP-44 vector file is partly stale.** Its `invalid.encrypt_msg_lengths` lists 65,536, 100,000 and 10,000,000 bytes as invalid. Current NIP-44 (nips `0b54c4d`, `44.md:87-91`) allows up to 2³²−1 bytes with a 6-byte prefix, and nostr-tools 2.25.2 follows the spec. The test keeps the still-invalid length 0 and checks the spec's own boundary vectors instead.

- **WebTorrent 3.0.21 is BitTorrent v1 only** (`parse-torrent` requires `info.pieces`). A browser cannot derive the swarm identity from the pointer, so `QS` v1 can carry a 20-byte v1 infohash as a *locator* (flags bit 0). Integrity still comes from the SHA-256 root, the AEAD and the object ID. The torrent transport itself is not built.
- **Same-document navigation.** Opening an app link in a tab that is already on the launcher changes only the fragment, so no page load happens. The launcher handles `hashchange`.
- **One signature, two writes.** The worker passes `url = home + path` into the module, so the ephemeral pod is a write-through replica of the home namespace, and the NIP-98 event that authorises the local write also authorises the push home. The pod module has no replay cache, so the same event is accepted by both servers, and again by either within its ±60 s window.
- **Bucket alignment.** Padding is sized so that the *blob*, not the plaintext, is 16 KiB·2^k. The pod's blob is 32 KiB (two blocks); a module under about 16 KiB keeps root = SHA-256(blob).

## Not built

- Torrent transport (WebTorrent, wss tracker, BEP 19 range requests).
- Mesh links between ephemeral nodes.
- A NIP-46 signer outside the test harness.
- Phone camera tests.
