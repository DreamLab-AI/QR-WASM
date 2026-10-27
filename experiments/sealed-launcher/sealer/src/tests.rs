use super::testing::{seal_fixed, seal_plain};
use super::*;
use serde_json::{json, Value};

const MODULE: &[u8] = include_bytes!("../../../compression/fixtures/base45-oz-wasmopt.wasm");
const OTHER: &[u8] = include_bytes!("../../../compression/fixtures/base45-fmt-oz-wasmopt.wasm");
/// `(module (import "env" "f" (func)))`, built by hand: magic, version, type section, import section.
const IMPORTING: &[u8] = &[0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 2, 9, 1, 3, b'e', b'n', b'v', 1, b'f', 0, 0];

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors")
}

fn read_json(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(vectors_dir().join(name)).unwrap()).unwrap()
}

/// Same generator as tools/libtorrent-vectors.py and test/data.mjs.
fn vector_data(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u32;
    while out.len() < n {
        let mut seed = b"qrw-bep52".to_vec();
        seed.extend_from_slice(&(n as u32).to_be_bytes());
        seed.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(&sha256(&seed));
        i += 1;
    }
    out.truncate(n);
    out
}

#[test]
fn bep52_and_bep3_match_libtorrent() {
    let reference = read_json("bep52-libtorrent.json");
    for v in reference["vectors"].as_array().unwrap() {
        let n = v["length"].as_u64().unwrap() as usize;
        let data = vector_data(n);
        assert_eq!(hex::encode(sha256(&data)), v["sha256"], "generator, {n} B");
        let root = pieces_root(&data);
        assert_eq!(hex::encode(root), v["piecesRoot"], "pieces root, {n} B");
        assert_eq!(hex::encode(infohash_v2(n, &root)), v["infohashV2"], "v2 infohash, {n} B");
        assert_eq!(hex::encode(infohash_v1(&data)), v["infohashV1"], "v1 infohash, {n} B");
    }
}

#[test]
fn every_bucket_size_is_exact_and_blobs_are_block_aligned() {
    for len in [0, 1, 100, 16_000, 16_340, 16_341, 16_400, 40_000, 65_000, 65_600, 200_000, (1 << 20) + 43] {
        let s = seal_envelope(&vec![0xa5; len], [0; 32]);
        assert!(s.blob.len() % PIECE == 0 && s.blob.len().is_power_of_two(), "{len}: blob {}", s.blob.len());
        assert_eq!(s.blob.len(), bucket(len).0);
        assert_eq!(open(&s.blob, &s.key).unwrap().len(), bucket(len).1);
    }
    // The smallest bucket keeps one block, so its root is the blob's plain SHA-256.
    let s = seal_module(MODULE);
    assert_eq!(s.blob.len(), PIECE);
    assert_eq!(s.root, sha256(&s.blob));
}

#[test]
fn sealing_twice_uses_fresh_key_and_iv() {
    let (a, b) = (seal_module(MODULE), seal_module(MODULE));
    assert_ne!(a.key, b.key);
    assert_ne!(a.blob[8..20], b.blob[8..20], "IV");
    assert_ne!(a.root, b.root);
    assert_eq!(a.object_id, b.object_id, "object ID depends on content only");
}

#[test]
fn coset_opens_the_cose_wg_a256gcm_example() {
    let cases = read_json("cose-wg.json");
    let c = &cases["cases"][1];
    assert_eq!(c["alg"], "A256GCM");
    let cbor = hex::decode(c["cbor"].as_str().unwrap()).unwrap();
    let key: [u8; 32] = base64url(c["keyB64url"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(open(&cbor, &key).unwrap(), c["plaintext"].as_str().unwrap().as_bytes());
    let mut tampered = cbor.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(open(&tampered, &key).is_err());
}

fn base64url(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        bits = bits << 6 | A.iter().position(|&a| a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// Re-derives root and locator for a tampered blob, so the case reaches the rule it targets.
fn rehash(mut s: Sealed, blob: Vec<u8>) -> Sealed {
    s.root = pieces_root(&blob);
    s.locator = infohash_v1(&blob);
    s.blob = blob;
    s
}

#[test]
fn launcher_vectors() {
    let (k, iv) = ([7u8; 32], [9u8; 12]);
    let env = encode_envelope(KIND_WASM, MODULE, &[]);
    let id = sha256(MODULE);
    let good = seal_fixed(&env, id, k, iv);
    let (_, plain_len) = bucket(env.len());
    let mut cases: Vec<(&str, Sealed, bool, Value)> = Vec::new();
    let mut push = |name, s: Sealed, locator: bool, expect: Value| cases.push((name, s, locator, expect));

    push("valid module", good.clone(), false, json!("ok"));
    push("valid module with v1 locator", good.clone(), true, json!("ok"));
    // Rule 3: the blob does not match the pointer.
    let swapped = seal_fixed(&env, id, [8; 32], [10; 12]);
    push("swapped blob of the same length", Sealed { blob: swapped.blob, ..good.clone() }, false, json!(3));
    push("truncated blob", Sealed { blob: good.blob[..good.blob.len() - 1].to_vec(), ..good.clone() }, false, json!(3));
    // Rule 4: COSE profile or AEAD failure (root re-derived so rule 3 passes).
    push("wrong key", Sealed { key: [8; 32], ..good.clone() }, false, json!(4));
    let mut b = good.blob.clone();
    *b.last_mut().unwrap() ^= 1;
    push("flipped ciphertext byte", rehash(good.clone(), b), false, json!(4));
    let mut b = good.blob.clone();
    assert_eq!(&b[..6], &[0xd0, 0x83, 0x43, 0xa1, 0x01, 0x03]);
    b[5] = 0x01;
    push("protected header A128GCM", rehash(good.clone(), b), false, json!(4));
    let mut b = vec![0xd0, 0x83, 0x43, 0xa1, 0x01, 0x03, 0xa1, 0x05, 0x4b];
    b.extend_from_slice(&good.blob[9..20]);
    b.extend_from_slice(&good.blob[21..]);
    push("11-byte IV", rehash(good.clone(), b), false, json!(4));
    let mut b = good.blob.clone();
    b.push(0);
    push("trailing byte after COSE", rehash(good.clone(), b), false, json!(4));
    // Rule 5: padding frame.
    let mut p = pad(&env, plain_len);
    *p.last_mut().unwrap() = 1;
    push("non-zero padding", seal_plain(&p, k, iv, id), false, json!(5));
    let mut p = pad(&env, plain_len);
    p[..4].copy_from_slice(&(plain_len as u32).to_be_bytes());
    push("envelope length exceeds plaintext", seal_plain(&p, k, iv, id), false, json!(5));
    // Rule 6: envelope decoder.
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&vec![0u8; 1 << 16]).unwrap();
    let bomb_body = z.finish().unwrap();
    let mut bomb = b"QW\x01\x01\x01\x00".to_vec();
    bomb.extend_from_slice(&100u32.to_be_bytes());
    bomb.extend_from_slice(&sha256(&[0u8; 100]));
    bomb.push(0);
    bomb.extend_from_slice(&bomb_body);
    push("decompression bomb", seal_fixed(&bomb, sha256(&[0u8; 100]), k, iv), false, json!(6));
    let mut bad = env.clone();
    bad[10] ^= 1;
    let mut bad_id = id;
    bad_id[0] ^= 1;
    push("envelope digest mismatch", seal_fixed(&bad, bad_id, k, iv), false, json!(6));
    // Rule 7: a valid object, but not the one the pointer names (key commitment).
    let other_env = encode_envelope(KIND_WASM, OTHER, &[]);
    push("valid sealed envelope of another object", seal_fixed(&other_env, id, k, iv), false, json!(7));
    // Rule 8: what may run.
    push("module importing env.f", seal_fixed(&encode_envelope(KIND_WASM, IMPORTING, &[]), sha256(IMPORTING), k, iv), false, json!(8));
    push("opaque data, not a module", seal_fixed(&encode_envelope(0x02, MODULE, &[]), id, k, iv), false, json!(8));

    let rows: Vec<Value> = cases
        .iter()
        .map(|(name, s, locator, expect)| {
            json!({"name": name, "pointer": hex::encode(s.pointer(*locator)), "blob": b64(&s.blob), "expect": expect,
                   "objectId": hex::encode(s.object_id)})
        })
        .collect();
    let doc = serde_json::to_string_pretty(&json!({
        "note": "Generated by sealer `cargo test`; fixed keys and IVs are test-only. Module: experiments/compression/fixtures/base45-oz-wasmopt.wasm",
        "moduleSha256": hex::encode(id), "cases": rows})).unwrap() + "\n";
    let path = vectors_dir().join("sealed.json");
    if std::env::var_os("WRITE_VECTORS").is_some() {
        std::fs::write(&path, &doc).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(&path).expect("run once with WRITE_VECTORS=1"), doc, "vectors drifted");
    }
    // coset itself must open every case that is meant to pass rule 4.
    for (name, s, _, expect) in &cases {
        let opens = open(&s.blob, &s.key).is_ok();
        let past_rule4 = expect == "ok" || expect.as_u64().is_some_and(|r| r > 4);
        if !matches!(*name, "swapped blob of the same length" | "truncated blob") {
            assert_eq!(opens, past_rule4, "coset disagrees on {name}");
        }
    }
}
