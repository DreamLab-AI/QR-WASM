//! QR-WASM sealer: envelope v1 → padded plaintext → COSE_Encrypt0 (A256GCM)
//! → `QS` pointer, plus the BitTorrent identities the launcher derives.
//!
//! Cryptography is RustCrypto `aes-gcm` with keys and IVs from `OsRng`; COSE
//! framing and the RFC 9052 `Enc_structure` come from `coset`. Nothing here
//! implements a primitive. The fixed-key path used for test vectors exists
//! only under `cfg(test)`.

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use coset::{iana, CoseEncrypt0Builder, HeaderBuilder, TaggedCborSerializable};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Write;

pub const PIECE: usize = 16384;
pub const NAME: &str = "m";
pub const MAX_ENVELOPE_PAYLOAD: usize = 1 << 20;
pub const KIND_WASM: u8 = 0x01;

/// Fixed COSE bytes around the ciphertext: tag 16 + array(3) + bstr{1:3} + {5: bstr(12)}.
const COSE_FIXED: usize = 1 + 1 + 4 + 15;
const TAG: usize = 16;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Envelope v1 (spec §2) with the smaller of codec none and deflate-raw.
pub fn encode_envelope(kind: u8, payload: &[u8], deps: &[[u8; 32]]) -> Vec<u8> {
    assert!(payload.len() <= MAX_ENVELOPE_PAYLOAD, "payload over the v1 ceiling");
    assert!(deps.len() <= 255);
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(payload).expect("in-memory write");
    let deflated = z.finish().expect("in-memory finish");
    let (codec, body) = if deflated.len() < payload.len() { (0x01, deflated) } else { (0x00, payload.to_vec()) };
    let mut out = Vec::with_capacity(43 + 32 * deps.len() + body.len());
    out.extend_from_slice(b"QW");
    out.extend_from_slice(&[0x01, kind, codec, 0x00]);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&sha256(payload));
    out.push(deps.len() as u8);
    deps.iter().for_each(|d| out.extend_from_slice(d));
    out.extend_from_slice(&body);
    out
}

fn bstr_head(n: usize) -> usize {
    match n {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        _ => 5,
    }
}

/// Smallest bucket 16 KiB·2^k whose blob holds `envelope_len`; returns (blob length, plaintext length).
pub fn bucket(envelope_len: usize) -> (usize, usize) {
    let need = 4 + envelope_len;
    let mut blob = PIECE;
    loop {
        for head in [1, 2, 3, 5] {
            let Some(c) = blob.checked_sub(COSE_FIXED + head) else { continue };
            if bstr_head(c) == head && c >= TAG && c - TAG >= need {
                return (blob, c - TAG);
            }
        }
        blob *= 2;
    }
}

/// `u32 n ‖ envelope ‖ zeros` of exactly `plain_len` bytes.
pub fn pad(envelope: &[u8], plain_len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(plain_len);
    p.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    p.extend_from_slice(envelope);
    p.resize(plain_len, 0);
    p
}

fn seal_with(plain: &[u8], key: &[u8; 32], iv: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    CoseEncrypt0Builder::new()
        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::A256GCM).build())
        .unprotected(HeaderBuilder::new().iv(iv.to_vec()).build())
        .create_ciphertext(plain, b"", |pt, aad| {
            cipher.encrypt(Nonce::from_slice(iv), Payload { msg: pt, aad }).expect("AES-GCM encrypt")
        })
        .build()
        .to_tagged_vec()
        .expect("COSE serialisation")
}

/// Opens a sealed blob with coset + aes-gcm (the launcher's JS path is separate).
pub fn open(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let enc = coset::CoseEncrypt0::from_tagged_slice(blob).map_err(|e| e.to_string())?;
    if enc.protected.header.alg != Some(coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A256GCM)) {
        return Err("not A256GCM".into());
    }
    let iv = enc.unprotected.iv.clone();
    if iv.len() != 12 {
        return Err("IV must be 12 bytes".into());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    enc.decrypt(b"", |ct, aad| cipher.decrypt(Nonce::from_slice(&iv), Payload { msg: ct, aad }).map_err(|_| "AES-GCM tag".to_string()))
}

/// BEP 52 pieces root over 16 KiB blocks, zero-hash padding to a power of two.
pub fn pieces_root(data: &[u8]) -> [u8; 32] {
    assert!(!data.is_empty());
    let mut layer: Vec<[u8; 32]> = data.chunks(PIECE).map(sha256).collect();
    layer.resize(layer.len().next_power_of_two(), [0; 32]);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| sha256(&[p[0], p[1]].concat())).collect();
    }
    layer[0]
}

fn bstr(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(format!("{}:", b.len()).as_bytes());
    out.extend_from_slice(b);
}

/// v2 infohash from (length, root): the launcher's fixed info dictionary.
pub fn infohash_v2(length: usize, root: &[u8; 32]) -> [u8; 32] {
    let mut d = Vec::new();
    d.extend_from_slice(b"d");
    bstr(&mut d, b"file tree");
    d.extend_from_slice(b"d");
    bstr(&mut d, NAME.as_bytes());
    d.extend_from_slice(b"d");
    bstr(&mut d, b"");
    d.extend_from_slice(b"d");
    bstr(&mut d, b"length");
    d.extend_from_slice(format!("i{length}e").as_bytes());
    bstr(&mut d, b"pieces root");
    bstr(&mut d, root);
    d.extend_from_slice(b"eee"); // closes {length, pieces root}, {"": …}, {m: …}
    bstr(&mut d, b"meta version");
    d.extend_from_slice(b"i2e");
    bstr(&mut d, b"name");
    bstr(&mut d, NAME.as_bytes());
    bstr(&mut d, b"piece length");
    d.extend_from_slice(format!("i{PIECE}e").as_bytes());
    d.extend_from_slice(b"e");
    sha256(&d)
}

/// v1 infohash (locator only; SHA-1 is never trusted for integrity).
pub fn infohash_v1(data: &[u8]) -> [u8; 20] {
    let pieces: Vec<u8> = data.chunks(PIECE).flat_map(|c| Sha1::digest(c).to_vec()).collect();
    let mut d = Vec::new();
    d.extend_from_slice(b"d");
    bstr(&mut d, b"length");
    d.extend_from_slice(format!("i{}e", data.len()).as_bytes());
    bstr(&mut d, b"name");
    bstr(&mut d, NAME.as_bytes());
    bstr(&mut d, b"piece length");
    d.extend_from_slice(format!("i{PIECE}e").as_bytes());
    bstr(&mut d, b"pieces");
    bstr(&mut d, &pieces);
    d.extend_from_slice(b"e");
    Sha1::digest(&d).into()
}

/// A sealed blob and every field of its `QS` pointer.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
    pub key: [u8; 32],
    pub object_id: [u8; 32],
    pub locator: [u8; 20],
}

impl Sealed {
    /// `QS` v1 pointer bytes, with the v1 locator when asked.
    pub fn pointer(&self, with_locator: bool) -> Vec<u8> {
        let mut p = Vec::with_capacity(124);
        p.extend_from_slice(&[b'Q', b'S', 0x01, with_locator as u8]);
        p.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        p.extend_from_slice(&self.root);
        p.extend_from_slice(&self.key);
        p.extend_from_slice(&self.object_id);
        if with_locator {
            p.extend_from_slice(&self.locator);
        }
        p
    }
}

fn finish(blob: Vec<u8>, key: [u8; 32], object_id: [u8; 32]) -> Sealed {
    Sealed { root: pieces_root(&blob), locator: infohash_v1(&blob), blob, key, object_id }
}

/// Seals an envelope under a fresh random key and IV.
pub fn seal_envelope(envelope: &[u8], object_id: [u8; 32]) -> Sealed {
    let key: [u8; 32] = Aes256Gcm::generate_key(OsRng).into();
    let iv: [u8; 12] = Aes256Gcm::generate_nonce(OsRng).into();
    let (blob_len, plain_len) = bucket(envelope.len());
    let blob = seal_with(&pad(envelope, plain_len), &key, &iv);
    assert_eq!(blob.len(), blob_len, "bucket arithmetic disagrees with coset encoding");
    finish(blob, key, object_id)
}

/// Seals a WebAssembly module (kind 0x01) as one object.
pub fn seal_module(module: &[u8]) -> Sealed {
    seal_envelope(&encode_envelope(KIND_WASM, module, &[]), sha256(module))
}

/// `url43` app link: alphanumeric origin, byte `#`, alphanumeric radix-43 pointer.
pub fn base43(bytes: &[u8]) -> String {
    const A: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:";
    let mut out = String::new();
    for pair in bytes.chunks(2) {
        let (mut n, digits) = if pair.len() == 2 { ((pair[0] as u32) << 8 | pair[1] as u32, 3) } else { (pair[0] as u32, 2) };
        for _ in 0..digits {
            out.push(A[(n % 43) as usize] as char);
            n /= 43;
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    /// Deterministic sealing for committed vectors only; unreachable from the CLI.
    pub fn seal_fixed(envelope: &[u8], object_id: [u8; 32], key: [u8; 32], iv: [u8; 12]) -> Sealed {
        let (_, plain_len) = bucket(envelope.len());
        finish(seal_with(&pad(envelope, plain_len), &key, &iv), key, object_id)
    }
    pub fn seal_plain(plain: &[u8], key: [u8; 32], iv: [u8; 12], object_id: [u8; 32]) -> Sealed {
        finish(seal_with(plain, &key, &iv), key, object_id)
    }
}

#[cfg(test)]
mod tests;
