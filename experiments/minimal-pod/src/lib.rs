//! Size probe: the smallest did:nostr-owned Solid-style pod that runs as one
//! WebAssembly module behind a browser service worker.
//!
//! The module is a pure function. The shell (`../shell.mjs`) hands it one
//! request together with whatever is stored at that path, and applies the single
//! write it returns. Service workers are stopped when idle, so persistence stays
//! in the shell (IndexedDB) while every policy decision — path rules, LDP status
//! codes, NIP-98 verification, the owner check — stays inside the hashed module.
//!
//! Wire format, both directions: a sequence of fields, each a big-endian `u32`
//! length followed by that many bytes.
//!
//! Request fields: method, absolute URL, path, Authorization, Content-Type,
//! If-None-Match, If-Match, now (decimal Unix seconds), body, stored kind
//! (`""`, `"resource"` or `"container"`), stored Content-Type, stored body or
//! newline-separated child names.
//!
//! Response fields: status (decimal), headers (`Name: value\n`…), body, write
//! op (`""`, `"put"` or `"delete"`), op path, op Content-Type, op body.
//!
//! Cargo features pick the Schnorr backend (`k256` or `libsecp256k1`), whether
//! the pod logic is included (`pod`; without it only `schnorr_verify` is
//! exported), and `bump`, a per-request bump allocator.

extern crate alloc;

use alloc::vec::Vec;
#[cfg(feature = "pod")]
use alloc::{format, string::String};

#[cfg(all(feature = "k256", feature = "libsecp256k1"))]
compile_error!("choose one Schnorr backend");

/// Verifies a BIP-340 signature over an arbitrary-length message.
pub fn verify_bip340(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    #[cfg(feature = "k256")]
    {
        use k256::schnorr::{Signature, VerifyingKey};
        let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(pubkey), Signature::try_from(&sig[..])) else {
            return false;
        };
        key.verify_raw(msg, &sig).is_ok()
    }
    #[cfg(feature = "libsecp256k1")]
    {
        use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
        let Ok(key) = XOnlyPublicKey::from_byte_array(*pubkey) else { return false };
        let sig = Signature::from_byte_array(*sig);
        Secp256k1::verification_only().verify_schnorr(&sig, msg, &key).is_ok()
    }
}

// --- Wire format --------------------------------------------------------------

/// Splits a length-prefixed field sequence; `None` if it is malformed.
pub fn read_fields(mut buf: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
        let field = buf.get(4..4 + len)?;
        out.push(field);
        buf = &buf[4 + len..];
    }
    Some(out)
}

/// Joins fields into the length-prefixed wire format.
pub fn write_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 4).sum());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

// --- Pod ----------------------------------------------------------------------

#[cfg(feature = "pod")]
pub mod pod {
    use super::*;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    /// NIP-98 HTTP auth event kind.
    pub const KIND_HTTP_AUTH: u64 = 27235;
    /// Largest accepted clock skew between the event and `now`, in seconds.
    pub const MAX_SKEW: u64 = 60;

    /// The write the shell must apply after sending the response.
    #[derive(Debug, PartialEq)]
    pub enum Op {
        None,
        Put { path: String, content_type: String, body: Vec<u8> },
        Delete { path: String },
    }

    /// What the shell holds at the request path.
    pub enum Stored<'a> {
        Absent,
        Resource { content_type: &'a str, body: &'a [u8] },
        Container { children: Vec<&'a str> },
    }

    /// One HTTP request plus the stored state it applies to.
    pub struct Request<'a> {
        pub method: &'a str,
        pub url: &'a str,
        pub path: &'a str,
        pub authorization: &'a str,
        pub content_type: &'a str,
        pub if_none_match: &'a str,
        pub if_match: &'a str,
        pub now: u64,
        pub body: &'a [u8],
        pub stored: Stored<'a>,
    }

    #[derive(Debug)]
    pub struct Response {
        pub status: u16,
        pub headers: Vec<(&'static str, String)>,
        pub body: Vec<u8>,
        pub op: Op,
    }

    fn status(status: u16) -> Response {
        Response { status, headers: Vec::new(), body: Vec::new(), op: Op::None }
    }

    fn etag(body: &[u8]) -> String {
        format!("\"{}\"", hex::encode(Sha256::digest(body)))
    }

    /// Absolute, normalised, printable ASCII, at most 1 KiB.
    pub fn valid_path(path: &str) -> bool {
        path.len() <= 1024
            && path.starts_with('/')
            && path.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'\\')
            && !path[1..].split('/').enumerate().any(|(i, s)| {
                s == "." || s == ".." || (s.is_empty() && i + 1 != path[1..].split('/').count())
            })
    }

    fn header_safe(v: &str) -> bool {
        v.len() <= 256 && v.bytes().all(|b| (0x20..0x7f).contains(&b))
    }

    /// Verifies a NIP-98 `Authorization: Nostr <base64 event>` header against
    /// this request and returns the signer's x-only public key.
    pub fn nip98(req: &Request) -> Result<[u8; 32], &'static str> {
        use base64::Engine;
        let b64 = req.authorization.strip_prefix("Nostr ").ok_or("scheme")?;
        let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).map_err(|_| "base64")?;
        let ev: Value = serde_json::from_slice(&raw).map_err(|_| "json")?;
        let kind = ev["kind"].as_u64().ok_or("kind")?;
        let created_at = ev["created_at"].as_u64().ok_or("created_at")?;
        let (pubkey, content, tags) = (ev["pubkey"].as_str().ok_or("pubkey")?, ev["content"].as_str().ok_or("content")?, &ev["tags"]);
        if kind != KIND_HTTP_AUTH {
            return Err("kind");
        }
        if created_at.abs_diff(req.now) > MAX_SKEW {
            return Err("stale");
        }
        let tag = |name: &str| {
            tags.as_array()?.iter().find_map(|t| match t.as_array()?.as_slice() {
                [Value::String(n), Value::String(v), ..] if n == name => Some(v.as_str()),
                _ => None,
            })
        };
        if tag("u") != Some(req.url) || tag("method") != Some(req.method) {
            return Err("binding");
        }
        if !req.body.is_empty() && tag("payload") != Some(hex::encode(Sha256::digest(req.body)).as_str()) {
            return Err("payload");
        }
        // NIP-01 id over the canonical serialisation, as solid-pod-rs-nostr computes it.
        let canonical = serde_json::to_string(&json!([0, pubkey, created_at, kind, tags, content])).map_err(|_| "json")?;
        let id = Sha256::digest(canonical.as_bytes());
        let mut claimed = [0u8; 32];
        hex::decode_to_slice(ev["id"].as_str().ok_or("id")?, &mut claimed).map_err(|_| "id")?;
        if claimed != id[..] {
            return Err("id");
        }
        let (mut pk, mut sig) = ([0u8; 32], [0u8; 64]);
        hex::decode_to_slice(pubkey, &mut pk).map_err(|_| "pubkey")?;
        hex::decode_to_slice(ev["sig"].as_str().ok_or("sig")?, &mut sig).map_err(|_| "sig")?;
        if !verify_bip340(&pk, &id, &sig) {
            return Err("signature");
        }
        Ok(pk)
    }

    /// The whole pod: one request in, one response and at most one write out.
    pub fn handle(owner: &[u8; 32], req: &Request) -> Response {
        if !valid_path(req.path) {
            return status(400);
        }
        let container = req.path.ends_with('/');
        match req.method {
            "GET" | "HEAD" => {
                let mut res = match (&req.stored, container) {
                    (Stored::Resource { content_type, body }, false) => {
                        let tag = etag(body);
                        if req.if_none_match == tag {
                            let mut r = status(304);
                            r.headers.push(("ETag", tag));
                            return r;
                        }
                        let mut r = status(200);
                        r.headers.push(("Content-Type", String::from(*content_type)));
                        r.headers.push(("ETag", tag));
                        r.headers.push(("Link", String::from("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")));
                        r.body = body.to_vec();
                        r
                    }
                    (Stored::Container { children }, true) => {
                        let contains: Vec<Value> = children.iter().map(|c| json!({"@id": format!("{}{}", req.path, c)})).collect();
                        let doc = json!({
                            "@context": {"ldp": "http://www.w3.org/ns/ldp#"},
                            "@id": req.path,
                            "@type": ["ldp:Container", "ldp:BasicContainer"],
                            "ldp:contains": contains,
                        });
                        let mut r = status(200);
                        r.body = serde_json::to_vec(&doc).unwrap_or_default();
                        r.headers.push(("Content-Type", String::from("application/ld+json")));
                        r.headers.push(("ETag", etag(&r.body)));
                        r.headers.push(("Link", String::from("<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")));
                        r
                    }
                    _ => status(404),
                };
                if req.method == "HEAD" {
                    res.body.clear();
                }
                res
            }
            "PUT" | "DELETE" => {
                let signer = match nip98(req) {
                    Ok(pk) => pk,
                    Err(_) => {
                        let mut r = status(401);
                        r.headers.push(("WWW-Authenticate", String::from("Nostr")));
                        return r;
                    }
                };
                if &signer != owner {
                    return status(403);
                }
                if container {
                    return status(405);
                }
                let current = match &req.stored {
                    Stored::Resource { body, .. } => Some(etag(body)),
                    _ => None,
                };
                if (req.if_none_match == "*" && current.is_some())
                    || (!req.if_match.is_empty() && current.as_deref() != Some(req.if_match))
                {
                    return status(412);
                }
                if req.method == "DELETE" {
                    if current.is_none() {
                        return status(404);
                    }
                    let mut r = status(204);
                    r.op = Op::Delete { path: String::from(req.path) };
                    return r;
                }
                let content_type = if req.content_type.is_empty() { "application/octet-stream" } else { req.content_type };
                if !header_safe(content_type) {
                    return status(400);
                }
                let mut r = status(if current.is_some() { 204 } else { 201 });
                r.headers.push(("ETag", etag(req.body)));
                r.op = Op::Put { path: String::from(req.path), content_type: String::from(content_type), body: req.body.to_vec() };
                r
            }
            _ => {
                let mut r = status(405);
                r.headers.push(("Allow", String::from("GET, HEAD, PUT, DELETE")));
                r
            }
        }
    }

    /// Decodes a wire request, runs [`handle`], and encodes the response.
    pub fn handle_wire(owner: &[u8; 32], wire: &[u8]) -> Vec<u8> {
        let parsed = read_fields(wire).filter(|f| f.len() == 12).and_then(|f| {
            let s = |i: usize| core::str::from_utf8(f[i]).ok();
            let stored = match s(9)? {
                "" => Stored::Absent,
                "resource" => Stored::Resource { content_type: s(10)?, body: f[11] },
                "container" => Stored::Container { children: s(11)?.split('\n').filter(|c| !c.is_empty()).collect() },
                _ => return None,
            };
            let req = Request {
                method: s(0)?, url: s(1)?, path: s(2)?, authorization: s(3)?, content_type: s(4)?,
                if_none_match: s(5)?, if_match: s(6)?, now: s(7)?.parse().ok()?, body: f[8], stored,
            };
            Some(handle(owner, &req))
        });
        let res = parsed.unwrap_or_else(|| status(400));
        let mut headers = String::new();
        for (k, v) in &res.headers {
            headers.push_str(k);
            headers.push_str(": ");
            headers.push_str(v);
            headers.push('\n');
        }
        let code = format!("{}", res.status);
        let (op, path, ctype, body): (&[u8], &[u8], &[u8], &[u8]) = match &res.op {
            Op::None => (b"", b"", b"", b""),
            Op::Put { path, content_type, body } => (b"put", path.as_bytes(), content_type.as_bytes(), body),
            Op::Delete { path } => (b"delete", path.as_bytes(), b"", b""),
        };
        write_fields(&[code.as_bytes(), headers.as_bytes(), &res.body, op, path, ctype, body])
    }
}

// --- WebAssembly exports ------------------------------------------------------

#[cfg(feature = "bump")]
mod bump {
    //! Per-request bump allocator: `free` is a no-op and [`reset`] reclaims everything.
    //! Sound only because the shell calls `reset` before each request and nothing
    //! the module allocates outlives the response it returns.
    use core::alloc::{GlobalAlloc, Layout};
    use core::arch::wasm32::{memory_grow, memory_size};

    extern "C" {
        static __heap_base: u8;
    }
    static mut NEXT: usize = 0;

    pub struct Bump;

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if NEXT == 0 {
                NEXT = core::ptr::addr_of!(__heap_base) as usize;
            }
            let start = (NEXT + layout.align() - 1) & !(layout.align() - 1);
            let end = match start.checked_add(layout.size()) {
                Some(e) => e,
                None => return core::ptr::null_mut(),
            };
            let have = memory_size(0) * 65536;
            if end > have && memory_grow(0, (end - have).div_ceil(65536)) == usize::MAX {
                return core::ptr::null_mut();
            }
            NEXT = end;
            start as *mut u8
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }

    pub fn reset() {
        unsafe { NEXT = 0 }
    }
}

#[cfg(feature = "bump")]
#[global_allocator]
static ALLOC: bump::Bump = bump::Bump;

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::*;

    static mut OWNER: [u8; 32] = [0; 32];

    /// Reclaims every allocation (bump builds); a no-op otherwise.
    #[no_mangle]
    pub extern "C" fn reset() {
        #[cfg(feature = "bump")]
        bump::reset();
    }

    #[no_mangle]
    pub extern "C" fn alloc(len: usize) -> *mut u8 {
        let mut v = Vec::<u8>::with_capacity(len);
        let p = v.as_mut_ptr();
        core::mem::forget(v);
        p
    }

    #[no_mangle]
    pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
        drop(Vec::from_raw_parts(ptr, 0, len));
    }

    /// BIP-340 verification: 32-byte key, message, 64-byte signature. Returns 1 if valid.
    #[no_mangle]
    pub unsafe extern "C" fn schnorr_verify(pk: *const u8, msg: *const u8, msg_len: usize, sig: *const u8) -> i32 {
        let pk = &*(pk as *const [u8; 32]);
        let sig = &*(sig as *const [u8; 64]);
        verify_bip340(pk, core::slice::from_raw_parts(msg, msg_len), sig) as i32
    }

    /// Sets the pod owner's x-only public key (32 bytes).
    #[no_mangle]
    pub unsafe extern "C" fn set_owner(pk: *const u8) {
        OWNER = *(pk as *const [u8; 32]);
    }

    /// Handles one wire request; returns `ptr << 32 | len` of the wire response.
    #[cfg(feature = "pod")]
    #[no_mangle]
    pub unsafe extern "C" fn handle(ptr: *const u8, len: usize) -> u64 {
        let owner = *core::ptr::addr_of!(OWNER);
        let out = pod::handle_wire(&owner, core::slice::from_raw_parts(ptr, len)).leak();
        ((out.as_ptr() as u64) << 32) | out.len() as u64
    }
}
