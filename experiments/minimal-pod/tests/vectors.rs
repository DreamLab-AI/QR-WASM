//! Generates and checks the pod's test vectors natively.
//!
//! NIP-98 events are signed with k256 (fixed keys, zero aux_rand, fixed
//! clock), so `vectors/nip98.json` is deterministic: this test fails if the
//! committed file drifts, and `WRITE_VECTORS=1 cargo test` rewrites it. The
//! Node harness (`../test.mjs`) replays the same file through the JS shell
//! against every committed WebAssembly rung.

use base64::Engine;
use k256::schnorr::SigningKey;
use qrwasm_minimal_pod::pod::{self, Event, Request, Stored};
use qrwasm_minimal_pod::verify_bip340;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_790_000_000;
const ORIGIN: &str = "https://pod.example";

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32]).unwrap()
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Signs `canonical` (or the module's own canonical form) and returns the event JSON.
fn event(sk: &SigningKey, created_at: u64, tags: Vec<Vec<&str>>, content: &str, canonical: Option<String>) -> Value {
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let ev = Event { id: "", pubkey: &pubkey, created_at, kind: pod::KIND_HTTP_AUTH, tags: tags.clone(), content, sig: "" };
    let ours = pod::canonical(&ev);
    let serialised = canonical.unwrap_or_else(|| {
        // Independent check: for strings without C0 controls, serde_json and NIP-01 agree.
        if !content.chars().any(|c| (c as u32) < 0x20) {
            let theirs = serde_json::to_string(&json!([0, pubkey, created_at, pod::KIND_HTTP_AUTH, tags, content])).unwrap();
            assert_eq!(ours, theirs, "canonical form disagrees with serde_json");
        }
        ours
    });
    let id = Sha256::digest(serialised.as_bytes());
    let sig = sk.sign_raw(&id, &[0u8; 32]).unwrap();
    json!({"id": hex::encode(id), "pubkey": pubkey, "created_at": created_at, "kind": pod::KIND_HTTP_AUTH,
           "tags": tags, "content": content, "sig": hex::encode(sig.to_bytes())})
}

fn header(ev: &Value) -> String {
    format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(ev.to_string()))
}

fn put_auth(sk: &SigningKey, path: &str, body: &[u8], created_at: u64) -> String {
    let url = format!("{ORIGIN}{path}");
    let payload = sha_hex(body);
    header(&event(sk, created_at, vec![vec!["u", &url], vec!["method", "PUT"], vec!["payload", &payload]], "", None))
}

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    headers: Value,
    body: &'static [u8],
    stored: Value,
    status: u16,
    op: &'static str,
}

fn cases() -> (String, Vec<Case>) {
    let owner = key(1);
    let stranger = key(2);
    let owner_hex = hex::encode(owner.verifying_key().to_bytes());
    let module: &'static [u8] = b"\0asm\x01\0\0\0";
    let stored_module = json!({"kind": "resource", "contentType": "application/wasm", "body": b64(module)});
    let tag = format!("\"{}\"", sha_hex(module));
    let put = |sk: &SigningKey, created_at| json!({"authorization": put_auth(sk, "/a.wasm", module, created_at), "content-type": "application/wasm"});
    let mut bad_sig = event(&owner, NOW, vec![vec!["u", "https://pod.example/a.wasm"], vec!["method", "PUT"], vec!["payload", &sha_hex(module)]], "", None);
    let s = bad_sig["sig"].as_str().unwrap().to_owned();
    bad_sig["sig"] = json!(format!("{}{}", if s.starts_with('0') { "1" } else { "0" }, &s[1..]));
    let wrong_url = header(&event(&owner, NOW, vec![vec!["u", "https://evil.example/a.wasm"], vec!["method", "PUT"], vec!["payload", &sha_hex(module)]], "", None));
    let wrong_payload = header(&event(&owner, NOW, vec![vec!["u", "https://pod.example/a.wasm"], vec!["method", "PUT"], vec!["payload", &sha_hex(b"other")]], "", None));
    let delete = header(&event(&owner, NOW, vec![vec!["u", "https://pod.example/a.wasm"], vec!["method", "DELETE"]], "", None));
    let delete_container = header(&event(&owner, NOW, vec![vec!["u", "https://pod.example/c/"], vec!["method", "DELETE"]], "", None));
    // NIP-01: only seven characters are escaped; U+0001 goes out verbatim.
    let tricky = "q\"b\\n\nc\u{1}é";
    let tricky_tags = vec![vec!["u", "https://pod.example/a.wasm"], vec!["method", "PUT"], vec!["payload", "PAYLOAD"]];
    let payload = sha_hex(module);
    let with_payload = |t: &Vec<Vec<&'static str>>| -> Vec<Vec<String>> {
        t.iter().map(|v| v.iter().map(|s| if *s == "PAYLOAD" { payload.clone() } else { s.to_string() }).collect()).collect()
    };
    let tt = with_payload(&tricky_tags);
    let tt_ref: Vec<Vec<&str>> = tt.iter().map(|v| v.iter().map(String::as_str).collect()).collect();
    let nip01_literal = format!(
        "[0,\"{owner_hex}\",{NOW},27235,[[\"u\",\"https://pod.example/a.wasm\"],[\"method\",\"PUT\"],[\"payload\",\"{payload}\"]],\"q\\\"b\\\\n\\nc\u{1}é\"]"
    );
    let nip01 = header(&event(&owner, NOW, tt_ref.clone(), tricky, Some(nip01_literal)));
    let json_stringify_style = serde_json::to_string(&json!([0, owner_hex, NOW, 27235, tt_ref, tricky])).unwrap();
    assert!(json_stringify_style.contains("\\u0001"));
    let stringify = header(&event(&owner, NOW, tt_ref, tricky, Some(json_stringify_style)));
    let none = json!({"kind": ""});
    let cases = vec![
        Case { name: "GET empty root container", method: "GET", path: "/", headers: json!({}), body: b"", stored: json!({"kind": "container", "children": []}), status: 200, op: "" },
        Case { name: "GET container lists children", method: "GET", path: "/c/", headers: json!({}), body: b"", stored: json!({"kind": "container", "children": ["a.wasm", "d/"]}), status: 200, op: "" },
        Case { name: "GET absent resource", method: "GET", path: "/a.wasm", headers: json!({}), body: b"", stored: none.clone(), status: 404, op: "" },
        Case { name: "PUT by owner creates", method: "PUT", path: "/a.wasm", headers: put(&owner, NOW), body: module, stored: none.clone(), status: 201, op: "put" },
        Case { name: "PUT by owner replaces", method: "PUT", path: "/a.wasm", headers: put(&owner, NOW - 30), body: module, stored: stored_module.clone(), status: 204, op: "put" },
        Case { name: "GET resource", method: "GET", path: "/a.wasm", headers: json!({}), body: b"", stored: stored_module.clone(), status: 200, op: "" },
        Case { name: "HEAD resource", method: "HEAD", path: "/a.wasm", headers: json!({}), body: b"", stored: stored_module.clone(), status: 200, op: "" },
        Case { name: "GET If-None-Match current ETag", method: "GET", path: "/a.wasm", headers: json!({"if-none-match": tag}), body: b"", stored: stored_module.clone(), status: 304, op: "" },
        Case { name: "PUT without auth", method: "PUT", path: "/a.wasm", headers: json!({}), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT with malformed auth", method: "PUT", path: "/a.wasm", headers: json!({"authorization": "Nostr !!!"}), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT with bad signature", method: "PUT", path: "/a.wasm", headers: json!({"authorization": header(&bad_sig)}), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT by non-owner", method: "PUT", path: "/a.wasm", headers: put(&stranger, NOW), body: module, stored: none.clone(), status: 403, op: "" },
        Case { name: "PUT with stale event", method: "PUT", path: "/a.wasm", headers: put(&owner, NOW - 61), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT with event from the future", method: "PUT", path: "/a.wasm", headers: put(&owner, NOW + 61), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT signed for another URL", method: "PUT", path: "/a.wasm", headers: json!({"authorization": wrong_url}), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT with payload hash mismatch", method: "PUT", path: "/a.wasm", headers: json!({"authorization": wrong_payload}), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "PUT If-None-Match * over existing", method: "PUT", path: "/a.wasm", headers: json!({"authorization": put_auth(&owner, "/a.wasm", module, NOW), "if-none-match": "*"}), body: module, stored: stored_module.clone(), status: 412, op: "" },
        Case { name: "PUT If-Match stale ETag", method: "PUT", path: "/a.wasm", headers: json!({"authorization": put_auth(&owner, "/a.wasm", module, NOW), "if-match": "\"00\""}), body: module, stored: stored_module.clone(), status: 412, op: "" },
        Case { name: "PUT event content with NIP-01 escapes", method: "PUT", path: "/a.wasm", headers: json!({"authorization": nip01}), body: module, stored: none.clone(), status: 201, op: "put" },
        Case { name: "PUT event signed with \\u0001 escaping is rejected", method: "PUT", path: "/a.wasm", headers: json!({"authorization": stringify}), body: module, stored: none.clone(), status: 401, op: "" },
        Case { name: "DELETE by owner", method: "DELETE", path: "/a.wasm", headers: json!({"authorization": delete.clone()}), body: b"", stored: stored_module.clone(), status: 204, op: "delete" },
        Case { name: "DELETE absent", method: "DELETE", path: "/a.wasm", headers: json!({"authorization": delete}), body: b"", stored: none.clone(), status: 404, op: "" },
        Case { name: "DELETE container", method: "DELETE", path: "/c/", headers: json!({"authorization": delete_container}), body: b"", stored: json!({"kind": "container", "children": []}), status: 405, op: "" },
        Case { name: "GET path with dot-dot", method: "GET", path: "/c/../a.wasm", headers: json!({}), body: b"", stored: none.clone(), status: 400, op: "" },
        Case { name: "GET path with empty segment", method: "GET", path: "/c//a.wasm", headers: json!({}), body: b"", stored: none.clone(), status: 400, op: "" },
        Case { name: "POST not allowed", method: "POST", path: "/c/", headers: json!({}), body: b"x", stored: none, status: 405, op: "" },
    ];
    (owner_hex, cases)
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Mirrors the JS shell: parse the Authorization header natively, pass fields.
fn run(owner: &[u8; 32], c: &Case) -> pod::Response {
    let h = |k: &str| c.headers[k].as_str().unwrap_or("");
    let parsed: Option<Value> = h("authorization")
        .strip_prefix("Nostr ")
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok());
    let tags: Vec<Vec<String>> = parsed.as_ref().and_then(|e| serde_json::from_value(e["tags"].clone()).ok()).unwrap_or_default();
    let auth = parsed.as_ref().and_then(|e| {
        Some(Event {
            id: e["id"].as_str()?, pubkey: e["pubkey"].as_str()?, created_at: e["created_at"].as_u64()?, kind: e["kind"].as_u64()?,
            tags: tags.iter().map(|t| t.iter().map(String::as_str).collect()).collect(), content: e["content"].as_str()?, sig: e["sig"].as_str()?,
        })
    });
    let body_store;
    let children: Vec<&str>;
    let stored = match c.stored["kind"].as_str().unwrap() {
        "resource" => {
            body_store = base64::engine::general_purpose::STANDARD.decode(c.stored["body"].as_str().unwrap()).unwrap();
            Stored::Resource { content_type: c.stored["contentType"].as_str().unwrap(), body: &body_store }
        }
        "container" => {
            children = c.stored["children"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            Stored::Container { children }
        }
        _ => Stored::Absent,
    };
    let url = format!("{ORIGIN}{}", c.path);
    let req = Request {
        method: c.method, url: &url, path: c.path, content_type: h("content-type"), if_none_match: h("if-none-match"),
        if_match: h("if-match"), now: NOW, body: c.body, stored, auth,
    };
    pod::handle(owner, &req)
}

#[test]
fn nip98_vectors() {
    let (owner_hex, cases) = cases();
    let mut owner = [0u8; 32];
    hex::decode_to_slice(&owner_hex, &mut owner).unwrap();
    let mut out = Vec::new();
    for c in &cases {
        let res = run(&owner, c);
        let op = match &res.op {
            pod::Op::None => "",
            pod::Op::Put { .. } => "put",
            pod::Op::Delete { .. } => "delete",
        };
        assert_eq!((res.status, op), (c.status, c.op), "{}", c.name);
        if c.name == "GET container lists children" {
            let doc: Value = serde_json::from_slice(&res.body).expect("listing is JSON");
            assert_eq!(doc["ldp:contains"], json!([{"@id": "/c/a.wasm"}, {"@id": "/c/d/"}]));
        }
        if c.method == "HEAD" {
            assert!(res.body.is_empty());
        }
        out.push(json!({
            "name": c.name, "request": {"method": c.method, "url": format!("{ORIGIN}{}", c.path), "path": c.path,
            "headers": c.headers, "body": b64(c.body)}, "stored": c.stored,
            "expect": {"status": c.status, "op": c.op, "body": if res.body.is_empty() { Value::Null } else { json!(b64(&res.body)) }},
        }));
    }
    let doc = serde_json::to_string_pretty(&json!({"owner": owner_hex, "now": NOW, "cases": out})).unwrap() + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/nip98.json");
    if std::env::var_os("WRITE_VECTORS").is_some() {
        std::fs::write(path, &doc).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(path).expect("run with WRITE_VECTORS=1 once"), doc, "vectors drifted");
    }
}

#[test]
fn bip340_vectors() {
    let csv = include_str!("../vectors/bip340-test-vectors.csv");
    let mut n = 0;
    for line in csv.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        let (mut pk, mut sig) = ([0u8; 32], [0u8; 64]);
        let msg = hex::decode(f[4]).unwrap();
        let expected = f[6] == "TRUE";
        // Rows with an off-curve or out-of-range key cannot even be parsed: they must verify false.
        let parsed = hex::decode_to_slice(f[2], &mut pk).is_ok() && hex::decode_to_slice(f[5], &mut sig).is_ok();
        assert_eq!(parsed && verify_bip340(&pk, &msg, &sig), expected, "BIP-340 vector {}", f[0]);
        n += 1;
    }
    assert_eq!(n, 19);
}
