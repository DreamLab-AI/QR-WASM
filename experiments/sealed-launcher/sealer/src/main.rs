//! `qrw-seal <module.wasm> --origin HTTPS://LAUNCHER.EXAMPLE/ --out <dir> [--locator]`
//!
//! Seals the module under a fresh random key, writes the blob to
//! `<dir>/<pieces-root-hex>` (the web-seed path), and prints the pointer and
//! app link as JSON on stdout. The key is printed because the app link *is*
//! the capability: treat stdout as secret.

use std::process::exit;

fn usage() -> ! {
    eprintln!("usage: qrw-seal <module.wasm> --origin <UPPER-CASE ORIGIN ENDING IN '/'> --out <dir> [--locator]");
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut module, mut origin, mut out, mut locator) = (None, None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--origin" => origin = it.next().cloned(),
            "--out" => out = it.next().cloned(),
            "--locator" => locator = true,
            _ if module.is_none() => module = Some(a.clone()),
            _ => usage(),
        }
    }
    let (Some(module), Some(origin), Some(out)) = (module, origin, out) else { usage() };
    // The origin goes into an alphanumeric QR segment: only these characters survive.
    if !origin.ends_with('/') || !origin.bytes().all(|b| b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:".contains(&b)) {
        eprintln!("origin must be upper-case QR-alphanumeric and end in '/', e.g. HTTPS://LAUNCHER.EXAMPLE/");
        exit(2);
    }
    let bytes = std::fs::read(&module).unwrap_or_else(|e| {
        eprintln!("{module}: {e}");
        exit(1)
    });
    if bytes.len() > qrw_seal::MAX_ENVELOPE_PAYLOAD {
        eprintln!("module exceeds the 1 MiB envelope ceiling");
        exit(1);
    }
    let sealed = qrw_seal::seal_module(&bytes);
    let root = hex::encode(sealed.root);
    std::fs::create_dir_all(&out).and_then(|_| std::fs::write(std::path::Path::new(&out).join(&root), &sealed.blob)).unwrap_or_else(|e| {
        eprintln!("{out}: {e}");
        exit(1)
    });
    let pointer = sealed.pointer(locator);
    println!(
        "{}",
        serde_json::json!({
            "appLink": format!("{origin}#{}", qrw_seal::base43(&pointer)),
            "origin": origin,
            "pointer": hex::encode(&pointer),
            "pointerBytes": pointer.len(),
            "blobLength": sealed.blob.len(),
            "piecesRoot": root,
            "objectId": hex::encode(sealed.object_id),
            "infohashV2": hex::encode(qrw_seal::infohash_v2(sealed.blob.len(), &sealed.root)),
            "infohashV1": hex::encode(sealed.locator),
        })
    );
}
