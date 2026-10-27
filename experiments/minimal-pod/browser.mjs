// In-browser counterparts of test.mjs. Serve this directory over HTTP, open any
// page on that origin, and run `(await import('/browser.mjs')).replay()`.
// `probe()` needs a secure context (https or localhost) for WebCrypto, so it is
// pasted into a page such as https://example.com instead of imported.
import {createPod} from './shell.mjs';

const RUNGS = ['P1-pod-k256', 'P2-pod-k256-bump', 'P3-pod-k256-bump-ia', 'P4-pod-secp-bump',
  'V1-verify-k256', 'V2-verify-k256-bump', 'V3-verify-k256-bump-ia', 'V4-verify-secp-bump'];

export async function replay() {
  const vectors = await (await fetch('/vectors/nip98.json')).json();
  const csv = (await (await fetch('/vectors/bip340-test-vectors.csv')).text()).trim().split('\n').slice(1).map(l => l.split(','));
  const hex = s => Uint8Array.from(s.match(/../g) ?? [], h => parseInt(h, 16));
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const out = {};
  for (const n of RUNGS) {
    const pod = await createPod(new Uint8Array(await (await fetch(`/fixtures/${n}.wasm`)).arrayBuffer()), vectors.owner);
    const x = pod.exports();
    const failed = [];
    for (const [i, , pk, , msg, sig, res] of csv) {
      x.reset();
      const m = hex(msg), at = x.alloc(96 + Math.max(m.length, 1));
      const mem = new Uint8Array(x.memory.buffer);
      mem.set(hex(pk), at); mem.set(hex(sig), at + 32); mem.set(m, at + 96);
      if (x.schnorr_verify(at, at + 96, m.length, at + 32) !== (res === 'TRUE' ? 1 : 0)) failed.push(`bip340 ${i}`);
    }
    let cases = 0;
    if (x.handle) for (const c of vectors.cases) {
      const r = pod.handle({...c.request, body: Uint8Array.fromBase64(c.request.body), now: vectors.now},
        {...c.stored, body: c.stored.body && Uint8Array.fromBase64(c.stored.body)});
      cases++;
      if (r.status !== c.expect.status || r.op.kind !== c.expect.op
        || (c.expect.body && !eq(r.body, Uint8Array.fromBase64(c.expect.body)))) failed.push(`${c.name}: ${r.status}`);
    }
    out[n] = {bip340: csv.length, cases, failed};
  }
  return {browser: navigator.userAgent.match(/(Chrome|Firefox|Version)\/[\d.]+/)?.[0], rungs: out};
}

// Paste-able: `(${probe})()` in a secure-context page.
export async function probe() {
  const out = {ua: navigator.userAgent, secure: isSecureContext, decompression: {}, compression: {}};
  for (const f of ['gzip', 'deflate', 'deflate-raw', 'brotli', 'zstd']) {
    try { new DecompressionStream(f); out.decompression[f] = true; } catch (e) { out.decompression[f] = e.name; }
  }
  for (const f of ['deflate-raw', 'brotli', 'zstd']) {
    try { new CompressionStream(f); out.compression[f] = true; } catch (e) { out.compression[f] = e.name; }
  }
  out.fromBase64 = typeof Uint8Array.fromBase64 === 'function';
  const hex = s => Uint8Array.from(s.match(/../g), h => parseInt(h, 16));
  try { // RFC 8032 §7.1 TEST 1
    const key = await crypto.subtle.importKey('raw', hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'), {name: 'Ed25519'}, false, ['verify']);
    out.ed25519Rfc8032Test1 = await crypto.subtle.verify('Ed25519', key, hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'), new Uint8Array());
  } catch (e) { out.ed25519Rfc8032Test1 = String(e); }
  for (const curve of ['K-256', 'secp256k1']) {
    try { await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: curve}, false, ['sign']); out[`ecdsa-${curve}`] = true; } catch (e) { out[`ecdsa-${curve}`] = e.name; }
  }
  out.jspi = typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function';
  out.barcodeDetector = 'BarcodeDetector' in self ? await BarcodeDetector.getSupportedFormats() : false;
  out.serviceWorker = 'serviceWorker' in navigator;
  out.opfs = typeof navigator.storage?.getDirectory === 'function';
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:';
  location.hash = `v1/${alphabet}`;
  out.hashPreserved43 = location.hash === `#v1/${alphabet}`;
  history.replaceState(null, '', location.pathname);
  return out;
}
