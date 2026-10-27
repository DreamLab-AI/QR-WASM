// Service-worker shell for the minimal did:nostr pod (src/lib.rs).
//
// The shell is cached origin code, never QR-delivered: the Service Worker
// spec registers only http(s) scripts. It does what the browser does natively
// — base64 and JSON.parse of the NIP-98 header, storage, decompression — and
// leaves every policy decision to the hashed module, which re-derives the
// NIP-01 serialisation from the fields given here and verifies the signature
// over it. Storage is the caller's: `handle` takes what is stored at the path
// and returns the single write to apply (IndexedDB in a worker, a Map in tests).

const encoder = new TextEncoder();
const fromBase64 = s => (Uint8Array.fromBase64 ? Uint8Array.fromBase64(s) : Uint8Array.from(atob(s), c => c.charCodeAt(0)));
const bytes = v => (v instanceof Uint8Array ? v : encoder.encode(String(v ?? '')));

export function writeFields(list) {
  const parts = list.map(bytes);
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const p of parts) { view.setUint32(at, p.length); out.set(p, at + 4); at += 4 + p.length; }
  return out;
}

export function readFields(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out = [];
  for (let at = 0; at < buf.length;) {
    const len = view.getUint32(at);
    out.push(buf.subarray(at + 4, at + 4 + len));
    at += 4 + len;
  }
  return out;
}

const isCount = n => Number.isSafeInteger(n) && n >= 0;
const isStrings = t => Array.isArray(t) && t.every(s => typeof s === 'string');

/** Parses `Authorization: Nostr <base64 event>`; null when absent or malformed. */
export function parseNip98(header) {
  if (!header?.startsWith('Nostr ')) return null;
  let ev;
  try { ev = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(fromBase64(header.slice(6).trim()))); } catch { return null; }
  const ok = ev && typeof ev === 'object' && ['id', 'pubkey', 'content', 'sig'].every(k => typeof ev[k] === 'string')
    && isCount(ev.created_at) && isCount(ev.kind) && Array.isArray(ev.tags) && ev.tags.every(isStrings);
  return ok ? ev : null;
}

export async function createPod(wasm, ownerHex) {
  const module = wasm instanceof WebAssembly.Module ? wasm : await WebAssembly.compile(wasm);
  const owner = Uint8Array.from(ownerHex.match(/../g), h => parseInt(h, 16));
  let x;
  const boot = () => {
    x = new WebAssembly.Instance(module, {}).exports;
    x.reset();
    const p = x.alloc(32);
    new Uint8Array(x.memory.buffer).set(owner, p);
    x.set_owner(p);
  };
  boot();

  /**
   * @param request {method, url, path, headers: {lower-case name: value}, body: Uint8Array, now: seconds}
   * @param stored  {kind: '' | 'resource' | 'container', contentType, body, children}
   */
  function handle(request, stored = {kind: ''}) {
    const h = request.headers ?? {};
    const ev = parseNip98(h.authorization);
    const tags = ev ? writeFields(ev.tags.map(t => writeFields(t))) : '';
    const wire = writeFields([
      request.method, request.url, request.path, h['content-type'], h['if-none-match'], h['if-match'],
      String(request.now), request.body ?? '', stored.kind, stored.contentType,
      stored.kind === 'container' ? stored.children.join('\n') : (stored.body ?? ''),
      ev?.id, ev?.pubkey, ev ? String(ev.created_at) : '', ev ? String(ev.kind) : '', tags, ev?.content, ev?.sig,
    ]);
    try {
      x.reset();
      const p = x.alloc(wire.length);
      new Uint8Array(x.memory.buffer).set(wire, p);
      const r = x.handle(p, wire.length);
      // Copy out before the next reset() can reclaim the response.
      const out = new Uint8Array(x.memory.buffer, Number(BigInt.asUintN(64, r) >> 32n), Number(BigInt.asUintN(64, r) & 0xffffffffn)).slice();
      const [code, headerText, body, op, opPath, opType, opBody] = readFields(out);
      const dec = new TextDecoder();
      const headers = Object.fromEntries(dec.decode(headerText).split('\n').filter(Boolean).map(l => l.split(/: (.*)/s).slice(0, 2)));
      return {status: Number(dec.decode(code)), headers, body,
        op: {kind: dec.decode(op), path: dec.decode(opPath), contentType: dec.decode(opType), body: opBody}};
    } catch (e) {
      // A trap leaves the instance in an unknown state: discard it.
      boot();
      return {status: 500, headers: {}, body: new Uint8Array(), op: {kind: ''}, error: String(e)};
    }
  }
  return {handle, exports: () => x};
}
