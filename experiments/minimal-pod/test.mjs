// Replays the committed vectors through the JS shell against every WebAssembly
// rung in fixtures/, then reports sizes and QR frame counts for the rungs that
// pass. Exits non-zero if any rung fails any vector. `--write` saves results.json.
import assert from 'node:assert/strict';
import {readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import zlib from 'node:zlib';
import {createPod} from './shell.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const vectors = JSON.parse(readFileSync(`${here}vectors/nip98.json`, 'utf8'));
const bip340 = readFileSync(`${here}vectors/bip340-test-vectors.csv`, 'utf8').trim().split('\n').slice(1).map(l => l.split(','));
const hex = s => Uint8Array.from(s.match(/../g) ?? [], h => parseInt(h, 16));
const b64 = s => Uint8Array.from(Buffer.from(s, 'base64'));
const fixtures = readdirSync(`${here}fixtures`).filter(f => f.endsWith('.wasm')).sort();

// QR-WASM v1 (docs/spec/qr-object-v1.md): 43-byte envelope + 39-byte frame header, binary transport, level L.
const BYTE_L = {10: 271, 15: 520, 25: 1273, 40: 2953};
const frames = envelope => Object.fromEntries(Object.entries(BYTE_L).map(([v, c]) => [`v${v}`, envelope <= c ? 1 : Math.ceil(envelope / (c - 39))]));

const results = {};
let failures = 0;
for (const name of fixtures) {
  const bytes = readFileSync(`${here}fixtures/${name}`);
  const failed = [];
  const pod = await createPod(bytes, vectors.owner);
  const x = pod.exports();

  // BIP-340 through the raw export.
  for (const [index, , pk, , msg, sig, result] of bip340) {
    x.reset();
    const m = hex(msg), at = x.alloc(32 + 64 + Math.max(m.length, 1));
    const mem = new Uint8Array(x.memory.buffer);
    mem.set(hex(pk).subarray(0, 32), at); mem.set(hex(sig), at + 32); mem.set(m, at + 96);
    if (x.schnorr_verify(at, at + 96, m.length, at + 32) !== (result === 'TRUE' ? 1 : 0)) failed.push(`BIP-340 vector ${index}`);
  }

  if (x.handle) {
    const run = () => {
      for (const c of vectors.cases) {
        const r = pod.handle({...c.request, body: b64(c.request.body), now: vectors.now},
          {...c.stored, body: c.stored.body && b64(c.stored.body)});
        try {
          assert.equal(r.status, c.expect.status);
          assert.equal(r.op.kind, c.expect.op);
          if (c.expect.body) assert.deepEqual(Buffer.from(r.body), Buffer.from(c.expect.body, 'base64'));
          if (c.expect.op === 'put') assert.equal(r.op.path, c.request.path);
        } catch (e) { failed.push(`${c.name}: ${e.message.split('\n')[0]}${r.error ? ` (${r.error})` : ''}`); }
      }
    };
    run(); run(); // the second pass reuses the instance: reset() must leave no state behind
    const big = new Uint8Array(1 << 20).fill(7);
    const put = pod.handle({method: 'PUT', url: 'https://pod.example/big', path: '/big', headers: {}, body: big, now: vectors.now});
    if (put.status !== 401) failed.push(`1 MiB unauthenticated PUT gave ${put.status}`);
    const get = pod.handle({method: 'GET', url: 'https://pod.example/big', path: '/big', headers: {}, now: vectors.now},
      {kind: 'resource', contentType: 'application/octet-stream', body: big});
    if (get.status !== 200 || !Buffer.from(get.body).equals(Buffer.from(big))) failed.push(`1 MiB GET gave ${get.status}`);
  }

  const deflate = zlib.deflateRawSync(bytes, {level: 9}).length;
  const brotli = zlib.brotliCompressSync(bytes, {params: {[zlib.constants.BROTLI_PARAM_QUALITY]: 11}}).length;
  results[name] = {pod: Boolean(x.handle), passed: failed.length === 0, wasm: bytes.length, deflate, brotli,
    framesDeflate: frames(43 + deflate), framesBrotli: frames(43 + brotli)};
  failures += failed.length;
  console.error(`${failed.length ? 'FAIL' : 'PASS'} ${name}${failed.length ? `\n  ${failed.join('\n  ')}` : ''}`);
}
console.log(JSON.stringify(results, null, 2));
if (process.argv.includes('--write')) {
  writeFileSync(`${here}results.json`, JSON.stringify({node: process.version, zlib: process.versions.zlib,
    toolchain: readFileSync(`${here}fixtures/TOOLCHAIN`, 'utf8').trim().split('\n'), cases: vectors.cases.length,
    bip340: bip340.length, results}, null, 2) + '\n');
}
process.exit(failures ? 1 : 0);
