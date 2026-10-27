// QR-WASM compression and capacity gate. Measures the committed fixtures against
// envelope v1 (docs/spec/qr-object-v1.md) and exits non-zero if any check fails.
// Every number the spec and findings quote comes from this script's output.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import zlib from 'node:zlib';
import QRCode from 'qrcode';

const here = fileURLToPath(new URL('.', import.meta.url));
const sha = b => createHash('sha256').update(b).digest();
const checks = [];
const check = (name, fn) => {
  try { fn(); checks.push({name, ok: true}); }
  catch (e) { checks.push({name, ok: false, error: e.message}); }
};

// --- Spec v1 constants (docs/spec/qr-object-v1.md §2, §4) -------------------
const ENVELOPE_MAGIC = Buffer.from('QW');
const FRAME_MAGIC = Buffer.from('QF');
const VERSION = 1;
const CODEC = {none: 0, 'deflate-raw': 1};
const ENVELOPE_FIXED = 2 + 1 + 1 + 1 + 1 + 4 + 32 + 1; // magic ver kind codec flags len digest ndeps
const DEP_BYTES = 32;
const FRAME_HEADER = 2 + 1 + 2 + 2 + 32;                // magic ver index total digest
const MAX_UNCOMPRESSED = 1 << 20;                     // spec §2.3 decoder ceiling
const URL_PREFIX = 'https://qr.example/#v1/';         // spec §5 fragment form (placeholder origin)

// --- Cited QR capacity at ECC level L ---------------------------------------
// Thonky, "Character Capacities by Version, Mode, and Error Correction",
// https://www.thonky.com/qr-code-tutorial/character-capacities (ISO/IEC 18004 table)
const CITED_L = {10: [395, 271], 15: [758, 520], 20: [1249, 858], 25: [1853, 1273], 30: [2520, 1732], 40: [4296, 2953]};
const VERSIONS = [10, 15, 20, 25, 30, 40];

// --- Encoders ---------------------------------------------------------------
const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
function base45Encode(bytes) {
  let out = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    let n = bytes[i] * 256 + bytes[i + 1];
    for (let k = 0; k < 3; k++) { out += B45[n % 45]; n = Math.floor(n / 45); }
  }
  if (bytes.length % 2) { const n = bytes[bytes.length - 1]; out += B45[n % 45] + B45[Math.floor(n / 45)]; }
  return out;
}
function base45Decode(str) {
  if (str.length % 3 === 1) throw new Error('base45: bad length');
  const out = [];
  for (let i = 0; i < str.length; i += 3) {
    const chunk = str.slice(i, i + 3);
    let n = 0, scale = 1;
    for (const c of chunk) {
      const v = B45.indexOf(c);
      if (v < 0) throw new Error('base45: bad character');
      n += v * scale; scale *= 45;
    }
    if (chunk.length === 3) { if (n > 0xffff) throw new Error('base45: overflow'); out.push(n >> 8, n & 0xff); }
    else { if (n > 0xff) throw new Error('base45: overflow'); out.push(n); }
  }
  return Buffer.from(out);
}
const deflateRaw = (b, dictionary) => zlib.deflateRawSync(b, {level: 9, ...(dictionary && {dictionary})});
const brotli = b => zlib.brotliCompressSync(b, {params: {
  [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
  [zlib.constants.BROTLI_PARAM_SIZE_HINT]: b.length,
}});

// --- Envelope v1 ------------------------------------------------------------
function encodeObject(module, {kind = 1, deps = []} = {}) {
  const candidates = [[CODEC.none, module], [CODEC['deflate-raw'], deflateRaw(module)]];
  const [codec, body] = candidates.reduce((a, b) => (b[1].length < a[1].length ? b : a));
  const head = Buffer.alloc(ENVELOPE_FIXED);
  ENVELOPE_MAGIC.copy(head, 0);
  head[2] = VERSION; head[3] = kind; head[4] = codec; head[5] = 0;
  head.writeUInt32BE(module.length, 6);
  sha(module).copy(head, 10);
  head[42] = deps.length;
  return Buffer.concat([head, ...deps, body]);
}
function decodeObject(env) {
  if (env.length < ENVELOPE_FIXED || !env.subarray(0, 2).equals(ENVELOPE_MAGIC)) throw new Error('not an envelope');
  if (env[2] !== VERSION) throw new Error('unsupported version');
  if (env[5] !== 0) throw new Error('reserved flags set');
  const length = env.readUInt32BE(6);
  if (length > MAX_UNCOMPRESSED) throw new Error('declared length over ceiling');
  const digest = env.subarray(10, 42);
  const ndeps = env[42];
  const bodyAt = ENVELOPE_FIXED + ndeps * DEP_BYTES;
  if (env.length < bodyAt) throw new Error('truncated dependency list');
  const deps = Array.from({length: ndeps}, (_, i) => env.subarray(ENVELOPE_FIXED + i * DEP_BYTES, ENVELOPE_FIXED + (i + 1) * DEP_BYTES));
  const body = env.subarray(bodyAt);
  let module;
  if (env[4] === CODEC.none) module = body;
  else if (env[4] === CODEC['deflate-raw']) module = zlib.inflateRawSync(body, {maxOutputLength: length});
  else throw new Error('unknown codec');
  if (module.length !== length) throw new Error('length mismatch');
  if (!sha(module).equals(digest)) throw new Error('digest mismatch');
  return {kind: env[3], digest, deps, module};
}

// --- Framing v1 -------------------------------------------------------------
const transports = {
  binary: {capacity: v => cap[v].byte, wrap: f => [{data: f, mode: 'byte'}], frameBytes: c => c},
  base45: {capacity: v => cap[v].alnum, wrap: f => [{data: base45Encode(f), mode: 'alphanumeric'}],
    frameBytes: c => Math.floor(c / 3) * 2 + (c % 3 === 2 ? 1 : 0)},
  url: {capacity: v => cap[v].byte, wrap: f => [{data: Buffer.from(URL_PREFIX + f.toString('base64url')), mode: 'byte'}],
    frameBytes: c => Math.floor((c - URL_PREFIX.length) * 3 / 4)},
};
function frameObject(env, transport, version) {
  const per = transports[transport].frameBytes(transports[transport].capacity(version)) - FRAME_HEADER;
  const digest = env.subarray(10, 42);
  const total = Math.ceil(env.length / per);
  if (total > 0xffff) throw new Error('too many frames');
  return Array.from({length: total}, (_, i) => {
    const head = Buffer.alloc(FRAME_HEADER);
    FRAME_MAGIC.copy(head, 0); head[2] = VERSION;
    head.writeUInt16BE(i, 3); head.writeUInt16BE(total, 5); digest.copy(head, 7);
    return Buffer.concat([head, env.subarray(i * per, (i + 1) * per)]);
  });
}
function reassemble(frames) {
  const parts = new Map();
  let digest, total;
  for (const f of frames) {
    if (!f.subarray(0, 2).equals(FRAME_MAGIC) || f[2] !== VERSION) throw new Error('not a frame');
    const i = f.readUInt16BE(3), t = f.readUInt16BE(5), d = f.subarray(7, 39);
    digest ??= d; total ??= t;
    if (!d.equals(digest) || t !== total || i >= t) throw new Error('frame from another object');
    if (parts.has(i) && !parts.get(i).equals(f)) throw new Error('conflicting duplicate frame');
    parts.set(i, f);
  }
  if (parts.size !== total) throw new Error('missing frames');
  const env = Buffer.concat([...Array(total).keys()].map(i => parts.get(i).subarray(FRAME_HEADER)));
  const obj = decodeObject(env);
  if (!obj.digest.equals(digest)) throw new Error('frame digest disagrees with envelope');
  return obj;
}

// --- QR capacity, probed from a real encoder --------------------------------
const fits = (segments, version) => { try { QRCode.create(segments, {errorCorrectionLevel: 'L', version}); return true; } catch { return false; } };
function probe(version, make) {
  let lo = 0, hi = 8000;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (fits(make(mid), version)) lo = mid; else hi = mid - 1; }
  return lo;
}
const cap = {};
for (const v of VERSIONS) cap[v] = {
  byte: probe(v, n => [{data: Buffer.alloc(n, 0xa5), mode: 'byte'}]),
  alnum: probe(v, n => [{data: 'A'.repeat(n), mode: 'alphanumeric'}]),
};
check('QR capacity probe matches cited ISO/IEC 18004 table (level L)', () => {
  for (const v of VERSIONS) assert.deepEqual([cap[v].alnum, cap[v].byte], CITED_L[v], `version ${v}`);
});

// --- Fixtures ---------------------------------------------------------------
// The hand-built pair from experiments/dynamic-linking/test.mjs; digests pinned to its output.
const hand = {
  provider: Buffer.from('0061736d0100000001060160017f017f03020100070a010673717561726500000a09010700200020006c0b', 'hex'),
  consumer: Buffer.from('0061736d0100000001060160017f017f020e0103656e7606737175617265000003020100070b0107636f6d7075746500010a0b0109002000100041016a0b', 'hex'),
};
const fixtures = {
  ...hand,
  'base45-oz': readFileSync(`${here}fixtures/base45-oz.wasm`),
  'base45-oz-wasmopt': readFileSync(`${here}fixtures/base45-oz-wasmopt.wasm`),
  'base45-fmt-oz': readFileSync(`${here}fixtures/base45-fmt-oz.wasm`),
  'base45-fmt-oz-wasmopt': readFileSync(`${here}fixtures/base45-fmt-oz-wasmopt.wasm`),
};
check('hand fixtures match dynamic-linking digests', () => {
  assert.equal(sha(hand.provider).toString('hex'), 'c853de413e6d8e118a0fd95e3ff2aafdbd65b311744a5731d4256362d41fe897');
  assert.equal(sha(hand.consumer).toString('hex'), '658da855614d3ab3fd373edc41204afea24d406bc13a6a16b13ca77c714e48e1');
});
for (const [name, bytes] of Object.entries(fixtures)) check(`fixture ${name} is valid WebAssembly`, () => assert.ok(WebAssembly.validate(bytes)));

// RFC 9285 §4.3 examples, then the Rust fixture must agree with the JS codec.
const RFC9285 = [['AB', 'BB8'], ['Hello!!', '%69 VD92EX0'], ['base-45', 'UJCLQE7W581'], ['ietf!', 'QED8WEX0']];
check('base45 matches RFC 9285 examples and round-trips', () => {
  for (const [plain, enc] of RFC9285) {
    assert.equal(base45Encode(Buffer.from(plain)), enc);
    assert.equal(base45Decode(enc).toString(), plain);
  }
  assert.throws(() => base45Decode('GGW'), /overflow/); // 65535 < 'GGW' per RFC 9285 §6
});
const rust = new WebAssembly.Instance(new WebAssembly.Module(fixtures['base45-oz-wasmopt'])).exports;
check('Rust base45 fixture agrees with the JS codec', () => {
  for (const [plain, enc] of RFC9285) {
    const mem = new Uint8Array(rust.memory.buffer);
    mem.set(Buffer.from(plain), rust.input_ptr());
    const n = rust.encode(plain.length);
    assert.equal(Buffer.from(rust.memory.buffer, rust.output_ptr(), n).toString(), enc);
  }
});
check('Rust fmt fixture executes', () => {
  const fmt = new WebAssembly.Instance(new WebAssembly.Module(fixtures['base45-fmt-oz-wasmopt'])).exports;
  assert.ok(fmt.describe(2048n, 0.5) > 0);
});

// --- Compression measurements -----------------------------------------------
const compression = {};
for (const [name, bytes] of Object.entries(fixtures)) {
  const d = deflateRaw(bytes).length, br = brotli(bytes).length;
  compression[name] = {raw: bytes.length, 'deflate-raw': d, brotli: br,
    ratioDeflate: +(d / bytes.length).toFixed(3), ratioBrotli: +(br / bytes.length).toFixed(3)};
}
// TLO primes deflate with a frozen dictionary. For WASM the natural dictionary is a
// module the receiver already holds: measure the fmt build against the plain build.
const primed = deflateRaw(fixtures['base45-fmt-oz-wasmopt'], fixtures['base45-oz-wasmopt']).length;
compression['base45-fmt-oz-wasmopt'].deflateWithCachedDependency = primed;
check('codec selection never inflates an envelope beyond codec none', () => {
  for (const bytes of Object.values(fixtures)) assert.ok(encodeObject(bytes).length <= ENVELOPE_FIXED + bytes.length);
});
check('tiny modules do not benefit from compression (codec none is chosen)', () => {
  for (const name of ['provider', 'consumer']) assert.equal(encodeObject(fixtures[name])[4], CODEC.none, name);
});

// --- Envelope and decoder rules ---------------------------------------------
const rng = n => { const out = []; for (let i = 0; out.length * 32 < n; i++) out.push(sha(Buffer.from(`qr-wasm-${i}`))); return Buffer.concat(out).subarray(0, n); };
const incompressible = rng(2048);
const dep = sha(hand.provider);
check('envelope round-trips every fixture', () => {
  for (const bytes of Object.values(fixtures)) assert.ok(decodeObject(encodeObject(bytes, {deps: [dep]})).module.equals(bytes));
});
check('decoder rejects a decompression bomb', () => {
  const env = encodeObject(Buffer.alloc(1 << 16));
  env.writeUInt32BE(100, 6); // claims 100 bytes; inflates to 64 KiB
  assert.throws(() => decodeObject(env), /RangeError|length|buffer/i);
});
check('decoder rejects a declared length over the ceiling', () => {
  const env = encodeObject(Buffer.alloc(16)); env.writeUInt32BE(MAX_UNCOMPRESSED + 1, 6);
  assert.throws(() => decodeObject(env), /ceiling/);
});
check('decoder rejects a tampered payload', () => {
  const env = encodeObject(incompressible); env[env.length - 1] ^= 1;
  assert.throws(() => decodeObject(env), /digest mismatch/);
});
check('decoder rejects truncated and foreign input', () => {
  assert.throws(() => decodeObject(Buffer.from('QW')), /not an envelope/);
  const env = encodeObject(incompressible); env[2] = 2;
  assert.throws(() => decodeObject(env), /unsupported version/);
});

// --- Framing: frames needed, verified by encoding each frame at its version --
const frameTable = {};
const subjects = {'incompressible-2048': incompressible, ...fixtures};
for (const [name, bytes] of Object.entries(subjects)) {
  const env = encodeObject(bytes, {deps: [dep]});
  frameTable[name] = {envelope: env.length};
  for (const t of Object.keys(transports)) for (const v of VERSIONS) {
    const frames = frameObject(env, t, v);
    frameTable[name][`${t}@v${v}`] = frames.length;
    if (name === 'incompressible-2048' || name === 'base45-fmt-oz-wasmopt') {
      check(`${name} ${t} frames encode at v${v}-L`, () => frames.forEach(f => assert.ok(fits(transports[t].wrap(f), v))));
    }
  }
}
check('frames reassemble shuffled and duplicated', () => {
  const env = encodeObject(fixtures['base45-fmt-oz-wasmopt'], {deps: [dep]});
  const frames = frameObject(env, 'binary', 15);
  const shuffled = [...frames.slice(1), frames[0], frames[2]].reverse();
  assert.ok(reassemble(shuffled).module.equals(fixtures['base45-fmt-oz-wasmopt']));
});
check('reassembly rejects a frame from another object and missing frames', () => {
  const a = frameObject(encodeObject(incompressible), 'binary', 10);
  const b = frameObject(encodeObject(rng(2049)), 'binary', 10);
  assert.throws(() => reassemble([...a.slice(1), b[0]]), /another object/);
  assert.throws(() => reassemble(a.slice(1)), /missing/);
});

// Spec §9 acceptance criteria: incompressible 2 KiB module with one dependency.
const AC = {'binary@v15': 5, 'binary@v25': 2, 'base45@v25': 2, 'url@v25': 3, 'binary@v40': 1};
check('spec §9 frame-count acceptance criteria hold', () => {
  for (const [k, n] of Object.entries(AC)) assert.equal(frameTable['incompressible-2048'][k], n, k);
});

// --- Provenance sizing (ADR-0002): NIP-94 kind 1063 event committing to the digest
// Hex fields are pseudo-random so compression sees realistic entropy (about 4 bits per character).
const hexOf = (seed, n) => sha(Buffer.from(seed)).toString('hex').repeat(2).slice(0, n);
const event = {id: hexOf('id', 64), pubkey: hexOf('pubkey', 64), created_at: 1790000000, kind: 1063,
  tags: [['x', sha(hand.provider).toString('hex')], ['m', 'application/wasm']], content: '', sig: hexOf('sig', 64) + hexOf('sig2', 64)};
const eventJson = Buffer.from(JSON.stringify(event));
const provenanceEnvelope = encodeObject(eventJson, {kind: 4, deps: [dep]});
const provenance = {
  nip01EventJsonBytes: eventJson.length,
  provenanceEnvelopeBytes: provenanceEnvelope.length,
  packedTrailerBytes: 32 + 8 + 64, // pubkey, created_at u64, sig; id, tags and content are reconstructed
};
check('provenance object (kind 0x04) fits one bare v15-L binary symbol', () => {
  assert.ok(fits([{data: provenanceEnvelope, mode: 'byte'}], 15));
});

// --- Report -----------------------------------------------------------------
const results = {
  node: process.version, zlib: process.versions.zlib, brotli: process.versions.brotli,
  toolchain: readFileSync(`${here}fixtures/TOOLCHAIN`, 'utf8').trim().split('\n'),
  constants: {ENVELOPE_FIXED, DEP_BYTES, FRAME_HEADER, URL_PREFIX, MAX_UNCOMPRESSED},
  capacityL: cap, compression, frames: frameTable, provenance,
  fixtureSha256: Object.fromEntries(Object.entries(fixtures).map(([k, b]) => [k, sha(b).toString('hex')])),
  checks,
};
if (process.argv.includes('--write')) writeFileSync(`${here}results.json`, JSON.stringify(results, null, 2) + '\n');
console.log(JSON.stringify({capacityL: cap, compression, frames: frameTable, provenance}, null, 2));
const failed = checks.filter(c => !c.ok);
for (const c of checks) console.error(`${c.ok ? 'PASS' : 'FAIL'} ${c.name}${c.ok ? '' : ` — ${c.error}`}`);
console.error(`${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length ? 1 : 0);
