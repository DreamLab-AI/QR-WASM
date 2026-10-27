// Launcher decode rules against sealer-generated vectors (vectors/sealed.json),
// the cose-wg examples, and pointer / base43 strictness.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as pointer from '../web/lib/pointer.mjs';
import * as base43 from '../web/lib/base43.mjs';
import {parseEncrypt0, decryptCore, encStructure} from '../web/lib/cose.mjs';
import {unseal} from '../web/lib/unseal.mjs';

const load = name => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url)));
const fromHex = h => Uint8Array.from(Buffer.from(h, 'hex'));
const fromB64 = s => Uint8Array.from(Buffer.from(s, 'base64'));
const hex = b => Buffer.from(b).toString('hex');

const sealed = load('sealed.json');
for (const c of sealed.cases) {
  test(`launcher: ${c.name} → ${c.expect === 'ok' ? 'runs' : `rule ${c.expect}`}`, async () => {
    const p = pointer.decode(fromHex(c.pointer));
    const run = unseal(p, fromB64(c.blob));
    if (c.expect === 'ok') {
      const {bytes, objectId, module} = await run;
      assert.equal(hex(objectId), sealed.moduleSha256);
      assert.equal(hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))), sealed.moduleSha256);
      assert.ok(module instanceof WebAssembly.Module);
    } else {
      await assert.rejects(run, e => e.rule === c.expect, `expected rule ${c.expect}`);
    }
  });
}

test('pointer round trip, with and without locator', () => {
  const p = pointer.decode(fromHex(sealed.cases[1].pointer));
  assert.equal(p.locator.length, 20);
  assert.equal(hex(pointer.encode(p)), sealed.cases[1].pointer);
  const bare = pointer.decode(fromHex(sealed.cases[0].pointer));
  assert.equal(bare.locator, undefined);
  assert.equal(fromHex(sealed.cases[0].pointer).length, 104);
});

test('pointer rejects malformed input (rule 1)', () => {
  const good = fromHex(sealed.cases[0].pointer);
  const variant = f => { const b = good.slice(); f(b); return b; };
  for (const [why, bytes] of [
    ['truncated', good.subarray(0, 103)],
    ['extra byte', Uint8Array.from([...good, 0])],
    ['magic', variant(b => { b[0] = 0x51; b[1] = 0x57; })],
    ['version', variant(b => { b[2] = 2; })],
    ['unknown flag', variant(b => { b[3] = 0x02; })],
    ['locator flag without locator', variant(b => { b[3] = 0x01; })],
    ['zero length', variant(b => { b.set([0, 0, 0, 0], 4); })],
    ['length over ceiling', variant(b => { b.set([0, 0x11, 0, 0], 4); })],
  ]) assert.throws(() => pointer.decode(bytes), undefined, why);
});

test('base43 round trip and strict decode', () => {
  for (const n of [0, 1, 2, 3, 104, 124]) {
    const b = Uint8Array.from({length: n}, (_, i) => (i * 37 + 11) & 255);
    assert.deepEqual(base43.decode(base43.encode(b)), b);
  }
  assert.equal(base43.encode(Uint8Array.of(0xff, 0xff)), '3JZ'); // matches experiments/compression/bench.mjs
  assert.throws(() => base43.decode('ABCD'), /length/);
  assert.throws(() => base43.decode('ab0'), /character/);
  assert.throws(() => base43.decode('::::'.slice(0, 3)), /overflow/); // 42·(1+43+1849) > 65535
  assert.throws(() => base43.decode('::'), /overflow/); // 42 + 42·43 > 255
});

test('cose-wg AES-GCM-ENC-03 (A256GCM) passes the strict profile and decrypts', async () => {
  const [, enc03] = load('cose-wg.json').cases;
  const blob = fromHex(enc03.cbor);
  const parts = parseEncrypt0(blob);
  assert.equal(hex(encStructure(parts.protectedBytes)).toUpperCase(), enc03.aadHex);
  const plain = await decryptCore(parts, Uint8Array.from(Buffer.from(enc03.keyB64url, 'base64url')));
  assert.equal(new TextDecoder().decode(plain), enc03.plaintext);
});

test('cose-wg ENC-01 decrypts in the core but fails the profile; ENC-04 fails its tag', async () => {
  const [enc01, , enc04] = load('cose-wg.json').cases;
  for (const c of [enc01, enc04]) assert.throws(() => parseEncrypt0(fromHex(c.cbor)), /\{1: 3\}/, c.title);
  // Core path, profile bypassed: split the identical framing by hand (protected = bytes 3..6, IV = 9..21).
  const core = c => { const b = fromHex(c.cbor); return {protectedBytes: b.subarray(3, 6), iv: b.subarray(9, 21), ciphertext: b.subarray(23)}; };
  const key = c => Uint8Array.from(Buffer.from(c.keyB64url, 'base64url'));
  assert.equal(hex(encStructure(core(enc01).protectedBytes)).toUpperCase(), enc01.aadHex);
  assert.equal(new TextDecoder().decode(await decryptCore(core(enc01), key(enc01))), enc01.plaintext);
  await assert.rejects(decryptCore(core(enc04), key(enc04)));
});
