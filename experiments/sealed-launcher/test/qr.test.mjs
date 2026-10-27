// QR round trip: build the real app and home codes with qrcode 1.5.4 (mixed
// segments), rasterise, decode with jsQR 1.4.0 (an independent decoder), and
// check the launcher parses what comes back. Records the measured versions.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import * as base43 from '../web/lib/base43.mjs';
import * as pointer from '../web/lib/pointer.mjs';
import {parseFragment, homeLink} from '../web/lib/codes.mjs';

const sealed = JSON.parse(readFileSync(new URL('../vectors/sealed.json', import.meta.url)));
const ORIGIN = 'HTTPS://LAUNCHER.EXAMPLE/';

/** Smallest level-L symbol for `segments`, rasterised at 4 px per module with a 4-module quiet zone. */
function render(segments) {
  const qr = QRCode.create(segments, {errorCorrectionLevel: 'L'});
  const n = qr.modules.size, scale = 4, quiet = 4, side = (n + 2 * quiet) * scale;
  const rgba = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    if (!qr.modules.get(y, x)) continue;
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
      const at = (((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx) * 4;
      rgba.fill(0, at, at + 3);
    }
  }
  return {version: qr.version, rgba, side};
}

const appSegments = (origin, p) => [
  {data: origin, mode: 'alphanumeric'}, {data: '#', mode: 'byte'}, {data: base43.encode(p), mode: 'alphanumeric'}];

const measured = {};

for (const [label, hexPointer] of [['app code, 104 B pointer', sealed.cases[0].pointer], ['app code + v1 locator, 124 B pointer', sealed.cases[1].pointer]]) {
  test(`${label}: jsQR decodes the mixed-segment symbol to a link the launcher parses`, () => {
    const p = Uint8Array.from(Buffer.from(hexPointer, 'hex'));
    const {version, rgba, side} = render(appSegments(ORIGIN, p));
    const decoded = jsQR(rgba, side, side);
    assert.ok(decoded, 'jsQR found a symbol');
    assert.equal(decoded.data, ORIGIN + '#' + base43.encode(p));
    const url = new URL(decoded.data);
    assert.equal(url.origin, 'https://launcher.example', 'scheme and host are case-insensitive');
    const parsed = parseFragment(url.hash);
    assert.equal(parsed.type, 'app');
    assert.deepEqual(pointer.encode(parsed.pointer), p);
    measured[label] = {version, modules: 17 + 4 * version, pointerBytes: p.length};
  });
}

test('home code: byte-mode symbol round-trips and parses as pairing', () => {
  // Field widths as the test signer emits them: 64-hex signer key, 32-hex secret.
  const link = homeLink('https://launcher.example/', {
    signer: 'a'.repeat(64), relay: 'wss://relay.home.example', secret: 'b'.repeat(32), home: 'https://pod.home.example/'});
  const {version, rgba, side} = render([{data: Buffer.from(link), mode: 'byte'}]);
  const decoded = jsQR(rgba, side, side);
  assert.equal(decoded.data, link);
  const parsed = parseFragment(new URL(decoded.data).hash);
  assert.equal(parsed.type, 'home');
  assert.equal(parsed.home.signer, 'a'.repeat(64));
  assert.equal(parsed.home.home, 'https://pod.home.example/');
  measured['home code'] = {version, modules: 17 + 4 * version, bytes: Buffer.byteLength(link)};
});

test.after(() => {
  writeFileSync(new URL('../vectors/qr-measured.json', import.meta.url),
    JSON.stringify({generator: 'qrcode 1.5.4 + jsQR 1.4.0, level L', origin: ORIGIN, measured}, null, 2) + '\n');
});
