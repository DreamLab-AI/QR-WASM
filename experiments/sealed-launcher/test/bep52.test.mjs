// BEP 52 / BEP 3 identities against libtorrent 2.0.15 (vectors/bep52-libtorrent.json).
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {piecesRoot, infohashV2, infohashV1} from '../web/lib/bep52.mjs';
import {vectorData} from './data.mjs';

const ref = JSON.parse(readFileSync(new URL('../vectors/bep52-libtorrent.json', import.meta.url)));
const hex = b => Buffer.from(b).toString('hex');

for (const v of ref.vectors) {
  test(`BEP 52 matches libtorrent for ${v.length} B`, async () => {
    const data = vectorData(v.length);
    assert.equal(hex(await crypto.subtle.digest('SHA-256', data)), v.sha256, 'deterministic data generator');
    const root = await piecesRoot(data);
    assert.equal(hex(root), v.piecesRoot);
    assert.equal(hex(await infohashV2(v.length, root)), v.infohashV2, 'v2 infohash from (length, root) alone');
    assert.equal(hex(await infohashV1(data)), v.infohashV1);
    if (v.length <= 16384) assert.equal(v.piecesRoot, v.sha256, 'one block: root is the plain SHA-256');
  });
}
