// Deterministic test data shared with tools/libtorrent-vectors.py:
// block i of a size-n input = SHA-256("qrw-bep52" || u32be(n) || u32be(i)), cut to n.
import {createHash} from 'node:crypto';

export function vectorData(n) {
  const out = new Uint8Array(n);
  for (let i = 0, at = 0; at < n; i++) {
    const seed = Buffer.alloc(17); seed.write('qrw-bep52'); seed.writeUInt32BE(n, 9); seed.writeUInt32BE(i, 13);
    const block = createHash('sha256').update(seed).digest();
    out.set(block.subarray(0, Math.min(32, n - at)), at); at += 32;
  }
  return out;
}
