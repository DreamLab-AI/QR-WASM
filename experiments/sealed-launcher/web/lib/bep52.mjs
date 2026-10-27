// BitTorrent identities for a sealed blob, as the launcher conventions fix them:
// one file named "m", piece length 16 KiB. Runs on WebCrypto (browser and Node).
//
// - piecesRoot: BEP 52 SHA-256 merkle root over 16 KiB blocks, leaves beyond the
//   file padded with zero hashes. For a blob of at most one block it is the
//   blob's plain SHA-256.
// - infohashV2: SHA-256 of the bencoded v2 info dictionary, derivable from
//   (length, piecesRoot) alone.
// - infohashV1: SHA-1 of the bencoded v1 info dictionary. Needs the data (it
//   covers SHA-1 piece hashes), so a pointer that wants browser swarms
//   (WebTorrent is v1-only) carries it as a locator. It is never trusted for
//   integrity: the SHA-256 root, AEAD tag and object ID are.

export const PIECE = 16384;
export const NAME = 'm';

const sha = async (alg, bytes) => new Uint8Array(await crypto.subtle.digest(alg, bytes));
const concat = parts => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const ascii = s => new TextEncoder().encode(s);

/** Minimal bencode for the dictionaries above: ints, byte strings, text keys, sorted dicts. */
export function bencode(x) {
  if (typeof x === 'number') {
    if (!Number.isSafeInteger(x)) throw new RangeError('bencode: unsafe integer');
    return ascii(`i${x}e`);
  }
  if (typeof x === 'string') x = ascii(x);
  if (x instanceof Uint8Array) return concat([ascii(`${x.length}:`), x]);
  if (x && typeof x === 'object') {
    // Keys are compared as raw bytes; all keys here are ASCII, so code-unit order is byte order.
    const keys = Object.keys(x).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return concat([ascii('d'), ...keys.flatMap(k => [bencode(k), bencode(x[k])]), ascii('e')]);
  }
  throw new TypeError('bencode: unsupported value');
}

/** BEP 52 pieces root of `data`. */
export async function piecesRoot(data) {
  if (data.length === 0) throw new RangeError('empty file has no pieces root');
  let layer = [];
  for (let i = 0; i < data.length; i += PIECE) layer.push(await sha('SHA-256', data.subarray(i, i + PIECE)));
  let width = 1;
  while (width < layer.length) width *= 2;
  while (layer.length < width) layer.push(new Uint8Array(32));
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(await sha('SHA-256', concat([layer[i], layer[i + 1]])));
    layer = next;
  }
  return layer[0];
}

export const infoV2 = (length, root) =>
  ({'file tree': {[NAME]: {'': {length, 'pieces root': root}}}, 'meta version': 2, name: NAME, 'piece length': PIECE});

/** v2 infohash from the pointer fields alone. */
export const infohashV2 = async (length, root) => sha('SHA-256', bencode(infoV2(length, root)));

/** v1 infohash; needs the data. */
export async function infohashV1(data) {
  const pieces = [];
  for (let i = 0; i < data.length; i += PIECE) pieces.push(await sha('SHA-1', data.subarray(i, i + PIECE)));
  return sha('SHA-1', bencode({length: data.length, name: NAME, 'piece length': PIECE, pieces: concat(pieces)}));
}
