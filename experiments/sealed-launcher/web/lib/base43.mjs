// Radix 43 over the QR alphanumeric characters a URL fragment keeps verbatim
// (spec §5 `url43`, same codec as experiments/compression/bench.mjs).
// Two bytes → three characters, least significant digit first; a final odd
// byte → two characters.

export const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:';
const VALUE = new Map([...ALPHABET].map((c, i) => [c, i]));

export function encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 2) {
    const pair = i + 1 < bytes.length;
    let n = pair ? bytes[i] * 256 + bytes[i + 1] : bytes[i];
    for (let k = 0; k < (pair ? 3 : 2); k++) { out += ALPHABET[n % 43]; n = Math.floor(n / 43); }
  }
  return out;
}

/** Strict decode: rejects foreign characters, a dangling character and overflowing groups. */
export function decode(text) {
  if (text.length % 3 === 1) throw new SyntaxError('base43: invalid length');
  const out = new Uint8Array(Math.floor(text.length / 3) * 2 + (text.length % 3 === 2 ? 1 : 0));
  let o = 0;
  for (let i = 0; i < text.length; i += 3) {
    const width = Math.min(3, text.length - i);
    let n = 0;
    for (let k = width - 1; k >= 0; k--) {
      const v = VALUE.get(text[i + k]);
      if (v === undefined) throw new SyntaxError('base43: invalid character');
      n = n * 43 + v;
    }
    if (width === 3) {
      if (n > 0xffff) throw new SyntaxError('base43: group overflow');
      out[o++] = n >> 8; out[o++] = n & 0xff;
    } else {
      if (n > 0xff) throw new SyntaxError('base43: group overflow');
      out[o++] = n;
    }
  }
  return out;
}
