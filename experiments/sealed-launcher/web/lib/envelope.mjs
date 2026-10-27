// Envelope v1 decoder (docs/spec/qr-object-v1.md §2), isomorphic: it inflates
// with DecompressionStream('deflate-raw') and stops at the declared length
// (rule 4), so a decompression bomb never allocates past `length`.

export const MAX_LENGTH = 1 << 20;
const HEADER = 43;

export async function decodeEnvelope(bytes, {maxLength = MAX_LENGTH} = {}) {
  if (bytes.length < HEADER) throw new SyntaxError('envelope: truncated header');
  if (bytes[0] !== 0x51 || bytes[1] !== 0x57) throw new SyntaxError('envelope: bad magic');
  if (bytes[2] !== 0x01) throw new SyntaxError('envelope: unsupported version');
  const kind = bytes[3], codec = bytes[4];
  if (bytes[5] !== 0) throw new SyntaxError('envelope: flags must be 0');
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const length = dv.getUint32(6);
  if (length > Math.min(maxLength, MAX_LENGTH)) throw new RangeError('envelope: length over ceiling');
  const digest = bytes.slice(10, 42);
  const ndeps = bytes[42];
  const bodyAt = HEADER + 32 * ndeps;
  if (bytes.length < bodyAt) throw new SyntaxError('envelope: truncated dependencies');
  const deps = Array.from({length: ndeps}, (_, i) => bytes.slice(HEADER + 32 * i, HEADER + 32 * (i + 1)));
  const body = bytes.subarray(bodyAt);

  let payload;
  if (codec === 0x00) {
    if (body.length !== length) throw new SyntaxError('envelope: length mismatch');
    payload = body.slice();
  } else if (codec === 0x01) {
    payload = await inflateBounded(body, length);
  } else {
    throw new SyntaxError('envelope: unsupported codec');
  }
  const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  if (actual.some((b, i) => b !== digest[i])) throw new Error('envelope: digest mismatch');
  return {kind, codec, length, digest, deps, payload};
}

async function inflateBounded(body, length) {
  const out = new Uint8Array(length);
  let at = 0;
  const reader = new Blob([body]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      if (at + value.length > length) throw new RangeError('envelope: inflates past declared length');
      out.set(value, at);
      at += value.length;
    }
  } catch (e) {
    await reader.cancel().catch(() => {});
    throw e instanceof RangeError ? e : new SyntaxError(`envelope: inflate failed (${e.message})`);
  }
  if (at !== length) throw new SyntaxError('envelope: length mismatch');
  return out;
}
