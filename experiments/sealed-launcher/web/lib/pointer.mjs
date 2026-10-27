// Sealed pointer `QS` v1 (README "Sealed pointer"). All integers big-endian.
//
//  0  2  magic "QS"
//  2  1  version 0x01
//  3  1  flags: bit 0 = v1 infohash locator appended; other bits must be 0
//  4  4  blob length
//  8 32  blob root (BEP 52 pieces root)
// 40 32  content key (AES-256-GCM)
// 72 32  object ID (SHA-256 of the uncompressed payload)
// 104 20 v1 infohash locator, present only if flags bit 0

export const BASE = 104;
export const LOCATOR = 20;
export const FLAG_V1_LOCATOR = 0x01;
/** Largest blob a launcher fetches: the 1 MiB envelope ceiling plus sealing overhead. */
export const MAX_BLOB = (1 << 20) + 4096;

export function encode({length, root, key, objectId, locator}) {
  for (const [name, v] of [['root', root], ['key', key], ['objectId', objectId]]) {
    if (!(v instanceof Uint8Array) || v.length !== 32) throw new TypeError(`${name} must be 32 bytes`);
  }
  if (locator !== undefined && (!(locator instanceof Uint8Array) || locator.length !== LOCATOR)) throw new TypeError('locator must be 20 bytes');
  if (!Number.isInteger(length) || length < 1 || length > MAX_BLOB) throw new RangeError('blob length out of range');
  const out = new Uint8Array(BASE + (locator ? LOCATOR : 0));
  const dv = new DataView(out.buffer);
  out.set([0x51, 0x53, 0x01, locator ? FLAG_V1_LOCATOR : 0]);
  dv.setUint32(4, length);
  out.set(root, 8); out.set(key, 40); out.set(objectId, 72);
  if (locator) out.set(locator, BASE);
  return out;
}

/** Launcher rule 1. Throws on anything but an exact, well-formed pointer. */
export function decode(bytes) {
  if (bytes.length < BASE) throw new SyntaxError('pointer: truncated');
  if (bytes[0] !== 0x51 || bytes[1] !== 0x53) throw new SyntaxError('pointer: bad magic');
  if (bytes[2] !== 0x01) throw new SyntaxError('pointer: unsupported version');
  const flags = bytes[3];
  if (flags & ~FLAG_V1_LOCATOR) throw new SyntaxError('pointer: unknown flags');
  const expected = BASE + (flags & FLAG_V1_LOCATOR ? LOCATOR : 0);
  if (bytes.length !== expected) throw new SyntaxError('pointer: wrong length');
  const length = new DataView(bytes.buffer, bytes.byteOffset).getUint32(4);
  if (length < 1 || length > MAX_BLOB) throw new RangeError('pointer: blob length out of range');
  const slice = (a, b) => bytes.slice(a, b);
  return {length, root: slice(8, 40), key: slice(40, 72), objectId: slice(72, 104),
    locator: flags & FLAG_V1_LOCATOR ? slice(BASE, BASE + LOCATOR) : undefined};
}
