// COSE_Encrypt0 (RFC 9052 §5.2) in the single profile the launcher accepts:
//
//   16([ h'A10103', {5: h'<12-byte IV>'}, h'<ciphertext ‖ 16-byte tag>' ])
//
// i.e. protected {1: 3} (alg A256GCM), unprotected {5: IV}, external AAD empty.
// The parser is exact rather than general: definite, minimal-length CBOR only,
// no extra headers, no trailing bytes. Decryption is WebCrypto AES-GCM; this
// file only frames bytes and builds the RFC 9052 §5.3 Enc_structure.

export const PROTECTED_A256GCM = Uint8Array.of(0xa1, 0x01, 0x03);
const TAG_ENCRYPT0 = 0xd0; // tag 16, one-byte head
const IV_LENGTH = 12;

class Reader {
  constructor(bytes) { this.b = bytes; this.at = 0; }
  byte() {
    if (this.at >= this.b.length) throw new SyntaxError('cose: truncated');
    return this.b[this.at++];
  }
  /** Head of a definite item with minimal-length argument; returns [major, argument]. */
  head() {
    const ib = this.byte(), major = ib >> 5, info = ib & 31;
    if (info < 24) return [major, info];
    if (info > 27) throw new SyntaxError('cose: indefinite or reserved length');
    const width = 1 << (info - 24);
    let n = 0;
    for (let i = 0; i < width; i++) n = n * 256 + this.byte();
    const min = [24, 256, 65536, 2 ** 32][info - 24];
    if (n < min) throw new SyntaxError('cose: non-minimal length');
    if (!Number.isSafeInteger(n)) throw new RangeError('cose: length too large');
    return [major, n];
  }
  bstr() {
    const [major, n] = this.head();
    if (major !== 2) throw new SyntaxError('cose: expected byte string');
    if (this.at + n > this.b.length) throw new SyntaxError('cose: truncated');
    const out = this.b.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }
  expect(...bytes) {
    for (const want of bytes) if (this.byte() !== want) throw new SyntaxError('cose: not the A256GCM Encrypt0 profile');
  }
}

const cborBstrHead = n =>
  n < 24 ? [0x40 | n] : n < 256 ? [0x58, n] : n < 65536 ? [0x59, n >> 8, n & 255] : [0x5a, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255];

/** RFC 9052 §5.3 Enc_structure ["Encrypt0", protected, external_aad], over the protected bytes as received. */
export function encStructure(protectedBytes, externalAad = new Uint8Array()) {
  const context = new TextEncoder().encode('Encrypt0');
  return Uint8Array.from([0x83, 0x68, ...context,
    ...cborBstrHead(protectedBytes.length), ...protectedBytes,
    ...cborBstrHead(externalAad.length), ...externalAad]);
}

/** Strict parse of the profile; returns the parts needed to decrypt. */
export function parseEncrypt0(blob) {
  const r = new Reader(blob);
  r.expect(TAG_ENCRYPT0, 0x83);
  const protectedBytes = r.bstr();
  if (protectedBytes.length !== 3 || protectedBytes.some((b, i) => b !== PROTECTED_A256GCM[i])) {
    throw new SyntaxError('cose: protected header must be exactly {1: 3}');
  }
  r.expect(0xa1, 0x05);
  const iv = r.bstr();
  if (iv.length !== IV_LENGTH) throw new SyntaxError('cose: IV must be 12 bytes');
  const ciphertext = r.bstr();
  if (r.at !== blob.length) throw new SyntaxError('cose: trailing bytes');
  if (ciphertext.length < 16) throw new SyntaxError('cose: ciphertext shorter than the tag');
  return {protectedBytes, iv, ciphertext};
}

/** AES-256-GCM decrypt of COSE parts; rejects (OperationError) on any tag failure. */
export async function decryptCore({protectedBytes, iv, ciphertext}, rawKey, externalAad) {
  const key = await crypto.subtle.importKey('raw', rawKey, {name: 'AES-GCM'}, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv, additionalData: encStructure(protectedBytes, externalAad), tagLength: 128}, key, ciphertext);
  return new Uint8Array(plain);
}

export const openEncrypt0 = async (blob, rawKey) => decryptCore(parseEncrypt0(blob), rawKey);
