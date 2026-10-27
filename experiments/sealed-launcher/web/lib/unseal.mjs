// Launcher decode rules 3–8 (README "Launcher decode rules"): from an untrusted
// blob and a decoded pointer to a module that is safe to instantiate under the
// allowlist. Every failure throws an Error whose `rule` names the rule.

import {piecesRoot} from './bep52.mjs';
import {openEncrypt0} from './cose.mjs';
import {decodeEnvelope} from './envelope.mjs';

export const KIND_WASM = 0x01;

const fail = (rule, message, cause) => Object.assign(new Error(`rule ${rule}: ${message}`), {rule, cause});
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/** Plaintext = u32 n ‖ envelope (n bytes) ‖ zero padding. */
export function unpad(plain) {
  if (plain.length < 4) throw fail(5, 'plaintext shorter than its length prefix');
  const n = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0);
  if (n > plain.length - 4) throw fail(5, 'envelope length exceeds plaintext');
  for (let i = 4 + n; i < plain.length; i++) if (plain[i] !== 0) throw fail(5, 'non-zero padding');
  return plain.subarray(4, 4 + n);
}

/**
 * @param pointer decoded `QS` pointer (pointer.mjs)
 * @param blob    bytes from any source
 * @param allowedImports Set of "module.name" a module may import (empty for the pod)
 */
export async function unseal(pointer, blob, allowedImports = new Set()) {
  if (blob.length !== pointer.length) throw fail(3, 'blob length differs from pointer');
  if (!equal(await piecesRoot(blob), pointer.root)) throw fail(3, 'blob root differs from pointer');
  let plain;
  try {
    plain = await openEncrypt0(blob, pointer.key);
  } catch (e) {
    throw fail(4, e instanceof SyntaxError ? e.message : 'AES-GCM authentication failed', e);
  }
  const envelopeBytes = unpad(plain);
  let envelope;
  try {
    envelope = await decodeEnvelope(envelopeBytes);
  } catch (e) {
    throw fail(6, e.message, e);
  }
  if (!equal(envelope.digest, pointer.objectId)) throw fail(7, 'object differs from pointer object ID');
  if (envelope.kind !== KIND_WASM) throw fail(8, 'not a WebAssembly module');
  let module;
  try {
    module = await WebAssembly.compile(envelope.payload);
  } catch (e) {
    throw fail(8, 'module does not compile', e);
  }
  const extra = WebAssembly.Module.imports(module).map(i => `${i.module}.${i.name}`).filter(i => !allowedImports.has(i));
  if (extra.length) throw fail(8, `imports outside allowlist: ${extra.join(', ')}`);
  return {module, bytes: envelope.payload, objectId: envelope.digest, deps: envelope.deps};
}
