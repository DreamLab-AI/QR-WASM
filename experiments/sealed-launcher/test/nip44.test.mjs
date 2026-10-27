// The NIP-46 transport's crypto (nostr-tools NIP-44 v2) against the official
// vectors. Both ends of our NIP-46 link use nostr-tools, so these vectors are
// the independent check. The file has no stated licence, so it is fetched at a
// pinned commit and verified against the checksum NIP-44 publishes (44.md:303).
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync, existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import * as nip44 from 'nostr-tools/nip44';
import {getPublicKey} from 'nostr-tools/pure';
import {hexToBytes, bytesToHex} from 'nostr-tools/utils';

const PINNED = 'https://raw.githubusercontent.com/paulmillr/nip44/671a1f04bcfacaf125b0db68adc45bc9ce0e763b/nip44.vectors.json';
const SHA256 = '269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040';
const file = new URL('../vectors/.cache/nip44.vectors.json', import.meta.url);

async function vectors() {
  if (!existsSync(file)) writeFileSync(file, Buffer.from(await (await fetch(PINNED)).arrayBuffer()));
  const raw = readFileSync(file);
  assert.equal(createHash('sha256').update(raw).digest('hex'), SHA256, 'vectors match the NIP-44 checksum');
  return JSON.parse(raw).v2;
}

test('NIP-44 v2 official vectors (nostr-tools)', async t => {
  const v = await vectors();
  await t.test('get_conversation_key', () => {
    for (const c of v.valid.get_conversation_key) assert.equal(bytesToHex(nip44.getConversationKey(hexToBytes(c.sec1), c.pub2)), c.conversation_key);
  });
  await t.test('encrypt_decrypt with fixed nonces', () => {
    for (const c of v.valid.encrypt_decrypt) {
      const key = nip44.getConversationKey(hexToBytes(c.sec1), getPublicKey(hexToBytes(c.sec2)));
      assert.equal(bytesToHex(key), c.conversation_key);
      assert.equal(nip44.v2.encrypt(c.plaintext, key, hexToBytes(c.nonce)), c.payload);
      assert.equal(nip44.decrypt(c.payload, key), c.plaintext);
    }
  });
  await t.test('invalid decrypts are rejected', () => {
    for (const c of v.invalid.decrypt) assert.throws(() => nip44.decrypt(c.payload, hexToBytes(c.conversation_key)), undefined, c.note);
  });
  await t.test('invalid conversation keys are rejected', () => {
    for (const c of v.invalid.get_conversation_key) assert.throws(() => nip44.getConversationKey(hexToBytes(c.sec1), c.pub2), undefined, c.note);
  });
});
