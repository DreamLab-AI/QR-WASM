// The NIP-46 transport's crypto (nostr-tools NIP-44 v2) against all eight official
// vectors. Both ends of our NIP-46 link use nostr-tools, so these vectors are
// the independent check. The file has no stated licence, so it is fetched at a
// pinned commit and verified against the checksum NIP-44 publishes (44.md:303).
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync, existsSync} from 'node:fs';
import {createHash, createHmac, createDecipheriv} from 'node:crypto';
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
  await t.test('get_message_keys: payloads use exactly the published ChaCha20 and HMAC keys', () => {
    // nostr-tools does not export its key schedule, so check its output against the vector keys:
    // the MAC must verify under hmac_key, and ChaCha20(chacha_key, chacha_nonce) must decrypt the body.
    const key = hexToBytes(v.valid.get_message_keys.conversation_key);
    for (const k of v.valid.get_message_keys.keys) {
      const payload = Buffer.from(nip44.v2.encrypt('qrw', key, hexToBytes(k.nonce)), 'base64');
      assert.equal(payload[0], 2);
      const nonce = payload.subarray(1, 33), ct = payload.subarray(33, -32), mac = payload.subarray(-32);
      assert.equal(nonce.toString('hex'), k.nonce);
      assert.equal(createHmac('sha256', Buffer.from(k.hmac_key, 'hex')).update(nonce).update(ct).digest('hex'), mac.toString('hex'));
      const iv = Buffer.concat([Buffer.alloc(4), Buffer.from(k.chacha_nonce, 'hex')]); // 32-bit counter 0 ‖ 96-bit nonce
      const padded = createDecipheriv('chacha20', Buffer.from(k.chacha_key, 'hex'), iv).update(ct);
      assert.equal(nip44.v2.utils.unpad(Uint8Array.from(padded)), 'qrw');
    }
  });
  await t.test('calc_padded_len', () => {
    for (const [len, padded] of v.valid.calc_padded_len) assert.equal(nip44.v2.utils.calcPaddedLen(len), padded, `len ${len}`);
  });
  await t.test('encrypt_decrypt_long_msg', () => {
    const sha = s => createHash('sha256').update(s).digest('hex');
    for (const c of v.valid.encrypt_decrypt_long_msg) {
      const plaintext = c.pattern.repeat(c.repeat);
      assert.equal(sha(plaintext), c.plaintext_sha256);
      const payload = nip44.v2.encrypt(plaintext, hexToBytes(c.conversation_key), hexToBytes(c.nonce));
      assert.equal(sha(payload), c.payload_sha256);
      assert.equal(nip44.decrypt(payload, hexToBytes(c.conversation_key)), plaintext);
    }
  });
  await t.test('invalid message lengths: only those NIP-44 still forbids', () => {
    // The vector file predates NIP-44's extended length prefix (nips 0b54c4d, 44.md:87-91), which
    // allows 1..2^32-1 bytes. Its entries ≥ 65536 are superseded; only lengths < 1 remain invalid.
    const key = hexToBytes(v.valid.get_message_keys.conversation_key);
    assert.deepEqual(v.invalid.encrypt_msg_lengths, [0, 65536, 100000, 10000000], 'vector file unchanged');
    for (const n of v.invalid.encrypt_msg_lengths.filter(n => n < 1)) assert.throws(() => nip44.v2.encrypt('a'.repeat(n), key), undefined, `length ${n}`);
  });
  await t.test('extended length prefix boundary (44.md:339-347)', () => {
    const key = hexToBytes('c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d');
    const nonce = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
    const sha = s => createHash('sha256').update(s).digest('hex');
    for (const [n, plainSha, payloadSha] of [
      [65535, '6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42', '6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84'],
      [65536, 'bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a', 'b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616'],
      [65537, '008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430', 'eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435'],
    ]) {
      const plaintext = 'a'.repeat(n);
      assert.equal(sha(plaintext), plainSha);
      const payload = nip44.v2.encrypt(plaintext, key, nonce);
      assert.equal(sha(payload), payloadSha, `payload for ${n} B`);
      assert.equal(nip44.decrypt(payload, key), plaintext);
    }
  });
});
