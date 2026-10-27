// Signer policy and pairing over a real relay, with nostr-tools' BunkerSigner
// as the client, exactly as the launcher uses it.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {BunkerSigner} from 'nostr-tools/nip46';
import {generateSecretKey, verifyEvent} from 'nostr-tools/pure';
import {startRelay} from './harness/relay.mjs';
import {startSigner, policy} from './harness/signer.mjs';
import {parseHome, underHome} from '../web/lib/codes.mjs';

const HOME = 'https://pod.home.example/alice/';
const now = Math.floor(Date.now() / 1000);
const nip98 = (u, extra = {}) => ({kind: 27235, created_at: now, tags: [['u', u], ['method', 'PUT']], content: '', ...extra});

test('policy: scope is parsed origin + path prefix, never a string prefix', () => {
  assert.equal(policy(nip98(`${HOME}notes/a.txt`), HOME, now), null);
  assert.equal(policy(nip98(HOME), HOME, now), null);
  for (const [why, t] of [
    ['look-alike host', nip98('https://pod.home.example.evil/alice/a')],
    ['sibling path', nip98('https://pod.home.example/alice-evil/a')],
    ['parent path', nip98('https://pod.home.example/')],
    ['other scheme', nip98('http://pod.home.example/alice/a')],
    ['userinfo trick', nip98('https://pod.home.example@evil.example/alice/a')],
    ['query smuggling', nip98(`${HOME}a?x=1`)],
    ['not NIP-98', nip98(`${HOME}a`, {kind: 1})],
    ['no method', {kind: 27235, created_at: now, tags: [['u', `${HOME}a`]], content: ''}],
    ['stale', nip98(`${HOME}a`, {created_at: now - 61})],
    ['content', nip98(`${HOME}a`, {content: 'x'})],
  ]) assert.notEqual(policy(t, HOME, now), null, why);
  assert.equal(underHome('https://pod.home.example/alice/../bob/x', HOME), false, 'dot segments are resolved by URL first');
});

test('home code parsing rejects malformed codes', () => {
  const ok = `bunker://${'a'.repeat(64)}?relay=wss%3A%2F%2Fr.example&secret=s&home=${encodeURIComponent(HOME)}`;
  assert.equal(parseHome(ok).home, HOME);
  for (const bad of [ok.replace('a'.repeat(64), 'A'.repeat(64)), ok.replace('relay=wss%3A%2F%2Fr.example&', ''),
    ok.replace('&secret=s', ''), ok.replace(encodeURIComponent(HOME), encodeURIComponent('https://pod.home.example/alice')),
    ok.replace('wss%3A', 'https%3A'), ok.replace(encodeURIComponent(HOME), encodeURIComponent(`${HOME}?q=1`))]) {
    assert.throws(() => parseHome(bad));
  }
});

test('pairing: single-use secret, bound client, scoped signing, user ≠ signer key', async () => {
  const relay = startRelay({port: 0 || 18802, host: '127.0.0.1'});
  const signer = await startSigner({relayUrl: 'ws://127.0.0.1:18802', home: HOME});
  try {
    const bp = parseHome(signer.bunker);
    const bunker = {pubkey: bp.signer, relays: bp.relays, secret: bp.secret};
    assert.notEqual(signer.userPubkey, signer.signerPubkey);

    const aKey = generateSecretKey();
    const a = BunkerSigner.fromBunker(aKey, bunker);
    await a.connect();
    assert.equal(await a.getPublicKey(), signer.userPubkey, 'owner is the user key, not the bunker key');
    const ev = await a.signEvent(nip98(`${HOME}notes/a.txt`, {created_at: Math.floor(Date.now() / 1000)}));
    assert.ok(verifyEvent(ev));
    assert.equal(ev.pubkey, signer.userPubkey);
    await assert.rejects(a.signEvent(nip98('https://pod.home.example/bob/x', {created_at: Math.floor(Date.now() / 1000)})), /not under home/);
    await assert.rejects(a.signEvent({kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'hi'}), /27235/);

    // The same secret from a second client is refused, and so is that client afterwards.
    const b = BunkerSigner.fromBunker(generateSecretKey(), bunker);
    await assert.rejects(b.connect(), /already used/);
    await assert.rejects(b.getPublicKey(), /unauthorized/);

    // The bound client survives a restart of its session: same client key, no connect, no secret.
    await a.close();
    const restored = BunkerSigner.fromBunker(aKey, {pubkey: bp.signer, relays: bp.relays});
    assert.equal(await restored.getPublicKey(), signer.userPubkey);
    await restored.close(); await b.close();
    assert.ok(signer.state.log.some(e => e.refused === 'unauthorized client'));
  } finally {
    await signer.close();
    await relay.close();
  }
});
