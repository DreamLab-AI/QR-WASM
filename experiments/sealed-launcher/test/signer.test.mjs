// Signer policy and pairing over a real relay, with nostr-tools' BunkerSigner
// as the client, exactly as the launcher uses it.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {BunkerSigner} from 'nostr-tools/nip46';
import {generateSecretKey, verifyEvent} from 'nostr-tools/pure';
import {startRelay} from './harness/relay.mjs';
import {startSigner, policy} from './harness/signer.mjs';
import {parseHome, underHome, homeTarget} from '../web/lib/codes.mjs';

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
    ['duplicate u (last-match verifier would see bob)', nip98(`${HOME}a`, {tags: [['u', `${HOME}a`], ['u', 'https://pod.home.example/bob/x'], ['method', 'PUT']]})],
    ['duplicate method', nip98(`${HOME}a`, {tags: [['u', `${HOME}a`], ['method', 'PUT'], ['method', 'DELETE']]})],
    ['unknown tag', nip98(`${HOME}a`, {tags: [['u', `${HOME}a`], ['method', 'PUT'], ['x', 'y']]})],
    ['non-canonical u', nip98('https://POD.home.example:443/alice/a')],
    ['percent-encoded slash traversal', nip98(`${HOME}..%2fbob/x`)],
    ['method not allowed', nip98(`${HOME}a`, {tags: [['u', `${HOME}a`], ['method', 'POST']]})],
    ['payload not a digest', nip98(`${HOME}a`, {tags: [['u', `${HOME}a`], ['method', 'PUT'], ['payload', 'x']]})],
  ]) assert.notEqual(policy(t, HOME, now), null, why);
  assert.equal(underHome('https://pod.home.example/alice/../bob/x', HOME), false, 'dot segments are resolved by URL first');
  assert.equal(policy(nip98(`${HOME}a`, {tags: [['u', `${HOME}a`], ['method', 'PUT'], ['payload', 'ab'.repeat(32)]]}), HOME, now), null);
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

test('pod paths map to home by string and cannot leave it', () => {
  assert.equal(homeTarget(HOME, '/notes/a.txt'), `${HOME}notes/a.txt`);
  // URL resolution would send these off-home ("http://evil.example/x"); string mapping keeps them under home.
  assert.equal(homeTarget(HOME, '/http:/evil.example/x'), `${HOME}http:/evil.example/x`);
  assert.equal(homeTarget(HOME, '/https:/x'), `${HOME}https:/x`);
  for (const bad of ['//evil.example/x', '/../bob/x', '/a?x=1', 'notes', '/a b', '/..%2fbob/x'])
    assert.throws(() => homeTarget(HOME, bad), undefined, bad);
});

test('cleartext home or relay only on loopback; empty query/fragment refused', () => {
  const code = (home, relay = 'wss://r.example') => `bunker://${'a'.repeat(64)}?relay=${encodeURIComponent(relay)}&secret=s&home=${encodeURIComponent(home)}`;
  assert.equal(parseHome(code('http://localhost:8801/', 'ws://localhost:8802')).home, 'http://localhost:8801/');
  for (const [why, c] of [['http home', code('http://pod.example/')], ['ws relay', code(HOME, 'ws://r.example')],
    ['empty query', code('https://pod.example/?')], ['empty fragment', code('https://pod.example/#')]]) assert.throws(() => parseHome(c), undefined, why);
});

test('concurrent writes cannot both pass a precondition', async () => {
  const {serve, mapStore} = await import('../web/lib/podstore.mjs');
  const store = mapStore();
  let seen = 0;
  // A stand-in pod that only succeeds when the resource is absent (If-None-Match: * semantics).
  const pod = {handle: (_req, stored) => (seen++, stored.kind === ''
    ? {status: 201, headers: {}, body: new Uint8Array(), op: {kind: 'put', path: '/x', contentType: 't', body: new Uint8Array([seen])}}
    : {status: 412, headers: {}, body: new Uint8Array(), op: {kind: ''}})};
  // Slow reads *and* writes, so without the lock every request reads before any write lands.
  const later = ms => new Promise(r => setTimeout(r, ms));
  const slow = {...store, get: async p => { await later(20); return store.get(p); }, set: async (p, r) => { await later(50); return store.set(p, r); }};
  const results = await Promise.all([1, 2, 3].map(() => serve(pod, slow, {method: 'PUT', path: '/x'})));
  assert.deepEqual(results.map(r => r.status).sort(), [201, 412, 412]);
});
