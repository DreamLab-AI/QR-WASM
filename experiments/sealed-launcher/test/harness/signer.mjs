// Test NIP-46 remote signer with the draft-0 policy:
//  - the bunker secret is single-use and binds the first client that connects;
//  - every other method needs the bound client;
//  - sign_event signs only kind 27235 (NIP-98) whose `u` lies under `home`
//    (same origin, path prefix), with a `method` tag and created_at within ±60 s.
// Crypto is nostr-tools (NIP-44 v2, BIP-340), checked against the official
// NIP-44 vectors in test/nip44.test.mjs. The signer key and the user key differ.
import {Relay, useWebSocketImplementation} from 'nostr-tools/relay';
import {finalizeEvent, getPublicKey, generateSecretKey} from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import {bytesToHex} from 'nostr-tools/utils';
import WebSocket from 'ws';
import {underHome, normaliseHome} from '../../web/lib/codes.mjs';

useWebSocketImplementation(WebSocket);
const KIND = 24133;

/** Pure policy check, exported for unit tests. Returns null when allowed, else the reason. */
export function policy(template, home, now = Math.floor(Date.now() / 1000)) {
  if (template?.kind !== 27235) return 'only kind 27235 (NIP-98) is signed';
  if (!Array.isArray(template.tags)) return 'missing tags';
  const tag = name => template.tags.find(t => t[0] === name)?.[1];
  const u = tag('u');
  if (!u || !underHome(u, home)) return 'u is not under home';
  if (!tag('method')) return 'missing method tag';
  if (!Number.isSafeInteger(template.created_at) || Math.abs(template.created_at - now) > 60) return 'created_at outside ±60 s';
  if (template.content !== '') return 'content must be empty';
  return null;
}

export async function startSigner({relayUrl, home, userSecret = generateSecretKey(), signerSecret = generateSecretKey()}) {
  home = normaliseHome(home);
  const signerPubkey = getPublicKey(signerSecret);
  const userPubkey = getPublicKey(userSecret);
  const secret = bytesToHex(generateSecretKey()).slice(0, 32);
  const state = {bound: null, secretUsed: false, log: []};
  const relay = await Relay.connect(relayUrl);

  const respond = async (client, id, result, error) => {
    const content = nip44.encrypt(JSON.stringify(error ? {id, result: '', error} : {id, result}), nip44.getConversationKey(signerSecret, client));
    await relay.publish(finalizeEvent({kind: KIND, created_at: Math.floor(Date.now() / 1000), tags: [['p', client]], content}, signerSecret));
  };

  relay.subscribe([{kinds: [KIND], '#p': [signerPubkey], limit: 0}], {
    onevent: async ev => {
      let req;
      try { req = JSON.parse(nip44.decrypt(ev.content, nip44.getConversationKey(signerSecret, ev.pubkey))); } catch { return; }
      const {id, method, params = []} = req;
      const client = ev.pubkey;
      const entry = {method, client, at: Date.now()};
      state.log.push(entry);
      const refuse = reason => { entry.refused = reason; return respond(client, id, null, reason); };
      if (method === 'connect') {
        if (params[0] !== signerPubkey) return refuse('wrong signer pubkey');
        if (state.bound === client) return respond(client, id, 'ack');
        if (state.secretUsed || params[1] !== secret) return refuse('secret invalid or already used');
        state.secretUsed = true;
        state.bound = client;
        return respond(client, id, 'ack');
      }
      if (client !== state.bound) return refuse('unauthorized client');
      if (method === 'ping') return respond(client, id, 'pong');
      if (method === 'get_public_key') return respond(client, id, userPubkey);
      if (method === 'sign_event') {
        let template;
        try { template = JSON.parse(params[0]); } catch { return refuse('malformed event'); }
        const why = policy(template, home);
        if (why) return refuse(why);
        const {kind, created_at, tags, content} = template;
        return respond(client, id, JSON.stringify(finalizeEvent({kind, created_at, tags, content}, userSecret)));
      }
      return refuse(`method ${method} not permitted`);
    },
  });

  const bunker = `bunker://${signerPubkey}?${new URLSearchParams({relay: relayUrl, secret, home})}`;
  return {bunker, signerPubkey, userPubkey, userSecret, secret, home, state, close: () => relay.close()};
}
