// Launcher page. Reads one code from the fragment (and clears it from history
// before doing anything else), then either pairs with the home signer or
// fetches, verifies and unseals an app and hands it to the service worker.
// Exposes window.qrw for the page UI and the e2e driver.

import {parseFragment, homeTarget} from './lib/codes.mjs';
import {unseal} from './lib/unseal.mjs';
import {kv, resources} from './lib/idb.mjs';
import {BunkerSigner, generateSecretKey, bytesToHex, hexToBytes} from './vendor/nip46.mjs';

// Take the fragment and drop it from the URL and history entry at once. A code
// opened in a tab already on the launcher changes only the fragment, which is a
// same-document navigation: it arrives as `hashchange`, not as a page load.
const take = () => {
  const f = location.hash;
  if (f) history.replaceState(null, '', location.pathname + location.search);
  return f;
};
const fragment = take();

// `doc` identifies this page load and `seq` counts codes handled in it, so a watcher can tell a fresh result from the last one.
const status = {phase: 'start', doc: crypto.randomUUID(), seq: 0, fragmentCleared: location.hash === ''};
const show = patch => {
  Object.assign(status, patch);
  const el = document.getElementById('status');
  if (el) el.textContent = JSON.stringify(status, null, 2);
};
const hex = b => bytesToHex(b);
const timeout = (p, ms, what) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error(`${what} timed out`)), ms))]);

async function worker() {
  const reg = await navigator.serviceWorker.register('/sw.mjs', {type: 'module', scope: '/'});
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise(r => navigator.serviceWorker.addEventListener('controllerchange', r, {once: true}));
  }
  return reg;
}

function ask(message, transfer = [], ms = 15000) {
  return timeout(new Promise((resolve, reject) => {
    const ch = new MessageChannel();
    ch.port1.onmessage = e => (e.data.ok ? resolve(e.data) : reject(new Error(e.data.error)));
    navigator.serviceWorker.controller.postMessage(message, [ch.port2, ...transfer]);
  }), ms, `service worker ${message.type}`);
}

let signer = null;
async function session() {
  const cfg = await kv.get('config');
  if (!cfg) throw new Error('not paired: scan the home code first');
  signer ??= BunkerSigner.fromBunker(hexToBytes(cfg.client), {pubkey: cfg.signer, relays: cfg.relays});
  return {cfg, signer};
}

/**
 * Nothing a link carries is acted on until the person confirms it on this page:
 * any site can navigate here with a crafted fragment. Resolves on Confirm,
 * rejects on Cancel. (The launcher must also be served with frame-ancestors
 * 'none' so the buttons cannot be clickjacked.)
 */
function consent(summary) {
  show({phase: 'confirm', confirm: summary});
  const box = document.getElementById('consent');
  document.getElementById('consent-text').textContent = JSON.stringify(summary, null, 2);
  box.hidden = false;
  return new Promise((resolve, reject) => {
    const done = ok => () => { box.hidden = true; show({confirm: undefined}); ok ? resolve() : reject(new Error('cancelled by user')); };
    document.getElementById('confirm').onclick = done(true);
    document.getElementById('cancel').onclick = done(false);
  });
}

/** Re-pairing starts clean: a module or data from the previous pairing must not carry over. */
async function wipe() {
  await kv.delete('boot');
  await resources.clear();
  await caches.delete('qrw-blobs');
  await ask({type: 'reset'});
  signer = null;
}

async function pair(home) {
  const existing = await kv.get('config');
  await consent({action: 'pair with home', home: home.home, signer: home.signer, relays: home.relays,
    replaces: existing ? existing.home : null, warning: existing ? 'replaces your current pairing and wipes this node' : undefined});
  show({phase: 'pairing', home: home.home});
  const client = generateSecretKey();
  const s = BunkerSigner.fromBunker(client, {pubkey: home.signer, relays: home.relays, secret: home.secret});
  // Prove the new pairing before touching the old one: a failed pair leaves this node as it was.
  await timeout(s.connect(), 15000, 'connect');
  const owner = await timeout(s.getPublicKey(), 15000, 'get_public_key');
  if (existing) await wipe();
  // The secret is single-use, so it is not kept; the client key is what the signer has bound.
  await kv.set('config', {signer: home.signer, relays: home.relays, home: home.home, owner, client: hex(client)});
  signer = s;
  show({phase: 'paired', paired: true, owner});
}

async function fetchBlob(pointer, cfg) {
  const root = hex(pointer.root);
  const cache = await caches.open('qrw-blobs');
  const sources = [
    ['cache', async () => (await cache.match(`/blob/${root}`))?.arrayBuffer()],
    ['home web seed', () => readCapped(new URL(`seed/${root}`, cfg.home), pointer.length)],
  ];
  const tried = [];
  for (const [name, get] of sources) {
    let buf;
    try { buf = await get(); } catch (e) { tried.push(`${name}: ${e.message}`); continue; }
    if (!buf) { tried.push(`${name}: absent`); continue; }
    const blob = new Uint8Array(buf);
    try {
      const app = await unseal(pointer, blob);
      await cache.put(`/blob/${root}`, new Response(blob));
      return {app, source: name, tried};
    } catch (e) {
      tried.push(`${name}: ${e.message}`);
      // Rule 3 means this source served the wrong bytes: try the next one.
      // Any later rule means the bytes matched the pointer, so the pointer itself is bad.
      if (e.rule !== 3) throw Object.assign(e, {tried});
    }
  }
  throw Object.assign(new Error('no source served the blob'), {rule: 2, tried});
}

/** Fetches at most `max` bytes within `ms`: an untrusted source cannot exhaust memory or stall the launcher. */
async function readCapped(url, max, ms = 30000) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(new Error('timed out')), ms);
  try {
    const r = await fetch(url, {cache: 'no-store', signal: abort.signal});
    if (!r.ok) return undefined;
    if (Number(r.headers.get('content-length') ?? 0) > max) throw new Error('larger than the pointer says');
    const out = new Uint8Array(max);
    let at = 0;
    for (const reader = r.body.getReader(); ;) {
      const {done, value} = await reader.read();
      if (done) break;
      if (at + value.length > max) { abort.abort(); throw new Error('larger than the pointer says'); }
      out.set(value, at);
      at += value.length;
    }
    return out.subarray(0, at);
  } finally {
    clearTimeout(timer);
  }
}

async function boot(pointer) {
  const {cfg} = await session();
  await consent({action: 'run app', objectId: hex(pointer.objectId), blobBytes: pointer.length, home: cfg.home});
  show({phase: 'fetching'});
  const {app, source, tried} = await fetchBlob(pointer, cfg);
  show({phase: 'starting', source, tried});
  const bytes = app.bytes.slice();
  const r = await ask({type: 'boot', module: bytes.buffer, objectId: hex(app.objectId), owner: cfg.owner, home: cfg.home}, [bytes.buffer]);
  show({phase: 'running', booted: true, objectId: hex(app.objectId), instance: r.instance});
}

async function nip98(url, method, body) {
  const {signer} = await session();
  const payload = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', body)));
  const tags = [['u', url], ['method', method]];
  if (body.length) tags.push(['payload', payload]);
  const ev = await timeout(signer.signEvent({kind: 27235, created_at: Math.floor(Date.now() / 1000), tags, content: ''}), 15000, 'sign_event');
  return 'Nostr ' + btoa(JSON.stringify(ev));
}

/** Write locally, then push the same signed request home. */
async function put(path, text, contentType = 'text/plain') {
  const {cfg} = await session();
  const body = new TextEncoder().encode(text);
  const target = homeTarget(cfg.home, path);
  const authorization = await nip98(target, 'PUT', body);
  const init = {method: 'PUT', headers: {authorization, 'content-type': contentType}, body};
  const local = await fetch(`/pod${path}`, init);
  const remote = await fetch(target, init);
  return {local: local.status, home: remote.status, etag: local.headers.get('etag')};
}

async function get(path) {
  const r = await fetch(`/pod${path}`, {cache: 'no-store'});
  return {status: r.status, text: await r.text(), etag: r.headers.get('etag'), instance: r.headers.get('x-qrw-instance'),
    loads: r.headers.get('x-qrw-loads'), contentType: r.headers.get('content-type')};
}

/** Asks the signer to sign an arbitrary template; returns the event or the refusal (policy tests). */
async function trySign(template) {
  const {signer} = await session();
  try { return {event: await timeout(signer.signEvent(template), 10000, 'sign_event')}; } catch (e) { return {refused: String(e.message ?? e)}; }
}

window.qrw = {status, put, get, trySign, workerStatus: () => ask({type: 'status'})};

// Codes queue behind worker registration, but are taken (and cleared from the URL) as they arrive.
const ready = worker();
let queue = ready.catch(() => {});
window.addEventListener('hashchange', () => { const f = take(); if (f) handle(f); });
const handle = f => (queue = queue.then(async () => {
  // Reset per-code fields so a stale result can never be read as this one's.
  show({phase: 'reading', seq: status.seq + 1, fragmentCleared: location.hash === '',
    error: undefined, rule: undefined, tried: undefined, source: undefined});
  try {
    const code = parseFragment(f);
    if (code.type === 'home') await pair(code.home);
    else await boot(code.pointer);
  } catch (e) {
    show({phase: 'error', error: String(e.message ?? e), rule: e.rule, tried: e.tried});
  }
}));

(async () => {
  try {
    await ready;
    show({phase: 'ready', worker: true});
    if (fragment) return handle(fragment);
    const s = await ask({type: 'status'});
    show({phase: s.booted ? 'running' : 'idle', booted: s.booted});
  } catch (e) {
    show({phase: 'error', error: String(e.message ?? e)});
  }
})();
