// Service worker: runs the unsealed pod and serves same-origin /pod/*.
//
// The page verifies and unseals; this worker trusts nothing it is handed. It
// re-hashes the module against the object ID and re-checks the import
// allowlist on every load, including each cold start from IndexedDB (workers
// are stopped when idle). Requests reach the module with url = home + path,
// so the ephemeral pod is a write-through replica of the home pod's namespace
// and one NIP-98 signature authorises the local write and the push home.

import {createPod} from './lib/pod-shell.mjs';
import {serve} from './lib/podstore.mjs';
import {kv, resources} from './lib/idb.mjs';

const INSTANCE = crypto.randomUUID();
let pod = null, home = null, loads = 0;

self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

async function load(rec) {
  const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', rec.module)));
  if (digest !== rec.objectId) throw new Error('module does not match its object ID');
  const module = await WebAssembly.compile(rec.module);
  if (WebAssembly.Module.imports(module).length) throw new Error('module imports are not allowed');
  pod = await createPod(module, rec.owner);
  home = rec.home;
  loads++;
}

async function ensure() {
  if (pod) return true;
  const rec = await kv.get('boot');
  if (!rec) return false;
  await load(rec);
  return true;
}

self.addEventListener('message', e => {
  const port = e.ports[0];
  const reply = p => p.then(v => port.postMessage({ok: true, ...v}), err => port.postMessage({ok: false, error: String(err)}));
  if (e.data?.type === 'boot') {
    const rec = {module: new Uint8Array(e.data.module), objectId: e.data.objectId, owner: e.data.owner, home: e.data.home};
    reply(load(rec).then(() => kv.set('boot', rec)).then(() => ({instance: INSTANCE})));
  } else if (e.data?.type === 'status') {
    reply(ensure().then(booted => ({booted, instance: INSTANCE, loads})));
  }
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith('/pod/')) return;
  e.respondWith(handle(e.request, url));
});

async function handle(request, url) {
  const meta = {'x-qrw-instance': INSTANCE, 'x-qrw-loads': String(loads)};
  try {
    if (!(await ensure())) return new Response('no app booted', {status: 503, headers: meta});
    const path = url.pathname.slice('/pod'.length);
    const res = await serve(pod, resources, {
      method: request.method,
      url: new URL(path.slice(1), home).href,
      path,
      headers: Object.fromEntries([...request.headers].map(([k, v]) => [k.toLowerCase(), v])),
      body: new Uint8Array(await request.arrayBuffer()),
      now: Math.floor(Date.now() / 1000),
    });
    return new Response(res.body, {status: res.status, headers: {...res.headers, ...meta, 'x-qrw-loads': String(loads)}});
  } catch (err) {
    return new Response(String(err), {status: 500, headers: meta});
  }
}
