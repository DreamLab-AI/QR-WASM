// HTTP servers for the e2e run:
//  - launcher: the static web/ app (service worker at the root scope);
//  - home:     the owner's main pod. The same hashed P2 module, run natively in
//              Node with a Map store, with CORS for the launcher origin. It is
//              also the web seed: sealed blobs are ordinary pod resources at
//              /seed/<pieces-root-hex>, PUT by the owner and readable by anyone.
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {createPod} from '../../../minimal-pod/shell.mjs';
import {serve, mapStore} from '../../web/lib/podstore.mjs';

const here = new URL('../../', import.meta.url);
const ROUTES = {
  '/': 'web/index.html', '/index.html': 'web/index.html', '/launcher.mjs': 'web/launcher.mjs', '/sw.mjs': 'web/sw.mjs',
  '/vendor/nip46.mjs': 'web/vendor/nip46.mjs', '/lib/pod-shell.mjs': '../minimal-pod/shell.mjs',
};
for (const f of ['base43', 'bep52', 'codes', 'cose', 'envelope', 'idb', 'pointer', 'podstore', 'unseal']) ROUTES[`/lib/${f}.mjs`] = `web/lib/${f}.mjs`;

export function startLauncher({port, host = '0.0.0.0'}) {
  const server = http.createServer(async (req, res) => {
    const file = ROUTES[new URL(req.url, 'http://x').pathname];
    if (!file || req.method !== 'GET') { res.writeHead(404).end(); return; }
    const type = file.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8';
    res.writeHead(200, {'content-type': type, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff'});
    res.end(await readFile(new URL(file, here)));
  });
  return new Promise(r => server.listen(port, host, () => r({close: () => new Promise(c => server.close(c))})));
}

export async function startHome({port, host = '0.0.0.0', origin, owner, launcherOrigin, modulePath}) {
  const pod = await createPod(await readFile(modulePath), owner);
  const store = mapStore();
  const cors = {
    'access-control-allow-origin': launcherOrigin,
    'access-control-expose-headers': 'ETag, Link, WWW-Authenticate, Content-Type',
    vary: 'Origin',
  };
  const requests = [];
  const server = http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {...cors, 'access-control-allow-methods': 'GET, HEAD, PUT, DELETE',
        'access-control-allow-headers': 'authorization, content-type, if-match, if-none-match', 'access-control-max-age': '60'}).end();
      return;
    }
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const path = new URL(req.url, origin).pathname;
    const out = await serve(pod, store, {
      method: req.method, url: origin + path, path, headers: req.headers,
      body: new Uint8Array(Buffer.concat(chunks)), now: Math.floor(Date.now() / 1000),
    });
    requests.push({method: req.method, path, status: out.status});
    res.writeHead(out.status, {...out.headers, ...cors});
    res.end(out.body ? Buffer.from(out.body) : undefined);
  });
  await new Promise(r => server.listen(port, host, r));
  return {store, requests, close: () => new Promise(c => server.close(c))};
}
