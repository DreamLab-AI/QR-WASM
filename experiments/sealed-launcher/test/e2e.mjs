// End-to-end gate in a real Chrome (the browsercontainer sidecar), driven over
// raw CDP so it re-runs without an agent:
//
//   node test/e2e.mjs            (needs: sealer built, `npm run build`, docker access to browsercontainer)
//
// It starts relay, signer, home pod and launcher here, forwards ports
// 8800–8802 onto the sidecar's localhost with socat (localhost is a secure
// context, which service workers require), then scans the home code and the
// app code by navigation, exactly as a phone camera would open them.
import {execFileSync} from 'node:child_process';
import {lookup} from 'node:dns/promises';
import {networkInterfaces} from 'node:os';
import {writeFileSync, readFileSync, mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import WebSocket from 'ws';
import {finalizeEvent} from 'nostr-tools/pure';
import {startRelay} from './harness/relay.mjs';
import {startSigner} from './harness/signer.mjs';
import {startLauncher, startHome} from './harness/servers.mjs';
import * as base43 from '../web/lib/base43.mjs';

const here = new URL('../', import.meta.url).pathname;
const P2 = new URL('../../minimal-pod/fixtures/P2-pod-k256-bump.wasm', import.meta.url).pathname;
const PORTS = {launcher: 8800, home: 8801, relay: 8802};
const LAUNCHER = `http://localhost:${PORTS.launcher}/`, HOME = `http://localhost:${PORTS.home}/`, RELAY = `ws://localhost:${PORTS.relay}`;
const CDP = process.env.CDP; // default: http://<sidecar IP>:9223 (Chrome rejects non-IP Host headers)
const SIDECAR = process.env.SIDECAR ?? 'browsercontainer';

const results = [];
const step = async (name, fn) => {
  const t = Date.now();
  try {
    const detail = await fn();
    results.push({name, ok: true, ms: Date.now() - t, detail});
    console.error(`ok   ${name}`);
  } catch (e) {
    results.push({name, ok: false, ms: Date.now() - t, error: String(e.stack ?? e)});
    console.error(`FAIL ${name}\n     ${e.message}`);
  }
};
const expect = (cond, msg) => { if (!cond) throw new Error(msg); };

async function myAddressFor(host) {
  const {address} = await lookup(host, 4);
  const prefix = address.split('.').slice(0, 3).join('.');
  for (const list of Object.values(networkInterfaces())) for (const i of list ?? []) {
    if (i.family === 'IPv4' && i.address.startsWith(prefix + '.')) return i.address;
  }
  throw new Error(`no local address on ${prefix}.0/24`);
}

const sidecar = (...args) => execFileSync('docker', ['exec', SIDECAR, ...args], {stdio: ['ignore', 'pipe', 'pipe']}).toString();
const unforward = () => { try { sidecar('sh', '-c', "pkill -f 'socat TCP-LISTEN:880[0-2]' || true"); } catch {} };

class Cdp {
  static async connect(base) {
    const {webSocketDebuggerUrl} = await (await fetch(`${base}/json/version`)).json();
    const url = new URL(webSocketDebuggerUrl);
    const b = new URL(base);
    url.host = b.host;
    const ws = new WebSocket(url.href, {perMessageDeflate: false});
    await new Promise((r, j) => { ws.once('open', r); ws.once('error', j); });
    return new Cdp(ws);
  }
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map();
    ws.on('message', raw => {
      const m = JSON.parse(raw);
      if (m.id && this.pending.has(m.id)) {
        const {resolve, reject} = this.pending.get(m.id);
        this.pending.delete(m.id);
        m.error ? reject(new Error(`${m.error.message} ${m.error.data ?? ''}`)) : resolve(m.result);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({id, method, params, sessionId}));
    return new Promise((resolve, reject) => this.pending.set(id, {resolve, reject}));
  }
  async page() {
    const {browserContextId} = await this.send('Target.createBrowserContext', {disposeOnDetach: true});
    const {targetId} = await this.send('Target.createTarget', {url: 'about:blank', browserContextId});
    const {sessionId} = await this.send('Target.attachToTarget', {targetId, flatten: true});
    await this.send('Page.enable', {}, sessionId);
    const cdp = this;
    return {
      sessionId, browserContextId,
      eval: async expr => {
        const r = await cdp.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true}, sessionId);
        if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
        return r.result.value;
      },
      go: url => cdp.send('Page.navigate', {url}, sessionId),
      close: () => cdp.send('Target.disposeBrowserContext', {browserContextId}),
    };
  }
}

const statusOf = page => page.eval('window.qrw ? JSON.parse(JSON.stringify(window.qrw.status)) : null').catch(() => null);

/** Opens a code link and waits for the launcher's result for *that* code: a new document, or a later seq in the same one. */
async function scan(page, url, ms = 30000) {
  const before = await statusOf(page);
  await page.go(url);
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const s = await statusOf(page);
    const fresh = s && (s.doc !== before?.doc || s.seq > before.seq);
    if (fresh && ['paired', 'running', 'error'].includes(s.phase)) return s;
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`launcher did not settle: ${JSON.stringify(await statusOf(page))}`);
}

const servers = [];
let cdp;
try {
  const relay = startRelay({port: PORTS.relay}); servers.push(relay);
  const signer = await startSigner({relayUrl: RELAY, home: HOME}); servers.push(signer);
  servers.push(await startLauncher({port: PORTS.launcher}));
  const home = await startHome({port: PORTS.home, origin: HOME.slice(0, -1), owner: signer.userPubkey,
    launcherOrigin: LAUNCHER.slice(0, -1), modulePath: P2});
  servers.push(home);

  // Seal the pod and publish the blob to the home pod's web seed, as the owner.
  const out = mkdtempSync(join(tmpdir(), 'qrw-seal-'));
  const sealed = JSON.parse(execFileSync(join(here, 'sealer/target/release/qrw-seal'),
    [P2, '--origin', LAUNCHER.toUpperCase(), '--out', out]).toString());
  const blob = readFileSync(join(out, sealed.piecesRoot));
  const seedUrl = `${HOME}seed/${sealed.piecesRoot}`;
  const auth = finalizeEvent({kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '',
    tags: [['u', seedUrl], ['method', 'PUT'], ['payload', createHash('sha256').update(blob).digest('hex')]]}, signer.userSecret);
  const seeded = await fetch(seedUrl, {method: 'PUT', body: blob,
    headers: {authorization: 'Nostr ' + Buffer.from(JSON.stringify(auth)).toString('base64'), 'content-type': 'application/octet-stream'}});
  expect(seeded.status === 201, `seed PUT returned ${seeded.status}`);

  const me = await myAddressFor(SIDECAR);
  unforward();
  for (const p of Object.values(PORTS)) {
    execFileSync('docker', ['exec', '-d', SIDECAR, 'socat', `TCP-LISTEN:${p},bind=127.0.0.1,fork,reuseaddr`, `TCP:${me}:${p}`]);
  }
  await new Promise(r => setTimeout(r, 500));
  cdp = await Cdp.connect(CDP ?? `http://${(await lookup(SIDECAR, 4)).address}:9223`);
  const {product} = await cdp.send('Browser.getVersion');
  const page = await cdp.page();
  const homeLink = `${LAUNCHER}#${signer.bunker}`;
  const p2sha = createHash('sha256').update(readFileSync(P2)).digest('hex');
  let instanceA;

  await step('home code pairs with the remote signer; fragment removed from URL', async () => {
    const s = await scan(page, homeLink);
    expect(s.phase === 'paired', JSON.stringify(s));
    expect(s.owner === signer.userPubkey, 'owner is the user key');
    expect(s.owner !== signer.signerPubkey, 'owner is not the bunker key');
    expect(s.fragmentCleared && (await page.eval('location.href')) === LAUNCHER, 'fragment cleared');
    return {owner: s.owner};
  });

  await step('app code: fetch from home web seed, verify, unseal, boot pod in service worker', async () => {
    const s = await scan(page, sealed.appLink);
    expect(s.phase === 'running', JSON.stringify(s));
    expect(s.objectId === p2sha, 'object ID is SHA-256 of P2');
    expect(s.source === 'home web seed', `source ${s.source}`);
    expect((await page.eval('location.href')) === LAUNCHER, 'fragment cleared');
    return {source: s.source, tried: s.tried, appLinkChars: sealed.appLink.length};
  });

  await step('signed write lands locally and at home (one NIP-98 signature via NIP-46)', async () => {
    const r = await page.eval("qrw.put('/notes/a.txt', 'hello from an ephemeral node')");
    expect(r.local === 201 && r.home === 201, JSON.stringify(r));
    const rec = home.store.raw.get('/notes/a.txt');
    expect(rec && Buffer.from(rec.body).toString() === 'hello from an ephemeral node', 'home pod holds the body');
    return r;
  });

  await step('local pod serves the resource and the LDP container', async () => {
    const r = await page.eval("qrw.get('/notes/a.txt')");
    expect(r.status === 200 && r.text === 'hello from an ephemeral node', JSON.stringify(r));
    instanceA = r.instance;
    const c = await page.eval("qrw.get('/notes/')");
    expect(c.status === 200 && JSON.parse(c.text)['ldp:contains'].some(x => x['@id'] === '/notes/a.txt'), c.text);
    return {etag: r.etag, container: JSON.parse(c.text)['ldp:contains']};
  });

  await step('unsigned and wrongly signed writes are refused by the module', async () => {
    const none = await page.eval("fetch('/pod/notes/b.txt', {method: 'PUT', body: 'x'}).then(r => r.status)");
    const forged = await page.eval(`(async () => {
      const ev = {kind: 27235, created_at: Math.floor(Date.now()/1000), tags: [['u', '${HOME}notes/b.txt'], ['method', 'PUT']], content: '',
        pubkey: '${signer.userPubkey}', id: '00'.repeat(32), sig: '00'.repeat(64)};
      return fetch('/pod/notes/b.txt', {method: 'PUT', headers: {authorization: 'Nostr ' + btoa(JSON.stringify(ev))}}).then(r => r.status);
    })()`);
    expect(none === 401 && forged === 401, `${none} ${forged}`);
    return {unsigned: none, forged};
  });

  await step('signer policy refuses out-of-scope requests from the browser', async () => {
    const t = Math.floor(Date.now() / 1000);
    const outside = await page.eval(`qrw.trySign({kind: 27235, created_at: ${t}, tags: [['u', 'http://localhost:8801.evil/x'], ['method', 'PUT']], content: ''})`);
    const note = await page.eval(`qrw.trySign({kind: 1, created_at: ${t}, tags: [], content: 'hi'})`);
    expect(outside.refused?.includes('not under home') && note.refused?.includes('27235'), JSON.stringify({outside, note}));
    return {outside: outside.refused, note: note.refused};
  });

  await step('service worker stopped and restarted cold: module re-hashed, data intact', async () => {
    await cdp.send('ServiceWorker.enable', {}, page.sessionId);
    await cdp.send('ServiceWorker.stopAllWorkers', {}, page.sessionId);
    await new Promise(r => setTimeout(r, 500));
    const r = await page.eval("qrw.get('/notes/a.txt')");
    expect(r.status === 200 && r.text === 'hello from an ephemeral node', JSON.stringify(r));
    expect(r.instance && r.instance !== instanceA, `new worker instance (${instanceA} → ${r.instance})`);
    expect(r.loads === '1', `cold load from IndexedDB (loads ${r.loads})`);
    return {before: instanceA, after: r.instance};
  });

  await step('re-scanning the app code boots from the verified local cache', async () => {
    const s = await scan(page, sealed.appLink);
    expect(s.phase === 'running' && s.source === 'cache', JSON.stringify(s));
    return {source: s.source};
  });

  await step('tampered app code (wrong key) fails at rule 4 and runs nothing new', async () => {
    const p = Uint8Array.from(Buffer.from(sealed.pointer, 'hex'));
    p[40] ^= 1;
    const s = await scan(page, `${LAUNCHER.toUpperCase()}#${base43.encode(p)}`);
    expect(s.phase === 'error' && s.rule === 4, JSON.stringify(s));
    return {error: s.error};
  });

  await step('pointer to an unseeded blob fails at rule 2', async () => {
    const p = Uint8Array.from(Buffer.from(sealed.pointer, 'hex'));
    p[8] ^= 1;
    const s = await scan(page, `${LAUNCHER.toUpperCase()}#${base43.encode(p)}`);
    expect(s.phase === 'error' && s.rule === 2, JSON.stringify(s));
    return {tried: s.tried};
  });

  await step('the home code is single-use: a second browser cannot pair with it', async () => {
    const other = await cdp.page();
    const s = await scan(other, homeLink);
    await other.close();
    expect(s.phase === 'error' && /already used/.test(s.error), JSON.stringify(s));
    return {error: s.error};
  });

  await page.close();
  const passed = results.every(r => r.ok);
  writeFileSync(join(here, 'e2e-results.json'), JSON.stringify({
    recorded: new Date().toISOString().slice(0, 10), browser: product, passed,
    appLink: {chars: sealed.appLink.length, pointerBytes: sealed.pointerBytes}, blobLength: sealed.blobLength,
    homeCodeChars: homeLink.length, steps: results.map(({name, ok, ms, detail, error}) => ({name, ok, ms, ...(ok ? {detail} : {error})})),
  }, null, 2) + '\n');
  console.error(`${results.filter(r => r.ok).length}/${results.length} e2e steps passed in ${product}`);
  process.exitCode = passed ? 0 : 1;
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  cdp?.ws.close();
  unforward();
  for (const s of servers.reverse()) await Promise.resolve(s.close?.()).catch(() => {});
}
