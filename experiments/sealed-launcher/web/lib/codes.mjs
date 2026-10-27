// The two codes as they arrive in the launcher's URL fragment.
//
//   app:  #<radix-43 QS pointer>               (upper-case alphabet, url43 transport)
//   home: #bunker://<signer>?relay=…&secret=…&home=…   (NIP-46 bunker URI plus `home`)
//
// A fragment never reaches a server. The launcher strips it from history as
// soon as it has been read (see launcher.mjs).

import * as base43 from './base43.mjs';
import * as pointer from './pointer.mjs';

const HEX64 = /^[0-9a-f]{64}$/;

/** The home pod URL the signer policy is scoped to: http(s), no query or fragment, path ending in '/'. */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
/** Cleartext would expose NIP-98 headers in transit: only loopback (development) may use it. */
const secureOrLoopback = (u, secure) => u.protocol === secure || (u.protocol === secure.replace('s:', ':') && LOOPBACK.has(u.hostname));

export function normaliseHome(raw) {
  if (/[?#]/.test(raw)) throw new SyntaxError('home: no query or fragment');
  const u = new URL(raw);
  if (!secureOrLoopback(u, 'https:')) throw new SyntaxError('home: must be https (http only on loopback)');
  if (u.search || u.hash || u.username || u.password) throw new SyntaxError('home: no query, fragment or credentials');
  if (!u.pathname.endsWith('/')) throw new SyntaxError("home: path must end in '/'");
  return u.href;
}

/** True when `target` lies under `home`: same origin and a path prefix ending at a '/'. */
export function underHome(target, home) {
  let t, h;
  try { t = new URL(target); h = new URL(home); } catch { return false; }
  // Encoded '/', '\\' or '.' would let a server that decodes before routing climb out of home.
  if (/%(2f|5c|2e)/i.test(t.pathname)) return false;
  return t.origin === h.origin && t.pathname.startsWith(h.pathname) && !t.search && !t.hash;
}

/**
 * The home URL a pod path maps to: `home` + path by string, never by URL
 * resolution (which would let "/http:/evil/x" escape), and checked to stay under home.
 */
export function homeTarget(home, path) {
  if (!path.startsWith('/') || path.startsWith('//') || /[\s\\#?]/.test(path)) throw new SyntaxError('pod path not allowed');
  const target = new URL(home + path.slice(1)).href;
  if (!underHome(target, home)) throw new SyntaxError('pod path leaves the home namespace');
  return target;
}

export function parseHome(uri) {
  const u = new URL(uri);
  if (u.protocol !== 'bunker:') throw new SyntaxError('home: not a bunker URI');
  const signer = u.host || u.pathname.replace(/^\/\//, '');
  if (!HEX64.test(signer)) throw new SyntaxError('home: signer must be 64 lower-case hex');
  const relays = u.searchParams.getAll('relay');
  if (relays.length === 0) throw new SyntaxError('home: no relay');
  for (const r of relays) if (!secureOrLoopback(new URL(r), 'wss:')) throw new SyntaxError('home: relay must be wss (ws only on loopback)');
  const secret = u.searchParams.get('secret');
  if (!secret) throw new SyntaxError('home: no secret');
  return {signer, relays, relay: relays[0], secret, home: normaliseHome(u.searchParams.get('home') ?? '')};
}

export function homeLink(launcher, {signer, relay, secret, home}) {
  const q = new URLSearchParams({relay, secret, home});
  return `${launcher}#bunker://${signer}?${q}`;
}

export function parseFragment(hash) {
  const f = hash.startsWith('#') ? hash.slice(1) : hash;
  if (f.startsWith('bunker://')) return {type: 'home', home: parseHome(f)};
  if (/^[0-9A-Z$*+\-./:]+$/.test(f)) return {type: 'app', pointer: pointer.decode(base43.decode(f))};
  throw new SyntaxError('fragment is neither an app code nor a home code');
}
