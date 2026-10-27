// Storage around the pure-function pod (experiments/minimal-pod): what is
// stored at a path goes in, the single write the module returns is applied.
// The same code serves the ephemeral pod (IndexedDB, in the service worker)
// and the home pod harness (a Map, in Node).
//
// store: {get(path) → {contentType, body} | undefined, set(path, rec), delete(path), keys() → [path]}

/** Containers are implicit: "/" always exists, any other "/…/" exists while something lies beneath it. */
export async function storedFor(store, path) {
  if (!path.endsWith('/')) {
    const rec = await store.get(path);
    return rec ? {kind: 'resource', contentType: rec.contentType, body: rec.body} : {kind: ''};
  }
  const children = new Set();
  for (const key of await store.keys()) {
    if (!key.startsWith(path) || key === path) continue;
    const rest = key.slice(path.length);
    const slash = rest.indexOf('/');
    children.add(slash === -1 ? rest : rest.slice(0, slash + 1));
  }
  if (path !== '/' && children.size === 0) return {kind: ''};
  return {kind: 'container', children: [...children].sort()};
}

export async function applyOp(store, op) {
  if (op.kind === 'put') await store.set(op.path, {contentType: op.contentType, body: op.body.slice()});
  else if (op.kind === 'delete') await store.delete(op.path);
  else if (op.kind !== '') throw new Error(`unknown op ${op.kind}`);
}

const NULL_BODY = new Set([101, 204, 205, 304]);

/**
 * One request through the module, then its write.
 * @param pod     createPod(...) from experiments/minimal-pod/shell.mjs
 * @param request {method, url, path, headers: {lower-case: value}, body: Uint8Array, now}
 */
export async function serve(pod, store, request) {
  const result = pod.handle(request, await storedFor(store, request.path));
  if (result.status < 400) await applyOp(store, result.op);
  const empty = NULL_BODY.has(result.status) || request.method === 'HEAD';
  return {status: result.status, headers: result.headers, body: empty ? null : result.body, error: result.error};
}

export function mapStore() {
  const m = new Map();
  return {get: async p => m.get(p), set: async (p, r) => void m.set(p, r), delete: async p => void m.delete(p),
    keys: async () => [...m.keys()], raw: m};
}
