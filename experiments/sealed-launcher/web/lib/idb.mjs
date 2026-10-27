// IndexedDB for the launcher page and service worker (both may open it).
//   kv:        "config" (pairing, written by the page), "boot" (module + owner, written by the worker)
//   resources: the ephemeral pod's store, keyed by pod path

const open = () => new Promise((resolve, reject) => {
  const req = indexedDB.open('qrw', 1);
  req.onupgradeneeded = () => {
    req.result.createObjectStore('kv');
    req.result.createObjectStore('resources');
  };
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

// One shared open, reset if the browser closes the connection or another context upgrades it.
let opening;
const database = () => (opening ??= open().then(d => {
  d.onclose = d.onversionchange = () => { d.close(); opening = undefined; };
  return d;
}, e => { opening = undefined; throw e; }));

async function tx(store, mode, fn) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const r = fn(t.objectStore(store));
    t.oncomplete = () => resolve(r?.result);
    t.onerror = t.onabort = () => reject(t.error);
  });
}

export const kv = {
  get: key => tx('kv', 'readonly', s => s.get(key)),
  set: (key, value) => tx('kv', 'readwrite', s => s.put(value, key)),
  delete: key => tx('kv', 'readwrite', s => s.delete(key)),
};

export const resources = {
  get: path => tx('resources', 'readonly', s => s.get(path)),
  set: (path, rec) => tx('resources', 'readwrite', s => s.put(rec, path)),
  delete: path => tx('resources', 'readwrite', s => s.delete(path)),
  keys: () => tx('resources', 'readonly', s => s.getAllKeys()),
  clear: () => tx('resources', 'readwrite', s => s.clear()),
};
