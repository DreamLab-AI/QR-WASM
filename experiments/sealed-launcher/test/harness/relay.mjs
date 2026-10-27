// Minimal NIP-01 relay for the tests: verifies every event's id and signature
// (nostr-tools verifyEvent), stores regular events, forwards ephemeral ones
// (kinds 20000–29999, e.g. NIP-46 kind 24133) to live subscriptions only.
import {WebSocketServer} from 'ws';
import {verifyEvent} from 'nostr-tools/pure';

function matches(f, ev) {
  if (f.ids && !f.ids.includes(ev.id)) return false;
  if (f.kinds && !f.kinds.includes(ev.kind)) return false;
  if (f.authors && !f.authors.includes(ev.pubkey)) return false;
  if (f.since && ev.created_at < f.since) return false;
  if (f.until && ev.created_at > f.until) return false;
  for (const [k, vals] of Object.entries(f)) {
    if (k[0] !== '#' || k.length !== 2) continue;
    if (!ev.tags.some(t => t[0] === k[1] && vals.includes(t[1]))) return false;
  }
  return true;
}

export function startRelay({port, host = '0.0.0.0'}) {
  const stored = [];
  const subs = new Map(); // ws → Map(id → filters)
  const wss = new WebSocketServer({port, host});
  const stats = {events: 0, rejected: 0};
  wss.on('connection', ws => {
    subs.set(ws, new Map());
    ws.on('close', () => subs.delete(ws));
    ws.on('message', raw => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return ws.send(JSON.stringify(['NOTICE', 'invalid JSON'])); }
      const [type, ...rest] = msg;
      if (type === 'EVENT') {
        const ev = rest[0];
        if (!ev || !verifyEvent(ev)) { stats.rejected++; return ws.send(JSON.stringify(['OK', ev?.id ?? '', false, 'invalid: bad id or signature'])); }
        stats.events++;
        if (!(ev.kind >= 20000 && ev.kind < 30000)) stored.push(ev);
        ws.send(JSON.stringify(['OK', ev.id, true, '']));
        for (const [client, m] of subs) for (const [id, filters] of m) {
          if (filters.some(f => matches(f, ev))) client.send(JSON.stringify(['EVENT', id, ev]));
        }
      } else if (type === 'REQ') {
        const [id, ...filters] = rest;
        subs.get(ws).set(id, filters);
        for (const ev of stored) if (filters.some(f => f.limit !== 0 && matches(f, ev))) ws.send(JSON.stringify(['EVENT', id, ev]));
        ws.send(JSON.stringify(['EOSE', id]));
      } else if (type === 'CLOSE') {
        subs.get(ws).delete(rest[0]);
      }
    });
  });
  return {stats, close: () => new Promise(r => { for (const c of wss.clients) c.terminate(); wss.close(r); })};
}
