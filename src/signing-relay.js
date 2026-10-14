import { WebSocketServer } from 'ws';
import { verifyEvent, matchFilter } from 'nostr-tools';
import { now } from './nostr.js';

// Ephemeral NIP-01 transport for one NIP-46 client/signer pair. This port is
// reachable only on the Compose network; signed payloads remain NIP-44 encrypted.
export function serveSigningRelay(config, port = 8080) {
  const server = new WebSocketServer({ port, maxPayload: 2 ** 20 });
  const peers = new Map([[config.pubkey, config.clientPubkey], [config.clientPubkey, config.pubkey]]);
  if (![...peers.keys()].every(k => /^[0-9a-f]{64}$/.test(k))) throw new Error('Invalid relay participants');
  const history = new Map();
  server.on('connection', ws => {
    ws.subs = new Map();
    ws.on('error', () => {});
    ws.on('message', raw => {
      try {
        const [type, id, filter] = JSON.parse(raw.toString());
        if (type === 'REQ') {
          if (typeof id !== 'string' || id.length > 128 || ws.subs.size >= 8) return;
          if (filter?.kinds?.length !== 1 || filter.kinds[0] !== 24133 ||
            filter['#p']?.length !== 1 || !peers.has(filter['#p'][0])) {
            ws.send(JSON.stringify(['CLOSED', id, 'restricted: NIP-46 pair only'])); return;
          }
          ws.subs.set(id, filter);
          for (const event of history.values()) if (event.created_at >= now() - 120 && matchFilter(filter, event)) ws.send(JSON.stringify(['EVENT', id, event]));
          ws.send(JSON.stringify(['EOSE', id]));
        } else if (type === 'CLOSE') ws.subs.delete(id);
        else if (type === 'EVENT') {
          const event = id;
          const valid = event.kind === 24133 && verifyEvent(event) && peers.has(event.pubkey) &&
            event.tags.length === 1 && event.tags[0].length === 2 && event.tags[0][0] === 'p' &&
            event.tags[0][1] === peers.get(event.pubkey) && Math.abs(event.created_at - now()) <= 120;
          if (!valid) { ws.send(JSON.stringify(['OK', event.id, false, 'restricted: NIP-46 pair only'])); return; }
          for (const [key, value] of history) if (value.created_at < now() - 120) history.delete(key);
          history.set(event.id, event);
          while (history.size > 256) history.delete(history.keys().next().value);
          ws.send(JSON.stringify(['OK', event.id, true, '']));
          for (const client of server.clients) for (const [sid, f] of client.subs) {
            if (matchFilter(f, event)) client.send(JSON.stringify(['EVENT', sid, event]));
          }
        }
      } catch { /* malformed input has no effect */ }
    });
  });
  server.on('listening', () => console.log('Private NIP-46 relay listening'));
  return server;
}
