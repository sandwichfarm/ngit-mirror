import { finalizeEvent, getPublicKey, nip44 } from 'nostr-tools';
import { Relay, now, sleep, unhex } from './nostr.js';
import { PERMISSIONS, validateSigningEvent } from './policy.js';

export function handleRequest(request, client, credentials, config) {
  if (client !== credentials.clientPubkey) throw new Error('Client denied');
  if (!request || !Array.isArray(request.params)) throw new Error('Invalid request');
  switch (request.method) {
    case 'ping': return 'pong';
    case 'get_public_key': return config.pubkey;
    case 'switch_relays': return JSON.stringify(config.signerRelays);
    case 'connect': {
      const requested = (request.params[2] || '').split(',').filter(Boolean);
      if (requested.some(p => !PERMISSIONS.split(',').includes(p))) throw new Error('Permission denied');
      return 'ack';
    }
    case 'sign_event': {
      const event = validateSigningEvent(JSON.parse(request.params[0]), config);
      return JSON.stringify(finalizeEvent({ kind: event.kind, content: '', tags: event.tags,
        created_at: event.created_at }, unhex(credentials.secret)));
    }
    default: throw new Error('Method denied');
  }
}

export async function serveSigner(credentials, config, urls = config.signerRelays) {
  const secret = unhex(credentials.secret);
  if (getPublicKey(secret) !== config.pubkey) throw new Error('Signer identity does not match config');
  await Promise.all(urls.map(async url => {
    for (;;) {
      const relay = new Relay(url);
      try {
        await relay.open();
        const seen = new Map();
        relay.subscribe({ kinds: [24133], authors: [credentials.clientPubkey], '#p': [config.pubkey], since: now() - 60 }, {
          event: event => {
            if (Math.abs(event.created_at - now()) > 120 || seen.has(event.id)) return;
            seen.set(event.id, now());
            for (const [id, time] of seen) if (time < now() - 120) seen.delete(id);
            void (async () => {
              const conversation = nip44.v2.utils.getConversationKey(secret, event.pubkey);
              let request;
              try { request = JSON.parse(nip44.v2.decrypt(event.content, conversation)); } catch { return; }
              if (typeof request.id !== 'string' || request.id.length > 256) return;
              let response;
              try { response = { id: request.id, result: handleRequest(request, event.pubkey, credentials, config) }; }
              catch (error) { response = { id: request.id, error: error.message }; }
              const reply = finalizeEvent({ kind: 24133, created_at: now(), tags: [['p', event.pubkey]],
                content: nip44.v2.encrypt(JSON.stringify(response), conversation) }, secret);
              await relay.publish(reply);
            })().catch(error => console.error(`Signer response failed: ${error.message}`));
          }, error: () => relay.close(),
        });
        console.log(`Signer connected: ${url}`);
        await relay.closed;
      } catch (error) { console.error(`Signer relay unavailable: ${url}: ${error.message}`); }
      finally { relay.close(); }
      await sleep(5000);
    }
  }));
}
