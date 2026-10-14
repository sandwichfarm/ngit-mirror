import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSecretKey, getPublicKey, finalizeEvent, nip44 } from 'nostr-tools';
import { Relay, RemoteSigner, now, hex } from '../src/nostr.js';
import { handleRequest } from '../src/signer.js';
import { serveSigningRelay } from '../src/signing-relay.js';

test('NIP-46 encrypted request/reply over the private relay and permission denial', async t => {
  const secret = generateSecretKey(), clientSecret = generateSecretKey(), pubkey = getPublicKey(secret);
  const config = { pubkey, clientPubkey: getPublicKey(clientSecret), org: 'sandwichfarm', signerRelays: [] };
  const server = serveSigningRelay(config, 0);
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { for (const client of server.clients) client.terminate(); server.close(); });
  const url = `ws://127.0.0.1:${server.address().port}`;
  const credentials = { secret: hex(secret), clientPubkey: getPublicKey(clientSecret) };
  config.signerRelays = [url];
  const relay = await new Relay(url).open(); t.after(() => relay.close());
  relay.subscribe({ kinds: [24133], '#p': [pubkey] }, { event: event => {
    void (async () => {
      const key = nip44.v2.utils.getConversationKey(secret, event.pubkey);
      const request = JSON.parse(nip44.v2.decrypt(event.content, key));
      let response;
      try { response = { id: request.id, result: handleRequest(request, event.pubkey, credentials, config) }; }
      catch (e) { response = { id: request.id, error: e.message }; }
      await relay.publish(finalizeEvent({ kind: 24133, tags: [['p', event.pubkey]], created_at: now(), content: nip44.v2.encrypt(JSON.stringify(response), key) }, secret));
    })();
  } });
  const signer = await new RemoteSigner({ remotePubkey: pubkey, clientSecret, relays: [url] }).open();
  t.after(() => signer.close());
  assert.equal(await signer.request('get_public_key'), pubkey);
  assert.equal(await signer.request('ping'), 'pong');
  signer.relay.ws.terminate();
  await signer.relay.closed;
  assert.equal(await signer.request('ping'), 'pong');
  await assert.rejects(signer.request('nip44_decrypt', ['bad', 'bad']), /denied/);
  const signed = await signer.sign({ kind: 30618, tags: [['d', 'sandwichfarm--example'], ['refs/heads/main', 'a'.repeat(40)], ['HEAD', 'ref: refs/heads/main']], content: '', created_at: now() }, pubkey);
  assert.equal(signed.kind, 30618);
  await assert.rejects(signer.sign({ kind: 1, tags: [], content: 'post', created_at: now() }, pubkey), /denied/);
  await assert.rejects(relay.publish(finalizeEvent({ kind: 1, tags: [], content: 'post', created_at: now() }, secret)), /restricted/);
  await assert.rejects(relay.publish(finalizeEvent({ kind: 24133, tags: [['p', pubkey]], content: 'bad', created_at: now() }, generateSecretKey())), /restricted/);
});
