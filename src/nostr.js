import WebSocket from 'ws';
import { randomUUID } from 'node:crypto';
import { bech32 } from '@scure/base';
import { finalizeEvent, getPublicKey, verifyEvent, nip44, matchFilter } from 'nostr-tools';

export const now = () => Math.floor(Date.now() / 1000);
export const hex = bytes => Buffer.from(bytes).toString('hex');
export const unhex = value => Uint8Array.from(Buffer.from(value, 'hex'));
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export function encodeSession({ remotePubkey, clientSecret, relays }) {
  const tlv = (type, bytes) => {
    if (bytes.length > 255) throw new Error('Session field exceeds 255 bytes');
    return [type, bytes.length, ...bytes];
  };
  const data = [...tlv(0, unhex(remotePubkey)), ...tlv(1, clientSecret),
    ...relays.flatMap(url => tlv(2, Buffer.from(url)))];
  return bech32.encode('nbunksec', bech32.toWords(Uint8Array.from(data)), 1000);
}

export function decodeSession(value) {
  const { prefix, words } = bech32.decode(value.trim(), 1000);
  if (prefix !== 'nbunksec') throw new Error('Expected NBUNKSEC');
  const bytes = bech32.fromWords(words);
  const fields = new Map();
  for (let i = 0; i < bytes.length;) {
    if (i + 2 > bytes.length) throw new Error('Truncated NBUNKSEC');
    const type = bytes[i++], length = bytes[i++];
    if (i + length > bytes.length) throw new Error('Truncated NBUNKSEC');
    fields.set(type, [...(fields.get(type) ?? []), bytes.slice(i, i + length)]);
    i += length;
  }
  if (fields.get(0)?.length !== 1 || fields.get(1)?.length !== 1 ||
      fields.get(0)[0].length !== 32 || fields.get(1)[0].length !== 32 || !fields.get(2)?.length) {
    throw new Error('Invalid NBUNKSEC fields');
  }
  return { remotePubkey: hex(fields.get(0)[0]), clientSecret: fields.get(1)[0],
    relays: fields.get(2).map(bytes => Buffer.from(bytes).toString()) };
}

// Bounded relay operations; every event is verified before application code sees it.
export class Relay {
  constructor(url, timeout = 20000) {
    this.url = url;
    this.timeout = timeout;
    this.subs = new Map();
    this.acks = new Map();
  }
  async open() {
    this.ws = new WebSocket(this.url, { handshakeTimeout: this.timeout, maxPayload: 2 ** 22 });
    this.ws.on('error', () => {});
    this.ws.on('message', raw => this.receive(raw));
    this.closed = new Promise(resolve => this.ws.once('close', () => {
      clearInterval(this.heartbeat);
      for (const item of this.acks.values()) item.reject(new Error(`Relay disconnected: ${this.url}`));
      for (const item of this.subs.values()) item.error?.(new Error(`Relay disconnected: ${this.url}`));
      resolve();
    }));
    await new Promise((resolve, reject) => {
      this.ws.once('open', resolve);
      this.ws.once('error', reject);
    });
    let alive = true;
    this.ws.on('pong', () => { alive = true; });
    this.heartbeat = setInterval(() => {
      if (!alive) return this.ws.terminate();
      alive = false;
      this.ws.ping();
    }, 30000);
    return this;
  }
  receive(raw) {
    try {
      const [type, id, data, message] = JSON.parse(raw.toString());
      if (type === 'OK') {
        const item = this.acks.get(id);
        if (item) data ? item.resolve(message) : item.reject(new Error(`Relay rejected event: ${message}`));
      } else if (type === 'EVENT') {
        const sub = this.subs.get(id);
        if (sub && verifyEvent(data) && matchFilter(sub.filter, data)) sub.event(data);
      } else if (type === 'EOSE') this.subs.get(id)?.eose?.();
      else if (type === 'CLOSED') this.subs.get(id)?.error?.(new Error(`Subscription closed: ${data}`));
    } catch { /* malformed relay messages are ignored */ }
  }
  send(value) {
    if (this.ws.readyState !== WebSocket.OPEN) throw new Error('Relay is not connected');
    this.ws.send(JSON.stringify(value));
  }
  subscribe(filter, handlers) {
    const id = randomUUID();
    this.subs.set(id, { filter, ...handlers });
    this.send(['REQ', id, filter]);
    return () => {
      this.subs.delete(id);
      if (this.ws.readyState === WebSocket.OPEN) this.send(['CLOSE', id]);
    };
  }
  async query(filter) {
    let close, timer;
    try {
      return await new Promise((resolve, reject) => {
        const events = [];
        close = this.subscribe(filter, { event: e => events.push(e), eose: () => resolve(events), error: reject });
        timer = setTimeout(() => reject(new Error(`Relay query timed out: ${this.url}`)), this.timeout);
      });
    } finally { clearTimeout(timer); close?.(); }
  }
  async publish(event) {
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        this.acks.set(event.id, { resolve, reject });
        timer = setTimeout(() => reject(new Error(`Relay publication timed out: ${this.url}`)), this.timeout);
        this.send(['EVENT', event]);
      });
    } finally { clearTimeout(timer); this.acks.delete(event.id); }
  }
  close() { clearInterval(this.heartbeat); this.ws?.close(); }
}

export class RemoteSigner {
  constructor(session) { this.session = session; }
  async open() {
    for (let attempt = 0; attempt < 3; attempt++) {
      for (const url of this.session.relays) {
        const relay = new Relay(url);
        try { await relay.open(); this.relay = relay; return this; }
        catch { relay.close(); }
      }
      if (attempt < 2) await sleep(2000);
    }
    throw new Error('No signing relay reachable');
  }
  async request(method, params = []) {
    try { return await this.requestOnce(method, params); }
    catch (error) {
      if (error.message.startsWith('Signer:')) throw error;
      this.close();
      await this.open();
      return this.requestOnce(method, params);
    }
  }
  async requestOnce(method, params = []) {
    const { clientSecret, remotePubkey } = this.session;
    const conversation = nip44.v2.utils.getConversationKey(clientSecret, remotePubkey);
    const id = randomUUID();
    let close, timer;
    const response = new Promise((resolve, reject) => {
      close = this.relay.subscribe({ kinds: [24133], authors: [remotePubkey], '#p': [getPublicKey(clientSecret)], since: now() - 30 }, {
        event: event => {
          try {
            const result = JSON.parse(nip44.v2.decrypt(event.content, conversation));
            if (result.id !== id) return;
            result.error ? reject(new Error(`Signer: ${result.error}`)) : resolve(result.result);
          } catch { /* not a valid response to this request */ }
        }, error: reject,
      });
      timer = setTimeout(() => reject(new Error('Signer response timed out; ensure signer service is online')), 45000);
    });
    const request = finalizeEvent({ kind: 24133, created_at: now(), tags: [['p', remotePubkey]],
      content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), conversation) }, clientSecret);
    try {
      const [, result] = await Promise.all([this.relay.publish(request), response]);
      return result;
    } finally { clearTimeout(timer); close?.(); }
  }
  async sign(event, expectedPubkey) {
    const result = JSON.parse(await this.request('sign_event', [JSON.stringify(event)]));
    if (!verifyEvent(result) || result.pubkey !== expectedPubkey || result.kind !== event.kind ||
        result.created_at !== event.created_at || result.content !== event.content ||
        JSON.stringify(result.tags) !== JSON.stringify(event.tags)) throw new Error('Signer returned a different or invalid event');
    return result;
  }
  close() { this.relay?.close(); }
}
