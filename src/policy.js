import { nip19 } from 'nostr-tools';
import { now } from './nostr.js';

export const PERMISSIONS = 'sign_event:30617,sign_event:30618';
export const identifier = (org, repo) => `${org.toLowerCase()}--${repo.toLowerCase()}`;
export const cloneUrl = (server, pubkey, id) => `https://${server}/${nip19.npubEncode(pubkey)}/${encodeURIComponent(id)}.git`;
export function validateConfig(config) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$/.test(config.org)) throw new Error('Invalid GitHub organization');
  if (!/^[0-9a-f]{64}$/.test(config.pubkey)) throw new Error('Invalid public key');
  if (!Array.isArray(config.servers) || !config.servers.length || config.servers.some(x =>
    !/^[a-z0-9.-]+(?::[0-9]+)?$/.test(x))) throw new Error('GRASP servers must be hostnames');
  if (!Array.isArray(config.signerRelays) || !config.signerRelays.length ||
    config.signerRelays.some(x => !x.startsWith('wss://') && x !== 'ws://signing-relay:8080')) throw new Error('Signing relays must use wss:// or the internal Compose relay');
  return config;
}

export function validateSigningEvent(event, config) {
  if (![30617, 30618].includes(event.kind)) throw new Error('Event kind denied');
  if (event.content !== '' || !Number.isSafeInteger(event.created_at) || Math.abs(event.created_at - now()) > 300) {
    throw new Error('Invalid content or timestamp');
  }
  if (!Array.isArray(event.tags) || event.tags.some(t => !Array.isArray(t) || t.some(v => typeof v !== 'string'))) {
    throw new Error('Invalid tags');
  }
  const ds = event.tags.filter(t => t[0] === 'd');
  const prefix = `${config.org.toLowerCase()}--`;
  const id = ds[0]?.[1];
  if (ds.length !== 1 || ds[0].length !== 2 || !id?.startsWith(prefix) ||
      !/^[a-z0-9_.-]+$/.test(id.slice(prefix.length)) || id.length > 160) throw new Error('Repository scope denied');
  const names = new Set();
  for (const tag of event.tags) {
    if (names.has(tag[0])) throw new Error('Duplicate tag');
    names.add(tag[0]);
    if (tag[0] === 'd') continue;
    if (event.kind === 30618) {
      if (tag[0] === 'HEAD') {
        if (tag.length !== 2 || !tag[1].startsWith('ref: refs/heads/') ||
          !event.tags.some(t => t[0] === tag[1].slice(5))) throw new Error('Invalid default branch');
      } else if (!/^refs\/(heads|tags)\/.+/.test(tag[0]) || tag.length !== 2 || !/^[0-9a-f]{40}$/.test(tag[1])) {
        throw new Error('Invalid git ref');
      }
    } else {
      const valid = {
        name: () => tag.length === 2 && tag[1].length <= 100,
        description: () => tag.length === 2 && tag[1].length <= 2000,
        web: () => tag.length === 2 && tag[1].toLowerCase() === `https://github.com/${config.org.toLowerCase()}/${id.slice(prefix.length)}`,
        clone: () => JSON.stringify(tag.slice(1)) === JSON.stringify(config.servers.map(s => cloneUrl(s, config.pubkey, id))),
        relays: () => JSON.stringify(tag.slice(1)) === JSON.stringify(config.servers.map(s => `wss://${s}`)),
        r: () => tag.length === 3 && /^[0-9a-f]{40}$/.test(tag[1]) && tag[2] === 'euc',
        maintainers: () => tag.length === 2 && tag[1] === config.pubkey,
      };
      if (!valid[tag[0]]?.()) throw new Error(`Announcement tag denied: ${tag[0]}`);
    }
  }
  if (event.kind === 30617 && !['clone', 'relays', 'web'].every(t => names.has(t))) throw new Error('Missing repository hosting');
  return event;
}
