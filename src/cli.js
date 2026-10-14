import { parseArgs } from 'node:util';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { encodeSession, hex, sleep } from './nostr.js';
import { validateConfig } from './policy.js';
import { serveSigner } from './signer.js';
import { serveSigningRelay } from './signing-relay.js';
import { discover, mirrorAll } from './mirror.js';

const { values, positionals } = parseArgs({ allowPositionals: true, options: {
  org: { type: 'string' }, config: { type: 'string', default: 'config.json' },
  secrets: { type: 'string', default: 'secrets' }, data: { type: 'string', default: 'data' },
  only: { type: 'string' }, watch: { type: 'boolean', default: false },
  interval: { type: 'string', default: '900' },
} });

async function main() {
  const command = positionals[0];
  if (command === 'setup') {
    if (!values.org) throw new Error('Usage: npm run setup -- --org sandwichfarm');
    for (const file of [values.config, path.join(values.secrets, 'signer.json'), path.join(values.secrets, 'nbunksec')]) {
      try { await access(file); throw new Error(`Refusing to overwrite ${file}; existing identity must be preserved`); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    const secret = generateSecretKey(), clientSecret = generateSecretKey();
    const pubkey = getPublicKey(secret);
    const config = validateConfig({ org: values.org, pubkey, clientPubkey: getPublicKey(clientSecret),
      servers: ['relay.ngit.dev', 'gitnostr.com'], signerRelays: ['ws://signing-relay:8080'] });
    await mkdir(values.secrets, { recursive: true, mode: 0o700 });
    await writeFile(path.join(values.secrets, 'signer.json'), JSON.stringify({ secret: hex(secret), clientPubkey: getPublicKey(clientSecret) }) + '\n', { flag: 'wx', mode: 0o600 });
    await writeFile(path.join(values.secrets, 'nbunksec'), encodeSession({ remotePubkey: pubkey, clientSecret, relays: config.signerRelays }) + '\n', { flag: 'wx', mode: 0o600 });
    await writeFile(values.config, JSON.stringify(config, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
    console.log(`Created ${nip19.npubEncode(pubkey)} for ${config.org}.\nNBUNKSEC saved to ${values.secrets}/nbunksec.\nStart: docker compose up -d --build\nBack up config.json and secrets/ privately. The signing key never needs to enter GitHub.`);
    return;
  }
  const config = validateConfig(JSON.parse(await readFile(values.config, 'utf8')));
  if (command === 'inventory') {
    const repos = await discover(config.org, process.env.GH_TOKEN);
    console.log(JSON.stringify(repos.map(r => ({ name: r.full_name, archived: r.archived, fork: r.fork, sizeKiB: r.size })), null, 2));
  } else if (command === 'relay') {
    serveSigningRelay(config);
  } else if (command === 'signer') {
    await serveSigner(JSON.parse(await readFile(path.join(values.secrets, 'signer.json'), 'utf8')), config);
  } else if (command === 'mirror') {
    const seconds = Number(values.interval);
    if (!Number.isFinite(seconds) || seconds < 60) throw new Error('Interval must be at least 60 seconds');
    do {
      try {
        const report = await mirrorAll(config, { dataDir: path.resolve(values.data), sessionFile: path.join(values.secrets, 'nbunksec'), token: process.env.GH_TOKEN, only: values.only });
        if (!report.ok && !values.watch) process.exitCode = 1;
      } catch (error) { console.error(error.message); if (!values.watch) throw error; }
      if (values.watch) await sleep(seconds * 1000);
    } while (values.watch);
  } else throw new Error('Commands: setup --org ORG | inventory | relay | signer | mirror [--watch] [--only REPO]');
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
