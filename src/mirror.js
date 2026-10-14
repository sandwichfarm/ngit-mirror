import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { nip19, verifyEvent } from 'nostr-tools';
import { Relay, RemoteSigner, decodeSession, now, sleep } from './nostr.js';
import { identifier, cloneUrl } from './policy.js';

const exec = promisify(execFile);
const gitEnv = { PATH: process.env.PATH, HOME: '/tmp', LANG: 'C', GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_LFS_SKIP_SMUDGE: '1' };
export async function git(args, cwd) {
  try {
    return (await exec('git', ['-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
      '-c', 'http.lowSpeedLimit=1000', '-c', 'http.lowSpeedTime=120', ...args],
    { cwd, env: gitEnv, timeout: 1800000, maxBuffer: 32 * 1024 * 1024 })).stdout.trim();
  } catch (error) { throw new Error(`git ${args[0]} failed: ${(error.stderr || error.message).slice(-1800)}`); }
}

export async function saveJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  await rename(temporary, file);
}

async function github(url, token) {
  const response = await fetch(url, { headers: { Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`GitHub HTTP ${response.status}: ${url}`);
  return { data: await response.json(), next: response.headers.get('link')?.match(/<([^>]+)>; rel="next"/)?.[1] };
}

export async function discover(org, token, request = github) {
  const repos = [];
  let url = `https://api.github.com/orgs/${encodeURIComponent(org)}/repos?type=public&per_page=100`;
  while (url) {
    const result = await request(url, token);
    for (const repo of result.data) {
      if (repo.private !== false || repo.visibility !== 'public' || repo.owner?.login.toLowerCase() !== org.toLowerCase()) continue;
      repos.push(repo);
    }
    url = result.next;
    if (url && new URL(url).origin !== 'https://api.github.com') throw new Error('Unexpected pagination host');
  }
  return repos.sort((a, b) => a.name.localeCompare(b.name));
}

export function parseRefs(output) {
  const refs = {};
  let head;
  for (const line of output.split('\n')) {
    const [oid, ref] = line.split(/\s+/);
    if (line.startsWith('ref: ')) {
      if (line.endsWith('\tHEAD')) head = line.split(/\s+/)[1];
    } else if (/^refs\/(heads|tags)\//.test(ref) && !ref.endsWith('^{}') && /^[0-9a-f]{40}$/.test(oid)) refs[ref] = oid;
  }
  return { refs, head };
}
export function equalRefs(a, b) {
  return JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort());
}
export async function snapshot(sourceUrl, directory, defaultBranch) {
  await mkdir(directory, { recursive: true });
  await git(['init', '--bare', '--quiet', directory]);
  await git(['fetch', '--force', '--prune', '--no-write-fetch-head', sourceUrl,
    '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*'], directory);
  const refs = parseRefs(await git(['for-each-ref', '--format=%(objectname) %(refname)', 'refs/heads', 'refs/tags'], directory)).refs;
  const head = `refs/heads/${defaultBranch}`;
  if (Object.keys(refs).some(r => r.startsWith('refs/heads/')) && !refs[head]) {
    throw new Error('Default branch changed during fetch; retry on next pass');
  }
  if (refs[head]) await git(['symbolic-ref', 'HEAD', head], directory);
  const roots = refs[head] ? (await git(['rev-list', '--max-parents=0', head], directory)).split('\n').sort() : [];
  return { refs, head: refs[head] ? head : undefined, root: roots[0] };
}

export function templates(config, repo, state) {
  const id = identifier(config.org, repo.name);
  const announcement = { kind: 30617, content: '', tags: [
    ['d', id], ['name', repo.name], ['description', (repo.description || '').slice(0, 2000)],
    ['web', `https://github.com/${config.org}/${repo.name}`],
    ['clone', ...config.servers.map(server => cloneUrl(server, config.pubkey, id))],
    ['relays', ...config.servers.map(server => `wss://${server}`)],
    ['maintainers', config.pubkey], ...(state.root ? [['r', state.root, 'euc']] : []),
  ] };
  const refs = { kind: 30618, content: '', tags: [['d', id],
    ...Object.entries(state.refs).sort().map(([name, oid]) => [name, oid]),
    ...(state.head ? [['HEAD', `ref: ${state.head}`]] : []),
  ] };
  return [announcement, refs];
}

const sameTemplate = (event, template) => event.kind === template.kind && event.content === template.content &&
  JSON.stringify(event.tags) === JSON.stringify(template.tags);
const newest = events => [...events].sort((a, b) => b.created_at - a.created_at || a.id.localeCompare(b.id))[0];

export async function mirrorRepository(config, repo, signer, dataDir) {
  const directory = path.join(dataDir, 'repos', `${repo.id}.git`);
  // The source is constructed from GitHub's public API, never a repository-supplied URL.
  const source = `https://github.com/${config.org}/${repo.name}.git`;
  const state = await snapshot(source, directory, repo.default_branch);
  // Recheck anonymous access immediately before signing, without consuming one
  // GitHub REST request per repository (the anonymous quota is only 60/hour).
  // A private source fails because git has no credentials or credential helpers.
  const fresh = parseRefs(await git(['ls-remote', '--symref', source], directory));
  if (!equalRefs(fresh.refs, state.refs) || fresh.head !== state.head) throw new Error('GitHub refs changed during fetch; retry on next pass');
  const id = identifier(config.org, repo.name);
  const relays = [];
  const errors = [];
  for (const server of config.servers) {
    const relay = new Relay(`wss://${server}`);
    try { await relay.open(); relays.push({ relay, server }); }
    catch (error) { relay.close(); errors.push(`${server}: ${error.message}`); }
  }
  if (!relays.length) throw new Error(`No GRASP server reachable: ${errors.join('; ')}`);
  const cacheFile = path.join(dataDir, 'events', `${repo.id}.json`);
  try {
    let cached = [];
    try { cached = JSON.parse(await readFile(cacheFile, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (!Array.isArray(cached) || cached.some(e => !verifyEvent(e))) throw new Error('Invalid cached event; remove this repository event cache and retry');
    const previous = [...cached];
    for (const { relay } of relays) {
      previous.push(...await relay.query({ kinds: [30617, 30618], authors: [config.pubkey], '#d': [id] }));
    }
    const signed = [];
    for (const template of templates(config, repo, state)) {
      const latest = newest(previous.filter(e => e.kind === template.kind && e.pubkey === config.pubkey && e.tags.some(t => t[0] === 'd' && t[1] === id)));
      if (latest && sameTemplate(latest, template)) signed.push(latest);
      else {
        const created_at = Math.max(now(), (latest?.created_at || 0) + 1);
        if (created_at > now() + 60) throw new Error('Relay state timestamp is too far in the future');
        signed.push(await signer.sign({ ...template, created_at }, config.pubkey));
      }
    }
    // Persist candidates before sending. A crash retries exactly the same events.
    await saveJson(cacheFile, signed);
    const successful = [];
    for (const { relay, server } of relays) {
      try {
        await syncServer(relay, cloneUrl(server, config.pubkey, id), directory, signed, state);
        successful.push(server);
      } catch (error) { errors.push(`${server}: ${error.message}`); }
    }
    return { repository: repo.full_name, identifier: id, refs: Object.keys(state.refs).length,
      status: successful.length === config.servers.length ? 'verified' : successful.length ? 'degraded' : 'failed',
      servers: successful, errors, nostr: `nostr://${nip19.npubEncode(config.pubkey)}/${encodeURIComponent(config.servers[0])}/${id}` };
  } finally { relays.forEach(({ relay }) => relay.close()); }
}

export async function syncServer(relay, destination, directory, signed, expected) {
  let failure;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      // GRASP-01: stage signed authorization, then supply its exact Git objects.
      for (const event of signed) await relay.publish(event);
      await git(['push', '--porcelain', '--prune', destination,
        '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*'], directory);
      const actual = parseRefs(await git(['ls-remote', '--symref', destination], directory));
      if (!equalRefs(actual.refs, expected.refs) || actual.head !== expected.head) throw new Error('Destination refs or HEAD do not match GitHub snapshot');
      const published = await relay.query({ kinds: [30617, 30618], authors: [signed[0].pubkey], '#d': [signed[0].tags[0][1]] });
      if (signed.some(event => !published.some(e => e.id === event.id))) throw new Error('Signed repository events are not yet queryable');
      return;
    } catch (error) { failure = error; if (attempt < 2) await sleep(2000 * (attempt + 1)); }
  }
  throw failure;
}

export async function mirrorAll(config, { dataDir, sessionFile, token, only }) {
  await mkdir(dataDir, { recursive: true });
  const repos = await discover(config.org, token);
  const chosen = only ? repos.filter(r => r.name === only) : repos;
  if (only && !chosen.length) throw new Error(`Public repository not found: ${only}`);
  await saveJson(path.join(dataDir, 'inventory.json'), repos.map(r => ({ id: r.id, name: r.full_name, archived: r.archived, fork: r.fork, sizeKiB: r.size })));
  const report = { started: new Date().toISOString(), org: config.org, discovered: repos.length, selected: chosen.length, repositories: [] };
  await saveJson(path.join(dataDir, 'report.json'), report);
  const signer = await new RemoteSigner(decodeSession(await readFile(sessionFile, 'utf8'))).open();
  try {
    if (await signer.request('get_public_key') !== config.pubkey) throw new Error('NBUNKSEC belongs to a different identity');
    for (const repo of chosen) {
      console.log(`Mirroring ${repo.full_name}`);
      let result;
      try { result = await mirrorRepository(config, repo, signer, dataDir); }
      catch (error) { result = { repository: repo.full_name, status: 'failed', errors: [error.message] }; }
      report.repositories.push(result);
      await saveJson(path.join(dataDir, 'report.json'), report);
      console.log(`${result.status}: ${repo.full_name}${result.errors?.length ? `: ${result.errors.join('; ')}` : ''}`);
    }
    report.finished = new Date().toISOString();
    report.ok = report.repositories.every(r => r.status === 'verified');
    await saveJson(path.join(dataDir, 'report.json'), report);
    return report;
  } finally { signer.close(); }
}
