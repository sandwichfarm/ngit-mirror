import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, stat } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools';
import { handleRequest } from '../src/signer.js';
import { encodeSession, decodeSession, hex, now } from '../src/nostr.js';
import { validateSigningEvent } from '../src/policy.js';
import { git, snapshot, templates, discover, parseRefs, equalRefs, syncServer } from '../src/mirror.js';

const secret = generateSecretKey(), clientSecret = generateSecretKey();
const config = { org: 'sandwichfarm', pubkey: getPublicKey(secret), servers: ['grasp.test'], signerRelays: ['wss://sign.test'] };
const credentials = { secret: hex(secret), clientPubkey: getPublicKey(clientSecret) };
const repo = { id: 1, name: 'example', full_name: 'sandwichfarm/example', default_branch: 'main' };
const state = { refs: { 'refs/heads/main': 'a'.repeat(40) }, head: 'refs/heads/main', root: 'a'.repeat(40) };
const draft = () => ({ ...templates(config, repo, state)[0], created_at: now() });

test('NBUNKSEC interoperable TLV round trip and malformed input rejected', () => {
  const session = { remotePubkey: config.pubkey, clientSecret, relays: config.signerRelays };
  const encoded = encodeSession(session);
  assert.match(encoded, /^nbunksec1/);
  assert.deepEqual(decodeSession(encoded), session);
  assert.throws(() => decodeSession(encoded.slice(0, -1)));
  assert.throws(() => decodeSession('nsec1invalid'));
});

test('one-time setup stores private files, exports no secrets, and refuses identity replacement', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ngit-setup-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const command = [new URL('../src/cli.js', import.meta.url).pathname, 'setup', '--org', 'sandwichfarm'];
  const { stdout } = await promisify(execFile)(process.execPath, command, { cwd: root });
  const keyFile = path.join(root, 'secrets', 'signer.json');
  const sessionFile = path.join(root, 'secrets', 'nbunksec');
  const saved = await readFile(keyFile, 'utf8');
  assert.equal(stdout.includes(JSON.parse(saved).secret), false);
  assert.equal(stdout.includes((await readFile(sessionFile, 'utf8')).trim()), false);
  assert.equal((await stat(keyFile)).mode & 0o777, 0o600);
  assert.equal((await stat(sessionFile)).mode & 0o777, 0o600);
  await assert.rejects(promisify(execFile)(process.execPath, command, { cwd: root }), /Refusing to overwrite/);
  assert.equal(await readFile(keyFile, 'utf8'), saved);
});

test('signer allows only bound client, two Git kinds and organization scope', () => {
  const signed = JSON.parse(handleRequest({ method: 'sign_event', params: [JSON.stringify(draft())] }, credentials.clientPubkey, credentials, config));
  assert.equal(verifyEvent(signed), true);
  assert.equal(signed.pubkey, config.pubkey);
  for (const kind of [0, 1, 4, 5, 1059, 10002, 10317, 24133, 27235]) {
    assert.throws(() => validateSigningEvent({ ...draft(), kind }, config), /denied/);
  }
  for (const method of ['nip04_encrypt', 'nip04_decrypt', 'nip44_encrypt', 'nip44_decrypt', 'unknown']) {
    assert.throws(() => handleRequest({ method, params: [] }, credentials.clientPubkey, credentials, config), /denied/);
  }
  assert.throws(() => handleRequest({ method: 'get_public_key', params: [] }, 'f'.repeat(64), credentials, config), /Client denied/);
  assert.throws(() => handleRequest({ method: 'connect', params: ['', '', 'sign_event:1'] }, credentials.clientPubkey, credentials, config), /Permission denied/);
  const otherOrg = draft(); otherOrg.tags[0][1] = 'another--example';
  assert.throws(() => validateSigningEvent(otherOrg, config), /scope denied/);
  const otherHost = draft(); otherHost.tags.find(t => t[0] === 'clone')[1] = 'https://evil.test/repo.git';
  assert.throws(() => validateSigningEvent(otherHost, config), /tag denied/);
  const otherMaintainer = draft(); otherMaintainer.tags.find(t => t[0] === 'maintainers')[1] = 'f'.repeat(64);
  assert.throws(() => validateSigningEvent(otherMaintainer, config), /tag denied/);
  assert.throws(() => validateSigningEvent({ ...draft(), content: 'post' }, config), /content/);
  assert.throws(() => validateSigningEvent({ ...draft(), created_at: now() + 1000 }, config), /timestamp/);
});

test('discovery paginates and includes forks and archived repos while excluding private and other owners', async () => {
  const publicRepo = (name, extra = {}) => ({ name, owner: { login: 'sandwichfarm' }, private: false, visibility: 'public', ...extra });
  let calls = 0;
  const result = await discover('sandwichfarm', undefined, async () => ++calls === 1 ? {
    data: [publicRepo('fork', { fork: true }), publicRepo('private', { private: true }), publicRepo('internal', { visibility: 'internal' })],
    next: 'https://api.github.com/page2',
  } : { data: [publicRepo('archived', { archived: true }), publicRepo('wrong', { owner: { login: 'other' } })] });
  assert.equal(calls, 2);
  assert.deepEqual(result.map(r => r.name), ['archived', 'fork']);
});

test('real Git mirrors branches, pr/* names, annotated tags, force-pushes, deletions, default changes, and retries', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ngit-mirror-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'), cache = path.join(root, 'cache.git'), target = path.join(root, 'target.git');
  await git(['init', '--quiet', '-b', 'main', source]);
  await git(['config', 'user.name', 'Mirror Test'], source);
  await git(['config', 'user.email', 'test@example.invalid'], source);
  await writeFile(path.join(source, 'README'), 'one');
  await git(['add', '.'], source);
  await git(['commit', '-qm', 'one'], source);
  const first = await git(['rev-parse', 'HEAD'], source);
  await git(['branch', 'feature'], source);
  await git(['branch', 'pr/ordinary-github-branch'], source);
  await git(['tag', '-am', 'release', 'v1'], source);
  await git(['init', '--bare', '--quiet', target]);
  await git(['config', 'receive.denyDeleteCurrent', 'ignore'], target);
  await git(['symbolic-ref', 'HEAD', 'refs/heads/main'], target);
  let expected = await snapshot(source, cache, 'main');
  const signed = templates(config, repo, expected).map(event => JSON.parse(handleRequest({ method: 'sign_event', params: [JSON.stringify({ ...event, created_at: now() })] }, credentials.clientPubkey, credentials, config)));
  const events = [];
  let staged = 0;
  const relay = { publish: async e => { staged++; events.push(e); }, query: async () => events };
  await syncServer(relay, target, cache, signed, expected);
  assert.equal(staged, 2);
  assert.equal(equalRefs(parseRefs(await git(['ls-remote', target])).refs, expected.refs), true);
  // The same snapshot works again after a lost success response.
  await syncServer(relay, target, cache, signed, expected);
  await writeFile(path.join(source, 'README'), 'two');
  await git(['commit', '-qam', 'two'], source);
  await git(['branch', '-D', 'feature'], source);
  await git(['tag', '-d', 'v1'], source);
  await git(['tag', '-am', 'new release', 'v2'], source);
  expected = await snapshot(source, cache, 'main');
  await git(['push', '--prune', target, '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*'], cache);
  assert.equal(equalRefs(parseRefs(await git(['ls-remote', target])).refs, expected.refs), true);
  await git(['reset', '--hard', first], source);
  await git(['branch', '-m', 'develop'], source);
  expected = await snapshot(source, cache, 'develop');
  await git(['push', '--prune', target, '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*'], cache);
  assert.equal(expected.refs['refs/heads/develop'], first);
  assert.equal('refs/heads/main' in expected.refs, false);
  assert.equal(equalRefs(parseRefs(await git(['ls-remote', target])).refs, expected.refs), true);
  assert.equal(templates(config, repo, expected)[1].tags.find(t => t[0] === 'HEAD')[1], 'ref: refs/heads/develop');
});
