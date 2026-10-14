# GitHub → ngit mirror

One service mirrors **every public repository in a GitHub organization**, including forks and archived repositories. New public repositories are discovered automatically. GitHub is authoritative: all branches, tags, force-pushes, deletions, and the default branch are copied to GRASP Git servers and announced through NIP-34. The original commit IDs and full reachable Git history are preserved.

## Run

Requires Docker with Compose. On a machine that stays online:

```sh
./scripts/setup.sh sandwichfarm   # once: generates identity + restricted NBUNKSEC
docker compose up -d --build
docker compose logs -f mirror
```

Compose runs the signer, mirror, and a private signing relay. No inbound ports are exposed. The first pass imports everything. Later passes run 15 minutes after the previous pass finishes. No GitHub write permission, per-repository workflow, or access token is required. For organizations large enough to exceed GitHub's anonymous API quota, set an optional `GH_TOKEN` in `.env`; public repository reads are sufficient.

`data/report.json` records each repository's clone URL, ref count, successful servers, and errors. **`ok: true` with `scope: "organization"` means every discovered repository was verified on every configured server.** A targeted `--only` run has `scope: "single"` and verifies only that repository. A report without `finished` is still in progress. Failures do not prevent other repositories from being attempted and are retried next pass.

```sh
# Stop automatic mirroring; signer remains online.
docker compose stop mirror
# Run once (exits nonzero if anything is unverified).
docker compose run --rm mirror mirror --config /config.json \
  --secrets /run/secrets --data /data
# Resume the service.
docker compose up -d mirror
```

Add `--only REPOSITORY_NAME` to the one-shot command for a targeted retry. Do not run a second deployment against the same Nostr identity. A filesystem lock prevents overlapping local mirror runs.

## Keys and permissions

Setup creates a dedicated Nostr identity. **Back up `config.json` and `secrets/` privately.** Setup refuses to overwrite them. Losing the identity key means losing control of its repository announcements.

| File | Used by | Contains |
| --- | --- | --- |
| `config.json` | Both services | Organization, public identity, GRASP and signing relay addresses |
| `secrets/signer.json` | Signer only | Identity private key and one authorized client public key |
| `secrets/nbunksec` | Mirror only | NIP-46 client key, remote signer public key, relay URLs |

The signer enforces **only `sign_event:30617` and `sign_event:30618`**, scoped to identifiers beginning `sandwichfarm--` (or the configured organization). Announcement hosting, maintainer, and GitHub URL tags are also constrained. Posting, DMs, encryption/decryption RPCs, and arbitrary event signing are denied. NIP-44 is used internally to encrypt the NIP-46 transport; that does not grant the client encryption/decryption permission over the identity key.

An NBUNKSEC is a reusable client credential, **not an offline signing key**. The signer must stay running. This deployment chooses the service option: its NBUNKSEC uses the internal `ws://signing-relay:8080` endpoint, and works on the Compose network. Moving the mirror to CI would also require an externally reachable WSS signing relay; a GitHub secret alone cannot replace the running signer. The internal relay avoids public signing-relay rate limits. Revoking the client means replacing its public key in `signer.json` and `config.json`, generating a new client NBUNKSEC, and restarting the stack. Do not regenerate the identity to rotate a client; that changes every repository address.

## Hosting and scope

Default GRASP servers are `relay.ngit.dev` and `gitnostr.com`. Both receive actual Git objects and signed repository events; this is an independent Git copy, not just a link back to GitHub. Change `servers` in `config.json`, then restart both services to rebuild their announcements and populate the new servers. Remove an old server only after the new one verifies.

Repository addresses use `nostr://<npub>/<relay-host>/sandwichfarm--<repository>`. An ordinary ngit installation can clone them. Every published address is recorded in `data/report.json`.

The mirror never pushes to GitHub. Merge contributions there; direct changes on the Nostr side are overwritten by the next GitHub snapshot. GitHub issues, PR discussions, release assets, Git LFS payloads, and submodule repositories are outside Git branch/tag mirroring. Git LFS pointers and submodule gitlinks remain intact. Empty repositories have no commit history to copy.

Repositories made private, deleted, or transferred out are excluded from subsequent discovery; already published public history is not erased. Renaming a repository creates a new organization-prefixed Nostr identifier, while its old announcement remains. Relays and public Git servers may retain previously published data.

## Why this implementation

[ngit](https://github.com/DanConwayDev/ngit-cli) is the client; [NIP-34](https://github.com/nostr-protocol/nips/blob/master/34.md) defines its repository announcements and state. [GRASP-01](https://ngit.dev/grasp.git) permits pushes matching signed repository state. This service stages those two signed events, pushes heads and tags with native Git, and verifies remote refs, HEAD, and queryable event IDs before reporting success.

Native `ngit sync --trust-server` only imports clean fast-forwards and does not cover an exact GitHub-authoritative mirror. Also, ngit's push interface treats `pr/*` branches as proposals. Using the GRASP protocol directly preserves those ordinary GitHub branch names and handles deletions without granting any proposal or social permissions. See [ngit's mirroring guide](https://ngit.dev/repositories/mirroring).

## Development

```sh
npm ci --ignore-scripts
npm test
```

Tests exercise real Git refs and history changes, public repository pagination/filtering, the signer policy, NBUNKSEC encoding, and encrypted NIP-46 request/reply over a local WebSocket relay. Public GRASP acceptance and storage limits can still cause runtime failures; the report names each affected repository and server.
