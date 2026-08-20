# npm release profile for `@cigar/sdk`

## Current decision

Do **not** publish `@cigar/sdk@0.9.4` to npm from this branch or from the existing
`v0.9.4` release asset. The immutable archive is technically functional, but it is not a
truthful provenance-bearing npm candidate:

- the public registry returned `E404` for `@cigar/sdk` on 2026-08-20, so no public 0.9.4
  collision was observed;
- `cigar-sdk-0.9.4.tgz` is 325,334 bytes, contains 78 regular mode-0644 files, and has
  SHA-256 `8160193eea7c51f58b13b3a69123e485d0b5aacb6f25687af98dc4a16423379f`;
- that archive declares `git+https://github.com/CIGAR/cigar.git`, which returns 404, rather
  than the public source repository `git+https://github.com/hashgraph-online/hol-cigar.git`;
- the archive omits `homepage` and `bugs` metadata for the actual public repository;
- the `v0.9.4` tag does not contain the npm Trusted Publishing workflow, so a workflow added
  after the tag cannot truthfully make provenance claim that it was the tagged build recipe;
- public absence does not prove that project maintainers control the `@cigar` npm scope; and
- npm Trusted Publishing configuration requires an existing package, so the first publication
  needs an explicitly approved bootstrap before tokenless OIDC can become authoritative.

Changing the archive metadata changes its bytes. npm package versions are immutable, and the
GitHub 0.9.4 release already names and hashes the current tarball. Rebuilding different bytes under
the same `@cigar/sdk@0.9.4` identity would create two conflicting artifacts. The fail-closed
authority in [`release-profile.v1.json`](release-profile.v1.json) therefore records
`publishable: false`.

## Verified compatibility surface

The current tarball is a developer-preview ESM package for exact Node `>=24.10.0 <25`. It exports
`cigar.context.v1`, all 45 frozen HTTP operations, 70 generated payload models, typed CIGAR
problems, bounded deadlines, `AbortSignal`, safe retry/idempotency behavior, effect ambiguity,
handoff, replay, context bundle/delta verification, and workflow recovery state.

The packed-consumer qualifier validates these boundaries:

| Consumer | Result and claim |
| --- | --- |
| Node ESM 24.10.0 | Supported; public root export resolves from the installed tarball. |
| TypeScript 7.0.2 NodeNext | Supported with `ES2024`, DOM, and `ESNext.Disposable` libraries. |
| TypeScript 7.0.2 Bundler resolution | Type resolution supported with the same libraries; this is not a browser runtime claim. |
| CommonJS `require()` | Intentionally refused by package exports. |
| Private `dist/*` subpaths | Intentionally refused by package exports. |
| Browser runtime | Not claimed or qualified. |

`AsyncDisposable` is part of the public stream type. Consumers that do not obtain it from their
Node ambient types must include `"ESNext.Disposable"` in `compilerOptions.lib`. Changing that
public declaration belongs in a version-next compatibility decision.

## Local non-publishing qualification

Use only exact pinned tools. The commands below inspect and exercise an archive; they do not log
in, change npm access, create a release, push, tag, or publish.

```text
python3 scripts/release/verify_npm_sdk.py \
  /absolute/path/cigar-sdk-0.9.4.tgz \
  --require-canonical-bytes

node scripts/release/qualify_npm_consumers.mjs \
  --archive /absolute/path/cigar-sdk-0.9.4.tgz \
  --expected-version 0.9.4 \
  --npm-cli /absolute/path/to/npm-11.6.0/bin/npm-cli.js \
  --tsc /absolute/path/to/typescript-7.0.2/bin/tsc

npm publish \
  --dry-run \
  --json \
  --ignore-scripts \
  --access public \
  --tag alpha \
  /absolute/path/cigar-sdk-0.9.4.tgz
```

The verifier bounds compressed and expanded sizes, rejects links and path collisions, requires
canonical ownership/modes, checks the exact package/release identity, scans secret-shaped values
and private paths, validates inline source maps, counts operations, records SHA-1/SHA-256/npm
SHA-512 integrity, calculates a semantic payload-tree digest, and emits the complete file
inventory. `--require-publishable` is the release gate and intentionally fails today.

The consumer qualifier materializes only the SDK tarball as the SDK source, disables lifecycle
scripts, verifies that the installation is not a workspace link, disables registry access after
dependency installation, then tests ESM runtime, NodeNext types, Bundler types, and unsupported
resolution refusal. A passing Bundler typecheck does not add a browser support claim.

## Truthful version-next path

The recommended corrective release is a new product prerelease such as `0.9.5-alpha.1`; the exact
identifier is a maintainer decision. Do not weaken the generator's product-wide cross-SDK version
invariant merely to reuse 0.9.4 for npm.

1. Confirm, through an authenticated npm owner session, whether the project controls `@cigar`.
   If it does not, approve a new unoccupied package identity and update every generated capability
   and release authority consistently.
2. Create a normal version-next PR from current public `main`. Update the product version authority,
   SDK manifests/release records, generated capability bindings, lockfile, release matrices, and
   tests together.
3. Set the TypeScript manifest repository to
   `git+https://github.com/hashgraph-online/hol-cigar.git`, directory `sdk/typescript`, homepage to
   `https://github.com/hashgraph-online/hol-cigar#readme`, and bugs URL to
   `https://github.com/hashgraph-online/hol-cigar/issues`.
4. Update this profile to the new prerelease, `alpha` dist-tag, new deterministic tarball hashes,
   and `release_decision: {"publishable":true,"status":"approved","blockers":[]}` only after
   independent review proves every blocker is resolved.
5. Require `fast-ci`, `security`, and `npm-sdk-readiness`. The combined gates cover frozen install,
   full client generation drift, formatting/linting, strict types, runtime tests, pack
   reproducibility, inventory/security, dependency audit, packed consumers, and publish dry-run.
6. Merge the reviewed workflow before creating the prerelease tag. Create the tag from the exact
   merge commit, then publish a GitHub prerelease for that tag. Never reuse or move `v0.9.4`.
7. Bootstrap the first npm package only through a separately approved, tag-bound GitHub Actions
   run using a short-lived granular publish credential and npm provenance. Do not add a token
   fallback to the permanent OIDC workflow. Immediately configure the package's Trusted Publisher
   for organization `hashgraph-online`, repository `hol-cigar`, workflow
   `publish-cigar-sdk-npm.yml`, environment `npm`, and publish-only permission; then revoke the
   bootstrap credential.
8. Configure the protected `npm` GitHub environment with required independent reviewers. Dispatch
   `publish-cigar-sdk-npm.yml` **from the exact prerelease tag** and enter its confirmation phrase.
   The workflow refuses branch refs, final-version tags, occupied versions, non-alpha tags,
   unapproved profiles, failed dry-runs, and non-reproducible tarballs.
9. Verify exact registry integrity and `dist-tags.alpha`, require npm provenance/attestations, and
   install the exact version in a clean smoke consumer. Do not assign `latest` to this
   developer-preview build.

If a bad package reaches npm, stop further releases, remove the `alpha` dist-tag from the affected
version or move it only to a separately verified replacement, and deprecate the bad exact version
with a concise migration message. Do not attempt to overwrite it and do not rely on unpublish as a
normal rollback mechanism.

## Permanent workflow authority

`.github/workflows/publish-cigar-sdk-npm.yml` is intentionally unusable for 0.9.4. For an approved
version-next prerelease it requires an exact prerelease tag, matching package version, matching
GitHub prerelease, profile approval, frozen tests, two byte-identical packs, packed-consumer
qualification, a dry-run, and an unoccupied registry version. Its publish job receives only
`contents: read` and `id-token: write`, uses the protected `npm` environment, consumes the staged
verified tarball, publishes with `alpha`, and checks integrity, dist-tag, and attestations.

Trusted Publishing and npm provenance require the manifest's public repository URL to match the
GitHub repository exactly. A post-0.9.4 workflow cannot repair the provenance of the already tagged
0.9.4 bytes; the workflow must be present in the later tag that is dispatched.

Authoritative npm references:

- [Trusted publishing for npm packages](https://docs.npmjs.com/trusted-publishers/)
- [Generating provenance statements](https://docs.npmjs.com/generating-provenance-statements/)
- [Creating and publishing scoped public packages](https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/)
- [Package scope, access level, and visibility](https://docs.npmjs.com/package-scope-access-level-and-visibility/)
