# npm release profile for `@hol-org/cigar`

## Current decision

`@hol-org/cigar@0.9.4` is a technically qualified first-publication candidate for the public
`alpha` channel. It is not yet authorized for external staging: the public packaging change must
first be reviewed and merged, and the exact staged package must then receive human 2FA approval.
The fail-closed state is recorded in `release-profile.v1.json`.

The npm registry returned `E404` for `@hol-org/cigar` on 2026-08-31. Authenticated npm identity
`tmcc_patches` is a developer in the `hol-org` organization; `kantorcodes` is the organization
owner. No package, version, dist-tag, trusted publisher, or staged package was created during
readiness work.

## Package identity and source relationship

The npm package is `@hol-org/cigar@0.9.4`, while the existing GitHub `v0.9.4` TypeScript asset is
named `cigar-sdk-0.9.4.tgz` and identifies the earlier unpublished `@cigar/sdk` package. The npm
candidate deliberately has different bytes because it corrects:

- the package and release-record identity to `@hol-org/cigar`;
- repository metadata to `git+https://github.com/hashgraph-online/hol-cigar.git`;
- homepage and issue URLs;
- examples and generated capability records that name the TypeScript module; and
- public-registry and `alpha` defaults in `publishConfig`.

The SDK implementation remains based on product tag `v0.9.4`, commit
`6e518ad95a018a80a04db295c0f91ec928a0ba0c`, tree
`eb0926ccb63b9a5a0ad1777334a04b3539b03d8b`. Do not move `v0.9.4`, replace its GitHub assets, or
represent the new npm tarball as byte-identical to the historical asset.

## Supported package surface

This developer preview supports ESM on Node `>=24.10.0 <25`, HTTP transport, strict TypeScript
NodeNext resolution, and type-only Bundler resolution. It exports the `cigar.context.v1` ABI, all
45 frozen HTTP operations, 70 generated payload models, bounded deadlines, abort signals,
idempotency-safe retries, effect-ambiguity handling, workflow recovery state, bundle/delta
verification, handoff, and replay.

CommonJS, private `dist/*` imports, and browser runtime execution are intentionally unsupported.
The public `AsyncDisposable` stream contract requires `ESNext.Disposable` when ambient Node types
do not provide it.

## Local non-publishing qualification

Qualification uses exact Node 24.10.0, npm 11.6.0, pnpm 10.34.5, and TypeScript 7.0.2. Staging
uses exact Node 24.19.0 and npm 12.0.2 because npm 11 does not provide `npm stage`, while npm
12.0.2 requires Node `^24.15.0`. These commands build and inspect a local candidate only:

```text
# Canonical package members are mode 0644; keep archive output directories mode 0700.
umask 022
pnpm --dir sdk/typescript run generate:check
python3 tools/quality/operation_surface_parity.py --quiet
pnpm --dir sdk/typescript run typecheck
pnpm --dir sdk/typescript test
python3 -m unittest scripts/release/tests/test_verify_npm_sdk.py

pnpm --dir sdk/typescript run prepack
npm pack --ignore-scripts --pack-destination /absolute/owner-only/output ./sdk/typescript

python3 scripts/release/verify_npm_sdk.py \
  /absolute/owner-only/output/hol-org-cigar-0.9.4.tgz \
  --require-canonical-bytes

node scripts/release/qualify_npm_consumers.mjs \
  --archive /absolute/owner-only/output/hol-org-cigar-0.9.4.tgz \
  --expected-version 0.9.4 \
  --npm-cli /absolute/path/to/npm-11.6.0/bin/npm-cli.js \
  --tsc /absolute/owner-controlled/typescript-7.0.2/bin/tsc

# Run this command with the separate Node 24.19.0/npm 12.0.2 staging toolchain.
npm stage publish --dry-run --json --ignore-scripts --access public --tag alpha \
  /absolute/owner-only/output/hol-org-cigar-0.9.4.tgz \
  >/absolute/owner-only/output/stage-dry-run.json

python3 scripts/release/verify_npm_sdk.py \
  /absolute/owner-only/output/hol-org-cigar-0.9.4.tgz \
  --require-canonical-bytes \
  --stage-dry-run /absolute/owner-only/output/stage-dry-run.json
```

The verifier reads without extraction, bounds compressed and expanded sizes, rejects links and
path collisions, requires canonical ownership and modes, scans secret-shaped values and private
paths, validates inline source maps, confirms package/release/ABI/operation identity, and binds the
complete inventory to the candidate hashes. It also binds every npm stage-dry-run identity,
integrity, size, file, and mode field back to that inventory. `--require-publishable`
intentionally fails until the reviewed profile changes to
`{"publishable":true,"status":"approved","blockers":[]}`.

The consumer qualifier rejects multi-linked tool inputs. Because pnpm may hard-link TypeScript
from its content-addressed store, CI copies the pinned TypeScript package and its locked native
platform package into an owner-controlled temporary dependency graph and requires every copied
file, including `bin/tsc`, to have exactly one link before use.

## First-publication bootstrap for 0.9.4

The package must exist before npm can bind a Trusted Publisher. The first release therefore uses
npm staged publishing with an authenticated human session; it does not use or store a long-lived
CI token.

1. Merge the public packaging PR only after required CI and review pass.
2. From the exact clean merge commit, build twice with the pinned qualification tools and require
   byte equality.
3. Require the resulting archive to match every value in `canonical_release_asset` and run the
   packed-consumer matrix.
4. Reconfirm that `npm view @hol-org/cigar@0.9.4 version` returns `E404` and that no pending staged
   0.9.4 package exists.
5. With Node 24.19.0, npm 12.0.2, and an authenticated `hol-org` developer session, stage only the
   exact reviewed archive:

   ```text
   npm stage publish --ignore-scripts --access public --tag alpha \
     /absolute/path/hol-org-cigar-0.9.4.tgz
   ```

6. In npmjs.com → Staged Packages, inspect the name, exact version, public visibility, `alpha`
   tag, file inventory, README, and integrity. Reject the stage if any field differs.
7. Approve the staged package with 2FA. Never assign `latest` to this developer preview.
8. Verify the live package's SHA-512 integrity against the local archive, confirm
   `dist-tags.alpha` is `0.9.4`, confirm `latest` is absent, and install the exact version into a
   clean consumer with lifecycle scripts disabled.
9. Log the registry URL, integrity, dist-tags, approval time, source commit, and clean-consumer
   result in the release report. End the bootstrap session with `npm logout`.

A name/version pair is immutable after approval. If any check fails before approval, reject the
stage and investigate; do not work around a gate or attempt a second artifact with the same
identity.

## Trusted Publisher for 0.9.5-alpha.1 and later

After 0.9.4 exists, configure a single stage-only Trusted Publisher for:

- GitHub organization: `hashgraph-online`
- Repository: `hol-cigar`
- Workflow filename: `stage-hol-cigar-npm.yml`
- Environment: `npm`
- Allowed action: `npm stage publish` only

Equivalent npm 12 command:

```text
npm trust github @hol-org/cigar \
  --repo hashgraph-online/hol-cigar \
  --file stage-hol-cigar-npm.yml \
  --env npm \
  --allow-stage-publish
```

Protect the GitHub `npm` environment with independent required reviewers. In npm package settings,
select “Require two-factor authentication and disallow tokens.” Future releases must merge the
workflow before tagging, use an exact prerelease tag such as `v0.9.5-alpha.1`, publish a matching
GitHub prerelease, dispatch the stage workflow from that tag, and receive a separate 2FA approval
on npm. Trusted Publishing then supplies short-lived OIDC credentials and automatic provenance.

## Recovery

Before approval, reject a bad staged package. After publication, never attempt to overwrite a
version. Remove or move only the `alpha` dist-tag to a separately verified replacement and
deprecate the bad exact version with a concise migration message. Unpublish is not the normal
rollback mechanism.

Authoritative npm references:

- https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/
- https://docs.npmjs.com/cli/v11/commands/npm-stage/
- https://docs.npmjs.com/trusted-publishers/
- https://docs.npmjs.com/cli/v11/commands/npm-trust/
