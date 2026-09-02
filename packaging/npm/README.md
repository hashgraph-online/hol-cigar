# npm release profile for `@hol-org/cigar`

## Current decision

`@hol-org/cigar@0.9.4` was published as a public developer preview on 2026-09-02 after the public
packaging PR merged. The registry tarball is byte-identical to the twice-built canonical archive,
and a clean exact-version install and production audit passed. The package is immutable and the
0.9.4 profile is now terminal and non-publishable.

The intended channel is `alpha`. npm nevertheless assigned both `alpha` and `latest` during the
first publication. A WebAuthn-authorized `npm dist-tag rm @hol-org/cigar latest` request was made
once and the registry rejected it with `E400 Bad Request`; no package or tag changed. This remains
an explicit tag-policy exception in `release-profile.v1.json`. Resolve it through npm package
settings or npm support, then require `alpha=0.9.4` and `latest` absent. Do not unpublish or
republish 0.9.4.

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
`eb0926ccb63b9a5a0ad1777334a04b3539b03d8b`. The published npm archive was rebuilt from the exact
merged packaging commit `7866bab567c29fecc19d34d9071dccd90d30bd7c`, tree
`71cc42969ec0636efa918cd57709352e627a5482`. Do not move `v0.9.4`, replace its GitHub assets, or
represent the npm tarball as byte-identical to the historical `cigar-sdk-0.9.4.tgz` asset.

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
intentionally fails for the terminal 0.9.4 profile. A future prerelease profile must use the exact
`{"publishable":true,"status":"approved","blockers":[]}` decision only after its own review and
before its one authorized staging attempt.

The consumer qualifier rejects multi-linked tool inputs. Because pnpm may hard-link TypeScript
from its content-addressed store, CI copies the pinned TypeScript package and its locked native
platform package into an owner-controlled temporary dependency graph and requires every copied
file, including `bin/tsc`, to have exactly one link before use.

## First-publication bootstrap for 0.9.4

Trusted Publisher configuration and staged publishing both require an existing npm package, so a
brand-new package cannot use `npm stage publish` for its bootstrap release. The reviewed 0.9.4
archive was therefore published once from an authenticated human session with public access and
the `alpha` tag. Authentication used npm's browser WebAuthn security-key/passkey challenge; npm
does not send an email or SMS OTP for that account configuration. No CI publishing token was
created or stored.

The completed bootstrap sequence was:

1. Merge the public packaging PR after required CI and independent review passed.
2. Rebuild twice from exact merge commit `7866bab567c29fecc19d34d9071dccd90d30bd7c`
   with the pinned qualification tools and require byte equality.
3. Require the archive to match every `canonical_release_asset` field, run the packed-consumer
   matrix, and run the npm 12 stage dry-run as a non-mutating package inspection.
4. Reconfirm the package and version were absent from the public registry.
5. Attempt staged publication, observe npm's documented new-package `E404` restriction, and create
   no stage.
6. Publish only the exact reviewed archive with lifecycle scripts disabled, public access, the
   `alpha` tag, and an interactive WebAuthn challenge.
7. Wait for npm's publication scan, then download the live registry tarball and require byte
   equality with the canonical archive.
8. Verify live name, version, repository, engine range, SHA-1, SHA-512 SRI, and 78-file inventory;
   perform a clean exact-version install with scripts disabled and run a production audit.
9. Configure and read back the stage-only Trusted Publisher, set the package MFA policy, then end
   the interactive session with `npm logout` and confirm `npm whoami` returns `ENEEDAUTH`.

The live tarball is
`https://registry.npmjs.org/@hol-org/cigar/-/cigar-0.9.4.tgz`, with SHA-256
`73eb45b5a096639653350a2ab6436f75d3de32a1e3692d1808e8b2cfe32a77f8` and npm SRI
`sha512-+XfQU9iD1RtUw5V1uGeABuMkbC2I2u6rbSJqp83nc4n9DOB/p0AacFyUqyOSFKbWVVKpSPK7WaetcgzHpUs6VA==`.

## Trusted Publisher for 0.9.5-alpha.1 and later

A single stage-only Trusted Publisher is now configured and was read back for:

- GitHub organization: `hashgraph-online`
- Repository: `hol-cigar`
- Workflow filename: `stage-hol-cigar-npm.yml`
- Environment: `npm`
- Allowed action: `npm stage publish` only

The equivalent npm 12 command is:

```text
npm trust github @hol-org/cigar \
  --repo hashgraph-online/hol-cigar \
  --file stage-hol-cigar-npm.yml \
  --env npm \
  --allow-stage-publish
```

Protect the GitHub `npm` environment with independent required reviewers. In npm package settings,
“Require two-factor authentication and disallow tokens” is enabled. The GitHub `npm` environment
requires reviewer `kantorcodes`, prevents self-review, and allows only tags matching `v0.9.*`.
Future releases must merge the workflow before tagging, use an exact prerelease tag such as
`v0.9.5-alpha.1`, publish a matching GitHub prerelease, dispatch the stage workflow from that tag,
and receive a separate 2FA approval on npm. Trusted Publishing then supplies short-lived OIDC
credentials and automatic provenance.

## Recovery

Before approval, reject a bad staged package. After publication, never attempt to overwrite a
version. Remove or move only the `alpha` dist-tag to a separately verified replacement and
deprecate the bad exact version with a concise migration message. A mistaken `latest` alias should
be removed without changing `alpha` or the immutable version. Unpublish is not the normal rollback
mechanism.

Authoritative npm references:

- https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/
- https://docs.npmjs.com/staged-publishing/
- https://docs.npmjs.com/trusted-publishers/
- https://docs.npmjs.com/cli/v11/commands/npm-trust/
