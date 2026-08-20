# `@cigar/sdk` 0.9.4 npm readiness assessment

Date: 2026-08-20
Decision: **blocked for publication; runtime/package qualification otherwise passed**

## Executive result

The public CIGAR TypeScript SDK is functional as an installed ESM tarball, preserves the frozen
`cigar.context.v1` ABI and all 45 operations, passes its source tests, passes clean ESM/NodeNext/
Bundler consumers, refuses unsupported CommonJS and private subpaths, packs reproducibly, and has no
known production dependency vulnerabilities at the time of this assessment.

It must not be published as `@cigar/sdk@0.9.4`. The immutable GitHub release asset contains a
repository URL that returns 404 and omits the actual repository homepage and issue URL. Repairing
that metadata changes package bytes after the 0.9.4 tag and release manifest were published. npm
package versions cannot be overwritten, and npm provenance requires the manifest repository to
match the public GitHub repository. A corrected version-next prerelease is the truthful path.

No npm publish, npm access/scope change, Git push, tag, GitHub release, pull request, Humidor change,
CEDAR change, hiero-pentest change, or sibling-repository change was performed.

## Source and immutable artifact identity

| Authority | Value |
| --- | --- |
| Public repository | `https://github.com/hashgraph-online/hol-cigar` |
| Tag | `v0.9.4` |
| Commit | `6e518ad95a018a80a04db295c0f91ec928a0ba0c` |
| Tree | `eb0926ccb63b9a5a0ad1777334a04b3539b03d8b` |
| Package | `@cigar/sdk@0.9.4` |
| ABI | `cigar.context.v1` |
| Operations | 45 |
| Models | 70 |
| Canonical asset | `cigar-sdk-0.9.4.tgz` |
| Canonical bytes | 325,334 |
| Canonical files | 78 regular files, all mode `0644`, UID/GID 0 |
| Canonical SHA-256 | `8160193eea7c51f58b13b3a69123e485d0b5aacb6f25687af98dc4a16423379f` |
| Canonical SHA-1/npm shasum | `6bfe1632cd8f9285bbb1774131bea20a72352ad1` |
| Canonical npm integrity | `sha512-n9Tsc4xb1rOxcc3FX2dBaavZLOySC4Adk2jRQ4W7/zBgwGOR1EbQprE6jEAVPxwCxvYDMkRDWgDIBBHfAoUK3g==` |
| Semantic payload tree | `b11ac72d2e9ef1f359564e39cf83f7a553b5266943c53242fafec228b493c627` |

The archive contains only `package.json`, README, Apache-2.0 license, NOTICE, one fixture, generated
ESM JavaScript, declarations, and inline source maps. It has no `.npmrc`, environment file, key,
certificate, source directory, test directory, `node_modules`, lifecycle install hook, native
binary, or symlink.

## Registry and provenance observations

Unauthenticated public registry lookup returned `E404` for `@cigar/sdk` on
2026-08-20T17:35:05Z. This establishes only that no public package/version collision was visible;
it does not establish that the HOL/CIGAR maintainers control the `@cigar` scope.

The archive declares `git+https://github.com/CIGAR/cigar.git`, and that Git endpoint returned
“Repository not found.” The authoritative public repository is
`git+https://github.com/hashgraph-online/hol-cigar.git`. The archive also lacks the corresponding
`homepage` and `bugs` fields. Every other checked package/release metadata predicate passed.

The npm publication workflow did not exist in `v0.9.4`. Adding it after the tag cannot make the
old tag contain its build recipe, and publishing from a later branch workflow would bind provenance
to the later workflow revision rather than repair the immutable tag. npm Trusted Publishing also
requires the package to exist before its trusted publisher can be configured, leaving an explicit
first-publication bootstrap action for an npm owner.

## Build and reproducibility results

Frozen tools used locally:

- Node `24.10.0`
- pnpm `10.34.5`
- npm `11.6.0`
- TypeScript `7.0.2`
- Python `3.14.6`
- Go/gofmt `1.26.6`
- actionlint `1.7.7`

Two independent npm 11.6.0 pack invocations after the reviewed prepack build were byte-identical:

| Property | Value |
| --- | --- |
| SHA-256 | `9e9114c7d9e19c54a0a6553b8ebd5461ee49988b4405ffc1793a8a1ada1dc0df` |
| SHA-1 | `9bf57c3c78e896121c6663eb0518130a22a0bfac` |
| npm integrity | `sha512-wg3yiPqrwC2Xe0KtkjUkKGikhKlHqIPZTp5UR+HvSjWgGk/lmfdVps7YZGaBbkP3eXBOkC1U7pk3YY+8o1qHuw==` |
| Compressed bytes | 340,754 |
| Unpacked bytes reported by npm | 2,305,102 |
| Files | 78 |
| Semantic payload tree | `b11ac72d2e9ef1f359564e39cf83f7a553b5266943c53242fafec228b493c627` |

The npm-produced `.tgz` and canonical GitHub release `.tgz` have different container bytes because
the release assembler normalizes tar/gzip metadata. Their path/mode/content semantic-tree digests
are identical. This is the explained reproducibility result; both inventories contain the same 78
payload files with the same bytes and modes.

A diagnostic `pnpm pack` was also tested and deliberately rejected as the release producer. pnpm
removed `packageManager` and `prepack` from the packed manifest, yielding a different semantic tree.
The prepared workflows therefore build with pnpm but pack with exact npm 11.6.0 and
`--ignore-scripts` after prepack.

## Tests and audits

| Gate | Result |
| --- | --- |
| Frozen workspace install | Passed |
| Full SDK generation drift check | Passed |
| Cross-surface operation parity | Passed |
| TypeScript strict typecheck | Passed |
| TypeScript runtime/unit suite | 29 passed, 0 failed |
| npm archive verifier unit suite | 5 passed, 0 failed |
| Canonical archive hash/inventory/mode validation | Passed |
| ABI/release identity and 45-operation validation | Passed |
| Inline source-map content and path scan | Passed |
| Secret-shaped value/private-path/archive scan | Passed |
| npm 11.6.0 two-pack byte reproducibility | Passed |
| `npm publish --dry-run --json --access public --tag alpha` | Passed; no publish occurred |
| Production dependency audit | Passed; no known vulnerabilities found |
| Locked license inventory | Complete; zero review-required components |
| Workflow YAML parse | Passed |
| actionlint 1.7.7 | Passed |

The sole runtime dependency is `@bufbuild/protobuf@2.12.1`, licensed
`(Apache-2.0 AND BSD-3-Clause)` and marked accepted in the locked project license inventory. The
dry-run reported `@cigar/sdk@0.9.4`, public access, `alpha`, 78 files, the npm-pack SHA-1/integrity
above, and no bundled dependencies.

## Packed consumer matrix

The consumer harness installed the SDK only from the `.tgz`, disabled install scripts, required a
materialized non-symlink package under a clean `node_modules`, and disabled registry access after
dependency installation.

| Consumer | Result |
| --- | --- |
| Node 24.10.0 ESM runtime | Passed; ABI `cigar.context.v1`, 45 operations |
| TypeScript 7.0.2 NodeNext | Passed with `ESNext.Disposable` library |
| TypeScript 7.0.2 Bundler resolution | Passed types only; no browser runtime claim |
| CommonJS `require()` | Refused as unsupported |
| `@cigar/sdk/dist/*` private subpath | Refused as unsupported |

The `ESNext.Disposable` requirement follows from the exported `AsyncDisposable` stream contract.
It should be documented in the eventual packed README or changed only through a version-next ABI
review. CommonJS and browser runtime support remain unclaimed.

## Publication blockers

1. **Immutable metadata mismatch:** the released 0.9.4 tarball points to a nonexistent repository.
   Fixing it changes tagged/released bytes.
2. **Scope ownership:** public `E404` does not prove control of `@cigar`; an authenticated npm owner
   must confirm it or approve a different package name.
3. **Trusted Publisher bootstrap:** the absent package cannot yet have an npm OIDC trusted publisher.
   First publication requires a separately approved tag-bound bootstrap, followed immediately by
   OIDC configuration and credential revocation.
4. **Workflow provenance:** `v0.9.4` does not contain the npm workflow. A later prerelease tag must
   contain the reviewed workflow before it is dispatched.

Recommended next identity: a product-wide prerelease such as `0.9.5-alpha.1`, subject to maintainer
approval. The generator's cross-SDK version invariant should remain fail-closed. Do not publish new
bytes as 0.9.4, move `v0.9.4`, overwrite its GitHub asset, or use npm's `latest` dist-tag.

## Prepared controls

- `packaging/npm/release-profile.v1.json` binds the current package, source, archive, toolchain,
  registry intent, exact blockers, and `publishable: false` decision.
- `scripts/release/verify_npm_sdk.py` performs bounded no-extraction validation and can require
  canonical bytes and/or a publishable profile.
- `scripts/release/qualify_npm_consumers.mjs` executes the tarball-only consumer matrix with registry
  access disabled after installation.
- `.github/workflows/npm-sdk-readiness.yml` prepares frozen PR qualification, full generation drift,
  source/type/runtime tests, two-pack reproducibility, consumers, audit, and dry-run.
- `.github/workflows/publish-cigar-sdk-npm.yml` is an OIDC-only, protected-environment,
  exact-prerelease-tag workflow that consumes one staged verified tarball. It refuses the current
  profile and cannot publish 0.9.4.
- `packaging/npm/README.md` contains the owner/OIDC/bootstrap/version-next/publish/verification/
  deprecation runbook.

## Evidence custody

Owner-only local evidence is stored outside the repository at
`/private/tmp/cigar-npm-094-evidence.4aEOk6` (directory mode `0700`; files mode `0400`):

| Evidence | SHA-256 |
| --- | --- |
| `canonical-0.9.4-assessment.json` | `8aedcb19ceddf702426905a95c5c56716aad3b1c28b668766cb4f90d7ffe817c` |
| `canonical-0.9.4-consumers.json` | `973ee404564fb8bf831abdbc38dd82b551a44b8aed753a2dc45c6c7d44ab4290` |
| `source-npm-pack-assessment.json` | `f96973713e9e6c2b092d5fa6912473403cf3f44f3028c8ba93fc2adf5cf6125f` |

These local receipts are development evidence, not signatures, registry provenance, publication
authorization, or support qualification.
