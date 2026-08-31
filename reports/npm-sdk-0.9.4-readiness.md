# `@hol-org/cigar` 0.9.4 npm readiness assessment

Assessment date: 2026-08-31

## Decision

`@hol-org/cigar@0.9.4` is technically qualified as a public npm developer-preview candidate for
the `alpha` dist-tag. External staging remains fail-closed until the packaging changes receive
public PR review and merge. After merge, the first package must be staged from the exact reviewed
archive and separately approved by an authorized npm maintainer with 2FA.

No npm package, version, dist-tag, trusted publisher, staged package, Git tag, GitHub release, PR,
or remote branch was created or changed during this assessment.

## Registry and authority

| Property | Observed value |
| --- | --- |
| Authenticated npm user | `tmcc_patches` |
| npm organization | `hol-org` |
| User role | developer |
| Organization owner | `kantorcodes` |
| Package | `@hol-org/cigar@0.9.4` |
| Registry state | public `E404` at 2026-08-31T15:14:38Z |
| Visibility | public |
| Intended dist-tag | `alpha` |
| `latest` | must remain absent |

The npm website session and CLI session are separate. The CLI identity was explicitly verified
with `npm whoami`, and organization membership was read back with `npm org ls hol-org`. No token or
credential was written to the repository or printed into assessment evidence.

## Source and identity migration

The runtime implementation is based on CIGAR `v0.9.4`, commit
`6e518ad95a018a80a04db295c0f91ec928a0ba0c`, tree
`eb0926ccb63b9a5a0ad1777334a04b3539b03d8b`. The npm packaging change migrates the TypeScript SDK
from the unavailable `@cigar/sdk` namespace to the project-controlled `@hol-org/cigar` namespace
and propagates that identity through:

- `package.json` and `release.json`;
- the cross-SDK capability generator and generated capability manifests;
- product-version and operation-parity authorities;
- clean-install and release-evidence builders;
- documentation, examples, and refusal tests; and
- npm readiness, verification, and staged-publication workflows.

The package now declares the exact public repository, homepage, issue tracker, public registry,
public access, and `alpha` default. The npm tarball is intentionally not byte-identical to the
historical GitHub `cigar-sdk-0.9.4.tgz` asset. The existing `v0.9.4` tag and GitHub assets must not
be moved or replaced.

## Canonical npm candidate

| Property | Value |
| --- | --- |
| Filename | `hol-org-cigar-0.9.4.tgz` |
| Compressed bytes | 340,971 |
| Files | 78 regular mode-0644 files |
| SHA-256 | `73eb45b5a096639653350a2ab6436f75d3de32a1e3692d1808e8b2cfe32a77f8` |
| SHA-1 | `ac08dbcad3dfacc0fa2f9d88dbaf5b28e5ac4e53` |
| npm integrity | `sha512-+XfQU9iD1RtUw5V1uGeABuMkbC2I2u6rbSJqp83nc4n9DOB/p0AacFyUqyOSFKbWVVKpSPK7WaetcgzHpUs6VA==` |
| Semantic tree SHA-256 | `dd2c0bc2b48d04ba0187fe017071edad4ad9d1ad3f7cf0203cffe975e43c2baa` |
| Direct runtime dependency | `@bufbuild/protobuf@2.12.1` |
| Context ABI | `cigar.context.v1` |
| Frozen operations | 45 |

Two independent npm 11.6.0 pack invocations, each following a fresh prepack build, produced
byte-identical archives. The no-extraction verifier matched every canonical candidate field and
all metadata, path, ownership, mode, source-map, secret-pattern, ABI, dependency, and operation
checks. The same verifier intentionally returned exit code 2 when `--require-publishable` was
added, proving the unreviewed publication gate remains closed.

The pack workflows explicitly set `umask 022` so package members are reproducibly mode `0644`;
the containing candidate directories remain owner-only mode `0700`.

## Test and hardening results

| Gate | Result |
| --- | --- |
| Full SDK generation drift, exact Go 1.26.6 formatter | Passed |
| Cross-SDK operation/capability parity | Passed |
| Strict TypeScript 7.0.2 typecheck | Passed |
| TypeScript runtime suite | 29 passed, 0 failed |
| Npm verifier/build/version compatibility tests | 27 passed, 0 failed |
| Two-pack npm 11.6.0 reproducibility | Passed; byte-identical |
| Archive bounds, inventory, modes, paths, maps, and secret scan | Passed |
| Production dependency audit | Passed; zero vulnerabilities at every severity |
| Locked pnpm audit policy structure | Passed |
| Exact npm stage dry-run identity, integrity, size, inventory, and modes | Passed; no staging occurred |
| actionlint 1.7.7 | Passed for both npm workflows |
| Patch whitespace/error check | Passed |

The production audit observed one direct SDK dependency and its transitive production graph; it
reported no advisories and zero info, low, moderate, high, or critical vulnerabilities.

## Packed-consumer matrix

The final tarball was installed as the only SDK source into an owner-only clean consumer. Install
scripts were disabled, the installed SDK was required to be a materialized directory rather than
a workspace link, and registry access was disabled after installation.

| Consumer | Result |
| --- | --- |
| Node 24.10.0 ESM runtime | Passed; ABI `cigar.context.v1`, 45 operations |
| TypeScript 7.0.2 NodeNext | Passed with `ESNext.Disposable` |
| TypeScript 7.0.2 Bundler resolution | Passed types only; no browser runtime claim |
| CommonJS `require()` | Refused as unsupported |
| `@hol-org/cigar/dist/*` private subpath | Refused as unsupported |

The supported engine range is Node `>=24.10.0 <25`. The package has no install hook, downloads no
binary, is ESM-only, and claims HTTP transport only.

Qualification deliberately uses Node 24.10.0 with npm 11.6.0 so the minimum supported engine is
exercised. npm 11 does not implement staged publishing, and npm 12.0.2 requires Node `^24.15.0`,
so the non-mutating stage dry run uses a separate Node 24.19.0/npm 12.0.2 toolchain. The archive
accepted by that staging toolchain is the exact npm 11-produced candidate qualified by consumers.

## Release controls

`.github/workflows/npm-sdk-readiness.yml` reproduces the source, type, runtime, verifier,
two-pack, consumer, audit, and stage-dry-run gates on PRs and `main`. It packs and qualifies with
Node 24.10.0/npm 11.6.0, then switches to Node 24.19.0/npm 12.0.2 only for the stage dry run.

`.github/workflows/stage-hol-cigar-npm.yml` is a future prerelease workflow. It requires an exact
prerelease tag matching the manifest, a matching non-draft GitHub prerelease, an approved release
profile, two identical packs, an unoccupied version, a protected `npm` environment, and OIDC with
only `contents: read` and `id-token: write`. It uses `npm stage publish`, not direct publication,
so an npm maintainer must still inspect and approve every candidate with 2FA.

Because npm requires an existing package before Trusted Publisher configuration, 0.9.4 uses a
one-time authenticated staged-publication bootstrap after merge. After 0.9.4 exists, configure the
workflow as the package's single stage-only Trusted Publisher and disallow traditional publishing
tokens. `0.9.5-alpha.1` and later can then receive OIDC-backed automatic provenance.

## Remaining blockers

1. Publicly review and merge this packaging change with required CI passing.
2. Rebuild the exact archive from the clean merge commit and require the same canonical digest.
3. Stage the archive with public access and the `alpha` tag; do not use `latest`.
4. Inspect and approve the staged package with 2FA.
5. Verify live integrity, dist-tags, and a clean exact-version installation.
6. Configure the stage-only Trusted Publisher and protected GitHub `npm` environment before
   `0.9.5-alpha.1`.

The executable commands, verification sequence, OIDC fields, and recovery procedure are in
`packaging/npm/README.md`.
