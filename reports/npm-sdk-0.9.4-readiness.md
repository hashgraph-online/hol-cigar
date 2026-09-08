# `@hol-org/cigar` 0.9.4 npm release assessment

Assessment date: 2026-09-02

## Decision

`@hol-org/cigar@0.9.4` is published as a public npm developer preview. The live registry tarball is
byte-identical to the twice-built canonical archive approved in public PR #33. Live metadata,
exact-version installation, ESM import, release identity, exported surface, and production audit
all passed. The immutable 0.9.4 profile is terminal and remains non-publishable so the release
workflow cannot attempt to stage the same version again.

The intended release channel is `alpha`. npm unexpectedly assigned both `alpha` and `latest` on
this first publication. One WebAuthn-authorized removal of only `latest` was attempted with the
documented `npm dist-tag rm` operation; the registry returned `E400 Bad Request` and did not change
either tag. This tag-policy exception remains open and is not counted as a successful gate.

## Registry and authority

| Property | Observed value |
| --- | --- |
| Authenticated npm user | `tmcc_patches` |
| npm organization | `hol-org` |
| User role | developer |
| Organization owner | `kantorcodes` |
| Package | `@hol-org/cigar@0.9.4` |
| Registry state | public; published 2026-09-02T23:08:48.217Z |
| Visibility | public |
| Intended dist-tag | `alpha` |
| Observed dist-tags | `alpha=0.9.4`, `latest=0.9.4` |
| `latest` remediation | one removal request rejected by npm with `E400`; no state change |
| Registry tarball | `https://registry.npmjs.org/@hol-org/cigar/-/cigar-0.9.4.tgz` |
| Trusted Publisher | GitHub `hashgraph-online/hol-cigar`, `stage-hol-cigar-npm.yml`, environment `npm`, stage permission only |

The npm website session and CLI session are separate. The CLI identity was explicitly verified
with `npm whoami`, and organization membership was read back with `npm org ls hol-org`. Interactive
approval used the account's WebAuthn security key/passkey; that configuration does not send an OTP
by email or SMS. No token or credential was written to the repository or printed into release
evidence. The bootstrap session ended with `npm logout`, and a final `npm whoami` returned
`ENEEDAUTH`.

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

PR #33 merged the packaging change as commit
`7866bab567c29fecc19d34d9071dccd90d30bd7c`, tree
`71cc42969ec0636efa918cd57709352e627a5482`; the published archive was built from that exact clean
merge. The package declares the exact public repository, homepage, issue tracker, public registry,
public access, and `alpha` default. The npm tarball is intentionally not byte-identical to the
historical GitHub `cigar-sdk-0.9.4.tgz` asset. The existing `v0.9.4` tag and GitHub assets must not
be moved or replaced.

## Canonical published artifact

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

Two independent npm 11.6.0 pack invocations from the clean merge, each following a fresh prepack
build, produced
byte-identical archives. The no-extraction verifier matched every canonical candidate field and
all metadata, path, ownership, mode, source-map, secret-pattern, ABI, dependency, and operation
checks. After publication, the registry tarball was downloaded independently and compared
byte-for-byte with the canonical archive; its SHA-1 and SHA-512 SRI also match. The verifier now
rejects `--require-publishable` because 0.9.4 is an immutable terminal release, rather than a
candidate eligible for another staging operation.

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
| Live registry tarball comparison | Passed; byte-identical to the canonical archive |
| Live exact-version clean install and ESM import | Passed; ABI and release identity matched |
| Live installed production audit | Passed; zero vulnerabilities |
| actionlint 1.7.7 | Passed for both npm workflows |
| Patch whitespace/error check | Passed |

The production audit observed one direct SDK dependency and its transitive production graph; it
reported no advisories and zero info, low, moderate, high, or critical vulnerabilities.

## Packed-consumer matrix

The final tarball was installed as the only SDK source into an owner-only clean consumer. Install
scripts were disabled, the installed SDK was required to be a materialized directory rather than
a workspace link, and registry access was disabled after installation. CI snapshots the pinned
TypeScript package and locked native platform package into an owner-controlled temporary graph so
the strict tool validator does not accept package-store hard links.

| Consumer | Result |
| --- | --- |
| Node 24.10.0 ESM runtime | Passed; ABI `cigar.context.v1`, 45 operations |
| TypeScript 7.0.2 NodeNext | Passed with `ESNext.Disposable` |
| TypeScript 7.0.2 Bundler resolution | Passed types only; no browser runtime claim |
| CommonJS `require()` | Refused as unsupported |
| `@hol-org/cigar/dist/*` private subpath | Refused as unsupported |
| Public registry exact-version install | Passed with npm 12.0.2, scripts disabled, and no Git dependencies allowed |

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

npm staged publishing cannot create a brand-new package: the package must already exist. The
initial `npm stage publish` therefore returned `E404` and created no stage. 0.9.4 used a one-time
direct publication of the exact verified archive through an interactive WebAuthn session. This
bootstrap exception did not create or store a long-lived publishing token.

After the package became visible, the workflow was configured as the package's single stage-only
Trusted Publisher. Readback returned trust ID `683e1f3b-2344-427f-acfc-b6f89266d7bf`, repository
`hashgraph-online/hol-cigar`, workflow `stage-hol-cigar-npm.yml`, environment `npm`, and only the
`createStagedPackage` permission. The GitHub `npm` environment requires reviewer `kantorcodes`,
prevents self-review, and permits only tags matching `v0.9.*`. Package access was set to require
2FA and disallow publishing-token bypass. `0.9.5-alpha.1` and later can therefore use OIDC-backed
staging and automatic provenance, while still requiring separate human approval on npm.

## Publication verification

| Check | Observed result |
| --- | --- |
| Public metadata availability | Passed after npm's publication scan completed |
| Name and version | `@hol-org/cigar@0.9.4` |
| SHA-1 | `ac08dbcad3dfacc0fa2f9d88dbaf5b28e5ac4e53` |
| SHA-512 SRI | `sha512-+XfQU9iD1RtUw5V1uGeABuMkbC2I2u6rbSJqp83nc4n9DOB/p0AacFyUqyOSFKbWVVKpSPK7WaetcgzHpUs6VA==` |
| Downloaded SHA-256 | `73eb45b5a096639653350a2ab6436f75d3de32a1e3692d1808e8b2cfe32a77f8` |
| Registry versus canonical bytes | Passed with exact binary comparison |
| Registry inventory | 78 files, 2,305,674 unpacked bytes |
| Clean consumer | Passed; `cigar.context.v1`, release JSON identity, and 104 exports observed |
| Production audit | Passed; zero vulnerabilities |
| Interactive-session cleanup | Passed; logged out and subsequent identity check returned `ENEEDAUTH` |

## Remaining exception

Remove only the unintended `latest` dist-tag through the npm package UI or npm support. After any
remediation, read back the complete tag map and require exactly `alpha=0.9.4` with `latest` absent.
Do not unpublish 0.9.4, do not alter its tarball, and do not republish the immutable name/version.
Until that readback passes, the machine profile remains
`published-with-tag-policy-exception` and non-publishable.

The executable commands, verification sequence, OIDC fields, and recovery procedure are in
`packaging/npm/README.md`.
