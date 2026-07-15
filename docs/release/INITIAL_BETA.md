# CIGAR `0.1.0-beta.1` release contract

Status: **RELEASE-BLOCKED unless one immutable candidate satisfies every gate below**

This document defines the initial beta lane. It is intentionally narrower than the CIGAR v1.0.0 production specification. Completing this lane does not complete WP19, WP20, WP21, WP22, any GA launch item, or any production-readiness claim.

## Immutable identity

| Field | Required value |
|---|---|
| Product | `cigar` |
| Version | `0.1.0-beta.1` |
| Tag | `v0.1.0-beta.1` |
| Channel | `beta` |
| Release profile | `cigar.beta.embedded-local.linux-x86_64.v1` |
| Target | `x86_64-unknown-linux-gnu` |
| Required qualification runtime | Ubuntu 24.04, x86-64, glibc 2.39 (`ubuntu-24.04-x86_64-glibc-2.39`) |
| Prerelease | `true` |
| Production ready | `false` |
| Distribution form | Six archives; no installer |

The checked-in machine-readable sources are `packaging/beta/product-version.v1.json`, `packaging/beta/capability-policy.v1.json`, `packaging/beta/artifact-matrix.v1.json`, and `packaging/beta/release-profile.v1.json`. A mismatch among those files, this document, compiled help, artifact contents, evidence, or published metadata is release-blocking.

## Exact included surface

The beta is a local workspace-state administration executable. Only these documented commands are in scope:

```text
cigar init [project-root]
cigar source add <source-id> <directory>
cigar source list
cigar source remove <source-id>
cigar project list
cigar project attach <project-id> <directory>
cigar project detach <project-id>
cigar project switch <project-id>
cigar project link <from-project-id> <to-project-id>
cigar project unlink <from-project-id> <to-project-id>
cigar focus switch <focus-id>
cigar focus close [focus-id]
cigar help
cigar version
```

The exact global options intended for the beta are the options in `crates/cigar-cli/assets/cigar-help-beta.txt`: `--output`, `--deadline`, `--config`, `--target embedded`, `--embedded`, `--dry-run`, `--yes`, `--non-interactive`, `--quiet`, `--color`, `--unicode`, `--width`, and `--explain-config`.

This surface administers local identifiers, directory bindings, project links, active project/focus state, and local state-file persistence. It does not ingest source contents, create catalog atoms, index data, retrieve records, plan or compile context, execute effects, or provide a background service.

### Explicit exclusions

The fail-closed excluded capability identifiers are:

| Identifier | Excluded surface |
|---|---|
| `catalog-discovery` | Source discovery and refresh |
| `catalog-ingest` | Catalog ingestion |
| `catalog-query` | Catalog inspection and query |
| `context` | Context planning, compilation, explanation, diff, revalidation, and materialization |
| `retrieval` | Retrieval and ranking |
| `handoff` | Handoff creation, inspection, acceptance, revocation, and merge |
| `space` | Space fork, publication, log, conflict, and checkpoint workflows |
| `replay` | Replay reconstruction, execution, comparison, and completeness |
| `policy` | Policy evaluation and explanation |
| `daemon` | `cigard`, daemon lifecycle, health/readiness, service operation |
| `effects` | External effect intent, approval, dispatch, and reconciliation |
| `extensions` | Extension loading, execution, and distribution |
| `installers` | Homebrew, packages, MSI/WinGet, system installers |
| `macos` | All macOS targets |
| `mcp` | MCP server and protocol surface |
| `oci` | Images, indexes, and container deployment |
| `otlp` | OTLP export and collector integration |
| `plugin` | Plugin packages and runtime |
| `remote` | Remote execution or service access |
| `sdk` | Rust, TypeScript, Python, and Go SDK packages |
| `shared` | Shared-service and multi-user operation |
| `vector` | Vector backends, indexing, and export |
| `windows` | All Windows targets |
| `arm` | ARM and AArch64 targets |
| `backup` | Backup and restore administration |
| `garbage-collection` | Garbage-collection planning and execution |
| `diagnostics` | Diagnostic bundle and doctor operations |
| `serving` | HTTP, gRPC, socket, and other service listeners |
| `completion-man` | Completion and manual-page generators |

No CLI/API behavior, dependency, payload, documentation claim, or release metadata may imply that an excluded capability is available. Unknown commands, unknown options, unsupported feature selections, and mixed full/beta feature selections must fail closed.

## Required artifact set

Exactly six artifacts are required. The set is closed: a missing artifact or an unlisted seventh artifact fails qualification.

| ID | Exact filename | Required payload |
|---|---|---|
| `source` | `cigar-0.1.0-beta.1-source.tar.gz` | Exact committed beta source projection |
| `docs` | `cigar-0.1.0-beta.1-docs.tar.gz` | Allowlisted beta documentation |
| `schemas` | `cigar-0.1.0-beta.1-schemas.tar.gz` | Allowlisted beta schemas and contracts |
| `conformance` | `cigar-0.1.0-beta.1-conformance.tar.gz` | Allowlisted offline conformance kit |
| `licenses` | `cigar-0.1.0-beta.1-licenses.tar.gz` | Exact license and notice material |
| `cigar-linux-x86_64-gnu` | `cigar-0.1.0-beta.1-x86_64-unknown-linux-gnu.tar.gz` | Exactly one executable payload, `bin/cigar` |

The category list in `packaging/beta/artifact-matrix.v1.json` is authoritative for every artifact;
partial prose lists must never be used to omit a required qualification category.

Every archive must be generated from the same committed candidate and deterministic source archive. Contract verification must reject extra or missing files, wrong type/mode/owner/timestamp, absolute or traversing paths, case collisions, hard links where forbidden, escaping symlinks, device nodes, FIFOs, sockets, duplicate members, decompression bombs, and trailing or ambiguous archive data.

## Evidence and signature domain separation

Beta qualification evidence uses:

- schema `cigar.beta.qualification-evidence.v1`;
- release schema `cigar.beta.release-evidence.v1`;
- purpose `cigar-beta-qualification-evidence-v1`.

The GA schemas `cigar.qualification-evidence.v1` and `cigar.release-evidence.v1` are forbidden in the beta lane. Beta evidence cannot satisfy or be rebound to a GA gate.

Only these beta signature purposes are permitted:

- `cigar-beta-qualification-evidence-v1`;
- `cigar-beta-release-artifact-v1`;
- `cigar-beta-release-checksums-v1`;
- `cigar-beta-release-evidence-v1`;
- `cigar-beta-release-provenance-v1`;
- `cigar-beta-release-sbom-v1`;
- `cigar-beta-release-spdx-v1`.

The GA purposes listed as forbidden in `packaging/beta/release-profile.v1.json` must be rejected. Verification must use a separately approved trust-root bundle and reject unknown purpose, wrong artifact, wrong source, wrong profile/version, duplicate envelope, expired/revoked identity, unsupported algorithm, malformed canonical bytes, or partial signature sets.

## Current candidate-source proof

The following checks passed from a clean detached committed candidate with build outputs and raw logs outside the checkout. Two independently created local source freezes were byte-identical and independently verified against the same Git object tree. These local results are candidate-source proof, not native artifact qualification or signed release evidence.

- [x] `python3 scripts/release/beta_profile.py check --root .` validated profile `cigar.beta.embedded-local.linux-x86_64.v1` and version `0.1.0-beta.1`; `python3 -B -m unittest tools.quality.tests.test_beta_profile -v` passed 8 tests. The related Ruff lint and format checks passed at the recorded proof point.
- [x] Compile-time feature-isolation checks passed: the full and `beta-embedded` modes build separately, neither/both selections fail closed, and the asserted daemon/API/crypto/effects/policy/store/network/OTLP/Wasmtime dependency families are absent from the beta dependency graph.
- [x] `cargo test -p cigar-cli --locked --no-default-features --features beta-embedded --lib --test beta_surface` passed 22 tests (10 unit and 12 integration); the full CLI composition passed 37 tests, the release-tool suite passed 58 tests, and projected-source plus strict beta/full Clippy checks passed in the available toolchain.

These checks prove the clean committed source and deterministic source-freeze gates only. They do
not prove the required Ubuntu builder identity, deterministic final artifacts, the safety of
installed final bytes, OS-enforced no-egress, final-byte security, SBOM and provenance approval,
production signatures, or publication.

## Release-tool sequence

The checked-in tools separate construction, external signing, assembly, and independent verification. Tool availability and unit-test success do not qualify a candidate.

1. Run `scripts/release/beta_profile.py check` and the beta runtime/release test suites against one clean detached candidate. Then run `CIGAR_EVIDENCE_DIR=/absolute/external/source-freeze scripts/release/beta_artifacts.py freeze-source --git /absolute/path/to/git`; the host-independent freeze requires a clean, stable Git commit/tree and writes exactly the deterministic source archive plus its canonical source descriptor outside the repository. An explicit `--evidence-dir` is equivalent; legacy `--out` remains mutually exclusive.
2. Run `scripts/release/beta_artifacts.py verify-source --source-freeze /absolute/external/source-freeze --git /absolute/path/to/git` independently from the same clean detached commit. This fail-closed check validates the exact two-file inventory, descriptor, deterministic archive, package contract, projected inputs, and read-only materialization, then recomputes the complete source selection from Git object bytes without claiming native-host qualification.
3. On the approved Ubuntu 24.04 x86-64/glibc 2.39 builder, with locked dependencies and independently enforced no-egress, select a new external candidate workspace with `CIGAR_EVIDENCE_DIR` or `--evidence-dir`, then run `scripts/release/beta_artifacts.py build --source-freeze /absolute/external/source-freeze` with all pinned tool/cache arguments. The build rejects a checkout whose clean commit/tree differs from the freeze, materializes build input only from the verified archive, copies the frozen archive and descriptor bytes unchanged, and produces an unsigned owner-only candidate containing the closed six-archive inventory plus checksums, CycloneDX, SPDX, provenance, manifest, and build-verification receipt.
4. Run `scripts/release/beta_artifacts.py verify` independently. This verifier reconstructs the committed source from the source archive and never executes candidate bytes.
5. Supply complete candidate-bound qualification receipts, their attachments, direct signatures for every required payload, and an independently provisioned trust policy conforming to the schemas in `packaging/beta/schemas/`.
6. Run `scripts/release/beta_release.py plan` with a new `CIGAR_EVIDENCE_DIR` or `--evidence-dir` to create `release-evidence.json`. Send only those exact canonical bytes to the approved isolated signer; no production private key may enter the workspace.
7. Run `scripts/release/beta_release.py assemble` with another new external evidence directory and the returned detached release-evidence signature, then unset `CIGAR_EVIDENCE_DIR` and run `scripts/release/beta_release.py verify` from a clean offline environment using the independently distributed trust policy. Verification is stdout-only and rejects an evidence selector instead of fabricating a receipt.

The manual GitHub workflow uploads an explicitly unsigned transport wrapper, not publishable release bytes. GitHub artifact modes are not preserved directly, so the workflow wraps the candidate in a POSIX tar, records its SHA-256 and GitHub artifact digest, restores it only into a new disposable owner-only directory, and reruns exact-inventory verification. A downloaded wrapper must first be authenticated against the recorded GitHub artifact digest and checksum; it must never be extracted directly into a source checkout, release directory, home directory, or other valuable path.

## Known release blockers

1. The frozen candidate has no complete six-artifact build or independent reproducibility result from the required Ubuntu 24.04 x86-64/glibc 2.39 runtime.
2. No installed-byte/no-egress qualification, approved final scan and legal disposition, production beta signature set, verified private reporting channel, or publisher authorization has been supplied.
3. No final offline complete-set verification or public readback receipt exists. Local tool implementation and tests cannot substitute for those external results.

## Qualification checklist

Every item below is required and remains unchecked until machine evidence for one immutable candidate proves it.

### Source freeze and binding

- [x] Commit all intended beta source, tests, contracts, generated outputs, lockfiles, and documentation; require a clean worktree before and after every source gate.
- [x] Record full commit SHA, tree SHA, commit timestamp/`SOURCE_DATE_EPOCH`, deterministic source-archive name/SHA-256/size, and exact profile/policy/contract/tool-input digests in one canonical source descriptor. Record builder, toolchain, and network observations later in candidate provenance and qualification receipts.
- [x] Build from the verified source archive in a detached/read-only source tree. Write all outputs and evidence outside it; prove source bytes and Git status are unchanged afterward.
- [x] Rerun the three workspace checks above against that exact source and bind their raw results to its source descriptor.

### Surface and state safety

- [x] Reconcile “embedded-local” language to workspace-metadata-administration-only behavior and contract-test the closed compiled command/option surface against the immutable candidate.
- [x] Reject the full-product/excluded commands, undocumented metadata/confirmation aliases, unknown options, incompatible targets, invalid identifiers, malformed state/configuration, and unsafe link/permission cases covered by the 22-test beta suite without mutation against the immutable candidate.
- [x] Fix the state-directory replacement/lock bypass with descriptor-relative state access and regress exclusive mutation, atomic replacement, restrictive file/directory modes, unsafe links, bounded deadlines, cancellation settlement, and concurrent updates against the immutable candidate.

### Native build and deterministic artifacts

- [ ] Build the binary on an isolated Ubuntu 24.04 x86-64/glibc 2.39 builder using pinned locked dependencies and the beta-only feature selection. Record compiler, linker, exact libc identity, environment, cache provenance, network mode, and build command digest.
- [ ] Produce exactly the six allowlisted archives and one canonical checksums document; validate every archive against its exact contract before any downstream gate.
- [ ] Rebuild independently from the same source archive, preferably on a second qualified Ubuntu 24.04 x86-64/glibc 2.39 builder, and require byte-identical archives or a documented deterministic normalization proof with an approved compare policy.
- [ ] Reject embedded developer paths, build-host identity, timestamps outside the deterministic policy, secrets, credentials, unexpected endpoints, and unallowlisted native/runtime dependencies.

### Installed and offline behavior

- [ ] Unpack/install as an unprivileged user in a clean Ubuntu 24.04 x86-64/glibc 2.39 VM/container without a compiler, source checkout, writable dependency cache, elevated privileges, or undeclared runtime package.
- [ ] Enforce network denial with OS-level no-egress controls and prove all included commands work without DNS or network access; environment flags alone do not establish offline operation.
- [ ] Run positive smoke tests for every exact command and output mode, persistence/restart tests, concurrent mutation tests, restrictive-permission checks, deadline/cancellation tests, malformed-state recovery, and negative tests for every excluded command/capability.
- [ ] Prove the executable reports exactly `0.1.0-beta.1`, the beta profile, prerelease status, target boundary, and administration-only help from the installed bytes.

### Final-byte security and supply chain

- [ ] Scan every packed and unpacked final artifact with pinned approved vulnerability, malware-indicator, secret, endpoint, and developer-path scanners. Resolve all critical/high findings and every unknown or skipped result.
- [ ] Reconcile approved third-party licenses and notices against the exact source and binary contents. Generate SPDX and CycloneDX SBOMs that bind every distributed artifact digest and include native/runtime components.
- [ ] Generate SLSA-compatible provenance binding candidate, source archive, all six artifacts, builder/toolchain/material digests, parameters, network mode, timestamps, and reproducibility result.
- [ ] Sign every artifact, checksums document, SBOM, provenance statement, and assembled beta release evidence with only the reserved beta purposes through the approved isolated signer.

### Independent verification and promotion

- [ ] Assemble one canonical `cigar.beta.release-evidence.v1` document with a closed expected-evidence set, raw attachment digests/sizes, all source/artifact bindings, and no failed/skipped/waived/unknown result.
- [ ] Run an independent offline verifier from a clean environment using only the candidate artifact set, signed evidence, pinned policy/contracts, and approved public trust roots. Require complete-set verification and exact digest agreement.
- [ ] Obtain release-owner/publisher approval after verification. Publish the already-qualified exact bytes under `v0.1.0-beta.1` without rebuilding or mutating metadata.
- [ ] Read every public artifact, checksum, signature, SBOM, provenance, and evidence object back; compare exact digests; prove the release is marked prerelease and did not update `latest`, stable, or GA channels.

## External prerequisites

Local code changes cannot fabricate the following authorities or environments:

- one qualified Ubuntu 24.04 x86-64/glibc 2.39 builder and preferably an independent second builder for reproducibility;
- approved vulnerability/malware data and a security approver for final-byte findings;
- legal/release approval for license and notice reconciliation;
- isolated production beta signer access plus independently distributed trusted public roots;
- release-host/tag/registry publisher authority and protected prerelease-channel configuration.
- a publisher-verified private security-reporting channel named in the authenticated release announcement.

Work may continue around an unavailable prerequisite, but its checkbox remains open and no placeholder, self-attestation, development key, cross-compiled host result, or hand-edited receipt may substitute for it.

## Historical, nonqualifying evidence

Receipts preserved under the external evidence directories named `launch-000-quality-cache-4081a835`, `launch-000-smoke-4081a835`, and `launch-000-wp20-local-4081a835` describe source revision `4081a8355b8e6bd5959dcc44c48b63b9d8dc55ca` (tree `844643f2d0daf36b4813c66fd62c3c65a2fdc952`). They are historical diagnostics only. They are not bound to the beta candidate, do not establish any beta artifact gate, and must never be copied, edited, or rebound as candidate evidence.

## Relationship to v1.0.0

The production target remains CIGAR v1.0.0 under the complete PRD. The beta intentionally excludes most of that product. Beta publication, if achieved, leaves WP19-WP22 and every GA stop-ship requirement unchanged. GA qualification must start from its own exact candidate and use the GA evidence/signature domains; beta artifacts and evidence do not count toward it.
