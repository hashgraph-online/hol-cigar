# CIGAR 0.11.0 distribution execution

Objective: execute the five standalone-adoption changes and prepare 0.11.0 for
distribution through npm and PyPI. This includes qualified default installation,
platform workers, standalone-first documentation, a complete packaged workflow,
and actionable diagnostics/agent instructions. The earlier macOS-only artifact is
historical evidence; changed SDK inputs require new artifacts and qualification.

## Delivery requirements

| Requirement | Implementation | Required evidence |
|---|---|---|
| Default installation | `@hol-org/cigar` 0.11.0 / `hol-cigar` 0.11.0; npm `latest`; immutable reviewed artifacts | Registry identity/version/tag and downloaded archive hashes after publication; artifacts and publishing workflow before publication |
| Native platforms | macOS ARM64/x64; Linux glibc x64/ARM64; Linux musl x64/ARM64; Windows x64 | Native builds, platform wheel tags, package worker manifests, complete installed-consumer checks on each target |
| Standalone discovery | npm/PyPI READMEs, repository, SDK and site entry pages | Executed examples, correct package/import names, working public links; no account/service step |
| Complete workflow | Both languages: ingest/update, dependencies, authorized compile, citations, trusted review, source refresh/recheck, cache reuse, close | Packaged examples run from empty consumers, including missing/unsupported/stale-review controls |
| Diagnostics | Capability APIs and `cigar-context doctor` commands in both packages | Correct version/platform detection, missing/tampered-worker failures, real synthetic compile, actionable content-free output |
| Agent use | Packaged human/agent instructions and an explicit source ingestion recipe | Archive membership and examples that use the local API without service configuration |
| Compatibility | Existing remote exports and ABI retained; current Node 24 and Python 3.14 ranges explicit | Existing SDK tests, baseline export checks and local entrypoint tests |
| Release integrity | Complete platform set, exact source/worker/artifact binding, independent builds, licenses/SBOMs and signed provenance | Negative verifier tests, current checks, complete hosted build/install results; final manifest and checksums |

## Packaging decisions

Use one npm archive containing the platform workers. This avoids optional-dependency
installation switches and extra npm package publication. Load exactly the current
platform's versioned, checksum-verified worker. Python wheels each contain one
worker and carry its exact platform tag. Both keep the explicit trusted-worker
override for unsupported environments and source installations.

Preserve the Rust context core's semantics. Keep the existing remote clients
available through their existing imports. Diagnostics do not infer credentials,
connect to a service, ingest caller files or download executables. Examples explicitly
label fixture reviewers; the package does not claim to supply a semantic judge.

Runtime support remains Node.js >=24.10.0 <25 (ESM) and Python >=3.14 <3.15 for this
release. Test the declared minimum and current patch runtimes; do not broaden ranges
without testing. Browser/edge execution is outside the native Node/Python product.

## Execution sequence

1. Implement common platform metadata and worker resolution, capability diagnostics,
   CLI entrypoints and meaningful failure tests in both SDKs.
2. Add complete packaged workflows and standalone/agent documentation; run local
   source and installed-package checks.
3. Extend worker building, wheel/npm assembly, artifact verification and hosted CI
   to every listed platform, retaining source binding and independent-build gates.
4. Build new artifacts from a clean revision, run installed-consumer qualification
   on every advertised target and resolve failures. Preserve exact logs/hashes.
5. Prepare and verify npm/PyPI publication from those bytes. Complete registry
   publication/default-tag readback where authorization and registry proof-of-presence
   controls permit it. Report any external approval still required separately.

Do not declare completion from source tests, workflow YAML, a partial platform matrix,
or the old macOS artifact. The final report must audit every row above against actual
artifacts and execution evidence. Evaluation remains offline; no model provider calls.
