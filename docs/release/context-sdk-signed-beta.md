# CIGAR 0.10.0 signed-beta release path

Status: release preparation, not a signed or published beta. The qualified local
Python and TypeScript packages are still `0.10.0rc1` / `0.10.0-rc.1`, with the
`cigar-context` 0.10.0 core. Do not rename RC archives to beta filenames.

This track covers the local context core and SDKs. It does not inherit the old
Linux-only 0.1.0-beta.1 CLI qualification or qualify the Honey daemon, CLI, MCP,
installers, Rust remote SDK, or Go SDK as 0.10.0.

## Release gates, in order

1. Approve the scope, supported platforms, and version identities. Recommended
   SDK prerelease identities are npm `0.10.0-beta.1` and Python `0.10.0b1`.
   Decide the Rust crate publication identity separately. Currently only the
   macOS ARM64 bundled worker is locally qualified; other native targets need
   their own builds and installed-consumer tests. macOS 11 is a deployment tag,
   not an observed test result on macOS 11.
2. Reconcile the independent SDK authority with legacy product-version,
   Honey matrix, and package-contract tooling. Run old release checks on the
   old source when qualifying 0.9.4. Do not loosen old contracts to accept
   differently versioned archives. The legacy version generator now refuses
   to mutate a checkout with the independent SDK authority, preventing a
   partially completed downgrade.
3. Build beta-versioned artifacts from a clean committed source snapshot.
   `prepare_context_sdk_rc.py` now requires a clean checkout by default and
   captures source digests before the build, checking them again afterwards.
   `--allow-dirty` is explicitly diagnostic. Qualification and retention check
   the same binding. These checks are not a hermetic-build attestation.
4. Run the core, SDK, installed-wheel/sdist/npm, previous-version compatibility,
   transport-failure, generated API, and release integration tests. Retain
   actual logs and recomputable comparisons. The RC's 516 consumer comparisons
   are regression evidence, not an LLM answer-quality measurement.
5. Produce two independent empty-cache native builds with locked tools,
   normalized paths and timestamps, matching unsigned payloads, SPDX and
   CycloneDX SBOMs, dependency/native-library license closure, provenance,
   current security qualification, and OS-enforced no-egress results. Packing
   twice from one compiled worker does not satisfy independent reproducibility.
6. Review the immutable handoff and independently distribute its expected
   manifest digest, approved public trust policy and policy digest. Use the
   existing isolated Ed25519 signing process. Private keys do not belong in
   this checkout, the handoff, a build job, or the conversation.
7. Verify every detached signature and exact payload inventory offline. Obtain
   explicit publication authorization, then publish through protected release
   jobs and verify registry downloads, prerelease tags and installed consumers.
   Signed Git commits/tags and artifact signatures are separate properties.

## Candidate signing handoff

`scripts/release/context_sdk_handoff.py` is a candidate-integrity tool. It does
not sign, publish, fetch keys, access registry credentials, execute candidate
code, or declare release readiness. Its `release_ready: false` result cannot
be waived by inserting booleans into a candidate report. The release gates
above still require a separately qualified release orchestration path.

The `stage` command accepts a finalized RC artifact directory and its retained
evidence directory, plus an explicit expected prerelease identity. Its
`--evidence-dir` (or `CIGAR_EVIDENCE_DIR`) must be a new absolute owner-only POSIX
directory outside the repository. It copies and verifies the exact four
archives, report and retained evidence, recomputes oracle comparisons and
checks log/advisory consistency, then writes canonical `checksums.json` and
`release-manifest.json`. Failed staging is incomplete evidence and must not be
signed; use a new directory for the next attempt.

Seven detached envelopes are required:

| Payload | Signature purpose |
| --- | --- |
| Each of the four archives | `cigar-context-sdk-artifact` |
| `qualification.json` | `cigar-context-sdk-evidence` |
| `checksums.json` | `cigar-context-sdk-checksums` |
| `release-manifest.json` | `cigar-context-sdk-manifest` |

The manifest/checksums also bind every retained log by path, size and SHA-256.
Place each envelope at `signatures/<payload-name>.sig.json`. Use the existing
`signatures.py sign` interface in the approved external signer; its reviewed
OpenSSL binary must be bound by SHA-256. This workflow deliberately has no
private-key argument or automatic signer selection.

`verify` requires all of these independently chosen inputs:

- `--handoff`: the transferred, signed handoff directory.
- `--expected-release`: exact SDK SemVer prerelease, not a floating channel.
- `--manifest-sha256`: the separately reviewed manifest digest.
- `--trust-policy` and `--trust-policy-sha256`: an external public policy using
  `cigar.release-trust-policy.v1`; public key files have distinct basenames in
  the policy's directory. A policy supplied inside the handoff is rejected.
- `--openssl` and `--openssl-sha256`: approved absolute executable and digest.
- `--verification-time`: the verifier's current UTC Unix time, not a timestamp
  chosen by the candidate to evade expiration or revocation.

Verification snapshots inputs into a private workspace. It rejects changed or
missing artifacts, unexpected files, symlinks/hardlinks, invalid inventory
bounds, manifest/policy substitution, missing signatures, incorrect purposes or
principals, inactive/revoked keys, expiration, and RC-to-beta relabeling. Its
success means the exact reviewed candidate is authenticated under the supplied
trust policy. It does not establish that the external policy was organizationally
approved, that a test log is truthful, or that remaining release gates passed.

## CI and diagnostics

`context-sdk-rc.yml` gates its macOS build on Linux signing-composition and
source-binding tests, including actual Ed25519 signatures with disposable test
keys. Those tests are not production signatures. The workflow has read-only
repository permissions, no registry token, no production signing identity, and
no publish command. Hosted execution remains a separate verification step.

The local prepare/qualify/finalize commands reject the release evidence selector
because their development output directories are not qualifying
`EvidenceWorkspace` producers. Use their documented output arguments. They
also reject optimized Python (`-O`) so assertions cannot silently disable their
qualification checks.

See [reproducibility and signing](reproducibility-signing.md) for the full
signing/trust policy, and [the SDK RC report](../../reports/cigar-0.10.0-sdk-rc.md)
for the retained functionality and compatibility measurements.
