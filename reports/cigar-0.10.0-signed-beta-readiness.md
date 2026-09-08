# CIGAR 0.10.0 signed-beta readiness

2026-09-07 (America/Los_Angeles). Outcome: committed release groundwork and a
new clean-source, locally qualified SDK RC. **Not yet a signed or publishable
beta.** The full release suite still has 30 failures and 8 setup errors, and no
organizational signing identity, final beta scope, or publication authorization
has been selected. No production private key was accessed; no push, tag,
registry publication or hosted workflow execution was performed.

## Commits and changes

- `c6a8afdf83fa9813448bf2b78174f7bbb228eccf`: commits the previously evaluated
  0.10.0 context core, optimizations, Python/TypeScript RCs and historical reports.
- `6019e9e2bc87d44609d839b2e6a30daddc8e16cc`: adds clean-source build binding,
  isolated signing handoffs, offline verification, 28 new tests, CI gates,
  complete locked license inventory, and the release plan.

The new build records 118 tracked input hashes before execution, checks them
and the commit again after execution, and derives `SOURCE_DATE_EPOCH` from that
commit. Dirty builds require an explicit diagnostic option. Qualification and
retention reject source drift; optimized Python cannot disable their assertions.
The legacy all-product version generator now stops before any writes when the
independent context SDK track is active, preventing a partial SDK downgrade.

The handoff tool freezes exact archives and evidence, validates checks and
recomputes retained oracle comparisons. It requires seven purpose-scoped
Ed25519 signatures, an externally supplied public trust policy, reviewed policy
and manifest digests, and a digest-pinned OpenSSL executable. Verification uses
private snapshots, rejects substitutions, missing/extra files, unsafe links,
incorrect scope/principal, inactive/revoked keys, expiry and relabeling, and
never executes a candidate. Even valid signatures do not mark a release ready.

The license inventory now covers 654 locked dependencies, up from 651:
`bstr@1.13.1`, `fancy-regex@0.17.0`, and `tiktoken-rs@0.12.0` were the only
additions. No existing entries changed; all pass the repository's license
policy. Release-tool lint and formatting now pass for all 111 Python files.
Fourteen incidental formatting-only files were also checked for identical
Python ASTs. This is not a legal opinion or a source security audit.

## Validation

| Check | Result |
| --- | --- |
| Focused signing/source/evidence/license/SBOM suite | 47 passed, 34 passing subtests |
| New tests within that suite | 20 signing-composition + 8 source/entrypoint tests |
| Rust core with BPE | 35 tests + 1 doctest passed |
| Rust core without optional features | 27 tests + 1 doctest passed |
| Python source, installed wheel, installed sdist | 36 passed in each run |
| TypeScript source and installed npm package | 37 passed in each run |
| Clean installed 0.9.4 SDK comparison | Python 28 passed; TypeScript 29 passed |
| Cross-language regression corpus | 172 cases × 3 consumers = 516 matching results |
| Successful snapshots / expected errors | 465 full-snapshot matches / 51 matching errors |
| Backward-compatible exported API | All 43 Python and 104 TypeScript legacy exports retained |
| Rendered context | Identical across the three installed consumers |
| Packaging repeatability | Three SDK archives byte-identical when packed twice from one staging tree |
| Additional checks | Clippy, Rust formatting, Python lint/types, TS types, generated SDKs, operation parity, strict Twine and actionlint passed |
| Advisory lookup | 36 dependency versions queried; zero returned advisories at 2026-09-08 05:07 UTC |

Signing-composition tests generate disposable keys and sign synthetic payloads;
they are not production signatures of the actual RC. The focused suite ran
before the final timestamp-binding addition; its eight source/entrypoint tests
were rerun afterwards, and the final whole-suite run includes all 28 new tests
at the committed implementation. JUnit counts include subtests; they must not
be confused with the test-function counts above.

The native worker is byte-identical to the earlier RC
(`3c5d5960bc78dae1a059a86cb0a2df219eb4e818d554068a17c604f67339cd1b`).
Archive-member comparison found no added or removed files. Only Cargo VCS
metadata, bundled native source-digest manifests, and the wheel's `RECORD`
changed; the sdist's file contents are identical. Archive timestamps also
changed. No context algorithm, SDK runtime API, token-reduction claim or new
performance claim is introduced by this release-engineering pass.

## Full release suite: blockers remain

| Checkout/run | Passed | Failed | Setup errors | Skipped | Passing subtests |
| --- | ---: | ---: | ---: | ---: | ---: |
| Initial 0.10.0 release-tool run | 373 | 35 | 8 | 31 | 309 |
| Original 0.9.4 comparison (`107880a5`) | 398 | 10 | 8 | 31 | 312 |
| Final 0.10.0 implementation (`6019e9e2`) | 406 | 30 | 8 | 31 | 334 |

The final run contains 475 test functions versus 447 before this pass. Adding
the pinned protoc to PATH removed two environment failures; repairing the
license closure and common entrypoint selector removed three actual test
failures. Existing skipped tests were not converted to passes or newly skipped.

Nine failures recur on both the old and new checkout: the frozen 0.9.2 input
contract and executable ownership/permission restrictions in old beta/plugin
builders. The old checkout additionally lacks an installed TypeScript build
dependency tree. The 21 current-only failures comprise seven TypeScript builder
inventory tests, ten Honey profile tests, and four product-version tests. They
are release-domain integration gaps, not evidence that the new SDK exports or
context results regressed.

All eight current Python builder setup errors reject the 0.10.0 SDK identity
under the older 0.9.4 Honey contract. The corresponding old tests instead stop
at an interpreter-ownership restriction. Thus their equal error counts do
**not** establish an unchanged cause. No executable permission checks or frozen
package contracts were weakened to manufacture a green result.

The old checkout remains clean. Its missing dependencies and tool ownership
restrictions limit the whole-suite comparison; the separately installed SDK
baseline tests did pass. The full current release suite is still a blocker.

## Artifacts and evidence

The new local archives are in
[`artifacts/packages/context-sdk-0.10.0-rc.1-clean-6019e9e2`](../artifacts/packages/context-sdk-0.10.0-rc.1-clean-6019e9e2/).
They remain Python `0.10.0rc1` and npm `0.10.0-rc.1`; the earlier RC directory
was preserved. These local binary artifacts are Git-ignored, not committed.

The [retained clean-run report](evidence/context-sdk-010-clean/release.json)
binds the four archive hashes, 83 compressed logs/evidence records, final
117-file diagnostic inventory, and the earlier 118-file pre/post-build binding.
The inventories serve different purposes; the pre/post-build binding includes
shared release helpers. The build and tests used macOS 26.6.1 ARM64, Rust 1.92.0,
Python 3.14.7, and Node 24.19.0/24.10.0. No native Linux/Windows or minimum macOS
11 execution is claimed. Python sdist local context still requires an explicit
worker path.

The unsigned signing handoff is at
`/private/tmp/cigar-010-signed-beta.3Ms2mh/clean-signing-handoff` and can be
regenerated from the retained report and local archives. Its reviewed
[manifest](evidence/context-sdk-010-release-gates/release-manifest.json) is
SHA-256 `f1b3f0f777e73ca6646eae2162e21a4c092e23578746bc7681c21791c58b1f59`.
It binds 89 payload files and requires seven detached signatures. None have
been produced for these real artifacts. Test-run XML and hashes are retained
in the [validation inventory](evidence/context-sdk-010-release-gates/validation.json).

The RC was built from clean implementation commit `6019e9e2`; the subsequent
report/evidence-only commit does not retroactively change its source identity.
Use the build commit when rerunning qualification of this exact candidate.

## Next release decision

Follow the [signed-beta release plan](../docs/release/context-sdk-signed-beta.md).
First decide whether the beta covers the context core/SDKs or the full runtime,
then reconcile the relevant version authorities and platform contracts. Build
actual beta-versioned archives; do not rename these RCs. Still required are
independent empty-cache reproducibility/provenance, release SBOMs and native
closure, OS-enforced offline evidence, release/security qualification, an
approved external signing policy/identity, and explicit publication authority.
The native build here reused the existing Cargo cache: this is clean-source
qualification, **not** independent-build reproducibility.
