# CIGAR 0.14.2 release readiness

Status on 2026-11-08: **unpublished candidate; release blocked**.
PR [#42](https://github.com/hashgraph-online/hol-cigar/pull/42) remains draft
and unmerged on `codex/cigar-0.14.2-speed`. Release preparation aligns the core,
Python and npm package identities to `0.14.2`, with `published: false`, without
changing the benchmark or granting publication permission.

## Published versions

Live registry reads on 2026-11-08 found:

| Channel | Published state |
| --- | --- |
| [GitHub](https://github.com/hashgraph-online/hol-cigar/releases/tag/v0.14.1) | Latest release `v0.14.1` |
| [PyPI](https://pypi.org/pypi/hol-cigar/json) | Latest `0.14.1`; neither `0.14.2` nor RC2 exists |
| [npm](https://registry.npmjs.org/%40hol-org%2Fcigar) | `latest` is `0.14.0`; neither `0.14.1`, `0.14.2` nor RC2 exists |

A GitHub release does not prove npm publication. The final release must verify
both registries against the authenticated release bytes and expected dist-tag.

## What the timing claim means

The sealed RC2 hour `20261108-005709-18540c` has 8,640 warm persistent query
samples: p50 **4.707916989 ms**, p95 **11.442875024 ms**, p99 **20.467208 ms**,
maximum **36.903667 ms**. Initial owner startup was **764.02 ms**, separately
recorded. Query time excludes local model generation.

The fresh cold per-query SDK profile `20261108-063531-f48ef7` instead recorded
26.7674 ms p50 / 134.893 ms p95 at the primary 2,048-token budget. These profiles
have different process lifetimes. Never replace the cold measurements with the
warm percentiles or advertise 4–11 ms as a universal end-to-end range.

The retained RC2 worker SHA-256 is
`4a8e4c2b0ea70d151a609b3c1ffe7645865b1ec030b2deabc242d0ead8e318f6`.
Its latest swarm result SHA-256 is
`84988a91fce0e1747b335dd776ff95f9900b41a3dd55435153e0b9a29f0e3694`.
The matched aggregate is **89.2849349274**, with Safe Workflow Completion
**100%** and token efficiency weighted at **20%**. NetworkX and rustworkx score
78.0622 and 77.1235 in that same isolated comparison.

Earlier shared-model/prompt-v1 and newer isolated-model/prompt-v6 composite
scores are different cohorts. Compare engine revisions only under one frozen
workload, prompt, reader, adapters, model, hardware/load, budgets and scoring
policy. Preserve both historic profiles and their artifacts.

## Gates and next actions

| Gate | Evidence / required action |
| --- | --- |
| Stable source identity | Preparation aligns the core manifest, root Cargo lock, Python manifest/lock/runtime metadata, Node manifest/runtime metadata, worker fixtures and release contract to `0.14.2`. Run `python3 -B scripts/release/check_context_version.py --expected 0.14.2`. |
| Package tooling failures | Initial distribution build failed in SDK generator RC validation; stable release tests also rejected the RC identity. Preparation uses the already supported stable identity, fixes the two Ruff formatting errors, normalizes the Honey test's Python version comparison and repairs the policy fixture's missing Python lock. Its negative check still rejects lock version drift. Re-run exact CI at the new commit. |
| Native workers | At prior head `f01561cc655e6c660ab7e3db2723aa50507ea229`, all 14 native jobs (seven platforms, two builders) passed in [run 42425989736](https://github.com/hashgraph-online/hol-cigar/actions/runs/42425989736). That does not qualify the newly versioned candidate or prove matching builds/installed consumers. |
| Final archive qualification | Previous packaging failed before archive comparison and the 14 installed runtime/platform combinations. Require successful `context-sdk-release` branch CI on the exact candidate head; no skipped qualification counts as a pass. |
| Python coverage | Candidate `fa9c619a` passed 539 functional tests in hosted packaging but `context.py` statement coverage was 93.0851%, below the unchanged 95% floor. Tests now exercise lazy runtime exports/type identities and the real stalled worker through the portable transport. Local source validation passes 541 tests plus 39 subtests, and the unchanged coverage gate passes with 95.2128% statements / 95.4545% branches for `context.py`. Hosted confirmation is still required. |
| Trusted xtask bootstrap | `fast-ci` source quality and security coverage fail because no protected command-specific tool authority is configured. The operator must provide independently reviewed executable and authority digests as documented in [xtask's bootstrap contract](../../crates/xtask/README.md#hosted-macos-ci-bootstrap-contract). Do not self-approve generated digests, remove the guard or mark diagnostic receipts as release evidence. |
| Repository dependency security | Initial live Dependabot read found 36 open alerts, including four critical Wasmtime alerts. The root Cargo deny job also flags Rustls/WebPKI, parser and compression dependencies; Go audit flags the pinned Go standard library and `x/net`. Update and qualify affected dependency/tool chains; do not suppress advisories or claim a green repository audit from SDK-only evidence. |
| SDK pnpm auditor | CI's pinned pnpm 11 auditor distribution digest does not match the hydrated tool. Independently verify official distribution provenance and the full inventory before changing a trusted digest. The original failure remains a blocker. |
| Final performance confirmation | Run the unchanged isolated benchmark against a descriptor bound to the final candidate archives. Retain the RC2 result and all peers. The RC2 result alone cannot certify the final-version package timing. |
| Publication and support | Keep PR draft/unmerged. After the above gates pass, review the exact candidate commit, hashes, SBOMs, provenance and notes before any separately authorized merge, `v0.14.2` tag or publication. Read back GitHub, PyPI and npm bytes and npm's `latest` tag. |

The recorded macOS RC2 native dependency inventory contains 59 packages and
excludes Wasmtime, Rustls, WebPKI, zstd and pulldown-cmark. This narrows the known
alert exposure for that artifact only; it does not close repository alerts,
audit other platforms or substitute for scanning final release dependencies.

At candidate `fa9c619ae32273064cf31917e2493081514b64f1`, clean packaged macOS
native validation passed 154 tests; installed Python passed 539 tests plus 39
subtests and installed Node passed 168 tests with zero skips. The 172-case RC2
comparison preserved 111 exports and verified all 155 successful snapshot/delta
pairs in both directions. A 61-query OSV lookup of the recorded macOS native
inventory and qualified Python/npm runtime dependencies found no listed
advisories. This does not resolve the separate repository security failures.
The added coverage tests change no shipping runtime code or benchmark inputs.

## Reproduction and evidence

Use Rust/Cargo `1.92.0`, Node `24.22.1`, the committed pnpm `10.34.5` toolchain,
Python 3.14 and the checked Python tooling lock. SDK CI commands are in
`context-distribution.yml`; production publication remains restricted to the
exact stable tag and its signed source digest.

For the clean committed macOS ARM64 candidate, the existing builder writes
create-new native, package, test and dependency evidence:

```sh
python3 -B scripts/release/build_context_worker.py \
  --platform darwin-arm64 \
  --cargo /absolute/path/to/rust-1.92.0/bin/cargo \
  --output /absolute/new/evidence/native \
  --target-dir /absolute/new/evidence/target
```

Local checks and one platform remain development evidence. The hosted matrix,
independent-build comparison, dependency gates, installed/offline consumers and
signed provenance are mandatory before a release claim.

An exploratory discovery of all release-tool tests ran 495 tests and failed
(5 failures, 57 errors, 31 skips). It mixed historical Honey publication and
reviewed-inventory contracts with the local SDK track and initially lacked the
required Cargo/Go/OpenSSL environment. Its full failure log is retained; no
repository-wide test pass is claimed. Local SDK source checks and their
corrected policy fixture are recorded independently and do not waive those gaps.

The local working evidence directory for this pass is
`../releases/cigar-0.14.2-readiness-20261108/` relative to this checkout. It retains
the initial GitHub failures, live registry readback, source checks and new build
results separately from all existing benchmark evidence. Do not check in package
binaries or replace sealed benchmark results with this release work.
