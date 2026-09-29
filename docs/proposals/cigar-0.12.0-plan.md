# CIGAR 0.12.0: integrity, lifecycle reliability and measured startup gains

Revised 2026-09-25 using the corrected audit of the published 0.11.0 release.
This supersedes the earlier feature-first plan. Source findings below are static
assessments; the earlier startup experiment remains separately recorded prototype
evidence. No 0.12 runtime implementation or candidate qualification is claimed.

## Release scope

Make the core release deliver five concrete improvements:

1. Lossless admission of canonical semantic data, plus Python/npm decoding parity.
2. Predictable worker shutdown, failure handling and process ownership.
3. Explicit native-package installation contracts and accurate release evidence.
4. A tested protobuf dependency range, compatible public APIs and actionable docs.
5. Faster local Python startup and bounded worker-hashing memory in both SDKs.

Keep batch ingestion, Python async APIs, parallel worker execution and a new wire
protocol outside the mandatory scope. They can follow once correctness and lifecycle
work is qualified. The corrected audit's 95–150-hour estimate describes a hardening
project; it does not cover those Rust/transport features or prolonged hosted
qualification. Estimate implementation after the regression and coverage baselines,
rather than treating the supplied hours as an established delivery commitment.

The release baseline is tag `v0.11.0`, commit
`f00d5e932d4c1a0348d912ce883068f96d3ac6f9`. Development must also carry the
already-tested npm union fix at `927b6772d8788cf3c8f80c8542ade30ee61dadcb`.
That source fix is not in the published npm 0.11.0 package. Preserve the separate
remote/Honey product identity and the frozen `cigar.context.v1` application ABI.

## Findings that change priorities

| Finding | Assessment | Decision |
| --- | --- | --- |
| Python semantic-bundle key collapse | Confirmed by source tracing, high confidence: `_normalize` coerces/NFC-normalizes keys into a dict, and `verify_bundle` reaches this path. | P0 correction and installed-artifact regression proof. The report's global Critical rating is not established. |
| uv 0.11.8 entry-point advisory | The pin is in the affected range. A malicious wheel reaching a relevant CI trust boundary remains a deployment-specific proof gap. | Upgrade promptly; distinguish an affected build tool from evidence that released CIGAR artifacts were compromised. |
| uv 0.12.3 Windows traversal claim | Not applicable to that pin: the upstream affected range is `>=0.12.7,<0.12.18`, on Windows. | Correct the attribution; still standardize on a reviewed patched toolchain. |
| Shutdown and fork behavior | `close()` has uncaught wait/queue/pipe failure paths; the graph has no PID ownership guard. Runtime impact has not been exercised in this review. | P0 lifecycle regression tests, then targeted fixes before adding async/concurrent APIs. |
| Portable wheel behavior | The build hook silently permits a wheel without a worker. The official 0.11 release already excludes universal wheels. | Make source/development opt-in explicit, with documented source-install migration. |
| SBOM drift | Python/npm dependency versions and license identities are literal tuples in `make_sbom`. | Derive evidence from archives and recorded qualification resolutions before widening dependencies. |
| Version drift | A local SDK identity manifest and generators already exist; several release constants remain duplicated. | Extend that authority and its checks; do not add a competing global version system. |
| Coverage/API gaps | Existing tests, Rust coverage and installed consumers are substantial. Python line/branch totals are not established here. | Measure full Python coverage, then add fault/property and public-type compatibility gates. |
| Support/docs drift | `SECURITY.md` references the old beta; released package material still contains candidate/branch wording. | Publish an explicit owner-approved support policy and verified private reporting route. |
| Startup costs | Earlier offline prototypes demonstrated substantial local-import savings and bounded hash allocation. | Retain these low-risk improvements with installed-package compatibility tests. |

Primary advisory sources: [entry-point names, GHSA-4gg8-gxpx-9rph](https://github.com/astral-sh/uv/security/advisories/GHSA-4gg8-gxpx-9rph)
and [Windows extraction, GHSA-2cv4-cqwr-gwf7](https://github.com/astral-sh/uv/security/advisories/GHSA-2cv4-cqwr-gwf7).
Both upstream advisories use Moderate severity. Release priority and application
exploit severity are separate judgments.

This assessment establishes the semantic-bundle integrity defect by source tracing.
Repository-specific exploitability of the affected installer remains unproven, and
the Windows advisory does not apply to the inspected pins. No runtime exploit
validation or full security scan was performed.

## 1. Integrity and SDK correctness

The relevant source is [digest.py](../../sdk/python/src/cigar_sdk/digest.py):
`bundle_id` normalizes before hashing; `verify_bundle` only checks that extensions
are a mapping before computing that identity. Distinct keys can therefore lose an
entry before hashing, including inside nested mappings. The original caller object
can retain entries which were absent from the commitment.

This crosses the integrity boundary of the exposed semantic-bundle helper and its
installed [verification CLI](../../sdk/python/src/cigar_sdk/qualify_bundle.py).
It does not demonstrate a SHA-256 weakness, authorization bypass in a deployed
application, or a defect in Rust `LocalContextGraph.verify`. The latter uses a
separate [snapshot implementation](../../crates/cigar-context/src/snapshot.rs).
TypeScript's canonical encoder already detects duplicate encoded keys.

Implement string-only map admission and reject duplicate keys under the existing
normalization profile before insertion. Apply the rule recursively, without
modifying caller inputs. Retain depth/node limits and stable `ValidationError`
behavior. The invariant is **no original map entry silently disappears**. Do not
require injectivity over raw spellings: NFC intentionally gives equivalent text
spellings one semantic representation.

Review shared encoder callers as part of the same change. In particular,
[models_runtime.py](../../sdk/python/src/cigar_sdk/models_runtime.py) imports
`_deterministic_cbor`, and its `_plain` also coerces mapping keys with `str()`.
A guard placed after an earlier lossy conversion cannot recover the lost entry.
Trace each affected payload path before changing it; do not infer that every
typed remote response is exploitable.

Required proof:

- Installed 0.11 reproduction for non-string and NFC-colliding maps, followed by
  rejection in the fixed artifact. Cover nested maps, both insertion orders and
  collisions even when the two values are equal.
- Property tests for accepted key cardinality, deterministic order, normalization
  equivalence, recursion bounds and input immutability. Use fixed seeds/retained
  examples for reproducibility, plus broader scheduled exploration.
- Frozen valid semantic-bundle, delta and operation-payload fixtures retain their
  IDs/bytes across Python, Node and Rust. Never regenerate expected IDs just to
  make the correction pass.
- The existing [union-response fixtures](../../sdk/fixtures/union-responses-v1.json)
  accept all 11 valid cases and reject all seven invalid cases through installed
  npm/Python consumers. Extend coverage to other union families and integer
  boundaries. An expected rejection of a valid response is not a passing parity test.

A narrowly scoped 0.11.1 patch containing the validated integrity correction and
npm decoder repair is preferable to leaving these issues until the larger minor
release. It needs its own qualification and publication decision; do not replace
the immutable 0.11.0 release.

## 2. Worker lifecycle and fork ownership

Harden [Python context.py](../../sdk/python/src/cigar_sdk/context.py) with an explicit
lifecycle: initializing, open, closing and closed. Ensure partial construction can
be cleaned up and that a primary timeout/transport/protocol error survives ordinary
cleanup failures. Preserve fail-closed mutation uncertainty and the no-retry rule.

Do not copy the audit's cleanup snippet verbatim. A second kill without a later
reap attempt does not prove cleanup; joining a thread with a timeout does not prove
it stopped; closing buffered pipes can block behind in-flight I/O. Define one
bounded shutdown deadline, descriptor ownership, wakeup/reap behavior and how
unresolved cleanup is reported without exposing source text or masking the original
error. Distinguish closed-to-new-work from completed resource cleanup.

Capture the owning PID before creating process/thread resources. Check it before
acquiring any inherited lock, queueing work, writing a pipe or signaling a worker.
An inherited instance must not kill or wait on the parent's worker. Define child-side
descriptor disposal without acquiring inherited buffered-I/O locks. New graphs
created in the child should work; inherited graphs should return a documented
stable error such as `ForkedProcess`.

Use deterministic synchronization and failure injection for:

- Immediate exit, exit during write and malformed replies.
- Concurrent/repeated close; timeout racing with close; queued/in-flight requests.
- Kill/wait/queue/pipe failures with preservation of the primary error.
- No orphan worker, leaked descriptors or live I/O thread after ordinary cleanup.
- POSIX fork while an instance is idle and while another thread owns its lock:
  inherited operations fail promptly and the parent graph remains usable.
- Exact framing boundaries, truncated/missing-newline responses, wrong/duplicate
  IDs and excess nesting. Include real-worker and adversarial-fixture paths.

Extend existing Python and Node lifecycle tests where the contracts overlap.
Keep current language-specific timeout accounting explicit; do not silently change
queue-wait semantics while fixing cleanup.

## 3. Toolchain, dependency range and release evidence

Replace all affected uv pins and corresponding version assertions, including
`fast-ci.yml`, `security.yml`, local SDK workflows and the pinned Linux consumer
container. Keep action commit pins and container image digests. Use a reviewed
release at least 0.12.18; PyPI already reports
[0.12.19](https://pypi.org/project/uv/0.12.19/), so 0.12.18 is a known fixed choice,
not an immutable claim about the latest version.

The other proposed versions were verified in public PyPI metadata on 2026-09-25:
[protobuf 7.36.2](https://pypi.org/project/protobuf/7.36.2/),
[pytest 9.1.1](https://pypi.org/project/pytest/9.1.1/),
[mypy 2.3.1](https://pypi.org/project/mypy/2.3.1/),
[Ruff 0.16.9](https://pypi.org/project/ruff/0.16.9/) and
[Hatchling 1.32.4](https://pypi.org/project/hatchling/1.32.4/).
They are upgrade candidates, not evidence that the current versions are vulnerable.
Separate the urgent installer upgrade from formatter/type-checker churn. Re-run
strict typing, generation and reproducible builds when each relevant tool changes.

A tool-policy check must be role-aware: minimum/current Python and Node matrix
versions intentionally differ, as do supported legacy product cohorts. Reject
unreviewed drift, not all unequal version strings.

Target `protobuf>=6.33.5,<8` only after independent qualification environments
exercise 6.33.5 and 7.36.2 against the same candidate wheel. Record the actual
installed version and dependency consistency; do not overwrite a frozen release
environment or rely on an import-only smoke test. Exercise generated protobuf
messages explicitly as well as CBOR payload families and existing SDK tests.

The checked-in gencode identifies version 6.33.2. Do not blindly regenerate it with
a newer generator while retaining an older minimum runtime. The upstream
[compatibility guarantee](https://protobuf.dev/support/cross-version-runtime-guarantee/)
supports old Python gencode on newer runtimes, but forbids new gencode on an older
runtime. Keep the generator compatible with the advertised lower bound.

Fix [SBOM construction](../../scripts/release/context_distribution_release.py)
before changing dependency metadata:

- Read declared dependency names, constraints and markers from the actual wheel
  METADATA and npm archive package metadata.
- Record exact resolved versions, hashes and license evidence from each qualified
  environment/lock; distinguish external SDK dependencies from bundled native bytes.
- Add package root components and dependency relationships, with traceability to
  artifact and platform identities.
- Validate that resolved versions satisfy artifact constraints. A requirement range
  is not an exact resolved version, and one wheel can legitimately qualify against
  two different protobuf environments.
- Preserve native dependency closure evidence, SBOM validation, advisory lookup and
  audit jobs. Report build-tool inventory separately from the shipped runtime closure.

## 4. Packaging, version authority and user documentation

Make a wheel without a staged native worker an explicit development/source-build
choice, using a documented opt-in such as `CIGAR_ALLOW_PORTABLE_WHEEL=1`.
Document that `pip install --no-binary hol-cigar` and source builds will need that
opt-in plus a matching trusted worker, or explicit native staging. Test both the
new default failure and the intentional portable build. This is a user-visible
build-contract change, not a transparent implementation detail.

The official release remains one npm archive, seven platform wheels and one Python
sdist, with no universal wheel. Preserve `py3-none-PLATFORM`: the native worker is
an executable, not a CPython extension. Keep no install-time worker download.
Do not introduce a second distribution name unless there is an actual supported
SDK-only product requirement.

Extend [existing archive verification](../../scripts/release/context_distribution.py)
for `py.typed`, entry points, metadata, RECORD, correct worker/manifest, package
licenses and native third-party notices. The sdist must retain sources/tests/docs
and exclude native executables. Existing inventory checks already reject an extra
universal wheel; reuse them instead of adding a parallel verifier.

Use [sdk/local-context-release.v1.json](../../sdk/local-context-release.v1.json)
and existing generators as the local SDK authority. Validate its agreement with
Python/npm/core versions, release profiles, constants, tag, manifests, filenames
and current release documentation before expensive builds. Preserve independent
remote/Honey versions, protocol identities and historical fixtures. Do not run a
repository-wide version replacement.

Keep Python `>=3.14,<3.15` for the initial candidate. Add a Python 3.15 informational
lane; advertise support only after final-interpreter artifact qualification on the
advertised platforms. Broader 3.12/3.13 support is no longer a mandatory 0.12 item.
Retain all currently supported Node/platform combinations.

Remove the deprecated license classifier while preserving SPDX Apache-2.0 and
LICENSE/NOTICE, following the [core metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/#classifier-multiple-use).
Add real documentation, changelog and security URLs. Create the Python changelog,
update agent instructions and migration notes, and replace temporary branch links
in release-facing package docs with immutable release links.

Scope documentation lint to current release surfaces. Historical release numbers,
compatibility fixtures and legitimate discussion of candidates must remain allowed.
The local manifest currently records `published: false` even though 0.11 shipped:
separate immutable candidate metadata from registry publication receipts instead of
retrospectively mutating an existing tagged artifact.

Update SECURITY.md with a concrete verified private reporting route and an
owner-approved support window. Do not invent an email address, promise a support
date or claim GitHub private reporting is enabled without checking it.

## 5. Preserve the measured startup improvements

Implement the previously explored lazy Python facade and bounded worker hashing in
both SDKs. Retain all 69 public names, signatures, TypedDict required/optional fields,
enum literals, error codes and public entry points. Cover `dir()`, import-star,
unknown names, concurrent first access and type-checker behavior. Guard the actual
eager modules: the 0.11 baseline already avoids loading `google.protobuf` in the
startup probe, so that assertion alone detects no improvement.

The [offline startup study](../../benches/context-012/README.md) measured:

| Diagnostic on one Mac/Python 3.14.7 | Installed 0.11 copy | Isolated prototype |
| --- | ---: | ---: |
| Local graph API import p50 | 67.27 ms | 11.95 ms |
| Import plus first graph p50 | 123.87 ms | 67.69 ms |
| Constructor after imports p50 | 56.41 ms | 55.65 ms |
| Hash-only maximum traced Python allocation | 7,284,019 bytes | 1,182,314 bytes |

These are 25 timing observations per case and five allocation observations, with
warm filesystem/bytecode caches in fresh Python processes. They establish feasibility,
not a qualified 0.12 comparison. Constructor-only speedup is modest. Keep remote-client
first-use cost visible so deferred imports are not counted as eliminated work.

Streaming hashes must preserve repeated tamper detection, manifest/version/platform
checks and error behavior. Use bounded reusable buffers and test short reads, I/O
errors and descriptor closure. Keep verification caching deferred.

## 6. Tests that determine release success

| Area | Required measurement or gate |
| --- | --- |
| Canonicalization | Ambiguous/non-string maps rejected through public helper and shared encoding paths; property tests preserve admitted key cardinality; all valid frozen IDs/bytes unchanged. |
| SDK parity | Valid npm/Python union fixtures succeed, invalid fixtures fail, wide integers remain exact; run against installed archives. |
| Lifecycle | Primary errors survive cleanup, resources terminate under ordinary failures, cancellation/close races are deterministic, inherited graphs cannot affect the parent worker. |
| API/types | 69 existing Python exports retained with signature and TypedDict-shape snapshots; existing Node exports, CLI JSON schema, stable defaults and error contracts preserved. |
| Python coverage | Establish full statement and branch baselines, including worker tests. Target >=90% statements and >=85% branches overall, with stronger digest/lifecycle goals after baseline review. Explicitly calculate branch/per-module thresholds; a single coverage combined-total flag does not enforce both. |
| Dependency range | Same candidate qualifies with minimum and current protobuf runtimes; include protobuf gencode use, CBOR conformance and dependency consistency. |
| Core compatibility | Existing 1,434-request differential corpus, exact budgets, selection, snapshots, deltas, source refresh and review contracts pass; expected stricter invalid-input rejection is reported separately. |
| Answer usefulness | Preserve supported positive controls and independently reviewed confident-error rejection. Report useful-fact recall, complete-answer yield, answerable refusals and unanswerable abstention separately. |
| Installed platforms | Seven native targets at minimum/current supported runtimes; clean wheel/npm installs, negative controls, source-build opt-in, doctor/demo and network-denied execution pass. |
| Release evidence | Independently built bytes agree; artifact metadata, dependency resolutions, SBOM/licenses and attestations agree; registry download hashes and default installs are verified after authorized publication. |

Coverage must include unimported handwritten modules in its denominator; exclude
generated protobuf implementation code explicitly and exercise it through conformance
tests. Combine pure-Python and real-worker coverage, with source paths normalized
across jobs. Do not claim overall coverage from the audit's suggested pure-Python
subset alone. Use meaningful property/fault cases before chasing percentages;
record any threshold exception by module and reason before feature freeze.

Extend the existing [release tracking](../../benches/release-tracking/README.md)
and [answer-quality](../../benches/answer-quality/README.md) suites. Keep evaluation
offline. In `hiero-test`, compare installed npm and Python adapters through ingest,
compile, prompt/citation resolution, independently reviewed scripted answer, display
or abstention, source replacement, stale-review rejection, delta verification and
continuation. Preserve bad-reviewer and incomplete-answer controls, as well as the
known EVM budget-overflow failure until actually resolved.

A digest correction improves integrity, not semantic truth discovery. Authored
confidence/oracle review fixtures cannot establish model hallucination frequency,
calibration, or universal truth. Any previously recorded independently annotated
model runs remain a separate cohort; do not call a provider for this evaluation.

For performance, retain eight paired process sessions with alternating order and
source/artifact/workload hashes. Add actual constructor/Popen, first compile,
close-idle/error, queue wait/Busy rate, large request/response and parent-plus-worker
RSS measurements. Reuse existing RPC, cache-pressure, prompt, verify and refresh
cohorts. Use allocation tools for allocations; cProfile alone is a CPU/call profiler.

Adopt the established median/RSS policy for comparable workloads: investigate a
repeatable >10% median latency or >20% peak-RSS regression and require an explicit
disposition before promotion. Report p95/max too. Proposed startup targets are >=50%
lower local-import p50 and >=25% lower import-plus-first-graph p50 on controlled
installed comparisons; constructor-only latency has its own denominator. Target
<=2 MiB incremental hashing allocation/buffer use without changing integrity behavior.

## Work sequence and release decisions

1. Freeze new integrity/lifecycle regressions and the compatibility baseline; validate
   the published-package behavior. Carry the npm repair and prepare a narrowly scoped
   0.11.1 option. Do not wait for elective new APIs to qualify a correctness repair.
2. Upgrade the affected installer toolchain. Resolve the existing source-quality,
   dependency-policy, static-security and coverage CI failures; reconcile main with
   release source and enforce a reviewed set of required passing checks.
3. Correct canonicalization and lifecycle/fork behavior, preserving valid IDs and
   supported behavior. Run targeted tests, then the required full SDK/core checks.
4. Refactor artifact/SBOM dependency binding, qualify protobuf bounds, and make the
   portable build contract explicit. Extend the existing local release authority.
5. Implement lazy imports and bounded hashes; finish coverage/API/docs and measured
   startup/full-cycle comparisons. Upgrade other development tools in isolated changes.
6. Freeze the RC commit, independently build/compare, qualify those exact artifacts
   across all advertised targets, produce signed evidence, and present the comparison.
   Retain protected publication approvals and post-registry hash/install verification.

The final comparison must identify released 0.11.0, the minimal correctness-fix
control (if prepared), and the exact 0.12 candidate. Report raw counts/denominators,
valid versus deliberately rejected inputs, p50/p95/RSS, source/worker/SDK hashes,
actual dependencies, failed/skipped tests and unsupported platforms. Do not turn
repetitions across runtimes/platforms into independent answer-quality trials.

Transactional batch ingestion and bounded Python async support remain useful follow-on
designs. Admit them to 0.12 only through a separately frozen scope and qualification
plan after lifecycle correctness; otherwise target the next minor release. Protobuf
IPC, parallel reads, streamed compile output, worker pooling, embedded PyO3, optional
custom-worker environment policies and raw stderr capture remain deferred pending
evidence and a defined compatibility/trust contract.
