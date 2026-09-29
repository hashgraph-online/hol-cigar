# Historical Hiero evidence audit

Status: offline data reanalysis completed on September 27, 2026. This validates
the v0.14 evaluation producer against a retained v0.11/v0.12 development study.
It is not a rerun, a comparison of published distributions, or evidence of v0.14
task-quality improvement. No campaign, worker, model or target was executed.

## What the archive establishes

The retained `e0120` study contains five workflows, five paired campaigns per
workflow and three requested iterations per campaign. All 50 attempts and 130
iteration receipts were retained. Both treatments completed 20 of 25 campaigns;
the EVM workflow stopped at its first iteration in every attempt because its
context could not fit the prompt budget without losing evidence.

| Workflow | v0.11 completed campaigns | v0.12 completed campaigns | Retained iterations per version | Independent terminal outcome |
| --- | ---: | ---: | ---: | --- |
| Consensus node | 5/5 | 5/5 | 15/15 | Unavailable |
| Blocknode TSS | 5/5 | 5/5 | 15/15 | Unavailable |
| Solo | 5/5 | 5/5 | 15/15 | Unavailable |
| JSON-RPC | 5/5 | 5/5 | 15/15 | Unavailable |
| EVM transaction liveness | 0/5 | 0/5 | 5/15 | Unavailable |

The four completed workflow strata declare context quality `passed`. That is
an application check, not an independently verified correct task outcome. The
consensus/TSS records separately report synthetic self-tests and zero target
executions. JSON-RPC explicitly uses a bounded fixture and its own source
declares AI unused. Other campaigns use mock AI. The outer historical batch
receipt calls all of them `mock`; the new task definitions preserve the actual
distinction rather than inventing a JSON-RPC provider invocation.

No independent terminal oracle/readback was retained for these attempts. Both
terminal metrics are therefore unavailable for both versions. Missing EVM
context fields also remain unavailable; the importer does not drop them to
report 100% context quality. The five workflows share three target repositories,
so the analysis has three task clusters, not 50 independent tasks. No confidence
interval is reported. Campaign wall times remain descriptive, including failed
processes; they do not establish a performance benefit.

## Bindings and reproducibility

The staging step rechecked all 308 original Hiero source files against the
historical source manifest. It retained their matching bytes, frozen corpus
indexes, original source input, campaign commands/receipts, controller logs,
offline profile/preflight, compiler executables and build declarations. The
source commits below are original build declarations. The executables match
the hashes recorded in each campaign; this is not a new publisher attestation.

| Identity | Value |
| --- | --- |
| Historical v0.11 source | `f00d5e932d4c1a0348d912ce883068f96d3ac6f9` |
| Historical v0.12 candidate source | `0ed2643f1ebc689db04974c713036f5f4de3d52c` |
| v0.11 Hiero compiler SHA-256 | `501bf0a59d66bc0a0088d27a5f0bf2accddf53b12ec3869070f855839ed31bff` |
| v0.12 Hiero compiler SHA-256 | `ce4847df4fcb0c0a2147556477cc28eb58e08a6ce384b3c9cf31102884ae77ee` |
| New evidence manifest SHA-256 | `e0ba1f1e78d195af537cf4eff1cf8499de58180072fdcf6156331b5bc3d2cfcd` |
| Recomputed result SHA-256 | `f9838ea5e5de4ef7e09b4dd3f46f0861c8af927bbdd0ed487ac67b96b9e7da6e` |
| Metric observations SHA-256 | `052a734763ab56d881af9ccd675283e7373c079eee7890ea8aa2892eb83aef5f` |

Private retained evidence lives under
`CIGAR/releases/cigar-0.14.0-development/hiero-e0120-contract-01`. Its `raw/`
directory contains all 189 supplied artifacts and the original input index.
Re-importing those originals produces identical manifest and result bytes:
500 metric observations from 50 campaigns, across five workflow tasks.
The separate re-import is retained as `hiero-e0120-reimport-01`.

The staging script is retained in the metadata archive. Its first attempt stopped
because the historical adapter was installed as `src/main.rs`, rather than its
template filename; partial staging remains in `hiero-e0120-input-01`. The corrected
mapping verified the original adapter hash and completed in
`hiero-e0120-input-02`. No campaign rerun or runtime repair occurred. The old plan
did not explicitly bind the offline npm-audit snapshot's own digest; its captured
bytes are retained with that limitation, not relabelled as prospectively bound.

## New producer guarantees and remaining work

The [Hiero producer](../../benches/context-evaluation/HIERO.md) binds original
process/iteration receipts to exact task, compiler and producer identities.
Optional terminal results are recomputed from typed JSON fields and an explicit
oracle, with execution/task/reader hashes. An absent, partial or synthetic
readback cannot count as a task success. Producer execution and reader
independence still require review; hashes do not prove either one.

All 47 common-evaluation tests and seven answer-metric tests pass. Thirteen new
Hiero tests cover wrong identities, missing/reused records, failed observations,
partial/synthetic readbacks, exact field types, absent terminal oracles and
re-import stability. Lint and formatting pass. Logs are retained in
`hiero-import-tests-01.log`; the existing three-OS CI job discovers these tests.

For the prospective v0.14 comparison, register independent task acceptance
conditions and budgets first, capture a target-state reader, retain its exact
output for every attempt, and compare exact frozen artifacts. The historical
audit improves evidence accounting; it does not close E2, qualify v0.14, or
measure confident model hallucinations.
