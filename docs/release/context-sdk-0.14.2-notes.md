# CIGAR 0.14.2 — query performance and atomic ticket consumption

The local Context SDK uses native, Python and TypeScript version `0.14.2`, based
on `0.14.1`. It includes exact-token query optimizations and additive atomic ticket
consumption. Install `hol-cigar==0.14.2` from PyPI or `@hol-org/cigar@0.14.2` from
npm after the signed release and registry publication complete. Availability and
qualification are established by the exact signed release/registry receipts;
see [release readiness](context-sdk-0.14.2-readiness.md) for the preparation record.

## Changes

The ordinary o200k counter initializes only the encoder and regex it uses, with
an immutable bounded-probe vocabulary lookup. It avoids unused decoder and
special-token tables and unnecessary per-thread tokenizer construction. Long
pieces retain heap merging. The pinned vocabulary, regex, merge ordering,
ordinary-token behavior and tokenizer identity remain unchanged.

Python worker imports and pipe handling reduce SDK overhead. Both the packaged
SDK and native adapter profiles remain available; their different process
lifetimes must be reported separately.

The additive broker `consume_ticket` operation checks current authority,
evidence and owner identity and removes a single-use ticket within the same
serialized operation. Consumption does not authorize an external effect.
Unknown outcomes are not automatically retried, and failed freshness checks
do not trigger permissive fallback.

Existing graph selection, exact budget checks, snapshot/delta formats,
authorization, privacy and cache boundaries, work limits, deadlines, persistence
and execution handoff semantics remain in place. The Context ABI and worker
protocol remain v1. Runtime requirements remain Node `>=24.22.1 <25`, Python
`>=3.14 <3.15`, and protobuf `>=6.33.5,<8`.

## Performance evidence and limits

The fixed paired SDK study recorded **55.24% lower median-of-task-medians**
(186.74 ms to 83.59 ms), with identical compared outputs. See
[the paired results](../performance/0.14.2-results.md) for its workload, samples,
compatibility checks and limits.

The retained final-version one-hour swarm run `20261109-010530-8faa41` recorded
**4.73 ms p50, 11.80 ms p95 and 22.44 ms p99** across 8,640 warm persistent
context queries, with 20/20 safe workflows, 58/58 answerable tasks, 2/2 abstentions
and 174/174 authority checks. Its standalone development composite is
**89.2563/100**, with 20% token efficiency; all source and aggregate replays pass.
The evaluator, v6 reader/model/prompt, workload, targets, budgets and schedule
stay fixed. Earlier shared-reader/prompt-v1 results use different conditions and
cannot establish an engine-only gain. See [the RC2 history](../performance/0.14.2-rc.2-results.md).

This measurement belongs to source `59bfc20be83236245d319a14507d43ba2acab2b3`,
wheel SHA-256 `9d0b4af81e4fcf8ae1137af6d356ecdf9ef48ef74931bd871e6be11e4efc30a6`
and worker SHA-256 `9ed9f5b441ba517df82b56039e10493b7f8872b01a703c70b70a1fdd9fb9e67c`.
Subsequent registry-guide corrections require newly qualified archives; retain
these original identities and verify any runtime-byte equivalence explicitly.
This is retained measurement evidence, not a new timing run of a rebuilt archive.
Warm query percentiles exclude startup and model generation and are not a
guaranteed 4–11 ms range. Cold per-query SDK and native-adapter profiles remain
separate. One host and public development cases do not establish an industry
ranking, general performance guarantee or security certification.

## Release requirements

Require two independent matching native/SDK builds, installed and offline
qualification on all seven declared platforms and both supported runtime
cohorts, unchanged-output compatibility, current dependency/security checks,
SBOMs and signed provenance. Preserve exact version/channel/tag binding.
Publishing remains restricted to the existing explicit `v0.14.2` release gates.

The PR remains draft and unmerged. No release tag, GitHub release or registry
publication is performed by the release preparation work.
