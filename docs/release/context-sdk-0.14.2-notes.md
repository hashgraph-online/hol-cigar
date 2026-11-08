# CIGAR 0.14.2 — unpublished release candidate

The candidate on `codex/cigar-0.14.2-speed` prepares native, Python and TypeScript
version `0.14.2`, based on main/release `0.14.1`. It includes RC2's query
optimizations and additive atomic ticket consumption. Stable package identities
are preparation for qualification; this document does not announce publication.
See [release readiness](context-sdk-0.14.2-readiness.md) for outstanding gates.

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

The latest sealed RC2 one-hour swarm run `20261108-005709-18540c` recorded
**4.71 ms p50, 11.44 ms p95 and 20.47 ms p99** across 8,640 warm persistent
context queries. It completed 20/20 safe workflows and 58/58 answerable model
tasks, with 2/2 correct abstentions. Startup and model generation are separate
metrics. These percentiles are not a guaranteed 4–11 ms response range.

On the matched isolated three-library development benchmark, the RC2 score is
**89.2849/100**, with token efficiency weighted at 20%. That score is specific to
the fixed v6 isolated-model profile. Earlier shared-model/prompt-v1 runs have
different conditions; their score changes cannot establish an engine-only gain.
See [the current RC2 evidence](../performance/0.14.2-rc.2-results.md).

The above swarm timings and score belong to the retained RC2 worker with SHA-256
`4a8e4c2b0ea70d151a609b3c1ffe7645865b1ec030b2deabc242d0ead8e318f6`.
They are not a fresh measurement of the final-version `0.14.2` archives.
Qualification and performance confirmation must bind the actual release bytes.

## Release requirements

Require two independent matching native/SDK builds, installed and offline
qualification on all seven declared platforms and both supported runtime
cohorts, unchanged-output compatibility, current dependency/security checks,
SBOMs and signed provenance. Preserve exact version/channel/tag binding.
Publishing remains restricted to the existing explicit `v0.14.2` release gates.

The PR remains draft and unmerged. No release tag, GitHub release or registry
publication is performed by the release preparation work.
