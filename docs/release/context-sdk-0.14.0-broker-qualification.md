# v0.14 broker source qualification

Status: local short fault qualification and corrected repeated load study passed.
The Windows source/runtime storage checks now pass in the
[hosted source run](https://github.com/hashgraph-online/hol-cigar/actions/runs/36332889565).
The 24-hour soak, Windows sustained load checks, installed
artifact matrix and independent task/answer efficacy remain pending. This is not
a v0.14 release receipt or a claim of version-wide nonregression.

## Repeated load results

All **288 fresh-process cells** passed: eight cohorts for each combination of
1/5/12 clients, Python/Node/mixed processes, memory/SQLite, and one/four in-flight
compile/forget cycles per client. The retained-data verifier recomputed all 36
groups, checked input/cell hashes and confirmed identical rendering across
runtimes/storage/concurrency for each fixture. **2,379,985 cycles** completed with
no unexpected API failure, wrong-context result, scope leak or cleanup failure.

Each three-second load window uses 256 readable documents per client and three
required evidence blocks. This is a warm scoped broker workload, not general
retrieval or a model-generated task. Source writes happen outside timed windows.
The total below includes the host, worker and every independent client process.
RSS is the maximum observed by 50 ms sampling in each cohort, then the median of
those eight values; it is neither PSS nor an exact allocation peak.

| Mixed clients / storage | In flight per client | Compile latency, median ms | Total cycles/s, median | Sampled total RSS, MiB | Worker RSS, MiB | Worst client p99, ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 / memory | 1 | 0.835 | 3,021 | 356.0 | 56.3 | 1.79 |
| 5 / memory | 4 | 2.956 | 3,403 | 357.3 | 56.7 | 5.11 |
| 5 / SQLite | 1 | 0.837 | 3,027 | 358.8 | 58.3 | 2.23 |
| 5 / SQLite | 4 | 2.958 | 3,382 | 359.3 | 58.6 | 5.27 |
| 12 / memory | 1 | 1.974 | 3,048 | 725.1 | 57.8 | 4.93 |
| 12 / memory | 4 | 7.437 | 3,191 | 728.6 | 58.7 | 39.47 |
| 12 / SQLite | 1 | 1.893 | 3,197 | 728.2 | 60.5 | 4.56 |
| 12 / SQLite | 4 | 7.350 | 3,227 | 731.4 | 61.5 | 38.16 |

Compile latency is the median of cohort-level, equally weighted client medians.
The slowest individual client's p99 across the complete matrix was **48.254 ms**
(12 Node clients, memory, four in flight); worst p95 was **12.388 ms**. The smallest
same-runtime minimum/maximum completion ratio was **0.9786**, above the registered
0.80 gate. Every client completed at least **235 cycles/s**, above the five/s gate.
The complete per-runtime results remain in the retained report; one-client mixed
cells duplicate the Python control by design.

Increasing in-flight work is a tradeoff, not a version improvement. At 12 mixed
clients, the paired mean throughput change is only **+2.02%** in memory and
**+1.56%** with SQLite, while compile latency rises substantially. The paired
throughput differences have descriptive 95% bootstrap intervals of +5.1 to
+145.3 cycles/s and +15.3 to +87.9 cycles/s respectively, resampling eight whole
process cohorts. For this workload, start with one in-flight operation per agent
and increase only if application measurements justify the extra queueing. The
12-Python SQLite throughput interval includes zero; more concurrency is not a
universal speedup. These are same-candidate comparisons, not v0.12/v0.14 Q1 results.

## Independent client faults

One optimized worker and copied source Python/compiled Node SDKs passed all 18
registered fault cells: 1, 5 and 12 application clients, Python/Node/mixed
processes, and memory/SQLite storage. The matrix recorded **3,879 passing checks**
with no failed event or cleanup. Each client runs in its own process; one trusted
host owns the shared graph. A separate Python fault driver is outside the
application-client count and outside load metrics.

| Boundary | Observed result |
| --- | --- |
| Exact scope and text | Every readable fixture document was verified in bounded context groups; denied required IDs and other clients' tickets failed. |
| Private updates | Affected tickets and reviews became stale; unrelated scopes remained valid. Withdrawal/change-back did not revive old work. |
| Competing writes | Proposed text stayed invisible until host admission. Exactly one proposal won the source CAS; the other conflicted and was explicitly rejected. The winner's receipt matched the host's receipt. |
| Revocation | Old credentials failed before dispatch; a replacement grant could not revive old tickets. |
| Resource isolation | Ticket quota and four incomplete authenticated connections stayed bounded. Other clients and the private host channel made progress while the faulty connections remained open. |
| Abandoned client | Killing and reaping the fault driver left application clients usable. |
| Durable restart | Killing the worker preserved admitted versions, provenance and text while changing the authority epoch. Old grants, tickets, reviews, pending proposals and uncommitted source transactions were rejected. |

The nine SQLite cells rechecked **13,878 document instances across client views**
after restart. That count includes common/pair-shared text appearing in more than
one view; it is not 13,878 distinct documents. The one-client cells have no
cross-owner comparison, and memory cells have no durable-restart claim.

The fixture's quoted hostile instructions did not enlarge API authority. That
does not make the library an OS sandbox or establish semantic truth. Host review
labels in this authored fixture test the review binding, not an independent
answer evaluator. Existing native scheduler, lost-acknowledgement and real
Honey HTTP/SQLite tests remain required.

## Measurement failure retained

The first repeated load run stopped after 180 of its planned 288 process cells.
Four cells failed only the complete-window gate; all 180 had zero API failures.
The harness used a monotonic deadline but incorrectly judged completion by wall
time. The old records lack an explicit monotonic window and cannot establish why
the clocks differed. This study remains incomplete, with its original records
and a separate disposition; its successful cells are not pooled with the rerun.

Both actors now record elapsed duration from their workload clock. Wall time
remains a shared-start/skew diagnostic. Regression tests cover backward wall
adjustment and early monotonic exit. All duration, latency, fairness, progress
and failure limits remain unchanged. A corrected 12-cell smoke run passed and
its report verified retained hashes, raw reductions and rendering equality.
The eight-cohort replacement is a new frozen study with the same worker/SDK bytes
and passed all 288 cells. None of the interrupted study's cells are pooled into it.

## Reproduction and evidence

See [the harness guide](../../benchmarks/BROKER_LOAD.md) and the
[preregistered plan and correction](../proposals/context-broker-qualification-0.14.0.md).
The diagnostic benchmark suite has 34 passing tests, including 18 new load/report
tests. Source CI now includes 5/12 mixed-client fault qualification on macOS and
Linux; those hosted executions are pending.

Local evidence is retained outside the source worktree at
`CIGAR/releases/cigar-0.14.0-development/`:

- `broker-fault-matrix-01/`: complete 18-cell fault matrix.
- `broker-load-matrix-01/`: interrupted clock-domain study and disposition.
- `broker-load-clock-smoke-01/`: corrected smoke and verified report.
- `broker-load-matrix-02/`: corrected complete matrix and verified `summary.json`.

The fault matrix used source commit
`059c0155385da5b2012b361d99a1ff8730e39199`, macOS 26.6.1 ARM64,
Python 3.14.7 and Node 24.19.0. Exact copied SDK/harness files and hashes are in
the plan; the source commit alone is not inferred proof of binary provenance.

| Evidence | SHA-256 |
| --- | --- |
| Worker | `135194f33d2d0985b45b727377ee5797ce9470ab3ef2784b668111a91e92aeb6` |
| Fault plan | `70af9aec880662ab91a23992171d418775796c5d0ecbd86ea408ad80ed74649f` |
| Fault result | `f9c030d2c8e9c0877aba1d937f6ae42d74aba361495fff186b63f5f76f30c7f8` |
| Corrected load plan | `5056565d51f0cadace4048ee28d862ff7ad05e715543c2b5b57df88e070d120e` |
| Corrected load result | `b50657f528b47b16741f1552038fa09b778f81f3b20ddc579496937be5a2ad2f` |
| Report verifier source | `7428561ac17e0814fa4ba4294d56eda7661abd59a250e61e154acab2e7c99ccb` |

These source runs use explicit loopback only by implementation. They do not
claim OS-enforced network denial, seven-platform installed qualification,
continuous 24-hour reliability, or reduced LLM hallucinations. Those remain
separate release gates with separate evidence.
