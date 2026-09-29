# CIGAR 0.14.0: completed 24-hour broker soak

The run passed all predeclared checks. Independent replay and installed-package
integrity checks also passed. The main follow-up from the detailed measurements
is sustained resident-memory growth in the Node clients, within the configured cap.

## Workload and scope

- September 27, 2026, 17:29 PDT through September 28, 2026, 17:29 PDT.
- 86,400.000643 seconds; macOS ARM64; Python 3.14.7 and Node 24.19.0.
- One SQLite-backed broker and twelve continuously running clients: six Python and six Node.
- One concurrent round per second, giving twelve client cycles per second.
- 1,284 initial synthetic documents: 128 common, 64 private per client, 64 shared
  by each client pair, and four sealed documents. Each client's allowed view
  contained 256 documents initially and 257 after a reviewed proposal was admitted.
- Routine requests selected three required documents within a 1,024-token budget.
- Each routine cycle compiled context, checked selected evidence/citations/scope/budget,
  and released its ticket. Warmup and maintenance generated additional operations.
- No model calls. This is a fixed-cadence local endurance workload; throughput at
  saturation, other platforms, and model answer quality require separate evidence.

## Completed work

| Measurement | Result |
| --- | ---: |
| Concurrent sampling rounds | 86,400 |
| Cycles per client | 86,400 |
| Total successful client cycles | 1,036,800 |
| Routine compile and ticket-release operations | 2,073,600 |
| Additional recorded validation checks | 104,561 |
| Failed recorded validation checks | 0 |
| Unexpected routine operation errors | 0 |
| Longest unexplained observation gap | 1.027 seconds; 5-second limit |
| Raw observation records | 91,625 |

Expected rejection responses (stale state, denied authority and competing writes)
were successful assertions, not unexpected failures. The twelve client processes
kept their identities across the entire run. The broker worker was deliberately
killed and replaced at hourly intervals.

## Maintenance and recovery

| Exercise | Completed rounds | What was verified | Slowest complete phase |
| --- | ---: | --- | ---: |
| Private-source mutations, every minute | 1,439 | Changed evidence invalidated the affected client's ticket and old review; other clients' tickets remained valid | 133.70 ms |
| Grant renewal, every two minutes | 719 | 8,628 client renewals; replaced grants and old tickets denied | 29.21 ms |
| Competing proposals, every five minutes | 287 | Two proposals per round; one admitted, one conflicted then rejected; rejected evidence unavailable | 34.83 ms |
| Explicit grant revocation, every ten minutes | 143 | Revoked access denied and replacement grant established | 2.85 ms |
| Forced worker termination and SQLite recovery, hourly | 23 | Documents and provenance restored exactly; old authority rejected; uncommitted staging and old reviews invalidated | 288.06 ms |

The median complete restart phase was 257.58 ms. This phase includes verification
before and after the restart, regranting and reconnection. All maintenance phases
met the 30-second cap. Scheduled events at the 24-hour endpoint are outside the run.

## Routine operation latency

Measured at the client, in milliseconds; compile includes SDK context validation.
These are descriptive measurements from the recorded operations, not additional
predeclared percentile pass/fail gates. Percentiles use linear interpolation.

| Operation | Median | p95 | p99 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Compile, all clients | 6.83 | 12.79 | 16.44 | 26.27 |
| Release ticket, all clients | 2.91 | 8.25 | 11.43 | 16.70 |
| Compile, Python clients | 5.79 | 11.65 | 14.76 | 24.56 |
| Compile, Node clients | 8.08 | 13.61 | 17.18 | 26.27 |

Each combined operation row contains 1,036,800 samples. Each runtime-specific row
contains 518,400 samples. Maintenance and warmup are excluded from these distributions.

## Memory

Resident memory was sampled once after each routine round. Values below are MiB.
The total includes the harness host, worker, and all twelve clients.

| Process group | First sample | Last sample | Sampled peak |
| --- | ---: | ---: | ---: |
| Harness host | 39.28 | 40.11 | 40.11 |
| Broker worker, restarted hourly | 62.03 | 54.36 | 64.08 |
| Six Python clients combined | 183.02 | 186.50 | 186.50 |
| Six Node clients combined | 367.03 | 863.92 | 863.92 |
| All processes combined | 651.36 | 1,144.89 | 1,147.69 |

The sampled total peaked at 1.121 GiB, below the 2 GiB cap. Node clients accounted
for almost all growth: approximately 497 MiB combined, or 83 MiB per client on
average, over the run. Their hourly median RSS rose from 434 MiB in the first hour
to 860 MiB in the final hour. A stable plateau was not demonstrated. The data does
not identify the cause; targeted heap measurements or a longer run are needed to
characterize retention. The worker's hourly restarts limit conclusions about a
single worker process staying alive for 24 hours.

RSS may count shared pages in multiple processes. Brief peaks between the once-per-round
samples are not measured. There was no predeclared memory-growth-slope gate;
the memory pass condition was the aggregate sampled 2 GiB cap.

## Verification and source data

Independent replay recomputed the complete result from the raw transcript. It
confirmed the duration, ordered observations, expected operation outcomes,
maintenance coverage, memory cap and observation-gap bound. All 187 frozen input
files and both interpreter hashes matched. The installed SDK and dependency files
also matched their package archives. The earlier interrupted run is excluded.

- [Final result](../../reports/evidence/context-sdk-014-soak/result.json)
- [Supervisor result](../../reports/evidence/context-sdk-014-soak/supervisor-result.json)
- [Independent replay and package integrity](../../reports/evidence/context-sdk-014-soak/independent-replay.json)
- [Full derived statistics, including all 24 hourly summaries](../../reports/evidence/context-sdk-014-soak/statistics.json)

Raw observations SHA-256: `31f792fb5e6185674140defc4a5d74a507325dcad4631ab17abf490ddb623f87`.
Original evidence files were preserved.

The [committed evidence manifest](../../reports/evidence/context-sdk-014-soak/manifest.json)
binds every receipt to its digest, the tested runtime source `a616c860`, and the
published release commit `830f9367`. The 311 MB raw transcript remains in the
original retained evidence; this repository contains compact results and hourly
statistics. Local paths inside original receipts record the producing host.
These results qualify the named artifacts and do not automatically qualify later
runtime changes or the entire legacy Honey release program.
