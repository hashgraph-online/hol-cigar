# Independent broker clients: load and faults

This source qualification complements the native transport/scheduler tests and
the SDK tests. It uses one graph owner and **independent application processes**,
with 1, 5 or 12 clients; Python, Node or alternating runtimes; memory or SQLite
storage; and one or four calls in flight per client. One-client `mixed` is Python
and is retained as a duplicate matrix control, not a third runtime.

The [registered plan](../docs/proposals/context-broker-qualification-0.14.0.md)
and `broker_load.v1.json` fix the fixture and operational gates. Requirements are
authored invariants; no model generates answers and no external provider is used.
Passing does not establish independent task efficacy, installed distribution
quality, a universal service-level guarantee, or 24-hour reliability.

## Reproduction

Use Python 3.14 and a built Node SDK, together with a matching worker built with
`bpe,broker-persistence`. Supply absolute paths and a **new** output directory:

```bash
python benchmarks/broker_load.py \
  --worker /absolute/path/cigar-context-worker \
  --node /absolute/path/node \
  --node-sdk /absolute/path/sdk/typescript/dist \
  --output /absolute/path/new-load-evidence \
  --cohorts 8

python benchmarks/broker_load.py \
  --worker /absolute/path/cigar-context-worker \
  --node /absolute/path/node \
  --node-sdk /absolute/path/sdk/typescript/dist \
  --output /absolute/path/new-fault-evidence \
  --cohorts 1 --only-faults
```

`--agent-counts`, `--runtimes`, `--storage-modes` and `--in-flight` can select a
bounded subset. Do not describe a subset as the complete matrix. `--cohorts 1`
is useful for a smoke run but cannot establish a performance interval. A full
eight-cohort load study contains 288 fresh process cells. Alternate matrix order
between cohorts; preserve every failure and outlier.

These orchestration/RSS scripts currently support macOS and Linux. Windows
continues to use the native transport and SDK crash-recovery tests; this harness
does not establish its load or process-tree cleanup behavior. Source CI runs the
5/12 mixed-runtime fault schedules on macOS/Linux. Hosted execution remains a
separate qualification from a local run.

## What a load observation proves

Each client has common, private and pair-shared sources: 256 readable documents
initially, three required blocks and a 1,024-token context budget. Every returned
block is compared against the exact host fixture text, source and document ID.
The readable document count and token budget are checked too. A sealed source,
other agents' private sources and quoted hostile instructions never expand the
client's authority.

Each measured cycle compiles, verifies the context against that fixture and
forgets the ticket. Both RPC outcomes are retained; a failed forget is a failed
cycle. Tickets cannot quietly accumulate until the benchmark measures quota
exhaustion instead of useful context compilation. Warmups precede a synchronized
three-second interval. Calls begun before the deadline complete afterward; their
full latency remains in the record. Start skew, capped runs and incomplete
windows are checked explicitly.

The deadline and recorded elapsed window use the same monotonic clock. Wall time
is used only for the shared start/skew and retained diagnostics. The first local
matrix exposed a clock-domain mismatch in the original reducer and remains an
incomplete study; the plan records the correction and requires a fresh complete
run. Do not use a wall-clock adjustment to accept an early monotonic exit.

Python timings include SDK calls and the local output check. A wrapper captures
native queue/service timings **after the production SDK validates the reply**.
Node supplies end-to-end timings and marks native timings unavailable. Neither
path adds a mock graph or a substitute protocol implementation to measured calls.

Per-agent p50/p95/p99/max, attempts, completions, failures and cycles/second are
retained. Fairness compares clients within the same runtime: min/max completions
and Jain's index. A mixed Python/Node throughput difference is not attributed to
the native scheduler. The whole fresh process cohort is the statistical unit;
thousands of dependent RPCs are not independent experimental replications.

RSS samples include the coordinator, native worker and every client at 50 ms
intervals. Their sum can double-count shared pages; it is neither PSS nor an exact
allocation peak. The separate launcher/report writer is outside the measured
application cohort. Construct/startup and fault phases are outside load timings.
Run no builds, test suites or other benchmark cohorts alongside measurements.

## What the fault schedule proves

The separate schedule verifies all readable document text in bounded groups,
then checks:

- Denied required evidence and cross-owner tickets; a one-client cell marks the
  cross-owner comparison inapplicable.
- Private updates, withdrawal and change-back: affected tickets and reviews
  fail while other scopes remain valid.
- Two proposals against the same source revision: no visibility before host
  admission, one committed winner, a conflicting loser, exact retained winner
  receipt and explicit loser rejection.
- Grant revocation/redefinition, bounded ticket retention and continued progress
  by other clients and the host.
- Four incomplete authenticated connections held by a separate Python fault
  driver, rejection of its fifth connection, and healthy client/host progress
  while all four remain open. The driver uses the SDK's actual mutual proof;
  it is excluded from load counts. Deliberately killing and reaping that driver
  must leave the application clients usable.
- In SQLite cells, killing the worker and reopening the store preserves source
  versions/provenance and every admitted document checked before restart.
  Epochs change; old grants, tickets, reviews, pending proposals and uncommitted
  source transactions are rejected. Memory cells mark restart inapplicable.

This schedule does not manufacture an unknown effect outcome. Existing SDK and
Honey HTTP/SQLite tests remain responsible for lost acknowledgements, complete
review-to-effect binding and the no-blind-retry contract. It does not replace
native queue cancellation, saturated scheduler or storage power-loss tests.

## Evidence and failure handling

The launcher copies worker, Python SDK, compiled Node SDK, fixture configuration
and harnesses before running any cell, and verifies their hashes afterward.
If the compiled Node directory lacks its package manifest, the snapshot records
an explicit ESM marker. Its generated bytes are part of the bound manifest.
The plan records source commit, Python/Node versions, Node executable hash,
OS and selected dimensions. It does not claim that a source checkout equals an
installed package, nor infer a binary's build provenance from its filename.

Grants enter private child stdin. Tickets used for cross-owner probes stay in
private control responses and are removed before retention. Retained records
reject credential field names recursively. The processes receive a minimal
environment; no credential store, provider discovery or external service is
consulted. This is loopback-only by implementation, not an OS-denied-network run.

Every cell is a fresh owned process group with a 120-second outer deadline.
Cleanup attempts every actor and the worker, preserving a primary error while
recording cleanup failures. A timed-out group is killed and reaped; its observation
is incomplete, not silently omitted. Matrix duplicates are rejected before
creating output files. The reducer checks observation completeness, runtime,
timing types, native-timing availability, context determinism and simultaneous
RSS consistency, then recomputes the cell result from raw data.

```bash
python -m unittest discover -s benchmarks -p 'test_broker_load.py'
```

These tests deliberately inject omitted calls, failures, unknown dispatch,
nonfinite values, altered rendering, early/capped windows, unfair work, missing
RSS and cleanup failures. Keep them alongside changes to the evidence format.

Recompute a completed load study without running any retained executable:

```bash
python benchmarks/broker_load_report.py /absolute/path/new-load-evidence \
  --output /absolute/path/new-summary.json
```

The report verifies retained input/cell hashes, recomputes every cell's gates,
preserves incomplete cohorts and checks rendered-context equality across runtime,
storage and concurrency treatments. It summarizes per-cohort agent medians and
compares one to four in-flight calls using whole paired process cohorts; eight
pairs are required before reporting the bootstrap interval. This comparison
changes offered concurrency and is explicitly a trade-off, not an old-version
nonregression result. The report records its own source hash separately from
the frozen measurement harness.
