# Development broker storage profile

Status: local diagnostic completed on September 27, 2026. This is an optimization
within the v0.14 development branch, not a v0.12/v0.14 comparison or release
qualification. Source/package version fields still carry the development alpha
identity. No model provider or external service was invoked.

The full-checkpoint prototype incurred an avoidable memory cost on macOS when
repeatedly hashing and encoding a growing graph. Streaming the checkpoint digest
and reusing the encoding buffer reduced combined host/worker sampled RSS by about
46% at 5,000 documents. It preserved canonical checkpoint bytes, storage limits,
transaction boundaries and restore behavior. Durable write latency remains about
35 ms for this workload; this change does not remove full-image writes.

## Workload and retained identities

The comparison uses eight fresh process cohorts at each of 100, 1,000 and 5,000
base documents, with 1,024 bytes per document. One separate source changes in each
cycle. Each of the four treatments (reference/candidate × memory/SQLite) excludes
two warmups and retains twelve update/compile cycles. Order reverses on alternate
cohorts. The identical source Python SDK drives both workers through explicit
worker paths. Each durable treatment also restores the store and checks evidence,
source versions and a fresh authority epoch.

Host: Apple M3 Ultra, 32 cores, 512 GiB RAM, macOS 26.6.1 ARM64. Python 3.14.7;
Rust 1.92.0 release profile with `bpe,broker-persistence`. Timings include SDK
serialization and local IPC. Explicit worker paths exclude bundled-worker hashing.
CPU excludes the additional recovery check. RSS is sampled simultaneously every
20 ms; it is neither PSS nor an exact peak. File sizes exclude transient rollback
journals and are not bytes written. Background system activity was not controlled.

| Input | Identity |
| --- | --- |
| Reference source | `42f571fbc63d01407d0cf4122ddd5221adf83e20` |
| Candidate source | Reference commit plus the retained `candidate.patch` |
| Candidate patch SHA-256 | `4a1235111e430878bd559a5f27a635c1a54f5bea0fe33e975d17b299886bf70e` |
| Reference worker SHA-256 | `e48548637f5c5ceac5669672daece9ae1245bc230af543f9fbecc1ab917dac89` |
| Candidate worker SHA-256 | `1b8852fb4e277cd99bbd08484c16df50bd0ad02c5691ffce11606715096ca4c0` |
| Result JSON SHA-256 | `c3040076dc616171da492f81130008b2cd3ee7dbf5ba78826b64d6f1a6a35844` |

The local evidence archive is
`CIGAR/releases/cigar-0.14.0-development/broker-storage-buffer-comparison-01`.
It contains the preregistered workload, corpora, exact harnesses, tracked patch,
raw observations and recomputed summary. It is excluded from public source
commits. The preceding storage-cost study and separate allocation diagnostics are
retained alongside it. Reproduction commands are in
[`benchmarks/BROKER_STORAGE.md`](../../benchmarks/BROKER_STORAGE.md).

## Durable-mode comparison

Latency values are medians of the eight process medians, in milliseconds. Memory
values are medians of the eight maximum sampled host-plus-worker totals, in MiB.

| Base documents | Update before → after | Compile before → after | Combined RSS before → after | Restore before → after |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 18.336 → 18.310 | 0.642 → 0.595 | 87.85 → 87.59 | 84.061 → 82.527 |
| 1,000 | 21.368 → 21.623 | 0.954 → 0.971 | 102.37 → 102.49 | 93.529 → 92.684 |
| 5,000 | 35.009 → 34.550 | 2.286 → 2.364 | 280.19 → 150.34 | 160.170 → 159.933 |

At 5,000 documents the mean paired RSS difference is −128.67 MiB, with a
descriptive process-bootstrap 95% interval of −130.40 to −126.89 MiB. Worker CPU
for the entire measured process was 466.70 → 462.56 ms, a small difference. Host
CPU was 25.00 → 25.47 ms. Retained database size was unchanged at 10,866,688 bytes.
The candidate worker grew from 8,300,320 to 8,316,880 bytes (about 0.2%).

The 5,000-document compile median increased about 3.4%; the mean paired increase
was 0.076 ms, with an interval of 0.025 to 0.127 ms. This is retained as a trade-off,
not omitted from the report. Update and restore intervals at that size included
zero, so the data do not establish a durable-latency improvement. The primary
observed benefit is lower memory retention.

The memory-only control retained matching rendered contexts and showed no
greater-than-10% median latency or greater-than-20% sampled RSS regression in this
probe. At 5,000 documents its compile medians were 1.704 → 1.685 ms and combined
RSS was 128.34 → 127.99 MiB. This is a narrowly scoped control, not proof of
non-regression across the project's other workloads or platforms.

## Allocation diagnosis and behavior checks

A separate 64-update diagnostic omitted agent compiles and inspected the same
synthetic worker with macOS memory tools. The original worker's post-call RSS
rose to 424,394,752 bytes and plateaued; the revised worker stayed around
102,432,768 bytes. Live allocation totals stayed near 51 MiB before the change;
the growth appeared in freed large allocation regions. With a retained encoding
buffer, live allocations were about 57 MiB and those freed regions stopped
accumulating. These observations support allocator retention from repeated
full-image buffers; they do not establish an unbounded live-object leak.

The fix leaves the ordinary context digest path unchanged. Checkpoint hashing
uses the same domain, NUL separator and serde JSON bytes through a 16 KiB buffered
hasher. `BrokerCheckpoint.encode_into` reuses caller-owned capacity and clears its
length on failure; it does not promise memory zeroization. The store retains one
bounded encoding buffer. No synchronization, integrity or transaction checks were
removed to improve the measurements.

Validation passed:

- 116 native all-feature tests, one doctest and 48 core-only invocations; strict
  Clippy and formatting. The ignored crash helper is invoked by its parent at
  four transaction boundaries.
- Seven Python and two Node persistence tests against the release-built worker.
- Six harness tests covering process weighting, failed/missing/duplicate cohorts,
  output mismatches, corpus bounds and interval eligibility.
- All 96 comparison processes, including all 48 durable restoration checks;
  rendered output matched across all four treatments within every cohort.
- A new codec regression proves legacy digest parity with escaped/Unicode data,
  exact byte bounds, buffer reuse and absence of partial output after failure.

## Decision and remaining work

Retain the buffer optimization. Durability remains explicit and optional. At
5,000 documents the revised durable mode still adds about 35 ms per write and
uses about 17% more sampled combined RSS than its memory-only control. Whole-image
serialization and disk writes still scale with total admitted evidence.

Do not treat this study as B3, R2 or Q1 completion. Larger sources, transaction
batches, filesystem/platform fault behavior, 1/5/12-agent tail latency and fairness,
the 24-hour soak, exact installed artifacts and matched-version performance gates
remain required. Windows runtime qualification also awaits the approved public
branch/hosted workflow path. No release or independent answer-quality benefit is
claimed by these measurements.
