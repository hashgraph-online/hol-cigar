# Transactional ingestion: v0.14 development evidence

Status: locally tested source, not a release qualification. Evaluation used no
model provider. The change adds a host-only way to replace one source across
multiple bounded requests while readers retain the previous evidence until
commit. Existing graph/broker APIs, source CAS, provenance checks and canonical
identities retain their behavior.

## Demonstrated benefit and limits

Both SDKs admitted **35,651,624 bytes of source text across 137 documents**, using
35 batches, while the ordinary single-request API rejected the same source
before dispatch. Its 32 MiB limit is unchanged. The largest dispatched batch
frame was 1,048,982 bytes including its envelope. Node checked every document's
complete text and citations in memory mode, durable mode and after recovery.
There was one replacement visibility point and one durable replacement receipt.

Python's paired diagnostic used eight fresh-process cohorts per API/storage/size
combination, for 96 successful observed processes. Sixteen of these correctly
rejected oversized complete-list calls; that rejection is a boundary assertion,
not successful ingestion. All comparable whole/batched runs produced the same
selected probe and rendering. Native tests separately compare complete ordinary
and batched graph results, and test partial rejection, ownership/CAS/derivation
changes, expiry, shared retention and restart.

| Source | Storage | Whole-request median | Batched median | Median change | Sampled host + worker RSS, whole → batch |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 MiB + probe | Memory | 13.120 ms | 13.449 ms | +2.5% | 84.64 → 84.71 MiB |
| 1 MiB + probe | SQLite | 35.542 ms | 35.449 ms | −0.3% | 96.46 → 95.07 MiB |
| 8 MiB + probe | Memory | 101.408 ms | 103.040 ms | +1.6% | 131.27 → 100.23 MiB |
| 8 MiB + probe | SQLite | 158.700 ms | 159.840 ms | +0.7% | 168.43 → 135.84 MiB |

At 8 MiB, mean paired sampled total-RSS reductions are 23.7% in memory mode and
19.3% in SQLite mode. Python host RSS falls from about 59.7 MiB to 39.0 MiB. The
mean paired latency increases are 1.454 ms (95% resampling interval
0.603–2.330 ms) and 1.545 ms (−0.125–2.939 ms), respectively. This is a memory and
capacity improvement with small observed median overhead, not a general speedup.

The 1 MiB SQLite batch cohort contains a **74.970 ms** operation, compared with a
36.382 ms maximum for ordinary replacement. It is retained. Its measured host
RPC phases sum to about 37.5 ms, so the evidence does not attribute the entire
delay to commit; input processing and scheduling remain included in end-to-end
time. Its paired mean difference is +4.870 ms with an interval of −0.869 to
14.929 ms. No tail-latency non-regression claim is made.

For the 34 MiB source, batched median input-to-ack is 433.225 ms in memory mode
and 576.431 ms with SQLite. Sampled total RSS is 126.77 MiB and 266.73 MiB;
Python host RSS is about 39.0 MiB in each. Median commit alone takes 298.095 ms
and 445.303 ms, and durable reconstruction takes 524.946 ms. The rejected
whole-request calls provide no successful-operation performance baseline.
Full-image checkpointing and indexing remain material costs.

The host was macOS 26.6.1 ARM64, Python 3.14.7 and Node 24.19.0. The worker used
Rust 1.92's optimized release profile with debug information and no stripping.
RSS sampling occurred every 20 ms during ingestion, not at exact allocation
peaks; the 1 MiB memory operation often finishes within one sampling period.
Timings include reading/parsing the retained JSONL source, serialization, IPC
and native work. The probes use explicit workers and exclude bundled verification.
See the [harness method](../../benchmarks/BROKER_INGESTION.md) for reproduction.

## Correctness and failure contract

Only the private host channel accepts batching. Staged material cannot grant
agent authority, become evidence, change reviews or survive a restart. At most
four replacements coexist, with 1–300,000 ms leases and shared retention limits.
Commit consumes the handle and rechecks current source CAS, provenance,
derivation, document ownership and graph bounds through the existing replacement
path. Invalid later batches leave prior staging unchanged. Definite commit
failure leaves the graph unchanged. The convenience APIs abort after a local
input failure and preserve the original error if cleanup also fails.

Durable commit uncertainty still closes the owner without a false success,
definite-failure receipt or automatic retry. A real bounded-checkpoint failure
exercises this path through both SDKs. Tests also prove that begin/append leave
database bytes unchanged, restart loses pending staging, and commit adds exactly
one replacement record. These tests do not establish power-loss durability on
every filesystem or platform.

Local regression results:

- 140 all-feature native tests, one doctest and 57 core-only test/doctest
  invocations; strict Clippy and native formatting pass. The one default-ignored
  crash child is invoked by its bounded parent test.
- 480 Python tests plus 39 subtests and 164 Node tests pass.
- Python coverage: 93.60% statements / 86.80% branches overall; the broker and
  context-effect adapter remain 100% / 100%. All critical-module gates pass.
- Sixteen benchmark-reducer tests, strict Python typing, changed-file lint/format
  and both generated-source drift checks pass.

The first new Python SQLite-inspection test failed because it attempted a second
connection while the owner held its exclusive lock; inspection was moved after
shutdown. The first benchmark smoke plan had incompatible graph/grant and
checkpoint/database limits; it was rejected and retained as a failed diagnostic.
The corrected smoke run and eight-cohort study passed without relaxing production
validation. Neither initial failure was hidden or counted as successful evidence.

## Retained identities

Evidence remains outside the public source tree under
`CIGAR/releases/cigar-0.14.0-development/`:

| Artifact | SHA-256 |
| --- | --- |
| `source-batches-comparison-01/worker` | `135194f33d2d0985b45b727377ee5797ce9470ab3ef2784b668111a91e92aeb6` |
| `source-batches-comparison-01/plan.json` | `74a8425548affbb31f76ab982325a22b87e58def824104f99296a229b72e2d19` |
| `source-batches-comparison-01/result.json` | `b32ce7052bb5fad46282c14ed46420f123a2eb7bea4e34f8f61091a08cee9901` |
| `source-batches-comparison-01/observations.jsonl` | `52b8ec5503cfb9c8cf171d85002908b7cdaa242affb9965639407452e9604d0c` |
| `source-batches-comparison-01/tracked.patch` | `b81b4ec4fda76be963dac2a3e317ed3fa48bc96cb855aff3f0efea81e733878f` |
| `source-batches-node-large-01.json` | `56de1a61b87a333285c028950f62b7c08f5bbec11f32856efcd114707db44ede` |

The study started from `3277fc557a1c30a3ead4aff262fd2e198ed363c0` plus the retained
tracked patch and two explicitly hashed/copied new native source files.
The SDK source digest is
`3a80823e348d19659c521e0b9f3d620e429b7a435686e8c536e6abf25ae8b9a8`.
Node records its compiled SDK, harness and corpus identities in its result.
Native logs use `source-batches-native-01/`; full SDK logs and coverage use the
`source-batches-` prefix. Smoke inputs/results are retained separately.

This evidence advances R2. It does not finish the version-wide performance gate,
independent task efficacy, sustained shared-agent load, hosted platform checks,
installed artifacts or release authorization. No v0.14 package is published by
this work.
