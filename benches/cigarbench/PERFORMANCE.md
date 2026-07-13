# Section 22 performance evidence harness

`performance.py` is a standard-library-only validator, report generator, and
candidate/baseline comparator for raw `cigard` performance measurements. It is
an analysis harness, not a benchmark collector. This repository intentionally
contains no claimed release performance result.

## Evidence contract

A qualifying run has three inputs:

- A `cigar.performance-run.v1` JSON manifest. It captures the CPU and core
  counts, memory, OS and kernel, filesystem, storage, power mode, compiler
  flags, background load, pinned runner, tokenizer, policy, warm-up plan, raw
  host calibration measurements, installed-daemon artifact and installation
  receipt digests, build and dataset digests, and immutable workload cases.
- A `cigar.performance-sample.v1` JSONL stream. Every line repeats the run,
  manifest, environment, build, dataset, daemon artifact, and workload-case
  bindings. Each line has a content-derived ID and links to the preceding line.
  The stream must contain exactly the warm-up and post-warm indexes declared by
  the manifest.
- A `cigar.performance-attestation.v1` JSON object made by an independent
  evaluator after validating the first two inputs. Its HMAC-SHA-256 tag binds
  the canonical manifest digest, exact raw-stream digest, terminal chain ID,
  sample count, evaluator role, and key ID. Verification uses a separately held
  key file of at least 32 bytes. An unattested or incorrectly keyed stream can
  be analyzed, but it can never qualify.

The exact accepted fields are the `*_KEYS` constants and validation functions
in `performance.py`; unknown and missing fields fail. JSON duplicate keys,
non-finite values, oversized inputs, symlinks, broken content IDs, broken chain
links, substituted digests, duplicate or missing indexes, and incomplete sample
streams also fail.

Collectors must provide every raw metric for every sample: latency, elapsed
time and work units, allocations and allocation bytes, CPU, RSS, disk
amplification, database and index size, lock time, queue depth, cache hit rate,
invalidation lag, failure counts, recall, leakage and correctness indicators,
materialization budget counts, plus separate model, embedding, network-source,
and connector latency. Throughput and failure rate are derived by the analyzer,
not accepted as self-reported values.

The public helpers `canonical_bytes`, `sha256_multihash`, `sample_with_id`, and
`manifest_digest` exist so an installed collector can emit the exact canonical
format. The tests in `tests/test_performance.py` are an executable construction
example. Collection must still occur against the real installed daemon on the
recorded pinned host.

## Qualification behavior

A run can return `pass` only when all of the following are true:

- `evidence_class` is `qualification`; `harness_smoke` is permanently
  ineligible.
- The independent evaluator attestation verifies against the configured trust
  key. Merely setting manifest fields such as `installed_cigard` or
  `dedicated_pinned_runner` is not sufficient.
- The target kind is `installed_cigard` and the runner declares itself
  dedicated and pinned.
- Every case has at least one warm-up and at least 30 post-warm samples.
- At least 30 raw host calibration measurements have a sample coefficient of
  variation strictly below 5%.
- All sixteen section 22.2 operation/profile entries are represented and
  evaluable. The shared-scale curve contains 1k, 10k, 100k, 1M, and 10M atom
  points.
- The load-matrix metadata covers the required atom values, candidate and blob
  boundaries, client counts, cold and warm cache, every retrieval mode and a
  combined mode, both consistency modes, and local and shared stores. This is
  axis coverage; the report does not falsely claim a full Cartesian product.
- Every measurable v1 SLO passes. Nearest-rank percentiles are used. Ingestion
  conservatively requires the minimum sample throughput to meet 250 atoms/s,
  idle RSS uses the strict 300 MiB bound, and hard-budget compliance is derived
  from raw counts.

The PRD does not put a number on “negligible” idle CPU. This harness versions a
conservative maximum of 1% as `IDLE_CPU_LIMIT_PERCENT` and records that
interpretation in every applicable SLO result. If the normative specification
later supplies a different number, the schema/version must change rather than
silently changing old decisions.

Reports retain the complete manifest, full raw-backed distributions (count,
range, mean, sample standard deviation, p25/p50/p75/p90/p95/p99), load coverage,
SLO checks, evidence eligibility, raw stream digest, and terminal chain ID.

## Candidate comparison

Comparison requires identical environment, dataset, tokenizer, policy,
workload-case digests, and sample plans. Build and installed-artifact digests
may differ. Candidate and baseline samples pair by sample index. The comparator:

- blocks a p95 latency regression only when the lower bound of a deterministic
  10,000-resample paired-bootstrap 95% interval is over 10%;
- blocks median throughput or p95 RSS regression over 15%;
- warns for point regressions over 5%;
- independently blocks candidate SLO breaches, lower minimum recall, increased
  leakage, or any recorded correctness loss/degradation.

Fewer than 10,000 bootstrap repetitions can be useful in bounded harness tests
but can never produce a passing comparison. The evaluator rejects more than
1,000,000 repetitions before doing any resampling, so a hostile report or CLI
argument cannot request unbounded bootstrap work.

## Commands

After independent collection and evaluation, authenticate the validated raw
stream. Keep the key out of reports and benchmark artifacts:

```sh
python3 benches/cigarbench/performance.py attest \
  --manifest reports/performance/candidate.run.json \
  --samples reports/performance/candidate.samples.jsonl \
  --key-file "$CIGAR_PERFORMANCE_EVALUATOR_KEY_FILE" \
  --key-id performance-evaluator-2026q3 \
  --output reports/performance/candidate.attestation.json
```

Validate one run and fail the command unless it is qualifying and passing:

```sh
python3 benches/cigarbench/performance.py validate \
  --manifest reports/performance/candidate.run.json \
  --samples reports/performance/candidate.samples.jsonl \
  --attestation reports/performance/candidate.attestation.json \
  --attestation-key-file "$CIGAR_PERFORMANCE_EVALUATOR_KEY_FILE" \
  --require-qualification \
  --output reports/performance/candidate.report.json
```

Compare like-for-like raw candidate and baseline runs:

```sh
python3 benches/cigarbench/performance.py compare \
  --candidate-manifest reports/performance/candidate.run.json \
  --candidate-samples reports/performance/candidate.samples.jsonl \
  --baseline-manifest reports/performance/baseline.run.json \
  --baseline-samples reports/performance/baseline.samples.jsonl \
  --candidate-attestation reports/performance/candidate.attestation.json \
  --candidate-attestation-key-file "$CIGAR_PERFORMANCE_EVALUATOR_KEY_FILE" \
  --baseline-attestation reports/performance/baseline.attestation.json \
  --baseline-attestation-key-file "$CIGAR_PERFORMANCE_EVALUATOR_KEY_FILE" \
  --bootstrap-repetitions 10000 \
  --require-qualification \
  --output reports/performance/comparison.report.json
```

Reproduce a report exactly from its bound raw inputs:

```sh
python3 benches/cigarbench/performance.py replay \
  --report reports/performance/comparison.report.json \
  --candidate-manifest reports/performance/candidate.run.json \
  --candidate-samples reports/performance/candidate.samples.jsonl \
  --candidate-attestation reports/performance/candidate.attestation.json \
  --candidate-attestation-key-file "$CIGAR_PERFORMANCE_EVALUATOR_KEY_FILE" \
  --baseline-manifest reports/performance/baseline.run.json \
  --baseline-samples reports/performance/baseline.samples.jsonl \
  --baseline-attestation reports/performance/baseline.attestation.json \
  --baseline-attestation-key-file "$CIGAR_PERFORMANCE_EVALUATOR_KEY_FILE"
```

Run the bounded unit suite with:

```sh
python3 -m unittest discover -s benches/cigarbench/tests -v
```

## Integrity boundary

Content IDs, the chain, raw-file digest, evaluator HMAC, report ID, and
deterministic replay detect mutation, substitution, and evidence created without
the configured evaluator key. HMAC trust depends on independent key custody; it
does not by itself prove that the evaluator followed the collection procedure
or that a host and daemon were genuine. Release automation must protect that
key and anchor the raw files, manifest, attestation, installation receipt,
report, and provenance in the project’s independently signed release-evidence
system. No smoke fixture or test-generated number is release evidence.
