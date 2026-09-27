# Broker storage cost probe

This diagnostic compares the same development worker with memory-only and
SQLite evidence storage. It measures the cost of adding durability, not a benefit
over v0.12, an agent task-success rate, or a published-package qualification.
No model or external service is invoked; broker traffic uses local loopback.
The harness does not claim OS-enforced network isolation.

Use a release-built worker and the pinned Python development environment:

```sh
python -m unittest discover -s benchmarks -p 'test_broker_storage.py'
python benchmarks/broker_storage.py \
  --worker /absolute/path/to/release/cigar-context-worker \
  --output /absolute/path/to/new-study
```

The default study uses eight fresh host/worker process pairs at each of 100,
1,000 and 5,000 documents, with 1,024 bytes per document. The base source remains
unchanged while one separate document is replaced. Each cohort excludes two
warmup update/compile cycles, then retains twelve measured cycles. Treatment
order alternates. Both treatments must return identical rendered context.
The durable treatment additionally reopens the store, checks preserved source
versions and fresh authority, and compiles the last base document plus the update.

Raw observations retain startup, initial admission, update, compile and close
latency; total host/worker CPU; 20 ms simultaneous RSS samples; OS-reported
individual RSS peaks; post-call database sizes; checkpoint size and restore
latency. The explicit worker path excludes bundled-binary verification.
Disk samples exclude transient journals and are not bytes written. CPU excludes
the extra durable recovery check. Sampled combined RSS is not an exact peak or PSS.
The sampler runs in both treatments and may affect timings.

The summary gives quantiles across **process medians**, with paired differences
and descriptive bootstrap intervals only after eight whole process pairs.
Raw per-call distributions remain in `observations.jsonl`. Failed/time-limited
processes remain failures; missing pairs cannot receive a successful summary.
Worker, SDK and corpus identities are checked; the plan, corpus bytes and
harness are retained before measurement. This is a development source probe:
it does not provide publisher attestations or replace the shared evaluation
envelope and exact-artifact gates required for release.

To isolate a native implementation change, retain both release-built workers
and compare them with the same current SDK and workload:

```sh
python benchmarks/broker_storage_compare.py \
  --reference-worker /absolute/path/to/retained/reference-worker \
  --reference-commit FULL_40_CHARACTER_SOURCE_COMMIT \
  --worker /absolute/path/to/candidate-worker \
  --output /absolute/path/to/new-comparison
```

This runs both memory and SQLite modes for each worker, reversing treatment order
on alternate cohorts. It binds worker hashes, the candidate's tracked source
patch, harnesses and corpora before measurement. Both workers use the same SDK,
so this does not qualify a change to the SDK itself. The caller supplies the
reference commit; that label is not a build attestation. Duplicate, missing,
failed or context-mismatched cohorts cannot receive a successful comparison.

The [first storage profile](../docs/release/context-sdk-0.14.0-storage-profile.md)
records the allocator-retention finding and the bounded checkpoint-buffer fix.

Use the results to profile growing checkpoint/serialization costs before choosing
incremental storage or a different transport. Acceptance of existing API
performance still requires the separate matched-version 10% latency and 20% RSS
regression gates. Do not reinterpret an optional durability cost as an improvement
to the memory-only baseline.
