# Changelog

## 0.12.0 — 2026-09-25

- Reject non-string and Unicode-normalization-colliding mapping keys before
  semantic-bundle hashing or nominal payload conversion. Valid canonical IDs
  remain unchanged.
- Preserve primary errors during worker cleanup; reject use of inherited graphs
  after `fork()`. Create a new graph in the child. `cleanup_complete` reports
  whether the worker was reaped and its I/O thread joined; close can retry.
- Load public Python exports on demand and hash bundled workers with a bounded
  buffer on every launch.
- Permit protobuf `>=6.33.5,<8`; qualify the minimum and current runtime separately.
- Require `CIGAR_ALLOW_PORTABLE_WHEEL=1` for intentional workerless source builds.
  Local graphs from such builds require a matching trusted `worker_path`.
- Add integrity property tests, lifecycle/fork tests, API compatibility and Python
  coverage measurements. Preserve the context ABI and local worker protocol.

The release includes seven native platform wheels and one portable source archive.
See the [comparison report](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/docs/release/context-sdk-0.12.0-comparison.md)
for measured improvements, observed increases and qualification limits. Exact
artifact hashes and signed qualification evidence accompany the GitHub release.

## 0.11.0 — 2026-09-24

- Standalone local context graphs, exact token budgets, citations and host-trusted
  answer-review gates. HOL services, credentials and an external database are not
  required for local use.
- Seven native platform wheels and a portable source distribution.
