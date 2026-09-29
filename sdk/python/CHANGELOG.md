# Changelog

## 0.14.0 — PyPI release, 24-hour soak completed

- Add `LocalContextBroker` and authenticated `LocalContextClient` for independent
  agent processes sharing one graph. The host owns grants, provenance admission,
  reviewer labels and execution policy; agents can submit bounded proposals.
- Add source revision conflict checks, per-agent quotas/fair admission, expiring
  tickets, grant revocation and optional SQLite recovery with a fresh authority epoch.
- Add transactional source batches, selected-evidence explanations, live feature
  discovery and reviewed context bindings for Honey effects without blind retries.
- Preserve 0.12 APIs and valid fixture IDs; reject inconsistent representation and
  transform receipts during semantic integrity verification.
- Reduce measured RPC compile latency by 6.48% versus 0.12 on the comparison host.
  Three startup comparisons exceed their original limits and were explicitly
  accepted: local API import adds about 2.36 ms and worker hashing about 0.51 ms
  versus 0.12. Hash verification still runs on every launch. Other compared
  latency/RSS guardrails pass; no blanket no-regression claim is made.
- Retain optional retrieval adapters with published costs and weaker results than
  the flat BM25 control on SciFact. No model-provider evaluation was performed.
- Publish to PyPI at the maintainer's request while the 24-hour soak was running.
  Seven-platform installed package checks, independent archive comparison and
  public registry readback passed. The completed soak and independent replay
  passed 1,036,800 cycles and 23 forced recoveries. Node client RSS grew within
  the cap; a plateau remains unproven. HUMIDOR adoption and broader Hiero/task
  evidence remain pending. The separately approved npm release is also public,
  with its archive verified against the signed release.

## 0.13.0a1 — local alpha

- Add host-scoped `LocalContextView` handles on one shared graph/index. Source
  reads and atomic replacements respect host-defined readable/writable scopes.
- Preserve reviews across outside-scope updates. Changes to any readable evidence,
  graph edge or view definition require fresh reviews; revocation rejects old handles.
- Bind scope commitments into existing snapshot/review identities and retain all
  0.12 exports, signatures, canonical fixtures and root-method freshness semantics.
- Include an offline five-agent example and paired 0.12 comparison harness.
- Local macOS ARM64 evaluation only. Calls are serialized; views are host-owned
  logical scopes, not authentication, durable recovery or an effect authority.
  HUMIDOR scheduling and its separate Honey integration are unchanged.

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
