# CIGAR 0.12.0 release

This release delivers integrity hardening, reliable worker cleanup and faster
Python startup. The Python distribution is `hol-cigar==0.12.0`; its native wheels
support all seven existing platforms. The npm 0.12.0 archive is qualified here,
but npm registry publication is a separate action.

The release rejects ambiguous Python semantic-bundle mapping keys, includes the
npm canonical-CBOR union response repair, preserves worker errors through cleanup,
and rejects inherited Python graphs after fork. It also adds lazy Python exports,
bounded worker hashing in both SDKs, explicit workerless build opt-in, dependency
compatibility qualification, public API snapshots and release dependency evidence.

Local context graphs require no HOL services, account, API key or network access.
The `cigar.context.v1` application ABI and `cigar.context-worker.v1` protocol remain
unchanged. Valid canonical bundle identities and snapshot semantics are preserved.

Python remains `>=3.14,<3.15`; Node remains `>=24.10.0,<25`. The Python runtime
requirement is `protobuf>=6.33.5,<8`, with minimum/current qualification recorded
separately. The seven-platform target matrix is unchanged. The signed release
manifest binds the exact archives to fourteen installed minimum/current
qualifications and two independent builds. Python 0.12.0 is supported for private
security reporting under the [security policy](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/SECURITY.md).

Source installs without a staged worker now require
`CIGAR_ALLOW_PORTABLE_WHEEL=1` and a matching trusted `worker_path`. Platform wheels
and the npm archive bundle their workers and never download one at runtime.

Create a new `LocalContextGraph` after fork; operations and close on an inherited
instance raise `ForkedProcess`. `close()` preserves ordinary primary errors and
can retry incomplete cleanup; `cleanup_complete` reports successful worker reaping
and I/O-thread completion.

Answer review still relies on independently trusted factual judgments. Offline
fixtures establish enforcement and compatibility, not a model hallucination rate.

The controlled installed comparison measured 89% lower local API import time,
43% lower import-plus-first-graph time, and 84% lower worker-hashing Python
allocation on one macOS ARM64 host. Steady-state compilation was essentially
unchanged. Some native benchmark medians increased up to 7.4%, one microsecond-scale
p95 increased 26%, and native process RSS increased up to 3.5%. Passing the
median/RSS thresholds does not establish zero degradation in every metric.

See the [comparison and qualification scope](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/docs/release/context-sdk-0.12.0-comparison.md)
and [Python changelog](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/sdk/python/CHANGELOG.md).
