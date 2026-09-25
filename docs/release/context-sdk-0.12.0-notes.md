# CIGAR 0.12.0 candidate

This is an unpublished candidate. Qualification results and artifact hashes must
be checked before installation or promotion. The existing 0.11.0 registry release
remains the public default until a separate publication decision.

The candidate rejects ambiguous Python semantic-bundle mapping keys, includes the
npm canonical-CBOR union response repair, preserves worker errors through cleanup,
and rejects inherited Python graphs after fork. It also adds lazy Python exports,
bounded worker hashing in both SDKs, explicit workerless build opt-in, dependency
compatibility qualification, public API snapshots and release dependency evidence.

Local context graphs require no HOL services, account, API key or network access.
The `cigar.context.v1` application ABI and `cigar.context-worker.v1` protocol remain
unchanged. Valid canonical bundle identities and snapshot semantics are preserved.

Python remains `>=3.14,<3.15`; Node remains `>=24.10.0,<25`. The Python runtime
requirement is `protobuf>=6.33.5,<8`, with minimum/current qualification recorded
separately. The seven-platform target matrix is unchanged; candidate testing is
not proof of a platform until its installed artifact checks complete.

Source installs without a staged worker now require
`CIGAR_ALLOW_PORTABLE_WHEEL=1` and a matching trusted `worker_path`. Platform wheels
and the npm archive bundle their workers and never download one at runtime.

Create a new `LocalContextGraph` after fork; operations and close on an inherited
instance raise `ForkedProcess`. `close()` preserves ordinary primary errors and
can retry incomplete cleanup; `cleanup_complete` reports successful worker reaping
and I/O-thread completion.

Answer review still relies on independently trusted factual judgments. Offline
fixtures establish enforcement and compatibility, not a model hallucination rate.

See the [implementation plan](../proposals/cigar-0.12.0-plan.md) and
[Python changelog](../../sdk/python/CHANGELOG.md).
