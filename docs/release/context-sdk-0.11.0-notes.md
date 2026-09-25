# CIGAR 0.11.0 local candidate

The local Rust core and Python/TypeScript SDKs add an explicit answer-review
contract for applications that need to stop confident unsupported answers before
display. `review_keys`/`reviewKeys` binds the exact claims, citations, confidence
and snapshot. `check_answer`/`checkAnswer` recompiles current authorized context
and checks separately supplied trusted reviews, selected citations, distinct
source groups and declared counterevidence. Missing reviews and unknown verdicts
block release. Confidence is reported but cannot authorize an answer.

CIGAR does not provide a semantic fact checker: the host must authenticate and
evaluate its reviewer independently, keep reviews and policy outside model
control, and show only reviewed claims. Citation existence, lexical coverage and
integrity hashes never establish factual support. Offline fixtures measure this
contract, not real-model hallucination reduction.

Existing snapshot/delta formats and retrieval semantics are retained, together
with 0.10.1's cache, common-term scoring and incremental indexing improvements.
Honey and the remote v1 ABI retain their existing identity. The SDKs add
`cigar-context doctor` and `demo`, capability inspection, explicit platform/worker
guidance, a complete offline workflow and packaged agent instructions. All local
operations work without HOL services, accounts or API keys.

The distribution matrix covers macOS ARM64/x64, Linux glibc/musl x64/ARM64 and
Windows x64. npm uses one archive with the platform workers; PyPI uses platform
wheels. The [distribution execution plan](https://github.com/hashgraph-online/hol-cigar/blob/codex/cigar-0.11.0-distribution/docs/proposals/cigar-0.11.0-distribution.md)
requires installed-consumer qualification for every advertised target before publication.

See the [measurement plan](https://github.com/hashgraph-online/hol-cigar/blob/v0.11.0/docs/proposals/cigar-0.11.0-plan.md)
for gates and the [reproducible offline test suite](https://github.com/hashgraph-online/hol-cigar/blob/v0.11.0/benches/release-tracking/README.md)
for comparisons. Local candidate preparation does not publish packages or supply
hosted provenance/signatures. Changed SDK inputs require new artifacts and
qualification; earlier local reports do not qualify new bytes.
