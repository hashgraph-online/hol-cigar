# CIGAR 0.10.1 performance and release scope

The 0.10.1 candidate exceeds a 50% median-latency reduction on the measured rotating
query, broad-query and incremental-update workloads while preserving every tested
retrieval result. It does not promise a 50% improvement in every KPI or downstream
workflow. Changes apply to the standalone Rust core and local Python/TypeScript SDKs.

## Implementation

The exact-token cache default increases from 1,024 to 2,048 entries while retaining
the 8 MiB text cap. Broad queries use integer document slots to accumulate the same
scores without repeatedly hashing IDs or resolving document maps. Sparse queries
keep the previous small-query strategy. Source replacement validates a complete
transaction but only indexes changed documents and withdraws obsolete IDs. Slot
reuse does not change document identity, authorization or retained hard edges.

`ContextPrompt` and the SDK `prompt_view` / `promptView` methods provide an additive,
verified rendering with short citation handles. Every selected text block and source
range remains. The caller retains the complete snapshot and citation map; resolution
verifies against the expected authorized snapshot. The independent exact-token budget
returns an error rather than truncating selected evidence. Existing snapshot/delta
schemas, IDs, tokenizer identity, ranking semantics and remote v1 APIs are preserved.

Persistent SDK workers already retain indexes between calls. This release improves
their source-update path; it adds neither disk persistence nor implicit filesystem
ingestion. Semantic retrieval quality, AST ingestion and downstream Hiero bridge
changes remain separate research/integration work.

## Measured results

Baseline: the 0.10.0-beta.1 source at
`11c38b0ba4fa00e1a03cad99ca316a875a03babd`. Both probes use Rust 1.92.0, the same
registry dependencies, release optimization, one codegen unit and thin LTO on the
same Apple-silicon macOS host. Two process-level rounds reverse treatment order.
Timings exclude input cloning, explicit cache clearing and verification unless
specified otherwise. See the [method](../benches/context-011/README.md),
[raw evidence inventory](evidence/context-011/manifest.json) and
[machine-readable summary](evidence/context-011/summary.json).

| KPI / workload | Baseline median | 0.10.1 median | Reduction | p95 reduction |
| --- | ---: | ---: | ---: | ---: |
| Rotating real-source queries, full chunks | 8.817 ms | 1.366 ms | 84.5% | 89.3% |
| Rotating real-source queries, line windows | 6.309 ms | 1.260 ms | 80.0% | 83.7% |
| Warm common query, 50,000 documents | 23.978 ms | 4.541 ms | 81.1% | 78.1% |
| Warm common query, 10,000 documents | 2.054 ms | 0.379 ms | 81.5% | 85.0% |
| Warm common query, 1,000 documents | 0.303 ms | 0.172 ms | 43.0% | 46.3% |
| Replace 504 unchanged source chunks | 66.685 ms | 0.285 ms | 99.6% | 99.5% |
| Replace 504 source chunks, one changed | 84.161 ms | 0.523 ms | 99.4% | 99.3% |

The rotating workload has 160 measured queries per representation/version. Each scale
query has 40 measured samples per treatment; each update type has 38. A warmed single
real-source query remains approximately unchanged: full text 0.945 → 0.952 ms and
windows 0.916 → 0.903 ms. Cold/uncached source queries change by only a few percent.
Selective warm queries remain approximately 5–6 microseconds. Initial indexing remains
approximately unchanged: the two 50k build observations are 207.8/202.7 ms baseline
and 205.7/197.0 ms candidate. These small sample counts do not establish a significance
claim for small differences.

The rotating working set reaches 1,362 cache entries and 2,238,384 retained text bytes,
with zero measured misses in the candidate. The baseline is capped at 1,024 entries
and reaches 1,781,035 retained text bytes. Maximum whole-process RSS across the full
warm/cold/uncached corpus is 218.1 MB baseline versus 235.4 MB candidate (**8.0% higher**);
the median process peak rises 5.3%. This is a throughput/memory tradeoff. Callers can
retain the old cache limit explicitly; that does not remove the internal slot index.

Across the 16 real-source requests, compact rendering uses 17,472 tokens versus 17,785
in the full snapshot rendering: **1.76% fewer**, with identical selected text. This
corpus is dominated by source text, so a 50% prompt-token reduction is not demonstrated.
Required/counterclaim text is never dropped to improve that number.

## Correctness and bugs

All **8,604 complete candidate-result comparisons** match the baseline over **1,434
distinct requests**: 1,226 successful snapshots and 208 expected errors per pass.
The original 1,034-request corpus is retained, with 400 additional queries over larger
seeded graphs. Cache modes, source updates and opposite run orders retain the same
results. Rotating-query snapshot commitments and 40 update/revision/commitment results
per version/round also agree. **Zero unexpected runtime bugs or retrieval regressions
were found in this qualification corpus.**

Targeted regression tests cover dense authorization after withdrawal and slot reuse,
unchanged source revisions, atomic rejection, hard-edge retention, compact prompt
aliases/Unicode/source preservation, exact budgets, tampering and snapshot mismatch.
Both SDK suites exercise the new prompt methods against a real Rust worker.

These counts describe this core qualification, not 50 end-to-end Hiero runs on 0.10.1,
live-model evaluation, or successful EVM runtime validation. The previous workflow
results must not be relabelled as tests of this candidate.

## Release qualification

Core and local SDK package identities are stable `0.10.1`. The macOS ARM64 wheel and
npm package bundle the matching worker; other platforms need an explicit worker.
Python supports 3.14.x; TypeScript supports Node 24.10–24.x ESM. Honey and the remote
Rust/Go SDKs retain 0.9.4.

The [stable release workflow](../.github/workflows/context-sdk-release.yml) builds
twice on the candidate branch. Publication runs only for the exact `v0.10.1` tag
and requires byte-identical independently qualified archives/workers, installed and
offline SDK oracles, older SDK compatibility, dependency advisory checks, license
notices, SBOMs and exact-commit signed provenance. Beta verification retains its
original signing identity. Local preparation does not publish or sign packages;
the final candidate artifact report records the actual qualification status.
