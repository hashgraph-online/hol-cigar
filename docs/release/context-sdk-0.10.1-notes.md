# CIGAR 0.10.1

This release improves the standalone `cigar-context` Rust library and its local
Python (`hol-cigar==0.10.1`) and TypeScript (`@hol-org/cigar@0.10.1`) SDKs. The
compatible remote v1 API surface and the separate Honey 0.9.4 runtime remain intact.

## Changes

- The default exact-token cache holds 2,048 entries under the same 8 MiB text cap.
  Reuse the graph/tokenizer across calls to benefit from it.
- Common-term queries accumulate exact scores in reusable document slots. Ranking,
  authorization, hard dependencies, citations, statistics and snapshot IDs retain
  their previous semantics. Sparse queries keep the small-query path.
- `replace_source` / `replaceSource` retains unchanged indexed documents and stages
  only changed ones. Duplicate IDs, cross-source collisions, capacity failures and
  invalid input still leave the graph unchanged; withdrawn hard edges fail closed.
- Optional `prompt_view` / `promptView` renders every selected text block with short
  citation handles and source ranges. Keep the full snapshot and citation map;
  verify or resolve handles against the expected authorized snapshot. The view has
  a separate exact budget and fails if it cannot fit, without truncating evidence.

## Measured performance

The retained same-host comparison against commit
`11c38b0ba4fa00e1a03cad99ca316a875a03babd` uses identical registry dependencies,
counterbalanced run order, 1,434 distinct requests and 8,604 exact candidate-output
comparisons. All snapshots and expected errors agreed.

| Workload | 0.10.0 median | 0.10.1 median | Latency reduction |
| --- | ---: | ---: | ---: |
| Rotating source queries, full chunks | 8.817 ms | 1.366 ms | 84.5% |
| Rotating source queries, windows | 6.309 ms | 1.260 ms | 80.0% |
| Common-term query, 50,000 documents, warm | 23.978 ms | 4.541 ms | 81.1% |
| Replace 504 unchanged source chunks | 66.685 ms | 0.285 ms | 99.6% |
| Replace 504 source chunks, one changed | 84.161 ms | 0.523 ms | 99.4% |

These are workload-specific timings, not a universal speed guarantee. Whole-process
peak memory in the full comparison increased 8.0%; the cache text cap is
unchanged. A repeated single query was approximately unchanged. Compact rendering
saved 1.8% of tokens in the real-source corpus; savings depend on citation overhead.
There is no new model answer-quality claim. See
[`reports/cigar-0.10.1.md`](../../reports/cigar-0.10.1.md) and
[`benches/context-011`](../../benches/context-011) for evidence and reproduction.

## Packaging and compatibility

The platform wheel and npm archive bundle the matching worker for macOS ARM64.
Python supports 3.14.x; TypeScript supports Node 24.10 through Node 24.x, ESM.
Other platforms need an explicit trusted worker built from the matching source.
The macOS 11 deployment floor is not a test result on macOS 11. There are no install
scripts or runtime binary downloads. Worker IPC and process memory remain additional
costs compared with embedding Rust directly.

The stable workflow requires two separately qualified hosted builds with identical
archive/worker bytes, fresh installed-consumer checks, the older SDK compatibility
suite, OS-enforced offline oracles, current dependency-advisory results, license
notices, CycloneDX/SPDX inventories and exact-tag/commit signed provenance. Local
archives are unsigned candidates until that workflow completes. Registry publication
is a separate operation. This change does not authorize or perform publication.
