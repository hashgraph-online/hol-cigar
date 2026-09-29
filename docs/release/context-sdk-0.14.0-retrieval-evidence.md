# v0.14 independent evidence-selection study

The candidate preserves v0.12 retrieval results exactly on this study. Adding the
reference BM25 ranks improves annotated-evidence recall at larger budgets, but
the flat BM25 control performs better than CIGAR's existing rank blending at all
three budgets. This is a measured retrieval limitation, not a reason to claim a
new default-ranking improvement in v0.14.

## Inputs and controls

The original SciFact archive contains 5,183 scientific abstracts, 809 training
claims, 300 development claims and 300 test claims, with disjoint claim IDs. The
study uses all 300 development claims, held out for this library evaluation. Its
labels include 124 support cases, 64 contradiction cases and 112 cases with no
annotated evidence. The latter are not discarded or treated as proven negatives
for every corpus document. Claims connected through shared gold papers form 276
clusters. These are public development labels, not the official hidden test set.

The [registered design](../proposals/context-retrieval-evaluation-0.14.0.md) fixes
the tokenizer, BM25 parameters, source representation and budgets before scoring.
The corpus uses titles plus complete abstracts; no labels, rationales,
`cited_doc_ids` or claim-derived edges enter retrieval. The independent oracle
uses the dataset's evidence annotations, not its broader citation lists.
[SciFact data specification](https://github.com/allenai/scifact/blob/master/doc/data.md).

Five treatments run at 512, 2,048 and 4,096 tokens: released v0.12 default,
candidate default, the same optional BM25 adapter on each, and a flat BM25 prefix
packed by the released v0.12 exact renderer. The last control stops at the first
non-fitting paper and uses only predicted IDs in `required`. It is an application
control available with v0.12, not a v0.14 feature or a gold-ID upper bound.

All **4,500 attempts** succeed. Every selected citation preserves its original
text and line range, and every result fits its registered budget. Native snapshot
verification also succeeds. All **1,800 version pairs** have identical complete
results for default and adapter treatments: snapshots, rendering, citations and
statistics. No relevance label was used to tune or change the ranker after this
study. No model, provider or HOL service was called.

## Quality and cost

Recall is the fraction of annotated claim/paper evidence pairs retained. Precision
is agreement with the annotation inventory among selected claim/paper pairs; it
does not establish that every unannotated paper is irrelevant or false. The same
quality values apply to v0.12 and the candidate for their matched treatments.

| Token budget | Default recall | BM25 through existing hook | Flat BM25 recall |
| --- | ---: | ---: | ---: |
| 512 | 8.13% | 8.13% | 47.37% |
| 2,048 | 45.93% | 64.59% | 81.34% |
| 4,096 | 46.41% | 77.99% | 89.47% |

| Token budget | Default precision | BM25 through existing hook | Flat BM25 precision |
| --- | ---: | ---: | ---: |
| 512 | 2.93% | 2.92% | 34.26% |
| 2,048 | 6.61% | 6.18% | 10.89% |
| 4,096 | 6.43% | 4.05% | 5.68% |

At 2,048 tokens, the fraction of evidence-bearing claims with at least one gold
paper is 50.53% default, 69.68% through the hook, and 88.30% flat. At 4,096 tokens
those values are 51.06%, 84.04% and 94.68%. Complete-rationale coverage at 2,048 is
45.27%, 61.83% and 81.66%. Because each selected paper contains its whole abstract,
this last metric largely follows paper retrieval; it is not a sentence-reasoning
or answer-correctness result.

The extra evidence uses more of the allowed budget. At 2,048 tokens, median
rendered usage is 1,309.5 default, 1,974 through the hook and 1,845 flat. Extra
recall therefore must be considered alongside precision and resource cost.

| Budget | Default median query ms | Hook median query ms | Flat median query ms |
| --- | ---: | ---: | ---: |
| 512 | 15.97 | 26.07 | 5.63 |
| 2,048 | 5.77 | 28.87 | 7.74 |
| 4,096 | 5.47 | 32.66 | 13.62 |

These timings include ranking plus compilation/packing, with index construction
reported separately. They are informational sequential runs, not the paired
process cohorts required for Q1. Reference-index construction takes 389–452 ms.
At 2,048 tokens, sampled total host-plus-worker RSS is 355.3 MiB default,
419.0 MiB through the hook and 413.3 MiB flat. RSS uses 50 ms samples, not exact
allocation peaks or proportional-set size. The adapter is not a free quality gain.

## Uncertainty and adverse results

Paired intervals resample whole shared-paper clusters, never repeated RPC calls.
The support stratum has 120 clusters and contradiction has 62; some clusters can
span strata. At 2,048 tokens, hook-minus-default mean cluster recall gains are
21.53 percentage points for support (descriptive 95% interval **14.58–28.89**) and
16.67 points for contradiction (**8.06–26.88**). At 4,096, they are 34.24 points
(**26.46–42.71**) and 29.30 points (**18.55–40.32**). At 512, neither stratum gains
recall. These cluster means differ from the pooled recall values in the table.

Precision falls in the support stratum at both larger budgets and in the
contradiction stratum at 4,096. The flat control has higher recall than the hook
in both strata at every budget; all six paired recall intervals favor flat.
At 2,048 tokens, hook-minus-flat mean cluster recall is -18.16 points for support
(**-25.24 to -11.91**) and -15.81 points for contradiction (**-27.42 to -4.19**).
These losses remain part of the release evidence.

The overall recall/hit/rationale paired interval is explicitly unavailable in
the common report because the 112 no-annotated-evidence cases have zero recall
denominators. Those cases remain in the inventory and in failure, budget,
precision and resource summaries. The stratum intervals above are reported
without replacing unavailable overall intervals or redefining the population.

## Engineering decision

Retain the default selector for compatibility. Keep the scoped adapter as an
explicit integration example and describe its measured costs and limitations.
Its benefit at larger budgets is available on v0.12 too; version numbering does
not create that efficacy gain. Do not recommend this blend as the best retriever
for scientific claims or as an automatic answer-quality improvement.

Applications that already have strong ranks need to understand that
`semantic_candidates` blends signals rather than preserving their order. The
flat control is a useful baseline for such applications. A future explicit
rank-preserving selection policy should preserve authorization, required graph
closure, counterevidence and exact budgets, then be qualified on a newly frozen
independent corpus. Do not tune a replacement on these exposed labels and reuse
this split as unseen evidence.

This study covers evidence retention in one scientific domain. It does not
measure confident hallucinations, semantic truth judgment, a 12-agent task's
completion or general superiority over retrieval systems. The broker/provenance
improvements have their own tests. Independent Hiero terminal outcomes, version
performance guardrails, installed artifacts and the long soak remain required.

## Retained evidence and reproduction

Evidence is outside the repository under
`CIGAR/releases/cigar-0.14.0-development/scifact-independent-02`. It contains the
original archive/license, acquisition record, frozen source/runtime bytes, all
15 prediction files, their seal, exact version-parity checks and twelve common
comparison reports. See [reproduction instructions](../../benchmarks/SCIFACT.md).

- Baseline: released wheel from commit `940fc65ee11ccda957649d7e5f1de5a4fa88e07a`.
- Candidate SDK source: `d19fd39ff82cc1af2c46f3271b420ef00ae9f364`; retained native
  worker built at `059c0155385da5b2012b361d99a1ff8730e39199`. Both hashes are bound
  independently; the candidate remains development source, not installed v0.14.
- Python 3.14.7 and protobuf 6.33.5 for every treatment, macOS ARM64.
- Registration SHA-256: `1c24ba24436d801ae00aff1be855a904204dccbf18c3ff5a1a1b2ed478716e82`.
- Archive SHA-256: `11c621288d41ac144d29b13b0f8503b3820b7d6e8b1f6ff24dff335c196d76be`.
- Oracle SHA-256: `86f0435d08fdb65d1aa41d1472684f57e6e71930626497bdf4d7a9ec1a632217`.
- Harness SHA-256: `c93588b5f34c77f8f6c71ab1a1e58208a5ad1150608bfaa8d6df827f329871f1`.
- Scorer SHA-256: `577c1d1a87cd765b1f48113e853db47ded4148a05ebaeb65bc6254fd9c9762b7`.
- Adapter SHA-256: `168972e8dce7317b4085668348f608a5d6620f22cc1588bae5f11c7366726ced`.
- Prediction seal SHA-256: `f8c7ef7d1700c88c55e2726224316d22549912cc52552fba8b4e5847e4bf30b0`.

The initial `scifact-independent-01` stopped during preparation because a training
claim has ID zero. Its archive and disposition remain retained; no predictions or
gold scores were generated. A parser-only correction accepts nonnegative integer
claim IDs and preserves duplicate/overlap rejection. The replacement study uses
the identical archive and ranking configuration. Authored smoke runs separately
document the earlier flat-control validation correction. No failed run was pooled
into the completed study.

SciFact annotations are CC BY 4.0; S2ORC-derived abstracts are ODC-By 1.0.
The [upstream license notice](https://github.com/allenai/scifact/blob/master/LICENSE.md)
is retained with the data. No raw corpus is added to the CIGAR package or public
source branch.
