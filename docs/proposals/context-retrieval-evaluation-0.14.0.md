# Scoped retrieval adapters and independent evidence evaluation

Status: registered design; the [first independent study](../release/context-sdk-0.14.0-retrieval-evidence.md)
is complete and reports gains, costs and a stronger flat-retrieval control.
This addresses part of the R1/E2 work. It does not replace
the broker fault/load gates or the separate Hiero terminal-outcome evaluation.

## Reuse the existing ranking boundary

`ContextRequest.semantic_candidates` already accepts an ordered list of IDs.
The Rust selector filters IDs by the current authorized set and combines rank
with lexical signals. This is an existing extension point, including in prior
versions; do not market a new helper as a new retrieval engine.

Provide a concrete offline adapter example and a documented input/output
contract before adding another core protocol or runtime dependency:

- The trusted application supplies source records, current source revisions and
  an explicit scope. Restrict records **before** indexing, calculating corpus
  statistics, ranking or invoking any optional external component. A global
  retrieval pass followed only by output filtering is insufficient for privacy.
- Return bounded, unique ranked IDs. Scores are ranking signals, never truth
  probabilities, reviews, authorization or permission to execute an effect.
- The current CIGAR view/grant remains the final authorization boundary. Keep
  the query, exact token budget, required evidence and policy under their existing
  contracts. An adapter cannot silently widen them.
- Bind any cached index to its exact scoped corpus, policy and tokenizer/ranker
  identity. A source change, withdrawal, policy change or restart requires an
  explicit refresh. Never silently call a provider or discover credentials.
- Start with a dependency-free reference ranker and caller-owned precomputed
  ranks. Model-backed integrations remain explicit optional application choices.
  Do not add a default ranker without measured benefit on unseen labels.

The example must test unauthorized records before the callback, malformed/duplicate
IDs, bounded input/output, deterministic ordering, empty results, source changes
and the production compiler's final authorization check. Existing APIs, worker
protocols and canonical valid fixtures remain unchanged.

## Independent corpus

Use the original SciFact release as a bounded evidence-selection study. Its
published data defines claim text, evidence documents, support/contradiction
labels and sentence rationales; cited-document IDs can include papers without
annotated evidence. The scorer must use evidence annotations, not equate citation
with support. [SciFact data specification](https://github.com/allenai/scifact/blob/master/doc/data.md).

The original development split has public labels; its test split does not.
Freeze the original development set as held-out for this library study and call
it that, rather than claiming official test-set performance. No tuning on its
results, and no leaderboard submission or provider request.
[SciFact dataset instructions](https://github.com/allenai/scifact#dataset).

Retain upstream attribution and license records: the project declares CC BY 4.0
for claim/evidence annotations and ODC-By 1.0 for its S2ORC-derived abstracts.
Keep the raw downloaded archive outside the CIGAR source distribution, inspect
only bounded regular members and hash every used input before evaluation.
[SciFact licensing](https://github.com/allenai/scifact/blob/master/LICENSE.md).

Acquire through the dataset owner's documented archive URL, recording retrieval
time, byte count and SHA-256. Never execute the upstream download script. Archive
inspection must determine actual counts and split overlap; do not assume the
BEIR reformatted subset and the original rationale task have identical labels.
The data-acquisition step is separate from offline execution. No live model or
service participates in the evaluation.

## Controls and leakage prevention

Before reading held-out labels or reporting scores, freeze all candidate bytes,
ingestion rules, ranker parameters, tokenization and treatment configuration.
Use the same corpus text/order and context budgets of 512, 2,048 and 4,096 tokens.
Use full abstract documents in the first study; any sentence chunking experiment
is a separately registered treatment with stable paper/sentence mappings.

Include these controls:

1. Exact released v0.12 ordinary graph and its default selector.
2. v0.14 ordinary graph with the same request and default selector.
3. A flat lexical ranker using the same source text and exact rendered-token
   accounting, with its complete implementation and parameters recorded.
4. Explicit ranked candidates through the existing hook. If the same adapter
   works with v0.12, run that control too; do not attribute its generic ranking
   benefit to the version number.

Do not ingest labels, gold IDs, rationales, `cited_doc_ids` or claim-derived graph
edges. Required evidence is empty for normal retrieval treatments. Any oracle
upper bound is a separate treatment clearly excluded from product comparisons.
An external ranker may supply predicted IDs to a budget-selection control, but
it must never receive relevance annotations. Retain failures and no-evidence
cases instead of dropping them from the experiment.

The reference lexical adapter is preregistered as BM25 (`k1=1.2`, `b=0.75`), with
NFC/case-folded Unicode alphanumeric terms, no stemming/stopwords, unique query
terms and UTF-8 ID tie breaking. Only abstract/title text supplied uniformly to
all treatments becomes an index feature. Source labels and document IDs are not
features. Build the index once from scoped records; record build latency and RSS
separately from query latency. The packaged recipe supports an explicit caller
callback and precomputed candidates without changing the compiler's defaults.
The [adapter guide](../../sdk/RETRIEVAL_ADAPTERS.md) records input limits and trust
boundaries. Freeze its exact source before reading held-out annotations.

Use the first 64 predicted IDs for ranked-candidate treatments, with the ordinary
request's 256 candidates, 16 blocks, depth two and full-document representation.
The flat control packs the longest BM25-ordered prefix fitting the same exact
rendered budget, stopping at its first non-fitting document or 16 documents.
It uses CIGAR's `required` field only as a budget/rendering oracle for those
predicted IDs, with an empty query and no edges; it never uses annotated IDs.
For an empty prefix only, use a fixed nonempty query with `allowed=[]`, because
the API rejects an empty query together with empty required IDs. This cannot
retrieve any document. Use the ordinary default of one witness per query term
uniformly across treatments.
An oversized first document therefore yields an empty flat prefix. Record this
as a baseline packing limit, not a failed worker or evidence of abstention quality.
Use the v0.12 renderer for that control and report its extra packing calls/time.
Create no claim-derived edges in any treatment. Ingest records in numeric paper
ID order; text is title, LF, then the original abstract sentences joined by LF.

## Report and acceptance

Measure document-evidence recall/precision, claim-level evidence hit rate,
complete-rationale coverage, selected citation/text fidelity, budget failures,
rendered tokens, latency and host-plus-worker RSS. Report support, contradiction
and no-annotated-evidence strata separately, with defined zero-denominator
behavior. Retrieving relevant evidence is not the same as producing a correct
answer; no hallucination, confidence-calibration or task-success rate can be
inferred without actual independently labeled outputs/outcomes.

Paired claim comparisons must preserve clusters shared through evidence papers;
do not treat repeated timing calls as new relevance observations. Bind the study
to the existing common evaluation contract, raw predictions and exact oracle
files. Compute oracle-derived metrics only after treatment predictions are frozen.

The ordinary v0.14 API must preserve valid v0.12 retrieval, citations, errors and
budgets. Investigate every difference rather than accepting an average that
hides a correctness loss. The optional adapter can be recommended as an efficacy
improvement only if its matched-budget evidence gain has a positive paired
interval and its contradiction stratum does not regress. Otherwise retain it as
an integration example with its limitations or omit the recommendation; keep
the default unchanged. Publish its additional latency/memory cost explicitly.

SciFact is a scientific evidence-retrieval domain, not a representative software
agent workload or a semantic truth oracle for all subjects. It supplies one
independently annotated slice. The Hiero executable-task oracle and separately
labeled answer study remain outstanding for broader E2 claims.
