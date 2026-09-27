# Application-owned retrieval

CIGAR accepts ranked document IDs through the existing `semantic_candidates`
request field. The compiler combines these ranks with its lexical and graph
signals, applies the current scope, and selects complete evidence within the
exact rendered token budget. Ranks do not override required dependencies,
counterevidence, source freshness, reviews or authorization. This extension point
also exists in v0.12; a new example does not make it a new retrieval engine.

Use an external index or reranker when a measured workload benefits from it.
There is no provider discovery or model dependency in the library. Ordinary
compilation keeps its existing ranking behavior.

## Scope before ranking

The trusted host first selects records for the agent's current view or grant.
Build corpus statistics, embeddings, indices and callback inputs from those
records alone. Retrieving against a global index and filtering its output does
not protect the query, private text or private corpus statistics from that index.

Keep policy capture, record capture and request construction consistent under
the application's existing host ownership/locking rules. The worker independently
checks the current grant on compilation. An in-process callback is trusted code;
a snapshot object does not sandbox it or retract text it has already received.
Untrusted agents receive only their permitted text and capability over protected
IPC, never the global record map or the host's authority.

The packaged Python example provides a bounded snapshot, candidate validator,
explicit callback port and dependency-free reference BM25 ranker:

```python
from cigar_sdk.examples.scoped_retrieval import (
    RetrievalDocument, ScopedBM25, ScopedCorpus,
)

# Values come from the host's admitted source inventory, not model-supplied scope.
records = {
    "retry-policy": RetrievalDocument(
        "retry-policy", "policy", "revision-7",
        "Retry using the same operation identifier.",
    ),
}
scope = ScopedCorpus(
    records,
    allowed=["retry-policy"],
    policy_revision="agent-policy-3",
)
index = ScopedBM25(scope)
query = "How should retries preserve operation identity?"
result = agent_view.compile({
    "query": query,
    "semantic_candidates": index.rank(query, limit=64),
    "max_candidates": 256,
    "max_tokens": 2048,
})
```

Here `agent_view` is a host-created `LocalContextView` or a restricted broker
client. An ordinary `LocalContextGraph` instead needs the host's explicit
`allowed` IDs in its request. The example never creates a view/grant or admits
records into a graph on the caller's behalf.

For your own ranker, use `scope.rank_with(query, callback, limit=64)`. The callback
receives the query, an immutable tuple of scoped records and the requested limit;
it returns an ordered sequence of unique IDs from that snapshot. Unknown,
duplicate, oversized or malformed output fails instead of silently broadening
scope. Alternatively validate explicit precomputed IDs with
`scope.checked_candidates(ids, limit=64)`. The caller owns callback timeouts and
any external disclosure. A model's similarity score is never a truth probability
or an answer-review verdict.

The same field is available in Node, with application-owned scoped retrieval:

```typescript
// scopedRecords was prepared by the trusted host for this client alone.
const ids = await applicationRanker(query, scopedRecords, 64);
const allowed = new Set(scopedRecords.map(record => record.id));
if (ids.length > 64 || new Set(ids).size !== ids.length ||
    ids.some(id => typeof id !== "string" || !allowed.has(id))) {
  throw new Error("invalid ranked candidates");
}
const result = await agentClient.compile({
  query, semantic_candidates: ids, max_candidates: 256, max_tokens: 2048,
});
```

Validate the callback's runtime result type before this typed example if it comes
from an untyped boundary. Neither SDK treats external ranks as authority. Final
scope enforcement also holds when a caller bypasses the example's validator.

## Index identity and refresh

`ScopedCorpus.identity` commits to the exact scoped IDs, source identities,
source revisions, text, policy revision and reference tokenizer/ranker identity.
Input ordering and changes to unselected records do not change it. Source text,
revision, withdrawal or policy changes require a new snapshot and index. Do not
infer the host's current source state from this hash: it is neither a signature
nor a live authorization check. Include the broker epoch in the supplied revision
or policy identity when using durable broker sources.

An external cache key also needs the exact query, requested limit and external
ranker/model version. Do not reuse cached candidates across privacy domains or
policy revisions. No cache is enabled implicitly by the example.

The reference index uses NFC plus Unicode case folding, alphanumeric terms, no
stemming or stopwords, unique query terms and BM25 with `k1=1.2`, `b=0.75`.
It indexes document text only, breaks ties by UTF-8 ID order and returns only
positive lexical matches. Those are fixed baseline choices, not tuned efficacy
claims. CIGAR still uses its own tokenizer to enforce the final context budget.
The parameters and IDF convention follow the published
[Lucene BM25 description](https://lucene.apache.org/core/10_3_1/core/org/apache/lucene/search/similarities/BM25Similarity.html);
this example is not a Lucene implementation or a cross-runtime score contract.

The recipe bounds scoped input to 100,000 documents, 1 MiB of UTF-8 per document
and 64 MiB including record identities, with a 16 KiB/64-term query and at most
256 candidates. Index memory exceeds input bytes because it stores postings.
The ranker is illustrative application code, not a stable top-level SDK API.
Measure its extra indexing/query cost and evidence quality at the same context
budget before adopting it. An independent retrieval study is registered in the
[evaluation plan](../docs/proposals/context-retrieval-evaluation-0.14.0.md);
no measured gain or reduced hallucination rate is established by the example.
