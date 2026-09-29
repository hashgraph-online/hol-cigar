# Selection explanations (0.14 development)

Use an explanation to inspect how the selector assembled an existing context.
It reports successful selection steps and the exact tokenizer identity. It does
not assess whether the evidence is true or supports an answer. Answer review and
effect authorization remain separate operations.

No service, model provider or additional dependency is required. The worker must
advertise `selection_explanation.v1`. This is a development API; installed release
qualification is pending.

```python
from cigar_sdk import LocalContextGraph

with LocalContextGraph("project") as graph:
    graph.upsert({"id": "retry-rule", "source": "policy", "text": "Reconcile an unknown effect before retrying."})
    request = {"query": "unknown effect retry", "max_tokens": 256}
    result = graph.compile(request)
    explanation = graph.explain(request, result["snapshot"])
    assert explanation["snapshot_id"] == result["snapshot"]["id"]
```

```typescript
import {LocalContextGraph} from "@hol-org/cigar/context";

await using graph = await LocalContextGraph.create("project");
await graph.upsert({id: "retry-rule", source: "policy", text: "Reconcile an unknown effect before retrying."});
const request = {query: "unknown effect retry", max_tokens: 256};
const result = await graph.compile(request);
const explanation = await graph.explain(request, result.snapshot);
```

The versioned `cigar.context-selection-explanation.v1` record contains:

| Field | Meaning |
| --- | --- |
| `snapshot_id` | Exact original snapshot being explained |
| `request_id` | Domain-separated digest of the exact native request, including its defaults |
| `checked_graph_revision` | Current revision when the worker validated the explanation |
| `tokenizer` | Algorithm/vocabulary identity used for exact context-text token counts |
| `steps` | Actual successful selection steps, in order |

Each step has a `root_id`, sorted `added_ids`, and `signals`. Added IDs cover each
selected document exactly once, including hard dependencies and counterevidence.
Identical text may occupy one physical block while retaining several source IDs.
The root is the candidate actually chosen by the selector. With a symmetric
contradiction edge, that may be the graph neighbor of the original lexical match.

| Signal | Meaning |
| --- | --- |
| `required` | The request explicitly required this root and its complete hard closure |
| `lexical_match` | The root's indexed text or locator matched a query term |
| `declaration_match` | The lexical declaration heuristic recognized a matched identifier; this is not an AST guarantee |
| `semantic_candidate` | The root came from the caller's ranked `semantic_candidates` input |
| `graph_expansion` | The root came from bounded expansion of graph relations |

These are retrieval signals. No signal or numeric rank means that a claim is
supported, independently corroborated, safe to execute, or likely to be correct.
The trace contains no similarity scores, truth probabilities, query text, source
text, source locators or rejected candidate IDs. It does contain selected IDs,
which can be sensitive: apply the context's disclosure policy and avoid logging
the record indiscriminately. It is not a signature or an independent audit receipt.

## Views and independent agents

For a host-owned view, call `view.explain(result["context"])` in Python or
`view.explain(result.context)` in Node. For an authenticated broker client, call
`client.explain(result["ticket"])` or `client.explain(result.ticket)`.

Broker clients supply only their own ticket. They cannot submit a different view,
request or snapshot to that operation. The broker checks current ownership,
grant expiry/revocation, source provenance and the entire readable scope before
returning anything. Expired, forgotten, foreign, revoked or stale tickets fail.
An ordinary view likewise revalidates its whole readable scope, including
unselected evidence. Root-graph explanations require the exact current snapshot.

An out-of-scope write can preserve a view or broker ticket. Its explanation keeps
the original `snapshot_id` and reports the newer `checked_graph_revision`. A
provenance-only update inside a broker's scope invalidates the ticket even when
document text is identical. Snapshot integrity alone is insufficient.

## Cost and reproducibility

An explanation recompiles under current authority and records the successful
selection steps. It reconstructs the supplied request; it is not a historical log
of a previous call. If it no longer reproduces the original evidence, it fails.
It neither changes ranking nor adds fields to the existing snapshot/request ABI.
Ordinary compilation allocates no trace. Explanation requests consume normal
worker time and queue capacity and are best used when inspection is needed.

External retrieval remains opt-in through ranked `semantic_candidates` IDs. The
host must scope the external index and any provider disclosure before retrieving;
CIGAR's later ID filtering cannot undo data sent to a provider. Ranking never
widens a view and cannot omit a selected root's required counterevidence. The
library does not call a retriever automatically or claim a task-quality gain from
the presence of a semantic signal.

The tokenizer count applies to rendered context text. Reserve separately for
system instructions, history, output and provider framing; an o200k identity is
not proof of compatibility with an arbitrary model's tokenizer.
