# cigar-retrieval

Stability: kernel, pre-v1. Owns authorized query planning and bounded exact, lexical, temporal, graph, and vector retrieval.

The crate builds complete immutable projection generations, verifies their semantic root, catches
up causal catalog outbox records, and atomically activates one generation. Every candidate request
is fixed to an authorization partition and a strong or explicitly bounded-stale catalog revision.
Candidates contain references, quantized features, evidence, and an exact generation disclosure;
they never contain unrestricted atom payloads.

`QueryPlanner` expands each requirement into independently capped exact, metadata, lexical, and
optional vector stages. `StagedRetrieval` applies the per-stage deadline and blocking semantics.
`InMemoryIndexManager` is the hermetic reference projection manager. Optional `VectorAdapter`
implementations are fingerprint-bound and receive only the semantic versions admitted by the hard
metadata gate. A missing, mismatched, or failed adapter can degrade to metadata retrieval only when
the planned request explicitly permits fallback.

See [`docs/reference/retrieval-indexes.md`](../../docs/reference/retrieval-indexes.md) for the
generation, consistency, authorization, and processor-confinement contracts.
