# Retrieval indexes and authorization

WP06 treats every index as a disposable projection of canonical catalog state. A build contains a
complete atom/edge snapshot, catalog revision, analyzer/projection configuration digest, verification
time, and optional vector fingerprint. It is not servable while building. Verification computes a
semantic root over sorted immutable versions, content digests, lifecycle, and graph adjacency. Only
a verified root can be atomically selected as the active generation. Quarantined generations cannot
be activated, and deleting the active generation is forbidden.

## Causal updates and consistency

`IndexWorker` consumes ordered `catalog.committed` outbox records idempotently. It loads the complete
canonical snapshot at the highest newly claimed causal revision, builds and verifies a disposable
generation, activates it with an expected-active compare, and advances its watermark only after that
activation succeeds. An interruption leaves the prior active generation and watermark unchanged;
the same records can then be retried.

A strong request returns candidates only when the active generation is built through the pinned
catalog revision. A bounded-stale request names an exact maximum revision lag. Every successful batch
discloses the generation ID, index fingerprint, built-through revision, actual revision lag, fallback
state, and last verification time. There is no implicit eventual mode for governed retrieval.

## Authorization-first channels

The frozen partition includes tenant, visible projects, purpose, processor, maximum classification,
maximum instruction authority, world-valid time, observation-time bound, vector permission, and a
policy decision digest. Lifecycle, scope, purpose, processor, classification, authority, validity,
and observation time are checked before a channel produces candidates. Exact, path/declared term,
lexical, graph, active-state/augmentation, and optional vector stages operate only on the resulting
partition.

Candidate references expose an immutable version, authorized source coordinates, integer feature
vector, checked score, and content-free match evidence. Their debug forms omit query text and paths.
Denied atoms cannot affect candidate counts, vector allowed-version sets, or caller-visible
diagnostics.

## Planning, caps, and vectors

`QueryPlanner` turns exact selectors into mandatory exact stages and query selectors into independent
metadata and lexical stages plus an optional vector stage. Each stage records a query fingerprint,
candidate cap, timeout, fallback rule, required watermark, and blocking disposition. The staged
executor uses the lesser of the parent and stage deadline and rejects a backend that exceeds its cap.

Vector adapters are optional and identified by model, dimensions, normalization, and preprocessing
fingerprint. The adapter request contains the policy partition digest, normalized query terms, and
only version IDs already admitted by metadata authorization—never atom payloads. Returned neighbors
must remain inside that set and use an integer similarity from 0 through 10,000. Processor denial,
fingerprint mismatch, out-of-partition neighbors, or invalid scores fail closed. Vector-disabled and
permitted-outage paths remain deterministic and do not change atom identity.
