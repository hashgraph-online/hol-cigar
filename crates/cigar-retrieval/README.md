# cigar-retrieval

Stability: kernel, pre-v1. Owns authorized query planning and bounded exact, lexical, temporal, graph, and vector retrieval.

The crate builds complete immutable projection generations, verifies their semantic root, catches
up causal catalog outbox records, and atomically activates one generation. Every candidate request
is fixed to an opaque, live policy authorization and a strong or explicitly bounded-stale
tenant-local catalog revision. The proof binds the authenticated principal, tenant, projects,
purpose, processor, classification and instruction-authority ceilings, bitemporal selectors,
capability grant, policy snapshot, revocation epoch, and a short engine-capped lifetime. It is
revalidated before index access, for every canonical record, and again before disclosure.
Candidates contain references, quantized features, evidence, and an exact generation disclosure;
they never contain unrestricted atom payloads.

Lineage histories are tenant-scoped. Retrieval first resolves the latest version at the authorized
valid/observation time, then applies that winner's lifecycle and governance. A later tombstone,
project move, purpose/processor restriction, or classification increase therefore suppresses the
older version without destroying historical as-of retrieval. Per-version governance indexes avoid
combining permissions from different versions. Graph traversal uses only authorized current
lineages and exact authorized version-pair edges; optional vector adapters iterate only the
authorized version set.

Each generation carries explicit per-tenant causal watermarks, including known empty tenants.
Freshness and disclosed lag use only the requesting tenant's watermark, so another tenant's commit
cannot alter a result, work receipt, or disclosure. Caller-visible generation identities are roots
of the authorized current documents and authorized edge topology. Vector-stage identities also bind
the complete optional vector generation/fingerprint; denied documents and edges do not perturb
these identities. Errors and debug surfaces expose stable categories and bounded counts, not denied
identifiers, paths, content, query text, policy selectors, or vector commitments.

`QueryPlanner` expands each requirement into independently capped exact, metadata, lexical, and
optional vector stages. `StagedRetrieval` applies the per-stage deadline and blocking semantics.
`InMemoryIndexManager` is the hermetic reference projection manager. Optional `VectorAdapter`
implementations are generation/fingerprint-bound and receive only a processor-approved bounded
quantized query plus the semantic versions admitted by the hard metadata gate. They never receive
atom payloads or unrestricted query text. A missing, mismatched, or failed adapter can degrade to
deterministic lexical and declared-metadata retrieval only when the planned request explicitly
permits fallback.

`SealedLocalVectorAdapter` is the first provider-neutral local implementation. Its default
configuration boundary is `LocalVectorAdapterEnablement::Disabled`; the macOS daemon installs it
only through an explicit local-only configuration section. Explicit enablement seals an in-memory
map whose fingerprint binds adapter version, model ID and artifact fingerprint, dimension,
preprocessing ID and implementation fingerprint, integer distance metric, quantization, policy
partition, vector generation, resource caps, version IDs, and vector commitments. It uses checked
integer arithmetic and stable version-ID tie ordering. This implementation loads no model and makes
no semantic-quality claim: an authorization-approved processor must supply already-quantized
vectors.

The adapter is a development implementation for the initial macOS cohort, not a packaged or
cross-platform surface. The macOS-only `DurableLocalVectorStore` is wired into the local daemon
behind disabled-by-default strict configuration; there is no CLI toggle. It stores bounded
canonical version IDs and processor-approved quantized vectors in immutable generation directories,
binds canonical data and manifest digests into an explicit current-generation record, and verifies
exact model, preprocessing, metric, quantization, partition, generation, watermark, and
sealed-adapter commitments on restart. Publication uses owner-private no-follow descriptors, file
and directory synchronization, no-replace generation rename, and atomic activation rename.
Incomplete or corrupt state is quarantined; missing, stale, or invalid activation returns no adapter
so an already-authorized caller can use deterministic lexical fallback. Startup fully verifies only
the selected generation; inactive generations receive a constant-cost structural screen and are
fully verified if later activated. Quarantine retention is fail-closed at 16 top-level entries
rather than growing without bound. There is no format upgrade promise yet.

The macOS source-tree qualification command is
`cargo test --locked -p cigar-retrieval --all-targets`: 48 unit tests and three public integration
tests cover deterministic sealing/scoring, denied-vector non-interference, dynamic partitions,
closed stage shapes, stale/missing/corrupt generations, descriptor attacks, every injected
publication and activation boundary, and restart recovery. Strict lint qualification is
`cargo clippy --locked -p cigar-retrieval --all-targets --all-features -- -D warnings`. Daemon-owned
tests separately cover strict local-only configuration and restart, corruption repair, storage
outage, and retention of the mandatory non-vector generation. Fuzzing, soak, installed
process-crash, and concurrent read-versus-refresh qualification are not part of this cohort.

See [`docs/reference/retrieval-indexes.md`](../../docs/reference/retrieval-indexes.md) for the
generation, consistency, authorization, and processor-confinement contracts.
