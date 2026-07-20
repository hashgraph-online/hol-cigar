# ADR-0004: Requirement-aware retrieval bounds and deterministic diversity

- Status: Accepted for Honey 0.9.1 implementation
- Date: 2026-07-20
- Applies to: retrieval planner, index execution, candidate coalescing, and compiler intake
- Compatibility: internal behavior under the existing v1 contract

## Context

The paired evaluation displaced 50,310 candidates while selecting 534, roughly 94 displaced
candidates for each selected block. Large duplicate and one-source candidate sets increase
governance, compiler, tokenization, and manifest work without improving the final context. Fixed
stage caps alone do not account for requested budget, lane, blocking requirements, mandatory
evidence, or source diversity.

Retrieval must remain deterministic, snapshot-pinned, policy-first, cancellation-aware, and
fail-closed. Exact and mandatory evidence cannot be lost to ordinary top-K or diversity. Candidate
identity must not be disclosed before authorization. Approximate vector search is optional and
cannot become authoritative state.

## Decision

The planner derives bounded per-requirement and per-lane candidate allowances from the normalized
contract's exact item/token budgets and the frozen compiler profile. It preserves a separately
bounded protected path for exact, mandatory, dependency, policy-required, and higher-authority
candidates. After governance, aliases and content-equivalent candidates are coalesced before compiler
submission, and optional candidates pass deterministic per-source/per-lineage/per-content-family
caps plus a quantized diversity stage.

The complete bound derivation and diversity parameters are included in the retrieval-plan digest and
compiler-profile authority. Unknown, inconsistent, zero, unbounded, or overflowing configuration is
rejected.

## Processing order and trust boundary

For each frozen catalog revision and authorized partition:

1. Normalize and validate requirements, lane budgets, item caps, retrieval profile, and cancellation.
2. Run exact/path/symbol/metadata/lexical and optional vector stages with their closed stage caps and
   timeouts.
3. Merge candidate references only; do not fetch or reveal protected content yet.
4. Apply tenant/partition, temporal, lifecycle, integrity, policy, disclosure, and instruction-
   authority governance.
5. Separate protected candidates: exact selector matches, explicit mandatory records, records needed
   for blocking requirements, dependency closure, and policy/higher-authority evidence.
6. Coalesce authorized aliases resolving to the same governed version, then safe content families
   when an authenticated content key is available.
7. Apply deterministic optional per-source, per-lineage, and per-content-family caps.
8. Apply deterministic quantized diversity within each requirement/lane allowance.
9. Union protected and optional results in stable order, recheck total hard limits, and submit only
   authorized metadata to the compiler.

Governance precedes coalescing and diversity so a permitted candidate cannot reveal the existence,
score, content key, or reason of a denied candidate. Metrics expose only closed aggregate counts.

## Bound derivation

The frozen profile defines checked integer constants for:

- minimum and maximum candidate allowance per requirement;
- optional oversampling multiplier per possible selected item;
- token-to-item estimate floor used only to derive a safe bound;
- maximum per lane and per query stage;
- maximum protected candidates per requirement and request;
- per-source, per-lineage, and per-content-family optional caps; and
- absolute compiler intake maximum.

For a lane, the planner computes a conservative possible selected-item count from both its exact item
cap and token budget using the frozen nonzero minimum token estimate. It multiplies by the bounded
oversampling factor, distributes a minimum allowance to each applicable requirement, and clamps to
the lane/stage/request maxima. Requirements and lanes are iterated in canonical order; remainder
allocation uses stable requirement index, never arrival order.

This estimate limits optional recall work only. It does not assert actual token cost and cannot admit
an item into the bundle. The compiler still measures each representation with the exact pinned
tokenizer and enforces every token/item/lane constraint.

If the protected path alone exceeds its separately frozen safety maximum, retrieval returns a stable
limit/policy error with readiness unaffected; it never demotes mandatory evidence to optional.

## Coalescing

Aliases that resolve to the same authorized version ID are one candidate before compiler submission.
Their requirement coverage and safe retrieval-channel evidence are unioned with bounded checked
sets. Where the index has an authenticated representation content key, optional entries may also be
coalesced by `(representation kind, content digest, governance domain)` before the compiler's full
content-equivalence logic. The compiler remains the final authority because it sees representation,
dependency, transform, and provenance semantics unavailable to retrieval.

No coalescing crosses tenant, partition, classification/disclosure policy, lifecycle eligibility,
instruction authority, snapshot revision, or index generation.

## Deterministic diversity

The optional stage uses a fixed-pass, quantized maximal-marginal-relevance-style selection:

- relevance is the existing checked integer balanced retrieval score;
- similarity is derived from frozen, non-content-bearing features such as same governed lineage,
  same source family, same authenticated content family, and optional quantized vector similarity;
- weights and similarity buckets are nonnegative fixed integers in the profile;
- candidates and already-selected entries are traversed in stable candidate order;
- ties use score, estimated tokens, canonical URI, and version ID as already defined; and
- the pass count and maximum comparisons are fixed and bounded.

Vector similarity is omitted when no approved vector stage is available. Its absence is a closed
degraded retrieval path, not fabricated zero-distance evidence. Approximate vector ordering never
overrides exact, mandatory, policy, or higher-authority candidates.

## Vector and graph projections

The existing vector stage remains optional with a bounded cap and timeout. A local adapter, Qdrant,
or another provider may return candidate version IDs through the same authorization-bound interface.
For an external/local-sidecar Qdrant adapter:

- points contain embeddings plus safe filter metadata and authoritative version pointers, not the
  repository's durable state;
- tenant, policy partition, lifecycle, revision/generation, model, and embedding fingerprints are
  mandatory filters/bindings;
- results are reauthorized and exact content/provenance is loaded from SQLite;
- updates flow from a transactional outbox and support reconciliation/rebuild; and
- Qdrant unavailability cannot corrupt repository state or cause readiness to authenticate stale
  evidence.

Qdrant's HNSW neighbor graph is a similarity index, not CIGAR's semantic/provenance graph. Catalog
edges and lineage remain authoritative in SQLite and derived graph projections. Honey 0.9.1 does not
require Qdrant and does not replace SQLite with it.

## Snapshot, cancellation, and caching

Every stage binds the exact catalog watermark, authorized partition, index generation, query-plan
digest, policy digest, and optional vector model/generation. Candidates from mismatched generations
or revisions are rejected rather than merged. Cancellation is checked before each stage, after each
bounded page, before protected content load, and before compiler submission.

Retrieval cache keys include all semantic pins and the bound-derivation/diversity profile. Unknown
semantic extensions, policy/watermark/tokenizer/materializer/compiler mismatches, or uncertain
authority bypass cache with closed reasons. Execution-only correlation is not removed from the
existing v1 contract digest in 0.9.1.

## Telemetry and gates

Closed content-free metrics count:

- raw candidates per stage;
- candidates after governance;
- protected candidates and protected-limit failures;
- candidates after version/alias coalescing;
- candidates after content-family coalescing;
- candidates after source/lineage/family caps;
- candidates after diversity and submitted to compiler;
- selected blocks, unique content keys, unique governed source versions/lineages;
- budget-displaced records; and
- cache hit/miss/bypass by closed reason.

Metrics never label tenant, source, path, query, requirement text, content digest, run/job/trace, or
extensions. Qualification requires globally fewer than ten budget-displaced candidates per selected
block, reports every workflow, preserves 100% required-source coverage, at least 99% citation
resolvability, and non-regressive governed-lineage diversity.

## Consequences

Retrieval and compiler work become proportional to plausible context capacity instead of corpus
duplicates. Deterministic diversity makes source flooding less effective and improves source breadth.
The protected bypass needs its own hard safety bound and can fail a request that presents an
unreasonably large mandatory closure; this is preferable to silently dropping required evidence.

## Rejected alternatives

- **One fixed top-K:** ignores requirement/lane budgets and can starve blocking evidence.
- **Apply top-K before governance:** may disclose or choose unauthorized candidates.
- **Unbounded mandatory bypass:** permits denial of service and memory exhaustion.
- **Floating-point/random MMR:** weakens deterministic identity and reproducibility.
- **Vector-only retrieval:** loses exact identifiers, symbols, paths, policy evidence, and predictable
  offline behavior.
- **Qdrant as repository authority:** does not address full-state snapshot modeling and weakens the
  required cross-domain transactional evidence boundary.

## Verification obligations

- Property tests for input/stage-result permutation and identical plan/candidate identities.
- Adversarial one-source, alias, duplicate-content, near-duplicate vector, required-evidence, and
  policy-denied flooding.
- Protected candidates survive optional caps/diversity or fail only at their explicit safety bound.
- Snapshot/generation/policy mismatches fail before compiler submission.
- Optional vector timeout/unavailability follows the declared degraded path with no leakage.
- Frozen cohorts meet displacement, diversity, duplicate, citation, required-source, latency, and
  completion gates.
