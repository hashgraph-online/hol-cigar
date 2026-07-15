# Retrieval indexes and authorization

WP06 treats every index as a disposable projection of canonical catalog state. A build contains a
complete atom/edge snapshot, global worker revision, explicit sorted per-tenant watermarks,
analyzer/projection configuration digest, verification time, and optional vector
generation/fingerprint binding. It is not servable while building. Verification computes a
semantic root over sorted immutable versions, content digests, lifecycle, and graph adjacency. Only
a verified root can be atomically selected as the active generation. Quarantined generations cannot
be activated, and deleting the active generation is forbidden.

## Causal updates and consistency

`IndexWorker` consumes ordered `catalog.committed` and `catalog.atom-tombstoned` outbox records
idempotently. It loads the complete
canonical snapshot at the highest newly claimed causal revision, builds and verifies a disposable
generation, activates it with an expected-active compare, and advances its watermark only after that
activation succeeds. An interruption leaves the prior active generation and watermark unchanged;
the same records can then be retried.

A strong request returns candidates only when the active generation's requesting-tenant watermark
is built through the pinned catalog revision. A bounded-stale request names an exact maximum
tenant-local revision lag. Missing tenant watermark metadata fails closed. Every successful batch
discloses the generation ID, index fingerprint, built-through revision, actual revision lag, fallback
state, and last verification time. There is no implicit eventual mode for governed retrieval.

## Authorization-first channels

The partition can be constructed only from an opaque process-local proof issued by the current
protected policy engine. It binds the authenticated principal, tenant, visible projects, purpose,
processor, maximum classification, maximum instruction authority, world-valid time,
observation-time bound, capability/grant scope, vector permission, policy snapshot and revision,
revocation epoch, and an engine-capped monotonic expiry. The issuing engine must remain live. Policy
availability, snapshot identity, grant/principal/resource revocation, and expiry are rechecked before
index access and immediately before disclosure.

The opaque proof and the semantic partition identity deliberately have different lifetimes. The
proof retains the exact world-valid, observation, decision-expiry, and process-monotonic times used
for the live authorization. The partition digest used by deterministic plans, retained retrieval
records, and vector processor bindings omits only those request-instance/TTL instants. It still
binds the principal, tenant, sorted project scope, purpose, processor, classification and
instruction ceilings, vector permission, fixed grant validity bounds and identity, complete
capability/configuration selectors, protected policy digest/revision, revocation epoch, and stable
per-project authority inputs. Thus two fresh proofs over identical governed state have one semantic
partition identity, while a scope, grant, policy, revocation, or governance change cannot alias it.
This does not extend authorization: every index use revalidates the live proof and every resource is
rechecked against its bitemporal metadata before scoring or disclosure. Candidate outcomes and
authorized index/content roots record an actual temporal result change.

Each canonical record is independently evaluated through Metadata and Content policy, plus Processor
policy before vector or compilation plaintext handling. Lifecycle, scope, purpose (including the
record wildcard), processor, classification, authority, validity, and observation time are checked
before a channel produces candidates. Exact, path/declared term,
lexical, graph, active-state/augmentation, and optional vector stages operate only on the resulting
partition.

Non-vector stage shapes are closed before index access. Exact requires at least one version, atom,
lineage, content-digest, canonical-URI, or source-revision identity; metadata requires an exact path
or declared term; lexical requires a normalized term; graph requires an authorized root; and
augmentation accepts no selector because it is the explicitly bounded authorized-current-state
enumeration. Selector fields from another stage and non-vector fallback flags fail as invalid
metadata instead of returning an empty or unexpectedly broad result. Blocking exact/query
requirements still fail with `RequiredCandidateMissing` when every valid channel is empty.

Candidate references expose an immutable version, authorized source coordinates, integer feature
vector, checked score, and content-free match evidence. Their debug forms omit query text and paths.
The current version for a tenant-scoped lineage is resolved at the proof's valid/observed time before
winner lifecycle and governance are evaluated. This prevents an older allowed version from
resurfacing after a tombstone, project move, tighter purpose/processor rule, or classification
increase while retaining explicit historical as-of behavior. Governance selectors are indexed per
version, so permissions from separate versions cannot be composed. Graph expansion performs exact
lookups among authorized current lineage/version pairs rather than scanning global adjacency.

Denied atoms, edges, and vectors cannot affect candidate counts, vector allowed-version sets, deterministic
retrieval-work receipts, caller-visible partition roots, generation identities, cache/query keys, or
diagnostics. Authorized partition roots include sorted authorized current-version edge topology;
vector-stage fingerprints additionally include a partition-local binding computed only from the
authorized vector versions and commitments. Tenant-local
watermarks prevent unrelated tenant commits from changing disclosed freshness. These are
deterministic logical-work and output non-interference guarantees, not a wall-clock constant-time
claim.

## Planning, caps, and vectors

`QueryPlanner` turns exact selectors into mandatory exact stages and query selectors into independent
metadata and lexical stages plus an optional vector stage. Each stage records a query fingerprint,
candidate cap, timeout, fallback rule, required watermark, and blocking disposition. The staged
executor uses the lesser of the parent and stage deadline and rejects a backend that exceeds its cap.

Vector adapters are optional. Vector stage shape is closed before index access: normalized terms are
required; exact, path, and graph selectors are forbidden; and absence of a processor-approved vector
is valid only for an explicitly permitted fallback. The adapter request contains the exact
policy-partition digest, sealed vector generation/fingerprint binding, one bounded
processor-approved quantized vector, and only version IDs already admitted by metadata
authorization. It contains neither atom payloads nor query text. Raw processor output has no public
constructor. The trusted processor receives and revalidates the live opaque authorization after
policy approval, and query commitments use a domain distinct from document-vector commitments while
binding the exact partition. The vector commitment participates in query identity without exposing
its values.

The provider-neutral `SealedLocalVectorAdapter` is disabled by default. On macOS, production daemon
bootstrap installs it only when the strict local-only `[local_vector]` section explicitly enables
an owner-private durable root and bounded dimension/entry/neighbor caps. Shared mode rejects the
section. Explicit enablement binds all of the following into an immutable
fingerprint:

- adapter version;
- model ID and artifact fingerprint, exact dimension, and preprocessing ID and implementation
  fingerprint;
- squared-Euclidean-v1 or Manhattan-v1 integer distance and symmetric signed-int8 quantization;
- policy partition and vector index generation;
- entry/neighbor caps; and
- sorted semantic version IDs and processor-vector commitments.

Every vector has exactly the configured dimension and values in the inclusive -127 through 127
range. Sealing rejects duplicate versions, foreign processor bindings, and cap violations. Queries
reject fingerprint, generation, partition, processor, dimension, and cap mismatches. Results are
intersected with the already-authorized allowed-version set, scored with checked integer arithmetic
in the closed 0 through 10,000 range, and sorted by descending score then ascending immutable version
ID. Invalid adapter output remains subject to the manager's independent allowed-version and score
checks.

When a request explicitly permits degradation, vector unavailability uses the same authorized
lexical and declared-metadata projections; it never relaxes scope or changes authorization. A policy
denial, cancellation, or deadline does not degrade. No correctness or authorization decision depends
on vector availability or semantic quality.

The local adapter is a development implementation for the initial macOS cohort. It loads no model,
has no external network dependency, and makes no semantic-quality or cross-platform claim. Its
internal macOS-only durable store is explicitly opened against an existing owner-private absolute
root by daemon bootstrap. The versioned canonical data
file contains only sorted semantic version IDs, vector commitments, and processor-approved quantized
values. Its canonical manifest binds adapter/model/preprocessing identities and fingerprints,
dimension, metric, quantization, partition, generation, resource caps, watermark, vector count,
data digest, processor binding, and sealed adapter fingerprint. An activation record additionally
binds the manifest and data digests.

Generation publication writes and synchronizes both files in a private temporary directory,
synchronizes the directory, performs a no-replace rename, and synchronizes the generation parent.
Activation uses an expected-current comparison, synchronized temporary record, atomic replacement,
and root-directory synchronization. Startup walks no-follow descriptor-relative paths, rejects
multi-link or unsafe files, and fully verifies canonical bytes and every commitment for the selected
generation. Inactive generations receive only a bounded structural screen during startup and undergo
the same full verification before any later activation, so accumulated 512 MiB generation bounds
cannot multiply startup hashing work. Incomplete or corrupt selected state is quarantined, stale
watermarks are refused, and retained quarantine is fail-closed at 16 top-level entries. In every
unavailable, invalid, corrupt, or stale case the store returns no vector adapter; callers may use
deterministic lexical fallback only under the existing authorization and fallback contract. The
format has no upgrade promise and no CLI surface.

## macOS vector qualification boundary

The source-tree qualification gate runs
`cargo test --locked -p cigar-retrieval --all-targets` (48 unit tests plus three public integration
tests) and
`cargo clippy --locked -p cigar-retrieval --all-targets --all-features -- -D warnings`. The durable
tests inject every modeled generation-publication and activation failure boundary, then reopen the
store and require one exact reconcilable state. They also cover deterministic rebuild and restart,
stale/missing activation, corrupt-state quarantine, hostile links and roots, bounded inactive
generation screening, and quarantine retention. The daemon regression
`production_vector::tests::restart_corruption_repair_and_storage_outage_preserve_mandatory_generation`
proves that restart reuses the same binding, corrupt selected state rebuilds from canonical catalog
truth, and a vector-store outage removes only the optional adapter while the mandatory generation
remains available. The strict configuration regression
`config::tests::local_vector_is_explicit_macos_only_bounded_and_shared_forbidden` proves default-off,
bounded local enablement and shared-mode refusal.

This evidence is macOS source-tree evidence. It does not qualify installed process-kill or
power-loss behavior, concurrent reads during refresh, another operating system, a shared vector
service, fuzzing, soak, format upgrade, or semantic retrieval quality.
