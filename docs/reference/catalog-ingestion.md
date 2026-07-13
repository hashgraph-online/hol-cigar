# Catalog ingestion and invalidation

WP05 publishes catalog state from an explicit preview and an immutable connector snapshot. The
preview is not an authorization shortcut: the connector repeats stable-record checks at read time,
and the ingestion coordinator repeats secret scanning immediately before atomization.

## Discovery order

Filesystem discovery evaluates the first decisive stage in this order:

1. hard exclusions (catalog internals, credential paths, external symlinks, ambiguous hard links);
2. tenant/project policy prefixes;
3. `.cigarignore`;
4. Git ignore;
5. per-record and aggregate size bounds;
6. permitted media types;
7. built-in, entropy/encoded, and organization-configured secret scanning;
8. inclusion.

An authorized preview override can broaden only ignore decisions. It cannot bypass hard, policy,
size, media, or secret decisions. Findings contain a detector class and byte offsets only; an
authorized caller can derive a tenant-keyed blinded fingerprint without retaining matched text.

## Snapshot and publication

An unchanged connector revision reuses the same snapshot identity and timestamp, which makes an
exact idempotent retry byte-for-byte stable. Publication stages the snapshot, all new atom versions,
and all provenance edges in one repository write transaction. A parser failure, cancellation,
deadline, revision conflict, validation error, or injected precommit abort exposes none of them.

Refresh compares stable source identities and revisions. Unchanged files retain existing atoms and
their original snapshot provenance. Changed lineages publish active successors and `Supersedes`
edges. Source or symbol lineages that disappear publish a later immutable tombstone. Bitemporal
selection chooses the latest observation valid at the requested semantic time, then excludes
tombstoned/quarantined lineages.

## Invalidation

Dependency edges are stored from dependent to dependency. `DependencyInvalidator` builds the
reverse adjacency map, rejects dependency/derivation cycles, and traverses a sorted bounded frontier.
The continuation batch carries both the remaining frontier and the accumulated idempotent closure.
Revocation, source change, policy change, and projection repair use the same traversal with distinct
priority causes. Unrelated versions are never added to the closure.

Watcher overflow is a typed change event and degrades connector health until a complete refresh.
A restarted connector establishes a fresh preview baseline rather than replaying unproven in-memory
events.

Use the filesystem connector when ingesting an uncommitted Git working tree; it honors Git ignore
rules while excluding `.git` internals and nested repositories/submodules. Use the Git connector
when the immutable committed tree is the source of truth; dirty worktree bytes are then irrelevant.
Project identity is separate from either current path and binds tenant, normalized remote,
persisted root lineage, and explicit disambiguator.
