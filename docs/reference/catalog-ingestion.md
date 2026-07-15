# Catalog ingestion and invalidation

WP05 publishes catalog state from an explicit preview and an immutable connector snapshot. The
preview is not an authorization shortcut: the daemon repeats discovery and requires the accepted
plan digest, counts, and byte total to match before ingestion. The filesystem connector seals each
eligible file's checked bytes during that discovery, while the Git connector reads only immutable
objects named by the accepted commit.

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

The filesystem connector applies root `.cigarignore` and directory-scoped `.gitignore` positive
path patterns while traversing. Matched directories are pruned before their descendants consume
the item/depth budget, except where an authorized exact include override requires descent. This is
a deliberately bounded, fail-closed subset rather than a claim of complete Git ignore semantics:
positive literals and `*` wildcards are supported; unescaped basename patterns apply at any depth;
unsupported escape, `?`, and character-class syntax rejects discovery instead of silently missing
an exclusion. Negated patterns are not re-inclusions and are ignored, so they cannot broaden
admission. Nested repositories, backslash/traversal spellings, portable case aliases, and
NFC-equivalent path aliases are rejected or excluded before publication. Repository controls and
well-known credential names are hard-excluded with ASCII-case-insensitive matching, including on a
case-sensitive macOS volume. A policy may retain at most 256 MiB in one sealed snapshot even if a
caller supplies a larger aggregate limit. Nested Git ignore controls are additionally capped at
8 MiB and 32,768 positive patterns in aggregate.

## Snapshot and publication

An unchanged connector revision reuses the same deterministic snapshot identity. A live path swap
after filesystem discovery cannot alter a read from the sealed capture; a refresh retires the old
record and creates a new preview. If the host wall clock regresses, publication advances the
source's observation time by one logical nanosecond beyond its latest immutable version so edits
and tombstones cannot sort behind prior state. Publication stages the snapshot, all new atom
versions, all provenance edges, and the `catalog.committed` outbox message in one repository write
transaction.

An unchanged restart capture is a no-op rather than an empty publication transaction. A parser
failure, cancellation, deadline, revision conflict, validation error, or injected precommit abort
exposes none of the staged records.

The publication and outbox identity bind the owning tenant and source-bound snapshot identity in
addition to its manifest, atoms, and edges. Empty sources and empty-file captures therefore cannot
collide across tenants or configured source roots when the production worker merges causal events.

Production composition binds the injected connector descriptor (implementation identity and exact
root) to the durable source configuration. It also binds a canonical ordered atomizer-registry
digest. Each atomizer configuration digest covers its identity/version, tenant and project scope,
governance, quality, lexical eligibility, and embedding eligibility; ingestion rejects output that
does not exactly reproduce that declared profile. This prevents a restart from silently attaching
a different root, partial parser registry, reordered registry, or broader atom profile.

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

Git subprocesses run with global/system configuration, interactive prompts, replacement objects,
and lazy object fetching disabled. Snapshot construction therefore fails closed on a missing local
object instead of consulting a promisor remote, and mutable replace refs cannot substitute a tree
for the committed object identifier.

Both ingestion commits and explicit `catalog.atom-tombstoned` commits wake the production index
worker. Index activation therefore cannot leave a manually tombstoned version visible merely
because no later ingestion occurred.

Use the filesystem connector when ingesting an uncommitted Git working tree; it honors Git ignore
rules while excluding `.git` internals and nested repositories/submodules. Use the Git connector
when the immutable committed tree is the source of truth; dirty worktree bytes are then irrelevant.
Project identity is separate from either current path and binds tenant, normalized remote,
persisted root lineage, and explicit disambiguator.
