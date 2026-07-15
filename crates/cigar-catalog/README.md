# cigar-catalog

Stability: kernel, pre-v1. Owns snapshots, immutable atoms, provenance graphs, tombstones, and invalidation.

The crate freezes bounded connector contracts for explicit discovery preview, immutable snapshot
reads, change watermarks, deterministic atomization, atomic repository publication, lifecycle
transitions, bitemporal lineage selection, and reverse-DAG invalidation.

Built-in connectors:

- `LocalFilesystemConnector` canonicalizes one root, never follows external symlinks, excludes
  ambiguous hard links, applies hard/policy/`.cigarignore`/Git-ignore/media/size stages in order,
  prunes positively ignored directory subtrees, hard-excludes repository controls and known
  credential names without trusting host casing, scans eligible bytes for secrets, seals admitted
  bytes against later path substitution, preserves inode identity across rename, rejects portable
  path aliases, and exposes overflow as a typed rescan requirement. Negated Git-ignore rules are
  deliberately not treated as re-inclusions in this bounded fail-closed subset.
- `GitConnector` reads only immutable `HEAD` tree objects through bounded `git cat-file` calls.
  Dirty worktree bytes, mutable replacement refs, and lazy network fetches cannot enter a
  snapshot; symlink and submodule tree entries are excluded.

`ProjectIdentity` derives a tenant-scoped stable ID from a credential-free normalized Git remote,
an explicitly persisted root-lineage UUID, and a fork/worktree disambiguator. Current directory
paths are deliberately excluded, so a move does not silently change project identity.

`IngestionService` consumes the daemon-revalidated discovery plan and connector snapshot, stages the
complete snapshot and atom/edge batch in one repository transaction, binds retries to a canonical
publication digest, retains unchanged source versions, adds `Supersedes` edges for changed
lineages, and emits immutable tombstone versions for deleted files or symbols.

Production callers must bind `SourceConnectorDescriptor` to the durable implementation/root and
bind the strictly ordered atomizer registry with `atomizer_registry_digest`. Atomizer descriptors
declare the exact scope, governance, quality, and retrieval flags accepted by ingestion; output
that diverges from those declarations is rejected before the repository transaction begins.

`CatalogAtomService` resolves bounded unique public atom IDs against one caller-supplied trusted
`AccessContext` and immutable `SnapshotSelection`, preserving request order while representing
missing and cross-tenant records identically. Its tombstone operation takes authority, server time,
expected store revision, idempotency key, and invalidation identity as trusted application inputs.
It resolves only the current active immutable atom, derives a canonical tombstone, and publishes
the tombstone plus its invalidation outbox item in one native repository commit.

Diagnostics deliberately expose counts, detector classes, ranges, and stable error codes—not
source bytes, paths, secret values, or connector roots.
