-- CIGAR SQLite schema v5. FRESH DISTINCT TARGETS ONLY.
-- sequence/name: 5 / incremental_repository_state
-- application compatibility: Honey 0.9.1 v5 offline migration/creation tooling only
-- classification/lock: explicit offline distinct-target creation; never ordinary SqliteStore::open
-- data backfill: explicit authenticated v4-to-v5 migration after verified backup and free-space proof
-- verification: consecutive revision envelope, canonical checkpoint/delta digests, roots, chain, pins
-- rollback or restore: reactivate the retained v4 descriptor; never rewrite or delete the v4 source

CREATE TABLE repository_revisions_v5 (
    revision INTEGER PRIMARY KEY CHECK (revision >= 0),
    parent_revision INTEGER UNIQUE CHECK (
        parent_revision IS NULL OR
        (revision > 0 AND parent_revision = revision - 1)
    ),
    state_digest TEXT NOT NULL CHECK (length(state_digest) = 68),
    catalog_root TEXT NOT NULL CHECK (length(catalog_root) = 68),
    semantic_root TEXT NOT NULL CHECK (length(semantic_root) = 68),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    referenced_blob_bytes INTEGER NOT NULL CHECK (referenced_blob_bytes >= 0),
    previous_chain_head TEXT NOT NULL CHECK (length(previous_chain_head) = 68),
    chain_head TEXT NOT NULL UNIQUE CHECK (length(chain_head) = 68),
    FOREIGN KEY (parent_revision) REFERENCES repository_revisions_v5(revision),
    FOREIGN KEY (parent_revision, previous_chain_head)
        REFERENCES repository_revisions_v5(revision, chain_head),
    UNIQUE (revision, chain_head),
    UNIQUE (
        revision, state_digest, catalog_root, semantic_root, atom_count, edge_count,
        referenced_blob_bytes, previous_chain_head, chain_head
    )
) STRICT;

CREATE UNIQUE INDEX repository_revisions_v5_single_chain_origin
    ON repository_revisions_v5((1)) WHERE parent_revision IS NULL;

CREATE TABLE repository_authority_v5 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version INTEGER NOT NULL CHECK (format_version = 5),
    capacity_profile TEXT NOT NULL CHECK (capacity_profile IN ('standard', 'large_local')),
    activated INTEGER NOT NULL CHECK (activated IN (0, 1)),
    current_revision INTEGER NOT NULL REFERENCES repository_revisions_v5(revision),
    chain_head TEXT NOT NULL REFERENCES repository_revisions_v5(chain_head),
    state_digest TEXT NOT NULL CHECK (length(state_digest) = 68),
    catalog_root TEXT NOT NULL CHECK (length(catalog_root) = 68),
    semantic_root TEXT NOT NULL CHECK (length(semantic_root) = 68),
    migration_receipt_schema_digest TEXT NOT NULL CHECK (length(migration_receipt_schema_digest) = 68),
    retention_policy_digest TEXT NOT NULL CHECK (length(retention_policy_digest) = 68),
    maximum_delta_operations INTEGER NOT NULL CHECK (maximum_delta_operations > 0),
    maximum_delta_bytes INTEGER NOT NULL CHECK (maximum_delta_bytes > 0),
    maximum_checkpoint_bytes INTEGER NOT NULL CHECK (maximum_checkpoint_bytes > 0),
    maximum_deltas_since_checkpoint INTEGER NOT NULL CHECK (maximum_deltas_since_checkpoint > 0),
    maximum_accumulated_delta_bytes INTEGER NOT NULL CHECK (maximum_accumulated_delta_bytes > 0),
    maximum_retained_revisions INTEGER NOT NULL CHECK (maximum_retained_revisions > 0),
    maximum_retained_age_nanos TEXT NOT NULL,
    maximum_physical_retained_bytes INTEGER NOT NULL CHECK (maximum_physical_retained_bytes > 0),
    minimum_reconstructable_revisions INTEGER NOT NULL CHECK (minimum_reconstructable_revisions > 0),
    minimum_verified_replay_revisions INTEGER NOT NULL CHECK (minimum_verified_replay_revisions > 0),
    created_at_unix_nanos TEXT NOT NULL,
    CHECK (minimum_reconstructable_revisions >= maximum_deltas_since_checkpoint),
    CHECK (minimum_verified_replay_revisions >= maximum_deltas_since_checkpoint),
    CHECK (maximum_retained_revisions >= minimum_reconstructable_revisions),
    CHECK (maximum_retained_revisions >= minimum_verified_replay_revisions),
    FOREIGN KEY (current_revision, chain_head)
        REFERENCES repository_revisions_v5(revision, chain_head)
) STRICT;

CREATE TABLE repository_checkpoints_v5 (
    revision INTEGER PRIMARY KEY REFERENCES repository_revisions_v5(revision),
    format_version INTEGER NOT NULL CHECK (format_version = 5),
    canonical_state BLOB NOT NULL CHECK (length(canonical_state) > 0),
    encoded_bytes INTEGER NOT NULL CHECK (
        encoded_bytes > 0 AND encoded_bytes = length(canonical_state)
    ),
    checkpoint_digest TEXT NOT NULL UNIQUE CHECK (length(checkpoint_digest) = 68),
    state_digest TEXT NOT NULL CHECK (length(state_digest) = 68),
    catalog_root TEXT NOT NULL CHECK (length(catalog_root) = 68),
    semantic_root TEXT NOT NULL CHECK (length(semantic_root) = 68),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    referenced_blob_bytes INTEGER NOT NULL CHECK (referenced_blob_bytes >= 0),
    previous_chain_head TEXT NOT NULL CHECK (length(previous_chain_head) = 68),
    chain_head TEXT NOT NULL CHECK (length(chain_head) = 68),
    reason TEXT NOT NULL CHECK (
        reason IN ('genesis', 'migration', 'delta_count', 'delta_bytes', 'compaction')
    ),
    FOREIGN KEY (
        revision, state_digest, catalog_root, semantic_root, atom_count, edge_count,
        referenced_blob_bytes, previous_chain_head, chain_head
    ) REFERENCES repository_revisions_v5(
        revision, state_digest, catalog_root, semantic_root, atom_count, edge_count,
        referenced_blob_bytes, previous_chain_head, chain_head
    )
) STRICT;

CREATE TABLE repository_deltas_v5 (
    revision INTEGER PRIMARY KEY REFERENCES repository_revisions_v5(revision),
    parent_revision INTEGER NOT NULL UNIQUE REFERENCES repository_revisions_v5(revision),
    format_version INTEGER NOT NULL CHECK (format_version = 5),
    canonical_delta BLOB NOT NULL CHECK (length(canonical_delta) > 0),
    encoded_bytes INTEGER NOT NULL CHECK (
        encoded_bytes > 0 AND encoded_bytes = length(canonical_delta)
    ),
    delta_digest TEXT NOT NULL UNIQUE CHECK (length(delta_digest) = 68),
    result_state_digest TEXT NOT NULL CHECK (length(result_state_digest) = 68),
    catalog_root TEXT NOT NULL CHECK (length(catalog_root) = 68),
    semantic_root TEXT NOT NULL CHECK (length(semantic_root) = 68),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    referenced_blob_bytes INTEGER NOT NULL CHECK (referenced_blob_bytes >= 0),
    previous_chain_head TEXT NOT NULL CHECK (length(previous_chain_head) = 68),
    chain_head TEXT NOT NULL CHECK (length(chain_head) = 68),
    logical_bytes INTEGER NOT NULL CHECK (logical_bytes >= 0),
    operation_count INTEGER NOT NULL CHECK (operation_count > 0),
    CHECK (revision > 0 AND parent_revision = revision - 1),
    FOREIGN KEY (
        revision, result_state_digest, catalog_root, semantic_root, atom_count, edge_count,
        referenced_blob_bytes, previous_chain_head, chain_head
    ) REFERENCES repository_revisions_v5(
        revision, state_digest, catalog_root, semantic_root, atom_count, edge_count,
        referenced_blob_bytes, previous_chain_head, chain_head
    )
) STRICT;

CREATE INDEX repository_deltas_v5_parent
    ON repository_deltas_v5(parent_revision, revision);
CREATE INDEX repository_checkpoints_v5_latest
    ON repository_checkpoints_v5(revision DESC);

CREATE TABLE repository_compaction_origin_v5 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    origin_revision INTEGER NOT NULL UNIQUE REFERENCES repository_revisions_v5(revision),
    prior_first_revision INTEGER NOT NULL CHECK (
        prior_first_revision >= 0 AND prior_first_revision < origin_revision
    ),
    removed_through_revision INTEGER NOT NULL CHECK (
        removed_through_revision = origin_revision - 1
    ),
    prior_chain_head TEXT NOT NULL CHECK (length(prior_chain_head) = 68),
    preview_digest TEXT NOT NULL UNIQUE CHECK (length(preview_digest) = 68),
    executed_at_unix_nanos TEXT NOT NULL,
    verification_state TEXT NOT NULL CHECK (verification_state = 'complete')
) STRICT;

CREATE TABLE repository_retention_pins_v5 (
    pin_id TEXT PRIMARY KEY CHECK (length(pin_id) = 68),
    first_revision INTEGER NOT NULL REFERENCES repository_revisions_v5(revision),
    last_revision INTEGER NOT NULL REFERENCES repository_revisions_v5(revision),
    reason TEXT NOT NULL CHECK (reason IN ('legal_hold', 'replay', 'backup', 'explicit')),
    authority_digest TEXT NOT NULL CHECK (length(authority_digest) = 68),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 68),
    issued_at_unix_nanos TEXT NOT NULL,
    expires_at_unix_nanos TEXT,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest) = 68),
    signature_identity_digest TEXT NOT NULL CHECK (length(signature_identity_digest) = 68),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 64 AND 512),
    verification_state TEXT NOT NULL CHECK (verification_state = 'verified'),
    state TEXT NOT NULL CHECK (state IN ('active', 'released')),
    released_at_unix_nanos TEXT,
    CHECK (first_revision <= last_revision),
    CHECK (
        (state = 'active' AND released_at_unix_nanos IS NULL) OR
        (state = 'released' AND released_at_unix_nanos IS NOT NULL)
    )
) STRICT;

CREATE INDEX repository_retention_pins_v5_active_range
    ON repository_retention_pins_v5(state, first_revision, last_revision, pin_id);
