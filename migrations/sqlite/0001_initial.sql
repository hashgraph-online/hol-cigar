-- CIGAR SQLite schema v1. Append-only; checksum recorded in schema_migrations.
-- sequence/name: 1 / initial
-- application compatibility: major 1 through major 1
-- classification/lock: offline / exclusive schema transaction
-- data backfill: none (fresh schema)
-- verification: required tables, indexes, triggers, FTS5, and revision zero exist
-- rollback or restore: restore the mandatory pre-migration signed backup
CREATE TABLE IF NOT EXISTS schema_migrations (
    sequence INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    checksum TEXT NOT NULL,
    applied_at_unix_nanos TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS state_snapshots (
    revision INTEGER PRIMARY KEY,
    state BLOB NOT NULL,
    checksum TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS tenants (tenant_id TEXT PRIMARY KEY, status TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS principals (tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, status TEXT NOT NULL, mapping_version INTEGER NOT NULL, PRIMARY KEY (tenant_id, principal_id)) STRICT;
CREATE TABLE IF NOT EXISTS source_snapshots (tenant_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, state TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, snapshot_id)) STRICT;
CREATE TABLE IF NOT EXISTS atoms (tenant_id TEXT NOT NULL, version_id TEXT NOT NULL, lineage_id TEXT NOT NULL, lifecycle TEXT NOT NULL, exact_text TEXT NOT NULL DEFAULT '', record BLOB NOT NULL, PRIMARY KEY (tenant_id, version_id)) STRICT;
CREATE TABLE IF NOT EXISTS atom_lineages (tenant_id TEXT NOT NULL, lineage_id TEXT NOT NULL, current_version_id TEXT, PRIMARY KEY (tenant_id, lineage_id)) STRICT;
CREATE TABLE IF NOT EXISTS edges (tenant_id TEXT NOT NULL, edge_id TEXT NOT NULL, from_version TEXT NOT NULL, to_version TEXT NOT NULL, kind TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, edge_id)) STRICT;
CREATE TABLE IF NOT EXISTS blobs (tenant_id TEXT NOT NULL, digest TEXT NOT NULL, size_bytes INTEGER NOT NULL, key_ref TEXT NOT NULL, reference_count INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, digest)) STRICT;
CREATE TABLE IF NOT EXISTS context_commits (tenant_id TEXT NOT NULL, space_id TEXT NOT NULL, sequence INTEGER NOT NULL, commit_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, space_id, sequence), UNIQUE (tenant_id, commit_id)) STRICT;
CREATE TABLE IF NOT EXISTS context_events (tenant_id TEXT NOT NULL, commit_id TEXT NOT NULL, ordinal INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, commit_id, ordinal)) STRICT;
CREATE TABLE IF NOT EXISTS policies (tenant_id TEXT NOT NULL, version_id TEXT NOT NULL, source_digest TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, version_id)) STRICT;
CREATE TABLE IF NOT EXISTS index_watermarks (tenant_id TEXT NOT NULL, index_id TEXT NOT NULL, partition_id TEXT NOT NULL, source_sequence INTEGER NOT NULL, PRIMARY KEY (tenant_id, index_id, partition_id)) STRICT;
CREATE TABLE IF NOT EXISTS plans (tenant_id TEXT NOT NULL, plan_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, plan_id)) STRICT;
CREATE TABLE IF NOT EXISTS bundles (tenant_id TEXT NOT NULL, bundle_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, bundle_id)) STRICT;
CREATE TABLE IF NOT EXISTS manifests (tenant_id TEXT NOT NULL, manifest_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, manifest_id)) STRICT;
CREATE TABLE IF NOT EXISTS materializations (tenant_id TEXT NOT NULL, materialization_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, materialization_id)) STRICT;
CREATE TABLE IF NOT EXISTS handoffs (tenant_id TEXT NOT NULL, handoff_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, handoff_id)) STRICT;
CREATE TABLE IF NOT EXISTS handoff_acceptances (tenant_id TEXT NOT NULL, handoff_id TEXT NOT NULL, recipient_id TEXT NOT NULL, attempt INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, handoff_id, recipient_id, attempt)) STRICT;
CREATE TABLE IF NOT EXISTS decision_records (tenant_id TEXT NOT NULL, decision_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, decision_id)) STRICT;
CREATE TABLE IF NOT EXISTS effect_intents (tenant_id TEXT NOT NULL, effect_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, effect_id)) STRICT;
CREATE TABLE IF NOT EXISTS effect_attempts (tenant_id TEXT NOT NULL, effect_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, effect_id, attempt_number)) STRICT;
CREATE TABLE IF NOT EXISTS effect_receipts (tenant_id TEXT NOT NULL, receipt_id TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, receipt_id)) STRICT;
CREATE TABLE IF NOT EXISTS effect_events (tenant_id TEXT NOT NULL, effect_id TEXT NOT NULL, sequence INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, effect_id, sequence)) STRICT;
CREATE TABLE IF NOT EXISTS outbox (tenant_id TEXT NOT NULL, message_id TEXT NOT NULL, causal_revision INTEGER NOT NULL, state TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, message_id)) STRICT;
CREATE TABLE IF NOT EXISTS invalidation_queue (tenant_id TEXT NOT NULL, invalidation_id TEXT NOT NULL, cursor INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, invalidation_id)) STRICT;
CREATE TABLE IF NOT EXISTS leases (tenant_id TEXT NOT NULL, lease_id TEXT NOT NULL, fencing_token INTEGER NOT NULL, expires_at_unix_nanos TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (tenant_id, lease_id)) STRICT;

CREATE INDEX IF NOT EXISTS atoms_by_lineage ON atoms (tenant_id, lineage_id, version_id);
CREATE INDEX IF NOT EXISTS edges_by_source ON edges (tenant_id, from_version, kind, edge_id);
CREATE INDEX IF NOT EXISTS outbox_by_state_revision ON outbox (tenant_id, state, causal_revision, message_id);
CREATE VIRTUAL TABLE IF NOT EXISTS atom_fts USING fts5(tenant_id UNINDEXED, version_id UNINDEXED, exact_text, tokenize = 'unicode61');

CREATE TRIGGER IF NOT EXISTS atom_fts_after_insert AFTER INSERT ON atoms BEGIN
    INSERT INTO atom_fts (tenant_id, version_id, exact_text)
    VALUES (new.tenant_id, new.version_id, new.exact_text);
END;
CREATE TRIGGER IF NOT EXISTS atom_fts_after_delete AFTER DELETE ON atoms BEGIN
    DELETE FROM atom_fts
    WHERE tenant_id = old.tenant_id AND version_id = old.version_id;
END;
CREATE TRIGGER IF NOT EXISTS atom_fts_after_update AFTER UPDATE ON atoms BEGIN
    DELETE FROM atom_fts
    WHERE tenant_id = old.tenant_id AND version_id = old.version_id;
    INSERT INTO atom_fts (tenant_id, version_id, exact_text)
    VALUES (new.tenant_id, new.version_id, new.exact_text);
END;
