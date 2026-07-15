-- CIGAR SQLite schema v2. Append-only rolling-compatible ledger expansion.
-- sequence/name: 2 / compatibility_ledger
-- application compatibility: major 1 through major 2
-- classification/lock: online / one bounded exclusive SQLite schema transaction
-- data backfill: SQLite supplies the declared defaults for the retained sequence-one row
-- verification: every ledger row is contiguous, immutable, version-bounded, and rolling-classified
-- rollback or restore: old binaries must refuse the newer ledger; restore the verified pre-migration backup
ALTER TABLE schema_migrations
    ADD COLUMN minimum_application_major INTEGER NOT NULL DEFAULT 1
    CHECK (minimum_application_major > 0);
ALTER TABLE schema_migrations
    ADD COLUMN maximum_application_major INTEGER NOT NULL DEFAULT 1
    CHECK (maximum_application_major >= minimum_application_major);
ALTER TABLE schema_migrations
    ADD COLUMN online INTEGER NOT NULL DEFAULT 0
    CHECK (online IN (0, 1));
