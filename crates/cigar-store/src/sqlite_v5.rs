//! Fresh-target SQLite v5 activation, atomic revision publication, and bounded replay.

use crate::memory::{CommittedState, StagedMutation, blob_digest, validate};
use crate::revision_delta::{
    MAX_ACCUMULATED_DELTA_BYTES_V5, MAX_DELTAS_SINCE_CHECKPOINT_V5, MAX_REPLAY_OPERATIONS_V5,
    MAX_REPOSITORY_CHECKPOINT_BYTES_V5, MAX_REPOSITORY_DELTA_BYTES_V5,
    MAX_REPOSITORY_DELTA_OPERATIONS_V5, PreparedRepositoryDeltaV5, RepositoryChainLinkV5,
    RepositoryCheckpointReasonV5, RepositoryCheckpointV5, RepositoryLogicalTotalsV5,
    apply_repository_delta_v5, catalog_mutation_commitment_from_records_v5,
    decode_catalog_free_state_v5, encode_catalog_free_state_v5, migration_receipt_schema_digest_v1,
    repository_chain_head_v5, repository_delta_from_service_v5, repository_delta_from_staged_v5,
    repository_delta_from_worker_v5, repository_genesis_parent_chain_head_v5,
    repository_result_state_digest_v5, repository_semantic_root_v5,
};
use crate::service_repository::{
    EffectRecoveryPage, EffectRecoveryQuery, OutboxRecoveryPage, OutboxRecoveryQuery, ServiceBatch,
    ServiceBatchReceipt, ServiceError, ServiceErrorCode, ServiceListPage, ServiceListQuery,
    ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRepository, WorkerLocator,
    WorkerState, WorkerUpdate, apply_service_batch, apply_worker_update, check_cancellation,
    effect_recovery_from_state, map_store_error, outbox_recovery_from_state,
    service_get_from_state, service_list_from_state, worker_get_from_state,
};
use crate::sqlite::{
    acquire_sqlite_runtime_shared_lock, apply_catalog_batch, catalog_root_from_table, configure,
    for_each_authenticated_v4_migration_revision, measure_startup_stage, persist_catalog_bucket,
    preflight_capacity_profile, prepare_secure_sqlite_path, read_revision_anchor,
    staged_logical_bytes, validate_staged_shape, verify_migrated_v5_catalog_history,
    verify_migrated_v5_catalog_history_range, verify_migrated_v5_latest_state_and_projection,
    verify_secure_sqlite_path, verify_v5_latest_state_and_projection, write_revision_anchor,
};
use crate::{
    AccessContext, BlobRecord, CancellationToken, CommitReceipt, EffectRecordEnvelope,
    IdempotencyIdentity, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES, MAX_SQLITE_DATABASE_BYTES,
    OutboxMessage, Repository, RepositoryBlobStore, RepositoryCommitBytes,
    RepositoryCommitDurations, RepositoryCommitKind, RepositoryCommitMetrics,
    RepositoryCommitMetricsObserver, RepositoryCommitOutcome, RepositoryRetentionCounts,
    RepositoryStartupMetricsObserver, RepositoryStartupStage, SnapshotSelection,
    SqliteCapacityProfile, SqliteReadTransaction, StoreError, StoreErrorCode, StoreRevision,
    WriteTransaction,
};
use cigar_protocol::{
    ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, EffectJournalEvent,
    RecordId, SourceSnapshot,
};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

const POLICY_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-RETENTION-POLICY";
const MAXIMUM_RETENTION_AGE_NANOS_V5: u64 = 315_576_000_000_000_000;
pub(crate) const MAXIMUM_RETAINED_REVISIONS_V5: u64 = 10_000_000;
const STANDARD_RETAINED_BYTES_V5: u64 = 3_221_225_472;
const LARGE_LOCAL_RETAINED_BYTES_V5: u64 = 64_424_509_440;
const DEFAULT_RETAINED_REVISIONS_V5: u64 = 100_000;
const DEFAULT_RETENTION_AGE_NANOS_V5: u64 = 2_592_000_000_000_000;
const RETENTION_HEADROOM_BYTES_V5: u64 = 67_108_864;

#[cfg(test)]
fn process_kill_failpoint_v5(stage: &str) {
    if std::env::var("CIGAR_V5_PROCESS_KILL_STAGE").as_deref() == Ok(stage) {
        std::process::abort();
    }
}

#[cfg(not(test))]
fn process_kill_failpoint_v5(_stage: &str) {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RepositoryPolicyV5 {
    maximum_delta_operations: u64,
    maximum_delta_bytes: u64,
    maximum_checkpoint_bytes: u64,
    maximum_deltas_since_checkpoint: u64,
    maximum_accumulated_delta_bytes: u64,
    maximum_retained_revisions: u64,
    maximum_retained_age_nanos: u64,
    maximum_physical_retained_bytes: u64,
    minimum_reconstructable_revisions: u64,
    minimum_verified_replay_revisions: u64,
}

impl RepositoryPolicyV5 {
    fn qualification(capacity_profile: &str) -> Result<Self, StoreError> {
        Self::new(
            u64::try_from(MAX_DELTAS_SINCE_CHECKPOINT_V5).map_err(|_error| limit_exceeded())?,
            u64::try_from(MAX_ACCUMULATED_DELTA_BYTES_V5).map_err(|_error| limit_exceeded())?,
            capacity_profile,
        )
    }

    fn new(
        maximum_deltas_since_checkpoint: u64,
        maximum_accumulated_delta_bytes: u64,
        capacity_profile: &str,
    ) -> Result<Self, StoreError> {
        let maximum_physical_retained_bytes = match capacity_profile {
            "standard" => STANDARD_RETAINED_BYTES_V5,
            "large_local" => LARGE_LOCAL_RETAINED_BYTES_V5,
            _ => return Err(invalid_record()),
        };
        let policy = Self {
            maximum_delta_operations: u64::try_from(MAX_REPOSITORY_DELTA_OPERATIONS_V5)
                .map_err(|_error| limit_exceeded())?,
            maximum_delta_bytes: u64::try_from(MAX_REPOSITORY_DELTA_BYTES_V5)
                .map_err(|_error| limit_exceeded())?,
            maximum_checkpoint_bytes: u64::try_from(MAX_REPOSITORY_CHECKPOINT_BYTES_V5)
                .map_err(|_error| limit_exceeded())?,
            maximum_deltas_since_checkpoint,
            maximum_accumulated_delta_bytes,
            maximum_retained_revisions: DEFAULT_RETAINED_REVISIONS_V5,
            maximum_retained_age_nanos: DEFAULT_RETENTION_AGE_NANOS_V5,
            maximum_physical_retained_bytes,
            minimum_reconstructable_revisions: maximum_deltas_since_checkpoint.max(256),
            minimum_verified_replay_revisions: maximum_deltas_since_checkpoint.max(256),
        };
        policy.validate(capacity_profile)?;
        Ok(policy)
    }

    fn validate(self, capacity_profile: &str) -> Result<(), StoreError> {
        let capacity_bytes = match capacity_profile {
            "standard" => MAX_SQLITE_DATABASE_BYTES,
            "large_local" => MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES,
            _ => return Err(invalid_record()),
        };
        let minimum_retained_bytes = self
            .maximum_checkpoint_bytes
            .checked_add(self.maximum_accumulated_delta_bytes)
            .and_then(|value| value.checked_add(RETENTION_HEADROOM_BYTES_V5))
            .ok_or_else(limit_exceeded)?;
        if self.maximum_delta_operations == 0
            || self.maximum_delta_operations
                > u64::try_from(MAX_REPOSITORY_DELTA_OPERATIONS_V5)
                    .map_err(|_error| limit_exceeded())?
            || self.maximum_delta_bytes == 0
            || self.maximum_delta_bytes
                > u64::try_from(MAX_REPOSITORY_DELTA_BYTES_V5).map_err(|_error| limit_exceeded())?
            || self.maximum_checkpoint_bytes == 0
            || self.maximum_checkpoint_bytes
                > u64::try_from(MAX_REPOSITORY_CHECKPOINT_BYTES_V5)
                    .map_err(|_error| limit_exceeded())?
            || self.maximum_deltas_since_checkpoint == 0
            || self.maximum_deltas_since_checkpoint
                > u64::try_from(MAX_DELTAS_SINCE_CHECKPOINT_V5)
                    .map_err(|_error| limit_exceeded())?
            || self.maximum_accumulated_delta_bytes == 0
            || self.maximum_accumulated_delta_bytes
                > u64::try_from(MAX_ACCUMULATED_DELTA_BYTES_V5)
                    .map_err(|_error| limit_exceeded())?
            || self.maximum_retained_revisions == 0
            || self.maximum_retained_revisions > MAXIMUM_RETAINED_REVISIONS_V5
            || self.maximum_retained_age_nanos == 0
            || self.maximum_retained_age_nanos > MAXIMUM_RETENTION_AGE_NANOS_V5
            || self.maximum_physical_retained_bytes < minimum_retained_bytes
            || self.maximum_physical_retained_bytes > capacity_bytes
            || self.minimum_reconstructable_revisions < self.maximum_deltas_since_checkpoint
            || self.minimum_verified_replay_revisions < self.maximum_deltas_since_checkpoint
            || self.maximum_retained_revisions < self.minimum_reconstructable_revisions
            || self.maximum_retained_revisions < self.minimum_verified_replay_revisions
        {
            return Err(limit_exceeded());
        }
        Ok(())
    }

    fn digest(self, capacity_profile: &str) -> Result<ContentDigest, StoreError> {
        self.validate(capacity_profile)?;
        digest_fields(
            POLICY_DOMAIN,
            &[
                &self.maximum_delta_operations.to_be_bytes(),
                &self.maximum_delta_bytes.to_be_bytes(),
                &self.maximum_checkpoint_bytes.to_be_bytes(),
                &self.maximum_deltas_since_checkpoint.to_be_bytes(),
                &self.maximum_accumulated_delta_bytes.to_be_bytes(),
                &self.maximum_retained_revisions.to_be_bytes(),
                &self.maximum_retained_age_nanos.to_be_bytes(),
                &self.maximum_physical_retained_bytes.to_be_bytes(),
                &self.minimum_reconstructable_revisions.to_be_bytes(),
                &self.minimum_verified_replay_revisions.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryPayloadKindV5 {
    Delta,
    Checkpoint(RepositoryCheckpointReasonV5),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryCommitV5 {
    revision: StoreRevision,
    chain_head: ContentDigest,
    payload_kind: RepositoryPayloadKindV5,
    encoded_delta_bytes: u64,
    checkpoint_bytes: u64,
}

pub(crate) struct MigratedRepositoryV5 {
    pub(crate) first_revision: StoreRevision,
    pub(crate) latest_revision: StoreRevision,
    pub(crate) retained_revisions: u64,
    pub(crate) checkpoint_bytes: u64,
    pub(crate) chain_head: ContentDigest,
    pub(crate) catalog_root: ContentDigest,
    pub(crate) semantic_root: ContentDigest,
}

pub(crate) fn verify_migrated_repository_v5(connection: &Connection) -> Result<u64, StoreError> {
    require_full_durability(connection)?;
    let authority = load_authority(connection)?;
    let range = connection
        .query_row(
            "SELECT MIN(revision), MAX(revision), COUNT(*),
                    (SELECT COUNT(*) FROM repository_checkpoints_v5),
                    (SELECT COUNT(*) FROM repository_deltas_v5),
                    (SELECT COUNT(*) FROM cigar_repository_revisions_v4)
             FROM repository_revisions_v5",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let first = range
        .0
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    let latest = range
        .1
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    let retained = u64::try_from(range.2).map_err(|_error| invalid_record())?;
    if latest != authority.current_revision
        || latest
            .0
            .checked_sub(first.0)
            .and_then(|value| value.checked_add(1))
            != Some(retained)
        || range.2 != range.3
        || range.4 != 0
        || range.5 != 1
    {
        return Err(invalid_record());
    }
    if verify_migrated_v5_catalog_history(connection)? != retained {
        return Err(invalid_record());
    }
    let mut revision = first;
    let latest_state = loop {
        let state = reconstruct_repository_revision_v5(connection, revision)?;
        if state.revision != revision {
            return Err(invalid_record());
        }
        if revision == latest {
            break state;
        }
        revision = revision
            .0
            .checked_add(1)
            .map(StoreRevision)
            .ok_or_else(limit_exceeded)?;
    };
    verify_migrated_v5_latest_state_and_projection(connection, &latest_state)?;
    Ok(retained)
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
enum RepositoryCommitAttemptV5 {
    Committed(RepositoryCommitV5),
    Replayed(CommitReceipt),
}

/// Content-free authenticated retention state for one SQLite v5 repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteRetentionStatisticsV5 {
    /// Current authenticated repository revision.
    pub current_revision: StoreRevision,
    /// Earliest exactly reconstructable retained revision.
    pub reconstructable_first_revision: StoreRevision,
    /// Latest exactly reconstructable retained revision.
    pub reconstructable_last_revision: StoreRevision,
    /// Earliest revision protected by replay minimums or an active pin.
    pub protected_first_revision: StoreRevision,
    /// Number of retained revision envelopes.
    pub retained_revisions: u64,
    /// Number of retained full checkpoints.
    pub retained_checkpoints: u64,
    /// Number of retained typed deltas.
    pub retained_deltas: u64,
    /// Canonical bytes held by retained checkpoints.
    pub retained_checkpoint_bytes: u64,
    /// Canonical bytes held by retained deltas.
    pub retained_delta_bytes: u64,
    /// Conservative payload bytes covered by replay minimums or active pins.
    pub protected_payload_bytes: u64,
    /// SQLite logical page bytes currently allocated.
    pub database_logical_bytes: u64,
    /// Active legal-hold pins.
    pub active_legal_hold_pins: u64,
    /// Active replay pins.
    pub active_replay_pins: u64,
    /// Active backup pins.
    pub active_backup_pins: u64,
    /// Active explicit pins.
    pub active_explicit_pins: u64,
    /// Maximum retained revisions from authenticated effective policy.
    pub maximum_retained_revisions: u64,
    /// Maximum retention age in nanoseconds from authenticated effective policy.
    pub maximum_retained_age_nanos: u64,
    /// Maximum physical retained bytes from authenticated effective policy.
    pub maximum_physical_retained_bytes: u64,
    /// Minimum reconstructable revision window.
    pub minimum_reconstructable_revisions: u64,
    /// Minimum fully verified replay window.
    pub minimum_verified_replay_revisions: u64,
    /// Maximum deltas following one checkpoint.
    pub maximum_deltas_since_checkpoint: u64,
    /// Maximum canonical delta bytes following one checkpoint.
    pub maximum_accumulated_delta_bytes: u64,
    /// True when another write must fail until authorized compaction or policy correction.
    pub capacity_blocked: bool,
    /// Authenticated effective policy identity.
    pub policy_digest: ContentDigest,
    /// Authenticated current revision-chain head.
    pub chain_head: ContentDigest,
}

/// Content-free result of the bounded v5 readiness authentication path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteStartupVerificationV5 {
    /// Latest authenticated repository revision.
    pub current_revision: StoreRevision,
    /// Latest checkpoint selected for readiness.
    pub checkpoint_revision: StoreRevision,
    /// Consecutive authenticated deltas replayed after the checkpoint.
    pub replayed_deltas: u64,
    /// Canonical bytes in the replayed delta suffix.
    pub replayed_delta_bytes: u64,
    /// Typed operations in the replayed delta suffix.
    pub replayed_operations: u64,
    /// Retained revision envelopes observed without hydrating their payloads.
    pub retained_revisions: u64,
    /// Atoms in the verified active projection.
    pub projection_atom_count: u64,
    /// Authenticated current chain head.
    pub chain_head: ContentDigest,
    /// Authenticated effective retention policy.
    pub policy_digest: ContentDigest,
}

/// Previously signed retained-history prefix accepted by an incremental deep check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPrefixStateV5 {
    pub(crate) first_revision: StoreRevision,
    pub(crate) through_revision: StoreRevision,
    pub(crate) through_chain_head: ContentDigest,
    pub(crate) policy_digest: ContentDigest,
}

/// Content-free result of a full or signed-prefix incremental v5 deep check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteDeepIntegrityReportV5 {
    /// First retained revision at verification time.
    pub first_retained_revision: StoreRevision,
    /// Current authenticated revision at verification time.
    pub current_revision: StoreRevision,
    /// First revision newly checked, or `None` when the signed prefix already covered the head.
    pub verified_from_revision: Option<StoreRevision>,
    /// Last revision covered by the completed check.
    pub verified_through_revision: StoreRevision,
    /// Revision payloads newly authenticated by this invocation.
    pub verified_revisions: u64,
    /// Revisions trusted through a validated signed prefix.
    pub reused_prefix_revisions: u64,
    /// Current normalized atoms checked against the active projection.
    pub projection_atom_count: u64,
    /// Authenticated current chain head.
    pub chain_head: ContentDigest,
    /// Authenticated effective retention policy.
    pub policy_digest: ContentDigest,
}

/// Authenticated unsigned compaction candidate derived under an offline exclusive lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactionPreviewStateV5 {
    pub(crate) head_revision: StoreRevision,
    pub(crate) chain_head: ContentDigest,
    pub(crate) policy_digest: ContentDigest,
    pub(crate) pins_digest: ContentDigest,
    pub(crate) current_first_revision: StoreRevision,
    pub(crate) compacted_first_revision: StoreRevision,
    pub(crate) candidate_last_revision: StoreRevision,
    pub(crate) candidate_revisions: u64,
    pub(crate) candidate_checkpoints: u64,
    pub(crate) candidate_deltas: u64,
    pub(crate) estimated_reclaimable_bytes: u64,
    pub(crate) retained_revisions: u64,
}

pub(crate) fn preview_repository_compaction_v5(
    connection: &Connection,
) -> Result<CompactionPreviewStateV5, StoreError> {
    require_full_durability(connection)?;
    let authority = load_authority(connection)?;
    let statistics = retention_statistics_v5(connection)?;
    let earliest_pin = connection
        .query_row(
            "SELECT MIN(first_revision) FROM repository_retention_pins_v5",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(unavailable)?
        .map(store_revision)
        .transpose()?;
    let protected_first = earliest_pin.map_or(statistics.protected_first_revision, |pin| {
        StoreRevision(pin.0.min(statistics.protected_first_revision.0))
    });
    let compacted_first = connection
        .query_row(
            "SELECT MAX(revision) FROM repository_checkpoints_v5 WHERE revision <= ?1",
            params![sqlite_revision(protected_first)?],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(unavailable)?
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    if compacted_first.0 <= statistics.reconstructable_first_revision.0 {
        return Err(StoreError::new(StoreErrorCode::NotFound));
    }
    let candidate_last = StoreRevision(
        compacted_first
            .0
            .checked_sub(1)
            .ok_or_else(invalid_record)?,
    );
    let candidates = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN c.revision IS NOT NULL THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN d.revision IS NOT NULL THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(COALESCE(c.encoded_bytes, d.encoded_bytes, 0)), 0)
             FROM repository_revisions_v5 r
             LEFT JOIN repository_checkpoints_v5 c ON c.revision = r.revision
             LEFT JOIN repository_deltas_v5 d ON d.revision = r.revision
             WHERE r.revision < ?1",
            params![sqlite_revision(compacted_first)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let candidate_revisions = u64::try_from(candidates.0).map_err(|_error| invalid_record())?;
    let retained_revisions = authority
        .current_revision
        .0
        .checked_sub(compacted_first.0)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(invalid_record)?;
    if candidate_revisions == 0
        || candidate_revisions.checked_add(retained_revisions)
            != Some(statistics.retained_revisions)
    {
        return Err(invalid_record());
    }
    Ok(CompactionPreviewStateV5 {
        head_revision: authority.current_revision,
        chain_head: authority.chain_head,
        policy_digest: authority.policy_digest,
        pins_digest: retention_pin_set_digest_v5(connection)?,
        current_first_revision: statistics.reconstructable_first_revision,
        compacted_first_revision: compacted_first,
        candidate_last_revision: candidate_last,
        candidate_revisions,
        candidate_checkpoints: u64::try_from(candidates.1).map_err(|_error| invalid_record())?,
        candidate_deltas: u64::try_from(candidates.2).map_err(|_error| invalid_record())?,
        estimated_reclaimable_bytes: u64::try_from(candidates.3)
            .map_err(|_error| invalid_record())?,
        retained_revisions,
    })
}

fn retention_pin_set_digest_v5(connection: &Connection) -> Result<ContentDigest, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT pin_id, first_revision, last_revision, reason, authority_digest,
                    policy_digest, issued_at_unix_nanos, COALESCE(expires_at_unix_nanos, ''),
                    receipt_digest, signature_identity_digest, hex(signature), verification_state,
                    state, COALESCE(released_at_unix_nanos, '')
             FROM repository_retention_pins_v5 ORDER BY pin_id",
        )
        .map_err(unavailable)?;
    let mut rows = statement.query([]).map_err(unavailable)?;
    let mut hash = Sha256::new();
    hash.update(b"CIGAR-REPOSITORY-RETENTION-PINS\0v5\0");
    let mut count = 0_u64;
    while let Some(row) = rows.next().map_err(unavailable)? {
        count = count.checked_add(1).ok_or_else(limit_exceeded)?;
        for index in 0..14 {
            let value = if matches!(index, 1 | 2) {
                row.get::<_, i64>(index).map_err(unavailable)?.to_string()
            } else {
                row.get::<_, String>(index).map_err(unavailable)?
            };
            hash.update(
                u64::try_from(value.len())
                    .map_err(|_error| limit_exceeded())?
                    .to_be_bytes(),
            );
            hash.update(value.as_bytes());
        }
    }
    hash.update(count.to_be_bytes());
    let suffix = hash.finalize();
    let mut value = String::from("1220");
    for byte in suffix {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| invalid_record())?;
    }
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

pub(crate) fn execute_repository_compaction_v5(
    connection: &mut Connection,
    expected: &CompactionPreviewStateV5,
    preview_digest: &ContentDigest,
    executed_at_unix_nanos: u128,
) -> Result<u64, StoreError> {
    let observed = preview_repository_compaction_v5(connection)?;
    if &observed != expected {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let origin_previous_head = connection
        .query_row(
            "SELECT previous_chain_head FROM repository_revisions_v5 WHERE revision = ?1",
            params![sqlite_revision(expected.compacted_first_revision)?],
            |row| row.get::<_, String>(0),
        )
        .map_err(unavailable)?;
    ContentDigest::new(origin_previous_head.clone()).map_err(|_error| invalid_record())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    transaction
        .pragma_update(None, "defer_foreign_keys", true)
        .map_err(unavailable)?;
    transaction
        .execute("DELETE FROM repository_compaction_origin_v5", [])
        .map_err(unavailable)?;
    transaction
        .execute(
            "DELETE FROM repository_deltas_v5 WHERE revision < ?1",
            params![sqlite_revision(expected.compacted_first_revision)?],
        )
        .map_err(unavailable)?;
    transaction
        .execute(
            "DELETE FROM repository_checkpoints_v5 WHERE revision < ?1",
            params![sqlite_revision(expected.compacted_first_revision)?],
        )
        .map_err(unavailable)?;
    transaction
        .execute(
            "DELETE FROM repository_revisions_v5 WHERE revision < ?1",
            params![sqlite_revision(expected.compacted_first_revision)?],
        )
        .map_err(unavailable)?;
    if transaction
        .execute(
            "UPDATE repository_revisions_v5 SET parent_revision = NULL WHERE revision = ?1",
            params![sqlite_revision(expected.compacted_first_revision)?],
        )
        .map_err(unavailable)?
        != 1
    {
        return Err(invalid_record());
    }
    transaction
        .execute(
            "INSERT INTO repository_compaction_origin_v5
                (singleton, origin_revision, prior_first_revision, removed_through_revision,
                 prior_chain_head, preview_digest, executed_at_unix_nanos, verification_state)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, 'complete')",
            params![
                sqlite_revision(expected.compacted_first_revision)?,
                sqlite_revision(expected.current_first_revision)?,
                sqlite_revision(expected.candidate_last_revision)?,
                origin_previous_head,
                preview_digest.as_str(),
                executed_at_unix_nanos.to_string(),
            ],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    let after = retention_statistics_v5(connection)?;
    if after.current_revision != expected.head_revision
        || after.reconstructable_first_revision != expected.compacted_first_revision
        || after.reconstructable_last_revision != expected.head_revision
        || after.retained_revisions != expected.retained_revisions
        || after.chain_head != expected.chain_head
        || after.policy_digest != expected.policy_digest
        || retention_pin_set_digest_v5(connection)? != expected.pins_digest
    {
        return Err(invalid_record());
    }
    let mut revision = expected.compacted_first_revision;
    loop {
        if reconstruct_repository_revision_v5(connection, revision)?.revision != revision {
            return Err(invalid_record());
        }
        if revision == expected.head_revision {
            break;
        }
        revision = StoreRevision(revision.0.checked_add(1).ok_or_else(limit_exceeded)?);
    }
    Ok(after.retained_revisions)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ActivePinCountsV5 {
    legal_hold: u64,
    replay: u64,
    backup: u64,
    explicit: u64,
    earliest_revision: Option<StoreRevision>,
}

fn invalid_record() -> StoreError {
    StoreError::new(StoreErrorCode::InvalidRecord)
}

fn unavailable(_error: rusqlite::Error) -> StoreError {
    StoreError::new(StoreErrorCode::Unavailable)
}

fn limit_exceeded() -> StoreError {
    StoreError::new(StoreErrorCode::LimitExceeded)
}

fn sqlite_revision(revision: StoreRevision) -> Result<i64, StoreError> {
    i64::try_from(revision.0).map_err(|_error| limit_exceeded())
}

fn store_revision(revision: i64) -> Result<StoreRevision, StoreError> {
    u64::try_from(revision)
        .map(StoreRevision)
        .map_err(|_error| invalid_record())
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Result<ContentDigest, StoreError> {
    let mut hash = Sha256::new();
    hash.update(
        u64::try_from(domain.len())
            .map_err(|_error| limit_exceeded())?
            .to_be_bytes(),
    );
    hash.update(domain);
    for field in fields {
        hash.update(
            u64::try_from(field.len())
                .map_err(|_error| limit_exceeded())?
                .to_be_bytes(),
        );
        hash.update(field);
    }
    let suffix = hash.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    for byte in suffix {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| invalid_record())?;
    }
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

fn require_full_durability(connection: &Connection) -> Result<(), StoreError> {
    let synchronous = connection
        .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let foreign_keys = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let defensive = connection
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .map_err(unavailable)?;
    if synchronous != 2 || foreign_keys != 1 || !defensive {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

fn catalog_totals(connection: &Connection) -> Result<RepositoryLogicalTotalsV5, StoreError> {
    let (atoms, edges, blobs) = connection
        .query_row(
            "SELECT COALESCE(SUM(atom_count), 0), COALESCE(SUM(edge_count), 0),
                    COALESCE(SUM(referenced_blob_bytes), 0)
             FROM cigar_catalog_root_buckets",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(unavailable)?;
    Ok(RepositoryLogicalTotalsV5 {
        atom_count: u64::try_from(atoms).map_err(|_error| invalid_record())?,
        edge_count: u64::try_from(edges).map_err(|_error| invalid_record())?,
        referenced_blob_bytes: u64::try_from(blobs).map_err(|_error| invalid_record())?,
    })
}

fn catalog_mutation_commitment_at_revision(
    connection: &Connection,
    revision: StoreRevision,
) -> Result<(ContentDigest, u32), StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT 'atom', record FROM cigar_catalog_atoms WHERE published_revision = ?1
             UNION ALL
             SELECT 'edge', record FROM cigar_catalog_edges WHERE published_revision = ?1",
        )
        .map_err(unavailable)?;
    let rows = statement
        .query_map(params![sqlite_revision(revision)?], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(unavailable)?;
    let mut records = Vec::new();
    for row in rows {
        if records.len() >= MAX_REPOSITORY_DELTA_OPERATIONS_V5 {
            return Err(limit_exceeded());
        }
        records.push(row.map_err(unavailable)?);
    }
    catalog_mutation_commitment_from_records_v5(records)
}

struct RevisionEnvelopeV5<'a> {
    revision: StoreRevision,
    parent_revision: Option<StoreRevision>,
    state_digest: &'a ContentDigest,
    catalog_root: &'a ContentDigest,
    semantic_root: &'a ContentDigest,
    totals: RepositoryLogicalTotalsV5,
    previous_chain_head: &'a ContentDigest,
    chain_head: &'a ContentDigest,
}

fn insert_revision(
    transaction: &Transaction<'_>,
    envelope: RevisionEnvelopeV5<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO repository_revisions_v5
                (revision, parent_revision, state_digest, catalog_root, semantic_root,
                 atom_count, edge_count, referenced_blob_bytes, previous_chain_head, chain_head)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                sqlite_revision(envelope.revision)?,
                envelope.parent_revision.map(sqlite_revision).transpose()?,
                envelope.state_digest.as_str(),
                envelope.catalog_root.as_str(),
                envelope.semantic_root.as_str(),
                i64::try_from(envelope.totals.atom_count).map_err(|_error| limit_exceeded())?,
                i64::try_from(envelope.totals.edge_count).map_err(|_error| limit_exceeded())?,
                i64::try_from(envelope.totals.referenced_blob_bytes)
                    .map_err(|_error| limit_exceeded())?,
                envelope.previous_chain_head.as_str(),
                envelope.chain_head.as_str(),
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn insert_checkpoint(
    transaction: &Transaction<'_>,
    checkpoint: &RepositoryCheckpointV5,
    chain_head: &ContentDigest,
) -> Result<u64, StoreError> {
    let encoded = checkpoint.encode()?;
    let encoded_bytes = u64::try_from(encoded.len()).map_err(|_error| limit_exceeded())?;
    let digest = checkpoint.checkpoint_digest()?;
    let totals = checkpoint.totals();
    process_kill_failpoint_v5("before_checkpoint_insert");
    transaction
        .execute(
            "INSERT INTO repository_checkpoints_v5
                (revision, format_version, canonical_state, encoded_bytes, checkpoint_digest,
                 state_digest, catalog_root, semantic_root, atom_count, edge_count,
                 referenced_blob_bytes, previous_chain_head, chain_head, reason)
             VALUES (?1, 5, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                sqlite_revision(checkpoint.revision())?,
                encoded,
                i64::try_from(encoded_bytes).map_err(|_error| limit_exceeded())?,
                digest.as_str(),
                checkpoint.state_digest().as_str(),
                checkpoint.catalog_root().as_str(),
                checkpoint.semantic_root().as_str(),
                i64::try_from(totals.atom_count).map_err(|_error| limit_exceeded())?,
                i64::try_from(totals.edge_count).map_err(|_error| limit_exceeded())?,
                i64::try_from(totals.referenced_blob_bytes).map_err(|_error| limit_exceeded())?,
                checkpoint.parent_chain_head().as_str(),
                chain_head.as_str(),
                match checkpoint.reason() {
                    RepositoryCheckpointReasonV5::Genesis => "genesis",
                    RepositoryCheckpointReasonV5::Migration => "migration",
                    RepositoryCheckpointReasonV5::DeltaCount => "delta_count",
                    RepositoryCheckpointReasonV5::DeltaBytes => "delta_bytes",
                    RepositoryCheckpointReasonV5::Compaction => "compaction",
                },
            ],
        )
        .map_err(unavailable)?;
    process_kill_failpoint_v5("after_checkpoint_insert");
    Ok(encoded_bytes)
}

#[cfg(test)]
fn activate_fresh_target_repository_v5_with_policy(
    connection: &mut Connection,
    capacity_profile: &str,
    created_at_unix_nanos: u64,
    policy: RepositoryPolicyV5,
) -> Result<RepositoryCommitV5, StoreError> {
    if !matches!(capacity_profile, "standard" | "large_local") {
        return Err(invalid_record());
    }
    policy.validate(capacity_profile)?;
    require_full_durability(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let schema: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations
             WHERE sequence = 5 AND name = 'incremental_repository_state'",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    let authority: i64 = transaction
        .query_row("SELECT COUNT(*) FROM repository_authority_v5", [], |row| {
            row.get(0)
        })
        .map_err(unavailable)?;
    if schema != 1 || authority != 0 {
        return Err(invalid_record());
    }

    let state = CommittedState::default();
    let canonical_state = encode_catalog_free_state_v5(&state)?;
    let catalog_root = catalog_root_from_table(&transaction)?;
    let totals = catalog_totals(&transaction)?;
    let state_digest = crate::revision_delta::repository_state_digest_v5(&canonical_state)?;
    let semantic_root =
        repository_semantic_root_v5(state.revision, &state_digest, &catalog_root, totals)?;
    let previous_chain_head = repository_genesis_parent_chain_head_v5()?;
    let checkpoint = RepositoryCheckpointV5::new(
        state.revision,
        canonical_state,
        catalog_root.clone(),
        semantic_root.clone(),
        previous_chain_head.clone(),
        totals,
        RepositoryCheckpointReasonV5::Genesis,
    )?;
    let checkpoint_digest = checkpoint.checkpoint_digest()?;
    let chain_head = repository_chain_head_v5(&RepositoryChainLinkV5 {
        previous_chain_head: &previous_chain_head,
        revision: state.revision,
        delta_or_checkpoint_digest: &checkpoint_digest,
        state_digest: &state_digest,
        catalog_root: &catalog_root,
        semantic_root: &semantic_root,
        totals,
        capacity_profile,
    })?;
    insert_revision(
        &transaction,
        RevisionEnvelopeV5 {
            revision: state.revision,
            parent_revision: None,
            state_digest: &state_digest,
            catalog_root: &catalog_root,
            semantic_root: &semantic_root,
            totals,
            previous_chain_head: &previous_chain_head,
            chain_head: &chain_head,
        },
    )?;
    let checkpoint_bytes = insert_checkpoint(&transaction, &checkpoint, &chain_head)?;
    let policy_digest = policy.digest(capacity_profile)?;
    transaction
        .execute(
            "INSERT INTO repository_authority_v5
                (singleton, format_version, capacity_profile, activated, current_revision,
                 chain_head, state_digest, catalog_root, semantic_root,
                 migration_receipt_schema_digest, retention_policy_digest,
                 maximum_delta_operations, maximum_delta_bytes, maximum_checkpoint_bytes,
                 maximum_deltas_since_checkpoint, maximum_accumulated_delta_bytes,
                 maximum_retained_revisions, maximum_retained_age_nanos,
                 maximum_physical_retained_bytes, minimum_reconstructable_revisions,
                 minimum_verified_replay_revisions, created_at_unix_nanos)
             VALUES (1, 5, ?1, 1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                capacity_profile,
                chain_head.as_str(),
                state_digest.as_str(),
                catalog_root.as_str(),
                semantic_root.as_str(),
                migration_receipt_schema_digest_v1()?.as_str(),
                policy_digest.as_str(),
                i64::try_from(policy.maximum_delta_operations).map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_delta_bytes).map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_checkpoint_bytes).map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_deltas_since_checkpoint)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_accumulated_delta_bytes)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_retained_revisions)
                    .map_err(|_error| limit_exceeded())?,
                policy.maximum_retained_age_nanos.to_string(),
                i64::try_from(policy.maximum_physical_retained_bytes)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.minimum_reconstructable_revisions)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.minimum_verified_replay_revisions)
                    .map_err(|_error| limit_exceeded())?,
                created_at_unix_nanos.to_string(),
            ],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    Ok(RepositoryCommitV5 {
        revision: StoreRevision(0),
        chain_head,
        payload_kind: RepositoryPayloadKindV5::Checkpoint(RepositoryCheckpointReasonV5::Genesis),
        encoded_delta_bytes: 0,
        checkpoint_bytes,
    })
}

#[cfg(test)]
fn activate_fresh_target_repository_v5(
    connection: &mut Connection,
    capacity_profile: &str,
    created_at_unix_nanos: u64,
) -> Result<RepositoryCommitV5, StoreError> {
    activate_fresh_target_repository_v5_with_policy(
        connection,
        capacity_profile,
        created_at_unix_nanos,
        RepositoryPolicyV5::qualification(capacity_profile)?,
    )
}

pub(crate) fn construct_migrated_repository_v5(
    connection: &mut Connection,
    source: &Path,
    capacity_profile: &str,
    created_at_unix_nanos: u64,
) -> Result<MigratedRepositoryV5, StoreError> {
    if !matches!(capacity_profile, "standard" | "large_local") {
        return Err(invalid_record());
    }
    let policy = RepositoryPolicyV5::qualification(capacity_profile)?;
    require_full_durability(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let schema: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations
             WHERE sequence = 5 AND name = 'incremental_repository_state'",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    let existing: (i64, i64, i64) = transaction
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM repository_authority_v5),
                (SELECT COUNT(*) FROM repository_revisions_v5),
                (SELECT COUNT(*) FROM repository_checkpoints_v5)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(unavailable)?;
    if schema != 1 || existing != (0, 0, 0) {
        return Err(invalid_record());
    }

    let genesis_parent = repository_genesis_parent_chain_head_v5()?;
    let mut previous_revision: Option<StoreRevision> = None;
    let mut previous_chain_head = genesis_parent;
    let mut first_revision = None;
    let mut retained_revisions = 0_u64;
    let mut checkpoint_bytes = 0_u64;
    let mut latest_catalog_root = None;
    let mut latest_semantic_root = None;
    let mut latest_state_digest = None;
    let streamed = for_each_authenticated_v4_migration_revision(source, |revision| {
        let current = revision.state.revision;
        if let Some(previous) = previous_revision {
            if previous.0.checked_add(1) != Some(current.0) {
                return Err(invalid_record());
            }
        } else {
            first_revision = Some(current);
        }
        let totals = RepositoryLogicalTotalsV5 {
            atom_count: revision.atom_count,
            edge_count: revision.edge_count,
            referenced_blob_bytes: revision.referenced_blob_bytes,
        };
        let canonical_state = encode_catalog_free_state_v5(&revision.state)?;
        let state_digest = crate::revision_delta::repository_state_digest_v5(&canonical_state)?;
        let checkpoint = RepositoryCheckpointV5::new(
            current,
            canonical_state,
            revision.catalog_root.clone(),
            revision.semantic_root.clone(),
            previous_chain_head.clone(),
            totals,
            RepositoryCheckpointReasonV5::Migration,
        )?;
        let checkpoint_digest = checkpoint.checkpoint_digest()?;
        let chain_head = repository_chain_head_v5(&RepositoryChainLinkV5 {
            previous_chain_head: &previous_chain_head,
            revision: current,
            delta_or_checkpoint_digest: &checkpoint_digest,
            state_digest: &state_digest,
            catalog_root: &revision.catalog_root,
            semantic_root: &revision.semantic_root,
            totals,
            capacity_profile,
        })?;
        insert_revision(
            &transaction,
            RevisionEnvelopeV5 {
                revision: current,
                parent_revision: previous_revision,
                state_digest: &state_digest,
                catalog_root: &revision.catalog_root,
                semantic_root: &revision.semantic_root,
                totals,
                previous_chain_head: &previous_chain_head,
                chain_head: &chain_head,
            },
        )?;
        checkpoint_bytes = checkpoint_bytes
            .checked_add(insert_checkpoint(&transaction, &checkpoint, &chain_head)?)
            .ok_or_else(limit_exceeded)?;
        retained_revisions = retained_revisions
            .checked_add(1)
            .ok_or_else(limit_exceeded)?;
        previous_revision = Some(current);
        previous_chain_head = chain_head;
        latest_catalog_root = Some(revision.catalog_root);
        latest_semantic_root = Some(revision.semantic_root);
        latest_state_digest = Some(state_digest);
        let _authenticated_source_residual = revision.residual_checksum;
        crate::migrate_v5::migration_v5_process_abort_if_armed(
            crate::migrate_v5::MigrationV5Failpoint::AfterRevisionBatch(current),
        );
        Ok(())
    })?;
    if streamed != retained_revisions {
        return Err(invalid_record());
    }
    let first_revision = first_revision.ok_or_else(invalid_record)?;
    let latest_revision = previous_revision.ok_or_else(invalid_record)?;
    let catalog_root = latest_catalog_root.ok_or_else(invalid_record)?;
    let semantic_root = latest_semantic_root.ok_or_else(invalid_record)?;
    let state_digest = latest_state_digest.ok_or_else(invalid_record)?;
    let target_catalog_root = catalog_root_from_table(&transaction)?;
    let target_totals = catalog_totals(&transaction)?;
    let final_envelope = transaction
        .query_row(
            "SELECT atom_count, edge_count, referenced_blob_bytes
             FROM repository_revisions_v5 WHERE revision = ?1",
            params![sqlite_revision(latest_revision)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let final_envelope = RepositoryLogicalTotalsV5 {
        atom_count: u64::try_from(final_envelope.0).map_err(|_error| invalid_record())?,
        edge_count: u64::try_from(final_envelope.1).map_err(|_error| invalid_record())?,
        referenced_blob_bytes: u64::try_from(final_envelope.2)
            .map_err(|_error| invalid_record())?,
    };
    if target_catalog_root != catalog_root || target_totals != final_envelope {
        return Err(invalid_record());
    }
    let policy_digest = policy.digest(capacity_profile)?;
    transaction
        .execute(
            "INSERT INTO repository_authority_v5
                (singleton, format_version, capacity_profile, activated, current_revision,
                 chain_head, state_digest, catalog_root, semantic_root,
                 migration_receipt_schema_digest, retention_policy_digest,
                 maximum_delta_operations, maximum_delta_bytes, maximum_checkpoint_bytes,
                 maximum_deltas_since_checkpoint, maximum_accumulated_delta_bytes,
                 maximum_retained_revisions, maximum_retained_age_nanos,
                 maximum_physical_retained_bytes, minimum_reconstructable_revisions,
                 minimum_verified_replay_revisions, created_at_unix_nanos)
             VALUES (1, 5, ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                     ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                capacity_profile,
                sqlite_revision(latest_revision)?,
                previous_chain_head.as_str(),
                state_digest.as_str(),
                catalog_root.as_str(),
                semantic_root.as_str(),
                migration_receipt_schema_digest_v1()?.as_str(),
                policy_digest.as_str(),
                i64::try_from(policy.maximum_delta_operations).map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_delta_bytes).map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_checkpoint_bytes).map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_deltas_since_checkpoint)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_accumulated_delta_bytes)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.maximum_retained_revisions)
                    .map_err(|_error| limit_exceeded())?,
                policy.maximum_retained_age_nanos.to_string(),
                i64::try_from(policy.maximum_physical_retained_bytes)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.minimum_reconstructable_revisions)
                    .map_err(|_error| limit_exceeded())?,
                i64::try_from(policy.minimum_verified_replay_revisions)
                    .map_err(|_error| limit_exceeded())?,
                created_at_unix_nanos.to_string(),
            ],
        )
        .map_err(unavailable)?;
    transaction
        .execute(
            "DELETE FROM cigar_repository_revisions_v4 WHERE revision != ?1",
            params![sqlite_revision(latest_revision)?],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    Ok(MigratedRepositoryV5 {
        first_revision,
        latest_revision,
        retained_revisions,
        checkpoint_bytes,
        chain_head: previous_chain_head,
        catalog_root,
        semantic_root,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorityV5 {
    capacity_profile: String,
    current_revision: StoreRevision,
    chain_head: ContentDigest,
    state_digest: ContentDigest,
    catalog_root: ContentDigest,
    semantic_root: ContentDigest,
    totals: RepositoryLogicalTotalsV5,
    policy: RepositoryPolicyV5,
    policy_digest: ContentDigest,
}

fn load_authority(connection: &Connection) -> Result<AuthorityV5, StoreError> {
    let row = connection
        .query_row(
            "SELECT capacity_profile, current_revision, chain_head, state_digest, catalog_root,
                    semantic_root, maximum_delta_operations, maximum_delta_bytes,
                    maximum_checkpoint_bytes, maximum_deltas_since_checkpoint,
                    maximum_accumulated_delta_bytes, maximum_retained_revisions,
                    maximum_retained_age_nanos, maximum_physical_retained_bytes,
                    minimum_reconstructable_revisions, minimum_verified_replay_revisions,
                    retention_policy_digest, migration_receipt_schema_digest
             FROM repository_authority_v5
             WHERE singleton = 1 AND format_version = 5 AND activated = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?
        .ok_or_else(invalid_record)?;
    let policy = RepositoryPolicyV5 {
        maximum_delta_operations: u64::try_from(row.6).map_err(|_error| invalid_record())?,
        maximum_delta_bytes: u64::try_from(row.7).map_err(|_error| invalid_record())?,
        maximum_checkpoint_bytes: u64::try_from(row.8).map_err(|_error| invalid_record())?,
        maximum_deltas_since_checkpoint: u64::try_from(row.9).map_err(|_error| invalid_record())?,
        maximum_accumulated_delta_bytes: u64::try_from(row.10)
            .map_err(|_error| invalid_record())?,
        maximum_retained_revisions: u64::try_from(row.11).map_err(|_error| invalid_record())?,
        maximum_retained_age_nanos: row.12.parse().map_err(|_error| invalid_record())?,
        maximum_physical_retained_bytes: u64::try_from(row.13)
            .map_err(|_error| invalid_record())?,
        minimum_reconstructable_revisions: u64::try_from(row.14)
            .map_err(|_error| invalid_record())?,
        minimum_verified_replay_revisions: u64::try_from(row.15)
            .map_err(|_error| invalid_record())?,
    };
    policy.validate(&row.0)?;
    let policy_digest = ContentDigest::new(row.16).map_err(|_error| invalid_record())?;
    if row.12 != policy.maximum_retained_age_nanos.to_string()
        || policy.digest(&row.0)? != policy_digest
        || ContentDigest::new(row.17).map_err(|_error| invalid_record())?
            != migration_receipt_schema_digest_v1()?
    {
        return Err(invalid_record());
    }
    Ok(AuthorityV5 {
        capacity_profile: row.0,
        current_revision: store_revision(row.1)?,
        chain_head: ContentDigest::new(row.2).map_err(|_error| invalid_record())?,
        state_digest: ContentDigest::new(row.3).map_err(|_error| invalid_record())?,
        catalog_root: ContentDigest::new(row.4).map_err(|_error| invalid_record())?,
        semantic_root: ContentDigest::new(row.5).map_err(|_error| invalid_record())?,
        totals: catalog_totals_from_revision(connection, store_revision(row.1)?)?,
        policy,
        policy_digest,
    })
}

struct AuthenticatedLatestV5 {
    state: CommittedState,
    first_revision: StoreRevision,
    checkpoint_revision: StoreRevision,
    replayed_deltas: u64,
    replayed_delta_bytes: u64,
    replayed_operations: u64,
    retained_revisions: u64,
    authority: AuthorityV5,
}

fn authenticate_latest_repository_state_v5(
    connection: &Connection,
) -> Result<AuthenticatedLatestV5, StoreError> {
    require_full_durability(connection)?;
    let authority = load_authority(connection)?;
    let checkpoint_revision = connection
        .query_row(
            "SELECT MAX(revision) FROM repository_checkpoints_v5 WHERE revision <= ?1",
            params![sqlite_revision(authority.current_revision)?],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(unavailable)?
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    let (replayed_deltas, replayed_delta_bytes, replayed_operations) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(encoded_bytes), 0), COALESCE(SUM(operation_count), 0)
             FROM repository_deltas_v5 WHERE revision > ?1 AND revision <= ?2",
            params![
                sqlite_revision(checkpoint_revision)?,
                sqlite_revision(authority.current_revision)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let replayed_deltas = u64::try_from(replayed_deltas).map_err(|_error| invalid_record())?;
    let replayed_delta_bytes =
        u64::try_from(replayed_delta_bytes).map_err(|_error| invalid_record())?;
    let replayed_operations =
        u64::try_from(replayed_operations).map_err(|_error| invalid_record())?;
    if replayed_deltas > authority.policy.maximum_deltas_since_checkpoint
        || replayed_delta_bytes > authority.policy.maximum_accumulated_delta_bytes
        || replayed_operations
            > u64::try_from(MAX_REPLAY_OPERATIONS_V5).map_err(|_error| limit_exceeded())?
    {
        return Err(limit_exceeded());
    }
    let (first_revision, retained_revisions) = connection
        .query_row(
            "SELECT MIN(revision), COUNT(*) FROM repository_revisions_v5",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(unavailable)?;
    let first_revision = first_revision
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    let retained_revisions =
        u64::try_from(retained_revisions).map_err(|_error| invalid_record())?;
    if authority
        .current_revision
        .0
        .checked_sub(first_revision.0)
        .and_then(|distance| distance.checked_add(1))
        != Some(retained_revisions)
        || retained_revisions == 0
        || retained_revisions > authority.policy.maximum_retained_revisions
    {
        return Err(invalid_record());
    }
    let state = reconstruct_repository_revision_v5(connection, authority.current_revision)?;
    if state.revision != authority.current_revision {
        return Err(invalid_record());
    }
    Ok(AuthenticatedLatestV5 {
        state,
        first_revision,
        checkpoint_revision,
        replayed_deltas,
        replayed_delta_bytes,
        replayed_operations,
        retained_revisions,
        authority,
    })
}

pub(crate) fn bounded_startup_verification_v5(
    connection: &Connection,
) -> Result<SqliteStartupVerificationV5, StoreError> {
    let authenticated = authenticate_latest_repository_state_v5(connection)?;
    let projection = verify_v5_latest_state_and_projection(
        connection,
        &authenticated.state,
        &authenticated.authority.state_digest,
        &authenticated.authority.catalog_root,
        &authenticated.authority.semantic_root,
        authenticated.authority.totals,
    )?;
    Ok(SqliteStartupVerificationV5 {
        current_revision: authenticated.authority.current_revision,
        checkpoint_revision: authenticated.checkpoint_revision,
        replayed_deltas: authenticated.replayed_deltas,
        replayed_delta_bytes: authenticated.replayed_delta_bytes,
        replayed_operations: authenticated.replayed_operations,
        retained_revisions: authenticated.retained_revisions,
        projection_atom_count: projection.projection_atom_count,
        chain_head: authenticated.authority.chain_head,
        policy_digest: authenticated.authority.policy_digest,
    })
}

pub(crate) fn recover_bounded_startup_v5(
    connection: &mut Connection,
) -> Result<SqliteStartupVerificationV5, StoreError> {
    let authenticated = authenticate_latest_repository_state_v5(connection)?;
    if catalog_root_from_table(connection)? != authenticated.authority.catalog_root
        || catalog_totals(connection)? != authenticated.authority.totals
    {
        return Err(invalid_record());
    }
    crate::sqlite::recover_v5_latest_projection(
        connection,
        &authenticated.state,
        &authenticated.authority.state_digest,
        &authenticated.authority.catalog_root,
        &authenticated.authority.semantic_root,
        authenticated.authority.totals,
    )?;
    bounded_startup_verification_v5(connection)
}

pub(crate) fn verified_prefix_is_compatible_v5(
    connection: &Connection,
    prefix: &VerifiedPrefixStateV5,
) -> Result<bool, StoreError> {
    let authority = load_authority(connection)?;
    let first = connection
        .query_row(
            "SELECT MIN(revision) FROM repository_revisions_v5",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(unavailable)?
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    if prefix.first_revision != first
        || prefix.through_revision.0 < first.0
        || prefix.through_revision.0 > authority.current_revision.0
        || prefix.policy_digest != authority.policy_digest
    {
        return Ok(false);
    }
    let observed = connection
        .query_row(
            "SELECT chain_head FROM repository_revisions_v5 WHERE revision = ?1",
            params![sqlite_revision(prefix.through_revision)?],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(unavailable)?;
    Ok(observed.as_deref() == Some(prefix.through_chain_head.as_str()))
}

pub(crate) fn deep_integrity_verification_v5(
    connection: &Connection,
    prefix: Option<&VerifiedPrefixStateV5>,
) -> Result<SqliteDeepIntegrityReportV5, StoreError> {
    let authenticated = authenticate_latest_repository_state_v5(connection)?;
    let projection = verify_v5_latest_state_and_projection(
        connection,
        &authenticated.state,
        &authenticated.authority.state_digest,
        &authenticated.authority.catalog_root,
        &authenticated.authority.semantic_root,
        authenticated.authority.totals,
    )?;
    let (first_new, reused_prefix_revisions) = match prefix {
        Some(prefix) if verified_prefix_is_compatible_v5(connection, prefix)? => (
            prefix.through_revision.0.checked_add(1).map(StoreRevision),
            prefix
                .through_revision
                .0
                .checked_sub(prefix.first_revision.0)
                .and_then(|distance| distance.checked_add(1))
                .ok_or_else(limit_exceeded)?,
        ),
        Some(_prefix) => return Err(StoreError::new(StoreErrorCode::RevisionConflict)),
        None => (Some(authenticated.first_revision), 0),
    };
    let first_new =
        first_new.filter(|revision| revision.0 <= authenticated.authority.current_revision.0);
    let verified_revisions = first_new.map_or(0, |first| {
        authenticated
            .authority
            .current_revision
            .0
            .saturating_sub(first.0)
            .saturating_add(1)
    });
    if let Some(first) = first_new {
        verify_migrated_v5_catalog_history_range(
            connection,
            first,
            authenticated.authority.current_revision,
        )?;
        let mut revision = first;
        loop {
            let state = reconstruct_repository_revision_v5(connection, revision)?;
            if state.revision != revision {
                return Err(invalid_record());
            }
            if revision == authenticated.authority.current_revision {
                break;
            }
            revision = revision
                .0
                .checked_add(1)
                .map(StoreRevision)
                .ok_or_else(limit_exceeded)?;
        }
    }
    Ok(SqliteDeepIntegrityReportV5 {
        first_retained_revision: authenticated.first_revision,
        current_revision: authenticated.authority.current_revision,
        verified_from_revision: first_new,
        verified_through_revision: authenticated.authority.current_revision,
        verified_revisions,
        reused_prefix_revisions,
        projection_atom_count: projection.projection_atom_count,
        chain_head: authenticated.authority.chain_head,
        policy_digest: authenticated.authority.policy_digest,
    })
}

fn catalog_totals_from_revision(
    connection: &Connection,
    revision: StoreRevision,
) -> Result<RepositoryLogicalTotalsV5, StoreError> {
    connection
        .query_row(
            "SELECT atom_count, edge_count, referenced_blob_bytes
             FROM repository_revisions_v5 WHERE revision = ?1",
            params![sqlite_revision(revision)?],
            |row| {
                Ok(RepositoryLogicalTotalsV5 {
                    atom_count: u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    edge_count: u64::try_from(row.get::<_, i64>(1)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    referenced_blob_bytes: u64::try_from(row.get::<_, i64>(2)?).map_err(
                        |error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                2,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        },
                    )?,
                })
            },
        )
        .map_err(unavailable)
}

fn canonical_u128(value: &str) -> Result<u128, StoreError> {
    let parsed = value.parse::<u128>().map_err(|_error| invalid_record())?;
    if parsed.to_string() != value {
        return Err(invalid_record());
    }
    Ok(parsed)
}

fn load_active_pin_counts(
    connection: &Connection,
    authority: &AuthorityV5,
) -> Result<ActivePinCountsV5, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT first_revision, last_revision, reason, authority_digest, policy_digest,
                    issued_at_unix_nanos, expires_at_unix_nanos, receipt_digest,
                    signature_identity_digest, length(signature), verification_state, state,
                    released_at_unix_nanos
             FROM repository_retention_pins_v5 WHERE state = 'active'
             ORDER BY first_revision, last_revision, pin_id",
        )
        .map_err(unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
            ))
        })
        .map_err(unavailable)?;
    let mut counts = ActivePinCountsV5::default();
    for row in rows {
        let row = row.map_err(unavailable)?;
        let first = store_revision(row.0)?;
        let last = store_revision(row.1)?;
        let signature_bytes = u64::try_from(row.9).map_err(|_error| invalid_record())?;
        let pin_authority = ContentDigest::new(row.3).map_err(|_error| invalid_record())?;
        let pin_policy = ContentDigest::new(row.4).map_err(|_error| invalid_record())?;
        ContentDigest::new(row.7).map_err(|_error| invalid_record())?;
        ContentDigest::new(row.8).map_err(|_error| invalid_record())?;
        canonical_u128(&row.5)?;
        if let Some(expires) = row.6 {
            canonical_u128(&expires)?;
        }
        if first.0 > last.0
            || last.0 > authority.current_revision.0
            || !(64..=512).contains(&signature_bytes)
            || row.10 != "verified"
            || row.11 != "active"
            || row.12.is_some()
            || pin_policy != authority.policy_digest
        {
            return Err(invalid_record());
        }
        let authority_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM repository_revisions_v5 WHERE chain_head = ?1)",
                params![pin_authority.as_str()],
                |value| value.get(0),
            )
            .map_err(unavailable)?;
        if authority_exists != 1 {
            return Err(invalid_record());
        }
        let existing: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM repository_revisions_v5
                 WHERE revision IN (?1, ?2)",
                params![sqlite_revision(first)?, sqlite_revision(last)?],
                |value| value.get(0),
            )
            .map_err(unavailable)?;
        let expected = if first == last { 1 } else { 2 };
        if existing != expected {
            return Err(invalid_record());
        }
        let counter = match row.2.as_str() {
            "legal_hold" => &mut counts.legal_hold,
            "replay" => &mut counts.replay,
            "backup" => &mut counts.backup,
            "explicit" => &mut counts.explicit,
            _ => return Err(invalid_record()),
        };
        *counter = counter.checked_add(1).ok_or_else(limit_exceeded)?;
        counts.earliest_revision = Some(
            counts
                .earliest_revision
                .map_or(first, |current| StoreRevision(current.0.min(first.0))),
        );
    }
    Ok(counts)
}

fn retention_capacity_blocked(
    policy: RepositoryPolicyV5,
    protected_payload_bytes: u64,
    database_logical_bytes: u64,
) -> Result<bool, StoreError> {
    let protected_required = protected_payload_bytes
        .checked_add(RETENTION_HEADROOM_BYTES_V5)
        .ok_or_else(limit_exceeded)?;
    Ok(protected_required > policy.maximum_physical_retained_bytes
        || database_logical_bytes > policy.maximum_physical_retained_bytes)
}

pub(crate) fn retention_statistics_v5(
    connection: &Connection,
) -> Result<SqliteRetentionStatisticsV5, StoreError> {
    let authority = load_authority(connection)?;
    let _authenticated =
        reconstruct_repository_revision_v5(connection, authority.current_revision)?;
    let (first_revision, retained_revisions, payload_mismatches) = connection
        .query_row(
            "SELECT COALESCE(MIN(r.revision), -1), COUNT(*),
                    COALESCE(SUM(CASE
                        WHEN (d.revision IS NULL) = (c.revision IS NULL) THEN 1 ELSE 0 END), 0)
             FROM repository_revisions_v5 r
             LEFT JOIN repository_deltas_v5 d ON d.revision = r.revision
             LEFT JOIN repository_checkpoints_v5 c ON c.revision = r.revision",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let reconstructable_first = connection
        .query_row(
            "SELECT MIN(revision) FROM repository_checkpoints_v5",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(unavailable)?
        .ok_or_else(invalid_record)
        .and_then(store_revision)?;
    let first_revision = store_revision(first_revision)?;
    let retained_revisions =
        u64::try_from(retained_revisions).map_err(|_error| invalid_record())?;
    let expected_revisions = authority
        .current_revision
        .0
        .checked_sub(first_revision.0)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(invalid_record)?;
    if retained_revisions != expected_revisions || payload_mismatches != 0 {
        return Err(invalid_record());
    }
    let (retained_checkpoints, checkpoint_bytes, retained_deltas, delta_bytes) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM repository_checkpoints_v5),
                (SELECT COALESCE(SUM(encoded_bytes), 0) FROM repository_checkpoints_v5),
                (SELECT COUNT(*) FROM repository_deltas_v5),
                (SELECT COALESCE(SUM(encoded_bytes), 0) FROM repository_deltas_v5)",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let pins = load_active_pin_counts(connection, &authority)?;
    let replay_window = authority
        .policy
        .minimum_reconstructable_revisions
        .max(authority.policy.minimum_verified_replay_revisions);
    let replay_first = StoreRevision(
        authority
            .current_revision
            .0
            .saturating_sub(replay_window.saturating_sub(1)),
    );
    let protected_first = pins
        .earliest_revision
        .map_or(replay_first, |pin| StoreRevision(pin.0.min(replay_first.0)));
    if protected_first.0 < reconstructable_first.0 {
        return Err(invalid_record());
    }
    let protected_payload_bytes = connection
        .query_row(
            "SELECT
                 COALESCE((SELECT SUM(encoded_bytes) FROM repository_checkpoints_v5
                           WHERE revision >= ?1), 0) +
                 COALESCE((SELECT SUM(encoded_bytes) FROM repository_deltas_v5
                           WHERE revision >= ?1), 0)",
            params![sqlite_revision(protected_first)?],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?;
    let page_size = connection
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let page_count = connection
        .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let database_logical_bytes = u64::try_from(page_size)
        .ok()
        .and_then(|size| {
            u64::try_from(page_count)
                .ok()
                .and_then(|count| size.checked_mul(count))
        })
        .ok_or_else(invalid_record)?;
    let protected_payload_bytes =
        u64::try_from(protected_payload_bytes).map_err(|_error| invalid_record())?;
    let capacity_blocked = retention_capacity_blocked(
        authority.policy,
        protected_payload_bytes,
        database_logical_bytes,
    )?;
    Ok(SqliteRetentionStatisticsV5 {
        current_revision: authority.current_revision,
        reconstructable_first_revision: reconstructable_first,
        reconstructable_last_revision: authority.current_revision,
        protected_first_revision: protected_first,
        retained_revisions,
        retained_checkpoints: u64::try_from(retained_checkpoints)
            .map_err(|_error| invalid_record())?,
        retained_deltas: u64::try_from(retained_deltas).map_err(|_error| invalid_record())?,
        retained_checkpoint_bytes: u64::try_from(checkpoint_bytes)
            .map_err(|_error| invalid_record())?,
        retained_delta_bytes: u64::try_from(delta_bytes).map_err(|_error| invalid_record())?,
        protected_payload_bytes,
        database_logical_bytes,
        active_legal_hold_pins: pins.legal_hold,
        active_replay_pins: pins.replay,
        active_backup_pins: pins.backup,
        active_explicit_pins: pins.explicit,
        maximum_retained_revisions: authority.policy.maximum_retained_revisions,
        maximum_retained_age_nanos: authority.policy.maximum_retained_age_nanos,
        maximum_physical_retained_bytes: authority.policy.maximum_physical_retained_bytes,
        minimum_reconstructable_revisions: authority.policy.minimum_reconstructable_revisions,
        minimum_verified_replay_revisions: authority.policy.minimum_verified_replay_revisions,
        maximum_deltas_since_checkpoint: authority.policy.maximum_deltas_since_checkpoint,
        maximum_accumulated_delta_bytes: authority.policy.maximum_accumulated_delta_bytes,
        capacity_blocked,
        policy_digest: authority.policy_digest,
        chain_head: authority.chain_head,
    })
}

fn enforce_retention_capacity_v5(connection: &Connection) -> Result<(), StoreError> {
    if retention_statistics_v5(connection)?.capacity_blocked {
        Err(limit_exceeded())
    } else {
        Ok(())
    }
}

fn verify_parent(
    transaction: &Transaction<'_>,
    prepared: &PreparedRepositoryDeltaV5,
    parent_state: &CommittedState,
) -> Result<AuthorityV5, StoreError> {
    let authority = load_authority(transaction)?;
    if prepared.delta().parent_revision() != authority.current_revision
        || parent_state.revision != authority.current_revision
        || !matches!(
            authority.capacity_profile.as_str(),
            "standard" | "large_local"
        )
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let envelope = transaction
        .query_row(
            "SELECT state_digest, catalog_root, semantic_root, atom_count, edge_count,
                    referenced_blob_bytes, chain_head
             FROM repository_revisions_v5 WHERE revision = ?1",
            params![sqlite_revision(authority.current_revision)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(unavailable)?;
    if envelope.0 != authority.state_digest.as_str()
        || envelope.1 != authority.catalog_root.as_str()
        || envelope.2 != authority.semantic_root.as_str()
        || u64::try_from(envelope.3).ok() != Some(authority.totals.atom_count)
        || u64::try_from(envelope.4).ok() != Some(authority.totals.edge_count)
        || u64::try_from(envelope.5).ok() != Some(authority.totals.referenced_blob_bytes)
        || envelope.6 != authority.chain_head.as_str()
    {
        return Err(invalid_record());
    }
    Ok(authority)
}

fn append_prepared_repository_delta_v5(
    transaction: &Transaction<'_>,
    prepared: &PreparedRepositoryDeltaV5,
    parent_state: &CommittedState,
) -> Result<(RepositoryCommitV5, CommittedState), StoreError> {
    let authority = verify_parent(transaction, prepared, parent_state)?;
    let delta = prepared.delta();
    let result_state = apply_repository_delta_v5(parent_state.clone(), delta)?;
    let (catalog_mutation_digest, catalog_mutation_count) =
        catalog_mutation_commitment_at_revision(transaction, delta.result_revision())?;
    if &catalog_mutation_digest != delta.catalog_mutation_digest()
        || catalog_mutation_count != delta.counts().catalog_mutations
    {
        return Err(invalid_record());
    }
    let catalog_root = catalog_root_from_table(transaction)?;
    let totals = catalog_totals(transaction)?;
    let encoded_delta_bytes =
        u64::try_from(prepared.canonical_delta().len()).map_err(|_error| limit_exceeded())?;
    if delta.counts().total()? > authority.policy.maximum_delta_operations
        || encoded_delta_bytes > authority.policy.maximum_delta_bytes
    {
        return Err(limit_exceeded());
    }
    let (suffix_count, suffix_bytes) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(encoded_bytes), 0)
             FROM repository_deltas_v5
             WHERE revision > COALESCE(
                 (SELECT MAX(revision) FROM repository_checkpoints_v5), -1
             )",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(unavailable)?;
    let next_count = u64::try_from(suffix_count)
        .map_err(|_error| invalid_record())?
        .checked_add(1)
        .ok_or_else(limit_exceeded)?;
    let next_bytes = u64::try_from(suffix_bytes)
        .map_err(|_error| invalid_record())?
        .checked_add(encoded_delta_bytes)
        .ok_or_else(limit_exceeded)?;
    let checkpoint_reason = if next_count > authority.policy.maximum_deltas_since_checkpoint {
        Some(RepositoryCheckpointReasonV5::DeltaCount)
    } else if next_bytes > authority.policy.maximum_accumulated_delta_bytes {
        Some(RepositoryCheckpointReasonV5::DeltaBytes)
    } else {
        None
    };

    let revision = delta.result_revision();
    let (state_digest, semantic_root, payload_digest, checkpoint) = if let Some(reason) =
        checkpoint_reason
    {
        let canonical_state = encode_catalog_free_state_v5(&result_state)?;
        let state_digest = crate::revision_delta::repository_state_digest_v5(&canonical_state)?;
        let semantic_root =
            repository_semantic_root_v5(revision, &state_digest, &catalog_root, totals)?;
        let checkpoint = RepositoryCheckpointV5::new(
            revision,
            canonical_state,
            catalog_root.clone(),
            semantic_root.clone(),
            authority.chain_head.clone(),
            totals,
            reason,
        )?;
        let payload_digest = checkpoint.checkpoint_digest()?;
        (
            state_digest,
            semantic_root,
            payload_digest,
            Some(checkpoint),
        )
    } else {
        let state_digest =
            repository_result_state_digest_v5(&authority.state_digest, prepared.delta_digest())?;
        let semantic_root =
            repository_semantic_root_v5(revision, &state_digest, &catalog_root, totals)?;
        (
            state_digest,
            semantic_root,
            prepared.delta_digest().clone(),
            None,
        )
    };
    let chain_head = repository_chain_head_v5(&RepositoryChainLinkV5 {
        previous_chain_head: &authority.chain_head,
        revision,
        delta_or_checkpoint_digest: &payload_digest,
        state_digest: &state_digest,
        catalog_root: &catalog_root,
        semantic_root: &semantic_root,
        totals,
        capacity_profile: &authority.capacity_profile,
    })?;
    insert_revision(
        transaction,
        RevisionEnvelopeV5 {
            revision,
            parent_revision: Some(authority.current_revision),
            state_digest: &state_digest,
            catalog_root: &catalog_root,
            semantic_root: &semantic_root,
            totals,
            previous_chain_head: &authority.chain_head,
            chain_head: &chain_head,
        },
    )?;

    let (payload_kind, stored_delta_bytes, checkpoint_bytes) = match checkpoint {
        Some(checkpoint) => {
            let reason = checkpoint.reason();
            let bytes = insert_checkpoint(transaction, &checkpoint, &chain_head)?;
            (RepositoryPayloadKindV5::Checkpoint(reason), 0, bytes)
        }
        None => {
            process_kill_failpoint_v5("before_delta_insert");
            transaction
                .execute(
                    "INSERT INTO repository_deltas_v5
                        (revision, parent_revision, format_version, canonical_delta, encoded_bytes,
                         delta_digest, result_state_digest, catalog_root, semantic_root, atom_count,
                         edge_count, referenced_blob_bytes, previous_chain_head, chain_head,
                         logical_bytes, operation_count)
                     VALUES (?1, ?2, 5, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        sqlite_revision(revision)?,
                        sqlite_revision(authority.current_revision)?,
                        prepared.canonical_delta(),
                        i64::try_from(encoded_delta_bytes).map_err(|_error| limit_exceeded())?,
                        prepared.delta_digest().as_str(),
                        state_digest.as_str(),
                        catalog_root.as_str(),
                        semantic_root.as_str(),
                        i64::try_from(totals.atom_count).map_err(|_error| limit_exceeded())?,
                        i64::try_from(totals.edge_count).map_err(|_error| limit_exceeded())?,
                        i64::try_from(totals.referenced_blob_bytes)
                            .map_err(|_error| limit_exceeded())?,
                        authority.chain_head.as_str(),
                        chain_head.as_str(),
                        i64::try_from(delta.logical_bytes()).map_err(|_error| limit_exceeded())?,
                        i64::try_from(delta.counts().total()?).map_err(|_error| limit_exceeded())?,
                    ],
                )
                .map_err(unavailable)?;
            process_kill_failpoint_v5("after_delta_insert");
            (RepositoryPayloadKindV5::Delta, encoded_delta_bytes, 0)
        }
    };
    process_kill_failpoint_v5("before_root_update");
    let updated = transaction
        .execute(
            "UPDATE repository_authority_v5
             SET current_revision = ?1, chain_head = ?2, state_digest = ?3,
                 catalog_root = ?4, semantic_root = ?5
             WHERE singleton = 1 AND current_revision = ?6 AND chain_head = ?7",
            params![
                sqlite_revision(revision)?,
                chain_head.as_str(),
                state_digest.as_str(),
                catalog_root.as_str(),
                semantic_root.as_str(),
                sqlite_revision(authority.current_revision)?,
                authority.chain_head.as_str(),
            ],
        )
        .map_err(unavailable)?;
    process_kill_failpoint_v5("after_root_update");
    if updated != 1 {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    Ok((
        RepositoryCommitV5 {
            revision,
            chain_head,
            payload_kind,
            encoded_delta_bytes: stored_delta_bytes,
            checkpoint_bytes,
        },
        result_state,
    ))
}

fn commit_prepared_repository_delta_v5(
    connection: &mut Connection,
    prepared: &PreparedRepositoryDeltaV5,
    parent_state: &CommittedState,
    apply_normalized_rows: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
) -> Result<(RepositoryCommitV5, CommittedState), StoreError> {
    require_full_durability(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    verify_parent(&transaction, prepared, parent_state)?;
    apply_normalized_rows(&transaction)?;
    let committed = append_prepared_repository_delta_v5(&transaction, prepared, parent_state)?;
    enforce_retention_capacity_v5(&transaction)?;
    process_kill_failpoint_v5("before_commit");
    process_kill_failpoint_v5("before_full_fsync_return");
    transaction.commit().map_err(unavailable)?;
    process_kill_failpoint_v5("after_full_fsync_return");
    process_kill_failpoint_v5("after_commit");
    Ok(committed)
}

fn commit_then_publish_repository_delta_v5(
    connection: &mut Connection,
    revision_anchor: &Path,
    prepared: &PreparedRepositoryDeltaV5,
    parent_state: &CommittedState,
    apply_normalized_rows: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
) -> Result<(RepositoryCommitV5, CommittedState), StoreError> {
    let committed = commit_prepared_repository_delta_v5(
        connection,
        prepared,
        parent_state,
        apply_normalized_rows,
    )?;
    process_kill_failpoint_v5("before_anchor_publication");
    write_revision_anchor(revision_anchor, committed.0.revision)?;
    process_kill_failpoint_v5("after_anchor_publication");
    Ok(committed)
}

fn recover_revision_anchor_v5(
    connection: &Connection,
    revision_anchor: &Path,
) -> Result<StoreRevision, StoreError> {
    require_full_durability(connection)?;
    let authority = load_authority(connection)?;
    let _authenticated =
        reconstruct_repository_revision_v5(connection, authority.current_revision)?;
    match read_revision_anchor(revision_anchor)? {
        Some(anchor) if anchor.0 > authority.current_revision.0 => return Err(invalid_record()),
        Some(anchor) if anchor == authority.current_revision => return Ok(anchor),
        _ => {}
    }
    write_revision_anchor(revision_anchor, authority.current_revision)?;
    Ok(authority.current_revision)
}

fn prior_idempotency_receipt_v5(
    state: &CommittedState,
    tenant_id: &cigar_protocol::RecordId,
    identity: &IdempotencyIdentity,
) -> Result<Option<CommitReceipt>, StoreError> {
    let Some((request_digest, receipt)) = state.tenants.get(tenant_id).and_then(|tenant| {
        tenant
            .idempotency
            .get(&(identity.scope.clone(), identity.key.clone()))
    }) else {
        return Ok(None);
    };
    if request_digest != &identity.request_digest {
        return Err(invalid_record());
    }
    Ok(Some(CommitReceipt {
        revision: receipt.revision,
        replayed: true,
    }))
}

#[cfg(test)]
fn commit_or_replay_repository_delta_v5(
    connection: &mut Connection,
    prepared: &PreparedRepositoryDeltaV5,
    parent_state: &CommittedState,
    identity: &IdempotencyIdentity,
    apply_normalized_rows: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
) -> Result<(RepositoryCommitAttemptV5, CommittedState), StoreError> {
    if let Some(receipt) =
        prior_idempotency_receipt_v5(parent_state, prepared.delta().tenant_id(), identity)?
    {
        return Ok((
            RepositoryCommitAttemptV5::Replayed(receipt),
            parent_state.clone(),
        ));
    }
    let (receipt, state) = commit_prepared_repository_delta_v5(
        connection,
        prepared,
        parent_state,
        apply_normalized_rows,
    )?;
    Ok((RepositoryCommitAttemptV5::Committed(receipt), state))
}

fn parse_digest(value: String) -> Result<ContentDigest, StoreError> {
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

fn reconstruct_repository_revision_v5(
    connection: &Connection,
    target: StoreRevision,
) -> Result<CommittedState, StoreError> {
    let authority = load_authority(connection)?;
    if target.0 > authority.current_revision.0 {
        return Err(StoreError::new(StoreErrorCode::NotFound));
    }
    let checkpoint_row = connection
        .query_row(
            "SELECT c.canonical_state, c.checkpoint_digest, c.state_digest, c.catalog_root,
                    c.semantic_root, c.atom_count, c.edge_count, c.referenced_blob_bytes,
                    c.previous_chain_head, c.chain_head, r.parent_revision
             FROM repository_checkpoints_v5 c
             JOIN repository_revisions_v5 r ON r.revision = c.revision
             WHERE c.revision <= ?1 ORDER BY c.revision DESC LIMIT 1",
            params![sqlite_revision(target)?],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?
        .ok_or_else(invalid_record)?;
    let checkpoint = RepositoryCheckpointV5::decode(&checkpoint_row.0)?;
    let checkpoint_digest = parse_digest(checkpoint_row.1)?;
    let stored_state_digest = parse_digest(checkpoint_row.2)?;
    let stored_catalog_root = parse_digest(checkpoint_row.3)?;
    let stored_semantic_root = parse_digest(checkpoint_row.4)?;
    let stored_totals = RepositoryLogicalTotalsV5 {
        atom_count: u64::try_from(checkpoint_row.5).map_err(|_error| invalid_record())?,
        edge_count: u64::try_from(checkpoint_row.6).map_err(|_error| invalid_record())?,
        referenced_blob_bytes: u64::try_from(checkpoint_row.7)
            .map_err(|_error| invalid_record())?,
    };
    let stored_previous_head = parse_digest(checkpoint_row.8)?;
    let stored_chain_head = parse_digest(checkpoint_row.9)?;
    if checkpoint.checkpoint_digest()? != checkpoint_digest
        || checkpoint.state_digest() != &stored_state_digest
        || checkpoint.catalog_root() != &stored_catalog_root
        || checkpoint.semantic_root() != &stored_semantic_root
        || checkpoint.totals() != stored_totals
        || checkpoint.parent_chain_head() != &stored_previous_head
    {
        return Err(invalid_record());
    }
    match (checkpoint.revision().0, checkpoint_row.10) {
        (0, None)
            if matches!(
                checkpoint.reason(),
                RepositoryCheckpointReasonV5::Genesis | RepositoryCheckpointReasonV5::Migration
            ) =>
        {
            if stored_previous_head != repository_genesis_parent_chain_head_v5()? {
                return Err(invalid_record());
            }
        }
        (_, None) if checkpoint.reason() == RepositoryCheckpointReasonV5::Migration => {
            if stored_previous_head != repository_genesis_parent_chain_head_v5()?
                && !is_authenticated_compaction_origin_v5(
                    connection,
                    checkpoint.revision(),
                    &stored_previous_head,
                )?
            {
                return Err(invalid_record());
            }
        }
        (_, None)
            if checkpoint.reason() == RepositoryCheckpointReasonV5::Compaction
                && is_authenticated_compaction_origin_v5(
                    connection,
                    checkpoint.revision(),
                    &stored_previous_head,
                )? => {}
        (revision, Some(parent)) if revision > 0 => {
            if u64::try_from(parent).ok() != revision.checked_sub(1) {
                return Err(invalid_record());
            }
            let parent_head = connection
                .query_row(
                    "SELECT chain_head FROM repository_revisions_v5 WHERE revision = ?1",
                    params![parent],
                    |row| row.get::<_, String>(0),
                )
                .map_err(unavailable)?;
            if parent_head != stored_previous_head.as_str() {
                return Err(invalid_record());
            }
        }
        _ => return Err(invalid_record()),
    }
    let expected_checkpoint_head = repository_chain_head_v5(&RepositoryChainLinkV5 {
        previous_chain_head: &stored_previous_head,
        revision: checkpoint.revision(),
        delta_or_checkpoint_digest: &checkpoint_digest,
        state_digest: &stored_state_digest,
        catalog_root: &stored_catalog_root,
        semantic_root: &stored_semantic_root,
        totals: stored_totals,
        capacity_profile: &authority.capacity_profile,
    })?;
    if expected_checkpoint_head != stored_chain_head {
        return Err(invalid_record());
    }

    let mut state = decode_catalog_free_state_v5(checkpoint.canonical_state())?;
    if state.revision != checkpoint.revision() {
        return Err(invalid_record());
    }
    let mut previous_chain_head = stored_chain_head;
    let mut previous_state_digest = stored_state_digest;
    let mut replayed = 0_usize;
    let mut replayed_bytes = 0_usize;
    let mut replayed_operations = 0_usize;
    let mut statement = connection
        .prepare(
            "SELECT d.canonical_delta, d.delta_digest, d.result_state_digest, d.catalog_root,
                    d.semantic_root, d.atom_count, d.edge_count, d.referenced_blob_bytes,
                    d.previous_chain_head, d.chain_head, d.encoded_bytes, d.operation_count,
                    d.revision, d.parent_revision, r.parent_revision, r.state_digest,
                    r.catalog_root, r.semantic_root, r.atom_count, r.edge_count,
                    r.referenced_blob_bytes, r.previous_chain_head, r.chain_head
             FROM repository_deltas_v5 d
             JOIN repository_revisions_v5 r ON r.revision = d.revision
             WHERE d.revision > ?1 AND d.revision <= ?2 ORDER BY d.revision",
        )
        .map_err(unavailable)?;
    let mut rows = statement
        .query(params![
            sqlite_revision(checkpoint.revision())?,
            sqlite_revision(target)?
        ])
        .map_err(unavailable)?;
    while let Some(row) = rows.next().map_err(unavailable)? {
        replayed = replayed.checked_add(1).ok_or_else(limit_exceeded)?;
        let canonical_delta = row.get::<_, Vec<u8>>(0).map_err(unavailable)?;
        let encoded_bytes = usize::try_from(row.get::<_, i64>(10).map_err(unavailable)?)
            .map_err(|_error| invalid_record())?;
        let operations = usize::try_from(row.get::<_, i64>(11).map_err(unavailable)?)
            .map_err(|_error| invalid_record())?;
        replayed_bytes = replayed_bytes
            .checked_add(encoded_bytes)
            .ok_or_else(limit_exceeded)?;
        replayed_operations = replayed_operations
            .checked_add(operations)
            .ok_or_else(limit_exceeded)?;
        if replayed > MAX_DELTAS_SINCE_CHECKPOINT_V5
            || replayed_bytes > MAX_ACCUMULATED_DELTA_BYTES_V5
            || replayed_operations > MAX_REPLAY_OPERATIONS_V5
            || canonical_delta.len() != encoded_bytes
        {
            return Err(limit_exceeded());
        }
        let delta = crate::revision_delta::RepositoryDeltaV5::decode(&canonical_delta)?;
        let delta_digest = parse_digest(row.get::<_, String>(1).map_err(unavailable)?)?;
        let result_state_digest = parse_digest(row.get::<_, String>(2).map_err(unavailable)?)?;
        let catalog_root = parse_digest(row.get::<_, String>(3).map_err(unavailable)?)?;
        let semantic_root = parse_digest(row.get::<_, String>(4).map_err(unavailable)?)?;
        let totals = RepositoryLogicalTotalsV5 {
            atom_count: u64::try_from(row.get::<_, i64>(5).map_err(unavailable)?)
                .map_err(|_error| invalid_record())?,
            edge_count: u64::try_from(row.get::<_, i64>(6).map_err(unavailable)?)
                .map_err(|_error| invalid_record())?,
            referenced_blob_bytes: u64::try_from(row.get::<_, i64>(7).map_err(unavailable)?)
                .map_err(|_error| invalid_record())?,
        };
        let row_previous_head = parse_digest(row.get::<_, String>(8).map_err(unavailable)?)?;
        let row_chain_head = parse_digest(row.get::<_, String>(9).map_err(unavailable)?)?;
        let row_revision = store_revision(row.get::<_, i64>(12).map_err(unavailable)?)?;
        let row_parent = store_revision(row.get::<_, i64>(13).map_err(unavailable)?)?;
        let envelope_parent = store_revision(row.get::<_, i64>(14).map_err(unavailable)?)?;
        let expected_revision = state
            .revision
            .0
            .checked_add(1)
            .map(StoreRevision)
            .ok_or_else(limit_exceeded)?;
        if row_revision != expected_revision
            || row_parent != state.revision
            || envelope_parent != state.revision
            || delta.parent_revision() != state.revision
            || delta.result_revision() != expected_revision
            || delta.delta_digest()? != delta_digest
            || row_previous_head != previous_chain_head
            || repository_result_state_digest_v5(&previous_state_digest, &delta_digest)?
                != result_state_digest
            || repository_semantic_root_v5(
                expected_revision,
                &result_state_digest,
                &catalog_root,
                totals,
            )? != semantic_root
            || row.get::<_, String>(15).map_err(unavailable)? != result_state_digest.as_str()
            || row.get::<_, String>(16).map_err(unavailable)? != catalog_root.as_str()
            || row.get::<_, String>(17).map_err(unavailable)? != semantic_root.as_str()
            || u64::try_from(row.get::<_, i64>(18).map_err(unavailable)?)
                .map_err(|_error| invalid_record())?
                != totals.atom_count
            || u64::try_from(row.get::<_, i64>(19).map_err(unavailable)?)
                .map_err(|_error| invalid_record())?
                != totals.edge_count
            || u64::try_from(row.get::<_, i64>(20).map_err(unavailable)?)
                .map_err(|_error| invalid_record())?
                != totals.referenced_blob_bytes
            || row.get::<_, String>(21).map_err(unavailable)? != row_previous_head.as_str()
            || row.get::<_, String>(22).map_err(unavailable)? != row_chain_head.as_str()
        {
            return Err(invalid_record());
        }
        let expected_head = repository_chain_head_v5(&RepositoryChainLinkV5 {
            previous_chain_head: &previous_chain_head,
            revision: expected_revision,
            delta_or_checkpoint_digest: &delta_digest,
            state_digest: &result_state_digest,
            catalog_root: &catalog_root,
            semantic_root: &semantic_root,
            totals,
            capacity_profile: &authority.capacity_profile,
        })?;
        if expected_head != row_chain_head {
            return Err(invalid_record());
        }
        state = apply_repository_delta_v5(state, &delta)?;
        previous_chain_head = row_chain_head;
        previous_state_digest = result_state_digest;
    }
    if state.revision != target {
        return Err(invalid_record());
    }
    let target_envelope = connection
        .query_row(
            "SELECT state_digest, chain_head FROM repository_revisions_v5 WHERE revision = ?1",
            params![sqlite_revision(target)?],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(unavailable)?;
    if target_envelope.0 != previous_state_digest.as_str()
        || target_envelope.1 != previous_chain_head.as_str()
    {
        return Err(invalid_record());
    }
    Ok(state)
}

fn is_authenticated_compaction_origin_v5(
    connection: &Connection,
    revision: StoreRevision,
    prior_chain_head: &ContentDigest,
) -> Result<bool, StoreError> {
    let row = connection
        .query_row(
            "SELECT prior_first_revision, removed_through_revision, prior_chain_head,
                    preview_digest, executed_at_unix_nanos, verification_state
             FROM repository_compaction_origin_v5
             WHERE singleton = 1 AND origin_revision = ?1",
            params![sqlite_revision(revision)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let prior_first = store_revision(row.0)?;
    let removed_through = store_revision(row.1)?;
    ContentDigest::new(row.3).map_err(|_error| invalid_record())?;
    canonical_u128(&row.4)?;
    if prior_first.0 >= revision.0
        || removed_through.0.checked_add(1) != Some(revision.0)
        || row.2 != prior_chain_head.as_str()
        || row.5 != "complete"
    {
        return Err(invalid_record());
    }
    Ok(true)
}

fn reconstruct_repository_snapshot_v5(
    connection: &Connection,
    selection: SnapshotSelection,
) -> Result<CommittedState, StoreError> {
    let target = match selection {
        SnapshotSelection::Latest => load_authority(connection)?.current_revision,
        SnapshotSelection::Revision(revision) => revision,
    };
    reconstruct_repository_revision_v5(connection, target)
}

/// Production SQLite repository over an already activated, authenticated v5 target.
///
/// This opener never creates or migrates a database. The active-store descriptor remains the
/// caller's authority for selecting `path`; this type then verifies the v5 authority chain,
/// bounded replay, normalized catalog projection, revision anchor, local capacity profile, and
/// encrypted blob roots before returning.
pub struct SqliteV5Store {
    path: PathBuf,
    connection: Mutex<Connection>,
    blob_repository: Arc<dyn RepositoryBlobStore>,
    _runtime_lock: Option<File>,
    secure_identity: crate::sqlite::SecureSqliteIdentity,
    capacity_profile: SqliteCapacityProfile,
    revision_anchor: PathBuf,
    fail_next_commit: AtomicBool,
    commit_metrics_observer: Option<Arc<dyn RepositoryCommitMetricsObserver>>,
}

impl fmt::Debug for SqliteV5Store {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteV5Store")
    }
}

impl SqliteV5Store {
    /// Opens one existing activated v5 target and completes bounded readiness recovery.
    pub fn open_with_blob_repository_capacity_and_startup_metrics(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn RepositoryBlobStore>,
        capacity_profile: SqliteCapacityProfile,
        observer: Arc<dyn RepositoryStartupMetricsObserver>,
    ) -> Result<Self, StoreError> {
        Self::open_internal(
            path.as_ref(),
            blob_repository,
            capacity_profile,
            Some(observer),
        )
    }

    /// Opens one existing activated v5 target without a startup observer.
    pub fn open_with_blob_repository_and_capacity_profile(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn RepositoryBlobStore>,
        capacity_profile: SqliteCapacityProfile,
    ) -> Result<Self, StoreError> {
        Self::open_internal(path.as_ref(), blob_repository, capacity_profile, None)
    }

    fn open_internal(
        path: &Path,
        blob_repository: Arc<dyn RepositoryBlobStore>,
        capacity_profile: SqliteCapacityProfile,
        startup_observer: Option<Arc<dyn RepositoryStartupMetricsObserver>>,
    ) -> Result<Self, StoreError> {
        let observer = startup_observer.as_ref();
        let (secure_identity, runtime_lock) =
            measure_startup_stage(observer, RepositoryStartupStage::PathConfiguration, || {
                preflight_capacity_profile(path, capacity_profile)?;
                let identity = prepare_secure_sqlite_path(path, false)?;
                let lock = acquire_sqlite_runtime_shared_lock(path)?;
                Ok((identity, lock))
            })?;
        let mut connection = measure_startup_stage(
            observer,
            RepositoryStartupStage::SqliteOpenConfigure,
            || {
                let connection =
                    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                        .map_err(unavailable)?;
                verify_secure_sqlite_path(path, secure_identity)?;
                configure(&connection, capacity_profile)?;
                Ok(connection)
            },
        )?;
        measure_startup_stage(observer, RepositoryStartupStage::MigrationLedger, || {
            verify_capacity_profile_v5(&connection, capacity_profile)
        })?;
        measure_startup_stage(observer, RepositoryStartupStage::ReadinessOpen, || {
            recover_bounded_startup_v5(&mut connection).map(|_verification| ())
        })?;
        let revision_anchor = revision_anchor_path(path)?;
        measure_startup_stage(observer, RepositoryStartupStage::RevisionAnchor, || {
            recover_revision_anchor_v5(&connection, &revision_anchor).map(|_revision| ())
        })?;
        verify_secure_sqlite_path(path, secure_identity)?;
        let store = Self {
            path: path.to_path_buf(),
            connection: Mutex::new(connection),
            blob_repository,
            _runtime_lock: runtime_lock,
            secure_identity,
            capacity_profile,
            revision_anchor,
            fail_next_commit: AtomicBool::new(false),
            commit_metrics_observer: None,
        };
        measure_startup_stage(observer, RepositoryStartupStage::BlobReconciliation, || {
            store.reconcile_blob_roots()
        })?;
        Ok(store)
    }

    /// Attaches a non-blocking content-free commit observer.
    #[must_use]
    pub fn with_commit_metrics_observer(
        mut self,
        observer: Arc<dyn RepositoryCommitMetricsObserver>,
    ) -> Self {
        self.commit_metrics_observer = Some(observer);
        self
    }

    /// Returns the authenticated current revision.
    pub fn revision(&self) -> Result<StoreRevision, StoreError> {
        let connection = self.lock()?;
        Ok(load_authority(&connection)?.current_revision)
    }

    /// Reauthenticates the active v5 authority and bounded latest state without changing schema.
    pub fn verify_migration_level(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        verify_capacity_profile_v5(&connection, self.capacity_profile)?;
        bounded_startup_verification_v5(&connection).map(|_verification| ())
    }

    /// Proves whether the authenticated latest state contains no effect envelope for any tenant.
    pub fn effect_store_is_empty(&self) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        let state = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)?;
        Ok(state
            .tenants
            .values()
            .all(|tenant| tenant.effect_records.is_empty()))
    }

    /// Performs an exact encrypted blob write/read/delete readiness probe.
    pub fn blob_readiness_probe(
        &self,
        tenant: &RecordId,
        blob: &BlobRecord,
    ) -> Result<(), StoreError> {
        self.blob_repository.readiness_probe(tenant, blob)
    }

    /// Reconciles encrypted objects against the authenticated latest metadata roots.
    pub fn reconcile_blob_roots(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let state = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)?;
        let live = state
            .tenants
            .into_iter()
            .map(|(tenant, state)| {
                (
                    tenant.as_str().to_owned(),
                    state.blobs.into_keys().collect(),
                )
            })
            .collect();
        self.blob_repository.reconcile(&live)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }

    fn observe_commit(&self, metrics: RepositoryCommitMetrics) {
        if let Some(observer) = &self.commit_metrics_observer {
            observer.observe_repository_commit(metrics);
        }
    }
}

fn capacity_profile_name(profile: SqliteCapacityProfile) -> &'static str {
    match profile {
        SqliteCapacityProfile::Standard => "standard",
        SqliteCapacityProfile::LargeLocal => "large_local",
    }
}

fn verify_capacity_profile_v5(
    connection: &Connection,
    profile: SqliteCapacityProfile,
) -> Result<(), StoreError> {
    require_full_durability(connection)?;
    let authority = load_authority(connection)?;
    if authority.capacity_profile != capacity_profile_name(profile) {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(())
}

fn revision_anchor_path(database: &Path) -> Result<PathBuf, StoreError> {
    let mut value = database.as_os_str().to_os_string();
    value.push(".cigar-revision");
    let path = PathBuf::from(value);
    if path.parent() != database.parent() {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(path)
}

#[derive(Clone, Copy, Default)]
struct V5CommitFootprint {
    database_bytes: Option<u64>,
    wal_bytes: Option<u64>,
    retained: RepositoryRetentionCounts,
}

fn v5_commit_footprint(connection: &Connection, path: &Path) -> V5CommitFootprint {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let retained = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM repository_checkpoints_v5),
                (SELECT COUNT(*) FROM repository_deltas_v5)",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .ok()
        .and_then(|(checkpoints, deltas)| {
            Some((
                u64::try_from(checkpoints).ok()?,
                u64::try_from(deltas).ok()?,
            ))
        });
    V5CommitFootprint {
        database_bytes: fs::metadata(path).ok().map(|metadata| metadata.len()),
        wal_bytes: fs::metadata(PathBuf::from(wal))
            .ok()
            .map(|metadata| metadata.len())
            .or(Some(0)),
        retained: RepositoryRetentionCounts {
            full_states: Some(0),
            checkpoints: retained.map(|value| value.0),
            deltas: retained.map(|value| value.1),
        },
    }
}

fn v5_commit_bytes(
    logical_changed: u64,
    committed: &RepositoryCommitV5,
    before: V5CommitFootprint,
    after: V5CommitFootprint,
) -> RepositoryCommitBytes {
    RepositoryCommitBytes {
        logical_changed,
        encoded_delta: committed.encoded_delta_bytes,
        checkpoint: committed.checkpoint_bytes,
        full_state: 0,
        database_before: before.database_bytes,
        database_after: after.database_bytes,
        wal_before: before.wal_bytes,
        wal_after: after.wal_bytes,
    }
}

/// Mutable transaction that publishes one typed v5 repository delta and then its revision anchor.
pub struct SqliteV5WriteTransaction<'store> {
    store: &'store SqliteV5Store,
    context: AccessContext,
    expected_revision: StoreRevision,
    cancellation: CancellationToken,
    staged: Vec<StagedMutation>,
}

impl fmt::Debug for SqliteV5WriteTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteV5WriteTransaction")
            .field("context", &self.context)
            .field("expected_revision", &self.expected_revision)
            .field("staged", &self.staged.len())
            .finish()
    }
}

impl SqliteV5WriteTransaction<'_> {
    fn stage(&mut self, mutation: StagedMutation) -> Result<(), StoreError> {
        self.cancellation.check()?;
        self.staged.push(mutation);
        Ok(())
    }
}

impl WriteTransaction for SqliteV5WriteTransaction<'_> {
    fn stage_snapshot(&mut self, snapshot: SourceSnapshot) -> Result<(), StoreError> {
        validate(&snapshot)?;
        self.stage(StagedMutation::Snapshot(snapshot))
    }

    fn publish_atoms(
        &mut self,
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
    ) -> Result<(), StoreError> {
        if atoms.is_empty() {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        for atom in &atoms {
            validate(atom)?;
            if &atom.scope.tenant_id != self.context.tenant_id() {
                return Err(StoreError::new(StoreErrorCode::InvalidContext));
            }
        }
        for edge in &edges {
            validate(edge)?;
        }
        self.stage(StagedMutation::Atoms(atoms, edges))
    }

    fn put_bundle(&mut self, bundle: ContextBundle) -> Result<(), StoreError> {
        validate(&bundle)?;
        self.stage(StagedMutation::Bundle(bundle))
    }

    fn append_context_commit(&mut self, commit: ContextCommit) -> Result<(), StoreError> {
        validate(&commit)?;
        if commit.purpose != self.context.purpose() {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        self.stage(StagedMutation::ContextCommit(commit))
    }

    fn append_effect_event(&mut self, event: EffectJournalEvent) -> Result<(), StoreError> {
        validate(&event)?;
        self.stage(StagedMutation::EffectEvent(event))
    }

    fn put_effect_record(&mut self, record: EffectRecordEnvelope) -> Result<(), StoreError> {
        self.stage(StagedMutation::EffectRecord(record))
    }

    fn put_blob(&mut self, blob: BlobRecord) -> Result<(), StoreError> {
        if blob_digest(blob.bytes()) != blob.reference.digest.as_str() {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        self.stage(StagedMutation::Blob(blob))
    }

    fn enqueue_outbox(&mut self, message: OutboxMessage) -> Result<(), StoreError> {
        message.validate()?;
        self.stage(StagedMutation::Outbox(message))
    }

    fn commit(self, idempotency: Option<IdempotencyIdentity>) -> Result<CommitReceipt, StoreError> {
        let total_started = Instant::now();
        self.cancellation.check()?;
        validate_staged_shape(&self.staged)?;
        let logical_changed = staged_logical_bytes(&self.staged)?;
        let lock_started = Instant::now();
        let mut connection = self.store.lock()?;
        let lock_wait = lock_started.elapsed();
        let before = v5_commit_footprint(&connection, &self.store.path);
        let load_started = Instant::now();
        let latest = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)?;
        let repository_load = load_started.elapsed();
        let revision_before = latest.revision;
        if let Some(identity) = &idempotency
            && let Some(receipt) =
                prior_idempotency_receipt_v5(&latest, self.context.tenant_id(), identity)?
        {
            let after = v5_commit_footprint(&connection, &self.store.path);
            drop(connection);
            self.store.observe_commit(RepositoryCommitMetrics {
                kind: RepositoryCommitKind::Repository,
                outcome: RepositoryCommitOutcome::Replayed,
                revision_before,
                revision_after: revision_before,
                receipt_only: false,
                durations: RepositoryCommitDurations {
                    total: total_started.elapsed(),
                    lock_wait,
                    repository_load,
                    ..RepositoryCommitDurations::default()
                },
                bytes: RepositoryCommitBytes {
                    database_before: before.database_bytes,
                    database_after: after.database_bytes,
                    wal_before: before.wal_bytes,
                    wal_after: after.wal_bytes,
                    ..RepositoryCommitBytes::default()
                },
                retained: after.retained,
            });
            return Ok(receipt);
        }
        if latest.revision != self.expected_revision {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
        let delta_started = Instant::now();
        let prepared = repository_delta_from_staged_v5(
            self.expected_revision,
            &self.context,
            &self.staged,
            idempotency.as_ref(),
            logical_changed,
        )?
        .prepare()?;
        let delta_encode = delta_started.elapsed();
        for mutation in &self.staged {
            if let StagedMutation::Blob(blob) = mutation {
                self.store
                    .blob_repository
                    .put(self.context.tenant_id(), blob)?;
            }
        }
        self.cancellation.check()?;
        let tenant_id = self.context.tenant_id().clone();
        let cancellation = self.cancellation;
        let staged = self.staged;
        let revision = prepared.delta().result_revision();
        let fail_next_commit = &self.store.fail_next_commit;
        let transaction_started = Instant::now();
        let (committed, _state) = commit_then_publish_repository_delta_v5(
            &mut connection,
            &self.store.revision_anchor,
            &prepared,
            &latest,
            move |transaction| {
                let mut touched_buckets = BTreeSet::new();
                for mutation in staged {
                    if let StagedMutation::Atoms(atoms, edges) = mutation {
                        touched_buckets.extend(apply_catalog_batch(
                            transaction,
                            &tenant_id,
                            atoms,
                            edges,
                            revision,
                            &cancellation,
                        )?);
                    }
                }
                for bucket in touched_buckets {
                    persist_catalog_bucket(transaction, bucket, revision)?;
                }
                if fail_next_commit.swap(false, Ordering::AcqRel) {
                    return Err(StoreError::new(StoreErrorCode::InjectedAbort));
                }
                Ok(())
            },
        )?;
        let sqlite_transaction = transaction_started.elapsed();
        verify_secure_sqlite_path(&self.store.path, self.store.secure_identity)?;
        let after = v5_commit_footprint(&connection, &self.store.path);
        drop(connection);
        self.store.observe_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Repository,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before,
            revision_after: committed.revision,
            receipt_only: logical_changed == 0,
            durations: RepositoryCommitDurations {
                total: total_started.elapsed(),
                lock_wait,
                repository_load,
                delta_encode,
                sqlite_transaction,
                ..RepositoryCommitDurations::default()
            },
            bytes: v5_commit_bytes(logical_changed, &committed, before, after),
            retained: after.retained,
        });
        Ok(CommitReceipt {
            revision: committed.revision,
            replayed: false,
        })
    }
}

impl Repository for SqliteV5Store {
    type Read<'store>
        = SqliteReadTransaction
    where
        Self: 'store;
    type Write<'store>
        = SqliteV5WriteTransaction<'store>
    where
        Self: 'store;

    fn begin_read(
        &self,
        context: AccessContext,
        selection: SnapshotSelection,
        cancellation: CancellationToken,
    ) -> Result<Self::Read<'_>, StoreError> {
        cancellation.check()?;
        let connection =
            Connection::open_with_flags(&self.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(unavailable)?;
        verify_secure_sqlite_path(&self.path, self.secure_identity)?;
        configure(&connection, self.capacity_profile)?;
        connection
            .execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED;")
            .map_err(unavailable)?;
        let state = reconstruct_repository_snapshot_v5(&connection, selection)?;
        Ok(SqliteReadTransaction::from_v5_state(
            connection,
            state,
            context,
            cancellation,
            Some(Arc::clone(&self.blob_repository)),
        ))
    }

    fn begin_write(
        &self,
        context: AccessContext,
        expected_revision: StoreRevision,
        cancellation: CancellationToken,
    ) -> Result<Self::Write<'_>, StoreError> {
        cancellation.check()?;
        Ok(SqliteV5WriteTransaction {
            store: self,
            context,
            expected_revision,
            cancellation,
            staged: Vec::new(),
        })
    }
}

impl ServiceRepository for SqliteV5Store {
    fn service_get(
        &self,
        locator: &ServiceRecordLocator,
        selection: ServiceRecordSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<ServiceRecord>, ServiceError> {
        check_cancellation(cancellation)?;
        let connection = self.lock().map_err(map_store_error)?;
        let state = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)
            .map_err(map_store_error)?;
        service_get_from_state(&state, locator, selection)
    }

    fn service_list(
        &self,
        query: &ServiceListQuery,
        cancellation: &CancellationToken,
    ) -> Result<ServiceListPage, ServiceError> {
        check_cancellation(cancellation)?;
        let selection = query
            .revision()
            .map_or(SnapshotSelection::Latest, SnapshotSelection::Revision);
        let connection = self.lock().map_err(map_store_error)?;
        let state =
            reconstruct_repository_snapshot_v5(&connection, selection).map_err(map_store_error)?;
        service_list_from_state(&state, query)
    }

    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError> {
        let total_started = Instant::now();
        check_cancellation(cancellation)?;
        let logical_changed = batch.logical_bytes();
        let tenant_id = batch.tenant_id().clone();
        let lock_started = Instant::now();
        let mut connection = self.lock().map_err(map_store_error)?;
        let lock_wait = lock_started.elapsed();
        let before = v5_commit_footprint(&connection, &self.path);
        let load_started = Instant::now();
        let latest = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)
            .map_err(map_store_error)?;
        let repository_load = load_started.elapsed();
        let revision_before = latest.revision;
        let staged_started = Instant::now();
        let (next, receipt) = apply_service_batch(&latest, batch)?;
        let staged_mutation = staged_started.elapsed();
        if receipt.replayed {
            let after = v5_commit_footprint(&connection, &self.path);
            drop(connection);
            self.observe_commit(RepositoryCommitMetrics {
                kind: RepositoryCommitKind::Service,
                outcome: RepositoryCommitOutcome::Replayed,
                revision_before,
                revision_after: revision_before,
                receipt_only: false,
                durations: RepositoryCommitDurations {
                    total: total_started.elapsed(),
                    lock_wait,
                    repository_load,
                    staged_mutation,
                    ..RepositoryCommitDurations::default()
                },
                bytes: RepositoryCommitBytes {
                    database_before: before.database_bytes,
                    database_after: after.database_bytes,
                    wal_before: before.wal_bytes,
                    wal_after: after.wal_bytes,
                    ..RepositoryCommitBytes::default()
                },
                retained: after.retained,
            });
            return Ok(receipt);
        }
        let next = next.ok_or_else(|| ServiceError::new(ServiceErrorCode::Unavailable))?;
        check_cancellation(cancellation)?;
        let delta_started = Instant::now();
        let prepared =
            repository_delta_from_service_v5(&latest, &next, &tenant_id, &receipt, logical_changed)
                .and_then(|delta| delta.prepare())
                .map_err(map_store_error)?;
        let delta_encode = delta_started.elapsed();
        let fail_next_commit = &self.fail_next_commit;
        let transaction_started = Instant::now();
        let (committed, committed_state) = commit_then_publish_repository_delta_v5(
            &mut connection,
            &self.revision_anchor,
            &prepared,
            &latest,
            |_transaction| {
                if fail_next_commit.swap(false, Ordering::AcqRel) {
                    return Err(StoreError::new(StoreErrorCode::InjectedAbort));
                }
                Ok(())
            },
        )
        .map_err(map_store_error)?;
        if committed_state != next || committed.revision != receipt.revision {
            return Err(ServiceError::new(ServiceErrorCode::Unavailable));
        }
        let sqlite_transaction = transaction_started.elapsed();
        verify_secure_sqlite_path(&self.path, self.secure_identity).map_err(map_store_error)?;
        let after = v5_commit_footprint(&connection, &self.path);
        drop(connection);
        self.observe_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Service,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before,
            revision_after: committed.revision,
            receipt_only: logical_changed == 0,
            durations: RepositoryCommitDurations {
                total: total_started.elapsed(),
                lock_wait,
                repository_load,
                staged_mutation,
                delta_encode,
                sqlite_transaction,
                ..RepositoryCommitDurations::default()
            },
            bytes: v5_commit_bytes(logical_changed, &committed, before, after),
            retained: after.retained,
        });
        Ok(receipt)
    }

    fn effect_recovery(
        &self,
        query: &EffectRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<EffectRecoveryPage, ServiceError> {
        check_cancellation(cancellation)?;
        let selection = query
            .revision()
            .map_or(SnapshotSelection::Latest, SnapshotSelection::Revision);
        let connection = self.lock().map_err(map_store_error)?;
        let state =
            reconstruct_repository_snapshot_v5(&connection, selection).map_err(map_store_error)?;
        effect_recovery_from_state(&state, query)
    }

    fn outbox_recovery(
        &self,
        query: &OutboxRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<OutboxRecoveryPage, ServiceError> {
        check_cancellation(cancellation)?;
        let selection = query
            .revision()
            .map_or(SnapshotSelection::Latest, SnapshotSelection::Revision);
        let connection = self.lock().map_err(map_store_error)?;
        let state =
            reconstruct_repository_snapshot_v5(&connection, selection).map_err(map_store_error)?;
        outbox_recovery_from_state(&state, query)
    }

    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError> {
        check_cancellation(cancellation)?;
        let connection = self.lock().map_err(map_store_error)?;
        let state = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)
            .map_err(map_store_error)?;
        worker_get_from_state(&state, locator)
    }

    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError> {
        let total_started = Instant::now();
        check_cancellation(cancellation)?;
        let logical_changed = update.logical_bytes(locator);
        let lock_started = Instant::now();
        let mut connection = self.lock().map_err(map_store_error)?;
        let lock_wait = lock_started.elapsed();
        let before = v5_commit_footprint(&connection, &self.path);
        let load_started = Instant::now();
        let latest = reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)
            .map_err(map_store_error)?;
        let repository_load = load_started.elapsed();
        let revision_before = latest.revision;
        let staged_started = Instant::now();
        let (next, state) = apply_worker_update(&latest, locator, update)?;
        let staged_mutation = staged_started.elapsed();
        check_cancellation(cancellation)?;
        let delta_started = Instant::now();
        let prepared =
            repository_delta_from_worker_v5(latest.revision, state.clone(), logical_changed)
                .and_then(|delta| delta.prepare())
                .map_err(map_store_error)?;
        let delta_encode = delta_started.elapsed();
        let fail_next_commit = &self.fail_next_commit;
        let transaction_started = Instant::now();
        let (committed, committed_state) = commit_then_publish_repository_delta_v5(
            &mut connection,
            &self.revision_anchor,
            &prepared,
            &latest,
            |_transaction| {
                if fail_next_commit.swap(false, Ordering::AcqRel) {
                    return Err(StoreError::new(StoreErrorCode::InjectedAbort));
                }
                Ok(())
            },
        )
        .map_err(map_store_error)?;
        if committed_state != next || committed.revision != state.store_revision() {
            return Err(ServiceError::new(ServiceErrorCode::Unavailable));
        }
        let sqlite_transaction = transaction_started.elapsed();
        verify_secure_sqlite_path(&self.path, self.secure_identity).map_err(map_store_error)?;
        let after = v5_commit_footprint(&connection, &self.path);
        drop(connection);
        self.observe_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Worker,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before,
            revision_after: committed.revision,
            receipt_only: logical_changed == 0,
            durations: RepositoryCommitDurations {
                total: total_started.elapsed(),
                lock_wait,
                repository_load,
                staged_mutation,
                delta_encode,
                sqlite_transaction,
                ..RepositoryCommitDurations::default()
            },
            bytes: v5_commit_bytes(logical_changed, &committed, before, after),
            retained: after.retained,
        });
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::{ConformanceRepository, run_repository_conformance};
    use crate::memory::{StagedMutation, validate};
    use crate::migrate_v5::prepare_fresh_target_schema_v5;
    use crate::revision_delta::repository_delta_from_staged_v5;
    use crate::sqlite::{
        apply_catalog_batch, persist_catalog_bucket, staged_logical_bytes,
        verify_secure_sqlite_identity_for_test,
    };
    use crate::{
        AccessContext, CancellationToken, LocalBlobStore, LocalRepositoryBlobStore,
        RepositoryBlobStore, ServiceBatch, ServiceExpectedVersion, ServiceRecordLocator,
        ServiceRecordSelection, ServiceRecordWrite, ServiceRepository, ServiceResponse,
        SqliteStore, StoreErrorCode, WorkerLocator, WorkerUpdate,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider,
    };
    use cigar_protocol::{ContextAtomV1, IdempotencyKey, RecordId, VersionId};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Barrier};

    fn configure_v5_test_connection(
        connection: &Connection,
        path: &Path,
    ) -> Result<(), StoreError> {
        connection
            .busy_timeout(std::time::Duration::from_secs(30))
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(unavailable)?;
        if !connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(unavailable)?
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        require_full_durability(connection)?;
        verify_secure_sqlite_identity_for_test(path)
    }

    fn open_production_v5_store(
        path: PathBuf,
        blob_repository: Arc<dyn RepositoryBlobStore>,
    ) -> Result<SqliteV5Store, StoreError> {
        drop(SqliteStore::open(&path)?);
        let mut connection = Connection::open(&path).map_err(unavailable)?;
        configure_v5_test_connection(&connection, &path)?;
        prepare_fresh_target_schema_v5(&mut connection, 1)?;
        activate_fresh_target_repository_v5(&mut connection, "standard", 2)?;
        drop(connection);
        SqliteV5Store::open_with_blob_repository_and_capacity_profile(
            path,
            blob_repository,
            SqliteCapacityProfile::Standard,
        )
    }

    impl ConformanceRepository for SqliteV5Store {
        fn inject_commit_abort(&self) {
            self.fail_next_commit.store(true, Ordering::Release);
        }
    }

    fn content(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn tenant() -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f78f1")?)
    }

    fn prepared_receipt_delta(
        parent: StoreRevision,
        suffix: &str,
    ) -> Result<PreparedRepositoryDeltaV5, Box<dyn std::error::Error>> {
        let context = AccessContext::new(tenant()?, "test")?;
        let identity = IdempotencyIdentity::new(
            "test",
            IdempotencyKey::new(format!("receipt-{suffix}"))?,
            content('a')?,
        )?;
        Ok(
            repository_delta_from_staged_v5(parent, &context, &[], Some(&identity), 1)?
                .prepare()?,
        )
    }

    fn identity(suffix: &str) -> Result<IdempotencyIdentity, Box<dyn std::error::Error>> {
        Ok(IdempotencyIdentity::new(
            "test",
            IdempotencyKey::new(format!("receipt-{suffix}"))?,
            content('a')?,
        )?)
    }

    fn fixture_atom() -> Result<ContextAtomV1, Box<dyn std::error::Error>> {
        let fixture = cigar_testkit::deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing ContextAtomV1 fixture")?;
        Ok(serde_json::from_value(fixture.input)?)
    }

    fn target(
        policy: RepositoryPolicyV5,
    ) -> Result<(tempfile::TempDir, Connection), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("target.sqlite3");
        drop(SqliteStore::open(&path)?);
        let mut connection = Connection::open(&path)?;
        configure_v5_test_connection(&connection, &path)?;
        prepare_fresh_target_schema_v5(&mut connection, 1)?;
        activate_fresh_target_repository_v5_with_policy(&mut connection, "standard", 2, policy)?;
        Ok((directory, connection))
    }

    fn target_with_receipt_deltas(
        count: u64,
    ) -> Result<(tempfile::TempDir, Connection), Box<dyn std::error::Error>> {
        target_with_receipt_deltas_and_policy(count, RepositoryPolicyV5::qualification("standard")?)
    }

    fn target_with_receipt_deltas_and_policy(
        count: u64,
        policy: RepositoryPolicyV5,
    ) -> Result<(tempfile::TempDir, Connection), Box<dyn std::error::Error>> {
        let (directory, mut connection) = target(policy)?;
        let mut state = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        for revision in 0..count {
            let prepared =
                prepared_receipt_delta(StoreRevision(revision), &format!("chain-{revision}"))?;
            let (_, next) = commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &state,
                |_transaction| Ok(()),
            )?;
            state = next;
        }
        Ok((directory, connection))
    }

    #[test]
    fn bounded_startup_uses_only_latest_checkpoint_suffix_and_recovers_current_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RepositoryPolicyV5::qualification("standard")?;
        policy.maximum_retained_revisions = 301;
        policy.validate("standard")?;
        let (_directory, mut connection) = target_with_receipt_deltas_and_policy(300, policy)?;
        connection.execute(
            "UPDATE repository_checkpoints_v5
             SET canonical_state = zeroblob(encoded_bytes) WHERE revision = 0",
            [],
        )?;
        connection.execute("DELETE FROM atom_projection_activation", [])?;
        let recovery_started = std::time::Instant::now();
        let recovered = recover_bounded_startup_v5(&mut connection)?;
        let recovery_elapsed = recovery_started.elapsed();
        assert!(recovery_elapsed < std::time::Duration::from_secs(30));
        assert_eq!(recovered.current_revision, StoreRevision(300));
        assert_eq!(recovered.checkpoint_revision, StoreRevision(257));
        assert_eq!(recovered.replayed_deltas, 43);
        assert_eq!(recovered.retained_revisions, 301);
        assert_eq!(recovered.projection_atom_count, 0);
        let clean_started = std::time::Instant::now();
        let bounded = bounded_startup_verification_v5(&connection)?;
        let clean_elapsed = clean_started.elapsed();
        assert!(clean_elapsed < std::time::Duration::from_secs(30));
        eprintln!(
            "bounded-startup clean_ms={} recovery_ms={} retained={} checkpoint={} deltas={}",
            clean_elapsed.as_millis(),
            recovery_elapsed.as_millis(),
            bounded.retained_revisions,
            bounded.checkpoint_revision.0,
            bounded.replayed_deltas
        );
        assert_eq!(bounded.checkpoint_revision, StoreRevision(257));
        assert_eq!(bounded.replayed_deltas, 43);
        assert_eq!(
            deep_integrity_verification_v5(&connection, None)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );
        Ok(())
    }

    #[test]
    fn deep_integrity_reuses_only_an_unchanged_authenticated_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, mut connection) = target_with_receipt_deltas(300)?;
        recover_bounded_startup_v5(&mut connection)?;
        let full = deep_integrity_verification_v5(&connection, None)?;
        assert_eq!(full.first_retained_revision, StoreRevision(0));
        assert_eq!(full.current_revision, StoreRevision(300));
        assert_eq!(full.verified_revisions, 301);
        assert_eq!(full.reused_prefix_revisions, 0);
        let prefix = VerifiedPrefixStateV5 {
            first_revision: full.first_retained_revision,
            through_revision: full.verified_through_revision,
            through_chain_head: full.chain_head.clone(),
            policy_digest: full.policy_digest.clone(),
        };
        let unchanged = deep_integrity_verification_v5(&connection, Some(&prefix))?;
        assert_eq!(unchanged.verified_revisions, 0);
        assert_eq!(unchanged.reused_prefix_revisions, 301);

        let mut state = reconstruct_repository_revision_v5(&connection, StoreRevision(300))?;
        for revision in 300_u64..303 {
            let prepared =
                prepared_receipt_delta(StoreRevision(revision), &format!("suffix-{revision}"))?;
            let (_, next) = commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &state,
                |_transaction| Ok(()),
            )?;
            state = next;
        }
        recover_bounded_startup_v5(&mut connection)?;
        let incremental = deep_integrity_verification_v5(&connection, Some(&prefix))?;
        assert_eq!(incremental.verified_from_revision, Some(StoreRevision(301)));
        assert_eq!(incremental.verified_through_revision, StoreRevision(303));
        assert_eq!(incremental.verified_revisions, 3);
        assert_eq!(incremental.reused_prefix_revisions, 301);

        let mut stale = prefix;
        stale.through_chain_head = ContentDigest::new(format!("1220{:064x}", 99))?;
        assert!(!verified_prefix_is_compatible_v5(&connection, &stale)?);
        assert_eq!(
            deep_integrity_verification_v5(&connection, Some(&stale))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::RevisionConflict)
        );
        Ok(())
    }

    fn assert_same_state(left: &CommittedState, right: &CommittedState) -> Result<(), StoreError> {
        assert_eq!(
            encode_catalog_free_state_v5(left)?,
            encode_catalog_free_state_v5(right)?
        );
        Ok(())
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RevisionEvidence {
        state_digest: ContentDigest,
        catalog_root: ContentDigest,
        semantic_root: ContentDigest,
        chain_head: ContentDigest,
        totals: RepositoryLogicalTotalsV5,
    }

    fn revision_evidence(
        connection: &Connection,
        revision: StoreRevision,
    ) -> Result<RevisionEvidence, StoreError> {
        let row = connection
            .query_row(
                "SELECT state_digest, catalog_root, semantic_root, chain_head,
                        atom_count, edge_count, referenced_blob_bytes
                 FROM repository_revisions_v5 WHERE revision = ?1",
                params![sqlite_revision(revision)?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .map_err(unavailable)?;
        Ok(RevisionEvidence {
            state_digest: parse_digest(row.0)?,
            catalog_root: parse_digest(row.1)?,
            semantic_root: parse_digest(row.2)?,
            chain_head: parse_digest(row.3)?,
            totals: RepositoryLogicalTotalsV5 {
                atom_count: u64::try_from(row.4).map_err(|_error| invalid_record())?,
                edge_count: u64::try_from(row.5).map_err(|_error| invalid_record())?,
                referenced_blob_bytes: u64::try_from(row.6).map_err(|_error| invalid_record())?,
            },
        })
    }

    fn capture_original_evidence(
        connection: &Connection,
        state: &CommittedState,
    ) -> Result<RevisionEvidence, StoreError> {
        let evidence = revision_evidence(connection, state.revision)?;
        assert_eq!(evidence.catalog_root, catalog_root_from_table(connection)?);
        assert_eq!(evidence.totals, catalog_totals(connection)?);
        assert_eq!(
            evidence.semantic_root,
            repository_semantic_root_v5(
                state.revision,
                &evidence.state_digest,
                &evidence.catalog_root,
                evidence.totals,
            )?
        );
        Ok(evidence)
    }

    fn capture_original_revision(
        connection: &Connection,
        state: &CommittedState,
    ) -> Result<(Vec<u8>, RevisionEvidence), StoreError> {
        Ok((
            encode_catalog_free_state_v5(state)?,
            capture_original_evidence(connection, state)?,
        ))
    }

    fn property_value(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *seed
    }

    fn generated_atom(template: &ContextAtomV1, unique: u64) -> Result<ContextAtomV1, StoreError> {
        let mut atom = template.clone();
        atom.atom_id = RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{unique:012x}"))
            .map_err(|_error| invalid_record())?;
        atom.version_id =
            VersionId::new(format!("1220{unique:064x}")).map_err(|_error| invalid_record())?;
        validate(&atom)?;
        Ok(atom)
    }

    fn representative_staged_mutations(
        fixture: &crate::conformance::RepositoryFixture,
        atom_template: &ContextAtomV1,
        revision: u64,
    ) -> Result<Vec<StagedMutation>, StoreError> {
        let mut staged = if revision.is_multiple_of(2) {
            vec![StagedMutation::Snapshot(fixture.snapshot.clone())]
        } else {
            vec![StagedMutation::Bundle(fixture.bundle.clone())]
        };
        if revision.is_multiple_of(10) {
            staged.push(StagedMutation::Atoms(
                vec![generated_atom(
                    atom_template,
                    revision.checked_add(100_000).ok_or_else(limit_exceeded)?,
                )?],
                Vec::new(),
            ));
        }
        Ok(staged)
    }

    fn representative_identity(revision: u64) -> Result<IdempotencyIdentity, StoreError> {
        IdempotencyIdentity::new(
            "qualification.sequence",
            IdempotencyKey::new(format!("qualification-{revision}"))
                .map_err(|_error| invalid_record())?,
            ContentDigest::new(format!("1220{revision:064x}"))
                .map_err(|_error| invalid_record())?,
        )
    }

    #[test]
    fn v5_backend_passes_reusable_repository_conformance() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let fixture = crate::conformance::tests::repository_fixture()?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let key = provider.create(CreateKeyRequest {
            tenant: fixture.context.tenant_id().as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let local = LocalBlobStore::open(directory.path().join("blobs"), provider)?;
        let blobs: Arc<dyn RepositoryBlobStore> =
            Arc::new(LocalRepositoryBlobStore::new(local, key.key_ref, 1));
        let store =
            open_production_v5_store(directory.path().join("conformance-v5.sqlite3"), blobs)?;
        let report = run_repository_conformance(&store, &fixture)?;
        assert_eq!(report.methods_exercised, 21);
        assert_eq!(report.concurrent_writers, 2);
        assert_eq!(report.invariants_checked, 19);
        let connection = store.lock()?;
        assert_eq!(
            retention_statistics_v5(&connection)?.current_revision,
            StoreRevision(2)
        );
        Ok(())
    }

    #[test]
    fn production_v5_service_and_worker_writes_survive_restart_without_v4_growth()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("production-v5.sqlite3");
        let provider = Arc::new(MemoryKeyProvider::default());
        let tenant = tenant()?;
        let key = provider.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let local = LocalBlobStore::open(directory.path().join("production-v5-blobs"), provider)?;
        let blobs: Arc<dyn RepositoryBlobStore> =
            Arc::new(LocalRepositoryBlobStore::new(local, key.key_ref, 1));
        let locator = ServiceRecordLocator::new(tenant.clone(), "runtime", "restart")?;
        let worker = WorkerLocator::new(tenant.clone(), "runtime-worker")?;
        {
            let store = open_production_v5_store(path.clone(), Arc::clone(&blobs))?;
            let receipt = store.service_commit(
                ServiceBatch::new(
                    tenant.clone(),
                    vec![ServiceRecordWrite::new(
                        "runtime",
                        "restart",
                        ServiceExpectedVersion::Absent,
                        b"v5-service-state".to_vec(),
                    )?],
                    ServiceResponse::new(200, "application/json", b"ok".to_vec())?,
                )?,
                &CancellationToken::default(),
            )?;
            assert_eq!(receipt.revision, StoreRevision(1));
            let state = store.worker_update(
                &worker,
                WorkerUpdate::Claim {
                    expected: ServiceExpectedVersion::Absent,
                    owner: "runtime-test".to_owned(),
                    now_unix_nanos: 1,
                    expires_at_unix_nanos: 100,
                },
                &CancellationToken::default(),
            )?;
            assert_eq!(state.store_revision(), StoreRevision(2));
        }

        let reopened = SqliteV5Store::open_with_blob_repository_and_capacity_profile(
            &path,
            blobs,
            SqliteCapacityProfile::Standard,
        )?;
        assert_eq!(reopened.revision()?, StoreRevision(2));
        let record = reopened
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )?
            .ok_or("missing v5 service record after restart")?;
        assert_eq!(record.bytes(), b"v5-service-state");
        assert_eq!(
            reopened
                .worker_get(&worker, &CancellationToken::default())?
                .ok_or("missing v5 worker state after restart")?
                .store_revision(),
            StoreRevision(2)
        );
        let connection =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM cigar_repository_revisions_v4",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM repository_deltas_v5", [], |row| row
                .get::<_, i64>(
                0
            ),)?,
            2
        );
        Ok(())
    }

    #[test]
    fn frozen_small_efficiency_fixture_is_incremental_bounded_and_ready()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority: serde_json::Value = serde_json::from_str(include_str!(
            "../../../benches/honey-efficiency/qualification-fixtures.v1.json"
        ))?;
        let small = authority
            .get("fixtures")
            .and_then(serde_json::Value::as_array)
            .and_then(|fixtures| {
                fixtures.iter().find(|fixture| {
                    fixture.get("id").and_then(serde_json::Value::as_str)
                        == Some("H91-FIXTURE-SMALL-GENERATED")
                })
            })
            .and_then(|fixture| fixture.get("generator_inputs"))
            .ok_or("frozen small efficiency fixture is unavailable")?;
        let initial_records = small
            .get("initial_records")
            .and_then(serde_json::Value::as_u64)
            .ok_or("small initial-record count is unavailable")?;
        let requests = small
            .get("request_count")
            .and_then(serde_json::Value::as_u64)
            .ok_or("small request count is unavailable")?;
        let mutations_per_request = small
            .get("mutations_per_request")
            .and_then(serde_json::Value::as_u64)
            .ok_or("small mutation count is unavailable")?;
        assert_eq!(
            (initial_records, requests, mutations_per_request),
            (8, 12, 4)
        );

        let fixture = crate::conformance::tests::repository_fixture()?;
        let atom_template = fixture.atoms.first().ok_or("missing fixture atom")?;
        let (directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let path = directory.path().join("target.sqlite3");
        let mut state = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;

        for record in 1..=initial_records {
            let staged = vec![StagedMutation::Atoms(
                vec![generated_atom(atom_template, record)?],
                Vec::new(),
            )];
            let logical_bytes = staged_logical_bytes(&staged)?;
            let prepared = repository_delta_from_staged_v5(
                state.revision,
                &fixture.context,
                &staged,
                None,
                logical_bytes,
            )?
            .prepare()?;
            let revision = prepared.delta().result_revision();
            let tenant_id = fixture.context.tenant_id().clone();
            let (_, next) = commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &state,
                move |transaction| {
                    let mut touched = BTreeSet::new();
                    for mutation in staged {
                        if let StagedMutation::Atoms(atoms, edges) = mutation {
                            touched.extend(apply_catalog_batch(
                                transaction,
                                &tenant_id,
                                atoms,
                                edges,
                                revision,
                                &CancellationToken::default(),
                            )?);
                        }
                    }
                    for bucket in touched {
                        persist_catalog_bucket(transaction, bucket, revision)?;
                    }
                    Ok(())
                },
            )?;
            state = next;
        }

        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let physical_before = std::fs::metadata(&path)?.len();
        let mut request_latencies = Vec::with_capacity(usize::try_from(requests)?);
        for request in 0..requests {
            let started = std::time::Instant::now();
            for operation in 0..mutations_per_request {
                let sequence = request
                    .checked_mul(mutations_per_request)
                    .and_then(|value| value.checked_add(operation))
                    .and_then(|value| value.checked_add(1))
                    .ok_or("small fixture operation overflow")?;
                let staged = representative_staged_mutations(&fixture, atom_template, sequence)?;
                let identity = representative_identity(sequence)?;
                let logical_bytes = staged_logical_bytes(&staged)?;
                let prepared = repository_delta_from_staged_v5(
                    state.revision,
                    &fixture.context,
                    &staged,
                    Some(&identity),
                    logical_bytes,
                )?
                .prepare()?;
                let revision = prepared.delta().result_revision();
                let tenant_id = fixture.context.tenant_id().clone();
                let (_, next) = commit_prepared_repository_delta_v5(
                    &mut connection,
                    &prepared,
                    &state,
                    move |transaction| {
                        let mut touched = BTreeSet::new();
                        for mutation in staged {
                            if let StagedMutation::Atoms(atoms, edges) = mutation {
                                touched.extend(apply_catalog_batch(
                                    transaction,
                                    &tenant_id,
                                    atoms,
                                    edges,
                                    revision,
                                    &CancellationToken::default(),
                                )?);
                            }
                        }
                        for bucket in touched {
                            persist_catalog_bucket(transaction, bucket, revision)?;
                        }
                        Ok(())
                    },
                )?;
                state = next;
            }
            request_latencies.push(i128::try_from(started.elapsed().as_nanos())?);
        }

        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let physical_after = std::fs::metadata(&path)?.len();
        let growth_per_request = physical_after
            .saturating_sub(physical_before)
            .div_ceil(requests);
        assert!(growth_per_request < 1_048_576);

        let mut ordered = request_latencies.clone();
        ordered.sort_unstable();
        let p95_index = usize::try_from(
            requests
                .checked_mul(95)
                .ok_or("p95 overflow")?
                .div_ceil(100)
                .checked_sub(1)
                .ok_or("p95 rank is empty")?,
        )?;
        assert!(
            *ordered
                .get(p95_index)
                .ok_or("p95 observation is unavailable")?
                < 10_000_000_000
        );
        let count = i128::try_from(request_latencies.len())?;
        let sum_x = count * (count - 1) / 2;
        let sum_x_squared = count * (count - 1) * (2 * count - 1) / 6;
        let slope_numerator = count
            * request_latencies
                .iter()
                .enumerate()
                .map(|(index, latency)| i128::try_from(index).unwrap_or(i128::MAX) * latency)
                .sum::<i128>()
            - sum_x * request_latencies.iter().sum::<i128>();
        let slope_denominator = count * sum_x_squared - sum_x * sum_x;
        assert!(slope_denominator > 0);
        assert!(slope_numerator <= 10_000_000 * slope_denominator);

        let statistics = retention_statistics_v5(&connection)?;
        let expected_revision = initial_records
            .checked_add(
                requests
                    .checked_mul(mutations_per_request)
                    .ok_or("revision overflow")?,
            )
            .ok_or("revision overflow")?;
        assert_eq!(
            statistics.current_revision,
            StoreRevision(expected_revision)
        );
        assert_eq!(
            statistics.retained_checkpoints + statistics.retained_deltas,
            statistics.retained_revisions
        );
        assert!(!statistics.capacity_blocked);
        for revision in 0..=expected_revision {
            assert_eq!(
                reconstruct_repository_revision_v5(&connection, StoreRevision(revision))?.revision,
                StoreRevision(revision)
            );
        }
        drop(connection);

        let startup_started = std::time::Instant::now();
        let startup = SqliteStore::v5_recover_bounded_startup_at(&path)?;
        assert!(startup_started.elapsed() < std::time::Duration::from_secs(30));
        assert_eq!(startup.current_revision, StoreRevision(expected_revision));
        assert!(startup.replayed_deltas <= statistics.maximum_deltas_since_checkpoint);
        assert!(startup.replayed_delta_bytes <= statistics.maximum_accumulated_delta_bytes);
        assert_eq!(SqliteStore::v5_bounded_startup_at(&path)?, startup);
        Ok(())
    }

    #[test]
    fn generated_valid_mutation_sequences_reconstruct_every_original_state_and_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = crate::conformance::tests::repository_fixture()?;
        let atom_template = fixture.atoms.first().ok_or("missing fixture atom")?;
        for case in 0_u64..12 {
            let mut seed = 0x9e37_79b9_7f4a_7c15_u64 ^ case.wrapping_mul(0x1000_0000_01b3);
            let checkpoint_count = property_value(&mut seed) % 7 + 1;
            let checkpoint_bytes = property_value(&mut seed) % 8_192 + 512;
            let policy = RepositoryPolicyV5::new(checkpoint_count, checkpoint_bytes, "standard")?;
            let (_directory, mut connection) = target(policy)?;
            let mut state = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
            let mut expected = vec![capture_original_revision(&connection, &state)?];
            let sequence_length = property_value(&mut seed) % 24 + 17;
            for step in 0..sequence_length {
                let choice = property_value(&mut seed);
                let mut staged = Vec::new();
                if choice & 1 != 0 {
                    staged.push(StagedMutation::Snapshot(fixture.snapshot.clone()));
                }
                if choice & 2 != 0 {
                    staged.push(StagedMutation::Bundle(fixture.bundle.clone()));
                }
                if staged.is_empty() {
                    staged.push(StagedMutation::Snapshot(fixture.snapshot.clone()));
                }
                if choice & 4 != 0 {
                    let unique = case
                        .checked_mul(1_000)
                        .and_then(|value| value.checked_add(step))
                        .and_then(|value| value.checked_add(1))
                        .ok_or_else(limit_exceeded)?;
                    staged.push(StagedMutation::Atoms(
                        vec![generated_atom(atom_template, unique)?],
                        Vec::new(),
                    ));
                }
                let identity = IdempotencyIdentity::new(
                    "property.sequence",
                    IdempotencyKey::new(format!("case-{case}-step-{step}"))?,
                    ContentDigest::new(format!("1220{:064x}", property_value(&mut seed)))?,
                )?;
                let logical_bytes = staged_logical_bytes(&staged)?;
                let prepared = repository_delta_from_staged_v5(
                    state.revision,
                    &fixture.context,
                    &staged,
                    Some(&identity),
                    logical_bytes,
                )?
                .prepare()?;
                let revision = prepared.delta().result_revision();
                let tenant_id = fixture.context.tenant_id().clone();
                let (committed, next) = commit_prepared_repository_delta_v5(
                    &mut connection,
                    &prepared,
                    &state,
                    move |transaction| {
                        let mut touched_buckets = BTreeSet::new();
                        for mutation in staged {
                            if let StagedMutation::Atoms(atoms, edges) = mutation {
                                touched_buckets.extend(apply_catalog_batch(
                                    transaction,
                                    &tenant_id,
                                    atoms,
                                    edges,
                                    revision,
                                    &CancellationToken::default(),
                                )?);
                            }
                        }
                        for bucket in touched_buckets {
                            persist_catalog_bucket(transaction, bucket, revision)?;
                        }
                        Ok(())
                    },
                )?;
                assert_eq!(committed.revision, revision);
                state = next;
                expected.push(capture_original_revision(&connection, &state)?);
            }

            for (revision, (canonical_state, original_evidence)) in expected.iter().enumerate() {
                let revision = StoreRevision(u64::try_from(revision)?);
                let reconstructed = reconstruct_repository_revision_v5(&connection, revision)?;
                assert_eq!(
                    encode_catalog_free_state_v5(&reconstructed)?,
                    *canonical_state
                );
                assert_eq!(
                    revision_evidence(&connection, revision)?,
                    *original_evidence
                );
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "explicit 10,000-mutation storage qualification gate"]
    fn ten_thousand_mutations_are_incremental_and_exactly_reconstructable()
    -> Result<(), Box<dyn std::error::Error>> {
        const MUTATIONS: u64 = 10_000;
        let fixture = crate::conformance::tests::repository_fixture()?;
        let atom_template = fixture.atoms.first().ok_or("missing fixture atom")?;
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let mut state = genesis.clone();
        let mut original_evidence = Vec::with_capacity(usize::try_from(MUTATIONS + 1)?);
        original_evidence.push(capture_original_evidence(&connection, &state)?);
        for revision in 1..=MUTATIONS {
            let staged = representative_staged_mutations(&fixture, atom_template, revision)?;
            let identity = revision
                .is_multiple_of(100)
                .then(|| representative_identity(revision))
                .transpose()?;
            let logical_bytes = staged_logical_bytes(&staged)?;
            let prepared = repository_delta_from_staged_v5(
                state.revision,
                &fixture.context,
                &staged,
                identity.as_ref(),
                logical_bytes,
            )?
            .prepare()?;
            let result_revision = prepared.delta().result_revision();
            let tenant_id = fixture.context.tenant_id().clone();
            let (_, next) = commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &state,
                move |transaction| {
                    let mut touched_buckets = BTreeSet::new();
                    for mutation in staged {
                        if let StagedMutation::Atoms(atoms, edges) = mutation {
                            touched_buckets.extend(apply_catalog_batch(
                                transaction,
                                &tenant_id,
                                atoms,
                                edges,
                                result_revision,
                                &CancellationToken::default(),
                            )?);
                        }
                    }
                    for bucket in touched_buckets {
                        persist_catalog_bucket(transaction, bucket, result_revision)?;
                    }
                    Ok(())
                },
            )?;
            state = next;
            original_evidence.push(capture_original_evidence(&connection, &state)?);
        }

        let counts: (i64, i64, i64, i64) = connection.query_row(
            "SELECT
                (SELECT COUNT(*) FROM repository_revisions_v5),
                (SELECT COUNT(*) FROM repository_deltas_v5),
                (SELECT COUNT(*) FROM repository_checkpoints_v5),
                (SELECT COUNT(*) FROM cigar_repository_revisions_v4)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(counts.0, 10_001);
        assert_eq!(counts.1 + counts.2, counts.0);
        assert!(counts.2 < 100);
        assert_eq!(counts.3, 1);

        let mut expected = genesis;
        assert!(reconstruct_repository_revision_v5(&connection, StoreRevision(0))? == expected);
        for revision in 1..=MUTATIONS {
            let staged = representative_staged_mutations(&fixture, atom_template, revision)?;
            let identity = revision
                .is_multiple_of(100)
                .then(|| representative_identity(revision))
                .transpose()?;
            let logical_bytes = staged_logical_bytes(&staged)?;
            let delta = repository_delta_from_staged_v5(
                expected.revision,
                &fixture.context,
                &staged,
                identity.as_ref(),
                logical_bytes,
            )?;
            expected = apply_repository_delta_v5(expected, &delta)?;
            let reconstructed =
                reconstruct_repository_revision_v5(&connection, StoreRevision(revision))?;
            assert!(reconstructed == expected, "revision {revision}");
            assert_eq!(
                revision_evidence(&connection, StoreRevision(revision))?,
                *original_evidence
                    .get(usize::try_from(revision)?)
                    .ok_or("missing original revision evidence")?
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "explicit 4-by-2,500 mixed-concurrency storage qualification gate"]
    fn mixed_concurrency_soak_is_reconcilable_and_exactly_reconstructable()
    -> Result<(), Box<dyn std::error::Error>> {
        const WORKERS: u64 = 4;
        const MUTATIONS_PER_WORKER: u64 = 2_500;
        const MAX_ATTEMPTS_PER_MUTATION: u64 = 10_000;

        let fixture = crate::conformance::tests::repository_fixture()?;
        let atom_template = fixture.atoms.first().ok_or("missing fixture atom")?.clone();
        let (directory, connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let path = directory.path().join("target.sqlite3");
        drop(connection);

        let barrier = Arc::new(Barrier::new(usize::try_from(WORKERS)?));
        let worker_results = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(usize::try_from(WORKERS).unwrap_or(4));
            for worker in 0..WORKERS {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                let fixture = fixture.clone();
                let atom_template = atom_template.clone();
                handles.push(scope.spawn(move || -> Result<(u64, u64, u64), StoreError> {
                    let mut connection = Connection::open(&path).map_err(unavailable)?;
                    configure_v5_test_connection(&connection, &path)?;
                    let mut committed = 0_u64;
                    let mut replayed = 0_u64;
                    let mut reconciliations = 0_u64;
                    barrier.wait();

                    for local_mutation in 0..MUTATIONS_PER_WORKER {
                        let operation = worker
                            .checked_mul(MUTATIONS_PER_WORKER)
                            .and_then(|value| value.checked_add(local_mutation))
                            .and_then(|value| value.checked_add(1))
                            .ok_or_else(limit_exceeded)?;
                        let identity = representative_identity(operation)?;
                        let mut completed = false;
                        for attempt in 0..MAX_ATTEMPTS_PER_MUTATION {
                            let authority = load_authority(&connection)?;
                            let state = reconstruct_repository_revision_v5(
                                &connection,
                                authority.current_revision,
                            )?;
                            let staged = representative_staged_mutations(
                                &fixture,
                                &atom_template,
                                operation,
                            )?;
                            let logical_bytes = staged_logical_bytes(&staged)?;
                            let prepared = repository_delta_from_staged_v5(
                                state.revision,
                                &fixture.context,
                                &staged,
                                Some(&identity),
                                logical_bytes,
                            )?
                            .prepare()?;
                            let result_revision = prepared.delta().result_revision();
                            let tenant_id = fixture.context.tenant_id().clone();
                            match commit_or_replay_repository_delta_v5(
                                &mut connection,
                                &prepared,
                                &state,
                                &identity,
                                move |transaction| {
                                    let mut touched_buckets = BTreeSet::new();
                                    for mutation in staged {
                                        if let StagedMutation::Atoms(atoms, edges) = mutation {
                                            touched_buckets.extend(apply_catalog_batch(
                                                transaction,
                                                &tenant_id,
                                                atoms,
                                                edges,
                                                result_revision,
                                                &CancellationToken::default(),
                                            )?);
                                        }
                                    }
                                    for bucket in touched_buckets {
                                        persist_catalog_bucket(
                                            transaction,
                                            bucket,
                                            result_revision,
                                        )?;
                                    }
                                    Ok(())
                                },
                            ) {
                                Ok((RepositoryCommitAttemptV5::Committed(_receipt), _state)) => {
                                    committed =
                                        committed.checked_add(1).ok_or_else(limit_exceeded)?;
                                    completed = true;
                                    break;
                                }
                                Ok((RepositoryCommitAttemptV5::Replayed(_receipt), _state)) => {
                                    replayed =
                                        replayed.checked_add(1).ok_or_else(limit_exceeded)?;
                                    completed = true;
                                    break;
                                }
                                Err(error)
                                    if matches!(
                                        error.code(),
                                        StoreErrorCode::RevisionConflict
                                            | StoreErrorCode::Unavailable
                                    ) && attempt + 1 < MAX_ATTEMPTS_PER_MUTATION =>
                                {
                                    reconciliations = reconciliations
                                        .checked_add(1)
                                        .ok_or_else(limit_exceeded)?;
                                }
                                Err(error) => {
                                    eprintln!(
                                        "mixed-concurrency stage=worker-failed worker={worker} local_mutation={local_mutation} operation={operation} attempt={attempt} code={:?}",
                                        error.code()
                                    );
                                    return Err(error);
                                }
                            }
                        }
                        if !completed {
                            return Err(StoreError::new(StoreErrorCode::Unavailable));
                        }
                    }
                    Ok((committed, replayed, reconciliations))
                }));
            }

            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(
                    handle
                        .join()
                        .map_err(|_panic| StoreError::new(StoreErrorCode::Unavailable))??,
                );
            }
            Ok::<Vec<(u64, u64, u64)>, StoreError>(results)
        })?;

        let mut connection = Connection::open(&path)?;
        configure_v5_test_connection(&connection, &path)?;
        let authority = load_authority(&connection)?;
        let expected_mutations = WORKERS
            .checked_mul(MUTATIONS_PER_WORKER)
            .ok_or("mutation count overflow")?;
        assert_eq!(
            authority.current_revision,
            StoreRevision(expected_mutations)
        );
        eprintln!(
            "mixed-concurrency stage=commits-complete revision={}",
            authority.current_revision.0
        );
        let reconstructed =
            reconstruct_repository_revision_v5(&connection, authority.current_revision)?;
        assert_eq!(reconstructed.revision, authority.current_revision);
        eprintln!("mixed-concurrency stage=exact-reconstruction-complete");
        let statistics = retention_statistics_v5(&connection)?;
        assert_eq!(statistics.retained_revisions, expected_mutations + 1);
        assert_eq!(
            statistics.retained_checkpoints + statistics.retained_deltas,
            statistics.retained_revisions
        );
        eprintln!("mixed-concurrency stage=retention-statistics-complete");
        let recovered = recover_bounded_startup_v5(&mut connection)?;
        assert_eq!(recovered.current_revision, authority.current_revision);
        assert!(recovered.replayed_deltas <= statistics.maximum_deltas_since_checkpoint);
        assert!(recovered.replayed_delta_bytes <= statistics.maximum_accumulated_delta_bytes);
        eprintln!("mixed-concurrency stage=startup-recovery-complete");
        let readiness = bounded_startup_verification_v5(&connection)?;
        assert!(readiness.replayed_deltas <= statistics.maximum_deltas_since_checkpoint);
        assert!(readiness.replayed_delta_bytes <= statistics.maximum_accumulated_delta_bytes);
        eprintln!("mixed-concurrency stage=bounded-readiness-complete");

        let (committed, replayed, reconciliations) =
            worker_results
                .into_iter()
                .fold((0_u64, 0_u64, 0_u64), |totals, result| {
                    (
                        totals.0.saturating_add(result.0),
                        totals.1.saturating_add(result.1),
                        totals.2.saturating_add(result.2),
                    )
                });
        assert_eq!(committed + replayed, expected_mutations);
        eprintln!(
            "mixed-concurrency workers={WORKERS} mutations_per_worker={MUTATIONS_PER_WORKER} committed={committed} replayed={replayed} reconciliations={reconciliations} checkpoints={} deltas={} checkpoint_bytes={} delta_bytes={} readiness_suffix={} readiness_suffix_bytes={}",
            statistics.retained_checkpoints,
            statistics.retained_deltas,
            statistics.retained_checkpoint_bytes,
            statistics.retained_delta_bytes,
            readiness.replayed_deltas,
            readiness.replayed_delta_bytes,
        );
        Ok(())
    }

    #[test]
    fn activation_and_atomic_delta_commit_reconstruct_exact_revisions()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "one")?;
        let (receipt, expected) = commit_prepared_repository_delta_v5(
            &mut connection,
            &prepared,
            &genesis,
            |_transaction| Ok(()),
        )?;
        assert_eq!(receipt.revision, StoreRevision(1));
        assert_eq!(receipt.payload_kind, RepositoryPayloadKindV5::Delta);
        assert!(receipt.encoded_delta_bytes > 0);
        assert_eq!(receipt.checkpoint_bytes, 0);
        assert_same_state(
            &reconstruct_repository_revision_v5(&connection, StoreRevision(1))?,
            &expected,
        )?;
        assert_same_state(
            &reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)?,
            &expected,
        )?;
        assert_same_state(
            &reconstruct_repository_snapshot_v5(
                &connection,
                SnapshotSelection::Revision(StoreRevision(0)),
            )?,
            &genesis,
        )?;

        assert_eq!(
            commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &genesis,
                |_transaction| Ok(())
            )
            .err()
            .map(|error| error.code()),
            Some(StoreErrorCode::RevisionConflict)
        );
        let revisions: i64 =
            connection.query_row("SELECT COUNT(*) FROM repository_revisions_v5", [], |row| {
                row.get(0)
            })?;
        assert_eq!(revisions, 2);
        Ok(())
    }

    #[test]
    fn transaction_rollback_never_publishes_a_hybrid_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        connection.execute("CREATE TABLE v5_test_marker (value INTEGER NOT NULL)", [])?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "rollback")?;
        let result = commit_prepared_repository_delta_v5(
            &mut connection,
            &prepared,
            &genesis,
            |transaction| {
                transaction
                    .execute("INSERT INTO v5_test_marker VALUES (1)", [])
                    .map_err(unavailable)?;
                Err(StoreError::new(StoreErrorCode::InjectedAbort))
            },
        );
        assert_eq!(
            result.err().map(|error| error.code()),
            Some(StoreErrorCode::InjectedAbort)
        );
        let marker: i64 =
            connection.query_row("SELECT COUNT(*) FROM v5_test_marker", [], |row| row.get(0))?;
        let revisions: i64 =
            connection.query_row("SELECT COUNT(*) FROM repository_revisions_v5", [], |row| {
                row.get(0)
            })?;
        assert_eq!((marker, revisions), (0, 1));
        assert_same_state(
            &reconstruct_repository_revision_v5(&connection, StoreRevision(0))?,
            &genesis,
        )?;
        Ok(())
    }

    #[test]
    fn count_and_byte_thresholds_create_bounded_checkpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let count_policy = RepositoryPolicyV5::new(
            1,
            u64::try_from(MAX_ACCUMULATED_DELTA_BYTES_V5)?,
            "standard",
        )?;
        let (_directory, mut connection) = target(count_policy)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let first = prepared_receipt_delta(StoreRevision(0), "count-one")?;
        let (_, first_state) = commit_prepared_repository_delta_v5(
            &mut connection,
            &first,
            &genesis,
            |_transaction| Ok(()),
        )?;
        let second = prepared_receipt_delta(StoreRevision(1), "count-two")?;
        let (receipt, second_state) = commit_prepared_repository_delta_v5(
            &mut connection,
            &second,
            &first_state,
            |_transaction| Ok(()),
        )?;
        assert_eq!(
            receipt.payload_kind,
            RepositoryPayloadKindV5::Checkpoint(RepositoryCheckpointReasonV5::DeltaCount)
        );
        assert_eq!(receipt.encoded_delta_bytes, 0);
        assert!(receipt.checkpoint_bytes > 0);
        assert_same_state(
            &reconstruct_repository_revision_v5(&connection, StoreRevision(2))?,
            &second_state,
        )?;

        let byte_policy = RepositoryPolicyV5::new(256, 1, "standard")?;
        let (_directory, mut connection) = target(byte_policy)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "bytes")?;
        let (receipt, expected) = commit_prepared_repository_delta_v5(
            &mut connection,
            &prepared,
            &genesis,
            |_transaction| Ok(()),
        )?;
        assert_eq!(
            receipt.payload_kind,
            RepositoryPayloadKindV5::Checkpoint(RepositoryCheckpointReasonV5::DeltaBytes)
        );
        assert_same_state(
            &reconstruct_repository_revision_v5(&connection, StoreRevision(1))?,
            &expected,
        )?;
        Ok(())
    }

    #[test]
    fn corrupt_delta_fails_closed_during_reconstruction() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "corrupt")?;
        commit_prepared_repository_delta_v5(
            &mut connection,
            &prepared,
            &genesis,
            |_transaction| Ok(()),
        )?;
        connection.execute(
            "UPDATE repository_deltas_v5 SET canonical_delta = x'00', encoded_bytes = 1
             WHERE revision = 1",
            [],
        )?;
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(1))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );
        Ok(())
    }

    #[test]
    fn missing_wrong_reordered_and_truncated_chain_rows_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, connection) = target_with_receipt_deltas(3)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute("DELETE FROM repository_revisions_v5 WHERE revision = 1", [])?;
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(3))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );

        let (_directory, connection) = target_with_receipt_deltas(3)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        let first_payload: Vec<u8> = connection.query_row(
            "SELECT canonical_delta FROM repository_deltas_v5 WHERE revision = 1",
            [],
            |row| row.get(0),
        )?;
        connection.execute(
            "UPDATE repository_deltas_v5 SET canonical_delta = ?1, encoded_bytes = ?2
             WHERE revision = 2",
            params![first_payload, i64::try_from(first_payload.len())?],
        )?;
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(3))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );

        let (_directory, connection) = target_with_receipt_deltas(3)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        let second_payload: Vec<u8> = connection.query_row(
            "SELECT canonical_delta FROM repository_deltas_v5 WHERE revision = 2",
            [],
            |row| row.get(0),
        )?;
        connection.execute(
            "UPDATE repository_deltas_v5 SET canonical_delta = ?1, encoded_bytes = ?2
             WHERE revision = 1",
            params![second_payload, i64::try_from(second_payload.len())?],
        )?;
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(3))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );

        let (_directory, connection) = target_with_receipt_deltas(3)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute("DELETE FROM repository_deltas_v5 WHERE revision = 3", [])?;
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(3))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );
        Ok(())
    }

    #[test]
    #[ignore = "spawned only by the process-kill recovery matrix"]
    fn v5_process_kill_child() -> Result<(), Box<dyn std::error::Error>> {
        let Some(path) = std::env::var_os("CIGAR_V5_PROCESS_KILL_DATABASE") else {
            return Ok(());
        };
        let database = PathBuf::from(path);
        let anchor = std::env::var_os("CIGAR_V5_PROCESS_KILL_ANCHOR")
            .ok_or("missing process-kill anchor")?;
        let mut connection = Connection::open(&database)?;
        configure_v5_test_connection(&connection, &database)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "process-kill")?;
        let _result = commit_then_publish_repository_delta_v5(
            &mut connection,
            &PathBuf::from(anchor),
            &prepared,
            &genesis,
            |_transaction| Ok(()),
        )?;
        Err("configured process-kill failpoint was not reached".into())
    }

    #[test]
    fn process_kill_matrix_recovers_only_prior_or_complete_revisions()
    -> Result<(), Box<dyn std::error::Error>> {
        struct CrashCase {
            stage: &'static str,
            checkpoint: bool,
            expected_revision: StoreRevision,
        }
        let cases = [
            CrashCase {
                stage: "before_delta_insert",
                checkpoint: false,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "after_delta_insert",
                checkpoint: false,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "before_checkpoint_insert",
                checkpoint: true,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "after_checkpoint_insert",
                checkpoint: true,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "before_root_update",
                checkpoint: false,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "after_root_update",
                checkpoint: false,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "before_commit",
                checkpoint: false,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "before_full_fsync_return",
                checkpoint: false,
                expected_revision: StoreRevision(0),
            },
            CrashCase {
                stage: "after_full_fsync_return",
                checkpoint: false,
                expected_revision: StoreRevision(1),
            },
            CrashCase {
                stage: "after_commit",
                checkpoint: false,
                expected_revision: StoreRevision(1),
            },
            CrashCase {
                stage: "before_anchor_publication",
                checkpoint: false,
                expected_revision: StoreRevision(1),
            },
            CrashCase {
                stage: "after_anchor_publication",
                checkpoint: false,
                expected_revision: StoreRevision(1),
            },
        ];
        let executable = std::env::current_exe()?;
        for case in cases {
            let policy = if case.checkpoint {
                RepositoryPolicyV5::new(256, 1, "standard")?
            } else {
                RepositoryPolicyV5::qualification("standard")?
            };
            let (directory, connection) = target(policy)?;
            let database = directory.path().join("target.sqlite3");
            let anchor = directory.path().join("process-anchor");
            drop(connection);
            let status = Command::new(&executable)
                .args([
                    "--ignored",
                    "--exact",
                    "sqlite_v5::tests::v5_process_kill_child",
                    "--test-threads=1",
                ])
                .env("CIGAR_V5_PROCESS_KILL_STAGE", case.stage)
                .env("CIGAR_V5_PROCESS_KILL_DATABASE", &database)
                .env("CIGAR_V5_PROCESS_KILL_ANCHOR", &anchor)
                .status()?;
            assert!(
                !status.success(),
                "failpoint did not kill at {}",
                case.stage
            );

            let connection = Connection::open(&database)?;
            configure_v5_test_connection(&connection, &database)?;
            let recovered =
                reconstruct_repository_snapshot_v5(&connection, SnapshotSelection::Latest)?;
            assert_eq!(recovered.revision, case.expected_revision, "{}", case.stage);
            assert_eq!(
                retention_statistics_v5(&connection)?.current_revision,
                case.expected_revision,
                "{}",
                case.stage
            );
            let counts: (i64, i64, i64) = connection.query_row(
                "SELECT
                    (SELECT COUNT(*) FROM repository_revisions_v5),
                    (SELECT COUNT(*) FROM repository_deltas_v5),
                    (SELECT COUNT(*) FROM repository_checkpoints_v5)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            let expected_counts = if case.expected_revision == StoreRevision(0) {
                (1, 0, 1)
            } else {
                (2, 1, 1)
            };
            assert_eq!(counts, expected_counts, "{}", case.stage);
            assert_eq!(
                read_revision_anchor(&anchor)?,
                if case.stage == "after_anchor_publication" {
                    Some(StoreRevision(1))
                } else {
                    None
                },
                "{}",
                case.stage
            );
            assert_eq!(
                recover_revision_anchor_v5(&connection, &anchor)?,
                case.expected_revision,
                "{}",
                case.stage
            );
        }
        Ok(())
    }

    #[test]
    fn activation_rejects_reuse_and_preserves_single_genesis()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        assert_eq!(
            activate_fresh_target_repository_v5(&mut connection, "standard", 3)
                .map_err(|error| error.code()),
            Err(StoreErrorCode::InvalidRecord)
        );
        let genesis: i64 = connection.query_row(
            "SELECT COUNT(*) FROM repository_checkpoints_v5 WHERE revision = 0",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(genesis, 1);
        Ok(())
    }

    #[test]
    fn retention_policy_rejects_zero_unbounded_and_profile_incompatible_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = RepositoryPolicyV5::qualification("standard")?;
        policy.validate("standard")?;

        let mut invalid = policy;
        invalid.maximum_retained_revisions = 0;
        assert_eq!(
            invalid.validate("standard").err().map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        invalid = policy;
        invalid.maximum_retained_age_nanos = u64::MAX;
        assert_eq!(
            invalid.validate("standard").err().map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        invalid = policy;
        invalid.maximum_physical_retained_bytes = MAX_SQLITE_DATABASE_BYTES.saturating_add(1);
        assert_eq!(
            invalid.validate("standard").err().map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        invalid = policy;
        invalid.minimum_verified_replay_revisions = 1;
        assert_eq!(
            invalid.validate("standard").err().map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        invalid = policy;
        invalid.maximum_retained_revisions =
            invalid.minimum_reconstructable_revisions.saturating_sub(1);
        assert_eq!(
            invalid.validate("standard").err().map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        assert_ne!(
            policy.digest("standard")?,
            RepositoryPolicyV5::qualification("large_local")?.digest("large_local")?
        );
        Ok(())
    }

    #[test]
    fn active_pin_extends_protected_range_and_public_diagnostics_are_content_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RepositoryPolicyV5::new(
            1,
            u64::try_from(MAX_ACCUMULATED_DELTA_BYTES_V5)?,
            "standard",
        )?;
        policy.minimum_reconstructable_revisions = 1;
        policy.minimum_verified_replay_revisions = 1;
        policy.validate("standard")?;
        let (directory, mut connection) = target(policy)?;
        let mut state = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        for (revision, suffix) in [(0, "pin-one"), (1, "pin-two"), (2, "pin-three")] {
            let prepared = prepared_receipt_delta(StoreRevision(revision), suffix)?;
            let (_, next) = commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &state,
                |_transaction| Ok(()),
            )?;
            state = next;
        }
        let before = retention_statistics_v5(&connection)?;
        assert_eq!(before.current_revision, StoreRevision(3));
        assert_eq!(before.protected_first_revision, StoreRevision(3));
        assert_eq!(before.active_legal_hold_pins, 0);
        let unpinned_preview = preview_repository_compaction_v5(&connection)?;
        assert_eq!(unpinned_preview.compacted_first_revision, StoreRevision(2));
        assert_eq!(unpinned_preview.candidate_revisions, 2);
        connection.execute(
            "INSERT INTO repository_retention_pins_v5
                (pin_id, first_revision, last_revision, reason, authority_digest, policy_digest,
                 issued_at_unix_nanos, expires_at_unix_nanos, receipt_digest,
                 signature_identity_digest, signature, verification_state, state,
                 released_at_unix_nanos)
             VALUES (?1, 0, 0, 'legal_hold', ?2, ?3, '1', '2', ?4, ?5, ?6,
                     'verified', 'active', NULL)",
            params![
                content('b')?.as_str(),
                before.chain_head.as_str(),
                before.policy_digest.as_str(),
                content('c')?.as_str(),
                content('d')?.as_str(),
                vec![7_u8; 64],
            ],
        )?;
        let pinned = retention_statistics_v5(&connection)?;
        assert_eq!(pinned.protected_first_revision, StoreRevision(0));
        assert_eq!(pinned.active_legal_hold_pins, 1);
        assert!(!pinned.capacity_blocked);
        assert_eq!(
            preview_repository_compaction_v5(&connection)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::NotFound)
        );
        let public =
            SqliteStore::v5_retention_statistics_at(directory.path().join("target.sqlite3"))?;
        assert_eq!(public, pinned);

        connection.execute(
            "UPDATE repository_retention_pins_v5
             SET state = 'released', released_at_unix_nanos = '3' WHERE first_revision = 0",
            [],
        )?;
        let released = retention_statistics_v5(&connection)?;
        assert_eq!(released.protected_first_revision, StoreRevision(3));
        assert_eq!(released.active_legal_hold_pins, 0);
        Ok(())
    }

    #[test]
    fn physical_ceiling_refuses_a_write_without_publishing_a_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RepositoryPolicyV5::new(1, 1_048_576, "standard")?;
        policy.maximum_delta_bytes = 1_048_576;
        policy.maximum_checkpoint_bytes = 1_048_576;
        policy.maximum_physical_retained_bytes = 70_000_000;
        policy.minimum_reconstructable_revisions = 1;
        policy.minimum_verified_replay_revisions = 1;
        policy.validate("standard")?;
        let (_directory, mut connection) = target(policy)?;
        connection.execute(
            "CREATE TABLE retention_pressure (payload BLOB NOT NULL)",
            [],
        )?;
        connection.execute(
            "INSERT INTO retention_pressure VALUES (zeroblob(71000000))",
            [],
        )?;
        assert!(retention_statistics_v5(&connection)?.capacity_blocked);

        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "capacity")?;
        assert_eq!(
            commit_prepared_repository_delta_v5(
                &mut connection,
                &prepared,
                &genesis,
                |_transaction| Ok(())
            )
            .err()
            .map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        let counts: (i64, i64) = connection.query_row(
            "SELECT
                 (SELECT COUNT(*) FROM repository_revisions_v5),
                 (SELECT COUNT(*) FROM repository_deltas_v5)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(counts, (1, 0));
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(0))?.revision,
            StoreRevision(0)
        );
        Ok(())
    }

    #[test]
    fn matching_idempotency_replays_without_a_duplicate_delta()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "replay")?;
        let identity = identity("replay")?;
        let (first, committed_state) = commit_or_replay_repository_delta_v5(
            &mut connection,
            &prepared,
            &genesis,
            &identity,
            |_transaction| Ok(()),
        )?;
        assert!(matches!(
            first,
            RepositoryCommitAttemptV5::Committed(RepositoryCommitV5 {
                revision: StoreRevision(1),
                ..
            })
        ));
        let (replayed, replayed_state) = commit_or_replay_repository_delta_v5(
            &mut connection,
            &prepared,
            &committed_state,
            &identity,
            |_transaction| Err(StoreError::new(StoreErrorCode::InjectedAbort)),
        )?;
        assert_eq!(
            replayed,
            RepositoryCommitAttemptV5::Replayed(CommitReceipt {
                revision: StoreRevision(1),
                replayed: true,
            })
        );
        assert_same_state(&replayed_state, &committed_state)?;
        let counts: (i64, i64, i64, i64) = connection.query_row(
            "SELECT
                 (SELECT COUNT(*) FROM repository_revisions_v5),
                 (SELECT COUNT(*) FROM repository_deltas_v5),
                 (SELECT COUNT(*) FROM repository_checkpoints_v5),
                 (SELECT COUNT(*) FROM cigar_repository_revisions_v4)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(counts, (2, 1, 1, 1));
        Ok(())
    }

    #[test]
    fn anchor_publication_follows_commit_and_reopen_recovers_ambiguity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let prepared = prepared_receipt_delta(StoreRevision(0), "anchor")?;
        let blocker = directory.path().join("not-a-directory");
        std::fs::File::create(&blocker)?;
        let impossible_anchor = blocker.join("revision");
        let result = commit_then_publish_repository_delta_v5(
            &mut connection,
            &impossible_anchor,
            &prepared,
            &genesis,
            |_transaction| Ok(()),
        );
        assert_eq!(
            result.err().map(|error| error.code()),
            Some(StoreErrorCode::Unavailable)
        );
        assert_eq!(
            reconstruct_repository_revision_v5(&connection, StoreRevision(1))?.revision,
            StoreRevision(1)
        );

        let anchor = directory.path().join("target.cigar-revision");
        assert_eq!(read_revision_anchor(&anchor)?, None);
        assert_eq!(
            recover_revision_anchor_v5(&connection, &anchor)?,
            StoreRevision(1)
        );
        assert_eq!(read_revision_anchor(&anchor)?, Some(StoreRevision(1)));
        write_revision_anchor(&anchor, StoreRevision(2))?;
        assert_eq!(
            recover_revision_anchor_v5(&connection, &anchor)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );
        assert_eq!(read_revision_anchor(&anchor)?, Some(StoreRevision(2)));
        Ok(())
    }

    #[test]
    fn catalog_commitment_matches_only_rows_applied_in_the_atomic_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let atom = fixture_atom()?;
        let tenant_id = atom.scope.tenant_id.clone();
        let context = AccessContext::new(tenant_id.clone(), "catalog")?;
        let staged = vec![StagedMutation::Atoms(vec![atom.clone()], Vec::new())];
        let prepared =
            repository_delta_from_staged_v5(StoreRevision(0), &context, &staged, None, 1)?
                .prepare()?;
        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let genesis_catalog_root = catalog_root_from_table(&connection)?;
        let (_, state) = commit_prepared_repository_delta_v5(
            &mut connection,
            &prepared,
            &genesis,
            |transaction| {
                let buckets = apply_catalog_batch(
                    transaction,
                    &tenant_id,
                    vec![atom.clone()],
                    Vec::new(),
                    StoreRevision(1),
                    &CancellationToken::default(),
                )?;
                for bucket in buckets {
                    persist_catalog_bucket(transaction, bucket, StoreRevision(1))?;
                }
                Ok(())
            },
        )?;
        assert_eq!(state.revision, StoreRevision(1));
        let totals = catalog_totals_from_revision(&connection, StoreRevision(1))?;
        assert_eq!(totals.atom_count, 1);
        assert_ne!(catalog_root_from_table(&connection)?, genesis_catalog_root);

        let (_directory, mut connection) = target(RepositoryPolicyV5::qualification("standard")?)?;
        let genesis = reconstruct_repository_revision_v5(&connection, StoreRevision(0))?;
        let receipt_only = prepared_receipt_delta(StoreRevision(0), "catalog-mismatch")?;
        let result = commit_prepared_repository_delta_v5(
            &mut connection,
            &receipt_only,
            &genesis,
            |transaction| {
                let buckets = apply_catalog_batch(
                    transaction,
                    &tenant_id,
                    vec![atom],
                    Vec::new(),
                    StoreRevision(1),
                    &CancellationToken::default(),
                )?;
                for bucket in buckets {
                    persist_catalog_bucket(transaction, bucket, StoreRevision(1))?;
                }
                Ok(())
            },
        );
        assert_eq!(
            result.err().map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );
        let counts: (i64, i64) = connection.query_row(
            "SELECT
                 (SELECT COUNT(*) FROM repository_revisions_v5),
                 (SELECT COUNT(*) FROM cigar_catalog_atoms)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(counts, (1, 0));
        Ok(())
    }
}
