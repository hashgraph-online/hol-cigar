//! Content-free repository commit measurements shared by durable backends and runtime telemetry.

use crate::StoreRevision;
use std::time::Duration;

/// Closed durable mutation path that produced one repository observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryCommitKind {
    /// A mutation through the public repository transaction contract.
    Repository,
    /// An atomic service-record batch.
    Service,
    /// A durable worker lease or checkpoint transition.
    Worker,
}

impl RepositoryCommitKind {
    /// Stable content-free metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Service => "service",
            Self::Worker => "worker",
        }
    }
}

/// Closed durable result represented by one commit measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryCommitOutcome {
    /// A new revision committed and its required external anchor was published.
    Committed,
    /// Request-bound idempotency returned an earlier result without a new revision.
    Replayed,
}

impl RepositoryCommitOutcome {
    /// Stable content-free metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Replayed => "replayed",
        }
    }
}

/// Monotonic elapsed time at each closed repository commit phase.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryCommitDurations {
    /// End-to-end time inside the backend commit call.
    pub total: Duration,
    /// Time waiting for the backend's single-writer serializer.
    pub lock_wait: Duration,
    /// Time loading repository bytes and metadata, excluding residual decode.
    pub repository_load: Duration,
    /// Time decoding and validating the catalog-free residual or checkpoint/delta state.
    pub residual_decode: Duration,
    /// Time validating and applying staged semantic mutations.
    pub staged_mutation: Duration,
    /// Time canonically encoding an incremental delta; zero for the v4 compatibility path.
    pub delta_encode: Duration,
    /// Time canonically encoding a complete residual/checkpoint.
    pub full_encode: Duration,
    /// Time calculating and authenticating catalog and semantic roots.
    pub catalog_root: Duration,
    /// Complete time from successful `BEGIN IMMEDIATE` through SQLite commit.
    pub sqlite_transaction: Duration,
    /// Time in the SQLite commit call, including configured durability work.
    pub commit_fsync: Duration,
    /// Time publishing and fsyncing the external revision anchor.
    pub revision_anchor: Duration,
}

/// Content-free logical and physical byte measurements for one commit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryCommitBytes {
    /// Bounded logical payload bytes of the semantic mutation input, excluding telemetry and
    /// external blob plaintext. Repository records use canonical record lengths; service/worker
    /// records use their exact bounded field-byte lengths.
    pub logical_changed: u64,
    /// Canonical incremental delta bytes; zero on v4.
    pub encoded_delta: u64,
    /// Canonical checkpoint bytes written by this commit; zero when no checkpoint was written.
    pub checkpoint: u64,
    /// Compatibility full-residual bytes written by this commit; zero on an incremental-only path.
    pub full_state: u64,
    /// Main database bytes observed before the transaction, when available.
    pub database_before: Option<u64>,
    /// Main database bytes observed after the transaction, when available.
    pub database_after: Option<u64>,
    /// SQLite WAL bytes observed before the transaction, when available.
    pub wal_before: Option<u64>,
    /// SQLite WAL bytes observed after the transaction, when available.
    pub wal_after: Option<u64>,
}

impl RepositoryCommitBytes {
    /// Positive change in combined main-database and WAL bytes, or `None` when either complete
    /// observation was unavailable. A physical decrease produces zero added bytes.
    #[must_use]
    pub fn durable_bytes_added(self) -> Option<u64> {
        let before = self.database_before?.checked_add(self.wal_before?)?;
        let after = self.database_after?.checked_add(self.wal_after?)?;
        Some(after.saturating_sub(before))
    }

    /// Per-commit write amplification in millionths, defined as positive durable bytes added
    /// divided by nonzero logical bytes changed. Receipt-only and unavailable measurements return
    /// `None` instead of inventing a denominator.
    #[must_use]
    pub fn write_amplification_millionths(self) -> Option<u64> {
        let logical = self.logical_changed;
        if logical == 0 {
            return None;
        }
        self.durable_bytes_added()
            .map(|durable| durable.saturating_mul(1_000_000) / logical)
    }
}

/// Retained durable revision-record counts after one commit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryRetentionCounts {
    /// V4 compatibility full residual snapshots.
    pub full_states: Option<u64>,
    /// V5 checkpoints.
    pub checkpoints: Option<u64>,
    /// V5 deltas.
    pub deltas: Option<u64>,
}

/// Complete content-free result emitted for a committed or idempotently replayed mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryCommitMetrics {
    /// Closed mutation path.
    pub kind: RepositoryCommitKind,
    /// Closed durable result.
    pub outcome: RepositoryCommitOutcome,
    /// Revision before the operation or original replayed result.
    pub revision_before: StoreRevision,
    /// Revision after the operation or original replayed result.
    pub revision_after: StoreRevision,
    /// True only when a committed revision carried no semantic mutation bytes and retained only an
    /// execution/idempotency receipt.
    pub receipt_only: bool,
    /// Closed monotonic phase durations.
    pub durations: RepositoryCommitDurations,
    /// Logical and physical byte measurements.
    pub bytes: RepositoryCommitBytes,
    /// Retained record counts after the operation.
    pub retained: RepositoryRetentionCounts,
}

impl RepositoryCommitMetrics {
    /// Monotonic revision advance. Corrupt or out-of-order inputs saturate at zero and remain
    /// detectable through the explicit before/after fields.
    #[must_use]
    pub const fn revision_delta(self) -> u64 {
        self.revision_after.0.saturating_sub(self.revision_before.0)
    }
}

/// Non-blocking content-free observer attached to a durable repository.
///
/// Implementations must not inspect repository content, perform repository I/O, or panic. The
/// backend invokes the observer only after a new commit and required anchor publication complete,
/// or immediately before returning an idempotent replay.
pub trait RepositoryCommitMetricsObserver: Send + Sync {
    /// Records one immutable content-free commit result.
    fn observe_repository_commit(&self, metrics: RepositoryCommitMetrics);
}

/// Closed startup stage shared by the SQLite repository and daemon readiness coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryStartupStage {
    /// Capacity, ownership, permissions, and path identity verification.
    PathConfiguration,
    /// SQLite connection open, defensive configuration, and feature verification.
    SqliteOpenConfigure,
    /// Migration-ledger authentication, supported migration application, and v4 activation.
    MigrationLedger,
    /// Latest authenticated residual/checkpoint metadata and bytes read.
    LatestCheckpointRead,
    /// Residual/checkpoint checksum and post-open path-identity verification.
    ChecksumVerification,
    /// Bounded incremental delta replay; a measured no-op for the v4 compatibility path.
    DeltaReplay,
    /// Catalog-free residual or checkpoint decode and revision validation.
    ResidualDecode,
    /// Mandatory catalog projection verification or recovery.
    CatalogProjection,
    /// External revision-anchor verification or monotonic advance.
    RevisionAnchor,
    /// Encrypted blob metadata/object reconciliation.
    BlobReconciliation,
    /// Required recovery actions through the atomic readiness transition.
    ReadinessOpen,
}

impl RepositoryStartupStage {
    /// Stable content-free metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathConfiguration => "path_configuration",
            Self::SqliteOpenConfigure => "sqlite_open_configure",
            Self::MigrationLedger => "migration_ledger",
            Self::LatestCheckpointRead => "latest_checkpoint_read",
            Self::ChecksumVerification => "checksum_verification",
            Self::DeltaReplay => "delta_replay",
            Self::ResidualDecode => "residual_decode",
            Self::CatalogProjection => "catalog_projection",
            Self::RevisionAnchor => "revision_anchor",
            Self::BlobReconciliation => "blob_reconciliation",
            Self::ReadinessOpen => "readiness_open",
        }
    }
}

/// Closed outcome for one measured startup stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryStartupOutcome {
    /// The stage completed and its authenticated result is usable by the next stage.
    Completed,
    /// The stage failed closed; its error remains the repository's stable content-free error.
    Failed,
}

impl RepositoryStartupOutcome {
    /// Stable content-free metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// One immutable content-free startup-stage measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryStartupMetrics {
    /// Closed startup stage.
    pub stage: RepositoryStartupStage,
    /// Closed success/failure outcome.
    pub outcome: RepositoryStartupOutcome,
    /// Monotonic elapsed time inside the stage.
    pub duration: Duration,
}

/// Non-blocking content-free observer for repository and readiness startup stages.
///
/// Implementations must not inspect repository content, perform repository I/O, or panic.
pub trait RepositoryStartupMetricsObserver: Send + Sync {
    /// Records one immutable stage result after the stage succeeds or fails closed.
    fn observe_repository_startup(&self, metrics: RepositoryStartupMetrics);
}

#[cfg(test)]
mod tests {
    use super::RepositoryCommitBytes;

    #[test]
    fn write_amplification_is_checked_and_zero_logical_is_explicit() {
        let bytes = RepositoryCommitBytes {
            logical_changed: 10,
            database_before: Some(100),
            database_after: Some(130),
            wal_before: Some(20),
            wal_after: Some(40),
            ..RepositoryCommitBytes::default()
        };
        assert_eq!(bytes.durable_bytes_added(), Some(50));
        assert_eq!(bytes.write_amplification_millionths(), Some(5_000_000));
        assert_eq!(
            RepositoryCommitBytes {
                logical_changed: 0,
                ..bytes
            }
            .write_amplification_millionths(),
            None
        );
        assert_eq!(
            RepositoryCommitBytes {
                wal_after: None,
                ..bytes
            }
            .durable_bytes_added(),
            None
        );
    }
}
