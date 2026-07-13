//! Backend-neutral append-only migration declarations and validation.

use crate::{StoreError, StoreErrorCode};
use cigar_protocol::ContentDigest;
use std::collections::BTreeSet;

/// Whether a migration may run while serving traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationMode {
    /// Migration is designed for bounded online execution.
    Online,
    /// Migration requires the service to be offline.
    Offline,
}

/// Immutable migration metadata required by every concrete backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationDefinition {
    /// Strictly increasing append-only sequence beginning at one.
    pub sequence: u32,
    /// Stable migration name.
    pub name: String,
    /// Digest of the exact migration implementation.
    pub checksum: ContentDigest,
    /// Earliest compatible application protocol major.
    pub minimum_application_major: u16,
    /// Latest compatible application protocol major.
    pub maximum_application_major: u16,
    /// Online or offline execution classification.
    pub mode: MigrationMode,
    /// Documented expected lock behavior.
    pub lock_behavior: String,
    /// Verification query or backend-neutral invariant name.
    pub verification: String,
    /// Rollback procedure or mandatory restore plan.
    pub rollback_or_restore: String,
}

/// Validated append-only migration sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationPlan {
    migrations: Vec<MigrationDefinition>,
}

impl MigrationPlan {
    /// Validates a complete ordered migration plan.
    pub fn new(migrations: Vec<MigrationDefinition>) -> Result<Self, StoreError> {
        let mut names = BTreeSet::new();
        for (index, migration) in migrations.iter().enumerate() {
            let expected = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            let valid_text = !migration.name.is_empty()
                && !migration.lock_behavior.is_empty()
                && !migration.verification.is_empty()
                && !migration.rollback_or_restore.is_empty();
            if migration.sequence != expected
                || !names.insert(migration.name.as_str())
                || migration.minimum_application_major == 0
                || migration.minimum_application_major > migration.maximum_application_major
                || !valid_text
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
        }
        Ok(Self { migrations })
    }

    /// Returns the immutable ordered definitions.
    #[must_use]
    pub fn migrations(&self) -> &[MigrationDefinition] {
        &self.migrations
    }

    /// Returns the latest migration sequence, or zero for a fresh empty backend.
    #[must_use]
    pub fn latest_sequence(&self) -> u32 {
        self.migrations
            .last()
            .map_or(0, |migration| migration.sequence)
    }
}
