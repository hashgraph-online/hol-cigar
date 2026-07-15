//! Backend-neutral append-only migration declarations and validation.

use crate::{StoreError, StoreErrorCode};
use cigar_protocol::ContentDigest;
use std::collections::BTreeSet;

/// Hard bound on one installed migration ledger.
pub const MAX_MIGRATION_ENTRIES: usize = 4_096;

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

/// One immutable row read from an installed migration ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationLedgerEntry {
    /// Contiguous one-based sequence.
    pub sequence: u32,
    /// Stable migration name.
    pub name: String,
    /// Digest of the exact migration implementation that was applied.
    pub checksum: ContentDigest,
    /// Oldest application major allowed to read and write this schema.
    pub minimum_application_major: u16,
    /// Newest application major allowed to read and write this schema.
    pub maximum_application_major: u16,
    /// Whether an older compatible application may remain online after this row is installed.
    pub online: bool,
}

/// Safe result of comparing an installed ledger with one application's embedded plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationCompatibility {
    /// The installed ledger exactly matches the embedded plan.
    Exact,
    /// The database is an intact retained prefix and needs the remaining embedded migrations.
    UpgradeRequired {
        /// Last installed sequence, or zero for a new database.
        installed_sequence: u32,
        /// Last sequence embedded in this application.
        target_sequence: u32,
    },
}

/// Content-free reason an installed migration ledger cannot be opened safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationCompatibilityError {
    /// The ledger is too large to validate within the fixed resource bound.
    LimitExceeded,
    /// A sequence is missing, duplicated, reordered, or otherwise malformed.
    InvalidLedger,
    /// A known append-only migration's immutable name, checksum, or metadata changed.
    ModifiedHistory,
    /// The application major is outside an installed row's declared compatibility interval.
    UnsupportedApplicationMajor,
    /// The ledger contains a row absent from this binary's immutable embedded authority.
    UnknownFutureMigration,
}

impl MigrationPlan {
    /// Validates a complete ordered migration plan.
    pub fn new(migrations: Vec<MigrationDefinition>) -> Result<Self, StoreError> {
        if migrations.len() > MAX_MIGRATION_ENTRIES {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
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

    /// Compares an installed ledger with this immutable embedded plan.
    ///
    /// Known rows must match byte-for-byte metadata. A retained prefix is upgradeable. A future
    /// suffix is always rejected because database-owned metadata cannot authenticate unknown DDL.
    /// Mixed-version operation therefore requires every participating binary to embed the same
    /// migration authority. This is the downgrade guard: an older binary never guesses that an
    /// unknown future schema is safe.
    pub fn check_installed(
        &self,
        installed: &[MigrationLedgerEntry],
        application_major: u16,
    ) -> Result<MigrationCompatibility, MigrationCompatibilityError> {
        if application_major == 0 || installed.len() > MAX_MIGRATION_ENTRIES {
            return Err(MigrationCompatibilityError::LimitExceeded);
        }
        let mut names = BTreeSet::new();
        for (index, entry) in installed.iter().enumerate() {
            let expected_sequence = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(MigrationCompatibilityError::LimitExceeded)?;
            if entry.sequence != expected_sequence
                || entry.name.is_empty()
                || entry.name.len() > 256
                || entry.name.bytes().any(|byte| byte.is_ascii_control())
                || !names.insert(entry.name.as_str())
                || entry.minimum_application_major == 0
                || entry.minimum_application_major > entry.maximum_application_major
            {
                return Err(MigrationCompatibilityError::InvalidLedger);
            }
            if application_major < entry.minimum_application_major
                || application_major > entry.maximum_application_major
            {
                return Err(MigrationCompatibilityError::UnsupportedApplicationMajor);
            }
            if let Some(expected) = self.migrations.get(index) {
                if entry.name != expected.name
                    || entry.checksum != expected.checksum
                    || entry.minimum_application_major != expected.minimum_application_major
                    || entry.maximum_application_major != expected.maximum_application_major
                    || entry.online != matches!(expected.mode, MigrationMode::Online)
                {
                    return Err(MigrationCompatibilityError::ModifiedHistory);
                }
            } else {
                return Err(MigrationCompatibilityError::UnknownFutureMigration);
            }
        }

        let installed_sequence = u32::try_from(installed.len())
            .map_err(|_error| MigrationCompatibilityError::LimitExceeded)?;
        let target_sequence = self.latest_sequence();
        Ok(if installed.len() < self.migrations.len() {
            MigrationCompatibility::UpgradeRequired {
                installed_sequence,
                target_sequence,
            }
        } else {
            MigrationCompatibility::Exact
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MigrationCompatibility, MigrationCompatibilityError, MigrationDefinition,
        MigrationLedgerEntry, MigrationMode, MigrationPlan,
    };
    use cigar_protocol::ContentDigest;

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn definition(
        sequence: u32,
        name: &str,
        checksum: ContentDigest,
        mode: MigrationMode,
    ) -> MigrationDefinition {
        MigrationDefinition {
            sequence,
            name: name.to_owned(),
            checksum,
            minimum_application_major: 1,
            maximum_application_major: 2,
            mode,
            lock_behavior: "bounded schema transaction".to_owned(),
            verification: "semantic root and schema shape".to_owned(),
            rollback_or_restore: "restore the verified pre-migration backup".to_owned(),
        }
    }

    fn entry(definition: &MigrationDefinition) -> MigrationLedgerEntry {
        MigrationLedgerEntry {
            sequence: definition.sequence,
            name: definition.name.clone(),
            checksum: definition.checksum.clone(),
            minimum_application_major: definition.minimum_application_major,
            maximum_application_major: definition.maximum_application_major,
            online: matches!(definition.mode, MigrationMode::Online),
        }
    }

    #[test]
    fn retained_prefix_and_exact_known_ledger_are_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = definition(1, "initial", digest('a')?, MigrationMode::Offline);
        let second = definition(2, "expansion", digest('b')?, MigrationMode::Online);
        let plan = MigrationPlan::new(vec![first.clone(), second.clone()])?;
        assert_eq!(
            plan.check_installed(&[entry(&first)], 1),
            Ok(MigrationCompatibility::UpgradeRequired {
                installed_sequence: 1,
                target_sequence: 2,
            })
        );
        assert_eq!(
            plan.check_installed(&[entry(&first), entry(&second)], 1),
            Ok(MigrationCompatibility::Exact)
        );
        let future = MigrationLedgerEntry {
            sequence: 3,
            name: "future_expansion".to_owned(),
            checksum: digest('c')?,
            minimum_application_major: 1,
            maximum_application_major: 2,
            online: true,
        };
        assert_eq!(
            plan.check_installed(&[entry(&first), entry(&second), future], 1),
            Err(MigrationCompatibilityError::UnknownFutureMigration)
        );
        Ok(())
    }

    #[test]
    fn modified_history_and_unsupported_downgrade_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = definition(1, "initial", digest('a')?, MigrationMode::Offline);
        let plan = MigrationPlan::new(vec![first.clone()])?;
        let mut modified = entry(&first);
        modified.checksum = digest('b')?;
        assert_eq!(
            plan.check_installed(&[modified], 1),
            Err(MigrationCompatibilityError::ModifiedHistory)
        );
        let incompatible = MigrationLedgerEntry {
            sequence: 2,
            name: "requires_v2".to_owned(),
            checksum: digest('c')?,
            minimum_application_major: 2,
            maximum_application_major: 2,
            online: true,
        };
        assert_eq!(
            plan.check_installed(&[entry(&first), incompatible], 1),
            Err(MigrationCompatibilityError::UnsupportedApplicationMajor)
        );
        let offline = MigrationLedgerEntry {
            sequence: 2,
            name: "offline_future".to_owned(),
            checksum: digest('d')?,
            minimum_application_major: 1,
            maximum_application_major: 2,
            online: false,
        };
        assert_eq!(
            plan.check_installed(&[entry(&first), offline], 1),
            Err(MigrationCompatibilityError::UnknownFutureMigration)
        );
        Ok(())
    }
}
