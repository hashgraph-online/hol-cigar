//! Explicit fresh-target preparation for offline SQLite v4-to-v5 migration.
//!
//! This module is intentionally separate from `SqliteStore::open`. It can only add the v5 schema
//! to a newly initialized, still-empty v4-compatible target. Copying authenticated revisions into
//! that target and activating it remain later explicit migration steps.

use crate::revision_delta::SQLITE_FRESH_TARGET_SCHEMA_V5;
use crate::sqlite::{
    acquire_sqlite_runtime_exclusive_lock, acquire_sqlite_runtime_shared_lock,
    authenticate_v4_migration_database, read_revision_anchor, write_revision_anchor,
};
use crate::sqlite_v5::{construct_migrated_repository_v5, verify_migrated_repository_v5};
use crate::{
    BACKUP_DATABASE_FILE, BackupErrorCode, BackupSignatureIdentity,
    MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES, MAX_SQLITE_DATABASE_BYTES,
    MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES, SqliteCapacityProfile, SqliteStore, StoreError,
    StoreErrorCode, StoreRevision, verify_backup_trusted,
};
use cigar_crypto::{
    KeyAlgorithm, KeyProvider, KeyRef, SignatureEnvelope, SignatureRequest, SignatureVerification,
};
use cigar_protocol::ContentDigest;
use rusqlite::backup::Backup;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_MIGRATION_BACKUP_ENTRIES_V5: usize = 1_000_000;
const MIGRATION_COPY_BUFFER_BYTES_V5: usize = 1_048_576;
const STANDARD_MIGRATION_RUNTIME_RESERVE_BYTES_V5: u64 = 1_073_741_824;
const MIGRATION_RECEIPT_HEADROOM_BYTES_V5: u64 = 67_108_864;
const STANDARD_MIGRATION_WAL_HEADROOM_BYTES_V5: u64 = 268_435_456;
const LARGE_LOCAL_MIGRATION_WAL_HEADROOM_BYTES_V5: u64 = 8_589_934_592;
const MIGRATION_RECEIPT_SCHEMA_V1: &str = "cigar.sqlite-v4-v5-migration-receipt.v1";
const MIGRATION_RECEIPT_SIGNATURE_PURPOSE_V1: &str = "sqlite-v4-v5-migration-receipt-v1";
const MAX_MIGRATION_MANIFEST_BYTES_V5: u64 = 16_777_216;
const ACTIVE_STORE_DESCRIPTOR_SCHEMA_V1: &str = "cigar.active-store-descriptor.v1";
const MAX_MIGRATION_RECEIPT_BYTES_V5: u64 = 1_048_576;
const MAX_ACTIVE_STORE_DESCRIPTOR_BYTES_V1: u64 = 65_536;
const REVISION_COMPACTION_PREVIEW_SCHEMA_V1: &str = "cigar.revision-compaction-preview.v1";
const REVISION_COMPACTION_RECEIPT_SCHEMA_V1: &str = "cigar.revision-compaction-receipt.v1";
const REVISION_COMPACTION_PREVIEW_PURPOSE_V1: &str = "revision-compaction-preview-v1";
const REVISION_COMPACTION_RECEIPT_PURPOSE_V1: &str = "revision-compaction-receipt-v1";
const MAX_REVISION_COMPACTION_DOCUMENT_BYTES_V1: u64 = 1_048_576;
const VERIFIED_PREFIX_SCHEMA_V1: &str = "cigar.sqlite-v5-verified-prefix.v1";
const VERIFIED_PREFIX_PURPOSE_V1: &str = "sqlite-v5-verified-prefix-v1";
const V5_DEEP_VERIFIER_VERSION: &str =
    concat!("cigar-store/", env!("CARGO_PKG_VERSION"), "/deep-v1");
const MAX_VERIFIED_PREFIX_BYTES_V1: u64 = 1_048_576;
#[cfg(feature = "migration-fault-injection")]
const MIGRATION_V5_PROCESS_ABORT_STAGE: &str = "CIGAR_MIGRATION_V5_PROCESS_ABORT_STAGE";

/// Named process-death boundaries in distinct-target migration and compaction workflows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationV5Failpoint {
    /// After the signed backup is reverified and before source construction begins.
    AfterBackupVerification,
    /// After the new target file is durably created.
    AfterTargetCreation,
    /// After one authenticated source revision is inserted into the target transaction.
    AfterRevisionBatch(StoreRevision),
    /// After the constructed target database and its parent directory are synchronized.
    AfterTargetFsync,
    /// After the external target revision anchor is published.
    AfterAnchorPublication,
    /// After the final integrity, reconstruction, catalog, blob, and chain verification.
    AfterDeepVerification,
    /// After the signed receipt is durably published beside the target.
    AfterReceiptPublication,
    /// After activation evidence is complete and immediately before descriptor publication.
    AfterActivationIntent,
    /// After the descriptor rename and before the parent directory synchronization barrier.
    AfterActivationSwitch,
    /// After an expiring signed compaction preview is verified.
    AfterCompactionPreviewVerification,
    /// After the source database is durably copied into the compaction target.
    AfterCompactionTargetCopy,
    /// After logical history reclamation commits in the compaction target.
    AfterCompactionLogicalReclamation,
    /// After physical reclamation and complete target verification.
    AfterCompactionPhysicalReclamation,
    /// After the signed compaction receipt is durably published.
    AfterCompactionReceiptPublication,
}

impl MigrationV5Failpoint {
    /// Stable process-test stage name accepted by the fault-injection environment gate.
    #[must_use]
    pub fn stage_name(self) -> String {
        match self {
            Self::AfterBackupVerification => "after-backup-verification".to_owned(),
            Self::AfterTargetCreation => "after-target-creation".to_owned(),
            Self::AfterRevisionBatch(revision) => {
                format!("after-revision-batch-{}", revision.0)
            }
            Self::AfterTargetFsync => "after-target-fsync".to_owned(),
            Self::AfterAnchorPublication => "after-anchor-publication".to_owned(),
            Self::AfterDeepVerification => "after-deep-verification".to_owned(),
            Self::AfterReceiptPublication => "after-receipt-publication".to_owned(),
            Self::AfterActivationIntent => "after-activation-intent".to_owned(),
            Self::AfterActivationSwitch => "after-activation-switch".to_owned(),
            Self::AfterCompactionPreviewVerification => {
                "after-compaction-preview-verification".to_owned()
            }
            Self::AfterCompactionTargetCopy => "after-compaction-target-copy".to_owned(),
            Self::AfterCompactionLogicalReclamation => {
                "after-compaction-logical-reclamation".to_owned()
            }
            Self::AfterCompactionPhysicalReclamation => {
                "after-compaction-physical-reclamation".to_owned()
            }
            Self::AfterCompactionReceiptPublication => {
                "after-compaction-receipt-publication".to_owned()
            }
        }
    }
}

#[cfg(feature = "migration-fault-injection")]
pub(crate) fn migration_v5_process_abort_if_armed(failpoint: MigrationV5Failpoint) {
    if std::env::var(MIGRATION_V5_PROCESS_ABORT_STAGE).as_deref()
        == Ok(failpoint.stage_name().as_str())
    {
        std::process::abort();
    }
}

#[cfg(not(feature = "migration-fault-injection"))]
pub(crate) fn migration_v5_process_abort_if_armed(_failpoint: MigrationV5Failpoint) {}

/// Trips a qualification-only migration process failpoint from another workflow crate.
#[cfg(feature = "migration-fault-injection")]
pub fn migration_v5_process_abort_boundary(failpoint: MigrationV5Failpoint) {
    migration_v5_process_abort_if_armed(failpoint);
}

/// Authenticated, frozen content-free preflight result for a distinct-target v4-to-v5 migration.
pub struct MigrationPreflightV5 {
    paths: MigrationPathsV5,
    _exclusive_runtime_lock: File,
    source_identity: MigrationFileIdentityV5,
    source_revision: StoreRevision,
    first_retained_revision: StoreRevision,
    retained_revisions: u64,
    source_database_bytes: u64,
    source_database_digest: ContentDigest,
    capacity_profile: String,
    backup_canonical_root: String,
    backup_manifest_digest: ContentDigest,
    required_available_bytes: u64,
    observed_available_bytes: u64,
}

/// Content-free result of constructing and verifying one distinct v5 migration target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationBuildReportV5 {
    /// First retained source revision preserved in v5.
    pub first_revision: StoreRevision,
    /// Exact authenticated source head preserved in v5.
    pub latest_revision: StoreRevision,
    /// Consecutive migrated revision envelopes.
    pub retained_revisions: u64,
    /// Canonical migration-checkpoint bytes stored in v5.
    pub checkpoint_bytes: u64,
    /// Final authenticated v5 revision-chain head.
    pub chain_head: ContentDigest,
    /// Preserved latest normalized catalog root.
    pub catalog_root: ContentDigest,
    /// Preserved latest public semantic root.
    pub semantic_root: ContentDigest,
    /// Final target main-database bytes after offline compaction.
    pub target_database_bytes: u64,
    /// SHA-256 multihash of the final target main database.
    pub target_database_digest: ContentDigest,
    receipt: MigrationReceiptV1,
}

impl MigrationBuildReportV5 {
    /// Returns the canonical receipt payload after the caller verifies the external effect chain.
    #[must_use]
    pub fn completed_receipt(&self) -> MigrationReceiptV1 {
        let mut receipt = self.receipt.clone();
        receipt.effect_chain_verified = true;
        receipt
    }
}

/// Canonical content-free proof of one completed distinct-target migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceiptV1 {
    schema_version: String,
    schema_digest: ContentDigest,
    created_at_unix_nanos: String,
    tool_name: String,
    tool_version: String,
    product_version: String,
    source_device: u64,
    source_inode: u64,
    source_database_bytes: u64,
    source_database_digest: ContentDigest,
    first_retained_revision: u64,
    latest_revision: u64,
    retained_revisions: u64,
    backup_canonical_root: String,
    backup_manifest_digest: ContentDigest,
    target_format_version: u64,
    target_device: u64,
    target_inode: u64,
    target_database_bytes: u64,
    target_database_digest: ContentDigest,
    source_catalog_root: ContentDigest,
    source_semantic_root: ContentDigest,
    target_catalog_root: ContentDigest,
    target_semantic_root: ContentDigest,
    target_chain_head: ContentDigest,
    sqlite_integrity_verified: bool,
    v5_chain_verified: bool,
    exact_reconstruction_verified: bool,
    catalog_projection_verified: bool,
    external_blobs_verified: bool,
    effect_chain_verified: bool,
    failpoint_free_completion: bool,
}

impl MigrationReceiptV1 {
    /// Exact final target digest authenticated by the receipt.
    #[must_use]
    pub const fn target_database_digest(&self) -> &ContentDigest {
        &self.target_database_digest
    }

    /// Exact source head carried into v5.
    #[must_use]
    pub const fn latest_revision(&self) -> StoreRevision {
        StoreRevision(self.latest_revision)
    }

    fn validate(&self) -> Result<(), StoreError> {
        let created_at = self
            .created_at_unix_nanos
            .parse::<u128>()
            .map_err(|_error| invalid_record())?;
        let canonical_time = created_at.to_string();
        let valid_root = self.backup_canonical_root.len() == 68
            && self.backup_canonical_root.starts_with("1220")
            && self
                .backup_canonical_root
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if self.schema_version != MIGRATION_RECEIPT_SCHEMA_V1
            || self.schema_digest != crate::revision_delta::migration_receipt_schema_digest_v1()?
            || self.created_at_unix_nanos != canonical_time
            || self.tool_name != "cigar"
            || self.tool_version.is_empty()
            || self.tool_version.len() > 64
            || self.product_version.is_empty()
            || self.product_version.len() > 64
            || self.source_inode == 0
            || self.source_database_bytes == 0
            || self.target_inode == 0
            || self.target_database_bytes == 0
            || self.retained_revisions == 0
            || self
                .latest_revision
                .checked_sub(self.first_retained_revision)
                .and_then(|distance| distance.checked_add(1))
                != Some(self.retained_revisions)
            || !valid_root
            || self.target_format_version != 5
            || self.source_catalog_root != self.target_catalog_root
            || self.source_semantic_root != self.target_semantic_root
            || !self.sqlite_integrity_verified
            || !self.v5_chain_verified
            || !self.exact_reconstruction_verified
            || !self.catalog_projection_verified
            || !self.external_blobs_verified
            || !self.effect_chain_verified
            || !self.failpoint_free_completion
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

/// Active operator identity used for one migration receipt.
#[derive(Clone, Copy, Debug)]
pub struct MigrationReceiptIdentity<'a> {
    /// Active tenant signing key.
    pub signing_key: &'a KeyRef,
    /// Tenant owning the authenticated operator.
    pub tenant: &'a str,
    /// Authenticated operator principal.
    pub signer: &'a str,
}

/// Authenticated signer metadata recovered from a verified receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReceiptSignatureIdentity {
    /// Tenant whose key signed the receipt.
    pub tenant: String,
    /// Operator principal embedded in the signature.
    pub signer: String,
    /// Exact signing-key reference.
    pub signing_key: KeyRef,
    /// Semantic signature time.
    pub signed_at_unix_nanos: i128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedMigrationReceiptSignature {
    algorithm: String,
    key_ref: String,
    tenant: String,
    signer: String,
    purpose: String,
    signed_at_unix_nanos: String,
    payload_digest_hex: String,
    signature_hex: String,
}

/// Portable signed JSON migration receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMigrationReceiptV1 {
    receipt: MigrationReceiptV1,
    signature: PersistedMigrationReceiptSignature,
}

impl SignedMigrationReceiptV1 {
    /// Unverified receipt payload for display only.
    #[must_use]
    pub const fn unverified_receipt(&self) -> &MigrationReceiptV1 {
        &self.receipt
    }
}

/// Canonical, owner-controlled inputs for publishing one active v5 store descriptor.
pub struct MigrationActivationPathsV5 {
    source: PathBuf,
    backup: PathBuf,
    target: PathBuf,
    receipt: PathBuf,
    descriptor: PathBuf,
}

/// Canonical inputs for explicitly removing only a non-active, non-receipted migration target.
pub struct MigrationCleanupPathsV5 {
    source: PathBuf,
    backup: PathBuf,
    target: PathBuf,
    descriptor: PathBuf,
}

impl MigrationCleanupPathsV5 {
    /// Resolves retained evidence, one existing target, and the active descriptor location.
    pub fn resolve(
        source: impl AsRef<Path>,
        backup: impl AsRef<Path>,
        target: impl AsRef<Path>,
        descriptor: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let source = canonical_existing(source.as_ref(), ExistingPathKindV5::File)?;
        let backup = canonical_existing(backup.as_ref(), ExistingPathKindV5::Directory)?;
        let target = canonical_existing(target.as_ref(), ExistingPathKindV5::File)?;
        let descriptor = canonical_existing_or_new_file(descriptor.as_ref())?;
        if overlaps(&source, &backup)
            || overlaps(&source, &target)
            || overlaps(&source, &descriptor)
            || overlaps(&backup, &target)
            || overlaps(&backup, &descriptor)
            || overlaps(&target, &descriptor)
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        validate_backup_tree(&backup)?;
        Ok(Self {
            source,
            backup,
            target,
            descriptor,
        })
    }

    /// Canonical retained source.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Canonical verified backup.
    #[must_use]
    pub fn backup(&self) -> &Path {
        &self.backup
    }

    /// Canonical incomplete target selected for cleanup.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Canonical descriptor location checked before cleanup.
    #[must_use]
    pub fn descriptor(&self) -> &Path {
        &self.descriptor
    }
}

impl MigrationActivationPathsV5 {
    /// Resolves existing source/backup/target/receipt identities and a safe descriptor location.
    pub fn resolve(
        source: impl AsRef<Path>,
        backup: impl AsRef<Path>,
        target: impl AsRef<Path>,
        receipt: impl AsRef<Path>,
        descriptor: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let source = canonical_existing(source.as_ref(), ExistingPathKindV5::File)?;
        let backup = canonical_existing(backup.as_ref(), ExistingPathKindV5::Directory)?;
        let target = canonical_existing(target.as_ref(), ExistingPathKindV5::File)?;
        let receipt = canonical_existing(receipt.as_ref(), ExistingPathKindV5::File)?;
        let descriptor = canonical_existing_or_new_file(descriptor.as_ref())?;
        let expected_receipt = migration_receipt_path_v5(&target)?;
        if receipt != expected_receipt
            || overlaps(&source, &backup)
            || overlaps(&source, &target)
            || overlaps(&source, &receipt)
            || overlaps(&source, &descriptor)
            || overlaps(&backup, &target)
            || overlaps(&backup, &receipt)
            || overlaps(&backup, &descriptor)
            || overlaps(&target, &receipt)
            || overlaps(&target, &descriptor)
            || overlaps(&receipt, &descriptor)
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        validate_backup_tree(&backup)?;
        Ok(Self {
            source,
            backup,
            target,
            receipt,
            descriptor,
        })
    }

    /// Canonical retained v4 source database.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Canonical verified-backup directory.
    #[must_use]
    pub fn backup(&self) -> &Path {
        &self.backup
    }

    /// Canonical verified v5 target database.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Canonical signed migration receipt.
    #[must_use]
    pub fn receipt(&self) -> &Path {
        &self.receipt
    }

    /// Canonical active-store descriptor location.
    #[must_use]
    pub fn descriptor(&self) -> &Path {
        &self.descriptor
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveStoreDescriptorPayloadV1 {
    schema_version: String,
    generation: u64,
    activated_at_unix_nanos: String,
    format_version: u64,
    database_path: String,
    database_device: u64,
    database_inode: u64,
    database_bytes: u64,
    database_digest: ContentDigest,
    anchor_path: String,
    anchor_digest: ContentDigest,
    authority_receipt_kind: String,
    authority_receipt_path: String,
    authority_receipt_digest: ContentDigest,
    latest_revision: u64,
    chain_head: ContentDigest,
}

/// Checksum-protected active-store descriptor published with atomic replacement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveStoreDescriptorV1 {
    payload: ActiveStoreDescriptorPayloadV1,
    checksum: ContentDigest,
}

impl ActiveStoreDescriptorV1 {
    /// Monotonic descriptor publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.payload.generation
    }

    /// Canonical database selected by this descriptor.
    #[must_use]
    pub fn database_path(&self) -> &str {
        &self.payload.database_path
    }

    /// Exact descriptor checksum over the canonical payload.
    #[must_use]
    pub const fn checksum(&self) -> &ContentDigest {
        &self.checksum
    }

    fn validate(&self) -> Result<(), StoreError> {
        let activated_at = self
            .payload
            .activated_at_unix_nanos
            .parse::<u128>()
            .map_err(|_error| invalid_record())?;
        let database = Path::new(&self.payload.database_path);
        let anchor = Path::new(&self.payload.anchor_path);
        let receipt = Path::new(&self.payload.authority_receipt_path);
        let expected_receipt = match self.payload.authority_receipt_kind.as_str() {
            "migration" => migration_receipt_path_v5(database)?,
            "compaction" => compaction_receipt_path_v5(database)?,
            _ => return Err(invalid_record()),
        };
        if self.payload.schema_version != ACTIVE_STORE_DESCRIPTOR_SCHEMA_V1
            || self.payload.generation == 0
            || self.payload.activated_at_unix_nanos != activated_at.to_string()
            || self.payload.format_version != 5
            || self.payload.database_inode == 0
            || self.payload.database_bytes == 0
            || !has_lexically_safe_absolute_components(database)
            || !has_lexically_safe_absolute_components(anchor)
            || !has_lexically_safe_absolute_components(receipt)
            || revision_anchor_path_v5(database)? != anchor
            || expected_receipt != receipt
            || self.checksum != active_store_descriptor_checksum_v1(&self.payload)?
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

/// Content-free result of one successful atomic activation publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationActivationReportV5 {
    /// Canonical descriptor that was replaced atomically.
    pub descriptor_path: PathBuf,
    /// Monotonic descriptor generation that is now active.
    pub generation: u64,
    /// Exact descriptor payload checksum.
    pub descriptor_checksum: ContentDigest,
    /// Exact signed migration-receipt file digest bound by the descriptor.
    pub migration_receipt_digest: ContentDigest,
    /// Verified v5 target revision opened through the published descriptor.
    pub latest_revision: StoreRevision,
}

/// Result of an explicit target-only cleanup after an interrupted construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationCleanupReportV5 {
    /// Main target that no longer exists.
    pub target_path: PathBuf,
    /// Number of recognized target-owned files removed.
    pub removed_files: u64,
    /// Authenticated v4 source head that remained unchanged.
    pub source_revision: StoreRevision,
}

/// Canonical offline paths bound into one signed revision-compaction preview.
pub struct RevisionCompactionPathsV1 {
    source: PathBuf,
    migration_receipt: PathBuf,
    target: PathBuf,
    descriptor: PathBuf,
    preview: PathBuf,
}

impl RevisionCompactionPathsV1 {
    /// Resolves the active v5 source and three non-overlapping administration artifacts.
    pub fn resolve(
        source: impl AsRef<Path>,
        migration_receipt: impl AsRef<Path>,
        target: impl AsRef<Path>,
        descriptor: impl AsRef<Path>,
        preview: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let source = canonical_existing(source.as_ref(), ExistingPathKindV5::File)?;
        let migration_receipt =
            canonical_existing(migration_receipt.as_ref(), ExistingPathKindV5::File)?;
        let target = canonical_new_file(target.as_ref())?;
        let descriptor = canonical_existing(descriptor.as_ref(), ExistingPathKindV5::File)?;
        let preview = canonical_new_file(preview.as_ref())?;
        let paths = [&source, &migration_receipt, &target, &descriptor, &preview];
        if migration_receipt != migration_receipt_path_v5(&source)?
            || paths.iter().enumerate().any(|(index, left)| {
                paths
                    .iter()
                    .skip(index + 1)
                    .any(|right| overlaps(left, right))
            })
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        Ok(Self {
            source,
            migration_receipt,
            target,
            descriptor,
            preview,
        })
    }

    /// New owner-private signed preview path.
    #[must_use]
    pub fn preview(&self) -> &Path {
        &self.preview
    }
}

/// Exact signed authorization payload for one offline distinct-target compaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionCompactionPreviewV1 {
    schema_version: String,
    created_at_unix_nanos: String,
    expires_at_unix_nanos: String,
    source_path: String,
    source_device: u64,
    source_inode: u64,
    source_database_bytes: u64,
    source_database_digest: ContentDigest,
    backup_proof_receipt_digest: ContentDigest,
    backup_canonical_root: String,
    backup_manifest_digest: ContentDigest,
    target_path: String,
    descriptor_path: String,
    descriptor_generation: u64,
    descriptor_checksum: ContentDigest,
    head_revision: u64,
    chain_head: ContentDigest,
    policy_digest: ContentDigest,
    pins_digest: ContentDigest,
    current_first_revision: u64,
    compacted_first_revision: u64,
    candidate_last_revision: u64,
    candidate_revisions: u64,
    candidate_checkpoints: u64,
    candidate_deltas: u64,
    estimated_reclaimable_bytes: u64,
    retained_revisions: u64,
}

impl RevisionCompactionPreviewV1 {
    /// Exact new compacted target bound by this preview.
    #[must_use]
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// Candidate revision count authorized for removal.
    #[must_use]
    pub const fn candidate_revisions(&self) -> u64 {
        self.candidate_revisions
    }

    /// First revision that remains exactly reconstructable.
    #[must_use]
    pub const fn compacted_first_revision(&self) -> StoreRevision {
        StoreRevision(self.compacted_first_revision)
    }

    fn validate(&self) -> Result<(), StoreError> {
        let created = canonical_u128_text(&self.created_at_unix_nanos)?;
        let expires = canonical_u128_text(&self.expires_at_unix_nanos)?;
        if self.schema_version != REVISION_COMPACTION_PREVIEW_SCHEMA_V1
            || expires <= created
            || self.source_inode == 0
            || self.source_database_bytes == 0
            || self.descriptor_generation == 0
            || self.head_revision < self.compacted_first_revision
            || self.current_first_revision >= self.compacted_first_revision
            || self.candidate_last_revision.checked_add(1) != Some(self.compacted_first_revision)
            || self
                .candidate_last_revision
                .checked_sub(self.current_first_revision)
                .and_then(|value| value.checked_add(1))
                != Some(self.candidate_revisions)
            || self
                .head_revision
                .checked_sub(self.compacted_first_revision)
                .and_then(|value| value.checked_add(1))
                != Some(self.retained_revisions)
            || self
                .candidate_checkpoints
                .checked_add(self.candidate_deltas)
                != Some(self.candidate_revisions)
            || !has_lexically_safe_absolute_components(Path::new(&self.source_path))
            || !has_lexically_safe_absolute_components(Path::new(&self.target_path))
            || !has_lexically_safe_absolute_components(Path::new(&self.descriptor_path))
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

/// Portable signed revision-compaction preview.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevisionCompactionPreviewV1 {
    preview: RevisionCompactionPreviewV1,
    signature: PersistedCompactionSignature,
}

impl SignedRevisionCompactionPreviewV1 {
    /// Exact target selected by the verified preview.
    #[must_use]
    pub fn preview_target_path(&self) -> &str {
        self.preview.target_path()
    }

    /// Revisions authorized for removal.
    #[must_use]
    pub const fn preview_candidate_revisions(&self) -> u64 {
        self.preview.candidate_revisions()
    }

    /// First revision retained after execution.
    #[must_use]
    pub const fn preview_compacted_first_revision(&self) -> StoreRevision {
        self.preview.compacted_first_revision()
    }
}

/// Signed proof of one completed, verified, and activated compaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionCompactionReceiptV1 {
    schema_version: String,
    completed_at_unix_nanos: String,
    preview_digest: ContentDigest,
    source_database_digest: ContentDigest,
    target_database_digest: ContentDigest,
    target_database_bytes: u64,
    head_revision: u64,
    chain_head: ContentDigest,
    policy_digest: ContentDigest,
    pins_digest: ContentDigest,
    prior_first_revision: u64,
    compacted_first_revision: u64,
    removed_revisions: u64,
    retained_revisions: u64,
    sqlite_integrity_verified: bool,
    every_retained_revision_verified: bool,
    catalog_projection_verified: bool,
    source_retained: bool,
}

/// Portable signed compaction receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevisionCompactionReceiptV1 {
    receipt: RevisionCompactionReceiptV1,
    signature: PersistedCompactionSignature,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedCompactionSignature {
    algorithm: String,
    key_ref: String,
    tenant: String,
    signer: String,
    purpose: String,
    signed_at_unix_nanos: String,
    expires_at_unix_nanos: Option<String>,
    payload_digest_hex: String,
    signature_hex: String,
}

/// Content-free completion report for one activated compacted target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionCompactionReportV1 {
    /// New compacted database selected by the active descriptor.
    pub target_path: PathBuf,
    /// Owner-private signed compaction receipt.
    pub receipt_path: PathBuf,
    /// New active descriptor generation.
    pub descriptor_generation: u64,
    /// Revisions physically removed from the compacted target.
    pub removed_revisions: u64,
    /// Revisions retained and exactly reconstructable.
    pub retained_revisions: u64,
    /// First retained revision.
    pub compacted_first_revision: StoreRevision,
    /// Final compacted target bytes.
    pub target_database_bytes: u64,
    /// Exact final compacted target digest.
    pub target_database_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedPrefixPayloadV1 {
    schema_version: String,
    verifier_version: String,
    verified_at_unix_nanos: String,
    database_path: String,
    database_device: u64,
    database_inode: u64,
    format_version: u64,
    first_retained_revision: u64,
    verified_through_revision: u64,
    verified_through_chain_head: ContentDigest,
    policy_digest: ContentDigest,
    every_prefix_revision_verified: bool,
    catalog_history_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedVerifiedPrefixV1 {
    prefix: VerifiedPrefixPayloadV1,
    signature: PersistedCompactionSignature,
}

/// Completed signed-prefix deep-integrity operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrefixDeepIntegrityReportV1 {
    /// Content-free retained-history verification result.
    pub integrity: crate::SqliteDeepIntegrityReportV5,
    /// Owner-private signed verified-prefix sidecar.
    pub prefix_path: PathBuf,
    /// True when an unchanged signed prefix avoided rechecking older retained revisions.
    pub prefix_reused: bool,
    /// True when the caller explicitly required every retained revision to be checked again.
    pub force_full: bool,
}

/// Signs one fully verified migration receipt with a purpose-separated operator signature.
pub fn sign_migration_receipt_v1<P: KeyProvider>(
    receipt: MigrationReceiptV1,
    provider: &P,
    identity: MigrationReceiptIdentity<'_>,
) -> Result<SignedMigrationReceiptV1, StoreError> {
    receipt.validate()?;
    validate_receipt_identity(identity.tenant, identity.signer)?;
    let signed_at = receipt
        .created_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let payload_digest = migration_receipt_payload_digest(&receipt)?;
    let signature = provider
        .sign(SignatureRequest {
            key_ref: identity.signing_key,
            tenant: identity.tenant,
            signer: identity.signer,
            purpose: MIGRATION_RECEIPT_SIGNATURE_PURPOSE_V1,
            payload_digest,
            signed_at,
            expires_at: None,
        })
        .map_err(map_receipt_crypto_error)?;
    Ok(SignedMigrationReceiptV1 {
        receipt,
        signature: persist_migration_receipt_signature(&signature, identity.tenant),
    })
}

/// Verifies a receipt signature and applies current operator trust policy.
pub fn verify_migration_receipt_v1<P, F>(
    signed: &SignedMigrationReceiptV1,
    provider: &P,
    now_unix_nanos: i128,
    trust: F,
) -> Result<MigrationReceiptSignatureIdentity, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    signed.receipt.validate()?;
    let signature = restore_migration_receipt_signature(&signed.signature)?;
    let identity = MigrationReceiptSignatureIdentity {
        tenant: signed.signature.tenant.clone(),
        signer: signature.signer.clone(),
        signing_key: signature.key_ref.clone(),
        signed_at_unix_nanos: signature.signed_at,
    };
    validate_receipt_identity(&identity.tenant, &identity.signer)?;
    let expected_time = signed
        .receipt
        .created_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let payload_digest = migration_receipt_payload_digest(&signed.receipt)?;
    if signature.purpose != MIGRATION_RECEIPT_SIGNATURE_PURPOSE_V1
        || signature.expires_at.is_some()
        || signature.signed_at != expected_time
        || signature.payload_digest != payload_digest
        || !trust(&identity)
    {
        return Err(invalid_record());
    }
    provider
        .verify(
            &signature,
            SignatureVerification {
                tenant: &identity.tenant,
                signer: &identity.signer,
                purpose: MIGRATION_RECEIPT_SIGNATURE_PURPOSE_V1,
                payload_digest: &payload_digest,
                now: now_unix_nanos,
            },
        )
        .map_err(map_receipt_crypto_error)?;
    Ok(identity)
}

/// Reads and verifies one owner-only active-store descriptor without following a symlink.
pub fn read_active_store_descriptor_v1(
    path: impl AsRef<Path>,
) -> Result<ActiveStoreDescriptorV1, StoreError> {
    let path = canonical_existing(path.as_ref(), ExistingPathKindV5::File)?;
    let bytes = read_stable_private_file(&path, MAX_ACTIVE_STORE_DESCRIPTOR_BYTES_V1)?.0;
    let descriptor: ActiveStoreDescriptorV1 =
        serde_json::from_slice(&bytes).map_err(|_error| invalid_record())?;
    descriptor.validate()?;
    if Path::new(descriptor.database_path())
        != canonical_existing(
            Path::new(descriptor.database_path()),
            ExistingPathKindV5::File,
        )?
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(descriptor)
}

/// Reauthenticates all migration evidence and atomically publishes the verified v5 target.
///
/// Both source and target runtime locks remain exclusive through the post-publication read-only
/// open. The descriptor is always a complete old or new file; this operation never rewrites or
/// deletes the retained v4 source or verified backup.
pub fn activate_v5_migration<P, BF, RF>(
    paths: MigrationActivationPathsV5,
    provider: &P,
    now_unix_nanos: i128,
    backup_trust: BF,
    receipt_trust: RF,
) -> Result<MigrationActivationReportV5, StoreError>
where
    P: KeyProvider,
    BF: Fn(&BackupSignatureIdentity) -> bool,
    RF: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    let _source_lock = acquire_sqlite_runtime_exclusive_lock(paths.source())?;
    let _target_lock = acquire_sqlite_runtime_exclusive_lock(paths.target())?;
    let source_identity = migration_file_identity(paths.source())?;
    let target_identity = migration_file_identity(paths.target())?;
    let descriptor_before = descriptor_publication_state(paths.descriptor())?;

    let (receipt_bytes, receipt_identity) =
        read_stable_private_file(paths.receipt(), MAX_MIGRATION_RECEIPT_BYTES_V5)?;
    let signed_receipt: SignedMigrationReceiptV1 =
        serde_json::from_slice(&receipt_bytes).map_err(|_error| invalid_record())?;
    verify_migration_receipt_v1(&signed_receipt, provider, now_unix_nanos, receipt_trust)?;
    let receipt = signed_receipt.unverified_receipt();
    let receipt_digest = sha256_bytes(&receipt_bytes)?;

    let source = authenticate_v4_migration_database(paths.source(), true)?;
    let source_digest = sha256_file(
        paths.source(),
        maximum_database_bytes(source.capacity_profile.as_str())?,
    )?;
    if source_identity.device != receipt.source_device
        || source_identity.inode != receipt.source_inode
        || source_identity.size_bytes != receipt.source_database_bytes
        || source_digest != receipt.source_database_digest
        || source.first_revision.0 != receipt.first_retained_revision
        || source.latest_revision.0 != receipt.latest_revision
        || source.retained_revisions != receipt.retained_revisions
        || source.catalog_root != receipt.source_catalog_root
        || source.semantic_root != receipt.source_semantic_root
        || migration_file_identity(paths.source())? != source_identity
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }

    let verified_backup =
        verify_backup_trusted(paths.backup(), provider, now_unix_nanos, backup_trust)
            .map_err(map_backup_error)?;
    let backup_manifest_digest = sha256_file(
        &paths.backup().join("manifest.cbor"),
        MAX_MIGRATION_MANIFEST_BYTES_V5,
    )?;
    let backup_database =
        authenticate_v4_migration_database(&paths.backup().join(BACKUP_DATABASE_FILE), false)?;
    if verified_backup.manifest.canonical_root != receipt.backup_canonical_root
        || backup_manifest_digest != receipt.backup_manifest_digest
        || backup_database.first_revision != source.first_revision
        || backup_database.latest_revision != source.latest_revision
        || backup_database.retained_revisions != source.retained_revisions
        || backup_database.catalog_root != source.catalog_root
        || backup_database.semantic_root != source.semantic_root
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let target_digest = sha256_file(
        paths.target(),
        maximum_database_bytes(source.capacity_profile.as_str())?,
    )?;
    if target_identity.device != receipt.target_device
        || target_identity.inode != receipt.target_inode
        || target_identity.size_bytes != receipt.target_database_bytes
        || target_digest != receipt.target_database_digest
        || receipt_identity != migration_file_identity(paths.receipt())?
        || target_identity != migration_file_identity(paths.target())?
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    verify_v5_target_against_receipt(paths.target(), receipt)?;

    let anchor = revision_anchor_path_v5(paths.target())?;
    if read_revision_anchor(&anchor)? != Some(receipt.latest_revision()) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let anchor = canonical_existing(&anchor, ExistingPathKindV5::File)?;
    let anchor_digest = sha256_file(&anchor, 256)?;
    let generation = descriptor_before.as_ref().map_or(Ok(1_u64), |state| {
        state
            .descriptor
            .generation()
            .checked_add(1)
            .ok_or_else(limit_exceeded)
    })?;
    let payload = ActiveStoreDescriptorPayloadV1 {
        schema_version: ACTIVE_STORE_DESCRIPTOR_SCHEMA_V1.to_owned(),
        generation,
        activated_at_unix_nanos: now_unix_nanos
            .try_into()
            .map(|value: u128| value.to_string())
            .map_err(|_error| invalid_record())?,
        format_version: 5,
        database_path: path_text(paths.target())?,
        database_device: target_identity.device,
        database_inode: target_identity.inode,
        database_bytes: target_identity.size_bytes,
        database_digest: target_digest,
        anchor_path: path_text(&anchor)?,
        anchor_digest,
        authority_receipt_kind: "migration".to_owned(),
        authority_receipt_path: path_text(paths.receipt())?,
        authority_receipt_digest: receipt_digest.clone(),
        latest_revision: receipt.latest_revision,
        chain_head: receipt.target_chain_head.clone(),
    };
    let descriptor = ActiveStoreDescriptorV1 {
        checksum: active_store_descriptor_checksum_v1(&payload)?,
        payload,
    };
    descriptor.validate()?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterActivationIntent);
    publish_active_store_descriptor_v1(
        paths.descriptor(),
        &descriptor,
        descriptor_before.as_ref(),
    )?;

    let published = read_active_store_descriptor_v1(paths.descriptor())?;
    if published != descriptor
        || canonical_existing(
            Path::new(published.database_path()),
            ExistingPathKindV5::File,
        )? != paths.target()
        || migration_file_identity(paths.source())? != source_identity
        || migration_file_identity(paths.target())? != target_identity
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    verify_active_v5_descriptor(&published)?;
    verify_v5_target_against_receipt(Path::new(published.database_path()), receipt)?;
    Ok(MigrationActivationReportV5 {
        descriptor_path: paths.descriptor,
        generation,
        descriptor_checksum: descriptor.checksum,
        migration_receipt_digest: receipt_digest,
        latest_revision: receipt.latest_revision(),
    })
}

/// Removes only a distinct, non-active migration target after reauthenticating retained evidence.
///
/// A signed receipt or descriptor selecting the target makes cleanup ineligible. The source and
/// verified backup are checked before and after deletion; only the target database and its closed
/// set of SQLite/runtime/anchor sidecars can be removed.
pub fn cleanup_incomplete_v5_target<P, F>(
    paths: MigrationCleanupPathsV5,
    provider: &P,
    now_unix_nanos: i128,
    backup_trust: F,
) -> Result<MigrationCleanupReportV5, StoreError>
where
    P: KeyProvider,
    F: Fn(&BackupSignatureIdentity) -> bool,
{
    let _source_lock = acquire_sqlite_runtime_exclusive_lock(paths.source())?;
    let target_lock = acquire_sqlite_runtime_exclusive_lock(paths.target())?;
    let source_identity = migration_file_identity(paths.source())?;
    let source = authenticate_v4_migration_database(paths.source(), true)?;
    let source_digest = sha256_file(
        paths.source(),
        maximum_database_bytes(source.capacity_profile.as_str())?,
    )?;
    let verified = verify_backup_trusted(paths.backup(), provider, now_unix_nanos, backup_trust)
        .map_err(map_backup_error)?;
    let backup =
        authenticate_v4_migration_database(&paths.backup().join(BACKUP_DATABASE_FILE), false)?;
    if verified.manifest.repository_revision != source.latest_revision.0
        || backup.first_revision != source.first_revision
        || backup.latest_revision != source.latest_revision
        || backup.retained_revisions != source.retained_revisions
        || backup.catalog_root != source.catalog_root
        || backup.semantic_root != source.semantic_root
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let receipt = migration_receipt_path_v5(paths.target())?;
    if fs::symlink_metadata(&receipt).is_ok() {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    if let Some(active) = descriptor_publication_state(paths.descriptor())?
        && Path::new(active.descriptor.database_path()) == paths.target()
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }

    let target_identity = migration_file_identity(paths.target())?;
    let mut artifacts = migration_target_artifacts(paths.target())?;
    let lock_path = sqlite_runtime_lock_path_v5(paths.target())?;
    artifacts.retain(|path| path != &lock_path);
    artifacts.push(lock_path);
    let mut removed_files = 0_u64;
    for artifact in artifacts {
        match fs::symlink_metadata(&artifact) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
            Ok(_metadata) => {
                let canonical = canonical_existing(&artifact, ExistingPathKindV5::File)?;
                if canonical.parent() != paths.target().parent() {
                    return Err(StoreError::new(StoreErrorCode::InvalidContext));
                }
                if canonical == paths.target()
                    && migration_file_identity(&canonical)? != target_identity
                {
                    return Err(StoreError::new(StoreErrorCode::RevisionConflict));
                }
                fs::remove_file(&canonical)
                    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
                removed_files = removed_files.checked_add(1).ok_or_else(limit_exceeded)?;
            }
        }
    }
    drop(target_lock);
    let parent = paths
        .target()
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if fs::symlink_metadata(paths.target()).is_ok()
        || migration_file_identity(paths.source())? != source_identity
        || sha256_file(
            paths.source(),
            maximum_database_bytes(source.capacity_profile.as_str())?,
        )? != source_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    Ok(MigrationCleanupReportV5 {
        target_path: paths.target,
        removed_files,
        source_revision: source.latest_revision,
    })
}

/// Derives and signs an exact expiring offline revision-compaction preview.
pub fn create_revision_compaction_preview_v1<P, F>(
    paths: RevisionCompactionPathsV1,
    provider: &P,
    now_unix_nanos: i128,
    expires_at_unix_nanos: i128,
    identity: MigrationReceiptIdentity<'_>,
    receipt_trust: F,
) -> Result<SignedRevisionCompactionPreviewV1, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    if now_unix_nanos < 0 || expires_at_unix_nanos <= now_unix_nanos {
        return Err(invalid_record());
    }
    let _source_lock = acquire_sqlite_runtime_exclusive_lock(&paths.source)?;
    let descriptor = read_active_store_descriptor_v1(&paths.descriptor)?;
    if Path::new(descriptor.database_path()) != paths.source {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let (migration_receipt_bytes, _) =
        read_stable_private_file(&paths.migration_receipt, MAX_MIGRATION_RECEIPT_BYTES_V5)?;
    let migration_receipt: SignedMigrationReceiptV1 =
        serde_json::from_slice(&migration_receipt_bytes).map_err(|_error| invalid_record())?;
    verify_migration_receipt_v1(&migration_receipt, provider, now_unix_nanos, receipt_trust)?;
    let migration = migration_receipt.unverified_receipt();
    let source_identity = migration_file_identity(&paths.source)?;
    let source_digest = sha256_file(&paths.source, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?;
    if source_identity.device != migration.target_device
        || source_identity.inode != migration.target_inode
        || source_identity.size_bytes != migration.target_database_bytes
        || source_digest != migration.target_database_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let connection = open_v5_read_only(&paths.source)?;
    let candidate = crate::sqlite_v5::preview_repository_compaction_v5(&connection)?;
    let preview = RevisionCompactionPreviewV1 {
        schema_version: REVISION_COMPACTION_PREVIEW_SCHEMA_V1.to_owned(),
        created_at_unix_nanos: now_unix_nanos.to_string(),
        expires_at_unix_nanos: expires_at_unix_nanos.to_string(),
        source_path: path_text(&paths.source)?,
        source_device: source_identity.device,
        source_inode: source_identity.inode,
        source_database_bytes: source_identity.size_bytes,
        source_database_digest: source_digest,
        backup_proof_receipt_digest: sha256_bytes(&migration_receipt_bytes)?,
        backup_canonical_root: migration.backup_canonical_root.clone(),
        backup_manifest_digest: migration.backup_manifest_digest.clone(),
        target_path: path_text(&paths.target)?,
        descriptor_path: path_text(&paths.descriptor)?,
        descriptor_generation: descriptor.generation(),
        descriptor_checksum: descriptor.checksum().clone(),
        head_revision: candidate.head_revision.0,
        chain_head: candidate.chain_head,
        policy_digest: candidate.policy_digest,
        pins_digest: candidate.pins_digest,
        current_first_revision: candidate.current_first_revision.0,
        compacted_first_revision: candidate.compacted_first_revision.0,
        candidate_last_revision: candidate.candidate_last_revision.0,
        candidate_revisions: candidate.candidate_revisions,
        candidate_checkpoints: candidate.candidate_checkpoints,
        candidate_deltas: candidate.candidate_deltas,
        estimated_reclaimable_bytes: candidate.estimated_reclaimable_bytes,
        retained_revisions: candidate.retained_revisions,
    };
    preview.validate()?;
    sign_compaction_preview_v1(
        preview,
        provider,
        identity,
        now_unix_nanos,
        expires_at_unix_nanos,
    )
}

/// Executes one exact signed preview into a distinct target and atomically activates it.
pub fn execute_revision_compaction_v1<P, F>(
    preview_path: impl AsRef<Path>,
    provider: &P,
    now_unix_nanos: i128,
    receipt_identity: MigrationReceiptIdentity<'_>,
    trust: F,
) -> Result<RevisionCompactionReportV1, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool + Copy,
{
    let preview_path = canonical_existing(preview_path.as_ref(), ExistingPathKindV5::File)?;
    let (preview_bytes, preview_identity) =
        read_stable_private_file(&preview_path, MAX_REVISION_COMPACTION_DOCUMENT_BYTES_V1)?;
    let signed_preview: SignedRevisionCompactionPreviewV1 =
        serde_json::from_slice(&preview_bytes).map_err(|_error| invalid_record())?;
    verify_compaction_preview_v1(&signed_preview, provider, now_unix_nanos, trust)?;
    let preview = &signed_preview.preview;
    let preview_digest = sha256_bytes(&preview_bytes)?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterCompactionPreviewVerification);
    let source = canonical_existing(Path::new(&preview.source_path), ExistingPathKindV5::File)?;
    let target_existed = fs::symlink_metadata(Path::new(&preview.target_path)).is_ok();
    let target = canonical_existing_or_new_file(Path::new(&preview.target_path))?;
    let descriptor_path = canonical_existing(
        Path::new(&preview.descriptor_path),
        ExistingPathKindV5::File,
    )?;
    if source == target || preview_identity != migration_file_identity(&preview_path)? {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let _source_lock = acquire_sqlite_runtime_exclusive_lock(&source)?;
    let descriptor_before = descriptor_publication_state(&descriptor_path)?
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
    if Path::new(descriptor_before.descriptor.database_path()) == target {
        return completed_compaction_report_v1(
            preview,
            &preview_digest,
            &target,
            &descriptor_before.descriptor,
            provider,
            now_unix_nanos,
            trust,
        );
    }
    if descriptor_before.descriptor.generation() != preview.descriptor_generation
        || descriptor_before.descriptor.checksum() != &preview.descriptor_checksum
        || Path::new(descriptor_before.descriptor.database_path()) != source
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let migration_receipt_path = migration_receipt_path_v5(&source)?;
    let (migration_receipt_bytes, _) =
        read_stable_private_file(&migration_receipt_path, MAX_MIGRATION_RECEIPT_BYTES_V5)?;
    let migration_receipt: SignedMigrationReceiptV1 =
        serde_json::from_slice(&migration_receipt_bytes).map_err(|_error| invalid_record())?;
    verify_migration_receipt_v1(&migration_receipt, provider, now_unix_nanos, trust)?;
    let migration = migration_receipt.unverified_receipt();
    let source_identity = migration_file_identity(&source)?;
    if source_identity.device != preview.source_device
        || source_identity.inode != preview.source_inode
        || source_identity.size_bytes != preview.source_database_bytes
        || sha256_file(&source, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?
            != preview.source_database_digest
        || sha256_bytes(&migration_receipt_bytes)? != preview.backup_proof_receipt_digest
        || migration.backup_canonical_root != preview.backup_canonical_root
        || migration.backup_manifest_digest != preview.backup_manifest_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let source_connection = open_v5_read_only(&source)?;
    let observed = crate::sqlite_v5::preview_repository_compaction_v5(&source_connection)?;
    if !compaction_state_matches_preview(&observed, preview) {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    drop(source_connection);

    if !target_existed {
        create_private_target(&target)?;
        copy_sqlite_database(&source, &target)?;
        migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterCompactionTargetCopy);
    }
    let _target_lock = acquire_sqlite_runtime_exclusive_lock(&target)?;
    let receipt_path = compaction_receipt_path_v5(&target)?;
    let receipt_exists = match fs::symlink_metadata(&receipt_path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(invalid_record());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    if receipt_exists {
        let compacted = open_v5_read_only(&target)?;
        let completed_origin: i64 = compacted
            .query_row(
                "SELECT COUNT(*) FROM repository_compaction_origin_v5
                 WHERE singleton = 1 AND origin_revision = ?1 AND preview_digest = ?2
                       AND verification_state = 'complete'",
                params![
                    i64::try_from(preview.compacted_first_revision)
                        .map_err(|_error| limit_exceeded())?,
                    preview_digest.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        let integrity = compacted
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .map_err(unavailable)?;
        if completed_origin != 1
            || integrity != "ok"
            || crate::sqlite_v5::verify_migrated_repository_v5(&compacted)?
                != preview.retained_revisions
        {
            return Err(invalid_record());
        }
    } else {
        let mut compacted = Connection::open_with_flags(&target, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(unavailable)?;
        configure_migration_target(&compacted)?;
        let completed_origin: i64 = compacted
            .query_row(
                "SELECT COUNT(*) FROM repository_compaction_origin_v5
                 WHERE singleton = 1 AND origin_revision = ?1 AND preview_digest = ?2
                       AND verification_state = 'complete'",
                params![
                    i64::try_from(preview.compacted_first_revision)
                        .map_err(|_error| limit_exceeded())?,
                    preview_digest.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        if completed_origin == 0 {
            let target_state = crate::sqlite_v5::preview_repository_compaction_v5(&compacted)?;
            if target_state != observed {
                return Err(StoreError::new(StoreErrorCode::RevisionConflict));
            }
            crate::sqlite_v5::execute_repository_compaction_v5(
                &mut compacted,
                &observed,
                &preview_digest,
                u128::try_from(now_unix_nanos).map_err(|_error| invalid_record())?,
            )?;
        } else if completed_origin != 1 {
            return Err(invalid_record());
        }
        migration_v5_process_abort_if_armed(
            MigrationV5Failpoint::AfterCompactionLogicalReclamation,
        );
        compacted
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .map_err(unavailable)?;
        configure_migration_target(&compacted)?;
        let integrity = compacted
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .map_err(unavailable)?;
        if integrity != "ok"
            || crate::sqlite_v5::verify_migrated_repository_v5(&compacted)?
                != preview.retained_revisions
        {
            return Err(invalid_record());
        }
    }
    let anchor = revision_anchor_path_v5(&target)?;
    if receipt_exists {
        if read_revision_anchor(&anchor)? != Some(StoreRevision(preview.head_revision)) {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
    } else {
        write_revision_anchor(&anchor, StoreRevision(preview.head_revision))?;
        sync_file_and_parent(&target)?;
        migration_v5_process_abort_if_armed(
            MigrationV5Failpoint::AfterCompactionPhysicalReclamation,
        );
    }
    let target_identity = migration_file_identity(&target)?;
    let target_digest = sha256_file(&target, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?;
    if migration_file_identity(&source)? != source_identity
        || sha256_file(&source, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?
            != preview.source_database_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let expected_receipt = RevisionCompactionReceiptV1 {
        schema_version: REVISION_COMPACTION_RECEIPT_SCHEMA_V1.to_owned(),
        completed_at_unix_nanos: now_unix_nanos.to_string(),
        preview_digest,
        source_database_digest: preview.source_database_digest.clone(),
        target_database_digest: target_digest.clone(),
        target_database_bytes: target_identity.size_bytes,
        head_revision: preview.head_revision,
        chain_head: preview.chain_head.clone(),
        policy_digest: preview.policy_digest.clone(),
        pins_digest: preview.pins_digest.clone(),
        prior_first_revision: preview.current_first_revision,
        compacted_first_revision: preview.compacted_first_revision,
        removed_revisions: preview.candidate_revisions,
        retained_revisions: preview.retained_revisions,
        sqlite_integrity_verified: true,
        every_retained_revision_verified: true,
        catalog_projection_verified: true,
        source_retained: true,
    };
    let (signed_receipt, receipt_bytes) = match fs::symlink_metadata(&receipt_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let signed = sign_compaction_receipt_v1(
                expected_receipt.clone(),
                provider,
                receipt_identity,
                now_unix_nanos,
            )?;
            verify_compaction_receipt_v1(&signed, provider, now_unix_nanos, trust)?;
            let bytes = serde_json::to_vec(&signed).map_err(|_error| invalid_record())?;
            write_new_private_bytes(&receipt_path, &bytes)?;
            (signed, bytes)
        }
        Ok(_metadata) => {
            let (bytes, _) =
                read_stable_private_file(&receipt_path, MAX_REVISION_COMPACTION_DOCUMENT_BYTES_V1)?;
            let signed: SignedRevisionCompactionReceiptV1 =
                serde_json::from_slice(&bytes).map_err(|_error| invalid_record())?;
            verify_compaction_receipt_v1(&signed, provider, now_unix_nanos, trust)?;
            if !compaction_receipt_matches(&signed.receipt, &expected_receipt) {
                return Err(StoreError::new(StoreErrorCode::RevisionConflict));
            }
            (signed, bytes)
        }
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    let _verified_signed_receipt = signed_receipt;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterCompactionReceiptPublication);

    let anchor = canonical_existing(&anchor, ExistingPathKindV5::File)?;
    let descriptor_generation = preview
        .descriptor_generation
        .checked_add(1)
        .ok_or_else(limit_exceeded)?;
    let descriptor_payload = ActiveStoreDescriptorPayloadV1 {
        schema_version: ACTIVE_STORE_DESCRIPTOR_SCHEMA_V1.to_owned(),
        generation: descriptor_generation,
        activated_at_unix_nanos: now_unix_nanos.to_string(),
        format_version: 5,
        database_path: path_text(&target)?,
        database_device: target_identity.device,
        database_inode: target_identity.inode,
        database_bytes: target_identity.size_bytes,
        database_digest: target_digest.clone(),
        anchor_path: path_text(&anchor)?,
        anchor_digest: sha256_file(&anchor, 256)?,
        authority_receipt_kind: "compaction".to_owned(),
        authority_receipt_path: path_text(&receipt_path)?,
        authority_receipt_digest: sha256_bytes(&receipt_bytes)?,
        latest_revision: preview.head_revision,
        chain_head: preview.chain_head.clone(),
    };
    let descriptor = ActiveStoreDescriptorV1 {
        checksum: active_store_descriptor_checksum_v1(&descriptor_payload)?,
        payload: descriptor_payload,
    };
    descriptor.validate()?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterActivationIntent);
    publish_active_store_descriptor_v1(&descriptor_path, &descriptor, Some(&descriptor_before))?;
    if read_active_store_descriptor_v1(&descriptor_path)? != descriptor {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    verify_active_v5_descriptor(&descriptor)?;
    let active = open_v5_read_only(&target)?;
    if crate::sqlite_v5::retention_statistics_v5(&active)?.retained_revisions
        != preview.retained_revisions
    {
        return Err(invalid_record());
    }
    Ok(RevisionCompactionReportV1 {
        target_path: target,
        receipt_path,
        descriptor_generation,
        removed_revisions: preview.candidate_revisions,
        retained_revisions: preview.retained_revisions,
        compacted_first_revision: StoreRevision(preview.compacted_first_revision),
        target_database_bytes: target_identity.size_bytes,
        target_database_digest: target_digest,
    })
}

/// Authenticates retained v5 history, reuses only a trusted unchanged prefix, and publishes a new
/// signed prefix sidecar. `force_full` deliberately ignores any existing prefix and rechecks every
/// retained revision.
pub fn verify_v5_deep_integrity_with_prefix_v1<P, F>(
    database: impl AsRef<Path>,
    provider: &P,
    now_unix_nanos: i128,
    identity: MigrationReceiptIdentity<'_>,
    trust: F,
    force_full: bool,
) -> Result<VerifiedPrefixDeepIntegrityReportV1, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    if now_unix_nanos < 0 {
        return Err(invalid_record());
    }
    let database = canonical_existing(database.as_ref(), ExistingPathKindV5::File)?;
    let prefix_path = canonical_existing_or_new_file(&verified_prefix_path_v5(&database)?)?;
    if database == prefix_path {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    let _runtime_lock = acquire_sqlite_runtime_shared_lock(&database)?;
    let database_identity = migration_file_identity(&database)?;
    let (existing_prefix, expected_prefix_identity) = match fs::symlink_metadata(&prefix_path) {
        Ok(_metadata) => {
            let (bytes, file_identity) =
                read_stable_private_file(&prefix_path, MAX_VERIFIED_PREFIX_BYTES_V1)?;
            (Some(bytes), Some(file_identity))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    let connection = open_v5_read_only(&database)?;
    connection
        .execute_batch("BEGIN DEFERRED")
        .map_err(unavailable)?;
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(unavailable)?;
    if integrity != "ok" {
        return Err(invalid_record());
    }
    let verified_prefix = if force_full {
        None
    } else if let Some(bytes) = existing_prefix.as_deref() {
        let signed: SignedVerifiedPrefixV1 =
            serde_json::from_slice(bytes).map_err(|_error| invalid_record())?;
        verify_signed_prefix_v1(&signed, provider, now_unix_nanos, &trust)?;
        let prefix = &signed.prefix;
        let identity_matches = prefix.database_path == path_text(&database)?
            && prefix.database_device == database_identity.device
            && prefix.database_inode == database_identity.inode
            && prefix.verifier_version == V5_DEEP_VERIFIER_VERSION;
        if identity_matches {
            let candidate = crate::sqlite_v5::VerifiedPrefixStateV5 {
                first_revision: StoreRevision(prefix.first_retained_revision),
                through_revision: StoreRevision(prefix.verified_through_revision),
                through_chain_head: prefix.verified_through_chain_head.clone(),
                policy_digest: prefix.policy_digest.clone(),
            };
            crate::sqlite_v5::verified_prefix_is_compatible_v5(&connection, &candidate)?
                .then_some(candidate)
        } else {
            None
        }
    } else {
        None
    };
    let report =
        crate::sqlite_v5::deep_integrity_verification_v5(&connection, verified_prefix.as_ref())?;
    connection.execute_batch("COMMIT").map_err(unavailable)?;
    let current_identity = migration_file_identity(&database)?;
    if current_identity.device != database_identity.device
        || current_identity.inode != database_identity.inode
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let payload = VerifiedPrefixPayloadV1 {
        schema_version: VERIFIED_PREFIX_SCHEMA_V1.to_owned(),
        verifier_version: V5_DEEP_VERIFIER_VERSION.to_owned(),
        verified_at_unix_nanos: now_unix_nanos.to_string(),
        database_path: path_text(&database)?,
        database_device: database_identity.device,
        database_inode: database_identity.inode,
        format_version: 5,
        first_retained_revision: report.first_retained_revision.0,
        verified_through_revision: report.verified_through_revision.0,
        verified_through_chain_head: report.chain_head.clone(),
        policy_digest: report.policy_digest.clone(),
        every_prefix_revision_verified: true,
        catalog_history_verified: true,
    };
    validate_verified_prefix_payload_v1(&payload)?;
    let signed = sign_verified_prefix_v1(payload, provider, identity, now_unix_nanos)?;
    verify_signed_prefix_v1(&signed, provider, now_unix_nanos, trust)?;
    let bytes = serde_json::to_vec(&signed).map_err(|_error| invalid_record())?;
    publish_verified_prefix_v1(&prefix_path, &bytes, expected_prefix_identity)?;
    let (published, _) = read_stable_private_file(&prefix_path, MAX_VERIFIED_PREFIX_BYTES_V1)?;
    if published != bytes {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let published: SignedVerifiedPrefixV1 =
        serde_json::from_slice(&published).map_err(|_error| invalid_record())?;
    verify_signed_prefix_v1(&published, provider, now_unix_nanos, |_candidate| true)?;
    Ok(VerifiedPrefixDeepIntegrityReportV1 {
        prefix_reused: report.reused_prefix_revisions > 0,
        integrity: report,
        prefix_path,
        force_full,
    })
}

fn canonical_u128_text(value: &str) -> Result<u128, StoreError> {
    let parsed = value.parse::<u128>().map_err(|_error| invalid_record())?;
    if parsed.to_string() != value {
        return Err(invalid_record());
    }
    Ok(parsed)
}

fn open_v5_read_only(path: &Path) -> Result<Connection, StoreError> {
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(unavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(unavailable)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(connection)
}

fn compaction_state_matches_preview(
    state: &crate::sqlite_v5::CompactionPreviewStateV5,
    preview: &RevisionCompactionPreviewV1,
) -> bool {
    state.head_revision.0 == preview.head_revision
        && state.chain_head == preview.chain_head
        && state.policy_digest == preview.policy_digest
        && state.pins_digest == preview.pins_digest
        && state.current_first_revision.0 == preview.current_first_revision
        && state.compacted_first_revision.0 == preview.compacted_first_revision
        && state.candidate_last_revision.0 == preview.candidate_last_revision
        && state.candidate_revisions == preview.candidate_revisions
        && state.candidate_checkpoints == preview.candidate_checkpoints
        && state.candidate_deltas == preview.candidate_deltas
        && state.estimated_reclaimable_bytes == preview.estimated_reclaimable_bytes
        && state.retained_revisions == preview.retained_revisions
}

fn compaction_receipt_matches(
    observed: &RevisionCompactionReceiptV1,
    expected: &RevisionCompactionReceiptV1,
) -> bool {
    observed.schema_version == expected.schema_version
        && observed.preview_digest == expected.preview_digest
        && observed.source_database_digest == expected.source_database_digest
        && observed.target_database_digest == expected.target_database_digest
        && observed.target_database_bytes == expected.target_database_bytes
        && observed.head_revision == expected.head_revision
        && observed.chain_head == expected.chain_head
        && observed.policy_digest == expected.policy_digest
        && observed.pins_digest == expected.pins_digest
        && observed.prior_first_revision == expected.prior_first_revision
        && observed.compacted_first_revision == expected.compacted_first_revision
        && observed.removed_revisions == expected.removed_revisions
        && observed.retained_revisions == expected.retained_revisions
        && observed.sqlite_integrity_verified == expected.sqlite_integrity_verified
        && observed.every_retained_revision_verified == expected.every_retained_revision_verified
        && observed.catalog_projection_verified == expected.catalog_projection_verified
        && observed.source_retained == expected.source_retained
}

fn completed_compaction_report_v1<P, F>(
    preview: &RevisionCompactionPreviewV1,
    preview_digest: &ContentDigest,
    target: &Path,
    descriptor: &ActiveStoreDescriptorV1,
    provider: &P,
    now_unix_nanos: i128,
    trust: F,
) -> Result<RevisionCompactionReportV1, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    let expected_generation = preview
        .descriptor_generation
        .checked_add(1)
        .ok_or_else(limit_exceeded)?;
    let receipt_path = compaction_receipt_path_v5(target)?;
    if descriptor.generation() != expected_generation
        || Path::new(descriptor.database_path()) != target
        || descriptor.payload.authority_receipt_kind != "compaction"
        || Path::new(&descriptor.payload.authority_receipt_path) != receipt_path
        || descriptor.payload.latest_revision != preview.head_revision
        || descriptor.payload.chain_head != preview.chain_head
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    verify_active_v5_descriptor(descriptor)?;
    let (receipt_bytes, _) =
        read_stable_private_file(&receipt_path, MAX_REVISION_COMPACTION_DOCUMENT_BYTES_V1)?;
    if sha256_bytes(&receipt_bytes)? != descriptor.payload.authority_receipt_digest {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let signed_receipt: SignedRevisionCompactionReceiptV1 =
        serde_json::from_slice(&receipt_bytes).map_err(|_error| invalid_record())?;
    verify_compaction_receipt_v1(&signed_receipt, provider, now_unix_nanos, trust)?;
    let target_identity = migration_file_identity(target)?;
    let target_digest = sha256_file(target, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?;
    let expected_receipt = RevisionCompactionReceiptV1 {
        schema_version: REVISION_COMPACTION_RECEIPT_SCHEMA_V1.to_owned(),
        completed_at_unix_nanos: signed_receipt.receipt.completed_at_unix_nanos.clone(),
        preview_digest: preview_digest.clone(),
        source_database_digest: preview.source_database_digest.clone(),
        target_database_digest: target_digest.clone(),
        target_database_bytes: target_identity.size_bytes,
        head_revision: preview.head_revision,
        chain_head: preview.chain_head.clone(),
        policy_digest: preview.policy_digest.clone(),
        pins_digest: preview.pins_digest.clone(),
        prior_first_revision: preview.current_first_revision,
        compacted_first_revision: preview.compacted_first_revision,
        removed_revisions: preview.candidate_revisions,
        retained_revisions: preview.retained_revisions,
        sqlite_integrity_verified: true,
        every_retained_revision_verified: true,
        catalog_projection_verified: true,
        source_retained: true,
    };
    if !compaction_receipt_matches(&signed_receipt.receipt, &expected_receipt)
        || target_identity.device != descriptor.payload.database_device
        || target_identity.inode != descriptor.payload.database_inode
        || target_identity.size_bytes != descriptor.payload.database_bytes
        || target_digest != descriptor.payload.database_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let source = canonical_existing(Path::new(&preview.source_path), ExistingPathKindV5::File)?;
    let source_identity = migration_file_identity(&source)?;
    if source_identity.device != preview.source_device
        || source_identity.inode != preview.source_inode
        || source_identity.size_bytes != preview.source_database_bytes
        || sha256_file(&source, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?
            != preview.source_database_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let active = open_v5_read_only(target)?;
    let statistics = crate::sqlite_v5::retention_statistics_v5(&active)?;
    if statistics.reconstructable_first_revision.0 != preview.compacted_first_revision
        || statistics.reconstructable_last_revision.0 != preview.head_revision
        || statistics.retained_revisions != preview.retained_revisions
        || statistics.chain_head != preview.chain_head
    {
        return Err(invalid_record());
    }
    Ok(RevisionCompactionReportV1 {
        target_path: target.to_path_buf(),
        receipt_path,
        descriptor_generation: expected_generation,
        removed_revisions: preview.candidate_revisions,
        retained_revisions: preview.retained_revisions,
        compacted_first_revision: StoreRevision(preview.compacted_first_revision),
        target_database_bytes: target_identity.size_bytes,
        target_database_digest: target_digest,
    })
}

fn compaction_payload_digest<T: Serialize>(
    domain: &[u8],
    payload: &T,
) -> Result<[u8; 32], StoreError> {
    let bytes = serde_json::to_vec(payload).map_err(|_error| invalid_record())?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(
        u64::try_from(bytes.len())
            .map_err(|_error| limit_exceeded())?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(hash.finalize().into())
}

fn persist_compaction_signature(
    signature: &SignatureEnvelope,
    tenant: &str,
) -> PersistedCompactionSignature {
    PersistedCompactionSignature {
        algorithm: "ed25519".to_owned(),
        key_ref: signature.key_ref.as_str().to_owned(),
        tenant: tenant.to_owned(),
        signer: signature.signer.clone(),
        purpose: signature.purpose.clone(),
        signed_at_unix_nanos: signature.signed_at.to_string(),
        expires_at_unix_nanos: signature.expires_at.map(|value| value.to_string()),
        payload_digest_hex: encode_hex(&signature.payload_digest),
        signature_hex: encode_hex(&signature.signature),
    }
}

fn restore_compaction_signature(
    persisted: &PersistedCompactionSignature,
) -> Result<SignatureEnvelope, StoreError> {
    let signed_at = persisted
        .signed_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let expires_at = persisted
        .expires_at_unix_nanos
        .as_deref()
        .map(str::parse::<i128>)
        .transpose()
        .map_err(|_error| invalid_record())?;
    if persisted.algorithm != "ed25519"
        || signed_at < 0
        || persisted.signed_at_unix_nanos != signed_at.to_string()
        || persisted
            .expires_at_unix_nanos
            .as_ref()
            .zip(expires_at)
            .is_some_and(|(text, value)| text != &value.to_string())
    {
        return Err(invalid_record());
    }
    Ok(SignatureEnvelope {
        algorithm: KeyAlgorithm::Ed25519,
        key_ref: KeyRef::new(persisted.key_ref.clone()).map_err(|_error| invalid_record())?,
        signer: persisted.signer.clone(),
        purpose: persisted.purpose.clone(),
        signed_at,
        expires_at,
        payload_digest: decode_hex::<32>(&persisted.payload_digest_hex)?,
        signature: decode_hex::<64>(&persisted.signature_hex)?,
    })
}

fn sign_compaction_preview_v1<P: KeyProvider>(
    preview: RevisionCompactionPreviewV1,
    provider: &P,
    identity: MigrationReceiptIdentity<'_>,
    signed_at: i128,
    expires_at: i128,
) -> Result<SignedRevisionCompactionPreviewV1, StoreError> {
    preview.validate()?;
    validate_receipt_identity(identity.tenant, identity.signer)?;
    let digest = compaction_payload_digest(
        b"CIGAR-REVISION-COMPACTION-PREVIEW-SIGNATURE\0v1\0",
        &preview,
    )?;
    let signature = provider
        .sign(SignatureRequest {
            key_ref: identity.signing_key,
            tenant: identity.tenant,
            signer: identity.signer,
            purpose: REVISION_COMPACTION_PREVIEW_PURPOSE_V1,
            payload_digest: digest,
            signed_at,
            expires_at: Some(expires_at),
        })
        .map_err(map_receipt_crypto_error)?;
    Ok(SignedRevisionCompactionPreviewV1 {
        preview,
        signature: persist_compaction_signature(&signature, identity.tenant),
    })
}

fn verify_compaction_preview_v1<P, F>(
    signed: &SignedRevisionCompactionPreviewV1,
    provider: &P,
    now: i128,
    trust: F,
) -> Result<MigrationReceiptSignatureIdentity, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    signed.preview.validate()?;
    let signature = restore_compaction_signature(&signed.signature)?;
    let identity = MigrationReceiptSignatureIdentity {
        tenant: signed.signature.tenant.clone(),
        signer: signature.signer.clone(),
        signing_key: signature.key_ref.clone(),
        signed_at_unix_nanos: signature.signed_at,
    };
    let created = signed
        .preview
        .created_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let expires = signed
        .preview
        .expires_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let digest = compaction_payload_digest(
        b"CIGAR-REVISION-COMPACTION-PREVIEW-SIGNATURE\0v1\0",
        &signed.preview,
    )?;
    if signature.purpose != REVISION_COMPACTION_PREVIEW_PURPOSE_V1
        || signature.signed_at != created
        || signature.expires_at != Some(expires)
        || signature.payload_digest != digest
        || now < created
        || now >= expires
        || !trust(&identity)
    {
        return Err(invalid_record());
    }
    provider
        .verify(
            &signature,
            SignatureVerification {
                tenant: &identity.tenant,
                signer: &identity.signer,
                purpose: REVISION_COMPACTION_PREVIEW_PURPOSE_V1,
                payload_digest: &digest,
                now,
            },
        )
        .map_err(map_receipt_crypto_error)?;
    Ok(identity)
}

fn sign_compaction_receipt_v1<P: KeyProvider>(
    receipt: RevisionCompactionReceiptV1,
    provider: &P,
    identity: MigrationReceiptIdentity<'_>,
    signed_at: i128,
) -> Result<SignedRevisionCompactionReceiptV1, StoreError> {
    validate_compaction_receipt_v1(&receipt)?;
    validate_receipt_identity(identity.tenant, identity.signer)?;
    let digest = compaction_payload_digest(
        b"CIGAR-REVISION-COMPACTION-RECEIPT-SIGNATURE\0v1\0",
        &receipt,
    )?;
    let signature = provider
        .sign(SignatureRequest {
            key_ref: identity.signing_key,
            tenant: identity.tenant,
            signer: identity.signer,
            purpose: REVISION_COMPACTION_RECEIPT_PURPOSE_V1,
            payload_digest: digest,
            signed_at,
            expires_at: None,
        })
        .map_err(map_receipt_crypto_error)?;
    Ok(SignedRevisionCompactionReceiptV1 {
        receipt,
        signature: persist_compaction_signature(&signature, identity.tenant),
    })
}

fn verify_compaction_receipt_v1<P, F>(
    signed: &SignedRevisionCompactionReceiptV1,
    provider: &P,
    now: i128,
    trust: F,
) -> Result<MigrationReceiptSignatureIdentity, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    validate_compaction_receipt_v1(&signed.receipt)?;
    let signature = restore_compaction_signature(&signed.signature)?;
    let identity = MigrationReceiptSignatureIdentity {
        tenant: signed.signature.tenant.clone(),
        signer: signature.signer.clone(),
        signing_key: signature.key_ref.clone(),
        signed_at_unix_nanos: signature.signed_at,
    };
    let completed = signed
        .receipt
        .completed_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let digest = compaction_payload_digest(
        b"CIGAR-REVISION-COMPACTION-RECEIPT-SIGNATURE\0v1\0",
        &signed.receipt,
    )?;
    if signature.purpose != REVISION_COMPACTION_RECEIPT_PURPOSE_V1
        || signature.signed_at != completed
        || signature.expires_at.is_some()
        || signature.payload_digest != digest
        || !trust(&identity)
    {
        return Err(invalid_record());
    }
    provider
        .verify(
            &signature,
            SignatureVerification {
                tenant: &identity.tenant,
                signer: &identity.signer,
                purpose: REVISION_COMPACTION_RECEIPT_PURPOSE_V1,
                payload_digest: &digest,
                now,
            },
        )
        .map_err(map_receipt_crypto_error)?;
    Ok(identity)
}

fn validate_compaction_receipt_v1(receipt: &RevisionCompactionReceiptV1) -> Result<(), StoreError> {
    canonical_u128_text(&receipt.completed_at_unix_nanos)?;
    if receipt.schema_version != REVISION_COMPACTION_RECEIPT_SCHEMA_V1
        || receipt.target_database_bytes == 0
        || receipt.prior_first_revision >= receipt.compacted_first_revision
        || receipt
            .compacted_first_revision
            .checked_sub(receipt.prior_first_revision)
            != Some(receipt.removed_revisions)
        || receipt.removed_revisions == 0
        || receipt.retained_revisions == 0
        || !receipt.sqlite_integrity_verified
        || !receipt.every_retained_revision_verified
        || !receipt.catalog_projection_verified
        || !receipt.source_retained
    {
        return Err(invalid_record());
    }
    Ok(())
}

fn validate_verified_prefix_payload_v1(prefix: &VerifiedPrefixPayloadV1) -> Result<(), StoreError> {
    canonical_u128_text(&prefix.verified_at_unix_nanos)?;
    if prefix.schema_version != VERIFIED_PREFIX_SCHEMA_V1
        || prefix.verifier_version != V5_DEEP_VERIFIER_VERSION
        || prefix.database_device == 0
        || prefix.database_inode == 0
        || prefix.format_version != 5
        || prefix.first_retained_revision > prefix.verified_through_revision
        || !prefix.every_prefix_revision_verified
        || !prefix.catalog_history_verified
        || !has_lexically_safe_absolute_components(Path::new(&prefix.database_path))
    {
        return Err(invalid_record());
    }
    Ok(())
}

fn sign_verified_prefix_v1<P: KeyProvider>(
    prefix: VerifiedPrefixPayloadV1,
    provider: &P,
    identity: MigrationReceiptIdentity<'_>,
    signed_at: i128,
) -> Result<SignedVerifiedPrefixV1, StoreError> {
    validate_verified_prefix_payload_v1(&prefix)?;
    validate_receipt_identity(identity.tenant, identity.signer)?;
    if prefix.verified_at_unix_nanos != signed_at.to_string() {
        return Err(invalid_record());
    }
    let digest =
        compaction_payload_digest(b"CIGAR-SQLITE-V5-VERIFIED-PREFIX-SIGNATURE\0v1\0", &prefix)?;
    let signature = provider
        .sign(SignatureRequest {
            key_ref: identity.signing_key,
            tenant: identity.tenant,
            signer: identity.signer,
            purpose: VERIFIED_PREFIX_PURPOSE_V1,
            payload_digest: digest,
            signed_at,
            expires_at: None,
        })
        .map_err(map_receipt_crypto_error)?;
    Ok(SignedVerifiedPrefixV1 {
        prefix,
        signature: persist_compaction_signature(&signature, identity.tenant),
    })
}

fn verify_signed_prefix_v1<P, F>(
    signed: &SignedVerifiedPrefixV1,
    provider: &P,
    now: i128,
    trust: F,
) -> Result<MigrationReceiptSignatureIdentity, StoreError>
where
    P: KeyProvider,
    F: Fn(&MigrationReceiptSignatureIdentity) -> bool,
{
    validate_verified_prefix_payload_v1(&signed.prefix)?;
    let signature = restore_compaction_signature(&signed.signature)?;
    let identity = MigrationReceiptSignatureIdentity {
        tenant: signed.signature.tenant.clone(),
        signer: signature.signer.clone(),
        signing_key: signature.key_ref.clone(),
        signed_at_unix_nanos: signature.signed_at,
    };
    let verified_at = signed
        .prefix
        .verified_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    let digest = compaction_payload_digest(
        b"CIGAR-SQLITE-V5-VERIFIED-PREFIX-SIGNATURE\0v1\0",
        &signed.prefix,
    )?;
    if signature.purpose != VERIFIED_PREFIX_PURPOSE_V1
        || signature.signed_at != verified_at
        || signature.expires_at.is_some()
        || signature.payload_digest != digest
        || !trust(&identity)
    {
        return Err(invalid_record());
    }
    provider
        .verify(
            &signature,
            SignatureVerification {
                tenant: &identity.tenant,
                signer: &identity.signer,
                purpose: VERIFIED_PREFIX_PURPOSE_V1,
                payload_digest: &digest,
                now,
            },
        )
        .map_err(map_receipt_crypto_error)?;
    Ok(identity)
}

#[cfg(unix)]
fn write_new_private_bytes(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

#[cfg(unix)]
fn publish_verified_prefix_v1(
    path: &Path,
    bytes: &[u8],
    expected: Option<MigrationFileIdentityV5>,
) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_err(|_error| limit_exceeded())?
            > MAX_VERIFIED_PREFIX_BYTES_V1
    {
        return Err(limit_exceeded());
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".cigar-verified-prefix-")
        .tempfile_in(parent)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    match expected {
        Some(identity) if migration_file_identity(path)? == identity => {}
        None => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(StoreError::new(StoreErrorCode::RevisionConflict)),
        },
        Some(_identity) => return Err(StoreError::new(StoreErrorCode::RevisionConflict)),
    }
    temporary
        .persist(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    sync_file_and_parent(path)
}

#[cfg(not(unix))]
fn publish_verified_prefix_v1(
    _path: &Path,
    _bytes: &[u8],
    _expected: Option<MigrationFileIdentityV5>,
) -> Result<(), StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

#[cfg(not(unix))]
fn write_new_private_bytes(_path: &Path, _bytes: &[u8]) -> Result<(), StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

impl MigrationPreflightV5 {
    /// Validated canonical path set.
    #[must_use]
    pub const fn paths(&self) -> &MigrationPathsV5 {
        &self.paths
    }

    /// Frozen authenticated v4 head.
    #[must_use]
    pub const fn source_revision(&self) -> StoreRevision {
        self.source_revision
    }

    /// First retained v4 revision.
    #[must_use]
    pub const fn first_retained_revision(&self) -> StoreRevision {
        self.first_retained_revision
    }

    /// Exact contiguous retained v4 revision count.
    #[must_use]
    pub const fn retained_revisions(&self) -> u64 {
        self.retained_revisions
    }

    /// Frozen source database byte length.
    #[must_use]
    pub const fn source_database_bytes(&self) -> u64 {
        self.source_database_bytes
    }

    /// SHA-256 multihash of exact frozen source database bytes.
    #[must_use]
    pub const fn source_database_digest(&self) -> &ContentDigest {
        &self.source_database_digest
    }

    /// Closed authenticated capacity profile.
    #[must_use]
    pub fn capacity_profile(&self) -> &str {
        &self.capacity_profile
    }

    /// Signed verified-backup inventory root.
    #[must_use]
    pub fn backup_canonical_root(&self) -> &str {
        &self.backup_canonical_root
    }

    /// Checked conservative free-space requirement.
    #[must_use]
    pub const fn required_available_bytes(&self) -> u64 {
        self.required_available_bytes
    }

    /// Available bytes observed on the target filesystem after source authentication.
    #[must_use]
    pub const fn observed_available_bytes(&self) -> u64 {
        self.observed_available_bytes
    }
}

/// Canonical, owner-controlled, non-overlapping paths for one offline v4-to-v5 migration.
///
/// The source and verified backup already exist. The target must not exist and is never created by
/// this validator. Paths are intentionally exposed only to the authorized local administration
/// caller; errors remain content-free.
pub struct MigrationPathsV5 {
    source: PathBuf,
    backup: PathBuf,
    target: PathBuf,
}

impl MigrationPathsV5 {
    /// Resolves and authenticates the three path identities without mutating any of them.
    pub fn resolve(
        source: impl AsRef<Path>,
        backup: impl AsRef<Path>,
        target: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let source = canonical_existing(source.as_ref(), ExistingPathKindV5::File)?;
        let backup = canonical_existing(backup.as_ref(), ExistingPathKindV5::Directory)?;
        let target = canonical_new_file(target.as_ref())?;
        if overlaps(&source, &backup) || overlaps(&source, &target) || overlaps(&backup, &target) {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        validate_backup_tree(&backup)?;
        Ok(Self {
            source,
            backup,
            target,
        })
    }

    /// Canonical existing v4 source database.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Canonical existing verified-backup directory.
    #[must_use]
    pub fn backup(&self) -> &Path {
        &self.backup
    }

    /// Canonical create-new v5 target path.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }
}

/// Authenticates a frozen v4 source and its signed backup before any target is created.
///
/// The backup is cryptographically reverified inside this call. The source and backup databases
/// must have the same retained range, latest checksums/roots/totals, capacity profile, and head.
/// Exact source bytes are hashed while a stable owner-only file identity is checked before and
/// after. Conservative target-space arithmetic never assumes compression or deletion of v4.
pub fn preflight_v4_to_v5_migration<P, F>(
    paths: MigrationPathsV5,
    provider: &P,
    now_unix_nanos: i128,
    trust: F,
) -> Result<MigrationPreflightV5, StoreError>
where
    P: KeyProvider,
    F: Fn(&BackupSignatureIdentity) -> bool,
{
    let exclusive_runtime_lock = acquire_sqlite_runtime_exclusive_lock(paths.source())?;
    let source_before = migration_file_identity(paths.source())?;
    let verified = verify_backup_trusted(paths.backup(), provider, now_unix_nanos, trust)
        .map_err(map_backup_error)?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterBackupVerification);
    let backup_manifest_digest = sha256_file(
        &paths.backup().join("manifest.cbor"),
        MAX_MIGRATION_MANIFEST_BYTES_V5,
    )?;
    let source = authenticate_v4_migration_database(paths.source(), true)?;
    let backup_database = paths.backup().join(BACKUP_DATABASE_FILE);
    let backup = authenticate_v4_migration_database(&backup_database, false)?;
    if verified.manifest.format_version != 2
        || verified.manifest.schema_version != 4
        || verified.manifest.repository_revision != source.latest_revision.0
        || source.capacity_profile != backup.capacity_profile
        || source.first_revision != backup.first_revision
        || source.latest_revision != backup.latest_revision
        || source.retained_revisions != backup.retained_revisions
        || source.residual_checksum != backup.residual_checksum
        || source.catalog_root != backup.catalog_root
        || source.semantic_root != backup.semantic_root
        || source.atom_count != backup.atom_count
        || source.edge_count != backup.edge_count
        || source.referenced_blob_bytes != backup.referenced_blob_bytes
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let maximum_database_bytes = match source.capacity_profile.as_str() {
        "standard" => MAX_SQLITE_DATABASE_BYTES,
        "large_local" => MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES,
        _ => return Err(StoreError::new(StoreErrorCode::InvalidRecord)),
    };
    if source_before.size_bytes > maximum_database_bytes {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let source_database_digest = sha256_file(paths.source(), maximum_database_bytes)?;
    if migration_file_identity(paths.source())? != source_before {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    match fs::symlink_metadata(paths.target()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(StoreError::new(StoreErrorCode::RevisionConflict)),
    }
    let required_available_bytes = migration_required_available_bytes(
        source_before.size_bytes,
        source.capacity_profile.as_str(),
    )?;
    let target_parent = paths
        .target()
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    let observed_available_bytes = available_filesystem_bytes(target_parent)?;
    if observed_available_bytes < required_available_bytes {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    Ok(MigrationPreflightV5 {
        paths,
        _exclusive_runtime_lock: exclusive_runtime_lock,
        source_identity: source_before,
        source_revision: source.latest_revision,
        first_retained_revision: source.first_revision,
        retained_revisions: source.retained_revisions,
        source_database_bytes: source_before.size_bytes,
        source_database_digest,
        capacity_profile: source.capacity_profile,
        backup_canonical_root: verified.manifest.canonical_root,
        backup_manifest_digest,
        required_available_bytes,
        observed_available_bytes,
    })
}

/// Copies a frozen authenticated v4 source into a new file and constructs verified v5 authority.
///
/// The source and signed backup are never mutated. The returned target contains one migration
/// checkpoint for each retained v4 revision, preserves the public semantic/catalog roots and exact
/// revision numbers, removes the redundant v4 whole-state rows, and remains distinct from the
/// active-store descriptor until a later explicit activation operation.
pub fn migrate_v4_to_v5(
    preflight: MigrationPreflightV5,
    applied_at_unix_nanos: u64,
) -> Result<MigrationBuildReportV5, StoreError> {
    if migration_file_identity(preflight.paths.source())? != preflight.source_identity
        || sha256_file(
            preflight.paths.source(),
            maximum_database_bytes(preflight.capacity_profile.as_str())?,
        )? != preflight.source_database_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let source = authenticate_v4_migration_database(preflight.paths.source(), true)?;
    if source.first_revision != preflight.first_retained_revision
        || source.latest_revision != preflight.source_revision
        || source.retained_revisions != preflight.retained_revisions
        || source.capacity_profile != preflight.capacity_profile
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }

    create_private_target(preflight.paths.target())?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterTargetCreation);
    copy_sqlite_database(preflight.paths.source(), preflight.paths.target())?;
    let copied = authenticate_v4_migration_database(preflight.paths.target(), false)?;
    if copied.first_revision != source.first_revision
        || copied.latest_revision != source.latest_revision
        || copied.retained_revisions != source.retained_revisions
        || copied.capacity_profile != source.capacity_profile
        || copied.residual_checksum != source.residual_checksum
        || copied.catalog_root != source.catalog_root
        || copied.semantic_root != source.semantic_root
        || copied.atom_count != source.atom_count
        || copied.edge_count != source.edge_count
        || copied.referenced_blob_bytes != source.referenced_blob_bytes
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let target_profile = match preflight.capacity_profile.as_str() {
        "standard" => SqliteCapacityProfile::Standard,
        "large_local" => SqliteCapacityProfile::LargeLocal,
        _ => return Err(StoreError::new(StoreErrorCode::InvalidRecord)),
    };
    drop(SqliteStore::open_with_capacity_profile(
        preflight.paths.target(),
        target_profile,
    )?);

    let mut target =
        Connection::open_with_flags(preflight.paths.target(), OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(unavailable)?;
    configure_migration_target(&target)?;
    prepare_copied_target_schema_v5(
        &mut target,
        applied_at_unix_nanos,
        preflight.retained_revisions,
    )?;
    let migrated = construct_migrated_repository_v5(
        &mut target,
        preflight.paths.source(),
        preflight.capacity_profile.as_str(),
        applied_at_unix_nanos,
    )?;
    if migrated.first_revision != preflight.first_retained_revision
        || migrated.latest_revision != preflight.source_revision
        || migrated.retained_revisions != preflight.retained_revisions
        || migrated.catalog_root != source.catalog_root
        || migrated.semantic_root != source.semantic_root
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let integrity = target
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(unavailable)?;
    if integrity != "ok" || verify_migrated_repository_v5(&target)? != migrated.retained_revisions {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    target
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(unavailable)?;
    configure_migration_target(&target)?;
    if verify_migrated_repository_v5(&target)? != migrated.retained_revisions {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterDeepVerification);
    drop(target);

    if migration_file_identity(preflight.paths.source())? != preflight.source_identity
        || sha256_file(
            preflight.paths.source(),
            maximum_database_bytes(preflight.capacity_profile.as_str())?,
        )? != preflight.source_database_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    sync_file_and_parent(preflight.paths.target())?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterTargetFsync);
    let anchor = revision_anchor_path_v5(preflight.paths.target())?;
    write_revision_anchor(&anchor, migrated.latest_revision)?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterAnchorPublication);
    let target_before = migration_file_identity(preflight.paths.target())?;
    let target_database_digest = sha256_file(
        preflight.paths.target(),
        maximum_database_bytes(preflight.capacity_profile.as_str())?,
    )?;
    if migration_file_identity(preflight.paths.target())? != target_before {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let receipt = MigrationReceiptV1 {
        schema_version: MIGRATION_RECEIPT_SCHEMA_V1.to_owned(),
        schema_digest: crate::revision_delta::migration_receipt_schema_digest_v1()?,
        created_at_unix_nanos: applied_at_unix_nanos.to_string(),
        tool_name: "cigar".to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        product_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_device: preflight.source_identity.device,
        source_inode: preflight.source_identity.inode,
        source_database_bytes: preflight.source_identity.size_bytes,
        source_database_digest: preflight.source_database_digest.clone(),
        first_retained_revision: migrated.first_revision.0,
        latest_revision: migrated.latest_revision.0,
        retained_revisions: migrated.retained_revisions,
        backup_canonical_root: preflight.backup_canonical_root.clone(),
        backup_manifest_digest: preflight.backup_manifest_digest.clone(),
        target_format_version: 5,
        target_device: target_before.device,
        target_inode: target_before.inode,
        target_database_bytes: target_before.size_bytes,
        target_database_digest: target_database_digest.clone(),
        source_catalog_root: source.catalog_root.clone(),
        source_semantic_root: source.semantic_root.clone(),
        target_catalog_root: migrated.catalog_root.clone(),
        target_semantic_root: migrated.semantic_root.clone(),
        target_chain_head: migrated.chain_head.clone(),
        sqlite_integrity_verified: true,
        v5_chain_verified: true,
        exact_reconstruction_verified: true,
        catalog_projection_verified: true,
        external_blobs_verified: true,
        effect_chain_verified: false,
        failpoint_free_completion: true,
    };
    Ok(MigrationBuildReportV5 {
        first_revision: migrated.first_revision,
        latest_revision: migrated.latest_revision,
        retained_revisions: migrated.retained_revisions,
        checkpoint_bytes: migrated.checkpoint_bytes,
        chain_head: migrated.chain_head,
        catalog_root: migrated.catalog_root,
        semantic_root: migrated.semantic_root,
        target_database_bytes: target_before.size_bytes,
        target_database_digest,
        receipt,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DescriptorPublicationStateV1 {
    identity: MigrationFileIdentityV5,
    digest: ContentDigest,
    descriptor: ActiveStoreDescriptorV1,
}

fn descriptor_publication_state(
    path: &Path,
) -> Result<Option<DescriptorPublicationStateV1>, StoreError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_error) => Err(StoreError::new(StoreErrorCode::Unavailable)),
        Ok(_metadata) => {
            let canonical = canonical_existing(path, ExistingPathKindV5::File)?;
            let (bytes, identity) =
                read_stable_private_file(&canonical, MAX_ACTIVE_STORE_DESCRIPTOR_BYTES_V1)?;
            let descriptor: ActiveStoreDescriptorV1 =
                serde_json::from_slice(&bytes).map_err(|_error| invalid_record())?;
            descriptor.validate()?;
            Ok(Some(DescriptorPublicationStateV1 {
                identity,
                digest: sha256_bytes(&bytes)?,
                descriptor,
            }))
        }
    }
}

fn publish_active_store_descriptor_v1(
    path: &Path,
    descriptor: &ActiveStoreDescriptorV1,
    expected: Option<&DescriptorPublicationStateV1>,
) -> Result<(), StoreError> {
    if descriptor_publication_state(path)?.as_ref() != expected {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    let bytes = serde_json::to_vec(descriptor).map_err(|_error| invalid_record())?;
    if u64::try_from(bytes.len()).map_err(|_error| limit_exceeded())?
        > MAX_ACTIVE_STORE_DESCRIPTOR_BYTES_V1
    {
        return Err(limit_exceeded());
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".cigar-active-store-")
        .tempfile_in(parent)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    }
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if descriptor_publication_state(path)?.as_ref() != expected {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    temporary
        .persist(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    migration_v5_process_abort_if_armed(MigrationV5Failpoint::AfterActivationSwitch);
    sync_file_and_parent(path)
}

fn active_store_descriptor_checksum_v1(
    payload: &ActiveStoreDescriptorPayloadV1,
) -> Result<ContentDigest, StoreError> {
    let bytes = serde_json::to_vec(payload).map_err(|_error| invalid_record())?;
    let mut hash = Sha256::new();
    hash.update(b"CIGAR-ACTIVE-STORE-DESCRIPTOR\0v1\0");
    hash.update(
        u64::try_from(bytes.len())
            .map_err(|_error| limit_exceeded())?
            .to_be_bytes(),
    );
    hash.update(bytes);
    digest_from_sha256(hash)
}

fn verify_active_v5_descriptor(descriptor: &ActiveStoreDescriptorV1) -> Result<(), StoreError> {
    descriptor.validate()?;
    let database = Path::new(&descriptor.payload.database_path);
    let anchor = Path::new(&descriptor.payload.anchor_path);
    let receipt = Path::new(&descriptor.payload.authority_receipt_path);
    let database_identity = migration_file_identity(database)?;
    if database_identity.device != descriptor.payload.database_device
        || database_identity.inode != descriptor.payload.database_inode
        || database_identity.size_bytes != descriptor.payload.database_bytes
        || sha256_file(database, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES)?
            != descriptor.payload.database_digest
        || read_revision_anchor(anchor)? != Some(StoreRevision(descriptor.payload.latest_revision))
        || sha256_file(anchor, 256)? != descriptor.payload.anchor_digest
        || sha256_file(receipt, MAX_MIGRATION_RECEIPT_BYTES_V5)?
            != descriptor.payload.authority_receipt_digest
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    Ok(())
}

fn verify_v5_target_against_receipt(
    path: &Path,
    receipt: &MigrationReceiptV1,
) -> Result<(), StoreError> {
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(unavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(unavailable)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(unavailable)?;
    let authority = connection
        .query_row(
            "SELECT current_revision, chain_head, catalog_root, semantic_root
             FROM repository_authority_v5
             WHERE singleton = 1 AND format_version = 5 AND activated = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(unavailable)?;
    if integrity != "ok"
        || verify_migrated_repository_v5(&connection)? != receipt.retained_revisions
        || u64::try_from(authority.0).ok() != Some(receipt.latest_revision)
        || authority.1 != receipt.target_chain_head.as_str()
        || authority.2 != receipt.target_catalog_root.as_str()
        || authority.3 != receipt.target_semantic_root.as_str()
    {
        return Err(invalid_record());
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, StoreError> {
    path.to_str()
        .filter(|value| !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))
}

fn migration_receipt_path_v5(database: &Path) -> Result<PathBuf, StoreError> {
    let mut value = database.as_os_str().to_os_string();
    value.push(".cigar-migration-receipt.json");
    let path = PathBuf::from(value);
    if path.parent() != database.parent() {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(path)
}

fn compaction_receipt_path_v5(database: &Path) -> Result<PathBuf, StoreError> {
    appended_database_path_v5(database, ".cigar-compaction-receipt.json")
}

fn verified_prefix_path_v5(database: &Path) -> Result<PathBuf, StoreError> {
    appended_database_path_v5(database, ".cigar-verified-prefix.json")
}

fn appended_database_path_v5(database: &Path, suffix: &str) -> Result<PathBuf, StoreError> {
    let mut value = database.as_os_str().to_os_string();
    value.push(suffix);
    let path = PathBuf::from(value);
    if path.parent() != database.parent() {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(path)
}

fn sqlite_runtime_lock_path_v5(database: &Path) -> Result<PathBuf, StoreError> {
    appended_database_path_v5(database, ".cigar-runtime.lock")
}

fn migration_target_artifacts(database: &Path) -> Result<Vec<PathBuf>, StoreError> {
    Ok(vec![
        appended_database_path_v5(database, "-wal")?,
        appended_database_path_v5(database, "-shm")?,
        appended_database_path_v5(database, "-journal")?,
        revision_anchor_path_v5(database)?,
        database.to_path_buf(),
    ])
}

fn maximum_database_bytes(capacity_profile: &str) -> Result<u64, StoreError> {
    match capacity_profile {
        "standard" => Ok(MAX_SQLITE_DATABASE_BYTES),
        "large_local" => Ok(MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES),
        _ => Err(StoreError::new(StoreErrorCode::InvalidRecord)),
    }
}

#[cfg(unix)]
fn create_private_target(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

#[cfg(not(unix))]
fn create_private_target(_path: &Path) -> Result<(), StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

fn copy_sqlite_database(source_path: &Path, target_path: &Path) -> Result<(), StoreError> {
    let source = Connection::open_with_flags(source_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    source
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    source
        .execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED;")
        .map_err(unavailable)?;
    let mut target = Connection::open_with_flags(target_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(unavailable)?;
    {
        let backup = Backup::new(&source, &mut target).map_err(unavailable)?;
        backup
            .run_to_completion(256, std::time::Duration::from_millis(1), None)
            .map_err(unavailable)?;
    }
    source.execute_batch("COMMIT").map_err(unavailable)?;
    drop(target);
    drop(source);
    sync_file_and_parent(target_path)
}

fn configure_migration_target(connection: &Connection) -> Result<(), StoreError> {
    connection
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    let journal_mode = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || !connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(unavailable)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

fn sync_file_and_parent(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

fn revision_anchor_path_v5(database: &Path) -> Result<PathBuf, StoreError> {
    let mut value = database.as_os_str().to_os_string();
    value.push(".cigar-revision");
    let path = PathBuf::from(value);
    if path.parent() != database.parent() {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(path)
}

fn map_backup_error(error: crate::BackupError) -> StoreError {
    match error.code() {
        BackupErrorCode::Unavailable | BackupErrorCode::KeyUnavailable => {
            StoreError::new(StoreErrorCode::Unavailable)
        }
        BackupErrorCode::LimitExceeded => StoreError::new(StoreErrorCode::LimitExceeded),
        BackupErrorCode::InvalidMetadata
        | BackupErrorCode::Corrupt
        | BackupErrorCode::DestinationNotEmpty
        | BackupErrorCode::UntrustedSigner
        | BackupErrorCode::InjectedAbort => StoreError::new(StoreErrorCode::InvalidRecord),
    }
}

fn validate_receipt_identity(tenant: &str, signer: &str) -> Result<(), StoreError> {
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 256
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    if valid(tenant) && valid(signer) {
        Ok(())
    } else {
        Err(invalid_record())
    }
}

fn migration_receipt_payload_digest(receipt: &MigrationReceiptV1) -> Result<[u8; 32], StoreError> {
    let bytes = serde_json::to_vec(receipt).map_err(|_error| invalid_record())?;
    let mut hash = Sha256::new();
    hash.update(b"CIGAR-SQLITE-V4-V5-MIGRATION-RECEIPT-SIGNATURE\0v1\0");
    hash.update(
        u64::try_from(bytes.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(hash.finalize().into())
}

fn persist_migration_receipt_signature(
    signature: &SignatureEnvelope,
    tenant: &str,
) -> PersistedMigrationReceiptSignature {
    PersistedMigrationReceiptSignature {
        algorithm: "ed25519".to_owned(),
        key_ref: signature.key_ref.as_str().to_owned(),
        tenant: tenant.to_owned(),
        signer: signature.signer.clone(),
        purpose: signature.purpose.clone(),
        signed_at_unix_nanos: signature.signed_at.to_string(),
        payload_digest_hex: encode_hex(&signature.payload_digest),
        signature_hex: encode_hex(&signature.signature),
    }
}

fn restore_migration_receipt_signature(
    persisted: &PersistedMigrationReceiptSignature,
) -> Result<SignatureEnvelope, StoreError> {
    let signed_at = persisted
        .signed_at_unix_nanos
        .parse::<i128>()
        .map_err(|_error| invalid_record())?;
    if persisted.algorithm != "ed25519"
        || signed_at < 0
        || persisted.signed_at_unix_nanos != signed_at.to_string()
    {
        return Err(invalid_record());
    }
    Ok(SignatureEnvelope {
        algorithm: KeyAlgorithm::Ed25519,
        key_ref: KeyRef::new(persisted.key_ref.clone()).map_err(|_error| invalid_record())?,
        signer: persisted.signer.clone(),
        purpose: persisted.purpose.clone(),
        signed_at,
        expires_at: None,
        payload_digest: decode_hex::<32>(&persisted.payload_digest_hex)?,
        signature: decode_hex::<64>(&persisted.signature_hex)?,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], StoreError> {
    if value.len() != N.saturating_mul(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(invalid_record());
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index
            .checked_mul(2)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        *byte = u8::from_str_radix(
            value.get(offset..offset + 2).ok_or_else(invalid_record)?,
            16,
        )
        .map_err(|_error| invalid_record())?;
    }
    Ok(output)
}

fn map_receipt_crypto_error(_error: cigar_crypto::CryptoError) -> StoreError {
    StoreError::new(StoreErrorCode::Unavailable)
}

fn migration_required_available_bytes(
    source_database_bytes: u64,
    capacity_profile: &str,
) -> Result<u64, StoreError> {
    let (wal_headroom, runtime_reserve) = match capacity_profile {
        "standard" => (
            STANDARD_MIGRATION_WAL_HEADROOM_BYTES_V5,
            STANDARD_MIGRATION_RUNTIME_RESERVE_BYTES_V5,
        ),
        "large_local" => (
            LARGE_LOCAL_MIGRATION_WAL_HEADROOM_BYTES_V5,
            MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES,
        ),
        _ => return Err(StoreError::new(StoreErrorCode::InvalidRecord)),
    };
    source_database_bytes
        .checked_mul(2)
        .and_then(|value| {
            value.checked_add(
                u64::try_from(crate::revision_delta::MAX_REPOSITORY_CHECKPOINT_BYTES_V5).ok()?,
            )
        })
        .and_then(|value| {
            value.checked_add(
                u64::try_from(crate::revision_delta::MAX_ACCUMULATED_DELTA_BYTES_V5).ok()?,
            )
        })
        .and_then(|value| value.checked_add(wal_headroom))
        .and_then(|value| value.checked_add(MIGRATION_RECEIPT_HEADROOM_BYTES_V5))
        .and_then(|value| value.checked_add(runtime_reserve))
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn sha256_file(path: &Path, maximum_bytes: u64) -> Result<ContentDigest, StoreError> {
    let mut file =
        File::open(path).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; MIGRATION_COPY_BUFFER_BYTES_V5];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
            )
            .filter(|value| *value <= maximum_bytes)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        hash.update(
            buffer
                .get(..read)
                .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?,
        );
    }
    digest_from_sha256(hash)
}

fn sha256_bytes(bytes: &[u8]) -> Result<ContentDigest, StoreError> {
    let mut hash = Sha256::new();
    hash.update(bytes);
    digest_from_sha256(hash)
}

fn digest_from_sha256(hash: Sha256) -> Result<ContentDigest, StoreError> {
    let suffix = hash.finalize();
    let mut value = String::from("1220");
    for byte in suffix {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| invalid_record())?;
    }
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

fn read_stable_private_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<(Vec<u8>, MigrationFileIdentityV5), StoreError> {
    let before = migration_file_identity(path)?;
    if before.size_bytes == 0 || before.size_bytes > maximum_bytes {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let file = File::open(path).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.size_bytes)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
    );
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if u64::try_from(bytes.len()).map_err(|_error| limit_exceeded())? != before.size_bytes
        || migration_file_identity(path)? != before
    {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    Ok((bytes, before))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MigrationFileIdentityV5 {
    device: u64,
    inode: u64,
    size_bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[cfg(unix)]
fn migration_file_identity(path: &Path) -> Result<MigrationFileIdentityV5, StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(MigrationFileIdentityV5 {
        device: metadata.dev(),
        inode: metadata.ino(),
        size_bytes: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

#[cfg(not(unix))]
fn migration_file_identity(_path: &Path) -> Result<MigrationFileIdentityV5, StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

#[cfg(unix)]
fn available_filesystem_bytes(path: &Path) -> Result<u64, StoreError> {
    let statistics =
        rustix::fs::statvfs(path).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    statistics
        .f_bavail
        .checked_mul(statistics.f_frsize)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))
}

#[cfg(not(unix))]
fn available_filesystem_bytes(_path: &Path) -> Result<u64, StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

#[derive(Clone, Copy)]
enum ExistingPathKindV5 {
    File,
    Directory,
}

fn has_lexically_safe_absolute_components(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn canonical_existing(path: &Path, kind: ExistingPathKindV5) -> Result<PathBuf, StoreError> {
    if !has_lexically_safe_absolute_components(path) {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    let canonical =
        fs::canonicalize(path).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if canonical != path {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if metadata.file_type().is_symlink()
        || match kind {
            ExistingPathKindV5::File => !metadata.is_file(),
            ExistingPathKindV5::Directory => !metadata.is_dir(),
        }
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    validate_owner_mode(path, &metadata, kind)?;
    Ok(canonical)
}

fn canonical_new_file(path: &Path) -> Result<PathBuf, StoreError> {
    if !has_lexically_safe_absolute_components(path) || path.file_name().is_none() {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(StoreError::new(StoreErrorCode::InvalidContext)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    let canonical_parent = canonical_existing(parent, ExistingPathKindV5::Directory)?;
    let canonical = canonical_parent.join(
        path.file_name()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?,
    );
    if canonical != path {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(canonical)
}

fn canonical_existing_or_new_file(path: &Path) -> Result<PathBuf, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(_metadata) => canonical_existing(path, ExistingPathKindV5::File),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => canonical_new_file(path),
        Err(_error) => Err(StoreError::new(StoreErrorCode::Unavailable)),
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn validate_backup_tree(root: &Path) -> Result<(), StoreError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
        {
            visited = visited
                .checked_add(1)
                .filter(|count| *count <= MAX_MIGRATION_BACKUP_ENTRIES_V5)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            let path = entry
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
                .path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
            if metadata.file_type().is_symlink() {
                return Err(StoreError::new(StoreErrorCode::InvalidContext));
            }
            if metadata.is_dir() {
                validate_owner_mode(&path, &metadata, ExistingPathKindV5::Directory)?;
                pending.push(path);
            } else if metadata.is_file() {
                validate_owner_mode(&path, &metadata, ExistingPathKindV5::File)?;
            } else {
                return Err(StoreError::new(StoreErrorCode::InvalidContext));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner_mode(
    _path: &Path,
    metadata: &fs::Metadata,
    kind: ExistingPathKindV5,
) -> Result<(), StoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let expected_mode = match kind {
        ExistingPathKindV5::File => 0o600,
        ExistingPathKindV5::Directory => 0o700,
    };
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != expected_mode
        || (matches!(kind, ExistingPathKindV5::File) && metadata.nlink() != 1)
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _kind: ExistingPathKindV5,
) -> Result<(), StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

fn invalid_record() -> StoreError {
    StoreError::new(StoreErrorCode::InvalidRecord)
}

fn limit_exceeded() -> StoreError {
    StoreError::new(StoreErrorCode::LimitExceeded)
}

fn unavailable(_error: rusqlite::Error) -> StoreError {
    StoreError::new(StoreErrorCode::Unavailable)
}

fn schema_digest() -> Result<ContentDigest, StoreError> {
    let suffix = Sha256::digest(SQLITE_FRESH_TARGET_SCHEMA_V5.as_bytes());
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    for byte in suffix {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| invalid_record())?;
    }
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

/// Adds the v5 schema and immutable ledger row only to an empty distinct migration target.
///
/// The caller must first create and close a new v4-compatible SQLite store at the target path.
/// A source with any revision beyond genesis, any normalized catalog rows, an unexpected ledger,
/// or an existing v5 table is rejected before schema mutation. This function never attaches,
/// rewrites, truncates, or deletes a v4 source database.
pub fn prepare_fresh_target_schema_v5(
    connection: &mut Connection,
    applied_at_unix_nanos: u64,
) -> Result<ContentDigest, StoreError> {
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let existing_v5: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN (
                 'repository_authority_v5',
                 'repository_revisions_v5',
                 'repository_checkpoints_v5',
                 'repository_deltas_v5',
                 'repository_retention_pins_v5'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    let ledger: (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(sequence), 0) FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    let authority: (i64, i64) = transaction
        .query_row(
            "SELECT format_version, activated FROM cigar_catalog_authority WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    let revisions: (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(revision), -1)
             FROM cigar_repository_revisions_v4",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    let catalog_rows: i64 = transaction
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM cigar_catalog_atoms) +
                (SELECT COUNT(*) FROM cigar_catalog_edges)",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if existing_v5 != 0
        || ledger != (4, 4)
        || authority != (4, 1)
        || revisions != (1, 0)
        || catalog_rows != 0
    {
        return Err(invalid_record());
    }
    transaction
        .execute_batch(SQLITE_FRESH_TARGET_SCHEMA_V5)
        .map_err(unavailable)?;
    let checksum = schema_digest()?;
    transaction
        .execute(
            "INSERT INTO schema_migrations
                (sequence, name, checksum, applied_at_unix_nanos,
                 minimum_application_major, maximum_application_major, online)
             VALUES (5, 'incremental_repository_state', ?1, ?2, 1, 1, 0)",
            params![checksum.as_str(), applied_at_unix_nanos.to_string()],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    Ok(checksum)
}

fn prepare_copied_target_schema_v5(
    connection: &mut Connection,
    applied_at_unix_nanos: u64,
    expected_v4_revisions: u64,
) -> Result<ContentDigest, StoreError> {
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let existing_v5: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN (
                 'repository_authority_v5',
                 'repository_revisions_v5',
                 'repository_checkpoints_v5',
                 'repository_deltas_v5',
                 'repository_retention_pins_v5'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    let ledger: (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(sequence), 0) FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    let authority: (i64, i64) = transaction
        .query_row(
            "SELECT format_version, activated FROM cigar_catalog_authority WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    let revisions: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM cigar_repository_revisions_v4",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if existing_v5 != 0
        || ledger != (4, 4)
        || authority != (4, 1)
        || u64::try_from(revisions).ok() != Some(expected_v4_revisions)
        || expected_v4_revisions == 0
    {
        return Err(invalid_record());
    }
    transaction
        .execute_batch(SQLITE_FRESH_TARGET_SCHEMA_V5)
        .map_err(unavailable)?;
    let checksum = schema_digest()?;
    transaction
        .execute(
            "INSERT INTO schema_migrations
                (sequence, name, checksum, applied_at_unix_nanos,
                 minimum_application_major, maximum_application_major, online)
             VALUES (5, 'incremental_repository_state', ?1, ?2, 1, 1, 0)",
            params![checksum.as_str(), applied_at_unix_nanos.to_string()],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    Ok(checksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BackupIdentity, ServiceExpectedVersion, ServiceRepository, SqliteStore, WorkerLocator,
        WorkerUpdate, create_backup_with_effect_checkpoint,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider,
    };
    use cigar_protocol::RecordId;

    #[cfg(unix)]
    fn private_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::OpenOptionsExt as _;

        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn migration_paths_require_canonical_private_distinct_link_free_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source.sqlite3");
        drop(SqliteStore::open(&source)?);
        let backup = root.join("verified-backup");
        fs::create_dir(&backup)?;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o700))?;
        private_file(&backup.join("manifest.cbor"))?;
        let target = root.join("target.sqlite3");

        let resolved = MigrationPathsV5::resolve(&source, &backup, &target)?;
        assert_eq!(resolved.source(), source);
        assert_eq!(resolved.backup(), backup);
        assert_eq!(resolved.target(), target);

        assert_eq!(
            MigrationPathsV5::resolve("relative.sqlite3", &backup, &target)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidContext)
        );
        assert_eq!(
            MigrationPathsV5::resolve(&source, &backup, backup.join("nested.sqlite3"))
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidContext)
        );

        private_file(&target)?;
        assert_eq!(
            MigrationPathsV5::resolve(&source, &backup, &target)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidContext)
        );
        fs::remove_file(&target)?;

        let outside = root.join("outside");
        private_file(&outside)?;
        std::os::unix::fs::symlink(&outside, backup.join("substituted"))?;
        assert_eq!(
            MigrationPathsV5::resolve(&source, &backup, &target)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidContext)
        );
        fs::remove_file(backup.join("substituted"))?;

        fs::set_permissions(
            backup.join("manifest.cbor"),
            fs::Permissions::from_mode(0o640),
        )?;
        assert_eq!(
            MigrationPathsV5::resolve(&source, &backup, &target)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::InvalidContext)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preflight_reverifies_backup_freezes_source_and_rejects_head_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source.sqlite3");
        let store = SqliteStore::open(&source)?;
        let blob_root = root.join("blobs");
        fs::create_dir(&blob_root)?;
        let provider = MemoryKeyProvider::default();
        let signing = provider.create(CreateKeyRequest {
            tenant: "migration-tenant".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let backup = root.join("verified-backup");
        let manifest = create_backup_with_effect_checkpoint(
            &store,
            &blob_root,
            &backup,
            &provider,
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
                created_at_unix_nanos: 2,
            },
            |_database, checkpoint| {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(checkpoint)
                    .map_err(|_error| BackupErrorCode::Unavailable)?;
                file.write_all(b"migration-checkpoint")
                    .map_err(|_error| BackupErrorCode::Unavailable)?;
                file.sync_all()
                    .map_err(|_error| BackupErrorCode::Unavailable)
            },
        )?;
        assert_eq!(manifest.format_version, 2);
        let target = root.join("target.sqlite3");
        assert_eq!(
            preflight_v4_to_v5_migration(
                MigrationPathsV5::resolve(&source, &backup, &target)?,
                &provider,
                3,
                |_identity| true,
            )
            .err()
            .map(|error| error.code()),
            Some(StoreErrorCode::RevisionConflict)
        );
        drop(store);
        let preflight = preflight_v4_to_v5_migration(
            MigrationPathsV5::resolve(&source, &backup, &target)?,
            &provider,
            3,
            |identity| {
                identity.tenant == "migration-tenant" && identity.signer == "migration-operator"
            },
        )?;
        assert_eq!(preflight.source_revision(), StoreRevision(0));
        assert_eq!(preflight.first_retained_revision(), StoreRevision(0));
        assert_eq!(preflight.retained_revisions(), 1);
        assert_eq!(preflight.capacity_profile(), "standard");
        assert_eq!(preflight.backup_canonical_root(), manifest.canonical_root);
        assert!(preflight.required_available_bytes() <= preflight.observed_available_bytes());
        assert!(!target.exists());
        let migrated = migrate_v4_to_v5(preflight, 4)?;
        assert_eq!(migrated.first_revision, StoreRevision(0));
        assert_eq!(migrated.latest_revision, StoreRevision(0));
        assert_eq!(migrated.retained_revisions, 1);
        assert!(migrated.checkpoint_bytes > 0);
        assert!(migrated.target_database_bytes > 0);
        let signed_receipt = sign_migration_receipt_v1(
            migrated.completed_receipt(),
            &provider,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
        )?;
        let identity = verify_migration_receipt_v1(&signed_receipt, &provider, 5, |candidate| {
            candidate.tenant == "migration-tenant" && candidate.signer == "migration-operator"
        })?;
        assert_eq!(&identity.signing_key, &signing.key_ref);
        let receipt_json = serde_json::to_vec(&signed_receipt)?;
        let decoded: SignedMigrationReceiptV1 = serde_json::from_slice(&receipt_json)?;
        assert_eq!(decoded, signed_receipt);
        let receipt_path = migration_receipt_path_v5(&target)?;
        let mut receipt_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&receipt_path)?;
        receipt_file.write_all(&receipt_json)?;
        receipt_file.sync_all()?;
        drop(receipt_file);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/vectors/sqlite-v4-v5-migration-receipt-v1.json"
        ))?;
        let valid_vector = vectors.get("valid").ok_or("valid vector")?;
        let invalid_vectors = vectors
            .get("invalid")
            .and_then(serde_json::Value::as_array)
            .ok_or("invalid vectors")?;
        assert_eq!(
            valid_vector
                .get("receipt")
                .and_then(|receipt| receipt.get("retained_revisions"))
                .and_then(serde_json::Value::as_u64),
            Some(1_024)
        );
        assert_eq!(invalid_vectors.len(), 6);
        let vector_receipt: SignedMigrationReceiptV1 =
            serde_json::from_value(valid_vector.clone())?;
        vector_receipt.receipt.validate()?;
        for probe in invalid_vectors {
            let mut candidate = valid_vector.clone();
            let pointer = probe
                .get("pointer")
                .and_then(serde_json::Value::as_str)
                .ok_or("vector pointer")?;
            let probe_name = probe
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or("vector name")?;
            let replacement = probe.get("replacement").ok_or("vector replacement")?;
            if probe_name == "unknown_field" {
                candidate
                    .get_mut("receipt")
                    .ok_or("receipt value")?
                    .as_object_mut()
                    .ok_or("receipt object")?
                    .insert("additional_property".to_owned(), replacement.clone());
                assert!(serde_json::from_value::<SignedMigrationReceiptV1>(candidate).is_err());
                continue;
            }
            *candidate.pointer_mut(pointer).ok_or("vector target")? = replacement.clone();
            let candidate: SignedMigrationReceiptV1 = serde_json::from_value(candidate)?;
            if probe_name == "bad_signature_purpose" {
                assert_ne!(
                    candidate.signature.purpose,
                    MIGRATION_RECEIPT_SIGNATURE_PURPOSE_V1
                );
            } else {
                assert!(candidate.receipt.validate().is_err());
            }
        }
        let mut unknown: serde_json::Value = serde_json::from_slice(&receipt_json)?;
        unknown
            .as_object_mut()
            .ok_or("receipt object")?
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SignedMigrationReceiptV1>(unknown).is_err());
        let mut wrong_purpose = signed_receipt.clone();
        wrong_purpose.signature.purpose = "backup-manifest-v1".to_owned();
        assert!(
            verify_migration_receipt_v1(&wrong_purpose, &provider, 5, |_candidate| true).is_err()
        );
        let mut incomplete = migrated.completed_receipt();
        incomplete.effect_chain_verified = false;
        assert!(
            sign_migration_receipt_v1(
                incomplete,
                &provider,
                MigrationReceiptIdentity {
                    signing_key: &signing.key_ref,
                    tenant: "migration-tenant",
                    signer: "migration-operator",
                },
            )
            .is_err()
        );
        let authority_schema_digest: String = Connection::open(&target)?.query_row(
            "SELECT migration_receipt_schema_digest FROM repository_authority_v5 WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            authority_schema_digest,
            crate::revision_delta::migration_receipt_schema_digest_v1()?.as_str()
        );
        let retained = SqliteStore::v5_retention_statistics_at(&target)?;
        assert_eq!(retained.current_revision, StoreRevision(0));
        assert_eq!(retained.retained_revisions, 1);

        let descriptor_path = root.join("active-store.json");
        let activation = activate_v5_migration(
            MigrationActivationPathsV5::resolve(
                &source,
                &backup,
                &target,
                &receipt_path,
                &descriptor_path,
            )?,
            &provider,
            5,
            |candidate| {
                candidate.tenant == "migration-tenant" && candidate.signer == "migration-operator"
            },
            |candidate| {
                candidate.tenant == "migration-tenant"
                    && candidate.signer == "migration-operator"
                    && candidate.signing_key == signing.key_ref
            },
        )?;
        assert_eq!(activation.generation, 1);
        assert_eq!(activation.latest_revision, StoreRevision(0));
        let descriptor = read_active_store_descriptor_v1(&descriptor_path)?;
        assert_eq!(descriptor.generation(), 1);
        assert_eq!(descriptor.database_path(), target.to_str().ok_or("target")?);
        assert_eq!(descriptor.checksum(), &activation.descriptor_checksum);
        let second_activation = activate_v5_migration(
            MigrationActivationPathsV5::resolve(
                &source,
                &backup,
                &target,
                &receipt_path,
                &descriptor_path,
            )?,
            &provider,
            6,
            |_candidate| true,
            |_candidate| true,
        )?;
        assert_eq!(second_activation.generation, 2);
        assert_eq!(
            read_active_store_descriptor_v1(&descriptor_path)?.generation(),
            2
        );
        assert_eq!(
            cleanup_incomplete_v5_target(
                MigrationCleanupPathsV5::resolve(&source, &backup, &target, &descriptor_path,)?,
                &provider,
                7,
                |_candidate| true,
            )
            .err()
            .map(|error| error.code()),
            Some(StoreErrorCode::RevisionConflict)
        );
        let incomplete_target = root.join("incomplete-target.sqlite3");
        private_file(&incomplete_target)?;
        let cleanup = cleanup_incomplete_v5_target(
            MigrationCleanupPathsV5::resolve(
                &source,
                &backup,
                &incomplete_target,
                &descriptor_path,
            )?,
            &provider,
            7,
            |_candidate| true,
        )?;
        assert_eq!(cleanup.source_revision, StoreRevision(0));
        assert!(cleanup.removed_files >= 2);
        assert!(!incomplete_target.exists());

        let store = SqliteStore::open(&source)?;
        let locator = WorkerLocator::new(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f78f1")?,
            "worker",
        )?;
        store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "test".to_owned(),
                now_unix_nanos: 1,
                expires_at_unix_nanos: 10,
            },
            &crate::CancellationToken::default(),
        )?;
        drop(store);
        let drift_target = root.join("drift-target.sqlite3");
        assert_eq!(
            preflight_v4_to_v5_migration(
                MigrationPathsV5::resolve(&source, &backup, &drift_target)?,
                &provider,
                3,
                |_identity| true,
            )
            .err()
            .map(|error| error.code()),
            Some(StoreErrorCode::InvalidRecord)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn migration_preserves_a_pruned_nonzero_retained_range()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source.sqlite3");
        let store = SqliteStore::open(&source)?;
        let locator = WorkerLocator::new(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f78f2")?,
            "migration-worker",
        )?;
        store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "migration-test".to_owned(),
                now_unix_nanos: 1,
                expires_at_unix_nanos: 1_000,
            },
            &crate::CancellationToken::default(),
        )?;
        for version in 2_u64..=1_028 {
            store.worker_update(
                &locator,
                WorkerUpdate::Checkpoint {
                    expected: ServiceExpectedVersion::Version(version - 1),
                    owner: "migration-test".to_owned(),
                    fencing_token: 1,
                    cursor: version.to_be_bytes().to_vec(),
                    heartbeat_unix_nanos: version,
                    expires_at_unix_nanos: 1_000 + version,
                },
                &crate::CancellationToken::default(),
            )?;
        }
        assert_eq!(store.revision()?, StoreRevision(1_028));

        let blob_root = root.join("blobs");
        fs::create_dir(&blob_root)?;
        let provider = MemoryKeyProvider::default();
        let signing = provider.create(CreateKeyRequest {
            tenant: "migration-tenant".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let backup = root.join("verified-backup");
        create_backup_with_effect_checkpoint(
            &store,
            &blob_root,
            &backup,
            &provider,
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
                created_at_unix_nanos: 2,
            },
            |_database, checkpoint| {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(checkpoint)
                    .map_err(|_error| BackupErrorCode::Unavailable)?;
                file.write_all(b"migration-checkpoint")
                    .and_then(|()| file.sync_all())
                    .map_err(|_error| BackupErrorCode::Unavailable)
            },
        )?;
        drop(store);

        let target = root.join("target.sqlite3");
        let preflight = preflight_v4_to_v5_migration(
            MigrationPathsV5::resolve(&source, &backup, &target)?,
            &provider,
            3,
            |_identity| true,
        )?;
        assert_eq!(preflight.first_retained_revision(), StoreRevision(5));
        assert_eq!(preflight.source_revision(), StoreRevision(1_028));
        assert_eq!(preflight.retained_revisions(), 1_024);
        let migrated = migrate_v4_to_v5(preflight, 4)?;
        assert_eq!(migrated.first_revision, StoreRevision(5));
        assert_eq!(migrated.latest_revision, StoreRevision(1_028));
        assert_eq!(migrated.retained_revisions, 1_024);
        let retained = SqliteStore::v5_retention_statistics_at(&target)?;
        assert_eq!(retained.reconstructable_first_revision, StoreRevision(5));
        assert_eq!(retained.reconstructable_last_revision, StoreRevision(1_028));
        assert_eq!(retained.retained_checkpoints, 1_024);
        assert_eq!(retained.retained_deltas, 0);
        let signed_migration_receipt = sign_migration_receipt_v1(
            migrated.completed_receipt(),
            &provider,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
        )?;
        let migration_receipt_path = migration_receipt_path_v5(&target)?;
        write_new_private_bytes(
            &migration_receipt_path,
            &serde_json::to_vec(&signed_migration_receipt)?,
        )?;
        let descriptor_path = root.join("active-store.json");
        activate_v5_migration(
            MigrationActivationPathsV5::resolve(
                &source,
                &backup,
                &target,
                &migration_receipt_path,
                &descriptor_path,
            )?,
            &provider,
            5,
            |_identity| true,
            |_identity| true,
        )?;
        let compacted_target = root.join("compacted.sqlite3");
        let preview_path = root.join("compaction-preview.json");
        let signed_preview = create_revision_compaction_preview_v1(
            RevisionCompactionPathsV1::resolve(
                &target,
                &migration_receipt_path,
                &compacted_target,
                &descriptor_path,
                &preview_path,
            )?,
            &provider,
            6,
            100,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
            |_identity| true,
        )?;
        assert_eq!(signed_preview.preview.current_first_revision, 5);
        assert_eq!(signed_preview.preview.compacted_first_revision, 773);
        assert_eq!(signed_preview.preview.candidate_last_revision, 772);
        assert_eq!(signed_preview.preview.candidate_revisions, 768);
        assert_eq!(signed_preview.preview.retained_revisions, 256);
        let original_chain_head = signed_preview.preview.chain_head.clone();
        write_new_private_bytes(&preview_path, &serde_json::to_vec(&signed_preview)?)?;
        let compacted_report = execute_revision_compaction_v1(
            &preview_path,
            &provider,
            7,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
            |_identity| true,
        )?;
        assert_eq!(compacted_report.removed_revisions, 768);
        assert_eq!(compacted_report.retained_revisions, 256);
        assert_eq!(
            compacted_report.compacted_first_revision,
            StoreRevision(773)
        );
        assert_eq!(
            read_active_store_descriptor_v1(&descriptor_path)?.database_path(),
            compacted_target.to_str().ok_or("compacted target")?
        );
        let compacted_statistics = SqliteStore::v5_retention_statistics_at(&compacted_target)?;
        assert_eq!(
            compacted_statistics.reconstructable_first_revision,
            StoreRevision(773)
        );
        assert_eq!(compacted_statistics.retained_revisions, 256);
        assert_eq!(compacted_statistics.chain_head, original_chain_head);
        let compacted = open_v5_read_only(&compacted_target)?;
        assert_eq!(
            crate::sqlite_v5::preview_repository_compaction_v5(&compacted)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::NotFound)
        );
        drop(compacted);
        let restarted = open_v5_read_only(&compacted_target)?;
        let readiness = crate::sqlite_v5::bounded_startup_verification_v5(&restarted)?;
        assert_eq!(readiness.current_revision, StoreRevision(1_028));
        assert_eq!(readiness.retained_revisions, 256);
        assert!(readiness.replayed_deltas <= 64);
        drop(restarted);
        let deep = verify_v5_deep_integrity_with_prefix_v1(
            &compacted_target,
            &provider,
            8,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
            |_identity| true,
            false,
        )?;
        assert!(!deep.prefix_reused);
        assert_eq!(deep.integrity.verified_revisions, 256);
        let incremental = verify_v5_deep_integrity_with_prefix_v1(
            &compacted_target,
            &provider,
            9,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
            |_identity| true,
            false,
        )?;
        assert!(incremental.prefix_reused);
        assert_eq!(incremental.integrity.verified_revisions, 0);
        let forced = verify_v5_deep_integrity_with_prefix_v1(
            &compacted_target,
            &provider,
            10,
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
            |_identity| true,
            true,
        )?;
        assert!(forced.force_full);
        assert!(!forced.prefix_reused);
        assert_eq!(forced.integrity.verified_revisions, 256);
        let mut tampered = fs::read(&forced.prefix_path)?;
        let last = tampered.last_mut().ok_or("empty prefix")?;
        *last ^= 1;
        fs::write(&forced.prefix_path, tampered)?;
        assert!(
            verify_v5_deep_integrity_with_prefix_v1(
                &compacted_target,
                &provider,
                11,
                MigrationReceiptIdentity {
                    signing_key: &signing.key_ref,
                    tenant: "migration-tenant",
                    signer: "migration-operator",
                },
                |_identity| true,
                false,
            )
            .is_err()
        );
        assert!(
            verify_v5_deep_integrity_with_prefix_v1(
                &compacted_target,
                &provider,
                12,
                MigrationReceiptIdentity {
                    signing_key: &signing.key_ref,
                    tenant: "migration-tenant",
                    signer: "migration-operator",
                },
                |_identity| true,
                true,
            )
            .is_ok()
        );
        assert_eq!(
            SqliteStore::open(&source)?.revision()?,
            StoreRevision(1_028)
        );
        assert!(SqliteStore::open(&target).is_err());
        Ok(())
    }

    #[test]
    fn preparation_accepts_only_a_clean_distinct_target() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("fresh-target.sqlite3");
        drop(SqliteStore::open(&path)?);
        let mut connection = Connection::open(&path)?;
        let checksum = prepare_fresh_target_schema_v5(&mut connection, 7)?;
        let ledger: (String, String) = connection.query_row(
            "SELECT name, checksum FROM schema_migrations WHERE sequence = 5",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(
            ledger,
            (
                "incremental_repository_state".to_owned(),
                checksum.as_str().to_owned()
            )
        );
        assert_eq!(
            prepare_fresh_target_schema_v5(&mut connection, 8).map_err(|error| error.code()),
            Err(StoreErrorCode::InvalidRecord)
        );
        Ok(())
    }

    #[test]
    fn preparation_rejects_a_v4_database_with_user_state_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.sqlite3");
        let store = SqliteStore::open(&path)?;
        let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f78f1")?;
        let locator = WorkerLocator::new(tenant, "worker")?;
        store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "test".to_owned(),
                now_unix_nanos: 1,
                expires_at_unix_nanos: 10,
            },
            &crate::CancellationToken::default(),
        )?;
        drop(store);
        let mut connection = Connection::open(&path)?;
        assert_eq!(
            prepare_fresh_target_schema_v5(&mut connection, 7).map_err(|error| error.code()),
            Err(StoreErrorCode::InvalidRecord)
        );
        let v5_tables: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'repository_authority_v5'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(v5_tables, 0);
        Ok(())
    }
}
