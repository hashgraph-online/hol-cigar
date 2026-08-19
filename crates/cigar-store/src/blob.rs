//! Authenticated, content-addressed local blob persistence and recovery.

use crate::{BlobRecord, StoreError, StoreErrorCode};
use cigar_crypto::{
    CreateKeyRequest, CryptoErrorCode, EncryptedEnvelope, KeyAlgorithm, KeyProvider, KeyPurpose,
    KeyRef, KeyStatus, decrypt_xchacha20_bytes, encrypt_xchacha20, generate_xchacha20_key,
};
use cigar_protocol::{BlobRef, ContentDigest, RecordId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const BLOB_MAGIC: &[u8; 16] = b"CIGAR-BLOB-v1\0\0\0";
const MAX_BLOB_FILE_BYTES: u64 = 67_110_000;
const MAX_KEY_REF_BYTES: usize = 128;
const MAX_RECONCILE_ENTRIES: usize = 1_000_000;
const KEY_REFERENCE_SUFFIX: &str = ".keyref";

/// Stable content-free local blob failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobErrorCode {
    /// Tenant, digest, key reference, or file framing is invalid.
    InvalidMetadata,
    /// The requested blob does not exist.
    NotFound,
    /// Ciphertext, authentication, size, or plaintext digest verification failed.
    Corrupt,
    /// The required wrapping key is unavailable or inactive.
    KeyUnavailable,
    /// A filesystem operation did not complete safely.
    Unavailable,
    /// A named durability failpoint interrupted publication.
    InjectedAbort,
    /// A file, scan, or bounded batch limit was exceeded.
    LimitExceeded,
    /// Retention, legal-hold, or backup policy forbids physical deletion.
    DeletionDenied,
}

/// Content-free blob error that never formats tenant, path, key, or plaintext values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlobError {
    code: BlobErrorCode,
}

impl BlobError {
    const fn new(code: BlobErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> BlobErrorCode {
        self.code
    }
}

impl fmt::Debug for BlobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BlobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "local blob operation failed: {:?}", self.code)
    }
}

impl std::error::Error for BlobError {}

/// Named one-shot failure boundaries in the atomic local publication protocol.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BlobFailpoint {
    /// After the temporary file exists but before bytes are written.
    AfterTemporaryCreate,
    /// After all framed ciphertext bytes are written.
    AfterTemporaryWrite,
    /// After file data and metadata are synchronized.
    AfterFileSync,
    /// After atomic rename but before parent-directory synchronization.
    AfterRename,
    /// After parent-directory synchronization and before returning success.
    AfterDirectorySync,
}

/// Recovery counts from one bounded local reconciliation pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconciliationReport {
    /// Incomplete temporary files removed.
    pub temporary_files_removed: u64,
    /// Unreferenced final blob files moved to quarantine.
    pub orphan_files_quarantined: u64,
    /// Live final blob files retained.
    pub live_files_retained: u64,
}

/// Preconditions for physical mark-and-sweep deletion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GarbageCollectionPolicy {
    /// All replay and retention windows have expired.
    pub retention_satisfied: bool,
    /// A legal hold currently protects the tenant data.
    pub legal_hold: bool,
    /// Required backup policy completed before deletion.
    pub backup_complete: bool,
}

/// Result of one bounded deterministic GC pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GarbageCollectionReport {
    /// Digests that were eligible in deterministic order.
    pub eligible: Vec<String>,
    /// Number of files physically removed; zero in dry-run mode.
    pub deleted: u64,
}

/// One tenant-qualified zero-reference blob selected by repository-owned reachability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGarbageCollectionCandidate {
    /// Exact tenant partition that owns the encrypted blob file.
    pub tenant_id: RecordId,
    /// Public content digest selected by the snapshot-consistent mark set.
    pub digest: ContentDigest,
}

/// Result of one bounded repository-wide mark-and-sweep pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepositoryGarbageCollectionReport {
    /// Tenant-qualified candidates in deterministic tenant/digest order.
    pub eligible: Vec<RepositoryGarbageCollectionCandidate>,
    /// Number of files physically removed; zero for a dry run.
    pub deleted: u64,
}

/// Opaque proof that shared GC passed PostgreSQL reference and backup-exclusion checks.
pub struct SharedGarbageCollectionAuthorization {
    _private: (),
}

impl SharedGarbageCollectionAuthorization {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

/// Encrypted filesystem blob store using a tenant-scoped wrapping-key provider.
pub struct LocalBlobStore<P: KeyProvider> {
    root: PathBuf,
    provider: Arc<P>,
    failpoints: Mutex<BTreeSet<BlobFailpoint>>,
}

/// Durable blob capability used by metadata repositories without exposing provider key bytes.
pub trait RepositoryBlobStore: Send + Sync {
    /// Durably publishes encrypted bytes before metadata visibility.
    fn put(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError>;
    /// Authenticates and decrypts one metadata-referenced blob.
    fn get(&self, tenant: &RecordId, reference: &BlobRef)
    -> Result<Option<BlobRecord>, StoreError>;
    /// Authenticates and decrypts one metadata-referenced blob without repairing, deleting, or
    /// quarantining any physical object.
    fn verify_integrity(&self, tenant: &RecordId, reference: &BlobRef) -> Result<(), StoreError> {
        match self.get(tenant, reference)? {
            Some(record) if record.reference == *reference => Ok(()),
            Some(_record) => Err(StoreError::new(StoreErrorCode::InvalidRecord)),
            None => Err(StoreError::new(StoreErrorCode::NotFound)),
        }
    }
    /// Proves an exact encrypted write/read/delete round trip without publishing metadata.
    fn readiness_probe(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError>;
    /// Reconciles temporary and final files against the latest live metadata roots.
    fn reconcile(&self, live: &BTreeMap<String, BTreeSet<ContentDigest>>)
    -> Result<(), StoreError>;
    /// Inventories every exact encrypted object reachable from one metadata snapshot.
    ///
    /// Implementations without a complete physical ciphertext view fail closed.
    fn backup_inventory(
        &self,
        _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<crate::object::ObjectBackupInventory, StoreError> {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
    /// Copies an exact metadata-reachable inventory into a self-contained backup namespace.
    ///
    /// Implementations must return only after the destination is complete and exactly inventoried.
    fn copy_backup_inventory(
        &self,
        _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        _destination: &dyn crate::object::ObjectStorage,
    ) -> Result<
        (
            crate::object::ObjectBackupInventory,
            crate::object::ObjectRestoreReceipt,
        ),
        StoreError,
    > {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
    /// Deletes an exact repository-validated zero-reference candidate set.
    ///
    /// Shared repositories invoke this only while holding their backup/GC exclusion lock and after
    /// proving that no retained metadata snapshot references any candidate.
    fn garbage_collect_candidates(
        &self,
        _authorization: &SharedGarbageCollectionAuthorization,
        _candidates: &[RepositoryGarbageCollectionCandidate],
        _policy: GarbageCollectionPolicy,
        _dry_run: bool,
        _max_objects: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
    /// Applies a repository-derived live-root snapshot to a bounded physical GC pass.
    ///
    /// Implementations that cannot safely enumerate their complete tenant storage fail closed.
    fn garbage_collect(
        &self,
        _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        _policy: GarbageCollectionPolicy,
        _dry_run: bool,
        _max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

/// Configured local adapter binding a blob store to the active wrapping key and semantic time.
pub struct LocalRepositoryBlobStore<P: KeyProvider> {
    store: LocalBlobStore<P>,
    configuration: Mutex<(KeyRef, i128)>,
}

impl<P: KeyProvider> fmt::Debug for LocalRepositoryBlobStore<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalRepositoryBlobStore([REDACTED])")
    }
}

impl<P: KeyProvider> LocalRepositoryBlobStore<P> {
    /// Binds a local encrypted store to one active wrapping key.
    #[must_use]
    pub fn new(store: LocalBlobStore<P>, wrapping_key: KeyRef, semantic_time: i128) -> Self {
        Self {
            store,
            configuration: Mutex::new((wrapping_key, semantic_time)),
        }
    }

    /// Switches future writes to a rotated key while historical reads retain file key refs.
    pub fn rotate_to(&self, wrapping_key: KeyRef, semantic_time: i128) -> Result<(), StoreError> {
        *self
            .configuration
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))? =
            (wrapping_key, semantic_time);
        Ok(())
    }

    fn configuration(&self) -> Result<(KeyRef, i128), StoreError> {
        self.configuration
            .lock()
            .map(|configuration| configuration.clone())
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }
}

impl<P: KeyProvider> RepositoryBlobStore for LocalRepositoryBlobStore<P> {
    fn put(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        let (key, now) = self.configuration()?;
        self.store
            .put(tenant.as_str(), &key, blob, now)
            .map_err(blob_store_error)
    }

    fn get(
        &self,
        tenant: &RecordId,
        reference: &BlobRef,
    ) -> Result<Option<BlobRecord>, StoreError> {
        let (_key, now) = self.configuration()?;
        match self.store.get(tenant.as_str(), reference, now) {
            Ok(blob) => Ok(Some(blob)),
            Err(error) if error.code() == BlobErrorCode::NotFound => Ok(None),
            Err(error) => Err(blob_store_error(error)),
        }
    }

    fn verify_integrity(&self, tenant: &RecordId, reference: &BlobRef) -> Result<(), StoreError> {
        let (_key, now) = self.configuration()?;
        self.store
            .verify_integrity(tenant.as_str(), reference, now)
            .map_err(blob_store_error)
    }

    fn readiness_probe(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        let (key, now) = self.configuration()?;
        match self.store.get(tenant.as_str(), &blob.reference, now) {
            Err(error) if error.code() == BlobErrorCode::NotFound => {}
            Ok(_existing) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
            Err(error) => return Err(blob_store_error(error)),
        }

        let write_result = self
            .store
            .put(tenant.as_str(), &key, blob, now)
            .map_err(blob_store_error);
        if let Err(error) = write_result {
            let cleanup_result = self
                .store
                .remove_readiness_probe(tenant.as_str(), &blob.reference)
                .map_err(blob_store_error);
            return cleanup_result.and(Err(error));
        }

        let read_result = self
            .store
            .get(tenant.as_str(), &blob.reference, now)
            .map_err(blob_store_error)
            .and_then(|observed| {
                if observed == *blob {
                    Ok(())
                } else {
                    Err(StoreError::new(StoreErrorCode::Unavailable))
                }
            });
        let delete_result = self
            .store
            .remove_readiness_probe(tenant.as_str(), &blob.reference)
            .map_err(blob_store_error);
        read_result.and(delete_result)
    }

    fn reconcile(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<(), StoreError> {
        let mut tenants: BTreeSet<String> = live.keys().cloned().collect();
        for entry in
            fs::read_dir(&self.store.root).map_err(|error| blob_store_error(io_error(error)))?
        {
            let entry = entry.map_err(|error| blob_store_error(io_error(error)))?;
            if entry
                .file_type()
                .map_err(|error| blob_store_error(io_error(error)))?
                .is_dir()
                && let Some(tenant) = entry.file_name().to_str()
                && validate_tenant(tenant).is_ok()
            {
                tenants.insert(tenant.to_owned());
            }
        }
        for tenant in tenants {
            let empty = BTreeSet::new();
            let digests = live.get(&tenant).unwrap_or(&empty);
            self.store
                .reconcile(&tenant, digests)
                .map_err(blob_store_error)?;
        }
        Ok(())
    }
}

/// Local encrypted blob repository that durably provisions one wrapping key per tenant.
///
/// Key-reference files contain only opaque provider handles. They are nevertheless published
/// without replacement under restrictive permissions so a filesystem race or symlink cannot
/// redirect tenant encryption to an attacker-selected key. Private material never leaves the
/// injected [`KeyProvider`].
pub struct MultiTenantLocalRepositoryBlobStore<P: KeyProvider> {
    root: PathBuf,
    key_reference_root: PathBuf,
    provider: Arc<P>,
    semantic_time: Mutex<i128>,
}

impl<P: KeyProvider> fmt::Debug for MultiTenantLocalRepositoryBlobStore<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MultiTenantLocalRepositoryBlobStore([REDACTED])")
    }
}

impl<P: KeyProvider> MultiTenantLocalRepositoryBlobStore<P> {
    /// Opens checked blob and key-reference roots at one semantic key-lifecycle time.
    pub fn open(
        root: impl AsRef<Path>,
        key_reference_root: impl AsRef<Path>,
        provider: Arc<P>,
        semantic_time: i128,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        let key_reference_root = key_reference_root.as_ref().to_path_buf();
        create_checked_directory(&root)?;
        create_checked_directory(&key_reference_root)?;
        Ok(Self {
            root,
            key_reference_root,
            provider,
            semantic_time: Mutex::new(semantic_time),
        })
    }

    /// Advances the semantic time used for key lifecycle checks and future encrypted writes.
    pub fn set_semantic_time(&self, semantic_time: i128) -> Result<(), StoreError> {
        *self
            .semantic_time
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))? = semantic_time;
        Ok(())
    }

    fn semantic_time(&self) -> Result<i128, StoreError> {
        self.semantic_time
            .lock()
            .map(|value| *value)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }

    fn key_path(&self, tenant: &RecordId) -> PathBuf {
        self.key_reference_root
            .join(format!("{}{KEY_REFERENCE_SUFFIX}", tenant.as_str()))
    }

    fn load_key(&self, tenant: &RecordId, at: i128) -> Result<Option<KeyRef>, StoreError> {
        let path = self.key_path(tenant);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(blob_store_error(io_error(error))),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_KEY_REF_BYTES as u64
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
        }
        let mut text = String::new();
        File::open(path)
            .and_then(|file| {
                file.take((MAX_KEY_REF_BYTES + 1) as u64)
                    .read_to_string(&mut text)
            })
            .map_err(|error| blob_store_error(io_error(error)))?;
        if text.is_empty()
            || text.len() > MAX_KEY_REF_BYTES
            || text.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let key_ref = KeyRef::new(text).map_err(crypto_store_error)?;
        let metadata = self
            .provider
            .resolve(&key_ref, tenant.as_str(), KeyPurpose::BlobEncryption, at)
            .map_err(crypto_store_error)?;
        if metadata.key_ref != key_ref
            || metadata.tenant != tenant.as_str()
            || metadata.purpose != KeyPurpose::BlobEncryption
            || metadata.algorithm != KeyAlgorithm::XChaCha20Poly1305
            || metadata.status != KeyStatus::Active
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        Ok(Some(key_ref))
    }

    fn create_key(&self, tenant: &RecordId, at: i128) -> Result<KeyRef, StoreError> {
        let metadata = self
            .provider
            .create(CreateKeyRequest {
                tenant: tenant.as_str().to_owned(),
                purpose: KeyPurpose::BlobEncryption,
                algorithm: KeyAlgorithm::XChaCha20Poly1305,
                created_at: at,
                activated_at: at,
            })
            .map_err(crypto_store_error)?;
        let path = self.key_path(tenant);
        let mut temporary = tempfile::Builder::new()
            .prefix(".cigar-keyref-")
            .tempfile_in(&self.key_reference_root)
            .map_err(|error| blob_store_error(io_error(error)))?;
        restrict_reference_permissions(temporary.as_file())?;
        temporary
            .write_all(metadata.key_ref.as_str().as_bytes())
            .and_then(|()| temporary.flush())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| blob_store_error(io_error(error)))?;
        match temporary.persist_noclobber(&path) {
            Ok(_file) => {
                sync_directory(&self.key_reference_root).map_err(blob_store_error)?;
                Ok(metadata.key_ref)
            }
            Err(error) if error.error.kind() == ErrorKind::AlreadyExists => self
                .load_key(tenant, at)?
                .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable)),
            Err(error) => Err(blob_store_error(io_error(error.error))),
        }
    }

    fn key(&self, tenant: &RecordId, at: i128) -> Result<KeyRef, StoreError> {
        self.load_key(tenant, at)?
            .map_or_else(|| self.create_key(tenant, at), Ok)
    }

    fn adapter(&self, tenant: &RecordId) -> Result<LocalRepositoryBlobStore<P>, StoreError> {
        let at = self.semantic_time()?;
        let key = self.key(tenant, at)?;
        let store = LocalBlobStore::open(&self.root, Arc::clone(&self.provider))
            .map_err(blob_store_error)?;
        Ok(LocalRepositoryBlobStore::new(store, key, at))
    }

    fn tenants_with_keys(&self) -> Result<BTreeSet<RecordId>, StoreError> {
        let mut tenants = BTreeSet::new();
        let mut count = 0_usize;
        for entry in fs::read_dir(&self.key_reference_root)
            .map_err(|error| blob_store_error(io_error(error)))?
        {
            let entry = entry.map_err(|error| blob_store_error(io_error(error)))?;
            count = count.saturating_add(1);
            if count > MAX_RECONCILE_ENTRIES {
                return Err(StoreError::new(StoreErrorCode::LimitExceeded));
            }
            if entry
                .file_type()
                .map_err(|error| blob_store_error(io_error(error)))?
                .is_symlink()
            {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
            let name = entry
                .file_name()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
            let Some(tenant) = name.strip_suffix(KEY_REFERENCE_SUFFIX) else {
                continue;
            };
            tenants.insert(
                RecordId::new(tenant.to_owned())
                    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            );
        }
        Ok(tenants)
    }

    fn tenants_with_data(&self) -> Result<BTreeSet<RecordId>, StoreError> {
        let mut tenants = BTreeSet::new();
        let mut count = 0_usize;
        for entry in fs::read_dir(&self.root).map_err(|error| blob_store_error(io_error(error)))? {
            let entry = entry.map_err(|error| blob_store_error(io_error(error)))?;
            count = count.saturating_add(1);
            if count > MAX_RECONCILE_ENTRIES {
                return Err(StoreError::new(StoreErrorCode::LimitExceeded));
            }
            let file_type = entry
                .file_type()
                .map_err(|error| blob_store_error(io_error(error)))?;
            if file_type.is_symlink() {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
            if !file_type.is_dir() {
                continue;
            }
            let name = entry
                .file_name()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
            if let Ok(tenant) = RecordId::new(name) {
                tenants.insert(tenant);
            }
        }
        Ok(tenants)
    }
}

impl<P: KeyProvider> RepositoryBlobStore for MultiTenantLocalRepositoryBlobStore<P> {
    fn put(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        self.adapter(tenant)?.put(tenant, blob)
    }

    fn get(
        &self,
        tenant: &RecordId,
        reference: &BlobRef,
    ) -> Result<Option<BlobRecord>, StoreError> {
        self.adapter(tenant)?.get(tenant, reference)
    }

    fn verify_integrity(&self, tenant: &RecordId, reference: &BlobRef) -> Result<(), StoreError> {
        let at = self.semantic_time()?;
        self.load_key(tenant, at)?
            .ok_or_else(|| StoreError::new(StoreErrorCode::NotFound))?;
        LocalBlobStore::open(&self.root, Arc::clone(&self.provider))
            .map_err(blob_store_error)?
            .verify_integrity(tenant.as_str(), reference, at)
            .map_err(blob_store_error)
    }

    fn readiness_probe(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        self.adapter(tenant)?.readiness_probe(tenant, blob)
    }

    fn reconcile(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<(), StoreError> {
        let mut tenants = self.tenants_with_keys()?;
        tenants.extend(self.tenants_with_data()?);
        for tenant in live.keys() {
            tenants.insert(
                RecordId::new(tenant.clone())
                    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            );
        }
        let store = LocalBlobStore::open(&self.root, Arc::clone(&self.provider))
            .map_err(blob_store_error)?;
        for tenant in tenants {
            let empty = BTreeSet::new();
            let digests = live.get(tenant.as_str()).unwrap_or(&empty);
            store
                .reconcile(tenant.as_str(), digests)
                .map_err(blob_store_error)?;
        }
        Ok(())
    }

    fn garbage_collect_candidates(
        &self,
        _authorization: &SharedGarbageCollectionAuthorization,
        candidates: &[RepositoryGarbageCollectionCandidate],
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        if !policy.retention_satisfied || policy.legal_hold || !policy.backup_complete {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        if max_files == 0
            || max_files > MAX_RECONCILE_ENTRIES
            || candidates.len() > max_files
            || candidates.windows(2).any(|pair| {
                pair.first().zip(pair.get(1)).is_some_and(|(left, right)| {
                    (&left.tenant_id, &left.digest) >= (&right.tenant_id, &right.digest)
                })
            })
        {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let store = LocalBlobStore::open(&self.root, Arc::clone(&self.provider))
            .map_err(blob_store_error)?;
        let mut by_tenant: BTreeMap<&RecordId, Vec<&ContentDigest>> = BTreeMap::new();
        for candidate in candidates {
            by_tenant
                .entry(&candidate.tenant_id)
                .or_default()
                .push(&candidate.digest);
        }
        let mut report = RepositoryGarbageCollectionReport::default();
        for (tenant, digests) in by_tenant {
            let deleted = store
                .garbage_collect_exact(tenant.as_str(), &digests, policy, dry_run)
                .map_err(blob_store_error)?;
            report.deleted = report
                .deleted
                .checked_add(deleted)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        }
        report.eligible = candidates.to_vec();
        Ok(report)
    }

    fn garbage_collect(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        if max_files == 0 || max_files > MAX_RECONCILE_ENTRIES {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut tenants = self.tenants_with_keys()?;
        tenants.extend(self.tenants_with_data()?);
        for tenant in live.keys() {
            tenants.insert(
                RecordId::new(tenant.clone())
                    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            );
        }
        let store = LocalBlobStore::open(&self.root, Arc::clone(&self.provider))
            .map_err(blob_store_error)?;
        let empty = BTreeSet::new();
        let mut result = RepositoryGarbageCollectionReport::default();
        for tenant in tenants {
            let remaining = max_files.saturating_sub(result.eligible.len());
            if remaining == 0 {
                break;
            }
            let roots = live.get(tenant.as_str()).unwrap_or(&empty);
            let report = store
                .garbage_collect(tenant.as_str(), roots, policy, dry_run, remaining)
                .map_err(blob_store_error)?;
            result.deleted = result
                .deleted
                .checked_add(report.deleted)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            for digest in report.eligible {
                result.eligible.push(RepositoryGarbageCollectionCandidate {
                    tenant_id: tenant.clone(),
                    digest: ContentDigest::new(digest)
                        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
                });
            }
        }
        Ok(result)
    }
}

impl<P: KeyProvider> fmt::Debug for LocalBlobStore<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalBlobStore([REDACTED])")
    }
}

impl<P: KeyProvider> LocalBlobStore<P> {
    /// Opens a local blob root and creates only fixed non-secret directory names.
    pub fn open(root: impl AsRef<Path>, provider: Arc<P>) -> Result<Self, BlobError> {
        fs::create_dir_all(root.as_ref()).map_err(io_error)?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            provider,
            failpoints: Mutex::new(BTreeSet::new()),
        })
    }

    /// Arms one named one-shot publication failpoint.
    pub fn inject_failpoint(&self, failpoint: BlobFailpoint) -> Result<(), BlobError> {
        self.failpoints
            .lock()
            .map_err(|_error| BlobError::new(BlobErrorCode::Unavailable))?
            .insert(failpoint);
        Ok(())
    }

    /// Encrypts and atomically publishes one content-addressed blob.
    pub fn put(
        &self,
        tenant: &str,
        wrapping_key: &KeyRef,
        blob: &BlobRecord,
        now: i128,
    ) -> Result<(), BlobError> {
        validate_tenant(tenant)?;
        validate_digest(&blob.reference.digest)?;
        let expected = plaintext_digest(blob.bytes());
        if expected != blob.reference.digest.as_str()
            || u64::try_from(blob.bytes().len()).ok() != Some(blob.reference.size_bytes)
        {
            return Err(BlobError::new(BlobErrorCode::InvalidMetadata));
        }
        let directory = self.blob_directory(tenant);
        fs::create_dir_all(&directory).map_err(io_error)?;
        let destination = directory.join(blob.reference.digest.as_str());
        if destination.exists() {
            self.get(tenant, &blob.reference, now)?;
            return Ok(());
        }
        let associated_data = blob_associated_data(tenant, &blob.reference)?;
        let data_key = generate_xchacha20_key().map_err(crypto_error)?;
        let wrapped_key = self
            .provider
            .wrap(wrapping_key, tenant, &data_key, &associated_data, now)
            .map_err(crypto_error)?;
        let encrypted_payload =
            encrypt_xchacha20(&data_key, blob.bytes(), &associated_data).map_err(crypto_error)?;
        let framed = encode_blob_file(
            wrapping_key,
            blob.reference.size_bytes,
            &wrapped_key,
            &encrypted_payload,
        )?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".cigar-tmp-")
            .tempfile_in(&directory)
            .map_err(io_error)?;
        self.trip(BlobFailpoint::AfterTemporaryCreate)?;
        temporary.write_all(&framed).map_err(io_error)?;
        temporary.flush().map_err(io_error)?;
        self.trip(BlobFailpoint::AfterTemporaryWrite)?;
        temporary.as_file().sync_all().map_err(io_error)?;
        self.trip(BlobFailpoint::AfterFileSync)?;
        temporary
            .persist_noclobber(&destination)
            .map_err(|error| io_error(error.error))?;
        self.trip(BlobFailpoint::AfterRename)?;
        sync_directory(&directory)?;
        self.trip(BlobFailpoint::AfterDirectorySync)?;
        Ok(())
    }

    /// Authenticates, decrypts, and verifies one expected blob or quarantines corruption.
    pub fn get(
        &self,
        tenant: &str,
        expected: &BlobRef,
        now: i128,
    ) -> Result<BlobRecord, BlobError> {
        validate_tenant(tenant)?;
        validate_digest(&expected.digest)?;
        let path = self.blob_directory(tenant).join(expected.digest.as_str());
        let result = self.read_verified(&path, tenant, expected, now);
        if result
            .as_ref()
            .is_err_and(|error| error.code() == BlobErrorCode::Corrupt)
        {
            let _quarantine_result = self.quarantine(tenant, &path, expected.digest.as_str());
        }
        result
    }

    /// Authenticates one expected blob without invoking the corruption-quarantine repair path.
    fn verify_integrity(
        &self,
        tenant: &str,
        expected: &BlobRef,
        now: i128,
    ) -> Result<(), BlobError> {
        validate_tenant(tenant)?;
        validate_digest(&expected.digest)?;
        let path = self.blob_directory(tenant).join(expected.digest.as_str());
        self.read_verified(&path, tenant, expected, now)
            .map(|_record| ())
    }

    fn remove_readiness_probe(&self, tenant: &str, expected: &BlobRef) -> Result<(), BlobError> {
        validate_tenant(tenant)?;
        validate_digest(&expected.digest)?;
        let directory = self.blob_directory(tenant);
        let path = directory.join(expected.digest.as_str());
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }

    /// Removes incomplete files and quarantines final files absent from live metadata.
    pub fn reconcile(
        &self,
        tenant: &str,
        live: &BTreeSet<ContentDigest>,
    ) -> Result<ReconciliationReport, BlobError> {
        validate_tenant(tenant)?;
        let directory = self.blob_directory(tenant);
        let directory_was_present = directory.is_dir();
        fs::create_dir_all(&directory).map_err(io_error)?;
        let mut entries = read_sorted_entries(&directory)?;
        if entries.len() > MAX_RECONCILE_ENTRIES {
            return Err(BlobError::new(BlobErrorCode::LimitExceeded));
        }
        let mut report = ReconciliationReport::default();
        for path in entries.drain(..) {
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.starts_with(".cigar-tmp-") {
                fs::remove_file(path).map_err(io_error)?;
                report.temporary_files_removed += 1;
                continue;
            }
            let is_live = ContentDigest::new(name.to_owned())
                .ok()
                .is_some_and(|digest| live.contains(&digest));
            if is_live {
                report.live_files_retained += 1;
            } else {
                self.quarantine(tenant, &path, name)?;
                report.orphan_files_quarantined += 1;
            }
        }
        if !directory_was_present
            || report.temporary_files_removed > 0
            || report.orphan_files_quarantined > 0
        {
            sync_directory(&directory)?;
        }
        Ok(report)
    }

    /// Plans or performs a bounded mark-and-sweep pass over zero-reference files.
    pub fn garbage_collect(
        &self,
        tenant: &str,
        live: &BTreeSet<ContentDigest>,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<GarbageCollectionReport, BlobError> {
        validate_tenant(tenant)?;
        if !policy.retention_satisfied || policy.legal_hold || !policy.backup_complete {
            return Err(BlobError::new(BlobErrorCode::DeletionDenied));
        }
        if max_files == 0 || max_files > MAX_RECONCILE_ENTRIES {
            return Err(BlobError::new(BlobErrorCode::LimitExceeded));
        }
        let directory = self.blob_directory(tenant);
        fs::create_dir_all(&directory).map_err(io_error)?;
        let mut report = GarbageCollectionReport::default();
        for path in read_sorted_entries(&directory)? {
            if report.eligible.len() == max_files {
                break;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(digest) = ContentDigest::new(name.to_owned()).ok() else {
                continue;
            };
            if live.contains(&digest) {
                continue;
            }
            report.eligible.push(name.to_owned());
            if !dry_run {
                fs::remove_file(path).map_err(io_error)?;
                report.deleted += 1;
            }
        }
        if report.deleted > 0 {
            sync_directory(&directory)?;
        }
        Ok(report)
    }

    fn garbage_collect_exact(
        &self,
        tenant: &str,
        candidates: &[&ContentDigest],
        policy: GarbageCollectionPolicy,
        dry_run: bool,
    ) -> Result<u64, BlobError> {
        validate_tenant(tenant)?;
        if !policy.retention_satisfied || policy.legal_hold || !policy.backup_complete {
            return Err(BlobError::new(BlobErrorCode::DeletionDenied));
        }
        if candidates.len() > MAX_RECONCILE_ENTRIES
            || candidates.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_some_and(|(left, right)| left >= right)
            })
        {
            return Err(BlobError::new(BlobErrorCode::LimitExceeded));
        }
        let directory = self.blob_directory(tenant);
        let mut paths = Vec::with_capacity(candidates.len());
        for digest in candidates {
            let path = directory.join(digest.as_str());
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    validate_open_blob_metadata(&metadata)?;
                    paths.push(path);
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        if dry_run || paths.is_empty() {
            return Ok(0);
        }
        let mut deleted = 0_u64;
        for path in paths {
            match fs::remove_file(path) {
                Ok(()) => {
                    deleted = deleted
                        .checked_add(1)
                        .ok_or_else(|| BlobError::new(BlobErrorCode::LimitExceeded))?;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        if deleted > 0 {
            sync_directory(&directory)?;
        }
        Ok(deleted)
    }

    /// Lists bounded corruption invalidations emitted during quarantine.
    pub fn invalidations(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<ContentDigest>, BlobError> {
        validate_tenant(tenant)?;
        if limit == 0 || limit > MAX_RECONCILE_ENTRIES {
            return Err(BlobError::new(BlobErrorCode::LimitExceeded));
        }
        let directory = self.root.join(tenant).join("quarantine");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut invalidations = Vec::new();
        for path in read_sorted_entries(&directory)? {
            if invalidations.len() == limit {
                break;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(digest) = name.strip_suffix(".invalidated") else {
                continue;
            };
            if let Ok(digest) = ContentDigest::new(digest.to_owned()) {
                invalidations.push(digest);
            }
        }
        Ok(invalidations)
    }

    fn read_verified(
        &self,
        path: &Path,
        tenant: &str,
        expected: &BlobRef,
        now: i128,
    ) -> Result<BlobRecord, BlobError> {
        let mut file = open_blob_readonly(path)?;
        let before = file.metadata().map_err(io_error)?;
        validate_open_blob_metadata(&before)?;
        let length = before.len();
        if length == 0 || length > MAX_BLOB_FILE_BYTES {
            return Err(BlobError::new(BlobErrorCode::Corrupt));
        }
        let capacity = usize::try_from(length)
            .map_err(|_error| BlobError::new(BlobErrorCode::LimitExceeded))?;
        let mut bytes = Vec::with_capacity(capacity);
        Read::by_ref(&mut file)
            .take(MAX_BLOB_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let after = file.metadata().map_err(io_error)?;
        validate_open_blob_metadata(&after)?;
        if u64::try_from(bytes.len()).ok() != Some(length)
            || after.len() != length
            || !same_open_blob_identity(&before, &after)
        {
            return Err(BlobError::new(BlobErrorCode::Corrupt));
        }
        authenticate_persisted_blob(self.provider.as_ref(), &bytes, tenant, expected, now)
            .map(|(_key, record)| record)
    }

    fn quarantine(&self, tenant: &str, path: &Path, name: &str) -> Result<(), BlobError> {
        let directory = self.root.join(tenant).join("quarantine");
        fs::create_dir_all(&directory).map_err(io_error)?;
        let destination = unique_quarantine_path(&directory, name)?;
        fs::rename(path, destination).map_err(io_error)?;
        sync_directory(&directory)?;
        write_invalidation(&directory, name)
    }

    fn blob_directory(&self, tenant: &str) -> PathBuf {
        self.root.join(tenant).join("blobs")
    }

    fn trip(&self, failpoint: BlobFailpoint) -> Result<(), BlobError> {
        let mut failpoints = self
            .failpoints
            .lock()
            .map_err(|_error| BlobError::new(BlobErrorCode::Unavailable))?;
        if failpoints.remove(&failpoint) {
            Err(BlobError::new(BlobErrorCode::InjectedAbort))
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn open_blob_readonly(path: &Path) -> Result<File, BlobError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            BlobError::new(BlobErrorCode::NotFound)
        } else {
            BlobError::new(BlobErrorCode::Unavailable)
        }
    })
}

#[cfg(windows)]
fn open_blob_readonly(path: &Path) -> Result<File, BlobError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BlobError::new(BlobErrorCode::NotFound)
        } else {
            io_error(error)
        }
    })
}

#[cfg(not(any(unix, windows)))]
fn open_blob_readonly(path: &Path) -> Result<File, BlobError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    File::open(path).map_err(io_error)
}

fn validate_open_blob_metadata(metadata: &fs::Metadata) -> Result<(), BlobError> {
    if !metadata.is_file() {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(BlobError::new(BlobErrorCode::Corrupt));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_open_blob_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_open_blob_identity(_before: &fs::Metadata, _after: &fs::Metadata) -> bool {
    true
}

struct DecodedBlobFile {
    wrapping_key: KeyRef,
    plaintext_size: u64,
    wrapped_key: EncryptedEnvelope,
    encrypted_payload: EncryptedEnvelope,
}

pub(crate) fn persisted_blob_key_ref(bytes: &[u8]) -> Result<KeyRef, BlobError> {
    decode_blob_file(bytes).map(|decoded| decoded.wrapping_key)
}

/// Authenticates one framed persisted blob against its authoritative tenant and metadata.
pub(crate) fn verify_persisted_blob<P: KeyProvider>(
    provider: &P,
    bytes: &[u8],
    tenant: &str,
    expected: &BlobRef,
    now: i128,
) -> Result<KeyRef, BlobError> {
    authenticate_persisted_blob(provider, bytes, tenant, expected, now)
        .map(|(wrapping_key, _record)| wrapping_key)
}

fn authenticate_persisted_blob<P: KeyProvider>(
    provider: &P,
    bytes: &[u8],
    tenant: &str,
    expected: &BlobRef,
    now: i128,
) -> Result<(KeyRef, BlobRecord), BlobError> {
    validate_tenant(tenant)?;
    validate_digest(&expected.digest)?;
    let decoded = decode_blob_file(bytes)?;
    if decoded.plaintext_size != expected.size_bytes {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    let associated_data = blob_associated_data(tenant, expected)?;
    let data_key = provider
        .unwrap(
            &decoded.wrapping_key,
            tenant,
            &decoded.wrapped_key,
            &associated_data,
            now,
        )
        .map_err(crypto_error)?;
    let plaintext =
        decrypt_xchacha20_bytes(&data_key, &decoded.encrypted_payload, &associated_data)
            .map_err(crypto_error)?;
    if u64::try_from(plaintext.len()).ok() != Some(expected.size_bytes)
        || plaintext_digest(&plaintext) != expected.digest.as_str()
    {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    let record = BlobRecord::new(expected.clone(), plaintext)
        .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
    Ok((decoded.wrapping_key, record))
}

fn encode_blob_file(
    wrapping_key: &KeyRef,
    plaintext_size: u64,
    wrapped_key: &EncryptedEnvelope,
    payload: &EncryptedEnvelope,
) -> Result<Vec<u8>, BlobError> {
    let key_length = u16::try_from(wrapping_key.as_str().len())
        .map_err(|_error| BlobError::new(BlobErrorCode::InvalidMetadata))?;
    let wrapped_length = u32::try_from(wrapped_key.ciphertext().len())
        .map_err(|_error| BlobError::new(BlobErrorCode::LimitExceeded))?;
    let payload_length = u32::try_from(payload.ciphertext().len())
        .map_err(|_error| BlobError::new(BlobErrorCode::LimitExceeded))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BLOB_MAGIC);
    bytes.extend_from_slice(&key_length.to_be_bytes());
    bytes.extend_from_slice(wrapping_key.as_str().as_bytes());
    bytes.extend_from_slice(wrapped_key.nonce());
    bytes.extend_from_slice(&wrapped_length.to_be_bytes());
    bytes.extend_from_slice(wrapped_key.ciphertext());
    bytes.extend_from_slice(payload.nonce());
    bytes.extend_from_slice(&plaintext_size.to_be_bytes());
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload.ciphertext());
    Ok(bytes)
}

fn decode_blob_file(bytes: &[u8]) -> Result<DecodedBlobFile, BlobError> {
    let mut reader = ByteReader::new(bytes);
    if reader.take(BLOB_MAGIC.len())? != BLOB_MAGIC {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    let key_length = usize::from(reader.u16()?);
    if key_length == 0 || key_length > MAX_KEY_REF_BYTES {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    let wrapping_key = std::str::from_utf8(reader.take(key_length)?)
        .ok()
        .and_then(|value| KeyRef::new(value.to_owned()).ok())
        .ok_or_else(|| BlobError::new(BlobErrorCode::Corrupt))?;
    let wrapped_nonce = reader.nonce()?;
    let wrapped_length =
        usize::try_from(reader.u32()?).map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
    let wrapped_key =
        EncryptedEnvelope::from_parts(wrapped_nonce, reader.take(wrapped_length)?.to_vec())
            .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
    let payload_nonce = reader.nonce()?;
    let plaintext_size = reader.u64()?;
    let payload_length =
        usize::try_from(reader.u32()?).map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
    let encrypted_payload =
        EncryptedEnvelope::from_parts(payload_nonce, reader.take(payload_length)?.to_vec())
            .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
    if !reader.is_empty() {
        return Err(BlobError::new(BlobErrorCode::Corrupt));
    }
    Ok(DecodedBlobFile {
        wrapping_key,
        plaintext_size,
        wrapped_key,
        encrypted_payload,
    })
}

pub(crate) fn protect_blob_bytes<P: KeyProvider>(
    provider: &P,
    tenant: &str,
    wrapping_key: &KeyRef,
    blob: &BlobRecord,
    now: i128,
) -> Result<Vec<u8>, StoreError> {
    validate_tenant(tenant).map_err(blob_store_error)?;
    validate_digest(&blob.reference.digest).map_err(blob_store_error)?;
    if plaintext_digest(blob.bytes()) != blob.reference.digest.as_str()
        || u64::try_from(blob.bytes().len()).ok() != Some(blob.reference.size_bytes)
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let associated_data =
        blob_associated_data(tenant, &blob.reference).map_err(blob_store_error)?;
    let data_key = generate_xchacha20_key().map_err(crypto_store_error)?;
    let wrapped_key = provider
        .wrap(wrapping_key, tenant, &data_key, &associated_data, now)
        .map_err(crypto_store_error)?;
    let encrypted_payload =
        encrypt_xchacha20(&data_key, blob.bytes(), &associated_data).map_err(crypto_store_error)?;
    encode_blob_file(
        wrapping_key,
        blob.reference.size_bytes,
        &wrapped_key,
        &encrypted_payload,
    )
    .map_err(blob_store_error)
}

pub(crate) fn unprotect_blob_bytes<P: KeyProvider>(
    provider: &P,
    tenant: &str,
    expected: &BlobRef,
    bytes: &[u8],
    now: i128,
) -> Result<BlobRecord, StoreError> {
    validate_tenant(tenant).map_err(blob_store_error)?;
    validate_digest(&expected.digest).map_err(blob_store_error)?;
    if bytes.len() as u64 > MAX_BLOB_FILE_BYTES {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let decoded = decode_blob_file(bytes).map_err(blob_store_error)?;
    if decoded.plaintext_size != expected.size_bytes {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let associated_data = blob_associated_data(tenant, expected).map_err(blob_store_error)?;
    let data_key = provider
        .unwrap(
            &decoded.wrapping_key,
            tenant,
            &decoded.wrapped_key,
            &associated_data,
            now,
        )
        .map_err(crypto_store_error)?;
    let plaintext =
        decrypt_xchacha20_bytes(&data_key, &decoded.encrypted_payload, &associated_data)
            .map_err(crypto_store_error)?;
    if u64::try_from(plaintext.len()).ok() != Some(expected.size_bytes)
        || plaintext_digest(&plaintext) != expected.digest.as_str()
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    BlobRecord::new(expected.clone(), plaintext)
}

struct ByteReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BlobError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or_else(|| BlobError::new(BlobErrorCode::Corrupt))?;
        self.remaining = remaining;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, BlobError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, BlobError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, BlobError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn nonce(&mut self) -> Result<[u8; 24], BlobError> {
        self.take(24)?
            .try_into()
            .map_err(|_error| BlobError::new(BlobErrorCode::Corrupt))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn blob_associated_data(tenant: &str, reference: &BlobRef) -> Result<Vec<u8>, BlobError> {
    let tenant_length = u16::try_from(tenant.len())
        .map_err(|_error| BlobError::new(BlobErrorCode::InvalidMetadata))?;
    let mut bytes = b"CIGAR-BLOB-AAD\0v1\0".to_vec();
    bytes.extend_from_slice(&tenant_length.to_be_bytes());
    bytes.extend_from_slice(tenant.as_bytes());
    bytes.extend_from_slice(reference.digest.as_str().as_bytes());
    bytes.extend_from_slice(&reference.size_bytes.to_be_bytes());
    Ok(bytes)
}

fn validate_tenant(tenant: &str) -> Result<(), BlobError> {
    if tenant.is_empty()
        || tenant.len() > 128
        || !tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(BlobError::new(BlobErrorCode::InvalidMetadata))
    } else {
        Ok(())
    }
}

fn validate_digest(digest: &ContentDigest) -> Result<(), BlobError> {
    if digest.as_str().len() == 68
        && digest.as_str().starts_with("1220")
        && digest.as_str().bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(BlobError::new(BlobErrorCode::InvalidMetadata))
    }
}

fn plaintext_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn read_sorted_entries(directory: &Path) -> Result<Vec<PathBuf>, BlobError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_file() {
            entries.push(entry.path());
        }
    }
    entries.sort();
    Ok(entries)
}

fn unique_quarantine_path(directory: &Path, name: &str) -> Result<PathBuf, BlobError> {
    for attempt in 0..1_000_u16 {
        let candidate = directory.join(format!("{name}.quarantine.{attempt:03}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(BlobError::new(BlobErrorCode::LimitExceeded))
}

fn write_invalidation(directory: &Path, digest: &str) -> Result<(), BlobError> {
    let destination = directory.join(format!("{digest}.invalidated"));
    if destination.exists() {
        return Ok(());
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".cigar-invalidation-")
        .tempfile_in(directory)
        .map_err(io_error)?;
    temporary
        .write_all(b"CIGAR-BLOB-INVALIDATION-v1\n")
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(io_error)?;
    match temporary.persist_noclobber(destination) {
        Ok(_file) => sync_directory(directory),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(io_error(error.error)),
    }
}

fn create_checked_directory(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path).map_err(|error| blob_store_error(io_error(error)))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| blob_store_error(io_error(error)))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_reference_permissions(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| blob_store_error(io_error(error)))
}

#[cfg(not(unix))]
fn restrict_reference_permissions(_file: &File) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), BlobError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), BlobError> {
    Ok(())
}

fn crypto_error(error: cigar_crypto::CryptoError) -> BlobError {
    let code = match error.code() {
        CryptoErrorCode::AuthenticationFailed | CryptoErrorCode::ScopeDenied => {
            BlobErrorCode::Corrupt
        }
        CryptoErrorCode::UnknownKey | CryptoErrorCode::KeyInactive => BlobErrorCode::KeyUnavailable,
        CryptoErrorCode::InvalidMetadata
        | CryptoErrorCode::InvalidKey
        | CryptoErrorCode::InvalidNonce => BlobErrorCode::InvalidMetadata,
        _ => BlobErrorCode::Unavailable,
    };
    BlobError::new(code)
}

fn crypto_store_error(error: cigar_crypto::CryptoError) -> StoreError {
    blob_store_error(crypto_error(error))
}

fn io_error(_error: std::io::Error) -> BlobError {
    BlobError::new(BlobErrorCode::Unavailable)
}

fn blob_store_error(error: BlobError) -> StoreError {
    let code = match error.code() {
        BlobErrorCode::InvalidMetadata | BlobErrorCode::Corrupt => StoreErrorCode::InvalidRecord,
        BlobErrorCode::NotFound => StoreErrorCode::NotFound,
        BlobErrorCode::LimitExceeded => StoreErrorCode::LimitExceeded,
        BlobErrorCode::InjectedAbort => StoreErrorCode::InjectedAbort,
        _ => StoreErrorCode::Unavailable,
    };
    StoreError::new(code)
}

#[cfg(test)]
mod tests {
    use super::{
        BlobErrorCode, BlobFailpoint, GarbageCollectionPolicy, KEY_REFERENCE_SUFFIX,
        LocalBlobStore, MultiTenantLocalRepositoryBlobStore, RepositoryBlobStore, plaintext_digest,
    };
    use crate::{BlobRecord, StoreErrorCode};
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider,
    };
    use cigar_protocol::{BlobRef, ContentDigest, MediaType, RecordId};
    use std::collections::BTreeSet;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::Arc;

    fn fixture() -> Result<(BlobRecord, ContentDigest), Box<dyn std::error::Error>> {
        let bytes = b"plaintext-secret-canary".to_vec();
        let digest = ContentDigest::new(plaintext_digest(&bytes))?;
        let record = BlobRecord::new(
            BlobRef {
                digest: digest.clone(),
                size_bytes: u64::try_from(bytes.len())?,
                media_type: MediaType::new("application/octet-stream")?,
            },
            bytes,
        )?;
        Ok((record, digest))
    }

    #[test]
    fn encrypted_publication_rotation_corruption_reconciliation_and_gc()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let first_key = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let store = LocalBlobStore::open(directory.path(), Arc::clone(&provider))?;
        let (blob, digest) = fixture()?;
        store.put("tenant-a", &first_key.key_ref, &blob, 1)?;
        let persisted = std::fs::read(
            directory
                .path()
                .join("tenant-a/blobs")
                .join(digest.as_str()),
        )?;
        assert!(
            !persisted
                .windows(blob.bytes().len())
                .any(|window| window == blob.bytes())
        );
        assert_eq!(store.get("tenant-a", &blob.reference, 1)?, blob);

        let successor = provider.rotate(&first_key.key_ref, "tenant-a", 2)?;
        assert_eq!(store.get("tenant-a", &blob.reference, 2)?, blob);
        let mut second = blob.clone();
        let second_bytes = b"second encrypted blob".to_vec();
        second.reference.digest = ContentDigest::new(plaintext_digest(&second_bytes))?;
        second.reference.size_bytes = u64::try_from(second_bytes.len())?;
        second = BlobRecord::new(second.reference, second_bytes)?;
        store.put("tenant-a", &successor.key_ref, &second, 2)?;

        let third_bytes = b"third encrypted blob".to_vec();
        let third = BlobRecord::new(
            BlobRef {
                digest: ContentDigest::new(plaintext_digest(&third_bytes))?,
                size_bytes: u64::try_from(third_bytes.len())?,
                media_type: second.reference.media_type.clone(),
            },
            third_bytes,
        )?;
        store.put("tenant-a", &successor.key_ref, &third, 2)?;
        let first_path = directory
            .path()
            .join("tenant-a/blobs")
            .join(digest.as_str());
        let swapped_path = directory
            .path()
            .join("tenant-a/blobs")
            .join(third.reference.digest.as_str());
        std::fs::copy(first_path, &swapped_path)?;
        assert_eq!(
            store
                .get("tenant-a", &third.reference, 2)
                .map_err(|error| error.code()),
            Err(BlobErrorCode::Corrupt)
        );
        assert!(!swapped_path.exists());

        let corrupt_path = directory
            .path()
            .join("tenant-a/blobs")
            .join(second.reference.digest.as_str());
        let mut corrupt = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&corrupt_path)?;
        corrupt.seek(SeekFrom::End(-1))?;
        let mut last = [0_u8; 1];
        corrupt.read_exact(&mut last)?;
        let byte = last.first_mut().ok_or("missing corruption byte")?;
        *byte ^= 1;
        corrupt.seek(SeekFrom::End(-1))?;
        corrupt.write_all(&last)?;
        corrupt.sync_all()?;
        assert_eq!(
            store
                .get("tenant-a", &second.reference, 2)
                .map_err(|error| error.code()),
            Err(BlobErrorCode::Corrupt)
        );
        assert!(!corrupt_path.exists());
        let invalidations = store.invalidations("tenant-a", 10)?;
        assert!(invalidations.contains(&second.reference.digest));
        assert!(invalidations.contains(&third.reference.digest));

        let live = BTreeSet::from([digest.clone()]);
        let reconciliation = store.reconcile("tenant-a", &live)?;
        assert_eq!(reconciliation.live_files_retained, 1);
        let dry_run = store.garbage_collect(
            "tenant-a",
            &BTreeSet::new(),
            GarbageCollectionPolicy {
                retention_satisfied: true,
                legal_hold: false,
                backup_complete: true,
            },
            true,
            10,
        )?;
        assert_eq!(dry_run.eligible, vec![digest.as_str().to_owned()]);
        assert_eq!(dry_run.deleted, 0);
        Ok(())
    }

    #[test]
    fn every_publication_failpoint_is_atomic_and_reconcilable()
    -> Result<(), Box<dyn std::error::Error>> {
        for failpoint in [
            BlobFailpoint::AfterTemporaryCreate,
            BlobFailpoint::AfterTemporaryWrite,
            BlobFailpoint::AfterFileSync,
            BlobFailpoint::AfterRename,
            BlobFailpoint::AfterDirectorySync,
        ] {
            let directory = tempfile::tempdir()?;
            let provider = Arc::new(MemoryKeyProvider::default());
            let key = provider.create(CreateKeyRequest {
                tenant: "tenant-a".to_owned(),
                purpose: KeyPurpose::BlobEncryption,
                algorithm: KeyAlgorithm::XChaCha20Poly1305,
                created_at: 1,
                activated_at: 1,
            })?;
            let store = LocalBlobStore::open(directory.path(), provider)?;
            let (blob, _digest) = fixture()?;
            store.inject_failpoint(failpoint)?;
            assert_eq!(
                store
                    .put("tenant-a", &key.key_ref, &blob, 1)
                    .map_err(|error| error.code()),
                Err(BlobErrorCode::InjectedAbort)
            );
            let report = store.reconcile("tenant-a", &BTreeSet::new())?;
            assert!(report.temporary_files_removed + report.orphan_files_quarantined <= 1);
        }
        Ok(())
    }

    #[test]
    fn multi_tenant_adapter_persists_distinct_scoped_key_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let blob_root = directory.path().join("blobs");
        let key_root = directory.path().join("key-references");
        let provider = Arc::new(MemoryKeyProvider::default());
        let first_tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?;
        let second_tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000002")?;
        let (blob, _digest) = fixture()?;

        {
            let repository = MultiTenantLocalRepositoryBlobStore::open(
                &blob_root,
                &key_root,
                Arc::clone(&provider),
                1,
            )?;
            repository.put(&first_tenant, &blob)?;
            repository.put(&second_tenant, &blob)?;
            assert_eq!(
                repository.get(&first_tenant, &blob.reference)?,
                Some(blob.clone())
            );
            assert_eq!(
                repository.get(&second_tenant, &blob.reference)?,
                Some(blob.clone())
            );
        }

        let first_key = std::fs::read_to_string(
            key_root.join(format!("{}{KEY_REFERENCE_SUFFIX}", first_tenant.as_str())),
        )?;
        let second_key = std::fs::read_to_string(
            key_root.join(format!("{}{KEY_REFERENCE_SUFFIX}", second_tenant.as_str())),
        )?;
        assert_ne!(first_key, second_key);

        let restarted =
            MultiTenantLocalRepositoryBlobStore::open(blob_root, key_root, provider, 2)?;
        assert_eq!(restarted.get(&first_tenant, &blob.reference)?, Some(blob));
        Ok(())
    }

    #[test]
    fn integrity_verification_detects_corruption_without_quarantining_or_repairing()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let blob_root = directory.path().join("blobs");
        let key_root = directory.path().join("key-references");
        let provider = Arc::new(MemoryKeyProvider::default());
        let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?;
        let (blob, digest) = fixture()?;
        let repository =
            MultiTenantLocalRepositoryBlobStore::open(&blob_root, key_root, provider, 1)?;
        repository.put(&tenant, &blob)?;
        repository.verify_integrity(&tenant, &blob.reference)?;

        let path = blob_root
            .join(tenant.as_str())
            .join("blobs")
            .join(digest.as_str());
        let mut corrupt = OpenOptions::new().read(true).write(true).open(&path)?;
        corrupt.seek(SeekFrom::End(-1))?;
        let mut last = [0_u8; 1];
        corrupt.read_exact(&mut last)?;
        let byte = last.first_mut().ok_or("missing corruption byte")?;
        *byte ^= 1;
        corrupt.seek(SeekFrom::End(-1))?;
        corrupt.write_all(&last)?;
        corrupt.sync_all()?;

        assert_eq!(
            repository
                .verify_integrity(&tenant, &blob.reference)
                .map_err(|error| error.code()),
            Err(StoreErrorCode::InvalidRecord)
        );
        assert!(path.is_file());
        assert!(!blob_root.join(tenant.as_str()).join("quarantine").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn blob_reads_never_follow_a_digest_named_symlink_outside_the_store()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let blob_root = directory.path().join("blobs");
        let key_root = directory.path().join("key-references");
        let provider = Arc::new(MemoryKeyProvider::default());
        let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?;
        let (blob, digest) = fixture()?;
        let repository =
            MultiTenantLocalRepositoryBlobStore::open(&blob_root, key_root, provider, 1)?;
        repository.put(&tenant, &blob)?;

        let path = blob_root
            .join(tenant.as_str())
            .join("blobs")
            .join(digest.as_str());
        let external = directory.path().join("external-valid-ciphertext");
        std::fs::rename(&path, &external)?;
        symlink(&external, &path)?;

        assert!(
            repository
                .verify_integrity(&tenant, &blob.reference)
                .is_err()
        );
        assert!(repository.get(&tenant, &blob.reference).is_err());
        assert!(path.symlink_metadata()?.file_type().is_symlink());
        assert!(external.is_file());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_blob_root_fails_closed_without_partial_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let key = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let store = LocalBlobStore::open(directory.path(), provider)?;
        let (blob, _digest) = fixture()?;
        let original = std::fs::metadata(directory.path())?.permissions();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500))?;
        let publication = store.put("tenant-a", &key.key_ref, &blob, 1);
        std::fs::set_permissions(directory.path(), original)?;
        assert_eq!(
            publication.map_err(|error| error.code()),
            Err(BlobErrorCode::Unavailable)
        );
        assert!(!directory.path().join("tenant-a").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn permission_loss_is_unavailable_without_quarantine_or_plaintext_diagnostic()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let key = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let store = LocalBlobStore::open(directory.path(), provider)?;
        let (blob, digest) = fixture()?;
        store.put("tenant-a", &key.key_ref, &blob, 1)?;
        let path = directory
            .path()
            .join("tenant-a/blobs")
            .join(digest.as_str());
        let original = std::fs::metadata(&path)?.permissions();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
        let result = store.get("tenant-a", &blob.reference, 1);
        std::fs::set_permissions(&path, original)?;
        let error = result
            .err()
            .ok_or("permission loss unexpectedly succeeded")?;
        assert_eq!(error.code(), BlobErrorCode::Unavailable);
        assert!(path.exists());
        assert!(!format!("{error:?}").contains("secret-canary"));
        Ok(())
    }
}
