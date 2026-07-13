//! Signed local backup creation, offline verification, and empty-target restore.

use crate::SqliteStore;
use crate::blob::{BlobError, BlobErrorCode, verify_persisted_blob};
use crate::sqlite::{backup_blob_references, verify_sqlite_file};
use cigar_crypto::{
    KeyAlgorithm, KeyProvider, KeyRef, SignatureEnvelope, SignatureRequest, SignatureVerification,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MANIFEST_FILE: &str = "manifest.cbor";
const SIGNATURE_FILE: &str = "manifest.signature.cbor";
const DATABASE_FILE: &str = "database.sqlite3";
const BLOBS_DIRECTORY: &str = "blobs";
const MAX_BACKUP_FILES: usize = 1_000_000;
const MAX_MANIFEST_BYTES: u64 = 67_108_864;
const MAX_BLOB_FILE_BYTES: u64 = 67_110_000;
const COPY_BUFFER_BYTES: usize = 1_048_576;

/// Stable content-free backup and restore failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupErrorCode {
    /// A path, manifest, signature, or bounded field is invalid.
    InvalidMetadata,
    /// A file checksum, manifest root, signature, or database integrity check failed.
    Corrupt,
    /// The destination is not empty or already contains an archive.
    DestinationNotEmpty,
    /// A required key cannot sign or verify the archive.
    KeyUnavailable,
    /// The authenticated archive signer is not accepted by the caller's current trust policy.
    UntrustedSigner,
    /// A filesystem, serialization, or database operation failed safely.
    Unavailable,
    /// A file-count or manifest-size bound was exceeded.
    LimitExceeded,
    /// A named backup durability failpoint interrupted creation.
    InjectedAbort,
}

/// Content-free backup error safe for logs and diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupError {
    code: BackupErrorCode,
}

impl BackupError {
    const fn new(code: BackupErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> BackupErrorCode {
        self.code
    }
}

impl fmt::Debug for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "backup operation failed: {:?}", self.code)
    }
}

impl std::error::Error for BackupError {}

/// One immutable encrypted or metadata file in a backup inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFile {
    /// Slash-separated archive-relative path.
    pub path: String,
    /// Exact file size.
    pub size_bytes: u64,
    /// SHA-256 multihash of exact stored bytes.
    pub checksum: String,
}

/// Signed semantic inventory for one consistent local backup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    /// Backup manifest format version.
    pub format_version: u8,
    /// SQLite schema migration sequence.
    pub schema_version: u64,
    /// Latest committed repository revision.
    pub repository_revision: u64,
    /// Backup creation time in Unix nanoseconds.
    pub created_at_unix_nanos: i128,
    /// Sorted file inventory excluding manifest and signature files.
    pub files: Vec<BackupFile>,
    /// Sorted opaque wrapping and signing key references needed by this archive.
    pub key_references: Vec<String>,
    /// Deterministic root over the sorted file inventory.
    pub canonical_root: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedSignature {
    algorithm: String,
    key_ref: String,
    tenant: String,
    signer: String,
    purpose: String,
    signed_at: i128,
    expires_at: Option<i128>,
    payload_digest: Vec<u8>,
    signature: Vec<u8>,
}

/// Authenticated identity carried by one signed backup archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSignatureIdentity {
    /// Tenant whose retained signing key authenticated the archive.
    pub tenant: String,
    /// Operator principal recorded in the signed envelope.
    pub signer: String,
    /// Exact active or retired signing key that authenticated the archive.
    pub signing_key: KeyRef,
    /// Semantic time at which the archive was signed.
    pub signed_at_unix_nanos: i128,
}

/// Manifest plus the exact signer identity authenticated during one verification pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBackup {
    /// Integrity-checked semantic inventory.
    pub manifest: BackupManifest,
    /// Cryptographically authenticated archive signer.
    pub signature: BackupSignatureIdentity,
}

/// Fully bound identity and semantic time for signing one backup manifest.
#[derive(Clone, Copy, Debug)]
pub struct BackupIdentity<'a> {
    /// Active tenant signing key.
    pub signing_key: &'a KeyRef,
    /// Tenant owning the backup.
    pub tenant: &'a str,
    /// Authenticated operator principal.
    pub signer: &'a str,
    /// Backup creation and signature time in Unix nanoseconds.
    pub created_at_unix_nanos: i128,
}

/// Named one-shot backup publication boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BackupFailpoint {
    /// After the consistent database copy is synchronized.
    AfterDatabaseBackup,
    /// After encrypted blob inventory files are copied.
    AfterBlobCopy,
    /// After manifest and signature files are synchronized.
    AfterManifestWrite,
    /// After the complete temporary archive directory is synchronized.
    AfterArchiveSync,
    /// After atomic archive rename and parent-directory synchronization.
    AfterRename,
    /// After all verified archive files are copied into the temporary restore.
    AfterRestoreCopy,
    /// After restored SQLite integrity validation.
    AfterRestoreValidation,
    /// After synchronizing the complete temporary restore tree.
    AfterRestoreSync,
    /// After atomic restored-location activation.
    AfterRestoreRename,
}

/// Thread-safe one-shot backup failpoint controller for crash-matrix tests.
#[derive(Default)]
pub struct BackupFailpoints {
    armed: Mutex<BTreeSet<BackupFailpoint>>,
}

impl fmt::Debug for BackupFailpoints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackupFailpoints")
    }
}

impl BackupFailpoints {
    /// Arms one named boundary.
    pub fn inject(&self, failpoint: BackupFailpoint) -> Result<(), BackupError> {
        self.armed
            .lock()
            .map_err(|_error| BackupError::new(BackupErrorCode::Unavailable))?
            .insert(failpoint);
        Ok(())
    }

    fn trip(&self, failpoint: BackupFailpoint) -> Result<(), BackupError> {
        if self
            .armed
            .lock()
            .map_err(|_error| BackupError::new(BackupErrorCode::Unavailable))?
            .remove(&failpoint)
        {
            Err(BackupError::new(BackupErrorCode::InjectedAbort))
        } else {
            Ok(())
        }
    }
}

/// Creates a signed, transactionally consistent local backup directory atomically.
pub fn create_backup<P: KeyProvider>(
    store: &SqliteStore,
    blob_root: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    provider: &P,
    identity: BackupIdentity<'_>,
) -> Result<BackupManifest, BackupError> {
    create_backup_internal(
        store,
        blob_root.as_ref(),
        destination.as_ref(),
        provider,
        identity,
        None,
    )
}

/// Creates a backup while exposing named one-shot crash boundaries to tests.
pub fn create_backup_with_failpoints<P: KeyProvider>(
    store: &SqliteStore,
    blob_root: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    provider: &P,
    identity: BackupIdentity<'_>,
    failpoints: &BackupFailpoints,
) -> Result<BackupManifest, BackupError> {
    create_backup_internal(
        store,
        blob_root.as_ref(),
        destination.as_ref(),
        provider,
        identity,
        Some(failpoints),
    )
}

fn create_backup_internal<P: KeyProvider>(
    store: &SqliteStore,
    blob_root: &Path,
    destination: &Path,
    provider: &P,
    identity: BackupIdentity<'_>,
    failpoints: Option<&BackupFailpoints>,
) -> Result<BackupManifest, BackupError> {
    if destination.exists() {
        return Err(BackupError::new(BackupErrorCode::DestinationNotEmpty));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| BackupError::new(BackupErrorCode::InvalidMetadata))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = tempfile::Builder::new()
        .prefix(".cigar-backup-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    restrict_directory_permissions(temporary.path())?;
    let database = temporary.path().join(DATABASE_FILE);
    let repository_revision =
        store.with_consistent_backup(&database, |revision| -> Result<u64, BackupError> {
            restrict_file_permissions(&database)?;
            normalize_backup_database(&database)?;
            sync_file(&database)?;
            trip_backup(failpoints, BackupFailpoint::AfterDatabaseBackup)?;
            let blobs = temporary.path().join(BLOBS_DIRECTORY);
            copy_tree(blob_root, &blobs)?;
            trip_backup(failpoints, BackupFailpoint::AfterBlobCopy)?;
            Ok(revision.0)
        })?;
    let files = inventory_data_files(temporary.path())?;
    let mut key_references = semantic_blob_key_references(
        temporary.path(),
        &database,
        &files,
        provider,
        identity.created_at_unix_nanos,
    )?;
    key_references.insert(identity.signing_key.as_str().to_owned());
    let canonical_root = inventory_root(&files)?;
    let schema_version = sqlite_schema_version(&database)?;
    let manifest = BackupManifest {
        format_version: 1,
        schema_version,
        repository_revision,
        created_at_unix_nanos: identity.created_at_unix_nanos,
        files,
        key_references: key_references.into_iter().collect(),
        canonical_root,
    };
    let manifest_bytes = encode_cbor(&manifest)?;
    let payload_digest = sha256_bytes(&manifest_bytes);
    let signature = provider
        .sign(SignatureRequest {
            key_ref: identity.signing_key,
            tenant: identity.tenant,
            signer: identity.signer,
            purpose: "backup-manifest-v1",
            payload_digest,
            signed_at: identity.created_at_unix_nanos,
            expires_at: None,
        })
        .map_err(crypto_error)?;
    write_new_synced(&temporary.path().join(MANIFEST_FILE), &manifest_bytes)?;
    write_new_synced(
        &temporary.path().join(SIGNATURE_FILE),
        &encode_cbor(&persisted_signature(&signature, identity.tenant))?,
    )?;
    trip_backup(failpoints, BackupFailpoint::AfterManifestWrite)?;
    sync_directory(temporary.path())?;
    trip_backup(failpoints, BackupFailpoint::AfterArchiveSync)?;
    let temporary_path = temporary.keep();
    fs::rename(temporary_path, destination).map_err(io_error)?;
    sync_directory(parent)?;
    trip_backup(failpoints, BackupFailpoint::AfterRename)?;
    Ok(manifest)
}

fn trip_backup(
    failpoints: Option<&BackupFailpoints>,
    failpoint: BackupFailpoint,
) -> Result<(), BackupError> {
    failpoints.map_or(Ok(()), |controller| controller.trip(failpoint))
}

/// Verifies signature, inventory, exact file checksums, root, schema, and database integrity.
pub fn verify_backup<P: KeyProvider>(
    backup: impl AsRef<Path>,
    provider: &P,
    tenant: &str,
    signer: &str,
    now: i128,
) -> Result<BackupManifest, BackupError> {
    verify_backup_trusted(backup, provider, now, |identity| {
        identity.tenant == tenant && identity.signer == signer
    })
    .map(|verified| verified.manifest)
}

/// Verifies one archive and applies current trust policy to its embedded signer atomically.
///
/// The callback observes untrusted bounded identity fields parsed from the same signature bytes
/// that are subsequently verified. It should accept only a configured tenant/principal/key tuple
/// and must reject current principal or key revocations. Retired provider keys remain usable for a
/// signature made before their retirement; destroyed, cross-tenant, or time-invalid keys fail at
/// the provider boundary.
pub fn verify_backup_trusted<P, F>(
    backup: impl AsRef<Path>,
    provider: &P,
    now: i128,
    trust: F,
) -> Result<VerifiedBackup, BackupError>
where
    P: KeyProvider,
    F: Fn(&BackupSignatureIdentity) -> bool,
{
    verify_backup_internal(backup.as_ref(), provider, now, &trust)
}

fn verify_backup_internal<P, F>(
    backup: &Path,
    provider: &P,
    now: i128,
    trust: &F,
) -> Result<VerifiedBackup, BackupError>
where
    P: KeyProvider,
    F: Fn(&BackupSignatureIdentity) -> bool,
{
    let manifest_bytes = read_bounded(&backup.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest: BackupManifest = decode_cbor(&manifest_bytes)?;
    if encode_cbor(&manifest)? != manifest_bytes {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    validate_manifest(&manifest)?;
    let persisted_bytes = read_bounded(&backup.join(SIGNATURE_FILE), MAX_MANIFEST_BYTES)?;
    let persisted: PersistedSignature = decode_cbor(&persisted_bytes)?;
    if encode_cbor(&persisted)? != persisted_bytes {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    let tenant = persisted.tenant.clone();
    let signature = restore_signature(persisted)?;
    let identity = BackupSignatureIdentity {
        tenant,
        signer: signature.signer.clone(),
        signing_key: signature.key_ref.clone(),
        signed_at_unix_nanos: signature.signed_at,
    };
    validate_signature_identity(&identity)?;
    if signature.purpose != "backup-manifest-v1"
        || signature.expires_at.is_some()
        || signature.signed_at != manifest.created_at_unix_nanos
        || manifest
            .key_references
            .binary_search_by(|reference| reference.as_str().cmp(signature.key_ref.as_str()))
            .is_err()
    {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    if !trust(&identity) {
        return Err(BackupError::new(BackupErrorCode::UntrustedSigner));
    }
    let payload_digest = sha256_bytes(&manifest_bytes);
    provider
        .verify(
            &signature,
            SignatureVerification {
                tenant: &identity.tenant,
                signer: &identity.signer,
                purpose: "backup-manifest-v1",
                payload_digest: &payload_digest,
                now,
            },
        )
        .map_err(crypto_error)?;
    let actual_files = inventory_data_files(backup)?;
    if actual_files != manifest.files || inventory_root(&actual_files)? != manifest.canonical_root {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    let database = backup.join(DATABASE_FILE);
    if sqlite_schema_version(&database)? != manifest.schema_version {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    verify_sqlite_file(&database).map_err(store_error)?;
    if sqlite_revision(&database)? != manifest.repository_revision {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    let mut semantic_key_references = semantic_blob_key_references(
        backup,
        &database,
        &actual_files,
        provider,
        manifest.created_at_unix_nanos,
    )?;
    semantic_key_references.insert(identity.signing_key.as_str().to_owned());
    if semantic_key_references.into_iter().collect::<Vec<_>>() != manifest.key_references {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    Ok(VerifiedBackup {
        manifest,
        signature: identity,
    })
}

/// Restores a verified archive into a nonexistent or exactly empty target directory.
pub fn restore_backup<P: KeyProvider>(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    provider: &P,
    tenant: &str,
    signer: &str,
    now: i128,
) -> Result<BackupManifest, BackupError> {
    restore_backup_internal(
        backup.as_ref(),
        destination.as_ref(),
        provider,
        now,
        &|identity| identity.tenant == tenant && identity.signer == signer,
        None,
    )
    .map(|verified| verified.manifest)
}

/// Restores only after the exact embedded signer passes current caller-supplied trust policy.
pub fn restore_backup_trusted<P, F>(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    provider: &P,
    now: i128,
    trust: F,
) -> Result<VerifiedBackup, BackupError>
where
    P: KeyProvider,
    F: Fn(&BackupSignatureIdentity) -> bool,
{
    restore_backup_internal(
        backup.as_ref(),
        destination.as_ref(),
        provider,
        now,
        &trust,
        None,
    )
}

/// Restores while exposing named one-shot copy, validation, sync, and activation boundaries.
pub fn restore_backup_with_failpoints<P: KeyProvider>(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    provider: &P,
    tenant: &str,
    signer: &str,
    now: i128,
    failpoints: &BackupFailpoints,
) -> Result<BackupManifest, BackupError> {
    restore_backup_internal(
        backup.as_ref(),
        destination.as_ref(),
        provider,
        now,
        &|identity| identity.tenant == tenant && identity.signer == signer,
        Some(failpoints),
    )
    .map(|verified| verified.manifest)
}

fn restore_backup_internal<P, F>(
    backup: &Path,
    destination: &Path,
    provider: &P,
    now: i128,
    trust: &F,
    failpoints: Option<&BackupFailpoints>,
) -> Result<VerifiedBackup, BackupError>
where
    P: KeyProvider,
    F: Fn(&BackupSignatureIdentity) -> bool,
{
    let source_verified = verify_backup_internal(backup, provider, now, trust)?;
    let destination_was_empty = if destination.exists() {
        if !destination.is_dir()
            || fs::read_dir(destination)
                .map_err(io_error)?
                .next()
                .is_some()
        {
            return Err(BackupError::new(BackupErrorCode::DestinationNotEmpty));
        }
        true
    } else {
        false
    };
    let parent = destination
        .parent()
        .ok_or_else(|| BackupError::new(BackupErrorCode::InvalidMetadata))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = tempfile::Builder::new()
        .prefix(".cigar-restore-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    restrict_directory_permissions(temporary.path())?;
    copy_tree(backup, temporary.path())?;
    trip_backup(failpoints, BackupFailpoint::AfterRestoreCopy)?;
    let verified = verify_backup_internal(temporary.path(), provider, now, trust)?;
    if verified != source_verified {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }
    trip_backup(failpoints, BackupFailpoint::AfterRestoreValidation)?;
    sync_tree(temporary.path())?;
    trip_backup(failpoints, BackupFailpoint::AfterRestoreSync)?;
    let temporary_path = temporary.keep();
    if destination_was_empty {
        fs::remove_dir(destination).map_err(io_error)?;
    }
    fs::rename(temporary_path, destination).map_err(io_error)?;
    sync_directory(parent)?;
    trip_backup(failpoints, BackupFailpoint::AfterRestoreRename)?;
    Ok(verified)
}

fn persisted_signature(signature: &SignatureEnvelope, tenant: &str) -> PersistedSignature {
    PersistedSignature {
        algorithm: "ed25519".to_owned(),
        key_ref: signature.key_ref.as_str().to_owned(),
        tenant: tenant.to_owned(),
        signer: signature.signer.clone(),
        purpose: signature.purpose.clone(),
        signed_at: signature.signed_at,
        expires_at: signature.expires_at,
        payload_digest: signature.payload_digest.to_vec(),
        signature: signature.signature.to_vec(),
    }
}

fn validate_signature_identity(identity: &BackupSignatureIdentity) -> Result<(), BackupError> {
    let valid_scope = |value: &str| {
        !value.is_empty()
            && value.len() <= 256
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    if identity.signed_at_unix_nanos < 0
        || !valid_scope(&identity.tenant)
        || !valid_scope(&identity.signer)
    {
        Err(BackupError::new(BackupErrorCode::InvalidMetadata))
    } else {
        Ok(())
    }
}

fn restore_signature(value: PersistedSignature) -> Result<SignatureEnvelope, BackupError> {
    if value.algorithm != "ed25519" {
        return Err(BackupError::new(BackupErrorCode::InvalidMetadata));
    }
    Ok(SignatureEnvelope {
        algorithm: KeyAlgorithm::Ed25519,
        key_ref: KeyRef::new(value.key_ref).map_err(crypto_error)?,
        signer: value.signer,
        purpose: value.purpose,
        signed_at: value.signed_at,
        expires_at: value.expires_at,
        payload_digest: value
            .payload_digest
            .try_into()
            .map_err(|_error| BackupError::new(BackupErrorCode::InvalidMetadata))?,
        signature: value
            .signature
            .try_into()
            .map_err(|_error| BackupError::new(BackupErrorCode::InvalidMetadata))?,
    })
}

fn validate_manifest(manifest: &BackupManifest) -> Result<(), BackupError> {
    if manifest.format_version != 1
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_BACKUP_FILES
        || manifest.key_references.is_empty()
        || manifest.files.windows(2).any(|pair| {
            pair.first().map(|entry| &entry.path) >= pair.get(1).map(|entry| &entry.path)
        })
        || manifest
            .key_references
            .windows(2)
            .any(|pair| pair.first().map(String::as_str) >= pair.get(1).map(String::as_str))
    {
        return Err(BackupError::new(BackupErrorCode::InvalidMetadata));
    }
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        validate_checksum(&file.checksum)?;
    }
    validate_checksum(&manifest.canonical_root)
}

fn inventory_data_files(root: &Path) -> Result<Vec<BackupFile>, BackupError> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.retain(|path| path != MANIFEST_FILE && path != SIGNATURE_FILE);
    if paths.len() > MAX_BACKUP_FILES {
        return Err(BackupError::new(BackupErrorCode::LimitExceeded));
    }
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    for relative in paths {
        let path = root.join(&relative);
        files.push(BackupFile {
            path: relative,
            size_bytes: path.metadata().map_err(io_error)?.len(),
            checksum: file_checksum(&path)?,
        });
    }
    Ok(files)
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<String>) -> Result<(), BackupError> {
    if !current.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(current)
        .map_err(io_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(io_error)?;
        if file_type.is_symlink() {
            return Err(BackupError::new(BackupErrorCode::InvalidMetadata));
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .map(|value| value.replace(std::path::MAIN_SEPARATOR, "/"))
                .ok_or_else(|| BackupError::new(BackupErrorCode::InvalidMetadata))?;
            validate_relative_path(&relative)?;
            files.push(relative);
            if files.len() > MAX_BACKUP_FILES {
                return Err(BackupError::new(BackupErrorCode::LimitExceeded));
            }
        }
    }
    Ok(())
}

fn semantic_blob_key_references<P: KeyProvider>(
    root: &Path,
    database: &Path,
    files: &[BackupFile],
    provider: &P,
    semantic_time: i128,
) -> Result<BTreeSet<String>, BackupError> {
    let authoritative = backup_blob_references(database)
        .map_err(|_error| BackupError::new(BackupErrorCode::Corrupt))?;
    let mut expected = BTreeMap::new();
    for (tenant, references) in authoritative {
        for reference in references {
            let path = format!(
                "{BLOBS_DIRECTORY}/{}/blobs/{}",
                tenant.as_str(),
                reference.digest.as_str()
            );
            validate_relative_path(&path)?;
            if expected
                .insert(path, (tenant.as_str().to_owned(), reference))
                .is_some()
            {
                return Err(BackupError::new(BackupErrorCode::Corrupt));
            }
        }
    }
    let actual = files
        .iter()
        .filter(|file| file.path.starts_with(&format!("{BLOBS_DIRECTORY}/")))
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if actual != expected.keys().cloned().collect() {
        return Err(BackupError::new(BackupErrorCode::Corrupt));
    }

    let mut references = BTreeSet::new();
    for (path, (tenant, reference)) in expected {
        let bytes = read_bounded(&root.join(path), MAX_BLOB_FILE_BYTES)?;
        let key = verify_persisted_blob(provider, &bytes, &tenant, &reference, semantic_time)
            .map_err(blob_error)?;
        references.insert(key.as_str().to_owned());
    }
    Ok(references)
}

fn inventory_root(files: &[BackupFile]) -> Result<String, BackupError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-BACKUP-ROOT\0v1\0");
    for file in files {
        let length = u32::try_from(file.path.len())
            .map_err(|_error| BackupError::new(BackupErrorCode::LimitExceeded))?;
        hasher.update(length.to_be_bytes());
        hasher.update(file.path.as_bytes());
        hasher.update(file.size_bytes.to_be_bytes());
        hasher.update(file.checksum.as_bytes());
    }
    Ok(multihash(hasher.finalize().as_slice()))
}

fn sqlite_schema_version(database: &Path) -> Result<u64, BackupError> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(sqlite_error)?;
    connection
        .query_row("SELECT MAX(sequence) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .map_err(sqlite_error)?
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| BackupError::new(BackupErrorCode::Corrupt))
}

fn sqlite_revision(database: &Path) -> Result<u64, BackupError> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(sqlite_error)?;
    connection
        .query_row("SELECT MAX(revision) FROM state_snapshots", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .map_err(sqlite_error)?
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| BackupError::new(BackupErrorCode::Corrupt))
}

fn normalize_backup_database(database: &Path) -> Result<(), BackupError> {
    let connection = rusqlite::Connection::open(database).map_err(sqlite_error)?;
    let mode = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_error)?;
    if mode != "delete" {
        return Err(BackupError::new(BackupErrorCode::Unavailable));
    }
    connection
        .execute_batch("PRAGMA synchronous = FULL;")
        .map_err(sqlite_error)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), BackupError> {
    if !source.exists() {
        fs::create_dir_all(destination).map_err(io_error)?;
        restrict_directory_permissions(destination)?;
        return Ok(());
    }
    fs::create_dir_all(destination).map_err(io_error)?;
    restrict_directory_permissions(destination)?;
    let mut entries = fs::read_dir(source)
        .map_err(io_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(io_error)?;
        let target = destination.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(BackupError::new(BackupErrorCode::InvalidMetadata));
        }
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            copy_file(&entry.path(), &target)?;
        }
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), BackupError> {
    let mut source = File::open(source).map_err(io_error)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut destination = options.open(destination).map_err(io_error)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| BackupError::new(BackupErrorCode::Unavailable))?;
        destination.write_all(chunk).map_err(io_error)?;
    }
    destination.sync_all().map_err(io_error)
}

fn sync_tree(root: &Path) -> Result<(), BackupError> {
    let mut directories = Vec::new();
    collect_directories(root, &mut directories)?;
    for directory in directories.into_iter().rev() {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn collect_directories(current: &Path, directories: &mut Vec<PathBuf>) -> Result<(), BackupError> {
    directories.push(current.to_path_buf());
    for entry in fs::read_dir(current).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_dir() {
            collect_directories(&entry.path(), directories)?;
        }
    }
    Ok(())
}

fn file_checksum(path: &Path) -> Result<String, BackupError> {
    let mut file = File::open(path).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(
            buffer
                .get(..read)
                .ok_or_else(|| BackupError::new(BackupErrorCode::Unavailable))?,
        );
    }
    Ok(multihash(hasher.finalize().as_slice()))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn multihash(bytes: &[u8]) -> String {
    let mut value = String::from("1220");
    for byte in bytes {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn validate_checksum(value: &str) -> Result<(), BackupError> {
    if value.len() == 68
        && value.starts_with("1220")
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(BackupError::new(BackupErrorCode::InvalidMetadata))
    }
}

fn validate_relative_path(value: &str) -> Result<(), BackupError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        Err(BackupError::new(BackupErrorCode::InvalidMetadata))
    } else {
        Ok(())
    }
}

fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, BackupError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|_error| BackupError::new(BackupErrorCode::Unavailable))?;
    Ok(bytes)
}

fn decode_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, BackupError> {
    ciborium::de::from_reader(bytes).map_err(|_error| BackupError::new(BackupErrorCode::Corrupt))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BackupError> {
    let mut file = File::open(path).map_err(io_error)?;
    let length = file.metadata().map_err(io_error)?.len();
    if length > maximum {
        return Err(BackupError::new(BackupErrorCode::LimitExceeded));
    }
    let capacity = usize::try_from(length)
        .map_err(|_error| BackupError::new(BackupErrorCode::LimitExceeded))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes).map_err(io_error)?;
    Ok(bytes)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn sync_file(path: &Path) -> Result<(), BackupError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), BackupError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

fn crypto_error(_error: cigar_crypto::CryptoError) -> BackupError {
    BackupError::new(BackupErrorCode::KeyUnavailable)
}

fn blob_error(error: BlobError) -> BackupError {
    match error.code() {
        BlobErrorCode::KeyUnavailable => BackupError::new(BackupErrorCode::KeyUnavailable),
        BlobErrorCode::LimitExceeded => BackupError::new(BackupErrorCode::LimitExceeded),
        _ => BackupError::new(BackupErrorCode::Corrupt),
    }
}

fn store_error(_error: crate::StoreError) -> BackupError {
    BackupError::new(BackupErrorCode::Unavailable)
}

impl From<crate::StoreError> for BackupError {
    fn from(error: crate::StoreError) -> Self {
        store_error(error)
    }
}

fn sqlite_error(_error: rusqlite::Error) -> BackupError {
    BackupError::new(BackupErrorCode::Corrupt)
}

fn io_error(_error: std::io::Error) -> BackupError {
    BackupError::new(BackupErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        BackupErrorCode, BackupFailpoint, BackupFailpoints, BackupIdentity, DATABASE_FILE,
        copy_tree, create_backup, create_backup_with_failpoints, restore_backup,
        restore_backup_trusted, restore_backup_with_failpoints, verify_backup,
        verify_backup_trusted,
    };
    use crate::{
        AccessContext, BlobRecord, CancellationToken, LocalBlobStore, LocalRepositoryBlobStore,
        ReadTransaction, Repository, SnapshotSelection, SqliteStore, StoreRevision,
        WriteTransaction,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider,
        SignatureRequest,
    };
    use cigar_protocol::{BlobRef, ContentDigest, MediaType, RecordId};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::Arc;

    fn digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        let suffix: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(ContentDigest::new(format!("1220{suffix}"))?)
    }

    #[test]
    fn backup_creation_rejects_unreferenced_physical_blobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("source.sqlite3"))?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let signing = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let wrapping = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let blob_root = directory.path().join("blob-source");
        let blobs = LocalBlobStore::open(&blob_root, Arc::clone(&provider))?;
        let bytes = b"unreferenced encrypted backup blob".to_vec();
        let blob = BlobRecord::new(
            BlobRef {
                digest: digest(&bytes)?,
                size_bytes: u64::try_from(bytes.len())?,
                media_type: MediaType::new("application/octet-stream")?,
            },
            bytes,
        )?;
        blobs.put("tenant-a", &wrapping.key_ref, &blob, 1)?;

        let result = create_backup(
            &store,
            &blob_root,
            directory.path().join("archive"),
            provider.as_ref(),
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "tenant-a",
                signer: "backup-operator",
                created_at_unix_nanos: 2,
            },
        );
        assert!(matches!(
            result,
            Err(error) if error.code() == BackupErrorCode::Corrupt
        ));
        Ok(())
    }

    #[test]
    fn signed_backup_verifies_restores_empty_and_preserves_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("source.sqlite3");
        let blob_tenant = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7890";
        let provider = Arc::new(MemoryKeyProvider::default());
        let signing = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let wrapping = provider.create(CreateKeyRequest {
            tenant: blob_tenant.to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let blob_root = directory.path().join("blob-source");
        let blobs = LocalBlobStore::open(&blob_root, Arc::clone(&provider))?;
        let repository = Arc::new(LocalRepositoryBlobStore::new(
            blobs,
            wrapping.key_ref.clone(),
            1,
        ));
        let store = SqliteStore::open_with_blob_repository(&database, repository)?;
        let bytes = b"backup encrypted secret canary".to_vec();
        let blob = BlobRecord::new(
            BlobRef {
                digest: digest(&bytes)?,
                size_bytes: u64::try_from(bytes.len())?,
                media_type: MediaType::new("application/octet-stream")?,
            },
            bytes,
        )?;
        let context = AccessContext::new(RecordId::new(blob_tenant)?, "backup")?;
        let mut write = store.begin_write(
            context.clone(),
            StoreRevision(0),
            CancellationToken::default(),
        )?;
        write.put_blob(blob.clone())?;
        write.commit(None)?;
        let read = store.begin_read(
            context,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;

        let source_blob = blob_root
            .join(blob_tenant)
            .join("blobs")
            .join(blob.reference.digest.as_str());
        let original_blob = fs::read(&source_blob)?;
        let mut corrupt_before_signing = original_blob.clone();
        *corrupt_before_signing
            .last_mut()
            .ok_or("missing source corruption byte")? ^= 1;
        fs::write(&source_blob, &corrupt_before_signing)?;
        let corrupt_before_signing_result = create_backup(
            &store,
            &blob_root,
            directory.path().join("backup-corrupt-before-signing"),
            provider.as_ref(),
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "tenant-a",
                signer: "backup-operator",
                created_at_unix_nanos: 2,
            },
        );
        assert!(matches!(
            corrupt_before_signing_result,
            Err(error) if error.code() == BackupErrorCode::Corrupt
        ));
        fs::write(&source_blob, &original_blob)?;
        fs::remove_file(&source_blob)?;
        let missing_before_signing_result = create_backup(
            &store,
            &blob_root,
            directory.path().join("backup-missing-before-signing"),
            provider.as_ref(),
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "tenant-a",
                signer: "backup-operator",
                created_at_unix_nanos: 2,
            },
        );
        assert!(matches!(
            missing_before_signing_result,
            Err(error) if error.code() == BackupErrorCode::Corrupt
        ));
        fs::write(&source_blob, &original_blob)?;

        let first_path = directory.path().join("backup-one");
        let first = create_backup(
            &store,
            &blob_root,
            &first_path,
            provider.as_ref(),
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "tenant-a",
                signer: "backup-operator",
                created_at_unix_nanos: 2,
            },
        )
        .map_err(|error| format!("create first: {error:?}"))?;
        assert_eq!(read.revision().0, 1);
        assert_eq!(
            verify_backup(
                &first_path,
                provider.as_ref(),
                "tenant-a",
                "backup-operator",
                3,
            )
            .map_err(|error| format!("verify first: {error:?}"))?,
            first
        );

        let resigned_corrupt_path = directory.path().join("backup-resigned-corrupt");
        copy_tree(&first_path, &resigned_corrupt_path)?;
        let resigned_corrupt_blob = resigned_corrupt_path
            .join(format!("blobs/{blob_tenant}/blobs"))
            .join(blob.reference.digest.as_str());
        let mut resigned_corrupt_bytes = fs::read(&resigned_corrupt_blob)?;
        *resigned_corrupt_bytes
            .last_mut()
            .ok_or("missing resigned corruption byte")? ^= 1;
        fs::write(&resigned_corrupt_blob, resigned_corrupt_bytes)?;
        let mut resigned_manifest = first.clone();
        resigned_manifest.files = super::inventory_data_files(&resigned_corrupt_path)?;
        resigned_manifest.canonical_root = super::inventory_root(&resigned_manifest.files)?;
        let resigned_manifest_bytes = super::encode_cbor(&resigned_manifest)?;
        let resigned_signature = provider.sign(SignatureRequest {
            key_ref: &signing.key_ref,
            tenant: "tenant-a",
            signer: "backup-operator",
            purpose: "backup-manifest-v1",
            payload_digest: super::sha256_bytes(&resigned_manifest_bytes),
            signed_at: resigned_manifest.created_at_unix_nanos,
            expires_at: None,
        })?;
        fs::write(
            resigned_corrupt_path.join(super::MANIFEST_FILE),
            resigned_manifest_bytes,
        )?;
        fs::write(
            resigned_corrupt_path.join(super::SIGNATURE_FILE),
            super::encode_cbor(&super::persisted_signature(&resigned_signature, "tenant-a"))?,
        )?;
        let resigned_corrupt_result = verify_backup(
            &resigned_corrupt_path,
            provider.as_ref(),
            "tenant-a",
            "backup-operator",
            3,
        );
        assert!(matches!(
            resigned_corrupt_result,
            Err(error) if error.code() == BackupErrorCode::Corrupt
        ));

        let corrupt_path = directory.path().join("backup-corrupt");
        copy_tree(&first_path, &corrupt_path)?;
        let corrupt_blob = corrupt_path
            .join(format!("blobs/{blob_tenant}/blobs"))
            .join(blob.reference.digest.as_str());
        let mut corrupt = OpenOptions::new()
            .read(true)
            .write(true)
            .open(corrupt_blob)?;
        corrupt.seek(SeekFrom::End(-1))?;
        let mut byte = [0_u8; 1];
        corrupt.read_exact(&mut byte)?;
        let value = byte.first_mut().ok_or("missing backup corruption byte")?;
        *value ^= 1;
        corrupt.seek(SeekFrom::End(-1))?;
        corrupt.write_all(&byte)?;
        corrupt.sync_all()?;
        let corrupt_result = verify_backup(
            &corrupt_path,
            provider.as_ref(),
            "tenant-a",
            "backup-operator",
            3,
        );
        assert!(matches!(
            corrupt_result,
            Err(error) if error.code() == BackupErrorCode::Corrupt
        ));
        for (index, failpoint) in [
            BackupFailpoint::AfterDatabaseBackup,
            BackupFailpoint::AfterBlobCopy,
            BackupFailpoint::AfterManifestWrite,
            BackupFailpoint::AfterArchiveSync,
            BackupFailpoint::AfterRename,
        ]
        .into_iter()
        .enumerate()
        {
            let destination = directory.path().join(format!("failed-backup-{index}"));
            let controller = BackupFailpoints::default();
            controller.inject(failpoint)?;
            let result = create_backup_with_failpoints(
                &store,
                &blob_root,
                &destination,
                provider.as_ref(),
                BackupIdentity {
                    signing_key: &signing.key_ref,
                    tenant: "tenant-a",
                    signer: "backup-operator",
                    created_at_unix_nanos: 3,
                },
                &controller,
            );
            assert!(matches!(
                result,
                Err(error) if error.code() == BackupErrorCode::InjectedAbort
            ));
            if failpoint == BackupFailpoint::AfterRename {
                verify_backup(
                    &destination,
                    provider.as_ref(),
                    "tenant-a",
                    "backup-operator",
                    4,
                )?;
            } else {
                assert!(!destination.exists());
            }
        }
        for (index, failpoint) in [
            BackupFailpoint::AfterRestoreCopy,
            BackupFailpoint::AfterRestoreValidation,
            BackupFailpoint::AfterRestoreSync,
            BackupFailpoint::AfterRestoreRename,
        ]
        .into_iter()
        .enumerate()
        {
            let destination = directory.path().join(format!("failed-restore-{index}"));
            let controller = BackupFailpoints::default();
            controller.inject(failpoint)?;
            let result = restore_backup_with_failpoints(
                &first_path,
                &destination,
                provider.as_ref(),
                "tenant-a",
                "backup-operator",
                4,
                &controller,
            );
            assert!(matches!(
                result,
                Err(error) if error.code() == BackupErrorCode::InjectedAbort
            ));
            if failpoint == BackupFailpoint::AfterRestoreRename {
                SqliteStore::open(destination.join("database.sqlite3"))?.integrity_check()?;
            } else {
                assert!(!destination.exists());
            }
        }
        let restored_path = directory.path().join("restored");
        restore_backup(
            &first_path,
            &restored_path,
            provider.as_ref(),
            "tenant-a",
            "backup-operator",
            3,
        )
        .map_err(|error| format!("restore: {error:?}"))?;
        let restored_store = SqliteStore::open(restored_path.join("database.sqlite3"))
            .map_err(|error| format!("open restored: {error:?}"))?;
        let second_path = directory.path().join("backup-two");
        let second = create_backup(
            &restored_store,
            restored_path.join("blobs"),
            &second_path,
            provider.as_ref(),
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "tenant-a",
                signer: "backup-operator",
                created_at_unix_nanos: 4,
            },
        )
        .map_err(|error| format!("create second: {error:?}"))?;
        assert_eq!(first.canonical_root, second.canonical_root);
        assert_eq!(first.repository_revision, second.repository_revision);
        Ok(())
    }

    #[test]
    fn embedded_signer_trust_survives_rotation_and_rejects_revocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("source.sqlite3"))?;
        let provider = MemoryKeyProvider::default();
        let signing = provider.create(CreateKeyRequest {
            tenant: "tenant-rotation".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let archive = directory.path().join("archive");
        create_backup(
            &store,
            directory.path().join("empty-blobs"),
            &archive,
            &provider,
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "tenant-rotation",
                signer: "operator-rotation",
                created_at_unix_nanos: 2,
            },
        )?;

        let successor = provider.rotate(&signing.key_ref, "tenant-rotation", 3)?;
        assert_ne!(successor.key_ref, signing.key_ref);
        let verified = verify_backup_trusted(&archive, &provider, 4, |identity| {
            identity.tenant == "tenant-rotation"
                && identity.signer == "operator-rotation"
                && identity.signing_key == signing.key_ref
        })?;
        assert_eq!(verified.signature.tenant, "tenant-rotation");
        assert_eq!(verified.signature.signer, "operator-rotation");
        assert_eq!(verified.signature.signing_key, signing.key_ref);
        assert_eq!(verified.signature.signed_at_unix_nanos, 2);

        let revoked = BTreeSet::from([signing.key_ref.clone()]);
        let denied = verify_backup_trusted(&archive, &provider, 4, |identity| {
            !revoked.contains(&identity.signing_key)
        })
        .map_err(|error| error.code());
        assert_eq!(denied, Err(BackupErrorCode::UntrustedSigner));

        let restored = directory.path().join("restored-after-rotation");
        let receipt = restore_backup_trusted(&archive, &restored, &provider, 4, |identity| {
            identity.tenant == "tenant-rotation"
                && identity.signer == "operator-rotation"
                && identity.signing_key == signing.key_ref
        })?;
        assert_eq!(receipt, verified);
        SqliteStore::open(restored.join(DATABASE_FILE))?.integrity_check()?;
        Ok(())
    }
}
