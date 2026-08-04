//! Tenant-key effect-record authentication with an external monotonic checkpoint file.

use cigar_canon::parse_strict_json;
use cigar_crypto::KeyRef;
use cigar_effects::{
    EffectError, EffectErrorCode, EffectRecordAuthenticator, EffectRecordSeal,
    persisted_effect_checkpoint_observation,
};
use cigar_protocol::{ContentDigest, RecordId};
use cigar_store::{SqliteStore, StoreErrorCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::cmp::Ordering;
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CHECKPOINT_SCHEMA: &str = "cigar.effect-checkpoints.v1";
const EFFECT_RECORD_SIGNATURE_DOMAIN: &[u8] = b"CIGAR-EFFECT-RECORD-SIGNATURE\0v1\0";
const MAX_CHECKPOINTS: usize = 1_000_000;
const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;
const TEMPORARY_NAME_ATTEMPTS: usize = 32;

/// Public signature material issued by the current tenant key authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecordSignature {
    key_ref: KeyRef,
    signed_at_unix_nanos: i128,
    signature: [u8; 64],
}

impl EffectRecordSignature {
    /// Creates one already verified-shape signature result.
    #[must_use]
    pub const fn new(key_ref: KeyRef, signed_at_unix_nanos: i128, signature: [u8; 64]) -> Self {
        Self {
            key_ref,
            signed_at_unix_nanos,
            signature,
        }
    }

    /// Returns the exact tenant key epoch.
    #[must_use]
    pub const fn key_ref(&self) -> &KeyRef {
        &self.key_ref
    }

    /// Returns the trusted signing time.
    #[must_use]
    pub const fn signed_at_unix_nanos(&self) -> i128 {
        self.signed_at_unix_nanos
    }

    /// Returns the Ed25519 proof bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Current tenant authority used for effect-specific signing and historical verification.
pub trait EffectRecordSignatureAuthority: Send + Sync {
    /// Signs one domain-separated canonical-record digest with the current non-revoked key.
    fn sign_effect_record(
        &self,
        tenant_id: &RecordId,
        payload_digest: [u8; 32],
    ) -> Result<EffectRecordSignature, EffectError>;

    /// Verifies one proof under current tenant and key-revocation authority.
    fn verify_effect_record(
        &self,
        tenant_id: &RecordId,
        payload_digest: &[u8; 32],
        signature: &EffectRecordSignature,
    ) -> Result<(), EffectError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectCheckpointEntry {
    tenant_id: RecordId,
    effect_id: RecordId,
    intent_digest: ContentDigest,
    effect_version: u64,
    authenticator: ContentDigest,
}

impl EffectCheckpointEntry {
    fn identity_cmp(&self, other: &Self) -> Ordering {
        (&self.tenant_id, &self.effect_id).cmp(&(&other.tenant_id, &other.effect_id))
    }

    fn identity_cmp_values(&self, tenant_id: &RecordId, effect_id: &RecordId) -> Ordering {
        (&self.tenant_id, &self.effect_id).cmp(&(tenant_id, effect_id))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectCheckpointDocument {
    schema_version: String,
    generation: u64,
    checkpoints: Vec<EffectCheckpointEntry>,
}

impl EffectCheckpointDocument {
    fn empty() -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA.to_owned(),
            generation: 0,
            checkpoints: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), EffectError> {
        if self.schema_version != CHECKPOINT_SCHEMA
            || self.checkpoints.len() > MAX_CHECKPOINTS
            || (self.generation == 0) != self.checkpoints.is_empty()
            || self.generation
                < u64::try_from(self.checkpoints.len())
                    .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?
            || self.checkpoints.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_none_or(|(left, right)| left.identity_cmp(right) != Ordering::Less)
            })
        {
            return Err(corrupt());
        }
        Ok(())
    }

    fn observe(
        &mut self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<bool, EffectError> {
        let location = self
            .checkpoints
            .binary_search_by(|checkpoint| checkpoint.identity_cmp_values(tenant_id, effect_id));
        match location {
            Ok(index) => {
                let checkpoint = self.checkpoints.get_mut(index).ok_or_else(corrupt)?;
                if intent_digest != &checkpoint.intent_digest
                    || (effect_version == checkpoint.effect_version
                        && authenticator != &checkpoint.authenticator)
                {
                    return Err(corrupt());
                }
                if effect_version < checkpoint.effect_version {
                    return Err(EffectError::new(EffectErrorCode::RevisionConflict));
                }
                if effect_version == checkpoint.effect_version {
                    return Ok(false);
                }
                checkpoint.effect_version = effect_version;
                checkpoint.authenticator = authenticator.clone();
            }
            Err(index) => {
                if self.checkpoints.len() >= MAX_CHECKPOINTS {
                    return Err(EffectError::new(EffectErrorCode::LimitExceeded));
                }
                self.checkpoints.insert(
                    index,
                    EffectCheckpointEntry {
                        tenant_id: tenant_id.clone(),
                        effect_id: effect_id.clone(),
                        intent_digest: intent_digest.clone(),
                        effect_version,
                        authenticator: authenticator.clone(),
                    },
                );
            }
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
        Ok(true)
    }

    fn verify_exact(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<(), EffectError> {
        let index = self
            .checkpoints
            .binary_search_by(|checkpoint| checkpoint.identity_cmp_values(tenant_id, effect_id))
            .map_err(|_index| corrupt())?;
        let checkpoint = self.checkpoints.get(index).ok_or_else(corrupt)?;
        if checkpoint.intent_digest != *intent_digest
            || checkpoint.effect_version != effect_version
            || checkpoint.authenticator != *authenticator
        {
            return Err(corrupt());
        }
        Ok(())
    }
}

/// Separately permissioned, cross-process monotonic effect checkpoint file.
pub struct EffectCheckpointFile {
    path: PathBuf,
    lock_path: PathBuf,
}

/// Opaque cross-process lock proving that current checkpoint truth equals a backup snapshot.
///
/// Keeping this value alive prevents a production effect worker from publishing a newer external
/// checkpoint while an offline restore is copied and verified. It grants no checkpoint mutation
/// capability and releases the operating-system lock when dropped.
pub struct ExactEffectCheckpointGuard {
    _lock: File,
}

impl std::fmt::Debug for ExactEffectCheckpointGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactEffectCheckpointGuard")
            .finish_non_exhaustive()
    }
}

impl EffectCheckpointFile {
    /// Opens and validates a preprovisioned checkpoint, optionally creating the initial empty
    /// document only after the caller has independently proved that the effect store is empty.
    pub fn open(path: impl Into<PathBuf>, create_empty: bool) -> Result<Self, EffectError> {
        let path = path.into();
        let parent = path.parent().ok_or_else(unavailable)?;
        validate_restricted_directory(parent)?;
        let lock_path = checkpoint_lock_path(&path)?;
        let checkpoint = Self { path, lock_path };
        let lock = checkpoint.open_lock()?;
        lock.lock().map_err(|_error| unavailable())?;
        match checkpoint.load_locked() {
            Ok(_document) => {}
            Err(error)
                if create_empty
                    && error.code() == EffectErrorCode::Unavailable
                    && !checkpoint.path.exists() =>
            {
                checkpoint.persist_locked(&EffectCheckpointDocument::empty())?;
            }
            Err(error) => return Err(error),
        }
        checkpoint.load_locked()?;
        Ok(checkpoint)
    }

    /// Opens and validates an existing checkpoint without creating a lock, checkpoint, or repair.
    pub fn open_read_only(path: impl Into<PathBuf>) -> Result<Self, EffectError> {
        let path = path.into();
        let parent = path.parent().ok_or_else(unavailable)?;
        validate_restricted_directory(parent)?;
        let checkpoint = Self {
            lock_path: checkpoint_lock_path(&path)?,
            path,
        };
        checkpoint.load_locked()?;
        Ok(checkpoint)
    }

    /// Captures one exact checkpoint file only when it completely matches a locked backup DB.
    ///
    /// The caller must hold the source repository's SQLite writer exclusion while this method
    /// runs. The checkpoint lock then freezes monotonic observations through validation and copy.
    pub fn capture_backup_snapshot(
        &self,
        backup_database: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<(), EffectError> {
        let destination = destination.as_ref();
        let parent = destination.parent().ok_or_else(unavailable)?;
        validate_restricted_directory(parent)?;
        if destination.exists() {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        lock.lock().map_err(|_error| unavailable())?;
        let document = self.load_locked()?;
        validate_checkpoint_against_database(backup_database.as_ref(), &document)?;
        let bytes = serde_json::to_vec(&document).map_err(|_error| unavailable())?;
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_CHECKPOINT_BYTES)
        {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        let mut file =
            create_owner_only_temporary_file(destination).map_err(|_error| unavailable())?;
        let mut cleanup = TemporaryCleanup::new(destination.to_path_buf());
        file.write_all(&bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|_error| unavailable())?;
        drop(file);
        sync_directory(parent)?;
        cleanup.persisted = true;
        Ok(())
    }

    /// Verifies that an immutable backup checkpoint completely matches its backup database.
    pub fn verify_backup_snapshot(
        backup_database: impl AsRef<Path>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<(), EffectError> {
        let checkpoint = Self::open_read_only(checkpoint_path)?;
        let document = checkpoint.load_locked()?;
        validate_checkpoint_against_database(backup_database.as_ref(), &document)
    }

    /// Compares current and archived checkpoint truth without creating or acquiring a lock.
    ///
    /// This is suitable only for a no-mutation preview. A committing restore must instead use
    /// [`Self::lock_exact_backup_snapshot`] and retain its guard through publication.
    pub fn verify_exact_backup_snapshot_read_only(
        current_checkpoint_path: impl Into<PathBuf>,
        backup_checkpoint_path: impl Into<PathBuf>,
    ) -> Result<(), EffectError> {
        let current = Self::open_read_only(current_checkpoint_path)?;
        let backup = Self::open_read_only(backup_checkpoint_path)?;
        if current.load_locked()? == backup.load_locked()? {
            Ok(())
        } else {
            Err(corrupt())
        }
    }

    /// Requires a signed backup's checkpoint to equal current monotonic external truth exactly.
    ///
    /// A newer live checkpoint, an older/rolled-back live checkpoint, or any substitution fails;
    /// this method never overwrites or repairs the external checkpoint.
    pub fn require_exact_backup_snapshot(
        &self,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<(), EffectError> {
        self.lock_exact_backup_snapshot(checkpoint_path).map(drop)
    }

    /// Locks current checkpoint truth only when it exactly equals a signed backup snapshot.
    ///
    /// The returned guard must remain alive through restore copy, verification, and publication.
    /// The checkpoint is never overwritten or repaired, including when either side is older.
    pub fn lock_exact_backup_snapshot(
        &self,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<ExactEffectCheckpointGuard, EffectError> {
        let backup = Self::open_read_only(checkpoint_path)?;
        let backup_document = backup.load_locked()?;
        let lock = self.open_lock()?;
        lock.lock().map_err(|_error| unavailable())?;
        if self.load_locked()? == backup_document {
            Ok(ExactEffectCheckpointGuard { _lock: lock })
        } else {
            Err(corrupt())
        }
    }

    fn observe(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<(), EffectError> {
        let lock = self.open_lock()?;
        lock.lock().map_err(|_error| unavailable())?;
        let mut document = self.load_locked()?;
        if document.observe(
            tenant_id,
            effect_id,
            intent_digest,
            effect_version,
            authenticator,
        )? {
            self.persist_locked(&document)?;
        }
        Ok(())
    }

    fn verify_exact(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<(), EffectError> {
        self.load_locked()?.verify_exact(
            tenant_id,
            effect_id,
            intent_digest,
            effect_version,
            authenticator,
        )
    }

    fn open_lock(&self) -> Result<File, EffectError> {
        let file = open_or_create_lock_file(&self.lock_path)?;
        validate_restricted_file(&self.lock_path, &file, true)?;
        Ok(file)
    }

    fn load_locked(&self) -> Result<EffectCheckpointDocument, EffectError> {
        let file = open_restricted_file(&self.path)?;
        validate_restricted_file(&self.path, &file, false)?;
        let metadata = file.metadata().map_err(|_error| unavailable())?;
        if metadata.len() == 0 || metadata.len() > MAX_CHECKPOINT_BYTES {
            return Err(corrupt());
        }
        let capacity = usize::try_from(metadata.len())
            .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_CHECKPOINT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_error| unavailable())?;
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_CHECKPOINT_BYTES)
        {
            return Err(corrupt());
        }
        parse_strict_json(&bytes).map_err(|_error| corrupt())?;
        let document: EffectCheckpointDocument =
            serde_json::from_slice(&bytes).map_err(|_error| corrupt())?;
        document.validate()?;
        if serde_json::to_vec(&document).map_err(|_error| unavailable())? != bytes {
            return Err(corrupt());
        }
        Ok(document)
    }

    fn persist_locked(&self, document: &EffectCheckpointDocument) -> Result<(), EffectError> {
        document.validate()?;
        let bytes = serde_json::to_vec(document).map_err(|_error| unavailable())?;
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_CHECKPOINT_BYTES)
        {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        let parent = self.path.parent().ok_or_else(unavailable)?;
        let (temporary_path, mut temporary) = create_temporary(parent)?;
        let mut cleanup = TemporaryCleanup::new(temporary_path.clone());
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.flush())
            .and_then(|()| temporary.sync_all())
            .map_err(|_error| unavailable())?;
        drop(temporary);
        replace_checkpoint_file(&temporary_path, &self.path)?;
        cleanup.persisted = true;
        sync_directory(parent)?;
        let published = open_restricted_file(&self.path)?;
        validate_restricted_file(&self.path, &published, false)?;
        Ok(())
    }
}

fn validate_checkpoint_against_database(
    database: &Path,
    document: &EffectCheckpointDocument,
) -> Result<(), EffectError> {
    document.validate()?;
    let inventory = SqliteStore::backup_effect_record_inventory_at(database).map_err(|error| {
        match error.code() {
            StoreErrorCode::InvalidRecord | StoreErrorCode::MixedSnapshot => corrupt(),
            _ => unavailable(),
        }
    })?;
    if inventory.len() != document.checkpoints.len() {
        return Err(corrupt());
    }
    for (tenant_id, envelope) in inventory {
        let observation = persisted_effect_checkpoint_observation(&envelope)?;
        document.verify_exact(
            &tenant_id,
            &observation.effect_id,
            &observation.intent_digest,
            observation.effect_version,
            &observation.authenticator,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_or_create_lock_file(path: &Path) -> Result<File, EffectError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
    options.open(path).map_err(|_error| unavailable())
}

#[cfg(windows)]
fn open_or_create_lock_file(path: &Path) -> Result<File, EffectError> {
    cigar_windows_ipc::open_or_create_owner_only_lock_file(path).map_err(|_error| unavailable())
}

#[cfg(not(any(unix, windows)))]
fn open_or_create_lock_file(_path: &Path) -> Result<File, EffectError> {
    Err(unavailable())
}

#[cfg(unix)]
fn open_restricted_file(path: &Path) -> Result<File, EffectError> {
    File::open(path).map_err(|_error| unavailable())
}

#[cfg(windows)]
fn open_restricted_file(path: &Path) -> Result<File, EffectError> {
    cigar_windows_ipc::open_owner_only_credential_file(path).map_err(|_error| unavailable())
}

#[cfg(not(any(unix, windows)))]
fn open_restricted_file(_path: &Path) -> Result<File, EffectError> {
    Err(unavailable())
}

#[cfg(unix)]
fn replace_checkpoint_file(source: &Path, destination: &Path) -> Result<(), EffectError> {
    std::fs::rename(source, destination).map_err(|_error| unavailable())
}

#[cfg(windows)]
fn replace_checkpoint_file(source: &Path, destination: &Path) -> Result<(), EffectError> {
    cigar_windows_ipc::replace_owner_only_file_write_through(source, destination)
        .map_err(|_error| unavailable())
}

#[cfg(not(any(unix, windows)))]
fn replace_checkpoint_file(_source: &Path, _destination: &Path) -> Result<(), EffectError> {
    Err(unavailable())
}

impl std::fmt::Debug for EffectCheckpointFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectCheckpointFile")
            .field("path", &"[RESTRICTED]")
            .finish_non_exhaustive()
    }
}

/// Production effect authenticator shared by API handlers, workers, and recovery checks.
pub struct ProductionEffectRecordAuthenticator {
    signatures: Arc<dyn EffectRecordSignatureAuthority>,
    checkpoints: EffectCheckpointFile,
}

impl ProductionEffectRecordAuthenticator {
    /// Opens one production authenticator over an explicitly provisioned external checkpoint.
    pub fn open(
        signatures: Arc<dyn EffectRecordSignatureAuthority>,
        checkpoint_path: impl Into<PathBuf>,
        create_empty: bool,
    ) -> Result<Self, EffectError> {
        Ok(Self {
            signatures,
            checkpoints: EffectCheckpointFile::open(checkpoint_path, create_empty)?,
        })
    }

    /// Opens an existing production authenticator for a strictly read-only integrity pass.
    pub fn open_read_only(
        signatures: Arc<dyn EffectRecordSignatureAuthority>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, EffectError> {
        Ok(Self {
            signatures,
            checkpoints: EffectCheckpointFile::open_read_only(checkpoint_path)?,
        })
    }
}

impl EffectRecordAuthenticator for ProductionEffectRecordAuthenticator {
    fn seal(
        &self,
        tenant_id: &RecordId,
        canonical_record: &[u8],
    ) -> Result<EffectRecordSeal, EffectError> {
        let payload_digest = effect_record_payload_digest(tenant_id, canonical_record)?;
        let signed = self
            .signatures
            .sign_effect_record(tenant_id, payload_digest)?;
        let authenticator = raw_multihash(signed.signature())?;
        EffectRecordSeal::new_signed(
            signed.key_ref().as_str().to_owned(),
            authenticator,
            signed.signed_at_unix_nanos(),
            *signed.signature(),
        )
    }

    fn verify(
        &self,
        tenant_id: &RecordId,
        canonical_record: &[u8],
        seal: &EffectRecordSeal,
    ) -> Result<(), EffectError> {
        let proof = seal.signed_proof().ok_or_else(corrupt)?;
        let signature: [u8; 64] = proof.signature().try_into().map_err(|_error| corrupt())?;
        if raw_multihash(&signature)? != *seal.authenticator() {
            return Err(corrupt());
        }
        let signed = EffectRecordSignature::new(
            KeyRef::new(seal.key_id().to_owned()).map_err(|_error| corrupt())?,
            proof.signed_at_unix_nanos(),
            signature,
        );
        self.signatures.verify_effect_record(
            tenant_id,
            &effect_record_payload_digest(tenant_id, canonical_record)?,
            &signed,
        )
    }

    fn verify_latest_read_only(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        canonical_record: &[u8],
        seal: &EffectRecordSeal,
    ) -> Result<(), EffectError> {
        self.verify(tenant_id, canonical_record, seal)?;
        self.checkpoints.verify_exact(
            tenant_id,
            effect_id,
            intent_digest,
            effect_version,
            seal.authenticator(),
        )
    }

    fn observe_latest(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<(), EffectError> {
        self.checkpoints.observe(
            tenant_id,
            effect_id,
            intent_digest,
            effect_version,
            authenticator,
        )
    }
}

impl std::fmt::Debug for ProductionEffectRecordAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionEffectRecordAuthenticator")
            .field("signatures", &"[TENANT-KMS]")
            .field("checkpoints", &self.checkpoints)
            .finish_non_exhaustive()
    }
}

fn effect_record_payload_digest(
    tenant_id: &RecordId,
    canonical_record: &[u8],
) -> Result<[u8; 32], EffectError> {
    let tenant = tenant_id.as_str().as_bytes();
    let tenant_length = u64::try_from(tenant.len())
        .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?;
    let record_length = u64::try_from(canonical_record.len())
        .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?;
    let mut hasher = Sha256::new();
    hasher.update(EFFECT_RECORD_SIGNATURE_DOMAIN);
    hasher.update(tenant_length.to_be_bytes());
    hasher.update(tenant);
    hasher.update(record_length.to_be_bytes());
    hasher.update(canonical_record);
    Ok(hasher.finalize().into())
}

fn raw_multihash(bytes: &[u8]) -> Result<ContentDigest, EffectError> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| unavailable())?;
    }
    ContentDigest::new(encoded).map_err(|_error| corrupt())
}

fn checkpoint_lock_path(path: &Path) -> Result<PathBuf, EffectError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(unavailable)?;
    Ok(path.with_file_name(format!(".{name}.lock")))
}

fn create_temporary(parent: &Path) -> Result<(PathBuf, File), EffectError> {
    for _attempt in 0..TEMPORARY_NAME_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_error| unavailable())?;
        let mut name = String::from(".cigar-effect-checkpoint-");
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut name, "{byte:02x}").map_err(|_error| unavailable())?;
        }
        let path = parent.join(name);
        match create_owner_only_temporary_file(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_error) => return Err(unavailable()),
        }
    }
    Err(unavailable())
}

#[cfg(unix)]
fn create_owner_only_temporary_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options.open(path)
}

#[cfg(windows)]
fn create_owner_only_temporary_file(path: &Path) -> std::io::Result<File> {
    cigar_windows_ipc::create_owner_only_credential_file(path)
}

#[cfg(not(any(unix, windows)))]
fn create_owner_only_temporary_file(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure checkpoint files are unsupported on this platform",
    ))
}

struct TemporaryCleanup {
    path: PathBuf,
    persisted: bool,
}

impl TemporaryCleanup {
    const fn new(path: PathBuf) -> Self {
        Self {
            path,
            persisted: false,
        }
    }
}

impl Drop for TemporaryCleanup {
    fn drop(&mut self) {
        if !self.persisted {
            let _removed = std::fs::remove_file(&self.path);
        }
    }
}

fn validate_restricted_directory(path: &Path) -> Result<(), EffectError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_error| unavailable())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || std::fs::canonicalize(path).map_err(|_error| unavailable())? != path
    {
        return Err(unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(unavailable());
        }
    }
    #[cfg(windows)]
    cigar_windows_ipc::validate_owner_only_directory(path).map_err(|_error| unavailable())?;
    Ok(())
}

fn validate_restricted_file(
    path: &Path,
    file: &File,
    allow_empty: bool,
) -> Result<(), EffectError> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_error| unavailable())?;
    let file_metadata = file.metadata().map_err(|_error| unavailable())?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || (!allow_empty && path_metadata.len() == 0)
        || path_metadata.len() > MAX_CHECKPOINT_BYTES
        || std::fs::canonicalize(path).map_err(|_error| unavailable())? != path
    {
        return Err(unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if path_metadata.uid() != rustix::process::geteuid().as_raw()
            || path_metadata.nlink() != 1
            || path_metadata.permissions().mode() & 0o077 != 0
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(unavailable());
        }
    }
    #[cfg(windows)]
    if file_metadata.permissions().readonly() {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), EffectError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| unavailable())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), EffectError> {
    // The audited replacement uses `MOVEFILE_WRITE_THROUGH`; Windows has no portable directory
    // `fsync` equivalent beyond that write-through rename contract.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> Result<(), EffectError> {
    Err(unavailable())
}

const fn corrupt() -> EffectError {
    EffectError::new(EffectErrorCode::CorruptJournal)
}

const fn unavailable() -> EffectError {
    EffectError::new(EffectErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        EffectCheckpointFile, EffectRecordSignature, EffectRecordSignatureAuthority,
        ProductionEffectRecordAuthenticator, raw_multihash,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider as _, KeyPurpose, KeyRef, MemoryKeyProvider,
    };
    use cigar_effects::reference::{DemoIssueConnector, DemoIssueRequest, DemoIssueService};
    use cigar_effects::{
        EffectAuthorization, EffectEngine, EffectError, EffectErrorCode, EffectRecordAuthenticator,
        verify_persisted_effect_record,
    };
    use cigar_protocol::{
        BlobRef, Capability, ContentDigest, EffectIntent, ExtensionMap, IdempotencyKey, MediaType,
        RecordId, RetryPolicy, RiskLevel, SchemaVersion, UtcTimestamp, VersionId,
    };
    use cigar_store::{
        AccessContext, BACKUP_DATABASE_FILE, BACKUP_EFFECT_CHECKPOINT_FILE, BackupErrorCode,
        BackupIdentity, CancellationToken, ReadTransaction as _, Repository as _,
        SnapshotSelection, SqliteStore, create_backup_with_effect_checkpoint, verify_backup,
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn record(value: u64) -> TestResult<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(value: u64) -> TestResult<ContentDigest> {
        Ok(raw_multihash(&value.to_be_bytes())?)
    }

    fn version(value: u64) -> TestResult<VersionId> {
        Ok(VersionId::new(digest(value)?.as_str())?)
    }

    fn time(seconds: i128) -> TestResult<UtcTimestamp> {
        Ok(UtcTimestamp::from_unix_nanos(
            seconds.saturating_mul(1_000_000_000),
        )?)
    }

    fn checkpoint_directory(root: &Path) -> TestResult<PathBuf> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
            Ok(std::fs::canonicalize(root)?)
        }
        #[cfg(windows)]
        {
            let directory = std::fs::canonicalize(root)?.join("owner-only-checkpoints");
            cigar_windows_ipc::create_or_validate_owner_only_directory(&directory)?;
            Ok(std::fs::canonicalize(directory)?)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _root = root;
            Err("secure checkpoints are unsupported on this platform".into())
        }
    }

    struct TestSignatures;

    impl TestSignatures {
        fn proof(payload_digest: &[u8; 32]) -> [u8; 64] {
            let left: [u8; 32] = Sha256::digest(payload_digest).into();
            let mut right_hasher = Sha256::new();
            right_hasher.update(b"test-effect-signature");
            right_hasher.update(payload_digest);
            let right: [u8; 32] = right_hasher.finalize().into();
            let mut proof = [0_u8; 64];
            if let Some(left_bytes) = proof.get_mut(..32) {
                left_bytes.copy_from_slice(&left);
            }
            if let Some(right_bytes) = proof.get_mut(32..) {
                right_bytes.copy_from_slice(&right);
            }
            proof
        }
    }

    impl EffectRecordSignatureAuthority for TestSignatures {
        fn sign_effect_record(
            &self,
            _tenant_id: &RecordId,
            payload_digest: [u8; 32],
        ) -> Result<EffectRecordSignature, EffectError> {
            Ok(EffectRecordSignature::new(
                KeyRef::new("test-effect-key")
                    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
                7,
                Self::proof(&payload_digest),
            ))
        }

        fn verify_effect_record(
            &self,
            _tenant_id: &RecordId,
            payload_digest: &[u8; 32],
            signature: &EffectRecordSignature,
        ) -> Result<(), EffectError> {
            if signature.key_ref().as_str() == "test-effect-key"
                && signature.signed_at_unix_nanos() == 7
                && signature.signature() == &Self::proof(payload_digest)
            {
                Ok(())
            } else {
                Err(EffectError::new(EffectErrorCode::CorruptJournal))
            }
        }
    }

    #[test]
    fn checkpoint_restart_two_factories_and_stale_observation_fail_closed() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = checkpoint_directory(directory.path())?.join("effect-checkpoints.json");
        let first = EffectCheckpointFile::open(path.clone(), true)?;
        let second = EffectCheckpointFile::open(path.clone(), false)?;
        let tenant = record(1)?;
        let effect = record(2)?;
        let intent = digest(3)?;
        let root_one = digest(4)?;
        let root_two = digest(5)?;
        first.observe(&tenant, &effect, &intent, 0, &root_one)?;
        second.observe(&tenant, &effect, &intent, 1, &root_two)?;
        assert_eq!(
            first
                .observe(&tenant, &effect, &intent, 0, &root_one)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::RevisionConflict)
        );
        assert_eq!(
            second
                .observe(&tenant, &effect, &intent, 1, &root_one)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::CorruptJournal)
        );
        assert_eq!(
            second
                .observe(&tenant, &effect, &digest(99)?, 2, &root_two)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::CorruptJournal)
        );
        drop(first);
        drop(second);
        let restarted = EffectCheckpointFile::open(path, false)?;
        assert_eq!(
            restarted
                .observe(&tenant, &effect, &intent, 0, &root_one)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::RevisionConflict)
        );
        Ok(())
    }

    #[test]
    fn read_only_backup_checkpoint_preview_creates_no_lock_or_state() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = checkpoint_directory(directory.path())?;
        let current = root.join("current-checkpoint.json");
        let backup = root.join("backup-checkpoint.json");
        drop(EffectCheckpointFile::open(current.clone(), true)?);
        std::fs::copy(&current, &backup)?;
        let current_lock = super::checkpoint_lock_path(&current)?;
        let backup_lock = super::checkpoint_lock_path(&backup)?;
        std::fs::remove_file(&current_lock)?;
        assert!(!backup_lock.exists());

        EffectCheckpointFile::verify_exact_backup_snapshot_read_only(&current, &backup)?;
        assert!(!current_lock.exists());
        assert!(!backup_lock.exists());
        Ok(())
    }

    #[test]
    fn signed_record_proof_binds_tenant_bytes_and_external_checkpoint() -> TestResult {
        let directory = tempfile::tempdir()?;
        let checkpoint_directory = checkpoint_directory(directory.path())?;
        let signatures: Arc<dyn EffectRecordSignatureAuthority> = Arc::new(TestSignatures);
        let authenticator = ProductionEffectRecordAuthenticator::open(
            signatures,
            checkpoint_directory.join("effect-checkpoints.json"),
            true,
        )?;
        let tenant = record(10)?;
        let other_tenant = record(11)?;
        let bytes = br#"{"record":"exact"}"#;
        let seal = authenticator.seal(&tenant, bytes)?;
        authenticator.verify(&tenant, bytes, &seal)?;
        assert_eq!(
            authenticator
                .verify(&other_tenant, bytes, &seal)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::CorruptJournal)
        );
        assert_eq!(
            authenticator
                .verify(&tenant, br#"{"record":"changed"}"#, &seal)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::CorruptJournal)
        );
        let effect = record(12)?;
        let intent = digest(13)?;
        authenticator.observe_latest(&tenant, &effect, &intent, 1, seal.authenticator())?;
        let read_only = ProductionEffectRecordAuthenticator::open_read_only(
            Arc::new(TestSignatures),
            checkpoint_directory.join("effect-checkpoints.json"),
        )?;
        read_only.verify_latest_read_only(&tenant, &effect, &intent, 1, bytes, &seal)?;
        assert_eq!(
            read_only
                .verify_latest_read_only(&tenant, &effect, &intent, 0, bytes, &seal)
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::CorruptJournal)
        );
        Ok(())
    }

    #[test]
    fn production_authenticator_backup_is_complete_and_rejects_checkpoint_rollback() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = checkpoint_directory(directory.path())?;
        let checkpoint = root.join("effect-checkpoints.json");
        let database = root.join("metadata.sqlite3");
        let tenant = record(20)?;
        let repository = Arc::new(SqliteStore::open(&database)?);
        let connector = Arc::new(DemoIssueConnector::new(
            "production-auth-test",
            Arc::new(DemoIssueService::default()),
        )?);
        let arguments_digest = connector.stage_request(DemoIssueRequest::new(
            "checkpoint-project",
            "version zero",
            "the prepared projection must be checkpointed",
        )?)?;
        let intent = EffectIntent {
            schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
            effect_id: record(21)?,
            connector: "production-auth-test".to_owned(),
            operation: "create_issue".to_owned(),
            arguments_digest,
            encrypted_arguments: BlobRef {
                digest: digest(22)?,
                size_bytes: 64,
                media_type: MediaType::new("application/octet-stream")?,
            },
            target: "checkpoint-project".to_owned(),
            preconditions: Vec::new(),
            result_schema_digest: digest(23)?,
            risk: RiskLevel::Low,
            source_decision_id: version(24)?,
            bundle_id: version(25)?,
            required_capability: Capability::InvokeTool,
            idempotency_scope: "checkpoint-tenant".to_owned(),
            idempotency_key: IdempotencyKey::new("checkpoint-version-zero")?,
            retry_policy: RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            created_at: time(1)?,
            expires_at: time(50)?,
            compensation: None,
            extensions: ExtensionMap::default(),
        };
        let authorization = EffectAuthorization {
            actor_id: record(26)?,
            capabilities: BTreeSet::from([Capability::ProposeEffect]),
            policy_allows: true,
            now: time(2)?,
        };

        let first_authenticator: Arc<dyn EffectRecordAuthenticator> =
            Arc::new(ProductionEffectRecordAuthenticator::open(
                Arc::new(TestSignatures),
                checkpoint.clone(),
                true,
            )?);
        let engine = EffectEngine::new_with_authenticator(
            Arc::clone(&repository),
            AccessContext::new(tenant.clone(), "effect-version-zero")?,
            first_authenticator,
        );
        engine.register_connector(connector.clone())?;
        let prepared = engine.prepare(intent, &authorization)?;
        assert_eq!(prepared.effect_version, 0);
        drop(engine);

        let transaction = repository.begin_read(
            AccessContext::new(tenant.clone(), "effect-read-only-verification")?,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        let envelope = transaction
            .get_effect_record(&prepared.intent.effect_id)?
            .ok_or("prepared effect envelope was not persisted")?;
        let read_only = ProductionEffectRecordAuthenticator::open_read_only(
            Arc::new(TestSignatures),
            checkpoint.clone(),
        )?;
        verify_persisted_effect_record(&tenant, &envelope, &read_only)?;

        let second_authenticator: Arc<dyn EffectRecordAuthenticator> =
            Arc::new(ProductionEffectRecordAuthenticator::open(
                Arc::new(TestSignatures),
                checkpoint.clone(),
                false,
            )?);
        let reopened = EffectEngine::new_with_authenticator(
            Arc::clone(&repository),
            AccessContext::new(tenant.clone(), "effect-version-zero-reopen")?,
            second_authenticator,
        );
        reopened.register_connector(connector)?;
        assert_eq!(reopened.get(&prepared.intent.effect_id)?, prepared);
        drop(reopened);

        let checkpoint_file = EffectCheckpointFile::open(checkpoint.clone(), false)?;
        let provider = MemoryKeyProvider::default();
        let signing = provider.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let archive = root.join("signed-backup");
        let manifest = create_backup_with_effect_checkpoint(
            repository.as_ref(),
            root.join("empty-blobs"),
            &archive,
            &provider,
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: tenant.as_str(),
                signer: "backup-operator",
                created_at_unix_nanos: 2,
            },
            |backup_database, backup_checkpoint| {
                checkpoint_file
                    .capture_backup_snapshot(backup_database, backup_checkpoint)
                    .map_err(|error| match error.code() {
                        EffectErrorCode::CorruptJournal | EffectErrorCode::InvalidInput => {
                            BackupErrorCode::Corrupt
                        }
                        EffectErrorCode::LimitExceeded => BackupErrorCode::LimitExceeded,
                        _ => BackupErrorCode::Unavailable,
                    })
            },
        )?;
        assert_eq!(manifest.format_version, 2);
        assert_eq!(
            verify_backup(&archive, &provider, tenant.as_str(), "backup-operator", 3,)?,
            manifest
        );
        EffectCheckpointFile::verify_backup_snapshot(
            archive.join(BACKUP_DATABASE_FILE),
            archive.join(BACKUP_EFFECT_CHECKPOINT_FILE),
        )?;
        checkpoint_file
            .require_exact_backup_snapshot(archive.join(BACKUP_EFFECT_CHECKPOINT_FILE))?;

        checkpoint_file.observe(
            &tenant,
            &prepared.intent.effect_id,
            &prepared.intent_digest,
            prepared.effect_version.saturating_add(1),
            &digest(99)?,
        )?;
        let restarted = EffectCheckpointFile::open(checkpoint, false)?;
        assert_eq!(
            restarted
                .require_exact_backup_snapshot(archive.join(BACKUP_EFFECT_CHECKPOINT_FILE))
                .err()
                .map(|error| error.code()),
            Some(EffectErrorCode::CorruptJournal)
        );
        Ok(())
    }
}
