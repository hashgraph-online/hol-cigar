//! Encrypted object-CAS publication with S3-compatible and deterministic test transports.

use crate::RepositoryGarbageCollectionCandidate;
use crate::blob::{persisted_blob_key_ref, protect_blob_bytes, unprotect_blob_bytes};
use crate::{
    BlobRecord, GarbageCollectionPolicy, RepositoryBlobStore, RepositoryGarbageCollectionReport,
    SharedGarbageCollectionAuthorization, StoreError, StoreErrorCode,
};
use cigar_crypto::{KeyProvider, KeyRef};
use cigar_protocol::{BlobRef, ContentDigest, RecordId};
use hmac::{Hmac, KeyInit, Mac};
use s3::creds::Credentials;
use s3::{Bucket, Region};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_OBJECT_BYTES: usize = 67_110_000;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_OBJECT_LIST_ITEMS: usize = 1_000_000;
const MAX_OBJECT_BACKUP_ENTRIES: usize = MAX_OBJECT_LIST_ITEMS - 1;
const MAX_S3_LIST_PAGES: usize = 10_001;
const MAX_S3_LIST_ELAPSED: Duration = Duration::from_secs(120);
const MAX_S3_PAGE_ELAPSED: Duration = Duration::from_secs(15);
const RESTORE_INCOMPLETE_KEY: &str = "restore/staging/incomplete-v1";
const RESTORE_INCOMPLETE_BYTES: &[u8] = b"CIGAR-OBJECT-RESTORE-INCOMPLETE-v1";

/// Stable content-free object provider failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStorageErrorCode {
    /// The requested immutable key does not exist.
    NotFound,
    /// A conditional create found a previously committed object.
    AlreadyExists,
    /// Explicit object credentials are expired or rejected.
    CredentialsExpired,
    /// A request, key, endpoint, or response violated a bound.
    InvalidMetadata,
    /// The provider could not complete the operation safely.
    Unavailable,
    /// A deterministic test failpoint interrupted the operation.
    InjectedAbort,
}

/// Content-free object provider error safe for diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObjectStorageError {
    code: ObjectStorageErrorCode,
}

impl ObjectStorageError {
    const fn new(code: ObjectStorageErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ObjectStorageErrorCode {
        self.code
    }
}

impl fmt::Debug for ObjectStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStorageError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ObjectStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "object storage operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for ObjectStorageError {}

/// Result of one immutable conditional object publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectWriteOutcome {
    /// This call durably created the key.
    Created,
    /// The key already existed and was left byte-for-byte unchanged.
    AlreadyExists,
}

/// Stable identity of one physical object namespace bound into backup evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStorageIdentity {
    /// Storage protocol and inventory semantics.
    pub provider: String,
    /// Exact bucket/prefix or deterministic test namespace.
    pub namespace: String,
}

/// One exact encrypted object bound into a backup inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectBackupEntry {
    /// Blinded immutable key relative to the configured namespace.
    pub storage_key: String,
    /// Historical wrapping-key reference parsed from the protected ciphertext frame.
    pub wrapping_key_ref: KeyRef,
    /// Exact ciphertext byte length.
    pub size_bytes: u64,
    /// SHA-256 multihash of the exact encrypted bytes.
    pub ciphertext_checksum: String,
}

/// Complete encrypted-object inventory derived from one metadata snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectBackupInventory {
    /// Inventory semantics version, currently two.
    pub format_version: u8,
    /// Physical source namespace whose contents were inventoried.
    pub storage: ObjectStorageIdentity,
    /// Strictly sorted complete set of metadata-referenced encrypted objects.
    pub entries: Vec<ObjectBackupEntry>,
}

impl ObjectBackupInventory {
    /// Validates namespace identity, exact encrypted-object metadata, ordering, and bounds.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.format_version != 2
            || !valid_identity_component(&self.storage.provider)
            || !valid_identity_component(&self.storage.namespace)
            || self.entries.len() > MAX_OBJECT_BACKUP_ENTRIES
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        let mut previous = None;
        for entry in &self.entries {
            validate_object_key(&entry.storage_key).map_err(object_error)?;
            let wrapping_key_ref = KeyRef::new(entry.wrapping_key_ref.as_str().to_owned())
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
            if !entry.storage_key.contains("/objects/")
                || wrapping_key_ref != entry.wrapping_key_ref
                || entry.size_bytes == 0
                || entry.size_bytes > MAX_OBJECT_BYTES as u64
                || !valid_multihash(&entry.ciphertext_checksum)
                || previous.is_some_and(|key: &str| key >= entry.storage_key.as_str())
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            previous = Some(entry.storage_key.as_str());
        }
        Ok(())
    }
}

/// Serializable content-free evidence for one exact encrypted-object copy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectCopyEvidence {
    /// Signed source namespace identity.
    pub source: ObjectStorageIdentity,
    /// Fresh destination namespace identity.
    pub destination: ObjectStorageIdentity,
    /// Number of exact encrypted objects copied and verified.
    pub object_count: u64,
    /// Sum of exact encrypted bytes copied and verified.
    pub ciphertext_bytes: u64,
    /// SHA-256 multihash over the ordered signed inventory entries.
    pub inventory_root: String,
}

/// Opaque receipt returned only after an exact encrypted-object restore succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObjectRestoreReceipt {
    #[serde(flatten)]
    evidence: ObjectCopyEvidence,
}

impl ObjectRestoreReceipt {
    /// Returns the signed source namespace identity.
    #[must_use]
    pub const fn source(&self) -> &ObjectStorageIdentity {
        &self.evidence.source
    }

    /// Returns the fresh destination namespace identity.
    #[must_use]
    pub const fn destination(&self) -> &ObjectStorageIdentity {
        &self.evidence.destination
    }

    /// Returns the exact copied object count.
    #[must_use]
    pub const fn object_count(&self) -> u64 {
        self.evidence.object_count
    }

    /// Returns the exact copied ciphertext byte count.
    #[must_use]
    pub const fn ciphertext_bytes(&self) -> u64 {
        self.evidence.ciphertext_bytes
    }

    /// Returns the exact signed inventory root.
    #[must_use]
    pub fn inventory_root(&self) -> &str {
        &self.evidence.inventory_root
    }

    pub(crate) fn evidence(&self) -> &ObjectCopyEvidence {
        &self.evidence
    }
}

/// Copies and verifies one signed object inventory into an exactly empty destination namespace.
///
/// Ciphertext is never decrypted or rewritten. The destination must be an entirely empty logical
/// namespace. An incomplete marker remains present throughout copying, every created key is rolled
/// back after an error, and the marker is removed only before an exact final namespace comparison.
/// Existing destination objects, a source-identity mismatch, checksum/key-reference drift,
/// truncation, or conditional-create collision all fail closed.
pub fn restore_object_backup_inventory(
    source: &dyn ObjectStorage,
    destination: &dyn ObjectStorage,
    inventory: &ObjectBackupInventory,
) -> Result<ObjectRestoreReceipt, StoreError> {
    inventory.validate()?;
    let object_count = u64::try_from(inventory.entries.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let inventory_root = object_inventory_root(inventory)?;
    let source_identity = source.identity();
    let destination_identity = destination.identity();
    if source_identity != inventory.storage || destination_identity == source_identity {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    if !destination
        .list_namespace(1)
        .map_err(object_error)?
        .is_empty()
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }

    let mut created = Vec::with_capacity(inventory.entries.len().saturating_add(1));
    match destination.put_if_absent(RESTORE_INCOMPLETE_KEY, RESTORE_INCOMPLETE_BYTES) {
        Ok(ObjectWriteOutcome::Created) => created.push(RESTORE_INCOMPLETE_KEY.to_owned()),
        Ok(ObjectWriteOutcome::AlreadyExists) => {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        Err(error) => {
            // A failed provider call can still have committed a partial object. Treat the reserved
            // marker as possibly created and remove it before returning the original error.
            created.push(RESTORE_INCOMPLETE_KEY.to_owned());
            return Err(restore_failure(destination, &created, object_error(error)));
        }
    }

    let mut ciphertext_bytes = 0_u64;
    for entry in &inventory.entries {
        let bytes = match source.get(&entry.storage_key) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(restore_failure(destination, &created, object_error(error)));
            }
        };
        if let Err(error) = verify_backup_entry(entry, &bytes) {
            return Err(restore_failure(destination, &created, error));
        }
        match destination.put_if_absent(&entry.storage_key, &bytes) {
            Ok(ObjectWriteOutcome::Created) => created.push(entry.storage_key.clone()),
            Ok(ObjectWriteOutcome::AlreadyExists) => {
                return Err(restore_failure(
                    destination,
                    &created,
                    StoreError::new(StoreErrorCode::InvalidContext),
                ));
            }
            Err(error) => {
                // Unknown/partial PUT outcomes must be included in rollback.
                created.push(entry.storage_key.clone());
                return Err(restore_failure(destination, &created, object_error(error)));
            }
        }
        let restored = match destination.get(&entry.storage_key) {
            Ok(restored) => restored,
            Err(error) => {
                return Err(restore_failure(destination, &created, object_error(error)));
            }
        };
        if let Err(error) = verify_backup_entry(entry, &restored) {
            return Err(restore_failure(destination, &created, error));
        }
        if restored != bytes {
            return Err(restore_failure(
                destination,
                &created,
                StoreError::new(StoreErrorCode::Unavailable),
            ));
        }
        ciphertext_bytes = match ciphertext_bytes.checked_add(entry.size_bytes) {
            Some(bytes) => bytes,
            None => {
                return Err(restore_failure(
                    destination,
                    &created,
                    StoreError::new(StoreErrorCode::LimitExceeded),
                ));
            }
        };
    }
    let expected: Vec<_> = inventory
        .entries
        .iter()
        .map(|entry| entry.storage_key.clone())
        .collect();
    let mut expected_incomplete = expected.clone();
    expected_incomplete.push(RESTORE_INCOMPLETE_KEY.to_owned());
    expected_incomplete.sort();
    match namespace_matches(destination, &expected_incomplete) {
        Ok(true) => {}
        Ok(false) => {
            return Err(restore_failure(
                destination,
                &created,
                StoreError::new(StoreErrorCode::InvalidContext),
            ));
        }
        Err(error) => return Err(restore_failure(destination, &created, error)),
    }
    if let Err(error) = destination.delete(RESTORE_INCOMPLETE_KEY) {
        return Err(restore_failure(destination, &created, object_error(error)));
    }
    match namespace_matches(destination, &expected) {
        Ok(true) => {}
        Ok(false) => {
            return Err(restore_failure(
                destination,
                &created,
                StoreError::new(StoreErrorCode::InvalidContext),
            ));
        }
        Err(error) => return Err(restore_failure(destination, &created, error)),
    }
    Ok(ObjectRestoreReceipt {
        evidence: ObjectCopyEvidence {
            source: source_identity,
            destination: destination_identity,
            object_count,
            ciphertext_bytes,
            inventory_root,
        },
    })
}

/// Minimal bounded object contract required by the encrypted CAS adapter.
pub trait ObjectStorage: Send + Sync {
    /// Returns the stable physical namespace identity used by backup evidence.
    fn identity(&self) -> ObjectStorageIdentity;
    /// Creates an immutable key only when absent.
    fn put_if_absent(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<ObjectWriteOutcome, ObjectStorageError>;
    /// Reads exact object bytes.
    fn get(&self, key: &str) -> Result<Vec<u8>, ObjectStorageError>;
    /// Deletes one exact key idempotently.
    fn delete(&self, key: &str) -> Result<(), ObjectStorageError>;
    /// Lists a complete bounded prefix in ascending key order.
    fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, ObjectStorageError>;
    /// Lists the complete logical namespace in ascending key order under a strict item bound.
    ///
    /// The fail-closed default preserves compatibility for providers that have not implemented a
    /// whole-namespace operation; such providers cannot be used as restore destinations.
    fn list_namespace(&self, _limit: usize) -> Result<Vec<String>, ObjectStorageError> {
        Err(ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))
    }
}

/// S3-compatible implementation using explicit credentials and conditional PUT.
pub struct S3CompatibleObjectStorage {
    bucket: Box<Bucket>,
    prefix: String,
    identity: ObjectStorageIdentity,
}

struct BoundedObjectWriter {
    bytes: Vec<u8>,
    maximum: usize,
    overflowed: bool,
}

struct S3ListingBudget {
    pages: usize,
    deadline: Instant,
    seen_tokens: BTreeSet<[u8; 32]>,
}

impl S3ListingBudget {
    fn new(now: Instant) -> Result<Self, ObjectStorageError> {
        let deadline = now
            .checked_add(MAX_S3_LIST_ELAPSED)
            .ok_or_else(|| ObjectStorageError::new(ObjectStorageErrorCode::InvalidMetadata))?;
        Ok(Self {
            pages: 0,
            deadline,
            seen_tokens: BTreeSet::new(),
        })
    }

    fn next_page_timeout(&mut self, now: Instant) -> Result<Duration, ObjectStorageError> {
        self.pages = self
            .pages
            .checked_add(1)
            .ok_or_else(|| ObjectStorageError::new(ObjectStorageErrorCode::InvalidMetadata))?;
        if self.pages > MAX_S3_LIST_PAGES {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        let remaining = self
            .deadline
            .checked_duration_since(now)
            .ok_or_else(|| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?;
        if remaining.is_zero() {
            return Err(ObjectStorageError::new(ObjectStorageErrorCode::Unavailable));
        }
        Ok(remaining.min(MAX_S3_PAGE_ELAPSED))
    }

    fn accept_continuation(
        &mut self,
        next: String,
        made_progress: bool,
    ) -> Result<String, ObjectStorageError> {
        if !made_progress
            || next.is_empty()
            || next.len() > 8_192
            || next.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        let digest: [u8; 32] = Sha256::digest(next.as_bytes()).into();
        if !self.seen_tokens.insert(digest) {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        Ok(next)
    }
}

impl BoundedObjectWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            overflowed: false,
        }
    }
}

impl Write for BoundedObjectWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "object response exceeds the configured bound",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for S3CompatibleObjectStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("S3CompatibleObjectStorage([REDACTED])")
    }
}

impl S3CompatibleObjectStorage {
    /// Creates an explicit S3/MinIO client with ambient credential discovery disabled.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        security_token: Option<String>,
        path_style: bool,
    ) -> Result<Self, ObjectStorageError> {
        let endpoint = endpoint.into();
        let region = region.into();
        let bucket_name = bucket.into();
        let prefix = normalize_prefix(prefix.into())?;
        let access_key = access_key.into();
        let secret_key = secret_key.into();
        if !valid_s3_endpoint(&endpoint) {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        if endpoint.len() > 2_048
            || region.is_empty()
            || region.len() > 128
            || bucket_name.is_empty()
            || bucket_name.len() > 63
            || access_key.is_empty()
            || access_key.len() > 256
            || secret_key.is_empty()
            || secret_key.len() > 4_096
        {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        let credentials = Credentials::new(
            Some(&access_key),
            Some(&secret_key),
            security_token.as_deref(),
            None,
            None,
        )
        .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::InvalidMetadata))?;
        let region = Region::Custom { region, endpoint };
        let bucket = Bucket::new(&bucket_name, region, credentials).map_err(s3_error)?;
        let bucket = if path_style {
            bucket.with_path_style()
        } else {
            bucket
        };
        let namespace = format!("{bucket_name}/{prefix}");
        Ok(Self {
            bucket,
            prefix,
            identity: ObjectStorageIdentity {
                provider: "s3-compatible-v1".to_owned(),
                namespace,
            },
        })
    }

    fn key(&self, key: &str) -> Result<String, ObjectStorageError> {
        validate_object_key(key)?;
        Ok(format!("{}{key}", self.prefix))
    }

    fn list_qualified_prefix(
        &self,
        qualified_prefix: String,
        limit: usize,
    ) -> Result<Vec<String>, ObjectStorageError> {
        validate_list_limit(limit)?;
        let mut keys = Vec::new();
        let mut continuation = None;
        let mut listing_budget = S3ListingBudget::new(Instant::now())?;
        loop {
            let request_timeout = listing_budget.next_page_timeout(Instant::now())?;
            let requested = limit
                .saturating_add(1)
                .saturating_sub(keys.len())
                .min(1_000);
            if requested == 0 {
                return Err(ObjectStorageError::new(
                    ObjectStorageErrorCode::InvalidMetadata,
                ));
            }
            let request_bucket = self
                .bucket
                .with_request_timeout(request_timeout)
                .map_err(s3_error)?;
            let (page, status) = request_bucket
                .list_page(
                    qualified_prefix.clone(),
                    None,
                    continuation.clone(),
                    None,
                    Some(requested),
                )
                .map_err(s3_error)?;
            match status {
                200..=299 => {}
                401 | 403 => {
                    return Err(ObjectStorageError::new(
                        ObjectStorageErrorCode::CredentialsExpired,
                    ));
                }
                _ => {
                    return Err(ObjectStorageError::new(ObjectStorageErrorCode::Unavailable));
                }
            }
            let keys_before = keys.len();
            for object in page.contents {
                let key = object
                    .key
                    .strip_prefix(&self.prefix)
                    .ok_or_else(|| {
                        ObjectStorageError::new(ObjectStorageErrorCode::InvalidMetadata)
                    })?
                    .to_owned();
                validate_object_key(&key)?;
                keys.push(key);
                if keys.len() > limit {
                    return Err(ObjectStorageError::new(
                        ObjectStorageErrorCode::InvalidMetadata,
                    ));
                }
            }
            if !page.is_truncated {
                break;
            }
            let next = page
                .next_continuation_token
                .ok_or_else(|| ObjectStorageError::new(ObjectStorageErrorCode::InvalidMetadata))?;
            continuation =
                Some(listing_budget.accept_continuation(next, keys.len() > keys_before)?);
        }
        keys.sort();
        if keys.windows(2).any(|pair| pair.first() == pair.get(1)) {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        Ok(keys)
    }
}

fn valid_s3_endpoint(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|endpoint| {
        let root_path = endpoint.path().is_empty() || endpoint.path() == "/";
        let no_ambient_authority = endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none();
        let secure = endpoint.scheme() == "https" && endpoint.host_str().is_some();
        let loopback_http = endpoint.scheme() == "http"
            && endpoint.port().is_some()
            && endpoint
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"));
        root_path
            && no_ambient_authority
            && !endpoint.cannot_be_a_base()
            && (secure || loopback_http)
    })
}

impl ObjectStorage for S3CompatibleObjectStorage {
    fn identity(&self) -> ObjectStorageIdentity {
        self.identity.clone()
    }

    fn put_if_absent(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<ObjectWriteOutcome, ObjectStorageError> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        let response = self
            .bucket
            .put_object_builder(self.key(key)?, bytes)
            .with_header("if-none-match", "*")
            .map_err(s3_error)?
            .execute()
            .map_err(s3_error)?;
        match response.status_code() {
            200..=299 => Ok(ObjectWriteOutcome::Created),
            409 | 412 => Ok(ObjectWriteOutcome::AlreadyExists),
            401 | 403 => Err(ObjectStorageError::new(
                ObjectStorageErrorCode::CredentialsExpired,
            )),
            _ => Err(ObjectStorageError::new(ObjectStorageErrorCode::Unavailable)),
        }
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, ObjectStorageError> {
        let mut writer = BoundedObjectWriter::new(MAX_OBJECT_BYTES);
        let response = self
            .bucket
            .get_object_to_writer(self.key(key)?, &mut writer);
        if writer.overflowed {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        let status = response.map_err(s3_error)?;
        match status {
            200..=299 if !writer.bytes.is_empty() => Ok(writer.bytes),
            200..=299 => Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            )),
            404 => Err(ObjectStorageError::new(ObjectStorageErrorCode::NotFound)),
            401 | 403 => Err(ObjectStorageError::new(
                ObjectStorageErrorCode::CredentialsExpired,
            )),
            _ => Err(ObjectStorageError::new(ObjectStorageErrorCode::Unavailable)),
        }
    }

    fn delete(&self, key: &str) -> Result<(), ObjectStorageError> {
        let response = self
            .bucket
            .delete_object(self.key(key)?)
            .map_err(s3_error)?;
        match response.status_code() {
            200..=299 | 404 => Ok(()),
            401 | 403 => Err(ObjectStorageError::new(
                ObjectStorageErrorCode::CredentialsExpired,
            )),
            _ => Err(ObjectStorageError::new(ObjectStorageErrorCode::Unavailable)),
        }
    }

    fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, ObjectStorageError> {
        let qualified_prefix = self.key(prefix)?;
        self.list_qualified_prefix(qualified_prefix, limit)
    }

    fn list_namespace(&self, limit: usize) -> Result<Vec<String>, ObjectStorageError> {
        self.list_qualified_prefix(self.prefix.clone(), limit)
    }
}

/// Named deterministic object provider faults.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectFailpoint {
    /// Writes a truncated object then reports failure.
    PartialUpload,
    /// Writes a truncated final object during restore after allowing its incomplete marker.
    PartialObjectUpload,
    /// Makes the next otherwise-present read look missing.
    MissingObject,
    /// Rejects the next operation as expired credentials.
    CredentialExpiry,
    /// Omits the newest object from one list response.
    StaleList,
}

/// Deterministic object provider for publication, recovery, and chaos tests.
pub struct InMemoryObjectStorage {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    failpoints: Mutex<BTreeSet<ObjectFailpoint>>,
    namespace: String,
}

impl Default for InMemoryObjectStorage {
    fn default() -> Self {
        Self {
            objects: Mutex::new(BTreeMap::new()),
            failpoints: Mutex::new(BTreeSet::new()),
            namespace: "default".to_owned(),
        }
    }
}

impl fmt::Debug for InMemoryObjectStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryObjectStorage")
    }
}

impl InMemoryObjectStorage {
    /// Creates an isolated deterministic namespace for backup/restore tests.
    pub fn with_namespace(namespace: impl Into<String>) -> Result<Self, ObjectStorageError> {
        let namespace = namespace.into();
        if namespace.is_empty()
            || namespace.len() > 1_024
            || namespace.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        Ok(Self {
            objects: Mutex::new(BTreeMap::new()),
            failpoints: Mutex::new(BTreeSet::new()),
            namespace,
        })
    }

    /// Arms one one-shot provider failure.
    pub fn inject(&self, failpoint: ObjectFailpoint) -> Result<(), ObjectStorageError> {
        self.failpoints
            .lock()
            .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?
            .insert(failpoint);
        Ok(())
    }

    fn trip(&self, failpoint: ObjectFailpoint) -> Result<bool, ObjectStorageError> {
        Ok(self
            .failpoints
            .lock()
            .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?
            .remove(&failpoint))
    }

    fn credentials(&self) -> Result<(), ObjectStorageError> {
        if self.trip(ObjectFailpoint::CredentialExpiry)? {
            Err(ObjectStorageError::new(
                ObjectStorageErrorCode::CredentialsExpired,
            ))
        } else {
            Ok(())
        }
    }
}

impl ObjectStorage for InMemoryObjectStorage {
    fn identity(&self) -> ObjectStorageIdentity {
        ObjectStorageIdentity {
            provider: "memory-object-v1".to_owned(),
            namespace: self.namespace.clone(),
        }
    }

    fn put_if_absent(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<ObjectWriteOutcome, ObjectStorageError> {
        self.credentials()?;
        validate_object_key(key)?;
        if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        let mut objects = self
            .objects
            .lock()
            .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?;
        if objects.contains_key(key) {
            return Ok(ObjectWriteOutcome::AlreadyExists);
        }
        if self.trip(ObjectFailpoint::PartialUpload)?
            || (key.contains("/objects/") && self.trip(ObjectFailpoint::PartialObjectUpload)?)
        {
            let prefix = bytes.len().saturating_sub(1).max(1);
            let partial = bytes
                .get(..prefix)
                .ok_or_else(|| ObjectStorageError::new(ObjectStorageErrorCode::InvalidMetadata))?
                .to_vec();
            objects.insert(key.to_owned(), partial);
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InjectedAbort,
            ));
        }
        objects.insert(key.to_owned(), bytes.to_vec());
        Ok(ObjectWriteOutcome::Created)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, ObjectStorageError> {
        self.credentials()?;
        validate_object_key(key)?;
        if self.trip(ObjectFailpoint::MissingObject)? {
            return Err(ObjectStorageError::new(ObjectStorageErrorCode::NotFound));
        }
        self.objects
            .lock()
            .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?
            .get(key)
            .cloned()
            .ok_or_else(|| ObjectStorageError::new(ObjectStorageErrorCode::NotFound))
    }

    fn delete(&self, key: &str) -> Result<(), ObjectStorageError> {
        self.credentials()?;
        validate_object_key(key)?;
        self.objects
            .lock()
            .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?
            .remove(key);
        Ok(())
    }

    fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, ObjectStorageError> {
        self.credentials()?;
        validate_object_key(prefix)?;
        self.list_matching(Some(prefix), limit)
    }

    fn list_namespace(&self, limit: usize) -> Result<Vec<String>, ObjectStorageError> {
        self.credentials()?;
        self.list_matching(None, limit)
    }
}

impl InMemoryObjectStorage {
    fn list_matching(
        &self,
        prefix: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, ObjectStorageError> {
        validate_list_limit(limit)?;
        let mut keys: Vec<_> = self
            .objects
            .lock()
            .map_err(|_error| ObjectStorageError::new(ObjectStorageErrorCode::Unavailable))?
            .keys()
            .filter(|key| prefix.is_none_or(|prefix| key.starts_with(prefix)))
            .take(limit.saturating_add(1))
            .cloned()
            .collect();
        if keys.len() > limit {
            return Err(ObjectStorageError::new(
                ObjectStorageErrorCode::InvalidMetadata,
            ));
        }
        if self.trip(ObjectFailpoint::StaleList)? {
            let _removed = keys.pop();
        }
        Ok(keys)
    }
}

/// Encrypted tenant-blinded repository adapter over an immutable object provider.
pub struct ObjectRepositoryBlobStore<P: KeyProvider, S: ObjectStorage> {
    provider: Arc<P>,
    storage: Arc<S>,
    default_wrapping_key: Mutex<Option<KeyRef>>,
    wrapping_keys: Mutex<BTreeMap<RecordId, KeyRef>>,
    semantic_time: Mutex<i128>,
    blinding_key: [u8; 32],
}

impl<P: KeyProvider, S: ObjectStorage> fmt::Debug for ObjectRepositoryBlobStore<P, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectRepositoryBlobStore([REDACTED])")
    }
}

impl<P: KeyProvider, S: ObjectStorage> ObjectRepositoryBlobStore<P, S> {
    /// Binds explicit crypto, object, wrapping, and key-blinding capabilities.
    #[must_use]
    pub fn new(
        provider: Arc<P>,
        storage: Arc<S>,
        wrapping_key: KeyRef,
        semantic_time: i128,
        blinding_key: [u8; 32],
    ) -> Self {
        Self {
            provider,
            storage,
            default_wrapping_key: Mutex::new(Some(wrapping_key)),
            wrapping_keys: Mutex::new(BTreeMap::new()),
            semantic_time: Mutex::new(semantic_time),
            blinding_key,
        }
    }

    /// Binds an exact non-empty tenant-to-wrapping-key map for shared service composition.
    pub fn new_multi_tenant(
        provider: Arc<P>,
        storage: Arc<S>,
        wrapping_keys: BTreeMap<RecordId, KeyRef>,
        semantic_time: i128,
        blinding_key: [u8; 32],
    ) -> Result<Self, StoreError> {
        if wrapping_keys.is_empty() || wrapping_keys.len() > 65_536 {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        Ok(Self {
            provider,
            storage,
            default_wrapping_key: Mutex::new(None),
            wrapping_keys: Mutex::new(wrapping_keys),
            semantic_time: Mutex::new(semantic_time),
            blinding_key,
        })
    }

    /// Rotates future encrypted object writes without invalidating old framed objects.
    pub fn rotate_to(&self, wrapping_key: KeyRef, semantic_time: i128) -> Result<(), StoreError> {
        *self
            .default_wrapping_key
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))? = Some(wrapping_key);
        *self
            .semantic_time
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))? = semantic_time;
        Ok(())
    }

    /// Rotates one exact shared tenant without changing any other tenant mapping.
    pub fn rotate_tenant(
        &self,
        tenant: RecordId,
        wrapping_key: KeyRef,
        semantic_time: i128,
    ) -> Result<(), StoreError> {
        self.wrapping_keys
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
            .insert(tenant, wrapping_key);
        *self
            .semantic_time
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))? = semantic_time;
        Ok(())
    }

    fn semantic_time(&self) -> Result<i128, StoreError> {
        self.semantic_time
            .lock()
            .map(|time| *time)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }

    fn configuration(&self, tenant: &RecordId) -> Result<(KeyRef, i128), StoreError> {
        let configured = self
            .wrapping_keys
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
            .get(tenant)
            .cloned();
        let key = match configured {
            Some(key) => key,
            None => self
                .default_wrapping_key
                .lock()
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
                .clone()
                .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?,
        };
        let time = *self
            .semantic_time
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        Ok((key, time))
    }

    fn tenant_prefix(&self, tenant: &RecordId) -> Result<String, StoreError> {
        let blinded = blind(&self.blinding_key, &[b"tenant", tenant.as_str().as_bytes()])?;
        Ok(format!("tenants/{blinded}/"))
    }

    fn final_key(&self, tenant: &RecordId, digest: &ContentDigest) -> Result<String, StoreError> {
        let prefix = self.tenant_prefix(tenant)?;
        let blinded = blind(
            &self.blinding_key,
            &[
                b"blob",
                tenant.as_str().as_bytes(),
                digest.as_str().as_bytes(),
            ],
        )?;
        Ok(format!("{prefix}objects/{blinded}"))
    }

    fn staging_key(&self, tenant: &RecordId, bytes: &[u8]) -> Result<String, StoreError> {
        let prefix = self.tenant_prefix(tenant)?;
        let digest = Sha256::digest(bytes);
        Ok(format!("{prefix}staging/{}", hex(&digest)))
    }

    /// Deletes an exact metadata-derived set of zero-reference blinded objects.
    fn garbage_collect_object_keys(
        &self,
        candidates: &[RepositoryGarbageCollectionCandidate],
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_objects: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        if !policy.retention_satisfied || policy.legal_hold || !policy.backup_complete {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        if max_objects == 0
            || max_objects > MAX_OBJECT_LIST_ITEMS
            || candidates.len() > max_objects
            || candidates.windows(2).any(|pair| {
                pair.first().zip(pair.get(1)).is_some_and(|(left, right)| {
                    (&left.tenant_id, &left.digest) >= (&right.tenant_id, &right.digest)
                })
            })
        {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut report = RepositoryGarbageCollectionReport::default();
        for candidate in candidates {
            let key = self.final_key(&candidate.tenant_id, &candidate.digest)?;
            match self.storage.get(&key) {
                Ok(_bytes) => {}
                Err(error) if error.code() == ObjectStorageErrorCode::NotFound => continue,
                Err(error) => return Err(object_error(error)),
            }
            report.eligible.push(candidate.clone());
            if !dry_run {
                self.storage.delete(&key).map_err(object_error)?;
                report.deleted = report
                    .deleted
                    .checked_add(1)
                    .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            }
        }
        Ok(report)
    }
}

impl<P: KeyProvider, S: ObjectStorage> RepositoryBlobStore for ObjectRepositoryBlobStore<P, S> {
    fn put(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        let (wrapping_key, now) = self.configuration(tenant)?;
        let protected = protect_blob_bytes(
            self.provider.as_ref(),
            tenant.as_str(),
            &wrapping_key,
            blob,
            now,
        )?;
        let staging_key = self.staging_key(tenant, &protected)?;
        self.storage
            .put_if_absent(&staging_key, &protected)
            .map_err(object_error)?;
        let staged = self.storage.get(&staging_key).map_err(object_error)?;
        if staged != protected {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let final_key = self.final_key(tenant, &blob.reference.digest)?;
        self.storage
            .put_if_absent(&final_key, &protected)
            .map_err(object_error)?;
        let committed = self.storage.get(&final_key).map_err(object_error)?;
        let observed = unprotect_blob_bytes(
            self.provider.as_ref(),
            tenant.as_str(),
            &blob.reference,
            &committed,
            now,
        )?;
        if observed != *blob {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let _cleanup = self.storage.delete(&staging_key);
        Ok(())
    }

    fn get(
        &self,
        tenant: &RecordId,
        reference: &BlobRef,
    ) -> Result<Option<BlobRecord>, StoreError> {
        let now = self.semantic_time()?;
        let key = self.final_key(tenant, &reference.digest)?;
        let bytes = match self.storage.get(&key) {
            Ok(bytes) => bytes,
            Err(error) if error.code() == ObjectStorageErrorCode::NotFound => return Ok(None),
            Err(error) => return Err(object_error(error)),
        };
        unprotect_blob_bytes(
            self.provider.as_ref(),
            tenant.as_str(),
            reference,
            &bytes,
            now,
        )
        .map(Some)
    }

    fn verify_integrity(&self, tenant: &RecordId, reference: &BlobRef) -> Result<(), StoreError> {
        match self.get(tenant, reference)? {
            Some(_record) => Ok(()),
            None => Err(StoreError::new(StoreErrorCode::NotFound)),
        }
    }

    fn readiness_probe(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        let (wrapping_key, now) = self.configuration(tenant)?;
        let protected = protect_blob_bytes(
            self.provider.as_ref(),
            tenant.as_str(),
            &wrapping_key,
            blob,
            now,
        )?;
        let key = format!(
            "{}probes/{}",
            self.tenant_prefix(tenant)?,
            hex(&Sha256::digest(&protected))
        );
        self.storage
            .put_if_absent(&key, &protected)
            .map_err(object_error)?;
        let observed = self.storage.get(&key).map_err(object_error)?;
        let result = unprotect_blob_bytes(
            self.provider.as_ref(),
            tenant.as_str(),
            &blob.reference,
            &observed,
            now,
        )
        .and_then(|observed| {
            if observed == *blob {
                Ok(())
            } else {
                Err(StoreError::new(StoreErrorCode::Unavailable))
            }
        });
        let cleanup = self.storage.delete(&key).map_err(object_error);
        result.and(cleanup)
    }

    fn reconcile(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<(), StoreError> {
        for (tenant, digests) in live {
            let tenant = RecordId::new(tenant.clone())
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?;
            for digest in digests {
                let key = self.final_key(&tenant, digest)?;
                self.storage.get(&key).map_err(object_error)?;
            }
        }
        for key in self
            .storage
            .list_prefix("tenants/", MAX_OBJECT_LIST_ITEMS)
            .map_err(object_error)?
        {
            if key.contains("/staging/") || key.contains("/probes/") {
                self.storage.delete(&key).map_err(object_error)?;
            }
        }
        Ok(())
    }

    fn backup_inventory(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<ObjectBackupInventory, StoreError> {
        if live.len() > 65_536 {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut entries = Vec::new();
        for (tenant, digests) in live {
            let tenant = RecordId::new(tenant.clone())
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?;
            for digest in digests {
                if entries.len() >= MAX_OBJECT_BACKUP_ENTRIES {
                    return Err(StoreError::new(StoreErrorCode::LimitExceeded));
                }
                let storage_key = self.final_key(&tenant, digest)?;
                let bytes = self.storage.get(&storage_key).map_err(object_error)?;
                let wrapping_key_ref = persisted_blob_key_ref(&bytes)
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
                let size_bytes = u64::try_from(bytes.len())
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
                let ciphertext_checksum = format!("1220{}", hex(&Sha256::digest(&bytes)));
                entries.push(ObjectBackupEntry {
                    storage_key,
                    wrapping_key_ref,
                    size_bytes,
                    ciphertext_checksum,
                });
            }
        }
        entries.sort_by(|left, right| left.storage_key.cmp(&right.storage_key));
        if entries.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(a, b)| a.storage_key >= b.storage_key)
        }) {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        Ok(ObjectBackupInventory {
            format_version: 2,
            storage: self.storage.identity(),
            entries,
        })
    }

    fn copy_backup_inventory(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        destination: &dyn ObjectStorage,
    ) -> Result<(ObjectBackupInventory, ObjectRestoreReceipt), StoreError> {
        let source = self.backup_inventory(live)?;
        let receipt = restore_object_backup_inventory(self.storage.as_ref(), destination, &source)?;
        let mut backup = source;
        backup.storage = destination.identity();
        backup.validate()?;
        Ok((backup, receipt))
    }

    fn garbage_collect_candidates(
        &self,
        _authorization: &SharedGarbageCollectionAuthorization,
        candidates: &[RepositoryGarbageCollectionCandidate],
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_objects: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        self.garbage_collect_object_keys(candidates, policy, dry_run, max_objects)
    }

    fn garbage_collect(
        &self,
        _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        policy: GarbageCollectionPolicy,
        _dry_run: bool,
        _max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        if !policy.retention_satisfied || policy.legal_hold || !policy.backup_complete {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        // Shared GC must use `garbage_collect_object_keys` with exact metadata-derived candidates;
        // blinded names intentionally cannot be reverse-mapped from a provider listing.
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

fn blind(key: &[u8; 32], components: &[&[u8]]) -> Result<String, StoreError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    mac.update(b"CIGAR-OBJECT-KEY-v1\0");
    for component in components {
        let length = u64::try_from(component.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        mac.update(&length.to_be_bytes());
        mac.update(component);
    }
    Ok(hex(&mac.finalize().into_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn normalize_prefix(mut prefix: String) -> Result<String, ObjectStorageError> {
    if prefix.starts_with('/') || prefix.contains("..") || prefix.len() > 512 {
        return Err(ObjectStorageError::new(
            ObjectStorageErrorCode::InvalidMetadata,
        ));
    }
    if !prefix.is_empty() && !prefix.ends_with('/') {
        prefix.push('/');
    }
    Ok(prefix)
}

fn validate_object_key(key: &str) -> Result<(), ObjectStorageError> {
    if key.is_empty()
        || key.len() > MAX_OBJECT_KEY_BYTES
        || key.starts_with('/')
        || key.contains("..")
        || key.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(ObjectStorageError::new(
            ObjectStorageErrorCode::InvalidMetadata,
        ))
    } else {
        Ok(())
    }
}

fn validate_list_limit(limit: usize) -> Result<(), ObjectStorageError> {
    if limit == 0 || limit > MAX_OBJECT_LIST_ITEMS {
        Err(ObjectStorageError::new(
            ObjectStorageErrorCode::InvalidMetadata,
        ))
    } else {
        Ok(())
    }
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_control())
}

fn valid_multihash(value: &str) -> bool {
    value.len() == 68
        && value.starts_with("1220")
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn restore_failure(
    destination: &dyn ObjectStorage,
    created: &[String],
    original: StoreError,
) -> StoreError {
    if rollback_restore_objects(destination, created).is_ok() {
        original
    } else {
        StoreError::new(StoreErrorCode::Unavailable)
    }
}

fn namespace_matches(storage: &dyn ObjectStorage, expected: &[String]) -> Result<bool, StoreError> {
    let listing_limit = expected.len().saturating_add(1).min(MAX_OBJECT_LIST_ITEMS);
    storage
        .list_namespace(listing_limit.max(1))
        .map(|observed| observed == expected)
        .map_err(object_error)
}

fn rollback_restore_objects(
    destination: &dyn ObjectStorage,
    created: &[String],
) -> Result<(), StoreError> {
    let mut deletion_failed = false;
    for key in created.iter().rev() {
        if destination.delete(key).is_err() {
            deletion_failed = true;
        }
    }
    let empty = destination
        .list_namespace(1)
        .map(|keys| keys.is_empty())
        .unwrap_or(false);
    if empty && !deletion_failed {
        Ok(())
    } else {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

fn verify_backup_entry(entry: &ObjectBackupEntry, bytes: &[u8]) -> Result<(), StoreError> {
    let size = u64::try_from(bytes.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let checksum = format!("1220{}", hex(&Sha256::digest(bytes)));
    let wrapping_key_ref = persisted_blob_key_ref(bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    if size == entry.size_bytes
        && checksum == entry.ciphertext_checksum
        && wrapping_key_ref == entry.wrapping_key_ref
    {
        Ok(())
    } else {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

fn object_inventory_root(inventory: &ObjectBackupInventory) -> Result<String, StoreError> {
    inventory.validate()?;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(inventory, &mut bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    Ok(format!("1220{}", hex(&Sha256::digest(bytes))))
}

fn object_error(error: ObjectStorageError) -> StoreError {
    match error.code() {
        ObjectStorageErrorCode::InvalidMetadata => StoreError::new(StoreErrorCode::InvalidRecord),
        ObjectStorageErrorCode::NotFound => StoreError::new(StoreErrorCode::NotFound),
        ObjectStorageErrorCode::InjectedAbort => StoreError::new(StoreErrorCode::InjectedAbort),
        _ => StoreError::new(StoreErrorCode::Unavailable),
    }
}

fn s3_error(_error: s3::error::S3Error) -> ObjectStorageError {
    ObjectStorageError::new(ObjectStorageErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedObjectWriter, InMemoryObjectStorage, MAX_S3_LIST_ELAPSED, MAX_S3_LIST_PAGES,
        ObjectFailpoint, ObjectRepositoryBlobStore, ObjectStorage, ObjectStorageErrorCode,
        S3CompatibleObjectStorage, S3ListingBudget, restore_object_backup_inventory,
    };
    use crate::{
        BlobRecord, GarbageCollectionPolicy, RepositoryBlobStore,
        RepositoryGarbageCollectionCandidate, StoreErrorCode,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, MemoryKeyProvider,
    };
    use cigar_protocol::{BlobRef, ContentDigest, MediaType, RecordId};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;
    use std::sync::Arc;
    use std::time::Instant;

    type Adapter = ObjectRepositoryBlobStore<MemoryKeyProvider, InMemoryObjectStorage>;
    type Fixture = (Arc<InMemoryObjectStorage>, Adapter, RecordId, BlobRecord);

    fn blob_record(bytes: &[u8]) -> Result<BlobRecord, Box<dyn std::error::Error>> {
        let digest = Sha256::digest(bytes);
        let mut value = String::from("1220");
        for byte in digest {
            use std::fmt::Write as _;
            let _result = write!(&mut value, "{byte:02x}");
        }
        Ok(BlobRecord::new(
            BlobRef {
                digest: ContentDigest::new(value)?,
                size_bytes: u64::try_from(bytes.len())?,
                media_type: MediaType::new("application/octet-stream")?,
            },
            bytes.to_vec(),
        )?)
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let provider = Arc::new(MemoryKeyProvider::default());
        let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?;
        let key = provider.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let storage = Arc::new(InMemoryObjectStorage::default());
        let adapter = ObjectRepositoryBlobStore::new(
            provider,
            Arc::clone(&storage),
            key.key_ref,
            1,
            [0x5a; 32],
        );
        let blob = blob_record(b"object-secret-canary")?;
        Ok((storage, adapter, tenant, blob))
    }

    #[test]
    fn encrypted_cas_is_blinded_idempotent_and_reconciles_staging()
    -> Result<(), Box<dyn std::error::Error>> {
        let (storage, adapter, tenant, blob) = fixture()?;
        adapter.put(&tenant, &blob)?;
        adapter.put(&tenant, &blob)?;
        assert_eq!(adapter.get(&tenant, &blob.reference)?, Some(blob.clone()));

        let keys = storage.list_prefix("tenants/", 100)?;
        assert_eq!(
            keys.iter().filter(|key| key.contains("/objects/")).count(),
            1
        );
        assert!(keys.iter().all(|key| !key.contains(tenant.as_str())));
        assert!(
            keys.iter()
                .all(|key| !key.contains(blob.reference.digest.as_str()))
        );
        for key in keys.iter().filter(|key| key.contains("/objects/")) {
            let protected = storage.get(key)?;
            assert!(
                !protected
                    .windows(blob.bytes().len())
                    .any(|window| window == blob.bytes())
            );
        }

        let mut live = BTreeMap::new();
        live.insert(
            tenant.as_str().to_owned(),
            BTreeSet::from([blob.reference.digest.clone()]),
        );
        adapter.reconcile(&live)?;
        assert!(
            storage
                .list_prefix("tenants/", 100)?
                .iter()
                .all(|key| !key.contains("/staging/"))
        );
        Ok(())
    }

    #[test]
    fn partial_missing_and_expired_credentials_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (storage, adapter, tenant, blob) = fixture()?;
        storage.inject(ObjectFailpoint::PartialUpload)?;
        assert_eq!(
            adapter.put(&tenant, &blob).map_err(|error| error.code()),
            Err(StoreErrorCode::InjectedAbort)
        );
        assert!(
            storage
                .list_prefix("tenants/", 100)?
                .iter()
                .all(|key| !key.contains("/objects/"))
        );
        adapter.reconcile(&BTreeMap::new())?;
        assert!(storage.list_prefix("tenants/", 100)?.is_empty());

        adapter.put(&tenant, &blob)?;
        storage.inject(ObjectFailpoint::MissingObject)?;
        assert!(adapter.get(&tenant, &blob.reference)?.is_none());
        storage.inject(ObjectFailpoint::CredentialExpiry)?;
        assert_eq!(
            adapter
                .get(&tenant, &blob.reference)
                .map_err(|error| error.code()),
            Err(StoreErrorCode::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn exact_metadata_candidates_drive_blinded_object_gc() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_storage, adapter, tenant, blob) = fixture()?;
        adapter.put(&tenant, &blob)?;
        let candidates = [RepositoryGarbageCollectionCandidate {
            tenant_id: tenant.clone(),
            digest: blob.reference.digest.clone(),
        }];
        let policy = GarbageCollectionPolicy {
            retention_satisfied: true,
            legal_hold: false,
            backup_complete: true,
        };
        let dry = adapter.garbage_collect_object_keys(&candidates, policy, true, 1)?;
        assert_eq!(dry.eligible, candidates);
        assert_eq!(dry.deleted, 0);
        assert_eq!(adapter.get(&tenant, &blob.reference)?, Some(blob.clone()));
        let deleted = adapter.garbage_collect_object_keys(&candidates, policy, false, 1)?;
        assert_eq!(deleted.eligible, candidates);
        assert_eq!(deleted.deleted, 1);
        assert!(adapter.get(&tenant, &blob.reference)?.is_none());
        Ok(())
    }

    #[test]
    fn readiness_probe_leaves_no_probe_object() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, adapter, tenant, blob) = fixture()?;
        adapter.readiness_probe(&tenant, &blob)?;
        assert!(storage.list_prefix("tenants/", 100)?.is_empty());
        Ok(())
    }

    #[test]
    fn s3_response_writer_stops_before_allocating_an_oversized_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = BoundedObjectWriter::new(4);
        writer.write_all(&[0x5a; 4])?;
        assert_eq!(writer.bytes.len(), 4);
        assert!(writer.write_all(&[0x5a]).is_err());
        assert!(writer.overflowed);
        assert_eq!(writer.bytes.len(), 4);
        Ok(())
    }

    #[test]
    fn s3_endpoint_is_a_closed_origin_without_embedded_authority() {
        let construct = |endpoint: &str| {
            S3CompatibleObjectStorage::new(
                endpoint,
                "us-east-1",
                "cigar-shared",
                "production",
                "explicit-access-key",
                "explicit-secret-key",
                None,
                false,
            )
        };
        for invalid in [
            "https://user@objects.example",
            "https://user:password@objects.example",
            "https://objects.example/path",
            "https://objects.example?tenant=other",
            "https://objects.example#fragment",
            "http://objects.example:9000",
            "http://localhost",
        ] {
            assert_eq!(
                construct(invalid).err().map(|error| error.code()),
                Some(ObjectStorageErrorCode::InvalidMetadata),
                "endpoint {invalid:?} must fail closed"
            );
        }
        for allowed in [
            "https://objects.example",
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            assert!(
                construct(allowed).is_ok(),
                "endpoint {allowed:?} should pass"
            );
        }
    }

    #[test]
    fn s3_listing_budget_rejects_nonprogress_cycles_and_unbounded_pages()
    -> Result<(), Box<dyn std::error::Error>> {
        let started = Instant::now();

        let mut no_progress = S3ListingBudget::new(started)?;
        no_progress.next_page_timeout(started)?;
        assert_eq!(
            no_progress
                .accept_continuation("A".to_owned(), false)
                .map_err(|error| error.code()),
            Err(ObjectStorageErrorCode::InvalidMetadata)
        );

        let mut cycle = S3ListingBudget::new(started)?;
        for token in ["A", "B"] {
            cycle.next_page_timeout(started)?;
            cycle.accept_continuation(token.to_owned(), true)?;
        }
        cycle.next_page_timeout(started)?;
        assert_eq!(
            cycle
                .accept_continuation("A".to_owned(), true)
                .map_err(|error| error.code()),
            Err(ObjectStorageErrorCode::InvalidMetadata)
        );

        let mut fresh = S3ListingBudget::new(started)?;
        for page in 0..MAX_S3_LIST_PAGES {
            fresh.next_page_timeout(started)?;
            fresh.accept_continuation(format!("token-{page}"), true)?;
        }
        assert_eq!(
            fresh
                .next_page_timeout(started)
                .map_err(|error| error.code()),
            Err(ObjectStorageErrorCode::InvalidMetadata)
        );

        let mut elapsed = S3ListingBudget::new(started)?;
        assert_eq!(
            elapsed
                .next_page_timeout(started + MAX_S3_LIST_ELAPSED)
                .map_err(|error| error.code()),
            Err(ObjectStorageErrorCode::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn backup_inventory_restores_exact_ciphertext_only_into_fresh_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, adapter, tenant, blob) = fixture()?;
        adapter.put(&tenant, &blob)?;
        let live = BTreeMap::from([(
            tenant.as_str().to_owned(),
            BTreeSet::from([blob.reference.digest.clone()]),
        )]);
        let inventory = adapter.backup_inventory(&live)?;
        inventory.validate()?;
        assert_eq!(inventory.entries.len(), 1);
        let entry = inventory
            .entries
            .first()
            .ok_or("backup inventory omitted its live object")?;
        assert!(!entry.wrapping_key_ref.as_str().is_empty());

        let destination = InMemoryObjectStorage::with_namespace("fresh-restore")?;
        let receipt = restore_object_backup_inventory(source.as_ref(), &destination, &inventory)?;
        assert_eq!(receipt.object_count(), 1);
        assert_eq!(receipt.ciphertext_bytes(), entry.size_bytes);
        assert_ne!(receipt.source(), receipt.destination());
        let keys = destination.list_namespace(10)?;
        assert_eq!(keys, vec![entry.storage_key.clone()]);
        let restored_key = keys.first().ok_or("restored object key is missing")?;
        assert_eq!(
            destination.get(restored_key)?,
            source.get(&entry.storage_key)?
        );

        assert!(
            restore_object_backup_inventory(source.as_ref(), &destination, &inventory).is_err()
        );
        Ok(())
    }

    #[test]
    fn restore_rejects_pollution_anywhere_in_the_destination_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, adapter, tenant, blob) = fixture()?;
        adapter.put(&tenant, &blob)?;
        let live = BTreeMap::from([(
            tenant.as_str().to_owned(),
            BTreeSet::from([blob.reference.digest.clone()]),
        )]);
        let inventory = adapter.backup_inventory(&live)?;
        let destination = InMemoryObjectStorage::with_namespace("polluted-restore")?;
        assert_eq!(
            destination.put_if_absent("unrelated/pollution", b"x")?,
            super::ObjectWriteOutcome::Created
        );

        assert!(
            restore_object_backup_inventory(source.as_ref(), &destination, &inventory).is_err()
        );
        assert_eq!(
            destination.list_namespace(10)?,
            vec!["unrelated/pollution".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn final_exact_listing_detects_stale_preflight_and_rolls_back_created_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, adapter, tenant, blob) = fixture()?;
        adapter.put(&tenant, &blob)?;
        let live = BTreeMap::from([(
            tenant.as_str().to_owned(),
            BTreeSet::from([blob.reference.digest.clone()]),
        )]);
        let inventory = adapter.backup_inventory(&live)?;
        let destination = InMemoryObjectStorage::with_namespace("stale-list-restore")?;
        assert_eq!(
            destination.put_if_absent("unrelated/pollution", b"x")?,
            super::ObjectWriteOutcome::Created
        );
        destination.inject(ObjectFailpoint::StaleList)?;

        assert!(
            restore_object_backup_inventory(source.as_ref(), &destination, &inventory).is_err()
        );
        assert_eq!(
            destination.list_namespace(10)?,
            vec!["unrelated/pollution".to_owned()],
            "all restore-created keys must be rolled back while pre-existing pollution remains"
        );
        Ok(())
    }

    #[test]
    fn partial_restore_object_upload_rolls_back_marker_and_truncated_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, adapter, tenant, blob) = fixture()?;
        adapter.put(&tenant, &blob)?;
        let live = BTreeMap::from([(
            tenant.as_str().to_owned(),
            BTreeSet::from([blob.reference.digest.clone()]),
        )]);
        let inventory = adapter.backup_inventory(&live)?;
        let destination = InMemoryObjectStorage::with_namespace("partial-restore")?;
        destination.inject(ObjectFailpoint::PartialObjectUpload)?;

        assert_eq!(
            restore_object_backup_inventory(source.as_ref(), &destination, &inventory)
                .map_err(|error| error.code()),
            Err(StoreErrorCode::InjectedAbort)
        );
        assert!(destination.list_namespace(10)?.is_empty());
        Ok(())
    }

    #[test]
    fn inventory_binds_each_objects_historical_wrapping_key_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let provider = Arc::new(MemoryKeyProvider::default());
        let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?;
        let first_key = provider.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let storage = Arc::new(InMemoryObjectStorage::with_namespace("historical-keys")?);
        let adapter = ObjectRepositoryBlobStore::new(
            Arc::clone(&provider),
            Arc::clone(&storage),
            first_key.key_ref.clone(),
            1,
            [0x6b; 32],
        );
        let first_blob = blob_record(b"encrypted-under-first-wrapping-key")?;
        adapter.put(&tenant, &first_blob)?;
        let successor = provider.rotate(&first_key.key_ref, tenant.as_str(), 2)?;
        adapter.rotate_to(successor.key_ref.clone(), 2)?;
        let second_blob = blob_record(b"encrypted-under-successor-wrapping-key")?;
        adapter.put(&tenant, &second_blob)?;

        let live = BTreeMap::from([(
            tenant.as_str().to_owned(),
            BTreeSet::from([
                first_blob.reference.digest.clone(),
                second_blob.reference.digest.clone(),
            ]),
        )]);
        let inventory = adapter.backup_inventory(&live)?;
        assert_eq!(inventory.format_version, 2);
        let observed: BTreeSet<_> = inventory
            .entries
            .iter()
            .map(|entry| entry.wrapping_key_ref.clone())
            .collect();
        assert_eq!(
            observed,
            BTreeSet::from([first_key.key_ref.clone(), successor.key_ref.clone()])
        );

        let mut tampered = inventory.clone();
        tampered
            .entries
            .first_mut()
            .ok_or("historical inventory unexpectedly empty")?
            .wrapping_key_ref = KeyRef::new("forged-wrapping-key")?;
        let rejected = InMemoryObjectStorage::with_namespace("historical-key-tamper")?;
        assert!(restore_object_backup_inventory(storage.as_ref(), &rejected, &tampered).is_err());
        assert!(rejected.list_namespace(10)?.is_empty());

        let destination = Arc::new(InMemoryObjectStorage::with_namespace(
            "historical-keys-restored",
        )?);
        restore_object_backup_inventory(storage.as_ref(), destination.as_ref(), &inventory)?;
        let restored =
            ObjectRepositoryBlobStore::new(provider, destination, successor.key_ref, 2, [0x6b; 32]);
        assert_eq!(
            restored.get(&tenant, &first_blob.reference)?,
            Some(first_blob)
        );
        assert_eq!(
            restored.get(&tenant, &second_blob.reference)?,
            Some(second_blob)
        );
        Ok(())
    }
}
