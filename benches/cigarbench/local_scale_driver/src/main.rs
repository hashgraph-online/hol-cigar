//! Native Apple-silicon physical driver for the immutable CIGAR large-local scale profile.

use cigar_crypto::{
    CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef,
    SecretBytes,
};
use cigar_protocol::{
    AtomPayload, BlobRef, ContentDigest, ContextAtomV1, ContextEdge, EdgeKind, LineageId,
    MediaType, RecordId, Validate, VersionId,
};
use cigar_store::{
    AccessContext, BackupIdentity, BlobRecord, CancellationToken, LocalBlobStore,
    LocalRepositoryBlobStore, Repository, RepositoryBlobStore, SqliteCapacityProfile,
    SqliteCatalogStatistics, SqliteStore, StoreErrorCode, StoreRevision, WriteTransaction,
    create_backup, restore_backup_trusted, verify_backup_trusted,
};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PROFILE_SCHEMA: &str = "cigar.local-scale-profile.v1";
const BINDING_SCHEMA: &str = "cigar.local-scale-binding.v1";
const CHECKPOINT_SCHEMA: &str = "cigar.local-scale-checkpoint.v1";
const OWNER_SCHEMA: &str = "cigar.local-scale-owned-workspace.v2";
const RESULT_SCHEMA: &str = "cigar.local-scale-result.v1";
const PLATFORM: &str = "aarch64-apple-darwin";
const TENANT_ID: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7814";
const SIGNER: &str = "cigar-local-scale-driver";
const MAX_CONTROL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_BOUND_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const PRODUCTION_ATOMS: u64 = 1_000_000;
const PRODUCTION_EDGES: u64 = 10_000_000;
const PRODUCTION_BLOB_OBJECTS: u64 = 1_600;
const PRODUCTION_BLOB_BYTES: u64 = 67_108_864;
const PRODUCTION_REFERENCED_BYTES: u64 = 107_374_182_400;
const MAX_DATABASE_BYTES: u64 = 68_719_476_736;
const MIN_INITIAL_BYTES: u64 = 322_122_547_200;
const MIN_RUNTIME_BYTES: u64 = 17_179_869_184;
const MAX_ATOMS: u64 = 1_250_000;
const MAX_EDGES: u64 = 12_500_000;
const MAX_REFERENCED_BYTES: u64 = 137_438_953_472;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriverErrorCode {
    InvalidArgument,
    UnsupportedHost,
    UnsafePath,
    InvalidBinding,
    InvalidProfile,
    InsufficientSpace,
    CheckpointMismatch,
    StoreFailure,
    IntegrityFailure,
    BackupFailure,
    PublicationFailure,
    InjectedStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DriverError(DriverErrorCode);

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "local-scale driver failed: {:?}", self.0)
    }
}

impl std::error::Error for DriverError {}

type Result<T> = std::result::Result<T, DriverError>;

fn error(code: DriverErrorCode) -> DriverError {
    DriverError(code)
}

fn map_store_failure(_failure: cigar_store::StoreError) -> DriverError {
    #[cfg(debug_assertions)]
    eprintln!("local-scale store category: {:?}", _failure.code());
    error(DriverErrorCode::StoreFailure)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: String,
    id: String,
    platform: String,
    capacity_profile: String,
    atoms: u64,
    edges: u64,
    blob_objects: u64,
    blob_bytes_each: u64,
    referenced_blob_bytes: u64,
    atom_batch_size: u64,
    edge_batch_size: u64,
    maximum_database_bytes: u64,
    minimum_initial_available_bytes: u64,
    minimum_runtime_reserve_bytes: u64,
    maximum_atoms: u64,
    maximum_edges: u64,
    maximum_referenced_blob_bytes: u64,
}

impl Profile {
    fn validate(&self, production: bool) -> Result<()> {
        let common = self.schema_version == PROFILE_SCHEMA
            && self.platform == PLATFORM
            && self.atoms >= if production { 12 } else { 2 }
            && self.edges > 0
            && self.blob_objects > 0
            && self.blob_objects <= self.atoms
            && self.blob_bytes_each >= 8
            && self.blob_bytes_each <= 67_108_864
            && self.referenced_blob_bytes
                == self
                    .blob_objects
                    .checked_mul(self.blob_bytes_each)
                    .ok_or_else(|| error(DriverErrorCode::InvalidProfile))?
            && self.atom_batch_size > 0
            && self.atom_batch_size <= 1_000
            && self.edge_batch_size > 0
            && self.edge_batch_size <= 100_000
            && self.atoms <= self.maximum_atoms
            && self.edges <= self.maximum_edges
            && self.referenced_blob_bytes <= self.maximum_referenced_blob_bytes;
        if !common {
            return Err(error(DriverErrorCode::InvalidProfile));
        }
        if production
            && (self.id != "large_local"
                || self.capacity_profile != "large_local"
                || self.atoms != PRODUCTION_ATOMS
                || self.edges != PRODUCTION_EDGES
                || self.blob_objects != PRODUCTION_BLOB_OBJECTS
                || self.blob_bytes_each != PRODUCTION_BLOB_BYTES
                || self.referenced_blob_bytes != PRODUCTION_REFERENCED_BYTES
                || self.atom_batch_size != 1_000
                || self.edge_batch_size != 10_000
                || self.maximum_database_bytes != MAX_DATABASE_BYTES
                || self.minimum_initial_available_bytes != MIN_INITIAL_BYTES
                || self.minimum_runtime_reserve_bytes != MIN_RUNTIME_BYTES
                || self.maximum_atoms != MAX_ATOMS
                || self.maximum_edges != MAX_EDGES
                || self.maximum_referenced_blob_bytes != MAX_REFERENCED_BYTES)
        {
            return Err(error(DriverErrorCode::InvalidProfile));
        }
        if !production {
            let registered_capacity = match self.capacity_profile.as_str() {
                "standard" => 4_294_967_296,
                "large_local" => MAX_DATABASE_BYTES,
                _ => return Err(error(DriverErrorCode::InvalidProfile)),
            };
            if self.id != "scaled_fixture"
                || self.maximum_database_bytes != registered_capacity
            {
                return Err(error(DriverErrorCode::InvalidProfile));
            }
        }
        Ok(())
    }

    fn counts(&self) -> Counts {
        Counts {
            atoms: self.atoms,
            edges: self.edges,
            blob_objects: self.blob_objects,
            blob_bytes_each: self.blob_bytes_each,
            referenced_blob_bytes: self.referenced_blob_bytes,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileBinding {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RunBinding {
    schema_version: String,
    run_id: String,
    repository_root: String,
    source_revision: String,
    source_tree_sha256: String,
    candidate: FileBinding,
    installed_tool: FileBinding,
    profile: FileBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    atoms: u64,
    edges: u64,
    blob_objects: u64,
    blob_bytes_each: u64,
    referenced_blob_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerMarker {
    schema_version: String,
    run_id: String,
    binding_sha256: String,
    profile_sha256: String,
    workspace_device: u64,
    workspace_inode: u64,
    initial_available_bytes: u64,
    semantic_time_unix_nanos: i128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CheckpointBody {
    schema_version: String,
    run_id: String,
    binding_sha256: String,
    profile_sha256: String,
    phase: String,
    revision: u64,
    atoms: u64,
    edges: u64,
    referenced_blob_bytes: u64,
    catalog_root: String,
    semantic_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Checkpoint {
    #[serde(flatten)]
    body: CheckpointBody,
    checkpoint_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Check {
    id: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Roots {
    catalog: String,
    semantic_before_reopen: String,
    semantic_after_reopen: String,
    semantic_after_restore: String,
    backup_canonical: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StorageEvidence {
    database_bytes: u64,
    database_page_count: u64,
    retained_snapshots: u64,
    backup_file_count: u64,
    backup_repository_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleEvidence {
    cold_start_nanoseconds: u64,
    steady_state_nanoseconds: u64,
    restart_nanoseconds: u64,
    warm_start_nanoseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    physical_scale_execution_attempted: bool,
    distinct_authoritative_atoms: bool,
    distinct_authoritative_edges: bool,
    distinct_encrypted_blob_objects: bool,
    fuzz_executed: bool,
    soak_executed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ResultBody {
    schema_version: String,
    result: String,
    release_scale_qualified: bool,
    run_id: String,
    started_at_unix_nanos: i128,
    finished_at_unix_nanos: i128,
    platform_scope: String,
    profile_sha256: String,
    binding_sha256: String,
    source_revision: String,
    source_tree_sha256: String,
    candidate: FileBinding,
    installed_tool: FileBinding,
    targets: Counts,
    observed: Counts,
    roots: Roots,
    storage: StorageEvidence,
    lifecycle: LifecycleEvidence,
    checks: Vec<Check>,
    claims: Claims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RunResult {
    #[serde(flatten)]
    body: ResultBody,
    receipt_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug)]
struct RunInputs {
    profile_path: PathBuf,
    binding_path: PathBuf,
    workspace: PathBuf,
    output: PathBuf,
    production: bool,
}

fn now_unix_nanos() -> Result<i128> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    i128::try_from(duration.as_nanos()).map_err(|_| error(DriverErrorCode::StoreFailure))
}

fn elapsed_nanoseconds(started: Instant) -> Result<u64> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|_| error(DriverErrorCode::StoreFailure))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn multihash(bytes: &[u8]) -> String {
    format!("1220{}", sha256_hex(bytes))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| error(DriverErrorCode::PublicationFailure))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_multihash(value: &str) -> bool {
    value.strip_prefix("1220").is_some_and(valid_sha256)
}

fn valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn valid_source_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lexical_absolute(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut root = false;
    for component in path.components() {
        match component {
            Component::RootDir if !root => root = true,
            Component::Normal(_) if root => {}
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return false,
            Component::Normal(_) => return false,
        }
    }
    root
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> DirectoryIdentity {
    use std::os::unix::fs::MetadataExt as _;
    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn validate_safe_ancestors(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if !lexical_absolute(path) {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let expected_uid = rustix::process::geteuid().as_raw();
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| error(DriverErrorCode::UnsafePath))?;
        let mode = metadata.permissions().mode();
        let protected_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != expected_uid)
            || (mode & 0o022 != 0 && !protected_sticky)
        {
            return Err(error(DriverErrorCode::UnsafePath));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(path: &Path) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    validate_safe_ancestors(path)?;
    let canonical = fs::canonicalize(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if canonical != path {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    Ok(metadata_identity(&metadata))
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<File> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| error(DriverErrorCode::UnsafePath))
}

#[cfg(unix)]
fn read_stable_regular(path: &Path, maximum: u64, require_private: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if !lexical_absolute(path) {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let parent = path
        .parent()
        .ok_or_else(|| error(DriverErrorCode::UnsafePath))?;
    validate_safe_ancestors(parent)?;
    let before = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let mut file = open_nofollow(path)?;
    let opened = file
        .metadata()
        .map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    let regular = |metadata: &fs::Metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_uid
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= maximum
            && metadata.permissions().mode() & 0o022 == 0
            && (!require_private || metadata.permissions().mode() & 0o077 == 0)
    };
    if !regular(&before)
        || !regular(&opened)
        || metadata_identity(&before) != metadata_identity(&opened)
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if u64::try_from(bytes.len()).ok() != Some(opened.len()) {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let after = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let opened_after = file
        .metadata()
        .map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if !regular(&after)
        || !regular(&opened_after)
        || metadata_identity(&before) != metadata_identity(&after)
        || metadata_identity(&opened) != metadata_identity(&opened_after)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.created().ok() != after.created().ok()
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn fingerprint(path: &Path, maximum: u64) -> Result<FileBinding> {
    streaming_fingerprint(path, maximum, false, false)
}

#[cfg(unix)]
fn streaming_fingerprint(
    path: &Path,
    maximum: u64,
    require_executable: bool,
    require_macho_arm64: bool,
) -> Result<FileBinding> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if !lexical_absolute(path) {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    validate_safe_ancestors(
        path.parent()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?,
    )?;
    let canonical = fs::canonicalize(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if canonical != path {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let before = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let mut file = open_nofollow(path)?;
    let opened = file
        .metadata()
        .map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    let valid = |metadata: &fs::Metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_uid
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= maximum
            && metadata.permissions().mode() & 0o022 == 0
            && (!require_executable || metadata.permissions().mode() & 0o111 != 0)
    };
    if !valid(&before)
        || !valid(&opened)
        || metadata_identity(&before) != metadata_identity(&opened)
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut prefix = Vec::with_capacity(16);
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| error(DriverErrorCode::UnsafePath))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| error(DriverErrorCode::UnsafePath))?)
            .filter(|count| *count <= maximum)
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?;
        if prefix.len() < 16 {
            let length = (16 - prefix.len()).min(read);
            prefix.extend_from_slice(
                buffer
                    .get(..length)
                    .ok_or_else(|| error(DriverErrorCode::UnsafePath))?,
            );
        }
        hasher.update(
            buffer
                .get(..read)
                .ok_or_else(|| error(DriverErrorCode::UnsafePath))?,
        );
    }
    let after = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let opened_after = file
        .metadata()
        .map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if !valid(&after)
        || !valid(&opened_after)
        || metadata_identity(&before) != metadata_identity(&after)
        || metadata_identity(&opened) != metadata_identity(&opened_after)
        || before.len() != total
        || after.len() != total
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    if require_macho_arm64 {
        let header: [u8; 16] = prefix
            .as_slice()
            .try_into()
            .map_err(|_| error(DriverErrorCode::InvalidBinding))?;
        let magic = u32::from_le_bytes(
            header
                .get(0..4)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| error(DriverErrorCode::InvalidBinding))?,
        );
        let cpu = u32::from_le_bytes(
            header
                .get(4..8)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| error(DriverErrorCode::InvalidBinding))?,
        );
        let file_type = u32::from_le_bytes(
            header
                .get(12..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| error(DriverErrorCode::InvalidBinding))?,
        );
        if magic != 0xfeed_facf || cpu != 0x0100_000c || file_type != 2 {
            return Err(error(DriverErrorCode::InvalidBinding));
        }
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(FileBinding {
        path: path
            .to_str()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?
            .to_owned(),
        sha256: digest,
        bytes: total,
    })
}

#[cfg(unix)]
fn executable_fingerprint(path: &Path, require_macho_arm64: bool) -> Result<FileBinding> {
    streaming_fingerprint(path, MAX_BOUND_FILE_BYTES, true, require_macho_arm64)
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], code: DriverErrorCode) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| error(code))
}

struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("strict finite JSON without duplicate keys")
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(StrictJsonValue)
                    .ok_or_else(|| E::custom("non-finite number"))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::String(value)))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Null))
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictJsonValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
                    values.push(value.0);
                }
                Ok(StrictJsonValue(serde_json::Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let value = map.next_value::<StrictJsonValue>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictJsonValue(serde_json::Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn require_exact_json_keys(
    bytes: &[u8],
    expected: &[&str],
    code: DriverErrorCode,
) -> Result<serde_json::Value> {
    let value = serde_json::from_slice::<StrictJsonValue>(bytes)
        .map_err(|_| error(code))?
        .0;
    let object = value.as_object().ok_or_else(|| error(code))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(error(code));
    }
    Ok(value)
}

fn parse_checkpoint(bytes: &[u8]) -> Result<Checkpoint> {
    let mut value = require_exact_json_keys(
        bytes,
        &[
            "schema_version",
            "run_id",
            "binding_sha256",
            "profile_sha256",
            "phase",
            "revision",
            "atoms",
            "edges",
            "referenced_blob_bytes",
            "catalog_root",
            "semantic_root",
            "checkpoint_id",
        ],
        DriverErrorCode::CheckpointMismatch,
    )?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| error(DriverErrorCode::CheckpointMismatch))?;
    let checkpoint_id = object
        .remove("checkpoint_id")
        .and_then(|item| item.as_str().map(str::to_owned))
        .ok_or_else(|| error(DriverErrorCode::CheckpointMismatch))?;
    let body =
        serde_json::from_value(value).map_err(|_| error(DriverErrorCode::CheckpointMismatch))?;
    Ok(Checkpoint {
        body,
        checkpoint_id,
    })
}

fn parse_result(bytes: &[u8]) -> Result<RunResult> {
    let mut value = require_exact_json_keys(
        bytes,
        &[
            "schema_version",
            "result",
            "release_scale_qualified",
            "run_id",
            "started_at_unix_nanos",
            "finished_at_unix_nanos",
            "platform_scope",
            "profile_sha256",
            "binding_sha256",
            "source_revision",
            "source_tree_sha256",
            "candidate",
            "installed_tool",
            "targets",
            "observed",
            "roots",
            "storage",
            "lifecycle",
            "checks",
            "claims",
            "receipt_id",
        ],
        DriverErrorCode::IntegrityFailure,
    )?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| error(DriverErrorCode::IntegrityFailure))?;
    let receipt_id = object
        .remove("receipt_id")
        .and_then(|item| item.as_str().map(str::to_owned))
        .ok_or_else(|| error(DriverErrorCode::IntegrityFailure))?;
    let body =
        serde_json::from_value(value).map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
    Ok(RunResult { body, receipt_id })
}

#[cfg(unix)]
fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    require_private: bool,
    code: DriverErrorCode,
) -> Result<(T, Vec<u8>)> {
    let bytes = read_stable_regular(path, MAX_CONTROL_FILE_BYTES, require_private)?;
    Ok((parse_json(&bytes, code)?, bytes))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let directory = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| error(DriverErrorCode::PublicationFailure))?;
    directory
        .sync_all()
        .map_err(|_| error(DriverErrorCode::PublicationFailure))
}

#[cfg(unix)]
fn write_new_private(path: &Path, bytes: &[u8], mode: u16) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error(DriverErrorCode::UnsafePath))?;
    validate_private_directory(parent)?;
    if !matches!(mode, 0o400 | 0o600) || bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(error(DriverErrorCode::PublicationFailure));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_raw_mode(mode),
    )
    .map_err(|_| error(DriverErrorCode::PublicationFailure))?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| error(DriverErrorCode::PublicationFailure))?;
    sync_directory(parent)
}

#[cfg(unix)]
fn atomic_private_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error(DriverErrorCode::UnsafePath))?;
    validate_private_directory(parent)?;
    let temporary = parent.join(".cigar-local-scale-checkpoint.tmp");
    if temporary.exists() {
        let metadata = fs::symlink_metadata(&temporary)
            .map_err(|_| error(DriverErrorCode::CheckpointMismatch))?;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(error(DriverErrorCode::CheckpointMismatch));
        }
        fs::remove_file(&temporary).map_err(|_| error(DriverErrorCode::CheckpointMismatch))?;
    }
    write_new_private(&temporary, bytes, 0o600)?;
    fs::rename(&temporary, path).map_err(|_| error(DriverErrorCode::PublicationFailure))?;
    sync_directory(parent)
}

fn path_contains(parent: &Path, child: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

#[cfg(unix)]
fn available_bytes(path: &Path) -> Result<u64> {
    let statistics =
        rustix::fs::statvfs(path).map_err(|_| error(DriverErrorCode::InsufficientSpace))?;
    let block_size = if statistics.f_frsize == 0 {
        statistics.f_bsize
    } else {
        statistics.f_frsize
    };
    statistics
        .f_bavail
        .checked_mul(block_size)
        .ok_or_else(|| error(DriverErrorCode::InsufficientSpace))
}

#[cfg(unix)]
fn validate_controlled_directory(path: &Path) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    validate_safe_ancestors(path)?;
    let canonical = fs::canonicalize(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if canonical != path
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    Ok(metadata_identity(&metadata))
}

#[cfg(unix)]
fn current_tool_fingerprint() -> Result<FileBinding> {
    let executable = env::current_exe().map_err(|_| error(DriverErrorCode::InvalidBinding))?;
    let canonical =
        fs::canonicalize(executable).map_err(|_| error(DriverErrorCode::InvalidBinding))?;
    executable_fingerprint(&canonical, true)
}

fn validate_binding_shape(binding: &RunBinding) -> Result<()> {
    if binding.schema_version != BINDING_SCHEMA
        || !valid_run_id(&binding.run_id)
        || !valid_source_revision(&binding.source_revision)
        || !valid_sha256(&binding.source_tree_sha256)
        || !lexical_absolute(Path::new(&binding.repository_root))
    {
        return Err(error(DriverErrorCode::InvalidBinding));
    }
    for item in [
        &binding.candidate,
        &binding.installed_tool,
        &binding.profile,
    ] {
        if !lexical_absolute(Path::new(&item.path))
            || !valid_sha256(&item.sha256)
            || item.bytes == 0
            || item.bytes > MAX_BOUND_FILE_BYTES
        {
            return Err(error(DriverErrorCode::InvalidBinding));
        }
    }
    Ok(())
}

#[cfg(unix)]
struct BindingPreparation {
    profile_path: PathBuf,
    candidate_path: PathBuf,
    repository_root: PathBuf,
    source_revision: String,
    source_tree_sha256: String,
    run_id: String,
    output: PathBuf,
    production: bool,
}

#[cfg(unix)]
fn prepare_binding(preparation: BindingPreparation) -> Result<RunBinding> {
    if !valid_run_id(&preparation.run_id)
        || !valid_source_revision(&preparation.source_revision)
        || !valid_sha256(&preparation.source_tree_sha256)
    {
        return Err(error(DriverErrorCode::InvalidArgument));
    }
    validate_controlled_directory(&preparation.repository_root)?;
    let (profile, _bytes): (Profile, Vec<u8>) = read_json(
        &preparation.profile_path,
        false,
        DriverErrorCode::InvalidProfile,
    )?;
    profile.validate(preparation.production)?;
    let profile_binding = fingerprint(&preparation.profile_path, MAX_CONTROL_FILE_BYTES)?;
    let candidate = executable_fingerprint(&preparation.candidate_path, preparation.production)
        .map_err(|_| error(DriverErrorCode::InvalidBinding))?;
    let installed_tool =
        current_tool_fingerprint().map_err(|_| error(DriverErrorCode::InvalidBinding))?;
    if candidate.path == installed_tool.path
        || candidate.path == profile_binding.path
        || installed_tool.path == profile_binding.path
    {
        return Err(error(DriverErrorCode::InvalidBinding));
    }
    let binding = RunBinding {
        schema_version: BINDING_SCHEMA.to_owned(),
        run_id: preparation.run_id,
        repository_root: preparation
            .repository_root
            .to_str()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?
            .to_owned(),
        source_revision: preparation.source_revision,
        source_tree_sha256: preparation.source_tree_sha256,
        candidate,
        installed_tool,
        profile: profile_binding,
    };
    validate_binding_shape(&binding)?;
    let mut bytes = canonical_json(&binding)?;
    bytes.push(b'\n');
    write_new_private(&preparation.output, &bytes, 0o400)?;
    Ok(binding)
}

#[cfg(unix)]
fn load_bound_inputs(inputs: &RunInputs) -> Result<(Profile, RunBinding, String, String)> {
    let (profile, profile_bytes): (Profile, Vec<u8>) =
        read_json(&inputs.profile_path, false, DriverErrorCode::InvalidProfile)?;
    profile.validate(inputs.production)?;
    let (binding, binding_bytes): (RunBinding, Vec<u8>) =
        read_json(&inputs.binding_path, true, DriverErrorCode::InvalidBinding)?;
    validate_binding_shape(&binding)?;
    let profile_fingerprint = fingerprint(&inputs.profile_path, MAX_CONTROL_FILE_BYTES)?;
    let candidate_fingerprint =
        executable_fingerprint(Path::new(&binding.candidate.path), inputs.production)
            .map_err(|_| error(DriverErrorCode::InvalidBinding))?;
    let installed_fingerprint =
        current_tool_fingerprint().map_err(|_| error(DriverErrorCode::InvalidBinding))?;
    let repository = Path::new(&binding.repository_root);
    validate_controlled_directory(repository)?;
    if profile_fingerprint != binding.profile
        || candidate_fingerprint != binding.candidate
        || installed_fingerprint != binding.installed_tool
        || inputs.profile_path != Path::new(&binding.profile.path)
    {
        return Err(error(DriverErrorCode::InvalidBinding));
    }
    let profile_sha256 = sha256_hex(&profile_bytes);
    let binding_sha256 = sha256_hex(&binding_bytes);
    if profile_sha256 != binding.profile.sha256 {
        return Err(error(DriverErrorCode::InvalidBinding));
    }
    Ok((profile, binding, profile_sha256, binding_sha256))
}

#[cfg(unix)]
fn validate_path_separation(inputs: &RunInputs, binding: &RunBinding) -> Result<DirectoryIdentity> {
    let workspace_identity = validate_private_directory(&inputs.workspace)?;
    let output_parent = inputs
        .output
        .parent()
        .ok_or_else(|| error(DriverErrorCode::UnsafePath))?;
    let output_identity = validate_private_directory(output_parent)?;
    let repository = Path::new(&binding.repository_root);
    let repository_identity = validate_controlled_directory(repository)?;
    if workspace_identity == output_identity
        || workspace_identity == repository_identity
        || output_identity == repository_identity
        || path_contains(repository, &inputs.workspace)
        || path_contains(&inputs.workspace, repository)
        || path_contains(repository, output_parent)
        || path_contains(output_parent, repository)
        || path_contains(output_parent, &inputs.workspace)
        || path_contains(&inputs.workspace, output_parent)
        || inputs.output.exists()
        || inputs.output == inputs.binding_path
        || inputs.output == inputs.profile_path
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    Ok(workspace_identity)
}

#[cfg(unix)]
fn validate_owned_tree(path: &Path, device: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let expected_uid = rustix::process::geteuid().as_raw();
    let mut pending = vec![path.to_path_buf()];
    let mut entries = 0_u64;
    while let Some(current) = pending.pop() {
        entries = entries
            .checked_add(1)
            .filter(|count| *count <= 2_000_000)
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?;
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| error(DriverErrorCode::UnsafePath))?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.dev() != device
            || (!metadata.is_dir() && !metadata.is_file())
        {
            return Err(error(DriverErrorCode::UnsafePath));
        }
        if metadata.is_dir() {
            let iterator =
                fs::read_dir(&current).map_err(|_| error(DriverErrorCode::UnsafePath))?;
            for child in iterator {
                pending.push(
                    child
                        .map_err(|_| error(DriverErrorCode::UnsafePath))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_workspace_entries(workspace: &Path, device: u64) -> Result<()> {
    let fixed: BTreeSet<&str> = BTreeSet::from([
        "backup",
        "blobs",
        "checkpoint.json",
        "database.sqlite3",
        "database.sqlite3-shm",
        "database.sqlite3-wal",
        "database.sqlite3.cigar-revision",
        "database.sqlite3.cigar-runtime.lock",
        "keystore.cbor",
        "keys.json",
        "owner.json",
        "passphrase.bin",
        "restored",
    ]);
    for entry in fs::read_dir(workspace).map_err(|_| error(DriverErrorCode::UnsafePath))? {
        let entry = entry.map_err(|_| error(DriverErrorCode::UnsafePath))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?
            .to_owned();
        if !fixed.contains(name.as_str())
            && !name.starts_with(".cigar-backup-")
            && !name.starts_with(".cigar-restore-")
            && name != ".cigar-local-scale-checkpoint.tmp"
        {
            return Err(error(DriverErrorCode::UnsafePath));
        }
        validate_owned_tree(&entry.path(), device)?;
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_owned_temporaries(workspace: &Path, device: u64) -> Result<()> {
    for entry in fs::read_dir(workspace).map_err(|_| error(DriverErrorCode::UnsafePath))? {
        let entry = entry.map_err(|_| error(DriverErrorCode::UnsafePath))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?
            .to_owned();
        if name.starts_with(".cigar-backup-") || name.starts_with(".cigar-restore-") {
            validate_owned_tree(&entry.path(), device)?;
            fs::remove_dir_all(entry.path()).map_err(|_| error(DriverErrorCode::UnsafePath))?;
        }
    }
    sync_directory(workspace)
}

fn owner_path(workspace: &Path) -> PathBuf {
    workspace.join("owner.json")
}

#[cfg(unix)]
fn open_or_create_owner(
    workspace: &Path,
    identity: DirectoryIdentity,
    profile: &Profile,
    binding: &RunBinding,
    binding_sha256: &str,
    profile_sha256: &str,
) -> Result<(OwnerMarker, bool)> {
    let path = owner_path(workspace);
    if path.exists() {
        let (owner, _): (OwnerMarker, Vec<u8>) =
            read_json(&path, true, DriverErrorCode::CheckpointMismatch)?;
        if owner.schema_version != OWNER_SCHEMA
            || owner.run_id != binding.run_id
            || owner.binding_sha256 != binding_sha256
            || owner.profile_sha256 != profile_sha256
            || owner.workspace_device != identity.device
            || owner.workspace_inode != identity.inode
            || owner.initial_available_bytes < profile.minimum_initial_available_bytes
            || owner.semantic_time_unix_nanos < 0
        {
            return Err(error(DriverErrorCode::CheckpointMismatch));
        }
        return Ok((owner, false));
    }
    if fs::read_dir(workspace)
        .map_err(|_| error(DriverErrorCode::UnsafePath))?
        .next()
        .is_some()
    {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    let initial_available_bytes = available_bytes(workspace)?;
    if initial_available_bytes < profile.minimum_initial_available_bytes {
        return Err(error(DriverErrorCode::InsufficientSpace));
    }
    let owner = OwnerMarker {
        schema_version: OWNER_SCHEMA.to_owned(),
        run_id: binding.run_id.clone(),
        binding_sha256: binding_sha256.to_owned(),
        profile_sha256: profile_sha256.to_owned(),
        workspace_device: identity.device,
        workspace_inode: identity.inode,
        initial_available_bytes,
        semantic_time_unix_nanos: now_unix_nanos()?,
    };
    let mut bytes = canonical_json(&owner)?;
    bytes.push(b'\n');
    write_new_private(&path, &bytes, 0o400)?;
    Ok((owner, true))
}

fn checkpoint_path(workspace: &Path) -> PathBuf {
    workspace.join("checkpoint.json")
}

fn phase_for_statistics(statistics: &SqliteCatalogStatistics, profile: &Profile) -> Result<String> {
    if statistics.atom_count < profile.atoms && statistics.edge_count == 0 {
        Ok("atoms".to_owned())
    } else if statistics.atom_count == profile.atoms && statistics.edge_count < profile.edges {
        Ok("edges".to_owned())
    } else if statistics.atom_count == profile.atoms && statistics.edge_count == profile.edges {
        Ok("validation".to_owned())
    } else {
        Err(error(DriverErrorCode::CheckpointMismatch))
    }
}

fn validate_catalog_shape(statistics: &SqliteCatalogStatistics, profile: &Profile) -> Result<()> {
    let expected_referenced = statistics
        .atom_count
        .min(profile.blob_objects)
        .checked_mul(profile.blob_bytes_each)
        .ok_or_else(|| error(DriverErrorCode::CheckpointMismatch))?;
    if statistics.atom_count > profile.atoms
        || statistics.edge_count > profile.edges
        || statistics.referenced_blob_bytes != expected_referenced
        || (statistics.edge_count > 0 && statistics.atom_count != profile.atoms)
        || !valid_multihash(statistics.catalog_root.as_str())
        || !valid_multihash(statistics.semantic_root.as_str())
    {
        return Err(error(DriverErrorCode::CheckpointMismatch));
    }
    Ok(())
}

fn checkpoint_for(
    statistics: &SqliteCatalogStatistics,
    profile: &Profile,
    binding: &RunBinding,
    binding_sha256: &str,
    profile_sha256: &str,
) -> Result<Checkpoint> {
    validate_catalog_shape(statistics, profile)?;
    let body = CheckpointBody {
        schema_version: CHECKPOINT_SCHEMA.to_owned(),
        run_id: binding.run_id.clone(),
        binding_sha256: binding_sha256.to_owned(),
        profile_sha256: profile_sha256.to_owned(),
        phase: phase_for_statistics(statistics, profile)?,
        revision: statistics.revision.0,
        atoms: statistics.atom_count,
        edges: statistics.edge_count,
        referenced_blob_bytes: statistics.referenced_blob_bytes,
        catalog_root: statistics.catalog_root.as_str().to_owned(),
        semantic_root: statistics.semantic_root.as_str().to_owned(),
    };
    let checkpoint_id = multihash(&canonical_json(&body)?);
    Ok(Checkpoint {
        body,
        checkpoint_id,
    })
}

fn validate_checkpoint(checkpoint: &Checkpoint) -> Result<()> {
    if checkpoint.body.schema_version != CHECKPOINT_SCHEMA
        || !valid_run_id(&checkpoint.body.run_id)
        || !valid_sha256(&checkpoint.body.binding_sha256)
        || !valid_sha256(&checkpoint.body.profile_sha256)
        || !matches!(
            checkpoint.body.phase.as_str(),
            "atoms" | "edges" | "validation"
        )
        || !valid_multihash(&checkpoint.body.catalog_root)
        || !valid_multihash(&checkpoint.body.semantic_root)
        || checkpoint.checkpoint_id != multihash(&canonical_json(&checkpoint.body)?)
    {
        return Err(error(DriverErrorCode::CheckpointMismatch));
    }
    Ok(())
}

#[cfg(unix)]
fn persist_checkpoint(
    workspace: &Path,
    statistics: &SqliteCatalogStatistics,
    profile: &Profile,
    binding: &RunBinding,
    binding_sha256: &str,
    profile_sha256: &str,
) -> Result<Checkpoint> {
    let checkpoint = checkpoint_for(statistics, profile, binding, binding_sha256, profile_sha256)?;
    let mut bytes = canonical_json(&checkpoint)?;
    bytes.push(b'\n');
    atomic_private_replace(&checkpoint_path(workspace), &bytes)?;
    let observed_bytes =
        read_stable_regular(&checkpoint_path(workspace), MAX_CONTROL_FILE_BYTES, true)?;
    let observed = parse_checkpoint(&observed_bytes)?;
    validate_checkpoint(&observed)?;
    if observed != checkpoint {
        return Err(error(DriverErrorCode::CheckpointMismatch));
    }
    Ok(checkpoint)
}

#[cfg(unix)]
fn recover_checkpoint(
    workspace: &Path,
    statistics: &SqliteCatalogStatistics,
    profile: &Profile,
    binding: &RunBinding,
    binding_sha256: &str,
    profile_sha256: &str,
    is_new: bool,
) -> Result<()> {
    validate_catalog_shape(statistics, profile)?;
    let path = checkpoint_path(workspace);
    if is_new {
        if statistics.revision != StoreRevision(0) || path.exists() {
            return Err(error(DriverErrorCode::CheckpointMismatch));
        }
        persist_checkpoint(
            workspace,
            statistics,
            profile,
            binding,
            binding_sha256,
            profile_sha256,
        )?;
        return Ok(());
    }
    let checkpoint_bytes = read_stable_regular(&path, MAX_CONTROL_FILE_BYTES, true)?;
    let checkpoint = parse_checkpoint(&checkpoint_bytes)?;
    validate_checkpoint(&checkpoint)?;
    if checkpoint.body.run_id != binding.run_id
        || checkpoint.body.binding_sha256 != binding_sha256
        || checkpoint.body.profile_sha256 != profile_sha256
        || checkpoint.body.revision > statistics.revision.0
        || checkpoint.body.atoms > statistics.atom_count
        || checkpoint.body.edges > statistics.edge_count
        || checkpoint.body.referenced_blob_bytes > statistics.referenced_blob_bytes
        || statistics
            .revision
            .0
            .saturating_sub(checkpoint.body.revision)
            > 1
        || statistics.atom_count.saturating_sub(checkpoint.body.atoms)
            > profile.atom_batch_size.max(1)
        || statistics.edge_count.saturating_sub(checkpoint.body.edges) > profile.edge_batch_size
    {
        return Err(error(DriverErrorCode::CheckpointMismatch));
    }
    persist_checkpoint(
        workspace,
        statistics,
        profile,
        binding,
        binding_sha256,
        profile_sha256,
    )?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationKeys {
    signing: KeyRef,
    wrapping: KeyRef,
}

type QualificationKeystore = EncryptedDevelopmentKeystore;
type QualificationBlobRepository = LocalRepositoryBlobStore<QualificationKeystore>;

#[cfg(unix)]
fn create_private_directory(path: &Path, device: u64) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if path.exists() {
        let identity = validate_private_directory(path)?;
        if identity.device != device {
            return Err(error(DriverErrorCode::UnsafePath));
        }
        return Ok(());
    }
    fs::create_dir(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| error(DriverErrorCode::UnsafePath))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    if metadata.dev() != device {
        return Err(error(DriverErrorCode::UnsafePath));
    }
    validate_private_directory(path)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?,
    )
}

#[cfg(unix)]
fn open_qualification_crypto(
    workspace: &Path,
    owner: &OwnerMarker,
    is_new: bool,
) -> Result<(
    Arc<QualificationKeystore>,
    QualificationKeys,
    Arc<QualificationBlobRepository>,
)> {
    let passphrase_path = workspace.join("passphrase.bin");
    let passphrase = if is_new {
        let mut bytes = vec![0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| error(DriverErrorCode::StoreFailure))?;
        write_new_private(&passphrase_path, &bytes, 0o600)?;
        bytes
    } else {
        read_stable_regular(&passphrase_path, 64, true)?
    };
    if passphrase.len() != 32 {
        return Err(error(DriverErrorCode::StoreFailure));
    }
    let provider = Arc::new(
        EncryptedDevelopmentKeystore::open(
            workspace.join("keystore.cbor"),
            SecretBytes::new(passphrase),
        )
        .map_err(|_| error(DriverErrorCode::StoreFailure))?,
    );
    let keys_path = workspace.join("keys.json");
    let keys = if is_new {
        let signing = provider
            .create(CreateKeyRequest {
                tenant: TENANT_ID.to_owned(),
                purpose: KeyPurpose::Signing,
                algorithm: KeyAlgorithm::Ed25519,
                created_at: owner.semantic_time_unix_nanos,
                activated_at: owner.semantic_time_unix_nanos,
            })
            .map_err(|_| error(DriverErrorCode::StoreFailure))?
            .key_ref;
        let wrapping = provider
            .create(CreateKeyRequest {
                tenant: TENANT_ID.to_owned(),
                purpose: KeyPurpose::BlobEncryption,
                algorithm: KeyAlgorithm::XChaCha20Poly1305,
                created_at: owner.semantic_time_unix_nanos,
                activated_at: owner.semantic_time_unix_nanos,
            })
            .map_err(|_| error(DriverErrorCode::StoreFailure))?
            .key_ref;
        let keys = QualificationKeys { signing, wrapping };
        let mut bytes = canonical_json(&keys)?;
        bytes.push(b'\n');
        write_new_private(&keys_path, &bytes, 0o600)?;
        keys
    } else {
        let (keys, _): (QualificationKeys, Vec<u8>) =
            read_json(&keys_path, true, DriverErrorCode::StoreFailure)?;
        keys
    };
    for (key, purpose) in [
        (&keys.signing, KeyPurpose::Signing),
        (&keys.wrapping, KeyPurpose::BlobEncryption),
    ] {
        provider
            .resolve(key, TENANT_ID, purpose, owner.semantic_time_unix_nanos)
            .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    }
    let blobs_path = workspace.join("blobs");
    create_private_directory(&blobs_path, owner.workspace_device)?;
    let local = LocalBlobStore::open(&blobs_path, Arc::clone(&provider))
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    let repository = Arc::new(LocalRepositoryBlobStore::new(
        local,
        keys.wrapping.clone(),
        owner.semantic_time_unix_nanos,
    ));
    Ok((provider, keys, repository))
}

fn capacity_profile(profile: &Profile) -> Result<SqliteCapacityProfile> {
    match profile.capacity_profile.as_str() {
        "standard" => Ok(SqliteCapacityProfile::Standard),
        "large_local" => Ok(SqliteCapacityProfile::LargeLocal),
        _ => Err(error(DriverErrorCode::InvalidProfile)),
    }
}

fn open_store(
    workspace: &Path,
    repository: Arc<QualificationBlobRepository>,
    profile: &Profile,
) -> Result<SqliteStore> {
    let erased: Arc<dyn RepositoryBlobStore> = repository;
    SqliteStore::open_with_blob_repository_and_capacity_profile(
        workspace.join("database.sqlite3"),
        erased,
        capacity_profile(profile)?,
    )
    .map_err(|store_error| {
        if store_error.code() == StoreErrorCode::LimitExceeded {
            error(DriverErrorCode::InsufficientSpace)
        } else {
            error(DriverErrorCode::StoreFailure)
        }
    })
}

fn validate_store_profile(store: &SqliteStore, profile: &Profile) -> Result<()> {
    let configuration = store
        .configuration()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    if store.capacity_profile() != capacity_profile(profile)?
        || configuration.max_database_bytes != profile.maximum_database_bytes
        || !configuration.journal_mode.eq_ignore_ascii_case("wal")
        || configuration.synchronous != 2
        || !configuration.foreign_keys
        || !configuration.full_text_search
        || !configuration.defensive
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn digest_from_hasher(hasher: Sha256) -> Result<ContentDigest> {
    let encoded: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ContentDigest::new(format!("1220{encoded}")).map_err(|_| error(DriverErrorCode::StoreFailure))
}

fn indexed_content_digest(domain: &[u8], index: u64) -> Result<ContentDigest> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(index.to_be_bytes());
    digest_from_hasher(hasher)
}

fn indexed_version(domain: &[u8], index: u64) -> Result<VersionId> {
    VersionId::new(indexed_content_digest(domain, index)?.as_str().to_owned())
        .map_err(|_| error(DriverErrorCode::StoreFailure))
}

fn indexed_uuid(namespace: u16, index: u64) -> Result<String> {
    if namespace > 0x0fff || index > 0x0000_ffff_ffff_ffff {
        return Err(error(DriverErrorCode::InvalidProfile));
    }
    Ok(format!("01890f47-8e7d-7{namespace:03x}-a000-{index:012x}"))
}

fn blob_marker(index: u64) -> u8 {
    u8::try_from(index % 251).unwrap_or(0).saturating_add(1)
}

fn blob_content_digest(index: u64, size: u64) -> Result<ContentDigest> {
    if !(8..=67_108_864).contains(&size) {
        return Err(error(DriverErrorCode::InvalidProfile));
    }
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    let marker = [blob_marker(index); 64 * 1024];
    let mut remaining = size - 8;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(marker.len() as u64))
            .map_err(|_| error(DriverErrorCode::InvalidProfile))?;
        hasher.update(
            marker
                .get(..length)
                .ok_or_else(|| error(DriverErrorCode::InvalidProfile))?,
        );
        remaining -= u64::try_from(length).map_err(|_| error(DriverErrorCode::InvalidProfile))?;
    }
    digest_from_hasher(hasher)
}

fn blob_bytes(index: u64, size: u64) -> Result<Vec<u8>> {
    let length = usize::try_from(size).map_err(|_| error(DriverErrorCode::InvalidProfile))?;
    if !(8..=67_108_864).contains(&length) {
        return Err(error(DriverErrorCode::InvalidProfile));
    }
    let mut bytes = vec![blob_marker(index); length];
    bytes
        .get_mut(..8)
        .ok_or_else(|| error(DriverErrorCode::InvalidProfile))?
        .copy_from_slice(&index.to_be_bytes());
    Ok(bytes)
}

fn atom_template() -> Result<ContextAtomV1> {
    let value = json!({
        "schema_version":"cigar.atom.v1",
        "atom_id":"01890f47-8e7d-7b42-a1d2-3c4d5e6f7812",
        "lineage_id":"01890f47-8e7d-7b42-a1d2-3c4d5e6f7813",
        "version_id":format!("1220{}", "4".repeat(64)),
        "content_digest":format!("1220{}", "5".repeat(64)),
        "kind":"documentation",
        "payload":{"type":"inline_text", "value":"safe fixture"},
        "source":{
            "uri":"file:///cigar-local-scale/generated",
            "revision":"local-scale-v1",
            "snapshot_digest":format!("1220{}", "6".repeat(64))
        },
        "scope":{
            "tenant_id":TENANT_ID,
            "project_ids":["01890f47-8e7d-7b42-a1d2-3c4d5e6f7815"]
        },
        "temporal":{
            "valid_from":"2026-07-10T00:00:00Z",
            "observed_at":"2026-07-10T00:00:00.000000001Z"
        },
        "governance":{
            "classification":"internal",
            "allowed_purposes":["qualification"],
            "processor_constraints":[],
            "instruction_authority":"data"
        },
        "quality":{"confidence":900000, "coverage":800000, "authority":1},
        "retrieval":{
            "exact_terms":[],
            "lexical_enabled":false,
            "embedding_eligible":false
        },
        "lifecycle":"active",
        "extensions":{}
    });
    let atom: ContextAtomV1 =
        serde_json::from_value(value).map_err(|_| error(DriverErrorCode::StoreFailure))?;
    atom.validate()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    Ok(atom)
}

fn make_atom(template: &ContextAtomV1, index: u64, profile: &Profile) -> Result<ContextAtomV1> {
    let mut atom = template.clone();
    atom.atom_id =
        RecordId::new(indexed_uuid(1, index)?).map_err(|_| error(DriverErrorCode::StoreFailure))?;
    atom.lineage_id = LineageId::new(indexed_uuid(2, index)?)
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    atom.version_id = indexed_version(b"CIGAR-LOCAL-SCALE-VERSION-v1\0", index)?;
    if index < profile.blob_objects {
        let digest = blob_content_digest(index, profile.blob_bytes_each)?;
        atom.content_digest = digest.clone();
        atom.payload = AtomPayload::Blob(BlobRef {
            digest,
            size_bytes: profile.blob_bytes_each,
            media_type: MediaType::new("application/octet-stream")
                .map_err(|_| error(DriverErrorCode::StoreFailure))?,
        });
    } else {
        let text = format!("cigar-local-scale-atom-{index:012x}");
        atom.content_digest = ContentDigest::new(multihash(text.as_bytes()))
            .map_err(|_| error(DriverErrorCode::StoreFailure))?;
        atom.payload = AtomPayload::InlineText(text);
    }
    atom.validate()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    Ok(atom)
}

fn edge_template() -> Result<ContextEdge> {
    let value = json!({
        "schema_version":"cigar.edge.v1",
        "edge_id":"01890f47-8e7d-7b42-a1d2-3c4d5e6f7811",
        "from_version":format!("1220{}", "1".repeat(64)),
        "to_version":format!("1220{}", "2".repeat(64)),
        "kind":"references",
        "provenance_digest":format!("1220{}", "3".repeat(64)),
        "lifecycle":"active",
        "extensions":{}
    });
    let edge: ContextEdge =
        serde_json::from_value(value).map_err(|_| error(DriverErrorCode::StoreFailure))?;
    edge.validate()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    Ok(edge)
}

fn make_edge(template: &ContextEdge, index: u64, profile: &Profile) -> Result<ContextEdge> {
    let mut edge = template.clone();
    let from_index = index % profile.atoms;
    let offset = (index / profile.atoms) % (profile.atoms - 1) + 1;
    let to_index = (from_index + offset) % profile.atoms;
    edge.edge_id =
        RecordId::new(indexed_uuid(3, index)?).map_err(|_| error(DriverErrorCode::StoreFailure))?;
    edge.from_version = indexed_version(b"CIGAR-LOCAL-SCALE-VERSION-v1\0", from_index)?;
    edge.to_version = indexed_version(b"CIGAR-LOCAL-SCALE-VERSION-v1\0", to_index)?;
    edge.kind = EdgeKind::References;
    edge.provenance_digest =
        indexed_content_digest(b"CIGAR-LOCAL-SCALE-EDGE-PROVENANCE-v1\0", index)?;
    edge.validate()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    Ok(edge)
}

#[derive(Clone, Copy, Debug, Default)]
struct RunControl {
    stop_after_commits: Option<u64>,
    commits: u64,
}

impl RunControl {
    fn committed(&mut self) -> Result<()> {
        self.commits = self
            .commits
            .checked_add(1)
            .ok_or_else(|| error(DriverErrorCode::StoreFailure))?;
        if self.stop_after_commits == Some(self.commits) {
            Err(error(DriverErrorCode::InjectedStop))
        } else {
            Ok(())
        }
    }
}

fn transaction_context() -> Result<AccessContext> {
    AccessContext::new(
        RecordId::new(TENANT_ID.to_owned()).map_err(|_| error(DriverErrorCode::StoreFailure))?,
        "local-scale-qualification",
    )
    .map_err(|_| error(DriverErrorCode::StoreFailure))
}

fn commit_blob_atom(
    store: &SqliteStore,
    template: &ContextAtomV1,
    index: u64,
    profile: &Profile,
) -> Result<()> {
    let atom = make_atom(template, index, profile)?;
    let reference = match &atom.payload {
        AtomPayload::Blob(reference) => reference.clone(),
        AtomPayload::InlineText(_) | AtomPayload::Structured(_) => {
            return Err(error(DriverErrorCode::StoreFailure));
        }
    };
    let bytes = blob_bytes(index, profile.blob_bytes_each)?;
    if reference.digest
        != ContentDigest::new(multihash(&bytes))
            .map_err(|_| error(DriverErrorCode::StoreFailure))?
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    let record =
        BlobRecord::new(reference, bytes).map_err(|_| error(DriverErrorCode::StoreFailure))?;
    let expected = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?
        .revision;
    let mut write = store
        .begin_write(
            transaction_context()?,
            expected,
            CancellationToken::default(),
        )
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    write
        .put_blob(record)
        .and_then(|()| write.publish_atoms(vec![atom], Vec::new()))
        .and_then(|()| write.commit(None).map(|_| ()))
        .map_err(map_store_failure)
}

fn commit_inline_atoms(
    store: &SqliteStore,
    template: &ContextAtomV1,
    first: u64,
    count: u64,
    profile: &Profile,
) -> Result<()> {
    let mut atoms = Vec::with_capacity(
        usize::try_from(count).map_err(|_| error(DriverErrorCode::InvalidProfile))?,
    );
    for index in first..first.saturating_add(count) {
        atoms.push(make_atom(template, index, profile)?);
    }
    let expected = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?
        .revision;
    let mut write = store
        .begin_write(
            transaction_context()?,
            expected,
            CancellationToken::default(),
        )
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    write
        .publish_atoms(atoms, Vec::new())
        .and_then(|()| write.commit(None).map(|_| ()))
        .map_err(map_store_failure)
}

fn commit_edges(
    store: &SqliteStore,
    atom_template: &ContextAtomV1,
    edge_template: &ContextEdge,
    first: u64,
    count: u64,
    profile: &Profile,
) -> Result<()> {
    let mut edges = Vec::with_capacity(
        usize::try_from(count).map_err(|_| error(DriverErrorCode::InvalidProfile))?,
    );
    for index in first..first.saturating_add(count) {
        edges.push(make_edge(edge_template, index, profile)?);
    }
    let placeholder = make_atom(atom_template, 0, profile)?;
    let expected = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?
        .revision;
    let mut write = store
        .begin_write(
            transaction_context()?,
            expected,
            CancellationToken::default(),
        )
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    write
        .publish_atoms(vec![placeholder], edges)
        .and_then(|()| write.commit(None).map(|_| ()))
        .map_err(map_store_failure)
}

#[cfg(unix)]
fn load_catalog(
    store: &SqliteStore,
    workspace: &Path,
    profile: &Profile,
    binding: &RunBinding,
    binding_sha256: &str,
    profile_sha256: &str,
    control: &mut RunControl,
) -> Result<SqliteCatalogStatistics> {
    let atom_template = atom_template()?;
    let edge_template = edge_template()?;
    let mut statistics = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    validate_catalog_shape(&statistics, profile)?;
    while statistics.atom_count < profile.blob_objects {
        commit_blob_atom(store, &atom_template, statistics.atom_count, profile)?;
        statistics = store
            .catalog_statistics()
            .map_err(|_| error(DriverErrorCode::StoreFailure))?;
        control.committed()?;
        persist_checkpoint(
            workspace,
            &statistics,
            profile,
            binding,
            binding_sha256,
            profile_sha256,
        )?;
    }
    while statistics.atom_count < profile.atoms {
        let count = profile
            .atom_batch_size
            .min(profile.atoms - statistics.atom_count);
        commit_inline_atoms(store, &atom_template, statistics.atom_count, count, profile)?;
        statistics = store
            .catalog_statistics()
            .map_err(|_| error(DriverErrorCode::StoreFailure))?;
        control.committed()?;
        persist_checkpoint(
            workspace,
            &statistics,
            profile,
            binding,
            binding_sha256,
            profile_sha256,
        )?;
    }
    while statistics.edge_count < profile.edges {
        let count = profile
            .edge_batch_size
            .min(profile.edges - statistics.edge_count);
        commit_edges(
            store,
            &atom_template,
            &edge_template,
            statistics.edge_count,
            count,
            profile,
        )?;
        statistics = store
            .catalog_statistics()
            .map_err(|_| error(DriverErrorCode::StoreFailure))?;
        control.committed()?;
        persist_checkpoint(
            workspace,
            &statistics,
            profile,
            binding,
            binding_sha256,
            profile_sha256,
        )?;
    }
    Ok(statistics)
}

fn verify_quota_rejection(
    store: &SqliteStore,
    profile: &Profile,
    before: &SqliteCatalogStatistics,
) -> Result<()> {
    if before.atom_count != profile.atoms
        || before.edge_count != profile.edges
        || before.referenced_blob_bytes != profile.referenced_blob_bytes
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    let overflow_size = profile
        .maximum_referenced_blob_bytes
        .checked_sub(before.referenced_blob_bytes)
        .and_then(|remaining| remaining.checked_add(1))
        .ok_or_else(|| error(DriverErrorCode::InvalidProfile))?;
    let mut atom = make_atom(&atom_template()?, profile.atoms, profile)?;
    let digest = indexed_content_digest(b"CIGAR-LOCAL-SCALE-QUOTA-REJECTION-v1\0", profile.atoms)?;
    atom.content_digest = digest.clone();
    atom.payload = AtomPayload::Blob(BlobRef {
        digest,
        size_bytes: overflow_size,
        media_type: MediaType::new("application/octet-stream")
            .map_err(|_| error(DriverErrorCode::StoreFailure))?,
    });
    atom.validate()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    let mut write = store
        .begin_write(
            transaction_context()?,
            before.revision,
            CancellationToken::default(),
        )
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    write
        .publish_atoms(vec![atom], Vec::new())
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    let failure = write
        .commit(None)
        .err()
        .ok_or_else(|| error(DriverErrorCode::IntegrityFailure))?;
    if failure.code() != StoreErrorCode::LimitExceeded {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    let after = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    if &after != before {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    Ok(())
}

#[cfg(unix)]
fn physical_blob_count(workspace: &Path, device: u64) -> Result<u64> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let directory = workspace.join("blobs").join(TENANT_ID).join("blobs");
    let metadata =
        fs::symlink_metadata(&directory).map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.dev() != device
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    let mut count = 0_u64;
    for entry in fs::read_dir(directory).map_err(|_| error(DriverErrorCode::IntegrityFailure))? {
        let entry = entry.map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
        let item = entry
            .file_name()
            .to_str()
            .ok_or_else(|| error(DriverErrorCode::IntegrityFailure))?
            .to_owned();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
        if !valid_multihash(&item)
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.dev() != device
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(error(DriverErrorCode::IntegrityFailure));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| error(DriverErrorCode::IntegrityFailure))?;
    }
    Ok(count)
}

#[cfg(unix)]
fn cleanup_owned_blob_quarantine(workspace: &Path, device: u64) -> Result<()> {
    let quarantine = workspace.join("blobs").join(TENANT_ID).join("quarantine");
    if !quarantine.exists() {
        return Ok(());
    }
    validate_owned_tree(&quarantine, device)?;
    fs::remove_dir_all(&quarantine).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    sync_directory(
        quarantine
            .parent()
            .ok_or_else(|| error(DriverErrorCode::UnsafePath))?,
    )
}

fn verify_deep_integrity(
    store: &SqliteStore,
    repository: &QualificationBlobRepository,
    profile: &Profile,
) -> Result<()> {
    let report = store
        .deep_integrity_check_with_blobs(repository)
        .map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
    if report.atom_count != profile.atoms
        || report.projection_atom_count != profile.atoms
        || report.blob_reference_count != profile.blob_objects
        || report.verified_blob_count != profile.blob_objects
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    Ok(())
}

fn reopen_blob_repository(
    blob_root: &Path,
    provider: Arc<QualificationKeystore>,
    keys: &QualificationKeys,
    semantic_time: i128,
) -> Result<Arc<QualificationBlobRepository>> {
    let local = LocalBlobStore::open(blob_root, provider)
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    Ok(Arc::new(LocalRepositoryBlobStore::new(
        local,
        keys.wrapping.clone(),
        semantic_time,
    )))
}

fn open_store_at(
    database: &Path,
    repository: Arc<QualificationBlobRepository>,
    profile: &Profile,
) -> Result<SqliteStore> {
    let erased: Arc<dyn RepositoryBlobStore> = repository;
    SqliteStore::open_with_blob_repository_and_capacity_profile(
        database,
        erased,
        capacity_profile(profile)?,
    )
    .map_err(|_| error(DriverErrorCode::StoreFailure))
}

fn validate_result(result: &RunResult, profile: &Profile, production: bool) -> Result<()> {
    let expected_checks = [
        "catalog-counts-and-roots",
        "encrypted-blob-reference-integrity",
        "one-over-quota-rejected",
        "checkpoint-recovery",
        "restart-and-reopen",
        "signed-backup-verification",
        "restore-semantic-root-equality",
        "input-bindings-stable",
    ];
    let body = &result.body;
    if body.schema_version != RESULT_SCHEMA
        || body.platform_scope != PLATFORM
        || body.started_at_unix_nanos < 0
        || body.finished_at_unix_nanos < body.started_at_unix_nanos
        || body.targets != profile.counts()
        || body.observed != body.targets
        || body.roots.semantic_before_reopen != body.roots.semantic_after_reopen
        || body.roots.semantic_before_reopen != body.roots.semantic_after_restore
        || !valid_multihash(&body.roots.catalog)
        || !valid_multihash(&body.roots.semantic_before_reopen)
        || !valid_multihash(&body.roots.backup_canonical)
        || body.storage.database_bytes == 0
        || body.storage.database_page_count == 0
        || body.storage.retained_snapshots == 0
        || body.storage.backup_file_count == 0
        || body.storage.backup_repository_revision == 0
        || body.lifecycle.cold_start_nanoseconds == 0
        || body.lifecycle.steady_state_nanoseconds == 0
        || body.lifecycle.restart_nanoseconds == 0
        || body.lifecycle.warm_start_nanoseconds == 0
        || body.checks.len() != expected_checks.len()
        || body
            .checks
            .iter()
            .zip(expected_checks)
            .any(|(check, expected)| check.id != expected || check.status != "passed")
        || !body.claims.physical_scale_execution_attempted
        || !body.claims.distinct_authoritative_atoms
        || !body.claims.distinct_authoritative_edges
        || !body.claims.distinct_encrypted_blob_objects
        || body.claims.fuzz_executed
        || body.claims.soak_executed
        || result.receipt_id != multihash(&canonical_json(body)?)
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    if production {
        if body.result != "qualification-passed" || !body.release_scale_qualified {
            return Err(error(DriverErrorCode::IntegrityFailure));
        }
    } else if body.result != "fixture-passed" || body.release_scale_qualified {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    Ok(())
}

#[cfg(unix)]
fn inputs_still_match(
    inputs: &RunInputs,
    binding: &RunBinding,
    profile_sha256: &str,
    binding_sha256: &str,
) -> Result<()> {
    let (_, profile_bytes): (Profile, Vec<u8>) =
        read_json(&inputs.profile_path, false, DriverErrorCode::InvalidProfile)?;
    let (_, binding_bytes): (RunBinding, Vec<u8>) =
        read_json(&inputs.binding_path, true, DriverErrorCode::InvalidBinding)?;
    if sha256_hex(&profile_bytes) != profile_sha256
        || sha256_hex(&binding_bytes) != binding_sha256
        || executable_fingerprint(Path::new(&binding.candidate.path), inputs.production)
            .map_err(|_| error(DriverErrorCode::InvalidBinding))?
            != binding.candidate
        || current_tool_fingerprint().map_err(|_| error(DriverErrorCode::InvalidBinding))?
            != binding.installed_tool
        || fingerprint(&inputs.profile_path, MAX_CONTROL_FILE_BYTES)? != binding.profile
    {
        return Err(error(DriverErrorCode::InvalidBinding));
    }
    Ok(())
}

#[cfg(unix)]
fn execute_run(inputs: &RunInputs, control: &mut RunControl) -> Result<RunResult> {
    if inputs.production && !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(error(DriverErrorCode::UnsupportedHost));
    }
    let (profile, binding, profile_sha256, binding_sha256) = load_bound_inputs(inputs)?;
    let workspace_identity = validate_path_separation(inputs, &binding)?;
    let (owner, is_new) = open_or_create_owner(
        &inputs.workspace,
        workspace_identity,
        &profile,
        &binding,
        &binding_sha256,
        &profile_sha256,
    )?;
    validate_workspace_entries(&inputs.workspace, workspace_identity.device)?;
    cleanup_owned_temporaries(&inputs.workspace, workspace_identity.device)?;
    let required = if is_new || !inputs.workspace.join("database.sqlite3").exists() {
        profile.minimum_initial_available_bytes
    } else {
        profile.minimum_runtime_reserve_bytes
    };
    if available_bytes(&inputs.workspace)? < required {
        return Err(error(DriverErrorCode::InsufficientSpace));
    }
    let (provider, keys, repository) =
        open_qualification_crypto(&inputs.workspace, &owner, is_new)?;
    let cold_start_started = Instant::now();
    let store = open_store(
        &inputs.workspace,
        Arc::clone(&repository),
        &profile,
    )?;
    validate_store_profile(&store, &profile)?;
    store
        .integrity_check()
        .map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
    let initial = store.catalog_statistics().map_err(map_store_failure)?;
    recover_checkpoint(
        &inputs.workspace,
        &initial,
        &profile,
        &binding,
        &binding_sha256,
        &profile_sha256,
        is_new,
    )?;
    let cold_start_nanoseconds = elapsed_nanoseconds(cold_start_started)?;
    let steady_state_started = Instant::now();
    let loaded = load_catalog(
        &store,
        &inputs.workspace,
        &profile,
        &binding,
        &binding_sha256,
        &profile_sha256,
        control,
    )?;
    if loaded.atom_count != profile.atoms
        || loaded.edge_count != profile.edges
        || loaded.referenced_blob_bytes != profile.referenced_blob_bytes
        || physical_blob_count(&inputs.workspace, workspace_identity.device)?
            != profile.blob_objects
    {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    verify_quota_rejection(&store, &profile, &loaded)?;
    store
        .rebuild_atom_projection_generation(&CancellationToken::default())
        .map_err(|_| error(DriverErrorCode::IntegrityFailure))?;
    verify_deep_integrity(&store, repository.as_ref(), &profile)?;
    cleanup_owned_blob_quarantine(&inputs.workspace, workspace_identity.device)?;
    let before_reopen = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    let storage = store
        .storage_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    let steady_state_nanoseconds = elapsed_nanoseconds(steady_state_started)?;
    drop(store);
    drop(repository);
    drop(provider);

    let restart_started = Instant::now();
    let (provider, reopened_keys, repository) =
        open_qualification_crypto(&inputs.workspace, &owner, false)?;
    if reopened_keys != keys {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    let store = open_store(
        &inputs.workspace,
        Arc::clone(&repository),
        &profile,
    )?;
    validate_store_profile(&store, &profile)?;
    let after_reopen = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    if after_reopen != before_reopen {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    verify_deep_integrity(&store, repository.as_ref(), &profile)?;
    let restart_nanoseconds = elapsed_nanoseconds(restart_started)?;

    drop(store);
    drop(repository);
    drop(provider);
    let warm_start_started = Instant::now();
    let (provider, warm_keys, repository) =
        open_qualification_crypto(&inputs.workspace, &owner, false)?;
    if warm_keys != keys {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    let store = open_store(
        &inputs.workspace,
        Arc::clone(&repository),
        &profile,
    )?;
    validate_store_profile(&store, &profile)?;
    let warm_statistics = store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    if warm_statistics != after_reopen {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    verify_deep_integrity(&store, repository.as_ref(), &profile)?;
    let warm_start_nanoseconds = elapsed_nanoseconds(warm_start_started)?;

    let backup_path = inputs.workspace.join("backup");
    let manifest = if backup_path.exists() {
        verify_backup_trusted(
            &backup_path,
            provider.as_ref(),
            owner.semantic_time_unix_nanos,
            |identity| {
                identity.tenant == TENANT_ID
                    && identity.signer == SIGNER
                    && identity.signing_key == keys.signing
            },
        )
        .map_err(|_| error(DriverErrorCode::BackupFailure))?
        .manifest
    } else {
        create_backup(
            &store,
            inputs.workspace.join("blobs"),
            &backup_path,
            provider.as_ref(),
            BackupIdentity {
                signing_key: &keys.signing,
                tenant: TENANT_ID,
                signer: SIGNER,
                created_at_unix_nanos: owner.semantic_time_unix_nanos,
            },
        )
        .map_err(|_| error(DriverErrorCode::BackupFailure))?
    };
    let verified = verify_backup_trusted(
        &backup_path,
        provider.as_ref(),
        owner.semantic_time_unix_nanos,
        |identity| {
            identity.tenant == TENANT_ID
                && identity.signer == SIGNER
                && identity.signing_key == keys.signing
        },
    )
    .map_err(|_| error(DriverErrorCode::BackupFailure))?;
    if verified.manifest != manifest
        || manifest.repository_revision != after_reopen.revision.0
        || !valid_multihash(&manifest.canonical_root)
    {
        return Err(error(DriverErrorCode::BackupFailure));
    }

    let restored_path = inputs.workspace.join("restored");
    if restored_path.exists() {
        validate_owned_tree(&restored_path, workspace_identity.device)?;
    } else {
        restore_backup_trusted(
            &backup_path,
            &restored_path,
            provider.as_ref(),
            owner.semantic_time_unix_nanos,
            |identity| {
                identity.tenant == TENANT_ID
                    && identity.signer == SIGNER
                    && identity.signing_key == keys.signing
            },
        )
        .map_err(|_| error(DriverErrorCode::BackupFailure))?;
    }
    let restored_repository = reopen_blob_repository(
        &restored_path.join("blobs"),
        Arc::clone(&provider),
        &keys,
        owner.semantic_time_unix_nanos,
    )?;
    let restored_store = open_store_at(
        &restored_path.join("database.sqlite3"),
        Arc::clone(&restored_repository),
        &profile,
    )?;
    validate_store_profile(&restored_store, &profile)?;
    let restored_statistics = restored_store
        .catalog_statistics()
        .map_err(|_| error(DriverErrorCode::StoreFailure))?;
    if restored_statistics != after_reopen {
        return Err(error(DriverErrorCode::IntegrityFailure));
    }
    verify_deep_integrity(&restored_store, restored_repository.as_ref(), &profile)?;
    inputs_still_match(inputs, &binding, &profile_sha256, &binding_sha256)?;

    let body = ResultBody {
        schema_version: RESULT_SCHEMA.to_owned(),
        result: if inputs.production {
            "qualification-passed".to_owned()
        } else {
            "fixture-passed".to_owned()
        },
        release_scale_qualified: inputs.production,
        run_id: binding.run_id.clone(),
        started_at_unix_nanos: owner.semantic_time_unix_nanos,
        finished_at_unix_nanos: now_unix_nanos()?,
        platform_scope: PLATFORM.to_owned(),
        profile_sha256,
        binding_sha256,
        source_revision: binding.source_revision.clone(),
        source_tree_sha256: binding.source_tree_sha256.clone(),
        candidate: binding.candidate.clone(),
        installed_tool: binding.installed_tool.clone(),
        targets: profile.counts(),
        observed: Counts {
            atoms: restored_statistics.atom_count,
            edges: restored_statistics.edge_count,
            blob_objects: physical_blob_count(&inputs.workspace, workspace_identity.device)?,
            blob_bytes_each: profile.blob_bytes_each,
            referenced_blob_bytes: restored_statistics.referenced_blob_bytes,
        },
        roots: Roots {
            catalog: restored_statistics.catalog_root.as_str().to_owned(),
            semantic_before_reopen: before_reopen.semantic_root.as_str().to_owned(),
            semantic_after_reopen: after_reopen.semantic_root.as_str().to_owned(),
            semantic_after_restore: restored_statistics.semantic_root.as_str().to_owned(),
            backup_canonical: manifest.canonical_root.clone(),
        },
        storage: StorageEvidence {
            database_bytes: storage.database_bytes,
            database_page_count: storage.page_count,
            retained_snapshots: storage.retained_snapshots,
            backup_file_count: u64::try_from(manifest.files.len())
                .map_err(|_| error(DriverErrorCode::BackupFailure))?,
            backup_repository_revision: manifest.repository_revision,
        },
        lifecycle: LifecycleEvidence {
            cold_start_nanoseconds,
            steady_state_nanoseconds,
            restart_nanoseconds,
            warm_start_nanoseconds,
        },
        checks: [
            "catalog-counts-and-roots",
            "encrypted-blob-reference-integrity",
            "one-over-quota-rejected",
            "checkpoint-recovery",
            "restart-and-reopen",
            "signed-backup-verification",
            "restore-semantic-root-equality",
            "input-bindings-stable",
        ]
        .into_iter()
        .map(|id| Check {
            id: id.to_owned(),
            status: "passed".to_owned(),
        })
        .collect(),
        claims: Claims {
            physical_scale_execution_attempted: true,
            distinct_authoritative_atoms: true,
            distinct_authoritative_edges: true,
            distinct_encrypted_blob_objects: true,
            fuzz_executed: false,
            soak_executed: false,
        },
    };
    let result = RunResult {
        receipt_id: multihash(&canonical_json(&body)?),
        body,
    };
    validate_result(&result, &profile, inputs.production)?;
    let mut bytes = canonical_json(&result)?;
    bytes.push(b'\n');
    write_new_private(&inputs.output, &bytes, 0o400)?;
    Ok(result)
}

#[cfg(unix)]
fn verify_result_file(profile_path: &Path, binding_path: &Path, receipt_path: &Path) -> Result<()> {
    let (profile, profile_bytes): (Profile, Vec<u8>) =
        read_json(profile_path, false, DriverErrorCode::InvalidProfile)?;
    let production = profile.id == "large_local";
    profile.validate(production)?;
    let (binding, binding_bytes): (RunBinding, Vec<u8>) =
        read_json(binding_path, true, DriverErrorCode::InvalidBinding)?;
    validate_binding_shape(&binding)?;
    let receipt_bytes = read_stable_regular(receipt_path, MAX_CONTROL_FILE_BYTES, true)?;
    let receipt = parse_result(&receipt_bytes)?;
    validate_result(&receipt, &profile, production)?;
    if receipt.body.run_id != binding.run_id
        || receipt.body.profile_sha256 != sha256_hex(&profile_bytes)
        || receipt.body.binding_sha256 != sha256_hex(&binding_bytes)
        || receipt.body.source_revision != binding.source_revision
        || receipt.body.source_tree_sha256 != binding.source_tree_sha256
        || receipt.body.candidate != binding.candidate
        || receipt.body.installed_tool != binding.installed_tool
        || fingerprint(profile_path, MAX_CONTROL_FILE_BYTES)? != binding.profile
        || executable_fingerprint(Path::new(&binding.candidate.path), production)
            .map_err(|_| error(DriverErrorCode::InvalidBinding))?
            != binding.candidate
        || current_tool_fingerprint().map_err(|_| error(DriverErrorCode::InvalidBinding))?
            != binding.installed_tool
    {
        return Err(error(DriverErrorCode::InvalidBinding));
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_workspace(profile_path: &Path, binding_path: &Path, workspace: &Path) -> Result<()> {
    let (profile, profile_bytes): (Profile, Vec<u8>) =
        read_json(profile_path, false, DriverErrorCode::InvalidProfile)?;
    let production = profile.id == "large_local";
    profile.validate(production)?;
    let (binding, binding_bytes): (RunBinding, Vec<u8>) =
        read_json(binding_path, true, DriverErrorCode::InvalidBinding)?;
    validate_binding_shape(&binding)?;
    let identity = validate_private_directory(workspace)?;
    let (owner, _): (OwnerMarker, Vec<u8>) = read_json(
        &owner_path(workspace),
        true,
        DriverErrorCode::CheckpointMismatch,
    )?;
    if owner.schema_version != OWNER_SCHEMA
        || owner.run_id != binding.run_id
        || owner.binding_sha256 != sha256_hex(&binding_bytes)
        || owner.profile_sha256 != sha256_hex(&profile_bytes)
        || owner.workspace_device != identity.device
        || owner.workspace_inode != identity.inode
    {
        return Err(error(DriverErrorCode::CheckpointMismatch));
    }
    validate_workspace_entries(workspace, identity.device)?;
    validate_owned_tree(workspace, identity.device)?;
    let parent = workspace
        .parent()
        .ok_or_else(|| error(DriverErrorCode::UnsafePath))?
        .to_path_buf();
    fs::remove_dir_all(workspace).map_err(|_| error(DriverErrorCode::UnsafePath))?;
    sync_directory(&parent)
}

fn usage() -> &'static str {
    r#"Usage: cigar-local-scale-driver <command> [options]
commands:
  prepare --profile <absolute-file> --candidate <absolute-file> \
    --repository-root <absolute-directory> --source-revision <git-object-id> \
    --source-tree-sha256 <sha256> --run-id <id> --output <new-private-file>
  run --profile <absolute-file> --binding <absolute-file> \
    --workspace <absolute-private-directory> --output <new-private-file>
  verify --profile <absolute-file> --binding <absolute-file> --receipt <absolute-file>
  cleanup --profile <absolute-file> --binding <absolute-file> \
    --workspace <absolute-private-directory>
The production run is native Apple-silicon macOS only and accepts only the immutable
1,000,000-atom / 10,000,000-edge / 1,600 x 64-MiB large_local profile.
"#
}

fn parse_options(arguments: &[String]) -> Result<BTreeMap<String, String>> {
    if arguments.len() > 32 || !arguments.len().is_multiple_of(2) {
        return Err(error(DriverErrorCode::InvalidArgument));
    }
    let mut result = BTreeMap::new();
    for [key, value] in arguments.as_chunks::<2>().0 {
        if !key.starts_with("--")
            || key.len() < 3
            || value.is_empty()
            || result.insert(key.clone(), value.clone()).is_some()
        {
            return Err(error(DriverErrorCode::InvalidArgument));
        }
    }
    Ok(result)
}

fn exact_options<const N: usize>(
    options: &BTreeMap<String, String>,
    expected: [&str; N],
) -> Result<()> {
    if options.len() != N || expected.into_iter().any(|key| !options.contains_key(key)) {
        Err(error(DriverErrorCode::InvalidArgument))
    } else {
        Ok(())
    }
}

fn option_path(options: &BTreeMap<String, String>, key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        options
            .get(key)
            .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
    );
    if !lexical_absolute(&path) {
        return Err(error(DriverErrorCode::InvalidArgument));
    }
    Ok(path)
}

#[cfg(unix)]
fn command(arguments: &[String]) -> Result<Option<String>> {
    let subcommand = arguments
        .first()
        .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?;
    if matches!(subcommand.as_str(), "--help" | "-h" | "help") {
        return Ok(Some(usage().to_owned()));
    }
    let options = parse_options(arguments.get(1..).unwrap_or_default())?;
    match subcommand.as_str() {
        "prepare" => {
            exact_options(
                &options,
                [
                    "--profile",
                    "--candidate",
                    "--repository-root",
                    "--source-revision",
                    "--source-tree-sha256",
                    "--run-id",
                    "--output",
                ],
            )?;
            if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                return Err(error(DriverErrorCode::UnsupportedHost));
            }
            let binding = prepare_binding(BindingPreparation {
                profile_path: option_path(&options, "--profile")?,
                candidate_path: option_path(&options, "--candidate")?,
                repository_root: option_path(&options, "--repository-root")?,
                source_revision: options
                    .get("--source-revision")
                    .cloned()
                    .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
                source_tree_sha256: options
                    .get("--source-tree-sha256")
                    .cloned()
                    .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
                run_id: options
                    .get("--run-id")
                    .cloned()
                    .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
                output: option_path(&options, "--output")?,
                production: true,
            })?;
            Ok(Some(format!("binding prepared: {}\n", binding.run_id)))
        }
        "run" => {
            exact_options(
                &options,
                ["--profile", "--binding", "--workspace", "--output"],
            )?;
            let inputs = RunInputs {
                profile_path: option_path(&options, "--profile")?,
                binding_path: option_path(&options, "--binding")?,
                workspace: option_path(&options, "--workspace")?,
                output: option_path(&options, "--output")?,
                production: true,
            };
            let result = execute_run(&inputs, &mut RunControl::default())?;
            Ok(Some(format!(
                "local-scale qualification passed: {}\n",
                result.receipt_id
            )))
        }
        "verify" => {
            exact_options(&options, ["--profile", "--binding", "--receipt"])?;
            verify_result_file(
                &option_path(&options, "--profile")?,
                &option_path(&options, "--binding")?,
                &option_path(&options, "--receipt")?,
            )?;
            Ok(Some("local-scale result verified\n".to_owned()))
        }
        "cleanup" => {
            exact_options(&options, ["--profile", "--binding", "--workspace"])?;
            cleanup_workspace(
                &option_path(&options, "--profile")?,
                &option_path(&options, "--binding")?,
                &option_path(&options, "--workspace")?,
            )?;
            Ok(Some("owned local-scale scratch removed\n".to_owned()))
        }
        #[cfg(debug_assertions)]
        "prepare-fixture" => {
            exact_options(
                &options,
                [
                    "--profile",
                    "--candidate",
                    "--repository-root",
                    "--source-revision",
                    "--source-tree-sha256",
                    "--run-id",
                    "--output",
                ],
            )?;
            let binding = prepare_binding(BindingPreparation {
                profile_path: option_path(&options, "--profile")?,
                candidate_path: option_path(&options, "--candidate")?,
                repository_root: option_path(&options, "--repository-root")?,
                source_revision: options
                    .get("--source-revision")
                    .cloned()
                    .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
                source_tree_sha256: options
                    .get("--source-tree-sha256")
                    .cloned()
                    .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
                run_id: options
                    .get("--run-id")
                    .cloned()
                    .ok_or_else(|| error(DriverErrorCode::InvalidArgument))?,
                output: option_path(&options, "--output")?,
                production: false,
            })?;
            Ok(Some(format!(
                "fixture binding prepared: {}\n",
                binding.run_id
            )))
        }
        #[cfg(debug_assertions)]
        "fixture-run" => {
            let has_stop = options.contains_key("--stop-after-commits");
            if has_stop {
                exact_options(
                    &options,
                    [
                        "--profile",
                        "--binding",
                        "--workspace",
                        "--output",
                        "--stop-after-commits",
                    ],
                )?;
            } else {
                exact_options(
                    &options,
                    ["--profile", "--binding", "--workspace", "--output"],
                )?;
            }
            let mut control = RunControl {
                stop_after_commits: options
                    .get("--stop-after-commits")
                    .map(|value| value.parse::<u64>())
                    .transpose()
                    .map_err(|_| error(DriverErrorCode::InvalidArgument))?,
                commits: 0,
            };
            let inputs = RunInputs {
                profile_path: option_path(&options, "--profile")?,
                binding_path: option_path(&options, "--binding")?,
                workspace: option_path(&options, "--workspace")?,
                output: option_path(&options, "--output")?,
                production: false,
            };
            let result = execute_run(&inputs, &mut control)?;
            Ok(Some(format!("fixture passed: {}\n", result.receipt_id)))
        }
        _ => Err(error(DriverErrorCode::InvalidArgument)),
    }
}

#[cfg(not(unix))]
fn command(_arguments: &[String]) -> Result<Option<String>> {
    Err(error(DriverErrorCode::UnsupportedHost))
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match command(&arguments) {
        Ok(Some(output)) => print!("{output}"),
        Ok(None) => {}
        Err(failure) => {
            eprintln!("{failure}");
            let status = if failure.0 == DriverErrorCode::InjectedStop {
                75
            } else {
                2
            };
            std::process::exit(status);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    struct FixtureEnvironment {
        _temporary: tempfile::TempDir,
        root: PathBuf,
        workspace: PathBuf,
        candidate: PathBuf,
        profile: PathBuf,
        binding: PathBuf,
        result: PathBuf,
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).expect("create private directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("restrict private directory");
    }

    fn fixture_profile(initial_available: u64) -> Profile {
        Profile {
            schema_version: PROFILE_SCHEMA.to_owned(),
            id: "scaled_fixture".to_owned(),
            platform: PLATFORM.to_owned(),
            capacity_profile: "standard".to_owned(),
            atoms: 12,
            edges: 24,
            blob_objects: 2,
            blob_bytes_each: 4_096,
            referenced_blob_bytes: 8_192,
            atom_batch_size: 4,
            edge_batch_size: 8,
            maximum_database_bytes: 4_294_967_296,
            minimum_initial_available_bytes: initial_available,
            minimum_runtime_reserve_bytes: 1,
            maximum_atoms: 10_000_000,
            maximum_edges: 10_000_000,
            maximum_referenced_blob_bytes: MAX_REFERENCED_BYTES,
        }
    }

    fn write_profile(path: &Path, profile: &Profile) {
        let mut bytes = canonical_json(profile).expect("serialize profile");
        bytes.push(b'\n');
        write_new_private(path, &bytes, 0o600).expect("write profile");
    }

    fn fixture_environment(initial_available: u64) -> FixtureEnvironment {
        let temporary = tempfile::Builder::new()
            .prefix("cigar-local-scale-driver-test-")
            .tempdir()
            .expect("create fixture root");
        let root = fs::canonicalize(temporary.path()).expect("canonical fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("restrict fixture root");
        let repository = root.join("repository");
        let evidence = root.join("evidence");
        let workspace = root.join("workspace");
        let candidate_directory = root.join("candidate");
        for directory in [&repository, &evidence, &workspace, &candidate_directory] {
            private_directory(directory);
        }
        let candidate = candidate_directory.join("cigard");
        fs::write(&candidate, b"scaled candidate fixture\n").expect("write candidate");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
            .expect("restrict candidate");
        let profile = evidence.join("profile.json");
        write_profile(&profile, &fixture_profile(initial_available));
        let binding = evidence.join("binding.json");
        let result = evidence.join("result.json");
        prepare_binding(BindingPreparation {
            profile_path: profile.clone(),
            candidate_path: candidate.clone(),
            repository_root: repository,
            source_revision: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            run_id: "scaled-fixture-run".to_owned(),
            output: binding.clone(),
            production: false,
        })
        .expect("prepare fixture binding");
        FixtureEnvironment {
            _temporary: temporary,
            root,
            workspace,
            candidate,
            profile,
            binding,
            result,
        }
    }

    fn inputs(environment: &FixtureEnvironment) -> RunInputs {
        RunInputs {
            profile_path: environment.profile.clone(),
            binding_path: environment.binding.clone(),
            workspace: environment.workspace.clone(),
            output: environment.result.clone(),
            production: false,
        }
    }

    #[test]
    fn immutable_production_profile_is_exact() {
        let profile: Profile =
            serde_json::from_str(include_str!("../../profiles/large-local-v1.json"))
                .expect("decode immutable profile");
        profile.validate(true).expect("validate immutable profile");
        assert_eq!(profile.counts().atoms, PRODUCTION_ATOMS);
        assert_eq!(profile.counts().edges, PRODUCTION_EDGES);
        assert_eq!(profile.counts().blob_objects, PRODUCTION_BLOB_OBJECTS);
        assert_eq!(
            profile.counts().referenced_blob_bytes,
            PRODUCTION_REFERENCED_BYTES
        );
    }

    #[test]
    fn scaled_fixture_selects_only_registered_capacity_profiles() {
        let standard = fixture_profile(1);
        standard.validate(false).expect("standard fixture profile");
        assert_eq!(
            capacity_profile(&standard).expect("standard capacity"),
            SqliteCapacityProfile::Standard
        );

        let mut large_local = standard.clone();
        large_local.capacity_profile = "large_local".to_owned();
        large_local.maximum_database_bytes = MAX_DATABASE_BYTES;
        large_local.validate(false).expect("large-local fixture profile");
        assert_eq!(
            capacity_profile(&large_local).expect("large-local capacity"),
            SqliteCapacityProfile::LargeLocal
        );

        large_local.maximum_database_bytes -= 1;
        assert_eq!(
            large_local.validate(false).expect_err("mismatched capacity must fail").0,
            DriverErrorCode::InvalidProfile
        );
    }

    #[test]
    fn deterministic_records_are_distinct_and_valid() {
        let profile = fixture_profile(1);
        let atom_template = atom_template().expect("atom template");
        let edge_template = edge_template().expect("edge template");
        let atoms = (0..profile.atoms)
            .map(|index| make_atom(&atom_template, index, &profile).expect("generated atom"))
            .collect::<Vec<_>>();
        assert_eq!(
            atoms
                .iter()
                .map(|atom| atom.atom_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            usize::try_from(profile.atoms).expect("atom count")
        );
        assert_eq!(
            atoms
                .iter()
                .map(|atom| atom.version_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            usize::try_from(profile.atoms).expect("version count")
        );
        let edges = (0..profile.edges)
            .map(|index| make_edge(&edge_template, index, &profile).expect("generated edge"))
            .collect::<Vec<_>>();
        assert_eq!(
            edges
                .iter()
                .map(|edge| edge.edge_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            usize::try_from(profile.edges).expect("edge count")
        );
        assert!(
            edges
                .iter()
                .all(|edge| edge.from_version != edge.to_version)
        );
        assert_ne!(
            blob_content_digest(0, profile.blob_bytes_each).expect("blob zero"),
            blob_content_digest(1, profile.blob_bytes_each).expect("blob one")
        );
    }

    #[test]
    fn scaled_physical_run_recovers_checkpoint_and_verifies_backup_restore() {
        let environment = fixture_environment(1);
        let first = execute_run(
            &inputs(&environment),
            &mut RunControl {
                stop_after_commits: Some(1),
                commits: 0,
            },
        );
        assert_eq!(
            first.expect_err("fixture should stop").0,
            DriverErrorCode::InjectedStop
        );
        assert!(!environment.result.exists());
        let checkpoint = parse_checkpoint(
            &read_stable_regular(
                &checkpoint_path(&environment.workspace),
                MAX_CONTROL_FILE_BYTES,
                true,
            )
            .expect("read pre-commit checkpoint"),
        )
        .expect("parse pre-commit checkpoint");
        assert_eq!(checkpoint.body.revision, 0);
        assert_eq!(checkpoint.body.atoms, 0);
        let result = execute_run(&inputs(&environment), &mut RunControl::default())
            .expect("resume scaled fixture");
        assert_eq!(result.body.result, "fixture-passed");
        assert!(!result.body.release_scale_qualified);
        assert_eq!(result.body.observed, fixture_profile(1).counts());
        let mut forged = result.clone();
        forged.body.storage.database_bytes = 0;
        forged.receipt_id = multihash(&canonical_json(&forged.body).expect("hash forged result"));
        assert_eq!(
            validate_result(&forged, &fixture_profile(1), false)
                .expect_err("zero storage evidence must fail")
                .0,
            DriverErrorCode::IntegrityFailure
        );
        assert_eq!(stat::mode(&environment.result), 0o400);
        verify_result_file(
            &environment.profile,
            &environment.binding,
            &environment.result,
        )
        .expect("verify result");
        cleanup_workspace(
            &environment.profile,
            &environment.binding,
            &environment.workspace,
        )
        .expect("cleanup owned workspace");
        assert!(!environment.workspace.exists());
        assert!(environment.result.exists());
    }

    #[test]
    fn bindings_reject_post_manifest_mutation_hardlinks_fifo_devices_and_aliases() {
        let environment = fixture_environment(1);
        fs::set_permissions(&environment.candidate, fs::Permissions::from_mode(0o600))
            .expect("make candidate writable");
        fs::write(&environment.candidate, b"mutated candidate\n").expect("mutate candidate");
        let failure = execute_run(&inputs(&environment), &mut RunControl::default())
            .expect_err("mutated candidate must fail");
        assert_eq!(failure.0, DriverErrorCode::InvalidBinding);

        let hardlink = environment.root.join("hardlinked-candidate");
        fs::hard_link(&environment.candidate, &hardlink).expect("create hardlink");
        assert_eq!(
            fingerprint(&environment.candidate, MAX_BOUND_FILE_BYTES)
                .expect_err("hardlink must fail")
                .0,
            DriverErrorCode::UnsafePath
        );

        let fifo = environment.root.join("candidate-fifo");
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .expect("invoke mkfifo");
        assert!(status.success());
        assert_eq!(
            fingerprint(&fifo, MAX_BOUND_FILE_BYTES)
                .expect_err("FIFO must fail")
                .0,
            DriverErrorCode::UnsafePath
        );
        assert_eq!(
            fingerprint(Path::new("/dev/null"), MAX_BOUND_FILE_BYTES)
                .expect_err("device must fail")
                .0,
            DriverErrorCode::UnsafePath
        );

        let real_workspace = environment.root.join("real-workspace");
        private_directory(&real_workspace);
        let alias = environment.root.join("workspace-alias");
        std::os::unix::fs::symlink(&real_workspace, &alias).expect("create alias");
        assert_eq!(
            validate_private_directory(&alias)
                .expect_err("symlink alias must fail")
                .0,
            DriverErrorCode::UnsafePath
        );

        let unexpected = fixture_environment(1);
        fs::write(
            unexpected.workspace.join("unexpected"),
            b"not driver owned\n",
        )
        .expect("write unexpected entry");
        assert_eq!(
            execute_run(&inputs(&unexpected), &mut RunControl::default())
                .expect_err("unexpected scratch entry must fail")
                .0,
            DriverErrorCode::UnsafePath
        );

        let duplicate_checkpoint = br#"{
            "schema_version":"cigar.local-scale-checkpoint.v1",
            "run_id":"one","run_id":"two",
            "binding_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "profile_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "phase":"atoms","revision":0,"atoms":0,"edges":0,
            "referenced_blob_bytes":0,
            "catalog_root":"12200000000000000000000000000000000000000000000000000000000000000000",
            "semantic_root":"12200000000000000000000000000000000000000000000000000000000000000000",
            "checkpoint_id":"12200000000000000000000000000000000000000000000000000000000000000000"
        }"#;
        assert_eq!(
            parse_checkpoint(duplicate_checkpoint)
                .expect_err("duplicate JSON key must fail")
                .0,
            DriverErrorCode::CheckpointMismatch
        );
    }

    #[test]
    fn insufficient_space_fails_before_store_creation_and_unowned_cleanup_is_denied() {
        let environment = fixture_environment(u64::MAX);
        let failure = execute_run(&inputs(&environment), &mut RunControl::default())
            .expect_err("impossible capacity must fail");
        assert_eq!(failure.0, DriverErrorCode::InsufficientSpace);
        assert!(!owner_path(&environment.workspace).exists());
        assert!(!environment.workspace.join("database.sqlite3").exists());

        let retry = execute_run(&inputs(&environment), &mut RunControl::default())
            .expect_err("a failed initial capacity check must not become a resume");
        assert_eq!(retry.0, DriverErrorCode::InsufficientSpace);
        assert!(!owner_path(&environment.workspace).exists());
        assert!(!environment.workspace.join("database.sqlite3").exists());

        let unowned = environment.root.join("unowned");
        private_directory(&unowned);
        fs::write(unowned.join("keep.txt"), b"must remain\n").expect("write unowned file");
        let failure = cleanup_workspace(&environment.profile, &environment.binding, &unowned)
            .expect_err("unowned cleanup must fail");
        assert_eq!(failure.0, DriverErrorCode::UnsafePath);
        assert!(unowned.join("keep.txt").exists());
    }

    mod stat {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::Path;

        pub(super) fn mode(path: &Path) -> u32 {
            fs::symlink_metadata(path)
                .expect("read mode")
                .permissions()
                .mode()
                & 0o777
        }
    }
}
