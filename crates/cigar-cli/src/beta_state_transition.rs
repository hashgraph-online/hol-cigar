//! macOS/Unix beta-to-full administrative-state transition boundary.

use crate::administration::{BlockingCancellation, read_frozen_beta_state_file};
use crate::beta_state_compat::{
    FROZEN_BETA_RELEASE, FROZEN_BETA_STATE_SCHEMA, FrozenBetaImportSnapshot,
    FrozenBetaStateSummary, MAX_FROZEN_BETA_STATE_BYTES, decode_frozen_beta_state,
};
use crate::error::CliError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

/// Schema written only after a verified beta backup exists.
///
/// The frozen beta decoder rejects this value, providing an enforceable in-place downgrade wall.
pub(crate) const IMPORTED_FULL_STATE_SCHEMA: &str = "cigar.cli-administration.imported-beta.v1";

const BACKUP_SCHEMA: &str = "cigar.beta-state-transition-backup.v1";
const MARKER_SCHEMA: &str = "cigar.beta-state-transition-marker.v1";
const RECEIPT_SCHEMA: &str = "cigar.beta-state-transition-receipt.v1";
const BACKUP_STATE_FILE: &str = "source-state.json";
const BACKUP_MANIFEST_FILE: &str = "manifest.json";
const IMPORTED_STATE_FILE: &str = "state.json";
const IMPORT_MARKER_FILE: &str = ".beta-transition.json";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_MARKER_BYTES: u64 = 16 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    schema_version: String,
    source_release: String,
    source_state_schema: String,
    source_sha256: String,
    source_byte_count: u64,
    source_generation: u64,
    project_count: u64,
    source_count: u64,
    link_count: u64,
    active_project_present: bool,
    active_focus_present: bool,
    source_bytes_preserved: bool,
    restore_policy: String,
    in_place_downgrade: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionMarker {
    schema_version: String,
    source_release: String,
    source_state_schema: String,
    imported_state_schema: String,
    source_sha256: String,
    source_byte_count: u64,
    source_generation: u64,
    backup_manifest_sha256: String,
    imported_state_sha256: String,
    source_bytes_preserved_in_verified_backup: bool,
    identifiers_preserved: bool,
    paths_preserved: bool,
    generation_preserved: bool,
    in_place_downgrade: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportedState {
    schema_version: String,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_focus: Option<String>,
    projects: BTreeMap<String, ImportedProject>,
    sources: BTreeMap<String, ImportedSource>,
    links: BTreeSet<ImportedLink>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportedProject {
    path: PathBuf,
    attached: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportedSource {
    path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportedLink {
    from: String,
    to: String,
}

#[derive(Clone, Debug)]
struct ValidatedSource {
    bytes: Vec<u8>,
    snapshot: FrozenBetaImportSnapshot,
    summary: FrozenBetaStateSummary,
    digest: String,
}

#[derive(Clone, Debug)]
struct VerifiedBackup {
    source: ValidatedSource,
    manifest: BackupManifest,
    manifest_bytes: Vec<u8>,
    manifest_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishStatus {
    Created,
    AlreadyExists,
}

struct FileSpec<'a> {
    name: &'static str,
    bytes: &'a [u8],
    mode: u32,
}

struct ParentBinding {
    path: PathBuf,
    directory: File,
    name: OsString,
    device: u64,
    inode: u64,
}

/// Imports exact beta semantics into a new full-only state directory after publishing and
/// re-verifying an exact-byte recovery backup.
pub(crate) fn import_beta_state(
    source_path: &Path,
    backup_path: &Path,
    target_path: &Path,
    dry_run: bool,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    validate_distinct_transition_paths(source_path, backup_path, target_path)?;
    let source = load_source(source_path)?;
    let manifest = manifest_for(&source)?;
    let manifest_bytes = serialize_document(&manifest)?;
    let manifest_digest = sha256_digest(&manifest_bytes);
    let imported = imported_state_for(&source.snapshot);
    let imported_bytes = serialize_document(&imported)?;
    let imported_digest = sha256_digest(&imported_bytes);
    let marker = marker_for(&source, &manifest_digest, &imported_digest);
    let marker_bytes = serialize_document(&marker)?;

    let backup_parent = ParentBinding::for_publication(backup_path)?;
    let target_parent = ParentBinding::for_publication(target_path)?;
    let backup_exists = entry_exists(&backup_parent.directory, &backup_parent.name)?;
    let target_exists = entry_exists(&target_parent.directory, &target_parent.name)?;

    if dry_run {
        if backup_exists || target_exists {
            return Err(CliError::state_conflict());
        }
        return Ok(import_receipt(
            &source,
            &manifest_digest,
            &imported_digest,
            "planned",
            "planned",
            false,
        ));
    }

    cancellation.checkpoint()?;
    let backup_reused = if backup_exists {
        let verified = verify_backup(backup_path)?;
        ensure_backup_matches(&verified, &source, &manifest)?;
        true
    } else {
        let status = publish_directory(
            &backup_parent,
            &[
                FileSpec {
                    name: BACKUP_STATE_FILE,
                    bytes: &source.bytes,
                    mode: 0o400,
                },
                FileSpec {
                    name: BACKUP_MANIFEST_FILE,
                    bytes: &manifest_bytes,
                    mode: 0o400,
                },
            ],
            0o700,
        )?;
        let verified = verify_backup(backup_path)?;
        ensure_backup_matches(&verified, &source, &manifest)?;
        status == PublishStatus::AlreadyExists
    };

    cancellation.checkpoint()?;
    let target_status = if target_exists {
        verify_import_target(
            target_path,
            &imported,
            &imported_bytes,
            &marker,
            &marker_bytes,
        )?;
        PublishStatus::AlreadyExists
    } else {
        let status = publish_directory(
            &target_parent,
            &[
                FileSpec {
                    name: IMPORTED_STATE_FILE,
                    bytes: &imported_bytes,
                    mode: 0o600,
                },
                FileSpec {
                    name: IMPORT_MARKER_FILE,
                    bytes: &marker_bytes,
                    mode: 0o400,
                },
            ],
            0o700,
        )?;
        verify_import_target(
            target_path,
            &imported,
            &imported_bytes,
            &marker,
            &marker_bytes,
        )?;
        status
    };

    Ok(import_receipt(
        &source,
        &manifest_digest,
        &imported_digest,
        if backup_reused {
            "reused_verified"
        } else {
            "created_verified"
        },
        if target_status == PublishStatus::AlreadyExists {
            "already_imported_verified"
        } else {
            "imported_verified"
        },
        target_status == PublishStatus::AlreadyExists,
    ))
}

/// Restores a verified transition backup into a distinct new beta-compatible recovery directory.
/// The active full state directory is never rewritten or downgraded by this operation.
pub(crate) fn restore_beta_backup(
    backup_path: &Path,
    recovery_target: &Path,
    active_full_target: &Path,
    dry_run: bool,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    validate_restore_paths(backup_path, recovery_target, active_full_target)?;
    let backup = verify_backup(backup_path)?;
    let target_parent = ParentBinding::for_publication(recovery_target)?;
    ensure_recovery_parent_outside_active_target(&target_parent, active_full_target)?;
    let target_exists = entry_exists(&target_parent.directory, &target_parent.name)?;
    if dry_run {
        if target_exists {
            return Err(CliError::state_conflict());
        }
        return Ok(restore_receipt(&backup, "planned", false));
    }

    cancellation.checkpoint()?;
    let status = if target_exists {
        verify_recovery_target(recovery_target, &backup.source.bytes)?;
        PublishStatus::AlreadyExists
    } else {
        let status = publish_directory(
            &target_parent,
            &[FileSpec {
                name: IMPORTED_STATE_FILE,
                bytes: &backup.source.bytes,
                mode: 0o600,
            }],
            0o700,
        )?;
        verify_recovery_target(recovery_target, &backup.source.bytes)?;
        status
    };
    Ok(restore_receipt(
        &backup,
        if status == PublishStatus::AlreadyExists {
            "already_restored_verified"
        } else {
            "restored_verified"
        },
        status == PublishStatus::AlreadyExists,
    ))
}

fn validate_distinct_transition_paths(
    source: &Path,
    backup: &Path,
    target: &Path,
) -> Result<(), CliError> {
    validate_absolute_path(source)?;
    validate_absolute_path(backup)?;
    validate_absolute_path(target)?;
    if source == backup
        || source == target
        || backup == target
        || backup.starts_with(target)
        || target.starts_with(backup)
    {
        return Err(CliError::state_conflict());
    }
    Ok(())
}

fn validate_restore_paths(
    backup: &Path,
    recovery_target: &Path,
    active_full_target: &Path,
) -> Result<(), CliError> {
    validate_absolute_path(backup)?;
    validate_absolute_path(recovery_target)?;
    validate_absolute_path(active_full_target)?;
    if backup == recovery_target
        || recovery_target == active_full_target
        || recovery_target.starts_with(backup)
        || backup.starts_with(recovery_target)
        || recovery_target.starts_with(active_full_target)
        || active_full_target.starts_with(recovery_target)
    {
        return Err(CliError::state_conflict());
    }
    Ok(())
}

fn ensure_recovery_parent_outside_active_target(
    recovery_parent: &ParentBinding,
    active_full_target: &Path,
) -> Result<(), CliError> {
    let active_parent = ParentBinding::for_publication(active_full_target)?;
    if !entry_exists(&active_parent.directory, &active_parent.name)? {
        return Ok(());
    }
    let active = open_private_directory(active_full_target, 0o700)?;
    let metadata = active
        .metadata()
        .map_err(|_error| CliError::state_unavailable())?;
    if directory_is_within(&recovery_parent.directory, metadata.dev(), metadata.ino())? {
        return Err(CliError::state_conflict());
    }
    Ok(())
}

fn directory_is_within(
    directory: &File,
    ancestor_device: u64,
    ancestor_inode: u64,
) -> Result<bool, CliError> {
    use rustix::fs::{Mode, OFlags, openat};

    let mut current = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::state_unavailable())?;
    for _depth in 0..1_024 {
        let metadata = current
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        validate_safe_ancestor(&metadata)?;
        if metadata.dev() == ancestor_device && metadata.ino() == ancestor_inode {
            return Ok(true);
        }
        let parent = openat(
            &current,
            "..",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_error| CliError::state_unavailable())?;
        let parent_metadata = parent
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        if parent_metadata.dev() == metadata.dev() && parent_metadata.ino() == metadata.ino() {
            return Ok(false);
        }
        current = parent;
    }
    Err(CliError::state_unavailable())
}

fn validate_absolute_path(path: &Path) -> Result<(), CliError> {
    if !path.is_absolute() {
        return Err(CliError::invalid_input());
    }
    let mut saw_root = false;
    let mut saw_name = false;
    for component in path.components() {
        match component {
            Component::RootDir if !saw_root && !saw_name => saw_root = true,
            Component::Normal(name)
                if name.to_str().is_some_and(|value| {
                    !value.is_empty() && !value.chars().any(char::is_control)
                }) =>
            {
                saw_name = true;
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir
            | Component::Normal(_) => return Err(CliError::invalid_input()),
        }
    }
    if !saw_root || !saw_name {
        return Err(CliError::invalid_input());
    }
    Ok(())
}

fn load_source(path: &Path) -> Result<ValidatedSource, CliError> {
    let bytes = read_frozen_beta_state_file(path)?;
    validated_source_from_bytes(bytes)
}

fn validated_source_from_bytes(bytes: Vec<u8>) -> Result<ValidatedSource, CliError> {
    let state =
        decode_frozen_beta_state(&bytes).map_err(|_error| CliError::beta_state_invalid())?;
    Ok(ValidatedSource {
        digest: sha256_digest(&bytes),
        summary: state.summary(),
        snapshot: state.import_snapshot(),
        bytes,
    })
}

fn manifest_for(source: &ValidatedSource) -> Result<BackupManifest, CliError> {
    Ok(BackupManifest {
        schema_version: BACKUP_SCHEMA.to_owned(),
        source_release: FROZEN_BETA_RELEASE.to_owned(),
        source_state_schema: FROZEN_BETA_STATE_SCHEMA.to_owned(),
        source_sha256: source.digest.clone(),
        source_byte_count: u64::try_from(source.bytes.len())
            .map_err(|_error| CliError::beta_state_invalid())?,
        source_generation: source.summary.generation,
        project_count: u64::try_from(source.summary.project_count)
            .map_err(|_error| CliError::beta_state_invalid())?,
        source_count: u64::try_from(source.summary.source_count)
            .map_err(|_error| CliError::beta_state_invalid())?,
        link_count: u64::try_from(source.summary.link_count)
            .map_err(|_error| CliError::beta_state_invalid())?,
        active_project_present: source.summary.has_active_project,
        active_focus_present: source.summary.has_active_focus,
        source_bytes_preserved: true,
        restore_policy: "new-empty-recovery-target-only".to_owned(),
        in_place_downgrade: "blocked".to_owned(),
    })
}

fn marker_for(
    source: &ValidatedSource,
    manifest_digest: &str,
    imported_state_digest: &str,
) -> TransitionMarker {
    TransitionMarker {
        schema_version: MARKER_SCHEMA.to_owned(),
        source_release: FROZEN_BETA_RELEASE.to_owned(),
        source_state_schema: FROZEN_BETA_STATE_SCHEMA.to_owned(),
        imported_state_schema: IMPORTED_FULL_STATE_SCHEMA.to_owned(),
        source_sha256: source.digest.clone(),
        source_byte_count: u64::try_from(source.bytes.len()).unwrap_or(u64::MAX),
        source_generation: source.summary.generation,
        backup_manifest_sha256: manifest_digest.to_owned(),
        imported_state_sha256: imported_state_digest.to_owned(),
        source_bytes_preserved_in_verified_backup: true,
        identifiers_preserved: true,
        paths_preserved: true,
        generation_preserved: true,
        in_place_downgrade: "blocked-by-imported-state-schema".to_owned(),
    }
}

fn imported_state_for(snapshot: &FrozenBetaImportSnapshot) -> ImportedState {
    ImportedState {
        schema_version: IMPORTED_FULL_STATE_SCHEMA.to_owned(),
        generation: snapshot.generation,
        active_project: snapshot.active_project.clone(),
        active_focus: snapshot.active_focus.clone(),
        projects: snapshot
            .projects
            .iter()
            .map(|(identifier, project)| {
                (
                    identifier.clone(),
                    ImportedProject {
                        path: project.path.clone(),
                        attached: project.attached,
                    },
                )
            })
            .collect(),
        sources: snapshot
            .sources
            .iter()
            .map(|(identifier, path)| (identifier.clone(), ImportedSource { path: path.clone() }))
            .collect(),
        links: snapshot
            .links
            .iter()
            .map(|link| ImportedLink {
                from: link.from.clone(),
                to: link.to.clone(),
            })
            .collect(),
    }
}

fn verify_backup(path: &Path) -> Result<VerifiedBackup, CliError> {
    let directory = open_private_directory(path, 0o700)?;
    require_exact_entries(&directory, &[BACKUP_MANIFEST_FILE, BACKUP_STATE_FILE])?;
    let source_bytes = read_private_file_at(
        &directory,
        BACKUP_STATE_FILE,
        MAX_FROZEN_BETA_STATE_BYTES,
        0o400,
    )?;
    let manifest_bytes =
        read_private_file_at(&directory, BACKUP_MANIFEST_FILE, MAX_MANIFEST_BYTES, 0o400)?;
    cigar_canon::parse_strict_json(&manifest_bytes)
        .map_err(|_error| CliError::beta_state_invalid())?;
    let manifest: BackupManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_error| CliError::beta_state_invalid())?;
    let source = validated_source_from_bytes(source_bytes)?;
    let expected = manifest_for(&source)?;
    if manifest != expected {
        return Err(CliError::beta_state_invalid());
    }
    Ok(VerifiedBackup {
        source,
        manifest,
        manifest_digest: sha256_digest(&manifest_bytes),
        manifest_bytes,
    })
}

fn ensure_backup_matches(
    backup: &VerifiedBackup,
    source: &ValidatedSource,
    manifest: &BackupManifest,
) -> Result<(), CliError> {
    if backup.source.bytes != source.bytes
        || backup.source.snapshot != source.snapshot
        || &backup.manifest != manifest
    {
        return Err(CliError::state_conflict());
    }
    Ok(())
}

fn verify_import_target(
    path: &Path,
    expected_state: &ImportedState,
    expected_state_bytes: &[u8],
    expected_marker: &TransitionMarker,
    expected_marker_bytes: &[u8],
) -> Result<(), CliError> {
    let directory = open_private_directory(path, 0o700)?;
    require_exact_entries(&directory, &[IMPORT_MARKER_FILE, IMPORTED_STATE_FILE])?;
    let state_bytes = read_private_file_at(
        &directory,
        IMPORTED_STATE_FILE,
        MAX_FROZEN_BETA_STATE_BYTES,
        0o600,
    )?;
    let marker_bytes =
        read_private_file_at(&directory, IMPORT_MARKER_FILE, MAX_MARKER_BYTES, 0o400)?;
    cigar_canon::parse_strict_json(&state_bytes).map_err(|_error| CliError::state_corrupt())?;
    cigar_canon::parse_strict_json(&marker_bytes).map_err(|_error| CliError::state_corrupt())?;
    let state: ImportedState =
        serde_json::from_slice(&state_bytes).map_err(|_error| CliError::state_corrupt())?;
    let marker: TransitionMarker =
        serde_json::from_slice(&marker_bytes).map_err(|_error| CliError::state_corrupt())?;
    if &state != expected_state
        || state_bytes != expected_state_bytes
        || &marker != expected_marker
        || marker_bytes != expected_marker_bytes
        || marker.imported_state_sha256 != sha256_digest(&state_bytes)
    {
        return Err(CliError::state_conflict());
    }
    Ok(())
}

fn verify_recovery_target(path: &Path, expected_bytes: &[u8]) -> Result<(), CliError> {
    let directory = open_private_directory(path, 0o700)?;
    require_exact_entries(&directory, &[IMPORTED_STATE_FILE])?;
    let bytes = read_private_file_at(
        &directory,
        IMPORTED_STATE_FILE,
        MAX_FROZEN_BETA_STATE_BYTES,
        0o600,
    )?;
    if bytes != expected_bytes || decode_frozen_beta_state(&bytes).is_err() {
        return Err(CliError::state_conflict());
    }
    Ok(())
}

fn serialize_document<T: Serialize>(document: &T) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec(document).map_err(|_error| CliError::state_corrupt())
}

fn import_receipt(
    source: &ValidatedSource,
    manifest_digest: &str,
    imported_digest: &str,
    backup_status: &str,
    target_status: &str,
    idempotent_replay: bool,
) -> Value {
    json!({
        "schema_version": RECEIPT_SCHEMA,
        "operation": "beta-to-full-import",
        "source": source_receipt(source),
        "backup": {
            "status": backup_status,
            "manifest_sha256": manifest_digest,
            "source_bytes_preserved": true,
            "restore_policy": "new-empty-recovery-target-only"
        },
        "target": {
            "status": target_status,
            "state_schema": IMPORTED_FULL_STATE_SCHEMA,
            "state_sha256": imported_digest,
            "idempotent_replay": idempotent_replay
        },
        "preservation": {
            "identifiers": true,
            "paths": true,
            "generation": true,
            "source_bytes": true,
            "content_free_output": true
        },
        "downgrade": {
            "in_place_status": "blocked",
            "enforcement": "imported-state-schema",
            "recovery_restore_status": "verified-empty-target-only"
        }
    })
}

fn restore_receipt(backup: &VerifiedBackup, status: &str, idempotent_replay: bool) -> Value {
    json!({
        "schema_version": RECEIPT_SCHEMA,
        "operation": "beta-backup-restore",
        "source": source_receipt(&backup.source),
        "backup": {
            "status": "verified",
            "manifest_sha256": backup.manifest_digest,
            "manifest_byte_count": backup.manifest_bytes.len()
        },
        "recovery_target": {
            "status": status,
            "state_schema": FROZEN_BETA_STATE_SCHEMA,
            "source_bytes_restored_exactly": true,
            "idempotent_replay": idempotent_replay
        },
        "downgrade": {
            "active_full_target_mutated": false,
            "in_place_status": "blocked",
            "recovery_restore_policy": "new-empty-target-only"
        },
        "content_free_output": true
    })
}

fn source_receipt(source: &ValidatedSource) -> Value {
    json!({
        "release": FROZEN_BETA_RELEASE,
        "state_schema": FROZEN_BETA_STATE_SCHEMA,
        "sha256": source.digest,
        "byte_count": source.bytes.len(),
        "generation": source.summary.generation,
        "project_count": source.summary.project_count,
        "source_count": source.summary.source_count,
        "link_count": source.summary.link_count,
        "active_project_present": source.summary.has_active_project,
        "active_focus_present": source.summary.has_active_focus
    })
}

impl ParentBinding {
    fn for_publication(path: &Path) -> Result<Self, CliError> {
        validate_absolute_path(path)?;
        let parent = path.parent().ok_or_else(CliError::invalid_input)?;
        let name = path
            .file_name()
            .ok_or_else(CliError::invalid_input)?
            .to_os_string();
        let directory = open_safe_directory_chain(parent)?;
        let metadata = directory
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        validate_publication_parent(&metadata)?;
        Ok(Self {
            path: parent.to_path_buf(),
            name,
            device: metadata.dev(),
            inode: metadata.ino(),
            directory,
        })
    }

    fn ensure_current(&self) -> Result<(), CliError> {
        let current = open_safe_directory_chain(&self.path)?;
        let metadata = current
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        validate_publication_parent(&metadata)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(CliError::state_unavailable());
        }
        Ok(())
    }
}

fn publish_directory(
    parent: &ParentBinding,
    files: &[FileSpec<'_>],
    final_mode: u32,
) -> Result<PublishStatus, CliError> {
    use rustix::fs::{AtFlags, Mode, RenameFlags, mkdirat, renameat_with, unlinkat};

    if files.is_empty() || files.len() > MAX_DIRECTORY_ENTRIES {
        return Err(CliError::state_corrupt());
    }
    parent.ensure_current()?;
    let temporary = format!(
        ".cigar-beta-transition-{}-{}",
        std::process::id(),
        random_suffix()?
    );
    mkdirat(
        &parent.directory,
        temporary.as_str(),
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|_error| CliError::state_unavailable())?;
    let staging = open_private_directory_at(&parent.directory, OsStr::new(&temporary), 0o700)?;
    let mut created_names = Vec::new();
    let mut published = false;
    let result = (|| {
        for specification in files {
            create_private_file_at(
                &staging,
                specification.name,
                specification.bytes,
                specification.mode,
            )?;
            created_names.push(specification.name);
        }
        staging
            .sync_all()
            .map_err(|_error| CliError::state_unavailable())?;
        // Establish the final directory mode before the atomic publication. A
        // crash after rename must never expose an intermediate permission
        // state. The cleanup path restores 0700 if NOREPLACE loses a race.
        staging
            .set_permissions(std::fs::Permissions::from_mode(final_mode))
            .map_err(|_error| CliError::state_unavailable())?;
        staging
            .sync_all()
            .map_err(|_error| CliError::state_unavailable())?;
        parent.ensure_current()?;
        match renameat_with(
            &parent.directory,
            temporary.as_str(),
            &parent.directory,
            &parent.name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                published = true;
                parent
                    .directory
                    .sync_all()
                    .map_err(|_error| CliError::state_unavailable())?;
                parent.ensure_current()?;
                Ok(PublishStatus::Created)
            }
            Err(error) if error == rustix::io::Errno::EXIST => Ok(PublishStatus::AlreadyExists),
            Err(_error) => Err(CliError::state_unavailable()),
        }
    })();
    if !published {
        // Keep best-effort cleanup owner-writable so a no-replace race cannot accumulate
        // transition directories in the publication parent.
        let _ignored = staging.set_permissions(std::fs::Permissions::from_mode(0o700));
        let _ignored = staging.sync_all();
        for name in created_names {
            let _ignored = unlinkat(&staging, name, AtFlags::empty());
        }
        drop(staging);
        let _ignored = unlinkat(&parent.directory, temporary.as_str(), AtFlags::REMOVEDIR);
        let _ignored = parent.directory.sync_all();
    }
    result
}

fn create_private_file_at(
    directory: &File,
    name: &str,
    bytes: &[u8],
    final_mode: u32,
) -> Result<(), CliError> {
    use rustix::fs::{Mode, OFlags, openat};

    let owned = openat(
        directory,
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_error| CliError::state_unavailable())?;
    let mut file = File::from(owned);
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_error| CliError::state_unavailable())?;
    let initial = file
        .metadata()
        .map_err(|_error| CliError::state_unavailable())?;
    if !initial.is_file()
        || initial.uid() != rustix::process::geteuid().as_raw()
        || initial.mode() & 0o777 != 0o600
        || initial.nlink() != 1
        || initial.len() != 0
    {
        return Err(CliError::state_corrupt());
    }
    file.write_all(bytes)
        .map_err(|_error| CliError::state_unavailable())?;
    file.sync_all()
        .map_err(|_error| CliError::state_unavailable())?;
    file.set_permissions(std::fs::Permissions::from_mode(final_mode))
        .map_err(|_error| CliError::state_unavailable())?;
    file.sync_all()
        .map_err(|_error| CliError::state_unavailable())?;
    validate_private_file_metadata(
        &file
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?,
        u64::try_from(bytes.len()).map_err(|_error| CliError::state_corrupt())?,
        final_mode,
    )
}

fn open_private_directory(path: &Path, mode: u32) -> Result<File, CliError> {
    validate_absolute_path(path)?;
    let directory = open_safe_directory_chain(path)?;
    validate_private_directory_metadata(
        &directory
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?,
        mode,
    )?;
    Ok(directory)
}

fn open_private_directory_at(parent: &File, name: &OsStr, mode: u32) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, openat};

    let directory = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::state_unavailable())?;
    validate_private_directory_metadata(
        &directory
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?,
        mode,
    )?;
    Ok(directory)
}

fn open_safe_directory_chain(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open, openat};

    validate_absolute_directory_path(path)?;
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::state_unavailable())?;
    validate_safe_ancestor(
        &directory
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?,
    )?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(|_error| CliError::state_unavailable())?;
                validate_safe_ancestor(
                    &directory
                        .metadata()
                        .map_err(|_error| CliError::state_unavailable())?,
                )?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(CliError::invalid_input());
            }
        }
    }
    Ok(directory)
}

fn validate_absolute_directory_path(path: &Path) -> Result<(), CliError> {
    if path == Path::new("/") {
        Ok(())
    } else {
        validate_absolute_path(path)
    }
}

fn validate_safe_ancestor(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if !metadata.is_dir()
        || (owner != 0 && owner != rustix::process::geteuid().as_raw())
        || (writable_by_others && !protected_sticky_root)
    {
        Err(CliError::state_unavailable())
    } else {
        Ok(())
    }
}

fn validate_publication_parent(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    validate_safe_ancestor(metadata)?;
    let protected_sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    if metadata.uid() != rustix::process::geteuid().as_raw() && !protected_sticky_root {
        return Err(CliError::state_unavailable());
    }
    Ok(())
}

fn validate_private_directory_metadata(
    metadata: &std::fs::Metadata,
    expected_mode: u32,
) -> Result<(), CliError> {
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != expected_mode
        || metadata.nlink() < 2
    {
        Err(CliError::state_corrupt())
    } else {
        Ok(())
    }
}

fn validate_private_file_metadata(
    metadata: &std::fs::Metadata,
    maximum: u64,
    expected_mode: u32,
) -> Result<(), CliError> {
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        Err(CliError::state_corrupt())
    } else {
        Ok(())
    }
}

fn read_private_file_at(
    directory: &File,
    name: &str,
    maximum: u64,
    expected_mode: u32,
) -> Result<Vec<u8>, CliError> {
    use rustix::fs::{Mode, OFlags, openat};

    let mut file = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::state_corrupt())?;
    let before = file
        .metadata()
        .map_err(|_error| CliError::state_unavailable())?;
    validate_private_file_metadata(&before, maximum, expected_mode)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_error| CliError::state_corrupt())?,
    );
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::state_unavailable())?;
    let after = file
        .metadata()
        .map_err(|_error| CliError::state_unavailable())?;
    validate_private_file_metadata(&after, maximum, expected_mode)?;
    if u64::try_from(bytes.len()).ok() != Some(before.len()) || !same_file_state(&before, &after) {
        return Err(CliError::state_corrupt());
    }
    Ok(bytes)
}

fn same_file_state(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
}

fn require_exact_entries(directory: &File, expected: &[&str]) -> Result<(), CliError> {
    let observed = list_directory_names(directory)?;
    let expected = expected.iter().map(OsString::from).collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(CliError::state_corrupt());
    }
    Ok(())
}

fn list_directory_names(directory: &File) -> Result<BTreeSet<OsString>, CliError> {
    let mut stream =
        rustix::fs::Dir::read_from(directory).map_err(|_error| CliError::state_unavailable())?;
    let mut names = BTreeSet::new();
    while let Some(entry) = stream.read() {
        let entry = entry.map_err(|_error| CliError::state_unavailable())?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.insert(OsString::from_vec(bytes.to_vec()));
        if names.len() > MAX_DIRECTORY_ENTRIES {
            return Err(CliError::state_corrupt());
        }
    }
    Ok(names)
}

fn entry_exists(directory: &File, name: &OsStr) -> Result<bool, CliError> {
    use rustix::fs::{AtFlags, statat};

    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_metadata) => Ok(true),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(_error) => Err(CliError::state_unavailable()),
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut value, "{byte:02x}");
    }
    value
}

fn random_suffix() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_error| CliError::state_unavailable())?;
    let mut suffix = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut suffix, "{byte:02x}").map_err(|_error| CliError::state_unavailable())?;
    }
    Ok(suffix)
}

#[cfg(test)]
mod tests {
    use super::{
        FileSpec, ParentBinding, PublishStatus, list_directory_names, open_safe_directory_chain,
        publish_directory,
    };
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn no_replace_race_cleans_staging_directory() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = std::fs::canonicalize(temporary.path())?;
        let final_path = root.join("already-published");
        std::fs::create_dir(&final_path)?;
        std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o700))?;
        let binding = ParentBinding::for_publication(&final_path)?;
        let status = publish_directory(
            &binding,
            &[FileSpec {
                name: "source-state.json",
                bytes: b"complete",
                mode: 0o400,
            }],
            0o700,
        )?;
        assert_eq!(status, PublishStatus::AlreadyExists);
        let names = list_directory_names(&open_safe_directory_chain(&root)?)?;
        assert!(names.iter().all(|name| {
            !name
                .to_string_lossy()
                .starts_with(".cigar-beta-transition-")
        }));
        Ok(())
    }

    #[test]
    fn file_creation_failure_leaves_no_partial_final_or_staging_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = std::fs::canonicalize(temporary.path())?;
        let final_path = root.join("must-remain-absent");
        let binding = ParentBinding::for_publication(&final_path)?;
        let result = publish_directory(
            &binding,
            &[
                FileSpec {
                    name: "duplicate",
                    bytes: b"first",
                    mode: 0o400,
                },
                FileSpec {
                    name: "duplicate",
                    bytes: b"second",
                    mode: 0o400,
                },
            ],
            0o700,
        );
        assert!(result.is_err());
        assert!(!final_path.exists());
        let names = list_directory_names(&open_safe_directory_chain(&root)?)?;
        assert!(names.iter().all(|name| {
            !name
                .to_string_lossy()
                .starts_with(".cigar-beta-transition-")
        }));
        Ok(())
    }
}
