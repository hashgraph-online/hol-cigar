//! Process-death qualification for the distinct-target SQLite v4-to-v5 workflow.

#![cfg(all(feature = "migration-fault-injection", unix))]

use cigar_crypto::{
    CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef,
    SecretBytes,
};
use cigar_protocol::{
    AtomPayload, BlobRef, ContentDigest, ContextAtomV1, LineageId, MediaType, RecordId, VersionId,
};
use cigar_store::migrate_v5::{
    MigrationActivationPathsV5, MigrationCleanupPathsV5, MigrationPathsV5,
    MigrationReceiptIdentity, MigrationV5Failpoint, RevisionCompactionPathsV1,
    activate_v5_migration, cleanup_incomplete_v5_target, create_revision_compaction_preview_v1,
    execute_revision_compaction_v1, migrate_v4_to_v5, migration_v5_process_abort_boundary,
    preflight_v4_to_v5_migration, read_active_store_descriptor_v1, sign_migration_receipt_v1,
};
use cigar_store::{
    AccessContext, BACKUP_EFFECT_CHECKPOINT_FILE, BackupErrorCode, BackupIdentity, Repository,
    ServiceExpectedVersion, ServiceRepository, SqliteStore, StoreRevision, WorkerLocator,
    WorkerUpdate, WriteTransaction, create_backup_with_effect_checkpoint,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

const CHILD_ROOT: &str = "CIGAR_MIGRATION_V5_PROCESS_ROOT";
const CHILD_RESUME: &str = "CIGAR_MIGRATION_V5_PROCESS_RESUME";
const CHILD_SETUP: &str = "CIGAR_MIGRATION_V5_PROCESS_SETUP";
const CHILD_LOGICAL_50_GIB: &str = "CIGAR_MIGRATION_V5_LOGICAL_50_GIB";
const CHILD_COMPACTION_SETUP: &str = "CIGAR_COMPACTION_V5_PROCESS_SETUP";
const ABORT_STAGE: &str = "CIGAR_MIGRATION_V5_PROCESS_ABORT_STAGE";
const TENANT: &str = "migration-process-tenant";
const SIGNER: &str = "migration-process-operator";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    source_database_digest: String,
    source_anchor_digest: String,
    backup_tree_digest: String,
    signing_key: String,
    source_revision: u64,
    referenced_blob_bytes: u64,
}

fn passphrase() -> SecretBytes {
    SecretBytes::new(b"migration-v5-process-passphrase-32".to_vec())
}

fn paths(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let source = root.join("source.sqlite3");
    let backup = root.join("verified-backup");
    let target = root.join("target.sqlite3");
    let receipt = PathBuf::from(format!("{}.cigar-migration-receipt.json", target.display()));
    let descriptor = root.join("active-store.json");
    let keystore = root.join("keys.cigar");
    (source, backup, target, receipt, descriptor, keystore)
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("missing parent")?)?.sync_all()?;
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn tree_digest(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push(path);
            } else {
                return Err("unexpected backup entry type".into());
            }
        }
    }
    files.sort();
    let mut hash = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(root)?.to_str().ok_or("non-UTF-8 path")?;
        let bytes = fs::read(&file)?;
        hash.update((relative.len() as u64).to_be_bytes());
        hash.update(relative.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(hex_digest(&hash.finalize()))
}

fn source_anchor(source: &Path) -> PathBuf {
    PathBuf::from(format!("{}.cigar-revision", source.display()))
}

fn evidence_path(root: &Path) -> PathBuf {
    root.join("evidence.json")
}

fn read_evidence(root: &Path) -> Result<Evidence, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(evidence_path(root))?)?)
}

fn assert_evidence_unchanged(root: &Path) -> Result<Evidence, Box<dyn std::error::Error>> {
    let (source, backup, _target, _receipt, _descriptor, _keystore) = paths(root);
    let evidence = read_evidence(root)?;
    assert_eq!(file_digest(&source)?, evidence.source_database_digest);
    assert_eq!(
        file_digest(&source_anchor(&source))?,
        evidence.source_anchor_digest
    );
    assert_eq!(tree_digest(&backup)?, evidence.backup_tree_digest);
    let connection = Connection::open_with_flags(&source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    assert_eq!(
        connection.query_row(
            "SELECT MAX(revision) FROM cigar_repository_revisions_v4",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        i64::try_from(evidence.source_revision)?
    );
    assert_eq!(
        connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
        "ok"
    );
    assert_eq!(
        connection.query_row(
            "SELECT referenced_blob_bytes FROM cigar_repository_revisions_v4
             ORDER BY revision DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        i64::try_from(evidence.referenced_blob_bytes)?
    );
    Ok(evidence)
}

fn create_fixture(
    root: &Path,
    logical_50_gib: bool,
    compaction_revisions: bool,
) -> Result<Evidence, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let (source, backup, _target, _receipt, _descriptor, keystore_path) = paths(root);
    let provider = EncryptedDevelopmentKeystore::open(&keystore_path, passphrase())?;
    let signing = provider.create(CreateKeyRequest {
        tenant: TENANT.to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let store = SqliteStore::open(&source)?;
    let locator = WorkerLocator::new(
        RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?,
        "migration-process-worker",
    )?;
    store.worker_update(
        &locator,
        WorkerUpdate::Claim {
            expected: ServiceExpectedVersion::Absent,
            owner: "migration-process".to_owned(),
            now_unix_nanos: 1,
            expires_at_unix_nanos: 100,
        },
        &cigar_store::CancellationToken::default(),
    )?;
    if logical_50_gib {
        let fixture = cigar_testkit::deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing ContextAtomV1 fixture")?;
        let template: ContextAtomV1 = serde_json::from_value(fixture.input)?;
        let context = AccessContext::new(template.scope.tenant_id.clone(), "logical-50-gib")?;
        let mut atoms = Vec::with_capacity(50);
        for index in 1_u64..=50 {
            let mut atom = template.clone();
            atom.atom_id =
                RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{:012x}", index + 1_000))?;
            atom.lineage_id =
                LineageId::new(format!("01890f47-8e7d-7b42-a1d2-{:012x}", index + 2_000))?;
            let digest = ContentDigest::new(format!("1220{:064x}", index + 3_000))?;
            atom.version_id = VersionId::new(digest.as_str().to_owned())?;
            atom.content_digest = digest.clone();
            atom.payload = AtomPayload::Blob(BlobRef {
                digest,
                size_bytes: 1_073_741_824,
                media_type: MediaType::new("application/octet-stream")?,
            });
            atoms.push(atom);
        }
        let mut write = store.begin_write(
            context,
            StoreRevision(1),
            cigar_store::CancellationToken::default(),
        )?;
        write.publish_atoms(atoms, Vec::new())?;
        assert_eq!(write.commit(None)?.revision, StoreRevision(2));
    }
    store.worker_update(
        &locator,
        WorkerUpdate::Checkpoint {
            expected: ServiceExpectedVersion::Version(1),
            owner: "migration-process".to_owned(),
            fencing_token: 1,
            cursor: b"revision-two".to_vec(),
            heartbeat_unix_nanos: 2,
            expires_at_unix_nanos: 100,
        },
        &cigar_store::CancellationToken::default(),
    )?;
    if compaction_revisions {
        for version in 3_u64..=260 {
            store.worker_update(
                &locator,
                WorkerUpdate::Checkpoint {
                    expected: ServiceExpectedVersion::Version(version - 1),
                    owner: "migration-process".to_owned(),
                    fencing_token: 1,
                    cursor: version.to_be_bytes().to_vec(),
                    heartbeat_unix_nanos: version,
                    expires_at_unix_nanos: 1_000 + version,
                },
                &cigar_store::CancellationToken::default(),
            )?;
        }
        assert_eq!(store.revision()?, StoreRevision(260));
    }
    let blobs = root.join("blobs");
    fs::create_dir(&blobs)?;
    create_backup_with_effect_checkpoint(
        &store,
        &blobs,
        &backup,
        &provider,
        BackupIdentity {
            signing_key: &signing.key_ref,
            tenant: TENANT,
            signer: SIGNER,
            created_at_unix_nanos: 3,
        },
        |_database, checkpoint| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(checkpoint)
                .map_err(|_error| BackupErrorCode::Unavailable)?;
            file.write_all(b"migration-process-checkpoint")
                .and_then(|()| file.sync_all())
                .map_err(|_error| BackupErrorCode::Unavailable)
        },
    )?;
    let source_revision = store.revision()?.0;
    let referenced_blob_bytes = store.catalog_statistics()?.referenced_blob_bytes;
    if logical_50_gib {
        assert_eq!(referenced_blob_bytes, 53_687_091_200);
    }
    drop(store);
    drop(preflight_v4_to_v5_migration(
        MigrationPathsV5::resolve(&source, &backup, root.join("warm-target.sqlite3"))?,
        &provider,
        4,
        |_identity| true,
    )?);
    let evidence = Evidence {
        source_database_digest: file_digest(&source)?,
        source_anchor_digest: file_digest(&source_anchor(&source))?,
        backup_tree_digest: tree_digest(&backup)?,
        signing_key: signing.key_ref.as_str().to_owned(),
        source_revision,
        referenced_blob_bytes,
    };
    private_write(&evidence_path(root), &serde_json::to_vec(&evidence)?)?;
    Ok(evidence)
}

fn finish_migration(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (source, backup, target, receipt, descriptor, keystore_path) = paths(root);
    let evidence = read_evidence(root)?;
    let provider = EncryptedDevelopmentKeystore::open(&keystore_path, passphrase())?;
    let signing_key = KeyRef::new(evidence.signing_key)?;
    let preflight = preflight_v4_to_v5_migration(
        MigrationPathsV5::resolve(&source, &backup, &target)?,
        &provider,
        10,
        |_identity| true,
    )?;
    let report = migrate_v4_to_v5(preflight, 11)?;
    let signed = sign_migration_receipt_v1(
        report.completed_receipt(),
        &provider,
        MigrationReceiptIdentity {
            signing_key: &signing_key,
            tenant: TENANT,
            signer: SIGNER,
        },
    )?;
    private_write(&receipt, &serde_json::to_vec(&signed)?)?;
    migration_v5_process_abort_boundary(MigrationV5Failpoint::AfterReceiptPublication);
    activate_v5_migration(
        MigrationActivationPathsV5::resolve(&source, &backup, &target, &receipt, &descriptor)?,
        &provider,
        12,
        |_identity| true,
        |_identity| true,
    )?;
    Ok(())
}

fn compaction_paths(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        root.join("compaction-preview.json"),
        root.join("compacted.sqlite3"),
        root.join("compacted.sqlite3.cigar-compaction-receipt.json"),
    )
}

fn setup_compaction(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    create_fixture(root, false, true)?;
    finish_migration(root)?;
    let (_source, _backup, target, migration_receipt, descriptor, keystore_path) = paths(root);
    let (preview_path, compacted_target, _compaction_receipt) = compaction_paths(root);
    let evidence = read_evidence(root)?;
    let provider = EncryptedDevelopmentKeystore::open(&keystore_path, passphrase())?;
    let signing_key = KeyRef::new(evidence.signing_key)?;
    let signed_preview = create_revision_compaction_preview_v1(
        RevisionCompactionPathsV1::resolve(
            &target,
            &migration_receipt,
            &compacted_target,
            &descriptor,
            &preview_path,
        )?,
        &provider,
        20,
        10_000,
        MigrationReceiptIdentity {
            signing_key: &signing_key,
            tenant: TENANT,
            signer: SIGNER,
        },
        |_identity| true,
    )?;
    assert_eq!(signed_preview.preview_candidate_revisions(), 5);
    assert_eq!(
        signed_preview.preview_compacted_first_revision(),
        StoreRevision(5)
    );
    private_write(&preview_path, &serde_json::to_vec(&signed_preview)?)?;
    Ok(())
}

fn finish_compaction(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (_source, _backup, _target, _receipt, _descriptor, keystore_path) = paths(root);
    let (preview_path, _compacted_target, _compaction_receipt) = compaction_paths(root);
    let evidence = read_evidence(root)?;
    let provider = EncryptedDevelopmentKeystore::open(&keystore_path, passphrase())?;
    let signing_key = KeyRef::new(evidence.signing_key)?;
    let report = execute_revision_compaction_v1(
        &preview_path,
        &provider,
        21,
        MigrationReceiptIdentity {
            signing_key: &signing_key,
            tenant: TENANT,
            signer: SIGNER,
        },
        |_identity| true,
    )?;
    assert_eq!(report.removed_revisions, 5);
    assert_eq!(report.retained_revisions, 256);
    assert_eq!(report.compacted_first_revision, StoreRevision(5));
    Ok(())
}

#[test]
fn migration_v5_abort_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    if std::env::var(CHILD_SETUP).as_deref() == Ok("1") {
        create_fixture(
            &root,
            std::env::var(CHILD_LOGICAL_50_GIB).as_deref() == Ok("1"),
            false,
        )?;
        return Ok(());
    }
    if std::env::var(CHILD_RESUME).as_deref() == Ok("1") {
        return finish_migration(&root);
    }
    finish_migration(&root)?;
    Err("configured migration failpoint was not reached".into())
}

#[test]
fn compaction_v5_abort_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    if std::env::var(CHILD_COMPACTION_SETUP).as_deref() == Ok("1") {
        setup_compaction(&root)?;
        return Ok(());
    }
    finish_compaction(&root)?;
    if std::env::var(ABORT_STAGE).is_ok() {
        return Err("configured compaction failpoint was not reached".into());
    }
    Ok(())
}

fn run_setup_child(
    executable: &Path,
    root: &Path,
    logical_50_gib: bool,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    let mut command = Command::new(executable);
    command
        .args(["--exact", "migration_v5_abort_child", "--nocapture"])
        .env(CHILD_ROOT, root)
        .env(CHILD_SETUP, "1");
    if logical_50_gib {
        command.env(CHILD_LOGICAL_50_GIB, "1");
    }
    Ok(command.status()?)
}

fn run_child(
    executable: &Path,
    root: &Path,
    stage: Option<&str>,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    let mut command = Command::new(executable);
    command
        .args(["--exact", "migration_v5_abort_child", "--nocapture"])
        .env(CHILD_ROOT, root);
    if let Some(stage) = stage {
        command.env(ABORT_STAGE, stage);
    } else {
        command.env(CHILD_RESUME, "1");
    }
    Ok(command.status()?)
}

fn run_compaction_child(
    executable: &Path,
    root: &Path,
    setup: bool,
    stage: Option<&str>,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    let mut command = Command::new(executable);
    command
        .args(["--exact", "compaction_v5_abort_child", "--nocapture"])
        .env(CHILD_ROOT, root);
    if setup {
        command.env(CHILD_COMPACTION_SETUP, "1");
    }
    if let Some(stage) = stage {
        command.env(ABORT_STAGE, stage);
    }
    Ok(command.status()?)
}

fn qualify_boundary(
    executable: &Path,
    boundary: MigrationV5Failpoint,
    logical_50_gib: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = fs::canonicalize(directory.path())?;
    let stage = boundary.stage_name();
    assert!(run_setup_child(executable, &root, logical_50_gib)?.success());
    let status = run_child(executable, &root, Some(&stage))?;
    assert!(!status.success(), "failpoint did not kill at {stage}");
    let evidence = assert_evidence_unchanged(&root)?;
    if logical_50_gib {
        assert_eq!(evidence.source_revision, 3);
    }
    let (source, backup, target, receipt, descriptor, keystore_path) = paths(&root);
    let provider = EncryptedDevelopmentKeystore::open(&keystore_path, passphrase())?;
    match boundary {
        MigrationV5Failpoint::AfterBackupVerification => {
            assert!(!target.exists());
            assert!(run_child(executable, &root, None)?.success());
        }
        MigrationV5Failpoint::AfterTargetCreation
        | MigrationV5Failpoint::AfterRevisionBatch(_)
        | MigrationV5Failpoint::AfterDeepVerification
        | MigrationV5Failpoint::AfterTargetFsync
        | MigrationV5Failpoint::AfterAnchorPublication => {
            assert!(target.exists());
            let cleanup = cleanup_incomplete_v5_target(
                MigrationCleanupPathsV5::resolve(&source, &backup, &target, &descriptor)?,
                &provider,
                20,
                |_identity| true,
            )?;
            assert!(cleanup.removed_files >= 2);
            assert!(!target.exists());
            assert!(run_child(executable, &root, None)?.success());
        }
        MigrationV5Failpoint::AfterReceiptPublication
        | MigrationV5Failpoint::AfterActivationIntent => {
            assert!(receipt.exists());
            assert!(!descriptor.exists());
            let signing_key = KeyRef::new(evidence.signing_key)?;
            let activation = activate_v5_migration(
                MigrationActivationPathsV5::resolve(
                    &source,
                    &backup,
                    &target,
                    &receipt,
                    &descriptor,
                )?,
                &provider,
                21,
                |_identity| true,
                |identity| identity.signing_key == signing_key,
            )?;
            assert_eq!(activation.generation, 1);
        }
        MigrationV5Failpoint::AfterActivationSwitch => {
            assert_eq!(
                read_active_store_descriptor_v1(&descriptor)?.generation(),
                1
            );
            let activation = activate_v5_migration(
                MigrationActivationPathsV5::resolve(
                    &source,
                    &backup,
                    &target,
                    &receipt,
                    &descriptor,
                )?,
                &provider,
                22,
                |_identity| true,
                |_identity| true,
            )?;
            assert_eq!(activation.generation, 2);
        }
        MigrationV5Failpoint::AfterCompactionPreviewVerification
        | MigrationV5Failpoint::AfterCompactionTargetCopy
        | MigrationV5Failpoint::AfterCompactionLogicalReclamation
        | MigrationV5Failpoint::AfterCompactionPhysicalReclamation
        | MigrationV5Failpoint::AfterCompactionReceiptPublication => {
            return Err("compaction boundary passed to migration qualifier".into());
        }
    }
    assert!(descriptor.exists());
    assert_evidence_unchanged(&root)?;
    assert_eq!(
        fs::read(backup.join(BACKUP_EFFECT_CHECKPOINT_FILE))?,
        b"migration-process-checkpoint"
    );
    Ok(())
}

fn qualify_compaction_boundary(
    executable: &Path,
    boundary: MigrationV5Failpoint,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = fs::canonicalize(directory.path())?;
    assert!(run_compaction_child(executable, &root, true, None)?.success());
    let (_source, _backup, migration_target, _migration_receipt, descriptor, _keystore) =
        paths(&root);
    let (_preview, compacted_target, compaction_receipt) = compaction_paths(&root);
    let migration_target_digest = file_digest(&migration_target)?;
    let source_statistics = SqliteStore::v5_retention_statistics_at(&migration_target)?;
    assert_eq!(
        source_statistics.reconstructable_last_revision,
        StoreRevision(260)
    );
    assert_eq!(source_statistics.retained_revisions, 261);
    assert_eq!(
        read_active_store_descriptor_v1(&descriptor)?.generation(),
        1
    );

    let stage = boundary.stage_name();
    let status = run_compaction_child(executable, &root, false, Some(&stage))?;
    assert!(!status.success(), "failpoint did not kill at {stage}");
    assert_evidence_unchanged(&root)?;
    assert_eq!(file_digest(&migration_target)?, migration_target_digest);

    let digest_after_receipt = if compaction_receipt.exists() {
        Some(file_digest(&compacted_target)?)
    } else {
        None
    };
    match boundary {
        MigrationV5Failpoint::AfterCompactionPreviewVerification => {
            assert!(!compacted_target.exists());
            assert!(!compaction_receipt.exists());
        }
        MigrationV5Failpoint::AfterCompactionTargetCopy
        | MigrationV5Failpoint::AfterCompactionLogicalReclamation
        | MigrationV5Failpoint::AfterCompactionPhysicalReclamation => {
            assert!(compacted_target.exists());
            assert!(!compaction_receipt.exists());
            assert_eq!(
                read_active_store_descriptor_v1(&descriptor)?.database_path(),
                migration_target.to_str().ok_or("migration target")?
            );
        }
        MigrationV5Failpoint::AfterCompactionReceiptPublication
        | MigrationV5Failpoint::AfterActivationIntent => {
            assert!(compaction_receipt.exists());
            assert_eq!(
                read_active_store_descriptor_v1(&descriptor)?.database_path(),
                migration_target.to_str().ok_or("migration target")?
            );
        }
        MigrationV5Failpoint::AfterActivationSwitch => {
            assert!(compaction_receipt.exists());
            assert_eq!(
                read_active_store_descriptor_v1(&descriptor)?.database_path(),
                compacted_target.to_str().ok_or("compacted target")?
            );
        }
        MigrationV5Failpoint::AfterBackupVerification
        | MigrationV5Failpoint::AfterTargetCreation
        | MigrationV5Failpoint::AfterRevisionBatch(_)
        | MigrationV5Failpoint::AfterTargetFsync
        | MigrationV5Failpoint::AfterAnchorPublication
        | MigrationV5Failpoint::AfterDeepVerification
        | MigrationV5Failpoint::AfterReceiptPublication => {
            return Err("migration boundary passed to compaction qualifier".into());
        }
    }
    assert!(run_compaction_child(executable, &root, false, None)?.success());
    assert_evidence_unchanged(&root)?;
    assert_eq!(file_digest(&migration_target)?, migration_target_digest);
    if let Some(digest) = digest_after_receipt {
        assert_eq!(file_digest(&compacted_target)?, digest);
    }
    let active = read_active_store_descriptor_v1(&descriptor)?;
    assert_eq!(active.generation(), 2);
    assert_eq!(
        active.database_path(),
        compacted_target.to_str().ok_or("compacted target")?
    );
    let compacted_statistics = SqliteStore::v5_retention_statistics_at(&compacted_target)?;
    assert_eq!(
        compacted_statistics.reconstructable_first_revision,
        StoreRevision(5)
    );
    assert_eq!(
        compacted_statistics.reconstructable_last_revision,
        StoreRevision(260)
    );
    assert_eq!(compacted_statistics.retained_revisions, 256);
    assert_eq!(
        compacted_statistics.chain_head,
        source_statistics.chain_head
    );
    Ok(())
}

#[test]
fn every_migration_process_boundary_is_target_only_and_recoverable()
-> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    for boundary in [
        MigrationV5Failpoint::AfterBackupVerification,
        MigrationV5Failpoint::AfterTargetCreation,
        MigrationV5Failpoint::AfterRevisionBatch(StoreRevision(0)),
        MigrationV5Failpoint::AfterRevisionBatch(StoreRevision(1)),
        MigrationV5Failpoint::AfterRevisionBatch(StoreRevision(2)),
        MigrationV5Failpoint::AfterDeepVerification,
        MigrationV5Failpoint::AfterTargetFsync,
        MigrationV5Failpoint::AfterAnchorPublication,
        MigrationV5Failpoint::AfterReceiptPublication,
        MigrationV5Failpoint::AfterActivationIntent,
        MigrationV5Failpoint::AfterActivationSwitch,
    ] {
        qualify_boundary(&executable, boundary, false)?;
    }
    Ok(())
}

#[test]
fn every_compaction_process_boundary_is_exactly_resumable() -> Result<(), Box<dyn std::error::Error>>
{
    let executable = std::env::current_exe()?;
    for boundary in [
        MigrationV5Failpoint::AfterCompactionPreviewVerification,
        MigrationV5Failpoint::AfterCompactionTargetCopy,
        MigrationV5Failpoint::AfterCompactionLogicalReclamation,
        MigrationV5Failpoint::AfterCompactionPhysicalReclamation,
        MigrationV5Failpoint::AfterCompactionReceiptPublication,
        MigrationV5Failpoint::AfterActivationIntent,
        MigrationV5Failpoint::AfterActivationSwitch,
    ] {
        qualify_compaction_boundary(&executable, boundary)?;
    }
    Ok(())
}

#[test]
fn logical_fifty_gib_fixture_passes_the_migration_crash_campaign()
-> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    for boundary in [
        MigrationV5Failpoint::AfterBackupVerification,
        MigrationV5Failpoint::AfterTargetCreation,
        MigrationV5Failpoint::AfterRevisionBatch(StoreRevision(3)),
        MigrationV5Failpoint::AfterDeepVerification,
        MigrationV5Failpoint::AfterTargetFsync,
        MigrationV5Failpoint::AfterAnchorPublication,
        MigrationV5Failpoint::AfterReceiptPublication,
        MigrationV5Failpoint::AfterActivationIntent,
        MigrationV5Failpoint::AfterActivationSwitch,
    ] {
        qualify_boundary(&executable, boundary, true)?;
    }
    Ok(())
}
