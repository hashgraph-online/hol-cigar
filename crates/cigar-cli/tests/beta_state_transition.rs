//! Full-only beta-to-full import, exact-byte recovery, and downgrade-wall checks.

#![cfg(all(feature = "full", unix))]

use cigar_cli::{TerminalContext, run};
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

const IMPORTED_SCHEMA: &str = "cigar.cli-administration.imported-beta.v1";

fn fixture(name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/beta-state-v0.1.0-beta.1")
            .join(name),
    )
}

fn args(values: &[&OsStr]) -> Vec<OsString> {
    values.iter().map(|value| (*value).to_os_string()).collect()
}

fn write_config(path: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(
        path,
        format!(
            "schema_version = 1\ntarget = \"local\"\nproject_state_directory = {}\n",
            serde_json::to_string(&target.display().to_string())?
        ),
    )?;
    Ok(())
}

fn make_source(root: &Path, name: &str) -> Result<(PathBuf, Vec<u8>), Box<dyn std::error::Error>> {
    let source = root.join(name);
    let bytes = fixture("valid.json")?;
    std::fs::write(&source, &bytes)?;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))?;
    Ok((source, bytes))
}

#[tokio::test]
async fn import_publishes_verified_backup_preserves_semantics_and_blocks_in_place_downgrade()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let (source, source_bytes) = make_source(&root, "beta-source.json")?;
    let backup = root.join("transition-backup");
    let target = root.join("full-state");
    let recovery = root.join("beta-recovery");
    let config = root.join("cli.toml");
    write_config(&config, &target)?;

    let outcome = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(outcome.stderr.is_empty());
    assert_eq!(std::fs::read(&source)?, source_bytes);
    assert_eq!(
        std::fs::read(backup.join("source-state.json"))?,
        source_bytes
    );
    assert_eq!(backup.metadata()?.mode() & 0o777, 0o700);
    assert_eq!(
        backup.join("source-state.json").metadata()?.mode() & 0o777,
        0o400
    );
    assert_eq!(
        backup.join("manifest.json").metadata()?.mode() & 0o777,
        0o400
    );
    assert_eq!(backup.join("source-state.json").metadata()?.nlink(), 1);

    let source_document: serde_json::Value = serde_json::from_slice(&source_bytes)?;
    let imported_bytes = std::fs::read(target.join("state.json"))?;
    let imported_document: serde_json::Value = serde_json::from_slice(&imported_bytes)?;
    assert_eq!(
        imported_document.pointer("/schema_version"),
        Some(&serde_json::json!(IMPORTED_SCHEMA))
    );
    for pointer in [
        "/generation",
        "/active_project",
        "/active_focus",
        "/projects",
        "/sources",
        "/links",
    ] {
        assert_eq!(
            imported_document.pointer(pointer),
            source_document.pointer(pointer),
            "semantic field changed at {pointer}"
        );
    }
    assert!(target.join(".beta-transition.json").is_file());

    let rendered: serde_json::Value = serde_json::from_str(&outcome.stdout)?;
    assert_eq!(
        rendered.pointer("/result/downgrade/in_place_status"),
        Some(&serde_json::json!("blocked"))
    );
    assert_eq!(
        rendered.pointer("/result/preservation/source_bytes"),
        Some(&serde_json::json!(true))
    );
    for private in [
        source.to_str().ok_or("source path")?,
        backup.to_str().ok_or("backup path")?,
        target.to_str().ok_or("target path")?,
        "project.alpha",
        "source_docs",
        "/Users/example",
    ] {
        assert!(
            !outcome.stdout.contains(private),
            "receipt leaked {private}"
        );
    }

    let beta_reopen = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("inspect-beta"),
            target.join("state.json").as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(beta_reopen.status, 65);
    assert!(beta_reopen.stdout.contains("CLI_BETA_STATE_INVALID"));

    let retry = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(retry.status, 0, "{}{}", retry.stdout, retry.stderr);
    let retry_document: serde_json::Value = serde_json::from_str(&retry.stdout)?;
    assert_eq!(
        retry_document.pointer("/result/target/idempotent_replay"),
        Some(&serde_json::json!(true))
    );

    let full_read = run(
        args(&[
            OsStr::new("project"),
            OsStr::new("list"),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(
        full_read.status, 0,
        "{}{}",
        full_read.stdout, full_read.stderr
    );
    let full_document: serde_json::Value = serde_json::from_str(&full_read.stdout)?;
    assert_eq!(
        full_document.pointer("/result/generation"),
        Some(&serde_json::json!(41))
    );

    let restore = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("restore-beta"),
            backup.as_os_str(),
            recovery.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(restore.status, 0, "{}{}", restore.stdout, restore.stderr);
    assert_eq!(std::fs::read(recovery.join("state.json"))?, source_bytes);
    assert_eq!(std::fs::read(target.join("state.json"))?, imported_bytes);
    let restore_document: serde_json::Value = serde_json::from_str(&restore.stdout)?;
    assert_eq!(
        restore_document.pointer("/result/downgrade/active_full_target_mutated"),
        Some(&serde_json::json!(false))
    );

    let restored_inspection = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("inspect-beta"),
            recovery.join("state.json").as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(
        restored_inspection.status, 0,
        "{}{}",
        restored_inspection.stdout, restored_inspection.stderr
    );
    let restored_retry = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("restore-beta"),
            backup.as_os_str(),
            recovery.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(
        restored_retry.status, 0,
        "{}{}",
        restored_retry.stdout, restored_retry.stderr
    );
    let restored_retry_document: serde_json::Value = serde_json::from_str(&restored_retry.stdout)?;
    assert_eq!(
        restored_retry_document.pointer("/result/recovery_target/idempotent_replay"),
        Some(&serde_json::json!(true))
    );
    for entry in std::fs::read_dir(&root)? {
        assert!(
            !entry?
                .file_name()
                .to_string_lossy()
                .starts_with(".cigar-beta-transition-")
        );
    }
    Ok(())
}

#[tokio::test]
async fn import_dry_run_and_missing_confirmation_publish_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let (source, source_bytes) = make_source(&root, "source.json")?;
    let backup = root.join("backup");
    let target = root.join("target");
    let config = root.join("cli.toml");
    write_config(&config, &target)?;

    let unconfirmed = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(unconfirmed.status, 2);
    assert!(unconfirmed.stderr.contains("CLI_CONFIRMATION_REQUIRED"));
    assert!(!backup.exists());
    assert!(!target.exists());

    let planned = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--dry-run"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(planned.status, 0, "{}{}", planned.stdout, planned.stderr);
    assert!(!backup.exists());
    assert!(!target.exists());
    assert_eq!(std::fs::read(source)?, source_bytes);
    Ok(())
}

#[tokio::test]
async fn target_conflict_leaves_a_verified_recovery_backup_and_never_overwrites()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let (source, source_bytes) = make_source(&root, "source.json")?;
    let backup = root.join("backup");
    let target = root.join("occupied-target");
    std::fs::create_dir(&target)?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(target.join("do-not-overwrite"), b"sentinel")?;
    let config = root.join("cli.toml");
    write_config(&config, &target)?;

    let outcome = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_ne!(outcome.status, 0);
    assert_eq!(std::fs::read(target.join("do-not-overwrite"))?, b"sentinel");
    assert_eq!(
        std::fs::read(backup.join("source-state.json"))?,
        source_bytes
    );
    assert_eq!(std::fs::read(source)?, source_bytes);
    Ok(())
}

#[tokio::test]
async fn transition_rejects_symlinked_publication_ancestors_and_tampered_backups()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let (source, _source_bytes) = make_source(&root, "source.json")?;
    let real_parent = root.join("real-parent");
    std::fs::create_dir(&real_parent)?;
    std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700))?;
    let linked_parent = root.join("linked-parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent)?;
    let backup = root.join("backup");
    let target = linked_parent.join("target");
    let config = root.join("cli.toml");
    write_config(&config, &target)?;

    let rejected = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_ne!(rejected.status, 0);
    assert!(!backup.exists());
    assert!(!real_parent.join("target").exists());

    let safe_target = root.join("safe-target");
    write_config(&config, &safe_target)?;
    let imported = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(imported.status, 0, "{}{}", imported.stdout, imported.stderr);

    std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(
        backup.join("source-state.json"),
        std::fs::Permissions::from_mode(0o600),
    )?;
    std::fs::write(backup.join("source-state.json"), fixture("valid-min.json")?)?;
    std::fs::set_permissions(
        backup.join("source-state.json"),
        std::fs::Permissions::from_mode(0o400),
    )?;
    std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o700))?;
    let recovery = root.join("recovery");
    let restore = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("restore-beta"),
            backup.as_os_str(),
            recovery.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
            OsStr::new("--output"),
            OsStr::new("json"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(restore.status, 65);
    assert!(restore.stdout.contains("CLI_BETA_STATE_INVALID"));
    assert!(!recovery.exists());
    Ok(())
}

#[tokio::test]
async fn recovery_restore_refuses_the_configured_active_full_target()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let (source, _source_bytes) = make_source(&root, "source.json")?;
    let backup = root.join("backup");
    let target = root.join("target");
    let config = root.join("cli.toml");
    write_config(&config, &target)?;
    let imported = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("import-beta"),
            source.as_os_str(),
            backup.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(imported.status, 0, "{}{}", imported.stdout, imported.stderr);

    let restore = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("restore-beta"),
            backup.as_os_str(),
            target.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(restore.status, 65);
    assert!(restore.stderr.contains("CLI_STATE_CONFLICT"));

    let nested_recovery = target.join("nested-recovery");
    let nested = run(
        args(&[
            OsStr::new("state"),
            OsStr::new("restore-beta"),
            backup.as_os_str(),
            nested_recovery.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--local"),
            OsStr::new("--yes"),
        ]),
        TerminalContext::default(),
    )
    .await;
    assert_eq!(nested.status, 65);
    assert!(nested.stderr.contains("CLI_STATE_CONFLICT"));
    assert!(!nested_recovery.exists());
    Ok(())
}
