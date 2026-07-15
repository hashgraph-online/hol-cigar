//! Authorization-file boundary tests.

use cigar_sdk::StaticAuthorization;

#[cfg(unix)]
#[test]
fn authorization_file_is_owner_only_descriptor_bound_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    use std::fs::hard_link;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let authorization = root.join("authorization");
    std::fs::write(&authorization, "Bearer explicit-test-value\n")?;
    std::fs::set_permissions(&authorization, std::fs::Permissions::from_mode(0o600))?;
    let provider = StaticAuthorization::from_file(&authorization)?;
    let rendered = format!("{provider:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("explicit-test-value"));

    std::fs::set_permissions(&authorization, std::fs::Permissions::from_mode(0o640))?;
    assert!(StaticAuthorization::from_file(&authorization).is_err());
    std::fs::set_permissions(&authorization, std::fs::Permissions::from_mode(0o600))?;

    let alias = root.join("authorization-hardlink");
    hard_link(&authorization, &alias)?;
    assert!(StaticAuthorization::from_file(&authorization).is_err());
    std::fs::remove_file(alias)?;

    let link = root.join("authorization-symlink");
    symlink(&authorization, &link)?;
    assert!(StaticAuthorization::from_file(&link).is_err());

    let fifo = root.join("authorization-fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success());
    assert!(StaticAuthorization::from_file(&fifo).is_err());
    Ok(())
}

#[test]
fn authorization_file_requires_an_absolute_path() {
    assert!(StaticAuthorization::from_file("relative/authorization").is_err());
}
