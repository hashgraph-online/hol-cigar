//! Full-CLI boundary checks for frozen beta-state inspection.

#![cfg(all(feature = "full", unix))]

use cigar_cli::{TerminalContext, run};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;

fn fixture(name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/beta-state-v0.1.0-beta.1")
            .join(name),
    )
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn full_cli_emits_only_a_bound_read_only_plan_and_preserves_the_file()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let state = root.join("beta-state.json");
    let config = root.join("cli.toml");
    let bytes = fixture("valid.json")?;
    std::fs::write(&state, &bytes)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\ntarget = \"local\"\nproject_state_directory = {}\n",
            serde_json::to_string(&root.join("full-state").display().to_string())?
        ),
    )?;

    let outcome = run(
        vec![
            OsString::from("state"),
            OsString::from("inspect-beta"),
            state.clone().into_os_string(),
            OsString::from("--config"),
            config.into_os_string(),
            OsString::from("--output"),
            OsString::from("json"),
        ],
        TerminalContext::default(),
    )
    .await;

    assert_eq!(outcome.status, 0, "{}", outcome.stderr);
    assert!(outcome.stderr.is_empty());
    assert_eq!(std::fs::read(&state)?, bytes);
    let output: serde_json::Value = serde_json::from_str(&outcome.stdout)?;
    assert_eq!(
        output
            .pointer("/result/source/sha256")
            .and_then(|value| value.as_str()),
        Some(hex_sha256(&bytes).as_str())
    );
    assert_eq!(
        output.pointer("/result/source/byte_count"),
        Some(&serde_json::json!(bytes.len()))
    );
    assert_eq!(
        output.pointer("/result/source/generation"),
        Some(&serde_json::json!(41))
    );
    assert_eq!(
        output.pointer("/result/transition/application/status"),
        Some(&serde_json::json!("explicit-command-required"))
    );
    assert_eq!(
        output.pointer("/result/transition/downgrade/status"),
        Some(&serde_json::json!("blocked"))
    );
    for private_value in [
        "project.alpha",
        "project-beta",
        "source_docs",
        "/Users/example",
        state.to_str().ok_or("state path")?,
    ] {
        assert!(
            !outcome.stdout.contains(private_value),
            "CLI output leaked {private_value}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn full_cli_rejects_hostile_state_without_rewriting_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let state = root.join("hostile.json");
    let bytes = fixture("duplicate-field.json")?;
    std::fs::write(&state, &bytes)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600))?;

    let outcome = run(
        vec![
            OsString::from("state"),
            OsString::from("inspect-beta"),
            state.clone().into_os_string(),
            OsString::from("--local"),
            OsString::from("--output"),
            OsString::from("json"),
        ],
        TerminalContext::default(),
    )
    .await;

    assert_eq!(outcome.status, 65);
    assert!(outcome.stderr.is_empty());
    assert!(outcome.stdout.contains("CLI_BETA_STATE_INVALID"));
    assert_eq!(std::fs::read(state)?, bytes);
    Ok(())
}

#[tokio::test]
async fn full_cli_rejects_any_implied_apply_or_downgrade_arguments()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    let state = root.join("beta-state.json");
    let bytes = fixture("valid-min.json")?;
    std::fs::write(&state, &bytes)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600))?;

    for trailing in ["apply", "downgrade"] {
        let outcome = run(
            vec![
                OsString::from("state"),
                OsString::from("inspect-beta"),
                state.clone().into_os_string(),
                OsString::from(trailing),
                OsString::from("--local"),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(outcome.status, 2, "unexpected acceptance of {trailing}");
        assert!(outcome.stderr.contains("CLI_INVALID_COMMAND"));
        assert_eq!(std::fs::read(&state)?, bytes);
    }

    let confirmed = run(
        vec![
            OsString::from("state"),
            OsString::from("inspect-beta"),
            state.clone().into_os_string(),
            OsString::from("--local"),
            OsString::from("--yes"),
        ],
        TerminalContext::default(),
    )
    .await;
    assert_eq!(confirmed.status, 2);
    assert!(confirmed.stderr.contains("CLI_INVALID_COMMAND"));
    assert_eq!(std::fs::read(state)?, bytes);
    Ok(())
}
