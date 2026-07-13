//! Public-boundary checks for the compile-time embedded-local beta surface.

#![cfg(feature = "beta-embedded")]

use cigar_cli::{TerminalContext, progress_start, run};
use std::ffi::OsString;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn public_parser_reaches_every_beta_command_and_no_excluded_command() {
    let terminal = TerminalContext {
        stderr: true,
        ..TerminalContext::default()
    };
    for values in [
        &["init", "--dry-run"][..],
        &["source", "add", "--dry-run"][..],
        &["source", "list"][..],
        &["source", "remove", "--dry-run"][..],
        &["project", "list"][..],
        &["project", "attach", "--dry-run"][..],
        &["project", "detach", "--dry-run"][..],
        &["project", "switch", "--dry-run"][..],
        &["project", "link", "--dry-run"][..],
        &["project", "unlink", "--dry-run"][..],
        &["focus", "switch", "--dry-run"][..],
        &["focus", "close", "--dry-run"][..],
    ] {
        assert!(
            progress_start(&args(values), terminal).is_some(),
            "beta command did not reach the public parser: {values:?}"
        );
    }
    for values in [
        &["status"][..],
        &["context", "compile"][..],
        &["effect", "dispatch"][..],
        &["serve"][..],
        &["mcp", "serve"][..],
        &["plugin", "install"][..],
    ] {
        assert!(
            progress_start(&args(values), terminal).is_none(),
            "excluded command reached the public beta parser: {values:?}"
        );
    }
}

#[tokio::test]
async fn beta_help_does_not_advertise_excluded_capabilities_or_flags() {
    let outcome = run(args(&["help"]), TerminalContext::default()).await;
    assert_eq!(outcome.status, 0);
    for excluded in [
        "cigar status",
        "cigar context",
        "cigar effect",
        "cigar replay",
        "cigar serve",
        "cigar mcp",
        "cigar plugin",
        "--remote",
        "--local",
        "--endpoint",
        "--authorization-file",
        "--security",
        "--deep",
    ] {
        assert!(
            !outcome.stdout.contains(excluded),
            "beta help leaked excluded surface: {excluded}"
        );
    }
}

#[tokio::test]
async fn beta_rejects_undocumented_metadata_and_confirmation_aliases() {
    for invocation in [
        &["--help"][..],
        &["-h"][..],
        &["--version"][..],
        &["-V"][..],
        &["help", "--confirm"][..],
        &["--help", "trailing-token"][..],
        &["--version", "trailing-token"][..],
    ] {
        let outcome = run(args(invocation), TerminalContext::default()).await;
        assert_eq!(
            outcome.status, 2,
            "alias unexpectedly accepted: {invocation:?}"
        );
    }
}

#[tokio::test]
async fn beta_version_reports_the_prerelease_identity() -> Result<(), Box<dyn std::error::Error>> {
    let outcome = run(args(&["version"]), TerminalContext::default()).await;
    assert_eq!(outcome.status, 0);
    let metadata: serde_json::Value = serde_json::from_str(&outcome.stdout)?;
    assert_eq!(
        metadata.get("version").and_then(serde_json::Value::as_str),
        Some("0.1.0-beta.1")
    );
    assert_eq!(
        metadata
            .get("release_profile")
            .and_then(serde_json::Value::as_str),
        Some("cigar.beta.embedded-local.linux-x86_64.v1")
    );
    assert_eq!(
        metadata.get("enabled_features"),
        Some(&serde_json::json!(["beta-embedded"]))
    );
    assert_eq!(
        metadata
            .get("capability_profile")
            .and_then(serde_json::Value::as_str),
        Some("workspace-metadata-only")
    );
    assert_eq!(
        metadata
            .get("production_ready")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        metadata
            .get("qualified_target_triple")
            .and_then(serde_json::Value::as_str),
        Some("x86_64-unknown-linux-gnu")
    );
    assert_eq!(
        metadata
            .get("target_os")
            .and_then(serde_json::Value::as_str),
        Some(std::env::consts::OS)
    );
    assert_eq!(
        metadata
            .get("target_arch")
            .and_then(serde_json::Value::as_str),
        Some(std::env::consts::ARCH)
    );
    assert_eq!(metadata.as_object().map(serde_json::Map::len), Some(13));
    Ok(())
}

#[tokio::test]
async fn beta_configuration_rejects_remote_and_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let config = directory.path().join("beta.toml");
    for document in [
        format!(
            "schema_version = 1\ntarget = \"remote\"\nproject_state_directory = {}\n",
            serde_json::to_string(&state.display().to_string())?
        ),
        format!(
            concat!(
                "schema_version = 1\n",
                "target = \"embedded\"\n",
                "project_state_directory = {}\n",
                "remote_endpoint = \"https://example.test\"\n"
            ),
            serde_json::to_string(&state.display().to_string())?
        ),
    ] {
        std::fs::write(&config, document)?;
        let outcome = run(
            vec![
                OsString::from("source"),
                OsString::from("list"),
                OsString::from("--config"),
                config.clone().into_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(outcome.status, 78);
        assert!(outcome.stdout.contains("CLI_INVALID_CONFIGURATION"));
    }
    Ok(())
}

#[tokio::test]
async fn beta_embedded_state_workflow_is_private_and_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let source = directory.path().join("source");
    let project = directory.path().join("project");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&project)?;
    let config = directory.path().join("beta.toml");
    std::fs::write(
        &config,
        format!(
            concat!(
                "schema_version = 1\n",
                "target = \"embedded\"\n",
                "project_state_directory = {}\n"
            ),
            serde_json::to_string(&state.display().to_string())?
        ),
    )?;
    let shared = [
        OsString::from("--config"),
        config.clone().into_os_string(),
        OsString::from("--yes"),
        OsString::from("--output"),
        OsString::from("json"),
    ];
    for mut invocation in [
        vec![OsString::from("init")],
        vec![
            OsString::from("source"),
            OsString::from("add"),
            OsString::from("docs"),
            source.into_os_string(),
        ],
        vec![
            OsString::from("project"),
            OsString::from("attach"),
            OsString::from("primary"),
            project.into_os_string(),
        ],
    ] {
        invocation.extend(shared.iter().cloned());
        let outcome = run(invocation, TerminalContext::default()).await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
    }
    let state_file = state.join("state.json");
    let document: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_file)?)?;
    assert_eq!(
        document
            .get("generation")
            .and_then(serde_json::Value::as_u64),
        Some(3)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&state)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(state_file)?.permissions().mode() & 0o777,
            0o600
        );
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_beta_mutations_are_serialized_without_lost_updates()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let source = directory.path().join("source");
    std::fs::create_dir(&source)?;
    let config = directory.path().join("beta.toml");
    std::fs::write(
        &config,
        format!(
            concat!(
                "schema_version = 1\n",
                "target = \"embedded\"\n",
                "project_state_directory = {}\n"
            ),
            serde_json::to_string(&state.display().to_string())?
        ),
    )?;
    let initialized = run(
        vec![
            OsString::from("init"),
            OsString::from("--config"),
            config.clone().into_os_string(),
            OsString::from("--yes"),
        ],
        TerminalContext::default(),
    )
    .await;
    assert_eq!(initialized.status, 0, "{}", initialized.stderr);

    let mut mutations = tokio::task::JoinSet::new();
    for index in 0..8 {
        let config = config.clone();
        let source = source.clone();
        mutations.spawn(async move {
            run(
                vec![
                    OsString::from("source"),
                    OsString::from("add"),
                    OsString::from(format!("source-{index}")),
                    source.into_os_string(),
                    OsString::from("--config"),
                    config.into_os_string(),
                    OsString::from("--yes"),
                ],
                TerminalContext::default(),
            )
            .await
        });
    }
    while let Some(completed) = mutations.join_next().await {
        let outcome = completed?;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
    }
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.join("state.json"))?)?;
    assert_eq!(
        document
            .get("generation")
            .and_then(serde_json::Value::as_u64),
        Some(9)
    );
    assert_eq!(
        document
            .get("sources")
            .and_then(serde_json::Value::as_object)
            .map(serde_json::Map::len),
        Some(8)
    );
    Ok(())
}

#[tokio::test]
async fn contended_beta_state_lock_honors_the_complete_command_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let source = directory.path().join("source");
    std::fs::create_dir(&source)?;
    let config = directory.path().join("beta.toml");
    std::fs::write(
        &config,
        format!(
            concat!(
                "schema_version = 1\n",
                "target = \"embedded\"\n",
                "project_state_directory = {}\n"
            ),
            serde_json::to_string(&state.display().to_string())?
        ),
    )?;
    let initialized = run(
        vec![
            OsString::from("init"),
            OsString::from("--config"),
            config.clone().into_os_string(),
            OsString::from("--yes"),
        ],
        TerminalContext::default(),
    )
    .await;
    assert_eq!(initialized.status, 0, "{}", initialized.stderr);

    let held = std::fs::File::open(&state)?;
    held.lock()?;
    let started = std::time::Instant::now();
    let timed_out = run(
        vec![
            OsString::from("source"),
            OsString::from("add"),
            OsString::from("late-update"),
            source.into_os_string(),
            OsString::from("--config"),
            config.clone().into_os_string(),
            OsString::from("--deadline"),
            OsString::from("10ms"),
            OsString::from("--yes"),
        ],
        TerminalContext::default(),
    )
    .await;
    assert_eq!(timed_out.status, 75);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    let recovered = run(
        vec![
            OsString::from("source"),
            OsString::from("list"),
            OsString::from("--config"),
            config.into_os_string(),
            OsString::from("--output"),
            OsString::from("json"),
        ],
        TerminalContext::default(),
    )
    .await;
    assert_eq!(recovered.status, 0, "{}", recovered.stderr);
    let recovered: serde_json::Value = serde_json::from_str(&recovered.stdout)?;
    assert_eq!(
        recovered.pointer("/result/generation"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        recovered.pointer("/result/sources"),
        Some(&serde_json::json!([]))
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn beta_state_and_configuration_reject_unsafe_links_and_modes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let config = directory.path().join("beta.toml");
    std::fs::write(
        &config,
        format!(
            concat!(
                "schema_version = 1\n",
                "target = \"embedded\"\n",
                "project_state_directory = {}\n"
            ),
            serde_json::to_string(&state.display().to_string())?
        ),
    )?;
    let invoke = |command: &[&str]| {
        let mut values = args(command);
        values.push(OsString::from("--config"));
        values.push(config.clone().into_os_string());
        values
    };
    let initialized = run(invoke(&["init", "--yes"]), TerminalContext::default()).await;
    assert_eq!(initialized.status, 0, "{}", initialized.stderr);

    let state_file = state.join("state.json");
    let extra_link = directory.path().join("state-hardlink");
    std::fs::hard_link(&state_file, &extra_link)?;
    let linked = run(invoke(&["source", "list"]), TerminalContext::default()).await;
    assert_eq!(linked.status, 65);
    std::fs::remove_file(extra_link)?;

    std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o644))?;
    let exposed = run(invoke(&["source", "list"]), TerminalContext::default()).await;
    assert_eq!(exposed.status, 65);
    std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o600))?;

    let config_link = directory.path().join("config-hardlink");
    std::fs::hard_link(&config, &config_link)?;
    let linked_config = run(invoke(&["source", "list"]), TerminalContext::default()).await;
    assert_eq!(linked_config.status, 78);
    std::fs::remove_file(config_link)?;

    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o664))?;
    let writable = run(invoke(&["source", "list"]), TerminalContext::default()).await;
    assert_eq!(writable.status, 78);
    Ok(())
}
