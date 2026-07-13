//! Public-boundary checks for the compile-time embedded-local beta surface.

#![cfg(feature = "beta-embedded")]

use cigar_cli::{TerminalContext, progress_start, run};
use std::ffi::OsString;
#[cfg(unix)]
use std::process::Command;

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
    assert_eq!(
        outcome.stdout,
        include_str!("../assets/cigar-help-beta.txt"),
        "help output must remain the reviewed text asset"
    );
    assert!(outcome.stdout.contains("Cancel before state publication"));
    assert!(!outcome.stdout.contains("Bound the complete command"));
    assert!(outcome.stdout.contains(
        "Qualification requires Ubuntu 24.04 x86-64 with glibc 2.39 and external signed release evidence;"
    ));
    assert!(outcome.stdout.contains(
        "this executable does not self-attest qualification and production_ready is false."
    ));
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
async fn help_is_always_text_and_version_is_always_json_regardless_of_output_mode()
-> Result<(), Box<dyn std::error::Error>> {
    let canonical_help = include_str!("../assets/cigar-help-beta.txt");
    let canonical_version = run(args(&["version"]), TerminalContext::default()).await;
    assert_eq!(canonical_version.status, 0);
    let _: serde_json::Value = serde_json::from_str(&canonical_version.stdout)?;

    for mode in ["text", "json"] {
        let help = run(
            args(&["--output", mode, "help"]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(help.status, 0);
        assert_eq!(help.stdout, canonical_help);

        let version = run(
            args(&["--output", mode, "version"]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(version.status, 0);
        assert_eq!(version.stdout, canonical_version.stdout);
        let _: serde_json::Value = serde_json::from_str(&version.stdout)?;
    }
    Ok(())
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
            .get("qualification_status")
            .and_then(serde_json::Value::as_str),
        Some("requires-external-release-evidence")
    );
    assert_eq!(
        metadata
            .get("required_target_triple")
            .and_then(serde_json::Value::as_str),
        Some("x86_64-unknown-linux-gnu")
    );
    assert_eq!(
        metadata
            .get("required_host_profile")
            .and_then(serde_json::Value::as_str),
        Some("ubuntu-24.04-x86_64-glibc-2.39")
    );
    assert_eq!(
        metadata
            .get("required_distribution")
            .and_then(serde_json::Value::as_str),
        Some("ubuntu")
    );
    assert_eq!(
        metadata
            .get("required_distribution_version")
            .and_then(serde_json::Value::as_str),
        Some("24.04")
    );
    assert_eq!(
        metadata
            .get("required_libc")
            .and_then(serde_json::Value::as_str),
        Some("glibc")
    );
    assert_eq!(
        metadata
            .get("required_libc_version")
            .and_then(serde_json::Value::as_str),
        Some("2.39")
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
    for obsolete in [
        "qualified_target_triple",
        "qualified_host_profile",
        "qualified_distribution",
        "qualified_distribution_version",
        "qualified_libc",
        "qualified_libc_version",
    ] {
        assert!(
            metadata.get(obsolete).is_none(),
            "obsolete claim present: {obsolete}"
        );
    }
    assert_eq!(metadata.as_object().map(serde_json::Map::len), Some(19));
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
async fn beta_explain_config_escapes_human_paths() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state-λ");
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
    let outcome = run(
        vec![
            OsString::from("source"),
            OsString::from("list"),
            OsString::from("--config"),
            config.into_os_string(),
            OsString::from("--explain-config"),
        ],
        TerminalContext::default(),
    )
    .await;
    assert_eq!(outcome.status, 0, "{}", outcome.stderr);
    assert!(!outcome.stdout.contains('λ'));
    assert!(outcome.stdout.contains(r"\u{3bb}"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn beta_default_configuration_rejects_a_control_character_cwd()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let unsafe_cwd = directory.path().join("workspace\nsegment");
    std::fs::create_dir(&unsafe_cwd)?;
    let output = Command::new(env!("CARGO_BIN_EXE_cigar"))
        .current_dir(&unsafe_cwd)
        .args(["source", "list", "--explain-config"])
        .output()?;
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("CLI_INVALID_CONFIGURATION"));
    assert!(!stderr.contains(&unsafe_cwd.display().to_string()));
    Ok(())
}

#[tokio::test]
async fn beta_embedded_state_workflow_is_private_and_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("state");
    let source = directory.path().join("source");
    let primary_project = directory.path().join("primary-project");
    let secondary_project = directory.path().join("secondary-project");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&primary_project)?;
    std::fs::create_dir(&secondary_project)?;
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
            primary_project.into_os_string(),
        ],
        vec![
            OsString::from("project"),
            OsString::from("attach"),
            OsString::from("secondary"),
            secondary_project.into_os_string(),
        ],
        vec![OsString::from("source"), OsString::from("list")],
        vec![OsString::from("project"), OsString::from("list")],
        vec![
            OsString::from("project"),
            OsString::from("switch"),
            OsString::from("secondary"),
        ],
        vec![
            OsString::from("project"),
            OsString::from("link"),
            OsString::from("primary"),
            OsString::from("secondary"),
        ],
        vec![
            OsString::from("project"),
            OsString::from("unlink"),
            OsString::from("primary"),
            OsString::from("secondary"),
        ],
        vec![
            OsString::from("focus"),
            OsString::from("switch"),
            OsString::from("review"),
        ],
        vec![
            OsString::from("focus"),
            OsString::from("close"),
            OsString::from("review"),
        ],
        vec![
            OsString::from("project"),
            OsString::from("detach"),
            OsString::from("secondary"),
        ],
        vec![
            OsString::from("source"),
            OsString::from("remove"),
            OsString::from("docs"),
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
        Some(11)
    );
    assert_eq!(document.get("active_project"), None);
    assert_eq!(document.get("active_focus"), None);
    assert_eq!(
        document
            .get("sources")
            .and_then(serde_json::Value::as_object)
            .map(serde_json::Map::len),
        Some(0)
    );
    assert_eq!(
        document
            .get("links")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        document.pointer("/projects/secondary/attached"),
        Some(&serde_json::json!(false))
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
async fn contended_beta_state_lock_honors_the_prepublication_deadline()
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
