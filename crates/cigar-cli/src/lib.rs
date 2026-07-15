//! Content-safe CIGAR command parsing, feature-selected execution, and rendering.

#[cfg(all(feature = "full", feature = "beta-embedded"))]
compile_error!("features `full` and `beta-embedded` are mutually exclusive");
#[cfg(not(any(feature = "full", feature = "beta-embedded")))]
compile_error!("exactly one of features `full` or `beta-embedded` must be enabled");

#[cfg(feature = "full")]
mod administration;
#[cfg(all(feature = "beta-embedded", not(feature = "full")))]
#[path = "beta/administration.rs"]
mod administration;
mod arguments;
mod beta_state_compat;
#[cfg(all(feature = "full", unix))]
mod beta_state_transition;
#[cfg(feature = "full")]
mod claude_plugin;
#[cfg(feature = "full")]
mod client;
#[cfg(all(feature = "beta-embedded", not(feature = "full")))]
#[path = "beta/client.rs"]
mod client;
mod command;
#[cfg(feature = "full")]
mod configuration;
#[cfg(all(feature = "beta-embedded", not(feature = "full")))]
#[path = "beta/configuration.rs"]
mod configuration;
mod error;
#[cfg(feature = "full")]
#[path = "generated/operation_mappings.rs"]
mod operation_mappings;
mod render;

use arguments::{ParsedInvocation, parse};
#[cfg(feature = "full")]
use client::{EmbeddedOperationClient, HttpOperationClient, OperationClient};
use configuration::EffectiveConfiguration;
use error::CliError;
use render::{render_error, render_success};
use std::ffi::OsString;

/// Terminal capabilities supplied by the process boundary and replaceable in tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalContext {
    /// Whether standard input is an interactive terminal.
    pub stdin: bool,
    /// Whether standard output is an interactive terminal.
    pub stdout: bool,
    /// Whether standard error is an interactive terminal.
    pub stderr: bool,
    /// Optional terminal width in columns.
    pub width: Option<usize>,
    /// Whether Unicode status glyphs are supported.
    pub unicode: bool,
    /// Result of an explicit interactive confirmation prompt, when one was shown.
    pub confirmed: Option<bool>,
    /// Whether the process boundary already emitted the live start marker.
    pub progress_started: bool,
}

/// Fully rendered process result with stable exit status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    /// Zero for success and a stable sysexits-compatible value for failure.
    pub status: u8,
    /// Standard output, including its final newline when non-empty.
    pub stdout: String,
    /// Standard error, including its final newline when non-empty.
    pub stderr: String,
}

impl ProcessOutcome {
    fn success(stdout: String, stderr: String) -> Self {
        Self {
            status: 0,
            stdout,
            stderr,
        }
    }

    fn failure(error: &CliError, invocation: Option<&ParsedInvocation>) -> Self {
        let output = invocation.map_or(arguments::OutputFormat::Text, |value| value.options.output);
        let rendered = render_error(error, output);
        if output == arguments::OutputFormat::Json {
            Self {
                status: error.exit_status(),
                stdout: rendered,
                stderr: String::new(),
            }
        } else {
            Self {
                status: error.exit_status(),
                stdout: String::new(),
                stderr: rendered,
            }
        }
    }
}

/// Parses and executes one CLI invocation using real local or HTTP operation dispatch.
pub async fn run(arguments: Vec<OsString>, terminal: TerminalContext) -> ProcessOutcome {
    let accepted_at = tokio::time::Instant::now();
    let parsed = match parse(arguments, terminal) {
        Ok(parsed) => parsed,
        Err(error) => return ProcessOutcome::failure(&error, None),
    };
    let deadline_at = accepted_at + parsed.options.deadline;
    match execute(parsed.clone(), terminal, deadline_at).await {
        Ok((stdout, stderr)) => ProcessOutcome::success(stdout, stderr),
        Err(error) => ProcessOutcome::failure(&error, Some(&parsed)),
    }
}

/// Returns whether this invocation needs an interactive confirmation prompt.
#[must_use]
pub fn confirmation_needed(arguments: &[OsString], terminal: TerminalContext) -> bool {
    let Ok(invocation) = parse(arguments.to_vec(), terminal) else {
        return false;
    };
    (invocation.command.mutates() || invocation.command.destructive())
        && !invocation.options.dry_run
        && !invocation.options.yes
        && !invocation.options.non_interactive
        && terminal.stdin
}

/// Returns the live progress marker a terminal process should emit before awaiting execution.
#[must_use]
pub fn progress_start(arguments: &[OsString], terminal: TerminalContext) -> Option<String> {
    let invocation = parse(arguments.to_vec(), terminal).ok()?;
    #[cfg(feature = "full")]
    let generated_asset = invocation.command.is_completion() || invocation.command.is_man();
    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    let generated_asset = false;
    if invocation.command.is_help()
        || invocation.command.is_version()
        || generated_asset
        || invocation.options.explain_config
        || invocation.require_confirmation(terminal).is_err()
        || !invocation.progress_enabled(terminal)
    {
        return None;
    }
    let marker = if invocation.unicode_enabled(terminal) {
        "\u{2026}"
    } else {
        "..."
    };
    Some(format!("{marker} {}\n", invocation.command.path()))
}

async fn execute(
    invocation: ParsedInvocation,
    terminal: TerminalContext,
    deadline_at: tokio::time::Instant,
) -> Result<(String, String), CliError> {
    if invocation.command.is_help() {
        return Ok((command::help_text(), String::new()));
    }
    if invocation.command.is_version() {
        #[cfg(feature = "full")]
        let rendered =
            cigar_protocol::BuildMetadata::current(env!("CARGO_PKG_VERSION")).to_stable_json();
        #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
        let rendered = beta_build_metadata()?;
        return Ok((format!("{rendered}\n"), String::new()));
    }
    #[cfg(feature = "full")]
    if invocation.command.is_completion() {
        let shell = invocation
            .positionals
            .first()
            .map(String::as_str)
            .ok_or_else(CliError::invalid_command)?;
        return Ok((command::completion(shell)?.to_owned(), String::new()));
    }
    #[cfg(feature = "full")]
    if invocation.command.is_man() {
        return Ok((command::man_page().to_owned(), String::new()));
    }

    #[cfg(feature = "full")]
    let configuration = EffectiveConfiguration::load(&invocation)?;
    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    let configuration = EffectiveConfiguration::load_until(&invocation, deadline_at).await?;
    if tokio::time::Instant::now() >= deadline_at {
        return Err(CliError::deadline_exceeded());
    }
    if invocation.options.explain_config {
        return Ok((
            configuration.explain(invocation.options.output)?,
            String::new(),
        ));
    }
    invocation.require_confirmation(terminal)?;
    let mut progress = String::new();
    if invocation.progress_enabled(terminal) && !terminal.progress_started {
        let marker = if invocation.unicode_enabled(terminal) {
            "\u{2026}"
        } else {
            "..."
        };
        progress.push_str(&format!("{marker} {}\n", invocation.command.path()));
    }
    #[cfg(feature = "full")]
    let response = if invocation.command.is_administration()
        || (invocation.command.path() == "doctor"
            && (invocation.options.security || invocation.options.deep))
    {
        tokio::select! {
            biased;
            signal = tokio::signal::ctrl_c() => {
                let _ignored = signal;
                return Err(CliError::interrupted());
            }
            _ = tokio::time::sleep_until(deadline_at) => {
                return Err(CliError::deadline_exceeded());
            }
            result = administration::execute(&invocation, &configuration) => result?,
        }
    } else {
        let request = invocation.operation_request(&configuration)?;
        if tokio::time::Instant::now() >= deadline_at {
            return Err(CliError::deadline_exceeded());
        }
        match configuration.target() {
            arguments::TargetKind::Embedded => {
                let client = tokio::select! {
                    biased;
                    signal = tokio::signal::ctrl_c() => {
                        let _ignored = signal;
                        return Err(CliError::interrupted());
                    }
                    _ = tokio::time::sleep_until(deadline_at) => {
                        return Err(CliError::deadline_exceeded());
                    }
                    result = EmbeddedOperationClient::start(&configuration) => result?,
                };
                tokio::select! {
                    biased;
                    signal = tokio::signal::ctrl_c() => {
                        let _ignored = signal;
                        client.shutdown().await?;
                        return Err(CliError::interrupted());
                    }
                    _ = tokio::time::sleep_until(deadline_at) => {
                        client.shutdown().await?;
                        return Err(CliError::deadline_exceeded());
                    }
                    result = client.execute(request) => result?,
                }
            }
            arguments::TargetKind::Local | arguments::TargetKind::Remote => {
                let client = HttpOperationClient::new(&configuration)?;
                tokio::select! {
                    biased;
                    signal = tokio::signal::ctrl_c() => {
                        let _ignored = signal;
                        return Err(CliError::interrupted());
                    }
                    _ = tokio::time::sleep_until(deadline_at) => {
                        return Err(CliError::deadline_exceeded());
                    }
                    result = client.execute(request) => result?,
                }
            }
        }
    };
    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    let response = administration::execute(&invocation, &configuration, deadline_at).await?;
    if invocation.progress_enabled(terminal) {
        let marker = if invocation.unicode_enabled(terminal) {
            "\u{2713}"
        } else {
            "OK"
        };
        progress.push_str(&format!("{marker} {}\n", invocation.command.path()));
    }
    let stdout = render_success(&invocation, &configuration, response)?;
    Ok((stdout, progress))
}

#[cfg(all(feature = "beta-embedded", not(feature = "full")))]
fn beta_build_metadata() -> Result<String, CliError> {
    #[derive(serde::Serialize)]
    struct BetaBuildMetadata {
        schema_version: &'static str,
        version: &'static str,
        source_revision: &'static str,
        build_profile: &'static str,
        release_profile: &'static str,
        channel: &'static str,
        production_ready: bool,
        qualification_status: &'static str,
        required_target_triple: &'static str,
        required_host_profile: &'static str,
        required_distribution: &'static str,
        required_distribution_version: &'static str,
        required_libc: &'static str,
        required_libc_version: &'static str,
        target_os: &'static str,
        target_arch: &'static str,
        target_env: &'static str,
        capability_profile: &'static str,
        enabled_features: [&'static str; 1],
    }

    let metadata = BetaBuildMetadata {
        schema_version: "cigar.beta.build-metadata.v1",
        // The embedded beta composition is a frozen compatibility artifact.  Its
        // externally visible identity must not drift when the full workspace
        // advances to a new development version.
        version: crate::beta_state_compat::FROZEN_BETA_RELEASE,
        source_revision: match option_env!("CIGAR_SOURCE_REVISION") {
            Some(revision) => revision,
            None => "unknown",
        },
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        release_profile: "cigar.beta.embedded-local.linux-x86_64.v1",
        channel: "beta",
        production_ready: false,
        qualification_status: "requires-external-release-evidence",
        required_target_triple: "x86_64-unknown-linux-gnu",
        required_host_profile: "ubuntu-24.04-x86_64-glibc-2.39",
        required_distribution: "ubuntu",
        required_distribution_version: "24.04",
        required_libc: "glibc",
        required_libc_version: "2.39",
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        target_env: if cfg!(target_env = "gnu") {
            "gnu"
        } else if cfg!(target_env = "musl") {
            "musl"
        } else if cfg!(target_env = "msvc") {
            "msvc"
        } else {
            ""
        },
        capability_profile: "workspace-metadata-only",
        enabled_features: ["beta-embedded"],
    };
    serde_json::to_string(&metadata).map_err(|_error| CliError::invalid_response())
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::{TerminalContext, confirmation_needed, progress_start, run};
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn record(value: u64) -> Result<cigar_protocol::RecordId, Box<dyn std::error::Error>> {
        Ok(cigar_protocol::RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn restricted_write(
        path: &std::path::Path,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn embedded_daemon_fixture()
    -> Result<(tempfile::TempDir, cigar_daemon::DaemonConfig), Box<dyn std::error::Error>> {
        use cigar_crypto::{
            CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider as _,
            KeyPurpose, SecretBytes,
        };
        use cigar_protocol::{Capability, Classification, InstructionAuthority, UtcTimestamp};

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let state = root.join("state");
        let runtime = root.join("run");
        let project = root.join("project");
        let trusted = root.join("trusted");
        let secrets = root.join("secrets");
        for path in [&state, &runtime, &project, &trusted, &secrets] {
            std::fs::create_dir_all(path)?;
        }
        let project = std::fs::canonicalize(project)?;
        let passphrase_file = secrets.join("keystore-passphrase");
        let passphrase = b"0123456789abcdef0123456789abcdef";
        restricted_write(&passphrase_file, passphrase)?;
        let keystore_file = state.join("keystore.cigar");
        let keystore = EncryptedDevelopmentKeystore::open(
            &keystore_file,
            SecretBytes::new(passphrase.to_vec()),
        )?;
        let tenant = record(1)?;
        let project_id = record(2)?;
        let principal = record(3)?;
        let signing = keystore.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?.unix_nanos(),
            activated_at: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?.unix_nanos(),
        })?;
        drop(keystore);

        let local = cigar_daemon::LocalIdentity::from_project_root(&project)?;
        let authenticated = local.authenticated();
        let authority = cigar_daemon::ProductionAuthorityConfiguration {
            schema_version: "cigar.production-authority.v1".to_owned(),
            runtime_audience: "local-runtime-v1".to_owned(),
            decision_ttl_seconds: 60,
            tenants: vec![cigar_daemon::ProductionTenantAuthority {
                authenticated_tenant: authenticated.tenant().as_str().to_owned(),
                tenant_id: tenant,
                active: true,
                issuer_key_ref: signing.key_ref,
                project_ids: vec![project_id.clone()],
                principals: vec![cigar_daemon::ProductionPrincipalAuthority {
                    authenticated_principal: authenticated.principal().as_str().to_owned(),
                    principal_id: principal.clone(),
                    grant_id: record(4)?,
                    active: true,
                    operator: true,
                    not_before: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?,
                    expires_at: UtcTimestamp::parse_rfc3339("2099-01-01T00:00:00Z")?,
                    roles: vec!["developer".to_owned()],
                    project_ids: vec![project_id],
                    capabilities: vec![Capability::ReadContext],
                    delegatable_capabilities: Vec::new(),
                    purposes: vec!["catalog.read".to_owned()],
                    processors: vec!["local".to_owned()],
                    catalog_purpose: "catalog.read".to_owned(),
                    catalog_processor: "local".to_owned(),
                    maximum_classification: Classification::Restricted,
                    maximum_instruction_authority: InstructionAuthority::System,
                    residency_allowed: true,
                    egress_allowed: false,
                    vector_allowed: false,
                    handoff_target_allowed: false,
                    effect_rules: Vec::new(),
                }],
                revoked_principal_ids: Vec::new(),
                revoked_key_refs: Vec::new(),
            }],
        };
        let authority_file = trusted.join("authority.json");
        std::fs::write(&authority_file, serde_json::to_vec(&authority)?)?;
        let policy_file = trusted.join("policy.json");
        std::fs::write(
            &policy_file,
            serde_json::to_vec(&cigar_policy::PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            })?,
        )?;
        let sources_file = trusted.join("sources.json");
        std::fs::write(
            &sources_file,
            br#"{"schema_version":"cigar.production-source-registry.v1","sources":[]}"#,
        )?;
        let effects_file = trusted.join("effects.json");
        std::fs::write(
            &effects_file,
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":false,"connectors":[]}"#,
        )?;
        let config = cigar_daemon::DaemonConfig {
            mode: cigar_daemon::DeploymentMode::Local,
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: state.clone(),
            runtime_directory: runtime.clone(),
            unix_socket: Some(runtime.join("cigard.sock")),
            windows_named_pipe: None,
            http_listen: None,
            grpc_listen: None,
            local_token_file: None,
            tls: None,
            oidc: None,
            production: cigar_daemon::ProductionPaths {
                project_directory: project,
                metadata_database: state.join("cigar.sqlite3"),
                blob_directory: state.join("blobs"),
                blob_key_reference_directory: state.join("blob-keys"),
                keystore_file,
                keystore_passphrase_file: passphrase_file,
                cursor_signing_key_file: state.join("cursor.key"),
                effect_checkpoint_file: root.join("effect-checkpoints/checkpoints.json"),
                policy_profile_file: policy_file,
                authority_file,
                source_registry_file: sources_file,
                effect_registry_file: effects_file,
            },
            local_vector: cigar_daemon::LocalVectorSettings::default(),
            shared_storage: None,
            request_deadline_ms: 5_000,
            shutdown_deadline_ms: 5_000,
            max_request_bytes: 1024 * 1024,
            max_expansion_ratio: 8,
            workers: cigar_daemon::WorkerCapacities {
                ingestion: 4,
                indexing: 4,
                invalidation: 4,
                compilation: 4,
                outbox: 4,
                reconciliation: 4,
                lease_cleanup: 4,
                backup: 2,
                garbage_collection: 2,
            },
            resources: cigar_daemon::ApplicationResourceLimits {
                global_request_concurrency: 32,
                per_tenant_request_concurrency: 8,
                blocking_active: 4,
                blocking_queued: 16,
                idempotency_wait_ms: 1_000,
            },
            telemetry: cigar_daemon::TelemetrySettings {
                otlp_endpoint: None,
                otlp_ca_certificate_file: None,
                export_timeout_ms: 1_000,
                metric_interval_ms: 1_000,
            },
        };
        config.validate()?;
        Ok((directory, config))
    }

    fn write_embedded_configuration(
        daemon: &cigar_daemon::DaemonConfig,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), Box<dyn std::error::Error>> {
        let root = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?;
        let daemon_config = root.join("cigard.toml");
        std::fs::write(&daemon_config, toml::to_string(daemon)?)?;
        let cli_config = root.join("cli.toml");
        std::fs::write(
            &cli_config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"embedded\"\n",
                    "daemon_config = {}\n",
                    "project_state_directory = {}\n"
                ),
                serde_json::to_string(&daemon_config.display().to_string())?,
                serde_json::to_string(
                    &daemon
                        .state_directory
                        .join("cli-state")
                        .display()
                        .to_string()
                )?
            ),
        )?;
        Ok((daemon_config, cli_config))
    }

    #[tokio::test]
    async fn version_and_help_are_stable_without_a_target() {
        let version = run(args(&["version"]), TerminalContext::default()).await;
        assert_eq!(version.status, 0);
        assert!(version.stdout.contains("\"version\":\"0.9.0-honey.1\""));
        assert!(version.stderr.is_empty());

        let help = run(Vec::new(), TerminalContext::default()).await;
        assert_eq!(help.status, 0);
        assert!(help.stdout.contains("cigar effect prepare"));
        assert!(help.stdout.contains("--target <embedded|local|remote>"));
        assert!(progress_start(&args(&["status"]), TerminalContext::default()).is_none());
        assert_eq!(
            progress_start(
                &args(&["status", "--unicode", "never"]),
                TerminalContext {
                    stderr: true,
                    ..TerminalContext::default()
                }
            ),
            Some("... status\n".to_owned())
        );
    }

    #[tokio::test]
    async fn unknown_input_is_never_reflected() {
        let secret = "customer-secret-value";
        let outcome = run(args(&["unknown", secret]), TerminalContext::default()).await;
        assert_ne!(outcome.status, 0);
        assert!(!outcome.stderr.contains(secret));
        assert!(outcome.stderr.starts_with("CLI_INVALID_COMMAND:"));
    }

    #[tokio::test]
    async fn confirmation_is_explicit_for_tty_and_noninteractive_calls()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let state = directory.path().join("state");
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\nproject_state_directory = {}\n",
                serde_json::to_string(&state.display().to_string())?
            ),
        )?;
        let arguments = vec![
            OsString::from("init"),
            OsString::from("--config"),
            config.clone().into_os_string(),
        ];
        let tty = TerminalContext {
            stdin: true,
            ..TerminalContext::default()
        };
        assert!(confirmation_needed(&arguments, tty));
        let missing = run(arguments.clone(), tty).await;
        assert_eq!(missing.status, 2);
        assert!(!state.exists());

        let confirmed = run(
            arguments,
            TerminalContext {
                stdin: true,
                confirmed: Some(true),
                ..TerminalContext::default()
            },
        )
        .await;
        assert_eq!(confirmed.status, 0, "{}", confirmed.stderr);
        assert!(state.join("state.json").is_file());

        let noninteractive = run(
            vec![
                OsString::from("source"),
                OsString::from("remove"),
                OsString::from("missing"),
                OsString::from("--config"),
                config.into_os_string(),
                OsString::from("--non-interactive"),
            ],
            TerminalContext {
                stdin: true,
                confirmed: Some(true),
                ..TerminalContext::default()
            },
        )
        .await;
        assert_eq!(noninteractive.status, 2);
        assert!(noninteractive.stderr.contains("CLI_CONFIRMATION_REQUIRED"));
        Ok(())
    }

    #[tokio::test]
    async fn local_administration_handles_unicode_and_dry_run()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source with 🐝");
        std::fs::create_dir(&source)?;
        let state = directory.path().join("state with spaces");
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\nproject_state_directory = {}\n",
                serde_json::to_string(&state.display().to_string())?
            ),
        )?;
        let config_text = config.display().to_string();
        let source_text = source.display().to_string();
        let initialize = run(
            args(&[
                "init",
                "--yes",
                "--config",
                &config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(initialize.status, 0, "{}", initialize.stderr);
        let add = run(
            args(&[
                "source",
                "add",
                "source-one",
                &source_text,
                "--yes",
                "--config",
                &config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(add.status, 0, "{}", add.stderr);
        assert!(add.stdout.contains("source-one"));
        assert!(add.stdout.contains("🐝"));

        let preview = run(
            args(&[
                "source",
                "remove",
                "source-one",
                "--dry-run",
                "--config",
                &config_text,
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(preview.status, 0);
        let list = run(
            args(&[
                "source",
                "list",
                "--config",
                &config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert!(list.stdout.contains("source-one"));
        let focus = run(
            args(&[
                "focus",
                "switch",
                "task-one",
                "--yes",
                "--config",
                &config_text,
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(focus.status, 0, "{}", focus.stderr);
        let close_preview = run(
            args(&[
                "focus",
                "close",
                "task-one",
                "--dry-run",
                "--config",
                &config_text,
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(close_preview.status, 0, "{}", close_preview.stderr);
        let closed = run(
            args(&[
                "focus",
                "close",
                "task-one",
                "--yes",
                "--config",
                &config_text,
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(closed.status, 0, "{}", closed.stderr);
        assert!(closed.stdout.contains("task-one"));
        assert!(state.join("state.json").is_file());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_backup_restore_and_store_owned_gc_use_signed_durable_state()
    -> Result<(), Box<dyn std::error::Error>> {
        use cigar_crypto::{EncryptedDevelopmentKeystore, KeyProvider as _, SecretBytes};
        use cigar_protocol::{BlobRef, ContentDigest, MediaType};
        use cigar_store::{
            BlobRecord, MultiTenantLocalRepositoryBlobStore, RepositoryBlobStore as _, SqliteStore,
        };
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;
        use std::sync::Arc;

        let (_directory, daemon) = embedded_daemon_fixture()?;
        let (_daemon_config, cli_config) = write_embedded_configuration(&daemon)?;
        let cli_config_text = cli_config.display().to_string();
        let ready = run(
            args(&["status", "--config", &cli_config_text, "--output", "json"]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(ready.status, 0, "{}", ready.stderr);

        let security = run(
            args(&[
                "doctor",
                "--security",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(security.status, 0, "{}", security.stderr);
        assert!(security.stdout.contains("\"security\":true"));
        assert!(security.stdout.contains("sqlite_integrity"));

        let deep = run(
            args(&[
                "doctor",
                "--deep",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(deep.status, 0, "{}", deep.stderr);
        assert!(deep.stdout.contains("\"deep\":true"));
        assert!(deep.stdout.contains("journal_chains"));
        assert!(deep.stdout.contains("effect_record_signatures"));
        assert!(deep.stdout.contains("effect_external_checkpoints"));
        assert!(deep.stdout.contains("\"verified_effect_record_count\":0"));
        assert!(deep.stdout.contains("fts_projection"));

        let fixture_root = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?;
        let support_one = fixture_root.join("support-one.tar");
        let support_two = fixture_root.join("support-two.tar");
        for support in [&support_one, &support_two] {
            let support_text = support.display().to_string();
            let created = run(
                args(&[
                    "diagnostics",
                    "bundle",
                    &support_text,
                    "--yes",
                    "--config",
                    &cli_config_text,
                    "--output",
                    "json",
                ]),
                TerminalContext::default(),
            )
            .await;
            assert_eq!(created.status, 0, "{}", created.stderr);
            assert!(created.stdout.contains("\"content_free\":true"));
            assert!(created.stdout.contains("\"created\":true"));
        }
        let support_bytes = std::fs::read(&support_one)?;
        assert_eq!(support_bytes, std::fs::read(&support_two)?);
        assert_eq!(support_bytes.len() % 512, 0);
        assert!(support_bytes.windows(6).any(|window| window == b"ustar\0"));
        for excluded in [
            b"0123456789abcdef0123456789abcdef".as_slice(),
            cli_config_text.as_bytes(),
            fixture_root.display().to_string().as_bytes(),
        ] {
            assert!(
                !support_bytes
                    .windows(excluded.len())
                    .any(|window| window == excluded)
            );
        }
        let existing = run(
            args(&[
                "diagnostics",
                "bundle",
                &support_one.display().to_string(),
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_ne!(existing.status, 0);
        assert_eq!(support_bytes, std::fs::read(&support_one)?);

        let backup = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?
            .join("signed backup with spaces");
        let backup_text = backup.display().to_string();
        let created = run(
            args(&[
                "backup",
                "create",
                &backup_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(
            created.status, 0,
            "stdout={} stderr={}",
            created.stdout, created.stderr
        );
        assert!(created.stdout.contains("\"signed\":true"));
        assert!(created.stdout.contains("\"verified\":true"));
        assert!(created.stdout.contains("\"format_version\":2"));
        assert!(backup.join("manifest.cbor").is_file());
        assert!(backup.join("manifest.signature.cbor").is_file());
        assert!(backup.join("database.sqlite3").is_file());
        assert!(backup.join("effect-checkpoints.json").is_file());

        let verified = run(
            args(&[
                "backup",
                "verify",
                &backup_text,
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(verified.status, 0, "{}", verified.stderr);
        assert!(verified.stdout.contains("\"action\":\"verified\""));

        let mut rotated_authority: cigar_daemon::ProductionAuthorityConfiguration =
            serde_json::from_slice(&std::fs::read(&daemon.production.authority_file)?)?;
        let active_tenant = rotated_authority
            .tenants
            .first_mut()
            .ok_or("missing tenant fixture")?;
        let old_signing_key = active_tenant.issuer_key_ref.clone();
        let tenant_id = active_tenant.tenant_id.as_str().to_owned();
        let rotation_keys = EncryptedDevelopmentKeystore::open(
            &daemon.production.keystore_file,
            SecretBytes::new(b"0123456789abcdef0123456789abcdef".to_vec()),
        )?;
        let rotation_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let rotated =
            rotation_keys.rotate(&old_signing_key, &tenant_id, i128::try_from(rotation_time)?)?;
        active_tenant.issuer_key_ref = rotated.key_ref;
        drop(rotation_keys);
        std::fs::write(
            &daemon.production.authority_file,
            serde_json::to_vec(&rotated_authority)?,
        )?;

        let restored = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?
            .join("restored empty target");
        let restored_text = restored.display().to_string();
        let restored_outcome = run(
            args(&[
                "backup",
                "restore",
                &backup_text,
                &restored_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(restored_outcome.status, 0, "{}", restored_outcome.stderr);
        assert!(restored.join("database.sqlite3").is_file());
        assert!(restored.join("effect-checkpoints.json").is_file());
        assert!(restored.join("blobs").is_dir());
        let source_semantic_root =
            SqliteStore::open(&daemon.production.metadata_database)?.semantic_root()?;
        assert_eq!(
            SqliteStore::open(restored.join("database.sqlite3"))?.semantic_root()?,
            source_semantic_root
        );

        let passphrase = b"0123456789abcdef0123456789abcdef";
        let keys = Arc::new(EncryptedDevelopmentKeystore::open(
            &daemon.production.keystore_file,
            SecretBytes::new(passphrase.to_vec()),
        )?);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let now = i128::try_from(now)?;
        let repository = MultiTenantLocalRepositoryBlobStore::open(
            &daemon.production.blob_directory,
            &daemon.production.blob_key_reference_directory,
            keys,
            now,
        )?;
        let payload = b"unreferenced encrypted CLI GC fixture";
        let digest = Sha256::digest(payload);
        let mut encoded_digest = String::from("1220");
        for byte in digest {
            write!(&mut encoded_digest, "{byte:02x}")?;
        }
        let blob = BlobRecord::new(
            BlobRef {
                digest: ContentDigest::new(encoded_digest.clone())?,
                size_bytes: u64::try_from(payload.len())?,
                media_type: MediaType::new("application/octet-stream")?,
            },
            payload.to_vec(),
        )?;
        let tenant = record(1)?;
        repository.put(&tenant, &blob)?;

        let blocked_gc_plan = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?
            .join("blocked-gc-plan.json");
        let blocked_gc_plan_text = blocked_gc_plan.display().to_string();
        let plan = run(
            args(&[
                "gc",
                "plan",
                &blocked_gc_plan_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(plan.status, 0, "{}", plan.stderr);
        assert!(
            plan.stdout.contains("\"candidate_count\":1"),
            "{}",
            plan.stdout
        );
        assert!(plan.stdout.contains("retention_or_replay_window"));
        assert!(plan.stdout.contains("legal_hold"));
        assert!(plan.stdout.contains("backup_policy"));
        let blocked_plan_bytes = std::fs::read(&blocked_gc_plan)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&blocked_gc_plan)?.permissions().mode() & 0o777,
                0o600
            );
        }
        let no_clobber = run(
            args(&[
                "gc",
                "plan",
                &blocked_gc_plan_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_ne!(no_clobber.status, 0);
        assert_eq!(std::fs::read(&blocked_gc_plan)?, blocked_plan_bytes);
        let blocked_run = run(
            args(&[
                "gc",
                "run",
                &blocked_gc_plan_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_ne!(blocked_run.status, 0);
        assert_eq!(
            repository.get(&tenant, &blob.reference)?,
            Some(blob.clone())
        );

        let gc_policy = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?
            .join("gc-policy.json");
        std::fs::write(
            &gc_policy,
            br#"{"schema_version":"cigar.gc-policy.v1","retention_satisfied":true,"legal_hold":false,"backup_complete":true,"max_files":10}"#,
        )?;
        let gc_policy_text = gc_policy.display().to_string();
        let signed_gc_plan = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?
            .join("signed-gc-plan.json");
        let signed_gc_plan_text = signed_gc_plan.display().to_string();
        let planned = run(
            args(&[
                "gc",
                "plan",
                &signed_gc_plan_text,
                "--yes",
                "--input",
                &gc_policy_text,
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(planned.status, 0, "{}", planned.stderr);
        assert!(planned.stdout.contains("\"signed\":true"));
        let signed_plan: cigar_store::SignedGarbageCollectionPlan =
            serde_json::from_slice(&std::fs::read(&signed_gc_plan)?)?;
        assert!(signed_plan.unverified_plan().policy().retention_satisfied);
        assert!(!signed_plan.unverified_plan().policy().legal_hold);
        assert!(signed_plan.unverified_plan().policy().backup_complete);
        assert_eq!(signed_plan.unverified_plan().maximum_candidates(), 10);
        let inspection_keys = Arc::new(EncryptedDevelopmentKeystore::open(
            &daemon.production.keystore_file,
            SecretBytes::new(passphrase.to_vec()),
        )?);
        let verification_time = i128::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let verified_plan = cigar_store::verify_garbage_collection_plan_trusted(
            signed_plan.clone(),
            inspection_keys.as_ref(),
            verification_time,
            |_identity| true,
        )
        .map_err(|error| format!("signed plan verification failed: {:?}", error.code()))?;
        let inspection_repository: Arc<dyn cigar_store::RepositoryBlobStore> =
            Arc::new(MultiTenantLocalRepositoryBlobStore::open(
                &daemon.production.blob_directory,
                &daemon.production.blob_key_reference_directory,
                inspection_keys,
                verification_time,
            )?);
        SqliteStore::run_garbage_collection_plan_at(
            &daemon.production.metadata_database,
            inspection_repository,
            &verified_plan,
            true,
        )
        .map_err(|error| format!("signed plan dry run failed: {:?}", error.code()))?;
        let previewed = run(
            args(&[
                "gc",
                "run",
                &signed_gc_plan_text,
                "--dry-run",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(
            previewed.status, 0,
            "stdout={} stderr={}",
            previewed.stdout, previewed.stderr
        );
        let collected = run(
            args(&[
                "gc",
                "run",
                &signed_gc_plan_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(
            collected.status, 0,
            "stdout={} stderr={}",
            collected.stdout, collected.stderr
        );
        assert!(collected.stdout.contains("\"deleted\":1"));
        assert_eq!(repository.get(&tenant, &blob.reference)?, None);
        assert_eq!(
            SqliteStore::open(&daemon.production.metadata_database)?.semantic_root()?,
            source_semantic_root
        );

        let authority_bytes = std::fs::read(&daemon.production.authority_file)?;
        let mut authority: cigar_daemon::ProductionAuthorityConfiguration =
            serde_json::from_slice(&authority_bytes)?;
        authority
            .tenants
            .first_mut()
            .ok_or("missing tenant fixture")?
            .revoked_key_refs
            .push(old_signing_key);
        std::fs::write(
            &daemon.production.authority_file,
            serde_json::to_vec(&authority)?,
        )?;
        let revoked = run(
            args(&[
                "backup",
                "verify",
                &backup_text,
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(revoked.status, 77);
        assert!(revoked.stdout.contains("CLI_CREDENTIAL_UNAVAILABLE"));

        let mut second = authority
            .tenants
            .first()
            .and_then(|tenant| tenant.principals.first())
            .cloned()
            .ok_or("missing operator fixture")?;
        second.authenticated_principal = "second-local-operator".to_owned();
        second.principal_id = record(5)?;
        second.grant_id = record(6)?;
        authority
            .tenants
            .first_mut()
            .ok_or("missing tenant fixture")?
            .principals
            .push(second);
        std::fs::write(
            &daemon.production.authority_file,
            serde_json::to_vec(&authority)?,
        )?;
        let ambiguous_backup = daemon
            .state_directory
            .parent()
            .ok_or("missing fixture root")?
            .join("ambiguous backup signer");
        let ambiguous_backup_text = ambiguous_backup.display().to_string();
        let rejected = run(
            args(&[
                "backup",
                "create",
                &ambiguous_backup_text,
                "--yes",
                "--config",
                &cli_config_text,
                "--output",
                "json",
            ]),
            TerminalContext::default(),
        )
        .await;
        assert_eq!(rejected.status, 77);
        assert!(rejected.stdout.contains("CLI_CREDENTIAL_UNAVAILABLE"));
        assert!(!ambiguous_backup.exists());
        Ok(())
    }

    #[tokio::test]
    async fn remote_only_admin_surface_fails_without_semantic_aliasing()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let authorization = directory.path().join("remote.authorization");
        restricted_write(&authorization, b"Bearer test-only-remote-authority")?;
        let outcome = run(
            vec![
                OsString::from("effect"),
                OsString::from("list"),
                OsString::from("--remote"),
                OsString::from("https://example.test"),
                OsString::from("--authorization-file"),
                authorization.into_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(outcome.status, 69);
        assert!(outcome.stdout.contains("CLI_UNSUPPORTED_SURFACE"));
        assert!(!outcome.stdout.contains("getDiagnostics"));
        assert!(!outcome.stdout.contains("getConfiguration"));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedded_target_runs_exact_production_facade_without_binding_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, daemon) = embedded_daemon_fixture()?;
        let daemon_config = daemon
            .state_directory
            .parent()
            .ok_or("missing parent")?
            .join("cigard.toml");
        std::fs::write(&daemon_config, toml::to_string(&daemon)?)?;
        let cli_config = daemon
            .state_directory
            .parent()
            .ok_or("missing parent")?
            .join("cli.toml");
        std::fs::write(
            &cli_config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"embedded\"\n",
                    "daemon_config = {}\n",
                    "project_state_directory = {}\n"
                ),
                serde_json::to_string(&daemon_config.display().to_string())?,
                serde_json::to_string(
                    &daemon
                        .state_directory
                        .join("cli-state")
                        .display()
                        .to_string()
                )?
            ),
        )?;
        let outcome = run(
            vec![
                OsString::from("status"),
                OsString::from("--config"),
                cli_config.into_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert!(outcome.stdout.contains("\"target\":\"embedded\""));
        assert!(outcome.stdout.contains("\"operation_id\":\"getReadiness\""));
        assert!(outcome.stdout.contains("\"ready\":true"));
        assert!(daemon.production.metadata_database.is_file());
        assert!(
            !daemon
                .unix_socket
                .as_deref()
                .is_some_and(std::path::Path::exists)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_api_uses_owner_only_unix_socket_without_bearer_header()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use base64::Engine as _;
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("cigard.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\ntarget = \"local\"\nlocal_socket = {}\n",
                serde_json::to_string(&socket.display().to_string())?
            ),
        )?;
        let server = tokio::spawn(async move {
            let (mut stream, _address) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await?;
                if count == 0 || request.len() > 16 * 1024 {
                    break;
                }
                request.extend_from_slice(buffer.get(..count).ok_or("invalid read")?);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request)?;
            assert!(request.starts_with("GET "));
            assert!(request.starts_with("GET /readyz HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("x-cigar-operation-id: getreadiness")
            );
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            let node = cigar_canon::parse_strict_json(br#"{"ready":true}"#)?;
            let payload = cigar_canon::to_deterministic_cbor(&node)?;
            let body = serde_json::to_vec(&serde_json::json!({
                "operation_id": "getReadiness",
                "payload_cbor": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
            }))?;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(&body).await?;
            stream.shutdown().await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let outcome = run(
            vec![
                OsString::from("status"),
                OsString::from("--config"),
                config.into_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert!(outcome.stdout.contains("\"operation_id\":\"getReadiness\""));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn loopback_fallback_requires_and_sends_protected_bearer_file()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let directory = tempfile::tempdir()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let token = directory.path().join("local.token");
        let protected = "loopback-secret-canary";
        std::fs::write(&token, protected)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        }
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"local\"\n",
                    "local_endpoint = \"http://{}\"\n",
                    "authorization_file = {}\n"
                ),
                address,
                serde_json::to_string(&token.display().to_string())?
            ),
        )?;
        let server = tokio::spawn(async move {
            let (mut stream, _address) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await?;
                request.extend_from_slice(buffer.get(..count).ok_or("invalid read")?);
                if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request)?;
            assert!(request.contains(&format!("authorization: Bearer {protected}")));
            let node = cigar_canon::parse_strict_json(br#"{"ready":true}"#)?;
            let payload = cigar_canon::to_deterministic_cbor(&node)?;
            let body = serde_json::to_vec(&serde_json::json!({
                "operation_id": "getReadiness",
                "payload_cbor": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
            }))?;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let outcome = run(
            vec![
                OsString::from("status"),
                OsString::from("--config"),
                config.into_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert!(!outcome.stdout.contains(protected));
        server.await??;

        let unsafe_config = directory.path().join("unsafe.toml");
        std::fs::write(
            &unsafe_config,
            format!(
                "schema_version = 1\ntarget = \"local\"\nlocal_endpoint = \"http://{}\"\n",
                address
            ),
        )?;
        let rejected = run(
            vec![
                OsString::from("status"),
                OsString::from("--config"),
                unsafe_config.into_os_string(),
            ],
            TerminalContext::default(),
        )
        .await;
        assert_eq!(rejected.status, 78);
        assert!(rejected.stderr.contains("CLI_INVALID_CONFIGURATION"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn public_unknown_effect_and_stale_daemon_errors_are_not_relabelled()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let problem = cigar_api::ApiError::new(
            cigar_protocol::ErrorCode::EffectUnknown,
            cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000063")?,
        )
        .into_problem()?;
        let unknown = run_unix_mock(
            "409 Conflict",
            "application/problem+json",
            serde_json::to_vec(&problem)?,
            &["effect", "inspect", "01890f47-8e7d-7b42-a1d2-000000000099"],
        )
        .await?;
        assert_eq!(unknown.status, 65);
        assert!(unknown.stdout.contains("EFFECT_UNKNOWN"));
        assert!(!unknown.stdout.contains("getDiagnostics"));

        let mislabeled = run_unix_mock(
            "409 Conflict",
            "application/json",
            serde_json::to_vec(&problem)?,
            &["effect", "inspect", "01890f47-8e7d-7b42-a1d2-000000000099"],
        )
        .await?;
        assert_eq!(mislabeled.status, 70);
        assert!(mislabeled.stdout.contains("CLI_INVALID_RESPONSE"));
        assert!(!mislabeled.stdout.contains("EFFECT_UNKNOWN"));

        use base64::Engine as _;
        let payload = cigar_canon::to_deterministic_cbor(&cigar_canon::parse_strict_json(b"{}")?)?;
        let stale = run_unix_mock(
            "200 OK",
            "application/json",
            serde_json::to_vec(&serde_json::json!({
                "operation_id": "getVersion",
                "payload_cbor": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
            }))?,
            &["status"],
        )
        .await?;
        assert_eq!(stale.status, 69);
        assert!(stale.stdout.contains("CLI_STALE_DAEMON"));
        Ok(())
    }

    #[cfg(unix)]
    async fn run_unix_mock(
        status: &str,
        content_type: &str,
        body: Vec<u8>,
        command: &[&str],
    ) -> Result<super::ProcessOutcome, Box<dyn std::error::Error + Send + Sync>> {
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("cigard.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\ntarget = \"local\"\nlocal_socket = {}\n",
                serde_json::to_string(&socket.display().to_string())?
            ),
        )?;
        let status = status.to_owned();
        let content_type = content_type.to_owned();
        let server = tokio::spawn(async move {
            let (mut stream, _address) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await?;
                request.extend_from_slice(buffer.get(..count).ok_or("invalid read")?);
                if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut arguments = command.iter().map(OsString::from).collect::<Vec<_>>();
        arguments.extend([
            OsString::from("--config"),
            config.into_os_string(),
            OsString::from("--output"),
            OsString::from("json"),
        ]);
        let outcome = run(arguments, TerminalContext::default()).await;
        server.await??;
        Ok(outcome)
    }
}
