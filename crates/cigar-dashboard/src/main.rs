//! Dashboard sidecar process entry point.

use cigar_dashboard::{DashboardApplication, DashboardConfig};
use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Some(code) = cigar_dashboard::run_internal_resource_launcher_if_requested() {
        return ExitCode::from(u8::try_from(code).unwrap_or(1));
    }
    match run(std::env::args_os().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Vec<OsString>) -> Result<(), &'static str> {
    let mut config_path = None;
    let mut check_config = false;
    let mut print_effective_config = false;
    let mut serve = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments
            .get(index)
            .and_then(|value| value.to_str())
            .ok_or("dashboard arguments are invalid")?;
        match argument {
            "--config" if config_path.is_none() => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or("--config requires an absolute path")?;
                config_path = Some(PathBuf::from(value));
            }
            "--check-config" if !check_config => check_config = true,
            "--print-effective-config" if !print_effective_config => print_effective_config = true,
            "serve" if !serve => serve = true,
            _ => {
                return Err(
                    "usage: cigar-dashboard serve --config <absolute-path> | cigar-dashboard --config <absolute-path> --check-config | cigar-dashboard --config <absolute-path> --print-effective-config",
                );
            }
        }
        index += 1;
    }
    let path = config_path.ok_or("--config is required")?;
    let selected_modes = usize::from(serve)
        .saturating_add(usize::from(check_config))
        .saturating_add(usize::from(print_effective_config));
    if selected_modes != 1 {
        return Err(
            "select exactly one dashboard mode: serve, --check-config, or --print-effective-config",
        );
    }
    let config =
        DashboardConfig::from_file(&path).map_err(|_error| "dashboard configuration is invalid")?;
    if check_config && !serve {
        println!("dashboard configuration valid");
        return Ok(());
    }
    if print_effective_config {
        let output = serde_json::to_string_pretty(&EffectiveConfig::from(&config))
            .map_err(|_error| "dashboard effective configuration could not be rendered")?;
        println!("{output}");
        return Ok(());
    }
    // Secure the configured listener before creating one-time authentication material. A bind
    // failure must not leave a bootstrap file behind and make the next explicit start fail.
    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .map_err(|_error| "dashboard listener failed")?;
    let application = DashboardApplication::initialize(&config)
        .map_err(|_error| "dashboard initialization failed")?;
    let status_monitor = application.start_status_monitor(&config);
    eprintln!(
        "dashboard one-time URL: http://{}/#bootstrap={}",
        application.listen(),
        application.bootstrap_token()
    );
    let result = axum::serve(listener, application.router())
        .with_graceful_shutdown(shutdown_signal())
        .await;
    status_monitor.shutdown().await;
    application
        .shutdown_controls(std::time::Duration::from_millis(
            config.server.shutdown_deadline_ms,
        ))
        .await;
    application.cleanup_bootstrap_file();
    result.map_err(|_error| "dashboard server failed")
}

#[derive(Serialize)]
struct EffectiveConfig<'a> {
    schema_version: &'static str,
    value_source: &'static str,
    server: EffectiveServer,
    target: EffectiveTarget<'a>,
    control: EffectiveControl,
    history: EffectiveHistory,
    display: EffectiveDisplay<'a>,
}

#[derive(Serialize)]
struct EffectiveServer {
    listen: String,
    local_paths: &'static str,
    request_timeout_ms: u64,
    shutdown_deadline_ms: u64,
    max_request_bytes: usize,
    max_event_bytes: usize,
    max_sse_subscribers: usize,
}

#[derive(Serialize)]
struct EffectiveTarget<'a> {
    endpoint: &'static str,
    credential_source: &'static str,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
    status_interval_ms: u64,
    diagnostics_interval_ms: u64,
    identity_interval_ms: u64,
    target_alias: &'a str,
}

#[derive(Serialize)]
struct EffectiveControl {
    enabled: bool,
    isolated_roots_configured: bool,
    profile_registry_configured: bool,
    max_concurrent_runs: usize,
}

#[derive(Serialize)]
struct EffectiveHistory {
    database_path: &'static str,
    max_runs: usize,
    max_events_per_run: usize,
    max_age_days: u32,
    max_bytes: u64,
}

#[derive(Serialize)]
struct EffectiveDisplay<'a> {
    target_alias: &'a str,
}

impl<'a> From<&'a DashboardConfig> for EffectiveConfig<'a> {
    fn from(config: &'a DashboardConfig) -> Self {
        Self {
            schema_version: "cigar.dashboard-effective-config.v1",
            value_source: "explicit_toml_file",
            server: EffectiveServer {
                listen: config.server.listen.to_string(),
                local_paths: "[REDACTED ABSOLUTE LOCAL PATHS]",
                request_timeout_ms: config.server.request_timeout_ms,
                shutdown_deadline_ms: config.server.shutdown_deadline_ms,
                max_request_bytes: config.server.max_request_bytes,
                max_event_bytes: config.server.max_event_bytes,
                max_sse_subscribers: config.server.max_sse_subscribers,
            },
            target: EffectiveTarget {
                endpoint: "[REDACTED NUMERIC LOOPBACK ENDPOINT]",
                credential_source: "[REDACTED OWNER-ONLY BEARER FILE]",
                connect_timeout_ms: config.target.connect_timeout_ms,
                request_timeout_ms: config.target.request_timeout_ms,
                status_interval_ms: config.target.status_interval_ms,
                diagnostics_interval_ms: config.target.diagnostics_interval_ms,
                identity_interval_ms: config.target.identity_interval_ms,
                target_alias: &config.display.target_alias,
            },
            control: EffectiveControl {
                enabled: config.control.enabled,
                isolated_roots_configured: config.control.workspace_root.is_some()
                    && config.control.evidence_directory.is_some()
                    && config.control.sandbox_directory.is_some(),
                profile_registry_configured: config.control.profile_registry.is_some(),
                max_concurrent_runs: config.control.max_concurrent_runs,
            },
            history: EffectiveHistory {
                database_path: "[REDACTED ABSOLUTE LOCAL PATH]",
                max_runs: config.history.max_runs,
                max_events_per_run: config.history.max_events_per_run,
                max_age_days: config.history.max_age_days,
                max_bytes: config.history.max_bytes,
            },
            display: EffectiveDisplay {
                target_alias: &config.display.target_alias,
            },
        }
    }
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
