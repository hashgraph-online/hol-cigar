//! Dashboard sidecar process entry point.

use cigar_dashboard::{DashboardApplication, DashboardConfig};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
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
            "serve" if !serve => serve = true,
            _ => {
                return Err(
                    "usage: cigar-dashboard serve --config <absolute-path> | cigar-dashboard --config <absolute-path> --check-config",
                );
            }
        }
        index += 1;
    }
    let path = config_path.ok_or("--config is required")?;
    let config =
        DashboardConfig::from_file(&path).map_err(|_error| "dashboard configuration is invalid")?;
    if check_config && !serve {
        println!("dashboard configuration valid");
        return Ok(());
    }
    if !serve || check_config {
        return Err(
            "usage: cigar-dashboard serve --config <absolute-path> | --config <path> --check-config",
        );
    }
    let application = DashboardApplication::initialize(&config)
        .map_err(|_error| "dashboard initialization failed")?;
    let status_monitor = application.start_status_monitor(&config);
    let listener = tokio::net::TcpListener::bind(application.listen())
        .await
        .map_err(|_error| "dashboard listener failed")?;
    eprintln!(
        "dashboard one-time URL: http://{}/#bootstrap={}",
        application.listen(),
        application.bootstrap_token()
    );
    let result = axum::serve(listener, application.router())
        .with_graceful_shutdown(shutdown_signal())
        .await;
    status_monitor.shutdown().await;
    application.cleanup_bootstrap_file();
    result.map_err(|_error| "dashboard server failed")
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
