//! Content-safe process command parsing and bounded configuration loading.

use crate::{DaemonConfig, DaemonError, DaemonErrorCode};
use cigar_protocol::BuildMetadata;
use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_POSTGRES_CA_BYTES: u64 = 2 * 1024 * 1024;
const EXIT_USAGE: u8 = 2;
const EXIT_CONFIGURATION: u8 = 78;
const EXIT_SOFTWARE: u8 = 70;
const HELP: &str =
    "Usage: cigard <version|validate-config|migrate|serve> [--config <absolute-path>]\n";

/// Fully rendered process result with stable exit status and content-safe diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    /// Process exit status; zero is reserved for completed commands.
    pub status: u8,
    /// Standard output, including its final newline when non-empty.
    pub stdout: String,
    /// Standard error, including its final newline when non-empty.
    pub stderr: String,
}

impl ProcessOutcome {
    fn success(stdout: String) -> Self {
        Self {
            status: 0,
            stdout,
            stderr: String::new(),
        }
    }

    fn failure(error: DaemonError, status: u8) -> Self {
        Self {
            status,
            stdout: String::new(),
            stderr: format!("{error}\n"),
        }
    }
}

/// Executes one non-serving daemon process command without terminating the caller.
///
/// The standalone `serve` command requires an asynchronous executor and is handled by
/// [`execute_process_command_until`]. Keeping this helper nonblocking prevents library callers
/// from accidentally starting an uninterruptible nested runtime.
#[must_use]
pub fn execute_process_command(arguments: &[OsString]) -> ProcessOutcome {
    match arguments {
        [] => ProcessOutcome::success(HELP.to_owned()),
        [single] if single == "--help" || single == "help" => {
            ProcessOutcome::success(HELP.to_owned())
        }
        [single] if single == "--version" || single == "version" => {
            ProcessOutcome::success(format!(
                "{}\n",
                BuildMetadata::current(env!("CARGO_PKG_VERSION")).to_stable_json()
            ))
        }
        [command, option, path] if command == "validate-config" && option == "--config" => {
            let path = PathBuf::from(path);
            match load_configuration(&path) {
                Ok(_config) => ProcessOutcome::success("{\"status\":\"valid\"}\n".to_owned()),
                Err(error) => ProcessOutcome::failure(error, EXIT_CONFIGURATION),
            }
        }
        [command, option, path] if command == "migrate" && option == "--config" => {
            let path = PathBuf::from(path);
            let config = match load_configuration(&path) {
                Ok(config) => config,
                Err(error) => return ProcessOutcome::failure(error, EXIT_CONFIGURATION),
            };
            match migrate_shared_storage(&config) {
                Ok(receipt) => ProcessOutcome::success(format!(
                    "{{\"checksums_verified\":{},\"latest_sequence\":{},\"status\":\"migrated\"}}\n",
                    receipt.checksums_verified, receipt.latest_sequence
                )),
                Err(error) => ProcessOutcome::failure(error, EXIT_SOFTWARE),
            }
        }
        _ => ProcessOutcome::failure(
            DaemonError::new(DaemonErrorCode::InvalidCommand),
            EXIT_USAGE,
        ),
    }
}

fn migrate_shared_storage(
    config: &DaemonConfig,
) -> Result<cigar_store::PostgresMigrationReceipt, DaemonError> {
    let settings = config
        .shared_storage
        .as_ref()
        .ok_or_else(|| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    let url = read_secret_text(&settings.postgres.migrator_url_file, 8_192)?;
    let mut postgres = cigar_store::PostgresConfiguration::new(url)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    let certificate_authority = read_secret_bytes(
        &settings.postgres.ca_certificate_file,
        MAX_POSTGRES_CA_BYTES,
    )?;
    postgres
        .configure_certificate_authority(
            settings.postgres.server_name.clone(),
            &certificate_authority,
        )
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    postgres.minimum_connections = settings.postgres.minimum_connections;
    postgres.maximum_connections = settings.postgres.maximum_connections;
    postgres.acquire_timeout = Duration::from_millis(settings.postgres.acquire_timeout_ms);
    postgres.statement_timeout = Duration::from_millis(settings.postgres.statement_timeout_ms);
    postgres.lock_timeout = Duration::from_millis(settings.postgres.lock_timeout_ms);
    postgres.idle_transaction_timeout =
        Duration::from_millis(settings.postgres.idle_transaction_timeout_ms);
    postgres
        .validate()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    cigar_store::PostgresStore::migrate(&postgres)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ProductionBootstrapFailed))
}

fn read_secret_text(path: &Path, maximum_bytes: u64) -> Result<String, DaemonError> {
    let mut bytes = read_secret_bytes(path, maximum_bytes)?;
    if bytes.last() == Some(&b'\n') {
        let _newline = bytes.pop();
    }
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
    }
    String::from_utf8(bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))
}

fn read_secret_bytes(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
        }
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|file| file.take(maximum_bytes + 1).read_to_end(&mut bytes))
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum_bytes) {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    Ok(bytes)
}

/// Executes every process command, running `serve` until the supplied shutdown signal resolves.
///
/// This injection point gives process tests and embedding supervisors a deterministic shutdown
/// boundary while the binary supplies real `SIGINT`/`SIGTERM` handling.
pub async fn execute_process_command_until<F>(arguments: &[OsString], signal: F) -> ProcessOutcome
where
    F: Future<Output = ()> + Send,
{
    match arguments {
        [command, option, path] if command == "serve" && option == "--config" => {
            let path = PathBuf::from(path);
            let config = match load_configuration(&path) {
                Ok(config) => config,
                Err(error) => return ProcessOutcome::failure(error, EXIT_CONFIGURATION),
            };
            let server = match crate::compose_production_server(config) {
                Ok(server) => server,
                Err(error) => return ProcessOutcome::failure(error, EXIT_SOFTWARE),
            };
            match server.run_until(signal).await {
                Ok(_receipt) => ProcessOutcome::success("{\"status\":\"stopped\"}\n".to_owned()),
                Err(error) => ProcessOutcome::failure(error, EXIT_SOFTWARE),
            }
        }
        _ => execute_process_command(arguments),
    }
}

/// Executes every process command using the operating system's shutdown signals.
pub async fn execute_process_command_async(arguments: &[OsString]) -> ProcessOutcome {
    execute_process_command_until(arguments, process_shutdown_signal()).await
}

async fn process_shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _result = tokio::signal::ctrl_c() => {},
                _signal = terminate.recv() => {},
            }
            return;
        }
    }
    let _result = tokio::signal::ctrl_c().await;
}

/// Reads a strict daemon configuration from one bounded regular file.
pub fn load_configuration(path: &Path) -> Result<DaemonConfig, DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
    }
    let link_metadata = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if !link_metadata.file_type().is_file()
        || link_metadata.file_type().is_symlink()
        || link_metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let file =
        File::open(path).map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let metadata = file
        .metadata()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_CONFIG_BYTES) {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let input = std::str::from_utf8(&bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    DaemonConfig::from_toml(input)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))
}

/// Writes a process outcome and returns its exit status.
pub fn render_process_outcome(
    outcome: &ProcessOutcome,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    if !outcome.stdout.is_empty() {
        let _ignored = stdout.write_all(outcome.stdout.as_bytes());
    }
    if !outcome.stderr.is_empty() {
        let _ignored = stderr.write_all(outcome.stderr.as_bytes());
    }
    outcome.status
}

#[cfg(test)]
mod tests {
    use super::{execute_process_command, load_configuration};
    use crate::DaemonErrorCode;
    use std::ffi::OsString;
    use std::path::Path;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn default_and_version_commands_are_stable() {
        let help = execute_process_command(&[]);
        assert_eq!(help.status, 0);
        assert_eq!(help.stdout, super::HELP);

        let version = execute_process_command(&arguments(&["version"]));
        assert_eq!(version.status, 0);
        assert!(version.stdout.contains("\"version\":\"0.1.0\""));
        assert!(version.stderr.is_empty());
    }

    #[test]
    fn validates_checked_in_configuration_and_sync_helper_never_blocks_on_serve()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/docker/cigard.example.toml")
            .canonicalize()?;
        let path = path.into_os_string();
        let validate = execute_process_command(&[
            OsString::from("validate-config"),
            OsString::from("--config"),
            path.clone(),
        ]);
        assert_eq!(validate.status, 0);
        assert_eq!(validate.stdout, "{\"status\":\"valid\"}\n");

        let serve =
            execute_process_command(&[OsString::from("serve"), OsString::from("--config"), path]);
        assert_eq!(serve.status, super::EXIT_USAGE);
        assert!(serve.stderr.contains("InvalidCommand"));
        assert!(!serve.stderr.contains("cigard.example.toml"));
        Ok(())
    }

    #[test]
    fn invalid_commands_and_configuration_fail_nonzero_without_echoing_input() {
        let invalid = execute_process_command(&arguments(&["unknown", "super-secret"]));
        assert_eq!(invalid.status, super::EXIT_USAGE);
        assert!(invalid.stderr.contains("InvalidCommand"));
        assert!(!invalid.stderr.contains("super-secret"));

        let relative = load_configuration(Path::new("secret/config.toml"));
        assert_eq!(
            relative.err().map(|error| error.code()),
            Some(DaemonErrorCode::InvalidConfiguration)
        );
    }

    #[cfg(unix)]
    #[test]
    fn configuration_symlinks_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source.toml");
        let link = directory.path().join("link.toml");
        std::fs::write(&source, "not used")?;
        symlink(&source, &link)?;
        let error = match load_configuration(&link) {
            Err(error) => error,
            Ok(_config) => {
                return Err(std::io::Error::other("configuration symlink was accepted").into());
            }
        };
        assert_eq!(error.code(), DaemonErrorCode::ConfigurationIo);
        Ok(())
    }
}
