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

pub(crate) fn read_secret_bytes(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
    }
    let link = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if link.file_type().is_symlink()
        || !link.is_file()
        || link.len() == 0
        || link.len() > maximum_bytes
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let mut file = open_bounded_read(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let opened = file
        .metadata()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if !opened.is_file()
        || opened.len() == 0
        || opened.len() > maximum_bytes
        || !same_file(&link, &opened)
        || !safe_secret_metadata(&opened)
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let after_read = file
        .metadata()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let final_link = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if final_link.file_type().is_symlink()
        || !same_file(&opened, &after_read)
        || !same_file(&after_read, &final_link)
        || !stable_file(&opened, &after_read)
        || u64::try_from(bytes.len()).map_or(true, |length| {
            length > maximum_bytes || length != after_read.len()
        })
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    Ok(bytes)
}

fn safe_secret_metadata(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
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
    let mut file = open_bounded_read(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let opened = file
        .metadata()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if !opened.is_file()
        || opened.len() > MAX_CONFIG_BYTES
        || !same_file(&link_metadata, &opened)
        || !safe_configuration_metadata(&opened)
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let after_read = file
        .metadata()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    let final_link = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ConfigurationIo))?;
    if final_link.file_type().is_symlink()
        || !same_file(&opened, &after_read)
        || !same_file(&after_read, &final_link)
        || !stable_file(&opened, &after_read)
        || u64::try_from(bytes.len()).map_or(true, |length| {
            length > MAX_CONFIG_BYTES || length != after_read.len()
        })
    {
        return Err(DaemonError::new(DaemonErrorCode::ConfigurationIo));
    }
    let input = std::str::from_utf8(&bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    DaemonConfig::from_toml(input)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

#[cfg(unix)]
fn stable_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
}

#[cfg(not(unix))]
fn stable_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn safe_configuration_metadata(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let owner = metadata.uid();
        let effective_uid = rustix::process::geteuid().as_raw();
        metadata.nlink() == 1
            && (owner == 0 || owner == effective_uid)
            && metadata.mode() & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

#[cfg(unix)]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    open_bounded_read_before_final(path, || Ok(()))
}

#[cfg(unix)]
fn open_bounded_read_before_final(
    path: &Path,
    before_final: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;

    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if names.is_empty() && !absolute => absolute = true,
            Component::Normal(name) => names.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(invalid_read_path()),
        }
    }
    let (file_name, ancestors) = names.split_last().ok_or_else(invalid_read_path)?;
    let base = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = open(
        base,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)?;
    validate_read_ancestor(&directory.metadata()?)?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            *ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)?;
        validate_read_ancestor(&directory.metadata()?)?;
    }
    before_final()?;
    openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(unix)]
fn validate_read_ancestor(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if metadata.is_dir()
        && (owner == 0 || owner == rustix::process::geteuid().as_raw())
        && (!writable_by_others || protected_sticky_root)
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe file ancestor",
        ))
    }
}

#[cfg(unix)]
fn invalid_read_path() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid file path")
}

#[cfg(not(unix))]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    File::open(path)
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
    #[cfg(unix)]
    use super::open_bounded_read_before_final;
    use super::{execute_process_command, load_configuration, read_secret_bytes, same_file};
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
        assert!(version.stdout.contains("\"version\":\"0.9.2\""));
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
        let root = std::fs::canonicalize(directory.path())?;
        let source = root.join("source.toml");
        let link = root.join("link.toml");
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

    #[cfg(unix)]
    #[test]
    fn configuration_owner_mode_and_link_count_are_enforced()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::hard_link;
        use std::os::unix::fs::PermissionsExt as _;

        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/docker/cigard.example.toml");
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let config = root.join("cigard.toml");
        std::fs::copy(source, &config)?;

        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666))?;
        assert_eq!(
            load_configuration(&config).err().map(|error| error.code()),
            Some(DaemonErrorCode::ConfigurationIo)
        );

        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))?;
        assert!(load_configuration(&config).is_ok());
        let alias = root.join("cigard-alias.toml");
        hard_link(&config, alias)?;
        assert_eq!(
            load_configuration(&config).err().map(|error| error.code()),
            Some(DaemonErrorCode::ConfigurationIo)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn secret_reads_reject_modes_links_and_replacement_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::hard_link;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let secret = root.join("secret");
        std::fs::write(&secret, b"explicit-secret")?;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(read_secret_bytes(&secret, 64)?, b"explicit-secret");

        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640))?;
        assert!(read_secret_bytes(&secret, 64).is_err());
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))?;

        let alias = root.join("secret-hardlink");
        hard_link(&secret, &alias)?;
        assert!(read_secret_bytes(&secret, 64).is_err());
        std::fs::remove_file(alias)?;

        let link = root.join("secret-symlink");
        symlink(&secret, &link)?;
        assert!(read_secret_bytes(&link, 64).is_err());

        let fifo = root.join("secret-fifo");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
        assert!(status.success());
        assert!(
            read_secret_bytes(&fifo, 64).is_err(),
            "a secret FIFO must fail without a blocking open"
        );
        assert!(
            load_configuration(&fifo).is_err(),
            "a daemon configuration FIFO must fail without a blocking open"
        );

        let replacement = root.join("replacement");
        std::fs::write(&replacement, b"replacement-secret")?;
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))?;
        let opened_identity = std::fs::metadata(&secret)?;
        let replacement_identity = std::fs::metadata(&replacement)?;
        assert!(
            !same_file(&opened_identity, &replacement_identity),
            "a final-component replacement must fail the descriptor identity binding"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reads_reject_symlinked_ancestors_and_pin_open_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read as _;
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let trusted = root.join("trusted");
        let replacement = root.join("replacement-directory");
        std::fs::create_dir(&trusted)?;
        std::fs::create_dir(&replacement)?;
        std::fs::write(trusted.join("value"), b"trusted")?;
        std::fs::write(replacement.join("value"), b"substituted")?;

        let alias = root.join("alias");
        symlink(&trusted, &alias)?;
        assert!(open_bounded_read_before_final(&alias.join("value"), || Ok(())).is_err());

        let moved = root.join("moved");
        let requested = trusted.join("value");
        let mut opened = open_bounded_read_before_final(&requested, || {
            std::fs::rename(&trusted, &moved)?;
            std::fs::rename(&replacement, &trusted)?;
            Ok(())
        })?;
        let mut value = String::new();
        opened.read_to_string(&mut value)?;
        assert_eq!(value, "trusted");
        assert_eq!(std::fs::read_to_string(&requested)?, "substituted");
        Ok(())
    }
}
