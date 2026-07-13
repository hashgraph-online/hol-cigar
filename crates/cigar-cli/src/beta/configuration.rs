//! Closed configuration model for the transport-free initial beta.

use crate::arguments::{OutputFormat, ParsedInvocation, TargetKind};
use crate::error::CliError;
use crate::render::escaped_terminal_text;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

const MAX_CONFIGURATION_BYTES: u64 = 1024 * 1024;
const MAX_CONFIGURATION_READ_WORKERS: usize = 4;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BetaConfiguration {
    schema_version: u32,
    target: String,
    project_state_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveConfiguration {
    project_state_directory: PathBuf,
    state_directory_source: &'static str,
}

impl EffectiveConfiguration {
    /// Loads beta configuration without allowing filesystem I/O to occupy the async runtime.
    ///
    /// A filesystem can ignore `O_NONBLOCK`, so reads run in a small, process-wide bounded worker
    /// pool. Deadline or interrupt wins only while no administration mutation has been started.
    pub(crate) async fn load_until(
        invocation: &ParsedInvocation,
        deadline_at: tokio::time::Instant,
    ) -> Result<Self, CliError> {
        let invocation = invocation.clone();
        run_bounded_configuration_read(move || Self::load(&invocation), deadline_at).await
    }

    pub(crate) fn load(invocation: &ParsedInvocation) -> Result<Self, CliError> {
        if invocation
            .options
            .target
            .is_some_and(|target| target != TargetKind::Embedded)
        {
            return Err(CliError::invalid_configuration());
        }
        if let Some(path) = &invocation.options.config {
            let bytes = read_bounded_regular(path)?;
            let layer: BetaConfiguration =
                toml::from_slice(&bytes).map_err(|_error| CliError::invalid_configuration())?;
            if layer.schema_version != 1 || layer.target != "embedded" {
                return Err(CliError::invalid_configuration());
            }
            let state = validate_state_directory(layer.project_state_directory)?;
            return Ok(Self {
                project_state_directory: state,
                state_directory_source: "explicit beta config",
            });
        }
        let current = std::env::current_dir().map_err(|_error| CliError::configuration_io())?;
        let state = validate_state_directory(current.join(".cigar"))?;
        Ok(Self {
            project_state_directory: state,
            state_directory_source: "compiled beta default",
        })
    }

    pub(crate) const fn target(&self) -> TargetKind {
        TargetKind::Embedded
    }

    pub(crate) fn project_state_directory(&self) -> &Path {
        &self.project_state_directory
    }

    pub(crate) fn explain(&self, output: OutputFormat) -> Result<String, CliError> {
        match output {
            OutputFormat::Json => serde_json::to_string(&json!({
                "schema_version": "cigar.cli.beta-embedded.configuration.v1",
                "profile": "cigar.beta.embedded-local.linux-x86_64.v1",
                "target": {"value": "embedded", "source": "compiled beta profile"},
                "project_state_directory": {
                    "value": self.project_state_directory.display().to_string(),
                    "source": self.state_directory_source
                }
            }))
            .map(|value| format!("{value}\n"))
            .map_err(|_error| CliError::invalid_configuration()),
            OutputFormat::Text => {
                let state_directory =
                    escaped_terminal_text(&self.project_state_directory.display().to_string());
                Ok(format!(
                    concat!(
                        "profile: cigar.beta.embedded-local.linux-x86_64.v1 (compiled beta profile)\n",
                        "target: embedded (compiled beta profile)\n",
                        "project_state_directory: {} ({})\n"
                    ),
                    state_directory, self.state_directory_source
                ))
            }
        }
    }
}

async fn run_bounded_configuration_read<T, F>(
    read: F,
    deadline_at: tokio::time::Instant,
) -> Result<T, CliError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CliError> + Send + 'static,
{
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let slots = Arc::clone(
        SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONFIGURATION_READ_WORKERS))),
    );
    let permit = tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => {
            let _ignored = signal;
            return Err(CliError::interrupted());
        }
        _ = tokio::time::sleep_until(deadline_at) => {
            return Err(CliError::deadline_exceeded());
        }
        permit = slots.acquire_owned() => {
            permit.map_err(|_closed| CliError::configuration_io())?
        }
    };

    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("cigar-beta-configuration-read".to_owned())
        .spawn(move || {
            let result = read();
            let _ignored = sender.send(result);
            drop(permit);
        })
        .map_err(|_error| CliError::configuration_io())?;

    tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => {
            let _ignored = signal;
            Err(CliError::interrupted())
        }
        _ = tokio::time::sleep_until(deadline_at) => Err(CliError::deadline_exceeded()),
        result = receiver => result
            .map_err(|_closed| CliError::configuration_io())?,
    }
}

fn validate_state_directory(path: PathBuf) -> Result<PathBuf, CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || path
            .to_str()
            .is_none_or(|value| value.chars().any(char::is_control))
    {
        Err(CliError::invalid_configuration())
    } else {
        Ok(path)
    }
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>, CliError> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt as _;

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_error| CliError::configuration_io())?;
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_error| CliError::configuration_io())?;
        if !private_regular_metadata(&metadata) || metadata.len() > MAX_CONFIGURATION_BYTES {
            return Err(CliError::configuration_io());
        }

        let binding =
            std::fs::symlink_metadata(path).map_err(|_error| CliError::configuration_io())?;
        if binding.file_type().is_symlink()
            || !private_regular_metadata(&binding)
            || binding.len() > MAX_CONFIGURATION_BYTES
            || binding.dev() != metadata.dev()
            || binding.ino() != metadata.ino()
        {
            return Err(CliError::configuration_io());
        }

        let bytes = read_bounded(&mut file, metadata.len())?;
        let after = file
            .metadata()
            .map_err(|_error| CliError::configuration_io())?;
        if !private_regular_metadata(&after)
            || after.len() != metadata.len()
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec()
        {
            return Err(CliError::configuration_io());
        }

        let rebound =
            std::fs::symlink_metadata(path).map_err(|_error| CliError::configuration_io())?;
        if rebound.file_type().is_symlink()
            || !private_regular_metadata(&rebound)
            || rebound.dev() != after.dev()
            || rebound.ino() != after.ino()
            || rebound.len() != after.len()
            || rebound.mtime() != after.mtime()
            || rebound.mtime_nsec() != after.mtime_nsec()
            || rebound.ctime() != after.ctime()
            || rebound.ctime_nsec() != after.ctime_nsec()
        {
            return Err(CliError::configuration_io());
        }
        Ok(bytes)
    }

    #[cfg(not(unix))]
    {
        let binding =
            std::fs::symlink_metadata(path).map_err(|_error| CliError::configuration_io())?;
        if binding.file_type().is_symlink()
            || !binding.is_file()
            || binding.len() > MAX_CONFIGURATION_BYTES
        {
            return Err(CliError::configuration_io());
        }
        let mut file = File::open(path).map_err(|_error| CliError::configuration_io())?;
        let metadata = file
            .metadata()
            .map_err(|_error| CliError::configuration_io())?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIGURATION_BYTES {
            return Err(CliError::configuration_io());
        }
        let bytes = read_bounded(&mut file, metadata.len())?;
        let after = file
            .metadata()
            .map_err(|_error| CliError::configuration_io())?;
        if !after.is_file() || after.len() != metadata.len() {
            return Err(CliError::configuration_io());
        }
        Ok(bytes)
    }
}

fn read_bounded(file: &mut File, length: u64) -> Result<Vec<u8>, CliError> {
    let capacity = usize::try_from(length).map_err(|_error| CliError::configuration_io())?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(file)
        .take(MAX_CONFIGURATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::configuration_io())?;
    let read = u64::try_from(bytes.len()).map_err(|_error| CliError::configuration_io())?;
    if read > MAX_CONFIGURATION_BYTES || read != length {
        Err(CliError::configuration_io())
    } else {
        Ok(bytes)
    }
}

#[cfg(unix)]
fn private_regular_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o022 == 0
        && metadata.nlink() == 1
}

#[cfg(test)]
mod tests {
    use super::run_bounded_configuration_read;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[tokio::test]
    async fn configuration_workers_are_bounded_and_waiters_honor_deadlines()
    -> Result<(), Box<dyn std::error::Error>> {
        let started = Arc::new(AtomicUsize::new(0));
        let mut releases = Vec::new();
        let mut workers = Vec::new();
        for _index in 0..super::MAX_CONFIGURATION_READ_WORKERS {
            let (release_sender, release_receiver) = mpsc::channel();
            releases.push(release_sender);
            let started = Arc::clone(&started);
            workers.push(tokio::spawn(run_bounded_configuration_read(
                move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    release_receiver
                        .recv()
                        .map_err(|_error| crate::error::CliError::configuration_io())?;
                    Ok(())
                },
                tokio::time::Instant::now() + Duration::from_secs(5),
            )));
        }

        let admission_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while started.load(Ordering::SeqCst) != super::MAX_CONFIGURATION_READ_WORKERS {
            assert!(
                tokio::time::Instant::now() < admission_deadline,
                "configuration workers did not reach the bounded test gate"
            );
            tokio::task::yield_now().await;
        }

        let overflow_started = Arc::clone(&started);
        let began = std::time::Instant::now();
        let overflow = run_bounded_configuration_read(
            move || {
                overflow_started.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            tokio::time::Instant::now() + Duration::from_millis(20),
        )
        .await;
        assert!(overflow.is_err_and(|error| error.code() == "DEADLINE_EXCEEDED"));
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(
            started.load(Ordering::SeqCst),
            super::MAX_CONFIGURATION_READ_WORKERS
        );

        for release in releases {
            release.send(())?;
        }
        for worker in workers {
            worker.await??;
        }
        let recovered_started = Arc::clone(&started);
        run_bounded_configuration_read(
            move || {
                recovered_started.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await?;
        assert_eq!(
            started.load(Ordering::SeqCst),
            super::MAX_CONFIGURATION_READ_WORKERS + 1
        );
        Ok(())
    }
}
