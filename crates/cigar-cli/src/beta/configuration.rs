//! Closed configuration model for the transport-free initial beta.

use crate::arguments::{OutputFormat, ParsedInvocation, TargetKind};
use crate::error::CliError;
use crate::render::escaped_terminal_text;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

const MAX_CONFIGURATION_BYTES: u64 = 1024 * 1024;

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
    let link = std::fs::symlink_metadata(path).map_err(|_error| CliError::configuration_io())?;
    if link.file_type().is_symlink() || !link.is_file() || link.len() > MAX_CONFIGURATION_BYTES {
        return Err(CliError::configuration_io());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if link.uid() != rustix::process::geteuid().as_raw()
            || link.mode() & 0o022 != 0
            || link.nlink() != 1
        {
            return Err(CliError::configuration_io());
        }
    }
    let mut file = File::open(path).map_err(|_error| CliError::configuration_io())?;
    let metadata = file
        .metadata()
        .map_err(|_error| CliError::configuration_io())?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIGURATION_BYTES {
        return Err(CliError::configuration_io());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.dev() != link.dev()
            || metadata.ino() != link.ino()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(CliError::configuration_io());
        }
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_error| CliError::configuration_io())?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(MAX_CONFIGURATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::configuration_io())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_CONFIGURATION_BYTES) {
        return Err(CliError::configuration_io());
    }
    let after = file
        .metadata()
        .map_err(|_error| CliError::configuration_io())?;
    if after.len() != metadata.len() || !after.is_file() {
        return Err(CliError::configuration_io());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec()
            || after.uid() != rustix::process::geteuid().as_raw()
            || after.mode() & 0o022 != 0
            || after.nlink() != 1
        {
            return Err(CliError::configuration_io());
        }
    }
    Ok(bytes)
}
