//! Layered CLI target configuration with redacted source explanation.

use crate::arguments::{OutputFormat, ParsedInvocation, TargetKind};
use crate::error::CliError;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_CONFIGURATION_BYTES: u64 = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 8 * 1024;
const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024;
const MAX_LOCAL_TOKEN_BYTES: usize = 128;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ConfigurationLayer {
    schema_version: Option<u32>,
    target: Option<String>,
    local_socket: Option<PathBuf>,
    windows_named_pipe: Option<String>,
    local_endpoint: Option<String>,
    remote_endpoint: Option<String>,
    authorization_file: Option<PathBuf>,
    project_state_directory: Option<PathBuf>,
    daemon_config: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigurationOrigin {
    CompiledDefault,
    SystemConfig,
    UserConfig,
    ProjectConfig,
    ExplicitConfig,
    Environment,
    CliFlag,
    Synthetic,
}

impl ConfigurationOrigin {
    const fn source(self) -> &'static str {
        match self {
            Self::CompiledDefault => "compiled default",
            Self::SystemConfig => "system config",
            Self::UserConfig => "user config",
            Self::ProjectConfig => "project config",
            Self::ExplicitConfig => "explicit config",
            Self::Environment => "environment",
            Self::CliFlag => "CLI flag",
            Self::Synthetic => "not configured",
        }
    }

    const fn explicitly_authorizes_project_endpoint(self) -> bool {
        matches!(
            self,
            Self::ExplicitConfig | Self::Environment | Self::CliFlag
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Sourced<T> {
    value: T,
    source: &'static str,
    origin: ConfigurationOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveConfiguration {
    target: Sourced<TargetKind>,
    endpoint: Sourced<Option<String>>,
    local_socket: Sourced<Option<PathBuf>>,
    windows_named_pipe: Sourced<Option<String>>,
    authorization_file: Sourced<Option<PathBuf>>,
    project_state_directory: Sourced<PathBuf>,
    daemon_config: Sourced<Option<PathBuf>>,
}

impl EffectiveConfiguration {
    pub(crate) fn load(invocation: &ParsedInvocation) -> Result<Self, CliError> {
        let mut accumulator = ConfigurationAccumulator::default();
        let default_state_directory = std::env::current_dir()
            .map_err(|_error| CliError::configuration_io())?
            .join(".cigar");
        let default_local_socket = if cfg!(unix) {
            Some(default_state_directory.join("cigard.sock"))
        } else {
            None
        };
        accumulator.apply(
            ConfigurationLayer {
                schema_version: Some(1),
                target: Some("local".to_owned()),
                local_socket: default_local_socket,
                windows_named_pipe: None,
                local_endpoint: None,
                remote_endpoint: None,
                authorization_file: None,
                project_state_directory: Some(default_state_directory),
                daemon_config: None,
            },
            ConfigurationOrigin::CompiledDefault,
        )?;
        apply_optional_file(
            &mut accumulator,
            Path::new("/etc/cigar/cli.toml"),
            ConfigurationOrigin::SystemConfig,
        )?;
        if let Some(path) = user_configuration_path() {
            apply_optional_file(&mut accumulator, &path, ConfigurationOrigin::UserConfig)?;
        }
        if let Ok(directory) = std::env::current_dir() {
            apply_optional_file(
                &mut accumulator,
                &directory.join(".cigar/cli.toml"),
                ConfigurationOrigin::ProjectConfig,
            )?;
        }
        if let Some(path) = &invocation.options.config {
            accumulator.apply(
                read_layer(path, ConfigurationOrigin::ExplicitConfig)?,
                ConfigurationOrigin::ExplicitConfig,
            )?;
        }
        accumulator.apply(environment_layer()?, ConfigurationOrigin::Environment)?;

        if let Some(target) = invocation.options.target {
            accumulator.target = Some(Sourced {
                value: target,
                source: "CLI flag",
                origin: ConfigurationOrigin::CliFlag,
            });
        }
        if let Some(endpoint) = &invocation.options.endpoint {
            match accumulator
                .target
                .as_ref()
                .map(|value| value.value)
                .unwrap_or_default()
            {
                TargetKind::Local => {
                    accumulator.local_endpoint = Some(Sourced {
                        value: endpoint.clone(),
                        source: "CLI flag",
                        origin: ConfigurationOrigin::CliFlag,
                    });
                    accumulator.local_socket = None;
                    accumulator.windows_named_pipe = None;
                }
                TargetKind::Remote => {
                    accumulator.remote_endpoint = Some(Sourced {
                        value: endpoint.clone(),
                        source: "CLI flag",
                        origin: ConfigurationOrigin::CliFlag,
                    });
                }
                TargetKind::Embedded => return Err(CliError::invalid_configuration()),
            }
        }
        if let Some(path) = &invocation.options.authorization_file {
            accumulator.authorization_file = Some(Sourced {
                value: path.clone(),
                source: "CLI flag",
                origin: ConfigurationOrigin::CliFlag,
            });
        }

        let target = accumulator
            .target
            .ok_or_else(CliError::invalid_configuration)?;
        let endpoint = match target.value {
            TargetKind::Local => accumulator.local_endpoint,
            TargetKind::Remote => accumulator.remote_endpoint,
            TargetKind::Embedded => None,
        };
        let endpoint = Sourced {
            value: endpoint.as_ref().map(|value| value.value.clone()),
            source: endpoint
                .as_ref()
                .map_or("not applicable", |value| value.source),
            origin: endpoint
                .as_ref()
                .map_or(ConfigurationOrigin::Synthetic, |value| value.origin),
        };
        let local_socket = if target.value == TargetKind::Local {
            accumulator.local_socket
        } else {
            None
        };
        let windows_named_pipe = if target.value == TargetKind::Local {
            accumulator.windows_named_pipe
        } else {
            None
        };
        validate_transport(
            target.value,
            endpoint.value.as_deref(),
            local_socket.as_ref().map(|value| value.value.as_path()),
            windows_named_pipe
                .as_ref()
                .map(|value| value.value.as_str()),
            accumulator.authorization_file.is_some(),
        )?;
        validate_credential_origin(
            endpoint.value.as_deref(),
            endpoint.origin,
            accumulator
                .authorization_file
                .as_ref()
                .map(|value| value.origin),
        )?;
        Ok(Self {
            target,
            endpoint,
            local_socket: Sourced {
                value: local_socket.as_ref().map(|value| value.value.clone()),
                source: local_socket
                    .as_ref()
                    .map_or("not configured", |value| value.source),
                origin: local_socket
                    .as_ref()
                    .map_or(ConfigurationOrigin::Synthetic, |value| value.origin),
            },
            windows_named_pipe: Sourced {
                value: windows_named_pipe.as_ref().map(|value| value.value.clone()),
                source: windows_named_pipe
                    .as_ref()
                    .map_or("not configured", |value| value.source),
                origin: windows_named_pipe
                    .as_ref()
                    .map_or(ConfigurationOrigin::Synthetic, |value| value.origin),
            },
            authorization_file: Sourced {
                value: accumulator
                    .authorization_file
                    .as_ref()
                    .map(|value| value.value.clone()),
                source: accumulator
                    .authorization_file
                    .as_ref()
                    .map_or("not configured", |value| value.source),
                origin: accumulator
                    .authorization_file
                    .as_ref()
                    .map_or(ConfigurationOrigin::Synthetic, |value| value.origin),
            },
            project_state_directory: accumulator
                .project_state_directory
                .ok_or_else(CliError::invalid_configuration)?,
            daemon_config: Sourced {
                value: accumulator
                    .daemon_config
                    .as_ref()
                    .map(|value| value.value.clone()),
                source: accumulator
                    .daemon_config
                    .as_ref()
                    .map_or("not configured", |value| value.source),
                origin: accumulator
                    .daemon_config
                    .as_ref()
                    .map_or(ConfigurationOrigin::Synthetic, |value| value.origin),
            },
        })
    }

    pub(crate) const fn target(&self) -> TargetKind {
        self.target.value
    }

    pub(crate) fn endpoint(&self) -> Result<&str, CliError> {
        self.endpoint
            .value
            .as_deref()
            .ok_or_else(CliError::invalid_configuration)
    }

    pub(crate) fn local_socket(&self) -> Option<&Path> {
        self.local_socket.value.as_deref()
    }

    pub(crate) fn windows_named_pipe(&self) -> Option<&str> {
        self.windows_named_pipe.value.as_deref()
    }

    pub(crate) fn authorization(&self) -> Result<Option<String>, CliError> {
        if self.target.value == TargetKind::Embedded
            || (self.target.value == TargetKind::Local
                && (self.local_socket.value.is_some() || self.windows_named_pipe.value.is_some()))
        {
            return Ok(None);
        }
        let Some(path) = &self.authorization_file.value else {
            return if self.target.value == TargetKind::Remote {
                Err(CliError::credential_unavailable())
            } else {
                Ok(None)
            };
        };
        let bytes = read_bounded_regular(path, MAX_CREDENTIAL_BYTES, FilePolicy::Credential)
            .map_err(|_error| CliError::credential_unavailable())?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_error| CliError::credential_unavailable())?;
        let value = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        let token = value.strip_prefix("Bearer ").unwrap_or(value);
        let maximum_token = if self.target.value == TargetKind::Local {
            MAX_LOCAL_TOKEN_BYTES
        } else {
            MAX_AUTHORIZATION_BYTES.saturating_sub("Bearer ".len())
        };
        if token.is_empty()
            || token.len() > maximum_token
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CliError::credential_unavailable());
        }
        let authorization = if value.starts_with("Bearer ") {
            value.to_owned()
        } else {
            format!("Bearer {value}")
        };
        if authorization.len() > MAX_AUTHORIZATION_BYTES {
            Err(CliError::credential_unavailable())
        } else {
            Ok(Some(authorization))
        }
    }

    pub(crate) fn project_state_directory(&self) -> &Path {
        &self.project_state_directory.value
    }

    pub(crate) fn daemon_config(&self) -> Option<&Path> {
        self.daemon_config.value.as_deref()
    }

    pub(crate) fn explain(&self, output: OutputFormat) -> Result<String, CliError> {
        match output {
            OutputFormat::Json => serde_json::to_string(&json!({
                "schema_version": "cigar.cli.configuration.v1",
                "target": {"value": self.target.value.as_str(), "source": self.target.source},
                "endpoint": {"value": self.endpoint.value, "source": self.endpoint.source},
                "local_socket": {
                    "value": self.local_socket.value.as_deref().map(|path| path.display().to_string()),
                    "source": self.local_socket.source
                },
                "windows_named_pipe": {
                    "value": self.windows_named_pipe.value,
                    "source": self.windows_named_pipe.source
                },
                "authorization": {
                    "value": self.authorization_file.value.as_ref().map(|_| "[REDACTED]"),
                    "source": self.authorization_file.source
                },
                "project_state_directory": {
                    "value": self.project_state_directory.value.display().to_string(),
                    "source": self.project_state_directory.source
                },
                "daemon_config": {
                    "value": self.daemon_config.value.as_deref().map(|path| path.display().to_string()),
                    "source": self.daemon_config.source
                }
            }))
            .map(|value| format!("{value}\n"))
            .map_err(|_error| CliError::invalid_configuration()),
            OutputFormat::Text => Ok(format!(
                concat!(
                    "target: {} ({})\n",
                    "endpoint: {} ({})\n",
                    "local_socket: {} ({})\n",
                    "windows_named_pipe: {} ({})\n",
                    "authorization: {} ({})\n",
                    "project_state_directory: {} ({})\n",
                    "daemon_config: {} ({})\n"
                ),
                self.target.value.as_str(),
                self.target.source,
                self.endpoint.value.as_deref().unwrap_or("not applicable"),
                self.endpoint.source,
                self.local_socket
                    .value
                    .as_deref()
                    .map_or_else(|| "not configured".to_owned(), |path| path.display().to_string()),
                self.local_socket.source,
                self.windows_named_pipe.value.as_deref().unwrap_or("not configured"),
                self.windows_named_pipe.source,
                if self.authorization_file.value.is_some() {
                    "[REDACTED]"
                } else {
                    "not configured"
                },
                self.authorization_file.source,
                self.project_state_directory.value.display(),
                self.project_state_directory.source,
                self.daemon_config
                    .value
                    .as_deref()
                    .map_or_else(|| "not configured".to_owned(), |path| path.display().to_string()),
                self.daemon_config.source,
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(target: TargetKind) -> Self {
        Self {
            target: Sourced {
                value: target,
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
            endpoint: Sourced {
                value: None,
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
            local_socket: Sourced {
                value: None,
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
            windows_named_pipe: Sourced {
                value: None,
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
            authorization_file: Sourced {
                value: None,
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
            project_state_directory: Sourced {
                value: PathBuf::from("/test/.cigar"),
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
            daemon_config: Sourced {
                value: None,
                source: "test",
                origin: ConfigurationOrigin::Synthetic,
            },
        }
    }
}

#[derive(Default)]
struct ConfigurationAccumulator {
    target: Option<Sourced<TargetKind>>,
    local_endpoint: Option<Sourced<String>>,
    local_socket: Option<Sourced<PathBuf>>,
    windows_named_pipe: Option<Sourced<String>>,
    remote_endpoint: Option<Sourced<String>>,
    authorization_file: Option<Sourced<PathBuf>>,
    project_state_directory: Option<Sourced<PathBuf>>,
    daemon_config: Option<Sourced<PathBuf>>,
}

impl ConfigurationAccumulator {
    fn apply(
        &mut self,
        layer: ConfigurationLayer,
        origin: ConfigurationOrigin,
    ) -> Result<(), CliError> {
        let source = origin.source();
        if layer.schema_version.is_some_and(|version| version != 1) {
            return Err(CliError::invalid_configuration());
        }
        let local_transports = usize::from(layer.local_endpoint.is_some())
            + usize::from(layer.local_socket.is_some())
            + usize::from(layer.windows_named_pipe.is_some());
        if local_transports > 1
            || (local_transports != 0 && layer.remote_endpoint.is_some())
            || (origin == ConfigurationOrigin::ProjectConfig && layer.authorization_file.is_some())
        {
            return Err(CliError::invalid_configuration());
        }
        if let Some(target) = layer.target.as_deref().map(parse_target).transpose()? {
            let incompatible = match target {
                TargetKind::Embedded => {
                    local_transports != 0
                        || layer.remote_endpoint.is_some()
                        || layer.authorization_file.is_some()
                }
                TargetKind::Local => layer.remote_endpoint.is_some(),
                TargetKind::Remote => local_transports != 0,
            };
            if incompatible {
                return Err(CliError::invalid_configuration());
            }
        }
        if let Some(target) = layer.target {
            self.target = Some(Sourced {
                value: parse_target(&target)?,
                source,
                origin,
            });
        }
        if let Some(endpoint) = layer.local_endpoint {
            self.local_endpoint = Some(Sourced {
                value: endpoint,
                source,
                origin,
            });
            self.local_socket = None;
            self.windows_named_pipe = None;
        }
        if let Some(path) = layer.local_socket {
            if !path.is_absolute() {
                return Err(CliError::invalid_configuration());
            }
            self.local_socket = Some(Sourced {
                value: path,
                source,
                origin,
            });
            self.local_endpoint = None;
            self.windows_named_pipe = None;
        }
        if let Some(pipe) = layer.windows_named_pipe {
            if !safe_windows_pipe(&pipe) {
                return Err(CliError::invalid_configuration());
            }
            self.windows_named_pipe = Some(Sourced {
                value: pipe,
                source,
                origin,
            });
            self.local_endpoint = None;
            self.local_socket = None;
        }
        if let Some(endpoint) = layer.remote_endpoint {
            self.remote_endpoint = Some(Sourced {
                value: endpoint,
                source,
                origin,
            });
        }
        if let Some(path) = layer.authorization_file {
            self.authorization_file = Some(Sourced {
                value: path,
                source,
                origin,
            });
        }
        if let Some(path) = layer.project_state_directory {
            if !path.is_absolute() {
                return Err(CliError::invalid_configuration());
            }
            self.project_state_directory = Some(Sourced {
                value: path,
                source,
                origin,
            });
        }
        if let Some(path) = layer.daemon_config {
            if !path.is_absolute() {
                return Err(CliError::invalid_configuration());
            }
            self.daemon_config = Some(Sourced {
                value: path,
                source,
                origin,
            });
        }
        Ok(())
    }
}

fn parse_target(value: &str) -> Result<TargetKind, CliError> {
    match value {
        "embedded" => Ok(TargetKind::Embedded),
        "local" => Ok(TargetKind::Local),
        "remote" => Ok(TargetKind::Remote),
        _ => Err(CliError::invalid_configuration()),
    }
}

fn environment_layer() -> Result<ConfigurationLayer, CliError> {
    let has_raw_authorization = std::env::var_os("CIGAR_AUTHORIZATION").is_some();
    let has_raw_token = std::env::var_os("CIGAR_TOKEN").is_some();
    let target = std::env::var("CIGAR_TARGET").ok();
    let endpoint = std::env::var("CIGAR_ENDPOINT").ok();
    let authorization_file = std::env::var_os("CIGAR_AUTHORIZATION_FILE").map(PathBuf::from);
    let local_socket = std::env::var_os("CIGAR_LOCAL_SOCKET").map(PathBuf::from);
    let windows_named_pipe = std::env::var("CIGAR_WINDOWS_NAMED_PIPE").ok();
    let project_state_directory =
        std::env::var_os("CIGAR_PROJECT_STATE_DIRECTORY").map(PathBuf::from);
    let daemon_config = std::env::var_os("CIGAR_DAEMON_CONFIG").map(PathBuf::from);
    let parsed_target = validate_environment_authority(
        has_raw_authorization,
        has_raw_token,
        target.as_deref(),
        endpoint.is_some(),
    )?;
    Ok(ConfigurationLayer {
        schema_version: Some(1),
        target,
        local_socket,
        windows_named_pipe,
        local_endpoint: if parsed_target != Some(TargetKind::Remote) {
            endpoint.clone()
        } else {
            None
        },
        remote_endpoint: if parsed_target == Some(TargetKind::Remote) {
            endpoint
        } else {
            None
        },
        authorization_file,
        project_state_directory,
        daemon_config,
    })
}

fn validate_environment_authority(
    has_raw_authorization: bool,
    has_raw_token: bool,
    target: Option<&str>,
    has_endpoint: bool,
) -> Result<Option<TargetKind>, CliError> {
    if has_raw_authorization || has_raw_token {
        return Err(CliError::invalid_configuration());
    }
    let parsed_target = target.map(parse_target).transpose()?;
    if has_endpoint && parsed_target.is_none() {
        return Err(CliError::invalid_configuration());
    }
    Ok(parsed_target)
}

fn user_configuration_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .map(|path| path.join("cigar/cli.toml"))
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|path| path.join(".config/cigar/cli.toml"))
        })
}

fn apply_optional_file(
    accumulator: &mut ConfigurationAccumulator,
    path: &Path,
    origin: ConfigurationOrigin,
) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(_metadata) => accumulator.apply(read_layer(path, origin)?, origin),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_error) => Err(CliError::configuration_io()),
    }
}

fn read_layer(path: &Path, _origin: ConfigurationOrigin) -> Result<ConfigurationLayer, CliError> {
    let bytes = read_bounded_regular(path, MAX_CONFIGURATION_BYTES, FilePolicy::Configuration)?;
    let text = std::str::from_utf8(&bytes).map_err(|_error| CliError::invalid_configuration())?;
    toml::from_str(text).map_err(|_error| CliError::invalid_configuration())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilePolicy {
    Configuration,
    Credential,
}

fn file_error(policy: FilePolicy) -> CliError {
    match policy {
        FilePolicy::Configuration => CliError::configuration_io(),
        FilePolicy::Credential => CliError::credential_unavailable(),
    }
}

fn read_bounded_regular(
    path: &Path,
    maximum: u64,
    policy: FilePolicy,
) -> Result<Vec<u8>, CliError> {
    let link = std::fs::symlink_metadata(path).map_err(|_error| CliError::configuration_io())?;
    if link.file_type().is_symlink() || !link.is_file() || link.len() > maximum {
        return Err(file_error(policy));
    }
    let mut file = open_bounded_read(path).map_err(|_error| file_error(policy))?;
    let opened = file.metadata().map_err(|_error| file_error(policy))?;
    if !opened.is_file()
        || opened.len() > maximum
        || !same_file(&link, &opened)
        || !safe_file_metadata(&opened, policy)
    {
        return Err(file_error(policy));
    }
    let capacity = usize::try_from(opened.len()).map_err(|_error| file_error(policy))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| file_error(policy))?;
    let after_read = file.metadata().map_err(|_error| file_error(policy))?;
    let final_link = std::fs::symlink_metadata(path).map_err(|_error| file_error(policy))?;
    if final_link.file_type().is_symlink()
        || !same_file(&opened, &after_read)
        || !same_file(&after_read, &final_link)
        || !stable_file(&opened, &after_read)
        || u64::try_from(bytes.len()).map_or(true, |length| {
            length > maximum || length != after_read.len()
        })
    {
        return Err(file_error(policy));
    }
    Ok(bytes)
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

    let normalized_path = trusted_platform_read_path(path)?;
    let mut absolute = false;
    let mut names = Vec::new();
    for component in normalized_path.components() {
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

#[cfg(target_os = "macos")]
fn trusted_platform_read_path(path: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    // macOS exposes these root-owned, system-managed aliases on normal installations. Resolve
    // only the closed aliases after verifying their owner and exact target; arbitrary symlinked
    // ancestors remain rejected by the descriptor walk below.
    for (alias, relative_target, absolute_target) in [
        ("/etc", "private/etc", "/private/etc"),
        ("/tmp", "private/tmp", "/private/tmp"),
        ("/var", "private/var", "/private/var"),
    ] {
        let alias_path = Path::new(alias);
        let Ok(remainder) = path.strip_prefix(alias_path) else {
            continue;
        };
        let metadata = std::fs::symlink_metadata(alias_path)?;
        if !metadata.file_type().is_symlink() {
            return Ok(path.to_path_buf());
        }
        let target = std::fs::read_link(alias_path)?;
        if metadata.uid() != 0
            || (target != Path::new(relative_target) && target != Path::new(absolute_target))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "untrusted platform path alias",
            ));
        }
        return Ok(Path::new(absolute_target).join(remainder));
    }
    Ok(path.to_path_buf())
}

#[cfg(not(target_os = "macos"))]
fn trusted_platform_read_path(path: &Path) -> std::io::Result<PathBuf> {
    Ok(path.to_path_buf())
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

fn safe_file_metadata(metadata: &std::fs::Metadata, policy: FilePolicy) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_uid = rustix::process::geteuid().as_raw();
        let owner = metadata.uid();
        if metadata.nlink() != 1 || (owner != 0 && owner != effective_uid) {
            return false;
        }
        match policy {
            FilePolicy::Configuration => metadata.mode() & 0o022 == 0,
            FilePolicy::Credential => {
                metadata.uid() == effective_uid && metadata.mode() & 0o077 == 0
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = policy;
        metadata.is_file()
    }
}

fn validate_credential_origin(
    endpoint: Option<&str>,
    endpoint_origin: ConfigurationOrigin,
    authorization_origin: Option<ConfigurationOrigin>,
) -> Result<(), CliError> {
    let Some(authorization_origin) = authorization_origin else {
        return Ok(());
    };
    if endpoint.is_none() {
        return Ok(());
    }
    if authorization_origin == ConfigurationOrigin::ProjectConfig
        || (endpoint_origin == ConfigurationOrigin::ProjectConfig
            && !authorization_origin.explicitly_authorizes_project_endpoint())
    {
        return Err(CliError::invalid_configuration());
    }
    Ok(())
}

fn validate_transport(
    target: TargetKind,
    endpoint: Option<&str>,
    local_socket: Option<&Path>,
    windows_named_pipe: Option<&str>,
    has_authorization_file: bool,
) -> Result<(), CliError> {
    if target == TargetKind::Embedded {
        return if endpoint.is_none()
            && local_socket.is_none()
            && windows_named_pipe.is_none()
            && !has_authorization_file
        {
            Ok(())
        } else {
            Err(CliError::invalid_configuration())
        };
    }
    if target == TargetKind::Local {
        let configured = usize::from(endpoint.is_some())
            + usize::from(local_socket.is_some())
            + usize::from(windows_named_pipe.is_some());
        if configured != 1 {
            return Err(CliError::invalid_configuration());
        }
        if let Some(path) = local_socket {
            return if cfg!(unix) && path.is_absolute() && !has_authorization_file {
                Ok(())
            } else {
                Err(CliError::invalid_configuration())
            };
        }
        if let Some(pipe) = windows_named_pipe {
            return if cfg!(windows) && safe_windows_pipe(pipe) && !has_authorization_file {
                Ok(())
            } else {
                Err(CliError::invalid_configuration())
            };
        }
    } else if local_socket.is_some() || windows_named_pipe.is_some() {
        return Err(CliError::invalid_configuration());
    }
    let value = endpoint.ok_or_else(CliError::invalid_configuration)?;
    let url = reqwest::Url::parse(value).map_err(|_error| CliError::invalid_configuration())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(CliError::invalid_configuration());
    }
    match target {
        TargetKind::Local
            if url.scheme() == "http"
                && url
                    .host_str()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"))
                && has_authorization_file =>
        {
            Ok(())
        }
        TargetKind::Remote
            if url.scheme() == "https" && url.host_str().is_some() && has_authorization_file =>
        {
            Ok(())
        }
        _ => Err(CliError::invalid_configuration()),
    }
}

fn safe_windows_pipe(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(r"\\.\pipe\cigar-") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 256
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::open_bounded_read_before_final;
    #[cfg(target_os = "macos")]
    use super::trusted_platform_read_path;
    use super::{
        ConfigurationAccumulator, ConfigurationLayer, ConfigurationOrigin, EffectiveConfiguration,
        FilePolicy, MAX_CONFIGURATION_BYTES, MAX_CREDENTIAL_BYTES, read_bounded_regular,
        validate_environment_authority, validate_transport,
    };
    use crate::TerminalContext;
    use crate::arguments::{OutputFormat, TargetKind, parse};
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[cfg(target_os = "macos")]
    #[test]
    fn root_owned_macos_aliases_normalize_without_allowing_arbitrary_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            trusted_platform_read_path(std::path::Path::new("/var/folders/example"))?,
            PathBuf::from("/private/var/folders/example")
        );
        assert_eq!(
            trusted_platform_read_path(std::path::Path::new("/tmp/example"))?,
            PathBuf::from("/private/tmp/example")
        );
        assert_eq!(
            trusted_platform_read_path(std::path::Path::new("/etc/cigar/cli.toml"))?,
            PathBuf::from("/private/etc/cigar/cli.toml")
        );
        Ok(())
    }

    #[test]
    fn explicit_configuration_explains_sources_and_redacts_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let token = root.join("token with space");
        std::fs::write(&token, "do-not-echo")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        }
        let config = root.join("cli config.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\ntarget = \"remote\"\nremote_endpoint = \"https://example.test\"\nauthorization_file = {:?}\n",
                token
            ),
        )?;
        let invocation = parse(
            vec![
                OsString::from("status"),
                OsString::from("--config"),
                config.into_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            TerminalContext::default(),
        )?;
        let effective = EffectiveConfiguration::load(&invocation)?;
        assert_eq!(
            effective.authorization()?,
            Some("Bearer do-not-echo".to_owned())
        );
        let rendered = effective.explain(OutputFormat::Json)?;
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("do-not-echo"));
        assert!(rendered.contains("explicit config"));
        Ok(())
    }

    #[test]
    fn authorization_rejects_non_graphic_non_ascii_and_over_bound_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let token = root.join("token");
        let config = root.join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\ntarget = \"remote\"\nremote_endpoint = \"https://example.test\"\nauthorization_file = {:?}\n",
                token
            ),
        )?;
        let invocation = parse(
            vec![
                OsString::from("status"),
                OsString::from("--config"),
                config.into_os_string(),
            ],
            TerminalContext::default(),
        )?;
        let effective = EffectiveConfiguration::load(&invocation)?;
        for invalid in [
            b" leading".as_slice(),
            b"interior space".as_slice(),
            b"Bearer two tokens".as_slice(),
            b"token\tvalue".as_slice(),
            "töken".as_bytes(),
            b"token\n\n".as_slice(),
        ] {
            std::fs::write(&token, invalid)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
            }
            assert!(effective.authorization().is_err());
        }
        std::fs::write(&token, vec![b'a'; 8 * 1024 - "Bearer ".len() + 1])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        }
        assert!(effective.authorization().is_err());
        Ok(())
    }

    #[test]
    fn one_layer_cannot_ambiguously_select_multiple_transports() {
        let local_fields = [
            ConfigurationLayer {
                local_endpoint: Some("http://127.0.0.1:7443".to_owned()),
                ..ConfigurationLayer::default()
            },
            ConfigurationLayer {
                local_socket: Some(PathBuf::from("/tmp/cigard.sock")),
                ..ConfigurationLayer::default()
            },
            ConfigurationLayer {
                windows_named_pipe: Some(r"\\.\pipe\cigar-local".to_owned()),
                ..ConfigurationLayer::default()
            },
        ];
        for (left_index, left) in local_fields.iter().enumerate() {
            for (right_index, right) in local_fields.iter().enumerate().skip(left_index + 1) {
                let mut candidate = ConfigurationLayer::default();
                for selected in [left, right] {
                    candidate.local_endpoint = candidate
                        .local_endpoint
                        .take()
                        .or_else(|| selected.local_endpoint.clone());
                    candidate.local_socket = candidate
                        .local_socket
                        .take()
                        .or_else(|| selected.local_socket.clone());
                    candidate.windows_named_pipe = candidate
                        .windows_named_pipe
                        .take()
                        .or_else(|| selected.windows_named_pipe.clone());
                }
                assert!(
                    ConfigurationAccumulator::default()
                        .apply(candidate, ConfigurationOrigin::ExplicitConfig)
                        .is_err(),
                    "transport pair {left_index}/{right_index} must fail closed"
                );
            }
        }
    }

    #[test]
    fn credentials_and_remote_url_authority_are_exact_and_unambiguous() {
        assert!(
            validate_transport(TargetKind::Embedded, None, None, None, true).is_err(),
            "embedded execution must not silently discard an authorization file"
        );
        #[cfg(unix)]
        assert!(
            validate_transport(
                TargetKind::Local,
                None,
                Some(std::path::Path::new("/tmp/cigard.sock")),
                None,
                true,
            )
            .is_err(),
            "owner-private Unix IPC must not silently discard an authorization file"
        );
        assert!(
            validate_transport(
                TargetKind::Local,
                Some("http://127.0.0.1:7443"),
                None,
                None,
                true,
            )
            .is_ok(),
            "loopback TCP must consume an explicit authorization file"
        );
        assert!(
            validate_transport(
                TargetKind::Remote,
                Some("https://cigar.example"),
                None,
                None,
                true,
            )
            .is_ok(),
            "remote HTTPS may consume an explicit authorization file"
        );
        assert!(
            validate_transport(
                TargetKind::Remote,
                Some("https://cigar.example"),
                None,
                None,
                false,
            )
            .is_err(),
            "remote HTTPS must never start without explicit authorization authority"
        );

        for endpoint in [
            "http://cigar.example/",
            "https://user@cigar.example/",
            "https://%75ser:%70ass@cigar.example/",
            "https://cigar.example/?authorization=Bearer%20secret",
            "https://cigar.example/#Bearer-secret",
            "https://cigar.example/v1",
        ] {
            assert!(
                validate_transport(TargetKind::Remote, Some(endpoint), None, None, true).is_err(),
                "ambiguous remote authority unexpectedly accepted: {endpoint}"
            );
        }
    }

    #[test]
    fn layer_target_and_project_secret_authority_fail_closed() {
        let cases = [
            (
                ConfigurationLayer {
                    target: Some("embedded".to_owned()),
                    remote_endpoint: Some("https://example.test".to_owned()),
                    ..ConfigurationLayer::default()
                },
                ConfigurationOrigin::ExplicitConfig,
            ),
            (
                ConfigurationLayer {
                    target: Some("local".to_owned()),
                    remote_endpoint: Some("https://example.test".to_owned()),
                    ..ConfigurationLayer::default()
                },
                ConfigurationOrigin::ExplicitConfig,
            ),
            (
                ConfigurationLayer {
                    target: Some("remote".to_owned()),
                    local_socket: Some(PathBuf::from("/tmp/cigard.sock")),
                    ..ConfigurationLayer::default()
                },
                ConfigurationOrigin::ExplicitConfig,
            ),
            (
                ConfigurationLayer {
                    authorization_file: Some(PathBuf::from("/tmp/token")),
                    ..ConfigurationLayer::default()
                },
                ConfigurationOrigin::ProjectConfig,
            ),
        ];
        for (layer, origin) in cases {
            assert!(
                ConfigurationAccumulator::default()
                    .apply(layer, origin)
                    .is_err()
            );
        }
    }

    #[test]
    fn precedence_is_low_to_high_and_provenance_tracks_the_winner()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut accumulator = ConfigurationAccumulator::default();
        for (index, origin) in [
            ConfigurationOrigin::CompiledDefault,
            ConfigurationOrigin::SystemConfig,
            ConfigurationOrigin::UserConfig,
            ConfigurationOrigin::ProjectConfig,
            ConfigurationOrigin::ExplicitConfig,
            ConfigurationOrigin::Environment,
            ConfigurationOrigin::CliFlag,
        ]
        .into_iter()
        .enumerate()
        {
            accumulator.apply(
                ConfigurationLayer {
                    schema_version: Some(1),
                    project_state_directory: Some(PathBuf::from(format!("/tmp/cigar-{index}"))),
                    ..ConfigurationLayer::default()
                },
                origin,
            )?;
        }
        let winner = accumulator
            .project_state_directory
            .ok_or("missing winner")?;
        assert_eq!(winner.value, PathBuf::from("/tmp/cigar-6"));
        assert_eq!(winner.source, "CLI flag");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn configuration_and_secret_files_are_descriptor_bound_and_owner_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::hard_link;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let config = root.join("cli.toml");
        std::fs::write(&config, "schema_version = 1\n")?;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644))?;
        assert!(
            read_bounded_regular(&config, MAX_CONFIGURATION_BYTES, FilePolicy::Configuration)
                .is_ok()
        );

        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666))?;
        assert!(
            read_bounded_regular(&config, MAX_CONFIGURATION_BYTES, FilePolicy::Configuration)
                .is_err()
        );
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))?;

        let hardlink = root.join("hardlink.toml");
        hard_link(&config, &hardlink)?;
        assert!(
            read_bounded_regular(&config, MAX_CONFIGURATION_BYTES, FilePolicy::Configuration)
                .is_err()
        );
        std::fs::remove_file(hardlink)?;

        let symlink_path = root.join("symlink.toml");
        symlink(&config, &symlink_path)?;
        assert!(
            read_bounded_regular(
                &symlink_path,
                MAX_CONFIGURATION_BYTES,
                FilePolicy::Configuration,
            )
            .is_err()
        );

        let fifo = root.join("config.fifo");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
        assert!(status.success());
        assert!(
            read_bounded_regular(&fifo, MAX_CONFIGURATION_BYTES, FilePolicy::Configuration)
                .is_err(),
            "a project configuration FIFO must fail without a blocking open"
        );

        let credential = root.join("credential");
        std::fs::write(&credential, "token")?;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o640))?;
        assert!(
            read_bounded_regular(&credential, MAX_CREDENTIAL_BYTES, FilePolicy::Credential)
                .is_err()
        );
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            read_bounded_regular(&credential, MAX_CREDENTIAL_BYTES, FilePolicy::Credential)?,
            b"token"
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
        let replacement = root.join("replacement");
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

    #[test]
    fn target_values_remain_closed() {
        let mut accumulator = ConfigurationAccumulator::default();
        assert!(
            accumulator
                .apply(
                    ConfigurationLayer {
                        target: Some("shared".to_owned()),
                        ..ConfigurationLayer::default()
                    },
                    ConfigurationOrigin::ExplicitConfig,
                )
                .is_err()
        );
        assert_eq!(TargetKind::default(), TargetKind::Local);
    }

    #[test]
    fn environment_rejects_raw_secrets_and_untyped_endpoints() {
        for (raw_authorization, raw_token) in [(true, false), (false, true), (true, true)] {
            assert!(
                validate_environment_authority(raw_authorization, raw_token, Some("remote"), true,)
                    .is_err()
            );
        }
        assert!(validate_environment_authority(false, false, None, true).is_err());
        assert!(matches!(
            validate_environment_authority(false, false, Some("remote"), true),
            Ok(Some(TargetKind::Remote))
        ));
        assert!(matches!(
            validate_environment_authority(false, false, Some("local"), true),
            Ok(Some(TargetKind::Local))
        ));
    }
}
