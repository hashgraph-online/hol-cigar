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
            accumulator.apply(read_layer(path)?, ConfigurationOrigin::ExplicitConfig)?;
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
            return Ok(None);
        };
        let bytes = read_bounded_regular(path, MAX_CREDENTIAL_BYTES)
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
    let target = std::env::var("CIGAR_TARGET").ok();
    let endpoint = std::env::var("CIGAR_ENDPOINT").ok();
    let authorization_file = std::env::var_os("CIGAR_AUTHORIZATION_FILE").map(PathBuf::from);
    let local_socket = std::env::var_os("CIGAR_LOCAL_SOCKET").map(PathBuf::from);
    let windows_named_pipe = std::env::var("CIGAR_WINDOWS_NAMED_PIPE").ok();
    let project_state_directory =
        std::env::var_os("CIGAR_PROJECT_STATE_DIRECTORY").map(PathBuf::from);
    let daemon_config = std::env::var_os("CIGAR_DAEMON_CONFIG").map(PathBuf::from);
    let parsed_target = target.as_deref().map(parse_target).transpose()?;
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
        Ok(_metadata) => accumulator.apply(read_layer(path)?, origin),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_error) => Err(CliError::configuration_io()),
    }
}

fn read_layer(path: &Path) -> Result<ConfigurationLayer, CliError> {
    let bytes = read_bounded_regular(path, MAX_CONFIGURATION_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_error| CliError::invalid_configuration())?;
    toml::from_str(text).map_err(|_error| CliError::invalid_configuration())
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let link = std::fs::symlink_metadata(path).map_err(|_error| CliError::configuration_io())?;
    if link.file_type().is_symlink() || !link.is_file() || link.len() > maximum {
        return Err(CliError::configuration_io());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if maximum == MAX_CREDENTIAL_BYTES && link.mode() & 0o077 != 0 {
            return Err(CliError::credential_unavailable());
        }
    }
    let file = File::open(path).map_err(|_error| CliError::configuration_io())?;
    let metadata = file
        .metadata()
        .map_err(|_error| CliError::configuration_io())?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(CliError::configuration_io());
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_error| CliError::configuration_io())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::configuration_io())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(CliError::configuration_io());
    }
    Ok(bytes)
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
        return if endpoint.is_none() && local_socket.is_none() && windows_named_pipe.is_none() {
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
            return if cfg!(unix) && path.is_absolute() {
                Ok(())
            } else {
                Err(CliError::invalid_configuration())
            };
        }
        if let Some(pipe) = windows_named_pipe {
            return if cfg!(windows) && safe_windows_pipe(pipe) {
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
        TargetKind::Remote if url.scheme() == "https" && url.host_str().is_some() => Ok(()),
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
    use super::EffectiveConfiguration;
    use crate::TerminalContext;
    use crate::arguments::{OutputFormat, parse};
    use std::ffi::OsString;

    #[test]
    fn explicit_configuration_explains_sources_and_redacts_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let token = directory.path().join("token with space");
        std::fs::write(&token, "do-not-echo")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        }
        let config = directory.path().join("cli config.toml");
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
        let token = directory.path().join("token");
        let config = directory.path().join("cli.toml");
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
}
