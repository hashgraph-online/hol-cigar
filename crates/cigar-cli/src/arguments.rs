//! Closed, content-safe command and global-option parser.

use crate::TerminalContext;
use crate::client::OperationRequest;
use crate::command::{CommandSpec, lookup};
use crate::configuration::EffectiveConfiguration;
use crate::error::CliError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::generated::{HttpMethod, IdempotencyRequirement, RevisionRequirement};
use cigar_canon::{CanonicalNode, parse_strict_json, to_deterministic_cbor};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEADLINE_MILLIS: u64 = 300_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TargetKind {
    Embedded,
    #[default]
    Local,
    Remote,
}

impl TargetKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Toggle {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GlobalOptions {
    pub(crate) output: OutputFormat,
    pub(crate) deadline: Duration,
    pub(crate) config: Option<PathBuf>,
    pub(crate) target: Option<TargetKind>,
    pub(crate) endpoint: Option<String>,
    pub(crate) authorization_file: Option<PathBuf>,
    pub(crate) input: Option<PathBuf>,
    pub(crate) idempotency_key: Option<String>,
    pub(crate) expected_revision: Option<String>,
    pub(crate) page_cursor: Option<String>,
    pub(crate) page_size: Option<u32>,
    pub(crate) quiet: bool,
    pub(crate) color: Toggle,
    pub(crate) unicode: Toggle,
    pub(crate) width: Option<usize>,
    pub(crate) non_interactive: bool,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
    pub(crate) explain_config: bool,
    pub(crate) security: bool,
    pub(crate) deep: bool,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            output: OutputFormat::Text,
            deadline: Duration::from_secs(30),
            config: None,
            target: None,
            endpoint: None,
            authorization_file: None,
            input: None,
            idempotency_key: None,
            expected_revision: None,
            page_cursor: None,
            page_size: None,
            quiet: false,
            color: Toggle::Auto,
            unicode: Toggle::Auto,
            width: None,
            non_interactive: false,
            yes: false,
            dry_run: false,
            explain_config: false,
            security: false,
            deep: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedInvocation {
    pub(crate) command: CommandSpec,
    pub(crate) positionals: Vec<String>,
    pub(crate) options: GlobalOptions,
}

impl ParsedInvocation {
    pub(crate) fn require_confirmation(&self, terminal: TerminalContext) -> Result<(), CliError> {
        let requires_confirmation = self.command.mutates() || self.command.destructive();
        if !requires_confirmation || self.options.dry_run || self.options.yes {
            return Ok(());
        }
        if terminal.stdin && !self.options.non_interactive && terminal.confirmed == Some(true) {
            Ok(())
        } else {
            Err(CliError::confirmation_required())
        }
    }

    pub(crate) fn progress_enabled(&self, terminal: TerminalContext) -> bool {
        self.options.output == OutputFormat::Text && terminal.stderr && !self.options.quiet
    }

    pub(crate) fn unicode_enabled(&self, terminal: TerminalContext) -> bool {
        match self.options.unicode {
            Toggle::Always => true,
            Toggle::Never => false,
            Toggle::Auto => terminal.unicode,
        }
    }

    pub(crate) fn operation_request(
        &self,
        configuration: &EffectiveConfiguration,
    ) -> Result<OperationRequest, CliError> {
        if self.command.is_administration() {
            return Err(CliError::unsupported_target());
        }
        let contract = self.command.contract()?;
        let path_names = cigar_api::contract_path_parameter_names(contract.http_path);
        if self.positionals.len() != path_names.len() {
            return Err(CliError::invalid_command());
        }
        let path_parameters = path_names
            .into_iter()
            .zip(&self.positionals)
            .map(|(name, value)| {
                if valid_path_value(value) {
                    Ok((name.to_owned(), value.clone()))
                } else {
                    Err(CliError::invalid_input())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let payload_cbor = match contract.http_method {
            HttpMethod::Get => Vec::new(),
            HttpMethod::Post => request_payload(&self.options.input, &path_parameters)?,
        };
        let idempotency_key = match contract.idempotency_requirement {
            IdempotencyRequirement::Required => Some(
                self.options
                    .idempotency_key
                    .clone()
                    .map_or_else(random_idempotency_key, Ok)?,
            ),
            IdempotencyRequirement::NotApplicable if self.options.idempotency_key.is_some() => {
                return Err(CliError::invalid_command());
            }
            IdempotencyRequirement::NotApplicable => None,
        };
        let expected_revision = match contract.revision_requirement {
            RevisionRequirement::Required => Some(
                self.options
                    .expected_revision
                    .clone()
                    .ok_or_else(CliError::invalid_input)?,
            ),
            RevisionRequirement::None if self.options.expected_revision.is_some() => {
                return Err(CliError::invalid_command());
            }
            RevisionRequirement::None => None,
        };
        Ok(OperationRequest {
            contract,
            payload_cbor,
            path_parameters,
            dry_run: self.options.dry_run,
            idempotency_key,
            expected_revision,
            page_cursor: self.options.page_cursor.clone(),
            page_size: self.options.page_size,
            deadline: self.options.deadline,
            authorization: configuration.authorization()?,
        })
    }
}

pub(crate) fn parse(
    arguments: Vec<OsString>,
    terminal: TerminalContext,
) -> Result<ParsedInvocation, CliError> {
    let mut values = arguments
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_value| CliError::invalid_command())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        values.push("help".to_owned());
    }
    if values
        .first()
        .is_some_and(|value| matches!(value.as_str(), "--help" | "-h"))
    {
        values = vec!["help".to_owned()];
    } else if values
        .first()
        .is_some_and(|value| matches!(value.as_str(), "--version" | "-V"))
    {
        values = vec!["version".to_owned()];
    }

    let mut options = GlobalOptions::default();
    let mut words = Vec::new();
    let mut index = 0;
    let mut positional_only = false;
    while index < values.len() {
        let value = values.get(index).ok_or_else(CliError::invalid_command)?;
        if positional_only {
            words.push(value.clone());
            index += 1;
            continue;
        }
        if value == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        match value.as_str() {
            "--output" => options.output = parse_output(take_value(&values, &mut index)?)?,
            "--deadline" => options.deadline = parse_deadline(take_value(&values, &mut index)?)?,
            "--config" => options.config = Some(PathBuf::from(take_value(&values, &mut index)?)),
            "--target" => options.target = Some(parse_target(take_value(&values, &mut index)?)?),
            "--endpoint" => options.endpoint = Some(take_value(&values, &mut index)?.to_owned()),
            "--authorization-file" => {
                options.authorization_file = Some(PathBuf::from(take_value(&values, &mut index)?));
            }
            "--input" => options.input = Some(PathBuf::from(take_value(&values, &mut index)?)),
            "--idempotency-key" => {
                options.idempotency_key =
                    Some(bounded_graphic(take_value(&values, &mut index)?, 256)?);
            }
            "--expected-revision" => {
                options.expected_revision =
                    Some(bounded_graphic(take_value(&values, &mut index)?, 256)?);
            }
            "--page-cursor" => {
                options.page_cursor =
                    Some(bounded_graphic(take_value(&values, &mut index)?, 4096)?);
            }
            "--page-size" => {
                let value = take_value(&values, &mut index)?
                    .parse::<u32>()
                    .map_err(|_error| CliError::invalid_command())?;
                if !(1..=1_000).contains(&value) {
                    return Err(CliError::invalid_command());
                }
                options.page_size = Some(value);
            }
            "--color" => options.color = parse_toggle(take_value(&values, &mut index)?)?,
            "--unicode" => options.unicode = parse_toggle(take_value(&values, &mut index)?)?,
            "--width" => {
                let width = take_value(&values, &mut index)?
                    .parse::<usize>()
                    .map_err(|_error| CliError::invalid_command())?;
                if !(20..=1_000).contains(&width) {
                    return Err(CliError::invalid_command());
                }
                options.width = Some(width);
            }
            "--quiet" => options.quiet = true,
            "--non-interactive" => options.non_interactive = true,
            "--yes" | "--confirm" => options.yes = true,
            "--dry-run" => options.dry_run = true,
            "--explain-config" => options.explain_config = true,
            "--security" => options.security = true,
            "--deep" => options.deep = true,
            "--embedded" => options.target = merge_target(options.target, TargetKind::Embedded)?,
            "--local" => options.target = merge_target(options.target, TargetKind::Local)?,
            "--remote" => {
                options.target = merge_target(options.target, TargetKind::Remote)?;
                options.endpoint = Some(take_value(&values, &mut index)?.to_owned());
            }
            _ if value.starts_with('-') => return Err(CliError::invalid_command()),
            _ => words.push(value.clone()),
        }
        index += 1;
    }
    let first = words.first().ok_or_else(CliError::invalid_command)?;
    let (path, consumed) = if group_requires_subcommand(first) {
        let second = words.get(1).ok_or_else(CliError::invalid_command)?;
        (format!("{first}.{second}"), 2)
    } else {
        (first.clone(), 1)
    };
    let command = lookup(&path).ok_or_else(CliError::invalid_command)?;
    let positionals: Vec<String> = words.into_iter().skip(consumed).collect();
    if command.is_completion() && positionals.len() != 1 {
        return Err(CliError::invalid_command());
    }
    if (options.security || options.deep) && command.path() != "doctor" {
        return Err(CliError::invalid_command());
    }
    if options.width.is_none() {
        options.width = terminal.width.filter(|width| (20..=1_000).contains(width));
    }
    Ok(ParsedInvocation {
        command,
        positionals,
        options,
    })
}

fn group_requires_subcommand(value: &str) -> bool {
    matches!(
        value,
        "source"
            | "context"
            | "catalog"
            | "project"
            | "focus"
            | "space"
            | "handoff"
            | "effect"
            | "replay"
            | "policy"
            | "backup"
            | "gc"
            | "diagnostics"
            | "mcp"
            | "plugin"
            | "release"
    )
}

fn take_value<'a>(values: &'a [String], index: &mut usize) -> Result<&'a str, CliError> {
    *index = index.checked_add(1).ok_or_else(CliError::invalid_command)?;
    values
        .get(*index)
        .map(String::as_str)
        .ok_or_else(CliError::invalid_command)
}

fn parse_output(value: &str) -> Result<OutputFormat, CliError> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(CliError::invalid_command()),
    }
}

fn parse_target(value: &str) -> Result<TargetKind, CliError> {
    match value {
        "embedded" => Ok(TargetKind::Embedded),
        "local" => Ok(TargetKind::Local),
        "remote" => Ok(TargetKind::Remote),
        _ => Err(CliError::invalid_command()),
    }
}

fn merge_target(
    current: Option<TargetKind>,
    next: TargetKind,
) -> Result<Option<TargetKind>, CliError> {
    if current.is_some_and(|current| current != next) {
        Err(CliError::invalid_command())
    } else {
        Ok(Some(next))
    }
}

fn parse_toggle(value: &str) -> Result<Toggle, CliError> {
    match value {
        "auto" => Ok(Toggle::Auto),
        "always" => Ok(Toggle::Always),
        "never" => Ok(Toggle::Never),
        _ => Err(CliError::invalid_command()),
    }
}

fn parse_deadline(value: &str) -> Result<Duration, CliError> {
    let (digits, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else {
        return Err(CliError::invalid_command());
    };
    let milliseconds = digits
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .filter(|value| (1..=MAX_DEADLINE_MILLIS).contains(value))
        .ok_or_else(CliError::invalid_command)?;
    Ok(Duration::from_millis(milliseconds))
}

fn bounded_graphic(value: &str, maximum: usize) -> Result<String, CliError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(CliError::invalid_command())
    } else {
        Ok(value.to_owned())
    }
}

fn valid_path_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn request_payload(
    input: &Option<PathBuf>,
    path_parameters: &[(String, String)],
) -> Result<Vec<u8>, CliError> {
    let node = if let Some(path) = input {
        let bytes = read_bounded_regular(path, MAX_INPUT_BYTES)?;
        parse_strict_json(&bytes).map_err(|_error| CliError::invalid_input())?
    } else if !path_parameters.is_empty() {
        CanonicalNode::Map(
            path_parameters
                .iter()
                .cloned()
                .map(|(name, value)| (name, CanonicalNode::Text(value)))
                .collect::<BTreeMap<_, _>>(),
        )
    } else {
        return Err(CliError::input_required());
    };
    let CanonicalNode::Map(mut values) = node else {
        return Err(CliError::invalid_input());
    };
    for (name, value) in path_parameters {
        match values.get(name) {
            Some(CanonicalNode::Text(existing)) if existing == value => {}
            Some(_) => return Err(CliError::invalid_input()),
            None => {
                values.insert(name.clone(), CanonicalNode::Text(value.clone()));
            }
        }
    }
    to_deterministic_cbor(&CanonicalNode::Map(values)).map_err(|_error| CliError::invalid_input())
}

fn read_bounded_regular(path: &PathBuf, maximum: u64) -> Result<Vec<u8>, CliError> {
    if path.as_os_str() == "-" {
        return Err(CliError::invalid_input());
    }
    let link = std::fs::symlink_metadata(path).map_err(|_error| CliError::invalid_input())?;
    if link.file_type().is_symlink() || !link.is_file() || link.len() > maximum {
        return Err(CliError::invalid_input());
    }
    let file = File::open(path).map_err(|_error| CliError::invalid_input())?;
    let metadata = file
        .metadata()
        .map_err(|_error| CliError::invalid_input())?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(CliError::invalid_input());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_error| CliError::invalid_input())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::invalid_input())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(CliError::invalid_input());
    }
    Ok(bytes)
}

fn random_idempotency_key() -> Result<String, CliError> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(|_error| CliError::target_unavailable())?;
    Ok(format!("cli-{}", URL_SAFE_NO_PAD.encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, TargetKind, parse};
    use crate::TerminalContext;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn globals_work_before_or_after_commands_and_targets_are_exclusive()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse(
            args(&[
                "--output",
                "json",
                "effect",
                "inspect",
                "effect-1",
                "--remote",
                "https://cigar.example",
            ]),
            TerminalContext::default(),
        )?;
        assert_eq!(parsed.command.path(), "effect.inspect");
        assert_eq!(parsed.options.output, OutputFormat::Json);
        assert_eq!(parsed.options.target, Some(TargetKind::Remote));
        assert_eq!(parsed.positionals, ["effect-1"]);

        assert!(
            parse(
                args(&["status", "--local", "--embedded"]),
                TerminalContext::default()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn malformed_deadline_width_and_unknown_flags_are_content_free_failures() {
        for values in [
            &["status", "--deadline", "0s"][..],
            &["status", "--width", "2"][..],
            &["status", "--secret-token", "do-not-echo"][..],
        ] {
            assert!(parse(args(values), TerminalContext::default()).is_err());
        }
    }
}
