//! Closed, content-safe command and global-option parser.

use crate::TerminalContext;
#[cfg(feature = "full")]
use crate::client::OperationRequest;
use crate::command::{CommandSpec, lookup};
#[cfg(feature = "full")]
use crate::configuration::EffectiveConfiguration;
use crate::error::CliError;
#[cfg(feature = "full")]
use base64::Engine as _;
#[cfg(feature = "full")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "full")]
use cigar_api::generated::{HttpMethod, IdempotencyRequirement, RevisionRequirement};
#[cfg(feature = "full")]
use cigar_canon::{CanonicalNode, parse_strict_json, to_deterministic_cbor};
#[cfg(feature = "full")]
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(feature = "full")]
use std::fs::File;
#[cfg(feature = "full")]
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "full")]
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
    #[cfg_attr(all(feature = "beta-embedded", not(feature = "full")), default)]
    Embedded,
    #[cfg(feature = "full")]
    #[cfg_attr(feature = "full", default)]
    Local,
    #[cfg(feature = "full")]
    Remote,
}

impl TargetKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            #[cfg(feature = "full")]
            Self::Local => "local",
            #[cfg(feature = "full")]
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
    #[cfg(feature = "full")]
    pub(crate) endpoint: Option<String>,
    #[cfg(feature = "full")]
    pub(crate) authorization_file: Option<PathBuf>,
    #[cfg(feature = "full")]
    pub(crate) input: Option<PathBuf>,
    #[cfg(feature = "full")]
    pub(crate) idempotency_key: Option<String>,
    #[cfg(feature = "full")]
    pub(crate) expected_revision: Option<String>,
    #[cfg(feature = "full")]
    pub(crate) page_cursor: Option<String>,
    #[cfg(feature = "full")]
    pub(crate) page_size: Option<u32>,
    pub(crate) quiet: bool,
    pub(crate) color: Toggle,
    pub(crate) unicode: Toggle,
    pub(crate) width: Option<usize>,
    pub(crate) non_interactive: bool,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
    pub(crate) explain_config: bool,
    #[cfg(feature = "full")]
    pub(crate) security: bool,
    #[cfg(feature = "full")]
    pub(crate) deep: bool,
    #[cfg(feature = "full")]
    pub(crate) force_full: bool,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            output: OutputFormat::Text,
            deadline: Duration::from_secs(30),
            config: None,
            target: None,
            #[cfg(feature = "full")]
            endpoint: None,
            #[cfg(feature = "full")]
            authorization_file: None,
            #[cfg(feature = "full")]
            input: None,
            #[cfg(feature = "full")]
            idempotency_key: None,
            #[cfg(feature = "full")]
            expected_revision: None,
            #[cfg(feature = "full")]
            page_cursor: None,
            #[cfg(feature = "full")]
            page_size: None,
            quiet: false,
            color: Toggle::Auto,
            unicode: Toggle::Auto,
            width: None,
            non_interactive: false,
            yes: false,
            dry_run: false,
            explain_config: false,
            #[cfg(feature = "full")]
            security: false,
            #[cfg(feature = "full")]
            deep: false,
            #[cfg(feature = "full")]
            force_full: false,
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

    #[cfg(feature = "full")]
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
    #[cfg(feature = "full")]
    {
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
            #[cfg(feature = "full")]
            "--endpoint" => options.endpoint = Some(take_value(&values, &mut index)?.to_owned()),
            #[cfg(feature = "full")]
            "--authorization-file" => {
                options.authorization_file = Some(PathBuf::from(take_value(&values, &mut index)?));
            }
            #[cfg(feature = "full")]
            "--input" => options.input = Some(PathBuf::from(take_value(&values, &mut index)?)),
            #[cfg(feature = "full")]
            "--idempotency-key" => {
                options.idempotency_key =
                    Some(bounded_graphic(take_value(&values, &mut index)?, 256)?);
            }
            #[cfg(feature = "full")]
            "--expected-revision" => {
                options.expected_revision =
                    Some(bounded_graphic(take_value(&values, &mut index)?, 256)?);
            }
            #[cfg(feature = "full")]
            "--page-cursor" => {
                options.page_cursor =
                    Some(bounded_graphic(take_value(&values, &mut index)?, 4096)?);
            }
            #[cfg(feature = "full")]
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
            "--yes" => options.yes = true,
            #[cfg(feature = "full")]
            "--confirm" => options.yes = true,
            "--dry-run" => options.dry_run = true,
            "--explain-config" => options.explain_config = true,
            #[cfg(feature = "full")]
            "--security" => options.security = true,
            #[cfg(feature = "full")]
            "--deep" => options.deep = true,
            #[cfg(feature = "full")]
            "--force-full" => options.force_full = true,
            "--embedded" => options.target = merge_target(options.target, TargetKind::Embedded)?,
            #[cfg(feature = "full")]
            "--local" => options.target = merge_target(options.target, TargetKind::Local)?,
            #[cfg(feature = "full")]
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
    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    if (command.is_help() || command.is_version()) && !positionals.is_empty() {
        return Err(CliError::invalid_command());
    }
    #[cfg(feature = "full")]
    if command.is_completion() && positionals.len() != 1 {
        return Err(CliError::invalid_command());
    }
    #[cfg(feature = "full")]
    if (options.security || options.deep) && command.path() != "doctor" {
        return Err(CliError::invalid_command());
    }
    #[cfg(feature = "full")]
    if options.force_full && command.path() != "integrity.deep" {
        return Err(CliError::invalid_command());
    }
    #[cfg(feature = "full")]
    validate_scoped_options(command, &options)?;
    if options.width.is_none() {
        options.width = terminal.width.filter(|width| (20..=1_000).contains(width));
    }
    Ok(ParsedInvocation {
        command,
        positionals,
        options,
    })
}

#[cfg(feature = "full")]
fn validate_scoped_options(command: CommandSpec, options: &GlobalOptions) -> Result<(), CliError> {
    if (options.input.is_some() && !command.accepts_input())
        || (options.idempotency_key.is_some() && !command.accepts_idempotency_key())
        || (options.expected_revision.is_some() && !command.accepts_expected_revision())
        || ((options.page_cursor.is_some() || options.page_size.is_some())
            && !command.accepts_pagination())
    {
        Err(CliError::invalid_command())
    } else {
        Ok(())
    }
}

#[cfg(feature = "full")]
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
            | "migration"
            | "compaction"
            | "integrity"
            | "gc"
            | "diagnostics"
            | "mcp"
            | "plugin"
            | "release"
            | "state"
    )
}

#[cfg(all(feature = "beta-embedded", not(feature = "full")))]
fn group_requires_subcommand(value: &str) -> bool {
    matches!(value, "source" | "project" | "focus")
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
        #[cfg(feature = "full")]
        "local" => Ok(TargetKind::Local),
        #[cfg(feature = "full")]
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

#[cfg(feature = "full")]
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

#[cfg(feature = "full")]
fn valid_path_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

#[cfg(feature = "full")]
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

#[cfg(feature = "full")]
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

#[cfg(feature = "full")]
fn random_idempotency_key() -> Result<String, CliError> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(|_error| CliError::target_unavailable())?;
    Ok(format!("cli-{}", URL_SAFE_NO_PAD.encode(bytes)))
}

#[cfg(all(test, feature = "full"))]
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

    #[test]
    fn operation_scoped_options_are_never_silently_ignored() {
        for values in [
            &["status", "--input", "/tmp/request.json"][..],
            &["init", "--idempotency-key", "ignored-key"][..],
            &["source", "list", "--expected-revision", "4"][..],
            &["doctor", "--page-size", "10"][..],
            &["catalog", "query", "--page-cursor", "ignored-cursor"][..],
            &["status", "--force-full"][..],
        ] {
            assert!(
                parse(args(values), TerminalContext::default()).is_err(),
                "scoped option unexpectedly accepted for {values:?}"
            );
        }

        for values in [
            &["catalog", "query", "--input", "/tmp/request.json"][..],
            &["context", "compile", "--idempotency-key", "compile-key"][..],
            &["effect", "dispatch", "effect-1", "--expected-revision", "4"][..],
            &["space", "log", "space-1", "--page-size", "10"][..],
            &["effect", "list", "--page-cursor", "cursor"][..],
            &["policy", "check", "--input", "/tmp/request.json"][..],
            &["gc", "plan", "plan.json", "--input", "/tmp/policy.json"][..],
            &["migration", "preflight", "source", "backup", "target"][..],
            &["compaction", "status", "descriptor.json"][..],
            &["integrity", "deep", "database.sqlite3", "--force-full"][..],
        ] {
            assert!(
                parse(args(values), TerminalContext::default()).is_ok(),
                "valid scoped option rejected for {values:?}"
            );
        }
    }
}

#[cfg(all(test, feature = "beta-embedded", not(feature = "full")))]
mod beta_tests {
    use super::{TargetKind, parse};
    use crate::TerminalContext;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn beta_parser_accepts_only_embedded_target_selection() -> Result<(), Box<dyn std::error::Error>>
    {
        for values in [
            &["source", "list"][..],
            &["source", "list", "--embedded"][..],
            &["source", "list", "--target", "embedded"][..],
        ] {
            let parsed = parse(args(values), TerminalContext::default())?;
            assert!(
                parsed
                    .options
                    .target
                    .is_none_or(|target| target == TargetKind::Embedded)
            );
        }
        Ok(())
    }

    #[test]
    fn beta_parser_rejects_every_excluded_transport_and_operation_flag() {
        for values in [
            &["source", "list", "--target", "local"][..],
            &["source", "list", "--target", "remote"][..],
            &["source", "list", "--local"][..],
            &["source", "list", "--remote", "https://example.test"][..],
            &["source", "list", "--endpoint", "http://localhost"][..],
            &["source", "list", "--authorization-file", "secret"][..],
            &["source", "list", "--input", "request.json"][..],
            &["source", "list", "--idempotency-key", "key"][..],
            &["source", "list", "--expected-revision", "1"][..],
            &["source", "list", "--page-cursor", "cursor"][..],
            &["source", "list", "--page-size", "1"][..],
            &["source", "list", "--security"][..],
            &["source", "list", "--deep"][..],
        ] {
            assert!(
                parse(args(values), TerminalContext::default()).is_err(),
                "excluded beta flag was accepted: {values:?}"
            );
        }
        for values in [&["help", "extra"][..], &["version", "extra"][..]] {
            assert!(
                parse(args(values), TerminalContext::default()).is_err(),
                "beta metadata command accepted an extra positional: {values:?}"
            );
        }
    }
}
