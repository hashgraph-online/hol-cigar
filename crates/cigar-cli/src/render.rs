//! Stable versioned JSON and terminal-safe human output.

use crate::arguments::{OutputFormat, ParsedInvocation};
use crate::client::OperationResponse;
use crate::configuration::EffectiveConfiguration;
use crate::error::CliError;
use serde_json::{Value, json};

pub(crate) fn render_success(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    response: OperationResponse,
) -> Result<String, CliError> {
    match invocation.options.output {
        OutputFormat::Json => {
            let value = json!({
                "schema_version": "cigar.cli.output.v1",
                "ok": true,
                "command": invocation.command.path(),
                "operation_id": response.operation_id,
                "target": configuration.target().as_str(),
                "dry_run": invocation.options.dry_run,
                "result": response.result,
                "metadata": {
                    "semantic_etag": response.semantic_etag,
                    "next_page_cursor": response.next_page_cursor
                }
            });
            serde_json::to_string(&value)
                .map(|value| format!("{value}\n"))
                .map_err(|_error| CliError::invalid_response())
        }
        OutputFormat::Text => {
            let mut output = String::new();
            render_plain_line(
                &format!(
                    "OK {}{}",
                    invocation.command.path(),
                    if invocation.options.dry_run {
                        " (dry run)"
                    } else {
                        ""
                    }
                ),
                &mut output,
                invocation.options.width,
            );
            render_line(
                "operation",
                &response.operation_id,
                &mut output,
                invocation.options.width,
            );
            render_line(
                "target",
                configuration.target().as_str(),
                &mut output,
                invocation.options.width,
            );
            render_value(&response.result, "", &mut output, invocation.options.width);
            if let Some(etag) = response.semantic_etag {
                render_line(
                    "semantic_etag",
                    &etag,
                    &mut output,
                    invocation.options.width,
                );
            }
            if let Some(cursor) = response.next_page_cursor {
                render_line(
                    "next_page_cursor",
                    &cursor,
                    &mut output,
                    invocation.options.width,
                );
            }
            Ok(output)
        }
    }
}

pub(crate) fn render_error(error: &CliError, output: OutputFormat) -> String {
    match output {
        OutputFormat::Text => format!(
            "{}: {}\nnext: {}\n",
            error.code(),
            error.message(),
            error.remediation()
        ),
        OutputFormat::Json => {
            let value = json!({
                "schema_version": "cigar.cli.output.v1",
                "ok": false,
                "error": {
                    "code": error.code(),
                    "message": error.message(),
                    "remediation": error.remediation()
                }
            });
            format!("{value}\n")
        }
    }
}

fn render_value(value: &Value, prefix: &str, output: &mut String, width: Option<usize>) {
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                let name = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                render_value(value, &name, output, width);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                render_value(value, &format!("{prefix}[{index}]"), output, width);
            }
            if values.is_empty() {
                output.push_str(&format!("{prefix}: []\n"));
            }
        }
        Value::String(value) => render_line(prefix, value, output, width),
        _ => render_line(prefix, &value.to_string(), output, width),
    }
}

fn render_line(prefix: &str, value: &str, output: &mut String, width: Option<usize>) {
    let label = format!("{prefix}: ");
    let value = escaped_terminal_text(value);
    let width = width.unwrap_or(usize::MAX);
    if label.chars().count().saturating_add(value.chars().count()) <= width {
        output.push_str(&label);
        output.push_str(&value);
        output.push('\n');
        return;
    }
    let first_capacity = width.saturating_sub(label.chars().count()).max(1);
    let continuation_capacity = width.saturating_sub(2).max(1);
    let mut remaining = value.as_str();
    let mut first = true;
    while !remaining.is_empty() {
        let capacity = if first {
            first_capacity
        } else {
            continuation_capacity
        };
        let split = remaining
            .char_indices()
            .nth(capacity)
            .map_or(remaining.len(), |(index, _character)| index);
        if first {
            output.push_str(&label);
            first = false;
        } else {
            output.push_str("  ");
        }
        let (chunk, rest) = remaining.split_at(split);
        output.push_str(chunk);
        output.push('\n');
        remaining = rest;
    }
}

fn render_plain_line(value: &str, output: &mut String, width: Option<usize>) {
    let value = escaped_terminal_text(value);
    let width = width.unwrap_or(usize::MAX);
    let mut remaining = value.as_str();
    while !remaining.is_empty() {
        let split = remaining
            .char_indices()
            .nth(width.max(1))
            .map_or(remaining.len(), |(index, _character)| index);
        let (chunk, rest) = remaining.split_at(split);
        output.push_str(chunk);
        output.push('\n');
        remaining = rest;
    }
}

fn escaped_terminal_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect()
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::{render_error, render_success};
    use crate::arguments::{GlobalOptions, OutputFormat, ParsedInvocation, TargetKind};
    use crate::client::OperationResponse;
    use crate::command::COMMANDS;
    use crate::configuration::EffectiveConfiguration;
    use crate::error::CliError;

    #[test]
    fn golden_json_error_is_versioned_and_one_line() {
        assert_eq!(
            render_error(&CliError::confirmation_required(), OutputFormat::Json),
            concat!(
                "{\"error\":{\"code\":\"CLI_CONFIRMATION_REQUIRED\",",
                "\"message\":\"the state-changing command was not confirmed\",",
                "\"remediation\":\"review with --dry-run, then repeat with --yes\"},",
                "\"ok\":false,\"schema_version\":\"cigar.cli.output.v1\"}\n"
            )
        );
    }

    #[test]
    fn every_command_has_versioned_json_success_and_error_goldens()
    -> Result<(), Box<dyn std::error::Error>> {
        let configuration = EffectiveConfiguration::for_test(TargetKind::Embedded);
        for command in COMMANDS {
            let invocation = ParsedInvocation {
                command: *command,
                positionals: Vec::new(),
                options: GlobalOptions {
                    output: OutputFormat::Json,
                    ..GlobalOptions::default()
                },
            };
            let operation_id = command
                .contract()
                .map(|contract| contract.operation_id.to_owned())
                .unwrap_or_else(|_error| {
                    format!("cigar.cli.{}.v1", command.path().replace('.', "-"))
                });
            let success = render_success(
                &invocation,
                &configuration,
                OperationResponse {
                    operation_id: operation_id.clone(),
                    result: serde_json::json!({"golden": true}),
                    semantic_etag: None,
                    next_page_cursor: None,
                },
            )?;
            let success: serde_json::Value = serde_json::from_str(&success)?;
            assert_eq!(
                success
                    .get("schema_version")
                    .and_then(serde_json::Value::as_str),
                Some("cigar.cli.output.v1")
            );
            assert_eq!(
                success.get("command").and_then(serde_json::Value::as_str),
                Some(command.path())
            );
            assert_eq!(
                success
                    .get("operation_id")
                    .and_then(serde_json::Value::as_str),
                Some(operation_id.as_str())
            );
            assert_eq!(
                success.get("ok").and_then(serde_json::Value::as_bool),
                Some(true)
            );

            let error = render_error(&CliError::invalid_input(), OutputFormat::Json);
            let error: serde_json::Value = serde_json::from_str(&error)?;
            assert_eq!(
                error
                    .get("schema_version")
                    .and_then(serde_json::Value::as_str),
                Some("cigar.cli.output.v1")
            );
            assert_eq!(
                error.get("ok").and_then(serde_json::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                error
                    .pointer("/error/code")
                    .and_then(serde_json::Value::as_str),
                Some("CLI_INVALID_INPUT")
            );
        }
        Ok(())
    }

    #[test]
    fn narrow_text_wraps_without_ansi_or_control_injection()
    -> Result<(), Box<dyn std::error::Error>> {
        let invocation = ParsedInvocation {
            command: crate::command::lookup("status").ok_or("missing command")?,
            positionals: Vec::new(),
            options: GlobalOptions {
                output: OutputFormat::Text,
                width: Some(20),
                ..GlobalOptions::default()
            },
        };
        let rendered = render_success(
            &invocation,
            &EffectiveConfiguration::for_test(TargetKind::Local),
            OperationResponse {
                operation_id: "getReadiness".to_owned(),
                result: serde_json::json!({
                    "message": "long unicode 🐝 value\nwith-control"
                }),
                semantic_etag: None,
                next_page_cursor: None,
            },
        )?;
        assert!(rendered.lines().all(|line| line.chars().count() <= 20));
        assert_eq!(super::escaped_terminal_text("\n"), "\\n");
        assert!(rendered.contains("with-control"));
        assert!(!rendered.contains('\u{1b}'));
        Ok(())
    }
}
