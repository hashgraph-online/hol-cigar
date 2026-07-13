//! Installed-binary protocol and diagnostic mode smoke tests.

use std::io::Write as _;
use std::process::{Command, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_cigar-mcp");

#[test]
fn schema_noop_is_stable_and_content_free() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(BINARY).arg("schema-noop").output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r#""protocol_version":"2025-06-18""#));
    assert!(stdout.contains(r#""source_revision""#));
    assert!(!stdout.contains(env!("CARGO_MANIFEST_DIR")));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn doctor_reports_only_content_free_unavailability() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(BINARY)
        .arg("doctor")
        .env("CIGAR_MCP_CLI_BINARY", "/definitely/not/a/cigar-binary")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "{\"status\":\"degraded\",\"daemon\":\"unavailable\"}\n"
    );
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn serve_handshake_lists_tools_and_keeps_notifications_silent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(BINARY)
        .arg("serve")
        .env("CIGAR_MCP_CLI_BINARY", "/definitely/not/a/cigar-binary")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing child stdin")?;
    stdin.write_all(
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"process-test","version":"1"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            "\n",
        )
        .as_bytes(),
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert!(
        lines
            .first()
            .is_some_and(|line| { line.contains(r#""protocolVersion":"2025-06-18""#) })
    );
    assert!(lines.get(1).is_some_and(|line| {
        line.contains(r#""name":"context_compile""#) && line.contains(r#""name":"effect_status""#)
    }));
    Ok(())
}

#[cfg(unix)]
#[test]
fn serve_calls_the_installed_cli_with_private_exact_input() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory =
        std::env::temp_dir().join(format!("cigar-mcp-process-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let script = directory.join("cigar fixture");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            "printf '%s\\n' \"$*\" >> \"$0.log\"\n",
            "printf '%s\\n' '{\"schema_version\":\"cigar.cli.output.v1\",\"ok\":true,\"result\":{\"bundle_id\":\"bundle-process\",\"snapshot_id\":\"snapshot-process\"}}'\n"
        ),
    )?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;

    let mut child = Command::new(BINARY)
        .arg("serve")
        .env("CIGAR_MCP_CLI_BINARY", &script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing child stdin")?;
    stdin.write_all(
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"process-test","version":"1"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"context_compile","arguments":{"request":{"contract":{"goal":"private-process-payload"}},"max_tokens":500}}}"#,
            "\n",
        )
        .as_bytes(),
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(stdout.lines().count(), 2);
    assert!(stdout.contains("bundle-process"));
    assert!(stdout.contains("snapshot-process"));
    let log = std::fs::read_to_string(script.with_extension("log"))?;
    assert!(log.contains("context plan --input"));
    assert!(!log.contains("private-process-payload"));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
