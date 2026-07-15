//! Installed-binary protocol and diagnostic mode smoke tests.

use std::io::{BufRead as _, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cigar_mcp::MAX_REQUEST_BYTES;

const BINARY: &str = env!("CARGO_BIN_EXE_cigar-mcp");

#[cfg(unix)]
fn fixture_directory(label: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory =
        std::env::temp_dir().join(format!("cigar-mcp-{label}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory)?;
    Ok(directory)
}

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

#[test]
fn serve_process_enforces_inventory_ids_duplicates_and_frame_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let long_id = "a".repeat(257);
    let mut child = Command::new(BINARY)
        .arg("serve")
        .env("CIGAR_MCP_CLI_BINARY", "/definitely/not/a/cigar-binary")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing child stdin")?;
    writeln!(stdin, "{}", "x".repeat(MAX_REQUEST_BYTES + 1))?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"process-test","version":"1"}}}}}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized","params":{{}}}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"unknown-notification","params":{{}}}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"1.0","method":"ping","params":{{}}}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{{}}}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":4,"id":5,"method":"ping"}}"#
    )?;
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":9007199254740992,"method":"ping","params":{{}}}}"#
    )?;
    writeln!(
        stdin,
        "{{\"jsonrpc\":\"2.0\",\"id\":\"{long_id}\",\"method\":\"ping\",\"params\":{{}}}}"
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    let lines = stdout.lines().collect::<Vec<_>>();
    let [
        oversized,
        initialized,
        tools,
        resources,
        duplicate,
        numeric_id,
        string_id,
    ] = lines.as_slice()
    else {
        return Err(format!("unexpected response lines: {stdout}").into());
    };
    assert!(oversized.contains("request_too_large"));
    assert!(initialized.contains(r#""protocolVersion":"2025-06-18""#));
    for tool in [
        "context_compile",
        "context_expand",
        "context_explain",
        "catalog_query",
        "checkpoint_create",
        "handoff_create",
        "handoff_accept",
        "effect_prepare",
        "effect_commit",
        "effect_status",
    ] {
        assert!(tools.contains(&format!(r#""name":"{tool}""#)));
    }
    for family in [
        "project",
        "workspace",
        "task",
        "decision",
        "bundle",
        "handoff",
        "effect",
        "artifact",
    ] {
        assert!(resources.contains(&format!("cigar://{family}")));
    }
    assert!(duplicate.contains("invalid_json"));
    assert!(numeric_id.contains("invalid_id"));
    assert!(string_id.contains("invalid_id"));
    Ok(())
}

#[test]
fn unavailable_process_never_synthesizes_resource_data_and_effects_fail_closed()
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
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"cigar://bundle/b1","max_tokens":500}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"effect_commit","arguments":{"preparation_id":"p1","idempotency_key":"commit-1","max_tokens":500}}}"#,
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
    let [_initialized, catalog, resource, effect] = lines.as_slice() else {
        return Err(format!("unexpected response lines: {stdout}").into());
    };
    assert!(catalog.contains(r#""isError":true"#));
    assert!(catalog.contains(r#""degraded":true"#));
    assert!(!catalog.contains(r#""structuredContent":{"data""#));
    assert!(resource.contains("backend_unavailable"));
    assert!(!resource.contains(r#""contents""#));
    assert!(effect.contains("Effect operation refused"));
    assert!(effect.contains(r#""isError":true"#));
    Ok(())
}

#[cfg(unix)]
#[test]
fn cancellation_notification_interrupts_the_live_cli_and_stays_silent()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = fixture_directory("cancel-process")?;
    let script = directory.join("slow cigar fixture");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            ": > \"$0.started\"\n",
            "while :; do :; done\n"
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
            r#"{"jsonrpc":"2.0","id":"slow-1","method":"tools/call","params":{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"max_tokens":500}}}"#,
            "\n",
        )
        .as_bytes(),
    )?;
    stdin.flush()?;
    let wait_started = Instant::now();
    while !script.with_extension("started").is_file() {
        if wait_started.elapsed() > Duration::from_secs(2) {
            let _ignored = child.kill();
            return Err("fixture CLI did not start".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let cancelled_at = Instant::now();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":"slow-1","reason":"test"}}}}"#
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(cancelled_at.elapsed() < Duration::from_secs(2));
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    assert!(stdout.contains(r#""id":"slow-1""#));
    assert!(stdout.contains(r#""isError":true"#));
    assert!(stdout.contains("cancelled"));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn opaque_process_handles_and_expansion_respect_the_complete_output_budget()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = fixture_directory("budget-process")?;
    let script = directory.join("large cigar fixture");
    let output = format!(
        "{{\"schema_version\":\"cigar.cli.output.v1\",\"ok\":true,\"result\":{{\"payload\":\"{}\"}}}}\n",
        "x".repeat(12_000)
    );
    std::fs::write(
        &script,
        format!("#!/bin/sh\nset -eu\nprintf '%s' '{output}'\n"),
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
    let stdout = child.stdout.take().ok_or("missing child stdout")?;
    let mut stdout = std::io::BufReader::new(stdout);
    stdin.write_all(
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"process-test","version":"1"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"max_tokens":500}}}"#,
            "\n",
        )
        .as_bytes(),
    )?;
    stdin.flush()?;
    let mut initialize = String::new();
    let mut handle_response = String::new();
    stdout.read_line(&mut initialize)?;
    stdout.read_line(&mut handle_response)?;
    assert!(handle_response.len() <= 2_001, "{}", handle_response.len());
    let marker = r#""output_handle":""#;
    let handle_start = handle_response
        .find(marker)
        .ok_or("missing output handle")?
        + marker.len();
    let handle_end = handle_response
        .get(handle_start..)
        .and_then(|tail| tail.find('"'))
        .map(|offset| handle_start + offset)
        .ok_or("unterminated output handle")?;
    let handle = handle_response
        .get(handle_start..handle_end)
        .ok_or("invalid output handle range")?;
    assert_eq!(handle.len(), 32);
    assert!(
        handle
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    writeln!(
        stdin,
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"context_expand\",\"arguments\":{{\"handle\":\"{handle}\",\"max_tokens\":500}}}}}}"
    )?;
    drop(stdin);
    let mut page = String::new();
    stdout.read_line(&mut page)?;
    assert!(page.len() <= 2_001, "{}", page.len());
    assert!(page.contains("next_cursor"));
    assert!(!page.contains(&"x".repeat(1_000)));
    let status = child.wait()?;
    assert!(status.success());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .ok_or("missing child stderr")?
        .read_to_string(&mut stderr)?;
    assert!(stderr.is_empty());
    std::fs::remove_dir_all(directory)?;
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
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"context_compile","arguments":{"request":{"contract":{"goal":"private-process-payload"}},"idempotency_key":"compile-process-1","max_tokens":500}}}"#,
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

#[cfg(unix)]
#[test]
fn all_ten_tools_use_only_the_frozen_cli_routes() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = fixture_directory("routes-process")?;
    let script = directory.join("route cigar fixture");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            "printf '%s\\n' \"$*\" >> \"$0.log\"\n",
            "printf '%s\\n' '{\"schema_version\":\"cigar.cli.output.v1\",\"ok\":true,\"result\":{\"bundle_id\":\"bundle-route\",\"snapshot_id\":\"snapshot-route\"}}'\n"
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
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"context_compile","arguments":{"contract":{"goal":"do-not-log"},"idempotency_key":"compile-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"context_expand","arguments":{"bundle_id":"b1","idempotency_key":"expand-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"context_explain","arguments":{"bundle_id":"b1","idempotency_key":"explain-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"checkpoint_create","arguments":{"request":{"space_id":"s1"},"idempotency_key":"checkpoint-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"handoff_create","arguments":{"request":{"bundle_id":"b1"},"idempotency_key":"handoff-create-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"handoff_accept","arguments":{"request":{"handoff_id":"h1"},"idempotency_key":"handoff-accept-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"effect_prepare","arguments":{"intent":{"connector":"fixture"},"idempotency_key":"effect-prepare-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"effect_commit","arguments":{"preparation_id":"p1","idempotency_key":"effect-commit-1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"effect_status","arguments":{"effect_id":"e1","max_tokens":500}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"administrative_escape","arguments":{}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"context_compile","arguments":{"request":{"contract":{}},"contract":{},"idempotency_key":"ambiguous-1"}}}"#,
            "\n",
        )
        .as_bytes(),
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(stdout.lines().count(), 13, "{stdout}");
    assert!(stdout.contains("unknown_tool"));
    assert!(stdout.contains("ambiguous_tool_arguments"));

    let log = std::fs::read_to_string(script.with_extension("log"))?;
    let lines = log.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 10, "{log}");
    for (line, prefix) in lines.iter().zip([
        "context plan ",
        "context materialize b1 ",
        "context explain b1 ",
        "catalog query ",
        "focus checkpoint s1 ",
        "handoff create ",
        "handoff accept h1 ",
        "effect prepare ",
        "effect dispatch p1 ",
        "effect inspect e1 ",
    ]) {
        assert!(line.starts_with(prefix), "{line}");
    }
    assert!(!log.contains("do-not-log"));
    assert!(!log.contains("administrative_escape"));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
