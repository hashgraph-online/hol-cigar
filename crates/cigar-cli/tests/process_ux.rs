//! Installed-binary terminal and interrupt behavior.

#[cfg(unix)]
mod unix {
    use base64::Engine as _;
    use std::ffi::OsString;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use tokio::io::AsyncReadExt as _;

    fn cli_binary() -> OsString {
        std::env::var_os("CIGAR_CLI_E2E_BINARY")
            .unwrap_or_else(|| OsString::from(env!("CARGO_BIN_EXE_cigar")))
    }

    #[test]
    fn project_configuration_cannot_retarget_an_inherited_user_credential()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let workspace = directory.path().join("workspace");
        let project_configuration = workspace.join(".cigar");
        let user_configuration = directory.path().join("xdg/cigar");
        std::fs::create_dir_all(&project_configuration)?;
        std::fs::create_dir_all(&user_configuration)?;

        let credential = directory.path().join("user.token");
        std::fs::write(&credential, "user-secret")?;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(
            user_configuration.join("cli.toml"),
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"remote\"\n",
                    "remote_endpoint = \"https://trusted.example\"\n",
                    "authorization_file = {}\n"
                ),
                serde_json::to_string(&credential.display().to_string())?
            ),
        )?;
        std::fs::write(
            project_configuration.join("cli.toml"),
            concat!(
                "schema_version = 1\n",
                "target = \"remote\"\n",
                "remote_endpoint = \"https://attacker.example\"\n"
            ),
        )?;

        let rejected = Command::new(cli_binary())
            .args(["status", "--explain-config", "--output", "json"])
            .env_clear()
            .env("XDG_CONFIG_HOME", directory.path().join("xdg"))
            .env("HOME", directory.path().join("home"))
            .current_dir(&workspace)
            .output()?;
        assert_eq!(rejected.status.code(), Some(78));
        assert!(rejected.stderr.is_empty());
        assert!(String::from_utf8(rejected.stdout)?.contains("CLI_INVALID_CONFIGURATION"));

        std::fs::write(
            project_configuration.join("cli.toml"),
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"remote\"\n",
                    "remote_endpoint = \"https://attacker.example\"\n",
                    "authorization_file = {}\n"
                ),
                serde_json::to_string(&credential.display().to_string())?
            ),
        )?;
        let project_selected_credential = Command::new(cli_binary())
            .args(["status", "--explain-config", "--output", "json"])
            .env_clear()
            .env("XDG_CONFIG_HOME", directory.path().join("xdg"))
            .env("HOME", directory.path().join("home"))
            .current_dir(&workspace)
            .output()?;
        assert_eq!(project_selected_credential.status.code(), Some(78));
        assert!(project_selected_credential.stderr.is_empty());
        assert!(
            String::from_utf8(project_selected_credential.stdout)?
                .contains("CLI_INVALID_CONFIGURATION")
        );

        let explicitly_authorized = Command::new(cli_binary())
            .args(["status", "--explain-config", "--output", "json"])
            .arg("--authorization-file")
            .arg(&credential)
            .env_clear()
            .env("XDG_CONFIG_HOME", directory.path().join("xdg"))
            .env("HOME", directory.path().join("home"))
            .current_dir(&workspace)
            .output()?;
        assert!(
            explicitly_authorized.status.success(),
            "{}",
            String::from_utf8_lossy(&explicitly_authorized.stderr)
        );
        let explained: serde_json::Value = serde_json::from_slice(&explicitly_authorized.stdout)?;
        assert_eq!(
            explained
                .pointer("/endpoint/source")
                .and_then(|value| value.as_str()),
            Some("project config")
        );
        assert_eq!(
            explained
                .pointer("/authorization/source")
                .and_then(|value| value.as_str()),
            Some("CLI flag")
        );
        assert_eq!(
            explained
                .pointer("/authorization/value")
                .and_then(|value| value.as_str()),
            Some("[REDACTED]")
        );
        Ok(())
    }

    fn slow_mutating_administration_fixture(
        directory: &tempfile::TempDir,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf, Vec<u8>), Box<dyn std::error::Error>> {
        let state = directory.path().join("slow-state");
        std::fs::create_dir(&state)?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        // Millions of valid path components keep strict decoding and state validation busy long
        // enough to exercise the complete-command deadline around blocking administration work.
        let slow_path = format!("/{}", "a/".repeat(3_600_000));
        let state_bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": "cigar.cli-administration.v1",
            "generation": 1,
            "projects": {},
            "sources": {"slow": {"path": slow_path}},
            "links": []
        }))?;
        assert!(state_bytes.len() < 8 * 1024 * 1024);
        let state_file = state.join("state.json");
        std::fs::write(&state_file, &state_bytes)?;
        std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o600))?;
        let config = directory.path().join("slow-cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\ntarget = \"local\"\nproject_state_directory = {}\n",
                serde_json::to_string(&state.display().to_string())?
            ),
        )?;
        Ok((config, state_file, state_bytes))
    }

    #[tokio::test]
    async fn sigint_cancels_an_inflight_command_with_stable_exit()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("cigard.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\ntarget = \"local\"\nlocal_socket = {}\n",
                serde_json::to_string(&socket.display().to_string())?
            ),
        )?;
        let (accepted_sender, accepted_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _address) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await?;
                request.extend_from_slice(buffer.get(..count).ok_or("invalid read")?);
                if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ignored = accepted_sender.send(());
            let mut discard = [0_u8; 16];
            let _closed = stream.read(&mut discard).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let child = Command::new(cli_binary())
            .args([
                "status",
                "--config",
                config.to_str().ok_or("config path")?,
                "--deadline",
                "30s",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        accepted_receiver.await?;
        let signal = Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()?;
        assert!(signal.success());
        let output = child.wait_with_output()?;
        assert_eq!(output.status.code(), Some(130));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("CLI_INTERRUPTED"));
        server.await??;
        Ok(())
    }

    #[test]
    fn slow_local_administration_honors_deadline_without_committing()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (config, state_file, original_state) =
            slow_mutating_administration_fixture(&directory)?;

        let started = std::time::Instant::now();
        let deadline = Command::new(cli_binary())
            .args(["source", "add", "new-source"])
            .arg(directory.path())
            .args(["--yes", "--deadline", "5ms", "--config"])
            .arg(&config)
            .output()?;
        assert_eq!(deadline.status.code(), Some(75));
        assert!(
            String::from_utf8(deadline.stderr)?.contains("DEADLINE_EXCEEDED"),
            "deadline error was not stable"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(std::fs::read(&state_file)?, original_state);

        Ok(())
    }

    #[test]
    fn sigint_cancels_delegated_administration_and_reaps_its_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin)?;
        let ready = directory.path().join("mcp.ready");
        let child_pid = directory.path().join("mcp.pid");
        let script = bin.join("cigar-mcp");
        std::fs::write(
            &script,
            b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > \"$CIGAR_MCP_CHILD_PID\"\n: > \"$CIGAR_MCP_READY\"\nexec sleep 30\n",
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
        let mut search_path = vec![bin];
        if let Some(path) = std::env::var_os("PATH") {
            search_path.extend(std::env::split_paths(&path));
        }
        let search_path = std::env::join_paths(search_path)?;
        let mut process = Command::new(cli_binary())
            .args(["mcp", "serve", "--yes", "--deadline", "30s"])
            .env("PATH", search_path)
            .env("CIGAR_MCP_READY", &ready)
            .env("CIGAR_MCP_CHILD_PID", &child_pid)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let wait_until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !ready.is_file() {
            if let Some(status) = process.try_wait()? {
                return Err(format!("cigar exited before MCP readiness: {status}").into());
            }
            if std::time::Instant::now() >= wait_until {
                return Err("delegated MCP child did not become ready".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let delegated_pid = std::fs::read_to_string(&child_pid)?;
        let delegated_pid = delegated_pid.trim().to_owned();
        assert!(!delegated_pid.is_empty());

        let interrupted_at = std::time::Instant::now();
        let signal = Command::new("kill")
            .args(["-INT", &process.id().to_string()])
            .status()?;
        assert!(signal.success());
        let output = process.wait_with_output()?;
        assert_eq!(output.status.code(), Some(130));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)?.contains("CLI_INTERRUPTED"));
        assert!(interrupted_at.elapsed() < std::time::Duration::from_secs(2));

        let reaped_by = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let alive = Command::new("kill")
                .args(["-0", &delegated_pid])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success();
            if !alive {
                break;
            }
            if std::time::Instant::now() >= reaped_by {
                return Err("delegated MCP child survived CLI interruption".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn installed_binary_runs_init_replay_and_effect_recovery_contracts()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let directory = tempfile::tempdir()?;
        let state = directory.path().join("installed state");
        let socket = state.join("cigard.sock");
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"local\"\n",
                    "project_state_directory = {}\n",
                    "local_socket = {}\n"
                ),
                serde_json::to_string(&state.display().to_string())?,
                serde_json::to_string(&socket.display().to_string())?
            ),
        )?;
        let initialized = Command::new(cli_binary())
            .args(["init", "--yes", "--config"])
            .arg(&config)
            .arg("--output")
            .arg("json")
            .output()?;
        assert!(
            initialized.status.success(),
            "{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        assert!(state.join("state.json").is_file());
        assert_eq!(std::fs::metadata(&state)?.permissions().mode() & 0o077, 0);

        let listener = tokio::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let replay_id = "01890f47-8e7d-7b42-a1d2-000000000701";
        let effect_id = "01890f47-8e7d-7b42-a1d2-000000000702";
        let intent_digest = format!("1220{:064x}", 703_u64);
        let replay_id_server = replay_id.to_owned();
        let effect_id_server = effect_id.to_owned();
        let server = tokio::spawn(async move {
            let responses = [
                (
                    "createReplay",
                    "/v1/replays",
                    serde_json::json!({
                        "replay_id": replay_id_server,
                        "mode": "evidence_reproduction",
                        "status": "incomplete"
                    }),
                ),
                (
                    "getReplayCompleteness",
                    "/v1/replays/01890f47-8e7d-7b42-a1d2-000000000701/completeness",
                    serde_json::json!({"available": [], "missing": ["source"]}),
                ),
                (
                    "reconcileEffect",
                    "/v1/effects/01890f47-8e7d-7b42-a1d2-000000000702:reconcile",
                    serde_json::json!({
                        "effect_id": effect_id_server,
                        "state": "succeeded",
                        "effect_version": 5,
                        "intent_digest": intent_digest,
                        "attempt_count": 1,
                        "reconciliation_count": 1
                    }),
                ),
            ];
            for (operation, path, payload) in responses {
                let (mut stream, _address) = listener.accept().await?;
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut buffer).await?;
                    request.extend_from_slice(buffer.get(..count).ok_or("invalid read")?);
                    if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request)?;
                let first_line = request.lines().next().ok_or("missing request line")?;
                assert!(first_line.contains(path), "{first_line}");
                assert!(request.to_ascii_lowercase().contains(&format!(
                    "x-cigar-operation-id: {}",
                    operation.to_ascii_lowercase()
                )));
                assert!(!request.to_ascii_lowercase().contains("authorization:"));
                let normalized = serde_json::to_vec(&payload)?;
                let node = cigar_canon::parse_strict_json(&normalized)?;
                let payload = cigar_canon::to_deterministic_cbor(&node)?;
                let body = serde_json::to_vec(&serde_json::json!({
                    "operation_id": operation,
                    "payload_cbor": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
                }))?;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.write_all(&body).await?;
                stream.shutdown().await?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let replay_input = directory.path().join("replay.json");
        std::fs::write(
            &replay_input,
            format!(
                "{{\"decision_id\":\"1220{:064x}\",\"mode\":\"evidence_reproduction\",\"simulate_effects\":true}}",
                700_u64
            ),
        )?;
        let replay = Command::new(cli_binary())
            .args(["replay", "reconstruct", "--yes", "--input"])
            .arg(&replay_input)
            .arg("--config")
            .arg(&config)
            .args(["--output", "json"])
            .output()?;
        assert!(
            replay.status.success(),
            "{}",
            String::from_utf8_lossy(&replay.stderr)
        );
        assert!(String::from_utf8(replay.stdout)?.contains(replay_id));

        let completeness = Command::new(cli_binary())
            .args(["replay", "completeness", replay_id, "--config"])
            .arg(&config)
            .args(["--output", "json"])
            .output()?;
        assert!(completeness.status.success());
        assert!(String::from_utf8(completeness.stdout)?.contains("source"));

        let recovery = Command::new(cli_binary())
            .args([
                "effect",
                "reconcile",
                effect_id,
                "--expected-revision",
                "4",
                "--yes",
                "--config",
            ])
            .arg(&config)
            .args(["--output", "json"])
            .output()?;
        assert!(
            recovery.status.success(),
            "{}",
            String::from_utf8_lossy(&recovery.stderr)
        );
        let recovery = String::from_utf8(recovery.stdout)?;
        assert!(recovery.contains("reconcileEffect"));
        assert!(recovery.contains("succeeded"));
        server.await??;
        Ok(())
    }

    #[test]
    fn installed_entrypoints_delegate_exact_release_and_mcp_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin)?;
        let script = b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CIGAR_CAPTURE\"\n";
        let cargo = bin.join("cargo");
        let mcp = bin.join("cigar-mcp");
        std::fs::write(&cargo, script)?;
        std::fs::write(&mcp, script)?;
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&mcp, std::fs::Permissions::from_mode(0o700))?;
        let release_capture = directory.path().join("release.args");
        let release_target = directory.path().join("release archive");
        std::fs::create_dir(&release_target)?;
        let release = Command::new(cli_binary())
            .args(["release", "verify"])
            .arg(&release_target)
            .arg("--output")
            .arg("json")
            .env("PATH", &bin)
            .env("CIGAR_CAPTURE", &release_capture)
            .current_dir(directory.path())
            .output()?;
        assert!(
            release.status.success(),
            "{}",
            String::from_utf8_lossy(&release.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&release_capture)?,
            format!("xtask\nrelease-verify\n{}\n", release_target.display())
        );

        let mcp_capture = directory.path().join("mcp.args");
        let served = Command::new(cli_binary())
            .args(["mcp", "serve", "--yes", "--output", "json"])
            .env("PATH", &bin)
            .env("CIGAR_CAPTURE", &mcp_capture)
            .current_dir(directory.path())
            .output()?;
        assert!(
            served.status.success(),
            "{}",
            String::from_utf8_lossy(&served.stderr)
        );
        assert_eq!(std::fs::read_to_string(mcp_capture)?, "serve\n");
        assert!(String::from_utf8(served.stdout)?.contains("cigar-mcp"));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pty_prompt_accepts_yes_and_commits_only_after_confirmation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let state = directory.path().join("state with spaces");
        let config = directory.path().join("cli.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\nproject_state_directory = {}\n",
                serde_json::to_string(&state.display().to_string())?
            ),
        )?;
        let mut child = Command::new("/usr/bin/script")
            .arg("-q")
            .arg("/dev/null")
            .arg(cli_binary())
            .args(["init", "--config"])
            .arg(&config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or("missing script stdin")?;
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            std::thread::sleep(std::time::Duration::from_millis(250));
            stdin.write_all(b"y\n")?;
            stdin.flush()?;
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(())
        });
        let output = child.wait_with_output()?;
        writer.join().map_err(|_panic| "prompt writer panicked")??;
        let mut rendered = String::from_utf8(output.stdout)?;
        rendered.push_str(&String::from_utf8(output.stderr)?);
        assert!(output.status.success(), "{}: {rendered}", output.status);
        assert!(rendered.contains("Confirm reviewed state change?"));
        let started = rendered
            .find("… init")
            .or_else(|| rendered.find("... init"))
            .ok_or("missing live progress start")?;
        let completed = rendered
            .find("✓ init")
            .or_else(|| rendered.find("OK init"))
            .ok_or("missing progress completion")?;
        assert!(started < completed);
        assert!(state.join("state.json").is_file());
        Ok(())
    }
}
