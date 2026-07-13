//! Strict, bounded adapter for Claude Code's documented command-hook surface.
//!
//! The adapter deliberately treats provider transcript locations as opaque input. It never opens
//! provider session files or writes provider-owned configuration. Durable adapter state lives only
//! below the explicitly supplied CIGAR plugin-data directory.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::io::AsyncReadExt as _;

const INPUT_LIMIT_BYTES: u64 = 64 * 1024;
const OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const STATE_LIMIT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SESSIONS: usize = 128;
const MAX_EVENTS_PER_SESSION: usize = 2_048;
const MAX_PRESENT_PER_SESSION: usize = 4_096;
const MAX_CHECKPOINTS_PER_SESSION: usize = 64;
const BACKEND_DEADLINE: Duration = Duration::from_millis(100);
const LOCK_DEADLINE: Duration = Duration::from_millis(25);
const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);
const STATE_SCHEMA: &str = "cigar.claude-hook-state.v1";
const EVENT_SCHEMA: &str = "cigar.claude-hook-event.v1";
const HANDOFF_TTL_SECONDS: u32 = 60;
const QUALIFIED_REGISTERED_HOOKS: [&str; 18] = [
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "InstructionsLoaded",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "PreCompact",
    "PostCompact",
    "CwdChanged",
    "WorktreeRemove",
    "Stop",
    "StopFailure",
];
const DEGRADED_MARKER: &str = "[CIGAR degraded: context service unavailable; Claude remains usable. Run cigar plugin doctor claude-code.]";

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Executes one hook CLI invocation and returns the process exit status.
///
/// Hook failures use exit status one, which is non-blocking on documented Claude Code command-hook
/// surfaces. A governed mediated effect denial is encoded as a successful structured hook result.
pub async fn run_process(arguments: Vec<OsString>) -> u8 {
    match ParsedCommand::parse(arguments) {
        Ok(ParsedCommand::Run {
            plugin_root,
            plugin_data,
        }) => match run_stdin(plugin_root.as_deref(), plugin_data.as_deref()).await {
            Ok(output) => {
                println!("{output}");
                0
            }
            Err(error) => {
                eprintln!("{}: {}", error.code(), error.safe_message());
                1
            }
        },
        Ok(ParsedCommand::Doctor { plugin_root }) => match validate_plugin_root(&plugin_root) {
            Ok(()) => {
                println!(
                    "{}",
                    json!({
                        "schema_version": "cigar.claude-hook-doctor.v1",
                        "ok": true,
                        "public_hook_surface": true,
                        "private_session_files": false,
                        "model_calls": 0
                    })
                );
                0
            }
            Err(error) => {
                eprintln!("{}: {}", error.code(), error.safe_message());
                1
            }
        },
        Ok(ParsedCommand::SchemaNoop) => {
            println!(
                "{}",
                json!({
                    "schema_version": EVENT_SCHEMA,
                    "ok": true,
                    "maximum_input_bytes": INPUT_LIMIT_BYTES,
                    "model_calls": 0,
                    "effect_precheck": "fail_closed"
                })
            );
            0
        }
        Ok(ParsedCommand::Why {
            plugin_data,
            session_id,
        }) => match explain_state(&plugin_data, session_id.as_deref()) {
            Ok(output) => {
                println!("{output}");
                0
            }
            Err(error) => {
                eprintln!("{}: {}", error.code(), error.safe_message());
                1
            }
        },
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.safe_message());
            1
        }
    }
}

#[derive(Debug)]
enum ParsedCommand {
    Run {
        plugin_root: Option<PathBuf>,
        plugin_data: Option<PathBuf>,
    },
    Doctor {
        plugin_root: PathBuf,
    },
    SchemaNoop,
    Why {
        plugin_data: PathBuf,
        session_id: Option<String>,
    },
}

impl ParsedCommand {
    fn parse(arguments: Vec<OsString>) -> Result<Self, HookError> {
        let values = arguments
            .into_iter()
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_value| HookError::InvalidCommand)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let command = values.first().map(String::as_str).unwrap_or("run");
        let mut plugin_root = None;
        let mut plugin_data = None;
        let mut session_id = None;
        let mut index = usize::from(!values.is_empty());
        while index < values.len() {
            let option = values.get(index).ok_or(HookError::InvalidCommand)?;
            index = index.checked_add(1).ok_or(HookError::InvalidCommand)?;
            let value = values.get(index).ok_or(HookError::InvalidCommand)?;
            match option.as_str() {
                "--plugin-root" => plugin_root = Some(PathBuf::from(value)),
                "--plugin-data" => plugin_data = Some(PathBuf::from(value)),
                "--session" => session_id = Some(validate_identifier(value)?.to_owned()),
                _ => return Err(HookError::InvalidCommand),
            }
            index = index.checked_add(1).ok_or(HookError::InvalidCommand)?;
        }
        match command {
            "run" => Ok(Self::Run {
                plugin_root,
                plugin_data,
            }),
            "doctor" => Ok(Self::Doctor {
                plugin_root: plugin_root.ok_or(HookError::InvalidCommand)?,
            }),
            "schema-noop" if plugin_root.is_none() && plugin_data.is_none() => Ok(Self::SchemaNoop),
            "why" => Ok(Self::Why {
                plugin_data: plugin_data.ok_or(HookError::InvalidCommand)?,
                session_id,
            }),
            _ => Err(HookError::InvalidCommand),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookError {
    InvalidCommand,
    InputMalformed,
    InputOversized,
    StateUnavailable,
    StateCorrupt,
    BackendUnavailable,
    PluginInvalid,
}

impl HookError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidCommand => "CIGAR_HOOK_INVALID_COMMAND",
            Self::InputMalformed => "CIGAR_HOOK_INPUT_MALFORMED",
            Self::InputOversized => "CIGAR_HOOK_INPUT_OVERSIZED",
            Self::StateUnavailable => "CIGAR_HOOK_STATE_UNAVAILABLE",
            Self::StateCorrupt => "CIGAR_HOOK_STATE_CORRUPT",
            Self::BackendUnavailable => "CIGAR_HOOK_BACKEND_UNAVAILABLE",
            Self::PluginInvalid => "CIGAR_HOOK_PLUGIN_INVALID",
        }
    }

    const fn safe_message(self) -> &'static str {
        match self {
            Self::InvalidCommand => "the hook invocation is invalid",
            Self::InputMalformed => "the documented hook event is malformed",
            Self::InputOversized => "the hook event exceeds the published byte limit",
            Self::StateUnavailable => "bounded adapter state is unavailable",
            Self::StateCorrupt => "bounded adapter state failed integrity validation",
            Self::BackendUnavailable => "the CIGAR service did not answer before the hook deadline",
            Self::PluginInvalid => "the plugin package failed local public-surface validation",
        }
    }
}

impl std::fmt::Display for HookError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for HookError {}

async fn run_stdin(
    plugin_root: Option<&Path>,
    plugin_data: Option<&Path>,
) -> Result<String, HookError> {
    if let Some(root) = plugin_root {
        validate_absolute_path(root)?;
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(INPUT_LIMIT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| HookError::InputMalformed)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > INPUT_LIMIT_BYTES) {
        return Err(HookError::InputOversized);
    }
    let state_directory = resolve_state_directory(plugin_data)?;
    let runtime = HookRuntime::new(state_directory, CliBackend);
    let output = runtime.handle(&bytes).await?;
    serde_json::to_string(&output).map_err(|_error| HookError::StateCorrupt)
}

fn resolve_state_directory(explicit: Option<&Path>) -> Result<PathBuf, HookError> {
    if let Some(path) = explicit {
        return prepare_private_directory(path);
    }
    if let Some(path) = std::env::var_os("CIGAR_CLAUDE_STATE_DIR") {
        return prepare_private_directory(Path::new(&path));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or(HookError::StateUnavailable)?;
    prepare_private_directory(&Path::new(&home).join(".cigar/claude-code"))
}

fn prepare_private_directory(path: &Path) -> Result<PathBuf, HookError> {
    validate_absolute_path(path)?;
    if path.exists() {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_error| HookError::StateUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HookError::StateUnavailable);
        }
    } else {
        std::fs::create_dir_all(path).map_err(|_error| HookError::StateUnavailable)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_error| HookError::StateUnavailable)?;
    }
    std::fs::canonicalize(path).map_err(|_error| HookError::StateUnavailable)
}

fn validate_absolute_path(path: &Path) -> Result<(), HookError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        Err(HookError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_plugin_root(root: &Path) -> Result<(), HookError> {
    validate_absolute_path(root)?;
    let metadata = std::fs::symlink_metadata(root).map_err(|_error| HookError::PluginInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HookError::PluginInvalid);
    }
    let mut documents = BTreeMap::new();
    for relative in [
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "hooks/hooks.json",
        "compatibility.json",
    ] {
        let path = root.join(relative);
        let bytes =
            read_bounded_regular(&path, 1024 * 1024).map_err(|_error| HookError::PluginInvalid)?;
        cigar_canon::parse_strict_json(&bytes).map_err(|_error| HookError::PluginInvalid)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_error| HookError::PluginInvalid)?;
        if !value.is_object() {
            return Err(HookError::PluginInvalid);
        }
        documents.insert(relative, value);
    }
    if documents.get(".mcp.json") != Some(&expected_mcp_configuration())
        || documents.get("hooks/hooks.json") != Some(&expected_hook_configuration())
    {
        return Err(HookError::PluginInvalid);
    }
    Ok(())
}

fn expected_mcp_configuration() -> Value {
    json!({
        "mcpServers": {
            "cigar": {
                "command": "cigar-mcp",
                "args": ["serve"],
                "env": {
                    "CIGAR_CLAUDE_PLUGIN_ROOT": "${CLAUDE_PLUGIN_ROOT}",
                    "CIGAR_CLAUDE_PLUGIN_DATA": "${CLAUDE_PLUGIN_DATA}"
                }
            }
        }
    })
}

fn expected_hook_configuration() -> Value {
    let handler = json!({
        "type": "command",
        "command": "cigar-claude-hook",
        "args": [
            "run",
            "--plugin-root",
            "${CLAUDE_PLUGIN_ROOT}",
            "--plugin-data",
            "${CLAUDE_PLUGIN_DATA}"
        ],
        "timeout": 1
    });
    let hooks = QUALIFIED_REGISTERED_HOOKS
        .into_iter()
        .map(|event| (event.to_owned(), json!([{"hooks": [handler.clone()]}])))
        .collect::<Map<_, _>>();
    json!({"hooks": hooks})
}

fn explain_state(directory: &Path, requested: Option<&str>) -> Result<Value, HookError> {
    let directory = prepare_private_directory(directory)?;
    let state = read_state(&directory)?;
    let sessions = state
        .sessions
        .iter()
        .filter(|(session_id, _state)| requested.is_none_or(|value| value == session_id.as_str()))
        .map(|(session_id, session)| {
            json!({
                "session_id": session_id,
                "last_injection": session.last_injection,
                "snapshot": session.snapshot,
                "bundle_or_source": session.bundle_or_source,
                "authority_lane": session.authority_lane,
                "token_accounting": session.accounting,
                "checkpoints": session.checkpoints
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": "cigar.claude-hook-explanation.v1",
        "sessions": sessions
    }))
}

struct HookRuntime<B> {
    state_directory: PathBuf,
    backend: B,
}

impl<B: HookBackend> HookRuntime<B> {
    fn new(state_directory: PathBuf, backend: B) -> Self {
        Self {
            state_directory,
            backend,
        }
    }

    async fn handle(&self, bytes: &[u8]) -> Result<Value, HookError> {
        let event = HookEvent::parse(bytes)?;
        let payload_digest = digest_bytes(&event.canonical_payload);
        let event_key = digest_bytes(
            format!(
                "{}\0{}\0{}",
                event.session_id,
                event.kind.as_str(),
                payload_digest
            )
            .as_bytes(),
        );
        let _lock = StateLock::acquire(&self.state_directory)?;
        let mut state = read_state(&self.state_directory)?;
        if let Some(cached) = state
            .sessions
            .get(&event.session_id)
            .and_then(|session| session.events.get(&event_key))
        {
            return Ok(cached.response.clone());
        }

        if !state.sessions.contains_key(&event.session_id) && state.sessions.len() >= MAX_SESSIONS {
            prune_oldest_session(&mut state);
        }
        let session = state.sessions.entry(event.session_id.clone()).or_default();
        session.sequence = session.sequence.saturating_add(1);
        observe_event(session, &event, &payload_digest);

        let response = self.dispatch(session, &event, &payload_digest).await;
        let response = match response {
            Ok(response) => response,
            Err(_error) if event.kind.is_governed_effect_precheck(&event.payload) => {
                effect_denied("CIGAR authorization could not be verified before mediated dispatch")
            }
            Err(_error) if event.kind.uses_context_backend() => degraded_response(event.kind),
            Err(_error) => quiet_response(),
        };
        let session = state
            .sessions
            .get_mut(&event.session_id)
            .ok_or(HookError::StateCorrupt)?;
        cache_event(session, event_key, payload_digest, response.clone());
        write_state(&self.state_directory, &state)?;
        Ok(response)
    }

    async fn dispatch(
        &self,
        session: &mut SessionState,
        event: &HookEvent,
        payload_digest: &str,
    ) -> Result<Value, HookError> {
        match event.kind {
            HookKind::SessionStart => {
                let source = required_string(&event.payload, "source", 64)?;
                if matches!(source, "startup" | "clear") {
                    session.present.clear();
                    session.injected.clear();
                    session.last_task_boundary = None;
                    session.bundle_or_source = None;
                }
                let reply = self
                    .backend
                    .call(BackendRequest::Bootstrap {
                        session_id: event.session_id.clone(),
                        cwd: event.cwd.clone(),
                    })
                    .await?;
                inject_reply(session, event.kind, reply, 500)
            }
            HookKind::UserPromptSubmit => {
                let prompt = required_string(&event.payload, "prompt", 32 * 1024)?;
                let boundary_digest = digest_bytes(normalize_prompt(prompt).as_bytes());
                if session.last_task_boundary.as_deref() == Some(&boundary_digest) {
                    return Ok(quiet_response());
                }
                session.last_task_boundary = Some(boundary_digest);
                let reply = self
                    .backend
                    .call(BackendRequest::PromptDelta {
                        session_id: event.session_id.clone(),
                        cwd: event.cwd.clone(),
                        prompt_digest: digest_bytes(prompt.as_bytes()),
                        base_bundle: session.bundle_or_source.clone(),
                    })
                    .await?;
                inject_reply(session, event.kind, reply, 4_000)
            }
            HookKind::PreCompact => {
                let checkpoint = digest_bytes(
                    format!(
                        "{}\0{}\0{}",
                        event.session_id, session.sequence, payload_digest
                    )
                    .as_bytes(),
                );
                let reply = self
                    .backend
                    .call(BackendRequest::Checkpoint {
                        session_id: event.session_id.clone(),
                        checkpoint: checkpoint.clone(),
                    })
                    .await?;
                record_checkpoint(session, reply.source.unwrap_or(checkpoint));
                Ok(quiet_response())
            }
            HookKind::PostCompact => {
                session.present.clear();
                session.injected.clear();
                let reply = self
                    .backend
                    .call(BackendRequest::Recompile {
                        session_id: event.session_id.clone(),
                        cwd: event.cwd.clone(),
                        checkpoint: session.checkpoints.last().cloned(),
                    })
                    .await?;
                inject_reply(session, event.kind, reply, 4_000)
            }
            HookKind::SubagentStart => {
                let agent_id = required_string(&event.payload, "agent_id", 256)?;
                let agent_type = required_string(&event.payload, "agent_type", 256)?;
                let reply = self
                    .backend
                    .call(BackendRequest::RecipientHandoff {
                        session_id: event.session_id.clone(),
                        recipient: format!("{agent_type}:{agent_id}"),
                        base_bundle: session.bundle_or_source.clone(),
                    })
                    .await?;
                if !reply.authorized || reply.authority_lane != "handoff" {
                    return Err(HookError::BackendUnavailable);
                }
                inject_reply(session, event.kind, reply, 1_000)
            }
            HookKind::PreToolUse if event.kind.is_governed_effect_precheck(&event.payload) => {
                let effect_id = effect_id(&event.payload).ok_or(HookError::BackendUnavailable)?;
                let reply = self
                    .backend
                    .call(BackendRequest::EffectPrecheck { effect_id })
                    .await?;
                if reply.authorized {
                    Ok(json!({
                        "suppressOutput": true,
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "additionalContext": "CIGAR verified the mediated effect authorization. Host tool permission remains independently enforced."
                        }
                    }))
                } else {
                    Ok(effect_denied(
                        "CIGAR denied mediated dispatch because the durable effect is not authorized",
                    ))
                }
            }
            HookKind::CwdChanged | HookKind::WorktreeCreate | HookKind::WorktreeRemove => {
                session.present.clear();
                session.injected.clear();
                session.last_task_boundary = None;
                session.bundle_or_source = None;
                Ok(quiet_response())
            }
            _ => Ok(quiet_response()),
        }
    }
}

fn inject_reply(
    session: &mut SessionState,
    kind: HookKind,
    reply: BackendReply,
    maximum_tokens: u64,
) -> Result<Value, HookError> {
    if reply.degraded || reply.content.trim().is_empty() {
        return Ok(degraded_response(kind));
    }
    let content = bounded_tokens(&reply.content, maximum_tokens)?;
    let injection_digest = digest_bytes(content.as_bytes());
    if !session.injected.insert(injection_digest.clone()) {
        session.accounting.cache_read_tokens = session
            .accounting
            .cache_read_tokens
            .saturating_add(reply.physical_tokens);
        return Ok(quiet_response());
    }
    session.snapshot = reply.snapshot;
    session.bundle_or_source = reply.bundle_or_source.or(reply.source);
    session.authority_lane = reply.authority_lane;
    session.last_injection = Some(injection_digest.clone());
    session.accounting.physical_tokens = session
        .accounting
        .physical_tokens
        .saturating_add(reply.physical_tokens);
    session.accounting.cache_write_tokens = session
        .accounting
        .cache_write_tokens
        .saturating_add(reply.cache_write_tokens);
    session.accounting.outcome_events = session.accounting.outcome_events.saturating_add(1);
    let context =
        format!("[CIGAR context manifest={injection_digest}]\n{content}\n[/CIGAR context]");
    Ok(json!({
        "suppressOutput": true,
        "hookSpecificOutput": {
            "hookEventName": kind.as_str(),
            "additionalContext": context
        }
    }))
}

fn bounded_tokens(value: &str, maximum: u64) -> Result<String, HookError> {
    if value
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(HookError::BackendUnavailable);
    }
    let words = value.split_whitespace().collect::<Vec<_>>();
    let maximum = usize::try_from(maximum).map_err(|_error| HookError::BackendUnavailable)?;
    if words.len() <= maximum {
        Ok(value.trim().to_owned())
    } else {
        let retained = words.get(..maximum).ok_or(HookError::BackendUnavailable)?;
        Ok(format!("{} … [CIGAR output bounded]", retained.join(" ")))
    }
}

fn quiet_response() -> Value {
    json!({"suppressOutput": true})
}

fn degraded_response(kind: HookKind) -> Value {
    if kind.supports_additional_context() {
        json!({
            "suppressOutput": true,
            "systemMessage": DEGRADED_MARKER,
            "hookSpecificOutput": {
                "hookEventName": kind.as_str(),
                "additionalContext": DEGRADED_MARKER
            }
        })
    } else {
        json!({"suppressOutput": true, "systemMessage": DEGRADED_MARKER})
    }
}

fn effect_denied(reason: &str) -> Value {
    json!({
        "suppressOutput": true,
        "systemMessage": "CIGAR blocked a mediated effect before dispatch.",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookKind {
    SessionStart,
    SessionEnd,
    UserPromptSubmit,
    InstructionsLoaded,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    PostToolBatch,
    SubagentStart,
    SubagentStop,
    TaskCreated,
    TaskCompleted,
    PreCompact,
    PostCompact,
    CwdChanged,
    WorktreeCreate,
    WorktreeRemove,
    Stop,
    StopFailure,
    Setup,
    UserPromptExpansion,
    PermissionRequest,
    PermissionDenied,
    Notification,
    MessageDisplay,
    TeammateIdle,
    ConfigChange,
    FileChanged,
    Elicitation,
    ElicitationResult,
}

impl HookKind {
    #[cfg(test)]
    const ALL: [&'static str; 30] = [
        "SessionStart",
        "SessionEnd",
        "UserPromptSubmit",
        "InstructionsLoaded",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PostToolBatch",
        "SubagentStart",
        "SubagentStop",
        "TaskCreated",
        "TaskCompleted",
        "PreCompact",
        "PostCompact",
        "CwdChanged",
        "WorktreeCreate",
        "WorktreeRemove",
        "Stop",
        "StopFailure",
        "Setup",
        "UserPromptExpansion",
        "PermissionRequest",
        "PermissionDenied",
        "Notification",
        "MessageDisplay",
        "TeammateIdle",
        "ConfigChange",
        "FileChanged",
        "Elicitation",
        "ElicitationResult",
    ];

    fn parse(value: &str) -> Result<Self, HookError> {
        match value {
            "SessionStart" => Ok(Self::SessionStart),
            "SessionEnd" => Ok(Self::SessionEnd),
            "UserPromptSubmit" => Ok(Self::UserPromptSubmit),
            "InstructionsLoaded" => Ok(Self::InstructionsLoaded),
            "PreToolUse" => Ok(Self::PreToolUse),
            "PostToolUse" => Ok(Self::PostToolUse),
            "PostToolUseFailure" => Ok(Self::PostToolUseFailure),
            "PostToolBatch" => Ok(Self::PostToolBatch),
            "SubagentStart" => Ok(Self::SubagentStart),
            "SubagentStop" => Ok(Self::SubagentStop),
            "TaskCreated" => Ok(Self::TaskCreated),
            "TaskCompleted" => Ok(Self::TaskCompleted),
            "PreCompact" => Ok(Self::PreCompact),
            "PostCompact" => Ok(Self::PostCompact),
            "CwdChanged" => Ok(Self::CwdChanged),
            "WorktreeCreate" => Ok(Self::WorktreeCreate),
            "WorktreeRemove" => Ok(Self::WorktreeRemove),
            "Stop" => Ok(Self::Stop),
            "StopFailure" => Ok(Self::StopFailure),
            "Setup" => Ok(Self::Setup),
            "UserPromptExpansion" => Ok(Self::UserPromptExpansion),
            "PermissionRequest" => Ok(Self::PermissionRequest),
            "PermissionDenied" => Ok(Self::PermissionDenied),
            "Notification" => Ok(Self::Notification),
            "MessageDisplay" => Ok(Self::MessageDisplay),
            "TeammateIdle" => Ok(Self::TeammateIdle),
            "ConfigChange" => Ok(Self::ConfigChange),
            "FileChanged" => Ok(Self::FileChanged),
            "Elicitation" => Ok(Self::Elicitation),
            "ElicitationResult" => Ok(Self::ElicitationResult),
            _ => Err(HookError::InputMalformed),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStart => "SessionStart",
            Self::SessionEnd => "SessionEnd",
            Self::UserPromptSubmit => "UserPromptSubmit",
            Self::InstructionsLoaded => "InstructionsLoaded",
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::PostToolUseFailure => "PostToolUseFailure",
            Self::PostToolBatch => "PostToolBatch",
            Self::SubagentStart => "SubagentStart",
            Self::SubagentStop => "SubagentStop",
            Self::TaskCreated => "TaskCreated",
            Self::TaskCompleted => "TaskCompleted",
            Self::PreCompact => "PreCompact",
            Self::PostCompact => "PostCompact",
            Self::CwdChanged => "CwdChanged",
            Self::WorktreeCreate => "WorktreeCreate",
            Self::WorktreeRemove => "WorktreeRemove",
            Self::Stop => "Stop",
            Self::StopFailure => "StopFailure",
            Self::Setup => "Setup",
            Self::UserPromptExpansion => "UserPromptExpansion",
            Self::PermissionRequest => "PermissionRequest",
            Self::PermissionDenied => "PermissionDenied",
            Self::Notification => "Notification",
            Self::MessageDisplay => "MessageDisplay",
            Self::TeammateIdle => "TeammateIdle",
            Self::ConfigChange => "ConfigChange",
            Self::FileChanged => "FileChanged",
            Self::Elicitation => "Elicitation",
            Self::ElicitationResult => "ElicitationResult",
        }
    }

    const fn uses_context_backend(self) -> bool {
        matches!(
            self,
            Self::SessionStart
                | Self::UserPromptSubmit
                | Self::SubagentStart
                | Self::PreCompact
                | Self::PostCompact
        )
    }

    const fn supports_additional_context(self) -> bool {
        matches!(
            self,
            Self::SessionStart
                | Self::UserPromptSubmit
                | Self::SubagentStart
                | Self::PreToolUse
                | Self::PostToolUse
                | Self::PostToolUseFailure
                | Self::PostToolBatch
                | Self::PostCompact
        )
    }

    fn is_governed_effect_precheck(self, payload: &Map<String, Value>) -> bool {
        self == Self::PreToolUse
            && payload
                .get("tool_name")
                .and_then(Value::as_str)
                .is_some_and(|tool| {
                    tool == "mcp__cigar__effect_commit"
                        || tool == "mcp__cigar__effect_dispatch"
                        || tool.ends_with("__effect_commit")
                })
    }
}

struct HookEvent {
    session_id: String,
    cwd: String,
    kind: HookKind,
    payload: Map<String, Value>,
    canonical_payload: Vec<u8>,
}

impl HookEvent {
    fn parse(bytes: &[u8]) -> Result<Self, HookError> {
        if bytes.is_empty() {
            return Err(HookError::InputMalformed);
        }
        let value = parse_strict_value(bytes)?;
        let canonical_payload =
            serde_json::to_vec(&value).map_err(|_error| HookError::InputMalformed)?;
        let payload = value.as_object().ok_or(HookError::InputMalformed)?.clone();
        validate_json_shape(&value, 0)?;
        let session_id =
            validate_identifier(required_string(&payload, "session_id", 256)?)?.to_owned();
        let cwd = required_string(&payload, "cwd", 16 * 1024)?.to_owned();
        if cwd.chars().any(char::is_control) {
            return Err(HookError::InputMalformed);
        }
        let kind = HookKind::parse(required_string(&payload, "hook_event_name", 64)?)?;
        validate_event_required_fields(kind, &payload)?;
        Ok(Self {
            session_id,
            cwd,
            kind,
            payload,
            canonical_payload,
        })
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a strict JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let StrictValue(value) = map.next_value::<StrictValue>()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn parse_strict_value(bytes: &[u8]) -> Result<Value, HookError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) =
        StrictValue::deserialize(&mut deserializer).map_err(|_error| HookError::InputMalformed)?;
    deserializer
        .end()
        .map_err(|_error| HookError::InputMalformed)?;
    Ok(value)
}

fn validate_event_required_fields(
    kind: HookKind,
    payload: &Map<String, Value>,
) -> Result<(), HookError> {
    match kind {
        HookKind::SessionStart => {
            required_string(payload, "source", 64)?;
            if payload.contains_key("model") {
                required_string(payload, "model", 256)?;
            }
        }
        HookKind::UserPromptSubmit => {
            required_string(payload, "prompt", 32 * 1024)?;
        }
        HookKind::PreToolUse | HookKind::PostToolUse => {
            required_string(payload, "tool_name", 512)?;
            required_object(payload, "tool_input")?;
        }
        HookKind::PostToolUseFailure => {
            required_string(payload, "tool_name", 512)?;
            required_object(payload, "tool_input")?;
            required_string(payload, "error", 32 * 1024)?;
        }
        HookKind::SubagentStart | HookKind::SubagentStop => {
            required_string(payload, "agent_id", 256)?;
            required_string(payload, "agent_type", 256)?;
        }
        HookKind::TaskCreated | HookKind::TaskCompleted => {
            required_string(payload, "task_id", 256)?;
        }
        HookKind::PreCompact => {
            required_string(payload, "trigger", 64)?;
            required_string(payload, "custom_instructions", 32 * 1024)?;
        }
        HookKind::WorktreeCreate => {
            required_string(payload, "name", 256)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_json_shape(value: &Value, depth: usize) -> Result<(), HookError> {
    if depth > 16 {
        return Err(HookError::InputMalformed);
    }
    match value {
        Value::String(value) if value.len() > 48 * 1024 => Err(HookError::InputMalformed),
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => Ok(()),
        Value::Array(values) if values.len() > 1_024 => Err(HookError::InputMalformed),
        Value::Array(values) => {
            for value in values {
                validate_json_shape(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) if values.len() > 1_024 => Err(HookError::InputMalformed),
        Value::Object(values) => {
            for (key, value) in values {
                if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
                    return Err(HookError::InputMalformed);
                }
                validate_json_shape(value, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn required_string<'a>(
    payload: &'a Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<&'a str, HookError> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or(HookError::InputMalformed)
}

fn required_object<'a>(
    payload: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, HookError> {
    payload
        .get(name)
        .and_then(Value::as_object)
        .ok_or(HookError::InputMalformed)
}

fn validate_identifier(value: &str) -> Result<&str, HookError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(HookError::InputMalformed)
    } else {
        Ok(value)
    }
}

fn normalize_prompt(prompt: &str) -> String {
    prompt.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn effect_id(payload: &Map<String, Value>) -> Option<String> {
    payload
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|input| input.get("effect_id"))
        .and_then(Value::as_str)
        .and_then(|value| validate_identifier(value).ok())
        .map(str::to_owned)
}

fn observe_event(session: &mut SessionState, event: &HookEvent, payload_digest: &str) {
    if let Some(usage) = event.payload.get("usage").and_then(Value::as_object) {
        let count = |name| usage.get(name).and_then(Value::as_u64).unwrap_or(0);
        session.accounting.physical_tokens = session
            .accounting
            .physical_tokens
            .saturating_add(count("input_tokens"))
            .saturating_add(count("output_tokens"));
        session.accounting.cache_write_tokens = session
            .accounting
            .cache_write_tokens
            .saturating_add(count("cache_creation_input_tokens"));
        session.accounting.cache_read_tokens = session
            .accounting
            .cache_read_tokens
            .saturating_add(count("cache_read_input_tokens"));
    }
    if matches!(
        event.kind,
        HookKind::PostToolUse | HookKind::InstructionsLoaded
    ) {
        let source = event
            .payload
            .get("tool_input")
            .and_then(Value::as_object)
            .and_then(|input| input.get("file_path").or_else(|| input.get("path")))
            .or_else(|| event.payload.get("file_path"))
            .and_then(Value::as_str);
        if let Some(source) = source.filter(|value| value.len() <= 16 * 1024) {
            if session.present.len() >= MAX_PRESENT_PER_SESSION {
                let first = session.present.keys().next().cloned();
                if let Some(first) = first {
                    session.present.remove(&first);
                }
            }
            session.present.insert(
                digest_bytes(source.as_bytes()),
                PresentObservation {
                    acquisition: event.kind.as_str().to_owned(),
                    payload_digest: payload_digest.to_owned(),
                    sequence: session.sequence,
                },
            );
        }
    }
}

fn record_checkpoint(session: &mut SessionState, checkpoint: String) {
    if session.checkpoints.len() >= MAX_CHECKPOINTS_PER_SESSION {
        session.checkpoints.remove(0);
    }
    session.checkpoints.push(checkpoint);
}

fn cache_event(session: &mut SessionState, key: String, payload_digest: String, response: Value) {
    if session.events.len() >= MAX_EVENTS_PER_SESSION
        && let Some(oldest) = session
            .events
            .iter()
            .min_by_key(|(_key, event)| event.sequence)
            .map(|(key, _event)| key.clone())
    {
        session.events.remove(&oldest);
    }
    session.events.insert(
        key,
        CachedEvent {
            sequence: session.sequence,
            payload_digest,
            response,
        },
    );
}

fn prune_oldest_session(state: &mut AdapterState) {
    if let Some(oldest) = state
        .sessions
        .iter()
        .min_by_key(|(_id, session)| session.sequence)
        .map(|(id, _session)| id.clone())
    {
        state.sessions.remove(&oldest);
    }
}

#[derive(Clone, Debug)]
enum BackendRequest {
    Bootstrap {
        session_id: String,
        cwd: String,
    },
    PromptDelta {
        session_id: String,
        cwd: String,
        prompt_digest: String,
        base_bundle: Option<String>,
    },
    Checkpoint {
        session_id: String,
        checkpoint: String,
    },
    Recompile {
        session_id: String,
        cwd: String,
        checkpoint: Option<String>,
    },
    RecipientHandoff {
        session_id: String,
        recipient: String,
        base_bundle: Option<String>,
    },
    EffectPrecheck {
        effect_id: String,
    },
}

#[derive(Clone, Debug)]
struct BackendReply {
    content: String,
    source: Option<String>,
    snapshot: Option<String>,
    bundle_or_source: Option<String>,
    authority_lane: String,
    degraded: bool,
    authorized: bool,
    physical_tokens: u64,
    cache_write_tokens: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HandoffRecipient {
    Principal(String),
    Role(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HandoffConfiguration {
    recipient: HandoffRecipient,
    project_id: String,
    target_plan_id: String,
    audience: String,
}

trait HookBackend: Send + Sync {
    fn call<'a>(
        &'a self,
        request: BackendRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BackendReply, HookError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug)]
struct CliBackend;

impl HookBackend for CliBackend {
    fn call<'a>(
        &'a self,
        request: BackendRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BackendReply, HookError>> + Send + 'a>> {
        Box::pin(async move { call_cli_backend(request).await })
    }
}

async fn call_cli_backend(request: BackendRequest) -> Result<BackendReply, HookError> {
    match request {
        BackendRequest::Bootstrap { session_id, cwd } => {
            compile_context(&session_id, &cwd, None).await
        }
        BackendRequest::PromptDelta {
            session_id,
            cwd,
            prompt_digest,
            base_bundle,
        } => {
            let evidence = format!(
                "prompt={prompt_digest};base={}",
                base_bundle.as_deref().unwrap_or("none")
            );
            compile_context(&session_id, &cwd, Some(&evidence)).await
        }
        BackendRequest::Recompile {
            session_id,
            cwd,
            checkpoint,
        } => {
            let evidence = format!("checkpoint={}", checkpoint.as_deref().unwrap_or("none"));
            compile_context(&session_id, &cwd, Some(&evidence)).await
        }
        BackendRequest::Checkpoint {
            session_id,
            checkpoint,
        } => create_checkpoint(&session_id, &checkpoint).await,
        BackendRequest::RecipientHandoff {
            session_id,
            recipient,
            base_bundle,
        } => {
            let configuration = handoff_configuration()?;
            let binary =
                std::env::var_os("CIGAR_CLI_BINARY").unwrap_or_else(|| OsString::from("cigar"));
            create_and_accept_recipient_handoff(
                &binary,
                &session_id,
                &recipient,
                &base_bundle.ok_or(HookError::BackendUnavailable)?,
                &configuration,
                BACKEND_DEADLINE,
            )
            .await
        }
        BackendRequest::EffectPrecheck { effect_id } => effect_precheck(&effect_id).await,
    }
}

fn handoff_configuration() -> Result<HandoffConfiguration, HookError> {
    let principal = std::env::var("CIGAR_CLAUDE_HANDOFF_RECIPIENT_ID").ok();
    let role = std::env::var("CIGAR_CLAUDE_HANDOFF_RECIPIENT_ROLE").ok();
    let recipient = match (principal, role) {
        (Some(principal), None) => HandoffRecipient::Principal(
            validate_identifier(&principal)
                .map_err(|_error| HookError::BackendUnavailable)?
                .to_owned(),
        ),
        (None, Some(role)) => HandoffRecipient::Role(
            validate_identifier(&role)
                .map_err(|_error| HookError::BackendUnavailable)?
                .to_owned(),
        ),
        (Some(_), Some(_)) | (None, None) => return Err(HookError::BackendUnavailable),
    };
    let project_id = required_handoff_environment("CIGAR_CLAUDE_HANDOFF_PROJECT_ID")?;
    let target_plan_id = required_handoff_environment("CIGAR_CLAUDE_PLAN_ID")?;
    let audience = required_handoff_environment("CIGAR_CLAUDE_HANDOFF_AUDIENCE")?;
    Ok(HandoffConfiguration {
        recipient,
        project_id,
        target_plan_id,
        audience,
    })
}

fn required_handoff_environment(name: &str) -> Result<String, HookError> {
    let value = std::env::var(name).map_err(|_error| HookError::BackendUnavailable)?;
    validate_identifier(&value)
        .map_err(|_error| HookError::BackendUnavailable)
        .map(str::to_owned)
}

impl HandoffRecipient {
    fn selector(&self) -> Value {
        match self {
            Self::Principal(value) => json!({"type": "principal", "value": value}),
            Self::Role(value) => json!({"type": "role", "value": value}),
        }
    }

    fn accepts_principal(&self, principal: &str) -> bool {
        match self {
            Self::Principal(expected) => expected == principal,
            Self::Role(_) => validate_identifier(principal).is_ok(),
        }
    }
}

async fn create_and_accept_recipient_handoff(
    binary: &OsStr,
    session_id: &str,
    recipient_label: &str,
    parent_bundle: &str,
    configuration: &HandoffConfiguration,
    deadline: Duration,
) -> Result<BackendReply, HookError> {
    validate_identifier(session_id).map_err(|_error| HookError::BackendUnavailable)?;
    validate_identifier(recipient_label).map_err(|_error| HookError::BackendUnavailable)?;
    if !valid_bundle_id(parent_bundle) {
        return Err(HookError::BackendUnavailable);
    }
    let task = format!("Execute the bounded Claude subagent assignment for {recipient_label}.");
    let criterion = format!("Return only evidence authorized for {recipient_label}.");
    let selector = configuration.recipient.selector();
    let create_request = json!({
        "recipient": selector,
        "task": task,
        "acceptance_criteria": [criterion],
        "requested_projects": [configuration.project_id],
        "requested_capabilities": ["read_context"],
        "budget": {
            "total_input_tokens": 1_000,
            "output_reserve_tokens": 256,
            "lane_input_tokens": {"evidence": 1_000}
        },
        "topics": ["handoff_revocation"],
        "references": {
            "sources": [],
            "states": [],
            "decisions": [],
            "artifacts": [],
            "uncertainties": [],
            "effects": []
        },
        "bundle_id": parent_bundle,
        "audience": configuration.audience,
        "ttl_seconds": HANDOFF_TTL_SECONDS,
        "reusable": false
    });
    let created = invoke_cli_with_binary_deadline(
        binary,
        &["handoff", "create"],
        Some(&create_request),
        &["--yes", "--output", "json", "--deadline", "100ms"],
        deadline,
    )
    .await?;
    let capsule = created
        .pointer("/result/capsule")
        .and_then(Value::as_object)
        .ok_or(HookError::BackendUnavailable)?;
    let handoff_id = capsule
        .get("handoff_id")
        .and_then(Value::as_str)
        .and_then(|value| validate_identifier(value).ok())
        .map(str::to_owned)
        .ok_or(HookError::BackendUnavailable)?;
    let expected_projects = json!([configuration.project_id]);
    let expected_capabilities = json!(["read_context"]);
    if capsule.get("schema_version").and_then(Value::as_str) != Some("cigar.handoff.v1")
        || capsule.get("recipient") != Some(&configuration.recipient.selector())
        || capsule.get("task").and_then(Value::as_str) != Some(task.as_str())
        || capsule.get("project_ids") != Some(&expected_projects)
        || capsule.get("delegated_capabilities") != Some(&expected_capabilities)
        || capsule.get("bundle_id").and_then(Value::as_str) != Some(parent_bundle)
        || capsule.get("audience").and_then(Value::as_str) != Some(configuration.audience.as_str())
        || capsule.get("reusable").and_then(Value::as_bool) != Some(false)
        || !capsule
            .get("signature")
            .is_some_and(nonempty_signature_value)
        || created.pointer("/result/preview/accepted_projects") != Some(&expected_projects)
        || created.pointer("/result/preview/accepted_capabilities") != Some(&expected_capabilities)
    {
        return Err(HookError::BackendUnavailable);
    }

    let accept_request = json!({
        "handoff_id": handoff_id,
        "target_plan_id": configuration.target_plan_id
    });
    let accepted = invoke_cli_with_binary_deadline(
        binary,
        &["handoff", "accept", &handoff_id],
        Some(&accept_request),
        &[
            "--expected-revision",
            "1",
            "--yes",
            "--output",
            "json",
            "--deadline",
            "100ms",
        ],
        deadline,
    )
    .await?;
    let acceptance = accepted
        .get("result")
        .and_then(Value::as_object)
        .ok_or(HookError::BackendUnavailable)?;
    let actual_recipient = acceptance
        .get("recipient_id")
        .and_then(Value::as_str)
        .filter(|principal| configuration.recipient.accepts_principal(principal))
        .map(str::to_owned)
        .ok_or(HookError::BackendUnavailable)?;
    let accepted_bundle = acceptance
        .get("bundle_id")
        .and_then(Value::as_str)
        .filter(|bundle| valid_bundle_id(bundle) && *bundle != parent_bundle)
        .map(str::to_owned)
        .ok_or(HookError::BackendUnavailable)?;
    if acceptance.get("schema_version").and_then(Value::as_str)
        != Some("cigar.handoff-acceptance.v1")
        || acceptance.get("handoff_id").and_then(Value::as_str) != Some(handoff_id.as_str())
        || acceptance.get("accepted_capabilities") != Some(&expected_capabilities)
        || acceptance.get("rejected_capabilities") != Some(&json!([]))
        || acceptance
            .get("acceptance_id")
            .and_then(Value::as_str)
            .and_then(|value| validate_identifier(value).ok())
            .is_none()
    {
        return Err(HookError::BackendUnavailable);
    }
    let content = format!(
        "Accepted recipient-specific CIGAR handoff {handoff_id} for Claude subagent {recipient_label} as authenticated recipient {actual_recipient}. Use only accepted bundle {accepted_bundle}; expand its authorized references through the CIGAR MCP server."
    );
    Ok(BackendReply {
        content,
        source: Some(handoff_id),
        snapshot: None,
        bundle_or_source: Some(accepted_bundle),
        authority_lane: "handoff".to_owned(),
        degraded: false,
        authorized: true,
        physical_tokens: 34,
        cache_write_tokens: 0,
    })
}

fn nonempty_signature_value(value: &Value) -> bool {
    match value {
        Value::Array(bytes) => !bytes.is_empty() && bytes.iter().all(Value::is_u64),
        Value::String(encoded) => !encoded.is_empty(),
        _ => false,
    }
}

fn valid_bundle_id(value: &str) -> bool {
    value.len() == 68
        && value.starts_with("1220")
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn create_checkpoint(session_id: &str, checkpoint: &str) -> Result<BackendReply, HookError> {
    let space_id =
        std::env::var("CIGAR_CLAUDE_SPACE_ID").map_err(|_error| HookError::BackendUnavailable)?;
    let focus_id =
        std::env::var("CIGAR_CLAUDE_FOCUS_ID").map_err(|_error| HookError::BackendUnavailable)?;
    validate_identifier(&space_id).map_err(|_error| HookError::BackendUnavailable)?;
    validate_identifier(&focus_id).map_err(|_error| HookError::BackendUnavailable)?;
    let request = json!({"space_id": space_id, "focus_id": focus_id});
    let output = invoke_cli(
        &["focus", "checkpoint", &space_id],
        Some(&request),
        &["--yes", "--output", "json", "--deadline", "100ms"],
    )
    .await?;
    let source = output
        .get("result")
        .and_then(|result| {
            result
                .get("checkpoint_id")
                .or_else(|| result.get("resource_id"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| digest_bytes(format!("{session_id}\0{checkpoint}").as_bytes()));
    Ok(BackendReply {
        content: String::new(),
        source: Some(source),
        snapshot: None,
        bundle_or_source: None,
        authority_lane: "state".to_owned(),
        degraded: false,
        authorized: false,
        physical_tokens: 0,
        cache_write_tokens: 0,
    })
}

async fn compile_context(
    session_id: &str,
    cwd: &str,
    evidence: Option<&str>,
) -> Result<BackendReply, HookError> {
    let plan_id =
        std::env::var("CIGAR_CLAUDE_PLAN_ID").map_err(|_error| HookError::BackendUnavailable)?;
    validate_identifier(&plan_id).map_err(|_error| HookError::BackendUnavailable)?;
    let request = json!({"plan_id": plan_id});
    let output = invoke_cli(
        &["context", "compile"],
        Some(&request),
        &["--yes", "--output", "json", "--deadline", "100ms"],
    )
    .await?;
    let result = output
        .get("result")
        .and_then(Value::as_object)
        .ok_or(HookError::BackendUnavailable)?;
    let bundle = result
        .get("bundle_id")
        .or_else(|| result.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| digest_bytes(output.to_string().as_bytes()));
    let snapshot = result
        .get("snapshot_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let content = format!(
        "CIGAR compiled bundle {bundle} for session {session_id} in the current public working directory. Use context_expand for bounded materialized blocks and context_explain or /cigar:why for provenance. Working-directory identity digest: {}. Boundary evidence: {}.",
        digest_bytes(cwd.as_bytes()),
        evidence.unwrap_or("startup")
    );
    Ok(BackendReply {
        content,
        source: Some(bundle.clone()),
        snapshot,
        bundle_or_source: Some(bundle),
        authority_lane: "context".to_owned(),
        degraded: false,
        authorized: false,
        physical_tokens: 38,
        cache_write_tokens: 20,
    })
}

async fn effect_precheck(effect_id: &str) -> Result<BackendReply, HookError> {
    let output = invoke_cli(
        &["effect", "inspect", effect_id],
        None,
        &["--output", "json", "--deadline", "100ms"],
    )
    .await?;
    let state = output
        .get("result")
        .and_then(|result| result.get("state"))
        .and_then(Value::as_str)
        .ok_or(HookError::BackendUnavailable)?;
    Ok(BackendReply {
        content: String::new(),
        source: Some(effect_id.to_owned()),
        snapshot: None,
        bundle_or_source: None,
        authority_lane: "effect".to_owned(),
        degraded: false,
        authorized: matches!(state, "authorized" | "authorized_for_retry"),
        physical_tokens: 0,
        cache_write_tokens: 0,
    })
}

async fn invoke_cli(
    command: &[&str],
    request: Option<&Value>,
    trailing: &[&str],
) -> Result<Value, HookError> {
    let binary = std::env::var_os("CIGAR_CLI_BINARY").unwrap_or_else(|| OsString::from("cigar"));
    invoke_cli_with_binary(&binary, command, request, trailing).await
}

async fn invoke_cli_with_binary(
    binary: &OsStr,
    command: &[&str],
    request: Option<&Value>,
    trailing: &[&str],
) -> Result<Value, HookError> {
    invoke_cli_with_binary_deadline(binary, command, request, trailing, BACKEND_DEADLINE).await
}

async fn invoke_cli_with_binary_deadline(
    binary: &OsStr,
    command: &[&str],
    request: Option<&Value>,
    trailing: &[&str],
    deadline: Duration,
) -> Result<Value, HookError> {
    let temporary = if let Some(request) = request {
        let root = std::env::temp_dir();
        let path = root.join(format!(
            "cigar-claude-hook-{}-{}.json",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        write_private_new(&path, request.to_string().as_bytes())?;
        Some(path)
    } else {
        None
    };
    let mut child = tokio::process::Command::new(binary);
    child.args(command);
    if let Some(path) = &temporary {
        child.arg("--input").arg(path);
    }
    child
        .args(trailing)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let result = async {
        let mut child = child
            .spawn()
            .map_err(|_error| HookError::BackendUnavailable)?;
        let stdout = child.stdout.take().ok_or(HookError::BackendUnavailable)?;
        let stderr = child.stderr.take().ok_or(HookError::BackendUnavailable)?;
        let stdout_task = tokio::spawn(read_bounded_async(stdout));
        let stderr_task = tokio::spawn(read_bounded_async(stderr));
        let status = match tokio::time::timeout(deadline, child.wait()).await {
            Ok(status) => status.map_err(|_error| HookError::BackendUnavailable)?,
            Err(_elapsed) => {
                let _ignored = child.kill().await;
                let _ignored = child.wait().await;
                return Err(HookError::BackendUnavailable);
            }
        };
        let stdout = stdout_task
            .await
            .map_err(|_join| HookError::BackendUnavailable)??;
        let _stderr = stderr_task
            .await
            .map_err(|_join| HookError::BackendUnavailable)??;
        if !status.success() {
            return Err(HookError::BackendUnavailable);
        }
        cigar_canon::parse_strict_json(&stdout).map_err(|_error| HookError::BackendUnavailable)?;
        let value: Value =
            serde_json::from_slice(&stdout).map_err(|_error| HookError::BackendUnavailable)?;
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(HookError::BackendUnavailable);
        }
        Ok(value)
    }
    .await;
    if let Some(path) = temporary {
        let _ignored = std::fs::remove_file(path);
    }
    result
}

async fn read_bounded_async<R>(reader: R) -> Result<Vec<u8>, HookError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let limit = u64::try_from(OUTPUT_LIMIT_BYTES)
        .map_err(|_error| HookError::BackendUnavailable)?
        .saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_error| HookError::BackendUnavailable)?;
    if bytes.len() > OUTPUT_LIMIT_BYTES {
        Err(HookError::BackendUnavailable)
    } else {
        Ok(bytes)
    }
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), HookError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_error| HookError::StateUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_error| HookError::StateUnavailable)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterState {
    schema_version: String,
    sessions: BTreeMap<String, SessionState>,
}

impl Default for AdapterState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA.to_owned(),
            sessions: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionState {
    sequence: u64,
    events: BTreeMap<String, CachedEvent>,
    injected: BTreeSet<String>,
    present: BTreeMap<String, PresentObservation>,
    checkpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_task_boundary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_injection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_or_source: Option<String>,
    authority_lane: String,
    accounting: TokenAccounting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedEvent {
    sequence: u64,
    payload_digest: String,
    response: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PresentObservation {
    acquisition: String,
    payload_digest: String,
    sequence: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenAccounting {
    physical_tokens: u64,
    cache_write_tokens: u64,
    cache_read_tokens: u64,
    outcome_events: u64,
}

fn read_state(directory: &Path) -> Result<AdapterState, HookError> {
    let path = directory.join("hook-state.json");
    if !path.exists() {
        return Ok(AdapterState::default());
    }
    let bytes = read_bounded_regular(&path, STATE_LIMIT_BYTES)?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| HookError::StateCorrupt)?;
    let state: AdapterState =
        serde_json::from_slice(&bytes).map_err(|_error| HookError::StateCorrupt)?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &AdapterState) -> Result<(), HookError> {
    if state.schema_version != STATE_SCHEMA || state.sessions.len() > MAX_SESSIONS {
        return Err(HookError::StateCorrupt);
    }
    for (session_id, session) in &state.sessions {
        validate_identifier(session_id).map_err(|_error| HookError::StateCorrupt)?;
        if session.events.len() > MAX_EVENTS_PER_SESSION
            || session.present.len() > MAX_PRESENT_PER_SESSION
            || session.checkpoints.len() > MAX_CHECKPOINTS_PER_SESSION
        {
            return Err(HookError::StateCorrupt);
        }
    }
    Ok(())
}

fn write_state(directory: &Path, state: &AdapterState) -> Result<(), HookError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_error| HookError::StateCorrupt)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > STATE_LIMIT_BYTES) {
        return Err(HookError::StateCorrupt);
    }
    let path = directory.join("hook-state.json");
    let temporary = directory.join(format!(
        ".hook-state-{}-{}.tmp",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_private_new(&temporary, &bytes)?;
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(&path).map_err(|_error| HookError::StateUnavailable)?;
    }
    let result = std::fs::rename(&temporary, &path).map_err(|_error| HookError::StateUnavailable);
    if result.is_err() {
        let _ignored = std::fs::remove_file(&temporary);
    }
    result
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, HookError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_error| HookError::StateUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(HookError::StateCorrupt);
    }
    let file = File::open(path).map_err(|_error| HookError::StateUnavailable)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| HookError::StateUnavailable)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        Err(HookError::StateCorrupt)
    } else {
        Ok(bytes)
    }
}

struct StateLock {
    path: PathBuf,
}

impl StateLock {
    fn acquire(directory: &Path) -> Result<Self, HookError> {
        let path = directory.join("hook-state.lock");
        let started = std::time::Instant::now();
        loop {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id())
                        .and_then(|()| file.sync_all())
                        .map_err(|_error| HookError::StateUnavailable)?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        let _ignored = std::fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() >= LOCK_DEADLINE {
                        return Err(HookError::StateUnavailable);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_error) => return Err(HookError::StateUnavailable),
            }
        }
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age > LOCK_STALE_AFTER)
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "1220{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FixedBackend {
        calls: Arc<Mutex<Vec<BackendRequest>>>,
        reply: Result<BackendReply, HookError>,
    }

    impl FixedBackend {
        fn available() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                reply: Ok(BackendReply {
                    content: "Stable project policy and current task delta.".to_owned(),
                    source: Some(digest_bytes(b"source")),
                    snapshot: Some(digest_bytes(b"snapshot")),
                    bundle_or_source: Some(digest_bytes(b"bundle")),
                    authority_lane: "context".to_owned(),
                    degraded: false,
                    authorized: true,
                    physical_tokens: 7,
                    cache_write_tokens: 5,
                }),
            }
        }

        fn unavailable() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                reply: Err(HookError::BackendUnavailable),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().map_or(usize::MAX, |calls| calls.len())
        }
    }

    impl HookBackend for FixedBackend {
        fn call<'a>(
            &'a self,
            request: BackendRequest,
        ) -> Pin<Box<dyn Future<Output = Result<BackendReply, HookError>> + Send + 'a>> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(request);
            }
            let reply = self.reply.clone();
            Box::pin(async move { reply })
        }
    }

    fn fixture(kind: &str, extra: Value) -> Vec<u8> {
        let mut value = json!({
            "session_id": "session-1",
            "transcript_path": "/opaque/provider/path/session.jsonl",
            "cwd": "/workspace",
            "hook_event_name": kind
        });
        if let (Some(target), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
            target.extend(extra.clone());
        }
        serde_json::to_vec(&value).unwrap_or_default()
    }

    fn runtime(
        backend: FixedBackend,
    ) -> Result<(tempfile::TempDir, HookRuntime<FixedBackend>), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        Ok((directory, HookRuntime::new(root, backend)))
    }

    #[test]
    fn public_event_inventory_is_unique_and_current() {
        let unique = HookKind::ALL.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), 30);
        for event in unique {
            assert!(HookKind::parse(event).is_ok(), "missing {event}");
        }
    }

    #[test]
    fn every_documented_event_has_a_strict_fixture() {
        for event in HookKind::ALL {
            let extra = match event {
                "SessionStart" => json!({"source": "startup", "model": "claude-sonnet-4-6"}),
                "UserPromptSubmit" => json!({"prompt": "implement the bounded task"}),
                "PreToolUse" | "PostToolUse" => {
                    json!({"tool_name": "Read", "tool_input": {"file_path": "/workspace/a.rs"}})
                }
                "PostToolUseFailure" => json!({
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/workspace/a.rs"},
                    "error": "content-safe failure"
                }),
                "SubagentStart" | "SubagentStop" => {
                    json!({"agent_id": "agent-1", "agent_type": "Explore"})
                }
                "TaskCreated" | "TaskCompleted" => json!({"task_id": "task-1"}),
                "PreCompact" => {
                    json!({"trigger": "manual", "custom_instructions": "retain task state"})
                }
                "WorktreeCreate" => json!({"name": "feature-one"}),
                _ => json!({}),
            };
            assert!(
                HookEvent::parse(&fixture(event, extra)).is_ok(),
                "fixture rejected for {event}"
            );
        }
    }

    #[tokio::test]
    async fn exact_duplicate_returns_original_without_second_backend_call()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = FixedBackend::available();
        let (_directory, runtime) = runtime(backend.clone())?;
        let event = fixture(
            "SessionStart",
            json!({"source": "startup", "model": "claude-sonnet-4-6"}),
        );
        let first = runtime.handle(&event).await?;
        let duplicate = runtime.handle(&event).await?;
        assert_eq!(first, duplicate);
        assert_eq!(backend.call_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn identical_materialization_is_not_injected_twice_across_distinct_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = FixedBackend::available();
        let (_directory, runtime) = runtime(backend)?;
        let first = runtime
            .handle(&fixture(
                "SessionStart",
                json!({"source": "startup", "model": "claude-sonnet-4-6"}),
            ))
            .await?;
        let second = runtime
            .handle(&fixture("UserPromptSubmit", json!({"prompt": "new task"})))
            .await?;
        assert!(first.to_string().contains("additionalContext"));
        assert_eq!(second, quiet_response());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn subagent_handoff_never_substitutes_the_parent_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let binary = directory.path().join("fake-cigar");
        let log = directory.path().join("calls.log");
        let parent = digest_bytes(b"parent-bundle");
        let accepted_bundle = digest_bytes(b"accepted-recipient-bundle");
        let handoff_id = "01890f47-8e7d-7b42-a1d2-000000000001";
        let acceptance_id = "01890f47-8e7d-7b42-a1d2-000000000002";
        let actual_recipient = "01890f47-8e7d-7b42-a1d2-000000000003";
        let project_id = "01890f47-8e7d-7b42-a1d2-000000000004";
        let target_plan_id = "01890f47-8e7d-7b42-a1d2-000000000005";
        let task = "Execute the bounded Claude subagent assignment for Explore:child-agent.";
        let created = json!({
            "ok": true,
            "result": {
                "capsule": {
                    "schema_version": "cigar.handoff.v1",
                    "handoff_id": handoff_id,
                    "recipient": {"type": "role", "value": "researcher"},
                    "task": task,
                    "project_ids": [project_id],
                    "delegated_capabilities": ["read_context"],
                    "bundle_id": parent,
                    "audience": "local-runtime-v1",
                    "reusable": false,
                    "signature": [1, 2, 3]
                },
                "preview": {
                    "accepted_projects": [project_id],
                    "accepted_capabilities": ["read_context"]
                }
            }
        });
        let accepted = json!({
            "ok": true,
            "result": {
                "schema_version": "cigar.handoff-acceptance.v1",
                "acceptance_id": acceptance_id,
                "handoff_id": handoff_id,
                "recipient_id": actual_recipient,
                "accepted_capabilities": ["read_context"],
                "rejected_capabilities": [],
                "bundle_id": accepted_bundle
            }
        });
        let script = format!(
            r#"#!/bin/sh
set -eu
request=
previous=
for argument in "$@"; do
  if [ "$previous" = "--input" ]; then request=$argument; fi
  previous=$argument
done
test -n "$request"
case "$1:$2" in
  handoff:create)
    grep -F '"type":"role"' "$request" >/dev/null
    grep -F '"value":"researcher"' "$request" >/dev/null
    grep -F '"bundle_id":"{parent}"' "$request" >/dev/null
    printf '%s\n' create >> "{}"
    printf '%s\n' '{}'
    ;;
  handoff:accept)
    test "$3" = "{handoff_id}"
    grep -F '"handoff_id":"{handoff_id}"' "$request" >/dev/null
    grep -F '"target_plan_id":"{target_plan_id}"' "$request" >/dev/null
    printf '%s\n' accept >> "{}"
    printf '%s\n' '{}'
    ;;
  *) exit 2 ;;
esac
"#,
            log.display(),
            created,
            log.display(),
            accepted
        );
        std::fs::write(&binary, script)?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
        let configuration = HandoffConfiguration {
            recipient: HandoffRecipient::Role("researcher".to_owned()),
            project_id: project_id.to_owned(),
            target_plan_id: target_plan_id.to_owned(),
            audience: "local-runtime-v1".to_owned(),
        };
        let reply = create_and_accept_recipient_handoff(
            binary.as_os_str(),
            "parent-session",
            "Explore:child-agent",
            &parent,
            &configuration,
            Duration::from_secs(2),
        )
        .await?;
        assert!(
            reply.authorized,
            "a child injection requires accepted authority"
        );
        assert_eq!(reply.source.as_deref(), Some(handoff_id));
        assert_eq!(
            reply.bundle_or_source.as_deref(),
            Some(accepted_bundle.as_str())
        );
        assert!(!reply.content.contains(&parent));
        assert_eq!(std::fs::read_to_string(log)?, "create\naccept\n");
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_context_fails_open_with_visible_bounded_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, runtime) = runtime(FixedBackend::unavailable())?;
        let response = runtime
            .handle(&fixture("UserPromptSubmit", json!({"prompt": "continue"})))
            .await?;
        assert_eq!(
            response.get("systemMessage").and_then(Value::as_str),
            Some(DEGRADED_MARKER)
        );
        assert!(!response.to_string().contains("permissionDecision"));
        assert!(response.to_string().len() < 1_000);
        Ok(())
    }

    #[tokio::test]
    async fn mediated_effect_is_fail_closed_when_authority_is_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, runtime) = runtime(FixedBackend::unavailable())?;
        let response = runtime
            .handle(&fixture(
                "PreToolUse",
                json!({
                    "tool_name": "mcp__cigar__effect_commit",
                    "tool_input": {"effect_id": "effect-1"}
                }),
            ))
            .await?;
        assert_eq!(
            response.pointer("/hookSpecificOutput/permissionDecision"),
            Some(&Value::String("deny".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn compaction_checkpoints_invalidates_present_set_and_recompiles()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = FixedBackend::available();
        let (_directory, runtime) = runtime(backend.clone())?;
        runtime
            .handle(&fixture(
                "PostToolUse",
                json!({"tool_name": "Read", "tool_input": {"file_path": "/workspace/a.rs"}}),
            ))
            .await?;
        runtime
            .handle(&fixture(
                "PreCompact",
                json!({"trigger": "manual", "custom_instructions": "retain task state"}),
            ))
            .await?;
        let response = runtime
            .handle(&fixture("PostCompact", json!({"trigger": "manual"})))
            .await?;
        assert!(response.to_string().contains("additionalContext"));
        assert_eq!(backend.call_count(), 2);
        Ok(())
    }

    #[test]
    fn malformed_duplicate_deep_and_oversized_inputs_are_rejected() {
        assert_eq!(
            HookEvent::parse(br#"{"session_id":"a","session_id":"b"}"#).err(),
            Some(HookError::InputMalformed)
        );
        let mut nested = json!(null);
        for _index in 0..18 {
            nested = json!([nested]);
        }
        let event = fixture("Notification", json!({"nested": nested}));
        assert_eq!(
            HookEvent::parse(&event).err(),
            Some(HookError::InputMalformed)
        );
        let event = fixture("UserPromptSubmit", json!({"prompt": "x".repeat(40_000)}));
        assert_eq!(
            HookEvent::parse(&event).err(),
            Some(HookError::InputMalformed)
        );
        let documented_general_json = fixture(
            "PostToolUse",
            json!({
                "tool_name": "mcp__fixture__read",
                "tool_input": {"optional": null, "ratio": 0.25}
            }),
        );
        assert!(HookEvent::parse(&documented_general_json).is_ok());
    }

    #[tokio::test]
    async fn warm_prompt_p95_and_p99_stay_within_acceptance_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = FixedBackend::available();
        let (_directory, runtime) = runtime(backend)?;
        let mut samples = Vec::new();
        for index in 0..120 {
            let event = fixture(
                "UserPromptSubmit",
                json!({"prompt": format!("task boundary {index}")}),
            );
            let started = std::time::Instant::now();
            let _response = runtime.handle(&event).await?;
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let p95 = samples.get(113).copied().ok_or("p95")?;
        let p99 = samples.get(118).copied().ok_or("p99")?;
        assert!(p95 <= Duration::from_millis(150), "p95={p95:?}");
        assert!(p99 <= Duration::from_secs(1), "p99={p99:?}");
        Ok(())
    }

    #[test]
    fn bootstrap_and_backend_output_are_bounded_without_model_calls() -> Result<(), HookError> {
        let content = (0..5_000)
            .map(|index| format!("word{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let bounded = bounded_tokens(&content, 500)?;
        assert!(bounded.split_whitespace().count() <= 504);
        assert!(!bounded.contains("anthropic"));
        Ok(())
    }

    #[test]
    fn source_never_contains_provider_private_path_access_primitives() {
        let source = include_str!("lib.rs");
        for forbidden in [
            concat!(".claude", "/projects"),
            concat!(".claude", ".json"),
            concat!("read_to_string(", "transcript"),
            concat!("File::open(", "transcript"),
            concat!("type: ", "\"prompt\""),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden private/model primitive: {forbidden}"
            );
        }
    }

    #[test]
    fn doctor_rejects_alternate_hook_and_mcp_executables_even_when_json_is_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/claude-code");
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        std::fs::create_dir_all(root.join(".claude-plugin"))?;
        std::fs::create_dir_all(root.join("hooks"))?;
        for relative in [
            ".claude-plugin/plugin.json",
            ".mcp.json",
            "hooks/hooks.json",
            "compatibility.json",
        ] {
            std::fs::copy(source.join(relative), root.join(relative))?;
        }
        let root = std::fs::canonicalize(root)?;
        assert!(validate_plugin_root(&root).is_ok());

        let mcp_path = root.join(".mcp.json");
        let mut mcp: Value = serde_json::from_slice(&std::fs::read(&mcp_path)?)?;
        *mcp.pointer_mut("/mcpServers/cigar/command")
            .ok_or("MCP command")? = "alternate-mcp".into();
        std::fs::write(&mcp_path, serde_json::to_vec(&mcp)?)?;
        assert_eq!(validate_plugin_root(&root), Err(HookError::PluginInvalid));
        std::fs::copy(source.join(".mcp.json"), &mcp_path)?;

        let hooks_path = root.join("hooks/hooks.json");
        let mut hooks: Value = serde_json::from_slice(&std::fs::read(&hooks_path)?)?;
        *hooks
            .pointer_mut("/hooks/SessionStart/0/hooks/0/command")
            .ok_or("hook command")? = "alternate-hook".into();
        std::fs::write(&hooks_path, serde_json::to_vec(&hooks)?)?;
        assert_eq!(validate_plugin_root(&root), Err(HookError::PluginInvalid));
        Ok(())
    }
}
