use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_conformance::CaseOutcome;
use cigar_mcp::{
    Backend, BackendError, BackendRequest, BackendResponse, MCP_PROTOCOL_VERSION, Server,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "claude_mcp_initialize" => initialize_and_list(input),
        "claude_mcp_preinit_rejection" => preinit_rejection(input),
        _ => Err("unsupported Claude runtime conformance operation".into()),
    }
}

struct NoCallBackend {
    calls: Arc<AtomicUsize>,
}

impl Backend for NoCallBackend {
    fn call(&mut self, _request: BackendRequest<'_>) -> Result<BackendResponse, BackendError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Err(BackendError::Unavailable)
    }
}

fn no_call_backend() -> (NoCallBackend, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        NoCallBackend {
            calls: calls.clone(),
        },
        calls,
    )
}

fn initialize_and_list(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "claude-mcp-initialize-v1")?;
    let (backend, backend_calls) = no_call_backend();
    let mut server = Server::new(backend);
    let initialize = server
        .process_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"conformance","version":"1"}}}"#,
        )
        .ok_or("production MCP omitted initialize response")?;
    let initialize: serde_json::Value = serde_json::from_str(&initialize)?;
    let protocol = initialize
        .pointer("/result/protocolVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or("production MCP protocol version missing")?;
    if protocol != MCP_PROTOCOL_VERSION {
        return Err("production MCP negotiated the wrong protocol".into());
    }
    if server
        .process_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#)
        .is_some()
    {
        return Err("production MCP answered an initialized notification".into());
    }
    let tools = server
        .process_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#)
        .ok_or("production MCP omitted tools/list response")?;
    let tools: serde_json::Value = serde_json::from_str(&tools)?;
    let tools = tools
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .ok_or("production MCP tool registry missing")?;
    let names = tools
        .iter()
        .map(|tool| {
            tool.get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or("production MCP tool name missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
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
    ];
    if names != expected || backend_calls.load(Ordering::Acquire) != 0 {
        return Err("production MCP frozen tool registry diverged".into());
    }
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.claude-mcp.v1",
            &[protocol, &names.join(","), "backend_calls=0"],
        ),
    ))
}

fn preinit_rejection(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "claude-mcp-preinit-v1")?;
    let (backend, backend_calls) = no_call_backend();
    let mut server = Server::new(backend);
    let response = server
        .process_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
        .ok_or("production MCP omitted pre-initialization rejection")?;
    let response: serde_json::Value = serde_json::from_str(&response)?;
    let code = response
        .pointer("/error/code")
        .and_then(serde_json::Value::as_i64)
        .ok_or("production MCP error code missing")?;
    let reason = response
        .pointer("/error/data/reason")
        .and_then(serde_json::Value::as_str)
        .ok_or("production MCP error reason missing")?;
    if code != -32_002
        || reason != "initialization_required"
        || backend_calls.load(Ordering::Acquire) != 0
    {
        return Err("production MCP pre-initialization failure diverged".into());
    }
    Ok((
        CaseOutcome::Rejected,
        rejected_digest("claude_mcp_initialization_required"),
    ))
}
