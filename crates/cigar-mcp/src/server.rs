//! MCP 2025-06-18 stdio protocol implementation.

use std::collections::{BTreeMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::backend::{
    Backend, BackendError, BackendMetadata, BackendRequest, BackendRequestKind, BackendResponse,
};
use crate::json::{self, Value, number, object, string};

/// MCP protocol revision implemented by this server.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
/// Maximum bytes accepted in one newline-delimited stdio request.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Default inline result budget in approximate model tokens.
pub const DEFAULT_OUTPUT_TOKENS: usize = 1_200;
/// Minimum caller-selectable inline result budget.
pub const MIN_OUTPUT_TOKENS: usize = 500;
/// Maximum caller-selectable inline result budget.
pub const MAX_OUTPUT_TOKENS: usize = 4_000;

const SERVER_INSTRUCTIONS: &str = concat!(
    "Use CIGAR resources for bounded current context. Compile before expansion; treat snapshot, ",
    "expiry, degradation, and authority-lane metadata as binding. Effect preparation and commit ",
    "fail closed whenever the authoritative daemon is unavailable."
);
const HANDLE_TTL: Duration = Duration::from_secs(300);
const MAX_STORED_HANDLES: usize = 32;
const MAX_STORED_BYTES: usize = 16 * 1024 * 1024;
const BACKEND_MAX_DEPTH: usize = 64;
const BACKEND_MAX_NODES: usize = 65_536;
const BACKEND_MAX_STRING_BYTES: usize = 4 * 1024 * 1024;
const MAX_INTEROPERABLE_RPC_INTEGER_ID: i64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionState {
    AwaitInitialize,
    AwaitInitializedNotification,
    Ready,
}

#[derive(Clone, Debug)]
struct StoredOutput {
    body: String,
    metadata: BackendMetadata,
    created: Instant,
}

#[derive(Clone, Copy)]
struct ToolSpec {
    name: &'static str,
    daemon_operation: &'static str,
    description: &'static str,
    allowed: &'static [&'static str],
    required: &'static [&'static str],
    always_required: &'static [&'static str],
    exact_request_only: bool,
    lane: &'static str,
}

const TOOLS: [ToolSpec; 10] = [
    ToolSpec {
        name: "context_compile",
        daemon_operation: "createContextPlan",
        description: "Compile a bounded context bundle from an explicit contract and source set.",
        allowed: &["request", "contract", "max_tokens"],
        required: &["contract"],
        always_required: &[],
        exact_request_only: false,
        lane: "context_read",
    },
    ToolSpec {
        name: "context_expand",
        daemon_operation: "materializeContextBundle",
        description: "Expand one bundle or page an opaque large-output handle within a strict budget.",
        allowed: &["request", "bundle_id", "handle", "cursor", "max_tokens"],
        required: &[],
        always_required: &[],
        exact_request_only: false,
        lane: "context_read",
    },
    ToolSpec {
        name: "context_explain",
        daemon_operation: "explainContextBundle",
        description: "Explain bounded compiler selection evidence for one immutable bundle.",
        allowed: &["request", "bundle_id", "selection_id", "max_tokens"],
        required: &["bundle_id"],
        always_required: &[],
        exact_request_only: false,
        lane: "context_read",
    },
    ToolSpec {
        name: "catalog_query",
        daemon_operation: "queryCatalog",
        description: "Query catalog metadata with an exact QueryCatalogRequest and bounded result page.",
        allowed: &["request", "max_tokens"],
        required: &[],
        always_required: &[],
        exact_request_only: true,
        lane: "catalog_read",
    },
    ToolSpec {
        name: "checkpoint_create",
        daemon_operation: "createSpaceCheckpoint",
        description: "Create a durable checkpoint from an exact CheckpointSpaceRequest.",
        allowed: &["request", "idempotency_key", "max_tokens"],
        required: &[],
        always_required: &["idempotency_key"],
        exact_request_only: true,
        lane: "coordination_write",
    },
    ToolSpec {
        name: "handoff_create",
        daemon_operation: "createHandoff",
        description: "Create a signed bounded handoff from an exact CreateHandoffRequest.",
        allowed: &["request", "idempotency_key", "max_tokens"],
        required: &[],
        always_required: &["idempotency_key"],
        exact_request_only: true,
        lane: "coordination_write",
    },
    ToolSpec {
        name: "handoff_accept",
        daemon_operation: "acceptHandoff",
        description: "Accept a signed handoff from an exact AcceptHandoffRequest after revalidation.",
        allowed: &["request", "idempotency_key", "max_tokens"],
        required: &[],
        always_required: &["idempotency_key"],
        exact_request_only: true,
        lane: "coordination_write",
    },
    ToolSpec {
        name: "effect_prepare",
        daemon_operation: "prepareEffect",
        description: "Prepare, but do not commit, an idempotent governed external effect.",
        allowed: &["request", "intent", "idempotency_key", "max_tokens"],
        required: &["intent"],
        always_required: &["idempotency_key"],
        exact_request_only: false,
        lane: "effect_prepare",
    },
    ToolSpec {
        name: "effect_commit",
        daemon_operation: "dispatchEffect",
        description: "Commit one authoritative prepared effect; unavailable authority fails closed.",
        allowed: &["request", "preparation_id", "idempotency_key", "max_tokens"],
        required: &["preparation_id"],
        always_required: &["idempotency_key"],
        exact_request_only: false,
        lane: "effect_commit",
    },
    ToolSpec {
        name: "effect_status",
        daemon_operation: "getEffectStatus",
        description: "Read bounded status and receipt metadata for one governed effect.",
        allowed: &["request", "effect_id", "max_tokens"],
        required: &["effect_id"],
        always_required: &[],
        exact_request_only: false,
        lane: "effect_read",
    },
];

const RESOURCE_FAMILIES: [(&str, &str, &str); 8] = [
    (
        "cigar://project",
        "Projects",
        "Authorized project snapshots",
    ),
    (
        "cigar://workspace",
        "Workspaces",
        "Authorized workspace state",
    ),
    ("cigar://task", "Tasks", "Current task context"),
    (
        "cigar://decision",
        "Decisions",
        "Recorded decision evidence",
    ),
    ("cigar://bundle", "Bundles", "Immutable compiled bundles"),
    ("cigar://handoff", "Handoffs", "Signed handoff state"),
    ("cigar://effect", "Effects", "Governed effect state"),
    (
        "cigar://artifact",
        "Artifacts",
        "Bounded artifact and output pages",
    ),
];

/// Stateful strict MCP server over an injected authoritative backend.
pub struct Server<B> {
    backend: B,
    session: SessionState,
    handles: BTreeMap<String, StoredOutput>,
    handle_order: VecDeque<String>,
    stored_bytes: usize,
    handle_seed: u128,
    next_handle: u64,
}

impl<B: Backend> Server<B> {
    /// Creates a fresh server. No backend call is made until a protocol request needs one.
    #[must_use]
    pub fn new(backend: B) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
            ^ u128::from(std::process::id());
        Self {
            backend,
            session: SessionState::AwaitInitialize,
            handles: BTreeMap::new(),
            handle_order: VecDeque::new(),
            stored_bytes: 0,
            handle_seed: seed,
            next_handle: 0,
        }
    }

    /// Processes one complete JSON-RPC message without its trailing newline.
    ///
    /// Notifications return `None`; requests and parse failures return one compact JSON response.
    #[must_use]
    pub fn process_line(&mut self, line: &str) -> Option<String> {
        let request = match json::parse(line) {
            Ok(request) => request,
            Err(_) => {
                return Some(rpc_error(
                    Value::Null,
                    -32_700,
                    "Parse error",
                    "invalid_json",
                ));
            }
        };
        self.process_request(request)
    }

    fn process_request(&mut self, request: Value) -> Option<String> {
        let Some(fields) = request.as_object() else {
            return Some(rpc_error(
                Value::Null,
                -32_600,
                "Invalid Request",
                "request_not_object",
            ));
        };
        if !only_keys(fields, &["jsonrpc", "id", "method", "params"])
            || request.object_field("jsonrpc").and_then(Value::as_str) != Some("2.0")
        {
            return Some(rpc_error(
                Value::Null,
                -32_600,
                "Invalid Request",
                "invalid_envelope",
            ));
        }

        let id = match request.object_field("id") {
            Some(value) if is_interoperable_rpc_id(value) => Some(value.clone()),
            Some(_) => {
                return Some(rpc_error(
                    Value::Null,
                    -32_600,
                    "Invalid Request",
                    "invalid_id",
                ));
            }
            None => None,
        };
        let Some(method) = request.object_field("method").and_then(Value::as_str) else {
            return Some(rpc_error(
                id.unwrap_or(Value::Null),
                -32_600,
                "Invalid Request",
                "missing_method",
            ));
        };
        let params = request
            .object_field("params")
            .cloned()
            .unwrap_or_else(|| Value::Object(Vec::new()));
        if params.as_object().is_none() {
            return id.map(|request_id| {
                rpc_error(request_id, -32_602, "Invalid params", "params_not_object")
            });
        }

        let outcome = self.dispatch(method, &params, id.is_none());
        match (id, outcome) {
            (None, _) => None,
            (Some(request_id), Ok(Some(result))) => Some(rpc_result(request_id, result)),
            (Some(request_id), Ok(None)) => Some(rpc_error(
                request_id,
                -32_600,
                "Invalid Request",
                "request_required",
            )),
            (Some(request_id), Err(error)) => Some(rpc_error(
                request_id,
                error.code,
                error.message,
                error.reason,
            )),
        }
    }

    fn dispatch(
        &mut self,
        method: &str,
        params: &Value,
        notification: bool,
    ) -> Result<Option<Value>, RpcFailure> {
        match method {
            "initialize" => self.initialize(params, notification).map(Some),
            "notifications/initialized" => {
                self.initialized(params, notification)?;
                Ok(None)
            }
            "notifications/cancelled" => {
                require_notification(notification)?;
                validate_cancelled(params)?;
                Ok(None)
            }
            "ping" => {
                require_request(notification)?;
                if !params_object(params)?.is_empty() {
                    return Err(RpcFailure::invalid_params("ping_params"));
                }
                Ok(Some(object([])))
            }
            _ if self.session != SessionState::Ready => Err(RpcFailure::new(
                -32_002,
                "Server not initialized",
                "initialization_required",
            )),
            "tools/list" => {
                require_request(notification)?;
                self.list_tools(params).map(Some)
            }
            "tools/call" => {
                require_request(notification)?;
                self.call_tool(params).map(Some)
            }
            "resources/list" => {
                require_request(notification)?;
                self.list_resources(params).map(Some)
            }
            "resources/read" => {
                require_request(notification)?;
                self.read_resource(params).map(Some)
            }
            "roots/list" => {
                require_request(notification)?;
                self.list_roots(params).map(Some)
            }
            _ => Err(RpcFailure::new(
                -32_601,
                "Method not found",
                "unknown_method",
            )),
        }
    }

    fn initialize(&mut self, params: &Value, notification: bool) -> Result<Value, RpcFailure> {
        if notification || self.session != SessionState::AwaitInitialize {
            return Err(RpcFailure::new(
                -32_600,
                "Invalid Request",
                "initialize_sequence",
            ));
        }
        let fields = params_object(params)?;
        if !only_keys(
            fields,
            &["protocolVersion", "capabilities", "clientInfo", "_meta"],
        ) || params
            .object_field("protocolVersion")
            .and_then(Value::as_str)
            .is_none()
            || params
                .object_field("capabilities")
                .and_then(Value::as_object)
                .is_none()
            || params
                .object_field("clientInfo")
                .and_then(Value::as_object)
                .is_none()
        {
            return Err(RpcFailure::invalid_params("invalid_initialize"));
        }
        self.session = SessionState::AwaitInitializedNotification;
        Ok(object([
            ("protocolVersion", string(MCP_PROTOCOL_VERSION)),
            (
                "capabilities",
                object([
                    ("tools", object([("listChanged", Value::Bool(false))])),
                    (
                        "resources",
                        object([
                            ("subscribe", Value::Bool(false)),
                            ("listChanged", Value::Bool(false)),
                        ]),
                    ),
                ]),
            ),
            (
                "serverInfo",
                object([
                    ("name", string("cigar-mcp")),
                    ("version", string(env!("CARGO_PKG_VERSION"))),
                    (
                        "description",
                        string("Bounded CIGAR context and governed-effect MCP facade"),
                    ),
                ]),
            ),
            ("instructions", string(SERVER_INSTRUCTIONS)),
        ]))
    }

    fn initialized(&mut self, params: &Value, notification: bool) -> Result<(), RpcFailure> {
        require_notification(notification)?;
        if !params_object(params)?.is_empty()
            || self.session != SessionState::AwaitInitializedNotification
        {
            return Err(RpcFailure::new(
                -32_600,
                "Invalid Request",
                "initialized_sequence",
            ));
        }
        self.session = SessionState::Ready;
        Ok(())
    }

    fn list_tools(&self, params: &Value) -> Result<Value, RpcFailure> {
        let (offset, page_size) = pagination(params, TOOLS.len(), 't')?;
        let tools = TOOLS
            .iter()
            .skip(offset)
            .take(page_size)
            .map(tool_definition)
            .collect::<Vec<_>>();
        let next = offset
            .checked_add(tools.len())
            .filter(|next| *next < TOOLS.len());
        let mut fields = vec![("tools".to_owned(), Value::Array(tools))];
        if let Some(next) = next {
            fields.push(("nextCursor".to_owned(), string(format!("t{next}"))));
        }
        Ok(Value::Object(fields))
    }

    fn call_tool(&mut self, params: &Value) -> Result<Value, RpcFailure> {
        let fields = params_object(params)?;
        if !only_keys(fields, &["name", "arguments", "_meta"]) {
            return Err(RpcFailure::invalid_params("unknown_tool_call_field"));
        }
        let name = params
            .object_field("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcFailure::invalid_params("missing_tool_name"))?;
        let spec = TOOLS
            .iter()
            .find(|tool| tool.name == name)
            .ok_or_else(|| RpcFailure::invalid_params("unknown_tool"))?;
        let arguments = params
            .object_field("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Vec::new()));
        validate_tool_arguments(spec, &arguments)?;
        let output_tokens = output_tokens(&arguments)?;

        if spec.name == "context_expand" && arguments.object_field("handle").is_some() {
            return self.expand_handle(spec, &arguments, output_tokens);
        }

        let rendered_arguments = arguments.render();
        let response = self.backend.call(BackendRequest {
            kind: BackendRequestKind::Tool,
            operation: spec.daemon_operation,
            arguments_json: &rendered_arguments,
        });
        match response {
            Ok(response) => self.backend_tool_result(spec, response, output_tokens),
            Err(error) => Ok(tool_backend_error(spec, error)),
        }
    }

    fn backend_tool_result(
        &mut self,
        spec: &ToolSpec,
        response: BackendResponse,
        output_tokens: usize,
    ) -> Result<Value, RpcFailure> {
        validate_backend_response(&response)?;
        let max_bytes = output_tokens.saturating_mul(4);
        if response.body.len().saturating_add(1_024) > max_bytes {
            let approximate_tokens = approximate_tokens(response.body.len());
            let (handle, metadata) = self.store_output(response)?;
            let visible = object([
                ("output_handle", string(handle)),
                ("cursor", string("0")),
                ("approximate_tokens", number(approximate_tokens)),
                ("metadata", result_metadata(&metadata, false, spec.lane)),
            ]);
            return Ok(object([
                (
                    "content",
                    Value::Array(vec![object([
                        ("type", string("text")),
                        ("text", string(visible.render())),
                    ])]),
                ),
                ("structuredContent", visible),
                ("_meta", result_metadata(&metadata, false, spec.lane)),
            ]));
        }
        let data = json::parse(&response.body)
            .map_err(|_| RpcFailure::new(-32_003, "Internal error", "invalid_backend_json"))?;
        let visible = object([
            ("data", data),
            (
                "metadata",
                result_metadata(&response.metadata, false, spec.lane),
            ),
        ]);
        Ok(object([
            (
                "content",
                Value::Array(vec![object([
                    ("type", string("text")),
                    ("text", string(visible.render())),
                ])]),
            ),
            ("structuredContent", visible),
            (
                "_meta",
                result_metadata(&response.metadata, false, spec.lane),
            ),
        ]))
    }

    fn expand_handle(
        &mut self,
        spec: &ToolSpec,
        arguments: &Value,
        output_tokens: usize,
    ) -> Result<Value, RpcFailure> {
        let handle = arguments
            .object_field("handle")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcFailure::invalid_params("invalid_handle"))?;
        if !valid_handle(handle) {
            return Err(RpcFailure::invalid_params("invalid_handle"));
        }
        let cursor = parse_output_cursor(arguments.object_field("cursor"))?;
        let expired = self
            .handles
            .get(handle)
            .is_some_and(|stored| stored.created.elapsed() > HANDLE_TTL);
        if expired {
            self.remove_handle(handle);
            return Ok(tool_local_error(spec, "output handle expired", false));
        }
        let Some(stored) = self.handles.get(handle).cloned() else {
            return Ok(tool_local_error(
                spec,
                "output handle is unavailable",
                false,
            ));
        };
        let page_bytes = output_tokens.saturating_mul(4).saturating_sub(1_024);
        let (page, next) = text_page(&stored.body, cursor, page_bytes)?;
        let mut structured = vec![
            ("output_handle".to_owned(), string(handle)),
            ("cursor".to_owned(), string(cursor.to_string())),
            (
                "data".to_owned(),
                json::parse(&page).unwrap_or_else(|_| string(page.clone())),
            ),
            (
                "metadata".to_owned(),
                result_metadata(&stored.metadata, false, spec.lane),
            ),
        ];
        if let Some(next) = next {
            structured.push(("next_cursor".to_owned(), string(next.to_string())));
        }
        let visible = Value::Object(structured);
        Ok(object([
            (
                "content",
                Value::Array(vec![object([
                    ("type", string("text")),
                    ("text", string(visible.render())),
                ])]),
            ),
            ("structuredContent", visible),
            ("_meta", result_metadata(&stored.metadata, false, spec.lane)),
        ]))
    }

    fn list_resources(&self, params: &Value) -> Result<Value, RpcFailure> {
        let (offset, page_size) = pagination(params, RESOURCE_FAMILIES.len(), 'r')?;
        let resources = RESOURCE_FAMILIES
            .iter()
            .skip(offset)
            .take(page_size)
            .map(|(uri, name, description)| {
                object([
                    ("uri", string(*uri)),
                    ("name", string(*name)),
                    ("description", string(*description)),
                    ("mimeType", string("application/json")),
                ])
            })
            .collect::<Vec<_>>();
        let next = offset
            .checked_add(resources.len())
            .filter(|next| *next < RESOURCE_FAMILIES.len());
        let mut fields = vec![("resources".to_owned(), Value::Array(resources))];
        if let Some(next) = next {
            fields.push(("nextCursor".to_owned(), string(format!("r{next}"))));
        }
        Ok(Value::Object(fields))
    }

    fn read_resource(&mut self, params: &Value) -> Result<Value, RpcFailure> {
        let fields = params_object(params)?;
        if !only_keys(fields, &["uri", "cursor", "max_tokens", "_meta"]) {
            return Err(RpcFailure::invalid_params("unknown_resource_field"));
        }
        let uri = params
            .object_field("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcFailure::invalid_params("missing_resource_uri"))?;
        if !valid_resource_uri(uri) {
            return Err(RpcFailure::invalid_params("invalid_resource_uri"));
        }
        let output_tokens = output_tokens(params)?;
        if let Some(handle) = uri.strip_prefix("cigar://artifact/") {
            return self.read_artifact_handle(uri, handle, params, output_tokens);
        }

        let rendered_arguments = params.render();
        let response = self.backend.call(BackendRequest {
            kind: BackendRequestKind::Resource,
            operation: "read",
            arguments_json: &rendered_arguments,
        });
        match response {
            Ok(response) => self.backend_resource_result(uri, response, output_tokens),
            Err(error) => Ok(resource_backend_error(uri, error)),
        }
    }

    fn backend_resource_result(
        &mut self,
        uri: &str,
        response: BackendResponse,
        output_tokens: usize,
    ) -> Result<Value, RpcFailure> {
        validate_backend_response(&response)?;
        let mut metadata = response.metadata.clone();
        let max_bytes = output_tokens.saturating_mul(4);
        let text = if response.body.len().saturating_add(1_024) > max_bytes {
            let approximate_tokens = approximate_tokens(response.body.len());
            let (handle, handle_metadata) = self.store_output(response)?;
            let artifact_uri = format!("cigar://artifact/{handle}");
            metadata = handle_metadata.clone();
            object([
                ("output_handle", string(handle)),
                ("uri", string(artifact_uri)),
                ("cursor", string("0")),
                ("approximate_tokens", number(approximate_tokens)),
                ("expiry", string(handle_metadata.expiry)),
            ])
            .render()
        } else {
            response.body
        };
        Ok(resource_result(uri, text, &metadata, false))
    }

    fn read_artifact_handle(
        &mut self,
        uri: &str,
        handle: &str,
        params: &Value,
        output_tokens: usize,
    ) -> Result<Value, RpcFailure> {
        if !valid_handle(handle) {
            return Err(RpcFailure::invalid_params("invalid_artifact_handle"));
        }
        let cursor = parse_output_cursor(params.object_field("cursor"))?;
        let expired = self
            .handles
            .get(handle)
            .is_some_and(|stored| stored.created.elapsed() > HANDLE_TTL);
        if expired {
            self.remove_handle(handle);
        }
        let Some(stored) = self.handles.get(handle).cloned() else {
            return Ok(resource_local_error(uri, "output handle is unavailable"));
        };
        let page_bytes = output_tokens.saturating_mul(4).saturating_sub(1_024);
        let (page, next) = text_page(&stored.body, cursor, page_bytes)?;
        let mut content = object([
            ("data", string(page)),
            ("cursor", string(cursor.to_string())),
        ]);
        if let (Some(next), Value::Object(fields)) = (next, &mut content) {
            fields.push(("next_cursor".to_owned(), string(next.to_string())));
        }
        Ok(resource_result(
            uri,
            content.render(),
            &stored.metadata,
            false,
        ))
    }

    fn list_roots(&self, params: &Value) -> Result<Value, RpcFailure> {
        if !params_object(params)?.is_empty() {
            return Err(RpcFailure::invalid_params("roots_params"));
        }
        Ok(object([(
            "roots",
            Value::Array(vec![object([
                ("uri", string("cigar://workspace")),
                ("name", string("Authorized CIGAR workspace")),
            ])]),
        )]))
    }

    fn store_output(
        &mut self,
        mut response: BackendResponse,
    ) -> Result<(String, BackendMetadata), RpcFailure> {
        if response.body.len() > MAX_STORED_BYTES {
            return Err(RpcFailure::new(
                -32_003,
                "Internal error",
                "output_storage_limit",
            ));
        }
        while self.handles.len() >= MAX_STORED_HANDLES
            || self.stored_bytes.saturating_add(response.body.len()) > MAX_STORED_BYTES
        {
            let Some(oldest) = self.handle_order.pop_front() else {
                break;
            };
            if let Some(removed) = self.handles.remove(&oldest) {
                self.stored_bytes = self.stored_bytes.saturating_sub(removed.body.len());
            }
        }
        let handle = loop {
            self.next_handle = self.next_handle.wrapping_add(1);
            let candidate = opaque_handle(self.handle_seed, self.next_handle);
            if !self.handles.contains_key(&candidate) {
                break candidate;
            }
        };
        response.metadata.expiry = "handle-ttl-300s".to_owned();
        let metadata = response.metadata.clone();
        self.stored_bytes = self.stored_bytes.saturating_add(response.body.len());
        self.handle_order.push_back(handle.clone());
        self.handles.insert(
            handle.clone(),
            StoredOutput {
                body: response.body,
                metadata: response.metadata,
                created: Instant::now(),
            },
        );
        Ok((handle, metadata))
    }

    fn remove_handle(&mut self, handle: &str) {
        if let Some(removed) = self.handles.remove(handle) {
            self.stored_bytes = self.stored_bytes.saturating_sub(removed.body.len());
        }
        self.handle_order.retain(|stored| stored != handle);
    }
}

/// Runs a newline-delimited stdio server until clean EOF.
pub fn serve<B: Backend, R: Read, W: Write>(
    reader: R,
    mut writer: W,
    backend: B,
) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut server = Server::new(backend);
    loop {
        match read_frame(&mut reader)? {
            Frame::Eof => return Ok(()),
            Frame::Empty => {}
            Frame::Oversized => {
                writer.write_all(
                    rpc_error(Value::Null, -32_600, "Invalid Request", "request_too_large")
                        .as_bytes(),
                )?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
            Frame::Message(message) => {
                let response = match std::str::from_utf8(&message) {
                    Ok(line) => server.process_line(line),
                    Err(_) => Some(rpc_error(
                        Value::Null,
                        -32_700,
                        "Parse error",
                        "invalid_utf8",
                    )),
                };
                if let Some(response) = response {
                    writer.write_all(response.as_bytes())?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                }
            }
        }
    }
}

enum Frame {
    Eof,
    Empty,
    Oversized,
    Message(Vec<u8>),
}

fn read_frame(reader: &mut impl BufRead) -> io::Result<Frame> {
    let mut message = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if message.is_empty() {
                return Ok(Frame::Eof);
            }
            return Ok(if oversized {
                Frame::Oversized
            } else {
                Frame::Message(message)
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position.saturating_add(1));
        let payload_len = newline.unwrap_or(consumed);
        if !oversized {
            let remaining = MAX_REQUEST_BYTES.saturating_sub(message.len());
            if payload_len > remaining {
                oversized = true;
                message.clear();
            } else if let Some(payload) = available.get(..payload_len) {
                message.extend_from_slice(payload);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            if oversized {
                return Ok(Frame::Oversized);
            }
            if message.last() == Some(&b'\r') {
                message.pop();
            }
            return Ok(if message.is_empty() {
                Frame::Empty
            } else {
                Frame::Message(message)
            });
        }
    }
}

#[derive(Clone, Copy)]
struct RpcFailure {
    code: i64,
    message: &'static str,
    reason: &'static str,
}

impl RpcFailure {
    const fn new(code: i64, message: &'static str, reason: &'static str) -> Self {
        Self {
            code,
            message,
            reason,
        }
    }

    const fn invalid_params(reason: &'static str) -> Self {
        Self::new(-32_602, "Invalid params", reason)
    }
}

fn rpc_result(id: Value, result: Value) -> String {
    object([("jsonrpc", string("2.0")), ("id", id), ("result", result)]).render()
}

fn rpc_error(id: Value, code: i64, message: &str, reason: &str) -> String {
    object([
        ("jsonrpc", string("2.0")),
        ("id", id),
        (
            "error",
            object([
                ("code", Value::Number(code.to_string())),
                ("message", string(message)),
                ("data", object([("reason", string(reason))])),
            ]),
        ),
    ])
    .render()
}

fn require_notification(notification: bool) -> Result<(), RpcFailure> {
    if notification {
        Ok(())
    } else {
        Err(RpcFailure::new(
            -32_600,
            "Invalid Request",
            "notification_required",
        ))
    }
}

fn require_request(notification: bool) -> Result<(), RpcFailure> {
    if notification {
        Err(RpcFailure::new(
            -32_600,
            "Invalid Request",
            "request_id_required",
        ))
    } else {
        Ok(())
    }
}

fn validate_cancelled(params: &Value) -> Result<(), RpcFailure> {
    let fields = params_object(params)?;
    if !only_keys(fields, &["requestId", "reason", "_meta"])
        || !params
            .object_field("requestId")
            .is_some_and(is_interoperable_rpc_id)
        || params
            .object_field("reason")
            .is_some_and(|reason| reason.as_str().is_none_or(|text| text.len() > 1_024))
    {
        return Err(RpcFailure::invalid_params("invalid_cancellation"));
    }
    Ok(())
}

fn params_object(params: &Value) -> Result<&[(String, Value)], RpcFailure> {
    params
        .as_object()
        .ok_or_else(|| RpcFailure::invalid_params("params_not_object"))
}

fn only_keys(fields: &[(String, Value)], allowed: &[&str]) -> bool {
    fields
        .iter()
        .all(|(key, _)| allowed.iter().any(|allowed_key| key == allowed_key))
}

fn is_interoperable_rpc_id(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Number(number) => number.parse::<i64>().is_ok_and(|number| {
            (-MAX_INTEROPERABLE_RPC_INTEGER_ID..=MAX_INTEROPERABLE_RPC_INTEGER_ID).contains(&number)
        }),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => false,
    }
}

fn has_only_interoperable_numbers(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.parse::<f64>().is_ok_and(f64::is_finite),
        Value::Array(values) => values.iter().all(has_only_interoperable_numbers),
        Value::Object(fields) => fields
            .iter()
            .all(|(_name, value)| has_only_interoperable_numbers(value)),
        Value::Null | Value::Bool(_) | Value::String(_) => true,
    }
}

fn pagination(
    params: &Value,
    total: usize,
    cursor_prefix: char,
) -> Result<(usize, usize), RpcFailure> {
    let fields = params_object(params)?;
    if !only_keys(fields, &["cursor", "page_size", "_meta"]) {
        return Err(RpcFailure::invalid_params("unknown_pagination_field"));
    }
    let offset = match params.object_field("cursor") {
        Some(Value::String(cursor)) => cursor_offset(cursor, total, cursor_prefix)?,
        Some(_) => return Err(RpcFailure::invalid_params("invalid_cursor")),
        None => 0,
    };
    let page_size = match params.object_field("page_size") {
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (1..=total.max(1)).contains(value))
            .ok_or_else(|| RpcFailure::invalid_params("invalid_page_size"))?,
        None => total.max(1),
    };
    Ok((offset, page_size))
}

fn cursor_offset(cursor: &str, total: usize, expected_prefix: char) -> Result<usize, RpcFailure> {
    let offset = cursor
        .get(1..)
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value <= total)
        .ok_or_else(|| RpcFailure::invalid_params("invalid_cursor"))?;
    if !cursor.starts_with(expected_prefix)
        || (offset != 0 && cursor.get(1..).is_some_and(|value| value.starts_with('0')))
    {
        return Err(RpcFailure::invalid_params("invalid_cursor"));
    }
    Ok(offset)
}

fn tool_definition(spec: &ToolSpec) -> Value {
    let mut properties = Vec::new();
    for property in spec.allowed {
        properties.push(((*property).to_owned(), schema_property(property)));
    }
    let mut required = spec
        .always_required
        .iter()
        .map(|name| string(*name))
        .collect::<Vec<_>>();
    if spec.exact_request_only {
        required.push(string("request"));
    }
    let schema = vec![
        ("type".to_owned(), string("object")),
        ("properties".to_owned(), Value::Object(properties)),
        ("required".to_owned(), Value::Array(required)),
        ("additionalProperties".to_owned(), Value::Bool(false)),
    ];
    object([
        ("name", string(spec.name)),
        ("description", string(spec.description)),
        ("inputSchema", Value::Object(schema)),
    ])
}

fn schema_property(name: &str) -> Value {
    match name {
        "request" | "contract" | "intent" => object([
            ("type", string("object")),
            ("description", string("Typed CIGAR protocol object")),
        ]),
        "source_ids" => object([
            ("type", string("array")),
            ("maxItems", number(256)),
            (
                "items",
                object([("type", string("string")), ("maxLength", number(256))]),
            ),
        ]),
        "max_tokens" => object([
            ("type", string("integer")),
            ("minimum", number(MIN_OUTPUT_TOKENS)),
            ("maximum", number(MAX_OUTPUT_TOKENS)),
            ("default", number(DEFAULT_OUTPUT_TOKENS)),
        ]),
        "query" | "task" | "label" => object([
            ("type", string("string")),
            ("minLength", number(1)),
            ("maxLength", number(8_192)),
        ]),
        "cursor" => object([("type", string("string")), ("maxLength", number(64))]),
        _ => object([
            ("type", string("string")),
            ("minLength", number(1)),
            ("maxLength", number(256)),
        ]),
    }
}

fn validate_tool_arguments(spec: &ToolSpec, arguments: &Value) -> Result<(), RpcFailure> {
    let fields = params_object(arguments)?;
    if !only_keys(fields, spec.allowed) {
        return Err(RpcFailure::invalid_params("unknown_tool_argument"));
    }
    for required in spec.always_required {
        if arguments.object_field(required).is_none() {
            return Err(RpcFailure::invalid_params("missing_tool_argument"));
        }
    }
    let exact_request = arguments.object_field("request");
    if exact_request.is_none() {
        if spec.exact_request_only {
            return Err(RpcFailure::invalid_params("missing_tool_argument"));
        }
        for required in spec.required {
            if arguments.object_field(required).is_none() {
                return Err(RpcFailure::invalid_params("missing_tool_argument"));
            }
        }
    } else if exact_request.and_then(Value::as_object).is_none() {
        return Err(RpcFailure::invalid_params("invalid_protocol_object"));
    }
    if spec.name == "context_expand"
        && arguments.object_field("handle").is_none()
        && arguments.object_field("bundle_id").is_none()
        && arguments.object_field("request").is_none()
    {
        return Err(RpcFailure::invalid_params("missing_expand_target"));
    }
    for (name, value) in fields {
        match name.as_str() {
            "max_tokens" => {
                let _validated = output_tokens(arguments)?;
            }
            "request" | "contract" | "intent" => {
                if value.as_object().is_none() {
                    return Err(RpcFailure::invalid_params("invalid_protocol_object"));
                }
            }
            "source_ids" => {
                let Value::Array(items) = value else {
                    return Err(RpcFailure::invalid_params("invalid_source_ids"));
                };
                if items.len() > 256
                    || items.iter().any(|item| {
                        item.as_str()
                            .is_none_or(|text| text.is_empty() || text.len() > 256)
                    })
                {
                    return Err(RpcFailure::invalid_params("invalid_source_ids"));
                }
            }
            "query" | "task" | "label" => {
                if value
                    .as_str()
                    .is_none_or(|text| text.is_empty() || text.len() > 8_192)
                {
                    return Err(RpcFailure::invalid_params("invalid_text_argument"));
                }
            }
            "cursor" => {
                if value.as_str().is_none_or(|text| text.len() > 64) {
                    return Err(RpcFailure::invalid_params("invalid_cursor"));
                }
            }
            _ => {
                if value
                    .as_str()
                    .is_none_or(|text| text.is_empty() || text.len() > 256)
                {
                    return Err(RpcFailure::invalid_params("invalid_identifier"));
                }
            }
        }
    }
    Ok(())
}

fn output_tokens(arguments: &Value) -> Result<usize, RpcFailure> {
    match arguments.object_field("max_tokens") {
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (MIN_OUTPUT_TOKENS..=MAX_OUTPUT_TOKENS).contains(value))
            .ok_or_else(|| RpcFailure::invalid_params("invalid_max_tokens")),
        None => Ok(DEFAULT_OUTPUT_TOKENS),
    }
}

fn validate_backend_response(response: &BackendResponse) -> Result<(), RpcFailure> {
    let body = json::parse_with_limits(
        &response.body,
        BACKEND_MAX_DEPTH,
        BACKEND_MAX_NODES,
        BACKEND_MAX_STRING_BYTES,
    )
    .map_err(|_| RpcFailure::new(-32_003, "Internal error", "invalid_backend_json"))?;
    if !has_only_interoperable_numbers(&body) {
        return Err(RpcFailure::new(
            -32_003,
            "Internal error",
            "invalid_backend_json",
        ));
    }
    if !safe_metadata_text(&response.metadata.snapshot)
        || !safe_metadata_text(&response.metadata.bundle_or_source)
        || !safe_metadata_text(&response.metadata.expiry)
    {
        return Err(RpcFailure::new(
            -32_003,
            "Internal error",
            "invalid_backend_metadata",
        ));
    }
    Ok(())
}

fn safe_metadata_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn result_metadata(metadata: &BackendMetadata, degraded: bool, lane: &str) -> Value {
    object([
        ("snapshot", string(metadata.snapshot.clone())),
        (
            "bundle_or_source",
            string(metadata.bundle_or_source.clone()),
        ),
        ("expiry", string(metadata.expiry.clone())),
        ("degraded", Value::Bool(degraded)),
        ("authority_lane", string(lane)),
    ])
}

fn unavailable_metadata(lane: &str) -> Value {
    result_metadata(
        &BackendMetadata::new("unavailable", "daemon-unavailable", "immediate"),
        true,
        lane,
    )
}

fn tool_backend_error(spec: &ToolSpec, error: BackendError) -> Value {
    let unavailable = error == BackendError::Unavailable;
    let effect_closed = unavailable && matches!(spec.name, "effect_prepare" | "effect_commit");
    let message = if effect_closed {
        "Effect operation refused: authoritative backend unavailable."
    } else {
        match error {
            BackendError::Unavailable => {
                "Authoritative backend unavailable; no result was synthesized."
            }
            BackendError::Rejected => "Authoritative backend rejected the request.",
            BackendError::ResponseTooLarge => "Authoritative response exceeded the hard limit.",
            BackendError::InvalidResponse => "Authoritative backend response was invalid.",
        }
    };
    let metadata = if unavailable {
        unavailable_metadata(spec.lane)
    } else {
        result_metadata(
            &BackendMetadata::new("rejected", "daemon", "immediate"),
            false,
            spec.lane,
        )
    };
    let visible = object([("error", string(message)), ("metadata", metadata.clone())]);
    object([
        (
            "content",
            Value::Array(vec![object([
                ("type", string("text")),
                ("text", string(visible.render())),
            ])]),
        ),
        ("structuredContent", visible),
        ("isError", Value::Bool(true)),
        ("_meta", metadata),
    ])
}

fn tool_local_error(spec: &ToolSpec, message: &str, degraded: bool) -> Value {
    let metadata = result_metadata(
        &BackendMetadata::new("unavailable", "local-output-store", "immediate"),
        degraded,
        spec.lane,
    );
    let visible = object([("error", string(message)), ("metadata", metadata.clone())]);
    object([
        (
            "content",
            Value::Array(vec![object([
                ("type", string("text")),
                ("text", string(visible.render())),
            ])]),
        ),
        ("structuredContent", visible),
        ("isError", Value::Bool(true)),
        ("_meta", metadata),
    ])
}

fn resource_result(uri: &str, text: String, metadata: &BackendMetadata, degraded: bool) -> Value {
    let metadata = result_metadata(metadata, degraded, "resource_read");
    let visible = object([
        (
            "data",
            json::parse(&text).unwrap_or_else(|_| string(text.clone())),
        ),
        ("metadata", metadata.clone()),
    ]);
    object([
        (
            "contents",
            Value::Array(vec![object([
                ("uri", string(uri)),
                ("mimeType", string("application/json")),
                ("text", string(visible.render())),
            ])]),
        ),
        ("_meta", metadata),
    ])
}

fn resource_backend_error(uri: &str, error: BackendError) -> Value {
    let unavailable = error == BackendError::Unavailable;
    let message = match error {
        BackendError::Unavailable => {
            "Authoritative backend unavailable; no resource was synthesized."
        }
        BackendError::Rejected => "Authoritative backend rejected the resource request.",
        BackendError::ResponseTooLarge => "Authoritative resource exceeded the hard limit.",
        BackendError::InvalidResponse => "Authoritative resource response was invalid.",
    };
    resource_result(
        uri,
        object([("error", string(message))]).render(),
        &BackendMetadata::new(
            if unavailable {
                "unavailable"
            } else {
                "rejected"
            },
            if unavailable {
                "daemon-unavailable"
            } else {
                "daemon"
            },
            "immediate",
        ),
        unavailable,
    )
}

fn resource_local_error(uri: &str, message: &str) -> Value {
    resource_result(
        uri,
        object([("error", string(message))]).render(),
        &BackendMetadata::new("unavailable", "local-output-store", "immediate"),
        false,
    )
}

fn valid_resource_uri(uri: &str) -> bool {
    if uri.len() > 512
        || uri.contains("..")
        || uri.contains(['\\', '@', '#', '%'])
        || !uri.chars().all(|value| {
            value.is_ascii_alphanumeric()
                || matches!(value, ':' | '/' | '?' | '&' | '=' | '_' | '-' | '.')
        })
    {
        return false;
    }
    RESOURCE_FAMILIES.iter().any(|(family, _, _)| {
        uri == *family
            || uri
                .strip_prefix(family)
                .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with('?'))
    })
}

fn parse_output_cursor(cursor: Option<&Value>) -> Result<usize, RpcFailure> {
    match cursor {
        Some(Value::String(value)) => value
            .parse::<usize>()
            .ok()
            .filter(|parsed| parsed.to_string() == *value)
            .ok_or_else(|| RpcFailure::invalid_params("invalid_output_cursor")),
        Some(_) => Err(RpcFailure::invalid_params("invalid_output_cursor")),
        None => Ok(0),
    }
}

fn text_page(
    text: &str,
    start: usize,
    max_bytes: usize,
) -> Result<(String, Option<usize>), RpcFailure> {
    if start > text.len() || !text.is_char_boundary(start) {
        return Err(RpcFailure::invalid_params("invalid_output_cursor"));
    }
    let remaining = text
        .get(start..)
        .ok_or_else(|| RpcFailure::invalid_params("invalid_output_cursor"))?;
    let mut used = 0_usize;
    for character in remaining.chars() {
        let width = character.len_utf8();
        if used.saturating_add(width) > max_bytes {
            break;
        }
        used = used.saturating_add(width);
    }
    let end = start.saturating_add(used);
    let page = text
        .get(start..end)
        .ok_or_else(|| RpcFailure::invalid_params("invalid_output_cursor"))?
        .to_owned();
    Ok((page, (end < text.len()).then_some(end)))
}

fn approximate_tokens(bytes: usize) -> usize {
    bytes.saturating_add(3) / 4
}

fn opaque_handle(seed: u128, counter: u64) -> String {
    let mut first = DefaultHasher::new();
    seed.hash(&mut first);
    counter.hash(&mut first);
    let first = first.finish();
    let mut second = DefaultHasher::new();
    seed.rotate_left(41).hash(&mut second);
    counter.rotate_left(17).hash(&mut second);
    let second = second.finish();
    format!("{first:016x}{second:016x}")
}

fn valid_handle(handle: &str) -> bool {
    handle.len() == 32 && handle.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{
        Backend, BackendError, BackendMetadata, BackendRequest, BackendRequestKind,
        BackendResponse, MAX_REQUEST_BYTES, MCP_PROTOCOL_VERSION, RESOURCE_FAMILIES,
        SERVER_INSTRUCTIONS, Server, TOOLS, Value, json, serve, validate_cancelled,
    };

    #[derive(Default)]
    struct MockBackend {
        responses: VecDeque<Result<BackendResponse, BackendError>>,
        calls: Vec<(BackendRequestKind, String, String)>,
    }

    impl MockBackend {
        fn success(body: impl Into<String>) -> Self {
            Self {
                responses: VecDeque::from([Ok(BackendResponse::new(
                    body,
                    BackendMetadata::new("snapshot-1", "bundle-1", "2099-01-01T00:00:00Z"),
                ))]),
                calls: Vec::new(),
            }
        }

        fn unavailable() -> Self {
            Self {
                responses: VecDeque::from([Err(BackendError::Unavailable)]),
                calls: Vec::new(),
            }
        }
    }

    impl Backend for MockBackend {
        fn call(&mut self, request: BackendRequest<'_>) -> Result<BackendResponse, BackendError> {
            self.calls.push((
                request.kind,
                request.operation.to_owned(),
                request.arguments_json.to_owned(),
            ));
            self.responses
                .pop_front()
                .unwrap_or(Err(BackendError::Unavailable))
        }
    }

    fn initialize(server: &mut Server<MockBackend>) -> Result<(), String> {
        let response = server
            .process_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            )
            .ok_or_else(|| "missing initialize response".to_owned())?;
        let parsed = json::parse(&response).map_err(|_| "initialize response parse".to_owned())?;
        assert_eq!(
            parsed
                .object_field("result")
                .and_then(|result| result.object_field("protocolVersion"))
                .and_then(Value::as_str),
            Some(MCP_PROTOCOL_VERSION)
        );
        assert!(
            server
                .process_line(
                    r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#
                )
                .is_none()
        );
        Ok(())
    }

    fn call(server: &mut Server<MockBackend>, id: u64, method: &str, params: &str) -> Value {
        let request = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}"
        );
        let response = server.process_line(&request).unwrap_or_default();
        json::parse(&response).unwrap_or(Value::Null)
    }

    #[test]
    fn handshake_ping_and_notification_sequence_are_strict() -> Result<(), String> {
        let mut server = Server::new(MockBackend::default());
        let early = call(&mut server, 1, "tools/list", "{}");
        assert_eq!(
            early
                .object_field("error")
                .and_then(|error| error.object_field("code")),
            Some(&Value::Number("-32002".to_owned()))
        );
        initialize(&mut server)?;
        let ping = call(&mut server, 2, "ping", "{}");
        assert!(
            ping.object_field("result")
                .and_then(Value::as_object)
                .is_some()
        );
        assert!(
            server
                .process_line(r#"{"jsonrpc":"2.0","method":"unknown","params":{}}"#)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn lists_exact_tool_and_resource_inventory_with_pagination() -> Result<(), String> {
        let mut server = Server::new(MockBackend::default());
        initialize(&mut server)?;
        let tools = call(&mut server, 2, "tools/list", "{}");
        let Value::Array(listed_tools) = tools
            .object_field("result")
            .and_then(|result| result.object_field("tools"))
            .cloned()
            .ok_or_else(|| "missing tools".to_owned())?
        else {
            return Err("tools not array".to_owned());
        };
        let names = listed_tools
            .iter()
            .filter_map(|tool| tool.object_field("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            TOOLS.iter().map(|tool| tool.name).collect::<Vec<_>>()
        );

        let page = call(&mut server, 3, "resources/list", r#"{"page_size":3}"#);
        assert_eq!(
            page.object_field("result")
                .and_then(|result| result.object_field("nextCursor"))
                .and_then(Value::as_str),
            Some("r3")
        );
        let resources = call(&mut server, 4, "resources/list", "{}");
        let Value::Array(listed_resources) = resources
            .object_field("result")
            .and_then(|result| result.object_field("resources"))
            .cloned()
            .ok_or_else(|| "missing resources".to_owned())?
        else {
            return Err("resources not array".to_owned());
        };
        let uris = listed_resources
            .iter()
            .filter_map(|resource| resource.object_field("uri").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(
            uris,
            RESOURCE_FAMILIES
                .iter()
                .map(|(uri, _, _)| *uri)
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn tool_call_uses_frozen_mapping_and_binds_all_metadata() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(r#"{"bundle_id":"b1"}"#));
        initialize(&mut server)?;
        let response = call(
            &mut server,
            2,
            "tools/call",
            r#"{"name":"context_compile","arguments":{"contract":{},"max_tokens":500}}"#,
        );
        let result = response
            .object_field("result")
            .ok_or_else(|| "missing result".to_owned())?;
        let metadata = result
            .object_field("_meta")
            .ok_or_else(|| "missing metadata".to_owned())?;
        for key in [
            "snapshot",
            "bundle_or_source",
            "expiry",
            "degraded",
            "authority_lane",
        ] {
            assert!(metadata.object_field(key).is_some(), "missing {key}");
        }
        let visible = result
            .object_field("content")
            .and_then(|content| match content {
                Value::Array(items) => items.first(),
                _ => None,
            })
            .and_then(|content| content.object_field("text"))
            .and_then(Value::as_str)
            .and_then(|text| json::parse(text).ok())
            .ok_or_else(|| "missing visible result envelope".to_owned())?;
        assert_eq!(
            visible
                .object_field("metadata")
                .and_then(|metadata| metadata.object_field("authority_lane"))
                .and_then(Value::as_str),
            Some("context_read")
        );
        assert_eq!(server.backend.calls.len(), 1);
        assert_eq!(
            server.backend.calls.first().map(|call| call.1.as_str()),
            Some("createContextPlan")
        );
        assert!(
            !server
                .backend
                .calls
                .first()
                .map_or("", |call| &call.2)
                .contains("CIGAR_MCP_DAEMON_URL")
        );
        Ok(())
    }

    #[test]
    fn exact_protocol_tools_require_explicit_idempotency_for_mutations() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(r#"{"checkpoint_id":"c1"}"#));
        initialize(&mut server)?;

        let shorthand = call(
            &mut server,
            2,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"query":"ambiguous"}}"#,
        );
        assert!(shorthand.object_field("error").is_some());

        let missing_key = call(
            &mut server,
            3,
            "tools/call",
            r#"{"name":"checkpoint_create","arguments":{"request":{"space_id":"s1","focus_id":"f1"}}}"#,
        );
        assert!(missing_key.object_field("error").is_some());

        let accepted = call(
            &mut server,
            4,
            "tools/call",
            r#"{"name":"checkpoint_create","arguments":{"request":{"space_id":"s1","focus_id":"f1"},"idempotency_key":"checkpoint-1"}}"#,
        );
        assert!(accepted.object_field("result").is_some());
        assert_eq!(server.backend.calls.len(), 1);
        assert_eq!(
            server.backend.calls.first().map(|call| call.1.as_str()),
            Some("createSpaceCheckpoint")
        );
        assert!(
            server
                .backend
                .calls
                .first()
                .is_some_and(|call| call.2.contains("\"focus_id\":\"f1\""))
        );
        Ok(())
    }

    #[test]
    fn large_output_is_opaque_and_pages_stay_in_budget() -> Result<(), String> {
        let large = format!("{{\"data\":\"{}\"}}", "x".repeat(9_000));
        let mut server = Server::new(MockBackend::success(large));
        initialize(&mut server)?;
        let response = call(
            &mut server,
            2,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"max_tokens":500}}"#,
        );
        let handle = response
            .object_field("result")
            .and_then(|result| result.object_field("structuredContent"))
            .and_then(|structured| structured.object_field("output_handle"))
            .and_then(Value::as_str)
            .ok_or_else(|| "missing handle".to_owned())?
            .to_owned();
        assert_eq!(handle.len(), 32);
        assert!(handle.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!response.render().contains(&"x".repeat(100)));

        let page = call(
            &mut server,
            3,
            "tools/call",
            &format!(
                "{{\"name\":\"context_expand\",\"arguments\":{{\"handle\":\"{handle}\",\"cursor\":\"0\",\"max_tokens\":500}}}}"
            ),
        );
        let text = page
            .object_field("result")
            .and_then(|result| result.object_field("content"))
            .and_then(|content| match content {
                Value::Array(items) => items.first(),
                _ => None,
            })
            .and_then(|content| content.object_field("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| "missing page".to_owned())?;
        assert!(text.len() <= 2_000);
        assert!(
            page.object_field("result")
                .and_then(|result| result.object_field("structuredContent"))
                .and_then(|structured| structured.object_field("next_cursor"))
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn unavailable_backend_degrades_visibly_and_effects_fail_closed() -> Result<(), String> {
        let mut read_server = Server::new(MockBackend::unavailable());
        initialize(&mut read_server)?;
        let read = call(
            &mut read_server,
            2,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1}}}"#,
        );
        assert_eq!(
            read.object_field("result")
                .and_then(|result| result.object_field("_meta"))
                .and_then(|metadata| metadata.object_field("degraded")),
            Some(&Value::Bool(true))
        );

        let mut effect_server = Server::new(MockBackend::unavailable());
        initialize(&mut effect_server)?;
        let effect = call(
            &mut effect_server,
            3,
            "tools/call",
            r#"{"name":"effect_commit","arguments":{"preparation_id":"p1","idempotency_key":"i1"}}"#,
        );
        let result = effect
            .object_field("result")
            .ok_or_else(|| "missing result".to_owned())?;
        assert_eq!(result.object_field("isError"), Some(&Value::Bool(true)));
        assert!(result.render().contains("refused"));
        assert_eq!(effect_server.backend.calls.len(), 1);
        Ok(())
    }

    #[test]
    fn request_methods_sent_as_notifications_never_reach_backend() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(r#"{"unexpected":true}"#));
        initialize(&mut server)?;
        assert!(
            server
                .process_line(
                    r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"effect_commit","arguments":{"preparation_id":"p1","idempotency_key":"i1"}}}"#
                )
                .is_none()
        );
        assert!(server.backend.calls.is_empty());
        let invalid_ping = call(&mut server, 4, "ping", r#"{"unexpected":true}"#);
        assert!(invalid_ping.object_field("error").is_some());
        Ok(())
    }

    #[test]
    fn resource_reads_use_the_frozen_route_and_include_metadata() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(r#"{"task":"bounded"}"#));
        initialize(&mut server)?;
        let response = call(
            &mut server,
            2,
            "resources/read",
            r#"{"uri":"cigar://task/current","max_tokens":500}"#,
        );
        let result = response
            .object_field("result")
            .ok_or_else(|| "missing resource result".to_owned())?;
        assert_eq!(
            result
                .object_field("_meta")
                .and_then(|metadata| metadata.object_field("authority_lane"))
                .and_then(Value::as_str),
            Some("resource_read")
        );
        assert_eq!(
            server.backend.calls.first().map(|call| call.0),
            Some(BackendRequestKind::Resource)
        );
        assert_eq!(
            server.backend.calls.first().map(|call| call.1.as_str()),
            Some("read")
        );
        Ok(())
    }

    #[test]
    fn large_resource_returns_readable_artifact_uri_and_handle_expiry() -> Result<(), String> {
        let large = format!("{{\"artifact\":\"{}\"}}", "z".repeat(9_000));
        let mut server = Server::new(MockBackend::success(large));
        initialize(&mut server)?;
        let response = call(
            &mut server,
            2,
            "resources/read",
            r#"{"uri":"cigar://bundle/current","max_tokens":500}"#,
        );
        let text = response
            .object_field("result")
            .and_then(|result| result.object_field("contents"))
            .and_then(|contents| match contents {
                Value::Array(items) => items.first(),
                _ => None,
            })
            .and_then(|content| content.object_field("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| "missing handle envelope".to_owned())?;
        let handle_envelope = json::parse(text).map_err(|_| "handle envelope parse".to_owned())?;
        let artifact_uri = handle_envelope
            .object_field("data")
            .and_then(|data| data.object_field("uri"))
            .and_then(Value::as_str)
            .ok_or_else(|| "missing artifact URI".to_owned())?;
        assert!(artifact_uri.starts_with("cigar://artifact/"));
        assert_eq!(
            response
                .object_field("result")
                .and_then(|result| result.object_field("_meta"))
                .and_then(|metadata| metadata.object_field("expiry"))
                .and_then(Value::as_str),
            Some("handle-ttl-300s")
        );

        let page = call(
            &mut server,
            3,
            "resources/read",
            &format!("{{\"uri\":\"{artifact_uri}\",\"max_tokens\":500}}"),
        );
        let page_text = page
            .object_field("result")
            .and_then(|result| result.object_field("contents"))
            .and_then(|contents| match contents {
                Value::Array(items) => items.first(),
                _ => None,
            })
            .and_then(|content| content.object_field("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| "missing artifact page".to_owned())?;
        assert!(page_text.len() <= 2_200);
        assert_eq!(server.backend.calls.len(), 1);
        Ok(())
    }

    #[test]
    fn malformed_backend_json_is_content_free_internal_error() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(r#"{"secret":"x","secret":"y"}"#));
        initialize(&mut server)?;
        let response = call(
            &mut server,
            2,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1}}}"#,
        );
        assert_eq!(
            response
                .object_field("error")
                .and_then(|error| error.object_field("code")),
            Some(&Value::Number("-32003".to_owned()))
        );
        assert!(!response.render().contains("secret"));
        Ok(())
    }

    #[test]
    fn backend_numbers_must_remain_interoperable_in_mcp_output() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(
            r#"{"safe":[1,{"protected-overflow":1e999}]}"#,
        ));
        initialize(&mut server)?;
        let response = call(
            &mut server,
            2,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1}}}"#,
        );
        assert_eq!(
            response
                .object_field("error")
                .and_then(|error| error.object_field("code")),
            Some(&Value::Number("-32003".to_owned()))
        );
        assert_eq!(
            response
                .object_field("error")
                .and_then(|error| error.object_field("data"))
                .and_then(|data| data.object_field("reason"))
                .and_then(Value::as_str),
            Some("invalid_backend_json")
        );
        assert!(!response.render().contains("protected-overflow"));

        let mut finite_server = Server::new(MockBackend::success(
            r#"{"safe":[1e308,1e-999,99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999]}"#,
        ));
        initialize(&mut finite_server)?;
        let finite = call(
            &mut finite_server,
            3,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1}}}"#,
        );
        assert!(finite.object_field("result").is_some());
        Ok(())
    }

    #[test]
    fn numeric_rpc_ids_are_integer_only_and_javascript_safe() -> Result<(), String> {
        let mut server = Server::new(MockBackend::default());
        for invalid_id in [
            "null",
            "1e999",
            "1e0",
            "1.0",
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551615",
        ] {
            let request = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{invalid_id},\"method\":\"ping\",\"params\":{{}}}}"
            );
            let response = server
                .process_line(&request)
                .ok_or_else(|| "invalid request id produced no response".to_owned())?;
            let parsed = json::parse(&response)
                .map_err(|_| "invalid request id response was not interoperable JSON".to_owned())?;
            assert_eq!(parsed.object_field("id"), Some(&Value::Null));
            assert_eq!(
                parsed
                    .object_field("error")
                    .and_then(|error| error.object_field("code")),
                Some(&Value::Number("-32600".to_owned()))
            );
            assert_eq!(
                parsed
                    .object_field("error")
                    .and_then(|error| error.object_field("data"))
                    .and_then(|data| data.object_field("reason"))
                    .and_then(Value::as_str),
                Some("invalid_id")
            );
        }

        for valid_id in ["-9007199254740991", "0", "9007199254740991"] {
            let request = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{valid_id},\"method\":\"ping\",\"params\":{{}}}}"
            );
            let response = server
                .process_line(&request)
                .ok_or_else(|| "valid request id produced no response".to_owned())?;
            let parsed = json::parse(&response)
                .map_err(|_| "valid request id response was not valid JSON".to_owned())?;
            assert_eq!(
                parsed.object_field("id"),
                Some(&Value::Number(valid_id.to_owned()))
            );
        }
        assert!(server.backend.calls.is_empty());
        Ok(())
    }

    #[test]
    fn cancellation_references_use_the_same_interoperable_id_boundary() -> Result<(), String> {
        for invalid_params in [
            r#"{"requestId":1e999}"#,
            r#"{"requestId":9007199254740992}"#,
            r#"{"requestId":null}"#,
        ] {
            let params = json::parse(invalid_params)
                .map_err(|_| "cancellation fixture did not parse".to_owned())?;
            let Err(error) = validate_cancelled(&params) else {
                return Err("invalid cancellation request id unexpectedly passed".to_owned());
            };
            assert_eq!(error.reason, "invalid_cancellation");
        }
        for valid_params in [
            r#"{"requestId":-9007199254740991}"#,
            r#"{"requestId":9007199254740991}"#,
            r#"{"requestId":"request-1"}"#,
        ] {
            let params = json::parse(valid_params)
                .map_err(|_| "cancellation fixture did not parse".to_owned())?;
            validate_cancelled(&params).map_err(|error| error.reason.to_owned())?;
        }
        Ok(())
    }

    #[test]
    fn malformed_duplicate_unknown_and_invalid_budget_requests_are_rejected() -> Result<(), String>
    {
        let mut server = Server::new(MockBackend::default());
        assert!(
            server
                .process_line(r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#)
                .unwrap_or_default()
                .contains("-32700")
        );
        initialize(&mut server)?;
        let unknown = call(
            &mut server,
            2,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"secret":"no"}}"#,
        );
        assert!(unknown.object_field("error").is_some());
        let budget = call(
            &mut server,
            3,
            "tools/call",
            r#"{"name":"catalog_query","arguments":{"request":{"requirements":[],"max_results":1},"max_tokens":499}}"#,
        );
        assert!(budget.object_field("error").is_some());
        let wrong_cursor = call(&mut server, 4, "tools/list", r#"{"cursor":"r1"}"#);
        assert!(wrong_cursor.object_field("error").is_some());
        assert!(server.backend.calls.is_empty());
        Ok(())
    }

    #[test]
    fn oversized_stdio_frame_is_rejected_without_allocating_it() -> Result<(), String> {
        let mut input = vec![b' '; MAX_REQUEST_BYTES.saturating_add(1)];
        input.push(b'\n');
        let mut output = Vec::new();
        serve(input.as_slice(), &mut output, MockBackend::default()).map_err(|_| "serve")?;
        let rendered = String::from_utf8(output).map_err(|_| "utf8")?;
        assert!(rendered.contains("request_too_large"));
        assert!(!rendered.contains(std::env::temp_dir().to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn instructions_and_descriptions_fit_two_kibibytes() {
        let bytes = SERVER_INSTRUCTIONS.len()
            + TOOLS
                .iter()
                .map(|tool| tool.description.len())
                .sum::<usize>();
        assert!(bytes < 2_048, "description budget was {bytes}");
    }

    #[test]
    fn resource_uri_validation_blocks_private_path_shapes() -> Result<(), String> {
        let mut server = Server::new(MockBackend::success(r#"{"ok":true}"#));
        initialize(&mut server)?;
        let invalid = call(
            &mut server,
            2,
            "resources/read",
            r#"{"uri":"cigar://artifact/../../private"}"#,
        );
        assert!(invalid.object_field("error").is_some());
        assert!(server.backend.calls.is_empty());
        Ok(())
    }
}
