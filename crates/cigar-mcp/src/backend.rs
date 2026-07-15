//! Bounded injectable daemon boundary.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::json::{self, Value};
use crate::operation_mappings::MCP_OPERATION_MAPPINGS;

const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:8080/v1/mcp";
const MAX_BACKEND_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const BACKEND_MAX_DEPTH: usize = 64;
const BACKEND_MAX_NODES: usize = 65_536;
const CLI_DEADLINE: Duration = Duration::from_secs(3);
static CLI_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Kind of frozen daemon route used by one backend request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendRequestKind {
    /// Invoke one named MCP facade tool.
    Tool,
    /// Read one stable CIGAR resource URI.
    Resource,
    /// Probe daemon health without returning configuration.
    Health,
}

/// One bounded request sent through the injectable daemon boundary.
#[derive(Clone, Copy, Debug)]
pub struct BackendRequest<'a> {
    /// Frozen route class.
    pub kind: BackendRequestKind,
    /// Stable daemon operation name; never a caller-controlled URL fragment.
    pub operation: &'a str,
    /// Strict JSON object serialized by the MCP server.
    pub arguments_json: &'a str,
}

/// Safe metadata bound to a successful backend response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendMetadata {
    /// Snapshot identity that produced the response.
    pub snapshot: String,
    /// Compiled bundle identity or authoritative source identity.
    pub bundle_or_source: String,
    /// Backend-provided expiry, or a conservative session expiry.
    pub expiry: String,
}

impl BackendMetadata {
    /// Constructs validated-at-use response metadata.
    #[must_use]
    pub fn new(
        snapshot: impl Into<String>,
        bundle_or_source: impl Into<String>,
        expiry: impl Into<String>,
    ) -> Self {
        Self {
            snapshot: snapshot.into(),
            bundle_or_source: bundle_or_source.into(),
            expiry: expiry.into(),
        }
    }
}

/// One JSON response body and its authoritative public metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendResponse {
    /// Strict JSON response body.
    pub body: String,
    /// Snapshot, source, and expiry identities.
    pub metadata: BackendMetadata,
}

impl BackendResponse {
    /// Constructs a backend response for an injected implementation.
    #[must_use]
    pub fn new(body: impl Into<String>, metadata: BackendMetadata) -> Self {
        Self {
            body: body.into(),
            metadata,
        }
    }
}

/// Content-free backend failure categories safe to cross the MCP boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    /// No authoritative daemon could be reached before the deadline.
    Unavailable,
    /// The daemon rejected the request without safe details.
    Rejected,
    /// The daemon response exceeded the hard response budget.
    ResponseTooLarge,
    /// The daemon returned malformed or unsupported transport data.
    InvalidResponse,
    /// The caller cancelled the request before an authoritative result was available.
    Cancelled,
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authoritative backend unavailable",
            Self::Rejected => "authoritative backend rejected request",
            Self::ResponseTooLarge => "authoritative backend response exceeded limit",
            Self::InvalidResponse => "authoritative backend returned an invalid response",
            Self::Cancelled => "authoritative backend request was cancelled",
        })
    }
}

impl std::error::Error for BackendError {}

/// Cloneable cancellation signal shared with one in-flight backend invocation.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a signal in the active state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Calling this more than once is harmless.
    pub fn cancel(&self) {
        self.cancelled.store(true, AtomicOrdering::Release);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(AtomicOrdering::Acquire)
    }
}

/// Injectable authority boundary used by the stdio protocol server.
pub trait Backend {
    /// Executes one bounded request without returning transport or host details in errors.
    fn call(&mut self, request: BackendRequest<'_>) -> Result<BackendResponse, BackendError>;

    /// Executes one bounded request while observing an MCP cancellation notification.
    ///
    /// Implementations that can interrupt I/O should override this method. The default preserves
    /// source compatibility for injected backends and fails before delegation when already
    /// cancelled.
    fn call_cancellable(
        &mut self,
        request: BackendRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<BackendResponse, BackendError> {
        if cancellation.is_cancelled() {
            Err(BackendError::Cancelled)
        } else {
            self.call(request)
        }
    }
}

/// Installed CIGAR CLI authority boundary used by the packaged stdio server.
///
/// Delegating through `cigar` reuses its production local Unix-socket, Windows named-pipe, remote
/// authentication, compatibility, deadline, and canonical-envelope implementation. MCP arguments
/// are written to an owner-only temporary input file and never exposed in the process argument
/// vector.
#[derive(Clone, Debug)]
pub struct CliBackend {
    binary: OsString,
}

impl CliBackend {
    /// Builds the backend from `CIGAR_MCP_CLI_BINARY`, defaulting to `cigar` on `PATH`.
    pub fn from_env() -> Result<Self, BackendError> {
        let binary = env::var_os("CIGAR_MCP_CLI_BINARY").unwrap_or_else(|| OsString::from("cigar"));
        if binary.is_empty() {
            Err(BackendError::Rejected)
        } else {
            Ok(Self { binary })
        }
    }

    /// Performs a real bounded `cigar status` handshake.
    #[must_use]
    pub fn is_available(&mut self) -> bool {
        self.invoke(&["status"], None, None, &CancellationToken::new())
            .is_ok()
    }

    fn invoke(
        &self,
        command: &[&str],
        payload: Option<&Value>,
        idempotency_key: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<BackendResponse, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        let temporary = payload.map(write_cli_input).transpose()?;
        let mut process = Command::new(&self.binary);
        process.args(command);
        if let Some(path) = &temporary {
            process.arg("--input").arg(path);
        }
        if let Some(key) = idempotency_key {
            process.arg("--idempotency-key").arg(key);
        }
        process
            .args([
                "--yes",
                "--non-interactive",
                "--output",
                "json",
                "--deadline",
                "2s",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let result = run_cli_process(process, cancellation);
        if let Some(path) = temporary {
            let _ignored = std::fs::remove_file(path);
        }
        decode_cli_output(&result?)
    }

    fn tool(
        &self,
        request: BackendRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<BackendResponse, BackendError> {
        let arguments = json::parse_with_limits(
            request.arguments_json,
            BACKEND_MAX_DEPTH,
            BACKEND_MAX_NODES,
            MAX_BACKEND_RESPONSE_BYTES,
        )
        .map_err(|_| BackendError::Rejected)?;
        let exact = arguments.object_field("request").cloned();
        let idempotency_key = arguments
            .object_field("idempotency_key")
            .and_then(Value::as_str);
        match request.operation {
            "createContextPlan" => {
                let payload = exact.unwrap_or_else(|| {
                    Value::Object(
                        arguments
                            .object_field("contract")
                            .cloned()
                            .map(|contract| vec![("contract".to_owned(), contract)])
                            .unwrap_or_default(),
                    )
                });
                require_nonempty_object(&payload)?;
                self.invoke(
                    &["context", "plan"],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "materializeContextBundle" => {
                let payload = exact.unwrap_or_else(|| {
                    Value::Object(vec![
                        (
                            "bundle_id".to_owned(),
                            arguments
                                .object_field("bundle_id")
                                .cloned()
                                .unwrap_or(Value::Null),
                        ),
                        (
                            "profile".to_owned(),
                            Value::String("claude_prompt".to_owned()),
                        ),
                    ])
                });
                let bundle = field_text(&payload, "bundle_id")?;
                self.invoke(
                    &["context", "materialize", bundle],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "explainContextBundle" => {
                let payload = exact.unwrap_or_else(|| {
                    let versions = arguments
                        .object_field("selection_id")
                        .cloned()
                        .map_or_else(Vec::new, |value| vec![value]);
                    Value::Object(vec![
                        (
                            "bundle_id".to_owned(),
                            arguments
                                .object_field("bundle_id")
                                .cloned()
                                .unwrap_or(Value::Null),
                        ),
                        ("version_ids".to_owned(), Value::Array(versions)),
                    ])
                });
                let bundle = field_text(&payload, "bundle_id")?;
                self.invoke(
                    &["context", "explain", bundle],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "queryCatalog" => {
                let payload = exact.ok_or(BackendError::Rejected)?;
                require_nonempty_object(&payload)?;
                self.invoke(
                    &["catalog", "query"],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "createSpaceCheckpoint" => {
                let payload = exact.ok_or(BackendError::Rejected)?;
                let space = field_text(&payload, "space_id")?;
                self.invoke(
                    &["focus", "checkpoint", space],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "createHandoff" => {
                let payload = exact.ok_or(BackendError::Rejected)?;
                require_nonempty_object(&payload)?;
                self.invoke(
                    &["handoff", "create"],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "acceptHandoff" => {
                let payload = exact.ok_or(BackendError::Rejected)?;
                let handoff = field_text(&payload, "handoff_id")?;
                self.invoke(
                    &["handoff", "accept", handoff],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "prepareEffect" => {
                let payload = exact
                    .or_else(|| arguments.object_field("intent").cloned())
                    .ok_or(BackendError::Rejected)?;
                require_nonempty_object(&payload)?;
                self.invoke(
                    &["effect", "prepare"],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "dispatchEffect" => {
                let payload = exact.unwrap_or_else(|| {
                    Value::Object(vec![(
                        "effect_id".to_owned(),
                        arguments
                            .object_field("preparation_id")
                            .cloned()
                            .unwrap_or(Value::Null),
                    )])
                });
                let effect = field_text(&payload, "effect_id")?;
                self.invoke(
                    &["effect", "dispatch", effect],
                    Some(&payload),
                    idempotency_key,
                    cancellation,
                )
            }
            "getEffectStatus" => {
                let payload = exact.unwrap_or_else(|| {
                    Value::Object(vec![(
                        "effect_id".to_owned(),
                        arguments
                            .object_field("effect_id")
                            .cloned()
                            .unwrap_or(Value::Null),
                    )])
                });
                let effect = field_text(&payload, "effect_id")?;
                self.invoke(&["effect", "inspect", effect], None, None, cancellation)
            }
            _ => Err(BackendError::Rejected),
        }
    }

    fn resource(
        &self,
        request: BackendRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<BackendResponse, BackendError> {
        let arguments = json::parse(request.arguments_json).map_err(|_| BackendError::Rejected)?;
        let uri = arguments
            .object_field("uri")
            .and_then(Value::as_str)
            .ok_or(BackendError::Rejected)?;
        let (family, identity) = uri
            .strip_prefix("cigar://")
            .and_then(|value| value.split_once('/'))
            .ok_or(BackendError::Rejected)?;
        if identity.is_empty()
            || identity.len() > 256
            || !identity.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
            })
        {
            return Err(BackendError::Rejected);
        }
        match family {
            "bundle" => {
                let payload = Value::Object(vec![
                    ("bundle_id".to_owned(), Value::String(identity.to_owned())),
                    (
                        "profile".to_owned(),
                        Value::String("canonical_json".to_owned()),
                    ),
                ]);
                self.invoke(
                    &["context", "materialize", identity],
                    Some(&payload),
                    None,
                    cancellation,
                )
            }
            "handoff" => self.invoke(&["handoff", "preview", identity], None, None, cancellation),
            "effect" => self.invoke(&["effect", "inspect", identity], None, None, cancellation),
            _ => Err(BackendError::Rejected),
        }
    }
}

impl Backend for CliBackend {
    fn call(&mut self, request: BackendRequest<'_>) -> Result<BackendResponse, BackendError> {
        self.call_cancellable(request, &CancellationToken::new())
    }

    fn call_cancellable(
        &mut self,
        request: BackendRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<BackendResponse, BackendError> {
        match request.kind {
            BackendRequestKind::Health if request.operation == "ping" => {
                self.invoke(&["status"], None, None, cancellation)
            }
            BackendRequestKind::Tool => self.tool(request, cancellation),
            BackendRequestKind::Resource if request.operation == "read" => {
                self.resource(request, cancellation)
            }
            BackendRequestKind::Health | BackendRequestKind::Resource => {
                Err(BackendError::Rejected)
            }
        }
    }
}

fn require_nonempty_object(value: &Value) -> Result<(), BackendError> {
    if value.as_object().is_some_and(|fields| !fields.is_empty()) {
        Ok(())
    } else {
        Err(BackendError::Rejected)
    }
}

fn field_text<'a>(value: &'a Value, name: &str) -> Result<&'a str, BackendError> {
    value
        .object_field(name)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
                })
        })
        .ok_or(BackendError::Rejected)
}

fn write_cli_input(value: &Value) -> Result<PathBuf, BackendError> {
    let path = env::temp_dir().join(format!(
        "cigar-mcp-{}-{}.json",
        std::process::id(),
        CLI_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|_| BackendError::Unavailable)?;
    if file
        .write_all(value.render().as_bytes())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ignored = std::fs::remove_file(&path);
        return Err(BackendError::Unavailable);
    }
    Ok(path)
}

fn run_cli_process(
    mut command: Command,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, BackendError> {
    if cancellation.is_cancelled() {
        return Err(BackendError::Cancelled);
    }
    let mut child = command.spawn().map_err(|_| BackendError::Unavailable)?;
    let Some(stdout) = child.stdout.take() else {
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(BackendError::Unavailable);
    };
    let Some(stderr) = child.stderr.take() else {
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(BackendError::Unavailable);
    };
    let output_reader = thread::spawn(move || read_limited(stdout));
    let error_reader = thread::spawn(move || read_limited(stderr));
    let started = Instant::now();
    let status = loop {
        if cancellation.is_cancelled() {
            let _ignored = child.kill();
            let _ignored = child.wait();
            let _output = output_reader.join();
            let _error = error_reader.join();
            return Err(BackendError::Cancelled);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                let _output = output_reader.join();
                let _error = error_reader.join();
                return Err(BackendError::Unavailable);
            }
        }
        if started.elapsed() >= CLI_DEADLINE {
            let _ignored = child.kill();
            let _ignored = child.wait();
            let _output = output_reader.join();
            let _error = error_reader.join();
            return Err(BackendError::Unavailable);
        }
        thread::sleep(Duration::from_millis(2));
    };
    let output = output_reader
        .join()
        .map_err(|_| BackendError::Unavailable)??;
    let _error = error_reader
        .join()
        .map_err(|_| BackendError::Unavailable)??;
    if status.success() {
        Ok(output)
    } else {
        Err(BackendError::Rejected)
    }
}

fn read_limited<R: Read>(reader: R) -> Result<Vec<u8>, BackendError> {
    let maximum =
        u64::try_from(MAX_BACKEND_RESPONSE_BYTES).map_err(|_| BackendError::ResponseTooLarge)?;
    let mut bytes = Vec::new();
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::Unavailable)?;
    if bytes.len() > MAX_BACKEND_RESPONSE_BYTES {
        Err(BackendError::ResponseTooLarge)
    } else {
        Ok(bytes)
    }
}

fn decode_cli_output(encoded: &[u8]) -> Result<BackendResponse, BackendError> {
    let text = std::str::from_utf8(encoded).map_err(|_| BackendError::InvalidResponse)?;
    let parsed = json::parse_with_limits(
        text,
        BACKEND_MAX_DEPTH,
        BACKEND_MAX_NODES,
        MAX_BACKEND_RESPONSE_BYTES,
    )
    .map_err(|_| BackendError::InvalidResponse)?;
    if !matches!(parsed.object_field("ok"), Some(Value::Bool(true))) {
        return Err(BackendError::Rejected);
    }
    let result = parsed
        .object_field("result")
        .ok_or(BackendError::InvalidResponse)?;
    let snapshot = find_public_identity(result, &["snapshot_id", "snapshot"])
        .unwrap_or_else(|| "current".to_owned());
    let bundle_or_source = find_public_identity(
        result,
        &[
            "bundle_id",
            "source_id",
            "resource_id",
            "handoff_id",
            "effect_id",
            "plan_id",
        ],
    )
    .or_else(|| {
        result
            .object_field("plan")
            .and_then(|plan| find_public_identity(plan, &["plan_id"]))
    })
    .unwrap_or_else(|| "cigar-daemon".to_owned());
    Ok(BackendResponse::new(
        result.render(),
        BackendMetadata::new(snapshot, bundle_or_source, "session"),
    ))
}

fn find_public_identity(value: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        value
            .object_field(name)
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && !value.chars().any(char::is_control)
                    && !value.contains(['/', '\\'])
                    && !value.contains("..")
            })
            .map(str::to_owned)
    })
}

/// Frozen loopback HTTP mapping for a running CIGAR daemon.
///
/// The adapter intentionally accepts only plain HTTP on loopback. Production TLS and
/// authentication can be supplied by a separate injected `Backend` implementation; this keeps
/// stdio from becoming a general-purpose SSRF client.
#[derive(Clone, Debug)]
pub struct HttpBackend {
    host: String,
    port: u16,
    base_path: String,
}

impl HttpBackend {
    /// Reads `CIGAR_MCP_DAEMON_URL`, defaulting to the loopback frozen MCP facade.
    ///
    /// Only `http://localhost`, `http://127.0.0.1`, and `http://[::1]` are accepted.
    pub fn from_env() -> Result<Self, BackendError> {
        let configured =
            env::var("CIGAR_MCP_DAEMON_URL").unwrap_or_else(|_| DEFAULT_DAEMON_URL.to_owned());
        Self::from_url(&configured)
    }

    /// Builds the bounded adapter from one loopback URL.
    pub fn from_url(url: &str) -> Result<Self, BackendError> {
        let remainder = url.strip_prefix("http://").ok_or(BackendError::Rejected)?;
        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, ""), |(authority, path)| (authority, path));
        if authority.contains('@') || authority.is_empty() {
            return Err(BackendError::Rejected);
        }

        let (host, port) = parse_loopback_authority(authority)?;
        let trimmed_path = path.trim_matches('/');
        if trimmed_path.contains("..")
            || !trimmed_path.chars().all(|value| {
                value.is_ascii_alphanumeric() || matches!(value, '/' | '_' | '-' | '.')
            })
        {
            return Err(BackendError::Rejected);
        }
        let base_path = if trimmed_path.is_empty() {
            String::new()
        } else {
            format!("/{trimmed_path}")
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            base_path,
        })
    }

    /// Performs a content-free health probe suitable for `doctor`.
    #[must_use]
    pub fn is_available(&mut self) -> bool {
        self.call(BackendRequest {
            kind: BackendRequestKind::Health,
            operation: "ping",
            arguments_json: "{}",
        })
        .is_ok()
    }

    fn request_path(&self, request: BackendRequest<'_>) -> Result<String, BackendError> {
        let suffix = match request.kind {
            BackendRequestKind::Tool
                if MCP_OPERATION_MAPPINGS
                    .iter()
                    .any(|mapping| mapping.operation_id == request.operation) =>
            {
                format!("/tools/{}", request.operation)
            }
            BackendRequestKind::Resource if request.operation == "read" => {
                "/resources/read".to_owned()
            }
            BackendRequestKind::Health if request.operation == "ping" => "/health".to_owned(),
            BackendRequestKind::Tool
            | BackendRequestKind::Resource
            | BackendRequestKind::Health => return Err(BackendError::Rejected),
        };
        Ok(format!("{}{suffix}", self.base_path))
    }
}

impl Backend for HttpBackend {
    fn call(&mut self, request: BackendRequest<'_>) -> Result<BackendResponse, BackendError> {
        let path = self.request_path(request)?;
        let connect_host = if self.host == "localhost" {
            "127.0.0.1"
        } else {
            &self.host
        };
        let address = format!("{connect_host}:{}", self.port);
        let socket = address
            .to_socket_addrs()
            .map_err(|_| BackendError::Unavailable)?
            .find(|candidate| candidate.ip().is_loopback())
            .ok_or(BackendError::Unavailable)?;
        let mut stream = TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT)
            .map_err(|_| BackendError::Unavailable)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| BackendError::Unavailable)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| BackendError::Unavailable)?;

        let request_head = format!(
            concat!(
                "POST {path} HTTP/1.1\r\n",
                "Host: {host}:{port}\r\n",
                "Content-Type: application/json\r\n",
                "Accept: application/json\r\n",
                "Connection: close\r\n",
                "Content-Length: {length}\r\n\r\n"
            ),
            path = path,
            host = self.host,
            port = self.port,
            length = request.arguments_json.len(),
        );
        stream
            .write_all(request_head.as_bytes())
            .and_then(|()| stream.write_all(request.arguments_json.as_bytes()))
            .and_then(|()| stream.flush())
            .map_err(|_| BackendError::Unavailable)?;

        let mut encoded = Vec::new();
        let max = u64::try_from(MAX_BACKEND_RESPONSE_BYTES)
            .map_err(|_| BackendError::ResponseTooLarge)?;
        stream
            .take(max.saturating_add(1))
            .read_to_end(&mut encoded)
            .map_err(|_| BackendError::Unavailable)?;
        if encoded.len() > MAX_BACKEND_RESPONSE_BYTES {
            return Err(BackendError::ResponseTooLarge);
        }
        decode_http_response(&encoded)
    }
}

fn parse_loopback_authority(authority: &str) -> Result<(&str, u16), BackendError> {
    if authority == "[::1]" {
        return Ok(("[::1]", 80));
    }
    if let Some(port) = authority.strip_prefix("[::1]:") {
        return Ok(("[::1]", parse_port(port)?));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, 80), |(host, port)| {
            (host, parse_port(port).unwrap_or(0))
        });
    if !matches!(host, "localhost" | "127.0.0.1") || port == 0 {
        return Err(BackendError::Rejected);
    }
    Ok((host, port))
}

fn parse_port(port: &str) -> Result<u16, BackendError> {
    port.parse::<u16>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(BackendError::Rejected)
}

fn decode_http_response(encoded: &[u8]) -> Result<BackendResponse, BackendError> {
    let separator = encoded
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(BackendError::InvalidResponse)?;
    let head = encoded
        .get(..separator)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or(BackendError::InvalidResponse)?;
    let body_offset = separator
        .checked_add(4)
        .ok_or(BackendError::InvalidResponse)?;
    let body = encoded
        .get(body_offset..)
        .ok_or(BackendError::InvalidResponse)?;

    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(BackendError::InvalidResponse)?;
    let mut status_parts = status.split_whitespace();
    if !matches!(status_parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(BackendError::InvalidResponse);
    }
    let status_code = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(BackendError::InvalidResponse)?;
    if !(200..300).contains(&status_code) {
        return Err(if (400..500).contains(&status_code) {
            BackendError::Rejected
        } else {
            BackendError::Unavailable
        });
    }

    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(BackendError::InvalidResponse)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(BackendError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(BackendError::InvalidResponse);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| BackendError::InvalidResponse)?,
            );
        }
    }
    if content_length.is_some_and(|expected| expected != body.len()) {
        return Err(BackendError::InvalidResponse);
    }
    let body = String::from_utf8(body.to_vec()).map_err(|_| BackendError::InvalidResponse)?;
    decode_json_body(body)
}

fn decode_json_body(body: String) -> Result<BackendResponse, BackendError> {
    let parsed = json::parse_with_limits(
        &body,
        BACKEND_MAX_DEPTH,
        BACKEND_MAX_NODES,
        MAX_BACKEND_RESPONSE_BYTES,
    )
    .map_err(|_| BackendError::InvalidResponse)?;
    if let Some(metadata) = parsed.object_field("metadata") {
        let root_fields = parsed.as_object().ok_or(BackendError::InvalidResponse)?;
        if root_fields.len() != 2
            || !root_fields
                .iter()
                .all(|(name, _)| matches!(name.as_str(), "data" | "metadata"))
        {
            return Err(BackendError::InvalidResponse);
        }
        let data = parsed
            .object_field("data")
            .ok_or(BackendError::InvalidResponse)?;
        let fields = metadata.as_object().ok_or(BackendError::InvalidResponse)?;
        if fields.len() != 3
            || !fields.iter().all(|(name, _)| {
                matches!(name.as_str(), "snapshot" | "bundle_or_source" | "expiry")
            })
        {
            return Err(BackendError::InvalidResponse);
        }
        let field = |name| {
            metadata
                .object_field(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(BackendError::InvalidResponse)
        };
        return Ok(BackendResponse::new(
            data.render(),
            BackendMetadata::new(
                field("snapshot")?,
                field("bundle_or_source")?,
                field("expiry")?,
            ),
        ));
    }
    let digest = public_digest(body.as_bytes());
    Ok(BackendResponse::new(
        body,
        BackendMetadata::new(format!("response-{digest:016x}"), "daemon", "session"),
    ))
}

fn public_digest(bytes: &[u8]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::{
        Backend, BackendError, BackendRequest, BackendRequestKind, CliBackend, HttpBackend,
        decode_http_response,
    };

    #[cfg(unix)]
    #[test]
    fn installed_cli_backend_uses_private_input_not_argv_and_extracts_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = std::env::temp_dir().join(format!(
            "cigar-mcp-cli-test-{}-{}",
            std::process::id(),
            super::CLI_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory)?;
        let script = directory.join("cigar fixture");
        std::fs::write(
            &script,
            concat!(
                "#!/bin/sh\n",
                "set -eu\n",
                "printf '%s\\n' \"$*\" >> \"$0.log\"\n",
                "printf '%s\\n' '{\"schema_version\":\"cigar.cli.output.v1\",\"ok\":true,\"result\":{\"bundle_id\":\"bundle-1\",\"snapshot_id\":\"snapshot-1\"}}'\n"
            ),
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
        let mut backend = CliBackend {
            binary: script.clone().into_os_string(),
        };
        assert!(backend.is_available());
        let response = backend.call(BackendRequest {
            kind: BackendRequestKind::Tool,
            operation: "createContextPlan",
            arguments_json: r#"{"request":{"contract":{"goal":"secret-payload"}},"max_tokens":500}"#,
        })?;
        assert_eq!(response.metadata.snapshot, "snapshot-1");
        assert_eq!(response.metadata.bundle_or_source, "bundle-1");
        let log = std::fs::read_to_string(script.with_extension("log"))?;
        assert!(log.contains("status --yes --non-interactive"));
        assert!(log.contains("context plan --input"));
        assert!(!log.contains("secret-payload"));
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn loopback_url_is_the_only_accepted_http_authority() {
        let backend = HttpBackend::from_url("http://127.0.0.1:9999/v1/mcp");
        assert!(backend.is_ok());
        assert!(HttpBackend::from_url("http://localhost/v1/mcp").is_ok());
        assert!(HttpBackend::from_url("http://[::1]:8080/v1/mcp").is_ok());
        assert_eq!(
            HttpBackend::from_url("https://127.0.0.1/v1/mcp").err(),
            Some(BackendError::Rejected)
        );
        assert_eq!(
            HttpBackend::from_url("http://example.test/v1/mcp").err(),
            Some(BackendError::Rejected)
        );
        assert!(HttpBackend::from_url("http://localhost/a/../private").is_err());
        assert!(HttpBackend::from_url("http://localhost/v1\r\nInjected-header").is_err());
    }

    #[test]
    fn frozen_route_mapping_never_uses_arguments_as_a_path() -> Result<(), BackendError> {
        let backend = HttpBackend::from_url("http://127.0.0.1:9999/v1/mcp")?;
        let tool = backend.request_path(BackendRequest {
            kind: BackendRequestKind::Tool,
            operation: "createContextPlan",
            arguments_json: r#"{"path":"../../private"}"#,
        })?;
        assert_eq!(tool, "/v1/mcp/tools/createContextPlan");
        assert_eq!(
            backend
                .request_path(BackendRequest {
                    kind: BackendRequestKind::Tool,
                    operation: "unlistedAdministrativeOperation",
                    arguments_json: "{}",
                })
                .err(),
            Some(BackendError::Rejected)
        );
        assert_eq!(
            backend.request_path(BackendRequest {
                kind: BackendRequestKind::Resource,
                operation: "read",
                arguments_json: r#"{"uri":"cigar://task/current"}"#,
            })?,
            "/v1/mcp/resources/read"
        );
        assert_eq!(
            backend.request_path(BackendRequest {
                kind: BackendRequestKind::Health,
                operation: "ping",
                arguments_json: "{}",
            })?,
            "/v1/mcp/health"
        );
        Ok(())
    }

    #[test]
    fn cli_backend_rejects_unlisted_route_kinds_before_process_spawn() {
        let mut backend = CliBackend {
            binary: "/definitely/not/a/cigar-binary".into(),
        };
        for request in [
            BackendRequest {
                kind: BackendRequestKind::Health,
                operation: "administrativeEscape",
                arguments_json: "{}",
            },
            BackendRequest {
                kind: BackendRequestKind::Resource,
                operation: "write",
                arguments_json: r#"{"uri":"cigar://bundle/b1"}"#,
            },
            BackendRequest {
                kind: BackendRequestKind::Tool,
                operation: "administrativeEscape",
                arguments_json: "{}",
            },
        ] {
            assert_eq!(backend.call(request).err(), Some(BackendError::Rejected));
        }
    }

    #[test]
    fn http_decoder_is_bounded_and_strict() -> Result<(), BackendError> {
        let response = decode_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
        )?;
        assert_eq!(response.body, "{\"ok\":true}");
        assert!(response.metadata.snapshot.starts_with("response-"));

        assert_eq!(
            decode_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                .err(),
            Some(BackendError::InvalidResponse)
        );
        assert_eq!(
            decode_http_response(b"HTTP/1.1 403 No\r\nContent-Length: 0\r\n\r\n").err(),
            Some(BackendError::Rejected)
        );
        Ok(())
    }

    #[test]
    fn http_decoder_extracts_authoritative_metadata_envelope() -> Result<(), BackendError> {
        let body = r#"{"data":{"bundle_id":"b1"},"metadata":{"snapshot":"s1","bundle_or_source":"b1","expiry":"2099-01-01T00:00:00Z"}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let decoded = decode_http_response(response.as_bytes())?;
        assert_eq!(decoded.body, r#"{"bundle_id":"b1"}"#);
        assert_eq!(decoded.metadata.snapshot, "s1");
        assert_eq!(decoded.metadata.bundle_or_source, "b1");
        assert_eq!(decoded.metadata.expiry, "2099-01-01T00:00:00Z");
        Ok(())
    }
}
