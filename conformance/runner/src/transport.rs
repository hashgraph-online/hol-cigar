//! Bounded adapter transports and local process isolation.

use crate::model::{AdapterRequest, VectorLimits};
use prost::Message;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_ENDPOINT_BYTES: usize = 2048;

/// Adapter target selected explicitly by the qualifier.
#[derive(Clone, Debug)]
pub enum AdapterTarget {
    /// A local executable using the stdin/stdout JSON protocol.
    Executable(PathBuf),
    /// An SDK adapter executable using the same protocol.
    SdkAdapter(PathBuf),
    /// A bounded HTTP JSON endpoint.
    Http(String),
    /// A bounded HTTP JSON endpoint over a Unix-domain socket.
    Unix(PathBuf),
    /// A bounded unary gRPC endpoint.
    Grpc(String),
}

/// Requested local isolation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationMode {
    /// Require an OS-enforced network and filesystem-write sandbox.
    Strict,
    /// Apply portable process bounds without claiming release qualification.
    Portable,
}

/// Raw bounded invocation result.
#[derive(Debug)]
pub struct Invocation {
    /// Response bytes when transport completed.
    pub response: Result<Vec<u8>, InvocationFailure>,
    /// Measured wall duration.
    pub duration_ms: u64,
}

/// Value-free failure categories safe to place in public reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationFailure {
    /// Required sandbox was unavailable or failed to start.
    IsolationUnavailable,
    /// Adapter exceeded its wall deadline.
    Timeout,
    /// Adapter terminated unsuccessfully.
    Crash,
    /// Adapter exceeded stdout or stderr bounds.
    OutputLimit,
    /// Adapter exceeded its process memory bound.
    ResourceLimit,
    /// Request could not be delivered within bounds.
    InputFailure,
    /// Selected remote transport failed.
    TransportFailure,
}

impl InvocationFailure {
    /// Stable, value-free public category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::IsolationUnavailable => "isolation_unavailable",
            Self::Timeout => "timeout",
            Self::Crash => "adapter_crash",
            Self::OutputLimit => "output_limit",
            Self::ResourceLimit => "memory_limit",
            Self::InputFailure => "input_failure",
            Self::TransportFailure => "transport_failure",
        }
    }
}

/// Returns the effective isolation label and release qualification bit.
#[must_use]
pub fn isolation_claim(target: &AdapterTarget, mode: IsolationMode) -> (&'static str, bool) {
    match target {
        AdapterTarget::Executable(_) | AdapterTarget::SdkAdapter(_) => match mode {
            IsolationMode::Strict => ("strict_local", true),
            IsolationMode::Portable => ("portable_local", false),
        },
        AdapterTarget::Http(_) | AdapterTarget::Unix(_) | AdapterTarget::Grpc(_) => {
            ("remote_bounded", false)
        }
    }
}

/// Invokes one case using the selected target and published vector limits.
pub fn invoke(
    target: &AdapterTarget,
    request: &AdapterRequest,
    timeout: Duration,
    limits: &VectorLimits,
    isolation: IsolationMode,
) -> Invocation {
    let started = Instant::now();
    let request_bytes = match serde_json::to_vec(request) {
        Ok(bytes) if bytes.len() <= limits.max_request_bytes => bytes,
        Ok(_) | Err(_) => {
            return Invocation {
                response: Err(InvocationFailure::InputFailure),
                duration_ms: elapsed_millis(started),
            };
        }
    };
    let response = match target {
        AdapterTarget::Executable(path) | AdapterTarget::SdkAdapter(path) => {
            invoke_local(path, &request_bytes, timeout, limits, isolation)
        }
        AdapterTarget::Http(endpoint) => {
            invoke_http(endpoint, &request_bytes, timeout, limits.max_response_bytes)
        }
        AdapterTarget::Unix(socket) => {
            invoke_unix(socket, &request_bytes, timeout, limits.max_response_bytes)
        }
        AdapterTarget::Grpc(endpoint) => {
            invoke_grpc(endpoint, &request_bytes, timeout, limits.max_response_bytes)
        }
    };
    Invocation {
        response,
        duration_ms: elapsed_millis(started),
    }
}

fn invoke_local(
    executable: &Path,
    request: &[u8],
    timeout: Duration,
    limits: &VectorLimits,
    isolation: IsolationMode,
) -> Result<Vec<u8>, InvocationFailure> {
    let executable = executable
        .canonicalize()
        .map_err(|_error| InvocationFailure::IsolationUnavailable)?;
    let metadata = std::fs::symlink_metadata(&executable)
        .map_err(|_error| InvocationFailure::IsolationUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(InvocationFailure::IsolationUnavailable);
    }
    let temporary = tempfile::Builder::new()
        .prefix("cigar-conformance-case-")
        .tempdir()
        .map_err(|_error| InvocationFailure::IsolationUnavailable)?;
    let mut command = local_command(&executable, temporary.path(), timeout, limits, isolation)?;
    command
        .current_dir(temporary.path())
        .env_clear()
        .env("HOME", temporary.path())
        .env("TMPDIR", temporary.path())
        .env("TEMP", temporary.path())
        .env("TMP", temporary.path())
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("CIGAR_CONFORMANCE_NETWORK", "denied")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_error| InvocationFailure::IsolationUnavailable)?;
    let Some(stdin) = child.stdin.take() else {
        terminate_process_group(&mut child);
        return Err(InvocationFailure::InputFailure);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(&mut child);
        return Err(InvocationFailure::Crash);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(&mut child);
        return Err(InvocationFailure::Crash);
    };
    let mut framed_request = request.to_vec();
    framed_request.push(b'\n');
    let input_thread = thread::spawn(move || {
        let mut stdin = stdin;
        stdin.write_all(&framed_request)
    });
    let stdout_bound = limits.max_response_bytes;
    let stdout_thread = thread::spawn(move || read_bounded(stdout, stdout_bound));
    let stderr_bound = limits.max_diagnostic_bytes;
    let stderr_thread = thread::spawn(move || read_bounded(stderr, stderr_bound));

    let deadline = Instant::now() + timeout;
    let (status, timed_out, resource_exceeded) =
        match wait_bounded(&mut child, deadline, limits.max_memory_bytes) {
            Ok(result) => result,
            Err(failure) => {
                terminate_process_group(&mut child);
                return Err(failure);
            }
        };
    if timed_out || resource_exceeded {
        terminate_process_group(&mut child);
    }
    let input = input_thread
        .join()
        .map_err(|_error| InvocationFailure::InputFailure)?;
    let (stdout, stdout_exceeded) = stdout_thread
        .join()
        .map_err(|_error| InvocationFailure::Crash)?;
    let (_stderr, stderr_exceeded) = stderr_thread
        .join()
        .map_err(|_error| InvocationFailure::Crash)?;
    if timed_out {
        return Err(InvocationFailure::Timeout);
    }
    if resource_exceeded {
        return Err(InvocationFailure::ResourceLimit);
    }
    input.map_err(|_error| InvocationFailure::InputFailure)?;
    if stdout_exceeded || stderr_exceeded {
        return Err(InvocationFailure::OutputLimit);
    }
    if !status.is_some_and(|status| status.success()) {
        return Err(InvocationFailure::Crash);
    }
    Ok(stdout)
}

#[cfg(unix)]
fn local_command(
    executable: &Path,
    case_root: &Path,
    timeout: Duration,
    limits: &VectorLimits,
    isolation: IsolationMode,
) -> Result<Command, InvocationFailure> {
    let mut target = Vec::<String>::new();
    match isolation {
        IsolationMode::Portable => target.push(executable.to_string_lossy().into_owned()),
        IsolationMode::Strict => append_strict_sandbox(&mut target, executable, case_root)?,
    }
    let cpu_seconds = timeout.as_secs().saturating_add(1).max(1);
    let file_blocks = limits.max_file_bytes.saturating_add(511) / 512;
    let memory_kib = limits.max_memory_bytes / 1024;
    #[cfg(target_os = "linux")]
    let script = "ulimit -t \"$1\" || exit 125; ulimit -f \"$2\" || exit 125; ulimit -n 64 || exit 125; ulimit -u \"$3\" || exit 125; ulimit -v \"$4\" || exit 125; shift 4; exec \"$@\"";
    #[cfg(not(target_os = "linux"))]
    let script = "ulimit -t \"$1\" || exit 125; ulimit -f \"$2\" || exit 125; ulimit -n 64 || exit 125; ulimit -u \"$3\" || exit 125; shift 4; exec \"$@\"";
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .arg("cigar-resource-limits")
        .arg(cpu_seconds.to_string())
        .arg(file_blocks.to_string())
        .arg(limits.max_processes.to_string())
        .arg(memory_kib.to_string())
        .args(target);
    Ok(command)
}

#[cfg(not(unix))]
fn local_command(
    executable: &Path,
    _case_root: &Path,
    _timeout: Duration,
    _limits: &VectorLimits,
    isolation: IsolationMode,
) -> Result<Command, InvocationFailure> {
    if isolation == IsolationMode::Strict {
        return Err(InvocationFailure::IsolationUnavailable);
    }
    Ok(Command::new(executable))
}

#[cfg(target_os = "macos")]
fn append_strict_sandbox(
    target: &mut Vec<String>,
    executable: &Path,
    case_root: &Path,
) -> Result<(), InvocationFailure> {
    let sandbox = Path::new("/usr/bin/sandbox-exec");
    if !sandbox.is_file() {
        return Err(InvocationFailure::IsolationUnavailable);
    }
    let executable_argument = executable
        .to_str()
        .ok_or(InvocationFailure::IsolationUnavailable)?
        .to_owned();
    let canonical_case_root = case_root
        .canonicalize()
        .map_err(|_error| InvocationFailure::IsolationUnavailable)?;
    let case_root = seatbelt_escape(&canonical_case_root)?;
    let profile = format!(
        "(version 1) (allow default) (deny network*) (deny file-write*) (allow file-write* (subpath \"{case_root}\"))"
    );
    target.push(sandbox.to_string_lossy().into_owned());
    target.push("-p".to_owned());
    target.push(profile);
    target.push(executable_argument);
    Ok(())
}

#[cfg(target_os = "macos")]
fn seatbelt_escape(path: &Path) -> Result<String, InvocationFailure> {
    let text = path
        .to_str()
        .ok_or(InvocationFailure::IsolationUnavailable)?;
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "linux")]
fn append_strict_sandbox(
    target: &mut Vec<String>,
    executable: &Path,
    case_root: &Path,
) -> Result<(), InvocationFailure> {
    let sandbox = [Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")]
        .into_iter()
        .find(|path| path.is_file())
        .ok_or(InvocationFailure::IsolationUnavailable)?;
    let values = [
        sandbox.to_string_lossy().into_owned(),
        "--unshare-all".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--ro-bind".to_owned(),
        "/".to_owned(),
        "/".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--bind".to_owned(),
        case_root.to_string_lossy().into_owned(),
        case_root.to_string_lossy().into_owned(),
        "--chdir".to_owned(),
        case_root.to_string_lossy().into_owned(),
        "--".to_owned(),
        executable.to_string_lossy().into_owned(),
    ];
    target.extend(values);
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn append_strict_sandbox(
    _target: &mut Vec<String>,
    _executable: &Path,
    _case_root: &Path,
) -> Result<(), InvocationFailure> {
    Err(InvocationFailure::IsolationUnavailable)
}

fn wait_bounded(
    child: &mut Child,
    deadline: Instant,
    max_memory_bytes: u64,
) -> Result<(Option<std::process::ExitStatus>, bool, bool), InvocationFailure> {
    let mut unavailable_memory_checks = 0_u8;
    let mut last_memory_check = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_error| InvocationFailure::Crash)?
        {
            return Ok((Some(status), false, false));
        }
        if Instant::now() >= deadline {
            return Ok((None, true, false));
        }
        if last_memory_check.elapsed() >= Duration::from_millis(25) {
            match process_group_memory_bytes(child.id()) {
                Some(bytes) if bytes > max_memory_bytes => return Ok((None, false, true)),
                Some(_) => unavailable_memory_checks = 0,
                None => {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|_error| InvocationFailure::Crash)?
                    {
                        return Ok((Some(status), false, false));
                    }
                    #[cfg(unix)]
                    {
                        // A very short-lived process can disappear from `ps` just
                        // before its wait status becomes observable. Keep failing
                        // closed if monitoring is genuinely unavailable, while
                        // tolerating that bounded exit race.
                        unavailable_memory_checks = unavailable_memory_checks.saturating_add(1);
                        if unavailable_memory_checks >= 3 {
                            return Err(InvocationFailure::IsolationUnavailable);
                        }
                    }
                }
            }
            last_memory_check = Instant::now();
        }
        thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(unix)]
fn process_group_memory_bytes(process_group: u32) -> Option<u64> {
    let output = Command::new("/bin/ps")
        .args(["-o", "rss=", "-g", &process_group.to_string()])
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return None;
    }
    let kibibytes = std::str::from_utf8(&output.stdout)
        .ok()?
        .lines()
        .try_fold(0_u64, |sum, line| {
            sum.checked_add(line.trim().parse::<u64>().ok()?)
        })?;
    kibibytes.checked_mul(1024)
}

#[cfg(not(unix))]
fn process_group_memory_bytes(_process_group: u32) -> Option<u64> {
    None
}

fn terminate_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        let _status = Command::new("/bin/kill")
            .arg("-KILL")
            .arg(format!("-{}", child.id()))
            .status();
    }
    let _result = child.kill();
    let _result = child.wait();
}

fn read_bounded(mut reader: impl Read, bound: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::with_capacity(bound.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    let mut exceeded = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = bound.saturating_sub(output.len());
                let retained = remaining.min(read);
                if let Some(bytes) = buffer.get(..retained) {
                    output.extend_from_slice(bytes);
                } else {
                    exceeded = true;
                }
                exceeded |= retained != read;
            }
            Err(_) => break,
        }
    }
    (output, exceeded)
}

fn invoke_http(
    endpoint: &str,
    request: &[u8],
    timeout: Duration,
    max_response: usize,
) -> Result<Vec<u8>, InvocationFailure> {
    let parsed = parse_http_endpoint(endpoint)?;
    let socket = resolve_one(&parsed.authority)?;
    let mut stream = TcpStream::connect_timeout(&socket, timeout)
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    write_http_request(&mut stream, &parsed.authority, &parsed.path, request)?;
    read_http_response(&mut stream, max_response)
}

#[cfg(unix)]
fn invoke_unix(
    socket: &Path,
    request: &[u8],
    timeout: Duration,
    max_response: usize,
) -> Result<Vec<u8>, InvocationFailure> {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::net::UnixStream;
    let metadata =
        std::fs::symlink_metadata(socket).map_err(|_error| InvocationFailure::TransportFailure)?;
    if !metadata.file_type().is_socket() {
        return Err(InvocationFailure::TransportFailure);
    }
    let mut stream =
        UnixStream::connect(socket).map_err(|_error| InvocationFailure::TransportFailure)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    write_http_request(&mut stream, "localhost", "/v1/conformance/run", request)?;
    read_http_response(&mut stream, max_response)
}

#[cfg(not(unix))]
fn invoke_unix(
    _socket: &Path,
    _request: &[u8],
    _timeout: Duration,
    _max_response: usize,
) -> Result<Vec<u8>, InvocationFailure> {
    Err(InvocationFailure::TransportFailure)
}

fn write_http_request(
    stream: &mut impl Write,
    authority: &str,
    path: &str,
    request: &[u8],
) -> Result<(), InvocationFailure> {
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        request.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(request))
        .and_then(|()| stream.flush())
        .map_err(|_error| InvocationFailure::TransportFailure)
}

fn read_http_response(
    stream: &mut impl Read,
    max_response: usize,
) -> Result<Vec<u8>, InvocationFailure> {
    let bound = MAX_HTTP_HEADER_BYTES
        .checked_add(max_response)
        .and_then(|value| value.checked_add(1))
        .ok_or(InvocationFailure::TransportFailure)?;
    let mut bytes = Vec::with_capacity(bound.min(64 * 1024));
    stream
        .take(bound as u64)
        .read_to_end(&mut bytes)
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    if bytes.len() == bound {
        return Err(InvocationFailure::OutputLimit);
    }
    let header_end = find_bytes(&bytes, b"\r\n\r\n").ok_or(InvocationFailure::TransportFailure)?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err(InvocationFailure::OutputLimit);
    }
    let header_bytes = bytes
        .get(..header_end)
        .ok_or(InvocationFailure::TransportFailure)?;
    let headers =
        std::str::from_utf8(header_bytes).map_err(|_error| InvocationFailure::TransportFailure)?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(InvocationFailure::TransportFailure);
    }
    let mut content_length = None;
    let mut content_type = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(InvocationFailure::TransportFailure)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(InvocationFailure::TransportFailure);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_error| InvocationFailure::TransportFailure)?;
            if content_length.replace(length).is_some() {
                return Err(InvocationFailure::TransportFailure);
            }
        }
        if name.eq_ignore_ascii_case("content-type")
            && value
                .trim()
                .split(';')
                .next()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("application/json"))
        {
            content_type = true;
        }
    }
    let body = bytes
        .get(header_end.saturating_add(4)..)
        .ok_or(InvocationFailure::TransportFailure)?;
    if !content_type
        || body.len() > max_response
        || content_length.is_some_and(|length| length != body.len())
    {
        return Err(InvocationFailure::TransportFailure);
    }
    Ok(body.to_vec())
}

struct HttpEndpoint {
    authority: String,
    path: String,
}

fn parse_http_endpoint(endpoint: &str) -> Result<HttpEndpoint, InvocationFailure> {
    if endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.contains(['\r', '\n', '#', '?', '@'])
        || !endpoint.starts_with("http://")
    {
        return Err(InvocationFailure::TransportFailure);
    }
    let remainder = endpoint
        .strip_prefix("http://")
        .ok_or(InvocationFailure::TransportFailure)?;
    let (authority, base_path) = remainder
        .split_once('/')
        .map_or((remainder, ""), |(authority, path)| (authority, path));
    if authority.is_empty() || !authority.contains(':') {
        return Err(InvocationFailure::TransportFailure);
    }
    let path = if base_path.is_empty() {
        "/v1/conformance/run".to_owned()
    } else {
        format!("/{}/v1/conformance/run", base_path.trim_end_matches('/'))
    };
    Ok(HttpEndpoint {
        authority: authority.to_owned(),
        path,
    })
}

fn resolve_one(authority: &str) -> Result<SocketAddr, InvocationFailure> {
    let addresses = authority
        .to_socket_addrs()
        .map_err(|_error| InvocationFailure::TransportFailure)?
        .take(2)
        .collect::<Vec<_>>();
    if addresses.len() != 1 {
        return Err(InvocationFailure::TransportFailure);
    }
    addresses
        .first()
        .copied()
        .ok_or(InvocationFailure::TransportFailure)
}

#[derive(Clone, PartialEq, Message)]
struct GrpcRequest {
    #[prost(bytes = "vec", tag = "1")]
    request_json: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct GrpcResponse {
    #[prost(bytes = "vec", tag = "1")]
    response_json: Vec<u8>,
}

fn invoke_grpc(
    endpoint: &str,
    request: &[u8],
    timeout: Duration,
    max_response: usize,
) -> Result<Vec<u8>, InvocationFailure> {
    if endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(InvocationFailure::TransportFailure);
    }
    let endpoint = endpoint
        .strip_prefix("grpc://")
        .map(|value| format!("http://{value}"))
        .or_else(|| {
            endpoint
                .strip_prefix("grpcs://")
                .map(|value| format!("https://{value}"))
        })
        .ok_or(InvocationFailure::TransportFailure)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_error| InvocationFailure::TransportFailure)?;
    let response = runtime.block_on(async move {
        let channel = tonic::transport::Endpoint::from_shared(endpoint)
            .map_err(|_error| InvocationFailure::TransportFailure)?
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect()
            .await
            .map_err(|_error| InvocationFailure::TransportFailure)?;
        let mut client = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(max_response.saturating_add(16))
            .max_encoding_message_size(request.len().saturating_add(16));
        client
            .ready()
            .await
            .map_err(|_error| InvocationFailure::TransportFailure)?;
        let path = tonic::codegen::http::uri::PathAndQuery::from_static(
            "/cigar.conformance.v1.ConformanceAdapter/RunCase",
        );
        let codec = tonic_prost::ProstCodec::<GrpcRequest, GrpcResponse>::default();
        let response: tonic::Response<GrpcResponse> = client
            .unary(
                tonic::Request::new(GrpcRequest {
                    request_json: request.to_vec(),
                }),
                path,
                codec,
            )
            .await
            .map_err(|_error| InvocationFailure::TransportFailure)?;
        Ok::<Vec<u8>, InvocationFailure>(response.into_inner().response_json)
    })?;
    if response.len() > max_response {
        return Err(InvocationFailure::OutputLimit);
    }
    Ok(response)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
