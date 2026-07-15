//! Process-boundary conformance runner acceptance and adversarial tests.

use cigar_conformance::{
    AdapterRequest, AdapterResponse, AdapterTarget, CaseOutcome, CaseStatus, IsolationMode,
    OverallResult, RunConfiguration, run_suite, verify_result,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

fn repository_root() -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root unavailable")?
        .to_path_buf())
}

fn vectors() -> Result<PathBuf, Box<dyn Error>> {
    Ok(repository_root()?.join("conformance/vectors/v1"))
}

fn configuration(executable: PathBuf, vectors: PathBuf) -> RunConfiguration {
    RunConfiguration {
        profiles: vec!["cigar-core-v1".to_owned()],
        target: AdapterTarget::Executable(executable),
        implementation: "integration-fixture".to_owned(),
        remote_build_digest: None,
        vectors,
        isolation: IsolationMode::Portable,
    }
}

fn all_profiles() -> Vec<String> {
    [
        "cigar-core-v1",
        "cigar-catalog-v1",
        "cigar-compiler-v1",
        "cigar-handoff-v1",
        "cigar-effect-v1",
        "cigar-replay-v1",
        "cigar-service-v1",
        "cigar-runtime-claude-code-v1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn configuration_for_profiles(
    executable: PathBuf,
    vectors: PathBuf,
    profiles: Vec<String>,
) -> RunConfiguration {
    RunConfiguration {
        profiles,
        target: AdapterTarget::Executable(executable),
        implementation: "integration-fixture".to_owned(),
        remote_build_digest: None,
        vectors,
        isolation: IsolationMode::Portable,
    }
}

fn copy_faulty(mode: &str, directory: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let suffix = std::env::consts::EXE_SUFFIX;
    let destination = directory.join(format!("cigar-fault-{mode}{suffix}"));
    fs::copy(env!("CARGO_BIN_EXE_cigar-conformance-faulty"), &destination)?;
    Ok(destination)
}

fn reduced_vectors(directory: &Path, timeout_ms: u64) -> Result<PathBuf, Box<dyn Error>> {
    let root = directory.join("vectors");
    fs::create_dir_all(&root)?;
    let source_vectors = vectors()?;
    let source = fs::read(source_vectors.join("core-v1.json"))?;
    fs::copy(
        source_vectors.join("fixture.toml"),
        root.join("fixture.toml"),
    )?;
    let mut value: Value = serde_json::from_slice(&source)?;
    let object = value.as_object_mut().ok_or("manifest is not an object")?;
    object.insert("profiles".to_owned(), serde_json::json!(["cigar-core-v1"]));
    let cases = object
        .get_mut("cases")
        .and_then(Value::as_array_mut)
        .ok_or("manifest cases missing")?;
    cases.truncate(1);
    let first = cases
        .first_mut()
        .and_then(Value::as_object_mut)
        .ok_or("first case missing")?;
    first.insert("timeout_ms".to_owned(), Value::from(timeout_ms));
    let limits = object
        .get_mut("limits")
        .and_then(Value::as_object_mut)
        .ok_or("manifest limits missing")?;
    limits.insert("max_case_timeout_ms".to_owned(), Value::from(timeout_ms));
    limits.insert("max_total_timeout_ms".to_owned(), Value::from(timeout_ms));
    fs::write(
        root.join("core-v1.json"),
        serde_json::to_vec_pretty(&value)?,
    )?;
    Ok(root)
}

fn recompute_result_digest(
    result: &mut cigar_conformance::ConformanceResult,
) -> Result<(), Box<dyn Error>> {
    let mut value = serde_json::to_value(&*result)?;
    value
        .as_object_mut()
        .ok_or("result is not an object")?
        .remove("result_digest");
    let digest = Sha256::digest(serde_json::to_vec(&value)?);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _result = write!(&mut encoded, "{byte:02x}");
    }
    result.result_digest = format!("sha256:{encoded}");
    Ok(())
}

#[test]
fn reference_core_profile_passes_and_verifies() -> Result<(), Box<dyn Error>> {
    let configuration = configuration(
        PathBuf::from(env!("CARGO_BIN_EXE_cigar-conformance-reference")),
        vectors()?,
    );
    let result = run_suite(&configuration)?;
    assert_eq!(result.overall, OverallResult::Passed);
    assert_eq!(result.cases.len(), 10);
    assert!(
        result
            .cases
            .iter()
            .all(|case| case.status == CaseStatus::Passed)
    );
    verify_result(&result, &configuration.vectors)?;
    Ok(())
}

#[test]
fn reference_all_production_profiles_pass_positive_and_negative_cases() -> Result<(), Box<dyn Error>>
{
    let configuration = configuration_for_profiles(
        PathBuf::from(env!("CARGO_BIN_EXE_cigar-conformance-reference")),
        vectors()?,
        all_profiles(),
    );
    let result = run_suite(&configuration)?;
    assert_eq!(result.overall, OverallResult::Passed);
    assert_eq!(result.cases.len(), 24);
    for profile in all_profiles() {
        let profile_cases = result
            .cases
            .iter()
            .filter(|case| case.profile == profile)
            .collect::<Vec<_>>();
        assert!(!profile_cases.is_empty(), "profile {profile}");
        assert!(
            profile_cases
                .iter()
                .any(|case| case.actual_outcome == Some(CaseOutcome::Success)),
            "profile {profile} lacks a positive production case"
        );
        assert!(
            profile_cases
                .iter()
                .any(|case| case.actual_outcome == Some(CaseOutcome::Rejected)),
            "profile {profile} lacks a negative production case"
        );
        assert!(
            profile_cases
                .iter()
                .all(|case| case.status == CaseStatus::Passed),
            "profile {profile} failed"
        );
    }
    verify_result(&result, &configuration.vectors)?;
    Ok(())
}

#[test]
fn every_profile_rejects_wrong_and_skipped_adapters() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    for mode in ["wrong", "skipped"] {
        let expected_diagnostic = match mode {
            "wrong" => "public_result_mismatch",
            "skipped" => "malformed_response",
            _ => return Err("unregistered profile fault mode".into()),
        };
        let executable = copy_faulty(mode, temporary.path())?;
        for profile in all_profiles() {
            let configuration =
                configuration_for_profiles(executable.clone(), vectors()?, vec![profile.clone()]);
            let result = run_suite(&configuration)?;
            assert_eq!(
                result.overall,
                OverallResult::Failed,
                "mode {mode}, profile {profile}"
            );
            assert!(
                result
                    .cases
                    .iter()
                    .all(|case| case.status == CaseStatus::Failed
                        && case.redacted_diagnostic.as_deref() == Some(expected_diagnostic)),
                "mode {mode}, profile {profile}"
            );
        }
    }
    Ok(())
}

#[test]
fn all_profile_result_verifier_rejects_case_tamper() -> Result<(), Box<dyn Error>> {
    let configuration = configuration_for_profiles(
        PathBuf::from(env!("CARGO_BIN_EXE_cigar-conformance-reference")),
        vectors()?,
        all_profiles(),
    );
    let mut result = run_suite(&configuration)?;
    verify_result(&result, &configuration.vectors)?;
    result
        .cases
        .iter_mut()
        .find(|case| case.profile == "cigar-catalog-v1")
        .ok_or("catalog result missing")?
        .actual_public_digest =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned());
    recompute_result_digest(&mut result)?;
    assert!(verify_result(&result, &configuration.vectors).is_err());
    Ok(())
}

#[test]
fn intentionally_faulty_implementations_fail_hard_invariants() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    for mode in ["wrong", "skipped"] {
        let expected_diagnostic = match mode {
            "wrong" => "public_result_mismatch",
            "skipped" => "malformed_response",
            _ => return Err("unregistered core fault mode".into()),
        };
        let executable = copy_faulty(mode, temporary.path())?;
        let configuration = configuration(executable, vectors()?);
        let result = run_suite(&configuration)?;
        assert_eq!(result.overall, OverallResult::Failed, "mode {mode}");
        assert!(
            result
                .cases
                .iter()
                .all(|case| case.status == CaseStatus::Failed
                    && case.redacted_diagnostic.as_deref() == Some(expected_diagnostic)),
            "mode {mode}"
        );
    }
    Ok(())
}

#[test]
fn result_verifier_rejects_every_single_field_tamper() -> Result<(), Box<dyn Error>> {
    let configuration = configuration(
        PathBuf::from(env!("CARGO_BIN_EXE_cigar-conformance-reference")),
        vectors()?,
    );
    let original = run_suite(&configuration)?;
    verify_result(&original, &configuration.vectors)?;

    let mut mutations = Vec::new();
    let mut value = original.clone();
    value.build_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
    mutations.push(value);
    let mut value = original.clone();
    value.runner_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
    mutations.push(value);
    let mut value = original.clone();
    value.vector_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
    mutations.push(value);
    let mut value = original.clone();
    value.claimed_profiles.push("cigar-core-v1".to_owned());
    mutations.push(value);
    let mut value = original.clone();
    value
        .cases
        .first_mut()
        .ok_or("result has no cases")?
        .case_id = "CORE-INVENTED-999".to_owned();
    mutations.push(value);
    let mut value = original.clone();
    value
        .cases
        .first_mut()
        .ok_or("result has no cases")?
        .actual_public_digest =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned());
    mutations.push(value);
    let mut value = original.clone();
    let first = value.cases.first_mut().ok_or("result has no cases")?;
    first.status = CaseStatus::Failed;
    first.redacted_diagnostic = Some("tampered".to_owned());
    mutations.push(value);
    let mut value = original.clone();
    value
        .cases
        .first_mut()
        .ok_or("result has no cases")?
        .duration_ms = 60_000;
    mutations.push(value);
    let mut value = original.clone();
    value.release_qualified = true;
    mutations.push(value);
    let mut value = original.clone();
    value.overall = OverallResult::Failed;
    mutations.push(value);

    for (index, mut mutation) in mutations.into_iter().enumerate() {
        // A build digest is an externally asserted identity for remote adapters. Its
        // integrity is covered by the enclosing result digest; the remaining fields
        // also have independent semantic bindings that must fail after recomputation.
        if index != 0 {
            recompute_result_digest(&mut mutation)?;
        }
        assert!(verify_result(&mutation, &configuration.vectors).is_err());
    }
    Ok(())
}

#[test]
fn every_case_uses_a_fresh_process_and_namespace() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let executable = copy_faulty("stateful", temporary.path())?;
    let configuration = configuration(executable, vectors()?);
    let result = run_suite(&configuration)?;
    assert_eq!(result.overall, OverallResult::Passed);
    assert_eq!(result.cases.len(), 10);
    assert!(
        result.cases.iter().all(|case| {
            case.status == CaseStatus::Passed && case.redacted_diagnostic.is_none()
        })
    );
    Ok(())
}

#[test]
fn timeout_crash_malformed_and_output_flood_are_distinct_failures() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    // Leave enough process-start headroom for this suite to run concurrently under
    // nextest; the timeout fixture still sleeps for 30 seconds and must be killed.
    let vector_root = reduced_vectors(temporary.path(), 2000)?;
    for (mode, category) in [
        ("timeout", "timeout"),
        ("crash", "adapter_crash"),
        ("malformed", "malformed_response"),
        ("flood", "output_limit"),
    ] {
        let executable = copy_faulty(mode, temporary.path())?;
        let configuration = configuration(executable, vector_root.clone());
        let result = run_suite(&configuration)?;
        assert_eq!(result.overall, OverallResult::Failed, "mode {mode}");
        assert_eq!(
            result.cases.first().map(|case| case.status),
            Some(CaseStatus::Failed),
            "mode {mode}"
        );
        assert_eq!(
            result
                .cases
                .first()
                .and_then(|case| case.redacted_diagnostic.as_deref()),
            Some(category),
            "mode {mode}"
        );
    }
    Ok(())
}

#[test]
fn vector_mutation_is_detected_and_fails_the_run() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let vector_root = reduced_vectors(temporary.path(), 250)?;
    let sentinel = vector_root.join("integrity-sentinel.txt");
    fs::write(&sentinel, b"before")?;
    let executable = copy_faulty("timeout", temporary.path())?;
    let configuration = configuration(executable, vector_root);
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        fs::write(sentinel, b"after")
    });
    let result = run_suite(&configuration)?;
    writer.join().map_err(|_error| "writer thread panicked")??;
    assert_eq!(result.overall, OverallResult::Failed);
    assert_eq!(result.integrity_errors, ["vector_mutation"]);
    Ok(())
}

#[test]
fn strict_sandbox_blocks_network_and_filesystem_escape() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let vector_root = reduced_vectors(temporary.path(), 5000)?;
    let manifest_path = vector_root.join("core-v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let input = manifest
        .get_mut("cases")
        .and_then(Value::as_array_mut)
        .and_then(|cases| cases.first_mut())
        .and_then(|case| case.get_mut("input"))
        .and_then(Value::as_object_mut)
        .ok_or("case input unavailable")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let escape_path = temporary.path().join("sandbox-escape-proof");
    input.insert(
        "probe_path".to_owned(),
        Value::String(escape_path.to_string_lossy().into_owned()),
    );
    input.insert(
        "probe_address".to_owned(),
        Value::String(listener.local_addr()?.to_string()),
    );
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    let executable = copy_faulty("escape", temporary.path())?;
    let mut configuration = configuration(executable, vector_root);
    configuration.isolation = IsolationMode::Strict;
    let result = run_suite(&configuration)?;
    if result
        .cases
        .first()
        .and_then(|case| case.redacted_diagnostic.as_deref())
        == Some("isolation_unavailable")
    {
        assert_ne!(
            std::env::consts::OS,
            "macos",
            "the registered macOS escape proof requires Seatbelt isolation"
        );
        assert_eq!(result.overall, OverallResult::Failed);
        assert!(!result.release_qualified);
        return Ok(());
    }
    assert_eq!(result.overall, OverallResult::Passed);
    assert!(result.release_qualified);
    assert!(!escape_path.exists());
    assert!(listener.accept().is_err());
    Ok(())
}

#[test]
fn executable_sdk_http_unix_and_grpc_transports_share_the_protocol() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let vector_root = reduced_vectors(temporary.path(), 5000)?;

    let mut sdk = configuration(
        PathBuf::from(env!("CARGO_BIN_EXE_cigar-conformance-reference")),
        vector_root.clone(),
    );
    sdk.target = AdapterTarget::SdkAdapter(match sdk.target {
        AdapterTarget::Executable(path) => path,
        _ => return Err("SDK fixture target changed".into()),
    });
    assert_eq!(run_suite(&sdk)?.overall, OverallResult::Passed);

    let http_listener = TcpListener::bind("127.0.0.1:0")?;
    let http_address = http_listener.local_addr()?;
    let http_thread = thread::spawn(move || serve_http_once(http_listener));
    let http = remote_configuration(
        AdapterTarget::Http(format!("http://{http_address}")),
        vector_root.clone(),
    );
    assert_eq!(run_suite(&http)?.overall, OverallResult::Passed);
    http_thread
        .join()
        .map_err(|_error| "HTTP fixture thread panicked")??;

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;
        let socket = temporary.path().join("adapter.sock");
        let listener = UnixListener::bind(&socket)?;
        let unix_thread = thread::spawn(move || serve_unix_once(listener));
        let unix = remote_configuration(AdapterTarget::Unix(socket), vector_root.clone());
        assert_eq!(run_suite(&unix)?.overall, OverallResult::Passed);
        unix_thread
            .join()
            .map_err(|_error| "Unix fixture thread panicked")??;
    }

    let (grpc_address, grpc_shutdown, grpc_thread) = start_grpc_server()?;
    thread::sleep(Duration::from_millis(50));
    let grpc = remote_configuration(
        AdapterTarget::Grpc(format!("grpc://{grpc_address}")),
        vector_root,
    );
    let grpc_result = run_suite(&grpc)?;
    grpc_shutdown
        .send(())
        .map_err(|_value| "gRPC fixture shutdown channel closed")?;
    let grpc_server_result = grpc_thread
        .join()
        .map_err(|_error| "gRPC fixture thread panicked")?;
    assert_eq!(
        grpc_result.overall,
        OverallResult::Passed,
        "cases={:?}, server={grpc_server_result:?}",
        grpc_result.cases
    );
    grpc_server_result?;
    Ok(())
}

fn remote_configuration(target: AdapterTarget, vectors: PathBuf) -> RunConfiguration {
    RunConfiguration {
        profiles: vec!["cigar-core-v1".to_owned()],
        target,
        implementation: "remote-integration-fixture".to_owned(),
        remote_build_digest: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        vectors,
        isolation: IsolationMode::Strict,
    }
}

fn adapter_response_bytes(request_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: AdapterRequest = serde_json::from_slice(request_bytes)
        .map_err(|error| format!("invalid fixture adapter request: {error}"))?;
    if request.case_id != "CORE-CANON-001" {
        return Err("unexpected fixture case".to_owned());
    }
    serde_json::to_vec(&AdapterResponse {
        schema_version: "cigar.conformance.response.v1".to_owned(),
        case_id: request.case_id,
        challenge: request.challenge,
        outcome: CaseOutcome::Success,
        public_digest: "1220e76d14455f390432ae81cb4ec53ba92d7ec514430a26d02bf8cbc1572d9f7835"
            .to_owned(),
        diagnostic: None,
    })
    .map_err(|error| format!("cannot encode fixture adapter response: {error}"))
}

fn serve_http_once(listener: TcpListener) -> Result<(), String> {
    let (mut stream, _address) = listener
        .accept()
        .map_err(|error| format!("cannot accept HTTP fixture: {error}"))?;
    serve_http_stream(&mut stream)
}

#[cfg(unix)]
fn serve_unix_once(listener: std::os::unix::net::UnixListener) -> Result<(), String> {
    let (mut stream, _address) = listener
        .accept()
        .map_err(|error| format!("cannot accept Unix fixture: {error}"))?;
    serve_http_stream(&mut stream)
}

fn serve_http_stream(
    stream: &mut (impl Read + Write + FixtureStreamTimeout),
) -> Result<(), String> {
    stream
        .set_read_timeout_fixture()
        .map_err(|error| format!("cannot bound fixture stream: {error}"))?;
    let body = read_http_request(stream)?;
    let response = adapter_response_bytes(&body)?;
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(&response))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("cannot write fixture response: {error}"))
}

trait FixtureStreamTimeout {
    fn set_read_timeout_fixture(&self) -> std::io::Result<()>;
}

impl FixtureStreamTimeout for TcpStream {
    fn set_read_timeout_fixture(&self) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(2)))
    }
}

#[cfg(unix)]
impl FixtureStreamTimeout for std::os::unix::net::UnixStream {
    fn set_read_timeout_fixture(&self) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(2)))
    }
}

fn read_http_request(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("cannot read fixture request: {error}"))?;
        if read == 0 || bytes.len().saturating_add(read) > 64 * 1024 {
            return Err("fixture request ended before bounded headers".to_owned());
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| "fixture read exceeded buffer".to_owned())?;
        bytes.extend_from_slice(chunk);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position.saturating_add(4);
        }
    };
    let headers = bytes
        .get(..header_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or_else(|| "invalid fixture request headers".to_owned())?;
    let content_length = headers
        .split("\r\n")
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .ok_or_else(|| "fixture request lacks content length".to_owned())?;
    if content_length > 1024 * 1024 {
        return Err("fixture request body is too large".to_owned());
    }
    let required = header_end
        .checked_add(content_length)
        .ok_or_else(|| "fixture request length overflow".to_owned())?;
    while bytes.len() < required {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("cannot finish fixture request: {error}"))?;
        if read == 0 || bytes.len().saturating_add(read) > required {
            return Err("fixture request body length mismatch".to_owned());
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| "fixture read exceeded buffer".to_owned())?;
        bytes.extend_from_slice(chunk);
    }
    bytes
        .get(header_end..required)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "fixture request body offset is invalid".to_owned())
}

mod grpc_fixture {
    use super::adapter_response_bytes;
    use prost::Message;
    use tonic::codegen::*;

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Request {
        #[prost(bytes = "vec", tag = "1")]
        pub(super) request_json: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Response {
        #[prost(bytes = "vec", tag = "1")]
        pub(super) response_json: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    pub(super) struct Service;

    impl<B> tonic::codegen::Service<http::Request<B>> for Service
    where
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            if request.uri().path() == "/cigar.conformance.v1.ConformanceAdapter/RunCase" {
                struct RunCase;
                impl tonic::server::UnaryService<Request> for RunCase {
                    type Response = Response;
                    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                    fn call(&mut self, request: tonic::Request<Request>) -> Self::Future {
                        Box::pin(async move {
                            let response_json =
                                adapter_response_bytes(&request.into_inner().request_json)
                                    .map_err(tonic::Status::invalid_argument)?;
                            Ok(tonic::Response::new(Response { response_json }))
                        })
                    }
                }
                Box::pin(async move {
                    let codec = tonic_prost::ProstCodec::<Response, Request>::default();
                    let mut grpc = tonic::server::Grpc::new(codec)
                        .apply_max_message_size_config(Some(1024 * 1024), Some(64 * 1024));
                    Ok(grpc.unary(RunCase, request).await)
                })
            } else {
                Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    response.headers_mut().insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    response.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                })
            }
        }
    }

    impl tonic::server::NamedService for Service {
        const NAME: &'static str = "cigar.conformance.v1.ConformanceAdapter";
    }
}

type GrpcServer = (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    thread::JoinHandle<Result<(), String>>,
);

fn start_grpc_server() -> Result<GrpcServer, Box<dyn Error>> {
    let (address_sender, address_receiver) = std::sync::mpsc::sync_channel(1);
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("cannot build gRPC fixture runtime: {error}"))?;
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| format!("cannot bind gRPC fixture: {error}"))?;
            let address = listener
                .local_addr()
                .map_err(|error| format!("cannot inspect gRPC fixture: {error}"))?;
            address_sender
                .send(address)
                .map_err(|_error| "gRPC fixture address receiver closed".to_owned())?;
            tonic::transport::Server::builder()
                .add_service(grpc_fixture::Service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async move {
                        let _result = shutdown_receiver.await;
                    },
                )
                .await
                .map_err(|error| format!("gRPC fixture failed: {error}"))
        })
    });
    let address = address_receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| format!("gRPC fixture did not start: {error}"))?;
    Ok((address, shutdown_sender, server))
}
