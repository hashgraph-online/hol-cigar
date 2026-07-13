//! Authoritative, dependency-light workspace automation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const GENERATED_MANIFEST: &str = concat!(
    "{\n",
    "  \"schema_version\": 1,\n",
    "  \"generator\": \"cargo xtask generate\",\n",
    "  \"protocol_min\": \"1.0\",\n",
    "  \"protocol_max\": \"1.x\",\n",
    "  \"artifacts\": [\n",
    "    \"json/candidate-disposition-v1.schema.json\",\n",
    "    \"json/capability-grant-v1.schema.json\",\n",
    "    \"json/compatibility-report-v1.schema.json\",\n",
    "    \"json/compensation-link-v1.schema.json\",\n",
    "    \"json/context-atom-v1.schema.json\",\n",
    "    \"json/context-block-v1.schema.json\",\n",
    "    \"json/context-bundle-v1.schema.json\",\n",
    "    \"json/context-commit-v1.schema.json\",\n",
    "    \"json/context-contract-v1.schema.json\",\n",
    "    \"json/context-delta-v1.schema.json\",\n",
    "    \"json/context-edge-v1.schema.json\",\n",
    "    \"json/context-plan-v1.schema.json\",\n",
    "    \"json/decision-record-v1.schema.json\",\n",
    "    \"json/effect-approval-v1.schema.json\",\n",
    "    \"json/effect-attempt-v1.schema.json\",\n",
    "    \"json/effect-intent-v1.schema.json\",\n",
    "    \"json/effect-journal-event-v1.schema.json\",\n",
    "    \"json/effect-receipt-v1.schema.json\",\n",
    "    \"json/extension-cancel-v1.schema.json\",\n",
    "    \"json/extension-host-call-v1.schema.json\",\n",
    "    \"json/extension-invocation-v1.schema.json\",\n",
    "    \"json/extension-manifest-v1.schema.json\",\n",
    "    \"json/extension-observation-v1.schema.json\",\n",
    "    \"json/extension-response-v1.schema.json\",\n",
    "    \"json/handoff-acceptance-v1.schema.json\",\n",
    "    \"json/handoff-capsule-v1.schema.json\",\n",
    "    \"json/handoff-delta-v1.schema.json\",\n",
    "    \"json/health-report-v1.schema.json\",\n",
    "    \"json/lease-v1.schema.json\",\n",
    "    \"json/materialized-context-v1.schema.json\",\n",
    "    \"json/overlay-v1.schema.json\",\n",
    "    \"json/page-cursor-v1.schema.json\",\n",
    "    \"json/plan-lane-v1.schema.json\",\n",
    "    \"json/problem-v1.schema.json\",\n",
    "    \"json/reconciliation-report-v1.schema.json\",\n",
    "    \"json/replay-completeness-v1.schema.json\",\n",
    "    \"json/replay-diff-v1.schema.json\",\n",
    "    \"json/replay-execution-v1.schema.json\",\n",
    "    \"json/replay-request-v1.schema.json\",\n",
    "    \"json/selection-manifest-v1.schema.json\",\n",
    "    \"json/source-snapshot-v1.schema.json\",\n",
    "    \"json/verification-receipt-v1.schema.json\"\n",
    "  ],\n",
    "  \"error_artifacts\": [\n",
    "    \"crates/cigar-protocol/src/generated/error_registry.rs\",\n",
    "    \"schemas/proto/generated/error_codes.proto\",\n",
    "    \"schemas/openapi/error-registry-v1.json\"\n",
    "  ],\n",
    "  \"api_artifacts\": [\n",
    "    \"crates/cigar-api/src/generated/operations.rs\",\n",
    "    \"schemas/json/api-payload-types-v1.schema.json\",\n",
    "    \"schemas/proto/cigar_service.proto\",\n",
    "    \"schemas/openapi/cigar-v1.json\"\n",
    "  ],\n",
    "  \"wire_artifacts\": [\n",
    "    \"crates/cigar-protocol/src/generated/cigar/context/v1/cigar.context.v1.rs\",\n",
    "    \"sdk/typescript/src/generated/cigar_service_pb.ts\",\n",
    "    \"sdk/typescript/src/generated/context_abi_pb.ts\",\n",
    "    \"sdk/typescript/src/generated/generated/error_codes_pb.ts\",\n",
    "    \"sdk/python/src/cigar_sdk/generated/cigar_service_pb2.py\",\n",
    "    \"sdk/python/src/cigar_sdk/generated/context_abi_pb2.py\",\n",
    "    \"sdk/python/src/cigar_sdk/generated/generated/error_codes_pb2.py\",\n",
    "    \"sdk/go/gen/cigarv1/cigar_service.pb.go\",\n",
    "    \"sdk/go/gen/cigarv1/cigar_service_grpc.pb.go\",\n",
    "    \"sdk/go/gen/contextv1/context_abi.pb.go\",\n",
    "    \"sdk/go/gen/contextv1/error_codes.pb.go\"\n",
    "  ],\n",
    "  \"sdk_artifacts\": [\n",
    "    \"sdk/capabilities-v1.json\",\n",
    "    \"sdk/typescript/src/generated/operations.ts\",\n",
    "    \"sdk/python/src/cigar_sdk/generated/operations.py\",\n",
    "    \"sdk/go/operations_gen.go\"\n",
    "  ],\n",
    "  \"fixture_manifest\": \"fixtures/wp01/manifest.json\"\n",
    "}\n"
);

const PACKAGE_LAYERS: &[(&str, u8)] = &[
    ("cigar-protocol", 0),
    ("cigar-canon", 1),
    ("cigar-crypto", 1),
    ("cigar-policy", 2),
    ("cigar-store", 2),
    ("cigar-catalog", 3),
    ("cigar-code-intel", 3),
    ("cigar-retrieval", 3),
    ("cigar-compiler", 4),
    ("cigar-space", 4),
    ("cigar-effects", 4),
    ("cigar-replay", 5),
    ("cigar-observe", 5),
    ("cigar-extension-host", 5),
    ("cigar-api", 6),
    ("cigar-daemon", 7),
    ("cigar-cli", 7),
    ("cigar-mcp", 7),
    ("cigar-testkit", 8),
    ("cigar-sim", 8),
    ("cigar-windows-ipc", 1),
];

#[derive(Deserialize, Serialize)]
struct ErrorCatalog {
    schema_version: u8,
    status: String,
    errors: Vec<ErrorCatalogEntry>,
}

#[derive(Deserialize, Serialize)]
struct ErrorCatalogEntry {
    code: u32,
    name: String,
    http: u16,
    grpc: String,
    retry: String,
    message: String,
    remediation: String,
    disclose_identity: bool,
}

#[derive(Deserialize)]
struct OperationCatalog {
    schema_version: u8,
    status: String,
    package: String,
    http_base: String,
    operation_count: usize,
    services: Vec<OperationService>,
}

#[derive(Deserialize)]
struct OperationService {
    name: String,
    operations: Vec<OperationEntry>,
}

#[derive(Deserialize)]
struct OperationEntry {
    rpc: String,
    operation_id: String,
    http_method: String,
    http_path: String,
    mutation: bool,
    idempotency_requirement: String,
    revision_requirement: String,
    stream_kind: String,
    auth_class: String,
}

#[derive(Deserialize)]
struct OperationPayloadCatalog {
    schema_version: u8,
    status: String,
    operation_count: usize,
    envelope_fields: Vec<PayloadField>,
    operations: Vec<OperationPayloadEntry>,
}

#[derive(Deserialize)]
struct OperationPayloadEntry {
    operation_id: String,
    request_schema: String,
    response_schema: String,
    event_schema: Option<String>,
    request_max_bytes: usize,
    response_max_bytes: usize,
    event_max_bytes: usize,
    request_fields: Vec<PayloadField>,
    response_fields: Vec<PayloadField>,
    event_fields: Vec<PayloadField>,
}

#[derive(Deserialize)]
struct PayloadField {
    name: String,
    source: String,
    bound: String,
}

const REQUIRED_V1_ROUTES: &[(&str, &str)] = &[
    ("POST", "/v1/sources:discover"),
    ("POST", "/v1/catalog:ingest"),
    ("GET", "/v1/catalog/sources/{source_id}"),
    ("POST", "/v1/catalog:query"),
    ("POST", "/v1/catalog/atoms:batch"),
    ("POST", "/v1/catalog/atoms/{atom_id}:tombstone"),
    ("POST", "/v1/context/plans"),
    ("POST", "/v1/context/bundles:compile"),
    ("POST", "/v1/context/deltas:compile"),
    ("GET", "/v1/context/bundles/{bundle_id}"),
    ("GET", "/v1/context/bundles/{bundle_id}/manifest"),
    ("POST", "/v1/context/bundles/{bundle_id}:explain"),
    ("POST", "/v1/context/bundles/{bundle_id}:materialize"),
    ("POST", "/v1/context/bundles/{bundle_id}:revalidate"),
    ("POST", "/v1/spaces"),
    ("POST", "/v1/spaces/{space_id}:fork"),
    ("POST", "/v1/spaces/{space_id}:publish"),
    ("GET", "/v1/spaces/{space_id}/log"),
    ("GET", "/v1/spaces/{space_id}/events"),
    ("POST", "/v1/spaces/{space_id}/checkpoints"),
    ("GET", "/v1/spaces/{space_id}/conflicts"),
    (
        "POST",
        "/v1/spaces/{space_id}/conflicts/{conflict_id}:resolve",
    ),
    ("POST", "/v1/handoffs"),
    ("POST", "/v1/handoffs/{handoff_id}:preview"),
    ("POST", "/v1/handoffs/{handoff_id}:accept"),
    ("POST", "/v1/handoffs/{handoff_id}:revoke"),
    ("POST", "/v1/handoffs/{handoff_id}/results"),
    ("POST", "/v1/handoffs/{handoff_id}:merge"),
    ("POST", "/v1/effects"),
    ("POST", "/v1/effects/{effect_id}:authorize"),
    ("POST", "/v1/effects/{effect_id}:dispatch"),
    ("GET", "/v1/effects/{effect_id}"),
    ("POST", "/v1/effects/{effect_id}:reconcile"),
    ("POST", "/v1/effects/{effect_id}:compensate"),
    ("POST", "/v1/replays"),
    ("POST", "/v1/replays/{replay_id}:run"),
    ("POST", "/v1/replays/{replay_id}:compare"),
    ("GET", "/v1/replays/{replay_id}/completeness"),
    ("GET", "/livez"),
    ("GET", "/readyz"),
    ("GET", "/v1/version"),
    ("GET", "/v1/capabilities"),
    ("GET", "/v1/configuration"),
    ("GET", "/v1/diagnostics"),
    ("GET", "/metrics"),
];

/// Failure produced by a workspace task.
#[derive(Debug)]
pub struct TaskError {
    message: String,
}

impl TaskError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TaskError {}

impl From<io::Error> for TaskError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Executes one xtask command from an argument iterator.
pub fn run(arguments: impl IntoIterator<Item = String>) -> Result<(), TaskError> {
    let mut arguments = arguments.into_iter();
    let Some(command) = arguments.next() else {
        return Err(TaskError::new(usage()));
    };
    let rest: Vec<String> = arguments.collect();
    let root = workspace_root()?;

    match command.as_str() {
        "bootstrap" => bootstrap(&root),
        "generate" => generate(&root, has_flag(&rest, "--check")),
        "vectors" => vectors(&root, &rest),
        "fmt" => format_workspace(&root, has_flag(&rest, "--check")),
        "lint" => lint(&root),
        "architecture-check" => architecture_check(&root),
        "conformance" => conformance(&root, &rest),
        "test" => test(&root, &rest),
        "docs" => docs(&root),
        "bench" => unavailable("bench", "WP20"),
        "package" => unavailable("package", "WP21"),
        "release-verify" => unavailable("release-verify", "WP21"),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        unknown => Err(TaskError::new(format!(
            "unknown xtask command `{unknown}`\n{}",
            usage()
        ))),
    }
}

fn usage() -> &'static str {
    "usage: cargo xtask <bootstrap|generate|vectors|fmt|lint|architecture-check|conformance|test|docs|bench|package|release-verify>"
}

fn workspace_root() -> Result<PathBuf, TaskError> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_directory
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| TaskError::new("xtask is not located under <workspace>/crates/xtask"))
}

fn has_flag(arguments: &[String], flag: &str) -> bool {
    arguments.iter().any(|argument| argument == flag)
}

fn unavailable(command: &str, packet: &str) -> Result<(), TaskError> {
    Err(TaskError::new(format!(
        "`cargo xtask {command}` is intentionally unavailable until {packet}; no placeholder success was returned"
    )))
}

#[derive(Clone, Copy)]
struct Tool<'a> {
    name: &'a str,
    program: &'a str,
    arguments: &'a [&'a str],
    expected: &'a str,
    install: &'a str,
    required: bool,
}

fn bootstrap(root: &Path) -> Result<(), TaskError> {
    let tools = [
        Tool {
            name: "Rust",
            program: "rustc",
            arguments: &["--version"],
            expected: "1.92.0",
            install: "https://rustup.rs",
            required: true,
        },
        Tool {
            name: "Cargo",
            program: "cargo",
            arguments: &["--version"],
            expected: "1.92.0",
            install: "https://rustup.rs",
            required: true,
        },
        Tool {
            name: "Node",
            program: "node",
            arguments: &["--version"],
            expected: "24.10.0",
            install: "https://nodejs.org/download",
            required: true,
        },
        Tool {
            name: "pnpm",
            program: "corepack",
            arguments: &["pnpm", "--version"],
            expected: "10.34.5",
            install: "https://pnpm.io/installation",
            required: true,
        },
        Tool {
            name: "Python",
            program: "python3",
            arguments: &["--version"],
            expected: "3.14.6",
            install: "https://www.python.org/downloads/",
            required: true,
        },
        Tool {
            name: "uv",
            program: "uv",
            arguments: &["--version"],
            expected: "0.11.8",
            install: "https://docs.astral.sh/uv/getting-started/installation/",
            required: true,
        },
        Tool {
            name: "Go",
            program: "go",
            arguments: &["version"],
            expected: "1.26.3",
            install: "https://go.dev/doc/install",
            required: true,
        },
        Tool {
            name: "Protobuf",
            program: "protoc",
            arguments: &["--version"],
            expected: "33.2",
            install: "https://protobuf.dev/installation/",
            required: true,
        },
        Tool {
            name: "SQLite",
            program: "sqlite3",
            arguments: &["--version"],
            expected: "3.43.2",
            install: "https://sqlite.org/download.html",
            required: true,
        },
        Tool {
            name: "Git",
            program: "git",
            arguments: &["--version"],
            expected: "2.",
            install: "https://git-scm.com/downloads",
            required: true,
        },
        Tool {
            name: "OpenSSL",
            program: "openssl",
            arguments: &["version"],
            expected: "3.6.2",
            install: "https://openssl-library.org/source/",
            required: true,
        },
        Tool {
            name: "Docker",
            program: "docker",
            arguments: &["--version"],
            expected: "Docker version",
            install: "https://docs.docker.com/engine/install/",
            required: false,
        },
        Tool {
            name: "cargo-nextest",
            program: "cargo",
            arguments: &["nextest", "--version"],
            expected: "cargo-nextest 0.9.140",
            install: "https://nexte.st/docs/installation/",
            required: true,
        },
        Tool {
            name: "cargo-deny",
            program: "cargo",
            arguments: &["deny", "--version"],
            expected: "cargo-deny 0.20.2",
            install: "https://embarkstudios.github.io/cargo-deny/",
            required: true,
        },
        Tool {
            name: "cargo-llvm-cov",
            program: "cargo",
            arguments: &["llvm-cov", "--version"],
            expected: "cargo-llvm-cov 0.8.7",
            install: "https://github.com/taiki-e/cargo-llvm-cov",
            required: true,
        },
        Tool {
            name: "just",
            program: "just",
            arguments: &["--version"],
            expected: "just 1.56.0",
            install: "https://just.systems/man/en/packages.html",
            required: true,
        },
        Tool {
            name: "protoc-gen-prost",
            program: "protoc-gen-prost",
            arguments: &["--version"],
            expected: "0.5.0",
            install: "cargo install --locked protoc-gen-prost@0.5.0",
            required: true,
        },
    ];

    let mut missing = Vec::new();
    for tool in tools {
        match inspect_tool(tool) {
            Ok(version) => println!("ok: {}: {}", tool.name, version.trim()),
            Err(error) if tool.required => missing.push(error.to_string()),
            Err(error) => eprintln!("warning: optional {error}"),
        }
    }
    inspect_wire_generators(root, &mut missing);
    if !missing.is_empty() {
        return Err(TaskError::new(format!(
            "bootstrap requirements failed:\n- {}",
            missing.join("\n- ")
        )));
    }

    validate_lockfiles(root)?;
    generate(root, true)?;
    architecture_check(root)?;
    initialize_bootstrap_fixtures(root)?;
    println!("bootstrap complete; next: cargo xtask test unit");
    Ok(())
}

fn initialize_bootstrap_fixtures(root: &Path) -> Result<(), TaskError> {
    let directory = root.join(".tmp/bootstrap");
    fs::create_dir_all(&directory)?;
    let key = directory.join("test-key.pem");
    let certificate = directory.join("test-certificate.pem");
    if !key.is_file() || !certificate.is_file() {
        run_command(
            root,
            "openssl",
            &[
                OsString::from("req"),
                OsString::from("-x509"),
                OsString::from("-newkey"),
                OsString::from("rsa:2048"),
                OsString::from("-keyout"),
                key.into_os_string(),
                OsString::from("-out"),
                certificate.into_os_string(),
                OsString::from("-nodes"),
                OsString::from("-subj"),
                OsString::from("/CN=cigar-hermetic-test.invalid"),
                OsString::from("-days"),
                OsString::from("1"),
            ],
        )?;
    }
    let database = directory.join("fixture.db");
    run_command(
        root,
        "sqlite3",
        &[
            database.into_os_string(),
            OsString::from("PRAGMA user_version=0; VACUUM;"),
        ],
    )?;
    println!(
        "initialized hermetic bootstrap fixtures in {}",
        directory.display()
    );
    Ok(())
}

fn inspect_tool(tool: Tool<'_>) -> Result<String, TaskError> {
    let output = Command::new(tool.program).args(tool.arguments).output();
    let output = output.map_err(|error| {
        TaskError::new(format!(
            "{} is missing ({error}); expected {}, install: {}",
            tool.name, tool.expected, tool.install
        ))
    })?;
    let combined = combined_output(&output);
    if !output.status.success() {
        return Err(TaskError::new(format!(
            "{} could not run successfully; expected {}, install: {}; output: {}",
            tool.name,
            tool.expected,
            tool.install,
            combined.trim()
        )));
    }
    if !combined.contains(tool.expected) {
        return Err(TaskError::new(format!(
            "{} version mismatch; expected {}, install: {}; found: {}",
            tool.name,
            tool.expected,
            tool.install,
            combined.trim()
        )));
    }
    Ok(combined)
}

fn combined_output(output: &Output) -> String {
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

fn inspect_wire_generators(root: &Path, missing: &mut Vec<String>) {
    let go_plugin = go_plugin_path(root);
    match go_plugin.and_then(|path| {
        inspect_generator(
            root,
            "protoc-gen-go",
            &path,
            &["--version"],
            "1.36.11",
            "go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11",
        )
    }) {
        Ok(version) => println!("ok: protoc-gen-go: {}", version.trim()),
        Err(error) => missing.push(error.to_string()),
    }

    let go_grpc_plugin = go_grpc_plugin_path(root);
    match go_grpc_plugin.and_then(|path| {
        inspect_generator(
            root,
            "protoc-gen-go-grpc",
            &path,
            &["--version"],
            "1.6.2",
            "go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2",
        )
    }) {
        Ok(version) => println!("ok: protoc-gen-go-grpc: {}", version.trim()),
        Err(error) => missing.push(error.to_string()),
    }

    let es_plugin = root.join("sdk/typescript/node_modules/.bin/protoc-gen-es");
    match inspect_generator(
        root,
        "protoc-gen-es",
        &es_plugin,
        &["--version"],
        "2.12.1",
        "corepack pnpm install --frozen-lockfile",
    ) {
        Ok(version) => println!("ok: protoc-gen-es: {}", version.trim()),
        Err(error) => missing.push(error.to_string()),
    }
}

fn inspect_generator(
    root: &Path,
    name: &str,
    program: &Path,
    arguments: &[&str],
    expected: &str,
    install: &str,
) -> Result<String, TaskError> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| {
            TaskError::new(format!(
                "{name} is missing ({error}); expected {expected}, install: {install}"
            ))
        })?;
    let combined = combined_output(&output);
    if !output.status.success() || !combined.contains(expected) {
        return Err(TaskError::new(format!(
            "{name} version mismatch; expected {expected}, install: {install}; found: {}",
            combined.trim()
        )));
    }
    Ok(combined)
}

fn go_plugin_path(root: &Path) -> Result<PathBuf, TaskError> {
    go_binary_path(root, "protoc-gen-go")
}

fn go_grpc_plugin_path(root: &Path) -> Result<PathBuf, TaskError> {
    go_binary_path(root, "protoc-gen-go-grpc")
}

fn go_binary_path(root: &Path, binary: &str) -> Result<PathBuf, TaskError> {
    let output = Command::new("go")
        .args(["env", "GOPATH"])
        .current_dir(root)
        .output()
        .map_err(|error| TaskError::new(format!("failed to locate GOPATH: {error}")))?;
    if !output.status.success() {
        return Err(TaskError::new(format!(
            "failed to locate GOPATH: {}",
            combined_output(&output).trim()
        )));
    }
    let gopath = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok(PathBuf::from(gopath).join("bin").join(binary))
}

fn validate_lockfiles(root: &Path) -> Result<(), TaskError> {
    for lock in ["Cargo.lock", "pnpm-lock.yaml", "uv.lock"] {
        if !root.join(lock).is_file() {
            return Err(TaskError::new(format!(
                "required lockfile `{lock}` is missing; generate it with its pinned package manager"
            )));
        }
    }
    Ok(())
}

fn generate(root: &Path, check: bool) -> Result<(), TaskError> {
    generate_schema_artifacts(root, check)?;
    generate_error_artifacts(root, check)?;
    generate_operation_artifacts(root, check)?;
    generate_wire_artifacts(root, check)?;
    generate_sdk_artifacts(root, check)?;
    if check {
        println!("generated artifacts are current");
    }
    Ok(())
}

fn generate_sdk_artifacts(root: &Path, check: bool) -> Result<(), TaskError> {
    let mut arguments = vec![OsString::from("sdk/generate_clients.py")];
    if check {
        arguments.push(OsString::from("--check"));
    }
    run_command(root, "python3", &arguments)
}

#[derive(Serialize)]
struct CanonicalVectorManifest {
    schema_version: u8,
    profile: &'static str,
    generator: &'static str,
    valid_count: usize,
    invalid_count: usize,
    valid: Vec<CanonicalVector>,
    invalid: Vec<InvalidCanonicalVector>,
    differential: DifferentialVector,
}

#[derive(Serialize)]
struct CanonicalVector {
    id: String,
    target: String,
    category: String,
    semantic_valid: bool,
    domain: &'static str,
    normalization: &'static str,
    json_input: String,
    normalized_json: String,
    cbor_hex: String,
    digest_hex: String,
    multihash: String,
    signature_input_hex: String,
}

#[derive(Serialize)]
struct InvalidCanonicalVector {
    id: &'static str,
    encoding: &'static str,
    input: &'static str,
    error: &'static str,
}

#[derive(Serialize)]
struct DifferentialVector {
    algorithm: &'static str,
    count: u32,
    domain: &'static str,
    digest_accumulator_hex: String,
}

fn vectors(root: &Path, arguments: &[String]) -> Result<(), TaskError> {
    let action = arguments.first().map(String::as_str).unwrap_or("check");
    let expected = render_canonical_vectors()?;
    let target = root.join("schemas/vectors/canonical-v1.json");
    match action {
        "update" => {
            let parent = target
                .parent()
                .ok_or_else(|| TaskError::new("canonical vector path has no parent"))?;
            fs::create_dir_all(parent)?;
            fs::write(&target, expected)?;
            println!("updated {}", target.display());
            Ok(())
        }
        "check" => {
            let actual = fs::read_to_string(&target).map_err(|error| {
                TaskError::new(format!(
                    "canonical vectors are missing or unreadable ({error}); run `cargo xtask vectors update`"
                ))
            })?;
            if actual == expected {
                println!("canonical vectors are current");
                Ok(())
            } else {
                Err(TaskError::new(
                    "canonical vectors are stale; run `cargo xtask vectors update`",
                ))
            }
        }
        _ => Err(TaskError::new("usage: cargo xtask vectors <update|check>")),
    }
}

fn render_canonical_vectors() -> Result<String, TaskError> {
    use cigar_canon::DigestDomain;

    let domains = [
        ("atom", DigestDomain::Atom),
        ("bundle", DigestDomain::Bundle),
        ("manifest", DigestDomain::Manifest),
        ("handoff", DigestDomain::Handoff),
        ("effect", DigestDomain::Effect),
        ("receipt", DigestDomain::Receipt),
        ("extension_manifest", DigestDomain::ExtensionManifest),
    ];
    let mut valid = Vec::new();
    for (index, fixture) in cigar_testkit::protocol_fixtures().into_iter().enumerate() {
        let json_input = serde_json::to_string(&fixture.input)
            .map_err(|error| TaskError::new(format!("failed to render vector input: {error}")))?;
        let (domain_name, domain) = domains
            .get(index % domains.len())
            .copied()
            .ok_or_else(|| TaskError::new("digest domain registry is empty"))?;
        valid.push(build_canonical_vector(
            fixture.id,
            fixture.target,
            fixture.category,
            fixture.expected_valid,
            domain_name,
            domain,
            "none",
            json_input,
        )?);
    }
    for (index, (id, category, normalization, json_input)) in [
        (
            "unicode.nfc.decomposed",
            "unicode_normalization",
            "nfc:/human_text",
            "{\"human_text\":\"e\\u0301\"}",
        ),
        (
            "unicode.nfc.composed",
            "unicode_normalization",
            "nfc:/human_text",
            "{\"human_text\":\"é\"}",
        ),
        (
            "unicode.exact.decomposed",
            "exact_text",
            "none",
            "{\"code\":\"e\\u0301\"}",
        ),
        (
            "unicode.exact.composed",
            "exact_text",
            "none",
            "{\"code\":\"é\"}",
        ),
        (
            "map.order.first",
            "map_permutation",
            "none",
            "{\"b\":2,\"a\":1}",
        ),
        (
            "map.order.second",
            "map_permutation",
            "none",
            "{\"a\":1,\"b\":2}",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (domain_name, domain) = domains
            .get(index % domains.len())
            .copied()
            .ok_or_else(|| TaskError::new("digest domain registry is empty"))?;
        valid.push(build_canonical_vector(
            id.to_owned(),
            "CanonicalProfile".to_owned(),
            category.to_owned(),
            true,
            domain_name,
            domain,
            normalization,
            json_input.to_owned(),
        )?);
    }
    let invalid = invalid_canonical_vectors();
    let manifest = CanonicalVectorManifest {
        schema_version: 1,
        profile: "cigar-canonical-v1",
        generator: "cargo xtask vectors update",
        valid_count: valid.len(),
        invalid_count: invalid.len(),
        valid,
        invalid,
        differential: DifferentialVector {
            algorithm: "cigar-differential-record-v1",
            count: 100_000,
            domain: "atom",
            digest_accumulator_hex: differential_accumulator(100_000)?,
        },
    };
    let mut rendered = serde_json::to_string_pretty(&manifest)
        .map_err(|error| TaskError::new(format!("failed to render canonical vectors: {error}")))?;
    rendered.push('\n');
    Ok(rendered)
}

#[allow(clippy::too_many_arguments)]
fn build_canonical_vector(
    id: String,
    target: String,
    category: String,
    semantic_valid: bool,
    domain_name: &'static str,
    domain: cigar_canon::DigestDomain,
    normalization: &'static str,
    json_input: String,
) -> Result<CanonicalVector, TaskError> {
    let mut node = cigar_canon::parse_strict_json(json_input.as_bytes()).map_err(|error| {
        TaskError::new(format!("fixture `{id}` is not canonical JSON: {error}"))
    })?;
    if normalization == "nfc:/human_text" {
        let cigar_canon::CanonicalNode::Map(fields) = &mut node else {
            return Err(TaskError::new("NFC vector is not an object"));
        };
        let Some(cigar_canon::CanonicalNode::Text(value)) = fields.get_mut("human_text") else {
            return Err(TaskError::new("NFC vector has no human_text field"));
        };
        *value = cigar_canon::normalize_nfc(value);
    }
    let normalized = cigar_canon::to_normalized_json(&node)
        .map_err(|error| TaskError::new(format!("fixture `{id}` JSON failed: {error}")))?;
    let cbor = cigar_canon::to_deterministic_cbor(&node)
        .map_err(|error| TaskError::new(format!("fixture `{id}` CBOR failed: {error}")))?;
    let digest = cigar_canon::digest_v1(domain, &cbor);
    let mut signature_input = b"CIGAR-SIGNATURE\0v1\0".to_vec();
    signature_input.extend_from_slice(&cbor);
    Ok(CanonicalVector {
        id,
        target,
        category,
        semantic_valid,
        domain: domain_name,
        normalization,
        json_input,
        normalized_json: String::from_utf8(normalized)
            .map_err(|error| TaskError::new(format!("normalized JSON is not UTF-8: {error}")))?,
        cbor_hex: lower_hex(&cbor),
        digest_hex: lower_hex(&digest),
        multihash: cigar_canon::multihash_v1(domain, &cbor),
        signature_input_hex: lower_hex(&signature_input),
    })
}

fn invalid_canonical_vectors() -> Vec<InvalidCanonicalVector> {
    vec![
        InvalidCanonicalVector {
            id: "json.duplicate",
            encoding: "json",
            input: "{\"a\":1,\"a\":2}",
            error: "duplicate_key",
        },
        InvalidCanonicalVector {
            id: "json.null",
            encoding: "json",
            input: "{\"a\":null}",
            error: "null_forbidden",
        },
        InvalidCanonicalVector {
            id: "json.float",
            encoding: "json",
            input: "{\"a\":1.5}",
            error: "float_forbidden",
        },
        InvalidCanonicalVector {
            id: "json.trailing",
            encoding: "json",
            input: "{} {}",
            error: "invalid_input",
        },
        InvalidCanonicalVector {
            id: "json.overflow",
            encoding: "json",
            input: "18446744073709551616",
            error: "float_forbidden",
        },
        InvalidCanonicalVector {
            id: "cbor.non_shortest",
            encoding: "cbor_hex",
            input: "1800",
            error: "non_canonical",
        },
        InvalidCanonicalVector {
            id: "cbor.indefinite",
            encoding: "cbor_hex",
            input: "9f01ff",
            error: "non_canonical",
        },
        InvalidCanonicalVector {
            id: "cbor.misordered_map",
            encoding: "cbor_hex",
            input: "a2616201616102",
            error: "non_canonical",
        },
        InvalidCanonicalVector {
            id: "cbor.duplicate_map",
            encoding: "cbor_hex",
            input: "a2616101616102",
            error: "non_canonical",
        },
        InvalidCanonicalVector {
            id: "cbor.float",
            encoding: "cbor_hex",
            input: "f93c00",
            error: "float_forbidden",
        },
        InvalidCanonicalVector {
            id: "cbor.null",
            encoding: "cbor_hex",
            input: "f6",
            error: "null_forbidden",
        },
        InvalidCanonicalVector {
            id: "cbor.tag",
            encoding: "cbor_hex",
            input: "c001",
            error: "non_canonical",
        },
        InvalidCanonicalVector {
            id: "cbor.trailing",
            encoding: "cbor_hex",
            input: "0001",
            error: "non_canonical",
        },
        InvalidCanonicalVector {
            id: "semantic.unknown_discriminant",
            encoding: "semantic",
            input: "__unknown_variant__",
            error: "invalid_argument",
        },
        InvalidCanonicalVector {
            id: "signature.malformed",
            encoding: "signature_hex",
            input: "00",
            error: "invalid_argument",
        },
    ]
}

fn differential_accumulator(count: u32) -> Result<String, TaskError> {
    use cigar_canon::{CanonicalNode, DigestDomain, digest_v1, to_deterministic_cbor};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let mut accumulator = Sha256::new();
    for index in 0..count {
        let mut record = BTreeMap::new();
        record.insert("active".to_owned(), CanonicalNode::Boolean(index % 2 == 0));
        record.insert(
            "index".to_owned(),
            CanonicalNode::Unsigned(u64::from(index)),
        );
        record.insert(
            "label".to_owned(),
            CanonicalNode::Text(format!("record-{}", index % 997)),
        );
        record.insert(
            "values".to_owned(),
            CanonicalNode::Array(vec![
                CanonicalNode::Unsigned(u64::from(index % 17)),
                CanonicalNode::Negative(-i64::from(index % 19) - 1),
            ]),
        );
        let cbor = to_deterministic_cbor(&CanonicalNode::Map(record))
            .map_err(|error| TaskError::new(format!("differential record failed: {error}")))?;
        accumulator.update(digest_v1(DigestDomain::Atom, &cbor));
    }
    Ok(lower_hex(&accumulator.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn generate_error_artifacts(root: &Path, check: bool) -> Result<(), TaskError> {
    let source = fs::read_to_string(root.join("spec/errors/catalog.yaml"))?;
    let catalog: ErrorCatalog = yaml_serde::from_str(&source)
        .map_err(|error| TaskError::new(format!("invalid error catalog YAML: {error}")))?;
    validate_error_catalog(&catalog)?;
    let artifacts = vec![
        (
            PathBuf::from("crates/cigar-protocol/src/generated/error_registry.rs"),
            render_rust_error_registry(&catalog),
        ),
        (
            PathBuf::from("schemas/proto/generated/error_codes.proto"),
            render_proto_error_registry(&catalog),
        ),
        (
            PathBuf::from("schemas/openapi/error-registry-v1.json"),
            render_openapi_error_registry(&catalog)?,
        ),
    ];
    synchronize_rendered_artifacts(root, check, artifacts)
}

fn synchronize_rendered_artifacts(
    root: &Path,
    check: bool,
    artifacts: Vec<(PathBuf, String)>,
) -> Result<(), TaskError> {
    for (relative_path, expected) in artifacts {
        let target = root.join(&relative_path);
        if check {
            let actual = fs::read_to_string(&target).map_err(|error| {
                TaskError::new(format!(
                    "generated artifact `{}` is missing or unreadable ({error}); run `cargo xtask generate`",
                    target.display()
                ))
            })?;
            if actual != expected {
                return Err(TaskError::new(format!(
                    "generated artifact `{}` is stale; run `cargo xtask generate`",
                    target.display()
                )));
            }
        } else {
            let parent = target
                .parent()
                .ok_or_else(|| TaskError::new("generated artifact has no parent directory"))?;
            fs::create_dir_all(parent)?;
            fs::write(&target, expected)?;
            println!("generated {}", target.display());
        }
    }
    Ok(())
}

fn validate_error_catalog(catalog: &ErrorCatalog) -> Result<(), TaskError> {
    if catalog.schema_version != 1 || catalog.status.is_empty() || catalog.errors.len() != 34 {
        return Err(TaskError::new(
            "error catalog must be schema v1 with status and exactly 34 frozen errors",
        ));
    }
    let mut codes = BTreeSet::new();
    let mut names = BTreeSet::new();
    for entry in &catalog.errors {
        let valid_name = !entry.name.is_empty()
            && entry
                .name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
        let valid_retry = matches!(
            entry.retry.as_str(),
            "never" | "safe" | "after_backoff" | "after_reauthorization" | "after_reconciliation"
        );
        if !codes.insert(entry.code)
            || !names.insert(entry.name.as_str())
            || !valid_name
            || !valid_retry
            || !(400..=599).contains(&entry.http)
            || entry.grpc.is_empty()
            || entry.message.is_empty()
            || entry.message.len() > 4_096
            || entry.remediation.is_empty()
            || entry.remediation.len() > 4_096
        {
            return Err(TaskError::new(format!(
                "invalid or duplicate error catalog entry `{}`",
                entry.name
            )));
        }
    }
    Ok(())
}

fn rust_variant(symbol: &str) -> String {
    symbol
        .split('_')
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => first
                    .to_uppercase()
                    .chain(characters.flat_map(char::to_lowercase))
                    .collect(),
                None => String::new(),
            }
        })
        .collect()
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

fn render_rust_error_registry(catalog: &ErrorCatalog) -> String {
    let mut output =
        String::from("// @generated by cargo xtask generate from spec/errors/catalog.yaml.\n\n");
    for entry in &catalog.errors {
        output.push_str(&format!(
            "const {}_DEFINITION: ErrorDefinition = ErrorDefinition {{\n    code: ErrorCode::{},\n    symbol: {},\n    http_status: {},\n    grpc_status: {},\n    retry: RetryClass::{},\n    message: {},\n    remediation: {},\n    disclose_identity: {},\n}};\n",
            entry.name,
            rust_variant(&entry.name),
            rust_string(&entry.name),
            entry.http,
            rust_string(&entry.grpc),
            rust_variant(&entry.retry.to_ascii_uppercase()),
            rust_string(&entry.message),
            rust_string(&entry.remediation),
            entry.disclose_identity,
        ));
    }
    output.push_str("\n/// Complete frozen v1 public error registry.\npub const ERROR_REGISTRY: &[ErrorDefinition] = &[\n");
    for entry in &catalog.errors {
        output.push_str(&format!("    {}_DEFINITION,\n", entry.name));
    }
    output.push_str(
        "];

pub(crate) const fn error_definition(code: ErrorCode) -> &'static ErrorDefinition {
    match code {
",
    );
    for entry in &catalog.errors {
        output.push_str(&format!(
            "        ErrorCode::{} => &{}_DEFINITION,\n",
            rust_variant(&entry.name),
            entry.name
        ));
    }
    output.push_str("    }\n}\n");
    output
}

fn render_proto_error_registry(catalog: &ErrorCatalog) -> String {
    let mut output = String::from(
        "// @generated by cargo xtask generate from spec/errors/catalog.yaml.\nsyntax = \"proto3\";\n\npackage cigar.context.v1;\n\noption go_package = \"github.com/CIGAR/cigar/sdk/go/gen/contextv1;contextv1\";\n\nenum ErrorCode {\n  ERROR_CODE_UNSPECIFIED = 0;\n",
    );
    for entry in &catalog.errors {
        output.push_str(&format!("  ERROR_CODE_{} = {};\n", entry.name, entry.code));
    }
    output.push_str("}\n\nenum RetryClass {\n  RETRY_CLASS_UNSPECIFIED = 0;\n  RETRY_CLASS_NEVER = 1;\n  RETRY_CLASS_SAFE = 2;\n  RETRY_CLASS_AFTER_BACKOFF = 3;\n  RETRY_CLASS_AFTER_REAUTHORIZATION = 4;\n  RETRY_CLASS_AFTER_RECONCILIATION = 5;\n}\n");
    output
}

fn render_openapi_error_registry(catalog: &ErrorCatalog) -> Result<String, TaskError> {
    let mut value = serde_json::to_value(catalog)
        .map_err(|error| TaskError::new(format!("failed to render error registry: {error}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| TaskError::new("error registry did not render as an object"))?;
    object.insert(
        "generator".to_owned(),
        serde_json::Value::String("cargo xtask generate".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&value)
        .map_err(|error| TaskError::new(format!("failed to render error registry: {error}")))?;
    rendered.push('\n');
    Ok(rendered)
}

fn generate_operation_artifacts(root: &Path, check: bool) -> Result<(), TaskError> {
    let catalog = load_operation_catalog(root)?;
    let payloads = load_operation_payload_catalog(root, &catalog)?;
    let artifacts = vec![
        (
            PathBuf::from("schemas/proto/cigar_service.proto"),
            render_operation_proto(&catalog),
        ),
        (
            PathBuf::from("schemas/openapi/cigar-v1.json"),
            render_operation_openapi(&catalog, &payloads)?,
        ),
        (
            PathBuf::from("crates/cigar-api/src/generated/operations.rs"),
            render_rust_operation_registry(&catalog),
        ),
    ];
    synchronize_rendered_artifacts(root, check, artifacts)
}

fn load_operation_payload_catalog(
    root: &Path,
    operations: &OperationCatalog,
) -> Result<OperationPayloadCatalog, TaskError> {
    let source = fs::read_to_string(root.join("spec/api/operation-payloads-v1.json"))?;
    let payloads: OperationPayloadCatalog = serde_json::from_str(&source).map_err(|error| {
        TaskError::new(format!("invalid operation payload catalog JSON: {error}"))
    })?;
    validate_operation_payload_catalog(&payloads, operations)?;
    Ok(payloads)
}

fn validate_operation_payload_catalog(
    payloads: &OperationPayloadCatalog,
    operations: &OperationCatalog,
) -> Result<(), TaskError> {
    if payloads.schema_version != 1
        || payloads.status != "frozen-v1"
        || payloads.operation_count != operations.operation_count
        || payloads.operations.len() != operations.operation_count
        || payloads.envelope_fields.is_empty()
    {
        return Err(TaskError::new(
            "operation payload catalog must contain the complete frozen v1 surface",
        ));
    }
    validate_payload_fields(&payloads.envelope_fields, &["envelope", "transport"])?;
    let envelope_names: BTreeSet<_> = payloads
        .envelope_fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    let required_envelope = BTreeSet::from([
        "dry_run",
        "expected_revision",
        "idempotency_key",
        "page_cursor",
        "page_size",
        "path_parameters",
    ]);
    if envelope_names != required_envelope {
        return Err(TaskError::new(
            "operation payload catalog envelope fields differ from frozen v1",
        ));
    }

    let contracts: BTreeMap<_, _> = operations
        .services
        .iter()
        .flat_map(|service| &service.operations)
        .map(|operation| (operation.operation_id.as_str(), operation))
        .collect();
    let mut seen = BTreeSet::new();
    for payload in &payloads.operations {
        let operation = contracts
            .get(payload.operation_id.as_str())
            .ok_or_else(|| {
                TaskError::new(format!(
                    "payload schema references unknown operation `{}`",
                    payload.operation_id
                ))
            })?;
        if !seen.insert(payload.operation_id.as_str())
            || !valid_schema_name(&payload.request_schema)
            || !valid_schema_name(&payload.response_schema)
            || payload
                .event_schema
                .as_deref()
                .is_some_and(|schema| !valid_schema_name(schema))
            || payload.request_max_bytes == 0
            || payload.request_max_bytes > 16 * 1024 * 1024
            || payload.response_max_bytes == 0
            || payload.response_max_bytes > 16 * 1024 * 1024
        {
            return Err(TaskError::new(format!(
                "invalid payload schema metadata for `{}`",
                payload.operation_id
            )));
        }
        let streaming = operation.stream_kind == "server_stream";
        if streaming != payload.event_schema.is_some()
            || (streaming && payload.event_max_bytes != 1024 * 1024)
            || (!streaming && payload.event_max_bytes != 0)
            || streaming == payload.event_fields.is_empty()
        {
            return Err(TaskError::new(format!(
                "event payload metadata disagrees with `{}`",
                payload.operation_id
            )));
        }
        validate_payload_fields(&payload.request_fields, &["caller", "path"])?;
        validate_payload_fields(&payload.response_fields, &["server"])?;
        validate_payload_fields(&payload.event_fields, &["server"])?;
        let declared_paths: BTreeSet<_> = payload
            .request_fields
            .iter()
            .filter(|field| field.source == "path")
            .map(|field| field.name.as_str())
            .collect();
        let expected_paths: BTreeSet<_> = path_parameter_names(&operation.http_path)
            .into_iter()
            .collect();
        if declared_paths != expected_paths {
            return Err(TaskError::new(format!(
                "payload path fields disagree with `{}`",
                payload.operation_id
            )));
        }
        if payload.request_fields.iter().any(|field| {
            matches!(
                field.name.as_str(),
                "tenant_id"
                    | "principal_id"
                    | "effective_capabilities"
                    | "policy_decision"
                    | "access_context"
                    | "clock"
                    | "event_id"
                    | "connector_registry"
                    | "dispatch_permit"
            )
        }) {
            return Err(TaskError::new(format!(
                "payload `{}` exposes a server-owned authority field",
                payload.operation_id
            )));
        }
    }
    if seen.len() != contracts.len() {
        return Err(TaskError::new(
            "operation payload catalog does not cover every frozen operation",
        ));
    }
    Ok(())
}

fn validate_payload_fields(
    fields: &[PayloadField],
    allowed_sources: &[&str],
) -> Result<(), TaskError> {
    let mut names = BTreeSet::new();
    for field in fields {
        if !valid_field_name(&field.name)
            || !names.insert(field.name.as_str())
            || !allowed_sources.contains(&field.source.as_str())
            || field.bound.is_empty()
            || field.bound.len() > 256
        {
            return Err(TaskError::new("invalid payload field metadata"));
        }
    }
    Ok(())
}

fn valid_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_schema_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn load_operation_catalog(root: &Path) -> Result<OperationCatalog, TaskError> {
    let source = fs::read_to_string(root.join("spec/api/operations-v1.json"))?;
    let catalog: OperationCatalog = serde_json::from_str(&source)
        .map_err(|error| TaskError::new(format!("invalid operation catalog JSON: {error}")))?;
    validate_operation_catalog(&catalog)?;
    Ok(catalog)
}

fn validate_operation_catalog(catalog: &OperationCatalog) -> Result<(), TaskError> {
    if catalog.schema_version != 1
        || catalog.status != "frozen-v1"
        || catalog.package != "cigar.v1"
        || catalog.http_base != "/v1"
        || catalog.operation_count != 45
        || catalog.services.len() != 7
    {
        return Err(TaskError::new(
            "operation catalog must be the frozen v1 package with 7 services and 45 operations",
        ));
    }

    let expected_routes: BTreeSet<String> = REQUIRED_V1_ROUTES
        .iter()
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    let mut service_names = BTreeSet::new();
    let mut routes = BTreeSet::new();
    let mut rpc_names = BTreeSet::new();
    let mut operation_ids = BTreeSet::new();
    let mut operation_count = 0_usize;

    for service in &catalog.services {
        if service.name.is_empty()
            || !service.name.ends_with("Service")
            || !service_names.insert(service.name.as_str())
            || service.operations.is_empty()
        {
            return Err(TaskError::new(format!(
                "invalid or duplicate operation service `{}`",
                service.name
            )));
        }
        for operation in &service.operations {
            operation_count = operation_count.saturating_add(1);
            let route = format!("{} {}", operation.http_method, operation.http_path);
            let lower_camel = lower_camel_rpc(&operation.rpc)
                .ok_or_else(|| TaskError::new(format!("invalid RPC name `{}`", operation.rpc)))?;
            let valid_method = matches!(operation.http_method.as_str(), "GET" | "POST");
            let valid_idempotency = if operation.mutation {
                operation.idempotency_requirement == "required"
            } else {
                operation.idempotency_requirement == "not_applicable"
            };
            let valid_revision =
                matches!(operation.revision_requirement.as_str(), "none" | "required")
                    && (operation.mutation || operation.revision_requirement == "none");
            let valid_stream = matches!(operation.stream_kind.as_str(), "unary" | "server_stream");
            let valid_auth = matches!(
                operation.auth_class.as_str(),
                "tenant" | "operator" | "health" | "anonymous"
            );
            if !routes.insert(route)
                || !rpc_names.insert(operation.rpc.as_str())
                || !operation_ids.insert(operation.operation_id.as_str())
                || operation.operation_id != lower_camel
                || !valid_method
                || !valid_idempotency
                || !valid_revision
                || !valid_stream
                || !valid_auth
                || !valid_http_path(&operation.http_path)
            {
                return Err(TaskError::new(format!(
                    "invalid or duplicate operation `{}`",
                    operation.rpc
                )));
            }
        }
    }

    if operation_count != catalog.operation_count || routes != expected_routes {
        return Err(TaskError::new(
            "operation catalog route set differs from the exact required v1 surface",
        ));
    }
    Ok(())
}

fn lower_camel_rpc(rpc: &str) -> Option<String> {
    let mut characters = rpc.chars();
    let first = characters.next()?;
    if !first.is_ascii_uppercase()
        || !characters
            .clone()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return None;
    }
    let mut lower_camel = String::with_capacity(rpc.len());
    lower_camel.push(first.to_ascii_lowercase());
    lower_camel.extend(characters);
    Some(lower_camel)
}

fn valid_http_path(path: &str) -> bool {
    if !path.starts_with('/') || path.len() > 512 || path.contains(char::is_whitespace) {
        return false;
    }
    let mut depth = 0_u8;
    for character in path.chars() {
        match character {
            '{' if depth == 0 => depth = 1,
            '}' if depth == 1 => depth = 0,
            '{' | '}' => return false,
            _ => {}
        }
    }
    depth == 0
}

fn render_operation_proto(catalog: &OperationCatalog) -> String {
    let mut output = String::from(
        "// @generated by cargo xtask generate from spec/api/operations-v1.json.\n\
syntax = \"proto3\";\n\n\
package cigar.v1;\n\n\
option go_package = \"github.com/CIGAR/cigar/sdk/go/gen/cigarv1;cigarv1\";\n\n\
// One bounded path binding. Repeated bindings are sorted uniquely by name.\n\
message PathParameter {\n\
  string name = 1; // 1..64 lowercase snake-case ASCII characters.\n\
  string value = 2; // 1..256 unreserved ASCII characters.\n\
}\n\n\
// Generic bounded transport request. Services validate operation-specific CBOR.\n\
message OperationRequest {\n\
  string operation_id = 1; // 1..128 ASCII characters.\n\
  string idempotency_key = 2; // At most 256 characters.\n\
  string expected_revision = 3; // At most 256 characters.\n\
  bytes payload_cbor = 4; // At most 16 MiB after decompression.\n\
  string page_cursor = 5; // At most 4096 characters.\n\
  uint32 page_size = 6; // Server-capped at 1000.\n\
  repeated PathParameter path_parameters = 7; // At most 8, sorted uniquely by name.\n\
  bool dry_run = 8; // Requests a governed preview; execution policy remains service-owned.\n\
}\n\n\
// Generic bounded transport response. Protected payloads remain canonical CBOR.\n\
message OperationResponse {\n\
  string operation_id = 1; // 1..128 ASCII characters.\n\
  bytes payload_cbor = 2; // At most 16 MiB.\n\
  string semantic_etag = 3; // At most 256 characters.\n\
  string next_page_cursor = 4; // At most 4096 characters.\n\
}\n\n\
// Generic bounded server-stream event with resumable identity.\n\
message OperationEvent {\n\
  string operation_id = 1; // 1..128 ASCII characters.\n\
  string event_id = 2; // At most 256 characters.\n\
  bytes payload_cbor = 3; // At most 1 MiB per event.\n\
}\n",
    );
    for service in &catalog.services {
        output.push_str(&format!("\nservice {} {{\n", service.name));
        for operation in &service.operations {
            let response = if operation.stream_kind == "server_stream" {
                "stream OperationEvent"
            } else {
                "OperationResponse"
            };
            output.push_str(&format!(
                "  // {} {} | operation_id={} | mutation={} | idempotency={} | revision={} | auth={}\n  rpc {}(OperationRequest) returns ({});\n",
                operation.http_method,
                operation.http_path,
                operation.operation_id,
                operation.mutation,
                operation.idempotency_requirement,
                operation.revision_requirement,
                operation.auth_class,
                operation.rpc,
                response,
            ));
        }
        output.push_str("}\n");
    }
    output
}

fn render_operation_openapi(
    catalog: &OperationCatalog,
    payloads: &OperationPayloadCatalog,
) -> Result<String, TaskError> {
    let payload_by_operation: BTreeMap<_, _> = payloads
        .operations
        .iter()
        .map(|payload| (payload.operation_id.as_str(), payload))
        .collect();
    let mut paths = serde_json::Map::new();
    for service in &catalog.services {
        for operation in &service.operations {
            let payload = payload_by_operation
                .get(operation.operation_id.as_str())
                .ok_or_else(|| TaskError::new("validated payload mapping disappeared"))?;
            let mut parameters = Vec::new();
            for name in path_parameter_names(&operation.http_path) {
                parameters.push(serde_json::json!({
                    "in": "path",
                    "name": name,
                    "required": true,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 256 }
                }));
            }
            if operation.idempotency_requirement == "required" {
                parameters.push(serde_json::json!({
                    "in": "header",
                    "name": "Idempotency-Key",
                    "required": true,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 256 }
                }));
            }
            if operation.revision_requirement == "required" {
                parameters.push(serde_json::json!({
                    "in": "header",
                    "name": "If-Match",
                    "required": true,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 256 }
                }));
            }
            let response_schema = if operation.stream_kind == "server_stream" {
                serde_json::json!({
                    "description": "Bounded resumable event stream",
                    "content": {
                        "text/event-stream": {
                            "schema": { "$ref": "#/components/schemas/OperationEvent" }
                        }
                    }
                })
            } else {
                serde_json::json!({
                    "description": "Successful bounded response",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/OperationResponse" }
                        }
                    }
                })
            };
            let security = match operation.auth_class.as_str() {
                "tenant" => serde_json::json!([{ "tenantBearer": [] }]),
                "operator" => serde_json::json!([{ "operatorBearer": [] }]),
                _ => serde_json::json!([]),
            };
            let mut definition = serde_json::json!({
                "operationId": operation.operation_id,
                "tags": [service.name],
                "parameters": parameters,
                "security": security,
                "responses": {
                    "200": response_schema,
                    "default": {
                        "description": "Stable CIGAR problem response",
                        "content": {
                            "application/problem+json": {
                                "schema": { "$ref": "#/components/schemas/Problem" }
                            }
                        }
                    }
                },
                "x-cigar-rpc": operation.rpc,
                "x-cigar-service": service.name,
                "x-cigar-mutation": operation.mutation,
                "x-cigar-idempotency-requirement": operation.idempotency_requirement,
                "x-cigar-revision-requirement": operation.revision_requirement,
                "x-cigar-stream-kind": operation.stream_kind,
                "x-cigar-auth-class": operation.auth_class
            });
            let object = definition
                .as_object_mut()
                .ok_or_else(|| TaskError::new("OpenAPI operation did not render as an object"))?;
            object.insert(
                "x-cigar-request-schema".to_owned(),
                serde_json::Value::String(payload.request_schema.clone()),
            );
            object.insert(
                "x-cigar-response-schema".to_owned(),
                serde_json::Value::String(payload.response_schema.clone()),
            );
            if let Some(event_schema) = &payload.event_schema {
                object.insert(
                    "x-cigar-event-schema".to_owned(),
                    serde_json::Value::String(event_schema.clone()),
                );
            }
            if operation.http_method == "POST" {
                object.insert(
                    "requestBody".to_owned(),
                    serde_json::json!({
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/OperationRequest" }
                            }
                        }
                    }),
                );
            }
            let path_item = paths
                .entry(operation.http_path.clone())
                .or_insert_with(|| serde_json::json!({}));
            let path_object = path_item
                .as_object_mut()
                .ok_or_else(|| TaskError::new("OpenAPI path item did not render as an object"))?;
            path_object.insert(operation.http_method.to_ascii_lowercase(), definition);
        }
    }

    let tags: Vec<serde_json::Value> = catalog
        .services
        .iter()
        .map(|service| serde_json::json!({ "name": service.name }))
        .collect();
    let value = serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "CIGAR Service API",
            "version": "1.0.0",
            "description": "Generated frozen v1 operation surface; payload bytes are bounded and operation-specific."
        },
        "tags": tags,
        "paths": paths,
        "components": {
            "securitySchemes": {
                "tenantBearer": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT or local token" },
                "operatorBearer": { "type": "http", "scheme": "bearer", "bearerFormat": "operator JWT or local token" }
            },
            "schemas": {
                "OperationRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "maxProperties": 8,
                    "required": ["operation_id", "payload_cbor", "path_parameters"],
                    "properties": {
                        "operation_id": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "idempotency_key": { "type": "string", "maxLength": 256 },
                        "expected_revision": { "type": "string", "maxLength": 256 },
                        "payload_cbor": { "type": "string", "contentEncoding": "base64url", "maxLength": 22369622 },
                        "page_cursor": { "type": "string", "maxLength": 4096 },
                        "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                        "dry_run": { "type": "boolean", "default": false },
                        "path_parameters": {
                            "type": "array",
                            "maxItems": 8,
                            "items": { "$ref": "#/components/schemas/PathParameter" }
                        }
                    }
                },
                "PathParameter": {
                    "type": "object",
                    "additionalProperties": false,
                    "maxProperties": 2,
                    "required": ["name", "value"],
                    "properties": {
                        "name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "pattern": "^[a-z][a-z0-9_]*$"
                        },
                        "value": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                            "pattern": "^[A-Za-z0-9._~-]+$"
                        }
                    }
                },
                "OperationResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "maxProperties": 4,
                    "required": ["operation_id", "payload_cbor"],
                    "properties": {
                        "operation_id": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "payload_cbor": { "type": "string", "contentEncoding": "base64url", "maxLength": 22369622 },
                        "semantic_etag": { "type": "string", "maxLength": 256 },
                        "next_page_cursor": { "type": "string", "maxLength": 4096 }
                    }
                },
                "OperationEvent": {
                    "type": "object",
                    "additionalProperties": false,
                    "maxProperties": 3,
                    "required": ["operation_id", "event_id", "payload_cbor"],
                    "properties": {
                        "operation_id": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "event_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                        "payload_cbor": { "type": "string", "contentEncoding": "base64url", "maxLength": 1398102 }
                    }
                },
                "Problem": {
                    "type": "object",
                    "additionalProperties": false,
                    "maxProperties": 5,
                    "required": ["code", "title"],
                    "properties": {
                        "code": { "type": "integer", "minimum": 1, "maximum": 4_294_967_295_u64 },
                        "title": { "type": "string", "minLength": 1, "maxLength": 256 },
                        "detail": { "type": "string", "maxLength": 4096 },
                        "trace_id": { "type": "string", "maxLength": 128 },
                        "retry": { "type": "string", "maxLength": 64 }
                    }
                }
            }
        }
    });
    let mut rendered = serde_json::to_string_pretty(&value)
        .map_err(|error| TaskError::new(format!("failed to render service OpenAPI: {error}")))?;
    rendered.push('\n');
    Ok(rendered)
}

fn path_parameter_names(path: &str) -> Vec<&str> {
    path.split('{')
        .skip(1)
        .filter_map(|remainder| remainder.split_once('}').map(|(name, _suffix)| name))
        .collect()
}

fn render_rust_operation_registry(catalog: &OperationCatalog) -> String {
    let mut output = String::from(
        r#"// @generated by cargo xtask generate from spec/api/operations-v1.json.

/// HTTP method for a frozen v1 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

/// Idempotency-key requirement for a frozen v1 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyRequirement {
    /// An idempotency key is mandatory.
    Required,
    /// The read operation does not accept an idempotency key.
    NotApplicable,
}

/// Optimistic-revision requirement for a frozen v1 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionRequirement {
    /// No expected revision is required.
    None,
    /// An expected revision is mandatory.
    Required,
}

/// Transport response shape for a frozen v1 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    /// One bounded response.
    Unary,
    /// A bounded resumable server stream.
    ServerStream,
}

/// Authentication class enforced before service authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthClass {
    /// Tenant-authenticated operation.
    Tenant,
    /// Operator-authenticated operation.
    Operator,
    /// Content-free health probe.
    Health,
    /// Public compatibility metadata.
    Anonymous,
}

/// One generated binding shared by embedded, HTTP, gRPC, SDK, CLI, and audit surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationContract {
    /// Protobuf service name.
    pub service: &'static str,
    /// Stable Protobuf RPC name.
    pub rpc: &'static str,
    /// Stable lower-camel operation identifier.
    pub operation_id: &'static str,
    /// HTTP method.
    pub http_method: HttpMethod,
    /// Exact frozen HTTP path template.
    pub http_path: &'static str,
    /// Whether the operation can change durable state.
    pub mutation: bool,
    /// Idempotency-key requirement.
    pub idempotency_requirement: IdempotencyRequirement,
    /// Optimistic revision requirement.
    pub revision_requirement: RevisionRequirement,
    /// Unary or server-streaming response shape.
    pub stream_kind: StreamKind,
    /// Authentication class.
    pub auth_class: AuthClass,
}

"#,
    );
    output.push_str(&format!(
        "/// Number of frozen v1 operations.\npub const OPERATION_COUNT: usize = {};\n\n/// Complete frozen v1 operation registry.\npub const OPERATIONS: &[OperationContract] = &[\n",
        catalog.operation_count
    ));
    for service in &catalog.services {
        for operation in &service.operations {
            output.push_str(&format!(
                "    OperationContract {{\n        service: {},\n        rpc: {},\n        operation_id: {},\n        http_method: HttpMethod::{},\n        http_path: {},\n        mutation: {},\n        idempotency_requirement: IdempotencyRequirement::{},\n        revision_requirement: RevisionRequirement::{},\n        stream_kind: StreamKind::{},\n        auth_class: AuthClass::{},\n    }},\n",
                rust_string(&service.name),
                rust_string(&operation.rpc),
                rust_string(&operation.operation_id),
                rust_variant(&operation.http_method),
                rust_string(&operation.http_path),
                operation.mutation,
                rust_variant(&operation.idempotency_requirement.to_ascii_uppercase()),
                rust_variant(&operation.revision_requirement.to_ascii_uppercase()),
                rust_variant(&operation.stream_kind.to_ascii_uppercase()),
                rust_variant(&operation.auth_class.to_ascii_uppercase()),
            ));
        }
    }
    output.push_str(
        "];\n\n/// Finds a frozen v1 operation by its shared operation identifier.\n#[must_use]\npub fn operation_by_id(operation_id: &str) -> Option<&'static OperationContract> {\n    OPERATIONS\n        .iter()\n        .find(|operation| operation.operation_id == operation_id)\n}\n",
    );
    output
}

fn generate_schema_artifacts(root: &Path, check: bool) -> Result<(), TaskError> {
    let artifacts = generated_artifacts()?;
    for (relative_path, expected) in artifacts {
        let target = root.join(&relative_path);
        if check {
            let actual = fs::read_to_string(&target).map_err(|error| {
                TaskError::new(format!(
                    "generated artifact `{}` is missing or unreadable ({error}); run `cargo xtask generate`",
                    target.display()
                ))
            })?;
            if actual != expected {
                return Err(TaskError::new(format!(
                    "generated artifact `{}` is stale; run `cargo xtask generate`",
                    target.display()
                )));
            }
        } else {
            let Some(parent) = target.parent() else {
                return Err(TaskError::new("generated artifact has no parent directory"));
            };
            fs::create_dir_all(parent)?;
            fs::write(&target, expected)?;
            println!("generated {}", target.display());
        }
    }
    Ok(())
}

fn generate_wire_artifacts(root: &Path, check: bool) -> Result<(), TaskError> {
    let staging = root.join(".tmp/generated-wire");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    for directory in ["rust", "typescript", "python", "go"] {
        fs::create_dir_all(staging.join(directory))?;
    }

    let proto = OsString::from("schemas/proto/context_abi.proto");
    let error_proto = OsString::from("schemas/proto/generated/error_codes.proto");
    let service_proto = OsString::from("schemas/proto/cigar_service.proto");
    let proto_path = OsString::from("--proto_path=schemas/proto");
    run_command(
        root,
        "protoc",
        &[
            OsString::from(format!("--prost_out={}", staging.join("rust").display())),
            proto_path.clone(),
            proto.clone(),
            error_proto.clone(),
        ],
    )?;
    run_command(
        root,
        "protoc",
        &[
            OsString::from(format!(
                "--plugin=protoc-gen-es={}",
                root.join("sdk/typescript/node_modules/.bin/protoc-gen-es")
                    .display()
            )),
            OsString::from(format!("--es_out={}", staging.join("typescript").display())),
            OsString::from("--es_opt=target=ts"),
            proto_path.clone(),
            proto.clone(),
            error_proto.clone(),
            service_proto.clone(),
        ],
    )?;
    let typescript_context = staging.join("typescript/context_abi_pb.ts");
    let typescript_source = fs::read_to_string(&typescript_context)?;
    let typescript_source = typescript_source.replace(
        "from \"./generated/error_codes_pb\";",
        "from \"./generated/error_codes_pb.js\";",
    );
    fs::write(&typescript_context, typescript_source)?;
    run_command(
        root,
        "protoc",
        &[
            OsString::from(format!(
                "--plugin=protoc-gen-go={}",
                go_plugin_path(root)?.display()
            )),
            OsString::from(format!("--go_out={}", staging.join("go").display())),
            OsString::from("--go_opt=module=github.com/CIGAR/cigar/sdk/go"),
            proto_path.clone(),
            proto.clone(),
            error_proto.clone(),
            service_proto.clone(),
        ],
    )?;
    run_command(
        root,
        "protoc",
        &[
            OsString::from(format!(
                "--plugin=protoc-gen-go-grpc={}",
                go_grpc_plugin_path(root)?.display()
            )),
            OsString::from(format!("--go-grpc_out={}", staging.join("go").display())),
            OsString::from("--go-grpc_opt=module=github.com/CIGAR/cigar/sdk/go"),
            proto_path.clone(),
            service_proto.clone(),
        ],
    )?;
    run_command(
        root,
        "protoc",
        &[
            OsString::from(format!("--python_out={}", staging.join("python").display())),
            proto_path,
            proto,
            error_proto,
            service_proto,
        ],
    )?;

    let python_context = staging.join("python/context_abi_pb2.py");
    let python_source = fs::read_to_string(&python_context)?;
    let python_source = python_source.replace(
        "from generated import error_codes_pb2 as generated_dot_error__codes__pb2",
        "from .generated import error_codes_pb2 as generated_dot_error__codes__pb2",
    );
    fs::write(&python_context, python_source)?;

    let artifacts = [
        (
            staging.join("rust/cigar/context/v1/cigar.context.v1.rs"),
            root.join("crates/cigar-protocol/src/generated/cigar/context/v1/cigar.context.v1.rs"),
        ),
        (
            staging.join("typescript/cigar_service_pb.ts"),
            root.join("sdk/typescript/src/generated/cigar_service_pb.ts"),
        ),
        (
            staging.join("typescript/context_abi_pb.ts"),
            root.join("sdk/typescript/src/generated/context_abi_pb.ts"),
        ),
        (
            staging.join("typescript/generated/error_codes_pb.ts"),
            root.join("sdk/typescript/src/generated/generated/error_codes_pb.ts"),
        ),
        (
            staging.join("python/cigar_service_pb2.py"),
            root.join("sdk/python/src/cigar_sdk/generated/cigar_service_pb2.py"),
        ),
        (
            staging.join("python/context_abi_pb2.py"),
            root.join("sdk/python/src/cigar_sdk/generated/context_abi_pb2.py"),
        ),
        (
            staging.join("python/generated/error_codes_pb2.py"),
            root.join("sdk/python/src/cigar_sdk/generated/generated/error_codes_pb2.py"),
        ),
        (
            staging.join("go/gen/cigarv1/cigar_service.pb.go"),
            root.join("sdk/go/gen/cigarv1/cigar_service.pb.go"),
        ),
        (
            staging.join("go/gen/cigarv1/cigar_service_grpc.pb.go"),
            root.join("sdk/go/gen/cigarv1/cigar_service_grpc.pb.go"),
        ),
        (
            staging.join("go/gen/contextv1/context_abi.pb.go"),
            root.join("sdk/go/gen/contextv1/context_abi.pb.go"),
        ),
        (
            staging.join("go/gen/contextv1/error_codes.pb.go"),
            root.join("sdk/go/gen/contextv1/error_codes.pb.go"),
        ),
    ];
    for (generated, target) in artifacts {
        let bytes = fs::read(&generated).map_err(|error| {
            TaskError::new(format!(
                "wire generator did not produce `{}`: {error}",
                generated.display()
            ))
        })?;
        if check {
            let actual = fs::read(&target).map_err(|error| {
                TaskError::new(format!(
                    "generated artifact `{}` is missing or unreadable ({error}); run `cargo xtask generate`",
                    target.display()
                ))
            })?;
            if actual != bytes {
                return Err(TaskError::new(format!(
                    "generated artifact `{}` is stale; run `cargo xtask generate`",
                    target.display()
                )));
            }
        } else {
            let parent = target
                .parent()
                .ok_or_else(|| TaskError::new("generated artifact has no parent directory"))?;
            fs::create_dir_all(parent)?;
            fs::write(&target, bytes)?;
            println!("generated {}", target.display());
        }
    }
    fs::remove_dir_all(staging)?;
    Ok(())
}

fn generated_artifacts() -> Result<Vec<(PathBuf, String)>, TaskError> {
    Ok(vec![
        (
            PathBuf::from("schemas/generated-manifest.json"),
            GENERATED_MANIFEST.to_owned(),
        ),
        (
            PathBuf::from("schemas/fixtures/wp01/manifest.json"),
            cigar_testkit::render_protocol_fixture_manifest().map_err(|error| {
                TaskError::new(format!("failed to render WP01 fixture manifest: {error}"))
            })?,
        ),
        (
            PathBuf::from("schemas/json/api-payload-types-v1.schema.json"),
            render_api_payload_schema_bundle()?,
        ),
        (
            PathBuf::from("schemas/json/candidate-disposition-v1.schema.json"),
            render_schema::<cigar_protocol::CandidateDisposition>("CandidateDisposition")?,
        ),
        (
            PathBuf::from("schemas/json/capability-grant-v1.schema.json"),
            render_schema::<cigar_protocol::CapabilityGrant>("CapabilityGrant")?,
        ),
        (
            PathBuf::from("schemas/json/compatibility-report-v1.schema.json"),
            render_schema::<cigar_protocol::CompatibilityReport>("CompatibilityReport")?,
        ),
        (
            PathBuf::from("schemas/json/compensation-link-v1.schema.json"),
            render_schema::<cigar_protocol::CompensationLink>("CompensationLink")?,
        ),
        (
            PathBuf::from("schemas/json/context-atom-v1.schema.json"),
            render_schema::<cigar_protocol::ContextAtomV1>("ContextAtomV1")?,
        ),
        (
            PathBuf::from("schemas/json/context-block-v1.schema.json"),
            render_schema::<cigar_protocol::ContextBlock>("ContextBlock")?,
        ),
        (
            PathBuf::from("schemas/json/context-bundle-v1.schema.json"),
            render_schema::<cigar_protocol::ContextBundle>("ContextBundle")?,
        ),
        (
            PathBuf::from("schemas/json/context-commit-v1.schema.json"),
            render_schema::<cigar_protocol::ContextCommit>("ContextCommit")?,
        ),
        (
            PathBuf::from("schemas/json/context-contract-v1.schema.json"),
            render_schema::<cigar_protocol::ContextContract>("ContextContract")?,
        ),
        (
            PathBuf::from("schemas/json/context-delta-v1.schema.json"),
            render_schema::<cigar_protocol::ContextDelta>("ContextDelta")?,
        ),
        (
            PathBuf::from("schemas/json/context-edge-v1.schema.json"),
            render_schema::<cigar_protocol::ContextEdge>("ContextEdge")?,
        ),
        (
            PathBuf::from("schemas/json/context-plan-v1.schema.json"),
            render_schema::<cigar_protocol::ContextPlan>("ContextPlan")?,
        ),
        (
            PathBuf::from("schemas/json/decision-record-v1.schema.json"),
            render_schema::<cigar_protocol::DecisionRecord>("DecisionRecord")?,
        ),
        (
            PathBuf::from("schemas/json/effect-approval-v1.schema.json"),
            render_schema::<cigar_protocol::EffectApproval>("EffectApproval")?,
        ),
        (
            PathBuf::from("schemas/json/effect-attempt-v1.schema.json"),
            render_schema::<cigar_protocol::EffectAttempt>("EffectAttempt")?,
        ),
        (
            PathBuf::from("schemas/json/effect-intent-v1.schema.json"),
            render_schema::<cigar_protocol::EffectIntent>("EffectIntent")?,
        ),
        (
            PathBuf::from("schemas/json/effect-journal-event-v1.schema.json"),
            render_schema::<cigar_protocol::EffectJournalEvent>("EffectJournalEvent")?,
        ),
        (
            PathBuf::from("schemas/json/effect-receipt-v1.schema.json"),
            render_schema::<cigar_protocol::EffectReceipt>("EffectReceipt")?,
        ),
        (
            PathBuf::from("schemas/json/extension-cancel-v1.schema.json"),
            render_schema::<cigar_protocol::ExtensionCancelV1>("ExtensionCancelV1")?,
        ),
        (
            PathBuf::from("schemas/json/extension-host-call-v1.schema.json"),
            render_schema::<cigar_protocol::ExtensionHostCallV1>("ExtensionHostCallV1")?,
        ),
        (
            PathBuf::from("schemas/json/extension-invocation-v1.schema.json"),
            render_schema::<cigar_protocol::ExtensionInvocationV1>("ExtensionInvocationV1")?,
        ),
        (
            PathBuf::from("schemas/json/extension-manifest-v1.schema.json"),
            render_schema::<cigar_protocol::ExtensionManifestV1>("ExtensionManifestV1")?,
        ),
        (
            PathBuf::from("schemas/json/extension-observation-v1.schema.json"),
            render_schema::<cigar_protocol::ExtensionObservationV1>("ExtensionObservationV1")?,
        ),
        (
            PathBuf::from("schemas/json/extension-response-v1.schema.json"),
            render_schema::<cigar_protocol::ExtensionResponseV1>("ExtensionResponseV1")?,
        ),
        (
            PathBuf::from("schemas/json/handoff-acceptance-v1.schema.json"),
            render_schema::<cigar_protocol::HandoffAcceptance>("HandoffAcceptance")?,
        ),
        (
            PathBuf::from("schemas/json/handoff-capsule-v1.schema.json"),
            render_schema::<cigar_protocol::HandoffCapsule>("HandoffCapsule")?,
        ),
        (
            PathBuf::from("schemas/json/handoff-delta-v1.schema.json"),
            render_schema::<cigar_protocol::HandoffDelta>("HandoffDelta")?,
        ),
        (
            PathBuf::from("schemas/json/health-report-v1.schema.json"),
            render_schema::<cigar_protocol::HealthReport>("HealthReport")?,
        ),
        (
            PathBuf::from("schemas/json/lease-v1.schema.json"),
            render_schema::<cigar_protocol::Lease>("Lease")?,
        ),
        (
            PathBuf::from("schemas/json/materialized-context-v1.schema.json"),
            render_schema::<cigar_protocol::MaterializedContext>("MaterializedContext")?,
        ),
        (
            PathBuf::from("schemas/json/overlay-v1.schema.json"),
            render_schema::<cigar_protocol::Overlay>("Overlay")?,
        ),
        (
            PathBuf::from("schemas/json/page-cursor-v1.schema.json"),
            render_schema::<cigar_protocol::PageCursor>("PageCursor")?,
        ),
        (
            PathBuf::from("schemas/json/plan-lane-v1.schema.json"),
            render_schema::<cigar_protocol::PlanLane>("PlanLane")?,
        ),
        (
            PathBuf::from("schemas/json/problem-v1.schema.json"),
            render_schema::<cigar_protocol::Problem>("Problem")?,
        ),
        (
            PathBuf::from("schemas/json/reconciliation-report-v1.schema.json"),
            render_schema::<cigar_protocol::ReconciliationReport>("ReconciliationReport")?,
        ),
        (
            PathBuf::from("schemas/json/replay-completeness-v1.schema.json"),
            render_schema::<cigar_protocol::ReplayCompleteness>("ReplayCompleteness")?,
        ),
        (
            PathBuf::from("schemas/json/replay-diff-v1.schema.json"),
            render_schema::<cigar_protocol::ReplayDiff>("ReplayDiff")?,
        ),
        (
            PathBuf::from("schemas/json/replay-execution-v1.schema.json"),
            render_schema::<cigar_protocol::ReplayExecution>("ReplayExecution")?,
        ),
        (
            PathBuf::from("schemas/json/replay-request-v1.schema.json"),
            render_schema::<cigar_protocol::ReplayRequest>("ReplayRequest")?,
        ),
        (
            PathBuf::from("schemas/json/selection-manifest-v1.schema.json"),
            render_schema::<cigar_protocol::SelectionManifest>("SelectionManifest")?,
        ),
        (
            PathBuf::from("schemas/json/source-snapshot-v1.schema.json"),
            render_schema::<cigar_protocol::SourceSnapshot>("SourceSnapshot")?,
        ),
        (
            PathBuf::from("schemas/json/verification-receipt-v1.schema.json"),
            render_schema::<cigar_protocol::VerificationReceipt>("VerificationReceipt")?,
        ),
    ])
}

fn render_schema<T: schemars::JsonSchema>(name: &str) -> Result<String, TaskError> {
    let schema = schemars::SchemaGenerator::default().into_root_schema_for::<T>();
    let mut rendered = serde_json::to_string_pretty(&schema)
        .map_err(|error| TaskError::new(format!("failed to render {name} schema: {error}")))?;
    rendered.push('\n');
    Ok(rendered)
}

fn render_api_payload_schema_bundle() -> Result<String, TaskError> {
    let documents = cigar_api::typed_operation_schemas();
    if documents.len() != 45 {
        return Err(TaskError::new(
            "typed API payload schema bundle must contain exactly 45 operations",
        ));
    }
    let mut types = BTreeMap::<String, serde_json::Value>::new();
    let mut operations = Vec::with_capacity(documents.len());
    for document in documents {
        let request_name = document.request.name;
        let response_name = document.response.name;
        let event_name = document.event.as_ref().map(|event| event.name);
        for payload in [
            Some(document.request),
            Some(document.response),
            document.event,
        ]
        .into_iter()
        .flatten()
        {
            let mut schema = serde_json::to_value(payload.schema).map_err(|error| {
                TaskError::new(format!(
                    "failed to serialize API payload schema `{}`: {error}",
                    payload.name
                ))
            })?;
            let object = schema.as_object_mut().ok_or_else(|| {
                TaskError::new(format!(
                    "API payload schema `{}` is not an object resource",
                    payload.name
                ))
            })?;
            object.insert(
                "$id".to_owned(),
                serde_json::Value::String(format!(
                    "https://cigar.dev/schemas/api-payload-types-v1/{}.schema.json",
                    payload.name
                )),
            );
            if let Some(existing) = types.insert(payload.name.to_owned(), schema.clone())
                && existing != schema
            {
                return Err(TaskError::new(format!(
                    "API payload schema name `{}` resolves to divergent Rust types",
                    payload.name
                )));
            }
        }
        operations.push(serde_json::json!({
            "operation_id": document.operation_id,
            "request_type": request_name,
            "response_type": response_name,
            "event_type": event_name,
        }));
    }
    if types.len() != 70 {
        return Err(TaskError::new(format!(
            "typed API payload schema bundle must contain exactly 70 unique types, found {}",
            types.len()
        )));
    }
    let bundle = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://cigar.dev/schemas/api-payload-types-v1.schema.json",
        "schema_version": "cigar.api-payload-schema-bundle.v1",
        "api_status": "frozen-v1",
        "operation_count": operations.len(),
        "type_count": types.len(),
        "operations": operations,
        "types": types,
    });
    let mut rendered = serde_json::to_string_pretty(&bundle).map_err(|error| {
        TaskError::new(format!(
            "failed to render API payload schema bundle: {error}"
        ))
    })?;
    rendered.push('\n');
    Ok(rendered)
}

fn format_workspace(root: &Path, check: bool) -> Result<(), TaskError> {
    let mut arguments = vec![OsString::from("fmt"), OsString::from("--all")];
    if check {
        arguments.push(OsString::from("--check"));
    }
    run_command(root, "cargo", &arguments)
}

fn lint(root: &Path) -> Result<(), TaskError> {
    scan_sources(root)?;
    validate_manifest_pins(root)?;
    validate_rustls_provider_contract(root)?;
    architecture_check(root)?;
    run_command(
        root,
        "cargo",
        &[
            OsString::from("clippy"),
            OsString::from("--workspace"),
            OsString::from("--all-targets"),
            OsString::from("--all-features"),
            OsString::from("--"),
            OsString::from("-D"),
            OsString::from("warnings"),
        ],
    )?;
    run_command(
        root,
        "cargo",
        &[OsString::from("deny"), OsString::from("check")],
    )
}

fn test(root: &Path, arguments: &[String]) -> Result<(), TaskError> {
    let suite = arguments
        .iter()
        .find(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("all");
    match suite {
        "unit" | "property" | "wp00" => run_command(
            root,
            "cargo",
            &[
                OsString::from("nextest"),
                OsString::from("run"),
                OsString::from("--workspace"),
                OsString::from("--all-targets"),
            ],
        ),
        "conformance" => test_conformance(root),
        "all" => unavailable("test all", "WP19"),
        "vectors" => verify_vector_suite(root),
        "integration" | "e2e" | "security" | "compatibility" | "chaos" => {
            unavailable(&format!("test {suite}"), "the owning packet")
        }
        unknown => Err(TaskError::new(format!("unknown test suite `{unknown}`"))),
    }
}

fn conformance(root: &Path, arguments: &[String]) -> Result<(), TaskError> {
    let action = arguments
        .iter()
        .find(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("build");
    match action {
        "build" => run_command(
            root,
            "cargo",
            &[
                OsString::from("build"),
                OsString::from("-p"),
                OsString::from("cigar-conformance"),
                OsString::from("--bins"),
            ],
        ),
        unknown => Err(TaskError::new(format!(
            "unknown conformance action `{unknown}`; expected `build`"
        ))),
    }
}

fn test_conformance(root: &Path) -> Result<(), TaskError> {
    conformance(root, &["build".to_owned()])?;
    run_command(
        root,
        "cargo",
        &[
            OsString::from("nextest"),
            OsString::from("run"),
            OsString::from("-p"),
            OsString::from("cigar-conformance"),
            OsString::from("--all-targets"),
        ],
    )?;
    let executable_suffix = std::env::consts::EXE_SUFFIX;
    let runner = root
        .join("target/debug")
        .join(format!("cigar-conformance{executable_suffix}"));
    let reference = root
        .join("target/debug")
        .join(format!("cigar-conformance-reference{executable_suffix}"));
    let result = root.join("reports/conformance-result.v1.json");
    let traceability = root.join("reports/invariant-traceability.v1.json");
    run_command(
        root,
        runner
            .to_str()
            .ok_or_else(|| TaskError::new("conformance runner path is not UTF-8"))?,
        &[
            OsString::from("run"),
            OsString::from("--profile"),
            OsString::from("cigar-core-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-catalog-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-compiler-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-handoff-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-effect-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-replay-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-service-v1"),
            OsString::from("--profile"),
            OsString::from("cigar-runtime-claude-code-v1"),
            OsString::from("--executable"),
            reference.into_os_string(),
            OsString::from("--implementation"),
            OsString::from("cigar-reference-rust"),
            OsString::from("--vectors"),
            OsString::from("conformance/vectors/v1"),
            OsString::from("--output"),
            result.clone().into_os_string(),
            OsString::from("--isolation"),
            OsString::from("strict"),
        ],
    )?;
    run_command(
        root,
        runner
            .to_str()
            .ok_or_else(|| TaskError::new("conformance runner path is not UTF-8"))?,
        &[
            OsString::from("verify"),
            result.into_os_string(),
            OsString::from("--vectors"),
            OsString::from("conformance/vectors/v1"),
        ],
    )?;
    run_command(
        root,
        runner
            .to_str()
            .ok_or_else(|| TaskError::new("conformance runner path is not UTF-8"))?,
        &[
            OsString::from("traceability"),
            OsString::from("--root"),
            root.as_os_str().to_os_string(),
            OsString::from("--manifest"),
            OsString::from("tests/invariants.yaml"),
            OsString::from("--output"),
            traceability.into_os_string(),
        ],
    )
}

fn verify_vector_suite(root: &Path) -> Result<(), TaskError> {
    vectors(root, &["check".to_owned()])?;
    run_command(
        root,
        "cargo",
        &[
            OsString::from("run"),
            OsString::from("-p"),
            OsString::from("cigar-canon"),
            OsString::from("--bin"),
            OsString::from("cigar-verify-vectors"),
            OsString::from("--"),
            OsString::from("schemas/vectors/canonical-v1.json"),
        ],
    )?;
    run_command(
        root,
        "corepack",
        &[
            OsString::from("pnpm"),
            OsString::from("--dir"),
            OsString::from("sdk/typescript"),
            OsString::from("vectors"),
        ],
    )?;
    run_command(
        root,
        "uv",
        &[
            OsString::from("run"),
            OsString::from("--project"),
            OsString::from("sdk/python"),
            OsString::from("python"),
            OsString::from("-m"),
            OsString::from("cigar_sdk.verify_vectors"),
            OsString::from("schemas/vectors/canonical-v1.json"),
        ],
    )?;
    run_command(
        root,
        "go",
        &[
            OsString::from("-C"),
            OsString::from("sdk/go"),
            OsString::from("run"),
            OsString::from("./cmd/cigar-verify-vectors"),
            OsString::from("../../schemas/vectors/canonical-v1.json"),
        ],
    )
}

fn docs(root: &Path) -> Result<(), TaskError> {
    generate_sdk_artifacts(root, true)?;
    run_command(
        root,
        "cargo",
        &[
            OsString::from("doc"),
            OsString::from("--workspace"),
            OsString::from("--no-deps"),
        ],
    )
}

fn run_command(root: &Path, program: &str, arguments: &[OsString]) -> Result<(), TaskError> {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .status()
        .map_err(|error| TaskError::new(format!("failed to start `{program}`: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(TaskError::new(format!(
            "`{program} {}` failed with {status}",
            arguments
                .iter()
                .map(|argument| argument.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        )))
    }
}

fn scan_sources(root: &Path) -> Result<(), TaskError> {
    let private_key_marker = ["BEGIN", " PRIVATE", " KEY"].concat();
    let secret_prefix = ["AK", "IA"].concat();
    let forbidden = [
        ["to", "do!("].concat(),
        ["unimplemented", "!("].concat(),
        ["TO", "DO"].concat(),
        ["FIX", "ME"].concat(),
    ];
    let mut failures = Vec::new();
    for path in collect_files(&root.join("crates"), "rs")? {
        let contents = fs::read_to_string(&path)?;
        for marker in &forbidden {
            if contents.contains(marker) {
                failures.push(format!(
                    "{} contains forbidden marker `{marker}`",
                    path.display()
                ));
            }
        }
        for marker in [&private_key_marker, &secret_prefix] {
            if contents.contains(marker) {
                failures.push(format!(
                    "{} resembles committed secret material",
                    path.display()
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(TaskError::new(failures.join("\n")))
    }
}

fn collect_files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, TaskError> {
    let mut result = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() && path.extension() == Some(OsStr::new(extension)) {
                result.push(path);
            }
        }
    }
    result.sort();
    Ok(result)
}

fn validate_manifest_pins(root: &Path) -> Result<(), TaskError> {
    for manifest in collect_files(&root.join("crates"), "toml")? {
        let contents = fs::read_to_string(&manifest)?;
        for line in contents.lines().map(str::trim) {
            if line.starts_with('#') || !line.contains('=') {
                continue;
            }
            if line.contains("version = \"*") || line.contains("version = \">") {
                return Err(TaskError::new(format!(
                    "{} contains unpinned dependency `{line}`",
                    manifest.display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_rustls_provider_contract(root: &Path) -> Result<(), TaskError> {
    for relative in [
        "vendor/aws-creds-0.39.1/Cargo.toml",
        "vendor/rust-s3-0.37.2/Cargo.toml",
    ] {
        let manifest = fs::read_to_string(root.join(relative))?;
        let exact_ring_feature = manifest
            .lines()
            .map(str::trim)
            .filter(|line| *line == "\"attohttpc/tls-rustls-webpki-roots-ring\",")
            .count();
        if exact_ring_feature != 1 {
            return Err(TaskError::new(format!(
                "{relative} must select the exact attohttpc Rustls ring feature once"
            )));
        }
        if manifest
            .lines()
            .map(str::trim)
            .any(|line| line == "\"attohttpc/tls-rustls\",")
        {
            return Err(TaskError::new(format!(
                "{relative} enables the provider-ambiguous attohttpc Rustls feature"
            )));
        }
    }
    let lock = fs::read_to_string(root.join("Cargo.lock"))?;
    for forbidden in ["aws-lc-rs", "aws-lc-sys"] {
        let lock_entry = format!("name = \"{forbidden}\"");
        if lock.lines().any(|line| line.trim() == lock_entry) {
            return Err(TaskError::new(format!(
                "Cargo.lock contains forbidden alternate Rustls provider `{forbidden}`"
            )));
        }
    }
    Ok(())
}

fn architecture_check(root: &Path) -> Result<(), TaskError> {
    let layers: BTreeMap<&str, u8> = PACKAGE_LAYERS.iter().copied().collect();
    let exceptions: BTreeSet<(&str, &str)> =
        [("cigar-testkit", "cigar-api"), ("cigar-sim", "cigar-api")]
            .into_iter()
            .collect();
    for (package, package_layer) in &layers {
        let manifest = root.join("crates").join(package).join("Cargo.toml");
        let contents = fs::read_to_string(&manifest)?;
        for (dependency, dependency_layer) in &layers {
            if package == dependency || !manifest_mentions_dependency(&contents, dependency) {
                continue;
            }
            if dependency_layer > package_layer && !exceptions.contains(&(*package, *dependency)) {
                return Err(TaskError::new(format!(
                    "forbidden dependency edge: {package} (layer {package_layer}) -> {dependency} (layer {dependency_layer})"
                )));
            }
        }
    }
    validate_protocol_dependency_allowlist(root)?;
    println!("architecture dependency direction is valid");
    Ok(())
}

fn validate_protocol_dependency_allowlist(root: &Path) -> Result<(), TaskError> {
    let manifest = fs::read_to_string(root.join("crates/cigar-protocol/Cargo.toml"))?;
    let allowed: BTreeSet<&str> = ["base64", "prost", "schemars", "serde"]
        .into_iter()
        .chain(["time"])
        .collect();
    let mut in_production_dependencies = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_production_dependencies = line == "[dependencies]";
            continue;
        }
        if !in_production_dependencies || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, _definition)) = line.split_once('=') else {
            continue;
        };
        let name = name
            .trim()
            .strip_suffix(".workspace")
            .unwrap_or(name.trim());
        if !allowed.contains(name) {
            return Err(TaskError::new(format!(
                "cigar-protocol production dependency `{name}` is outside the portable ABI allowlist"
            )));
        }
    }
    Ok(())
}

fn manifest_mentions_dependency(contents: &str, dependency: &str) -> bool {
    contents.lines().map(str::trim).any(|line| {
        line.starts_with(dependency)
            && line
                .get(dependency.len()..)
                .is_some_and(|tail| tail.trim_start().starts_with('='))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ErrorCatalog, ErrorCatalogEntry, REQUIRED_V1_ROUTES, Tool, architecture_check,
        generate_error_artifacts, generate_operation_artifacts, generate_schema_artifacts,
        generated_artifacts, inspect_tool, load_operation_catalog, load_operation_payload_catalog,
        lower_camel_rpc, render_operation_openapi, render_operation_proto,
        render_proto_error_registry, render_rust_error_registry, render_rust_operation_registry,
        scan_sources, validate_error_catalog, validate_manifest_pins,
        validate_rustls_provider_contract,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TemporaryDirectory {
        path: PathBuf,
    }

    impl TemporaryDirectory {
        fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!("cigar-{label}-{nonce}"));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _result = fs::remove_dir_all(&self.path);
        }
    }

    fn require_bounded_schema_shapes(value: &serde_json::Value, path: &str) -> Result<(), String> {
        if let Some(object) = value.as_object() {
            let kind = object.get("type").and_then(serde_json::Value::as_str);
            if kind == Some("array") && !object.contains_key("maxItems") {
                return Err(format!("{path} is an array without maxItems"));
            }
            if kind == Some("string")
                && !object.contains_key("maxLength")
                && !object.contains_key("const")
                && !object.contains_key("enum")
                && !object.contains_key("format")
            {
                return Err(format!("{path} is a string without a declared bound"));
            }
            let map_like = object.contains_key("patternProperties")
                || object
                    .get("additionalProperties")
                    .is_some_and(serde_json::Value::is_object);
            if kind == Some("object") && map_like && !object.contains_key("maxProperties") {
                return Err(format!("{path} is a map without maxProperties"));
            }
            for (key, child) in object {
                require_bounded_schema_shapes(child, &format!("{path}/{key}"))?;
            }
        } else if let Some(array) = value.as_array() {
            for (index, child) in array.iter().enumerate() {
                require_bounded_schema_shapes(child, &format!("{path}/{index}"))?;
            }
        }
        Ok(())
    }

    #[test]
    fn stale_generated_file_fails_check() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("stale-generated")?;
        fs::create_dir_all(temporary.path.join("schemas/json"))?;
        fs::write(
            temporary.path.join("schemas/generated-manifest.json"),
            "stale",
        )?;
        let error = match generate_schema_artifacts(&temporary.path, true) {
            Ok(()) => return Err("stale data unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("is stale"));
        generate_schema_artifacts(&temporary.path, false)?;
        generate_schema_artifacts(&temporary.path, true)?;
        Ok(())
    }

    #[test]
    fn generated_protocol_schemas_expose_all_collection_and_string_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        for (path, rendered) in generated_artifacts()?
            .into_iter()
            .filter(|(path, _rendered)| path.starts_with("schemas/json"))
        {
            let schema: serde_json::Value = serde_json::from_str(&rendered)?;
            require_bounded_schema_shapes(&schema, &path.display().to_string())?;
        }
        Ok(())
    }

    #[test]
    fn generated_error_artifacts_are_current_and_cover_frozen_catalog()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        generate_error_artifacts(&root, true)?;
        let source = fs::read_to_string(root.join("spec/errors/catalog.yaml"))?;
        let catalog: ErrorCatalog = yaml_serde::from_str(&source)?;
        validate_error_catalog(&catalog)?;
        assert_eq!(catalog.errors.len(), 34);
        assert_eq!(
            render_rust_error_registry(&catalog)
                .lines()
                .filter(|line| line.starts_with("const ") && line.contains("_DEFINITION:"))
                .count(),
            34
        );
        assert_eq!(
            render_proto_error_registry(&catalog)
                .matches("  ERROR_CODE_")
                .count(),
            35
        );
        Ok(())
    }

    #[test]
    fn generated_service_contract_is_exact_and_complete() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        generate_operation_artifacts(&root, true)?;
        let catalog = load_operation_catalog(&root)?;
        let payloads = load_operation_payload_catalog(&root, &catalog)?;
        assert_eq!(catalog.services.len(), 7);
        assert_eq!(payloads.operations.len(), 45);

        let proto = render_operation_proto(&catalog);
        let openapi = render_operation_openapi(&catalog, &payloads)?;
        let rust = render_rust_operation_registry(&catalog);
        let openapi_value: serde_json::Value = serde_json::from_str(&openapi)?;
        let paths = openapi_value
            .get("paths")
            .and_then(serde_json::Value::as_object)
            .ok_or("OpenAPI paths missing")?;
        let path_parameter_schema = openapi_value
            .get("components")
            .and_then(|components| components.get("schemas"))
            .and_then(|schemas| schemas.get("PathParameter"))
            .ok_or("OpenAPI PathParameter schema missing")?;
        assert_eq!(
            path_parameter_schema
                .get("additionalProperties")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert!(proto.contains("message PathParameter {"));
        assert!(proto.contains("repeated PathParameter path_parameters = 7;"));
        assert!(proto.contains("bool dry_run = 8;"));
        let expected_routes: BTreeSet<String> = REQUIRED_V1_ROUTES
            .iter()
            .map(|(method, path)| format!("{method} {path}"))
            .collect();
        let mut routes = BTreeSet::new();
        let mut rpcs = BTreeSet::new();
        let mut operation_ids = BTreeSet::new();
        let mut count = 0_usize;

        for service in &catalog.services {
            assert!(proto.contains(&format!("service {} {{", service.name)));
            for operation in &service.operations {
                count = count.saturating_add(1);
                assert!(
                    routes.insert(format!("{} {}", operation.http_method, operation.http_path))
                );
                assert!(rpcs.insert(operation.rpc.as_str()));
                assert!(operation_ids.insert(operation.operation_id.as_str()));
                assert_eq!(
                    Some(operation.operation_id.clone()),
                    lower_camel_rpc(&operation.rpc)
                );
                if operation.mutation {
                    assert_eq!(operation.idempotency_requirement, "required");
                }

                assert!(proto.contains(&format!("rpc {}(OperationRequest)", operation.rpc)));
                assert!(rust.contains(&format!("rpc: {:?}", operation.rpc)));
                let method = operation.http_method.to_ascii_lowercase();
                let openapi_operation = paths
                    .get(&operation.http_path)
                    .and_then(|path| path.get(&method))
                    .ok_or("OpenAPI operation missing")?;
                assert_eq!(
                    openapi_operation
                        .get("operationId")
                        .and_then(serde_json::Value::as_str),
                    Some(operation.operation_id.as_str())
                );
                assert_eq!(
                    openapi_operation
                        .get("x-cigar-rpc")
                        .and_then(serde_json::Value::as_str),
                    Some(operation.rpc.as_str())
                );
                let payload = payloads
                    .operations
                    .iter()
                    .find(|payload| payload.operation_id == operation.operation_id)
                    .ok_or("operation payload mapping missing")?;
                assert_eq!(
                    openapi_operation
                        .get("x-cigar-request-schema")
                        .and_then(serde_json::Value::as_str),
                    Some(payload.request_schema.as_str())
                );
            }
        }

        let non_mutating_posts: BTreeSet<_> = catalog
            .services
            .iter()
            .flat_map(|service| service.operations.iter())
            .filter(|operation| operation.http_method == "POST" && !operation.mutation)
            .map(|operation| operation.operation_id.as_str())
            .collect();
        assert_eq!(
            non_mutating_posts,
            BTreeSet::from([
                "batchAtoms",
                "discoverSources",
                "previewHandoff",
                "queryCatalog",
            ])
        );

        assert_eq!(count, 45);
        assert_eq!(routes, expected_routes);
        assert_eq!(rpcs.len(), 45);
        assert_eq!(operation_ids.len(), 45);
        assert_eq!(proto.matches("  rpc ").count(), 45);
        assert_eq!(openapi.matches("\"operationId\"").count(), 45);
        assert_eq!(rust.matches("    OperationContract {").count(), 45);
        Ok(())
    }

    #[test]
    fn stale_service_contract_fails_generation_check() -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let temporary = TemporaryDirectory::new("stale-service-contract")?;
        fs::create_dir_all(temporary.path.join("spec/api"))?;
        fs::write(
            temporary.path.join("spec/api/operations-v1.json"),
            fs::read(root.join("spec/api/operations-v1.json"))?,
        )?;
        fs::write(
            temporary.path.join("spec/api/operation-payloads-v1.json"),
            fs::read(root.join("spec/api/operation-payloads-v1.json"))?,
        )?;
        generate_operation_artifacts(&temporary.path, false)?;
        fs::write(
            temporary.path.join("schemas/proto/cigar_service.proto"),
            "stale",
        )?;
        let error = match generate_operation_artifacts(&temporary.path, true) {
            Ok(()) => return Err("stale operation contract unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("is stale"));
        Ok(())
    }

    #[test]
    fn payload_catalog_missing_or_alias_operation_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let operations = load_operation_catalog(&root)?;
        let source = fs::read_to_string(root.join("spec/api/operation-payloads-v1.json"))?;
        let mut value: serde_json::Value = serde_json::from_str(&source)?;
        let rows = value
            .get_mut("operations")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("payload rows missing")?;
        let first = rows.first_mut().ok_or("payload rows empty")?;
        first
            .as_object_mut()
            .ok_or("payload row must be an object")?
            .insert(
                "operation_id".to_owned(),
                serde_json::Value::String("discoverSourceAlias".to_owned()),
            );

        let temporary = TemporaryDirectory::new("payload-alias")?;
        fs::create_dir_all(temporary.path.join("spec/api"))?;
        fs::write(
            temporary.path.join("spec/api/operation-payloads-v1.json"),
            serde_json::to_vec_pretty(&value)?,
        )?;
        let error = match load_operation_payload_catalog(&temporary.path, &operations) {
            Ok(_) => return Err("payload operation alias unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown operation"));
        Ok(())
    }

    #[test]
    fn duplicate_error_code_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let errors = (0..34)
            .map(|index| ErrorCatalogEntry {
                code: if index == 33 { 1 } else { index + 1 },
                name: format!("ERROR_{index}"),
                http: 400,
                grpc: "INVALID_ARGUMENT".to_owned(),
                retry: "never".to_owned(),
                message: "safe message".to_owned(),
                remediation: "safe remediation".to_owned(),
                disclose_identity: false,
            })
            .collect();
        let catalog = ErrorCatalog {
            schema_version: 1,
            status: "frozen".to_owned(),
            errors,
        };
        let Err(error) = validate_error_catalog(&catalog) else {
            return Err("duplicate code unexpectedly passed".into());
        };
        assert!(error.to_string().contains("duplicate"));
        Ok(())
    }

    #[test]
    fn missing_tool_has_supported_version_and_install_help()
    -> Result<(), Box<dyn std::error::Error>> {
        let tool = Tool {
            name: "fixture-tool",
            program: "cigar-tool-that-does-not-exist",
            arguments: &["--version"],
            expected: "9.9.9",
            install: "https://example.invalid/install",
            required: true,
        };
        let Err(error) = inspect_tool(tool) else {
            return Err("missing fixture tool unexpectedly passed".into());
        };
        let message = error.to_string();
        assert!(message.contains("9.9.9"));
        assert!(message.contains("https://example.invalid/install"));
        Ok(())
    }

    #[test]
    fn forbidden_dependency_edge_fails() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("architecture")?;
        for package in [
            "cigar-protocol",
            "cigar-canon",
            "cigar-crypto",
            "cigar-policy",
            "cigar-store",
            "cigar-catalog",
            "cigar-code-intel",
            "cigar-retrieval",
            "cigar-compiler",
            "cigar-space",
            "cigar-effects",
            "cigar-replay",
            "cigar-observe",
            "cigar-extension-host",
            "cigar-api",
            "cigar-daemon",
            "cigar-cli",
            "cigar-mcp",
            "cigar-testkit",
            "cigar-sim",
            "cigar-windows-ipc",
        ] {
            let directory = temporary.path.join("crates").join(package);
            fs::create_dir_all(&directory)?;
            fs::write(directory.join("Cargo.toml"), "[dependencies]\n")?;
        }
        fs::write(
            temporary.path.join("crates/cigar-protocol/Cargo.toml"),
            "[dependencies]\ncigar-api = { path = \"../cigar-api\" }\n",
        )?;
        let error = match architecture_check(&temporary.path) {
            Ok(()) => return Err("upward dependency unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cigar-protocol"));
        assert!(error.to_string().contains("cigar-api"));
        Ok(())
    }

    #[test]
    fn unpinned_dependency_fails() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("unpinned")?;
        let directory = temporary.path.join("crates/example");
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join("Cargo.toml"),
            "[dependencies]\nexample = { version = \"*\" }\n",
        )?;
        let Err(error) = validate_manifest_pins(&temporary.path) else {
            return Err("unpinned dependency unexpectedly passed".into());
        };
        assert!(error.to_string().contains("unpinned dependency"));
        Ok(())
    }

    #[test]
    fn rustls_provider_contract_rejects_ambiguous_vendor_feature_and_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("rustls-provider")?;
        for relative in [
            "vendor/aws-creds-0.39.1/Cargo.toml",
            "vendor/rust-s3-0.37.2/Cargo.toml",
        ] {
            let path = temporary.path.join(relative);
            fs::create_dir_all(path.parent().ok_or("manifest parent missing")?)?;
            fs::write(
                path,
                "rustls-tls = [\n  \"attohttpc/tls-rustls-webpki-roots-ring\",\n]\n",
            )?;
        }
        fs::write(temporary.path.join("Cargo.lock"), "version = 4\n")?;
        validate_rustls_provider_contract(&temporary.path)?;

        fs::write(
            temporary.path.join("vendor/aws-creds-0.39.1/Cargo.toml"),
            "rustls-tls = [\n  \"attohttpc/tls-rustls\",\n]\n",
        )?;
        let Err(error) = validate_rustls_provider_contract(&temporary.path) else {
            return Err("ambiguous attohttpc Rustls feature unexpectedly passed".into());
        };
        assert!(error.to_string().contains("exact attohttpc Rustls ring"));

        fs::write(
            temporary.path.join("vendor/aws-creds-0.39.1/Cargo.toml"),
            "rustls-tls = [\n  \"attohttpc/tls-rustls-webpki-roots-ring\",\n]\n",
        )?;
        fs::write(
            temporary.path.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"aws-lc-rs\"\nversion = \"1.0.0\"\n",
        )?;
        let Err(error) = validate_rustls_provider_contract(&temporary.path) else {
            return Err("alternate Rustls provider lock entry unexpectedly passed".into());
        };
        assert!(
            error
                .to_string()
                .contains("forbidden alternate Rustls provider")
        );
        Ok(())
    }

    #[test]
    fn placeholder_macro_fails_source_scan() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("placeholder")?;
        let directory = temporary.path.join("crates/example/src");
        fs::create_dir_all(&directory)?;
        let marker = ["to", "do!(\"fixture\")"].concat();
        fs::write(
            directory.join("lib.rs"),
            format!("fn fixture() {{ {marker}; }}"),
        )?;
        let Err(error) = scan_sources(&temporary.path) else {
            return Err("placeholder macro unexpectedly passed".into());
        };
        assert!(error.to_string().contains("forbidden marker"));
        Ok(())
    }

    #[test]
    fn strict_workspace_lints_reject_warnings_and_missing_docs()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
        assert!(manifest.contains("missing_docs = \"deny\""));
        assert!(manifest.contains("warnings = \"deny\""));
        assert!(manifest.contains("unsafe_code = \"forbid\""));
        Ok(())
    }
}
