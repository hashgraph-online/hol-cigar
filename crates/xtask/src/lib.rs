//! Authoritative, dependency-light workspace automation.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

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
    "    \"json/sqlite-v4-v5-migration-receipt-v1.schema.json\",\n",
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceProjectionCatalog {
    schema_version: u8,
    status: String,
    cli: CliProjectionCatalog,
    mcp: McpProjectionCatalog,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliProjectionCatalog {
    mapping_count: usize,
    mappings: Vec<CliProjectionEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliProjectionEntry {
    exposed_name: String,
    operation_id: String,
    operation_kind: String,
    #[serde(default)]
    alias_of: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpProjectionCatalog {
    mapping_count: usize,
    mappings: Vec<McpProjectionEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpProjectionEntry {
    exposed_name: String,
    operation_id: String,
    operation_kind: String,
    authority_lane: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrdCommandArgument {
    Literal(&'static str),
    SafeRelativePath {
        name: &'static str,
        example: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QualityMatrixCommand {
    suite: &'static str,
    matrix: &'static str,
    output: &'static str,
}

const COMPATIBILITY_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "compatibility",
    matrix: "tests/compatibility/matrix-v1.json",
    output: "quality/compatibility-matrix-result.v1.json",
};
const INTEGRATION_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "integration",
    matrix: "tests/integration/matrix-v1.json",
    output: "quality/integration-matrix-result.v1.json",
};
const E2E_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "e2e",
    matrix: "tests/e2e/matrix-v1.json",
    output: "quality/e2e-matrix-result.v1.json",
};
const SECURITY_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "security",
    matrix: "tests/security/matrix-v1.json",
    output: "quality/security-matrix-result.v1.json",
};
const OFFLINE_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "offline",
    matrix: "tests/offline/matrix-v1.json",
    output: "quality/offline-matrix-result.v1.json",
};
const MODELS_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "models",
    matrix: "tests/models/matrix-v1.json",
    output: "quality/models-matrix-result.v1.json",
};
const CHAOS_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "chaos",
    matrix: "tests/chaos/matrix-v1.json",
    output: "quality/chaos-matrix-result.v1.json",
};
const MIGRATION_MATRIX: QualityMatrixCommand = QualityMatrixCommand {
    suite: "migration",
    matrix: "tests/migration/matrix-v1.json",
    output: "quality/migration-matrix-result.v1.json",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrdCommandImplementation {
    BootstrapVerify,
    FormatCheck,
    GenerateCheck,
    Lint,
    DocsCheck,
    TestUnit,
    TestVectors,
    TestConformance,
    TestMatrix(QualityMatrixCommand),
    TestCoverage,
    TestMutations,
    BenchMicroVerify,
    BenchMacroVerify,
    BenchEfficacy,
    PackageAll,
    PackageSmoke,
    ReleaseReproduce,
    ReleaseSbom,
    ReleaseSign,
    ReleaseAttest,
    ReleaseVerify,
    TestSanitizers,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrdCommandSpec {
    id: &'static str,
    arguments: &'static [PrdCommandArgument],
    implementation: PrdCommandImplementation,
    work_packet: &'static str,
}

const PRD_28_1_COMMANDS: &[PrdCommandSpec] = &[
    PrdCommandSpec {
        id: "bootstrap-verify",
        arguments: &[
            PrdCommandArgument::Literal("bootstrap"),
            PrdCommandArgument::Literal("--verify"),
        ],
        implementation: PrdCommandImplementation::BootstrapVerify,
        work_packet: "WP00",
    },
    PrdCommandSpec {
        id: "format-check",
        arguments: &[
            PrdCommandArgument::Literal("fmt"),
            PrdCommandArgument::Literal("--check"),
        ],
        implementation: PrdCommandImplementation::FormatCheck,
        work_packet: "WP00",
    },
    PrdCommandSpec {
        id: "generate-check",
        arguments: &[
            PrdCommandArgument::Literal("generate"),
            PrdCommandArgument::Literal("--check"),
        ],
        implementation: PrdCommandImplementation::GenerateCheck,
        work_packet: "WP00",
    },
    PrdCommandSpec {
        id: "lint",
        arguments: &[PrdCommandArgument::Literal("lint")],
        implementation: PrdCommandImplementation::Lint,
        work_packet: "WP00",
    },
    PrdCommandSpec {
        id: "docs-check",
        arguments: &[
            PrdCommandArgument::Literal("docs"),
            PrdCommandArgument::Literal("--check"),
        ],
        implementation: PrdCommandImplementation::DocsCheck,
        work_packet: "WP00",
    },
    PrdCommandSpec {
        id: "test-unit",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("unit"),
        ],
        implementation: PrdCommandImplementation::TestUnit,
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-vectors",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("vectors"),
        ],
        implementation: PrdCommandImplementation::TestVectors,
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-compatibility",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("compatibility"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(COMPATIBILITY_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-integration",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("integration"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(INTEGRATION_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-conformance",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("conformance"),
        ],
        implementation: PrdCommandImplementation::TestConformance,
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-e2e",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("e2e"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(E2E_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-security",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("security"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(SECURITY_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-offline",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("offline"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(OFFLINE_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "fuzz-smoke",
        arguments: &[
            PrdCommandArgument::Literal("fuzz"),
            PrdCommandArgument::Literal("smoke"),
        ],
        implementation: PrdCommandImplementation::Unavailable,
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-models",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("models"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(MODELS_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-coverage-verify",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("coverage"),
            PrdCommandArgument::Literal("--verify"),
        ],
        implementation: PrdCommandImplementation::TestCoverage,
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-mutations-verify",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("mutations"),
            PrdCommandArgument::Literal("--verify"),
        ],
        implementation: PrdCommandImplementation::TestMutations,
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-chaos",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("chaos"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(CHAOS_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "test-migrations",
        arguments: &[
            PrdCommandArgument::Literal("test"),
            PrdCommandArgument::Literal("migrations"),
        ],
        implementation: PrdCommandImplementation::TestMatrix(MIGRATION_MATRIX),
        work_packet: "WP19",
    },
    PrdCommandSpec {
        id: "bench-micro-verify",
        arguments: &[
            PrdCommandArgument::Literal("bench"),
            PrdCommandArgument::Literal("micro"),
            PrdCommandArgument::Literal("--verify"),
        ],
        implementation: PrdCommandImplementation::BenchMicroVerify,
        work_packet: "WP20",
    },
    PrdCommandSpec {
        id: "bench-macro-verify",
        arguments: &[
            PrdCommandArgument::Literal("bench"),
            PrdCommandArgument::Literal("macro"),
            PrdCommandArgument::Literal("--verify"),
        ],
        implementation: PrdCommandImplementation::BenchMacroVerify,
        work_packet: "WP20",
    },
    PrdCommandSpec {
        id: "bench-efficacy",
        arguments: &[
            PrdCommandArgument::Literal("bench"),
            PrdCommandArgument::Literal("efficacy"),
        ],
        implementation: PrdCommandImplementation::BenchEfficacy,
        work_packet: "WP20",
    },
    PrdCommandSpec {
        id: "package-all",
        arguments: &[
            PrdCommandArgument::Literal("package"),
            PrdCommandArgument::Literal("--all"),
        ],
        implementation: PrdCommandImplementation::PackageAll,
        work_packet: "WP21",
    },
    PrdCommandSpec {
        id: "package-smoke",
        arguments: &[
            PrdCommandArgument::Literal("package"),
            PrdCommandArgument::Literal("--smoke"),
            PrdCommandArgument::SafeRelativePath {
                name: "artifact-directory",
                example: "dist/",
            },
        ],
        implementation: PrdCommandImplementation::PackageSmoke,
        work_packet: "WP21",
    },
    PrdCommandSpec {
        id: "release-reproduce",
        arguments: &[
            PrdCommandArgument::Literal("release"),
            PrdCommandArgument::Literal("reproduce"),
        ],
        implementation: PrdCommandImplementation::ReleaseReproduce,
        work_packet: "WP21",
    },
    PrdCommandSpec {
        id: "release-sbom",
        arguments: &[
            PrdCommandArgument::Literal("release"),
            PrdCommandArgument::Literal("sbom"),
        ],
        implementation: PrdCommandImplementation::ReleaseSbom,
        work_packet: "WP21",
    },
    PrdCommandSpec {
        id: "release-sign",
        arguments: &[
            PrdCommandArgument::Literal("release"),
            PrdCommandArgument::Literal("sign"),
        ],
        implementation: PrdCommandImplementation::ReleaseSign,
        work_packet: "WP21",
    },
    PrdCommandSpec {
        id: "release-attest",
        arguments: &[
            PrdCommandArgument::Literal("release"),
            PrdCommandArgument::Literal("attest"),
        ],
        implementation: PrdCommandImplementation::ReleaseAttest,
        work_packet: "WP21",
    },
    PrdCommandSpec {
        id: "release-verify",
        arguments: &[
            PrdCommandArgument::Literal("release"),
            PrdCommandArgument::Literal("verify"),
            PrdCommandArgument::SafeRelativePath {
                name: "artifact-directory",
                example: "dist/",
            },
        ],
        implementation: PrdCommandImplementation::ReleaseVerify,
        work_packet: "WP21",
    },
];

const NATIVE_EXTRA_COMMANDS: &[PrdCommandSpec] = &[PrdCommandSpec {
    id: "test-sanitizers",
    arguments: &[
        PrdCommandArgument::Literal("test"),
        PrdCommandArgument::Literal("sanitizers"),
    ],
    implementation: PrdCommandImplementation::TestSanitizers,
    work_packet: "WP19",
}];

fn prd_command_example_arguments(spec: &PrdCommandSpec) -> Vec<String> {
    spec.arguments
        .iter()
        .map(|argument| match argument {
            PrdCommandArgument::Literal(value) => (*value).to_owned(),
            PrdCommandArgument::SafeRelativePath { example, .. } => (*example).to_owned(),
        })
        .collect()
}

fn prd_command_display(spec: &PrdCommandSpec) -> String {
    format!(
        "cargo xtask {}",
        prd_command_example_arguments(spec).join(" ")
    )
}

fn quality_matrix_runner_arguments(
    matrix: QualityMatrixCommand,
    evidence_directory: Option<&Path>,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("tools/quality/run_matrix.py"),
        OsString::from("--matrix"),
        OsString::from(matrix.matrix),
        OsString::from("--profile"),
        OsString::from("local"),
        OsString::from("--require-evidence"),
        OsString::from("--isolate-evidence-environment"),
        OsString::from("--output"),
        OsString::from(matrix.output),
    ];
    if let Some(directory) = evidence_directory {
        arguments.push(OsString::from("--evidence-dir"));
        arguments.push(directory.as_os_str().to_owned());
    }
    arguments
}

fn run_quality_matrix(
    root: &Path,
    matrix: QualityMatrixCommand,
    evidence_directory: Option<&Path>,
) -> Result<(), TaskError> {
    if std::env::consts::OS != "macos" {
        return Err(TaskError::new(format!(
            "test {} is currently implemented only for native macOS qualification",
            matrix.suite
        )));
    }
    run_command(
        root,
        "python3",
        &quality_matrix_runner_arguments(matrix, evidence_directory),
    )
}

const EVIDENCE_PYTHON: &str = "/usr/bin/python3";
const NATIVE_PYTHON_PATH: &str = "CIGAR_XTASK_NATIVE_PYTHON_PATH";
const NATIVE_PYTHON_SHA256: &str = "CIGAR_XTASK_NATIVE_PYTHON_SHA256";
const NATIVE_PYTHON_VERSION: &str = "3.14.6";
const CLOSED_COMMAND_PATH: &str = "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const MAXIMUM_HELPER_OUTPUT_BYTES: usize = 1024 * 1024;
const COMMAND_EVIDENCE_CLOSURE: &[&str] = &[
    "crates/xtask/command_plane_evidence.py",
    "crates/xtask/route-tools.v1.json",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "tools/quality/hermetic_execution.py",
    "tools/quality/mutation_campaign.py",
];
const NATIVE_ADAPTER_CLOSURE: &[&str] = &[
    "crates/xtask/native_macos_command_plane.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/signatures.py",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct PythonRuntimeIdentity {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    root_owned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PythonVersionProbe {
    exit_code: i32,
    stderr_bytes: usize,
    stderr_sha256: String,
    stdout_bytes: usize,
    stdout_sha256: String,
    version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceFileIdentity {
    bytes: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    device: u64,
    inode: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    owner: u32,
    path: PathBuf,
    sha256: String,
}

#[cfg(unix)]
fn snapshot_source_file(path: &Path) -> Result<SourceFileIdentity, TaskError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0000_0100)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > 16 * 1024 * 1024
    {
        return Err(TaskError::new(
            "command evidence dependency is not a protected regular file",
        ));
    }
    let mut payload = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    file.read_to_end(&mut payload)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(TaskError::new(
            "command evidence dependency changed while inspected",
        ));
    }
    Ok(SourceFileIdentity {
        bytes: before.len(),
        changed_seconds: before.ctime(),
        changed_nanoseconds: before.ctime_nsec(),
        device: before.dev(),
        inode: before.ino(),
        mode: before.mode(),
        modified_seconds: before.mtime(),
        modified_nanoseconds: before.mtime_nsec(),
        owner: before.uid(),
        path: path.to_path_buf(),
        sha256: sha256_bytes(&payload),
    })
}

#[cfg(not(unix))]
fn snapshot_source_file(_path: &Path) -> Result<SourceFileIdentity, TaskError> {
    Err(TaskError::new(
        "command evidence closure currently requires macOS",
    ))
}

fn snapshot_command_evidence_closure(
    root: &Path,
) -> Result<BTreeMap<String, SourceFileIdentity>, TaskError> {
    COMMAND_EVIDENCE_CLOSURE
        .iter()
        .map(|relative| {
            snapshot_source_file(&root.join(relative))
                .map(|identity| ((*relative).to_owned(), identity))
        })
        .collect()
}

fn recheck_command_evidence_closure(
    expected: &BTreeMap<String, SourceFileIdentity>,
) -> Result<(), TaskError> {
    for identity in expected.values() {
        if snapshot_source_file(&identity.path)? != *identity {
            return Err(TaskError::new(
                "command evidence execution closure changed or was substituted",
            ));
        }
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn validate_runtime_lineage(path: &Path, root_owned: bool) -> Result<(), TaskError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let current_uid = rustix::process::getuid().as_raw();
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            TaskError::new(format!(
                "reviewed Python runtime parent is unavailable: {error}"
            ))
        })?;
        let mode = metadata.permissions().mode();
        let sticky_root = metadata.uid() == 0 && mode & 0o1000 != 0;
        let owner_is_accepted = if root_owned {
            metadata.uid() == 0
        } else {
            metadata.uid() == 0 || metadata.uid() == current_uid
        };
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || !owner_is_accepted
            || (mode & 0o022 != 0 && !sticky_root)
        {
            return Err(TaskError::new(
                "reviewed Python runtime has an unprotected path ancestor",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn snapshot_python_runtime(
    selected: &Path,
    expected_sha256: Option<&str>,
    root_owned: bool,
) -> Result<PythonRuntimeIdentity, TaskError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    if !selected.is_absolute() {
        return Err(TaskError::new(
            "reviewed Python runtime path must be absolute",
        ));
    }
    let path = fs::canonicalize(selected).map_err(|error| {
        TaskError::new(format!("reviewed Python runtime is unavailable: {error}"))
    })?;
    if path != selected {
        return Err(TaskError::new(
            "reviewed Python runtime path must be canonical and free of aliases",
        ));
    }
    validate_runtime_lineage(&path, root_owned)?;
    let named_before = fs::symlink_metadata(&path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(&path)
        .map_err(|error| {
            TaskError::new(format!("reviewed Python runtime cannot be opened: {error}"))
        })?;
    let before = file.metadata()?;
    let current_uid = rustix::process::getuid().as_raw();
    let mode = before.permissions().mode();
    let accepted_owner = if root_owned {
        before.uid() == 0
    } else {
        before.uid() == 0 || before.uid() == current_uid
    };
    if !before.is_file()
        || !named_before.is_file()
        || named_before.file_type().is_symlink()
        || (named_before.dev(), named_before.ino()) != (before.dev(), before.ino())
        || before.file_type().is_symlink()
        || !accepted_owner
        || mode & 0o022 != 0
        || mode & 0o111 == 0
        || (!root_owned && before.uid() != 0 && before.nlink() != 1)
        || before.len() == 0
        || before.len() > 128 * 1024 * 1024
    {
        return Err(TaskError::new(
            "reviewed Python runtime is not a protected executable file",
        ));
    }
    let mut accumulator = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let chunk = buffer.get(..count).ok_or_else(|| {
            TaskError::new("reviewed Python runtime returned an invalid read length")
        })?;
        accumulator.update(chunk);
        copied = copied
            .checked_add(u64::try_from(count).map_err(|_error| {
                TaskError::new("reviewed Python runtime size cannot be represented")
            })?)
            .ok_or_else(|| TaskError::new("reviewed Python runtime size overflowed"))?;
    }
    if copied != before.len() {
        return Err(TaskError::new(
            "reviewed Python runtime changed while it was hashed",
        ));
    }
    let after = file.metadata()?;
    let named_after = fs::symlink_metadata(&path)?;
    let stable = before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && named_before.dev() == named_after.dev()
        && named_before.ino() == named_after.ino()
        && named_before.mode() == named_after.mode()
        && named_before.uid() == named_after.uid()
        && named_before.nlink() == named_after.nlink()
        && named_before.len() == named_after.len()
        && named_before.mtime() == named_after.mtime()
        && named_before.mtime_nsec() == named_after.mtime_nsec()
        && named_before.ctime() == named_after.ctime()
        && named_before.ctime_nsec() == named_after.ctime_nsec()
        && (named_after.dev(), named_after.ino()) == (after.dev(), after.ino());
    if !stable {
        return Err(TaskError::new(
            "reviewed Python runtime changed while it was hashed",
        ));
    }
    let sha256 = accumulator
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if expected_sha256.is_some_and(|expected| expected != sha256) {
        return Err(TaskError::new(
            "reviewed Python runtime SHA-256 does not match operator authority",
        ));
    }
    Ok(PythonRuntimeIdentity {
        path,
        sha256,
        bytes: before.len(),
        device: before.dev(),
        inode: before.ino(),
        mode: before.mode(),
        owner: before.uid(),
        links: before.nlink(),
        modified_seconds: before.mtime(),
        modified_nanoseconds: before.mtime_nsec(),
        changed_seconds: before.ctime(),
        changed_nanoseconds: before.ctime_nsec(),
        root_owned,
    })
}

#[cfg(not(unix))]
fn snapshot_python_runtime(
    _selected: &Path,
    _expected_sha256: Option<&str>,
    _root_owned: bool,
) -> Result<PythonRuntimeIdentity, TaskError> {
    Err(TaskError::new(
        "the authoritative command evidence runner currently requires macOS",
    ))
}

fn system_python_runtime() -> Result<PythonRuntimeIdentity, TaskError> {
    snapshot_python_runtime(Path::new(EVIDENCE_PYTHON), None, true)
}

fn probe_native_python_runtime(
    root: &Path,
    runtime: &PythonRuntimeIdentity,
) -> Result<PythonVersionProbe, TaskError> {
    let output = run_bounded_python(
        root,
        runtime,
        &[OsString::from("--version")],
        Duration::from_secs(30),
        16 * 1024,
        16 * 1024,
        false,
    )?;
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_error| TaskError::new("reviewed Python version output is not UTF-8"))?;
    let stderr = std::str::from_utf8(&output.stderr)
        .map_err(|_error| TaskError::new("reviewed Python version error output is not UTF-8"))?;
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() || combined.trim() != format!("Python {NATIVE_PYTHON_VERSION}") {
        return Err(TaskError::new(format!(
            "reviewed native Python must report exactly Python {NATIVE_PYTHON_VERSION}; output was suppressed"
        )));
    }
    Ok(PythonVersionProbe {
        exit_code: output.status.code().unwrap_or(-1),
        stderr_bytes: output.stderr.len(),
        stderr_sha256: sha256_bytes(&output.stderr),
        stdout_bytes: output.stdout.len(),
        stdout_sha256: sha256_bytes(&output.stdout),
        version: NATIVE_PYTHON_VERSION.to_owned(),
    })
}

fn native_python_runtime_from(
    root: &Path,
    selected: &Path,
    expected: &str,
) -> Result<(PythonRuntimeIdentity, PythonVersionProbe), TaskError> {
    if !is_lower_sha256(expected) {
        return Err(TaskError::new(format!(
            "{NATIVE_PYTHON_SHA256} must be one lowercase SHA-256 digest"
        )));
    }
    let runtime = snapshot_python_runtime(selected, Some(expected), false)?;
    if runtime.path.starts_with(root) {
        return Err(TaskError::new(
            "reviewed native Python runtime must be outside the source repository",
        ));
    }
    let probe = probe_native_python_runtime(root, &runtime)?;
    Ok((runtime, probe))
}

fn native_python_runtime(
    root: &Path,
) -> Result<(PythonRuntimeIdentity, PythonVersionProbe), TaskError> {
    let selected = env::var(NATIVE_PYTHON_PATH).map_err(|_error| {
        TaskError::new(format!(
            "native command requires {NATIVE_PYTHON_PATH}=<reviewed-canonical-python-path>"
        ))
    })?;
    let expected = env::var(NATIVE_PYTHON_SHA256).map_err(|_error| {
        TaskError::new(format!(
            "native command requires {NATIVE_PYTHON_SHA256}=<reviewed-lowercase-sha256>"
        ))
    })?;
    native_python_runtime_from(root, Path::new(&selected), &expected)
}

fn recheck_python_runtime(identity: &PythonRuntimeIdentity) -> Result<(), TaskError> {
    let current =
        snapshot_python_runtime(&identity.path, Some(&identity.sha256), identity.root_owned)?;
    if &current != identity {
        return Err(TaskError::new(
            "reviewed Python runtime changed or was substituted during execution",
        ));
    }
    Ok(())
}

const TOOL_AUTHORITY_SELECTOR: &str = "CIGAR_XTASK_TOOL_INPUTS";
const TOOL_AUTHORITY_SHA256_SELECTOR: &str = "CIGAR_XTASK_TOOL_INPUTS_SHA256";
const TOOL_AUTHORITY_SCHEMA: &str = "cigar.xtask-tool-inputs.v2";
const ROUTE_TOOL_SCHEMA: &str = "cigar.xtask-route-tools.v1";
const ROUTE_TOOL_MANIFEST: &str = include_str!("../route-tools.v1.json");
const MAXIMUM_TOOL_AUTHORITY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteToolManifest {
    routes: BTreeMap<String, Vec<String>>,
    schema_version: String,
}

fn route_tool_names(command_id: &str) -> Result<BTreeSet<String>, TaskError> {
    let manifest: RouteToolManifest = serde_json::from_str(ROUTE_TOOL_MANIFEST)
        .map_err(|error| TaskError::new(format!("route tool manifest is invalid: {error}")))?;
    if manifest.schema_version != ROUTE_TOOL_SCHEMA {
        return Err(TaskError::new("route tool manifest schema is unsupported"));
    }
    let expected_routes = PRD_28_1_COMMANDS
        .iter()
        .chain(NATIVE_EXTRA_COMMANDS)
        .map(|spec| spec.id)
        .collect::<BTreeSet<_>>();
    if manifest
        .routes
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_routes
    {
        return Err(TaskError::new(
            "route tool manifest does not exactly cover the command authority",
        ));
    }
    for tools in manifest.routes.values() {
        if tools.iter().any(|tool| !validate_tool_name(tool))
            || !tools
                .windows(2)
                .all(|pair| matches!(pair, [left, right] if left < right))
        {
            return Err(TaskError::new(
                "route tool manifest inventories must be sorted, unique, and portable",
            ));
        }
    }
    manifest
        .routes
        .get(command_id)
        .map(|tools| tools.iter().cloned().collect())
        .ok_or_else(|| TaskError::new("route tool manifest omits the selected command"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolAuthorityDocument {
    command_id: String,
    environment: BTreeMap<String, String>,
    schema_version: String,
    source: serde_json::Value,
    tools: BTreeMap<String, ToolAuthorityEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolAuthorityEntry {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct ReviewedExecution {
    command_sha256: String,
    executable_sha256: String,
    exit_code: i32,
    stderr_bytes: usize,
    stderr_sha256: String,
    stdout_bytes: usize,
    stdout_sha256: String,
    tool: String,
}

#[derive(Debug)]
struct ActiveToolAuthority {
    binding_bytes: u64,
    binding_sha256: String,
    command_id: String,
    environment: BTreeMap<String, PathBuf>,
    executions: Mutex<Vec<ReviewedExecution>>,
    manifest_path: PathBuf,
    review_status: &'static str,
    shim_directory: PathBuf,
    tools: BTreeMap<String, PythonRuntimeIdentity>,
}

impl Drop for ActiveToolAuthority {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.shim_directory);
    }
}

thread_local! {
    static ACTIVE_TOOL_AUTHORITY: RefCell<Option<Arc<ActiveToolAuthority>>> = const { RefCell::new(None) };
}

struct ToolAuthorityGuard;

impl Drop for ToolAuthorityGuard {
    fn drop(&mut self) {
        ACTIVE_TOOL_AUTHORITY.with(|selected| {
            *selected.borrow_mut() = None;
        });
    }
}

fn sha256_bytes(payload: &[u8]) -> String {
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn protected_authority_payload(path: &Path) -> Result<(Vec<u8>, u64, String), TaskError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(TaskError::new(
            "tool authority path must be absolute, canonical, and free of symlinks",
        ));
    }
    validate_runtime_lineage(path, false)?;
    let named_before = fs::symlink_metadata(path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(path)?;
    let before = file.metadata()?;
    let current_uid = rustix::process::getuid().as_raw();
    if !before.is_file()
        || !named_before.is_file()
        || named_before.file_type().is_symlink()
        || (named_before.dev(), named_before.ino()) != (before.dev(), before.ino())
        || before.uid() != current_uid
        || before.nlink() != 1
        || before.permissions().mode() & 0o077 != 0
        || before.len() == 0
        || before.len() > MAXIMUM_TOOL_AUTHORITY_BYTES
    {
        return Err(TaskError::new(
            "tool authority must be one owner-private regular file",
        ));
    }
    let mut payload = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    file.read_to_end(&mut payload)?;
    let after = file.metadata()?;
    let named_after = fs::symlink_metadata(path)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || u64::try_from(payload.len()).ok() != Some(before.len())
        || !named_after.is_file()
        || named_after.file_type().is_symlink()
        || (named_after.dev(), named_after.ino()) != (after.dev(), after.ino())
        || named_before.dev() != named_after.dev()
        || named_before.ino() != named_after.ino()
        || named_before.mode() != named_after.mode()
        || named_before.uid() != named_after.uid()
        || named_before.nlink() != named_after.nlink()
        || named_before.len() != named_after.len()
        || named_before.mtime() != named_after.mtime()
        || named_before.mtime_nsec() != named_after.mtime_nsec()
        || named_before.ctime() != named_after.ctime()
        || named_before.ctime_nsec() != named_after.ctime_nsec()
    {
        return Err(TaskError::new("tool authority changed while it was read"));
    }
    let digest = sha256_bytes(&payload);
    Ok((payload, before.len(), digest))
}

fn authority_review_status(
    actual: &str,
    expected: Option<&str>,
) -> Result<&'static str, TaskError> {
    let Some(expected) = expected else {
        return Ok("diagnostic-self-observed");
    };
    if !is_lower_sha256(expected) || expected != actual {
        return Err(TaskError::new(
            "tool authority bytes differ from the independently reviewed digest",
        ));
    }
    Ok("operator-reviewed")
}

#[cfg(unix)]
const fn libc_o_nofollow() -> i32 {
    0x0000_0100
}

#[cfg(not(unix))]
fn protected_authority_payload(_path: &Path) -> Result<(Vec<u8>, u64, String), TaskError> {
    Err(TaskError::new(
        "tool authority currently requires Apple-silicon macOS",
    ))
}

fn canonical_json_payload(value: &serde_json::Value) -> Result<Vec<u8>, TaskError> {
    let mut payload = serde_json::to_vec(value)
        .map_err(|error| TaskError::new(format!("tool authority cannot be encoded: {error}")))?;
    payload.push(b'\n');
    Ok(payload)
}

fn validate_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_'))
}

#[cfg(unix)]
fn private_authority_directory(value: &str, label: &str) -> Result<PathBuf, TaskError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let selected = Path::new(value);
    if !selected.is_absolute() || fs::canonicalize(selected)? != selected {
        return Err(TaskError::new(format!(
            "tool authority {label} must be an absolute canonical directory"
        )));
    }
    validate_runtime_lineage(selected, false)?;
    let metadata = fs::metadata(selected)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(TaskError::new(format!(
            "tool authority {label} must be owner-private"
        )));
    }
    Ok(selected.to_path_buf())
}

#[cfg(not(unix))]
fn private_authority_directory(_value: &str, _label: &str) -> Result<PathBuf, TaskError> {
    Err(TaskError::new(
        "tool authority currently requires Apple-silicon macOS",
    ))
}

#[cfg(unix)]
fn create_tool_shim_directory(
    tools: &BTreeMap<String, PythonRuntimeIdentity>,
) -> Result<PathBuf, TaskError> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| TaskError::new(format!("system clock precedes Unix epoch: {error}")))?
        .as_nanos();
    let directory = PathBuf::from(format!(
        "/private/tmp/cigar-xtask-tools-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    for (name, identity) in tools {
        symlink(&identity.path, directory.join(name))?;
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn create_tool_shim_directory(
    _tools: &BTreeMap<String, PythonRuntimeIdentity>,
) -> Result<PathBuf, TaskError> {
    Err(TaskError::new(
        "tool authority currently requires Apple-silicon macOS",
    ))
}

fn load_tool_authority(
    root: &Path,
    expected_source: &str,
    command_id: &str,
) -> Result<Arc<ActiveToolAuthority>, TaskError> {
    let selected = env::var(TOOL_AUTHORITY_SELECTOR).map_err(|_error| {
        TaskError::new(format!(
            "implemented PRD command requires {TOOL_AUTHORITY_SELECTOR}=<protected-canonical-manifest>"
        ))
    })?;
    let path = PathBuf::from(selected);
    let (payload, binding_bytes, binding_sha256) = protected_authority_payload(&path)?;
    let expected_binding = env::var(TOOL_AUTHORITY_SHA256_SELECTOR).ok();
    let review_status = authority_review_status(&binding_sha256, expected_binding.as_deref())?;
    if path.starts_with(root) {
        return Err(TaskError::new(
            "tool authority must be outside the source repository",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|error| TaskError::new(format!("tool authority is not strict JSON: {error}")))?;
    if canonical_json_payload(&value)? != payload {
        return Err(TaskError::new(
            "tool authority must use canonical sorted JSON with one trailing newline",
        ));
    }
    let document: ToolAuthorityDocument = serde_json::from_value(value)
        .map_err(|error| TaskError::new(format!("tool authority shape is invalid: {error}")))?;
    let expected: serde_json::Value = serde_json::from_str(expected_source)
        .map_err(|error| TaskError::new(format!("source snapshot became invalid: {error}")))?;
    if document.schema_version != TOOL_AUTHORITY_SCHEMA
        || document.command_id != command_id
        || document.source != expected
    {
        return Err(TaskError::new(
            "tool authority is stale or has an unsupported schema",
        ));
    }
    let required_tools = route_tool_names(command_id)?;
    if document.tools.keys().cloned().collect::<BTreeSet<_>>() != required_tools {
        return Err(TaskError::new(
            "tool authority must contain the exact least-privilege route tool set",
        ));
    }
    let allowed_environment = BTreeSet::from([
        "CARGO_HOME",
        "COREPACK_HOME",
        "GOCACHE",
        "GOMODCACHE",
        "HOME",
        "NPM_CONFIG_CACHE",
        "RUSTUP_HOME",
        "UV_CACHE_DIR",
    ]);
    if !document.environment.contains_key("HOME")
        || document.environment.len() > allowed_environment.len()
        || document
            .environment
            .keys()
            .any(|key| !allowed_environment.contains(key.as_str()))
    {
        return Err(TaskError::new(
            "tool authority environment must contain only reviewed cache roots and HOME",
        ));
    }
    let mut environment = BTreeMap::new();
    for (name, value) in document.environment {
        environment.insert(name.clone(), private_authority_directory(&value, &name)?);
    }
    let mut tools = BTreeMap::new();
    for (name, entry) in document.tools {
        if !validate_tool_name(&name) || !is_lower_sha256(&entry.sha256) {
            return Err(TaskError::new(
                "tool authority contains an invalid tool identity",
            ));
        }
        let identity = snapshot_python_runtime(&entry.path, Some(&entry.sha256), false)?;
        if identity.path.starts_with(root) {
            return Err(TaskError::new(
                "external tool authority cannot select a repository executable",
            ));
        }
        tools.insert(name, identity);
    }
    let shim_directory = create_tool_shim_directory(&tools)?;
    Ok(Arc::new(ActiveToolAuthority {
        binding_bytes,
        binding_sha256,
        command_id: command_id.to_owned(),
        environment,
        executions: Mutex::new(Vec::new()),
        manifest_path: path,
        review_status,
        shim_directory,
        tools,
    }))
}

fn install_tool_authority(
    authority: Arc<ActiveToolAuthority>,
) -> Result<ToolAuthorityGuard, TaskError> {
    ACTIVE_TOOL_AUTHORITY.with(|selected| {
        let mut selected = selected.borrow_mut();
        if selected.is_some() {
            return Err(TaskError::new("tool authority is already active"));
        }
        *selected = Some(authority);
        Ok(ToolAuthorityGuard)
    })
}

fn active_tool_authority() -> Option<Arc<ActiveToolAuthority>> {
    ACTIVE_TOOL_AUTHORITY.with(|selected| selected.borrow().clone())
}

fn reviewed_tool_binding() -> Result<Option<String>, TaskError> {
    let Some(authority) = active_tool_authority() else {
        return Ok(None);
    };
    let (_payload, bytes, sha256) = protected_authority_payload(&authority.manifest_path)?;
    if bytes != authority.binding_bytes || sha256 != authority.binding_sha256 {
        return Err(TaskError::new(
            "reviewed tool authority changed or was substituted during execution",
        ));
    }
    for identity in authority.tools.values() {
        recheck_python_runtime(identity)?;
    }
    let executions = authority
        .executions
        .lock()
        .map_err(|_error| TaskError::new("reviewed execution inventory lock is poisoned"))?
        .clone();
    let tools = authority
        .tools
        .iter()
        .map(|(name, identity)| (name.clone(), identity.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    let binding = serde_json::json!({
        "command_id": authority.command_id,
        "executions": executions,
        "manifest": {
            "bytes": authority.binding_bytes,
            "sha256": authority.binding_sha256,
        },
        "network_enforcement": "not-enforced",
        "review_status": authority.review_status,
        "tools": tools,
    });
    serde_json::to_string(&binding)
        .map(Some)
        .map_err(|error| TaskError::new(format!("tool binding cannot be encoded: {error}")))
}

fn append_reviewed_tool_binding(arguments: &mut Vec<OsString>, binding: Option<&str>) {
    if let Some(binding) = binding {
        arguments.push(OsString::from("--tool-authority-binding"));
        arguments.push(OsString::from(binding));
    }
}

fn drain_bounded_output(
    mut stream: impl Read,
    maximum: usize,
    exceeded: Arc<AtomicBool>,
) -> io::Result<Vec<u8>> {
    let mut captured = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(captured.len());
        captured.extend(buffer.iter().take(count.min(remaining)).copied());
        if count > remaining {
            exceeded.store(true, Ordering::Release);
        }
    }
    Ok(captured)
}

fn terminate_python_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(raw) = i32::try_from(child.id())
        && let Some(group) = rustix::process::Pid::from_raw(raw)
    {
        let _ignored = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    let _ignored = child.kill();
    let _ignored = child.wait();
}

fn closed_python_environment(command: &mut Command, native: bool) {
    command
        .env_clear()
        .env("HOME", "/var/empty")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", CLOSED_COMMAND_PATH)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONHASHSEED", "0")
        .env("PYTHONNOUSERSITE", "1")
        .env("TMPDIR", "/private/tmp")
        .env("TZ", "UTC");
    if let Some(authority) = active_tool_authority() {
        command.env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                authority.shim_directory.display()
            ),
        );
        for (name, path) in &authority.environment {
            command.env(name, path);
        }
        command
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_NET_OFFLINE", "true")
            .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
            .env("COREPACK_ENABLE_NETWORK", "0")
            .env("GOTOOLCHAIN", "local")
            .env("NPM_CONFIG_OFFLINE", "true")
            .env("RUSTUP_AUTO_INSTALL", "0")
            .env("UV_OFFLINE", "1");
    }
    if native {
        if let Some(authority) = env::var_os("CIGAR_XTASK_COMMAND_INPUTS") {
            command.env("CIGAR_XTASK_COMMAND_INPUTS", authority);
        }
        if let Some(digest) = env::var_os("CIGAR_XTASK_COMMAND_INPUTS_SHA256") {
            command.env("CIGAR_XTASK_COMMAND_INPUTS_SHA256", digest);
        }
        if env::var("CIGAR_NO_EGRESS_ENFORCED").as_deref() == Ok("1") {
            command.env("CIGAR_NO_EGRESS_ENFORCED", "1");
        }
    }
}

fn run_bounded_python(
    root: &Path,
    runtime: &PythonRuntimeIdentity,
    arguments: &[OsString],
    timeout: Duration,
    maximum_stdout: usize,
    maximum_stderr: usize,
    native: bool,
) -> Result<Output, TaskError> {
    recheck_python_runtime(runtime)?;
    let mut command = Command::new(&runtime.path);
    command
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    closed_python_environment(&mut command, native);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| TaskError::new(format!("failed to start reviewed Python: {error}")))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_python_process_group(&mut child);
        TaskError::new("reviewed Python stdout pipe is unavailable")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_python_process_group(&mut child);
        TaskError::new("reviewed Python stderr pipe is unavailable")
    })?;
    let output_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_exceeded = Arc::clone(&output_exceeded);
    let stderr_exceeded = Arc::clone(&output_exceeded);
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
    let _stdout_thread = thread::spawn(move || {
        let _ignored = stdout_sender.send(drain_bounded_output(
            stdout,
            maximum_stdout,
            stdout_exceeded,
        ));
    });
    let _stderr_thread = thread::spawn(move || {
        let _ignored = stderr_sender.send(drain_bounded_output(
            stderr,
            maximum_stderr,
            stderr_exceeded,
        ));
    });
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if output_exceeded.load(Ordering::Acquire) {
            terminate_python_process_group(&mut child);
            break None;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            terminate_python_process_group(&mut child);
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                #[cfg(unix)]
                if let Ok(raw) = i32::try_from(child.id())
                    && let Some(group) = rustix::process::Pid::from_raw(raw)
                {
                    let _ignored =
                        rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                }
                break Some(status);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_error) => {
                terminate_python_process_group(&mut child);
                break None;
            }
        }
    };
    let settlement = Duration::from_secs(2);
    let stdout = stdout_receiver
        .recv_timeout(settlement)
        .map_err(|_error| {
            TaskError::new(
                "reviewed Python stdout did not settle; an escaped-session descendant may remain",
            )
        })?
        .map_err(|_error| TaskError::new("reviewed Python stdout could not be drained"))?;
    let stderr = stderr_receiver
        .recv_timeout(settlement)
        .map_err(|_error| {
            TaskError::new(
                "reviewed Python stderr did not settle; an escaped-session descendant may remain",
            )
        })?
        .map_err(|_error| TaskError::new("reviewed Python stderr could not be drained"))?;
    recheck_python_runtime(runtime)?;
    if timed_out {
        return Err(TaskError::new(
            "reviewed Python command exceeded its timeout",
        ));
    }
    if output_exceeded.load(Ordering::Acquire) {
        return Err(TaskError::new(
            "reviewed Python command exceeded its output bound",
        ));
    }
    let status = status.ok_or_else(|| TaskError::new("reviewed Python command failed"))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[derive(Debug)]
struct CommandEvidenceContext {
    expected_source: String,
    started_unix_ms: u128,
    started: Instant,
    evidence_python: PythonRuntimeIdentity,
    helper_closure: BTreeMap<String, SourceFileIdentity>,
}

fn require_prd_evidence_directory<'a>(
    spec: &PrdCommandSpec,
    evidence_directory: Option<&'a Path>,
) -> Result<&'a Path, TaskError> {
    evidence_directory.ok_or_else(|| {
        TaskError::new(format!(
            "`{}` requires --evidence-dir <absolute-directory> or CIGAR_EVIDENCE_DIR so success cannot escape without a source-bound receipt",
            prd_command_display(spec)
        ))
    })
}

fn begin_command_evidence(
    root: &Path,
    evidence_directory: &Path,
) -> Result<CommandEvidenceContext, TaskError> {
    let evidence_python = system_python_runtime()?;
    let helper_closure = snapshot_command_evidence_closure(root)?;
    let arguments = [
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("snapshot"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
    ];
    let output = run_bounded_python(
        root,
        &evidence_python,
        &arguments,
        Duration::from_secs(2 * 60),
        64 * 1024,
        64 * 1024,
        false,
    )?;
    recheck_command_evidence_closure(&helper_closure)?;
    if !output.status.success() {
        return Err(TaskError::new(format!(
            "command evidence source snapshot failed with {}; output was suppressed",
            output.status
        )));
    }
    if output.stdout.is_empty() || output.stdout.len() > 64 * 1024 {
        return Err(TaskError::new(
            "command evidence source snapshot is empty or exceeds 64 KiB",
        ));
    }
    let source: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        TaskError::new(format!(
            "command evidence source snapshot is not strict JSON: {error}"
        ))
    })?;
    if !source.is_object() {
        return Err(TaskError::new(
            "command evidence source snapshot must be a JSON object",
        ));
    }
    let started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| TaskError::new(format!("system clock precedes Unix epoch: {error}")))?
        .as_millis();
    Ok(CommandEvidenceContext {
        expected_source: serde_json::to_string(&source).map_err(|error| {
            TaskError::new(format!("failed to encode source snapshot: {error}"))
        })?,
        started_unix_ms,
        started: Instant::now(),
        evidence_python,
        helper_closure,
    })
}

fn command_evidence_helper(
    root: &Path,
    context: &CommandEvidenceContext,
    arguments: &[OsString],
) -> Result<Vec<u8>, TaskError> {
    recheck_command_evidence_closure(&context.helper_closure)?;
    let output = run_bounded_python(
        root,
        &context.evidence_python,
        arguments,
        Duration::from_secs(72 * 60 * 60),
        MAXIMUM_HELPER_OUTPUT_BYTES,
        MAXIMUM_HELPER_OUTPUT_BYTES,
        false,
    )?;
    recheck_command_evidence_closure(&context.helper_closure)?;
    if !output.status.success() {
        return Err(TaskError::new(format!(
            "command evidence helper failed with {}; output was suppressed",
            output.status
        )));
    }
    if output.stdout.is_empty() || output.stdout.len() > 1024 * 1024 {
        return Err(TaskError::new(
            "command evidence helper returned an empty or oversized receipt",
        ));
    }
    Ok(output.stdout)
}

fn validate_command_receipt(
    payload: &[u8],
    spec: &PrdCommandSpec,
    context: &CommandEvidenceContext,
) -> Result<(), TaskError> {
    let receipt: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| TaskError::new(format!("command receipt is not strict JSON: {error}")))?;
    let expected_source: serde_json::Value = serde_json::from_str(&context.expected_source)
        .map_err(|error| TaskError::new(format!("source snapshot became invalid: {error}")))?;
    let attachments = receipt
        .get("attachments")
        .and_then(serde_json::Value::as_array);
    let attachment_is_nonempty_and_bound = attachments.is_some_and(|attachments| {
        attachments.len() == 1
            && attachments.first().is_some_and(|attachment| {
                attachment
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|path| !path.is_empty())
                    && attachment
                        .get("bytes")
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|bytes| bytes > 0)
                    && attachment
                        .get("sha256")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|digest| {
                            digest.len() == 64
                                && digest.bytes().all(|byte| {
                                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                })
                        })
            })
    });
    if receipt
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        != Some("cigar.xtask-command-receipt.v1")
        || receipt
            .pointer("/command/id")
            .and_then(serde_json::Value::as_str)
            != Some(spec.id)
        || receipt.get("status").and_then(serde_json::Value::as_str) != Some("passed")
        || receipt.get("source") != Some(&expected_source)
        || !attachment_is_nonempty_and_bound
        || receipt
            .get("release_eligible")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(TaskError::new(
            "command receipt is empty, stale, unbound, or has an unexpected identity",
        ));
    }
    Ok(())
}

fn finish_command_evidence(
    root: &Path,
    spec: &PrdCommandSpec,
    evidence_directory: &Path,
    context: &CommandEvidenceContext,
    attachment_relative: Option<&str>,
) -> Result<(), TaskError> {
    let duration_ms = context.started.elapsed().as_millis();
    let tool_binding = reviewed_tool_binding()?;
    let mut arguments = vec![
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("record"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--command-id"),
        OsString::from(spec.id),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
        OsString::from("--started-unix-ms"),
        OsString::from(context.started_unix_ms.to_string()),
        OsString::from("--duration-ms"),
        OsString::from(duration_ms.to_string()),
    ];
    if let Some(relative) = attachment_relative {
        arguments.push(OsString::from("--attachment-relative"));
        arguments.push(OsString::from(relative));
    }
    append_reviewed_tool_binding(&mut arguments, tool_binding.as_deref());
    command_evidence_helper(root, context, &arguments)?;
    let mut verification = vec![
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("verify"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--command-id"),
        OsString::from(spec.id),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
    ];
    if let Some(relative) = attachment_relative {
        verification.push(OsString::from("--attachment-relative"));
        verification.push(OsString::from(relative));
    }
    append_reviewed_tool_binding(&mut verification, tool_binding.as_deref());
    let receipt = command_evidence_helper(root, context, &verification)?;
    validate_command_receipt(&receipt, spec, context)
}

fn run_coverage_gate(
    root: &Path,
    spec: &PrdCommandSpec,
    evidence_directory: &Path,
    context: &CommandEvidenceContext,
) -> Result<(), TaskError> {
    let tool_binding = reviewed_tool_binding()?;
    let mut arguments = vec![
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("coverage"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
    ];
    append_reviewed_tool_binding(&mut arguments, tool_binding.as_deref());
    command_evidence_helper(root, context, &arguments)?;
    let mut verification = vec![
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("verify"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--command-id"),
        OsString::from(spec.id),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
    ];
    append_reviewed_tool_binding(&mut verification, tool_binding.as_deref());
    let receipt = command_evidence_helper(root, context, &verification)?;
    validate_command_receipt(&receipt, spec, context)
}

fn run_mutation_gate(
    root: &Path,
    spec: &PrdCommandSpec,
    evidence_directory: &Path,
    context: &CommandEvidenceContext,
) -> Result<(), TaskError> {
    let tool_binding = reviewed_tool_binding()?;
    let mut arguments = vec![
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("mutations"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
    ];
    append_reviewed_tool_binding(&mut arguments, tool_binding.as_deref());
    command_evidence_helper(root, context, &arguments)?;
    let mut verification = vec![
        OsString::from("crates/xtask/command_plane_evidence.py"),
        OsString::from("verify"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--command-id"),
        OsString::from(spec.id),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
    ];
    append_reviewed_tool_binding(&mut verification, tool_binding.as_deref());
    let receipt = command_evidence_helper(root, context, &verification)?;
    validate_command_receipt(&receipt, spec, context)
}

fn run_reproducibility_gate(root: &Path, evidence_directory: &Path) -> Result<(), TaskError> {
    run_command(
        root,
        "python3",
        &[
            OsString::from("scripts/release/check_reproducibility.py"),
            OsString::from("--root"),
            root.as_os_str().to_owned(),
            OsString::from("--evidence-dir"),
            evidence_directory.as_os_str().to_owned(),
            OsString::from("--report"),
            OsString::from("release/reproducibility-result.v1.json"),
            OsString::from("--require-committed-clean"),
        ],
    )
}

fn run_native_macos_command_gate(
    root: &Path,
    spec: &PrdCommandSpec,
    evidence_directory: &Path,
    context: &CommandEvidenceContext,
    relative_directory: Option<&str>,
) -> Result<(), TaskError> {
    let (runtime, version_probe) = native_python_runtime(root)?;
    let producer = NATIVE_ADAPTER_CLOSURE
        .iter()
        .map(|relative| {
            snapshot_source_file(&root.join(relative))
                .map(|identity| ((*relative).to_owned(), identity))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut arguments = vec![
        OsString::from("crates/xtask/native_macos_command_plane.py"),
        OsString::from("run"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--route"),
        OsString::from(spec.id),
        OsString::from("--expected-source"),
        OsString::from(&context.expected_source),
        OsString::from("--evidence-dir"),
        evidence_directory.as_os_str().to_owned(),
        OsString::from("--expected-python-path"),
        runtime.path.as_os_str().to_owned(),
        OsString::from("--expected-python-sha256"),
        OsString::from(&runtime.sha256),
        OsString::from("--expected-python-version"),
        OsString::from(NATIVE_PYTHON_VERSION),
    ];
    if let Some(directory) = relative_directory {
        arguments.push(OsString::from("--relative-directory"));
        arguments.push(OsString::from(directory));
    }
    let timeout = match spec.implementation {
        PrdCommandImplementation::BenchEfficacy => Duration::from_secs(52 * 60 * 60),
        PrdCommandImplementation::PackageAll => Duration::from_secs(24 * 60 * 60),
        PrdCommandImplementation::TestSanitizers => Duration::from_secs(4 * 60 * 60),
        _ => Duration::from_secs(8 * 60 * 60),
    };
    let output = run_bounded_python(
        root,
        &runtime,
        &arguments,
        timeout,
        MAXIMUM_HELPER_OUTPUT_BYTES,
        MAXIMUM_HELPER_OUTPUT_BYTES,
        true,
    )?;
    if !output.status.success() {
        return Err(TaskError::new(format!(
            "native macOS command adapter failed with {}; output was suppressed",
            output.status
        )));
    }
    recheck_command_evidence_closure(&producer)?;
    let attachment = evidence_directory
        .join("command-plane")
        .join(format!("{}.raw.json", spec.id));
    let payload = fs::read(&attachment).map_err(|error| {
        TaskError::new(format!(
            "native macOS command runtime attachment is unavailable: {error}"
        ))
    })?;
    if payload.is_empty() || payload.len() > MAXIMUM_HELPER_OUTPUT_BYTES {
        return Err(TaskError::new(
            "native macOS command runtime attachment is empty or oversized",
        ));
    }
    let raw: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
        TaskError::new(format!(
            "native macOS command runtime attachment is not JSON: {error}"
        ))
    })?;
    let expected_runtime = serde_json::json!({
        "path": runtime.path,
        "bytes": runtime.bytes,
        "sha256": runtime.sha256,
        "authority": "operator-reviewed-sha256",
        "limitation": "transitive-runtime-files-not-bound",
        "version": NATIVE_PYTHON_VERSION,
        "version_probe": version_probe,
    });
    let expected_producer = serde_json::json!({
        "closure": producer
            .iter()
            .map(|(relative, identity)| {
                (relative.clone(), serde_json::json!({
                    "bytes": identity.bytes,
                    "sha256": identity.sha256,
                }))
            })
            .collect::<BTreeMap<_, _>>(),
    });
    if raw.get("runtime") != Some(&expected_runtime)
        || raw.get("producer") != Some(&expected_producer)
    {
        return Err(TaskError::new(
            "native macOS command attachment is not bound to its reviewed runtime and producer closure",
        ));
    }
    recheck_python_runtime(&runtime)
}

fn resolve_prd_28_1_command(
    arguments: &[String],
) -> Result<Option<&'static PrdCommandSpec>, TaskError> {
    for spec in PRD_28_1_COMMANDS {
        if arguments.len() != spec.arguments.len() {
            continue;
        }
        let mut matches = true;
        for (argument, expected) in arguments.iter().zip(spec.arguments) {
            match expected {
                PrdCommandArgument::Literal(value) if argument != value => {
                    matches = false;
                    break;
                }
                PrdCommandArgument::Literal(_) => {}
                PrdCommandArgument::SafeRelativePath { .. } => {
                    require_safe_relative_path(argument, &prd_command_display(spec))?;
                }
            }
        }
        if matches {
            return Ok(Some(spec));
        }
    }
    Ok(None)
}

fn execute_prd_28_1_command(
    root: &Path,
    spec: &PrdCommandSpec,
    command_arguments: &[String],
    evidence_directory: Option<&Path>,
) -> Result<(), TaskError> {
    if spec.implementation == PrdCommandImplementation::Unavailable {
        return unavailable(
            prd_command_display(spec)
                .strip_prefix("cargo xtask ")
                .unwrap_or(spec.id),
            spec.work_packet,
        );
    }
    let evidence_directory = require_prd_evidence_directory(spec, evidence_directory)?;
    let evidence = begin_command_evidence(root, evidence_directory)?;
    let uses_native_authority = matches!(
        spec.implementation,
        PrdCommandImplementation::BenchMicroVerify
            | PrdCommandImplementation::BenchMacroVerify
            | PrdCommandImplementation::BenchEfficacy
            | PrdCommandImplementation::PackageAll
            | PrdCommandImplementation::PackageSmoke
            | PrdCommandImplementation::ReleaseSbom
            | PrdCommandImplementation::ReleaseSign
            | PrdCommandImplementation::ReleaseAttest
            | PrdCommandImplementation::ReleaseVerify
            | PrdCommandImplementation::TestSanitizers
    );
    let _tool_authority_guard = if uses_native_authority {
        None
    } else {
        let authority = load_tool_authority(root, &evidence.expected_source, spec.id)?;
        Some(install_tool_authority(authority)?)
    };
    if spec.implementation == PrdCommandImplementation::TestCoverage {
        return run_coverage_gate(root, spec, evidence_directory, &evidence);
    }
    if spec.implementation == PrdCommandImplementation::TestMutations {
        return run_mutation_gate(root, spec, evidence_directory, &evidence);
    }
    let relative_directory = spec.arguments.iter().zip(command_arguments).find_map(
        |(argument, supplied)| match argument {
            PrdCommandArgument::SafeRelativePath { .. } => Some(supplied.as_str()),
            PrdCommandArgument::Literal(_) => None,
        },
    );
    let attachment = match spec.implementation {
        PrdCommandImplementation::BootstrapVerify => bootstrap(root),
        PrdCommandImplementation::FormatCheck => format_workspace(root, true),
        PrdCommandImplementation::GenerateCheck => generate(root, true),
        PrdCommandImplementation::Lint => lint(root),
        PrdCommandImplementation::DocsCheck => docs(root),
        PrdCommandImplementation::TestUnit => test(root, &["unit".to_owned()]),
        PrdCommandImplementation::TestVectors => test(root, &["vectors".to_owned()]),
        PrdCommandImplementation::TestConformance => test(root, &["conformance".to_owned()]),
        PrdCommandImplementation::TestMatrix(matrix) => {
            run_quality_matrix(root, matrix, Some(evidence_directory))
        }
        PrdCommandImplementation::ReleaseReproduce => {
            run_reproducibility_gate(root, evidence_directory)
        }
        PrdCommandImplementation::BenchMicroVerify
        | PrdCommandImplementation::BenchMacroVerify
        | PrdCommandImplementation::BenchEfficacy
        | PrdCommandImplementation::PackageAll
        | PrdCommandImplementation::PackageSmoke
        | PrdCommandImplementation::ReleaseSbom
        | PrdCommandImplementation::ReleaseSign
        | PrdCommandImplementation::ReleaseAttest
        | PrdCommandImplementation::ReleaseVerify
        | PrdCommandImplementation::TestSanitizers => run_native_macos_command_gate(
            root,
            spec,
            evidence_directory,
            &evidence,
            relative_directory,
        ),
        PrdCommandImplementation::TestCoverage
        | PrdCommandImplementation::TestMutations
        | PrdCommandImplementation::Unavailable => {
            return Err(TaskError::new(
                "authoritative command implementation routing invariant failed",
            ));
        }
    };
    attachment?;
    let native_attachment = format!("command-plane/{}.raw.json", spec.id);
    let attachment_relative = match spec.implementation {
        PrdCommandImplementation::TestMatrix(matrix) => Some(matrix.output),
        PrdCommandImplementation::ReleaseReproduce => {
            Some("release/reproducibility-result.v1.json")
        }
        PrdCommandImplementation::BenchMicroVerify
        | PrdCommandImplementation::BenchMacroVerify
        | PrdCommandImplementation::BenchEfficacy
        | PrdCommandImplementation::PackageAll
        | PrdCommandImplementation::PackageSmoke
        | PrdCommandImplementation::ReleaseSbom
        | PrdCommandImplementation::ReleaseSign
        | PrdCommandImplementation::ReleaseAttest
        | PrdCommandImplementation::ReleaseVerify
        | PrdCommandImplementation::TestSanitizers => Some(native_attachment.as_str()),
        _ => None,
    };
    finish_command_evidence(
        root,
        spec,
        evidence_directory,
        &evidence,
        attachment_relative,
    )
}

#[derive(Debug, Eq, PartialEq)]
struct GlobalArguments {
    command: Vec<String>,
    evidence_directory: Option<PathBuf>,
}

fn parse_global_arguments(arguments: Vec<String>) -> Result<GlobalArguments, TaskError> {
    let mut command = Vec::with_capacity(arguments.len());
    let mut evidence_directory = None;
    let mut index = 0_usize;
    while let Some(argument) = arguments.get(index) {
        if argument == "--evidence-dir" {
            if evidence_directory.is_some() {
                return Err(TaskError::new(
                    "duplicate global argument `--evidence-dir`; provide it exactly once",
                ));
            }
            let value = arguments.get(index + 1).ok_or_else(|| {
                TaskError::new("missing value for global argument `--evidence-dir`")
            })?;
            let path = PathBuf::from(value);
            validate_evidence_directory(&path)?;
            evidence_directory = Some(path);
            index += 2;
            continue;
        }
        if argument.starts_with("--evidence-dir=") {
            return Err(TaskError::new(
                "global `--evidence-dir` requires a separate absolute path value",
            ));
        }
        command.push(argument.clone());
        index += 1;
    }
    Ok(GlobalArguments {
        command,
        evidence_directory,
    })
}

fn validate_evidence_directory(path: &Path) -> Result<(), TaskError> {
    let Some(value) = path.to_str() else {
        return Err(TaskError::new(
            "global evidence directory must be valid Unicode",
        ));
    };
    if value.is_empty()
        || value.starts_with('-')
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(TaskError::new(
            "global evidence directory must be an absolute normalized path",
        ));
    }
    Ok(())
}

fn validate_global_evidence_selection(
    command_line: Option<&Path>,
    environment: Option<&OsStr>,
) -> Result<(), TaskError> {
    if command_line.is_some() && environment.is_some() {
        return Err(TaskError::new(
            "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide exactly one selector",
        ));
    }
    if let Some(value) = environment {
        validate_evidence_directory(Path::new(value))?;
    }
    Ok(())
}

fn selected_global_evidence_directory(
    command_line: Option<PathBuf>,
    environment: Option<OsString>,
) -> Result<Option<PathBuf>, TaskError> {
    validate_global_evidence_selection(command_line.as_deref(), environment.as_deref())?;
    Ok(command_line.or_else(|| environment.map(PathBuf::from)))
}

/// Executes one xtask command from an argument iterator.
pub fn run(arguments: impl IntoIterator<Item = String>) -> Result<(), TaskError> {
    let global = parse_global_arguments(arguments.into_iter().collect())?;
    let evidence_directory = selected_global_evidence_directory(
        global.evidence_directory,
        env::var_os("CIGAR_EVIDENCE_DIR"),
    )?;
    let arguments = global.command;
    let Some(command) = arguments.first() else {
        return Err(TaskError::new(usage()));
    };
    let root = workspace_root()?;
    if let Some(spec) = resolve_prd_28_1_command(&arguments)? {
        return execute_prd_28_1_command(&root, spec, &arguments, evidence_directory.as_deref());
    }
    if arguments == ["test", "sanitizers"] {
        let spec = NATIVE_EXTRA_COMMANDS
            .first()
            .ok_or_else(|| TaskError::new("sanitizer command authority is missing"))?;
        return execute_prd_28_1_command(&root, spec, &arguments, evidence_directory.as_deref());
    }
    let rest = arguments.get(1..).unwrap_or_default();

    match command.as_str() {
        "bootstrap" => {
            optional_flag(rest, "--verify", "cargo xtask bootstrap [--verify]")?;
            bootstrap(&root)
        }
        "generate" => generate(
            &root,
            optional_flag(rest, "--check", "cargo xtask generate [--check]")?,
        ),
        "vectors" => vectors(&root, rest),
        "fmt" => format_workspace(
            &root,
            optional_flag(rest, "--check", "cargo xtask fmt [--check]")?,
        ),
        "lint" => {
            require_no_arguments(rest, "cargo xtask lint")?;
            lint(&root)
        }
        "architecture-check" => {
            require_no_arguments(rest, "cargo xtask architecture-check")?;
            architecture_check(&root)
        }
        "conformance" => conformance(&root, rest),
        "test" => test(&root, rest),
        "docs" => {
            optional_flag(rest, "--check", "cargo xtask docs [--check]")?;
            docs(&root)
        }
        "fuzz" => fuzz(rest),
        "bench" => bench(rest),
        "package" => package(rest),
        "release" => release(rest),
        "release-verify" => release_verify(rest),
        "help" | "--help" | "-h" => {
            require_no_arguments(rest, "cargo xtask help")?;
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
    "usage: cargo xtask [--evidence-dir <absolute-directory>] <bootstrap|generate|vectors|fmt|lint|architecture-check|conformance|test|docs|fuzz|bench|package|release|release-verify>"
}

fn workspace_root() -> Result<PathBuf, TaskError> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_directory
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| TaskError::new("xtask is not located under <workspace>/crates/xtask"))
}

fn optional_flag(arguments: &[String], flag: &str, usage: &str) -> Result<bool, TaskError> {
    let mut seen = false;
    for argument in arguments {
        if argument != flag {
            return Err(TaskError::new(format!(
                "unexpected argument `{argument}`; usage: {usage}"
            )));
        }
        if seen {
            return Err(TaskError::new(format!(
                "duplicate argument `{flag}`; usage: {usage}"
            )));
        }
        seen = true;
    }
    Ok(seen)
}

fn require_no_arguments(arguments: &[String], usage: &str) -> Result<(), TaskError> {
    if let Some(argument) = arguments.first() {
        return Err(TaskError::new(format!(
            "unexpected argument `{argument}`; usage: {usage}"
        )));
    }
    Ok(())
}

fn required_flag(arguments: &[String], flag: &str, usage: &str) -> Result<(), TaskError> {
    if !optional_flag(arguments, flag, usage)? {
        return Err(TaskError::new(format!(
            "missing required argument `{flag}`; usage: {usage}"
        )));
    }
    Ok(())
}

fn require_safe_relative_path(argument: &str, usage: &str) -> Result<(), TaskError> {
    let path = Path::new(argument);
    let without_trailing_separator = argument.strip_suffix('/').unwrap_or(argument);
    if argument.is_empty()
        || without_trailing_separator.is_empty()
        || argument.starts_with('-')
        || argument.contains(['\\', ':', '\0'])
        || argument.chars().any(char::is_control)
        || path.is_absolute()
        || without_trailing_separator
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(TaskError::new(format!(
            "unsafe relative path `{argument}`; usage: {usage}"
        )));
    }
    Ok(())
}

fn unavailable(command: &str, packet: &str) -> Result<(), TaskError> {
    Err(TaskError::new(format!(
        "`cargo xtask {command}` is intentionally unavailable until {packet}; no placeholder success was returned"
    )))
}

fn fuzz(arguments: &[String]) -> Result<(), TaskError> {
    let usage = "cargo xtask fuzz <smoke|nightly>";
    let [suite] = arguments else {
        return Err(TaskError::new(format!("usage: {usage}")));
    };
    match suite.as_str() {
        "smoke" | "nightly" => unavailable(&format!("fuzz {suite}"), "WP19"),
        unknown => Err(TaskError::new(format!(
            "unknown fuzz suite `{unknown}`; usage: {usage}"
        ))),
    }
}

fn bench(arguments: &[String]) -> Result<(), TaskError> {
    let Some(suite) = arguments.first().map(String::as_str) else {
        return Err(TaskError::new(
            "usage: cargo xtask bench <smoke|micro --verify|macro --verify|efficacy>",
        ));
    };
    let rest = arguments.get(1..).unwrap_or_default();
    match suite {
        "smoke" | "efficacy" => {
            require_no_arguments(rest, &format!("cargo xtask bench {suite}"))?;
            unavailable(&format!("bench {suite}"), "WP20")
        }
        "micro" | "macro" => {
            required_flag(
                rest,
                "--verify",
                &format!("cargo xtask bench {suite} --verify"),
            )?;
            unavailable(&format!("bench {suite} --verify"), "WP20")
        }
        unknown => Err(TaskError::new(format!(
            "unknown benchmark suite `{unknown}`; usage: cargo xtask bench <smoke|micro --verify|macro --verify|efficacy>"
        ))),
    }
}

fn package(arguments: &[String]) -> Result<(), TaskError> {
    match arguments {
        [flag] if flag == "--all" => unavailable("package --all", "WP21"),
        [flag, directory] if flag == "--smoke" => {
            require_safe_relative_path(directory, "cargo xtask package --smoke <directory>")?;
            unavailable("package --smoke", "WP21")
        }
        [flag, profile]
            if flag == "--profile" && matches!(profile.as_str(), "local" | "shared") =>
        {
            unavailable(&format!("package --profile {profile}"), "WP21")
        }
        _ => Err(TaskError::new(
            "usage: cargo xtask package <--all|--smoke <directory>|--profile <local|shared>>",
        )),
    }
}

fn release(arguments: &[String]) -> Result<(), TaskError> {
    let Some(action) = arguments.first().map(String::as_str) else {
        return Err(TaskError::new(
            "usage: cargo xtask release <reproduce|sbom|sign|attest|verify <directory>>",
        ));
    };
    let rest = arguments.get(1..).unwrap_or_default();
    match action {
        "reproduce" | "sbom" | "sign" | "attest" => {
            require_no_arguments(rest, &format!("cargo xtask release {action}"))?;
            unavailable(&format!("release {action}"), "WP21")
        }
        "verify" => {
            let [directory] = rest else {
                return Err(TaskError::new(
                    "usage: cargo xtask release verify <directory>",
                ));
            };
            require_safe_relative_path(directory, "cargo xtask release verify <directory>")?;
            unavailable("release verify", "WP21")
        }
        unknown => Err(TaskError::new(format!(
            "unknown release action `{unknown}`; usage: cargo xtask release <reproduce|sbom|sign|attest|verify <directory>>"
        ))),
    }
}

fn release_verify(arguments: &[String]) -> Result<(), TaskError> {
    let [directory] = arguments else {
        return Err(TaskError::new(
            "usage: cargo xtask release-verify <directory>",
        ));
    };
    require_safe_relative_path(directory, "cargo xtask release-verify <directory>")?;
    unavailable("release-verify", "WP21")
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
            expected: "1.26.5",
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
        match inspect_tool(root, tool) {
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

fn inspect_tool(root: &Path, tool: Tool<'_>) -> Result<String, TaskError> {
    let arguments = tool
        .arguments
        .iter()
        .copied()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let output = run_reviewed_command(root, tool.program, &arguments).map_err(|error| {
        TaskError::new(format!(
            "{} is missing ({error}); expected {}, install: {}",
            tool.name, tool.expected, tool.install
        ))
    })?;
    let combined = combined_output(&output);
    if !output.status.success() {
        return Err(TaskError::new(format!(
            "{} could not run successfully; expected {}, install: {}; output was suppressed",
            tool.name, tool.expected, tool.install
        )));
    }
    if !combined.contains(tool.expected) {
        return Err(TaskError::new(format!(
            "{} version mismatch; expected {}, install: {}; output was suppressed",
            tool.name, tool.expected, tool.install
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
    match inspect_generator(
        root,
        "protoc-gen-go",
        &["--version"],
        "1.36.11",
        "go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11",
    ) {
        Ok(version) => println!("ok: protoc-gen-go: {}", version.trim()),
        Err(error) => missing.push(error.to_string()),
    }

    match inspect_generator(
        root,
        "protoc-gen-go-grpc",
        &["--version"],
        "1.6.2",
        "go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2",
    ) {
        Ok(version) => println!("ok: protoc-gen-go-grpc: {}", version.trim()),
        Err(error) => missing.push(error.to_string()),
    }

    match inspect_generator(
        root,
        "protoc-gen-es",
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
    arguments: &[&str],
    expected: &str,
    install: &str,
) -> Result<String, TaskError> {
    let arguments = arguments
        .iter()
        .copied()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let output = run_reviewed_command(root, name, &arguments).map_err(|error| {
        TaskError::new(format!(
            "{name} is missing ({error}); expected {expected}, install: {install}"
        ))
    })?;
    let combined = combined_output(&output);
    if !output.status.success() || !combined.contains(expected) {
        return Err(TaskError::new(format!(
            "{name} version mismatch; expected {expected}, install: {install}; output was suppressed"
        )));
    }
    Ok(combined)
}

fn go_plugin_path(root: &Path) -> Result<PathBuf, TaskError> {
    reviewed_tool_path(root, "protoc-gen-go")
}

fn go_grpc_plugin_path(root: &Path) -> Result<PathBuf, TaskError> {
    reviewed_tool_path(root, "protoc-gen-go-grpc")
}

fn reviewed_tool_path(_root: &Path, name: &str) -> Result<PathBuf, TaskError> {
    let authority = active_tool_authority().ok_or_else(|| {
        TaskError::new(format!(
            "reviewed tool `{name}` requires {TOOL_AUTHORITY_SELECTOR}"
        ))
    })?;
    let identity = authority
        .tools
        .get(name)
        .ok_or_else(|| TaskError::new(format!("reviewed tool authority omits `{name}`")))?;
    recheck_python_runtime(identity)?;
    Ok(identity.path.clone())
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
    generate_prd_command_manifest(root, check)?;
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

fn generate_prd_command_manifest(root: &Path, check: bool) -> Result<(), TaskError> {
    synchronize_rendered_artifacts(
        root,
        check,
        vec![
            (
                PathBuf::from("crates/xtask/prd-28.1-command-manifest.v1.json"),
                render_prd_command_manifest()?,
            ),
            (
                PathBuf::from("crates/xtask/generated/readme-command-inventory.md"),
                render_readme_command_inventory(),
            ),
            (
                PathBuf::from("crates/xtask/generated/ci-command-inventory.v1.json"),
                render_ci_command_inventory()?,
            ),
            (
                PathBuf::from("crates/xtask/generated/release-command-inventory.v1.json"),
                render_release_command_inventory()?,
            ),
        ],
    )
}

fn prd_command_gate_state(spec: &PrdCommandSpec) -> (&'static str, bool) {
    match spec.implementation {
        PrdCommandImplementation::Unavailable => ("unavailable", false),
        _ => ("implemented-with-source-bound-content-free-receipt", true),
    }
}

fn rendered_command_entry(spec: &PrdCommandSpec) -> serde_json::Value {
    let arguments: Vec<serde_json::Value> = spec
        .arguments
        .iter()
        .map(|argument| match argument {
            PrdCommandArgument::Literal(value) => serde_json::json!({
                "kind": "literal",
                "value": value,
            }),
            PrdCommandArgument::SafeRelativePath { name, example } => serde_json::json!({
                "kind": "safe-relative-path",
                "name": name,
                "example": example,
            }),
        })
        .collect();
    let (gate_state, receipt_implemented) = prd_command_gate_state(spec);
    serde_json::json!({
        "arguments": arguments,
        "command": prd_command_display(spec),
        "gate_state": gate_state,
        "id": spec.id,
        "release_eligible": false,
        "receipt": {
            "implemented": receipt_implemented,
            "required": true,
        },
        "work_packet": spec.work_packet,
    })
}

fn render_prd_command_manifest() -> Result<String, TaskError> {
    let commands: Vec<serde_json::Value> = PRD_28_1_COMMANDS
        .iter()
        .map(rendered_command_entry)
        .collect();
    let additional_commands: Vec<serde_json::Value> = NATIVE_EXTRA_COMMANDS
        .iter()
        .map(rendered_command_entry)
        .collect();
    let manifest = serde_json::json!({
        "additional_command_count": additional_commands.len(),
        "additional_commands": additional_commands,
        "authority": "crates/xtask/src/lib.rs::PRD_28_1_COMMANDS",
        "command_count": commands.len(),
        "commands": commands,
        "execution_policy": {
            "evidence_workspace": "absolute-external-create-new",
            "source_state": "clean-committed-git-checkout",
        },
        "generator": "cargo xtask generate",
        "platform_scope": ["macos-arm64"],
        "projections": {
            "ci": "crates/xtask/generated/ci-command-inventory.v1.json",
            "readme": "crates/xtask/generated/readme-command-inventory.md",
            "release": "crates/xtask/generated/release-command-inventory.v1.json",
        },
        "schema_version": 1,
        "source": "prd.md#28.1-clean-source-qualification",
    });
    let mut rendered = serde_json::to_string_pretty(&manifest).map_err(|error| {
        TaskError::new(format!("failed to render PRD command manifest: {error}"))
    })?;
    rendered.push('\n');
    Ok(rendered)
}

fn render_readme_command_inventory() -> String {
    let mut output = String::from(
        "<!-- generated by cargo xtask generate; edit PRD_28_1_COMMANDS instead -->\n\n\
# PRD 28.1 command inventory\n\n\
All successful implemented routes require native macOS arm64, a clean committed checkout,\n\
and an absolute external create-new evidence workspace.\n\
Unavailable routes fail closed and never emit placeholder success.\n\n\
| Command | Packet | Gate state |\n\
|---|---|---|\n",
    );
    for spec in PRD_28_1_COMMANDS {
        let (state, _receipt) = prd_command_gate_state(spec);
        output.push_str(&format!(
            "| `{}` | {} | `{state}` |\n",
            prd_command_display(spec),
            spec.work_packet
        ));
    }
    output.push_str("\n## Additional native qualification commands\n\n");
    for spec in NATIVE_EXTRA_COMMANDS {
        let (state, _receipt) = prd_command_gate_state(spec);
        output.push_str(&format!(
            "| `{}` | {} | `{state}` |\n",
            prd_command_display(spec),
            spec.work_packet
        ));
    }
    output
}

fn render_command_projection(
    schema_version: &str,
    audience: &str,
    include_unavailable: bool,
) -> Result<String, TaskError> {
    let commands = PRD_28_1_COMMANDS
        .iter()
        .chain(NATIVE_EXTRA_COMMANDS)
        .filter(|spec| {
            include_unavailable || spec.implementation != PrdCommandImplementation::Unavailable
        })
        .map(|spec| {
            let (gate_state, receipt_implemented) = prd_command_gate_state(spec);
            serde_json::json!({
                "command": prd_command_display(spec),
                "gate_state": gate_state,
                "id": spec.id,
                "receipt_required": true,
                "receipt_implemented": receipt_implemented,
                "release_eligible": false,
                "work_packet": spec.work_packet,
            })
        })
        .collect::<Vec<_>>();
    let projection = serde_json::json!({
        "audience": audience,
        "authority": "crates/xtask/src/lib.rs::PRD_28_1_COMMANDS",
        "command_count": commands.len(),
        "commands": commands,
        "execution_policy": {
            "evidence_workspace": "absolute-external-create-new",
            "source_state": "clean-committed-git-checkout",
        },
        "generated_by": "cargo xtask generate",
        "platform_scope": ["macos-arm64"],
        "schema_version": schema_version,
    });
    let mut rendered = serde_json::to_string_pretty(&projection).map_err(|error| {
        TaskError::new(format!(
            "failed to render {audience} command inventory: {error}"
        ))
    })?;
    rendered.push('\n');
    Ok(rendered)
}

fn render_ci_command_inventory() -> Result<String, TaskError> {
    render_command_projection("cigar.xtask-ci-command-inventory.v1", "ci", false)
}

fn render_release_command_inventory() -> Result<String, TaskError> {
    render_command_projection(
        "cigar.xtask-release-command-inventory.v1",
        "release-qualification",
        true,
    )
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
    if arguments.len() > 1 {
        return Err(TaskError::new("usage: cargo xtask vectors <update|check>"));
    }
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
    let catalog = load_error_catalog(root)?;
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

fn load_error_catalog(root: &Path) -> Result<ErrorCatalog, TaskError> {
    let source = fs::read_to_string(root.join("spec/errors/catalog.yaml"))?;
    let catalog: ErrorCatalog = yaml_serde::from_str(&source)
        .map_err(|error| TaskError::new(format!("invalid error catalog YAML: {error}")))?;
    validate_error_catalog(&catalog)?;
    Ok(catalog)
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
    let mut previous_code = None;
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
        let valid_grpc = !entry.grpc.is_empty()
            && entry
                .grpc
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_');
        if !codes.insert(entry.code)
            || !names.insert(entry.name.as_str())
            || !valid_name
            || !valid_retry
            || !(400..=599).contains(&entry.http)
            || !valid_grpc
            || previous_code.is_some_and(|previous| entry.code <= previous)
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
        previous_code = Some(entry.code);
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
    let errors = load_error_catalog(root)?;
    let projections = load_interface_projection_catalog(root, &catalog, &payloads)?;
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
        (
            PathBuf::from("crates/cigar-cli/src/generated/operation_mappings.rs"),
            render_cli_operation_mappings(&projections.cli),
        ),
        (
            PathBuf::from("crates/cigar-mcp/src/generated/operation_mappings.rs"),
            render_mcp_operation_mappings(&projections.mcp),
        ),
        (
            PathBuf::from("crates/cigar-dashboard/src/generated/protocol-catalog-v1.json"),
            render_dashboard_protocol_projection(&catalog, &payloads, &errors)?,
        ),
        (
            PathBuf::from("schemas/dashboard/dashboard-protocol-v1.schema.json"),
            render_dashboard_protocol_schema(&catalog, &errors)?,
        ),
        (
            PathBuf::from("spec/api/operations-v1.md"),
            render_normative_operation_table(&catalog, &payloads, &errors, &projections)?,
        ),
    ];
    synchronize_rendered_artifacts(root, check, artifacts)
}

fn load_interface_projection_catalog(
    root: &Path,
    operations: &OperationCatalog,
    payloads: &OperationPayloadCatalog,
) -> Result<InterfaceProjectionCatalog, TaskError> {
    let source = fs::read_to_string(root.join("spec/api/interface-projections-v1.json"))?;
    let projections: InterfaceProjectionCatalog =
        serde_json::from_str(&source).map_err(|error| {
            TaskError::new(format!(
                "invalid interface projection catalog JSON: {error}"
            ))
        })?;
    validate_interface_projection_catalog(&projections, operations, payloads)?;
    Ok(projections)
}

fn validate_interface_projection_catalog(
    projections: &InterfaceProjectionCatalog,
    operations: &OperationCatalog,
    payloads: &OperationPayloadCatalog,
) -> Result<(), TaskError> {
    if projections.schema_version != 1
        || projections.status != "development-closed"
        || projections.cli.mapping_count != 34
        || projections.cli.mappings.len() != projections.cli.mapping_count
        || projections.mcp.mapping_count != 10
        || projections.mcp.mappings.len() != projections.mcp.mapping_count
    {
        return Err(TaskError::new(
            "interface projections must be the closed 34-command CLI and 10-tool MCP surfaces",
        ));
    }

    let contracts: BTreeMap<_, _> = operations
        .services
        .iter()
        .flat_map(|service| &service.operations)
        .map(|operation| (operation.operation_id.as_str(), operation))
        .collect();
    let payload_ids: BTreeSet<_> = payloads
        .operations
        .iter()
        .map(|payload| payload.operation_id.as_str())
        .collect();

    let mut cli_names = BTreeSet::new();
    let mut canonical_cli_operations = BTreeMap::new();
    for mapping in &projections.cli.mappings {
        let operation = validate_projection_mapping(
            "CLI command",
            &mapping.exposed_name,
            &mapping.operation_id,
            &mapping.operation_kind,
            &contracts,
            &payload_ids,
            valid_cli_exposed_name,
        )?;
        if !cli_names.insert(mapping.exposed_name.as_str()) {
            return Err(TaskError::new(format!(
                "duplicate CLI projection `{}`",
                mapping.exposed_name
            )));
        }
        if mapping.alias_of.is_none()
            && canonical_cli_operations
                .insert(
                    operation.operation_id.as_str(),
                    mapping.exposed_name.as_str(),
                )
                .is_some()
        {
            return Err(TaskError::new(format!(
                "CLI operation `{}` has more than one canonical command",
                operation.operation_id
            )));
        }
    }
    let cli_by_name: BTreeMap<_, _> = projections
        .cli
        .mappings
        .iter()
        .map(|mapping| (mapping.exposed_name.as_str(), mapping))
        .collect();
    for mapping in &projections.cli.mappings {
        let Some(alias_of) = mapping.alias_of.as_deref() else {
            continue;
        };
        let canonical = cli_by_name.get(alias_of).ok_or_else(|| {
            TaskError::new(format!(
                "CLI alias `{}` references missing command `{alias_of}`",
                mapping.exposed_name
            ))
        })?;
        if alias_of == mapping.exposed_name
            || canonical.alias_of.is_some()
            || canonical.operation_id != mapping.operation_id
            || canonical_cli_operations
                .get(mapping.operation_id.as_str())
                .copied()
                != Some(alias_of)
        {
            return Err(TaskError::new(format!(
                "CLI alias `{}` does not bind one canonical operation mapping",
                mapping.exposed_name
            )));
        }
    }

    let mut mcp_names = BTreeSet::new();
    let mut mcp_operations = BTreeSet::new();
    for mapping in &projections.mcp.mappings {
        let operation = validate_projection_mapping(
            "MCP tool",
            &mapping.exposed_name,
            &mapping.operation_id,
            &mapping.operation_kind,
            &contracts,
            &payload_ids,
            valid_mcp_exposed_name,
        )?;
        if !mcp_names.insert(mapping.exposed_name.as_str())
            || !mcp_operations.insert(operation.operation_id.as_str())
            || !matches!(
                mapping.authority_lane.as_str(),
                "context_read"
                    | "catalog_read"
                    | "coordination_write"
                    | "effect_prepare"
                    | "effect_commit"
                    | "effect_read"
            )
        {
            return Err(TaskError::new(format!(
                "invalid or duplicate MCP projection `{}`",
                mapping.exposed_name
            )));
        }
    }
    Ok(())
}

fn validate_projection_mapping<'a>(
    surface: &str,
    exposed_name: &str,
    operation_id: &str,
    operation_kind: &str,
    contracts: &BTreeMap<&str, &'a OperationEntry>,
    payload_ids: &BTreeSet<&str>,
    valid_name: fn(&str) -> bool,
) -> Result<&'a OperationEntry, TaskError> {
    let operation = contracts.get(operation_id).copied().ok_or_else(|| {
        TaskError::new(format!(
            "{surface} `{exposed_name}` references unknown operation `{operation_id}`"
        ))
    })?;
    let expected_kind = if operation.mutation {
        "mutation"
    } else {
        "read"
    };
    if !valid_name(exposed_name)
        || operation_kind != expected_kind
        || !payload_ids.contains(operation_id)
    {
        return Err(TaskError::new(format!(
            "{surface} `{exposed_name}` has a mismatched operation kind or payload contract"
        )));
    }
    Ok(operation)
}

fn valid_cli_exposed_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.split('.').all(valid_projection_name_part)
}

fn valid_mcp_exposed_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && valid_projection_name_part(value)
}

fn valid_projection_name_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
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
    let problem_schema: serde_json::Value = serde_json::from_str(&render_schema::<
        cigar_protocol::Problem,
    >("Problem")?)
    .map_err(|error| {
        TaskError::new(format!(
            "failed to load the frozen Problem schema for OpenAPI: {error}"
        ))
    })?;
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
                "Problem": problem_schema
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

fn render_cli_operation_mappings(catalog: &CliProjectionCatalog) -> String {
    let mut output = String::from(
        r#"// @generated by cargo xtask generate from spec/api/interface-projections-v1.json.

/// One explicitly exposed CLI command backed by a frozen protocol operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CliOperationMapping {
    pub(crate) exposed_name: &'static str,
    pub(crate) operation_id: &'static str,
    pub(crate) mutation: bool,
}

/// Closed operation-backed CLI surface. Administrative commands are intentionally absent.
pub(crate) const CLI_OPERATION_MAPPINGS: &[CliOperationMapping] = &[
"#,
    );
    for mapping in &catalog.mappings {
        output.push_str(&format!(
            "    CliOperationMapping {{\n        exposed_name: {},\n        operation_id: {},\n        mutation: {},\n    }},\n",
            rust_string(&mapping.exposed_name),
            rust_string(&mapping.operation_id),
            mapping.operation_kind == "mutation",
        ));
    }
    output.push_str(
        r#"];

/// Resolves only commands explicitly exposed by the closed mapping authority.
#[must_use]
pub(crate) fn cli_operation_mapping(exposed_name: &str) -> Option<&'static CliOperationMapping> {
    CLI_OPERATION_MAPPINGS
        .iter()
        .find(|mapping| mapping.exposed_name == exposed_name)
}
"#,
    );
    output
}

fn render_mcp_operation_mappings(catalog: &McpProjectionCatalog) -> String {
    let mut output = String::from(
        r#"// @generated by cargo xtask generate from spec/api/interface-projections-v1.json.

/// One explicitly exposed MCP tool backed by a frozen protocol operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct McpOperationMapping {
    pub(crate) exposed_name: &'static str,
    pub(crate) operation_id: &'static str,
    pub(crate) mutation: bool,
    pub(crate) authority_lane: &'static str,
}

/// Closed operation-backed MCP tool surface. Unimplemented protocol operations are absent.
pub(crate) const MCP_OPERATION_MAPPINGS: &[McpOperationMapping] = &[
"#,
    );
    for mapping in &catalog.mappings {
        output.push_str(&format!(
            "    McpOperationMapping {{\n        exposed_name: {},\n        operation_id: {},\n        mutation: {},\n        authority_lane: {},\n    }},\n",
            rust_string(&mapping.exposed_name),
            rust_string(&mapping.operation_id),
            mapping.operation_kind == "mutation",
            rust_string(&mapping.authority_lane),
        ));
    }
    output.push_str(
        r#"];

/// Resolves only tools explicitly exposed by the closed mapping authority.
#[must_use]
pub(crate) fn mcp_operation_mapping(exposed_name: &str) -> Option<&'static McpOperationMapping> {
    MCP_OPERATION_MAPPINGS
        .iter()
        .find(|mapping| mapping.exposed_name == exposed_name)
}
"#,
    );
    output
}

fn payload_field_projection(field: &PayloadField) -> serde_json::Value {
    serde_json::json!({
        "bound": field.bound,
        "name": field.name,
        "source": field.source,
    })
}

fn render_dashboard_protocol_projection(
    catalog: &OperationCatalog,
    payloads: &OperationPayloadCatalog,
    errors: &ErrorCatalog,
) -> Result<String, TaskError> {
    let payload_by_id: BTreeMap<_, _> = payloads
        .operations
        .iter()
        .map(|payload| (payload.operation_id.as_str(), payload))
        .collect();
    let mut services = Vec::with_capacity(catalog.services.len());
    for service in &catalog.services {
        let mut operations = Vec::with_capacity(service.operations.len());
        for operation in &service.operations {
            let payload = payload_by_id
                .get(operation.operation_id.as_str())
                .copied()
                .ok_or_else(|| {
                    TaskError::new(format!(
                        "dashboard projection is missing payload `{}`",
                        operation.operation_id
                    ))
                })?;
            operations.push(serde_json::json!({
                "auth": operation.auth_class,
                "http_method": operation.http_method,
                "http_path": operation.http_path,
                "idempotency": operation.idempotency_requirement,
                "mutation": operation.mutation,
                "operation_id": operation.operation_id,
                "payload": {
                    "event_fields": payload.event_fields.iter().map(payload_field_projection).collect::<Vec<_>>(),
                    "event_max_bytes": payload.event_max_bytes,
                    "event_schema": payload.event_schema,
                    "request_fields": payload.request_fields.iter().map(payload_field_projection).collect::<Vec<_>>(),
                    "request_max_bytes": payload.request_max_bytes,
                    "request_schema": payload.request_schema,
                    "response_fields": payload.response_fields.iter().map(payload_field_projection).collect::<Vec<_>>(),
                    "response_max_bytes": payload.response_max_bytes,
                    "response_schema": payload.response_schema,
                },
                "revision": operation.revision_requirement,
                "rpc": operation.rpc,
                "service": service.name,
                "stream": operation.stream_kind,
            }));
        }
        services.push(serde_json::json!({
            "name": service.name,
            "operations": operations,
        }));
    }
    let error_rows = errors
        .errors
        .iter()
        .map(|entry| {
            serde_json::json!({
                "disclose_identity": entry.disclose_identity,
                "grpc_status": entry.grpc,
                "http_status": entry.http,
                "numeric_code": entry.code,
                "retry": entry.retry,
                "symbol": entry.name,
            })
        })
        .collect::<Vec<_>>();
    let projection = serde_json::json!({
        "envelope_fields": payloads.envelope_fields.iter().map(payload_field_projection).collect::<Vec<_>>(),
        "error_count": errors.errors.len(),
        "errors": error_rows,
        "operation_count": catalog.operation_count,
        "schema_version": "cigar.dashboard-protocol.v1",
        "service_count": catalog.services.len(),
        "services": services,
        "source": "cargo-xtask-interface-projection",
    });
    let mut rendered = serde_json::to_string(&projection).map_err(|error| {
        TaskError::new(format!("failed to render dashboard projection: {error}"))
    })?;
    if rendered.contains(['<', '>']) || rendered.contains("\\u2028") || rendered.contains("\\u2029")
    {
        return Err(TaskError::new(
            "dashboard protocol projection contains browser-unsafe text",
        ));
    }
    rendered.push('\n');
    Ok(rendered)
}

fn render_dashboard_protocol_schema(
    catalog: &OperationCatalog,
    errors: &ErrorCatalog,
) -> Result<String, TaskError> {
    let schema = serde_json::json!({
        "$defs": {
            "error": {
                "additionalProperties": false,
                "properties": {
                    "disclose_identity": { "type": "boolean" },
                    "grpc_status": { "pattern": "^[A-Z][A-Z_]{0,63}$", "type": "string" },
                    "http_status": { "maximum": 599, "minimum": 400, "type": "integer" },
                    "numeric_code": { "maximum": 999999, "minimum": 1, "type": "integer" },
                    "retry": { "enum": ["never", "safe", "after_backoff", "after_reauthorization", "after_reconciliation"] },
                    "symbol": { "pattern": "^[A-Z][A-Z0-9_]{0,127}$", "type": "string" },
                },
                "required": ["numeric_code", "symbol", "http_status", "grpc_status", "retry", "disclose_identity"],
                "type": "object",
            },
            "field": {
                "additionalProperties": false,
                "properties": {
                    "bound": { "maxLength": 256, "minLength": 1, "pattern": "^[a-z0-9_,.=]+$", "type": "string" },
                    "name": { "maxLength": 64, "pattern": "^[a-z][a-z0-9_]*$", "type": "string" },
                    "source": { "enum": ["caller", "envelope", "path", "server", "transport"] },
                },
                "required": ["name", "source", "bound"],
                "type": "object",
            },
            "operation": {
                "additionalProperties": false,
                "properties": {
                    "auth": { "enum": ["tenant", "operator", "health", "anonymous"] },
                    "http_method": { "enum": ["GET", "POST"] },
                    "http_path": { "maxLength": 512, "pattern": "^/\\S*$", "type": "string" },
                    "idempotency": { "enum": ["required", "not_applicable"] },
                    "mutation": { "type": "boolean" },
                    "operation_id": { "maxLength": 128, "pattern": "^[a-z][A-Za-z0-9]*$", "type": "string" },
                    "payload": { "$ref": "#/$defs/payload" },
                    "revision": { "enum": ["none", "required"] },
                    "rpc": { "maxLength": 128, "pattern": "^[A-Z][A-Za-z0-9]*$", "type": "string" },
                    "service": { "maxLength": 64, "pattern": "^[A-Z][A-Za-z0-9]*Service$", "type": "string" },
                    "stream": { "enum": ["unary", "server_stream"] },
                },
                "required": ["service", "rpc", "operation_id", "http_method", "http_path", "mutation", "idempotency", "revision", "stream", "auth", "payload"],
                "type": "object",
            },
            "payload": {
                "additionalProperties": false,
                "properties": {
                    "event_fields": { "items": { "$ref": "#/$defs/field" }, "maxItems": 64, "type": "array" },
                    "event_max_bytes": { "maximum": 1048576, "minimum": 0, "type": "integer" },
                    "event_schema": { "oneOf": [{ "maxLength": 128, "pattern": "^[A-Z][A-Za-z0-9]*$", "type": "string" }, { "type": "null" }] },
                    "request_fields": { "items": { "$ref": "#/$defs/field" }, "maxItems": 64, "type": "array" },
                    "request_max_bytes": { "maximum": 16777216, "minimum": 1, "type": "integer" },
                    "request_schema": { "maxLength": 128, "pattern": "^[A-Z][A-Za-z0-9]*$", "type": "string" },
                    "response_fields": { "items": { "$ref": "#/$defs/field" }, "maxItems": 64, "type": "array" },
                    "response_max_bytes": { "maximum": 16777216, "minimum": 1, "type": "integer" },
                    "response_schema": { "maxLength": 128, "pattern": "^[A-Z][A-Za-z0-9]*$", "type": "string" },
                },
                "required": ["request_schema", "response_schema", "event_schema", "request_max_bytes", "response_max_bytes", "event_max_bytes", "request_fields", "response_fields", "event_fields"],
                "type": "object",
            },
            "service": {
                "additionalProperties": false,
                "properties": {
                    "name": { "maxLength": 64, "pattern": "^[A-Z][A-Za-z0-9]*Service$", "type": "string" },
                    "operations": { "items": { "$ref": "#/$defs/operation" }, "maxItems": 45, "minItems": 1, "type": "array" },
                },
                "required": ["name", "operations"],
                "type": "object",
            },
        },
        "$id": "https://cigar.dev/schemas/dashboard/dashboard-protocol-v1.schema.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "envelope_fields": { "items": { "$ref": "#/$defs/field" }, "maxItems": 6, "minItems": 6, "type": "array" },
            "error_count": { "const": errors.errors.len() },
            "errors": { "items": { "$ref": "#/$defs/error" }, "maxItems": errors.errors.len(), "minItems": errors.errors.len(), "type": "array" },
            "operation_count": { "const": catalog.operation_count },
            "schema_version": { "const": "cigar.dashboard-protocol.v1" },
            "service_count": { "const": catalog.services.len() },
            "services": { "items": { "$ref": "#/$defs/service" }, "maxItems": catalog.services.len(), "minItems": catalog.services.len(), "type": "array" },
            "source": { "const": "cargo-xtask-interface-projection" },
        },
        "required": ["schema_version", "source", "service_count", "operation_count", "error_count", "envelope_fields", "services", "errors"],
        "title": "CIGAR dashboard generated protocol catalog v1",
        "type": "object",
    });
    let mut rendered = serde_json::to_string_pretty(&schema).map_err(|error| {
        TaskError::new(format!(
            "failed to render dashboard protocol schema: {error}"
        ))
    })?;
    rendered.push('\n');
    Ok(rendered)
}

fn render_normative_operation_table(
    catalog: &OperationCatalog,
    payloads: &OperationPayloadCatalog,
    errors: &ErrorCatalog,
    projections: &InterfaceProjectionCatalog,
) -> Result<String, TaskError> {
    let payload_by_id: BTreeMap<_, _> = payloads
        .operations
        .iter()
        .map(|payload| (payload.operation_id.as_str(), payload))
        .collect();
    let mut output = String::from(
        "<!-- @generated by cargo xtask generate; do not edit. -->\n\n\
# Exact v1 development interface projection\n\n\
Status: exact generated projection for this development source tree, not a released or frozen\n\
compatibility promise. Sources are `operations-v1.json`, `operation-payloads-v1.json`,\n\
`interface-projections-v1.json`, and the generated error/retry registry.\n\n\
The protocol has exactly 7 services and 45 operations. CLI and MCP tables below are deliberately\n\
closed subsets: absence means the command or tool is not implemented on that surface. Error retry\n\
guidance comes from `spec/errors/catalog.yaml`; it is distinct from an SDK's request replay policy.\n\n\
## Operations\n\n\
| Service | RPC | Operation ID | HTTP | Mutates | Idempotency | Revision | Stream | Auth | Request | Response / event | Max bytes (request / response / event) |\n\
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for service in &catalog.services {
        for operation in &service.operations {
            let payload = payload_by_id
                .get(operation.operation_id.as_str())
                .copied()
                .ok_or_else(|| {
                    TaskError::new(format!(
                        "normative table is missing payload `{}`",
                        operation.operation_id
                    ))
                })?;
            let response = payload.event_schema.as_deref().map_or_else(
                || format!("`{}`", payload.response_schema),
                |event| format!("`{}` / `{event}`", payload.response_schema),
            );
            output.push_str(&format!(
                "| {} | `{}` | `{}` | `{} {}` | {} | {} | {} | {} | {} | `{}` | {} | {} / {} / {} |\n",
                service.name,
                operation.rpc,
                operation.operation_id,
                operation.http_method,
                operation.http_path,
                if operation.mutation { "yes" } else { "no" },
                operation.idempotency_requirement,
                operation.revision_requirement,
                operation.stream_kind,
                operation.auth_class,
                payload.request_schema,
                response,
                payload.request_max_bytes,
                payload.response_max_bytes,
                payload.event_max_bytes,
            ));
        }
    }

    output.push_str(
        "\n## Shared envelope fields\n\n\
| Field | Authority source | Bound |\n\
| --- | --- | --- |\n",
    );
    for field in &payloads.envelope_fields {
        output.push_str(&format!(
            "| `{}` | {} | `{}` |\n",
            field.name, field.source, field.bound
        ));
    }

    output.push_str(
        "\n## Operation-backed CLI commands\n\n\
Administrative commands are outside the service protocol and therefore do not appear here.\n\n\
| Command | Operation ID | Kind | Alias of |\n\
| --- | --- | --- | --- |\n",
    );
    for mapping in &projections.cli.mappings {
        output.push_str(&format!(
            "| `cigar {}` | `{}` | {} | {} |\n",
            mapping.exposed_name.replace('.', " "),
            mapping.operation_id,
            mapping.operation_kind,
            mapping
                .alias_of
                .as_deref()
                .map_or("-".to_owned(), |value| format!("`{value}`")),
        ));
    }

    output.push_str(
        "\n## MCP tools\n\n\
| Tool | Operation ID | Kind | Authority lane |\n\
| --- | --- | --- | --- |\n",
    );
    for mapping in &projections.mcp.mappings {
        output.push_str(&format!(
            "| `{}` | `{}` | {} | `{}` |\n",
            mapping.exposed_name,
            mapping.operation_id,
            mapping.operation_kind,
            mapping.authority_lane,
        ));
    }

    output.push_str(
        "\n## Error retry registry\n\n\
| Code | Symbol | HTTP | gRPC | Retry | Identity disclosure |\n\
| --- | --- | --- | --- | --- | --- |\n",
    );
    for entry in &errors.errors {
        output.push_str(&format!(
            "| {} | `{}` | {} | `{}` | `{}` | {} |\n",
            entry.code,
            entry.name,
            entry.http,
            entry.grpc,
            entry.retry,
            if entry.disclose_identity { "yes" } else { "no" },
        ));
    }
    Ok(output)
}

fn upper_snake_rpc(rpc: &str) -> String {
    let mut output = String::with_capacity(rpc.len().saturating_add(8));
    for (index, character) in rpc.chars().enumerate() {
        if index > 0 && character.is_ascii_uppercase() {
            output.push('_');
        }
        output.push(character.to_ascii_uppercase());
    }
    output
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

/// One authoritative generated binding used by transports and checked interface projections.
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
        "/// Number of frozen v1 operations.\npub const OPERATION_COUNT: usize = {};\n\n",
        catalog.operation_count
    ));
    output.push_str(
        "/// Stable operation identifiers for audit records, telemetry, and internal dispatch.\n\
pub mod operation_ids {\n",
    );
    for operation in catalog
        .services
        .iter()
        .flat_map(|service| &service.operations)
    {
        output.push_str(&format!(
            "    /// `{}`.\n    pub const {}: &str = {};\n",
            operation.operation_id,
            upper_snake_rpc(&operation.rpc),
            rust_string(&operation.operation_id),
        ));
    }
    output.push_str("}\n\n/// Complete frozen v1 operation registry.\npub const OPERATIONS: &[OperationContract] = &[\n");
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
        "];\n\n/// Finds a frozen v1 operation by its shared operation identifier.\n#[must_use]\npub fn operation_by_id(operation_id: &str) -> Option<&'static OperationContract> {\n    match operation_id {\n",
    );
    for (index, operation) in catalog
        .services
        .iter()
        .flat_map(|service| &service.operations)
        .enumerate()
    {
        let lookup = if index == 0 {
            "OPERATIONS.first()".to_owned()
        } else {
            format!("OPERATIONS.get({index})")
        };
        output.push_str(&format!(
            "        operation_ids::{} => {lookup},\n",
            upper_snake_rpc(&operation.rpc),
        ));
    }
    output.push_str(
        "        _ => None,\n    }\n}\n\n/// Returns whether an audit or telemetry identity is a frozen v1 operation.\n#[must_use]\npub fn is_known_operation_id(operation_id: &str) -> bool {\n    operation_by_id(operation_id).is_some()\n}\n",
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
                reviewed_tool_path(root, "protoc-gen-es")?.display()
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
            PathBuf::from("schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json"),
            include_str!("../../../schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json")
                .to_owned(),
        ),
        (
            PathBuf::from(
                "crates/cigar-store/schemas/sqlite-v4-v5-migration-receipt-v1.schema.json",
            ),
            include_str!("../../../schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json")
                .to_owned(),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClippyProfile {
    name: &'static str,
    arguments: &'static [&'static str],
}

// Cargo features are additive, so `--all-features` cannot represent this workspace: the CLI's
// `full` and `beta-embedded` modes are mutually exclusive, as are the synchronous and Tokio S3
// backends. Keep every supported composition explicit so a new feature cannot silently turn the
// strict lint gate into a compile-error-only check.
const CLIPPY_PROFILES: &[ClippyProfile] = &[
    ClippyProfile {
        name: "workspace-default",
        arguments: &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--exclude",
            "cigar-soak",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-cli-beta-embedded",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-cli",
            "--no-default-features",
            "--features",
            "beta-embedded",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-sdk-remote",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-sdk",
            "--no-default-features",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-aws-creds-no-http",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-aws-creds-http-no-tls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "http-credentials",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-aws-creds-native-tls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "native-tls",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-aws-creds-native-tls-vendored",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "native-tls-vendored",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-aws-creds-rustls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "rustls-tls",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-sync-no-tls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-sync-native-tls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-native-tls",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-sync-native-tls-vendored",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-native-tls-vendored",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-sync-rustls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-rustls-tls",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-sync-orthogonal",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-rustls-tls,fail-on-err,http-credentials,tags",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-tokio-no-tls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "with-tokio",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-tokio-native-tls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "tokio-native-tls",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-tokio-rustls",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "tokio-rustls-tls",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    ClippyProfile {
        name: "cigar-rust-s3-tokio-orthogonal",
        arguments: &[
            "clippy",
            "--locked",
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "tokio-rustls-tls,blocking,fail-on-err,http-credentials,tags",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
];

fn lint(root: &Path) -> Result<(), TaskError> {
    scan_sources(root)?;
    validate_manifest_pins(root)?;
    validate_rustls_provider_contract(root)?;
    architecture_check(root)?;
    for profile in CLIPPY_PROFILES {
        println!("linting Rust composition `{}`", profile.name);
        let arguments = profile
            .arguments
            .iter()
            .copied()
            .map(OsString::from)
            .collect::<Vec<_>>();
        run_command(root, "cargo", &arguments)?;
    }
    run_command(
        root,
        "cargo",
        &[
            OsString::from("deny"),
            OsString::from("--locked"),
            OsString::from("check"),
        ],
    )
}

fn test(root: &Path, arguments: &[String]) -> Result<(), TaskError> {
    let suite = arguments.first().map(String::as_str).unwrap_or("all");
    let rest = arguments.get(1..).unwrap_or_default();
    match suite {
        "unit" | "wp00" => {
            require_no_arguments(rest, &format!("cargo xtask test {suite}"))?;
            run_command(
                root,
                "cargo",
                &[
                    OsString::from("nextest"),
                    OsString::from("run"),
                    OsString::from("--workspace"),
                    OsString::from("--all-targets"),
                ],
            )
        }
        "property" => {
            require_no_arguments(rest, "cargo xtask test property")?;
            run_command(
                root,
                "cargo",
                &[
                    OsString::from("nextest"),
                    OsString::from("run"),
                    OsString::from("--locked"),
                    OsString::from("--manifest-path"),
                    OsString::from("tests/properties/Cargo.toml"),
                    OsString::from("--config-file"),
                    OsString::from("tests/properties/.config/nextest.toml"),
                    OsString::from("--user-config-file"),
                    OsString::from("none"),
                    OsString::from("--all-targets"),
                ],
            )
        }
        "conformance" => {
            require_no_arguments(rest, "cargo xtask test conformance")?;
            test_conformance(root)
        }
        "all" => {
            require_no_arguments(rest, "cargo xtask test all")?;
            unavailable("test all", "WP19")
        }
        "vectors" => {
            require_no_arguments(rest, "cargo xtask test vectors")?;
            verify_vector_suite(root)
        }
        "coverage" | "mutations" => {
            required_flag(
                rest,
                "--verify",
                &format!("cargo xtask test {suite} --verify"),
            )?;
            unavailable(&format!("test {suite} --verify"), "WP19")
        }
        "compatibility" | "integration" | "e2e" | "security" | "offline" | "models" | "chaos"
        | "migrations" => {
            require_no_arguments(rest, &format!("cargo xtask test {suite}"))?;
            let matrix = match suite {
                "compatibility" => COMPATIBILITY_MATRIX,
                "integration" => INTEGRATION_MATRIX,
                "e2e" => E2E_MATRIX,
                "security" => SECURITY_MATRIX,
                "offline" => OFFLINE_MATRIX,
                "models" => MODELS_MATRIX,
                "chaos" => CHAOS_MATRIX,
                "migrations" => MIGRATION_MATRIX,
                _ => return Err(TaskError::new("quality matrix routing invariant failed")),
            };
            run_quality_matrix(root, matrix, None)
        }
        "sanitizers" => {
            require_no_arguments(rest, "cargo xtask test sanitizers")?;
            unavailable("test sanitizers", "WP19")
        }
        unknown => Err(TaskError::new(format!("unknown test suite `{unknown}`"))),
    }
}

fn conformance(root: &Path, arguments: &[String]) -> Result<(), TaskError> {
    if arguments.len() > 1 {
        return Err(TaskError::new("usage: cargo xtask conformance [build]"));
    }
    let action = arguments.first().map(String::as_str).unwrap_or("build");
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

fn run_reviewed_command(
    root: &Path,
    program: &str,
    arguments: &[OsString],
) -> Result<Output, TaskError> {
    let authority = active_tool_authority().ok_or_else(|| {
        TaskError::new(format!(
            "`{program}` execution requires a source-bound {TOOL_AUTHORITY_SELECTOR} manifest"
        ))
    })?;
    let identity = if Path::new(program).is_absolute() {
        let selected = Path::new(program);
        let target_root = fs::canonicalize(root.join("target")).map_err(|error| {
            TaskError::new(format!("derived target root is unavailable: {error}"))
        })?;
        let identity = snapshot_python_runtime(selected, None, false)?;
        if !identity.path.starts_with(&target_root) {
            return Err(TaskError::new(
                "absolute command is not a derived target executable",
            ));
        }
        identity
    } else {
        authority.tools.get(program).cloned().ok_or_else(|| {
            TaskError::new(format!(
                "reviewed tool authority does not contain exact executable `{program}`"
            ))
        })?
    };
    let mut nested_plugins = BTreeSet::new();
    if program == "protoc" {
        for argument in arguments {
            let rendered = argument.to_string_lossy();
            for (flag, plugin) in [
                ("--prost_out=", "protoc-gen-prost"),
                ("--es_out=", "protoc-gen-es"),
                ("--go_out=", "protoc-gen-go"),
                ("--go-grpc_out=", "protoc-gen-go-grpc"),
            ] {
                if rendered.starts_with(flag) {
                    nested_plugins.insert(plugin.to_owned());
                }
            }
            if let Some(declaration) = rendered.strip_prefix("--plugin=") {
                let (name, selected) = declaration
                    .split_once('=')
                    .ok_or_else(|| TaskError::new("protoc plugin declaration is malformed"))?;
                if !matches!(
                    name,
                    "protoc-gen-es" | "protoc-gen-go" | "protoc-gen-go-grpc"
                ) {
                    return Err(TaskError::new("protoc selected an unreviewed plugin"));
                }
                let expected = authority
                    .tools
                    .get(name)
                    .ok_or_else(|| TaskError::new("protoc plugin is absent from tool authority"))?;
                if Path::new(selected) != expected.path {
                    return Err(TaskError::new(
                        "protoc plugin path differs from reviewed tool authority",
                    ));
                }
                nested_plugins.insert(name.to_owned());
            }
        }
    }
    let output = run_bounded_python(
        root,
        &identity,
        arguments,
        Duration::from_secs(4 * 60 * 60),
        32 * 1024 * 1024,
        32 * 1024 * 1024,
        false,
    )?;
    let mut command_identity = vec![program.to_owned()];
    command_identity.extend(
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    let command_payload = serde_json::to_vec(&command_identity)
        .map_err(|error| TaskError::new(format!("command identity cannot be encoded: {error}")))?;
    let tool_identifier = if Path::new(program).is_absolute() {
        format!(
            "derived-target:{}",
            Path::new(program)
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| TaskError::new("derived command name is not UTF-8"))?
        )
    } else {
        program.to_owned()
    };
    let execution = ReviewedExecution {
        command_sha256: sha256_bytes(&command_payload),
        executable_sha256: identity.sha256,
        exit_code: output.status.code().unwrap_or(-1),
        stderr_bytes: output.stderr.len(),
        stderr_sha256: sha256_bytes(&output.stderr),
        stdout_bytes: output.stdout.len(),
        stdout_sha256: sha256_bytes(&output.stdout),
        tool: tool_identifier,
    };
    let mut inventory = authority
        .executions
        .lock()
        .map_err(|_error| TaskError::new("reviewed execution inventory lock is poisoned"))?;
    inventory.push(execution);
    for plugin in nested_plugins {
        let plugin_identity = authority
            .tools
            .get(&plugin)
            .ok_or_else(|| TaskError::new("protoc plugin is absent from tool authority"))?;
        let plugin_command = serde_json::to_vec(&serde_json::json!({
            "invoked_by": "protoc",
            "parent_command_sha256": sha256_bytes(&command_payload),
            "plugin": plugin.clone(),
        }))
        .map_err(|error| {
            TaskError::new(format!(
                "plugin execution identity cannot be encoded: {error}"
            ))
        })?;
        inventory.push(ReviewedExecution {
            command_sha256: sha256_bytes(&plugin_command),
            executable_sha256: plugin_identity.sha256.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            stderr_bytes: 0,
            stderr_sha256: sha256_bytes(b""),
            stdout_bytes: 0,
            stdout_sha256: sha256_bytes(b""),
            tool: format!("nested-protoc-plugin:{plugin}"),
        });
    }
    drop(inventory);
    Ok(output)
}

fn run_command(root: &Path, program: &str, arguments: &[OsString]) -> Result<(), TaskError> {
    let output = run_reviewed_command(root, program, arguments)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(TaskError::new(format!(
            "reviewed tool `{program}` failed with {}; output was suppressed",
            output.status
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
        CLIPPY_PROFILES, CommandEvidenceContext, ErrorCatalog, ErrorCatalogEntry,
        InterfaceProjectionCatalog, PRD_28_1_COMMANDS, PrdCommandImplementation,
        REQUIRED_V1_ROUTES, Tool, architecture_check, authority_review_status,
        generate_error_artifacts, generate_operation_artifacts, generate_prd_command_manifest,
        generate_schema_artifacts, generated_artifacts, inspect_tool, load_error_catalog,
        load_interface_projection_catalog, load_operation_catalog, load_operation_payload_catalog,
        lower_camel_rpc, native_python_runtime_from, optional_flag, parse_global_arguments,
        prd_command_display, prd_command_example_arguments, quality_matrix_runner_arguments,
        render_ci_command_inventory, render_dashboard_protocol_projection,
        render_operation_openapi, render_operation_proto, render_prd_command_manifest,
        render_proto_error_registry, render_readme_command_inventory,
        render_release_command_inventory, render_rust_error_registry,
        render_rust_operation_registry, require_no_arguments, require_prd_evidence_directory,
        resolve_prd_28_1_command, route_tool_names, run, run_bounded_python, run_command,
        scan_sources, sha256_bytes, snapshot_command_evidence_closure, system_python_runtime,
        validate_command_receipt, validate_error_catalog, validate_global_evidence_selection,
        validate_interface_projection_catalog, validate_manifest_pins, validate_runtime_lineage,
        validate_rustls_provider_contract,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

    fn copy_interface_authorities(
        source_root: &std::path::Path,
        target_root: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(target_root.join("spec/api"))?;
        fs::create_dir_all(target_root.join("spec/errors"))?;
        for relative in [
            "spec/api/operations-v1.json",
            "spec/api/operation-payloads-v1.json",
            "spec/api/interface-projections-v1.json",
            "spec/errors/catalog.yaml",
        ] {
            fs::write(
                target_root.join(relative),
                fs::read(source_root.join(relative))?,
            )?;
        }
        Ok(())
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
    fn optional_flag_accepts_only_zero_or_one_exact_flag() -> Result<(), Box<dyn std::error::Error>>
    {
        assert!(!optional_flag(
            &[],
            "--check",
            "cargo xtask generate [--check]"
        )?);
        assert!(optional_flag(
            &["--check".to_owned()],
            "--check",
            "cargo xtask generate [--check]"
        )?);
        let Err(unknown) = optional_flag(
            &["--write".to_owned()],
            "--check",
            "cargo xtask generate [--check]",
        ) else {
            return Err("unknown flag unexpectedly passed".into());
        };
        assert!(
            unknown
                .to_string()
                .contains("unexpected argument `--write`")
        );
        let Err(duplicate) = optional_flag(
            &["--check".to_owned(), "--check".to_owned()],
            "--check",
            "cargo xtask generate [--check]",
        ) else {
            return Err("duplicate flag unexpectedly passed".into());
        };
        assert!(
            duplicate
                .to_string()
                .contains("duplicate argument `--check`")
        );
        Ok(())
    }

    #[test]
    fn evidence_directory_is_one_normalized_absolute_global_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = parse_global_arguments(vec![
            "test".to_owned(),
            "compatibility".to_owned(),
            "--evidence-dir".to_owned(),
            "/private/tmp/cigar-evidence".to_owned(),
        ])?;
        assert_eq!(selected.command, ["test", "compatibility"]);
        assert_eq!(
            selected.evidence_directory,
            Some(PathBuf::from("/private/tmp/cigar-evidence"))
        );
        validate_global_evidence_selection(
            Some(std::path::Path::new("/private/tmp/cigar-evidence")),
            None,
        )?;
        validate_global_evidence_selection(
            None,
            Some(std::ffi::OsStr::new("/private/tmp/cigar-evidence")),
        )?;
        assert!(
            validate_global_evidence_selection(
                Some(std::path::Path::new("/private/tmp/one")),
                Some(std::ffi::OsStr::new("/private/tmp/two")),
            )
            .is_err()
        );
        assert!(
            validate_global_evidence_selection(
                None,
                Some(std::ffi::OsStr::new("relative/evidence")),
            )
            .is_err()
        );

        for invalid in [
            vec!["test", "compatibility", "--evidence-dir"],
            vec![
                "--evidence-dir",
                "relative/evidence",
                "test",
                "compatibility",
            ],
            vec![
                "--evidence-dir=/private/tmp/evidence",
                "test",
                "compatibility",
            ],
            vec![
                "--evidence-dir",
                "/private/tmp/one",
                "test",
                "compatibility",
                "--evidence-dir",
                "/private/tmp/two",
            ],
        ] {
            assert!(
                parse_global_arguments(invalid.into_iter().map(str::to_owned).collect()).is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn no_argument_parser_rejects_trailing_input() -> Result<(), Box<dyn std::error::Error>> {
        require_no_arguments(&[], "cargo xtask lint")?;
        let Err(error) = require_no_arguments(&["--quiet".to_owned()], "cargo xtask lint") else {
            return Err("trailing argument unexpectedly passed".into());
        };
        assert!(error.to_string().contains("unexpected argument `--quiet`"));
        Ok(())
    }

    #[test]
    fn prd_command_manifest_exactly_covers_section_28_1() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let prd = fs::read_to_string(root.join("prd.md"))?;
        let section = prd
            .split("## **28.1 Clean-source qualification**")
            .nth(1)
            .and_then(|tail| tail.split("## **28.2").next())
            .ok_or("PRD section 28.1 is missing")?;
        let declared: BTreeSet<String> = section
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("cargo xtask "))
            .map(|line| {
                line.replace("\\--", "--")
                    .replace("\\<", "<")
                    .replace("\\>", ">")
            })
            .collect();
        let inventoried: BTreeSet<String> =
            PRD_28_1_COMMANDS.iter().map(prd_command_display).collect();

        assert_eq!(PRD_28_1_COMMANDS.len(), 29);
        assert_eq!(inventoried.len(), PRD_28_1_COMMANDS.len());
        assert_eq!(inventoried, declared);

        let mut ids = BTreeSet::new();
        for spec in PRD_28_1_COMMANDS {
            assert!(ids.insert(spec.id), "duplicate command id: {}", spec.id);
            assert!(!spec.work_packet.is_empty());
            assert!(!spec.arguments.is_empty());
        }
        Ok(())
    }

    #[test]
    fn prd_command_examples_dispatch_through_the_authoritative_table()
    -> Result<(), Box<dyn std::error::Error>> {
        for expected in PRD_28_1_COMMANDS {
            let arguments = prd_command_example_arguments(expected);
            let actual = resolve_prd_28_1_command(&arguments)?.ok_or_else(|| {
                format!("route did not resolve: {}", prd_command_display(expected))
            })?;
            assert_eq!(actual.id, expected.id);
        }

        for id in ["package-smoke", "release-verify"] {
            let spec = PRD_28_1_COMMANDS
                .iter()
                .find(|spec| spec.id == id)
                .ok_or("path-bearing route missing")?;
            let mut arguments = prd_command_example_arguments(spec);
            let last = arguments.last_mut().ok_or("path argument missing")?;
            *last = "artifacts/candidate".to_owned();
            assert_eq!(
                resolve_prd_28_1_command(&arguments)?.map(|item| item.id),
                Some(id)
            );
        }
        Ok(())
    }

    #[test]
    fn generated_prd_command_inventory_is_current_and_honest()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        generate_prd_command_manifest(&root, true)?;

        let manifest: serde_json::Value = serde_json::from_str(&render_prd_command_manifest()?)?;
        assert_eq!(
            manifest
                .get("command_count")
                .and_then(serde_json::Value::as_u64),
            Some(29)
        );
        assert_eq!(
            manifest
                .get("additional_command_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            manifest
                .pointer("/additional_commands/0/id")
                .and_then(serde_json::Value::as_str),
            Some("test-sanitizers")
        );
        assert_eq!(
            manifest
                .pointer("/platform_scope/0")
                .and_then(serde_json::Value::as_str),
            Some("macos-arm64")
        );
        assert_eq!(
            manifest
                .pointer("/execution_policy/source_state")
                .and_then(serde_json::Value::as_str),
            Some("clean-committed-git-checkout")
        );
        assert_eq!(
            manifest
                .pointer("/projections/ci")
                .and_then(serde_json::Value::as_str),
            Some("crates/xtask/generated/ci-command-inventory.v1.json")
        );
        let commands = manifest
            .get("commands")
            .and_then(serde_json::Value::as_array)
            .ok_or("generated command inventory is missing commands")?;
        assert_eq!(commands.len(), PRD_28_1_COMMANDS.len());
        for (command, spec) in commands.iter().zip(PRD_28_1_COMMANDS) {
            assert_eq!(
                command
                    .get("release_eligible")
                    .and_then(serde_json::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                command
                    .pointer("/receipt/required")
                    .and_then(serde_json::Value::as_bool),
                Some(true)
            );
            assert_eq!(
                command
                    .pointer("/receipt/implemented")
                    .and_then(serde_json::Value::as_bool),
                Some(spec.implementation != PrdCommandImplementation::Unavailable)
            );
            let expected_gate = match spec.implementation {
                PrdCommandImplementation::Unavailable => "unavailable",
                _ => "implemented-with-source-bound-content-free-receipt",
            };
            assert_eq!(
                command
                    .get("gate_state")
                    .and_then(serde_json::Value::as_str),
                Some(expected_gate)
            );
        }

        let ci: serde_json::Value = serde_json::from_str(&render_ci_command_inventory()?)?;
        assert_eq!(
            ci.get("command_count").and_then(serde_json::Value::as_u64),
            Some(29)
        );
        assert!(
            ci.get("commands")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|commands| commands.iter().all(|command| {
                    command.get("receipt_implemented") == Some(&serde_json::Value::Bool(true))
                        && command
                            .get("gate_state")
                            .and_then(serde_json::Value::as_str)
                            != Some("unavailable")
                }))
        );
        let release: serde_json::Value =
            serde_json::from_str(&render_release_command_inventory()?)?;
        assert_eq!(
            release
                .get("command_count")
                .and_then(serde_json::Value::as_u64),
            Some(30)
        );
        assert_eq!(
            render_readme_command_inventory()
                .lines()
                .filter(|line| line.starts_with("| `cargo xtask "))
                .count(),
            30
        );
        Ok(())
    }

    #[test]
    fn command_receipt_validation_rejects_empty_or_unbound_attachments()
    -> Result<(), Box<dyn std::error::Error>> {
        let spec = PRD_28_1_COMMANDS
            .iter()
            .find(|spec| spec.id == "lint")
            .ok_or("lint route must exist")?;
        let source = serde_json::json!({"revision": "1"});
        let context = CommandEvidenceContext {
            expected_source: serde_json::to_string(&source)?,
            started_unix_ms: 0,
            started: Instant::now(),
            evidence_python: system_python_runtime()?,
            helper_closure: snapshot_command_evidence_closure(
                &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
            )?,
        };
        let mut receipt = serde_json::json!({
            "schema_version": "cigar.xtask-command-receipt.v1",
            "command": {"id": "lint"},
            "status": "passed",
            "source": source,
            "attachments": [{
                "path": "command-plane/lint.raw.json",
                "bytes": 1,
                "sha256": "a".repeat(64),
            }],
            "release_eligible": false,
        });
        let encoded = serde_json::to_vec(&receipt)?;
        validate_command_receipt(&encoded, spec, &context)?;

        for invalid in [
            serde_json::json!([]),
            serde_json::json!([{
                "path": "command-plane/lint.raw.json",
                "bytes": 0,
                "sha256": "a".repeat(64),
            }]),
            serde_json::json!([{
                "path": "command-plane/lint.raw.json",
                "bytes": 1,
                "sha256": "A".repeat(64),
            }]),
        ] {
            let attachments = receipt
                .get_mut("attachments")
                .ok_or("receipt attachments disappeared")?;
            *attachments = invalid;
            let encoded = serde_json::to_vec(&receipt)?;
            assert!(validate_command_receipt(&encoded, spec, &context).is_err());
        }
        Ok(())
    }

    #[test]
    fn reviewed_python_runner_uses_a_closed_environment_and_caps_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = system_python_runtime()?;
        let output = run_bounded_python(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path(),
            &runtime,
            &[
                "-c".into(),
                "import json,os;print(json.dumps(dict(os.environ),sort_keys=True))".into(),
            ],
            Duration::from_secs(10),
            64 * 1024,
            64 * 1024,
            false,
        )?;
        assert!(output.status.success());
        let environment: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            environment.get("PATH").and_then(serde_json::Value::as_str),
            Some(super::CLOSED_COMMAND_PATH)
        );
        assert!(environment.get("PYTHONPATH").is_none());
        assert!(environment.get("DYLD_INSERT_LIBRARIES").is_none());
        assert!(environment.get("CIGAR_EVIDENCE_DIR").is_none());

        let oversized = run_bounded_python(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path(),
            &runtime,
            &["-c".into(), "import sys;sys.stdout.write('x'*4096)".into()],
            Duration::from_secs(10),
            1024,
            1024,
            false,
        )
        .err()
        .ok_or("oversized output did not fail closed")?;
        assert!(oversized.to_string().contains("output bound"));
        Ok(())
    }

    #[test]
    fn reviewed_python_runner_kills_its_process_group_on_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("runner-timeout")?;
        let marker = temporary.path.join("descendant-marker");
        let child = format!(
            "import pathlib,time;time.sleep(0.7);pathlib.Path({:?}).write_text('survived')",
            marker.to_string_lossy()
        );
        let parent = format!(
            "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child:?}]);time.sleep(10)"
        );
        let result = run_bounded_python(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path(),
            &system_python_runtime()?,
            &["-c".into(), parent.into()],
            Duration::from_millis(150),
            64 * 1024,
            64 * 1024,
            false,
        );
        assert!(result.is_err());
        std::thread::sleep(Duration::from_millis(900));
        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn reviewed_python_runner_does_not_hang_on_escaped_pipe_holder()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TemporaryDirectory::new("runner-escaped-session")?;
        let pid_file = temporary.path.join("escaped-pid");
        let child = format!(
            "import os,pathlib,time;os.setsid();pathlib.Path({:?}).write_text(str(os.getpid()));time.sleep(30)",
            pid_file.to_string_lossy()
        );
        let parent = format!(
            "import pathlib,subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child:?}]);p=pathlib.Path({:?});\nwhile not p.exists(): time.sleep(0.01)\ntime.sleep(30)",
            pid_file.to_string_lossy()
        );
        let started = Instant::now();
        let result = run_bounded_python(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path(),
            &system_python_runtime()?,
            &["-c".into(), parent.into()],
            Duration::from_millis(200),
            64 * 1024,
            64 * 1024,
            false,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        if let Ok(pid) = fs::read_to_string(&pid_file) {
            let _ignored = std::process::Command::new("/bin/kill")
                .args(["-KILL", pid.trim()])
                .status();
        }
        let error = result.as_ref().err().ok_or("escaped holder did not fail")?;
        assert!(error.to_string().contains("escaped-session"));
        Ok(())
    }

    #[test]
    fn legacy_command_execution_rejects_ambient_path_without_authority() {
        let error = run_command(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path(),
            "attacker-fake-success",
            &[],
        )
        .err();
        assert!(
            error.is_some_and(|error| error.to_string().contains(super::TOOL_AUTHORITY_SELECTOR))
        );
    }

    #[test]
    fn tool_authority_labels_missing_review_and_rejects_stale_review_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let digest = "a".repeat(64);
        let wrong = "b".repeat(64);
        assert_eq!(
            authority_review_status(&digest, Some(digest.as_str()))?,
            "operator-reviewed"
        );
        assert_eq!(
            authority_review_status(&digest, None)?,
            "diagnostic-self-observed"
        );
        for expected in [Some("invalid"), Some(wrong.as_str())] {
            let error = authority_review_status(&digest, expected)
                .err()
                .ok_or("malformed or stale review digest did not fail")?;
            assert!(error.to_string().contains("independently reviewed"));
        }
        Ok(())
    }

    #[test]
    fn route_tool_authority_is_exact_and_least_privilege() -> Result<(), Box<dyn std::error::Error>>
    {
        for spec in PRD_28_1_COMMANDS.iter().chain(super::NATIVE_EXTRA_COMMANDS) {
            let tools = route_tool_names(spec.id)?;
            let uses_native = matches!(
                spec.implementation,
                PrdCommandImplementation::BenchMicroVerify
                    | PrdCommandImplementation::BenchMacroVerify
                    | PrdCommandImplementation::BenchEfficacy
                    | PrdCommandImplementation::PackageAll
                    | PrdCommandImplementation::PackageSmoke
                    | PrdCommandImplementation::ReleaseSbom
                    | PrdCommandImplementation::ReleaseSign
                    | PrdCommandImplementation::ReleaseAttest
                    | PrdCommandImplementation::ReleaseVerify
                    | PrdCommandImplementation::TestSanitizers
                    | PrdCommandImplementation::Unavailable
            );
            assert_eq!(tools.is_empty(), uses_native, "route {}", spec.id);
        }
        assert_eq!(
            route_tool_names("format-check")?,
            BTreeSet::from([
                "cargo".to_owned(),
                "cargo-fmt".to_owned(),
                "rustfmt".to_owned(),
            ])
        );
        assert!(!route_tool_names("lint")?.contains("cargo-mutants"));
        assert!(!route_tool_names("test-unit")?.contains("protoc"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn reviewed_runtime_rejects_user_owned_group_writable_ancestor()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TemporaryDirectory::new("group-writable-runtime")?;
        let hostile_parent = temporary.path.join("group-writable");
        fs::create_dir(&hostile_parent)?;
        fs::set_permissions(&hostile_parent, fs::Permissions::from_mode(0o770))?;
        let selected = hostile_parent.join("tool");
        fs::write(&selected, b"protected executable fixture")?;

        let error = validate_runtime_lineage(&selected, false)
            .err()
            .ok_or("group-writable ancestor did not fail")?;
        assert!(error.to_string().contains("unprotected path ancestor"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn configured_native_python_accepts_protected_non_homebrew_path_and_rejects_digest_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TemporaryDirectory::new("hosted-python-runtime")?;
        fs::set_permissions(&temporary.path, fs::Permissions::from_mode(0o700))?;
        let canonical_temporary = fs::canonicalize(&temporary.path)?;
        let directory = canonical_temporary.join("hostedtoolcache/python/3.14.6/arm64/bin");
        fs::create_dir_all(&directory)?;
        let runtime = directory.join("python3");
        let script = b"#!/bin/sh\nprintf 'Python 3.14.6\\n'\n";
        fs::write(&runtime, script)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
        let digest = sha256_bytes(script);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

        let (identity, probe) = native_python_runtime_from(&root, &runtime, &digest)?;
        assert_eq!(identity.path, runtime);
        assert_eq!(probe.version, "3.14.6");
        assert_eq!(probe.exit_code, 0);
        assert!(!identity.path.to_string_lossy().contains("homebrew"));

        let error = native_python_runtime_from(&root, &runtime, &"0".repeat(64))
            .err()
            .ok_or("stale operator digest did not fail")?;
        assert!(error.to_string().contains("SHA-256"));
        Ok(())
    }

    #[test]
    fn production_xtask_has_one_bounded_process_launcher() {
        let source = include_str!("lib.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert_eq!(production.matches("Command::new").count(), 1);
        assert!(production.contains("fn run_bounded_python("));
    }

    #[test]
    fn every_implemented_prd_route_requires_an_external_receipt_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut implemented = 0_usize;
        let mut unavailable = 0_usize;
        for spec in PRD_28_1_COMMANDS {
            if spec.implementation == PrdCommandImplementation::Unavailable {
                unavailable += 1;
                continue;
            }
            implemented += 1;
            let error = require_prd_evidence_directory(spec, None)
                .err()
                .ok_or("implemented route accepted missing evidence workspace")?;
            assert!(error.to_string().contains("source-bound receipt"));
            assert_eq!(
                require_prd_evidence_directory(
                    spec,
                    Some(std::path::Path::new("/private/tmp/cigar-evidence"))
                )?,
                std::path::Path::new("/private/tmp/cigar-evidence")
            );
        }
        assert_eq!(implemented, 28);
        assert_eq!(unavailable, 1);
        Ok(())
    }

    #[test]
    fn macos_quality_matrix_routes_are_distinct_and_receipted()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let matrices = PRD_28_1_COMMANDS
            .iter()
            .filter_map(|spec| match spec.implementation {
                PrdCommandImplementation::TestMatrix(matrix) => Some(matrix),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(matrices.len(), 8);

        let mut suites = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        for matrix in matrices {
            assert!(
                suites.insert(matrix.suite),
                "duplicate suite: {}",
                matrix.suite
            );
            assert!(
                paths.insert(matrix.matrix),
                "duplicate matrix: {}",
                matrix.matrix
            );
            assert!(
                outputs.insert(matrix.output),
                "duplicate output: {}",
                matrix.output
            );
            assert!(matrix.output.starts_with("quality/"));
            assert!(matrix.output.ends_with("-matrix-result.v1.json"));

            let document: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(root.join(matrix.matrix))?)?;
            assert_eq!(
                document.get("suite").and_then(serde_json::Value::as_str),
                Some(matrix.suite)
            );

            let arguments = quality_matrix_runner_arguments(matrix, None);
            let rendered = arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                rendered,
                [
                    "tools/quality/run_matrix.py",
                    "--matrix",
                    matrix.matrix,
                    "--profile",
                    "local",
                    "--require-evidence",
                    "--isolate-evidence-environment",
                    "--output",
                    matrix.output,
                ]
            );

            let selected = quality_matrix_runner_arguments(
                matrix,
                Some(std::path::Path::new("/private/tmp/cigar-evidence")),
            );
            let selected = selected
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                selected.get(selected.len().saturating_sub(2)..),
                Some(
                    [
                        "--evidence-dir".to_owned(),
                        "/private/tmp/cigar-evidence".to_owned()
                    ]
                    .as_slice()
                )
            );
        }
        Ok(())
    }

    #[test]
    fn stale_prd_command_inventory_fails_generation_check() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = TemporaryDirectory::new("stale-prd-command-inventory")?;
        generate_prd_command_manifest(&temporary.path, false)?;
        generate_prd_command_manifest(&temporary.path, true)?;
        fs::write(
            temporary
                .path
                .join("crates/xtask/prd-28.1-command-manifest.v1.json"),
            "stale\n",
        )?;
        let Err(error) = generate_prd_command_manifest(&temporary.path, true) else {
            return Err("stale inventory unexpectedly passed generation check".into());
        };
        assert!(error.to_string().contains("is stale"));
        Ok(())
    }

    #[test]
    fn every_prd_command_rejects_unknown_and_duplicate_input_before_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        for spec in PRD_28_1_COMMANDS {
            let example = prd_command_example_arguments(spec);

            let mut unknown = example.clone();
            unknown.push("--unknown".to_owned());
            let Err(error) = run(unknown) else {
                return Err(format!("unknown input executed task {}", spec.id).into());
            };
            assert!(
                !error.to_string().contains("intentionally unavailable"),
                "unknown input reached the gate for {}: {error}",
                spec.id
            );

            let duplicated = example
                .iter()
                .find(|argument| argument.starts_with("--"))
                .or_else(|| example.last())
                .ok_or("manifest example is empty")?
                .clone();
            let mut duplicate = example;
            duplicate.push(duplicated);
            let Err(error) = run(duplicate) else {
                return Err(format!("duplicate input executed task {}", spec.id).into());
            };
            assert!(
                !error.to_string().contains("intentionally unavailable"),
                "duplicate input reached the gate for {}: {error}",
                spec.id
            );
        }
        Ok(())
    }

    #[test]
    fn required_prd_arguments_and_incompatible_combinations_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        for spec in PRD_28_1_COMMANDS {
            let mut missing = prd_command_example_arguments(spec);
            let _removed = missing.pop();
            assert!(
                resolve_prd_28_1_command(&missing)?.is_none(),
                "short input resolved as a PRD command for {}",
                spec.id
            );
        }

        for arguments in [
            vec!["fuzz"],
            vec!["test", "coverage"],
            vec!["test", "mutations"],
            vec!["bench", "micro"],
            vec!["bench", "macro"],
            vec!["package", "--smoke"],
            vec!["release", "verify"],
            vec!["package", "--all", "--smoke", "dist/"],
            vec!["bench", "micro", "--verify", "efficacy"],
            vec!["release", "sbom", "verify", "dist/"],
        ] {
            let Err(error) = run(arguments.into_iter().map(str::to_owned)) else {
                return Err("missing or incompatible input executed a task".into());
            };
            assert!(
                !error.to_string().contains("intentionally unavailable"),
                "malformed input reached a gate: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn prd_path_arguments_reject_escape_absolute_and_ambiguous_forms()
    -> Result<(), Box<dyn std::error::Error>> {
        for route_prefix in [vec!["package", "--smoke"], vec!["release", "verify"]] {
            for unsafe_path in [
                "",
                ".",
                "..",
                "../dist",
                "dist/../candidate",
                "dist/./candidate",
                "dist//candidate",
                "/tmp/dist",
                "C:/dist",
                "dist\\candidate",
                "--unknown",
                "dist\ncandidate",
            ] {
                let mut arguments: Vec<String> = route_prefix
                    .iter()
                    .map(|argument| (*argument).to_owned())
                    .collect();
                arguments.push(unsafe_path.to_owned());
                let Err(error) = run(arguments) else {
                    return Err(format!("unsafe path {unsafe_path:?} reached a gate").into());
                };
                assert!(
                    error.to_string().contains("unsafe relative path"),
                    "unexpected error for {unsafe_path:?}: {error}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn dispatcher_rejects_extra_or_unsupported_arguments_before_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        for arguments in [
            vec!["vectors", "check", "extra"],
            vec!["test", "unit", "--case"],
            vec!["test", "coverage"],
            vec!["test", "coverage", "--verify", "--verify"],
            vec!["docs", "--write"],
            vec!["lint", "--quiet"],
            vec!["fuzz"],
            vec!["fuzz", "smoke", "extra"],
            vec!["bench", "micro"],
            vec!["bench", "micro", "--verify", "--verify"],
            vec!["package", "--smoke", "../dist"],
            vec!["release", "verify", "/tmp/dist"],
            vec!["release", "sbom", "--unused"],
            vec!["release-verify"],
        ] {
            let Err(error) = run(arguments.into_iter().map(str::to_owned)) else {
                return Err("invalid arguments unexpectedly executed a task".into());
            };
            assert!(
                error.to_string().contains("usage")
                    || error.to_string().contains("unexpected argument")
                    || error.to_string().contains("unsafe relative path"),
                "unexpected dispatcher error: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn incomplete_prd_routes_parse_exactly_then_fail_as_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        for spec in PRD_28_1_COMMANDS
            .iter()
            .filter(|spec| spec.implementation == PrdCommandImplementation::Unavailable)
        {
            let Err(error) = run(prd_command_example_arguments(spec)) else {
                return Err(format!("incomplete route {} returned success", spec.id).into());
            };
            assert!(
                error.to_string().contains("intentionally unavailable"),
                "valid incomplete route {} did not reach its distinct gate: {error}",
                spec.id
            );
        }
        Ok(())
    }

    #[test]
    fn property_workspace_nextest_policy_is_fail_closed_and_serial()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let policy = fs::read_to_string(root.join("tests/properties/.config/nextest.toml"))?;
        assert_eq!(
            policy
                .matches("leak-timeout = { period = \"2s\", result = \"fail\" }")
                .count(),
            2
        );
        assert!(policy.contains("[test-groups.cigar-quality-properties]"));
        assert!(policy.contains("[profile.macos-qualification]"));
        assert!(policy.contains("inherits = \"ci\""));
        assert!(policy.contains("test-threads = 1"));
        assert!(policy.contains("max-threads = 1"));
        assert!(policy.contains("filter = \"package(cigar-quality-properties)\""));
        assert!(policy.contains("test-group = \"cigar-quality-properties\""));
        Ok(())
    }

    #[test]
    fn workspace_nextest_policy_isolates_resource_sensitive_acceptance_gates()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let policy = fs::read_to_string(root.join(".config/nextest.toml"))?;
        let group = "cigar-resource-sensitive-acceptance";
        assert_eq!(policy.matches(&format!("[test-groups.{group}]")).count(), 1);
        assert!(policy.contains(&format!("[test-groups.{group}]\nmax-threads = 1")));

        let filters = [
            "package(=cigar-daemon) & test(=production_runtime::tests::real_daemon_handles_32_mixed_clients_with_exact_replay_and_no_quota_leak)",
            "package(=cigar-claude-hook) & test(=tests::warm_prompt_p95_and_p99_stay_within_acceptance_bounds)",
        ];
        for profile in ["default", "ci"] {
            for filter in filters {
                let override_policy = format!(
                    "[[profile.{profile}.overrides]]\nfilter = \"{filter}\"\ntest-group = \"{group}\"\nthreads-required = \"num-test-threads\""
                );
                assert!(
                    policy.contains(&override_policy),
                    "missing full-pool {profile} override for {filter}"
                );
            }
        }
        assert_eq!(
            policy
                .matches("threads-required = \"num-test-threads\"")
                .count(),
            4
        );

        let macos_profile = "[profile.macos-qualification]\n\
inherits = \"ci\"\n\
test-threads = 1";
        assert!(
            policy.contains(macos_profile),
            "macOS qualification must inherit the fail-closed CI profile and serialize process launches"
        );
        let macos_start = policy
            .find(macos_profile)
            .ok_or("macOS qualification profile unavailable")?;
        let macos_tail = &policy[macos_start..];
        let macos_end = macos_tail[1..]
            .find("\n[")
            .map_or(macos_tail.len(), |offset| offset + 1);
        assert!(
            !macos_tail[..macos_end].contains("leak-timeout"),
            "macOS qualification must inherit, not weaken or replace, strict CI leak detection"
        );
        assert!(policy.contains(
            "[profile.ci]\nfail-fast = false\nretries = 0\nleak-timeout = { period = \"2s\", result = \"fail\" }"
        ));
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
        let problem_schema = openapi_value
            .get("components")
            .and_then(|components| components.get("schemas"))
            .and_then(|schemas| schemas.get("Problem"))
            .ok_or("OpenAPI Problem schema missing")?;
        let expected_problem: serde_json::Value =
            serde_json::from_str(&super::render_schema::<cigar_protocol::Problem>("Problem")?)?;
        assert_eq!(problem_schema, &expected_problem);
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
        assert_eq!(rust.matches("=> OPERATIONS.first()").count(), 1);
        assert_eq!(rust.matches("=> OPERATIONS.get(").count(), 44);
        assert!(!rust.contains("&OPERATIONS["));
        Ok(())
    }

    #[test]
    fn interface_projection_is_deterministic_content_safe_and_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let operations = load_operation_catalog(&root)?;
        let payloads = load_operation_payload_catalog(&root, &operations)?;
        let errors = load_error_catalog(&root)?;
        let projections = load_interface_projection_catalog(&root, &operations, &payloads)?;
        assert_eq!(projections.cli.mappings.len(), 34);
        assert_eq!(projections.mcp.mappings.len(), 10);
        let first = render_dashboard_protocol_projection(&operations, &payloads, &errors)?;
        let second = render_dashboard_protocol_projection(&operations, &payloads, &errors)?;
        assert_eq!(first, second);
        assert!(!first.contains(['<', '>']));
        let value: serde_json::Value = serde_json::from_str(&first)?;
        assert_eq!(
            value.get("operation_count"),
            Some(&serde_json::Value::from(45))
        );
        assert_eq!(value.get("error_count"), Some(&serde_json::Value::from(34)));
        assert!(first.len() < 64 * 1024);
        assert!(!first.contains("remediation"));
        assert!(!first.contains("message"));
        Ok(())
    }

    #[test]
    fn interface_projection_rejects_unknown_duplicate_and_semantic_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let operations = load_operation_catalog(&root)?;
        let payloads = load_operation_payload_catalog(&root, &operations)?;
        let source = fs::read_to_string(root.join("spec/api/interface-projections-v1.json"))?;

        let mut unknown: InterfaceProjectionCatalog = serde_json::from_str(&source)?;
        unknown
            .cli
            .mappings
            .first_mut()
            .ok_or("CLI projection unexpectedly empty")?
            .operation_id = "unsupportedOperation".to_owned();
        let error = match validate_interface_projection_catalog(&unknown, &operations, &payloads) {
            Ok(()) => return Err("unknown operation unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown operation"));

        let mut duplicate: InterfaceProjectionCatalog = serde_json::from_str(&source)?;
        let duplicate_name = duplicate
            .cli
            .mappings
            .first()
            .ok_or("CLI projection unexpectedly empty")?
            .exposed_name
            .clone();
        duplicate
            .cli
            .mappings
            .get_mut(1)
            .ok_or("CLI projection unexpectedly has fewer than two mappings")?
            .exposed_name = duplicate_name;
        let error = match validate_interface_projection_catalog(&duplicate, &operations, &payloads)
        {
            Ok(()) => return Err("duplicate command unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("duplicate CLI"));

        let mut mismatch: InterfaceProjectionCatalog = serde_json::from_str(&source)?;
        mismatch
            .cli
            .mappings
            .first_mut()
            .ok_or("CLI projection unexpectedly empty")?
            .operation_kind = "mutation".to_owned();
        let error = match validate_interface_projection_catalog(&mismatch, &operations, &payloads) {
            Ok(()) => return Err("semantic mismatch unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("mismatched operation kind"));
        Ok(())
    }

    #[test]
    fn dashboard_retry_projection_rejects_missing_error_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let mut errors = load_error_catalog(&root)?;
        let _removed = errors.errors.pop();
        let error = match validate_error_catalog(&errors) {
            Ok(()) => return Err("missing error unexpectedly passed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exactly 34"));
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
        copy_interface_authorities(&root, &temporary.path)?;
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
    fn stale_browser_projection_fails_generation_check() -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("xtask root unavailable")?
            .to_path_buf();
        let temporary = TemporaryDirectory::new("stale-browser-projection")?;
        copy_interface_authorities(&root, &temporary.path)?;
        generate_operation_artifacts(&temporary.path, false)?;
        fs::write(
            temporary
                .path
                .join("crates/cigar-dashboard/src/generated/protocol-catalog-v1.json"),
            "stale",
        )?;
        let error = match generate_operation_artifacts(&temporary.path, true) {
            Ok(()) => return Err("stale browser projection unexpectedly passed".into()),
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
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let Err(error) = inspect_tool(&root, tool) else {
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
    fn lint_feature_matrix_is_locked_strict_and_uses_only_supported_compositions()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = BTreeMap::from([
            ("workspace-default", None),
            ("cigar-cli-beta-embedded", Some("beta-embedded")),
            ("cigar-sdk-remote", None),
            ("cigar-aws-creds-no-http", None),
            ("cigar-aws-creds-http-no-tls", Some("http-credentials")),
            ("cigar-aws-creds-native-tls", Some("native-tls")),
            (
                "cigar-aws-creds-native-tls-vendored",
                Some("native-tls-vendored"),
            ),
            ("cigar-aws-creds-rustls", Some("rustls-tls")),
            ("cigar-rust-s3-sync-no-tls", Some("sync")),
            ("cigar-rust-s3-sync-native-tls", Some("sync-native-tls")),
            (
                "cigar-rust-s3-sync-native-tls-vendored",
                Some("sync-native-tls-vendored"),
            ),
            ("cigar-rust-s3-sync-rustls", Some("sync-rustls-tls")),
            (
                "cigar-rust-s3-sync-orthogonal",
                Some("sync-rustls-tls,fail-on-err,http-credentials,tags"),
            ),
            ("cigar-rust-s3-tokio-no-tls", Some("with-tokio")),
            ("cigar-rust-s3-tokio-native-tls", Some("tokio-native-tls")),
            ("cigar-rust-s3-tokio-rustls", Some("tokio-rustls-tls")),
            (
                "cigar-rust-s3-tokio-orthogonal",
                Some("tokio-rustls-tls,blocking,fail-on-err,http-credentials,tags"),
            ),
        ]);
        let actual = CLIPPY_PROFILES
            .iter()
            .map(|profile| {
                let features = profile.arguments.windows(2).find_map(|pair| {
                    let [flag, value] = pair else {
                        return None;
                    };
                    (*flag == "--features").then_some(*value)
                });
                (profile.name, features)
            })
            .collect::<BTreeMap<_, _>>();

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), CLIPPY_PROFILES.len());
        for profile in CLIPPY_PROFILES {
            assert_eq!(profile.arguments.first(), Some(&"clippy"));
            assert!(profile.arguments.contains(&"--locked"));
            assert!(profile.arguments.contains(&"--all-targets"));
            assert!(!profile.arguments.contains(&"--all-features"));
            assert!(profile.arguments.ends_with(&["--", "-D", "warnings"]));
        }

        let workspace = CLIPPY_PROFILES
            .iter()
            .find(|profile| profile.name == "workspace-default")
            .ok_or("workspace lint profile must be present")?;
        assert!(workspace.arguments.contains(&"--workspace"));
        assert!(
            workspace
                .arguments
                .windows(2)
                .any(|pair| pair == ["--exclude", "cigar-soak"])
        );
        for profile in CLIPPY_PROFILES
            .iter()
            .filter(|profile| profile.name != "workspace-default")
        {
            assert!(profile.arguments.contains(&"--package"));
            assert!(profile.arguments.contains(&"--no-default-features"));
        }
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
