//! Artifact-bound, no-egress qualification of an installed macOS CIGAR runtime.

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("cigar-install-qualifier requires macOS");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    macos::entry()
}

#[cfg(target_os = "macos")]
mod macos {
    use base64::Engine as _;
    use cigar_api::{
        BundleIdRequest, CompileContextBundleRequest, CompileContextDeltaRequest,
        CreateContextPlanRequest, DiscoverSourcesRequest, ExplainContextBundleRequest,
        IngestCatalogRequest, MaterializationProfile, MaterializeContextBundleRequest,
        QueryCatalogRequest,
    };
    use cigar_crypto::{
        CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider as _, KeyPurpose,
        SecretBytes,
    };
    use cigar_daemon::{
        ApplicationResourceLimits, DaemonConfig, DeploymentMode, LocalIdentity,
        ProductionAtomizationConfiguration, ProductionAuthorityConfiguration, ProductionPaths,
        ProductionPrincipalAuthority, ProductionSourceConnectorConfiguration,
        ProductionSourceConnectorKind, ProductionSourceEntry, ProductionSourceRegistry,
        ProductionTenantAuthority, SourceConfiguration, SourceDiscoveryPolicyConfiguration,
        TelemetrySettings, WorkerCapacities,
    };
    use cigar_protocol::{
        AtomKind, AtomPayload, Budget, Capability, Classification, ConsistencyMode, ContentDigest,
        ContextAtomV1, ContextContract, ContextEdge, ContextRequirement, EdgeKind, ExtensionMap,
        FixedPoint, GovernanceEnvelope, InstructionAuthority, LaneKind, Lifecycle, MediaType,
        OperationClass, QualityEnvelope, RecordId, RequirementSelector, SchemaVersion, SourceUri,
        TargetProfile, UtcTimestamp, Validate as _, VersionId,
    };
    use rusqlite::config::DbConfig;
    use rusqlite::{Connection, OpenFlags, params};
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::ffi::{OsStr, OsString};
    use std::fmt::Write as _;
    use std::fs::{self, File, OpenOptions, Permissions};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::os::unix::fs::{
        FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

    const HELP: &str = concat!(
        "Usage: cigar-install-qualifier ",
        "--cigar <absolute-path> --cigard <absolute-path> ",
        "--workspace <absolute-path> --artifact-id <id> ",
        "--artifact-sha256 <sha256> --product-version <semver> ",
        "--context-abi cigar.context.v1 --source-revision <git-object-id> ",
        "--sandbox-root <absolute-path> --candidate-input-root <absolute-path>\n"
    );
    const MAX_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_BACKUP_INVENTORY_FILES: usize = 1_000_000;
    const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
    const TENANT_VALUE: u64 = 1;
    const PROJECT_VALUE: u64 = 2;
    const PRINCIPAL_VALUE: u64 = 3;
    const GRANT_VALUE: u64 = 4;
    const SOURCE_VALUE: u64 = 5;
    const SOURCE_CANARY: &str = "installed-qualification-canary";
    const RUNTIME_PROFILE: &str = "cigar.full.local-macos-aarch64.v1";
    const WORKFLOW_PROFILE: &str = "cigar.full.offline-read-only.macos-aarch64.v1";
    const MACOS_SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
    const NO_EGRESS_ENFORCEMENT: &str =
        "darwin-seatbelt-deny-network-mach-confine-writes-protect-candidate-workspace-unix-v1";
    const PROCESS_ENFORCEMENT: &str = "darwin-seatbelt-deny-process-fork-signal-v1";
    const REFERENCE_TOKENIZER_FINGERPRINT: &str =
        "1220704360550f3e648c66e8333d6f68beccead8c630c31b640385e72bcaf3266657";
    const INITIAL_MIGRATION: &str =
        include_str!("../../../../crates/cigar-store/migrations/sqlite/0001_initial.sql");
    const COMPATIBILITY_LEDGER_MIGRATION: &str = include_str!(
        "../../../../crates/cigar-store/migrations/sqlite/0002_compatibility_ledger.sql"
    );
    const GENERATION_BOUND_ATOM_PROJECTION_MIGRATION: &str = include_str!(
        "../../../../crates/cigar-store/migrations/sqlite/0003_generation_bound_atom_projection.sql"
    );
    const NORMALIZED_AUTHORITATIVE_CATALOG_MIGRATION: &str = include_str!(
        "../../../../crates/cigar-store/migrations/sqlite/0004_normalized_authoritative_catalog.sql"
    );
    const RETAINED_V1_FIXTURE: &str =
        include_str!("../../fixtures/sqlite-v1-retained-nonempty.json");
    const RETAINED_V1_FIXTURE_SHA256: &str =
        "850efd95333f1f20784ebaf99309a5ea4db595e27fff2109b08c3f5be3fcb501";
    const AUTHORITATIVE_FULL_HELP: &[u8] =
        include_bytes!("../../../../crates/cigar-cli/assets/cigar-help.txt");

    static CAPTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    static QUALIFICATION_PHASE: AtomicU8 = AtomicU8::new(0);

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Arguments {
        cigar: PathBuf,
        cigard: PathBuf,
        workspace: PathBuf,
        artifact_id: String,
        artifact_sha256: String,
        product_version: String,
        context_abi: String,
        source_revision: String,
        sandbox_root: PathBuf,
        candidate_input_root: PathBuf,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CandidateSandbox {
        policy: String,
    }

    #[derive(Serialize)]
    struct DriverReceipt<'a> {
        schema_version: &'static str,
        status: &'static str,
        artifact_id: &'a str,
        artifact_sha256: &'a str,
        product_version: &'a str,
        context_abi: &'a str,
        source_revision: &'a str,
        runtime_profile: &'static str,
        installed_workflow: InstalledWorkflowReceipt,
        process_enforcement: &'static str,
        checks: Vec<CheckReceipt<'static>>,
    }

    #[derive(Serialize)]
    struct InstalledWorkflowReceipt {
        profile: &'static str,
        full_surface_sha256: String,
        semantic_identity_sha256: String,
        cigar_sha256: String,
        cigard_sha256: String,
        binding_sha256: String,
        no_egress_enforcement: &'static str,
    }

    struct GovernedWorkflowEvidence {
        semantic_identity_sha256: String,
    }

    #[derive(Serialize)]
    struct CheckReceipt<'a> {
        id: &'a str,
        status: &'static str,
    }

    struct CapturedOutput {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct SqliteBackupFingerprint {
        migrations: Vec<(i64, String, String)>,
        revision: i64,
        semantic_root: String,
        catalog_root: String,
        atom_count: i64,
        edge_count: i64,
        referenced_blob_bytes: i64,
        open_lineages: i64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RetainedV1Fixture {
        schema_version: String,
        revision: u64,
        tenant_id: RecordId,
        lineage_head_version_id: VersionId,
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
        expected: RetainedV1Pins,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RetainedV1Pins {
        semantic_root: String,
        residual_checksum: String,
        catalog_root: String,
        atom_count: u64,
        edge_count: u64,
        open_lineage_count: u64,
        referenced_blob_bytes: u64,
        root_bucket_count: u64,
        atom_record_checksums: BTreeMap<String, String>,
        edge_record_checksums: BTreeMap<String, String>,
    }

    #[derive(Serialize)]
    struct LegacyCommittedStateV1 {
        revision: cigar_store::StoreRevision,
        tenants: BTreeMap<RecordId, LegacyTenantStateV1>,
    }

    #[derive(Serialize)]
    struct LegacyTenantStateV1 {
        atoms: BTreeMap<VersionId, ContextAtomV1>,
        edges: BTreeMap<RecordId, ContextEdge>,
        bundles: BTreeMap<String, Value>,
        snapshots: BTreeMap<String, Value>,
        context_commits: BTreeMap<String, Value>,
        effects: BTreeMap<String, Value>,
        blobs: BTreeMap<String, Value>,
        outbox: Vec<Value>,
        idempotency: BTreeMap<String, Value>,
    }

    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct CatalogFreeStateV4Fixture {
        format_version: u8,
        revision: cigar_store::StoreRevision,
        tenants: BTreeMap<RecordId, CatalogFreeTenantStateV4Fixture>,
    }

    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct CatalogFreeTenantStateV4Fixture {
        bundles: BTreeMap<String, Value>,
        snapshots: BTreeMap<String, Value>,
        context_commits: BTreeMap<String, Value>,
        effects: BTreeMap<String, Value>,
        effect_records: BTreeMap<String, Value>,
        blobs: BTreeMap<String, Value>,
        outbox: Vec<Value>,
        idempotency: BTreeMap<String, Value>,
        service_records: BTreeMap<String, Value>,
        service_idempotency: BTreeMap<String, Value>,
        worker_states: BTreeMap<String, Value>,
    }

    struct ExpectedCatalogAtom {
        atom: ContextAtomV1,
        record: Vec<u8>,
        record_checksum: String,
        exact_text: String,
        referenced_blob_bytes: u64,
        root_bucket: u16,
    }

    struct ExpectedCatalogEdge {
        edge: ContextEdge,
        record: Vec<u8>,
        record_checksum: String,
        root_bucket: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ExpectedCatalogBucket {
        atom_count: u64,
        edge_count: u64,
        referenced_blob_bytes: u64,
        atom_root: String,
        edge_root: String,
    }

    struct PreparedRetainedV1Fixture {
        revision: cigar_store::StoreRevision,
        tenant_id: RecordId,
        lineage_head_version_id: VersionId,
        state: Vec<u8>,
        semantic_root: String,
        residual_state: Vec<u8>,
        residual_checksum: String,
        catalog_root: String,
        atoms: Vec<ExpectedCatalogAtom>,
        edges: Vec<ExpectedCatalogEdge>,
        lineage_heads: BTreeMap<String, String>,
        buckets: BTreeMap<u16, ExpectedCatalogBucket>,
        referenced_blob_bytes: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ExpectedMigrationLedgerRow {
        sequence: i64,
        name: &'static str,
        checksum: String,
        minimum_application_major: i64,
        maximum_application_major: i64,
        online: i64,
    }

    struct MockExchange {
        operation: String,
        method: &'static str,
        path: String,
        request_body: Option<Value>,
        idempotency_key: Option<String>,
        expected_revision: Option<String>,
        response: Value,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        owner: u32,
        links: u64,
        bytes: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    struct ProcessGuard {
        child: Child,
        group: rustix::process::Pid,
        settled: bool,
    }

    struct Fixture {
        root: PathBuf,
        project: PathBuf,
        state: PathBuf,
        runtime: PathBuf,
        daemon_config: PathBuf,
        embedded_config: PathBuf,
        local_config: PathBuf,
        source_id: RecordId,
        project_id: RecordId,
        principal_id: RecordId,
        sandbox: CandidateSandbox,
    }

    struct DaemonChild {
        process: ProcessGuard,
        binary: PathBuf,
        identity: FileIdentity,
        stdout: PathBuf,
        stderr: PathBuf,
    }

    impl ProcessGuard {
        fn spawn(command: &mut Command) -> Result<Self> {
            command.process_group(0);
            let child = command.spawn()?;
            let raw = i32::try_from(child.id())?;
            let group = rustix::process::Pid::from_raw(raw).ok_or("invalid child process id")?;
            Ok(Self {
                child,
                group,
                settled: false,
            })
        }

        fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
            let status = self.child.try_wait()?;
            if status.is_some() {
                let _ignored =
                    rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
                self.settled = true;
            }
            Ok(status)
        }

        fn terminate(&self) -> Result<()> {
            rustix::process::kill_process_group(self.group, rustix::process::Signal::TERM)?;
            Ok(())
        }

        fn force_settle(&mut self) {
            if self.settled {
                return;
            }
            let _ignored =
                rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
            let _ignored = self.child.kill();
            let _ignored = self.child.wait();
            self.settled = true;
        }
    }

    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            self.force_settle();
        }
    }

    pub(super) fn entry() -> ExitCode {
        match execute(std::env::args_os().skip(1).collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_error) => {
                eprintln!(
                    "cigar-install-qualifier failed at {}",
                    qualification_phase_label(QUALIFICATION_PHASE.load(Ordering::Relaxed))
                );
                ExitCode::FAILURE
            }
        }
    }

    fn qualification_phase(identifier: u8) {
        QUALIFICATION_PHASE.store(identifier, Ordering::Relaxed);
    }

    fn qualification_phase_label(identifier: u8) -> &'static str {
        match identifier {
            1 => "version-binding",
            2 => "full-surface",
            3 => "governed-workflow",
            4 => "no-egress",
            5 => "doctor",
            6 => "backup-restore",
            7 => "daemon-lifecycle",
            8 => "local-contracts",
            9 => "upgrade",
            10 => "executable-immutability",
            11 => "receipt",
            20 => "upgrade-integrity",
            21 => "upgrade-migration-ledger",
            22 => "upgrade-normalized-catalog",
            23 => "upgrade-atom-projection",
            24 => "upgrade-retained-backup",
            30 => "upgrade-catalog-authority",
            31 => "upgrade-catalog-revision",
            32 => "upgrade-catalog-legacy-retirement",
            33 => "upgrade-catalog-atoms",
            34 => "upgrade-catalog-edges",
            35 => "upgrade-catalog-lineages",
            36 => "upgrade-catalog-buckets",
            _ => "bootstrap",
        }
    }

    fn execute(raw: Vec<OsString>) -> Result<()> {
        if raw.len() == 1
            && raw
                .first()
                .and_then(|value| value.to_str())
                .is_some_and(|value| matches!(value, "--help" | "-h" | "help"))
        {
            print!("{HELP}");
            return Ok(());
        }
        if !cfg!(target_arch = "aarch64") {
            return Err("qualification requires native Apple silicon".into());
        }
        if std::env::var("CIGAR_NO_EGRESS_ENFORCED").as_deref() != Ok("1") {
            return Err("no-egress enforcement is absent".into());
        }
        let arguments = Arguments::parse(raw)?;
        let validated = arguments.validate()?;
        let sandbox = CandidateSandbox::for_arguments(&validated)?;
        let cigar_before = digest_file(&validated.cigar, MAX_BINARY_BYTES)?;
        let cigard_before = digest_file(&validated.cigard, MAX_BINARY_BYTES)?;

        let root = validated.workspace.join("cigar-install-qualification-v1");
        create_private_directory(&root)?;
        for name in ["home", "tmp", "captures"] {
            create_private_directory(&root.join(name))?;
        }

        qualification_phase(1);
        qualify_versions(&validated, &root, &sandbox)?;
        qualification_phase(2);
        let full_surface_sha256 = qualify_full_surface(&validated.cigar, &root, &sandbox)?;
        let fixture = Fixture::new(
            &root.join("governed-workflow"),
            &allocate_runtime_directory("governed")?,
            false,
            sandbox.clone(),
        )?;
        qualification_phase(3);
        let workflow = qualify_governed_workflow(&validated.cigar, &fixture)?;
        qualification_phase(4);
        qualify_no_egress_and_excluded_surfaces(&validated.cigar, &fixture)?;
        qualification_phase(5);
        qualify_doctor(&validated.cigar, &fixture)?;
        qualification_phase(6);
        qualify_backup_restore(&validated.cigar, &fixture)?;
        qualification_phase(7);
        qualify_daemon_lifecycle(&validated.cigar, &validated.cigard, &fixture)?;
        qualification_phase(8);
        qualify_local_contracts(
            &validated.cigar,
            &root.join("local-contracts"),
            &allocate_runtime_directory("contracts")?,
            &sandbox,
        )?;
        qualification_phase(9);
        qualify_upgrade(
            &validated.cigar,
            &validated.cigard,
            &root.join("upgrade"),
            &allocate_runtime_directory("upgrade")?,
            sandbox,
        )?;

        qualification_phase(10);
        if digest_file(&validated.cigar, MAX_BINARY_BYTES)? != cigar_before
            || digest_file(&validated.cigard, MAX_BINARY_BYTES)? != cigard_before
        {
            return Err("installed executable changed during qualification".into());
        }

        let binding_sha256 = installed_workflow_binding(
            &validated.artifact_id,
            &validated.artifact_sha256,
            &validated.source_revision,
            &full_surface_sha256,
            &workflow.semantic_identity_sha256,
            &cigar_before,
            &cigard_before,
        );

        qualification_phase(11);
        let checks = [
            "approved-source-config",
            "backup-restore",
            "catalog-query-retrieval",
            "compile",
            "daemon-lifecycle",
            "delta",
            "doctor",
            "effect-reconcile-cli-contract",
            "excluded-surface-negative",
            "explain",
            "full-surface",
            "handoff-preview-cli-contract",
            "ingest",
            "init",
            "materialize",
            "no-egress",
            "offline-restart",
            "permission-denial",
            "revalidate",
            "replay-cli-contract",
            "source-add",
            "upgrade",
            "version-binding",
        ]
        .into_iter()
        .map(|id| CheckReceipt {
            id,
            status: "passed",
        })
        .collect();
        let receipt = DriverReceipt {
            schema_version: "cigar.installed-driver.v1",
            status: "passed",
            artifact_id: &validated.artifact_id,
            artifact_sha256: &validated.artifact_sha256,
            product_version: &validated.product_version,
            context_abi: &validated.context_abi,
            source_revision: &validated.source_revision,
            runtime_profile: RUNTIME_PROFILE,
            installed_workflow: InstalledWorkflowReceipt {
                profile: WORKFLOW_PROFILE,
                full_surface_sha256,
                semantic_identity_sha256: workflow.semantic_identity_sha256,
                cigar_sha256: cigar_before,
                cigard_sha256: cigard_before,
                binding_sha256,
                no_egress_enforcement: NO_EGRESS_ENFORCEMENT,
            },
            process_enforcement: PROCESS_ENFORCEMENT,
            checks,
        };
        let stdout = std::io::stdout();
        let mut locked = stdout.lock();
        serde_json::to_writer(&mut locked, &receipt)?;
        locked.write_all(b"\n")?;
        locked.flush()?;
        Ok(())
    }

    impl Arguments {
        fn parse(raw: Vec<OsString>) -> Result<Self> {
            let mut cigar = None;
            let mut cigard = None;
            let mut workspace = None;
            let mut artifact_id = None;
            let mut artifact_sha256 = None;
            let mut product_version = None;
            let mut context_abi = None;
            let mut source_revision = None;
            let mut sandbox_root = None;
            let mut candidate_input_root = None;
            let mut values = raw.into_iter();
            while let Some(flag) = values.next() {
                let name = flag.to_str().ok_or("argument name is not UTF-8")?;
                let value = values.next().ok_or("argument has no value")?;
                match name {
                    "--cigar" => set_once(&mut cigar, PathBuf::from(value))?,
                    "--cigard" => set_once(&mut cigard, PathBuf::from(value))?,
                    "--workspace" => set_once(&mut workspace, PathBuf::from(value))?,
                    "--artifact-id" => set_once(
                        &mut artifact_id,
                        value
                            .into_string()
                            .map_err(|_value| "artifact id is not UTF-8")?,
                    )?,
                    "--artifact-sha256" => set_once(
                        &mut artifact_sha256,
                        value
                            .into_string()
                            .map_err(|_value| "artifact digest is not UTF-8")?,
                    )?,
                    "--product-version" => set_once(
                        &mut product_version,
                        value
                            .into_string()
                            .map_err(|_value| "product version is not UTF-8")?,
                    )?,
                    "--context-abi" => set_once(
                        &mut context_abi,
                        value
                            .into_string()
                            .map_err(|_value| "context ABI is not UTF-8")?,
                    )?,
                    "--source-revision" => set_once(
                        &mut source_revision,
                        value
                            .into_string()
                            .map_err(|_value| "source revision is not UTF-8")?,
                    )?,
                    "--sandbox-root" => set_once(&mut sandbox_root, PathBuf::from(value))?,
                    "--candidate-input-root" => {
                        set_once(&mut candidate_input_root, PathBuf::from(value))?
                    }
                    _ => return Err("unknown qualification argument".into()),
                }
            }
            Ok(Self {
                cigar: cigar.ok_or("missing --cigar")?,
                cigard: cigard.ok_or("missing --cigard")?,
                workspace: workspace.ok_or("missing --workspace")?,
                artifact_id: artifact_id.ok_or("missing --artifact-id")?,
                artifact_sha256: artifact_sha256.ok_or("missing --artifact-sha256")?,
                product_version: product_version.ok_or("missing --product-version")?,
                context_abi: context_abi.ok_or("missing --context-abi")?,
                source_revision: source_revision.ok_or("missing --source-revision")?,
                sandbox_root: sandbox_root.ok_or("missing --sandbox-root")?,
                candidate_input_root: candidate_input_root
                    .ok_or("missing --candidate-input-root")?,
            })
        }

        fn validate(mut self) -> Result<Self> {
            self.cigar = validate_executable(&self.cigar, "cigar")?;
            self.cigard = validate_executable(&self.cigard, "cigard")?;
            if self.cigar.parent() != self.cigard.parent() || self.cigar == self.cigard {
                return Err("installed executables are not one exact runtime pair".into());
            }
            if !self.workspace.is_absolute() {
                return Err("qualification workspace is not absolute".into());
            }
            self.workspace = self.workspace.canonicalize()?;
            validate_owner_directory(&self.workspace)?;
            if !self.sandbox_root.is_absolute() || !self.candidate_input_root.is_absolute() {
                return Err("qualification sandbox paths are not absolute".into());
            }
            self.sandbox_root = self.sandbox_root.canonicalize()?;
            self.candidate_input_root = self.candidate_input_root.canonicalize()?;
            validate_owner_directory(&self.sandbox_root)?;
            validate_owner_directory(&self.candidate_input_root)?;
            if !self.workspace.starts_with(&self.sandbox_root)
                || !self.candidate_input_root.starts_with(&self.sandbox_root)
                || self.candidate_input_root == self.sandbox_root
            {
                return Err("qualification sandbox roots are not nested safely".into());
            }
            if !valid_identifier(&self.artifact_id)
                || !valid_hex_digest(&self.artifact_sha256)
                || !valid_version(&self.product_version)
                || self.context_abi != "cigar.context.v1"
                || !valid_source_revision(&self.source_revision)
            {
                return Err("artifact binding is invalid".into());
            }
            Ok(self)
        }
    }

    impl CandidateSandbox {
        fn for_arguments(arguments: &Arguments) -> Result<Self> {
            let runtime_root = arguments
                .cigar
                .parent()
                .and_then(Path::parent)
                .ok_or("installed runtime has no prefix")?
                .canonicalize()?;
            validate_owner_directory(&runtime_root)?;

            let current_executable =
                validate_executable(&std::env::current_exe()?, "cigar-install-qualifier")?;
            let tool_root = current_executable
                .parent()
                .and_then(Path::parent)
                .ok_or("qualification tool has no prefix")?
                .canonicalize()?;
            validate_owner_directory(&tool_root)?;

            let protected = [
                arguments.candidate_input_root.as_path(),
                runtime_root.as_path(),
                tool_root.as_path(),
            ];
            if protected
                .iter()
                .any(|path| !path.starts_with(&arguments.sandbox_root))
                || protected.iter().enumerate().any(|(offset, path)| {
                    protected.iter().skip(offset + 1).any(|other| path == other)
                })
            {
                return Err("candidate protected roots are not exact sandbox descendants".into());
            }

            Self::for_roots(&arguments.sandbox_root, &protected)
        }

        fn for_roots(writable_root: &Path, protected_roots: &[&Path]) -> Result<Self> {
            let writable = sandbox_path_literal(writable_root)?;
            let mut policy = format!(
                concat!(
                    "(version 1)(allow default)",
                    "(deny network*)(deny file-write*)(deny process-fork)(deny signal)",
                    "(deny mach-lookup)",
                    "(allow file-write* (subpath {}))"
                ),
                writable
            );
            for path in protected_roots {
                policy.push_str("(deny file-write* (subpath ");
                policy.push_str(&sandbox_path_literal(path)?);
                policy.push_str("))");
            }
            policy.push_str("(allow network-bind network-inbound network-outbound (subpath ");
            policy.push_str(&writable);
            policy.push_str("))");
            Ok(Self { policy })
        }
    }

    fn sandbox_path_literal(path: &Path) -> Result<String> {
        let value = path
            .to_str()
            .ok_or("qualification sandbox path is not UTF-8")?;
        Ok(serde_json::to_string(value)?)
    }

    fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
        if slot.replace(value).is_some() {
            return Err("duplicate qualification argument".into());
        }
        Ok(())
    }

    fn valid_identifier(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
    }

    fn valid_hex_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn valid_source_revision(value: &str) -> bool {
        matches!(value.len(), 40 | 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn valid_version(value: &str) -> bool {
        value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            && value.split('.').take(3).count() == 3
            && value.bytes().any(|byte| byte == b'.')
    }

    fn validate_executable(path: &Path, expected_name: &str) -> Result<PathBuf> {
        if !path.is_absolute() || path.file_name() != Some(OsStr::new(expected_name)) {
            return Err("installed executable path is invalid".into());
        }
        let link = fs::symlink_metadata(path)?;
        let canonical = path.canonicalize()?;
        let identity = executable_identity(&canonical)?;
        if link.file_type().is_symlink()
            || identity.owner != rustix::process::geteuid().as_raw()
            || identity.links != 1
            || identity.mode & 0o022 != 0
            || identity.mode & 0o111 == 0
            || identity.bytes == 0
            || identity.bytes > MAX_BINARY_BYTES
            || !has_private_ancestor(&canonical)?
        {
            return Err("installed executable is not owner-controlled".into());
        }
        Ok(canonical)
    }

    fn executable_identity(path: &Path) -> Result<FileIdentity> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("installed executable identity is invalid".into());
        }
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            links: metadata.nlink(),
            bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn has_private_ancestor(path: &Path) -> Result<bool> {
        let owner = rustix::process::geteuid().as_raw();
        for ancestor in path.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("installed executable ancestor is invalid".into());
            }
            if metadata.uid() == owner && metadata.mode() & 0o777 == 0o700 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_owner_directory(path: &Path) -> Result<()> {
        let link = fs::symlink_metadata(path)?;
        let metadata = fs::metadata(path)?;
        if link.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err("qualification directory is not owner-controlled".into());
        }
        Ok(())
    }

    fn create_private_directory(path: &Path) -> Result<()> {
        fs::create_dir(path)?;
        fs::set_permissions(path, Permissions::from_mode(0o700))?;
        validate_owner_directory(path)
    }

    fn allocate_runtime_directory(label: &str) -> Result<PathBuf> {
        let temporary = PathBuf::from(std::env::var_os("TMPDIR").ok_or("TMPDIR is absent")?);
        if !temporary.is_absolute() {
            return Err("TMPDIR is not absolute".into());
        }
        let temporary = temporary.canonicalize()?;
        validate_owner_directory(&temporary)?;
        let runtime = temporary.join(format!("cigar-q-{label}"));
        create_private_directory(&runtime)?;
        let socket = runtime.join("cigard.sock");
        if socket.as_os_str().as_encoded_bytes().len() > 96 {
            return Err("qualified Unix socket path exceeds the macOS bound".into());
        }
        Ok(runtime)
    }

    fn restricted_write(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::set_permissions(path, Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn digest_file(path: &Path, maximum: u64) -> Result<String> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err("bounded file validation failed".into());
        }
        let mut file = File::open(path)?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(count)?)
                .ok_or("file length overflow")?;
            if total > maximum {
                return Err("bounded file validation failed".into());
            }
            let chunk = buffer.get(..count).ok_or("invalid file read")?;
            digest.update(chunk);
        }
        if total != metadata.len() {
            return Err("file changed during digest".into());
        }
        Ok(hex_bytes(&digest.finalize()))
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn content_free_digest(domain: &str, values: &[&str]) -> String {
        let mut digest = Sha256::new();
        for value in std::iter::once(domain).chain(values.iter().copied()) {
            let bytes = value.as_bytes();
            digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(bytes);
        }
        hex_bytes(&digest.finalize())
    }

    fn installed_workflow_binding(
        artifact_id: &str,
        artifact_sha256: &str,
        source_revision: &str,
        full_surface_sha256: &str,
        semantic_identity_sha256: &str,
        cigar_sha256: &str,
        cigard_sha256: &str,
    ) -> String {
        content_free_digest(
            "cigar.installed-workflow-binding.v1",
            &[
                artifact_id,
                artifact_sha256,
                source_revision,
                RUNTIME_PROFILE,
                WORKFLOW_PROFILE,
                full_surface_sha256,
                semantic_identity_sha256,
                cigar_sha256,
                cigard_sha256,
                NO_EGRESS_ENFORCEMENT,
                PROCESS_ENFORCEMENT,
            ],
        )
    }

    fn create_capture(root: &Path, label: &str) -> Result<(PathBuf, File)> {
        let sequence = CAPTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = root
            .join("captures")
            .join(format!("{label}-{sequence:016x}.capture"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok((path, file))
    }

    fn configure_candidate_command(
        command: &mut Command,
        binary: &Path,
        cwd: &Path,
        root: &Path,
    ) -> Result<()> {
        let binary_directory = binary.parent().ok_or("candidate has no parent")?;
        command
            .current_dir(cwd)
            .env_clear()
            .env("CIGAR_NO_EGRESS_ENFORCED", "1")
            .env("HOME", root.join("home"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("NO_COLOR", "1")
            .env("PATH", binary_directory)
            .env("TMPDIR", root.join("tmp"))
            .env("TZ", "UTC")
            .stdin(Stdio::null());
        Ok(())
    }

    fn validated_sandbox_launcher() -> Result<PathBuf> {
        let path = PathBuf::from(MACOS_SANDBOX_EXEC);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_BINARY_BYTES
            || path.canonicalize()? != path
        {
            return Err("fixed macOS process sandbox launcher is not root-controlled".into());
        }
        Ok(path)
    }

    fn sandboxed_candidate_command(binary: &Path, sandbox: &CandidateSandbox) -> Result<Command> {
        let mut command = Command::new(validated_sandbox_launcher()?);
        command.args(["-p", sandbox.policy.as_str()]).arg(binary);
        Ok(command)
    }

    fn run_candidate(
        binary: &Path,
        arguments: &[OsString],
        cwd: &Path,
        root: &Path,
        sandbox: &CandidateSandbox,
    ) -> Result<CapturedOutput> {
        let identity = executable_identity(binary)?;
        let (stdout_path, stdout_file) = create_capture(root, "stdout")?;
        let (stderr_path, stderr_file) = create_capture(root, "stderr")?;
        let mut command = sandboxed_candidate_command(binary, sandbox)?;
        configure_candidate_command(&mut command, binary, cwd, root)?;
        command
            .args(arguments)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        let mut process = ProcessGuard::spawn(&mut command)?;
        let status = wait_for_exit(&mut process, &stdout_path, &stderr_path, PROCESS_TIMEOUT)?;
        if executable_identity(binary)? != identity {
            return Err("candidate executable identity changed".into());
        }
        let stdout = read_capture(&stdout_path)?;
        let stderr = read_capture(&stderr_path)?;
        fs::remove_file(stdout_path)?;
        fs::remove_file(stderr_path)?;
        Ok(CapturedOutput {
            status,
            stdout,
            stderr,
        })
    }

    fn wait_for_exit(
        process: &mut ProcessGuard,
        stdout: &Path,
        stderr: &Path,
        timeout: Duration,
    ) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            validate_capture_size(stdout)?;
            validate_capture_size(stderr)?;
            if let Some(status) = process.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("candidate process timed out".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn validate_capture_size(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_CAPTURE_BYTES
        {
            return Err("candidate output exceeded its bound".into());
        }
        Ok(())
    }

    fn read_capture(path: &Path) -> Result<Vec<u8>> {
        validate_capture_size(path)?;
        let bytes = fs::read(path)?;
        if u64::try_from(bytes.len())? > MAX_CAPTURE_BYTES {
            return Err("candidate output exceeded its bound".into());
        }
        Ok(bytes)
    }

    fn successful_json(output: CapturedOutput, target: Option<&str>) -> Result<Value> {
        if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
            return Err("candidate command failed".into());
        }
        let value: Value = serde_json::from_slice(&output.stdout)?;
        if value.pointer("/ok").and_then(Value::as_bool) != Some(true) {
            return Err("candidate success envelope is malformed".into());
        }
        if let Some(expected) = target
            && value.pointer("/target").and_then(Value::as_str) != Some(expected)
        {
            return Err("candidate target binding is wrong".into());
        }
        Ok(value)
    }

    fn failed_json(
        output: CapturedOutput,
        expected_code: Option<&str>,
        forbidden: &[&str],
    ) -> Result<Value> {
        if output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
            return Err("candidate negative command did not fail safely".into());
        }
        let value: Value = serde_json::from_slice(&output.stdout)?;
        let code = value
            .pointer("/error/code")
            .and_then(Value::as_str)
            .ok_or("candidate negative response omitted its content-safe code")?;
        if value.pointer("/schema_version").and_then(Value::as_str) != Some("cigar.cli.output.v1")
            || value.pointer("/ok").and_then(Value::as_bool) != Some(false)
            || expected_code.is_some_and(|expected| code != expected)
        {
            return Err("candidate negative response is malformed".into());
        }
        let combined = String::from_utf8_lossy(&output.stdout);
        if forbidden
            .iter()
            .any(|secret| !secret.is_empty() && combined.contains(secret))
        {
            return Err("candidate negative response disclosed protected input".into());
        }
        Ok(value)
    }

    fn candidate_json(
        cigar: &Path,
        cwd: &Path,
        root: &Path,
        config: &Path,
        arguments: &[&OsStr],
        target: &str,
        sandbox: &CandidateSandbox,
    ) -> Result<Value> {
        let mut complete = arguments
            .iter()
            .map(|value| (*value).to_os_string())
            .collect::<Vec<_>>();
        complete.extend([
            OsString::from("--config"),
            config.as_os_str().to_os_string(),
            OsString::from("--output"),
            OsString::from("json"),
            OsString::from("--deadline"),
            OsString::from("30s"),
        ]);
        successful_json(
            run_candidate(cigar, &complete, cwd, root, sandbox)?,
            Some(target),
        )
    }

    fn qualify_versions(
        arguments: &Arguments,
        root: &Path,
        sandbox: &CandidateSandbox,
    ) -> Result<()> {
        let cigar_output = run_candidate(
            &arguments.cigar,
            &[
                OsString::from("--output"),
                OsString::from("json"),
                OsString::from("version"),
            ],
            root,
            root,
            sandbox,
        )?;
        if !cigar_output.status.success() || !cigar_output.stderr.is_empty() {
            return Err("cigar version command failed".into());
        }
        let cigar: Value = serde_json::from_slice(&cigar_output.stdout)?;
        let expected = json!({
            "version": arguments.product_version,
            "source_revision": arguments.source_revision,
            "context_abi": arguments.context_abi,
            "protocol_min": "1.0",
            "protocol_max": "1.x",
            "build_profile": "release",
            "enabled_features": [],
        });
        if cigar != expected {
            return Err("cigar version identity is not exactly release-bound".into());
        }
        let daemon = run_candidate(
            &arguments.cigard,
            &[OsString::from("version")],
            root,
            root,
            sandbox,
        )?;
        if !daemon.status.success() || !daemon.stderr.is_empty() {
            return Err("cigard version command failed".into());
        }
        let value: Value = serde_json::from_slice(&daemon.stdout)?;
        if value != expected || value != cigar {
            return Err("cigard version identity is not the exact runtime pair".into());
        }
        Ok(())
    }

    fn qualify_full_surface(
        cigar: &Path,
        root: &Path,
        sandbox: &CandidateSandbox,
    ) -> Result<String> {
        let output = run_candidate(cigar, &[OsString::from("help")], root, root, sandbox)?;
        if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
            return Err("installed full-surface help probe failed".into());
        }
        validate_full_surface_help(&output.stdout)
    }

    fn validate_full_surface_help(payload: &[u8]) -> Result<String> {
        if payload != AUTHORITATIVE_FULL_HELP {
            return Err("installed archive help differs from the closed full surface".into());
        }
        let help = std::str::from_utf8(payload)?;
        for required in [
            "cigar source add | list | refresh | inspect | remove",
            "cigar catalog query",
            "cigar context plan | compile | explain | diff | revalidate | materialize",
            "cigar effect prepare | approve | dispatch | list | inspect | reconcile | compensate",
            "cigar serve",
            "cigar mcp serve",
            "cigar plugin doctor claude-code",
            "--target <embedded|local|remote>",
        ] {
            if !help.contains(required) {
                return Err("installed archive does not expose the exact full surface".into());
            }
        }
        if help.contains("CIGAR initial beta")
            || help.contains("this build does not discover, ingest, index, retrieve, or compile")
        {
            return Err("narrow beta bytes cannot satisfy full-product qualification".into());
        }
        Ok(hex_bytes(&Sha256::digest(payload)))
    }

    impl Fixture {
        fn new(
            root: &Path,
            runtime: &Path,
            legacy_database: bool,
            sandbox: CandidateSandbox,
        ) -> Result<Self> {
            create_private_directory(root)?;
            let state = root.join("state");
            let runtime = runtime.to_path_buf();
            let project = root.join("project");
            let trusted = root.join("trusted");
            let secrets = root.join("secrets");
            let home = root.join("home");
            let temporary = root.join("tmp");
            let captures = root.join("captures");
            for path in [
                &state, &project, &trusted, &secrets, &home, &temporary, &captures,
            ] {
                create_private_directory(path)?;
            }
            validate_owner_directory(&runtime)?;
            restricted_write(
                &project.join("README.md"),
                format!(
                    "# Installed qualification\n\n{SOURCE_CANARY} is selected only through governed local context.\n"
                )
                .as_bytes(),
            )?;

            let tenant_id = record(TENANT_VALUE)?;
            let project_id = record(PROJECT_VALUE)?;
            let principal_id = record(PRINCIPAL_VALUE)?;
            let source_id = record(SOURCE_VALUE)?;
            let passphrase_file = secrets.join("keystore-passphrase");
            let passphrase = b"0123456789abcdef0123456789abcdef";
            restricted_write(&passphrase_file, passphrase)?;
            let keystore_file = state.join("keystore.cigar");
            let keystore = EncryptedDevelopmentKeystore::open(
                &keystore_file,
                SecretBytes::new(passphrase.to_vec()),
            )?;
            let signing = keystore.create(CreateKeyRequest {
                tenant: tenant_id.as_str().to_owned(),
                purpose: KeyPurpose::Signing,
                algorithm: KeyAlgorithm::Ed25519,
                created_at: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?.unix_nanos(),
                activated_at: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?.unix_nanos(),
            })?;
            drop(keystore);

            let authenticated = LocalIdentity::from_project_root(&project)?.authenticated();
            let authority = ProductionAuthorityConfiguration {
                schema_version: "cigar.production-authority.v1".to_owned(),
                runtime_audience: "local-runtime-v1".to_owned(),
                decision_ttl_seconds: 60,
                tenants: vec![ProductionTenantAuthority {
                    authenticated_tenant: authenticated.tenant().as_str().to_owned(),
                    tenant_id: tenant_id.clone(),
                    active: true,
                    issuer_key_ref: signing.key_ref,
                    project_ids: vec![project_id.clone()],
                    principals: vec![ProductionPrincipalAuthority {
                        authenticated_principal: authenticated.principal().as_str().to_owned(),
                        principal_id: principal_id.clone(),
                        grant_id: record(GRANT_VALUE)?,
                        active: true,
                        operator: true,
                        not_before: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?,
                        expires_at: UtcTimestamp::parse_rfc3339("2099-01-01T00:00:00Z")?,
                        roles: vec!["developer".to_owned()],
                        project_ids: vec![project_id.clone()],
                        capabilities: vec![Capability::ReadContext, Capability::CompileContext],
                        delegatable_capabilities: Vec::new(),
                        purposes: vec!["catalog.read".to_owned()],
                        processors: vec!["cigar-reference".to_owned(), "local".to_owned()],
                        catalog_purpose: "catalog.read".to_owned(),
                        catalog_processor: "local".to_owned(),
                        maximum_classification: Classification::Restricted,
                        maximum_instruction_authority: InstructionAuthority::System,
                        residency_allowed: true,
                        egress_allowed: true,
                        vector_allowed: false,
                        handoff_target_allowed: false,
                        effect_rules: Vec::new(),
                    }],
                    revoked_principal_ids: Vec::new(),
                    revoked_key_refs: Vec::new(),
                }],
            };
            let authority_file = trusted.join("authority.json");
            restricted_write(&authority_file, &serde_json::to_vec(&authority)?)?;
            let policy_file = trusted.join("policy.json");
            restricted_write(
                &policy_file,
                &serde_json::to_vec(&cigar_policy::PolicyProfile {
                    schema_version: "cigar.policy-profile.v1".to_owned(),
                    revision: 1,
                    protected: true,
                    rules: Vec::new(),
                })?,
            )?;

            let atomization = ProductionAtomizationConfiguration {
                project_ids: vec![project_id.clone()],
                governance: GovernanceEnvelope {
                    classification: Classification::Internal,
                    allowed_purposes: vec!["catalog.read".to_owned()],
                    processor_constraints: Vec::new(),
                    instruction_authority: InstructionAuthority::Data,
                },
                quality: QualityEnvelope {
                    confidence: FixedPoint::new(FixedPoint::ONE)?,
                    coverage: FixedPoint::new(FixedPoint::ONE)?,
                    authority: 10,
                },
                lexical_enabled: true,
                embedding_eligible: false,
                atomizer_set: "required_v1".to_owned(),
            };
            let source = ProductionSourceEntry {
                tenant_id: tenant_id.clone(),
                source: SourceConfiguration {
                    schema_version: "cigar.source-configuration.v1".to_owned(),
                    source_id: source_id.clone(),
                    root: SourceUri::new(canonical_file_uri(&project)?)?,
                    connector_identity: "cigar.builtin.filesystem.v1".to_owned(),
                    atomization_profile_digest: atomization.registry_digest(&tenant_id)?,
                    discovery_policy: SourceDiscoveryPolicyConfiguration {
                        max_items: 100,
                        max_total_bytes: 1024 * 1024,
                        max_record_bytes: 1024 * 1024,
                        excluded_prefixes: Vec::new(),
                        allowed_media_types: BTreeSet::from([MediaType::new("text/markdown")?]),
                        allow_user_broadening: false,
                        follow_internal_symlinks: false,
                        secret_patterns: Vec::new(),
                    },
                },
                connector: ProductionSourceConnectorConfiguration {
                    kind: ProductionSourceConnectorKind::Filesystem,
                    root_directory: project.clone(),
                },
                atomization,
            };
            let sources_file = trusted.join("sources.json");
            restricted_write(
                &sources_file,
                &serde_json::to_vec(&ProductionSourceRegistry {
                    schema_version: "cigar.production-source-registry.v1".to_owned(),
                    sources: vec![source],
                })?,
            )?;
            let effects_file = trusted.join("effects.json");
            restricted_write(
                &effects_file,
                br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":false,"connectors":[]}"#,
            )?;

            let metadata_database = state.join("cigar.sqlite3");
            let daemon = DaemonConfig {
                mode: DeploymentMode::Local,
                local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
                state_directory: state.clone(),
                runtime_directory: runtime.clone(),
                unix_socket: Some(runtime.join("cigard.sock")),
                windows_named_pipe: None,
                http_listen: None,
                grpc_listen: None,
                local_token_file: None,
                tls: None,
                oidc: None,
                production: ProductionPaths {
                    project_directory: project.clone(),
                    metadata_database: metadata_database.clone(),
                    active_store_descriptor: None,
                    blob_directory: state.join("blobs"),
                    blob_key_reference_directory: state.join("blob-keys"),
                    keystore_file,
                    keystore_passphrase_file: passphrase_file,
                    cursor_signing_key_file: state.join("cursor.key"),
                    effect_checkpoint_file: root.join("effect-checkpoints/checkpoints.json"),
                    policy_profile_file: policy_file,
                    authority_file,
                    source_registry_file: sources_file,
                    effect_registry_file: effects_file,
                },
                shared_storage: None,
                local_vector: cigar_daemon::LocalVectorSettings::default(),
                request_deadline_ms: 30_000,
                shutdown_deadline_ms: 30_000,
                max_request_bytes: 1024 * 1024,
                max_expansion_ratio: 8,
                workers: WorkerCapacities {
                    ingestion: 4,
                    indexing: 4,
                    invalidation: 4,
                    compilation: 4,
                    outbox: 4,
                    reconciliation: 4,
                    lease_cleanup: 4,
                    backup: 2,
                    garbage_collection: 2,
                },
                resources: ApplicationResourceLimits {
                    global_request_concurrency: 32,
                    per_tenant_request_concurrency: 8,
                    blocking_active: 4,
                    blocking_queued: 16,
                    idempotency_wait_ms: 5_000,
                },
                telemetry: TelemetrySettings {
                    otlp_endpoint: None,
                    otlp_ca_certificate_file: None,
                    export_timeout_ms: 1_000,
                    metric_interval_ms: 1_000,
                },
            };
            daemon.validate()?;
            let daemon_config = root.join("cigard.toml");
            restricted_write(&daemon_config, toml::to_string(&daemon)?.as_bytes())?;
            let embedded_config = root.join("embedded-cli.toml");
            restricted_write(
                &embedded_config,
                format!(
                    concat!(
                        "schema_version = 1\n",
                        "target = \"embedded\"\n",
                        "daemon_config = {}\n",
                        "project_state_directory = {}\n"
                    ),
                    serde_json::to_string(&daemon_config.display().to_string())?,
                    serde_json::to_string(&state.join("embedded-cli-state").display().to_string())?,
                )
                .as_bytes(),
            )?;
            let local_config = root.join("local-cli.toml");
            restricted_write(
                &local_config,
                format!(
                    concat!(
                        "schema_version = 1\n",
                        "target = \"local\"\n",
                        "project_state_directory = {}\n",
                        "local_socket = {}\n"
                    ),
                    serde_json::to_string(&state.join("local-cli-state").display().to_string())?,
                    serde_json::to_string(&runtime.join("cigard.sock").display().to_string())?,
                )
                .as_bytes(),
            )?;
            if legacy_database {
                create_legacy_v1_database(&metadata_database)?;
            }
            Ok(Self {
                root: root.to_path_buf(),
                project,
                state,
                runtime,
                daemon_config,
                embedded_config,
                local_config,
                source_id,
                project_id,
                principal_id,
                sandbox,
            })
        }

        fn write_input(&self, name: &str, value: &impl Serialize) -> Result<PathBuf> {
            let path = self.root.join(name);
            restricted_write(&path, &serde_json::to_vec(value)?)?;
            Ok(path)
        }

        fn embedded(&self, cigar: &Path, arguments: &[&OsStr]) -> Result<Value> {
            successful_json(self.embedded_output(cigar, arguments)?, Some("embedded"))
        }

        fn embedded_output(&self, cigar: &Path, arguments: &[&OsStr]) -> Result<CapturedOutput> {
            let mut complete = arguments
                .iter()
                .map(|value| (*value).to_os_string())
                .collect::<Vec<_>>();
            complete.extend([
                OsString::from("--config"),
                self.embedded_config.as_os_str().to_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
                OsString::from("--deadline"),
                OsString::from("30s"),
            ]);
            run_candidate(cigar, &complete, &self.project, &self.root, &self.sandbox)
        }

        fn local(&self, cigar: &Path, arguments: &[&OsStr]) -> Result<Value> {
            candidate_json(
                cigar,
                &self.project,
                &self.root,
                &self.local_config,
                arguments,
                "local",
                &self.sandbox,
            )
        }

        fn socket(&self) -> PathBuf {
            self.runtime.join("cigard.sock")
        }
    }

    fn qualify_governed_workflow(
        cigar: &Path,
        fixture: &Fixture,
    ) -> Result<GovernedWorkflowEvidence> {
        let discovery_input = fixture.write_input(
            "discover.json",
            &DiscoverSourcesRequest {
                source_id: fixture.source_id.clone(),
                include_paths: Vec::new(),
            },
        )?;
        let refresh = [
            OsStr::new("source"),
            OsStr::new("refresh"),
            OsStr::new("--input"),
            discovery_input.as_os_str(),
            OsStr::new("--yes"),
        ];
        let first_discovery = fixture.embedded(cigar, &refresh)?;
        let second_discovery = fixture.embedded(cigar, &refresh)?;
        if first_discovery.pointer("/operation_id") != Some(&json!("discoverSources"))
            || first_discovery.pointer("/result") != second_discovery.pointer("/result")
            || first_discovery
                .pointer("/result/included_count")
                .and_then(Value::as_u64)
                != Some(1)
        {
            return Err("source discovery is not deterministic".into());
        }
        let plan_digest = required_string(&first_discovery, "/result/plan_digest")?;
        let inspected = fixture.embedded(
            cigar,
            &[
                OsStr::new("source"),
                OsStr::new("inspect"),
                OsStr::new(fixture.source_id.as_str()),
            ],
        )?;
        if inspected.pointer("/result/status").and_then(Value::as_str) != Some("ready") {
            return Err("source did not become ready".into());
        }

        let ingest_input = fixture.write_input(
            "ingest.json",
            &IngestCatalogRequest {
                source_id: fixture.source_id.clone(),
                plan_digest: ContentDigest::new(plan_digest)?,
            },
        )?;
        let ingest = [
            OsStr::new("ingest"),
            OsStr::new("--input"),
            ingest_input.as_os_str(),
            OsStr::new("--idempotency-key"),
            OsStr::new("installed-ingest-v1"),
            OsStr::new("--yes"),
        ];
        let first_ingest = fixture.embedded(cigar, &ingest)?;
        let repeated_ingest = fixture.embedded(cigar, &ingest)?;
        if first_ingest.pointer("/operation_id") != Some(&json!("ingestCatalog"))
            || first_ingest.pointer("/result") != repeated_ingest.pointer("/result")
            || first_ingest
                .pointer("/result/published_atoms")
                .and_then(Value::as_u64)
                .is_none_or(|count| count == 0)
        {
            return Err("ingestion was not durable and idempotent".into());
        }

        let requirement = ContextRequirement {
            semantic_type: AtomKind::Documentation,
            selector: RequirementSelector::Query("installed qualification".to_owned()),
            minimum_authority: 1,
            maximum_age: None,
            minimum_coverage: FixedPoint::new(0)?,
            blocking: true,
        };
        let query_input = fixture.write_input(
            "query.json",
            &QueryCatalogRequest {
                requirements: vec![requirement],
                max_results: 16,
            },
        )?;
        let query = [
            OsStr::new("catalog"),
            OsStr::new("query"),
            OsStr::new("--input"),
            query_input.as_os_str(),
        ];
        let first_query = fixture.embedded(cigar, &query)?;
        let restarted_query = fixture.embedded(cigar, &query)?;
        if first_query.pointer("/result") != restarted_query.pointer("/result") {
            return Err("offline process restart changed catalog results".into());
        }
        let selected_version = first_query
            .pointer("/result/version_ids/0")
            .and_then(Value::as_str)
            .ok_or("catalog query returned no governed version")?
            .to_owned();

        let denied_input = fixture.write_input(
            "denied-plan.json",
            &CreateContextPlanRequest {
                contract: context_contract(
                    fixture.principal_id.clone(),
                    record(999)?,
                    VersionId::new(selected_version.clone())?,
                )?,
            },
        )?;
        let denied = fixture.embedded_output(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("plan"),
                OsStr::new("--input"),
                denied_input.as_os_str(),
                OsStr::new("--dry-run"),
            ],
        )?;
        failed_json(
            denied,
            None,
            &[SOURCE_CANARY, "README.md", selected_version.as_str()],
        )?;

        let plan_input = fixture.write_input(
            "plan.json",
            &CreateContextPlanRequest {
                contract: context_contract(
                    fixture.principal_id.clone(),
                    fixture.project_id.clone(),
                    VersionId::new(selected_version.clone())?,
                )?,
            },
        )?;
        let dry_plan = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("plan"),
                OsStr::new("--input"),
                plan_input.as_os_str(),
                OsStr::new("--dry-run"),
            ],
        )?;
        let committed_plan = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("plan"),
                OsStr::new("--input"),
                plan_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-plan-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        if dry_plan.pointer("/result") != committed_plan.pointer("/result") {
            return Err("dry and committed context plans diverged".into());
        }
        let plan_id = required_string(&committed_plan, "/result/plan/plan_id")?;
        let bundle_id = required_string(&committed_plan, "/result/bundle_id")?;
        let manifest_digest = required_string(&committed_plan, "/result/manifest_digest")?;

        let compile_input = fixture.write_input(
            "compile.json",
            &CompileContextBundleRequest {
                plan_id: RecordId::new(plan_id.clone())?,
            },
        )?;
        let compiled = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("compile"),
                OsStr::new("--input"),
                compile_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-compile-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        if compiled
            .pointer("/result/bundle_id")
            .and_then(Value::as_str)
            != Some(bundle_id.as_str())
            || compiled
                .pointer("/result/manifest_digest")
                .and_then(Value::as_str)
                != Some(manifest_digest.as_str())
        {
            return Err("compiled bundle lost its exact plan binding".into());
        }
        validate_plan_and_compiled_provenance(
            &committed_plan,
            &compiled,
            &BTreeSet::from([selected_version.clone()]),
        )?;

        let explain_input = fixture.write_input(
            "explain.json",
            &ExplainContextBundleRequest {
                bundle_id: VersionId::new(bundle_id.clone())?,
                version_ids: vec![VersionId::new(selected_version.clone())?],
            },
        )?;
        let explained = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("explain"),
                OsStr::new(&bundle_id),
                OsStr::new("--input"),
                explain_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-explain-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        if explained
            .pointer("/result/entries/0/version_id")
            .and_then(Value::as_str)
            != Some(selected_version.as_str())
        {
            return Err("explain did not retain provenance".into());
        }

        let bundle_request = BundleIdRequest {
            bundle_id: VersionId::new(bundle_id.clone())?,
        };
        let revalidate_input = fixture.write_input("revalidate.json", &bundle_request)?;
        let revalidated = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("revalidate"),
                OsStr::new(&bundle_id),
                OsStr::new("--input"),
                revalidate_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-revalidate-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        if revalidated
            .pointer("/result/valid")
            .and_then(Value::as_bool)
            != Some(true)
            || revalidated.pointer("/result/reasons") != Some(&json!([]))
        {
            return Err("installed bundle did not revalidate after restart".into());
        }

        let materialize_input = fixture.write_input(
            "materialize.json",
            &MaterializeContextBundleRequest {
                bundle_id: VersionId::new(bundle_id.clone())?,
                profile: MaterializationProfile::CanonicalJson,
            },
        )?;
        let materialized = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("materialize"),
                OsStr::new(&bundle_id),
                OsStr::new("--input"),
                materialize_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-materialize-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        if materialized
            .pointer("/result/context/bundle_id")
            .and_then(Value::as_str)
            != Some(bundle_id.as_str())
            || materialized
                .pointer("/result/physical_input_tokens")
                .and_then(Value::as_u64)
                .is_none_or(|tokens| tokens == 0)
        {
            return Err("installed materialization is not bound to the compiled bundle".into());
        }
        let materialized_bytes = required_string(&materialized, "/result/context/bytes")?;
        let materialized_digest = content_free_digest(
            "cigar.installed-materialization.v1",
            &[
                &bundle_id,
                &materialized_bytes,
                &materialized
                    .pointer("/result/physical_input_tokens")
                    .and_then(Value::as_u64)
                    .ok_or("materialization omitted physical token accounting")?
                    .to_string(),
            ],
        );

        let mut target_contract = context_contract(
            fixture.principal_id.clone(),
            fixture.project_id.clone(),
            VersionId::new(selected_version.clone())?,
        )?;
        target_contract.job_goal =
            "Answer the revised installed qualification question from governed evidence".to_owned();
        let target_plan_input = fixture.write_input(
            "target-plan.json",
            &CreateContextPlanRequest {
                contract: target_contract,
            },
        )?;
        let target_plan = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("plan"),
                OsStr::new("--input"),
                target_plan_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-target-plan-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        let target_plan_id = required_string(&target_plan, "/result/plan/plan_id")?;
        let target_bundle_id = required_string(&target_plan, "/result/bundle_id")?;
        if target_bundle_id == bundle_id {
            return Err("distinct installed target plan reused the base bundle identity".into());
        }
        let delta_input = fixture.write_input(
            "delta.json",
            &CompileContextDeltaRequest {
                base_bundle_id: VersionId::new(bundle_id.clone())?,
                target_plan_id: RecordId::new(target_plan_id.clone())?,
            },
        )?;
        let delta = fixture.embedded(
            cigar,
            &[
                OsStr::new("context"),
                OsStr::new("diff"),
                OsStr::new("--input"),
                delta_input.as_os_str(),
                OsStr::new("--idempotency-key"),
                OsStr::new("installed-delta-v1"),
                OsStr::new("--yes"),
            ],
        )?;
        if delta
            .pointer("/result/delta/base_bundle_id")
            .and_then(Value::as_str)
            != Some(bundle_id.as_str())
            || delta
                .pointer("/result/delta/target_bundle_id")
                .and_then(Value::as_str)
                != Some(target_bundle_id.as_str())
        {
            return Err("installed delta lost its exact base or target binding".into());
        }
        let delta_digest = required_string(&delta, "/result/delta_digest")?;

        if !fixture.state.join("cigar.sqlite3").is_file()
            || fixture.socket().exists()
            || fs::metadata(&fixture.state)?.mode() & 0o077 != 0
        {
            return Err("embedded workflow left unsafe or transient state".into());
        }
        Ok(GovernedWorkflowEvidence {
            semantic_identity_sha256: content_free_digest(
                "cigar.installed-offline-workflow-semantics.v1",
                &[
                    &selected_version,
                    &plan_id,
                    &bundle_id,
                    &manifest_digest,
                    &materialized_digest,
                    &target_plan_id,
                    &target_bundle_id,
                    &delta_digest,
                ],
            ),
        })
    }

    fn qualify_no_egress_and_excluded_surfaces(cigar: &Path, fixture: &Fixture) -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("https://{}/", listener.local_addr()?);
        let authorization = fixture.root.join("remote.authorization");
        let authorization_value = "Bearer installed-qualification-no-egress-probe";
        restricted_write(&authorization, authorization_value.as_bytes())?;
        let remote_config = fixture.root.join("remote-cli.toml");
        restricted_write(
            &remote_config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"remote\"\n",
                    "remote_endpoint = {}\n",
                    "authorization_file = {}\n",
                    "project_state_directory = {}\n"
                ),
                serde_json::to_string(&endpoint)?,
                serde_json::to_string(&authorization.display().to_string())?,
                serde_json::to_string(
                    &fixture.root.join("remote-cli-state").display().to_string()
                )?,
            )
            .as_bytes(),
        )?;

        let remote_status = run_candidate(
            cigar,
            &[
                OsString::from("status"),
                OsString::from("--config"),
                remote_config.as_os_str().to_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
                OsString::from("--deadline"),
                OsString::from("3s"),
            ],
            &fixture.project,
            &fixture.root,
            &fixture.sandbox,
        )?;
        failed_json(
            remote_status,
            Some("CLI_TARGET_UNAVAILABLE"),
            &[
                SOURCE_CANARY,
                "README.md",
                authorization_value,
                fixture
                    .project
                    .to_str()
                    .ok_or("project path is not UTF-8")?,
            ],
        )?;
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((_stream, _peer)) => {
                return Err("candidate escaped no-egress enforcement".into());
            }
            Err(error) => return Err(error.into()),
        }

        let home_before = inventory_regular_files(&fixture.root.join("home"))?;
        for arguments in [
            vec!["effect", "list"],
            vec!["plugin", "doctor", "claude-code"],
            vec!["serve", "--yes"],
        ] {
            let mut complete = arguments
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            complete.extend([
                OsString::from("--config"),
                remote_config.as_os_str().to_os_string(),
                OsString::from("--output"),
                OsString::from("json"),
                OsString::from("--deadline"),
                OsString::from("3s"),
            ]);
            let excluded = run_candidate(
                cigar,
                &complete,
                &fixture.project,
                &fixture.root,
                &fixture.sandbox,
            )?;
            failed_json(
                excluded,
                Some("CLI_UNSUPPORTED_SURFACE"),
                &[SOURCE_CANARY, "README.md", authorization_value],
            )?;
        }
        if inventory_regular_files(&fixture.root.join("home"))? != home_before {
            return Err("excluded remote administration mutated user state".into());
        }
        Ok(())
    }

    fn validate_plan_and_compiled_provenance(
        plan_response: &Value,
        compiled_response: &Value,
        authorized_versions: &BTreeSet<String>,
    ) -> Result<()> {
        if authorized_versions.is_empty() {
            return Err("installed provenance proof has no authorized versions".into());
        }
        let dispositions = plan_response
            .pointer("/result/plan/dispositions")
            .and_then(Value::as_array)
            .ok_or("installed plan omitted its complete disposition table")?;
        if dispositions.is_empty() {
            return Err("installed plan disposition table is empty".into());
        }
        let mut considered = BTreeSet::new();
        let mut selected = BTreeSet::new();
        for disposition in dispositions {
            let pair = disposition
                .as_array()
                .filter(|values| values.len() == 2)
                .ok_or("installed plan contains a malformed disposition")?;
            let version = pair
                .first()
                .and_then(Value::as_str)
                .ok_or("installed plan disposition omitted its version")?;
            VersionId::new(version.to_owned())?;
            if !considered.insert(version.to_owned()) {
                return Err("installed plan contains a duplicate disposition".into());
            }
            let state = pair
                .get(1)
                .and_then(|value| value.get("state"))
                .and_then(Value::as_str)
                .ok_or("installed plan disposition omitted its state")?;
            match state {
                "selected" => {
                    if !authorized_versions.contains(version) {
                        return Err("installed plan selected an unauthorized version".into());
                    }
                    selected.insert(version.to_owned());
                }
                "excluded" | "redacted" | "required_missing" => {}
                _ => return Err("installed plan contains an unknown disposition state".into()),
            }
        }
        if selected.is_empty() || !authorized_versions.is_subset(&considered) {
            return Err("installed plan did not dispose every authorized candidate".into());
        }

        let lanes = plan_response
            .pointer("/result/plan/lanes")
            .and_then(Value::as_array)
            .ok_or("installed plan omitted its selected lanes")?;
        let mut lane_versions = BTreeSet::new();
        for lane in lanes {
            let candidates = lane
                .get("candidate_versions")
                .and_then(Value::as_array)
                .ok_or("installed plan lane omitted its candidate inventory")?;
            for candidate in candidates {
                let version = candidate
                    .as_str()
                    .ok_or("installed plan lane contains a malformed candidate")?;
                if !lane_versions.insert(version.to_owned()) {
                    return Err("installed plan selected one candidate more than once".into());
                }
            }
        }
        if lane_versions != selected {
            return Err("installed plan lanes and selected dispositions disagree".into());
        }

        let blocks = compiled_response
            .pointer("/result/blocks")
            .and_then(Value::as_array)
            .ok_or("installed bundle omitted its block inventory")?;
        if blocks.len() != selected.len() {
            return Err("installed bundle block count differs from selected candidates".into());
        }
        let mut provenance_union = BTreeSet::new();
        for block in blocks {
            let provenance = block
                .get("provenance")
                .and_then(Value::as_array)
                .filter(|values| !values.is_empty())
                .ok_or("installed catalog-derived block has no provenance")?;
            let mut block_provenance = BTreeSet::new();
            for candidate in provenance {
                let version = candidate
                    .as_str()
                    .ok_or("installed block contains malformed provenance")?;
                if !selected.contains(version) || !block_provenance.insert(version.to_owned()) {
                    return Err("installed block provenance is unauthorized or duplicated".into());
                }
                provenance_union.insert(version.to_owned());
            }
        }
        if provenance_union != selected {
            return Err(
                "installed bundle did not preserve every selected provenance identity".into(),
            );
        }
        Ok(())
    }

    fn qualify_doctor(cigar: &Path, fixture: &Fixture) -> Result<()> {
        let doctor = fixture.embedded(cigar, &[OsStr::new("doctor")])?;
        if doctor.pointer("/operation_id").and_then(Value::as_str) != Some("getDiagnostics")
            || doctor.pointer("/result/ready").and_then(Value::as_bool) != Some(true)
        {
            return Err("doctor operation did not run".into());
        }
        Ok(())
    }

    fn qualify_backup_restore(cigar: &Path, fixture: &Fixture) -> Result<()> {
        let backup = fixture.root.join("signed-backup");
        let restored = fixture.root.join("restored-state");
        let live_database = fixture.state.join("cigar.sqlite3");
        let live_checkpoint = fixture.root.join("effect-checkpoints/checkpoints.json");
        let live_fingerprint = sqlite_backup_fingerprint(&live_database)?;
        let live_checkpoint_digest = digest_file(&live_checkpoint, MAX_BINARY_BYTES)?;
        let created = fixture.embedded(
            cigar,
            &[
                OsStr::new("backup"),
                OsStr::new("create"),
                backup.as_os_str(),
                OsStr::new("--yes"),
            ],
        )?;
        let verified = fixture.embedded(
            cigar,
            &[
                OsStr::new("backup"),
                OsStr::new("verify"),
                backup.as_os_str(),
            ],
        )?;
        let restored_receipt = fixture.embedded(
            cigar,
            &[
                OsStr::new("backup"),
                OsStr::new("restore"),
                backup.as_os_str(),
                restored.as_os_str(),
                OsStr::new("--yes"),
            ],
        )?;
        let created_root = required_string(&created, "/result/canonical_root")?;
        let created_revision = created
            .pointer("/result/repository_revision")
            .and_then(Value::as_u64)
            .ok_or("backup creation omitted its repository revision")?;
        let created_schema = created
            .pointer("/result/schema_version")
            .and_then(Value::as_u64)
            .ok_or("backup creation omitted its schema version")?;
        if required_string(&verified, "/result/canonical_root")? != created_root
            || required_string(&restored_receipt, "/result/canonical_root")? != created_root
            || verified
                .pointer("/result/repository_revision")
                .and_then(Value::as_u64)
                != Some(created_revision)
            || restored_receipt
                .pointer("/result/repository_revision")
                .and_then(Value::as_u64)
                != Some(created_revision)
            || created_revision == 0
            || created_schema != 4
            || restored_receipt
                .pointer("/result/restored")
                .and_then(Value::as_bool)
                != Some(true)
            || !restored.join("database.sqlite3").is_file()
        {
            return Err("signed backup verification or restore failed".into());
        }

        let backup_fingerprint = sqlite_backup_fingerprint(&backup.join("database.sqlite3"))?;
        let restored_fingerprint = sqlite_backup_fingerprint(&restored.join("database.sqlite3"))?;
        if live_fingerprint != backup_fingerprint
            || backup_fingerprint != restored_fingerprint
            || u64::try_from(restored_fingerprint.revision)? != created_revision
        {
            return Err("backup and restored SQLite semantics are not identical".into());
        }

        let backup_inventory = inventory_regular_files(&backup)?;
        let restored_inventory = inventory_regular_files(&restored)?;
        for signed_metadata in ["manifest.cbor", "manifest.signature.cbor"] {
            if !backup_inventory.contains_key(signed_metadata)
                || restored_inventory.get(signed_metadata) != backup_inventory.get(signed_metadata)
            {
                return Err("signed backup metadata is incomplete".into());
            }
        }
        let backup_checkpoint_digest = backup_inventory
            .get("effect-checkpoints.json")
            .map(|(_bytes, digest)| digest.as_str());
        if backup_inventory != restored_inventory
            || !backup_inventory.contains_key("database.sqlite3")
            || backup_checkpoint_digest != Some(live_checkpoint_digest.as_str())
            || digest_file(&restored.join("effect-checkpoints.json"), MAX_BINARY_BYTES)?
                != live_checkpoint_digest
        {
            return Err("restored file or checkpoint inventory differs from its source".into());
        }

        let tampered = fixture.root.join("tampered-backup");
        copy_regular_tree(&backup, &tampered)?;
        OpenOptions::new()
            .append(true)
            .open(tampered.join("database.sqlite3"))?
            .write_all(b"tamper")?;
        let tamper_result = fixture.embedded_output(
            cigar,
            &[
                OsStr::new("backup"),
                OsStr::new("verify"),
                tampered.as_os_str(),
            ],
        )?;
        if tamper_result.status.success() {
            return Err("tampered signed backup was accepted".into());
        }

        let occupied = fixture.root.join("occupied-restore-target");
        create_private_directory(&occupied)?;
        restricted_write(&occupied.join("retain"), b"do-not-replace\n")?;
        let occupied_before = inventory_regular_files(&occupied)?;
        let occupied_result = fixture.embedded_output(
            cigar,
            &[
                OsStr::new("backup"),
                OsStr::new("restore"),
                backup.as_os_str(),
                occupied.as_os_str(),
                OsStr::new("--yes"),
            ],
        )?;
        if occupied_result.status.success()
            || inventory_regular_files(&occupied)? != occupied_before
        {
            return Err("backup restore replaced a non-empty destination".into());
        }
        Ok(())
    }

    fn sqlite_backup_fingerprint(path: &Path) -> Result<SqliteBackupFingerprint> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(30))?;
        if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)? {
            return Err("SQLite defensive mode is unavailable".into());
        }
        connection.pragma_update(None, "query_only", true)?;
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err("backup SQLite integrity check failed".into());
        }
        let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
        if foreign_keys.query([])?.next()?.is_some() {
            return Err("backup SQLite foreign-key check failed".into());
        }

        let migrations = verify_exact_v4_migration_ledger(&connection)?;

        let (revision, semantic_root, catalog_root, atom_count, edge_count, referenced_blob_bytes) =
            connection.query_row(
                "SELECT revision, semantic_root, catalog_root, atom_count, edge_count,
                        referenced_blob_bytes
                 FROM cigar_repository_revisions_v4 ORDER BY revision DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )?;
        let legacy_rows: i64 =
            connection.query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| row.get(0))?;
        let authority: (i64, String, i64) = connection.query_row(
            "SELECT format_version, capacity_profile, activated
             FROM cigar_catalog_authority WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let actual_atoms: i64 =
            connection.query_row("SELECT COUNT(*) FROM cigar_catalog_atoms", [], |row| {
                row.get(0)
            })?;
        let actual_edges: i64 =
            connection.query_row("SELECT COUNT(*) FROM cigar_catalog_edges", [], |row| {
                row.get(0)
            })?;
        let open_lineages: i64 = connection.query_row(
            "SELECT COUNT(*) FROM cigar_catalog_lineage_heads WHERE valid_to_revision IS NULL",
            [],
            |row| row.get(0),
        )?;
        let bucket_totals: (i64, i64, i64) = connection.query_row(
            "SELECT COALESCE(SUM(atom_count), 0), COALESCE(SUM(edge_count), 0),
                    COALESCE(SUM(referenced_blob_bytes), 0)
             FROM cigar_catalog_root_buckets",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if revision <= 0
            || !valid_multihash(&semantic_root)
            || !valid_multihash(&catalog_root)
            || atom_count <= 0
            || edge_count < 0
            || referenced_blob_bytes < 0
            || legacy_rows != 0
            || authority != (4, "standard".to_owned(), 1)
            || actual_atoms != atom_count
            || actual_edges != edge_count
            || open_lineages <= 0
            || bucket_totals != (atom_count, edge_count, referenced_blob_bytes)
        {
            return Err("backup SQLite normalized authority is incomplete".into());
        }
        Ok(SqliteBackupFingerprint {
            migrations,
            revision,
            semantic_root,
            catalog_root,
            atom_count,
            edge_count,
            referenced_blob_bytes,
            open_lineages,
        })
    }

    fn valid_multihash(value: &str) -> bool {
        value.len() == 68
            && value.starts_with("1220")
            && value
                .bytes()
                .skip(4)
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn inventory_regular_files(root: &Path) -> Result<BTreeMap<String, (u64, String)>> {
        let mut inventory = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let path = entry?.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err("backup inventory contains a symbolic link".into());
                }
                if metadata.is_dir() {
                    pending.push(path);
                    continue;
                }
                if !metadata.is_file() || metadata.len() > MAX_BINARY_BYTES {
                    return Err("backup inventory contains an invalid file".into());
                }
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or("backup path is not UTF-8")?;
                if relative.is_empty()
                    || relative.split('/').any(|component| {
                        component.is_empty() || component == "." || component == ".."
                    })
                    || inventory.len() >= MAX_BACKUP_INVENTORY_FILES
                {
                    return Err("backup inventory path or count is invalid".into());
                }
                if inventory
                    .insert(
                        relative.to_owned(),
                        (metadata.len(), digest_file(&path, MAX_BINARY_BYTES)?),
                    )
                    .is_some()
                {
                    return Err("backup inventory contains a duplicate path".into());
                }
            }
        }
        Ok(inventory)
    }

    fn copy_regular_tree(source: &Path, destination: &Path) -> Result<()> {
        create_private_directory(destination)?;
        let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
        let mut files = 0_usize;
        while let Some((source_directory, destination_directory)) = pending.pop() {
            for entry in fs::read_dir(source_directory)? {
                let source_path = entry?.path();
                let metadata = fs::symlink_metadata(&source_path)?;
                let destination_path = destination_directory.join(
                    source_path
                        .file_name()
                        .ok_or("backup copy path has no file name")?,
                );
                if metadata.file_type().is_symlink() {
                    return Err("backup copy source contains a symbolic link".into());
                }
                if metadata.is_dir() {
                    create_private_directory(&destination_path)?;
                    pending.push((source_path, destination_path));
                } else if metadata.is_file()
                    && metadata.len() <= MAX_BINARY_BYTES
                    && files < MAX_BACKUP_INVENTORY_FILES
                {
                    fs::copy(&source_path, &destination_path)?;
                    fs::set_permissions(&destination_path, Permissions::from_mode(0o600))?;
                    files += 1;
                } else {
                    return Err("backup copy source is invalid".into());
                }
            }
        }
        Ok(())
    }

    fn qualify_daemon_lifecycle(cigar: &Path, cigard: &Path, fixture: &Fixture) -> Result<()> {
        for _attempt in 0..2 {
            let mut daemon = spawn_daemon(cigard, fixture)?;
            wait_for_socket(&mut daemon, &fixture.socket())?;
            let status = fixture.local(cigar, &[OsStr::new("status")])?;
            if !readiness_passed(&status) {
                return Err("local status did not reach installed daemon".into());
            }
            stop_daemon(daemon, &fixture.socket())?;
        }
        Ok(())
    }

    fn spawn_daemon(cigard: &Path, fixture: &Fixture) -> Result<DaemonChild> {
        if fixture.socket().exists() {
            return Err("stale daemon socket exists".into());
        }
        let (stdout, stdout_file) = create_capture(&fixture.root, "cigard-stdout")?;
        let (stderr, stderr_file) = create_capture(&fixture.root, "cigard-stderr")?;
        let mut command = sandboxed_candidate_command(cigard, &fixture.sandbox)?;
        configure_candidate_command(&mut command, cigard, &fixture.project, &fixture.root)?;
        command
            .args(["serve", "--config"])
            .arg(&fixture.daemon_config)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        let identity = executable_identity(cigard)?;
        Ok(DaemonChild {
            process: ProcessGuard::spawn(&mut command)?,
            binary: cigard.to_path_buf(),
            identity,
            stdout,
            stderr,
        })
    }

    fn wait_for_socket(daemon: &mut DaemonChild, socket: &Path) -> Result<()> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            validate_capture_size(&daemon.stdout)?;
            validate_capture_size(&daemon.stderr)?;
            if let Some(status) = daemon.process.try_wait()? {
                return Err(format!("daemon exited during startup: {status}").into());
            }
            if let Ok(metadata) = fs::symlink_metadata(socket)
                && metadata.file_type().is_socket()
                && metadata.mode() & 0o777 == 0o600
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("daemon startup timed out".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop_daemon(mut daemon: DaemonChild, socket: &Path) -> Result<()> {
        daemon.process.terminate()?;
        let status = wait_for_exit(
            &mut daemon.process,
            &daemon.stdout,
            &daemon.stderr,
            Duration::from_secs(45),
        )?;
        if executable_identity(&daemon.binary)? != daemon.identity {
            return Err("daemon executable identity changed".into());
        }
        let stdout = read_capture(&daemon.stdout)?;
        let stderr = read_capture(&daemon.stderr)?;
        fs::remove_file(daemon.stdout)?;
        fs::remove_file(daemon.stderr)?;
        if !status.success() || !stderr.is_empty() {
            return Err("daemon did not stop cleanly".into());
        }
        let receipt: Value = serde_json::from_slice(&stdout)?;
        if receipt.pointer("/status").and_then(Value::as_str) != Some("stopped") || socket.exists()
        {
            return Err("daemon shutdown receipt or socket cleanup is invalid".into());
        }
        Ok(())
    }

    fn qualify_local_contracts(
        cigar: &Path,
        root: &Path,
        runtime: &Path,
        sandbox: &CandidateSandbox,
    ) -> Result<()> {
        create_private_directory(root)?;
        for name in ["home", "tmp", "captures", "project"] {
            create_private_directory(&root.join(name))?;
        }
        restricted_write(&root.join("project/README.md"), b"local contract source\n")?;
        let state = root.join("installed state");
        validate_owner_directory(runtime)?;
        let socket = runtime.join("cigard.sock");
        let config = root.join("cli.toml");
        restricted_write(
            &config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"local\"\n",
                    "project_state_directory = {}\n",
                    "local_socket = {}\n"
                ),
                serde_json::to_string(&state.display().to_string())?,
                serde_json::to_string(&socket.display().to_string())?,
            )
            .as_bytes(),
        )?;
        let project = root.join("project");
        let init = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[OsStr::new("init"), OsStr::new("--yes")],
            "local",
            sandbox,
        )?;
        if init.pointer("/result/initialized").and_then(Value::as_bool) != Some(true)
            || fs::metadata(&state)?.mode() & 0o077 != 0
        {
            return Err("local init did not create private state".into());
        }
        let added = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[
                OsStr::new("source"),
                OsStr::new("add"),
                OsStr::new("qualification-source"),
                project.as_os_str(),
                OsStr::new("--yes"),
            ],
            "local",
            sandbox,
        )?;
        if added.pointer("/result/source_id").and_then(Value::as_str)
            != Some("qualification-source")
        {
            return Err("local source add did not persist".into());
        }
        let listed = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[OsStr::new("source"), OsStr::new("list")],
            "local",
            sandbox,
        )?;
        if listed
            .pointer("/result/sources/0/source_id")
            .and_then(Value::as_str)
            != Some("qualification-source")
        {
            return Err("local source list lost persisted state".into());
        }

        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, Permissions::from_mode(0o600))?;
        let replay_id = "01890f47-8e7d-7b42-a1d2-000000000701";
        let effect_id = "01890f47-8e7d-7b42-a1d2-000000000702";
        let handoff_id = "01890f47-8e7d-7b42-a1d2-000000000704";
        let replay_request = json!({
            "decision_id": format!("1220{:064x}", 700_u64),
            "mode": "evidence_reproduction",
            "simulate_effects": true
        });
        let replay_idempotency = "installed-replay-contract-v1";
        let effect_idempotency = "installed-effect-reconcile-contract-v1";
        let responses = vec![
            MockExchange {
                operation: "createReplay".to_owned(),
                method: "POST",
                path: "/v1/replays".to_owned(),
                request_body: Some(mock_request_body(
                    "createReplay",
                    &replay_request,
                    Some(replay_idempotency),
                    None,
                    Vec::new(),
                )?),
                idempotency_key: Some(replay_idempotency.to_owned()),
                expected_revision: None,
                response: json!({
                    "replay_id": replay_id,
                    "mode": "evidence_reproduction",
                    "status": "incomplete"
                }),
            },
            MockExchange {
                operation: "getReplayCompleteness".to_owned(),
                method: "GET",
                path: format!("/v1/replays/{replay_id}/completeness"),
                request_body: None,
                idempotency_key: None,
                expected_revision: None,
                response: json!({"available": [], "missing": ["source"]}),
            },
            MockExchange {
                operation: "reconcileEffect".to_owned(),
                method: "POST",
                path: format!("/v1/effects/{effect_id}:reconcile"),
                request_body: Some(mock_request_body(
                    "reconcileEffect",
                    &json!({"effect_id": effect_id}),
                    Some(effect_idempotency),
                    Some("4"),
                    vec![("effect_id", effect_id)],
                )?),
                idempotency_key: Some(effect_idempotency.to_owned()),
                expected_revision: Some("4".to_owned()),
                response: json!({
                    "effect_id": effect_id,
                    "state": "succeeded",
                    "effect_version": 5,
                    "intent_digest": format!("1220{:064x}", 703_u64),
                    "attempt_count": 1,
                    "reconciliation_count": 1
                }),
            },
            MockExchange {
                operation: "previewHandoff".to_owned(),
                method: "POST",
                path: format!("/v1/handoffs/{handoff_id}:preview"),
                request_body: Some(mock_request_body(
                    "previewHandoff",
                    &json!({"handoff_id": handoff_id}),
                    None,
                    None,
                    vec![("handoff_id", handoff_id)],
                )?),
                idempotency_key: None,
                expected_revision: None,
                response: json!({
                    "handoff_id": handoff_id,
                    "accepted_projects": [],
                    "rejected_projects": [],
                    "accepted_capabilities": [],
                    "rejected_capabilities": [],
                    "reference_count": 0
                }),
            },
        ];
        let server = std::thread::Builder::new()
            .name("cigar-installed-cli-contract-fixture".to_owned())
            .spawn(move || serve_contract_fixture(listener, responses))?;

        let replay_input = root.join("replay.json");
        restricted_write(&replay_input, &serde_json::to_vec(&replay_request)?)?;
        let replay = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[
                OsStr::new("replay"),
                OsStr::new("reconstruct"),
                OsStr::new("--yes"),
                OsStr::new("--idempotency-key"),
                OsStr::new(replay_idempotency),
                OsStr::new("--input"),
                replay_input.as_os_str(),
            ],
            "local",
            sandbox,
        )?;
        if replay.pointer("/result/replay_id").and_then(Value::as_str) != Some(replay_id) {
            return Err("replay reconstruction contract failed".into());
        }
        let completeness = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[
                OsStr::new("replay"),
                OsStr::new("completeness"),
                OsStr::new(replay_id),
            ],
            "local",
            sandbox,
        )?;
        if completeness
            .pointer("/result/missing/0")
            .and_then(Value::as_str)
            != Some("source")
        {
            return Err("replay completeness contract failed".into());
        }
        let effect = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[
                OsStr::new("effect"),
                OsStr::new("reconcile"),
                OsStr::new(effect_id),
                OsStr::new("--expected-revision"),
                OsStr::new("4"),
                OsStr::new("--idempotency-key"),
                OsStr::new(effect_idempotency),
                OsStr::new("--yes"),
            ],
            "local",
            sandbox,
        )?;
        if effect.pointer("/result/state").and_then(Value::as_str) != Some("succeeded") {
            return Err("effect recovery contract failed".into());
        }
        let handoff = candidate_json(
            cigar,
            &project,
            root,
            &config,
            &[
                OsStr::new("handoff"),
                OsStr::new("preview"),
                OsStr::new(handoff_id),
            ],
            "local",
            sandbox,
        )?;
        if handoff
            .pointer("/result/handoff_id")
            .and_then(Value::as_str)
            != Some(handoff_id)
        {
            return Err("handoff preview contract failed".into());
        }
        server
            .join()
            .map_err(|_panic| "local CLI contract fixture panicked")??;
        fs::remove_file(socket)?;
        Ok(())
    }

    fn mock_request_body(
        operation: &str,
        payload: &Value,
        idempotency_key: Option<&str>,
        expected_revision: Option<&str>,
        path_parameters: Vec<(&str, &str)>,
    ) -> Result<Value> {
        let normalized = serde_json::to_vec(payload)?;
        let node = cigar_canon::parse_strict_json(&normalized)?;
        let payload_cbor = cigar_canon::to_deterministic_cbor(&node)?;
        let mut body = serde_json::Map::from_iter([
            ("operation_id".to_owned(), json!(operation)),
            (
                "payload_cbor".to_owned(),
                json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_cbor)),
            ),
            ("dry_run".to_owned(), json!(false)),
            (
                "path_parameters".to_owned(),
                Value::Array(
                    path_parameters
                        .into_iter()
                        .map(|(name, value)| json!({"name": name, "value": value}))
                        .collect(),
                ),
            ),
        ]);
        if let Some(value) = idempotency_key {
            body.insert("idempotency_key".to_owned(), json!(value));
        }
        if let Some(value) = expected_revision {
            body.insert("expected_revision".to_owned(), json!(value));
        }
        Ok(Value::Object(body))
    }

    fn serve_contract_fixture(listener: UnixListener, responses: Vec<MockExchange>) -> Result<()> {
        for exchange in responses {
            let (mut stream, _address) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer)?;
                if count == 0 {
                    return Err("mock request ended before its headers".into());
                }
                let chunk = buffer.get(..count).ok_or("invalid mock request read")?;
                request.extend_from_slice(chunk);
                if request.len() > 64 * 1024 {
                    return Err("CLI contract request headers exceeded their bound".into());
                }
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .ok_or("CLI contract request has no header terminator")?;
            let header_bytes = request
                .get(..header_end)
                .ok_or("CLI contract request header split is invalid")?;
            let header_text = std::str::from_utf8(header_bytes)?;
            let header_text = header_text
                .strip_suffix("\r\n\r\n")
                .ok_or("CLI contract request headers are not canonical HTTP/1.1")?;
            let mut lines = header_text.split("\r\n");
            let request_line = lines
                .next()
                .ok_or("CLI contract request has no request line")?;
            if request_line != format!("{} {} HTTP/1.1", exchange.method, exchange.path) {
                return Err("CLI contract request method or target is wrong".into());
            }
            let mut headers = BTreeMap::new();
            for line in lines {
                let (name, value) = line
                    .split_once(':')
                    .ok_or("CLI contract request has a malformed header")?;
                let name = name.to_ascii_lowercase();
                let value = value.trim().to_owned();
                if name.is_empty() || value.is_empty() || headers.insert(name, value).is_some() {
                    return Err("CLI contract request has an invalid or duplicate header".into());
                }
            }
            if headers.get("host").map(String::as_str) != Some("localhost")
                || headers.get("x-cigar-operation-id").map(String::as_str)
                    != Some(exchange.operation.as_str())
                || headers.get("x-cigar-timeout-ms").map(String::as_str) != Some("30000")
                || headers.contains_key("authorization")
                || headers.contains_key("transfer-encoding")
                || headers.get("idempotency-key") != exchange.idempotency_key.as_ref()
                || headers.get("if-match") != exchange.expected_revision.as_ref()
            {
                return Err("CLI contract request headers are wrong".into());
            }
            let mut request_body = request
                .get(header_end..)
                .ok_or("CLI contract request body split is invalid")?
                .to_vec();
            match exchange.request_body {
                Some(expected_body) => {
                    if exchange.method != "POST"
                        || headers.get("content-type").map(String::as_str)
                            != Some("application/json")
                    {
                        return Err("CLI contract POST content type is wrong".into());
                    }
                    let content_length = headers
                        .get("content-length")
                        .ok_or("CLI contract POST has no content length")?
                        .parse::<usize>()?;
                    if content_length == 0
                        || content_length > 64 * 1024
                        || request_body.len() > content_length
                    {
                        return Err("CLI contract POST content length is invalid".into());
                    }
                    while request_body.len() < content_length {
                        let count = stream.read(&mut buffer)?;
                        if count == 0 {
                            return Err("CLI contract POST body ended early".into());
                        }
                        let remaining = content_length - request_body.len();
                        if count > remaining {
                            return Err("CLI contract POST body exceeds its length".into());
                        }
                        request_body.extend_from_slice(
                            buffer
                                .get(..count)
                                .ok_or("invalid CLI contract body read")?,
                        );
                    }
                    cigar_canon::parse_strict_json(&request_body)?;
                    let observed_body: Value = serde_json::from_slice(&request_body)?;
                    if observed_body != expected_body {
                        return Err("CLI contract POST body is wrong".into());
                    }
                }
                None => {
                    if exchange.method != "GET"
                        || !request_body.is_empty()
                        || headers
                            .get("content-length")
                            .is_some_and(|value| value != "0")
                        || headers.contains_key("content-type")
                    {
                        return Err("CLI contract GET unexpectedly has a body".into());
                    }
                }
            }
            let normalized = serde_json::to_vec(&exchange.response)?;
            let node = cigar_canon::parse_strict_json(&normalized)?;
            let payload = cigar_canon::to_deterministic_cbor(&node)?;
            let body = serde_json::to_vec(&json!({
                "operation_id": exchange.operation,
                "payload_cbor": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
            }))?;
            write!(
                stream,
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "content-type: application/json\r\n",
                    "content-length: {}\r\n",
                    "connection: close\r\n\r\n"
                ),
                body.len()
            )?;
            stream.write_all(&body)?;
            stream.flush()?;
        }
        Ok(())
    }

    fn qualify_upgrade(
        cigar: &Path,
        cigard: &Path,
        root: &Path,
        runtime: &Path,
        sandbox: CandidateSandbox,
    ) -> Result<()> {
        let fixture = Fixture::new(root, runtime, true, sandbox)?;
        let database = fixture.state.join("cigar.sqlite3");
        let retained = prepare_retained_v1_fixture()?;
        verify_legacy_v1_database(&database, &retained)?;
        let backup = root.join("pre-upgrade-v1.sqlite3");
        fs::copy(&database, &backup)?;
        fs::set_permissions(&backup, Permissions::from_mode(0o600))?;
        let backup_digest = digest_file(&backup, MAX_BINARY_BYTES)?;
        verify_legacy_v1_database(&backup, &retained)?;

        let mut daemon = spawn_daemon(cigard, &fixture)?;
        wait_for_socket(&mut daemon, &fixture.socket())?;
        let status = fixture.local(cigar, &[OsStr::new("status")])?;
        if !readiness_passed(&status) {
            return Err("upgraded daemon did not serve status".into());
        }
        stop_daemon(daemon, &fixture.socket())?;
        verify_upgraded_database(&database, &retained)?;
        qualification_phase(24);
        if digest_file(&backup, MAX_BINARY_BYTES)? != backup_digest {
            return Err("pre-upgrade backup changed".into());
        }
        verify_legacy_v1_database(&backup, &retained)?;
        Ok(())
    }

    fn create_legacy_v1_database(path: &Path) -> Result<()> {
        let retained = prepare_retained_v1_fixture()?;
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?,
        );
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(30))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA cache_size = -32768;
             PRAGMA wal_autocheckpoint = 1000;
             PRAGMA temp_store = MEMORY;
             PRAGMA trusted_schema = OFF;
             PRAGMA secure_delete = ON;",
        )?;
        if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)? {
            return Err("SQLite defensive mode is unavailable".into());
        }
        connection.execute_batch(INITIAL_MIGRATION)?;
        connection.execute(
            concat!(
                "INSERT INTO schema_migrations ",
                "(sequence, name, checksum, applied_at_unix_nanos) ",
                "VALUES (1, 'initial', ?1, '1700000000000000000')"
            ),
            params![multihash(INITIAL_MIGRATION.as_bytes())],
        )?;
        connection.execute(
            "INSERT INTO state_snapshots (revision, state, checksum) VALUES (?1, ?2, ?3)",
            params![
                i64::try_from(retained.revision.0)?,
                &retained.state,
                &retained.semantic_root
            ],
        )?;
        let checkpoint: (i64, i64, i64) =
            connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        if checkpoint.0 != 0 {
            return Err("retained v1 fixture WAL checkpoint was busy".into());
        }
        drop(connection);
        secure_sqlite_family(path)?;
        verify_legacy_v1_database(path, &retained)?;
        Ok(())
    }

    fn verify_upgraded_database(path: &Path, retained: &PreparedRetainedV1Fixture) -> Result<()> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(30))?;
        if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)? {
            return Err("SQLite defensive mode is unavailable".into());
        }
        connection.pragma_update(None, "query_only", true)?;
        qualification_phase(20);
        verify_sqlite_integrity(&connection, "upgraded")?;
        qualification_phase(21);
        verify_exact_v4_migration_ledger(&connection)?;
        qualification_phase(22);
        verify_exact_normalized_catalog(&connection, retained)?;
        qualification_phase(23);
        verify_exact_atom_projection(&connection, retained)?;
        Ok(())
    }

    fn prepare_retained_v1_fixture() -> Result<PreparedRetainedV1Fixture> {
        let source_sha256 = hex_bytes(&Sha256::digest(RETAINED_V1_FIXTURE.as_bytes()));
        if source_sha256 != RETAINED_V1_FIXTURE_SHA256 {
            return Err("retained v1 fixture source digest is not the committed digest".into());
        }
        cigar_canon::parse_strict_json(RETAINED_V1_FIXTURE.as_bytes())?;
        let source: RetainedV1Fixture = serde_json::from_str(RETAINED_V1_FIXTURE)?;
        let RetainedV1Fixture {
            schema_version,
            revision,
            tenant_id,
            lineage_head_version_id,
            atoms: source_atoms,
            edges: source_edges,
            expected: pins,
        } = source;
        if schema_version != "cigar.sqlite-retained-v1-fixture.v1"
            || revision == 0
            || source_atoms.len() < 2
            || source_edges.is_empty()
            || source_atoms.windows(2).any(|pair| {
                pair.first().zip(pair.get(1)).is_none_or(|(left, right)| {
                    left.version_id.as_str() >= right.version_id.as_str()
                })
            })
            || source_edges.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_none_or(|(left, right)| left.edge_id.as_str() >= right.edge_id.as_str())
            })
        {
            return Err("retained v1 fixture shape is not exact and non-empty".into());
        }
        for root in [
            pins.semantic_root.as_str(),
            pins.residual_checksum.as_str(),
            pins.catalog_root.as_str(),
        ] {
            if !valid_multihash(root) {
                return Err("retained v1 fixture contains an invalid pinned root".into());
            }
        }

        let mut atom_map = BTreeMap::new();
        for atom in &source_atoms {
            atom.validate()?;
            if atom.scope.tenant_id != tenant_id {
                return Err("retained v1 atom escaped its fixture tenant".into());
            }
            if atom_map
                .insert(atom.version_id.clone(), atom.clone())
                .is_some()
            {
                return Err("retained v1 fixture repeats an atom version".into());
            }
        }
        let mut edge_map = BTreeMap::new();
        for edge in &source_edges {
            edge.validate()?;
            if !atom_map.contains_key(&edge.from_version)
                || !atom_map.contains_key(&edge.to_version)
                || edge_map
                    .insert(edge.edge_id.clone(), edge.clone())
                    .is_some()
            {
                return Err("retained v1 fixture edge graph is not closed and unique".into());
            }
        }
        if !source_atoms
            .iter()
            .any(|atom| matches!(&atom.payload, AtomPayload::Blob(blob) if blob.size_bytes > 0))
        {
            return Err("retained v1 fixture lacks a referenced blob".into());
        }

        let mut current_lineages = BTreeMap::<String, (UtcTimestamp, String)>::new();
        for atom in &source_atoms {
            let candidate = (
                atom.temporal.observed_at,
                atom.version_id.as_str().to_owned(),
            );
            let lineage = atom.lineage_id.as_str().to_owned();
            if current_lineages
                .get(&lineage)
                .is_none_or(|current| candidate > *current)
            {
                current_lineages.insert(lineage, candidate);
            }
        }
        let lineage_heads = current_lineages
            .into_iter()
            .map(|(lineage, (_observed_at, version))| (lineage, version))
            .collect::<BTreeMap<_, _>>();
        if lineage_heads.is_empty()
            || !lineage_heads
                .values()
                .any(|version| version == lineage_head_version_id.as_str())
        {
            return Err("retained v1 fixture lineage-head declaration is wrong".into());
        }

        let revision = cigar_store::StoreRevision(revision);
        let legacy_state = LegacyCommittedStateV1 {
            revision,
            tenants: BTreeMap::from([(
                tenant_id.clone(),
                LegacyTenantStateV1 {
                    atoms: atom_map,
                    edges: edge_map,
                    bundles: BTreeMap::new(),
                    snapshots: BTreeMap::new(),
                    context_commits: BTreeMap::new(),
                    effects: BTreeMap::new(),
                    blobs: BTreeMap::new(),
                    outbox: Vec::new(),
                    idempotency: BTreeMap::new(),
                },
            )]),
        };
        let state = encode_fixture_cbor(&legacy_state)?;
        let semantic_root = multihash(&state);

        let residual = CatalogFreeStateV4Fixture {
            format_version: 4,
            revision,
            tenants: BTreeMap::from([(
                tenant_id.clone(),
                CatalogFreeTenantStateV4Fixture {
                    bundles: BTreeMap::new(),
                    snapshots: BTreeMap::new(),
                    context_commits: BTreeMap::new(),
                    effects: BTreeMap::new(),
                    effect_records: BTreeMap::new(),
                    blobs: BTreeMap::new(),
                    outbox: Vec::new(),
                    idempotency: BTreeMap::new(),
                    service_records: BTreeMap::new(),
                    service_idempotency: BTreeMap::new(),
                    worker_states: BTreeMap::new(),
                },
            )]),
        };
        let residual_state = encode_fixture_cbor(&residual)?;
        let residual_checksum = multihash(&residual_state);

        let mut atoms = Vec::with_capacity(source_atoms.len());
        let mut referenced_blob_bytes = 0_u64;
        for atom in source_atoms {
            let record = encode_fixture_cbor(&atom)?;
            let record_checksum = multihash(&record);
            let exact_text = catalog_exact_text_fixture(&atom).to_owned();
            let referenced = atom_referenced_blob_bytes_fixture(&atom);
            referenced_blob_bytes = referenced_blob_bytes
                .checked_add(referenced)
                .ok_or("retained v1 referenced byte total overflowed")?;
            let root_bucket = catalog_root_bucket_fixture(
                b"CIGAR-CATALOG-ATOM-BUCKET-v1",
                tenant_id.as_str(),
                atom.version_id.as_str(),
            );
            atoms.push(ExpectedCatalogAtom {
                atom,
                record,
                record_checksum,
                exact_text,
                referenced_blob_bytes: referenced,
                root_bucket,
            });
        }
        let mut edges = Vec::with_capacity(source_edges.len());
        for edge in source_edges {
            let record = encode_fixture_cbor(&edge)?;
            let record_checksum = multihash(&record);
            let root_bucket = catalog_root_bucket_fixture(
                b"CIGAR-CATALOG-EDGE-BUCKET-v1",
                tenant_id.as_str(),
                edge.edge_id.as_str(),
            );
            edges.push(ExpectedCatalogEdge {
                edge,
                record,
                record_checksum,
                root_bucket,
            });
        }
        let buckets = expected_catalog_buckets(&tenant_id, &atoms, &edges)?;
        let catalog_root = expected_catalog_root(&buckets)?;

        let atom_record_checksums = atoms
            .iter()
            .map(|row| {
                (
                    row.atom.version_id.as_str().to_owned(),
                    row.record_checksum.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let edge_record_checksums = edges
            .iter()
            .map(|row| {
                (
                    row.edge.edge_id.as_str().to_owned(),
                    row.record_checksum.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if pins.semantic_root != semantic_root
            || pins.residual_checksum != residual_checksum
            || pins.catalog_root != catalog_root
            || usize::try_from(pins.atom_count).ok() != Some(atoms.len())
            || usize::try_from(pins.edge_count).ok() != Some(edges.len())
            || usize::try_from(pins.open_lineage_count).ok() != Some(lineage_heads.len())
            || pins.referenced_blob_bytes != referenced_blob_bytes
            || usize::try_from(pins.root_bucket_count).ok() != Some(buckets.len())
            || pins.atom_record_checksums != atom_record_checksums
            || pins.edge_record_checksums != edge_record_checksums
        {
            return Err(format!(
                concat!(
                    "retained v1 fixture pins differ from their source: ",
                    "semantic_root={}, residual_checksum={}, catalog_root={}, ",
                    "atom_record_checksums={:?}, edge_record_checksums={:?}, ",
                    "root_bucket_count={}"
                ),
                semantic_root,
                residual_checksum,
                catalog_root,
                atom_record_checksums,
                edge_record_checksums,
                buckets.len()
            )
            .into());
        }

        Ok(PreparedRetainedV1Fixture {
            revision,
            tenant_id,
            lineage_head_version_id,
            state,
            semantic_root,
            residual_state,
            residual_checksum,
            catalog_root,
            atoms,
            edges,
            lineage_heads,
            buckets,
            referenced_blob_bytes,
        })
    }

    fn encode_fixture_cbor(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(value, &mut encoded)?;
        Ok(encoded)
    }

    fn expected_catalog_buckets(
        tenant_id: &RecordId,
        atoms: &[ExpectedCatalogAtom],
        edges: &[ExpectedCatalogEdge],
    ) -> Result<BTreeMap<u16, ExpectedCatalogBucket>> {
        let mut membership = BTreeMap::<u16, (Vec<usize>, Vec<usize>)>::new();
        for (index, atom) in atoms.iter().enumerate() {
            membership
                .entry(atom.root_bucket)
                .or_default()
                .0
                .push(index);
        }
        for (index, edge) in edges.iter().enumerate() {
            membership
                .entry(edge.root_bucket)
                .or_default()
                .1
                .push(index);
        }
        let mut buckets = BTreeMap::new();
        for (bucket, (atom_indexes, edge_indexes)) in membership {
            let mut atom_root = catalog_hash_fixture(b"CIGAR-CATALOG-ATOM-ROOT-v1");
            let mut edge_root = catalog_hash_fixture(b"CIGAR-CATALOG-EDGE-ROOT-v1");
            let mut referenced_blob_bytes = 0_u64;
            for index in &atom_indexes {
                let row = atoms
                    .get(*index)
                    .ok_or("invalid fixture atom bucket index")?;
                catalog_hash_field_fixture(&mut atom_root, tenant_id.as_str().as_bytes())?;
                catalog_hash_field_fixture(
                    &mut atom_root,
                    row.atom.version_id.as_str().as_bytes(),
                )?;
                catalog_hash_field_fixture(&mut atom_root, row.record_checksum.as_bytes())?;
                referenced_blob_bytes = referenced_blob_bytes
                    .checked_add(row.referenced_blob_bytes)
                    .ok_or("retained v1 bucket byte total overflowed")?;
            }
            for index in &edge_indexes {
                let row = edges
                    .get(*index)
                    .ok_or("invalid fixture edge bucket index")?;
                catalog_hash_field_fixture(&mut edge_root, tenant_id.as_str().as_bytes())?;
                catalog_hash_field_fixture(&mut edge_root, row.edge.edge_id.as_str().as_bytes())?;
                catalog_hash_field_fixture(&mut edge_root, row.record_checksum.as_bytes())?;
            }
            buckets.insert(
                bucket,
                ExpectedCatalogBucket {
                    atom_count: u64::try_from(atom_indexes.len())?,
                    edge_count: u64::try_from(edge_indexes.len())?,
                    referenced_blob_bytes,
                    atom_root: finish_hash_fixture(atom_root),
                    edge_root: finish_hash_fixture(edge_root),
                },
            );
        }
        Ok(buckets)
    }

    fn expected_catalog_root(buckets: &BTreeMap<u16, ExpectedCatalogBucket>) -> Result<String> {
        let mut root = catalog_hash_fixture(b"CIGAR-CATALOG-ROOT-v4");
        for (bucket, state) in buckets {
            root.update(bucket.to_be_bytes());
            root.update(state.atom_count.to_be_bytes());
            root.update(state.edge_count.to_be_bytes());
            root.update(state.referenced_blob_bytes.to_be_bytes());
            catalog_hash_field_fixture(&mut root, state.atom_root.as_bytes())?;
            catalog_hash_field_fixture(&mut root, state.edge_root.as_bytes())?;
        }
        Ok(finish_hash_fixture(root))
    }

    fn expected_normalized_semantic_root_fixture(
        revision: u64,
        residual_checksum: &str,
        catalog_root: &str,
        atom_count: u64,
        edge_count: u64,
        referenced_blob_bytes: u64,
    ) -> Result<String> {
        let mut root = catalog_hash_fixture(b"CIGAR-SQLITE-SEMANTIC-ROOT-v4");
        root.update(revision.to_be_bytes());
        catalog_hash_field_fixture(&mut root, residual_checksum.as_bytes())?;
        catalog_hash_field_fixture(&mut root, catalog_root.as_bytes())?;
        root.update(atom_count.to_be_bytes());
        root.update(edge_count.to_be_bytes());
        root.update(referenced_blob_bytes.to_be_bytes());
        Ok(finish_hash_fixture(root))
    }

    fn catalog_root_bucket_fixture(domain: &[u8], tenant: &str, identifier: &str) -> u16 {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(tenant.len().to_be_bytes());
        hash.update(tenant.as_bytes());
        hash.update(identifier.len().to_be_bytes());
        hash.update(identifier.as_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        u16::from_be_bytes([digest[0], digest[1]])
    }

    fn catalog_hash_fixture(domain: &[u8]) -> Sha256 {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash
    }

    fn catalog_hash_field_fixture(hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
        hash.update(u64::try_from(bytes.len())?.to_be_bytes());
        hash.update(bytes);
        Ok(())
    }

    fn finish_hash_fixture(hash: Sha256) -> String {
        format!("1220{}", hex_bytes(&hash.finalize()))
    }

    fn catalog_exact_text_fixture(atom: &ContextAtomV1) -> &str {
        match &atom.payload {
            AtomPayload::InlineText(text) => text,
            AtomPayload::Structured(_) | AtomPayload::Blob(_) => "",
        }
    }

    const fn atom_referenced_blob_bytes_fixture(atom: &ContextAtomV1) -> u64 {
        match &atom.payload {
            AtomPayload::Blob(reference) => reference.size_bytes,
            AtomPayload::InlineText(_) | AtomPayload::Structured(_) => 0,
        }
    }

    const fn lifecycle_name_fixture(lifecycle: Lifecycle) -> &'static str {
        match lifecycle {
            Lifecycle::Active => "active",
            Lifecycle::Superseded => "superseded",
            Lifecycle::Tombstoned => "tombstoned",
            Lifecycle::Quarantined => "quarantined",
        }
    }

    const fn atom_kind_name_fixture(kind: AtomKind) -> &'static str {
        match kind {
            AtomKind::Instruction => "instruction",
            AtomKind::SourceCode => "source_code",
            AtomKind::Documentation => "documentation",
            AtomKind::Decision => "decision",
            AtomKind::Conversation => "conversation",
            AtomKind::ToolResult => "tool_result",
            AtomKind::Schema => "schema",
            AtomKind::Policy => "policy",
            AtomKind::Test => "test",
            AtomKind::Artifact => "artifact",
        }
    }

    const fn edge_kind_name_fixture(kind: EdgeKind) -> &'static str {
        match kind {
            EdgeKind::DependsOn => "depends_on",
            EdgeKind::Defines => "defines",
            EdgeKind::References => "references",
            EdgeKind::Supersedes => "supersedes",
            EdgeKind::Contradicts => "contradicts",
            EdgeKind::Supports => "supports",
            EdgeKind::DerivedFrom => "derived_from",
            EdgeKind::AppliesTo => "applies_to",
        }
    }

    fn verify_sqlite_integrity(connection: &Connection, label: &str) -> Result<()> {
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(format!("{label} SQLite integrity check failed").into());
        }
        let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
        if foreign_keys.query([])?.next()?.is_some() {
            return Err(format!("{label} SQLite foreign-key check failed").into());
        }
        Ok(())
    }

    fn verify_legacy_v1_database(path: &Path, retained: &PreparedRetainedV1Fixture) -> Result<()> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(30))?;
        if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)? {
            return Err("SQLite defensive mode is unavailable".into());
        }
        connection.pragma_update(None, "query_only", true)?;
        verify_sqlite_integrity(&connection, "retained v1")?;
        let columns = {
            let mut statement = connection.prepare("PRAGMA table_info(schema_migrations)")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if columns != ["sequence", "name", "checksum", "applied_at_unix_nanos"] {
            return Err("retained fixture is not an exact v1 migration ledger".into());
        }
        let ledger = {
            let mut statement = connection.prepare(
                "SELECT sequence, name, checksum, applied_at_unix_nanos
                 FROM schema_migrations ORDER BY sequence",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if ledger
            != [(
                1,
                "initial".to_owned(),
                multihash(INITIAL_MIGRATION.as_bytes()),
                "1700000000000000000".to_owned(),
            )]
        {
            return Err("retained fixture v1 migration row is not exact".into());
        }
        let snapshots = {
            let mut statement = connection.prepare(
                "SELECT revision, state, checksum FROM state_snapshots ORDER BY revision",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let expected_revision = i64::try_from(retained.revision.0)?;
        if snapshots.len() != 1
            || snapshots.first().is_none_or(|row| {
                row.0 != expected_revision
                    || row.1 != retained.state
                    || row.2 != retained.semantic_root
                    || multihash(&row.1) != retained.semantic_root
            })
        {
            return Err("retained v1 semantic root is not independently reproducible".into());
        }
        let v4_tables: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name LIKE 'cigar_catalog_%'",
            [],
            |row| row.get(0),
        )?;
        if v4_tables != 0 {
            return Err("retained v1 fixture already contains normalized catalog tables".into());
        }
        Ok(())
    }

    fn expected_v4_migration_ledger() -> Vec<ExpectedMigrationLedgerRow> {
        [
            ("initial", INITIAL_MIGRATION, 1, 1, 0),
            (
                "compatibility_ledger",
                COMPATIBILITY_LEDGER_MIGRATION,
                1,
                2,
                1,
            ),
            (
                "generation_bound_atom_projection",
                GENERATION_BOUND_ATOM_PROJECTION_MIGRATION,
                1,
                1,
                0,
            ),
            (
                "normalized_authoritative_catalog",
                NORMALIZED_AUTHORITATIVE_CATALOG_MIGRATION,
                1,
                1,
                0,
            ),
        ]
        .into_iter()
        .enumerate()
        .map(
            |(offset, (name, sql, minimum, maximum, online))| ExpectedMigrationLedgerRow {
                sequence: i64::try_from(offset + 1).unwrap_or_default(),
                name,
                checksum: multihash(sql.as_bytes()),
                minimum_application_major: minimum,
                maximum_application_major: maximum,
                online,
            },
        )
        .collect()
    }

    fn verify_exact_v4_migration_ledger(
        connection: &Connection,
    ) -> Result<Vec<(i64, String, String)>> {
        let rows = {
            let mut statement = connection.prepare(
                "SELECT sequence, name, checksum, applied_at_unix_nanos,
                        minimum_application_major, maximum_application_major, online
                 FROM schema_migrations ORDER BY sequence",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let expected = expected_v4_migration_ledger();
        if rows.len() != expected.len()
            || rows.iter().zip(&expected).any(|(actual, expected)| {
                actual.0 != expected.sequence
                    || actual.1 != expected.name
                    || actual.2 != expected.checksum
                    || actual.4 != expected.minimum_application_major
                    || actual.5 != expected.maximum_application_major
                    || actual.6 != expected.online
                    || actual.3.is_empty()
                    || !actual.3.bytes().all(|byte| byte.is_ascii_digit())
                    || actual.3.parse::<u128>().ok().is_none_or(|value| value == 0)
            })
        {
            return Err("installed daemon migration ledger is not byte-source exact".into());
        }
        Ok(rows.into_iter().map(|row| (row.0, row.1, row.2)).collect())
    }

    fn verify_exact_normalized_catalog(
        connection: &Connection,
        retained: &PreparedRetainedV1Fixture,
    ) -> Result<()> {
        qualification_phase(30);
        let authority = {
            let mut statement = connection.prepare(
                "SELECT singleton, format_version, capacity_profile, activated
                 FROM cigar_catalog_authority ORDER BY singleton",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if authority != [(1, 4, "standard".to_owned(), 1)] {
            return Err("normalized catalog authority row is not exact".into());
        }

        qualification_phase(31);
        let revisions = {
            let mut statement = connection.prepare(
                "SELECT revision, residual_state, residual_checksum, catalog_root,
                        semantic_root, semantic_root_format, atom_count, edge_count,
                        referenced_blob_bytes
                 FROM cigar_repository_revisions_v4 ORDER BY revision",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let expected_revision = i64::try_from(retained.revision.0)?;
        if revisions.is_empty()
            || revisions.len() > 4_096
            || revisions.first().is_none_or(|row| {
                row.0 != expected_revision
                    || row.1.as_slice() != retained.residual_state.as_slice()
                    || row.2 != retained.residual_checksum
                    || multihash(&row.1) != retained.residual_checksum
                    || row.3 != retained.catalog_root
                    || row.4 != retained.semantic_root
                    || row.5 != 1
                    || usize::try_from(row.6).ok() != Some(retained.atoms.len())
                    || usize::try_from(row.7).ok() != Some(retained.edges.len())
                    || u64::try_from(row.8).ok() != Some(retained.referenced_blob_bytes)
            })
        {
            return Err("normalized revision did not preserve the exact retained semantics".into());
        }
        let mut previous_revision = expected_revision;
        for row in revisions.iter().skip(1) {
            let revision = u64::try_from(row.0)?;
            let atom_count = u64::try_from(row.6)?;
            let edge_count = u64::try_from(row.7)?;
            let referenced_blob_bytes = u64::try_from(row.8)?;
            if row.0
                != previous_revision
                    .checked_add(1)
                    .ok_or("revision overflow")?
                || row.2 != multihash(&row.1)
                || row.3 != retained.catalog_root
                || row.5 != 4
                || usize::try_from(atom_count).ok() != Some(retained.atoms.len())
                || usize::try_from(edge_count).ok() != Some(retained.edges.len())
                || referenced_blob_bytes != retained.referenced_blob_bytes
                || row.4
                    != expected_normalized_semantic_root_fixture(
                        revision,
                        &row.2,
                        &row.3,
                        atom_count,
                        edge_count,
                        referenced_blob_bytes,
                    )?
            {
                return Err(
                    "post-upgrade operational revision changed retained catalog semantics".into(),
                );
            }
            previous_revision = row.0;
        }

        qualification_phase(32);
        let legacy_snapshots: i64 =
            connection.query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| row.get(0))?;
        let legacy_catalog_rows: i64 = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM atoms) +
                    (SELECT COUNT(*) FROM atom_lineages) +
                    (SELECT COUNT(*) FROM edges)",
            [],
            |row| row.get(0),
        )?;
        if legacy_snapshots != 0 || legacy_catalog_rows != 0 {
            return Err("normalized activation retained legacy whole-state catalog rows".into());
        }

        qualification_phase(33);
        let mut atom_statement = connection.prepare(
            "SELECT tenant_id, version_id, atom_id, lineage_id, kind, lifecycle,
                    observed_at_unix_nanos, exact_text, referenced_blob_bytes,
                    root_bucket, published_revision, record, record_checksum
             FROM cigar_catalog_atoms ORDER BY tenant_id, version_id",
        )?;
        let mut atom_rows = atom_statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, String>(12)?,
            ))
        })?;
        for expected in &retained.atoms {
            let actual = atom_rows
                .next()
                .ok_or("normalized catalog omitted a retained atom")??;
            if actual.0 != retained.tenant_id.as_str()
                || actual.1 != expected.atom.version_id.as_str()
                || actual.2 != expected.atom.atom_id.as_str()
                || actual.3 != expected.atom.lineage_id.as_str()
                || actual.4 != atom_kind_name_fixture(expected.atom.kind)
                || actual.5 != lifecycle_name_fixture(expected.atom.lifecycle)
                || actual.6 != expected.atom.temporal.observed_at.unix_nanos().to_string()
                || actual.7 != expected.exact_text
                || u64::try_from(actual.8).ok() != Some(expected.referenced_blob_bytes)
                || actual.9 != i64::from(expected.root_bucket)
                || actual.10 != expected_revision
                || actual.11 != expected.record
                || actual.12 != expected.record_checksum
                || multihash(&actual.11) != expected.record_checksum
            {
                return Err("normalized catalog atom row differs from its retained record".into());
            }
        }
        if atom_rows.next().is_some() {
            return Err("normalized catalog contains an unexpected atom row".into());
        }

        qualification_phase(34);
        let mut edge_statement = connection.prepare(
            "SELECT tenant_id, edge_id, from_version, to_version, kind, lifecycle,
                    root_bucket, published_revision, record, record_checksum
             FROM cigar_catalog_edges ORDER BY tenant_id, edge_id",
        )?;
        let mut edge_rows = edge_statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;
        for expected in &retained.edges {
            let actual = edge_rows
                .next()
                .ok_or("normalized catalog omitted a retained edge")??;
            if actual.0 != retained.tenant_id.as_str()
                || actual.1 != expected.edge.edge_id.as_str()
                || actual.2 != expected.edge.from_version.as_str()
                || actual.3 != expected.edge.to_version.as_str()
                || actual.4 != edge_kind_name_fixture(expected.edge.kind)
                || actual.5 != lifecycle_name_fixture(expected.edge.lifecycle)
                || actual.6 != i64::from(expected.root_bucket)
                || actual.7 != expected_revision
                || actual.8 != expected.record
                || actual.9 != expected.record_checksum
                || multihash(&actual.8) != expected.record_checksum
            {
                return Err("normalized catalog edge row differs from its retained record".into());
            }
        }
        if edge_rows.next().is_some() {
            return Err("normalized catalog contains an unexpected edge row".into());
        }

        qualification_phase(35);
        let lineage_rows = {
            let mut statement = connection.prepare(
                "SELECT tenant_id, lineage_id, valid_from_revision, valid_to_revision, version_id
                 FROM cigar_catalog_lineage_heads
                 ORDER BY tenant_id, lineage_id, valid_from_revision",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if lineage_rows.len() != retained.lineage_heads.len()
            || lineage_rows.iter().zip(&retained.lineage_heads).any(
                |(actual, (lineage, version))| {
                    actual.0 != retained.tenant_id.as_str()
                        || actual.1 != *lineage
                        || actual.2 != expected_revision
                        || actual.3.is_some()
                        || actual.4 != *version
                },
            )
            || !lineage_rows
                .iter()
                .any(|row| row.4 == retained.lineage_head_version_id.as_str())
        {
            return Err("normalized catalog lineage heads are not exact".into());
        }

        qualification_phase(36);
        let bucket_rows = {
            let mut statement = connection.prepare(
                "SELECT root_bucket, atom_count, edge_count, referenced_blob_bytes,
                        atom_root, edge_root
                 FROM cigar_catalog_root_buckets ORDER BY root_bucket",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if bucket_rows.len() != retained.buckets.len()
            || bucket_rows
                .iter()
                .zip(&retained.buckets)
                .any(|(actual, (bucket, expected))| {
                    actual.0 != i64::from(*bucket)
                        || u64::try_from(actual.1).ok() != Some(expected.atom_count)
                        || u64::try_from(actual.2).ok() != Some(expected.edge_count)
                        || u64::try_from(actual.3).ok() != Some(expected.referenced_blob_bytes)
                        || actual.4 != expected.atom_root
                        || actual.5 != expected.edge_root
                })
        {
            return Err("normalized catalog root-bucket rows are not exact".into());
        }
        let bucket_totals = bucket_rows.iter().try_fold(
            (0_u64, 0_u64, 0_u64),
            |(atoms, edges, bytes), row| -> Result<_> {
                Ok((
                    atoms
                        .checked_add(u64::try_from(row.1)?)
                        .ok_or("bucket atom total overflowed")?,
                    edges
                        .checked_add(u64::try_from(row.2)?)
                        .ok_or("bucket edge total overflowed")?,
                    bytes
                        .checked_add(u64::try_from(row.3)?)
                        .ok_or("bucket byte total overflowed")?,
                ))
            },
        )?;
        if bucket_totals
            != (
                u64::try_from(retained.atoms.len())?,
                u64::try_from(retained.edges.len())?,
                retained.referenced_blob_bytes,
            )
            || expected_catalog_root(&retained.buckets)? != retained.catalog_root
        {
            return Err("normalized catalog bucket totals or root are wrong".into());
        }
        Ok(())
    }

    fn verify_exact_atom_projection(
        connection: &Connection,
        retained: &PreparedRetainedV1Fixture,
    ) -> Result<()> {
        let generation_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM atom_projection_generations",
            [],
            |row| row.get(0),
        )?;
        let activation_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM atom_projection_activation",
            [],
            |row| row.get(0),
        )?;
        let activation = connection.query_row(
            "SELECT a.generation, a.source_revision, a.state_checksum,
                    g.atom_count, g.projection_root, g.complete,
                    g.source_revision, g.state_checksum
             FROM atom_projection_activation AS a
             JOIN atom_projection_generations AS g ON g.generation = a.generation
             WHERE a.singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )?;
        let expected_revision = i64::try_from(retained.revision.0)?;
        let expected_projection_root = expected_projection_root(retained, 1)?;
        if generation_count != 1
            || activation_count != 1
            || activation.0 != 1
            || activation.1 != expected_revision
            || activation.2 != retained.catalog_root
            || usize::try_from(activation.3).ok() != Some(retained.atoms.len())
            || activation.4 != expected_projection_root
            || activation.5 != 1
            || activation.6 != expected_revision
            || activation.7 != retained.catalog_root
        {
            return Err("atom projection activation is not exactly fixture-bound".into());
        }

        let mut row_statement = connection.prepare(
            "SELECT generation, tenant_id, version_id, lineage_id, lifecycle,
                    exact_text, record, record_checksum
             FROM atom_projection_rows ORDER BY generation, tenant_id, version_id",
        )?;
        let mut rows = row_statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        for expected in &retained.atoms {
            let actual = rows
                .next()
                .ok_or("atom projection omitted a retained atom")??;
            if actual.0 != 1
                || actual.1 != retained.tenant_id.as_str()
                || actual.2 != expected.atom.version_id.as_str()
                || actual.3 != expected.atom.lineage_id.as_str()
                || actual.4 != lifecycle_name_fixture(expected.atom.lifecycle)
                || actual.5 != expected.exact_text
                || actual.6 != expected.record
                || actual.7 != expected.record_checksum
                || multihash(&actual.6) != expected.record_checksum
            {
                return Err("atom projection row differs from its normalized record".into());
            }
        }
        if rows.next().is_some() {
            return Err("atom projection contains an unexpected row".into());
        }

        let fts_rows = {
            let mut statement = connection.prepare(
                "SELECT generation, tenant_id, version_id, exact_text
                 FROM atom_projection_fts ORDER BY generation, tenant_id, version_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if fts_rows.len() != retained.atoms.len()
            || fts_rows
                .iter()
                .zip(&retained.atoms)
                .any(|(actual, expected)| {
                    actual.0 != 1
                        || actual.1 != retained.tenant_id.as_str()
                        || actual.2 != expected.atom.version_id.as_str()
                        || actual.3 != expected.exact_text
                })
        {
            return Err("atom projection FTS rows are not exact".into());
        }
        Ok(())
    }

    fn expected_projection_root(
        retained: &PreparedRetainedV1Fixture,
        generation: u64,
    ) -> Result<String> {
        let mut root = Sha256::new();
        root.update(b"CIGAR-SQLITE-ATOM-PROJECTION\0v1\0");
        root.update(generation.to_be_bytes());
        root.update(retained.revision.0.to_be_bytes());
        catalog_hash_field_fixture(&mut root, retained.catalog_root.as_bytes())?;
        for row in &retained.atoms {
            for field in [
                retained.tenant_id.as_str(),
                row.atom.version_id.as_str(),
                row.atom.lineage_id.as_str(),
                lifecycle_name_fixture(row.atom.lifecycle),
                row.exact_text.as_str(),
                row.record_checksum.as_str(),
            ] {
                catalog_hash_field_fixture(&mut root, field.as_bytes())?;
            }
        }
        Ok(finish_hash_fixture(root))
    }

    fn secure_sqlite_family(path: &Path) -> Result<()> {
        fs::set_permissions(path, Permissions::from_mode(0o600))?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
            if sidecar.exists() {
                fs::set_permissions(sidecar, Permissions::from_mode(0o600))?;
            }
        }
        Ok(())
    }

    fn readiness_passed(value: &Value) -> bool {
        value.pointer("/operation_id").and_then(Value::as_str) == Some("getReadiness")
            && value.pointer("/result/ready").and_then(Value::as_bool) == Some(true)
            && value.pointer("/result/gate_open").and_then(Value::as_bool) == Some(true)
    }

    fn context_contract(
        principal_id: RecordId,
        project_id: RecordId,
        version_id: VersionId,
    ) -> Result<ContextContract> {
        Ok(ContextContract {
            schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
            job_goal: "Answer only from governed installed qualification evidence".to_owned(),
            operation_class: OperationClass::Read,
            principal_id,
            purpose: "catalog.read".to_owned(),
            context_space_id: None,
            project_ids: vec![project_id],
            target: TargetProfile {
                provider: "cigar-reference".to_owned(),
                model_family: "cigar.reference-tokenizer.utf8-bytes.v1".to_owned(),
                tokenizer_fingerprint: ContentDigest::new(REFERENCE_TOKENIZER_FINGERPRINT)?,
                materializer_fingerprint: digest_bytes(b"cigar.materializer.json.v1")?,
                max_context_tokens: 4_096,
            },
            budget: Budget {
                total_input_tokens: 1_024,
                output_reserve_tokens: 256,
                lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 1_024)]),
            },
            requirements: vec![ContextRequirement {
                semantic_type: AtomKind::Documentation,
                selector: RequirementSelector::Exact(version_id),
                minimum_authority: 1,
                maximum_age: None,
                minimum_coverage: FixedPoint::new(0)?,
                blocking: true,
            }],
            consistency: ConsistencyMode::Strong,
            maximum_staleness: None,
            extensions: ExtensionMap::default(),
        })
    }

    fn record(value: u64) -> Result<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest> {
        let mut encoded = String::from("1220");
        for byte in Sha256::digest(bytes) {
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(ContentDigest::new(encoded)?)
    }

    fn multihash(bytes: &[u8]) -> String {
        format!("1220{}", hex_bytes(&Sha256::digest(bytes)))
    }

    fn canonical_file_uri(path: &Path) -> Result<String> {
        let text = path.to_str().ok_or("source root is not UTF-8")?;
        let mut uri = String::from("file://");
        for byte in text.bytes() {
            if byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~')
            {
                uri.push(char::from(byte));
            } else {
                write!(&mut uri, "%{byte:02X}")?;
            }
        }
        Ok(uri)
    }

    fn required_string(value: &Value, pointer: &str) -> Result<String> {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "required response string is absent".into())
    }

    #[cfg(test)]
    mod tests {
        use super::{
            AUTHORITATIVE_FULL_HELP, Arguments, CAPTURE_SEQUENCE, CandidateSandbox, ProcessGuard,
            Result, create_legacy_v1_database, installed_workflow_binding,
            prepare_retained_v1_fixture, sandboxed_candidate_command, valid_hex_digest,
            valid_identifier, valid_source_revision, valid_version, validate_full_surface_help,
            validate_plan_and_compiled_provenance, verify_legacy_v1_database,
            verify_upgraded_database, wait_for_exit,
        };
        use serde_json::json;
        use std::collections::BTreeSet;
        use std::ffi::OsString;
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        use std::path::PathBuf;
        use std::process::{Command, Stdio};
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        fn arguments() -> Vec<OsString> {
            [
                "--cigar",
                "/private/tmp/install/bin/cigar",
                "--cigard",
                "/private/tmp/install/bin/cigard",
                "--workspace",
                "/private/tmp/workspace",
                "--artifact-id",
                "cli-daemon-macos-aarch64",
                "--artifact-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--product-version",
                "1.0.0-dev.1",
                "--context-abi",
                "cigar.context.v1",
                "--source-revision",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--sandbox-root",
                "/private/tmp",
                "--candidate-input-root",
                "/private/tmp/inputs",
            ]
            .into_iter()
            .map(OsString::from)
            .collect()
        }

        #[test]
        fn exact_argument_surface_is_closed() -> Result<()> {
            let parsed = Arguments::parse(arguments())?;
            assert_eq!(
                parsed.cigar,
                PathBuf::from("/private/tmp/install/bin/cigar")
            );
            assert_eq!(parsed.context_abi, "cigar.context.v1");
            assert_eq!(
                parsed.source_revision,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );

            let mut duplicate = arguments();
            duplicate.extend([OsString::from("--cigar"), OsString::from("/tmp/other")]);
            assert!(Arguments::parse(duplicate).is_err());
            let mut unknown = arguments();
            unknown.extend([OsString::from("--extra"), OsString::from("value")]);
            assert!(Arguments::parse(unknown).is_err());
            Ok(())
        }

        #[test]
        fn artifact_bindings_reject_ambiguous_values() {
            assert!(valid_identifier("cli-daemon-macos-aarch64"));
            assert!(!valid_identifier("CLI daemon"));
            assert!(valid_hex_digest(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ));
            assert!(!valid_hex_digest(
                "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
            ));
            assert!(valid_source_revision(
                "0123456789abcdef0123456789abcdef01234567"
            ));
            assert!(!valid_source_revision(
                "0123456789ABCDEF0123456789ABCDEF01234567"
            ));
            assert!(valid_version("1.0.0-dev.1"));
            assert!(!valid_version("version one"));
        }

        #[test]
        fn installed_workflow_binding_is_domain_separated_and_cross_language_stable() {
            assert_eq!(
                installed_workflow_binding(
                    "cli-daemon-macos-aarch64",
                    &"a".repeat(64),
                    &"b".repeat(40),
                    &"1".repeat(64),
                    &"2".repeat(64),
                    &"3".repeat(64),
                    &"4".repeat(64),
                ),
                "84956be5a2614f8af42760e747b02e29c711183e872516f4f5bb91a2d24c5eee"
            );
        }

        #[test]
        fn full_surface_probe_rejects_the_narrow_beta_help() -> Result<()> {
            let full = AUTHORITATIVE_FULL_HELP;
            let beta = include_bytes!("../../../../crates/cigar-cli/assets/cigar-help-beta.txt");
            assert!(validate_full_surface_help(full).is_ok());
            assert!(validate_full_surface_help(beta).is_err());

            let mut missing_delta = full.to_vec();
            let needle = b" | diff";
            let offset = missing_delta
                .windows(needle.len())
                .position(|window| window == needle)
                .ok_or("full help contains diff")?;
            missing_delta.drain(offset..offset + needle.len());
            assert!(validate_full_surface_help(&missing_delta).is_err());

            let mut extra_command = full.to_vec();
            extra_command.extend_from_slice(b"  cigar hidden unsafe-command\n");
            assert!(validate_full_surface_help(&extra_command).is_err());

            let changed_option = full
                .windows(b"--deadline".len())
                .position(|window| window == b"--deadline")
                .ok_or("full help contains deadline")?;
            let mut changed_option_help = full.to_vec();
            *changed_option_help
                .get_mut(changed_option)
                .ok_or("full help option index is unavailable")? = b'+';
            assert!(validate_full_surface_help(&changed_option_help).is_err());
            Ok(())
        }

        #[test]
        fn complete_provenance_probe_rejects_a_later_block_without_provenance() -> Result<()> {
            let first = format!("1220{}", "1".repeat(64));
            let second = format!("1220{}", "2".repeat(64));
            let plan = json!({
                "result": {
                    "plan": {
                        "dispositions": [
                            [first, {"state": "selected", "lane": "evidence", "score": 1}],
                            [second, {"state": "selected", "lane": "evidence", "score": 1}]
                        ],
                        "lanes": [{"candidate_versions": [first, second]}]
                    }
                }
            });
            let compiled = json!({
                "result": {
                    "blocks": [
                        {"provenance": [first]},
                        {"provenance": [second]}
                    ]
                }
            });
            let authorized = BTreeSet::from([first.clone(), second.clone()]);
            assert!(validate_plan_and_compiled_provenance(&plan, &compiled, &authorized).is_ok());

            let mut missing_later_provenance = compiled;
            *missing_later_provenance
                .pointer_mut("/result/blocks/1/provenance")
                .ok_or("fixture provenance path is unavailable")? = json!([]);
            assert!(
                validate_plan_and_compiled_provenance(
                    &plan,
                    &missing_later_provenance,
                    &authorized,
                )
                .is_err()
            );

            let authorized_first_only = BTreeSet::from([first]);
            assert!(
                validate_plan_and_compiled_provenance(
                    &plan,
                    &json!({
                        "result": {
                            "blocks": [
                                {"provenance": [second.clone()]},
                                {"provenance": [second]}
                            ]
                        }
                    }),
                    &authorized_first_only,
                )
                .is_err()
            );
            Ok(())
        }

        #[test]
        fn retained_v1_fixture_is_source_bound_and_nonempty() -> Result<()> {
            let fixture = prepare_retained_v1_fixture()?;
            assert!(fixture.revision.0 > 0);
            assert!(fixture.atoms.len() >= 2);
            assert!(!fixture.edges.is_empty());
            assert!(!fixture.lineage_heads.is_empty());
            assert!(fixture.referenced_blob_bytes > 0);
            assert!(!fixture.state.is_empty());
            Ok(())
        }

        #[test]
        fn retained_v1_to_v4_upgrade_is_semantically_exact() -> Result<()> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let database = directory.path().join("retained-v1.sqlite3");
            create_legacy_v1_database(&database)?;
            let fixture = prepare_retained_v1_fixture()?;
            verify_legacy_v1_database(&database, &fixture)?;
            let store = cigar_store::SqliteStore::open(&database)?;
            assert_eq!(store.revision()?, fixture.revision);
            drop(store);
            verify_upgraded_database(&database, &fixture)?;
            Ok(())
        }

        #[test]
        fn candidate_sandbox_denies_process_creation() -> Result<()> {
            let sandbox = CandidateSandbox {
                policy: "(version 1)(allow default)(deny process-fork)(deny signal)".to_owned(),
            };
            let mut command =
                sandboxed_candidate_command(std::path::Path::new("/bin/sh"), &sandbox)?;
            let output = command
                .args(["-c", "sleep 1 & child=$!; wait \"$child\""])
                .stdin(Stdio::null())
                .output()?;
            assert!(!output.status.success());
            Ok(())
        }

        #[test]
        fn candidate_sandbox_cannot_signal_an_unrelated_same_user_process() -> Result<()> {
            let sandbox = CandidateSandbox {
                policy: "(version 1)(allow default)(deny signal)".to_owned(),
            };
            let mut helper = Command::new("/bin/sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let mut command =
                sandboxed_candidate_command(std::path::Path::new("/bin/kill"), &sandbox)?;
            let output = command
                .arg("-TERM")
                .arg(helper.id().to_string())
                .stdin(Stdio::null())
                .output()?;
            let helper_survived = helper.try_wait()?.is_none();
            let _ignored = helper.kill();
            let _ignored = helper.wait();
            if output.status.success() || !helper_survived {
                return Err("candidate Seatbelt profile allowed a same-user signal".into());
            }
            Ok(())
        }

        #[test]
        fn candidate_sandbox_cannot_broker_preferences_outside_the_workspace() -> Result<()> {
            let sandbox = CandidateSandbox {
                policy: concat!(
                    "(version 1)(allow default)(deny file-write*)",
                    "(deny mach-lookup)"
                )
                .to_owned(),
            };
            let sequence = CAPTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let domain = format!(
                "com.cigar.install-qualifier-test-{}-{sequence}",
                std::process::id()
            );
            let mut command =
                sandboxed_candidate_command(std::path::Path::new("/usr/bin/defaults"), &sandbox)?;
            let output = command
                .args(["write", domain.as_str(), "probe", "-bool", "true"])
                .stdin(Stdio::null())
                .output()?;
            let read = Command::new("/usr/bin/defaults")
                .args(["read", domain.as_str()])
                .stdin(Stdio::null())
                .output()?;
            let _cleanup = Command::new("/usr/bin/defaults")
                .args(["delete", domain.as_str()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if output.status.success() || read.status.success() {
                return Err(
                    "candidate Seatbelt profile allowed a brokered preference write".into(),
                );
            }
            Ok(())
        }

        #[test]
        fn combined_candidate_sandbox_preserves_only_bounded_legitimate_behavior() -> Result<()> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let protected = directory.path().join("candidate-input");
            fs::create_dir(&protected)?;
            fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))?;
            let outside = tempfile::tempdir()?;
            fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700))?;
            let root = directory.path().canonicalize()?;
            let protected = protected.canonicalize()?;
            let outside_root = outside.path().canonicalize()?;
            let sandbox = CandidateSandbox::for_roots(&root, &[&protected])?;
            let script = r#"
import os
import socket
import sys

root, protected, outside = sys.argv[1:]
with open(os.path.join(root, "allowed"), "wb") as stream:
    stream.write(b"allowed")
for path in (
    os.path.join(protected, "denied"),
    os.path.join(outside, "denied"),
):
    try:
        with open(path, "wb") as stream:
            stream.write(b"denied")
    except PermissionError:
        pass
    else:
        raise SystemExit(10)
ip = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    ip.bind(("127.0.0.1", 0))
except PermissionError:
    pass
else:
    raise SystemExit(11)
finally:
    ip.close()
unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
unix.bind(os.path.join(root, "allowed.sock"))
unix.close()
try:
    child = os.fork()
except OSError:
    pass
else:
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)
    raise SystemExit(12)
"#;
            let mut command =
                sandboxed_candidate_command(std::path::Path::new("/usr/bin/python3"), &sandbox)?;
            let output = command
                .arg("-c")
                .arg(script)
                .arg(&root)
                .arg(&protected)
                .arg(&outside_root)
                .stdin(Stdio::null())
                .output()?;
            if !output.status.success() {
                return Err(format!(
                    "combined Seatbelt proof failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            Ok(())
        }

        #[test]
        fn timeout_settlement_kills_and_reaps_descendant_group() -> Result<()> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let pid_file = directory.path().join("descendant.pid");
            let stdout = directory.path().join("stdout");
            let stderr = directory.path().join("stderr");
            let stdout_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&stdout)?;
            let stderr_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&stderr)?;
            let mut command = Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    "sleep 30 & child=$!; printf '%s\\n' \"$child\" > \"$1\"; wait",
                    "qualifier-timeout-probe",
                ])
                .arg(&pid_file)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout_file))
                .stderr(Stdio::from(stderr_file));
            let mut process = ProcessGuard::spawn(&mut command)?;
            wait_for_file(&pid_file)?;
            let descendant = read_pid(&pid_file)?;
            assert!(
                wait_for_exit(&mut process, &stdout, &stderr, Duration::from_millis(25)).is_err()
            );
            drop(process);
            assert_process_gone(descendant)?;
            Ok(())
        }

        #[test]
        fn output_flood_settlement_kills_and_reaps_descendant_group() -> Result<()> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let pid_file = directory.path().join("descendant.pid");
            let stdout = directory.path().join("stdout");
            let stderr = directory.path().join("stderr");
            let stdout_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&stdout)?;
            let stderr_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&stderr)?;
            let mut command = Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    "/usr/bin/yes flood & child=$!; printf '%s\\n' \"$child\" > \"$1\"; wait",
                    "qualifier-flood-probe",
                ])
                .arg(&pid_file)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout_file))
                .stderr(Stdio::from(stderr_file));
            let mut process = ProcessGuard::spawn(&mut command)?;
            wait_for_file(&pid_file)?;
            let descendant = read_pid(&pid_file)?;
            assert!(wait_for_exit(&mut process, &stdout, &stderr, Duration::from_secs(5)).is_err());
            drop(process);
            assert_process_gone(descendant)?;
            Ok(())
        }

        fn wait_for_file(path: &std::path::Path) -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !path.is_file() {
                if Instant::now() >= deadline {
                    return Err("descendant pid file timed out".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        }

        fn read_pid(path: &std::path::Path) -> Result<rustix::process::Pid> {
            let raw = fs::read_to_string(path)?.trim().parse::<i32>()?;
            rustix::process::Pid::from_raw(raw).ok_or_else(|| "invalid descendant pid".into())
        }

        fn assert_process_gone(pid: rustix::process::Pid) -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if rustix::process::test_kill_process(pid).is_err() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("descendant survived process-group settlement".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
