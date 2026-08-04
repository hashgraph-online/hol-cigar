//! Process-boundary qualification for the governed full-profile embedded workflow.

#![cfg(all(feature = "full", target_os = "macos"))]

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
    AtomKind, Budget, Capability, Classification, ConsistencyMode, ContentDigest, ContextContract,
    ContextRequirement, ExtensionMap, FixedPoint, GovernanceEnvelope, InstructionAuthority,
    LaneKind, MediaType, OperationClass, QualityEnvelope, RecordId, RequirementSelector,
    SchemaVersion, SourceUri, TargetProfile, UtcTimestamp, VersionId,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TENANT_VALUE: u64 = 1;
const PROJECT_VALUE: u64 = 2;
const PRINCIPAL_VALUE: u64 = 3;
const GRANT_VALUE: u64 = 4;
const SOURCE_VALUE: u64 = 5;
const DENIED_PROJECT_VALUE: u64 = 999;
const SOURCE_CANARY: &str = "launch-evidence-canary";
const REFERENCE_TOKENIZER_FINGERPRINT: &str =
    "1220704360550f3e648c66e8333d6f68beccead8c630c31b640385e72bcaf3266657";

struct EmbeddedFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
    state: PathBuf,
    cli_config: PathBuf,
    source_id: RecordId,
    project_id: RecordId,
    principal_id: RecordId,
}

impl EmbeddedFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let state = root.join("state");
        let runtime = root.join("run");
        let project = root.join("project");
        let trusted = root.join("trusted");
        let secrets = root.join("secrets");
        for path in [&state, &runtime, &project, &trusted, &secrets] {
            std::fs::create_dir_all(path)?;
        }
        let project = std::fs::canonicalize(project)?;
        std::fs::write(
            project.join("README.md"),
            format!(
                "# Launch evidence\n\n{SOURCE_CANARY} is selected only through governed local context.\n"
            ),
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
        trusted_write(&authority_file, &serde_json::to_vec(&authority)?)?;
        let policy_file = trusted.join("policy.json");
        trusted_write(
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
        let source_uri = SourceUri::new(canonical_file_uri(&project)?)?;
        let source = ProductionSourceEntry {
            tenant_id: tenant_id.clone(),
            source: SourceConfiguration {
                schema_version: "cigar.source-configuration.v1".to_owned(),
                source_id: source_id.clone(),
                root: source_uri,
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
        trusted_write(
            &sources_file,
            &serde_json::to_vec(&ProductionSourceRegistry {
                schema_version: "cigar.production-source-registry.v1".to_owned(),
                sources: vec![source],
            })?,
        )?;
        let effects_file = trusted.join("effects.json");
        trusted_write(
            &effects_file,
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":false,"connectors":[]}"#,
        )?;

        let daemon = DaemonConfig {
            mode: DeploymentMode::Local,
            intelligence_profile: cigar_daemon::IntelligenceProfile::default(),
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
                metadata_database: state.join("cigar.sqlite3"),
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
        trusted_write(&daemon_config, toml::to_string(&daemon)?.as_bytes())?;
        let cli_config = root.join("cli.toml");
        trusted_write(
            &cli_config,
            format!(
                concat!(
                    "schema_version = 1\n",
                    "target = \"embedded\"\n",
                    "daemon_config = {}\n",
                    "project_state_directory = {}\n"
                ),
                serde_json::to_string(&daemon_config.display().to_string())?,
                serde_json::to_string(&state.join("cli-state").display().to_string())?,
            )
            .as_bytes(),
        )?;

        Ok(Self {
            _directory: directory,
            root,
            project,
            state,
            cli_config,
            source_id,
            project_id,
            principal_id,
        })
    }

    fn write_input(&self, name: &str, value: &impl Serialize) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.root.join(name);
        restricted_write(&path, &serde_json::to_vec(value)?)?;
        Ok(path)
    }

    fn invoke(
        &self,
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Output, Box<dyn Error>> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cigar"));
        command
            .current_dir(&self.project)
            .env_clear()
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .args(arguments)
            .arg("--config")
            .arg(&self.cli_config)
            .args(["--output", "json", "--deadline", "30s"]);
        Ok(command.output()?)
    }

    fn success(&self, arguments: &[&OsStr]) -> Result<Value, Box<dyn Error>> {
        let output = self.invoke(arguments.iter().map(OsString::from))?;
        self.decode_success(arguments, output)
    }

    fn decode_success(
        &self,
        arguments: &[&OsStr],
        output: Output,
    ) -> Result<Value, Box<dyn Error>> {
        if !output.status.success() {
            return Err(format!(
                "embedded command {arguments:?} failed: status={:?} stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        if !output.stderr.is_empty() {
            return Err(format!(
                "non-TTY embedded command wrote stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let value: Value = serde_json::from_slice(&output.stdout)?;
        if value.pointer("/ok").and_then(Value::as_bool) != Some(true)
            || value.pointer("/target").and_then(Value::as_str) != Some("embedded")
        {
            return Err(format!("invalid success envelope: {value}").into());
        }
        Ok(value)
    }
}

#[test]
fn full_cli_process_completes_governed_offline_workflow_across_restarts()
-> Result<(), Box<dyn Error>> {
    let fixture = EmbeddedFixture::new()?;
    let source = fixture.source_id.as_str();

    let discovery_input = fixture.write_input(
        "discover.json",
        &DiscoverSourcesRequest {
            source_id: fixture.source_id.clone(),
            include_paths: Vec::new(),
        },
    )?;
    let refresh_arguments = [
        OsStr::new("source"),
        OsStr::new("refresh"),
        OsStr::new("--input"),
        discovery_input.as_os_str(),
        OsStr::new("--yes"),
    ];
    let first_discovery = fixture.success(&refresh_arguments)?;
    let second_discovery = fixture.success(&refresh_arguments)?;
    assert_eq!(
        first_discovery.pointer("/operation_id"),
        Some(&json!("discoverSources"))
    );
    assert_eq!(
        first_discovery.pointer("/result"),
        second_discovery.pointer("/result")
    );
    assert_eq!(
        first_discovery.pointer("/result/included_count"),
        Some(&json!(1))
    );
    let plan_digest = required_string(&first_discovery, "/result/plan_digest")?;

    let inspected = fixture.success(&[
        OsStr::new("source"),
        OsStr::new("inspect"),
        OsStr::new(source),
    ])?;
    assert_eq!(
        inspected.pointer("/operation_id"),
        Some(&json!("getSourceStatus"))
    );
    assert_eq!(inspected.pointer("/result/status"), Some(&json!("ready")));

    let ingest_input = fixture.write_input(
        "ingest.json",
        &IngestCatalogRequest {
            source_id: fixture.source_id.clone(),
            plan_digest: ContentDigest::new(plan_digest)?,
        },
    )?;
    let ingest_arguments = [
        OsStr::new("ingest"),
        OsStr::new("--input"),
        ingest_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-ingest-v1"),
        OsStr::new("--yes"),
    ];
    let first_ingest = fixture.success(&ingest_arguments)?;
    let replayed_ingest = fixture.success(&ingest_arguments)?;
    assert_eq!(
        first_ingest.pointer("/operation_id"),
        Some(&json!("ingestCatalog"))
    );
    assert_eq!(
        first_ingest.pointer("/result"),
        replayed_ingest.pointer("/result")
    );
    assert!(
        first_ingest
            .pointer("/result/published_atoms")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    );

    let requirement = ContextRequirement {
        semantic_type: AtomKind::Documentation,
        selector: RequirementSelector::Query("launch evidence".to_owned()),
        minimum_authority: 1,
        maximum_age: None,
        minimum_coverage: FixedPoint::new(0)?,
        blocking: true,
    };
    let query_input = fixture.write_input(
        "query.json",
        &QueryCatalogRequest {
            requirements: vec![requirement.clone()],
            max_results: 16,
        },
    )?;
    let query_arguments = [
        OsStr::new("catalog"),
        OsStr::new("query"),
        OsStr::new("--input"),
        query_input.as_os_str(),
    ];
    let first_query = fixture.success(&query_arguments)?;
    let restarted_query = fixture.success(&query_arguments)?;
    assert_eq!(
        first_query.pointer("/operation_id"),
        Some(&json!("queryCatalog"))
    );
    assert_eq!(
        first_query.pointer("/result"),
        restarted_query.pointer("/result")
    );
    let selected_version = first_query
        .pointer("/result/version_ids/0")
        .and_then(Value::as_str)
        .ok_or("catalog query returned no authorized version")?
        .to_owned();

    let denied_contract = contract(
        fixture.principal_id.clone(),
        record(DENIED_PROJECT_VALUE)?,
        VersionId::new(selected_version.clone())?,
    )?;
    let denied_input = fixture.write_input(
        "denied-plan.json",
        &CreateContextPlanRequest {
            contract: denied_contract,
        },
    )?;
    let denied = fixture.invoke([
        OsString::from("context"),
        OsString::from("plan"),
        OsString::from("--input"),
        denied_input.into_os_string(),
        OsString::from("--dry-run"),
    ])?;
    assert!(!denied.status.success());
    let denied_text = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(!denied_text.contains(SOURCE_CANARY));
    assert!(!denied_text.contains("README.md"));
    assert!(!denied_text.contains(&selected_version));
    let denied_json: Value = serde_json::from_slice(&denied.stdout)?;
    assert_eq!(denied_json.pointer("/ok"), Some(&json!(false)));

    let exact_requirement = ContextRequirement {
        semantic_type: AtomKind::Documentation,
        selector: RequirementSelector::Exact(VersionId::new(selected_version.clone())?),
        minimum_authority: 1,
        maximum_age: None,
        minimum_coverage: FixedPoint::new(0)?,
        blocking: true,
    };
    let plan_input = fixture.write_input(
        "plan.json",
        &CreateContextPlanRequest {
            contract: contract_with_requirement(
                fixture.principal_id.clone(),
                fixture.project_id.clone(),
                exact_requirement,
            )?,
        },
    )?;
    let dry_plan = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("plan"),
        OsStr::new("--input"),
        plan_input.as_os_str(),
        OsStr::new("--dry-run"),
    ])?;
    let committed_plan = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("plan"),
        OsStr::new("--input"),
        plan_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-plan-v1"),
        OsStr::new("--yes"),
    ])?;
    assert_eq!(
        dry_plan.pointer("/result"),
        committed_plan.pointer("/result")
    );
    let plan_id = required_string(&committed_plan, "/result/plan/plan_id")?;
    let bundle_id = required_string(&committed_plan, "/result/bundle_id")?;
    let manifest_digest = required_string(&committed_plan, "/result/manifest_digest")?;
    assert!(!manifest_digest.is_empty());

    let compile_input = fixture.write_input(
        "compile.json",
        &CompileContextBundleRequest {
            plan_id: RecordId::new(plan_id.clone())?,
        },
    )?;
    let compiled = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("compile"),
        OsStr::new("--input"),
        compile_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-compile-v1"),
        OsStr::new("--yes"),
    ])?;
    assert_eq!(
        compiled.pointer("/result/bundle_id"),
        Some(&json!(bundle_id))
    );
    assert_eq!(
        compiled.pointer("/result/manifest_digest"),
        Some(&json!(manifest_digest))
    );
    assert!(
        compiled
            .pointer("/result/blocks/0/provenance")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value == &json!(selected_version)))
    );

    let explain_input = fixture.write_input(
        "explain.json",
        &ExplainContextBundleRequest {
            bundle_id: VersionId::new(bundle_id.clone())?,
            version_ids: vec![VersionId::new(selected_version.clone())?],
        },
    )?;
    let explained = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("explain"),
        OsStr::new(&bundle_id),
        OsStr::new("--input"),
        explain_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-explain-v1"),
        OsStr::new("--yes"),
    ])?;
    assert_eq!(
        explained.pointer("/result/entries/0/version_id"),
        Some(&json!(selected_version))
    );

    let bundle_request = BundleIdRequest {
        bundle_id: VersionId::new(bundle_id.clone())?,
    };
    let revalidate_input = fixture.write_input("revalidate.json", &bundle_request)?;
    let revalidated = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("revalidate"),
        OsStr::new(&bundle_id),
        OsStr::new("--input"),
        revalidate_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-revalidate-v1"),
        OsStr::new("--yes"),
    ])?;
    assert_eq!(revalidated.pointer("/result/valid"), Some(&json!(true)));
    assert_eq!(revalidated.pointer("/result/reasons"), Some(&json!([])));

    let materialize_input = fixture.write_input(
        "materialize.json",
        &MaterializeContextBundleRequest {
            bundle_id: VersionId::new(bundle_id.clone())?,
            profile: MaterializationProfile::CanonicalJson,
        },
    )?;
    let materialized = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("materialize"),
        OsStr::new(&bundle_id),
        OsStr::new("--input"),
        materialize_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-materialize-v1"),
        OsStr::new("--yes"),
    ])?;
    assert_eq!(
        materialized.pointer("/result/context/bundle_id"),
        Some(&json!(bundle_id))
    );
    assert!(
        materialized
            .pointer("/result/physical_input_tokens")
            .and_then(Value::as_u64)
            .is_some_and(|tokens| tokens > 0)
    );

    let mut target_contract = contract(
        fixture.principal_id.clone(),
        fixture.project_id.clone(),
        VersionId::new(selected_version)?,
    )?;
    target_contract.job_goal =
        "Answer the revised launch question from the same evidence".to_owned();
    let target_plan_input = fixture.write_input(
        "target-plan.json",
        &CreateContextPlanRequest {
            contract: target_contract,
        },
    )?;
    let target_plan = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("plan"),
        OsStr::new("--input"),
        target_plan_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-target-plan-v1"),
        OsStr::new("--yes"),
    ])?;
    let target_plan_id = required_string(&target_plan, "/result/plan/plan_id")?;
    let target_bundle_id = required_string(&target_plan, "/result/bundle_id")?;
    assert_ne!(target_bundle_id, bundle_id);

    let delta_input = fixture.write_input(
        "delta.json",
        &CompileContextDeltaRequest {
            base_bundle_id: VersionId::new(bundle_id.clone())?,
            target_plan_id: RecordId::new(target_plan_id)?,
        },
    )?;
    let delta = fixture.success(&[
        OsStr::new("context"),
        OsStr::new("diff"),
        OsStr::new("--input"),
        delta_input.as_os_str(),
        OsStr::new("--idempotency-key"),
        OsStr::new("embedded-delta-v1"),
        OsStr::new("--yes"),
    ])?;
    assert_eq!(
        delta.pointer("/result/delta/base_bundle_id"),
        Some(&json!(bundle_id))
    );
    assert_eq!(
        delta.pointer("/result/delta/target_bundle_id"),
        Some(&json!(target_bundle_id))
    );

    assert!(fixture.state.join("cigar.sqlite3").is_file());
    assert!(!fixture.root.join("run/cigard.sock").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&fixture.state)?.permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            std::fs::metadata(fixture.state.join("cigar.sqlite3"))?
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    Ok(())
}

fn contract(
    principal_id: RecordId,
    project_id: RecordId,
    version_id: VersionId,
) -> Result<ContextContract, Box<dyn Error>> {
    contract_with_requirement(
        principal_id,
        project_id,
        ContextRequirement {
            semantic_type: AtomKind::Documentation,
            selector: RequirementSelector::Exact(version_id),
            minimum_authority: 1,
            maximum_age: None,
            minimum_coverage: FixedPoint::new(0)?,
            blocking: true,
        },
    )
}

fn contract_with_requirement(
    principal_id: RecordId,
    project_id: RecordId,
    requirement: ContextRequirement,
) -> Result<ContextContract, Box<dyn Error>> {
    Ok(ContextContract {
        schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
        job_goal: "Answer only from governed launch evidence".to_owned(),
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
        requirements: vec![requirement],
        consistency: ConsistencyMode::Strong,
        maximum_staleness: None,
        extensions: ExtensionMap::default(),
    })
}

fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let mut encoded = String::from("1220");
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn canonical_file_uri(path: &Path) -> Result<String, Box<dyn Error>> {
    let text = path.to_str().ok_or("source root is not UTF-8")?;
    let mut uri = String::from("file://");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            write!(&mut uri, "%{byte:02X}")?;
        }
    }
    Ok(uri)
}

fn required_string(value: &Value, pointer: &str) -> Result<String, Box<dyn Error>> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string at {pointer}").into())
}

fn trusted_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn restricted_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    trusted_write(path, bytes)
}
