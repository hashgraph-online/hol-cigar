//! Exercises the public Rust SDK against the shared recorded workflow.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_sdk::api::{
    ApiError, BundleIdRequest, CompileContextBundleRequest, CreateContextPlanRequest,
    DiscoverSourcesRequest, FacadeEventStream, IngestCatalogRequest, PrincipalId, RequestContext,
    RequestEnvelope, ResponseEnvelope, ServiceFacade, ServiceFuture, TenantId,
};
use cigar_sdk::protocol::{ErrorCode, IdempotencyKey, RecordId};
use cigar_sdk::{
    CallOptions, EmbeddedClientBuilder, EmbeddedRuntime, EmbeddedRuntimeConfig,
    EmbeddedRuntimeFactory, PolicyProfile, SdkError, SdkFuture, StorageProfile,
    verify_bundle_manifest,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const TENANT_ID: &str = "sdk-workflow-tenant";
const PRINCIPAL_ID: &str = "sdk-workflow-principal";
const CORRELATION_ID: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7890";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePathParameter {
    name: String,
    value: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureOperation {
    operation_id: String,
    idempotency_key: Option<String>,
    path_parameters: Vec<FixturePathParameter>,
    request: Value,
    request_cbor_base64url: String,
    response: Value,
    response_cbor_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema_version: String,
    expected_operations: Vec<String>,
    expected_bundle_id: String,
    expected_manifest_id: String,
    expected_contract_digest: String,
    operations: Vec<FixtureOperation>,
}

struct RecordedState {
    position: usize,
    failed: bool,
}

struct RecordedFacade {
    fixture: Arc<Fixture>,
    state: Mutex<RecordedState>,
}

impl RecordedFacade {
    fn new(fixture: Arc<Fixture>) -> Self {
        Self {
            fixture,
            state: Mutex::new(RecordedState {
                position: 0,
                failed: false,
            }),
        }
    }

    fn fail(state: &mut RecordedState) -> Result<ResponseEnvelope, ApiError> {
        state.failed = true;
        Err(recorded_api_error())
    }

    fn complete(&self) -> Result<(), SdkError> {
        let state = self.state.lock().map_err(|_| SdkError::protocol())?;
        if state.failed || state.position != self.fixture.operations.len() {
            Err(SdkError::protocol())
        } else {
            Ok(())
        }
    }
}

impl ServiceFacade for RecordedFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        envelope: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| recorded_api_error())?;
            let Some(expected) = self.fixture.operations.get(state.position) else {
                return Self::fail(&mut state);
            };
            state.position += 1;
            if context.cancellation().is_cancelled()
                || context.operation().as_str() != expected.operation_id
                || context.identity().tenant().as_str() != TENANT_ID
                || context.identity().principal().as_str() != PRINCIPAL_ID
                || envelope.operation_id().as_str() != expected.operation_id
                || envelope.idempotency_key() != expected.idempotency_key.as_deref()
                || envelope.path_parameters().len() != expected.path_parameters.len()
                || envelope
                    .path_parameters()
                    .iter()
                    .zip(&expected.path_parameters)
                    .any(|(actual, fixture)| {
                        actual.name() != fixture.name || actual.value() != fixture.value
                    })
            {
                return Self::fail(&mut state);
            }
            let request_cbor = match URL_SAFE_NO_PAD.decode(&expected.request_cbor_base64url) {
                Ok(value) => value,
                Err(_) => return Self::fail(&mut state),
            };
            if envelope.payload_cbor() != request_cbor {
                return Self::fail(&mut state);
            }
            let response_cbor = match URL_SAFE_NO_PAD.decode(&expected.response_cbor_base64url) {
                Ok(value) => value,
                Err(_) => return Self::fail(&mut state),
            };
            ResponseEnvelope::new(expected.operation_id.clone(), response_cbor, None, None)
                .map_err(|_| recorded_api_error())
        })();
        Box::pin(async move { result })
    }

    fn subscribe<'a>(
        &'a self,
        _context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        Box::pin(async { Err(recorded_api_error()) })
    }
}

fn recorded_api_error() -> ApiError {
    let correlation = RecordId::new(CORRELATION_ID)
        .expect("the source-controlled correlation ID must remain valid");
    ApiError::new(ErrorCode::Internal, correlation)
}

struct RecordedRuntime {
    facade: Arc<RecordedFacade>,
    shutdown: Arc<AtomicBool>,
}

impl EmbeddedRuntime for RecordedRuntime {
    fn facade(&self) -> Arc<dyn ServiceFacade> {
        self.facade.clone()
    }

    fn shutdown<'a>(&'a self) -> SdkFuture<'a, Result<(), SdkError>> {
        self.shutdown.store(true, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

struct RecordedRuntimeFactory {
    facade: Arc<RecordedFacade>,
    starts: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

impl EmbeddedRuntimeFactory for RecordedRuntimeFactory {
    fn start<'a>(
        &'a self,
        config: EmbeddedRuntimeConfig,
    ) -> SdkFuture<'a, Result<Arc<dyn EmbeddedRuntime>, SdkError>> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let valid = matches!(
            config.storage(),
            StorageProfile::Memory {
                maximum_records: 1_024
            }
        ) && matches!(config.policy(), PolicyProfile::DenyAll);
        let facade = self.facade.clone();
        let shutdown = self.shutdown.clone();
        Box::pin(async move {
            if !valid {
                return Err(SdkError::protocol());
            }
            Ok(Arc::new(RecordedRuntime { facade, shutdown }) as Arc<dyn EmbeddedRuntime>)
        })
    }
}

fn operation<'a>(
    fixture: &'a Fixture,
    operation_id: &str,
) -> Result<&'a FixtureOperation, SdkError> {
    fixture
        .operations
        .iter()
        .find(|candidate| candidate.operation_id == operation_id)
        .ok_or_else(SdkError::protocol)
}

fn request<T: DeserializeOwned>(operation: &FixtureOperation) -> Result<T, serde_json::Error> {
    serde_json::from_value(operation.request.clone())
}

fn mutation_options(operation: &FixtureOperation) -> Result<CallOptions, Box<dyn Error>> {
    let key = operation
        .idempotency_key
        .as_ref()
        .ok_or_else(|| "fixture mutation lacks its idempotency key".to_owned())?;
    Ok(CallOptions::mutation(IdempotencyKey::new(key.clone())?))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let source = include_str!("../../workflow-fixture-v1.json");
    let fixture: Arc<Fixture> = Arc::new(serde_json::from_str(source)?);
    let expected = [
        "discoverSources",
        "ingestCatalog",
        "createContextPlan",
        "compileContextBundle",
        "getContextBundleManifest",
    ];
    if fixture.schema_version != "cigar.sdk-recorded-workflow.v1"
        || fixture.operations.len() != expected.len()
        || fixture
            .expected_operations
            .iter()
            .map(String::as_str)
            .ne(expected)
    {
        return Err("workflow fixture schema or operation sequence is unsupported".into());
    }
    for operation in &fixture.operations {
        if operation.response.is_null() {
            return Err("workflow response fixture must be non-null".into());
        }
    }
    let facade = Arc::new(RecordedFacade::new(Arc::clone(&fixture)));
    let starts = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let factory = Arc::new(RecordedRuntimeFactory {
        facade: facade.clone(),
        starts: starts.clone(),
        shutdown: shutdown.clone(),
    });
    let client = EmbeddedClientBuilder::new(factory)
        .storage_profile(StorageProfile::Memory {
            maximum_records: 1_024,
        })
        .policy_profile(PolicyProfile::DenyAll)
        .identity(TenantId::new(TENANT_ID)?, PrincipalId::new(PRINCIPAL_ID)?)
        .build()
        .await?;

    let discover_operation = operation(&fixture, "discoverSources")?;
    let discover_request: DiscoverSourcesRequest = request(discover_operation)?;
    let discovered = client
        .discover_sources(discover_request.clone(), CallOptions::read())
        .await?;

    let ingest_operation = operation(&fixture, "ingestCatalog")?;
    let ingest_request: IngestCatalogRequest = request(ingest_operation)?;
    let ingested = client
        .ingest_catalog(ingest_request, mutation_options(ingest_operation)?)
        .await?;

    let plan_operation = operation(&fixture, "createContextPlan")?;
    let plan_request: CreateContextPlanRequest = request(plan_operation)?;
    let planned = client
        .create_context_plan(plan_request, mutation_options(plan_operation)?)
        .await?;

    let compile_operation = operation(&fixture, "compileContextBundle")?;
    let compile_request: CompileContextBundleRequest = request(compile_operation)?;
    let compiled = client
        .compile_context_bundle(compile_request, mutation_options(compile_operation)?)
        .await?;

    let manifest_operation = operation(&fixture, "getContextBundleManifest")?;
    let manifest_request: BundleIdRequest = request(manifest_operation)?;
    let manifest = client
        .get_context_bundle_manifest(manifest_request, CallOptions::read())
        .await?;

    facade.complete()?;
    if discovered.value.source_id != discover_request.source_id
        || ingested.value.snapshot_id.as_str().is_empty()
        || planned.value.bundle_id.as_str() != fixture.expected_bundle_id
        || compiled.value.bundle_id.as_str() != fixture.expected_bundle_id
        || manifest.value.manifest_id.as_str() != fixture.expected_manifest_id
        || compiled.value.contract_digest.as_str() != fixture.expected_contract_digest
    {
        return Err("workflow response chain differs from the fixture".into());
    }
    verify_bundle_manifest(&compiled.value, &manifest.value)?;
    client.shutdown().await?;
    if starts.load(Ordering::SeqCst) != 1 || !shutdown.load(Ordering::SeqCst) {
        return Err("embedded runtime lifecycle did not complete exactly once".into());
    }
    println!("{}", fixture.expected_bundle_id);
    Ok(())
}
