//! Production-handler transport differential tests.
//!
//! The API crate exhaustively verifies transport normalization with synthetic handlers. These
//! tests close the complementary composition gap: concrete daemon handlers must produce the same
//! typed response and durable repository state when reached through embedded, HTTP, or gRPC mode.

use crate::{
    CatalogContextApplication, CurrentSpaceHandoffAuthorization, DomainAuthorizationError,
    DomainIdentityResolver, EffectServiceHandlers, HandoffReferenceResolver,
    HandoffResultMergePlanner, OperationalHandlers, RecipientBundleCompiler,
    RecipientCompilationRequest, ReplayServiceHandlers, RepositorySpaceHandoffStateProvider,
    ResolvedDomainIdentity, ResolvedHandoffReference, SpaceHandoffApplication,
    SpaceHandoffAuthorizationScope, SpaceHandoffAuthorizer, SpaceHandoffDependencyError,
    SpaceHandoffStateProvider, SpaceHandoffValueSource,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::generated::{OPERATION_COUNT, OPERATIONS, StreamKind};
use cigar_api::proto::space_service_client::SpaceServiceClient;
use cigar_api::proto::{
    OperationRequest as GrpcOperationRequest, OperationResponse as GrpcOperationResponse,
    PathParameter as GrpcPath,
};
use cigar_api::{
    ApiError, AuthenticatedIdentity, CancellationToken, ContextInput, CreateSpaceOperation,
    CreateSpaceRequest, CursorCodec, FacadeErrorFactory, FacadeEventStream, GetSpaceLogOperation,
    GrpcService, OperationId, PathParameter, PrincipalId, RequestAuthority, RequestContext,
    RequestEnvelope, ResponseEnvelope, ServiceFacade, ServiceFuture, ServiceKernel,
    SpaceLogResponse, TenantId, TraceId, TransportConfig, TypedOperation, TypedStreamService,
    TypedUnaryAdapter, TypedUnaryService, UnaryOperationHandler, decode_operation_payload,
    encode_operation_payload, http_router, registered_http_routes,
};
use cigar_crypto::{CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider};
use cigar_policy::EffectiveCapabilities;
use cigar_protocol::{
    Capability, ContentDigest, ContextCommit, ContextSpaceId, ErrorCode, RecordId, UtcTimestamp,
    VersionId,
};
use cigar_space::{
    HandoffMergeMaterial, RecipientBundleReceipt, ResultMergeKind, ResultMergeMapping,
};
use cigar_store::{CancellationToken as StoreCancellationToken, InMemoryStore, StoreRevision};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request as GrpcRequest;
use tonic::metadata::MetadataValue;
use tonic::transport::Server;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const AUTHORIZATION_VALUE: &str = "Bearer production-differential";
const TRACE_ID: &str = "1234567890abcdef1234567890abcdef";
const IDEMPOTENCY_KEY: &str = "production-differential-create";

fn record(value: u64) -> TestResult<RecordId> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn digest(value: u64) -> TestResult<ContentDigest> {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn add_seconds(timestamp: UtcTimestamp, seconds: u64) -> TestResult<UtcTimestamp> {
    let delta = i128::from(seconds)
        .checked_mul(1_000_000_000)
        .ok_or("timestamp delta overflow")?;
    Ok(UtcTimestamp::from_unix_nanos(
        timestamp
            .unix_nanos()
            .checked_add(delta)
            .ok_or("timestamp overflow")?,
    )?)
}

fn test_time() -> TestResult<UtcTimestamp> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds = i128::from(elapsed.as_secs());
    Ok(UtcTimestamp::from_unix_nanos(
        seconds
            .checked_mul(1_000_000_000)
            .ok_or("test time overflow")?,
    )?)
}

struct TestAuthority {
    accepted_at: UtcTimestamp,
    deadline: UtcTimestamp,
    correlation: RecordId,
}

impl TestAuthority {
    fn error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.correlation.clone())
    }

    fn context(
        &self,
        operation: OperationId,
        cancellation: CancellationToken,
    ) -> Result<RequestContext, ApiError> {
        RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new("transport-tenant")
                    .map_err(|_error| self.error(ErrorCode::Internal))?,
                PrincipalId::new("issuer").map_err(|_error| self.error(ErrorCode::Internal))?,
            ),
            operation,
            self.deadline,
            TraceId::new(TRACE_ID).map_err(|_error| self.error(ErrorCode::Internal))?,
            cancellation,
            self.accepted_at,
        )
        .map_err(|_error| self.error(ErrorCode::Internal))
    }

    fn embedded_context(&self, operation: &'static str) -> Result<RequestContext, ApiError> {
        let operation =
            OperationId::new(operation).map_err(|_error| self.error(ErrorCode::Internal))?;
        self.context(operation, CancellationToken::new())
    }
}

impl FacadeErrorFactory for TestAuthority {
    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.error(code)
    }
}

impl RequestAuthority for TestAuthority {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        let result = if input.authorization() == Some(AUTHORIZATION_VALUE) {
            self.context(input.operation_id().clone(), input.cancellation().clone())
        } else {
            Err(self.error(ErrorCode::UnknownPrincipal))
        };
        Box::pin(async move { result })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        FacadeErrorFactory::public_error(self, code)
    }
}

struct FixedIdentity {
    tenant: RecordId,
    principal: RecordId,
}

impl DomainIdentityResolver for FixedIdentity {
    fn resolve(
        &self,
        _context: &RequestContext,
    ) -> Result<ResolvedDomainIdentity, crate::DomainIdentityError> {
        Ok(ResolvedDomainIdentity {
            tenant_id: self.tenant.clone(),
            principal_id: self.principal.clone(),
        })
    }
}

struct AllowSpaceAuthority {
    tenant: RecordId,
    principal: RecordId,
    project: RecordId,
    key_ref: cigar_crypto::KeyRef,
    expires_at: UtcTimestamp,
    policy_digest: ContentDigest,
}

impl SpaceHandoffAuthorizer for AllowSpaceAuthority {
    fn authorize(
        &self,
        _context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        scope: &SpaceHandoffAuthorizationScope,
        _now: UtcTimestamp,
    ) -> Result<CurrentSpaceHandoffAuthorization, DomainAuthorizationError> {
        if identity.tenant_id != self.tenant || identity.principal_id != self.principal {
            return Err(DomainAuthorizationError::Denied);
        }
        let capabilities = BTreeSet::from([
            Capability::ReadContext,
            Capability::WriteOverlay,
            Capability::PublishOverlay,
        ]);
        Ok(CurrentSpaceHandoffAuthorization {
            effective: EffectiveCapabilities {
                tenant: self.tenant.as_str().to_owned(),
                subject_id: self.principal.clone(),
                grant_id: record(90).map_err(|_error| DomainAuthorizationError::Invalid)?,
                capabilities,
                project_ids: BTreeSet::from([self.project.clone()]),
                processors: BTreeSet::from(["production-differential".to_owned()]),
                expires_at: self.expires_at,
            },
            resource_project_id: match scope {
                SpaceHandoffAuthorizationScope::NewSpace { project_id }
                | SpaceHandoffAuthorizationScope::Space { project_id, .. }
                | SpaceHandoffAuthorizationScope::HandoffMerge { project_id, .. } => {
                    Some(project_id.clone())
                }
                _ => None,
            },
            roles: BTreeSet::new(),
            policy_allowed_projects: BTreeSet::from([self.project.clone()]),
            policy_allowed_capabilities: BTreeSet::new(),
            visible_projects: BTreeSet::from([self.project.clone()]),
            policy_digest: self.policy_digest.clone(),
            revoked_principals: BTreeSet::new(),
            revoked_key_ids: BTreeSet::new(),
            issuer_key_ref: self.key_ref.clone(),
            runtime_audience: "production-differential".to_owned(),
            target_allowed: true,
        })
    }

    fn reference_authorized(
        &self,
        _context: &RequestContext,
        _identity: &ResolvedDomainIdentity,
        _scope: &SpaceHandoffAuthorizationScope,
        _policy_digest: &ContentDigest,
        _version_id: &VersionId,
        _now: UtcTimestamp,
    ) -> Result<bool, DomainAuthorizationError> {
        Ok(true)
    }
}

struct UnusedCompiler;

impl RecipientBundleCompiler for UnusedCompiler {
    fn compile_recipient_bundle(
        &self,
        _request: RecipientCompilationRequest,
        _cancellation: &StoreCancellationToken,
    ) -> Result<RecipientBundleReceipt, SpaceHandoffDependencyError> {
        Err(SpaceHandoffDependencyError::Unavailable)
    }
}

struct UnusedMergePlanner;

impl HandoffResultMergePlanner for UnusedMergePlanner {
    fn plan_mappings(
        &self,
        _context: &RequestContext,
        _identity: &ResolvedDomainIdentity,
        _authorization: &CurrentSpaceHandoffAuthorization,
        _material: &HandoffMergeMaterial,
    ) -> Result<Vec<ResultMergeMapping>, SpaceHandoffDependencyError> {
        Err(SpaceHandoffDependencyError::Unavailable)
    }
}

impl HandoffReferenceResolver for UnusedMergePlanner {
    fn resolve_reference(
        &self,
        _context: &RequestContext,
        _identity: &ResolvedDomainIdentity,
        _authorization: &CurrentSpaceHandoffAuthorization,
        _project_id: &RecordId,
        _version_id: &VersionId,
        _expected_kind: ResultMergeKind,
        _cancellation: &StoreCancellationToken,
    ) -> Result<ResolvedHandoffReference, SpaceHandoffDependencyError> {
        Err(SpaceHandoffDependencyError::Unavailable)
    }
}

struct DeterministicValues {
    now: UtcTimestamp,
    next: AtomicU64,
}

impl SpaceHandoffValueSource for DeterministicValues {
    fn now(&self) -> Result<UtcTimestamp, SpaceHandoffDependencyError> {
        Ok(self.now)
    }

    fn record_id(&self) -> Result<RecordId, SpaceHandoffDependencyError> {
        record(self.next.fetch_add(1, Ordering::Relaxed))
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)
    }

    fn nonce(&self) -> Result<Vec<u8>, SpaceHandoffDependencyError> {
        Ok(vec![7; 32])
    }
}

/// A narrow embedded facade that delegates only to concrete production handlers under test.
/// The exhaustive exact-45 concrete binding proof lives in the separate test below.
struct RealSpaceFacade {
    create: TypedUnaryAdapter<CreateSpaceOperation, SpaceHandoffApplication>,
    log: TypedUnaryAdapter<GetSpaceLogOperation, SpaceHandoffApplication>,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl ServiceFacade for RealSpaceFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        match request.operation_id().as_str() {
            CreateSpaceOperation::OPERATION_ID => self.create.call(context, request),
            GetSpaceLogOperation::OPERATION_ID => self.log.call(context, request),
            _ => {
                let error = self.errors.public_error(ErrorCode::InvalidArgument);
                Box::pin(async move { Err(error) })
            }
        }
    }

    fn subscribe<'a>(
        &'a self,
        _context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        let error = self.errors.public_error(ErrorCode::InvalidArgument);
        Box::pin(async move { Err(error) })
    }
}

struct Fixture {
    facade: Arc<RealSpaceFacade>,
    authority: Arc<TestAuthority>,
    repository: Arc<InMemoryStore>,
    key_provider: Arc<MemoryKeyProvider>,
    tenant: RecordId,
    project: RecordId,
}

fn fixture(observed_at: UtcTimestamp) -> TestResult<Fixture> {
    let tenant = record(1)?;
    let principal = record(2)?;
    let project = record(3)?;
    let repository = Arc::new(InMemoryStore::default());
    let key_provider = Arc::new(MemoryKeyProvider::default());
    let key = key_provider.create(CreateKeyRequest {
        tenant: tenant.as_str().to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: observed_at.unix_nanos(),
        activated_at: observed_at.unix_nanos(),
    })?;
    let states = Arc::new(RepositorySpaceHandoffStateProvider::new(
        repository.clone(),
        key_provider.clone(),
        4,
    )?);
    let authority = Arc::new(TestAuthority {
        accepted_at: observed_at,
        deadline: add_seconds(observed_at, 120)?,
        correlation: record(99)?,
    });
    let errors: Arc<dyn FacadeErrorFactory> = authority.clone();
    let application = Arc::new(SpaceHandoffApplication::new(
        states,
        Arc::new(FixedIdentity {
            tenant: tenant.clone(),
            principal: principal.clone(),
        }),
        Arc::new(AllowSpaceAuthority {
            tenant: tenant.clone(),
            principal,
            project: project.clone(),
            key_ref: key.key_ref,
            expires_at: add_seconds(observed_at, 300)?,
            policy_digest: digest(70)?,
        }),
        Arc::new(UnusedCompiler),
        Arc::new(UnusedMergePlanner),
        Arc::new(UnusedMergePlanner),
        Arc::new(DeterministicValues {
            now: observed_at,
            next: AtomicU64::new(10_000),
        }),
        Arc::new(CursorCodec::new(cigar_api::CursorSigningKey::new(vec![
            9;
            32
        ])?)),
        Arc::clone(&errors),
        Duration::from_secs(300),
        Duration::from_millis(10),
    )?);
    let facade = Arc::new(RealSpaceFacade {
        create: TypedUnaryAdapter::new(Arc::clone(&application), Arc::clone(&errors)),
        log: TypedUnaryAdapter::new(application, errors),
        errors: authority.clone(),
    });
    Ok(Fixture {
        facade,
        authority,
        repository,
        key_provider,
        tenant,
        project,
    })
}

fn create_request(project: RecordId) -> TestResult<RequestEnvelope> {
    let payload = CreateSpaceRequest {
        workspace_id: record(10)?,
        project_id: project,
        branch_id: record(11)?,
        task_id: record(12)?,
        session_id: record(13)?,
        purpose: "production transport differential".to_owned(),
    };
    Ok(RequestEnvelope::new(
        CreateSpaceOperation::OPERATION_ID,
        encode_operation_payload(&payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?,
        Some(IDEMPOTENCY_KEY.to_owned()),
        None,
        None,
        None,
        Vec::new(),
    )?)
}

fn log_request(space_id: &ContextSpaceId) -> TestResult<RequestEnvelope> {
    Ok(RequestEnvelope::new(
        GetSpaceLogOperation::OPERATION_ID,
        Vec::new(),
        None,
        None,
        None,
        None,
        vec![PathParameter::new("space_id", space_id.as_str())?],
    )?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EnvelopeProjection {
    operation_id: String,
    payload_cbor: Vec<u8>,
    semantic_etag: Option<String>,
    next_page_cursor: Option<String>,
}

impl From<ResponseEnvelope> for EnvelopeProjection {
    fn from(response: ResponseEnvelope) -> Self {
        Self {
            operation_id: response.operation_id().as_str().to_owned(),
            payload_cbor: response.payload_cbor().to_vec(),
            semantic_etag: response.semantic_etag().map(str::to_owned),
            next_page_cursor: response.next_page_cursor().map(str::to_owned),
        }
    }
}

#[derive(Deserialize)]
struct HttpWireResponse {
    operation_id: String,
    payload_cbor: String,
    #[serde(default)]
    semantic_etag: Option<String>,
    #[serde(default)]
    next_page_cursor: Option<String>,
}

async fn live_http_projection(
    address: std::net::SocketAddr,
    request: Vec<u8>,
) -> TestResult<EnvelopeProjection> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(&request).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let response = String::from_utf8(response)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("HTTP response body missing")?;
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    let wire: HttpWireResponse = serde_json::from_str(body)?;
    Ok(EnvelopeProjection {
        operation_id: wire.operation_id,
        payload_cbor: URL_SAFE_NO_PAD.decode(wire.payload_cbor)?,
        semantic_etag: wire.semantic_etag,
        next_page_cursor: wire.next_page_cursor,
    })
}

fn http_create(address: std::net::SocketAddr, request: &RequestEnvelope) -> TestResult<Vec<u8>> {
    let body = json!({
        "operation_id": request.operation_id().as_str(),
        "payload_cbor": URL_SAFE_NO_PAD.encode(request.payload_cbor()),
        "idempotency_key": IDEMPOTENCY_KEY,
        "path_parameters": []
    });
    let body = serde_json::to_vec(&body)?;
    let mut wire = format!(
        "POST /v1/spaces HTTP/1.1\r\nHost: {address}\r\nAuthorization: {AUTHORIZATION_VALUE}\r\nContent-Type: application/json\r\nIdempotency-Key: {IDEMPOTENCY_KEY}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(&body);
    Ok(wire)
}

fn http_log(address: std::net::SocketAddr, space_id: &ContextSpaceId) -> Vec<u8> {
    format!(
        "GET /v1/spaces/{}/log HTTP/1.1\r\nHost: {address}\r\nAuthorization: {AUTHORIZATION_VALUE}\r\nConnection: close\r\n\r\n",
        space_id.as_str()
    )
    .into_bytes()
}

fn grpc_request(request: &RequestEnvelope) -> TestResult<GrpcRequest<GrpcOperationRequest>> {
    let mut grpc = GrpcRequest::new(GrpcOperationRequest {
        operation_id: request.operation_id().as_str().to_owned(),
        idempotency_key: request.idempotency_key().unwrap_or_default().to_owned(),
        expected_revision: request.expected_revision().unwrap_or_default().to_owned(),
        payload_cbor: request.payload_cbor().to_vec(),
        page_cursor: request.page_cursor().unwrap_or_default().to_owned(),
        page_size: request.page_size().unwrap_or_default(),
        path_parameters: request
            .path_parameters()
            .iter()
            .map(|parameter| GrpcPath {
                name: parameter.name().to_owned(),
                value: parameter.value().to_owned(),
            })
            .collect(),
        dry_run: request.dry_run(),
    });
    grpc.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(AUTHORIZATION_VALUE)?,
    );
    if request.idempotency_key().is_some() {
        grpc.metadata_mut()
            .insert("idempotency-key", MetadataValue::try_from(IDEMPOTENCY_KEY)?);
    }
    Ok(grpc)
}

fn grpc_projection(response: GrpcOperationResponse) -> EnvelopeProjection {
    EnvelopeProjection {
        operation_id: response.operation_id,
        payload_cbor: response.payload_cbor,
        semantic_etag: (!response.semantic_etag.is_empty()).then_some(response.semantic_etag),
        next_page_cursor: (!response.next_page_cursor.is_empty())
            .then_some(response.next_page_cursor),
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Embedded,
    Http,
    Grpc,
}

struct LiveServer<E> {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), E>>>,
}

impl<E> LiveServer<E> {
    fn new(shutdown: oneshot::Sender<()>, task: tokio::task::JoinHandle<Result<(), E>>) -> Self {
        Self {
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }
}

impl<E> LiveServer<E>
where
    E: Error + Send + Sync + 'static,
{
    async fn shutdown(mut self) -> TestResult {
        if let Some(shutdown) = self.shutdown.take() {
            let _ignored = shutdown.send(());
        }
        let task = self.task.take().ok_or("live server task missing")?;
        task.await??;
        Ok(())
    }
}

impl<E> Drop for LiveServer<E> {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ignored = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Observation {
    create: EnvelopeProjection,
    log: EnvelopeProjection,
    durable_log: Vec<ContextCommit>,
    repository_revision: StoreRevision,
}

async fn exercise(mode: Mode, observed_at: UtcTimestamp) -> TestResult<Observation> {
    let fixture = fixture(observed_at)?;
    let facade: Arc<dyn ServiceFacade> = fixture.facade.clone();
    let request_authority: Arc<dyn RequestAuthority> = fixture.authority.clone();
    let kernel = ServiceKernel::new(facade, request_authority, TransportConfig::default());
    let create_request = create_request(fixture.project)?;

    let (create, log) = match mode {
        Mode::Embedded => {
            let create: EnvelopeProjection = fixture
                .facade
                .call(
                    fixture
                        .authority
                        .embedded_context(CreateSpaceOperation::OPERATION_ID)?,
                    create_request.clone(),
                )
                .await?
                .into();
            let created: ContextCommit = decode_operation_payload(
                &create.payload_cbor,
                cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
            )?;
            let log = fixture
                .facade
                .call(
                    fixture
                        .authority
                        .embedded_context(GetSpaceLogOperation::OPERATION_ID)?,
                    log_request(&created.space_id)?,
                )
                .await?
                .into();
            (create, log)
        }
        Mode::Http => {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let server = tokio::spawn(async move {
                axum::serve(listener, http_router(kernel))
                    .with_graceful_shutdown(async move {
                        let _ignored = shutdown_receiver.await;
                    })
                    .await
            });
            let server = LiveServer::new(shutdown_sender, server);
            let create =
                live_http_projection(address, http_create(address, &create_request)?).await?;
            let created: ContextCommit = decode_operation_payload(
                &create.payload_cbor,
                cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
            )?;
            let log = live_http_projection(address, http_log(address, &created.space_id)).await?;
            server.shutdown().await?;
            (create, log)
        }
        Mode::Grpc => {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let grpc = GrpcService::new(kernel);
            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let server = tokio::spawn(async move {
                Server::builder()
                    .add_service(grpc.space_server())
                    .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                        let _ignored = shutdown_receiver.await;
                    })
                    .await
            });
            let server = LiveServer::new(shutdown_sender, server);
            let mut client = SpaceServiceClient::connect(format!("http://{address}")).await?;
            let create = grpc_projection(
                client
                    .create_space(grpc_request(&create_request)?)
                    .await?
                    .into_inner(),
            );
            let created: ContextCommit = decode_operation_payload(
                &create.payload_cbor,
                cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
            )?;
            let log = grpc_projection(
                client
                    .get_space_log(grpc_request(&log_request(&created.space_id)?)?)
                    .await?
                    .into_inner(),
            );
            drop(client);
            server.shutdown().await?;
            (create, log)
        }
    };
    let created: ContextCommit =
        decode_operation_payload(&create.payload_cbor, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;
    let typed_log: SpaceLogResponse =
        decode_operation_payload(&log.payload_cbor, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;

    // Reopen the production state provider rather than reading through the live handler cache.
    let reopened = RepositorySpaceHandoffStateProvider::new(
        fixture.repository.clone(),
        fixture.key_provider,
        4,
    )?;
    let durable_log = reopened
        .services(&fixture.tenant, &StoreCancellationToken::default())?
        .spaces
        .log(&created.space_id)?;
    assert_eq!(typed_log.commits, durable_log);
    assert_eq!(durable_log, vec![created]);

    Ok(Observation {
        create,
        log,
        durable_log,
        repository_revision: fixture.repository.revision()?,
    })
}

#[tokio::test]
async fn real_durable_mutation_and_read_are_identical_embedded_live_http_and_live_grpc()
-> TestResult {
    let observed_at = test_time()?;
    let embedded = exercise(Mode::Embedded, observed_at).await?;
    let http = exercise(Mode::Http, observed_at).await?;
    let grpc = exercise(Mode::Grpc, observed_at).await?;

    assert_eq!(http, embedded);
    assert_eq!(grpc, embedded);
    assert_eq!(
        embedded.create.operation_id,
        CreateSpaceOperation::OPERATION_ID
    );
    assert_eq!(
        embedded.log.operation_id,
        GetSpaceLogOperation::OPERATION_ID
    );
    Ok(())
}

fn assert_unary_binding<O, H>()
where
    O: TypedOperation,
    H: TypedUnaryService<O>,
{
}

fn assert_stream_binding<O, H>()
where
    O: TypedOperation,
    H: TypedStreamService<O>,
{
}

macro_rules! concrete_unary_bindings {
    ($ids:ident, $handler:ty => [$($operation:ty),+ $(,)?]) => {{
        $(
            assert_unary_binding::<$operation, $handler>();
            $ids.push(<$operation as TypedOperation>::OPERATION_ID);
        )+
    }};
}

#[test]
fn every_exact_contract_is_bound_to_a_concrete_production_handler() {
    let mut concrete = Vec::with_capacity(OPERATION_COUNT);
    concrete_unary_bindings!(concrete, OperationalHandlers => [
        cigar_api::GetLivenessOperation,
        cigar_api::GetReadinessOperation,
        cigar_api::GetVersionOperation,
        cigar_api::GetCapabilitiesOperation,
        cigar_api::GetConfigurationOperation,
        cigar_api::GetDiagnosticsOperation,
        cigar_api::GetMetricsOperation,
    ]);
    concrete_unary_bindings!(concrete, CatalogContextApplication<InMemoryStore> => [
        cigar_api::DiscoverSourcesOperation,
        cigar_api::IngestCatalogOperation,
        cigar_api::GetSourceStatusOperation,
        cigar_api::QueryCatalogOperation,
        cigar_api::BatchAtomsOperation,
        cigar_api::TombstoneAtomOperation,
        cigar_api::CreateContextPlanOperation,
        cigar_api::CompileContextBundleOperation,
        cigar_api::CompileContextDeltaOperation,
        cigar_api::GetContextBundleOperation,
        cigar_api::GetContextBundleManifestOperation,
        cigar_api::ExplainContextBundleOperation,
        cigar_api::MaterializeContextBundleOperation,
        cigar_api::RevalidateContextBundleOperation,
    ]);
    concrete_unary_bindings!(concrete, SpaceHandoffApplication => [
        cigar_api::CreateSpaceOperation,
        cigar_api::ForkSpaceOperation,
        cigar_api::PublishSpaceOperation,
        cigar_api::GetSpaceLogOperation,
        cigar_api::CreateSpaceCheckpointOperation,
        cigar_api::ListSpaceConflictsOperation,
        cigar_api::ResolveSpaceConflictOperation,
        cigar_api::CreateHandoffOperation,
        cigar_api::PreviewHandoffOperation,
        cigar_api::AcceptHandoffOperation,
        cigar_api::RevokeHandoffOperation,
        cigar_api::RecordHandoffResultOperation,
        cigar_api::MergeHandoffOperation,
    ]);
    assert_stream_binding::<cigar_api::SubscribeSpaceEventsOperation, SpaceHandoffApplication>();
    concrete.push(cigar_api::SubscribeSpaceEventsOperation::OPERATION_ID);
    concrete_unary_bindings!(concrete, EffectServiceHandlers<InMemoryStore> => [
        cigar_api::PrepareEffectOperation,
        cigar_api::AuthorizeEffectOperation,
        cigar_api::DispatchEffectOperation,
        cigar_api::GetEffectStatusOperation,
        cigar_api::ReconcileEffectOperation,
        cigar_api::CompensateEffectOperation,
    ]);
    concrete_unary_bindings!(concrete, ReplayServiceHandlers => [
        cigar_api::CreateReplayOperation,
        cigar_api::RunObservationalReplayOperation,
        cigar_api::CompareLiveReplayOperation,
        cigar_api::GetReplayCompletenessOperation,
    ]);

    concrete.sort_unstable();
    let mut generated: Vec<_> = OPERATIONS
        .iter()
        .map(|operation| operation.operation_id)
        .collect();
    generated.sort_unstable();
    assert_eq!(concrete.len(), OPERATION_COUNT);
    assert_eq!(concrete, generated);

    let http: BTreeSet<_> = registered_http_routes()
        .into_iter()
        .map(|(_method, _path, operation)| operation)
        .collect();
    let grpc: BTreeSet<_> = OPERATIONS
        .iter()
        .map(|operation| (operation.service, operation.rpc, operation.operation_id))
        .collect();
    assert_eq!(http.len(), OPERATION_COUNT);
    assert_eq!(grpc.len(), OPERATION_COUNT);
    assert_eq!(
        OPERATIONS
            .iter()
            .filter(|operation| operation.stream_kind == StreamKind::Unary)
            .count(),
        44
    );
    assert_eq!(
        OPERATIONS
            .iter()
            .filter(|operation| operation.stream_kind == StreamKind::ServerStream)
            .count(),
        1
    );
}
