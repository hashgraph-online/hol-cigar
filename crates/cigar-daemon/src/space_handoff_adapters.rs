//! Real typed application adapters for durable context spaces and signed handoffs.

use crate::{
    AuthorityClock, DaemonTelemetry, DomainIdentityResolver, DurableContextSpaceService,
    DurableHandoffService, DurableSnapshotAuthenticator, DurableStateError, DurableStateErrorCode,
    HandoffAcceptanceOutcome, ProductionApplicationBuilder, ResolvedDomainIdentity,
};
use base64::Engine as _;
use cigar_api::{
    AcceptHandoffOperation, ApiError, CheckpointSpaceRequest, ConflictListResponse,
    ConflictResolution, ConflictResolutionResponse, ConflictSummary, CreateHandoffOperation,
    CreateHandoffResponse, CreateSpaceCheckpointOperation, CreateSpaceOperation, CursorCodec,
    CursorScope, FacadeErrorFactory, ForkSpaceOperation, GetSpaceLogOperation,
    HandlerRegistryError, HandoffIdRequest, HandoffMergeResponse, HandoffPreviewResponse,
    HandoffResultReceipt as ApiHandoffResultReceipt, ListSpaceConflictsOperation,
    MergeHandoffOperation, MutationReceipt, PreviewHandoffOperation, PublishSpaceOperation,
    RecordHandoffResultOperation, ResolveSpaceConflictOperation, RevokeHandoffOperation,
    SpaceCheckpointResponse, SpaceEventPayload, SpaceFork, SpaceForkResponse, SpaceIdRequest,
    SpaceLogResponse, SpacePublishResponse, SubscribeSpaceEventsOperation, TypedEvent,
    TypedEventStream, TypedRequest, TypedResponse, TypedStreamService, TypedUnaryService,
};
use cigar_crypto::{KeyProvider, KeyRef, MonotonicUuidV7Generator};
use cigar_policy::EffectiveCapabilities;
use cigar_protocol::{
    Capability, ContentDigest, ContextCommit, ContextSpaceId, ExpectedRevision, ExtensionMap,
    HandoffAcceptance, HandoffDelta, Overlay, OverlayMutation, PageCursor, RecordId, SchemaVersion,
    UtcTimestamp, VersionId,
};
use cigar_space::{
    AcceptHandoffRequest as DomainAcceptHandoffRequest, AcceptedHandoffContext,
    CreateHandoffRequest as DomainCreateHandoffRequest,
    CreateSpaceRequest as DomainCreateSpaceRequest, EventCursor, HandoffError,
    HandoffMergeMaterial, PublishOutcome, PublishRequest, RecipientBundleReceipt,
    RecordHandoffResultRequest as DomainRecordHandoffResultRequest, ResolveConflictRequest,
    ResolverKind, ResultMergeKind, ResultMergeMapping,
    RevokeHandoffRequest as DomainRevokeHandoffRequest, SpaceError, SpaceHierarchy,
    StoredMergeConflict, merge_child_result,
};
use cigar_store::{CancellationToken as StoreCancellationToken, ServiceRepository};
use futures_core::Stream;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1_000;
const STREAM_BATCH_SIZE: usize = 256;
const NONCE_BYTES: usize = 32;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const LOG_CURSOR_BYTES: usize = 8 + 8 + 68;
const CONFLICT_CURSOR_BYTES: usize = 8 + 8 + 8 + 68;

/// Content-free failure returned by injected current-domain policy and record authorities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainAuthorizationError {
    /// The authenticated request or server-owned mapping is malformed.
    Invalid,
    /// Current policy denies the exact operation and resource scope.
    Denied,
    /// Current policy, revocation, or record authority is unavailable.
    Unavailable,
}

impl fmt::Display for DomainAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("current domain authorization failed")
    }
}

impl std::error::Error for DomainAuthorizationError {}

/// Exact resource scope reauthorized for a typed space or handoff operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpaceHandoffAuthorizationScope {
    /// Creation of a space under one caller-selected active project.
    NewSpace {
        /// Active project selected for the new hierarchy.
        project_id: RecordId,
    },
    /// One existing context space. Denial and absence must be indistinguishable.
    Space {
        /// Exact context-space identity being authorized.
        space_id: ContextSpaceId,
        /// Immutable active project resolved from the persisted space hierarchy.
        project_id: RecordId,
    },
    /// Creation of a new signed handoff.
    NewHandoff,
    /// One existing handoff. Denial and absence must be indistinguishable.
    Handoff {
        /// Exact persisted handoff identity being authorized.
        handoff_id: RecordId,
    },
    /// A retained child result entering one exact parent context space.
    HandoffMerge {
        /// Exact persisted handoff whose retained result is entering the parent.
        handoff_id: RecordId,
        /// Exact parent context space receiving the retained result.
        space_id: ContextSpaceId,
        /// Immutable active project resolved from the parent space hierarchy.
        project_id: RecordId,
    },
}

/// Current server-authoritative policy state used by one operation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSpaceHandoffAuthorization {
    /// Effective grant reverified for the resolved tenant and principal.
    pub effective: EffectiveCapabilities,
    /// Exact existing/new-space project bound into this decision, when applicable.
    pub resource_project_id: Option<RecordId>,
    /// Current authenticated recipient roles.
    pub roles: BTreeSet<String>,
    /// Projects current handoff policy permits the caller to delegate.
    pub policy_allowed_projects: BTreeSet<RecordId>,
    /// Capabilities current handoff policy permits the caller to delegate or accept.
    pub policy_allowed_capabilities: BTreeSet<Capability>,
    /// Projects whose context-space events may be disclosed on this poll.
    pub visible_projects: BTreeSet<RecordId>,
    /// Exact immutable policy decision used by this attempt.
    pub policy_digest: ContentDigest,
    /// Current principals revoked independently of historical signatures.
    pub revoked_principals: BTreeSet<RecordId>,
    /// Current signing keys revoked independently of historical verification.
    pub revoked_key_ids: BTreeSet<String>,
    /// Active tenant-scoped issuer signing key.
    pub issuer_key_ref: KeyRef,
    /// Current runtime audience accepted by recipient compilation.
    pub runtime_audience: String,
    /// Whether the current recipient target/model restriction permits compilation.
    pub target_allowed: bool,
}

/// Reauthorizes every attempt and every context-space stream poll against current policy.
pub trait SpaceHandoffAuthorizer: Send + Sync {
    /// Resolves current authority for an exact operation/resource scope.
    fn authorize(
        &self,
        context: &cigar_api::RequestContext,
        identity: &ResolvedDomainIdentity,
        scope: &SpaceHandoffAuthorizationScope,
        now: UtcTimestamp,
    ) -> Result<CurrentSpaceHandoffAuthorization, DomainAuthorizationError>;

    /// Reauthorizes one immutable reference under the same exact policy snapshot.
    fn reference_authorized(
        &self,
        context: &cigar_api::RequestContext,
        identity: &ResolvedDomainIdentity,
        scope: &SpaceHandoffAuthorizationScope,
        policy_digest: &ContentDigest,
        version_id: &VersionId,
        now: UtcTimestamp,
    ) -> Result<bool, DomainAuthorizationError>;
}

/// Content-free failure from recipient compilation or semantic result mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaceHandoffDependencyError {
    /// The request cannot be mapped to the required typed dependency input.
    Invalid,
    /// Current policy or record authority denies the dependency operation.
    Denied,
    /// The compiler or mapping authority is unavailable.
    Unavailable,
}

impl fmt::Display for SpaceHandoffDependencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("space or handoff dependency failed")
    }
}

impl std::error::Error for SpaceHandoffDependencyError {}

/// Complete trusted input to recipient-specific bundle compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientCompilationRequest {
    /// Exact persisted handoff whose signed scope controls derivation.
    pub handoff_id: RecordId,
    /// Exact source bundle signed into the persisted capsule.
    pub source_bundle_id: VersionId,
    /// Persisted caller-selected target plan.
    pub target_plan_id: RecordId,
    /// Reauthorized attenuated recipient input from the signed capsule.
    pub accepted: AcceptedHandoffContext,
    /// Resolved tenant partition.
    pub tenant_id: RecordId,
    /// Resolved authenticated recipient.
    pub recipient_id: RecordId,
    /// Exact current policy decision.
    pub policy_digest: ContentDigest,
    /// Server-observed compilation instant.
    pub observed_at: UtcTimestamp,
    /// Preview intent; implementations must not mutate durable state when true.
    pub dry_run: bool,
}

/// Real recipient compiler used by handoff acceptance; no synthetic bundle IDs are permitted.
pub trait RecipientBundleCompiler: Send + Sync {
    /// Compiles or previews the exact persisted target plan under attenuated recipient authority.
    fn compile_recipient_bundle(
        &self,
        request: RecipientCompilationRequest,
        cancellation: &StoreCancellationToken,
    ) -> Result<RecipientBundleReceipt, SpaceHandoffDependencyError>;
}

/// Plans semantic parent resource keys for one retained child result.
pub trait HandoffResultMergePlanner: Send + Sync {
    /// Produces one unique mapping for every mergeable child version.
    fn plan_mappings(
        &self,
        context: &cigar_api::RequestContext,
        identity: &ResolvedDomainIdentity,
        authorization: &CurrentSpaceHandoffAuthorization,
        material: &HandoffMergeMaterial,
    ) -> Result<Vec<ResultMergeMapping>, SpaceHandoffDependencyError>;
}

/// Immutable catalog reference proven to exist, match its semantic kind, and remain visible in
/// the exact target project under the current policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHandoffReference {
    /// Exact immutable version resolved from the repository.
    pub version_id: VersionId,
    /// Semantic kind proven from repository metadata.
    pub kind: ResultMergeKind,
    /// Content digest bound to the resolved immutable record.
    pub content_digest: ContentDigest,
}

/// Repository-backed semantic authority for opaque handoff and conflict references.
pub trait HandoffReferenceResolver: Send + Sync {
    /// Resolves and reauthorizes one exact immutable reference without disclosing absence.
    #[allow(clippy::too_many_arguments)]
    fn resolve_reference(
        &self,
        context: &cigar_api::RequestContext,
        identity: &ResolvedDomainIdentity,
        authorization: &CurrentSpaceHandoffAuthorization,
        project_id: &RecordId,
        version_id: &VersionId,
        expected_kind: ResultMergeKind,
        cancellation: &StoreCancellationToken,
    ) -> Result<ResolvedHandoffReference, SpaceHandoffDependencyError>;
}

/// Server-owned source of clocks, UUIDv7 identities, and replay-protection nonces.
pub trait SpaceHandoffValueSource: Send + Sync {
    /// Returns the current protocol timestamp.
    fn now(&self) -> Result<UtcTimestamp, SpaceHandoffDependencyError>;
    /// Allocates one globally unique protocol record identity.
    fn record_id(&self) -> Result<RecordId, SpaceHandoffDependencyError>;
    /// Allocates one unpredictable bounded handoff nonce.
    fn nonce(&self) -> Result<Vec<u8>, SpaceHandoffDependencyError>;
}

/// Production value source backed by the daemon clock, monotonic UUIDv7, and OS randomness.
pub struct SystemSpaceHandoffValueSource {
    clock: Arc<dyn AuthorityClock>,
    ids: MonotonicUuidV7Generator,
}

impl SystemSpaceHandoffValueSource {
    /// Creates a trusted value source around the daemon's wall-clock authority.
    #[must_use]
    pub fn new(clock: Arc<dyn AuthorityClock>) -> Self {
        Self {
            clock,
            ids: MonotonicUuidV7Generator::default(),
        }
    }
}

impl SpaceHandoffValueSource for SystemSpaceHandoffValueSource {
    fn now(&self) -> Result<UtcTimestamp, SpaceHandoffDependencyError> {
        self.clock
            .now()
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)
    }

    fn record_id(&self) -> Result<RecordId, SpaceHandoffDependencyError> {
        let generated = self
            .ids
            .generate()
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
        RecordId::new(generated.to_string()).map_err(|_error| SpaceHandoffDependencyError::Invalid)
    }

    fn nonce(&self) -> Result<Vec<u8>, SpaceHandoffDependencyError> {
        let mut nonce = vec![0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
        Ok(nonce)
    }
}

impl fmt::Debug for SystemSpaceHandoffValueSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemSpaceHandoffValueSource([TRUSTED])")
    }
}

/// Tenant-scoped durable services shared by every adapter for that tenant.
#[derive(Clone)]
pub struct TenantSpaceHandoffServices {
    /// Root-last durable context-space state.
    pub spaces: Arc<DurableContextSpaceService>,
    /// Root-last durable signed-handoff state.
    pub handoffs: Arc<DurableHandoffService>,
}

impl fmt::Debug for TenantSpaceHandoffServices {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantSpaceHandoffServices([DURABLE])")
    }
}

/// Opens or returns one shared durable service pair for a resolved tenant partition.
pub trait SpaceHandoffStateProvider: Send + Sync {
    /// Returns services that are never shared across different resolved tenant IDs.
    fn services(
        &self,
        tenant_id: &RecordId,
        cancellation: &StoreCancellationToken,
    ) -> Result<TenantSpaceHandoffServices, DurableStateError>;
}

/// Bounded production cache of repository-backed tenant services.
pub struct RepositorySpaceHandoffStateProvider {
    repository: Arc<dyn ServiceRepository>,
    key_provider: Arc<dyn KeyProvider>,
    snapshot_authenticator: Arc<dyn DurableSnapshotAuthenticator>,
    maximum_tenants: usize,
    tenants: Mutex<BTreeMap<RecordId, TenantSpaceHandoffServices>>,
}

impl RepositorySpaceHandoffStateProvider {
    /// Creates a shared per-process tenant cache with an explicit nonzero bound.
    pub fn new_authenticated(
        repository: Arc<dyn ServiceRepository>,
        key_provider: Arc<dyn KeyProvider>,
        snapshot_authenticator: Arc<dyn DurableSnapshotAuthenticator>,
        maximum_tenants: usize,
    ) -> Result<Self, SpaceHandoffDependencyError> {
        if maximum_tenants == 0 {
            return Err(SpaceHandoffDependencyError::Invalid);
        }
        Ok(Self {
            repository,
            key_provider,
            snapshot_authenticator,
            maximum_tenants,
            tenants: Mutex::new(BTreeMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        repository: Arc<dyn ServiceRepository>,
        key_provider: Arc<dyn KeyProvider>,
        maximum_tenants: usize,
    ) -> Result<Self, SpaceHandoffDependencyError> {
        Self::new_authenticated(
            repository,
            key_provider,
            crate::test_snapshot_authenticator(),
            maximum_tenants,
        )
    }
}

impl SpaceHandoffStateProvider for RepositorySpaceHandoffStateProvider {
    fn services(
        &self,
        tenant_id: &RecordId,
        cancellation: &StoreCancellationToken,
    ) -> Result<TenantSpaceHandoffServices, DurableStateError> {
        let mut tenants = self
            .tenants
            .lock()
            .map_err(|_error| DurableStateError::unavailable())?;
        if let Some(services) = tenants.get(tenant_id) {
            return Ok(services.clone());
        }
        if tenants.len() >= self.maximum_tenants {
            return Err(DurableStateError::unavailable());
        }
        let services = TenantSpaceHandoffServices {
            spaces: Arc::new(DurableContextSpaceService::open_authenticated(
                self.repository.clone(),
                self.snapshot_authenticator.clone(),
                tenant_id.clone(),
                cancellation,
            )?),
            handoffs: Arc::new(DurableHandoffService::open_authenticated(
                self.repository.clone(),
                self.snapshot_authenticator.clone(),
                tenant_id.clone(),
                self.key_provider.clone(),
                cancellation,
            )?),
        };
        tenants.insert(tenant_id.clone(), services.clone());
        Ok(services)
    }
}

impl fmt::Debug for RepositorySpaceHandoffStateProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositorySpaceHandoffStateProvider")
            .field("repository", &"[INJECTED]")
            .field("key_provider", &"[INJECTED]")
            .field("snapshot_authenticator", &"[INJECTED]")
            .field("maximum_tenants", &self.maximum_tenants)
            .finish_non_exhaustive()
    }
}

/// Complete real typed implementation of all eight space and six handoff operations.
pub struct SpaceHandoffApplication {
    states: Arc<dyn SpaceHandoffStateProvider>,
    identities: Arc<dyn DomainIdentityResolver>,
    authorizer: Arc<dyn SpaceHandoffAuthorizer>,
    compiler: Arc<dyn RecipientBundleCompiler>,
    merge_planner: Arc<dyn HandoffResultMergePlanner>,
    references: Arc<dyn HandoffReferenceResolver>,
    values: Arc<dyn SpaceHandoffValueSource>,
    cursors: Arc<CursorCodec>,
    errors: Arc<dyn FacadeErrorFactory>,
    cursor_ttl: Duration,
    stream_poll_interval: Duration,
    telemetry: Option<Arc<DaemonTelemetry>>,
}

impl SpaceHandoffApplication {
    /// Constructs the application boundary from concrete durable and authority dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        states: Arc<dyn SpaceHandoffStateProvider>,
        identities: Arc<dyn DomainIdentityResolver>,
        authorizer: Arc<dyn SpaceHandoffAuthorizer>,
        compiler: Arc<dyn RecipientBundleCompiler>,
        merge_planner: Arc<dyn HandoffResultMergePlanner>,
        references: Arc<dyn HandoffReferenceResolver>,
        values: Arc<dyn SpaceHandoffValueSource>,
        cursors: Arc<CursorCodec>,
        errors: Arc<dyn FacadeErrorFactory>,
        cursor_ttl: Duration,
        stream_poll_interval: Duration,
    ) -> Result<Self, SpaceHandoffDependencyError> {
        if cursor_ttl.is_zero() || stream_poll_interval.is_zero() {
            return Err(SpaceHandoffDependencyError::Invalid);
        }
        Ok(Self {
            states,
            identities,
            authorizer,
            compiler,
            merge_planner,
            references,
            values,
            cursors,
            errors,
            cursor_ttl,
            stream_poll_interval,
            telemetry: None,
        })
    }

    /// Attaches the process telemetry authority used by production composition.
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Arc<DaemonTelemetry>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    fn invocation(
        &self,
        context: &cigar_api::RequestContext,
        scope: SpaceHandoffAuthorizationScope,
    ) -> Result<Invocation, ApiError> {
        let now = self.values.now().map_err(|error| self.dependency(error))?;
        context
            .check_active(now)
            .map_err(|_error| self.public(cigar_protocol::ErrorCode::DeadlineExceeded))?;
        let identity = self
            .identities
            .resolve(context)
            .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?;
        let cancellation = store_cancellation(context);
        let services = self
            .states
            .services(&identity.tenant_id, &cancellation)
            .map_err(|error| self.durable(error))?;
        self.authorized_invocation(context, now, identity, scope, cancellation, services)
    }

    fn invocation_for_space(
        &self,
        context: &cigar_api::RequestContext,
        space_id: ContextSpaceId,
    ) -> Result<Invocation, ApiError> {
        let now = self.values.now().map_err(|error| self.dependency(error))?;
        context
            .check_active(now)
            .map_err(|_error| self.public(cigar_protocol::ErrorCode::DeadlineExceeded))?;
        let identity = self
            .identities
            .resolve(context)
            .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?;
        let cancellation = store_cancellation(context);
        let services = self
            .states
            .services(&identity.tenant_id, &cancellation)
            .map_err(|error| self.durable(error))?;
        let project_id = services
            .spaces
            .active_project_id(&space_id)
            .map_err(|error| self.existing_space_binding(error))?;
        let scope = SpaceHandoffAuthorizationScope::Space {
            space_id,
            project_id,
        };
        self.authorized_invocation(context, now, identity, scope, cancellation, services)
    }

    fn invocation_for_handoff_merge(
        &self,
        context: &cigar_api::RequestContext,
        handoff_id: RecordId,
        space_id: ContextSpaceId,
    ) -> Result<Invocation, ApiError> {
        let now = self.values.now().map_err(|error| self.dependency(error))?;
        context
            .check_active(now)
            .map_err(|_error| self.public(cigar_protocol::ErrorCode::DeadlineExceeded))?;
        let identity = self
            .identities
            .resolve(context)
            .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?;
        let cancellation = store_cancellation(context);
        let services = self
            .states
            .services(&identity.tenant_id, &cancellation)
            .map_err(|error| self.durable(error))?;
        let project_id = services
            .spaces
            .active_project_id(&space_id)
            .map_err(|error| self.existing_space_binding(error))?;
        let scope = SpaceHandoffAuthorizationScope::HandoffMerge {
            handoff_id,
            space_id,
            project_id,
        };
        self.authorized_invocation(context, now, identity, scope, cancellation, services)
    }

    #[allow(clippy::too_many_arguments)]
    fn authorized_invocation(
        &self,
        context: &cigar_api::RequestContext,
        now: UtcTimestamp,
        identity: ResolvedDomainIdentity,
        scope: SpaceHandoffAuthorizationScope,
        cancellation: StoreCancellationToken,
        services: TenantSpaceHandoffServices,
    ) -> Result<Invocation, ApiError> {
        let authorization = self
            .authorizer
            .authorize(context, &identity, &scope, now)
            .map_err(|error| self.authorization(error))?;
        validate_authorization(&identity, &scope, &authorization, now)
            .map_err(|error| self.authorization(error))?;
        Ok(Invocation {
            now,
            identity,
            authorization,
            scope,
            cancellation,
            services,
        })
    }

    fn existing_space_binding(&self, error: DurableStateError) -> ApiError {
        match error.code() {
            DurableStateErrorCode::Space(SpaceError::NotFound | SpaceError::Forbidden) => {
                self.public(cigar_protocol::ErrorCode::PolicyDenied)
            }
            _ => self.durable(error),
        }
    }

    fn public(&self, code: cigar_protocol::ErrorCode) -> ApiError {
        self.errors.public_error(code)
    }

    fn authorization(&self, error: DomainAuthorizationError) -> ApiError {
        self.public(match error {
            DomainAuthorizationError::Invalid => cigar_protocol::ErrorCode::InvalidCapability,
            DomainAuthorizationError::Denied => cigar_protocol::ErrorCode::PolicyDenied,
            DomainAuthorizationError::Unavailable => {
                cigar_protocol::ErrorCode::DependencyUnavailable
            }
        })
    }

    fn dependency(&self, error: SpaceHandoffDependencyError) -> ApiError {
        self.public(match error {
            SpaceHandoffDependencyError::Invalid => cigar_protocol::ErrorCode::InvalidArgument,
            SpaceHandoffDependencyError::Denied => cigar_protocol::ErrorCode::PolicyDenied,
            SpaceHandoffDependencyError::Unavailable => {
                cigar_protocol::ErrorCode::DependencyUnavailable
            }
        })
    }

    fn durable(&self, error: DurableStateError) -> ApiError {
        self.public(map_durable_error(error))
    }
}

impl fmt::Debug for SpaceHandoffApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpaceHandoffApplication")
            .field("states", &"[INJECTED]")
            .field("identities", &"[INJECTED]")
            .field("authorizer", &"[INJECTED]")
            .field("compiler", &"[INJECTED]")
            .field("merge_planner", &"[INJECTED]")
            .finish_non_exhaustive()
    }
}

struct Invocation {
    now: UtcTimestamp,
    identity: ResolvedDomainIdentity,
    authorization: CurrentSpaceHandoffAuthorization,
    scope: SpaceHandoffAuthorizationScope,
    cancellation: StoreCancellationToken,
    services: TenantSpaceHandoffServices,
}

impl TypedUnaryService<CreateSpaceOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::CreateSpaceRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ContextCommit>, ApiError>> {
        Box::pin(async move {
            let invocation = self.invocation(
                &context,
                SpaceHandoffAuthorizationScope::NewSpace {
                    project_id: request.payload.project_id.clone(),
                },
            )?;
            let space_record = self
                .values
                .record_id()
                .map_err(|error| self.dependency(error))?;
            let space_id = ContextSpaceId::new(space_record.as_str().to_owned())
                .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?;
            let domain = DomainCreateSpaceRequest {
                space_id,
                hierarchy: SpaceHierarchy {
                    tenant_id: invocation.identity.tenant_id,
                    workspace_id: request.payload.workspace_id,
                    active_project_id: request.payload.project_id,
                    branch_id: request.payload.branch_id,
                    task_id: request.payload.task_id,
                    session_id: request.payload.session_id,
                },
                author_id: invocation.identity.principal_id,
                purpose: request.payload.purpose,
                policy_snapshot_digest: invocation.authorization.policy_digest,
                committed_at: invocation.now,
                event_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
            };
            let commit = if request.metadata.dry_run() {
                invocation
                    .services
                    .spaces
                    .simulate(move |service| service.create_space(domain))
            } else {
                invocation
                    .services
                    .spaces
                    .create_space(domain, &invocation.cancellation)
            }
            .map_err(|error| self.durable(error))?;
            let revision = commit.sequence;
            Ok(revision_response(commit, revision))
        })
    }
}

impl TypedUnaryService<ForkSpaceOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::ForkSpaceRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<SpaceForkResponse>, ApiError>> {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let response = match request.payload.fork {
                SpaceFork::PrivateOverlay {
                    base_commit_id,
                    ttl_seconds,
                } => {
                    let overlay_id = self
                        .values
                        .record_id()
                        .map_err(|error| self.dependency(error))?;
                    let overlay = Overlay {
                        schema_version: SchemaVersion::new("cigar.overlay", 1)
                            .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?,
                        overlay_id: overlay_id.clone(),
                        space_id: request.payload.space_id.clone(),
                        base_commit_id: base_commit_id.clone(),
                        owner_id: invocation.identity.principal_id,
                        created_at: invocation.now,
                        expires_at: add_seconds(invocation.now, ttl_seconds)
                            .map_err(|error| self.dependency(error))?,
                        mutations: Vec::new(),
                        extensions: ExtensionMap::default(),
                    };
                    if request.metadata.dry_run() {
                        invocation.services.spaces.simulate(move |service| {
                            service.create_overlay_at_revision(overlay, expected)
                        })
                    } else {
                        invocation.services.spaces.create_overlay_at_revision(
                            overlay,
                            expected,
                            &invocation.cancellation,
                        )
                    }
                    .map_err(|error| self.durable(error))?;
                    SpaceForkResponse::PrivateOverlay {
                        overlay_id,
                        base_commit_id,
                    }
                }
                SpaceFork::FocusBranch {
                    focus_id,
                    label,
                    offline,
                } => {
                    let branch = if request.metadata.dry_run() {
                        let space_id = request.payload.space_id.clone();
                        invocation.services.spaces.simulate(move |service| {
                            service.fork_focus_at_revision(
                                &space_id, focus_id, label, offline, expected,
                            )
                        })
                    } else {
                        invocation.services.spaces.fork_focus_at_revision(
                            &request.payload.space_id,
                            focus_id,
                            label,
                            offline,
                            expected,
                            &invocation.cancellation,
                        )
                    }
                    .map_err(|error| self.durable(error))?;
                    SpaceForkResponse::FocusBranch {
                        focus_id: branch.branch_id,
                        fork_commit_id: branch.fork_commit_id,
                    }
                }
            };
            Ok(revision_response(response, expected.0))
        })
    }
}

impl TypedUnaryService<PublishSpaceOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::PublishSpaceRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<SpacePublishResponse>, ApiError>> {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let publish = PublishRequest {
                expected_head: expected,
                actor_id: invocation.identity.principal_id.clone(),
                purpose: request.payload.purpose,
                policy_snapshot_digest: invocation.authorization.policy_digest,
                committed_at: invocation.now,
                event_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
            };
            let (outcome, conflict_ids) = if request.metadata.dry_run() {
                let space_id = request.payload.space_id.clone();
                let overlay_id = request.payload.overlay_id.clone();
                let actor_id = invocation.identity.principal_id;
                invocation
                    .services
                    .spaces
                    .simulate(move |service| {
                        let outcome = service.publish(&space_id, &overlay_id, publish)?;
                        let conflicts = publication_conflict_ids(
                            service.list_conflicts(&space_id, &actor_id)?,
                            &overlay_id,
                        );
                        Ok((outcome, conflicts))
                    })
                    .map_err(|error| self.durable(error))?
            } else {
                let outcome = invocation
                    .services
                    .spaces
                    .publish(
                        &request.payload.space_id,
                        &request.payload.overlay_id,
                        publish,
                        &invocation.cancellation,
                    )
                    .map_err(|error| self.durable(error))?;
                let conflicts = publication_conflict_ids(
                    invocation
                        .services
                        .spaces
                        .list_conflicts(
                            &request.payload.space_id,
                            &invocation.identity.principal_id,
                        )
                        .map_err(|error| self.durable(error))?,
                    &request.payload.overlay_id,
                );
                (outcome, conflicts)
            };
            let response = space_publish_response(outcome, conflict_ids)
                .map_err(|error| self.dependency(error))?;
            let revision = match &response {
                SpacePublishResponse::Published { commit }
                | SpacePublishResponse::Deduplicated { commit } => commit.sequence,
                SpacePublishResponse::Conflicted { .. } => expected.0,
            };
            Ok(revision_response(response, revision))
        })
    }
}

impl TypedUnaryService<GetSpaceLogOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<SpaceIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<SpaceLogResponse>, ApiError>> {
        Box::pin(async move {
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let commits = invocation
                .services
                .spaces
                .log(&request.payload.space_id)
                .map_err(|error| self.durable(error))?;
            let scope = cursor_scope(
                &context,
                b"CIGAR-SPACE-LOG\0v1\0",
                &request.payload.space_id,
            )
            .map_err(|error| self.dependency(error))?;
            let (start, total, pinned_head, expires_at) = match request.metadata.page_cursor() {
                Some(encoded) => {
                    let cursor =
                        decode_wire_cursor(encoded).map_err(|error| self.dependency(error))?;
                    let claims =
                        self.cursors
                            .open(&cursor, &scope, invocation.now)
                            .map_err(|_error| {
                                self.public(cigar_protocol::ErrorCode::InvalidArgument)
                            })?;
                    let (start, total, head) = decode_log_position(claims.position())
                        .map_err(|error| self.dependency(error))?;
                    (start, total, head, claims.expires_at())
                }
                None => {
                    let head = commits
                        .last()
                        .ok_or_else(|| self.public(cigar_protocol::ErrorCode::IntegrityFailure))?
                        .commit_id
                        .clone();
                    (
                        0,
                        commits.len(),
                        head,
                        add_duration(invocation.now, self.cursor_ttl)
                            .map_err(|error| self.dependency(error))?,
                    )
                }
            };
            validate_pinned_log(&commits, start, total, &pinned_head)
                .map_err(|error| self.dependency(error))?;
            let page_size = requested_page_size(&request);
            let end = start.saturating_add(page_size).min(total);
            let next_page_cursor = if end < total {
                let position = encode_log_position(end, total, &pinned_head)
                    .map_err(|error| self.dependency(error))?;
                let cursor = self
                    .cursors
                    .seal(&scope, &position, expires_at)
                    .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?;
                Some(encode_wire_cursor(&cursor).map_err(|error| self.dependency(error))?)
            } else {
                None
            };
            let page_commits = commits
                .get(start..end)
                .ok_or_else(|| self.public(cigar_protocol::ErrorCode::Internal))?
                .to_vec();
            Ok(TypedResponse {
                payload: SpaceLogResponse {
                    commits: page_commits,
                },
                semantic_etag: Some(format!("\"{}\"", pinned_head.as_str())),
                next_page_cursor,
            })
        })
    }
}

impl TypedUnaryService<CreateSpaceCheckpointOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<CheckpointSpaceRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<SpaceCheckpointResponse>, ApiError>>
    {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let branch = if request.metadata.dry_run() {
                let space_id = request.payload.space_id.clone();
                let focus_id = request.payload.focus_id.clone();
                invocation.services.spaces.simulate(move |service| {
                    service.checkpoint_focus_at_revision(&space_id, &focus_id, expected)
                })
            } else {
                invocation.services.spaces.checkpoint_focus_at_revision(
                    &request.payload.space_id,
                    &request.payload.focus_id,
                    expected,
                    &invocation.cancellation,
                )
            }
            .map_err(|error| self.durable(error))?;
            let commit_id = branch
                .checkpoint_commit_id
                .ok_or_else(|| self.public(cigar_protocol::ErrorCode::Internal))?;
            Ok(revision_response(
                SpaceCheckpointResponse {
                    focus_id: branch.branch_id,
                    commit_id,
                },
                expected.0,
            ))
        })
    }
}

impl TypedUnaryService<ListSpaceConflictsOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<SpaceIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ConflictListResponse>, ApiError>> {
        Box::pin(async move {
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let mut conflicts = invocation
                .services
                .spaces
                .list_conflicts(&request.payload.space_id, &invocation.identity.principal_id)
                .map_err(|error| self.durable(error))?;
            conflicts.sort_by(|left, right| left.conflict_id.cmp(&right.conflict_id));
            let generation = invocation
                .services
                .spaces
                .generation()
                .map_err(|error| self.durable(error))?;
            let digest = conflict_set_digest(&conflicts).map_err(|error| self.dependency(error))?;
            let scope = cursor_scope(
                &context,
                b"CIGAR-SPACE-CONFLICTS\0v1\0",
                &request.payload.space_id,
            )
            .map_err(|error| self.dependency(error))?;
            let (start, total, expires_at) =
                match request.metadata.page_cursor() {
                    Some(encoded) => {
                        let cursor =
                            decode_wire_cursor(encoded).map_err(|error| self.dependency(error))?;
                        let claims = self.cursors.open(&cursor, &scope, invocation.now).map_err(
                            |_error| self.public(cigar_protocol::ErrorCode::InvalidArgument),
                        )?;
                        let (start, total, pinned_generation, pinned_digest) =
                            decode_conflict_position(claims.position())
                                .map_err(|error| self.dependency(error))?;
                        if pinned_generation != generation || pinned_digest != digest {
                            return Err(self.public(cigar_protocol::ErrorCode::RevisionConflict));
                        }
                        (start, total, claims.expires_at())
                    }
                    None => (
                        0,
                        conflicts.len(),
                        add_duration(invocation.now, self.cursor_ttl)
                            .map_err(|error| self.dependency(error))?,
                    ),
                };
            if total != conflicts.len() || start > total {
                return Err(self.public(cigar_protocol::ErrorCode::RevisionConflict));
            }
            let end = start
                .saturating_add(requested_page_size(&request))
                .min(total);
            let mut base_by_overlay: BTreeMap<RecordId, VersionId> = BTreeMap::new();
            let mut summaries = Vec::with_capacity(end.saturating_sub(start));
            let page_conflicts = conflicts
                .get(start..end)
                .ok_or_else(|| self.public(cigar_protocol::ErrorCode::Internal))?;
            for conflict in page_conflicts {
                let base_commit_id = if let Some(base) = base_by_overlay.get(&conflict.overlay_id) {
                    base.clone()
                } else {
                    let view = invocation
                        .services
                        .spaces
                        .view(
                            &request.payload.space_id,
                            &invocation.identity.principal_id,
                            Some(&conflict.overlay_id),
                        )
                        .map_err(|error| self.durable(error))?;
                    let overlay = view
                        .overlay
                        .ok_or_else(|| self.public(cigar_protocol::ErrorCode::Internal))?;
                    base_by_overlay
                        .insert(conflict.overlay_id.clone(), overlay.base_commit_id.clone());
                    overlay.base_commit_id
                };
                summaries.push(ConflictSummary {
                    conflict_id: conflict.conflict_id.clone(),
                    base_commit_id,
                    resolver: resolver_symbol(conflict.conflict.required_resolver).to_owned(),
                });
            }
            let next_page_cursor = if end < total {
                let position = encode_conflict_position(end, total, generation, &digest)
                    .map_err(|error| self.dependency(error))?;
                let cursor = self
                    .cursors
                    .seal(&scope, &position, expires_at)
                    .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?;
                Some(encode_wire_cursor(&cursor).map_err(|error| self.dependency(error))?)
            } else {
                None
            };
            Ok(TypedResponse {
                payload: ConflictListResponse {
                    conflicts: summaries,
                },
                semantic_etag: Some(format!("\"{}\"", digest.as_str())),
                next_page_cursor,
            })
        })
    }
}

impl TypedUnaryService<ResolveSpaceConflictOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::ResolveSpaceConflictRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ConflictResolutionResponse>, ApiError>>
    {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let stored = invocation
                .services
                .spaces
                .list_conflicts(&request.payload.space_id, &invocation.identity.principal_id)
                .map_err(|error| self.durable(error))?
                .into_iter()
                .find(|conflict| conflict.conflict_id == request.payload.conflict_id)
                .ok_or_else(|| self.public(cigar_protocol::ErrorCode::PolicyDenied))?;
            if let ConflictResolution::TypedDecision { decision_id } = &request.payload.resolution {
                let project_id =
                    invocation_project(&invocation).map_err(|error| self.dependency(error))?;
                let resolved = self
                    .references
                    .resolve_reference(
                        &context,
                        &invocation.identity,
                        &invocation.authorization,
                        project_id,
                        decision_id,
                        ResultMergeKind::Decision,
                        &invocation.cancellation,
                    )
                    .map_err(|error| self.dependency(error))?;
                if resolved.version_id != *decision_id || resolved.kind != ResultMergeKind::Decision
                {
                    return Err(self.public(cigar_protocol::ErrorCode::DependencyUnavailable));
                }
            }
            let (resolution, mut evidence) =
                conflict_resolution(&stored, &request.payload.resolution)
                    .map_err(|error| self.dependency(error))?;
            if let ConflictResolution::TypedDecision { decision_id } = &request.payload.resolution {
                evidence.push(decision_id.clone());
                evidence.sort();
                evidence.dedup();
            }
            let resolve = ResolveConflictRequest {
                expected_head: expected,
                actor_id: invocation.identity.principal_id.clone(),
                resolver: stored.conflict.required_resolver,
                resolution,
                evidence,
                policy_snapshot_digest: invocation.authorization.policy_digest.clone(),
                resolved_at: invocation.now,
            };
            let publish = PublishRequest {
                expected_head: expected,
                actor_id: invocation.identity.principal_id.clone(),
                purpose: "resolve space conflict".to_owned(),
                policy_snapshot_digest: invocation.authorization.policy_digest,
                committed_at: invocation.now,
                event_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
            };
            let (_receipt, outcome) = if request.metadata.dry_run() {
                let space_id = request.payload.space_id.clone();
                let conflict_id = request.payload.conflict_id.clone();
                invocation.services.spaces.simulate(move |service| {
                    let receipt = service.resolve_conflict(&space_id, &conflict_id, resolve)?;
                    let outcome = service.publish(&space_id, &receipt.overlay_id, publish)?;
                    Ok((receipt, outcome))
                })
            } else {
                invocation.services.spaces.resolve_conflict_and_publish(
                    &request.payload.space_id,
                    &request.payload.conflict_id,
                    resolve,
                    publish,
                    &invocation.cancellation,
                )
            }
            .map_err(|error| self.durable(error))?;
            let commit = match outcome {
                PublishOutcome::Published(commit) | PublishOutcome::Deduplicated(commit) => commit,
                PublishOutcome::Conflicted(_) => {
                    return Err(self.public(cigar_protocol::ErrorCode::UnresolvedCriticalConflict));
                }
            };
            let revision = commit.sequence;
            Ok(revision_response(
                ConflictResolutionResponse {
                    conflict_id: request.payload.conflict_id,
                    commit,
                },
                revision,
            ))
        })
    }
}

impl TypedUnaryService<CreateHandoffOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::CreateHandoffRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<CreateHandoffResponse>, ApiError>> {
        Box::pin(async move {
            let invocation =
                self.invocation(&context, SpaceHandoffAuthorizationScope::NewHandoff)?;
            if request.payload.audience != invocation.authorization.runtime_audience {
                return Err(self.public(cigar_protocol::ErrorCode::PolicyDenied));
            }
            let handoff_id = self
                .values
                .record_id()
                .map_err(|error| self.dependency(error))?;
            let domain = DomainCreateHandoffRequest {
                handoff_id,
                issuer_effective: invocation.authorization.effective.clone(),
                recipient: request.payload.recipient,
                task: request.payload.task,
                acceptance_criteria: request.payload.acceptance_criteria,
                requested_projects: request.payload.requested_projects.into_iter().collect(),
                requested_capabilities: request
                    .payload
                    .requested_capabilities
                    .into_iter()
                    .collect(),
                policy_allowed_projects: invocation.authorization.policy_allowed_projects.clone(),
                policy_allowed_capabilities: invocation
                    .authorization
                    .policy_allowed_capabilities
                    .clone(),
                budget: request.payload.budget,
                topics: request.payload.topics.into_iter().collect(),
                references: request.payload.references,
                bundle_id: request.payload.bundle_id,
                audience: request.payload.audience,
                created_at: invocation.now,
                expires_at: add_seconds(invocation.now, request.payload.ttl_seconds)
                    .map_err(|error| self.dependency(error))?,
                nonce: self
                    .values
                    .nonce()
                    .map_err(|error| self.dependency(error))?,
                reusable: request.payload.reusable,
                issuer_key_ref: invocation.authorization.issuer_key_ref,
            };
            let (capsule, preview) = if request.metadata.dry_run() {
                invocation
                    .services
                    .handoffs
                    .simulate(move |service| service.create(domain))
            } else {
                invocation
                    .services
                    .handoffs
                    .create(domain, &invocation.cancellation)
            }
            .map_err(|error| self.durable(error))?;
            let preview_handoff_id = capsule.handoff_id.clone();
            Ok(revision_response(
                CreateHandoffResponse {
                    capsule,
                    preview: handoff_preview(preview_handoff_id, preview)
                        .map_err(|error| self.dependency(error))?,
                },
                1,
            ))
        })
    }
}

impl TypedUnaryService<PreviewHandoffOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<HandoffIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<HandoffPreviewResponse>, ApiError>> {
        Box::pin(async move {
            let invocation = self.invocation(
                &context,
                SpaceHandoffAuthorizationScope::Handoff {
                    handoff_id: request.payload.handoff_id.clone(),
                },
            )?;
            let preview = invocation
                .services
                .handoffs
                .persisted_preview(
                    &request.payload.handoff_id,
                    &invocation.identity.principal_id,
                    &invocation.authorization.roles,
                )
                .map_err(|error| self.durable(error))?;
            let revision = invocation
                .services
                .handoffs
                .handoff_revision(
                    &request.payload.handoff_id,
                    &invocation.identity.principal_id,
                    &invocation.authorization.roles,
                )
                .map_err(|error| self.durable(error))?;
            Ok(revision_response(
                handoff_preview(request.payload.handoff_id, preview)
                    .map_err(|error| self.dependency(error))?,
                revision,
            ))
        })
    }
}

impl TypedUnaryService<AcceptHandoffOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::AcceptHandoffRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<HandoffAcceptance>, ApiError>> {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation = self.invocation(
                &context,
                SpaceHandoffAuthorizationScope::Handoff {
                    handoff_id: request.payload.handoff_id.clone(),
                },
            )?;
            let capsule = invocation
                .services
                .handoffs
                .persisted_capsule(
                    &request.payload.handoff_id,
                    &invocation.identity.principal_id,
                    &invocation.authorization.roles,
                )
                .map_err(|error| self.durable(error))?;
            let current_revision = invocation
                .services
                .handoffs
                .handoff_revision(
                    &request.payload.handoff_id,
                    &invocation.identity.principal_id,
                    &invocation.authorization.roles,
                )
                .map_err(|error| self.durable(error))?;
            if current_revision != expected.0 {
                return Err(self.public(cigar_protocol::ErrorCode::RevisionConflict));
            }
            let authorized_references =
                self.authorized_handoff_references(&context, &invocation, &capsule.references)?;
            let target_plan_id = request.payload.target_plan_id;
            let dry_run = request.metadata.dry_run();
            let compile_tenant = invocation.identity.tenant_id.clone();
            let compile_recipient = invocation.identity.principal_id.clone();
            let compile_policy = invocation.authorization.policy_digest.clone();
            let compile_now = invocation.now;
            let compile_handoff = capsule.handoff_id.clone();
            let compile_source_bundle = capsule.bundle_id.clone();
            let compile_cancellation = invocation.cancellation.clone();
            let domain = DomainAcceptHandoffRequest {
                capsule,
                expected_revision: expected,
                acceptance_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
                recipient_id: invocation.identity.principal_id,
                recipient_roles: invocation.authorization.roles,
                expected_audience: invocation.authorization.runtime_audience,
                tenant: invocation.identity.tenant_id.as_str().to_owned(),
                now: invocation.now,
                recipient_effective: invocation.authorization.effective,
                policy_allowed_capabilities: invocation.authorization.policy_allowed_capabilities,
                policy_digest: invocation.authorization.policy_digest,
                revoked_principals: invocation.authorization.revoked_principals,
                revoked_key_ids: invocation.authorization.revoked_key_ids,
                target_allowed: invocation.authorization.target_allowed,
                accepted_at: invocation.now,
            };
            let compile = |accepted: &AcceptedHandoffContext| {
                self.compiler
                    .compile_recipient_bundle(
                        RecipientCompilationRequest {
                            handoff_id: compile_handoff,
                            source_bundle_id: compile_source_bundle,
                            target_plan_id,
                            accepted: accepted.clone(),
                            tenant_id: compile_tenant,
                            recipient_id: compile_recipient,
                            policy_digest: compile_policy,
                            observed_at: compile_now,
                            dry_run,
                        },
                        &compile_cancellation,
                    )
                    .map_err(map_dependency_to_handoff)
            };
            let acceptance = if dry_run {
                invocation.services.handoffs.simulate(move |service| {
                    service.accept(
                        domain,
                        |reference| authorized_references.contains(reference),
                        compile,
                    )
                })
            } else {
                invocation.services.handoffs.accept(
                    domain,
                    |reference| authorized_references.contains(reference),
                    compile,
                    &invocation.cancellation,
                )
            };
            let acceptance = match acceptance {
                Ok(acceptance) => acceptance,
                Err(error) => {
                    if let Some(outcome) = handoff_acceptance_metric_outcome(error)
                        && let Some(telemetry) = &self.telemetry
                    {
                        telemetry.record_handoff_acceptance(outcome);
                    }
                    return Err(self.durable(error));
                }
            };
            if let Some(telemetry) = &self.telemetry {
                telemetry.record_handoff_acceptance(HandoffAcceptanceOutcome::Accepted);
            }
            Ok(revision_response(acceptance, expected.0))
        })
    }
}

impl TypedUnaryService<RevokeHandoffOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::RevokeHandoffRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<MutationReceipt>, ApiError>> {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation = self.invocation(
                &context,
                SpaceHandoffAuthorizationScope::Handoff {
                    handoff_id: request.payload.handoff_id.clone(),
                },
            )?;
            let domain = DomainRevokeHandoffRequest {
                handoff_id: request.payload.handoff_id.clone(),
                expected_revision: expected,
                actor_id: invocation.identity.principal_id,
                policy_digest: invocation.authorization.policy_digest,
                reason_digest: request.payload.reason_digest,
                revoked_at: invocation.now,
                event_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
            };
            let revocation = if request.metadata.dry_run() {
                invocation
                    .services
                    .handoffs
                    .simulate(move |service| service.revoke(domain))
            } else {
                invocation
                    .services
                    .handoffs
                    .revoke(domain, &invocation.cancellation)
            }
            .map_err(|error| self.durable(error))?;
            let revision = revocation.revision;
            Ok(revision_response(
                MutationReceipt {
                    resource_id: revocation.handoff_id,
                    revision,
                    replayed: false,
                },
                revision,
            ))
        })
    }
}

impl TypedUnaryService<RecordHandoffResultOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::RecordHandoffResultRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ApiHandoffResultReceipt>, ApiError>>
    {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation = self.invocation(
                &context,
                SpaceHandoffAuthorizationScope::Handoff {
                    handoff_id: request.payload.handoff_id.clone(),
                },
            )?;
            let acceptance = invocation
                .services
                .handoffs
                .acceptance_for_result(
                    &request.payload.handoff_id,
                    &invocation.identity.principal_id,
                    &request.payload.base_commit_id,
                )
                .map_err(|error| self.durable(error))?;
            let delta_id = self
                .values
                .record_id()
                .map_err(|error| self.dependency(error))?;
            let delta = HandoffDelta {
                schema_version: SchemaVersion::new("cigar.handoff-delta", 1)
                    .map_err(|_error| self.public(cigar_protocol::ErrorCode::Internal))?,
                delta_id: delta_id.clone(),
                handoff_id: request.payload.handoff_id.clone(),
                base_commit_id: request.payload.base_commit_id,
                producer_id: invocation.identity.principal_id.clone(),
                claims: request.payload.claims,
                decisions: request.payload.decisions,
                artifacts: request.payload.artifacts,
                source_changes: request.payload.source_changes,
                verifier_receipts: request.payload.verifier_receipts,
                unresolved_questions: request.payload.unresolved_questions,
                blockers: request.payload.blockers,
                effect_references: request.payload.effect_references,
                requested_followup_capabilities: request.payload.requested_followup_capabilities,
                extensions: ExtensionMap::default(),
            };
            let domain = DomainRecordHandoffResultRequest {
                expected_revision: expected,
                acceptance_id: acceptance.acceptance_id,
                actor_id: invocation.identity.principal_id,
                current_project_ids: invocation.authorization.effective.project_ids,
                delta,
                event_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
            };
            let receipt = if request.metadata.dry_run() {
                invocation
                    .services
                    .handoffs
                    .simulate(move |service| service.record_result(domain))
            } else {
                invocation
                    .services
                    .handoffs
                    .record_result(domain, &invocation.cancellation)
            }
            .map_err(|error| self.durable(error))?;
            let revision = receipt.revision;
            Ok(revision_response(
                ApiHandoffResultReceipt {
                    delta_id,
                    handoff_id: request.payload.handoff_id,
                    result_digest: receipt.event.payload_digest,
                    revision,
                },
                revision,
            ))
        })
    }
}

impl TypedUnaryService<MergeHandoffOperation> for SpaceHandoffApplication {
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<cigar_api::MergeHandoffRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<HandoffMergeResponse>, ApiError>> {
        Box::pin(async move {
            let expected = expected_revision(&request, self.errors.as_ref())?;
            let invocation = self.invocation_for_handoff_merge(
                &context,
                request.payload.handoff_id.clone(),
                request.payload.space_id.clone(),
            )?;
            let head = invocation
                .services
                .spaces
                .head(&request.payload.space_id)
                .map_err(|error| self.durable(error))?;
            if head.sequence != expected.0 {
                return Err(self.public(cigar_protocol::ErrorCode::RevisionConflict));
            }
            let material = invocation
                .services
                .handoffs
                .verified_merge_material(
                    &request.payload.delta_id,
                    &invocation.identity.principal_id,
                    invocation.identity.tenant_id.as_str(),
                    &invocation.authorization.revoked_principals,
                    &invocation.authorization.revoked_key_ids,
                )
                .map_err(|error| self.durable(error))?;
            if material.capsule.handoff_id != request.payload.handoff_id {
                return Err(self.public(cigar_protocol::ErrorCode::PolicyDenied));
            }
            let resolved_merge_references =
                self.resolved_merge_references(&context, &invocation, &material)?;
            let mappings = self
                .merge_planner
                .plan_mappings(
                    &context,
                    &invocation.identity,
                    &invocation.authorization,
                    &material,
                )
                .map_err(|error| self.dependency(error))?;
            validate_merge_mappings(&material, &mappings)
                .map_err(|error| self.dependency(error))?;
            let authorized = self.authorized_merge_references(
                &context,
                &invocation,
                &material,
                &resolved_merge_references,
            )?;
            let publish = PublishRequest {
                expected_head: expected,
                actor_id: invocation.identity.principal_id.clone(),
                purpose: "merge retained handoff result".to_owned(),
                policy_snapshot_digest: invocation.authorization.policy_digest,
                committed_at: invocation.now,
                event_id: self
                    .values
                    .record_id()
                    .map_err(|error| self.dependency(error))?,
            };
            let expected_base = material.acceptance.bundle_id.clone();
            let (receipt, outcome, conflict_ids) = if request.metadata.dry_run() {
                let space_id = request.payload.space_id.clone();
                let overlay_id = request.payload.overlay_id.clone();
                let parent_id = invocation.identity.principal_id.clone();
                let capsule = material.capsule.clone();
                let acceptance = material.acceptance.clone();
                let delta = material.result.delta.clone();
                invocation.services.spaces.simulate(move |service| {
                    let receipt = merge_child_result(
                        service,
                        &space_id,
                        &overlay_id,
                        &parent_id,
                        &capsule,
                        &acceptance,
                        &delta,
                        &expected_base,
                        &mappings,
                        |version| authorized.contains(version),
                    )
                    .map_err(map_handoff_to_space)?;
                    let outcome = service.publish(&space_id, &overlay_id, publish)?;
                    let conflicts = publication_conflict_ids(
                        service.list_conflicts(&space_id, &parent_id)?,
                        &overlay_id,
                    );
                    Ok((receipt, outcome, conflicts))
                })
            } else {
                invocation.services.spaces.merge_child_result_and_publish(
                    &request.payload.space_id,
                    &request.payload.overlay_id,
                    &invocation.identity.principal_id,
                    &material.capsule,
                    &material.acceptance,
                    &material.result.delta,
                    &expected_base,
                    &mappings,
                    |version| authorized.contains(version),
                    publish,
                    &invocation.cancellation,
                )
            }
            .map_err(|error| self.durable(error))?;
            let commit = match outcome {
                PublishOutcome::Published(commit) | PublishOutcome::Deduplicated(commit) => {
                    Some(commit)
                }
                PublishOutcome::Conflicted(_) => None,
            };
            let revision = commit
                .as_ref()
                .map_or(expected.0, |published| published.sequence);
            if let Some(telemetry) = &self.telemetry {
                telemetry.record_handoff_merge_conflicts(
                    u64::try_from(conflict_ids.len()).unwrap_or(u64::MAX),
                );
            }
            Ok(revision_response(
                HandoffMergeResponse {
                    delta_id: receipt.delta_id,
                    proposed_versions: receipt.proposed_versions,
                    rejected_versions: receipt.rejected_versions,
                    conflict_ids,
                    commit,
                },
                revision,
            ))
        })
    }
}

impl SpaceHandoffApplication {
    fn authorized_handoff_references(
        &self,
        context: &cigar_api::RequestContext,
        invocation: &Invocation,
        references: &cigar_protocol::HandoffReferences,
    ) -> Result<BTreeSet<VersionId>, ApiError> {
        let mut authorized = BTreeSet::new();
        for version in handoff_reference_ids(references) {
            if self
                .authorizer
                .reference_authorized(
                    context,
                    &invocation.identity,
                    &invocation.scope,
                    &invocation.authorization.policy_digest,
                    version,
                    invocation.now,
                )
                .map_err(|error| self.authorization(error))?
            {
                authorized.insert(version.clone());
            }
        }
        Ok(authorized)
    }

    fn authorized_merge_references(
        &self,
        context: &cigar_api::RequestContext,
        invocation: &Invocation,
        material: &HandoffMergeMaterial,
        resolved_merge_references: &BTreeSet<VersionId>,
    ) -> Result<BTreeSet<VersionId>, ApiError> {
        let mut versions = BTreeSet::new();
        for version in handoff_reference_ids(&material.capsule.references) {
            versions.insert(version.clone());
        }
        for version in material
            .result
            .delta
            .claims
            .iter()
            .flat_map(|claim| claim.evidence.iter())
            .chain(&material.result.delta.verifier_receipts)
            .chain(&material.result.delta.effect_references)
        {
            versions.insert(version.clone());
        }
        let mut authorized = resolved_merge_references.clone();
        for version in versions {
            if self
                .authorizer
                .reference_authorized(
                    context,
                    &invocation.identity,
                    &invocation.scope,
                    &invocation.authorization.policy_digest,
                    &version,
                    invocation.now,
                )
                .map_err(|error| self.authorization(error))?
            {
                authorized.insert(version);
            }
        }
        Ok(authorized)
    }

    fn resolved_merge_references(
        &self,
        context: &cigar_api::RequestContext,
        invocation: &Invocation,
        material: &HandoffMergeMaterial,
    ) -> Result<BTreeSet<VersionId>, ApiError> {
        let project_id = invocation_project(invocation).map_err(|error| self.dependency(error))?;
        let mut resolved = BTreeSet::new();
        for (versions, kind) in [
            (&material.result.delta.decisions, ResultMergeKind::Decision),
            (&material.result.delta.artifacts, ResultMergeKind::Artifact),
            (
                &material.result.delta.source_changes,
                ResultMergeKind::SourceChange,
            ),
        ] {
            for version_id in versions {
                if !resolved.insert(version_id.clone()) {
                    return Err(self.public(cigar_protocol::ErrorCode::InvalidArgument));
                }
                let reference = self
                    .references
                    .resolve_reference(
                        context,
                        &invocation.identity,
                        &invocation.authorization,
                        project_id,
                        version_id,
                        kind,
                        &invocation.cancellation,
                    )
                    .map_err(|error| self.dependency(error))?;
                if reference.version_id != *version_id || reference.kind != kind {
                    return Err(self.public(cigar_protocol::ErrorCode::DependencyUnavailable));
                }
            }
        }
        Ok(resolved)
    }
}

impl TypedStreamService<SubscribeSpaceEventsOperation> for SpaceHandoffApplication {
    fn subscribe_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<SpaceIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedEventStream<SpaceEventPayload>, ApiError>> {
        Box::pin(async move {
            let invocation =
                self.invocation_for_space(&context, request.payload.space_id.clone())?;
            let cursor = match request.metadata.page_cursor() {
                Some(encoded) => {
                    let event_id = RecordId::new(encoded.to_owned()).map_err(|_error| {
                        self.public(cigar_protocol::ErrorCode::InvalidArgument)
                    })?;
                    invocation
                        .services
                        .spaces
                        .event_cursor_for_id(
                            &request.payload.space_id,
                            &invocation.authorization.visible_projects,
                            &event_id,
                        )
                        .map_err(|error| self.durable(error))?
                }
                None => EventCursor::default(),
            };
            let mut interval = tokio::time::interval(self.stream_poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let maximum_page = requested_page_size(&request).min(STREAM_BATCH_SIZE);
            Ok(Box::pin(SpaceEventStream {
                context,
                identity: invocation.identity,
                authorization_scope: invocation.scope,
                spaces: invocation.services.spaces,
                authorizer: self.authorizer.clone(),
                values: self.values.clone(),
                cursor,
                space_id: request.payload.space_id,
                maximum_page,
                interval,
                buffered: VecDeque::new(),
                errors: self.errors.clone(),
                ended: false,
            }) as TypedEventStream<SpaceEventPayload>)
        })
    }
}

struct SpaceEventStream {
    context: cigar_api::RequestContext,
    identity: ResolvedDomainIdentity,
    authorization_scope: SpaceHandoffAuthorizationScope,
    spaces: Arc<DurableContextSpaceService>,
    authorizer: Arc<dyn SpaceHandoffAuthorizer>,
    values: Arc<dyn SpaceHandoffValueSource>,
    cursor: EventCursor,
    space_id: ContextSpaceId,
    maximum_page: usize,
    interval: tokio::time::Interval,
    buffered: VecDeque<cigar_space::SpaceEvent>,
    errors: Arc<dyn FacadeErrorFactory>,
    ended: bool,
}

impl SpaceEventStream {
    fn fail(
        &mut self,
        code: cigar_protocol::ErrorCode,
    ) -> Poll<Option<Result<TypedEvent<SpaceEventPayload>, ApiError>>> {
        self.ended = true;
        Poll::Ready(Some(Err(self.errors.public_error(code))))
    }

    fn encode_event(&self, event: cigar_space::SpaceEvent) -> TypedEvent<SpaceEventPayload> {
        TypedEvent {
            event_id: event.event.event_id.as_str().to_owned(),
            payload: SpaceEventPayload {
                space_id: event.space_id,
                project_id: event.project_id,
                event: event.event,
            },
        }
    }
}

impl Stream for SpaceEventStream {
    type Item = Result<TypedEvent<SpaceEventPayload>, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if Pin::new(&mut self.interval).poll_tick(context).is_pending() {
            return Poll::Pending;
        }
        let now = match self.values.now() {
            Ok(now) => now,
            Err(_error) => return self.fail(cigar_protocol::ErrorCode::DependencyUnavailable),
        };
        if self.context.check_active(now).is_err() {
            return self.fail(cigar_protocol::ErrorCode::DeadlineExceeded);
        }
        let authorization = match self.authorizer.authorize(
            &self.context,
            &self.identity,
            &self.authorization_scope,
            now,
        ) {
            Ok(authorization) => authorization,
            Err(DomainAuthorizationError::Invalid | DomainAuthorizationError::Denied) => {
                return self.fail(cigar_protocol::ErrorCode::PolicyDenied);
            }
            Err(DomainAuthorizationError::Unavailable) => {
                return self.fail(cigar_protocol::ErrorCode::DependencyUnavailable);
            }
        };
        if validate_authorization(
            &self.identity,
            &self.authorization_scope,
            &authorization,
            now,
        )
        .is_err()
        {
            return self.fail(cigar_protocol::ErrorCode::PolicyDenied);
        }
        if let Some(event) = self.buffered.pop_front() {
            self.cursor = event.cursor;
            return Poll::Ready(Some(Ok(self.encode_event(event))));
        }
        let page = match self.spaces.poll_events(
            &self.space_id,
            &authorization.visible_projects,
            self.cursor,
            self.maximum_page,
        ) {
            Ok(page) => page,
            Err(error) => return self.fail(map_durable_error(error)),
        };
        self.buffered.extend(page.events);
        if let Some(event) = self.buffered.pop_front() {
            self.cursor = event.cursor;
            Poll::Ready(Some(Ok(self.encode_event(event))))
        } else {
            self.cursor = page.resume_cursor;
            let _pending_tick = Pin::new(&mut self.interval).poll_tick(context);
            Poll::Pending
        }
    }
}

/// Registers exactly the eight SpaceService and six HandoffService typed handlers.
pub fn register_space_handoff_handlers(
    builder: &mut ProductionApplicationBuilder,
    application: Arc<SpaceHandoffApplication>,
) -> Result<(), HandlerRegistryError> {
    builder.register_unary::<CreateSpaceOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<ForkSpaceOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<PublishSpaceOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<GetSpaceLogOperation, _>(Arc::clone(&application))?;
    builder.register_stream::<SubscribeSpaceEventsOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<CreateSpaceCheckpointOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<ListSpaceConflictsOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<ResolveSpaceConflictOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<CreateHandoffOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<PreviewHandoffOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<AcceptHandoffOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<RevokeHandoffOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<RecordHandoffResultOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<MergeHandoffOperation, _>(application)?;
    Ok(())
}

fn expected_revision<T>(
    request: &TypedRequest<T>,
    errors: &dyn FacadeErrorFactory,
) -> Result<ExpectedRevision, ApiError> {
    let raw = request
        .metadata
        .expected_revision()
        .ok_or_else(|| errors.public_error(cigar_protocol::ErrorCode::InvalidArgument))?;
    let normalized = match raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        Some(unquoted) => unquoted,
        None if !raw.starts_with('"') && !raw.ends_with('"') => raw,
        None => return Err(errors.public_error(cigar_protocol::ErrorCode::InvalidArgument)),
    };
    if normalized.is_empty()
        || (normalized.len() > 1 && normalized.starts_with('0'))
        || !normalized.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(errors.public_error(cigar_protocol::ErrorCode::InvalidArgument));
    }
    let revision = normalized
        .parse::<u64>()
        .map_err(|_error| errors.public_error(cigar_protocol::ErrorCode::InvalidArgument))?;
    Ok(ExpectedRevision(revision))
}

fn requested_page_size<T>(request: &TypedRequest<T>) -> usize {
    request
        .metadata
        .page_size()
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .min(MAX_PAGE_SIZE)
}

fn revision_response<T>(payload: T, revision: u64) -> TypedResponse<T> {
    TypedResponse {
        payload,
        semantic_etag: Some(format!("\"{revision}\"")),
        next_page_cursor: None,
    }
}

fn add_seconds(
    timestamp: UtcTimestamp,
    seconds: u32,
) -> Result<UtcTimestamp, SpaceHandoffDependencyError> {
    let nanos = i128::from(seconds)
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|delta| timestamp.unix_nanos().checked_add(delta))
        .ok_or(SpaceHandoffDependencyError::Invalid)?;
    UtcTimestamp::from_unix_nanos(nanos).map_err(|_error| SpaceHandoffDependencyError::Invalid)
}

fn add_duration(
    timestamp: UtcTimestamp,
    duration: Duration,
) -> Result<UtcTimestamp, SpaceHandoffDependencyError> {
    let nanos = i128::try_from(duration.as_nanos())
        .ok()
        .and_then(|delta| timestamp.unix_nanos().checked_add(delta))
        .ok_or(SpaceHandoffDependencyError::Invalid)?;
    UtcTimestamp::from_unix_nanos(nanos).map_err(|_error| SpaceHandoffDependencyError::Invalid)
}

fn validate_authorization(
    identity: &ResolvedDomainIdentity,
    scope: &SpaceHandoffAuthorizationScope,
    authorization: &CurrentSpaceHandoffAuthorization,
    now: UtcTimestamp,
) -> Result<(), DomainAuthorizationError> {
    let valid_roles = authorization.roles.len() <= 256
        && authorization
            .roles
            .iter()
            .all(|role| !role.is_empty() && role.len() <= 256 && !role.contains('\0'));
    let expected_project = match scope {
        SpaceHandoffAuthorizationScope::NewSpace { project_id }
        | SpaceHandoffAuthorizationScope::Space { project_id, .. }
        | SpaceHandoffAuthorizationScope::HandoffMerge { project_id, .. } => Some(project_id),
        SpaceHandoffAuthorizationScope::NewHandoff
        | SpaceHandoffAuthorizationScope::Handoff { .. } => None,
    };
    if authorization.effective.tenant != identity.tenant_id.as_str()
        || authorization.effective.subject_id != identity.principal_id
        || authorization.resource_project_id.as_ref() != expected_project
        || now >= authorization.effective.expires_at
        || authorization.runtime_audience.is_empty()
        || authorization.runtime_audience.len() > 256
        || authorization
            .runtime_audience
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || !valid_roles
        || !authorization
            .visible_projects
            .is_subset(&authorization.effective.project_ids)
    {
        Err(DomainAuthorizationError::Invalid)
    } else {
        Ok(())
    }
}

fn invocation_project(invocation: &Invocation) -> Result<&RecordId, SpaceHandoffDependencyError> {
    match &invocation.scope {
        SpaceHandoffAuthorizationScope::NewSpace { project_id }
        | SpaceHandoffAuthorizationScope::Space { project_id, .. }
        | SpaceHandoffAuthorizationScope::HandoffMerge { project_id, .. } => Ok(project_id),
        SpaceHandoffAuthorizationScope::NewHandoff
        | SpaceHandoffAuthorizationScope::Handoff { .. } => {
            Err(SpaceHandoffDependencyError::Invalid)
        }
    }
}

fn store_cancellation(context: &cigar_api::RequestContext) -> StoreCancellationToken {
    let cancellation = StoreCancellationToken::default();
    if context.cancellation().is_cancelled() {
        cancellation.cancel();
    }
    cancellation
}

fn map_durable_error(error: DurableStateError) -> cigar_protocol::ErrorCode {
    match error.code() {
        DurableStateErrorCode::Space(error) => map_space_error(error),
        DurableStateErrorCode::Handoff(error) => map_handoff_error(error),
        DurableStateErrorCode::Snapshot(snapshot) => match snapshot {
            crate::DurableSnapshotErrorCode::LimitExceeded => {
                cigar_protocol::ErrorCode::LimitExceeded
            }
            crate::DurableSnapshotErrorCode::RevisionConflict => {
                cigar_protocol::ErrorCode::RevisionConflict
            }
            crate::DurableSnapshotErrorCode::Cancelled => {
                cigar_protocol::ErrorCode::DeadlineExceeded
            }
            crate::DurableSnapshotErrorCode::InvalidSnapshot => {
                cigar_protocol::ErrorCode::IntegrityFailure
            }
            crate::DurableSnapshotErrorCode::InjectedAbort
            | crate::DurableSnapshotErrorCode::Unavailable => {
                cigar_protocol::ErrorCode::DependencyUnavailable
            }
        },
    }
}

const fn handoff_acceptance_metric_outcome(
    error: DurableStateError,
) -> Option<HandoffAcceptanceOutcome> {
    match error.code() {
        DurableStateErrorCode::Handoff(HandoffError::Expired) => {
            Some(HandoffAcceptanceOutcome::Expired)
        }
        DurableStateErrorCode::Handoff(HandoffError::Unavailable)
        | DurableStateErrorCode::Snapshot(_)
        | DurableStateErrorCode::Space(_) => None,
        DurableStateErrorCode::Handoff(_) => Some(HandoffAcceptanceOutcome::Rejected),
    }
}

const fn map_space_error(error: SpaceError) -> cigar_protocol::ErrorCode {
    match error {
        SpaceError::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        SpaceError::NotFound | SpaceError::Forbidden => cigar_protocol::ErrorCode::PolicyDenied,
        SpaceError::StaleRevision => cigar_protocol::ErrorCode::RevisionConflict,
        SpaceError::Conflict => cigar_protocol::ErrorCode::UnresolvedCriticalConflict,
        SpaceError::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        SpaceError::Integrity => cigar_protocol::ErrorCode::IntegrityFailure,
    }
}

const fn map_handoff_error(error: HandoffError) -> cigar_protocol::ErrorCode {
    match error {
        HandoffError::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        HandoffError::InvalidSignature => cigar_protocol::ErrorCode::IntegrityFailure,
        HandoffError::Forbidden => cigar_protocol::ErrorCode::PolicyDenied,
        HandoffError::Revoked => cigar_protocol::ErrorCode::InvalidCapability,
        HandoffError::Replay | HandoffError::RevisionConflict => {
            cigar_protocol::ErrorCode::RevisionConflict
        }
        HandoffError::Expired => cigar_protocol::ErrorCode::HandoffExpired,
        HandoffError::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        HandoffError::Unavailable => cigar_protocol::ErrorCode::DependencyUnavailable,
        HandoffError::Merge => cigar_protocol::ErrorCode::UnresolvedCriticalConflict,
    }
}

const fn map_dependency_to_handoff(error: SpaceHandoffDependencyError) -> HandoffError {
    match error {
        SpaceHandoffDependencyError::Invalid => HandoffError::InvalidInput,
        SpaceHandoffDependencyError::Denied => HandoffError::Forbidden,
        SpaceHandoffDependencyError::Unavailable => HandoffError::Unavailable,
    }
}

const fn map_handoff_to_space(error: HandoffError) -> SpaceError {
    match error {
        HandoffError::InvalidInput | HandoffError::InvalidSignature => SpaceError::InvalidInput,
        HandoffError::Forbidden | HandoffError::Revoked | HandoffError::Expired => {
            SpaceError::Forbidden
        }
        HandoffError::Replay | HandoffError::RevisionConflict | HandoffError::Merge => {
            SpaceError::Conflict
        }
        HandoffError::LimitExceeded => SpaceError::LimitExceeded,
        HandoffError::Unavailable => SpaceError::Integrity,
    }
}

fn publication_conflict_ids(
    conflicts: Vec<StoredMergeConflict>,
    overlay_id: &RecordId,
) -> Vec<RecordId> {
    let mut ids: Vec<_> = conflicts
        .into_iter()
        .filter(|conflict| &conflict.overlay_id == overlay_id)
        .map(|conflict| conflict.conflict_id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn space_publish_response(
    outcome: PublishOutcome,
    conflict_ids: Vec<RecordId>,
) -> Result<SpacePublishResponse, SpaceHandoffDependencyError> {
    match outcome {
        PublishOutcome::Published(commit) => Ok(SpacePublishResponse::Published { commit }),
        PublishOutcome::Deduplicated(commit) => Ok(SpacePublishResponse::Deduplicated { commit }),
        PublishOutcome::Conflicted(_) if !conflict_ids.is_empty() => {
            Ok(SpacePublishResponse::Conflicted { conflict_ids })
        }
        PublishOutcome::Conflicted(_) => Err(SpaceHandoffDependencyError::Unavailable),
    }
}

fn handoff_preview(
    handoff_id: RecordId,
    preview: cigar_space::HandoffCreationPreview,
) -> Result<HandoffPreviewResponse, SpaceHandoffDependencyError> {
    Ok(HandoffPreviewResponse {
        handoff_id,
        accepted_projects: preview.accepted_projects,
        rejected_projects: preview.rejected_projects,
        accepted_capabilities: preview.delegated_capabilities,
        rejected_capabilities: preview.rejected_capabilities,
        reference_count: u32::try_from(preview.reference_count)
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    })
}

const fn resolver_symbol(resolver: ResolverKind) -> &'static str {
    match resolver {
        ResolverKind::TypedDecision => "typed_decision",
        ResolverKind::ExactBase => "exact_base",
    }
}

fn conflict_resolution(
    stored: &StoredMergeConflict,
    choice: &ConflictResolution,
) -> Result<(OverlayMutation, Vec<VersionId>), SpaceHandoffDependencyError> {
    let resolution = match choice {
        ConflictResolution::Base => stored
            .conflict
            .base
            .clone()
            .ok_or(SpaceHandoffDependencyError::Invalid)?,
        ConflictResolution::Current => stored
            .conflict
            .current
            .clone()
            .ok_or(SpaceHandoffDependencyError::Invalid)?,
        ConflictResolution::Proposed => stored.conflict.proposed.clone(),
        ConflictResolution::TypedDecision { decision_id } => {
            if stored.conflict.required_resolver != ResolverKind::TypedDecision {
                return Err(SpaceHandoffDependencyError::Invalid);
            }
            OverlayMutation::Decision(decision_id.clone())
        }
    };
    Ok((resolution, stored.conflict.evidence.clone()))
}

fn validate_merge_mappings(
    material: &HandoffMergeMaterial,
    mappings: &[ResultMergeMapping],
) -> Result<(), SpaceHandoffDependencyError> {
    let mut expected = BTreeMap::new();
    for (versions, kind) in [
        (&material.result.delta.decisions, ResultMergeKind::Decision),
        (&material.result.delta.artifacts, ResultMergeKind::Artifact),
        (
            &material.result.delta.source_changes,
            ResultMergeKind::SourceChange,
        ),
    ] {
        for version in versions {
            if expected.insert(version.clone(), kind).is_some() {
                return Err(SpaceHandoffDependencyError::Invalid);
            }
        }
    }
    let mapped: BTreeMap<_, _> = mappings
        .iter()
        .map(|mapping| (mapping.version_id.clone(), mapping.kind))
        .collect();
    let keys: BTreeSet<_> = mappings
        .iter()
        .map(|mapping| mapping.resource_key.clone())
        .collect();
    if expected != mapped || mapped.len() != mappings.len() || keys.len() != mappings.len() {
        Err(SpaceHandoffDependencyError::Invalid)
    } else {
        Ok(())
    }
}

fn handoff_reference_ids(references: &cigar_protocol::HandoffReferences) -> Vec<&VersionId> {
    references
        .sources
        .iter()
        .chain(&references.states)
        .chain(&references.decisions)
        .chain(&references.artifacts)
        .chain(&references.uncertainties)
        .chain(&references.effects)
        .collect()
}

fn cursor_scope(
    context: &cigar_api::RequestContext,
    domain: &[u8],
    space_id: &ContextSpaceId,
) -> Result<CursorScope, SpaceHandoffDependencyError> {
    let query_digest = multihash_digest(&[domain, space_id.as_str().as_bytes()])?;
    let snapshot_digest = multihash_digest(&[
        b"CIGAR-SPACE-CURSOR-SCOPE\0v1\0",
        space_id.as_str().as_bytes(),
    ])?;
    Ok(CursorScope::new(
        context.identity().tenant().clone(),
        context.identity().principal().clone(),
        context.operation().clone(),
        query_digest,
        snapshot_digest,
    ))
}

fn multihash_digest(parts: &[&[u8]]) -> Result<ContentDigest, SpaceHandoffDependencyError> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
    }
    ContentDigest::new(encoded).map_err(|_error| SpaceHandoffDependencyError::Invalid)
}

fn decode_wire_cursor(encoded: &str) -> Result<PageCursor, SpaceHandoffDependencyError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    PageCursor::new(bytes).map_err(|_error| SpaceHandoffDependencyError::Invalid)
}

fn encode_wire_cursor(cursor: &PageCursor) -> Result<String, SpaceHandoffDependencyError> {
    if cursor.as_bytes().is_empty() {
        return Err(SpaceHandoffDependencyError::Invalid);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cursor.as_bytes()))
}

fn encode_log_position(
    start: usize,
    total: usize,
    head: &VersionId,
) -> Result<Vec<u8>, SpaceHandoffDependencyError> {
    let start = u64::try_from(start).map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    let total = u64::try_from(total).map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    let mut output = Vec::with_capacity(LOG_CURSOR_BYTES);
    output.extend_from_slice(&start.to_be_bytes());
    output.extend_from_slice(&total.to_be_bytes());
    output.extend_from_slice(head.as_str().as_bytes());
    if output.len() != LOG_CURSOR_BYTES {
        return Err(SpaceHandoffDependencyError::Invalid);
    }
    Ok(output)
}

fn decode_log_position(
    position: &[u8],
) -> Result<(usize, usize, VersionId), SpaceHandoffDependencyError> {
    if position.len() != LOG_CURSOR_BYTES {
        return Err(SpaceHandoffDependencyError::Invalid);
    }
    let start = u64::from_be_bytes(
        position
            .get(0..8)
            .ok_or(SpaceHandoffDependencyError::Invalid)?
            .try_into()
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    );
    let total = u64::from_be_bytes(
        position
            .get(8..16)
            .ok_or(SpaceHandoffDependencyError::Invalid)?
            .try_into()
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    );
    let head = std::str::from_utf8(
        position
            .get(16..)
            .ok_or(SpaceHandoffDependencyError::Invalid)?,
    )
    .map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    Ok((
        usize::try_from(start).map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
        usize::try_from(total).map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
        VersionId::new(head.to_owned()).map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    ))
}

fn validate_pinned_log(
    commits: &[ContextCommit],
    start: usize,
    total: usize,
    head: &VersionId,
) -> Result<(), SpaceHandoffDependencyError> {
    if total == 0
        || start > total
        || commits.len() < total
        || commits
            .get(total.saturating_sub(1))
            .is_none_or(|commit| &commit.commit_id != head)
    {
        Err(SpaceHandoffDependencyError::Invalid)
    } else {
        Ok(())
    }
}

fn conflict_set_digest(
    conflicts: &[StoredMergeConflict],
) -> Result<ContentDigest, SpaceHandoffDependencyError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-SPACE-CONFLICT-SET\0v1\0");
    for conflict in conflicts {
        hasher.update(conflict.conflict_id.as_str().as_bytes());
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
    }
    ContentDigest::new(encoded).map_err(|_error| SpaceHandoffDependencyError::Invalid)
}

fn encode_conflict_position(
    start: usize,
    total: usize,
    generation: u64,
    digest: &ContentDigest,
) -> Result<Vec<u8>, SpaceHandoffDependencyError> {
    let start = u64::try_from(start).map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    let total = u64::try_from(total).map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    let mut output = Vec::with_capacity(CONFLICT_CURSOR_BYTES);
    output.extend_from_slice(&start.to_be_bytes());
    output.extend_from_slice(&total.to_be_bytes());
    output.extend_from_slice(&generation.to_be_bytes());
    output.extend_from_slice(digest.as_str().as_bytes());
    if output.len() != CONFLICT_CURSOR_BYTES {
        return Err(SpaceHandoffDependencyError::Invalid);
    }
    Ok(output)
}

fn decode_conflict_position(
    position: &[u8],
) -> Result<(usize, usize, u64, ContentDigest), SpaceHandoffDependencyError> {
    if position.len() != CONFLICT_CURSOR_BYTES {
        return Err(SpaceHandoffDependencyError::Invalid);
    }
    let start = u64::from_be_bytes(
        position
            .get(0..8)
            .ok_or(SpaceHandoffDependencyError::Invalid)?
            .try_into()
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    );
    let total = u64::from_be_bytes(
        position
            .get(8..16)
            .ok_or(SpaceHandoffDependencyError::Invalid)?
            .try_into()
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    );
    let generation = u64::from_be_bytes(
        position
            .get(16..24)
            .ok_or(SpaceHandoffDependencyError::Invalid)?
            .try_into()
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    );
    let digest = std::str::from_utf8(
        position
            .get(24..)
            .ok_or(SpaceHandoffDependencyError::Invalid)?,
    )
    .map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
    Ok((
        usize::try_from(start).map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
        usize::try_from(total).map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
        generation,
        ContentDigest::new(digest.to_owned())
            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cigar_api::{
        AuthenticatedIdentity, CancellationToken, OperationId, OperationPayload, PathParameter,
        PrincipalId, RequestContext, RequestEnvelope, StreamOperationHandler, TenantId, TraceId,
        TypedOperation, TypedStreamAdapter, TypedUnaryAdapter, UnaryOperationHandler,
        decode_operation_payload, encode_operation_payload,
    };
    use cigar_crypto::{CreateKeyRequest, KeyAlgorithm, KeyPurpose, MemoryKeyProvider};
    use cigar_protocol::{
        Budget, CoordinationEvent, CoordinationEventKind, CoordinationTopic, HandoffReferences,
        LaneKind, RecipientSelector, ResultClaim,
    };
    use cigar_space::{ProposedMutation, ResourceKey};
    use cigar_store::InMemoryStore;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tokio_stream::StreamExt as _;

    type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    fn record(value: u64) -> TestResult<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn version(value: u64) -> TestResult<VersionId> {
        let digest: [u8; 32] = Sha256::digest(value.to_be_bytes()).into();
        let mut encoded = String::from("1220");
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(VersionId::new(encoded)?)
    }

    fn content(value: u64) -> TestResult<ContentDigest> {
        Ok(ContentDigest::new(version(value)?.as_str())?)
    }

    fn time(second: u8) -> TestResult<UtcTimestamp> {
        Ok(UtcTimestamp::parse_rfc3339(&format!(
            "2026-07-11T12:00:{second:02}Z"
        ))?)
    }

    struct Errors(RecordId);

    impl FacadeErrorFactory for Errors {
        fn public_error(&self, code: cigar_protocol::ErrorCode) -> ApiError {
            ApiError::new(code, self.0.clone())
        }
    }

    struct Identities {
        tenant: RecordId,
        issuer: RecordId,
        recipient: RecordId,
    }

    impl DomainIdentityResolver for Identities {
        fn resolve(
            &self,
            context: &RequestContext,
        ) -> Result<ResolvedDomainIdentity, crate::DomainIdentityError> {
            let principal_id = if context.identity().principal().as_str() == "issuer" {
                self.issuer.clone()
            } else {
                self.recipient.clone()
            };
            Ok(ResolvedDomainIdentity {
                tenant_id: self.tenant.clone(),
                principal_id,
            })
        }
    }

    struct Authorizer {
        tenant: RecordId,
        project: RecordId,
        issuer: RecordId,
        key_ref: KeyRef,
        deny: AtomicBool,
    }

    impl SpaceHandoffAuthorizer for Authorizer {
        fn authorize(
            &self,
            _context: &RequestContext,
            identity: &ResolvedDomainIdentity,
            scope: &SpaceHandoffAuthorizationScope,
            _now: UtcTimestamp,
        ) -> Result<CurrentSpaceHandoffAuthorization, DomainAuthorizationError> {
            if self.deny.load(Ordering::Acquire) {
                return Err(DomainAuthorizationError::Denied);
            }
            let capabilities = BTreeSet::from([
                Capability::ReadContext,
                Capability::CompileContext,
                Capability::WriteOverlay,
                Capability::PublishOverlay,
                Capability::CreateHandoff,
                Capability::AcceptHandoff,
                Capability::InvokeTool,
            ]);
            Ok(CurrentSpaceHandoffAuthorization {
                effective: EffectiveCapabilities {
                    tenant: self.tenant.as_str().to_owned(),
                    subject_id: identity.principal_id.clone(),
                    grant_id: if identity.principal_id == self.issuer {
                        record(901).map_err(|_error| DomainAuthorizationError::Invalid)?
                    } else {
                        record(902).map_err(|_error| DomainAuthorizationError::Invalid)?
                    },
                    capabilities,
                    project_ids: BTreeSet::from([self.project.clone()]),
                    processors: BTreeSet::from(["test-compiler".to_owned()]),
                    expires_at: time(50).map_err(|_error| DomainAuthorizationError::Invalid)?,
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
                policy_allowed_capabilities: BTreeSet::from([
                    Capability::ReadContext,
                    Capability::AcceptHandoff,
                ]),
                visible_projects: BTreeSet::from([self.project.clone()]),
                policy_digest: content(903).map_err(|_error| DomainAuthorizationError::Invalid)?,
                revoked_principals: BTreeSet::new(),
                revoked_key_ids: BTreeSet::new(),
                issuer_key_ref: self.key_ref.clone(),
                runtime_audience: "test-runtime".to_owned(),
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

    struct Compiler {
        bundle_id: VersionId,
        dry_runs: Mutex<Vec<bool>>,
    }

    impl RecipientBundleCompiler for Compiler {
        fn compile_recipient_bundle(
            &self,
            request: RecipientCompilationRequest,
            _cancellation: &StoreCancellationToken,
        ) -> Result<RecipientBundleReceipt, SpaceHandoffDependencyError> {
            self.dry_runs
                .lock()
                .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?
                .push(request.dry_run);
            let digest = ContentDigest::new(self.bundle_id.as_str().to_owned())
                .map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
            Ok(RecipientBundleReceipt {
                bundle_id: self.bundle_id.clone(),
                source_bundle_id: request.source_bundle_id,
                target_plan_id: request.target_plan_id,
                target_plan_revision: 1,
                target_plan_digest: digest.clone(),
                derivation_digest: digest,
            })
        }
    }

    struct MergePlanner;

    impl HandoffResultMergePlanner for MergePlanner {
        fn plan_mappings(
            &self,
            _context: &RequestContext,
            _identity: &ResolvedDomainIdentity,
            _authorization: &CurrentSpaceHandoffAuthorization,
            material: &HandoffMergeMaterial,
        ) -> Result<Vec<ResultMergeMapping>, SpaceHandoffDependencyError> {
            material
                .result
                .delta
                .decisions
                .iter()
                .map(|version| (version, ResultMergeKind::Decision))
                .chain(
                    material
                        .result
                        .delta
                        .artifacts
                        .iter()
                        .map(|version| (version, ResultMergeKind::Artifact)),
                )
                .chain(
                    material
                        .result
                        .delta
                        .source_changes
                        .iter()
                        .map(|version| (version, ResultMergeKind::SourceChange)),
                )
                .enumerate()
                .map(|(index, (version_id, kind))| {
                    Ok(ResultMergeMapping {
                        version_id: version_id.clone(),
                        kind,
                        resource_key: ResourceKey::new(format!("child-result-{index}"))
                            .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
                    })
                })
                .collect()
        }
    }

    struct ReferenceResolver {
        denied: Mutex<BTreeSet<VersionId>>,
    }

    impl HandoffReferenceResolver for ReferenceResolver {
        fn resolve_reference(
            &self,
            _context: &RequestContext,
            _identity: &ResolvedDomainIdentity,
            _authorization: &CurrentSpaceHandoffAuthorization,
            _project_id: &RecordId,
            version_id: &VersionId,
            expected_kind: ResultMergeKind,
            _cancellation: &StoreCancellationToken,
        ) -> Result<ResolvedHandoffReference, SpaceHandoffDependencyError> {
            if self
                .denied
                .lock()
                .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?
                .contains(version_id)
            {
                return Err(SpaceHandoffDependencyError::Denied);
            }
            Ok(ResolvedHandoffReference {
                version_id: version_id.clone(),
                kind: expected_kind,
                content_digest: ContentDigest::new(version_id.as_str().to_owned())
                    .map_err(|_error| SpaceHandoffDependencyError::Invalid)?,
            })
        }
    }

    struct Values {
        now: UtcTimestamp,
        next: AtomicU64,
    }

    impl SpaceHandoffValueSource for Values {
        fn now(&self) -> Result<UtcTimestamp, SpaceHandoffDependencyError> {
            Ok(self.now)
        }

        fn record_id(&self) -> Result<RecordId, SpaceHandoffDependencyError> {
            record(self.next.fetch_add(1, Ordering::Relaxed))
                .map_err(|_error| SpaceHandoffDependencyError::Unavailable)
        }

        fn nonce(&self) -> Result<Vec<u8>, SpaceHandoffDependencyError> {
            Ok(vec![7_u8; NONCE_BYTES])
        }
    }

    struct Fixture {
        application: Arc<SpaceHandoffApplication>,
        errors: Arc<dyn FacadeErrorFactory>,
        repository: Arc<InMemoryStore>,
        key_provider: Arc<MemoryKeyProvider>,
        tenant: RecordId,
        issuer: RecordId,
        recipient: RecordId,
        project: RecordId,
        compiler: Arc<Compiler>,
        authorizer: Arc<Authorizer>,
        references: Arc<ReferenceResolver>,
    }

    fn fixture() -> TestResult<Fixture> {
        let tenant = record(1)?;
        let issuer = record(2)?;
        let recipient = record(3)?;
        let project = record(4)?;
        let repository = Arc::new(InMemoryStore::default());
        let key_provider = Arc::new(MemoryKeyProvider::default());
        let key = key_provider.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: time(0)?.unix_nanos(),
            activated_at: time(0)?.unix_nanos(),
        })?;
        let states = Arc::new(RepositorySpaceHandoffStateProvider::new(
            repository.clone(),
            key_provider.clone(),
            8,
        )?);
        let identities = Arc::new(Identities {
            tenant: tenant.clone(),
            issuer: issuer.clone(),
            recipient: recipient.clone(),
        });
        let authorizer = Arc::new(Authorizer {
            tenant: tenant.clone(),
            project: project.clone(),
            issuer: issuer.clone(),
            key_ref: key.key_ref,
            deny: AtomicBool::new(false),
        });
        let compiler = Arc::new(Compiler {
            bundle_id: version(500)?,
            dry_runs: Mutex::new(Vec::new()),
        });
        let errors: Arc<dyn FacadeErrorFactory> = Arc::new(Errors(record(999)?));
        let references = Arc::new(ReferenceResolver {
            denied: Mutex::new(BTreeSet::new()),
        });
        let application = Arc::new(SpaceHandoffApplication::new(
            states,
            identities,
            authorizer.clone(),
            compiler.clone(),
            Arc::new(MergePlanner),
            references.clone(),
            Arc::new(Values {
                now: time(10)?,
                next: AtomicU64::new(10_000),
            }),
            Arc::new(CursorCodec::new(cigar_api::CursorSigningKey::new(
                vec![9_u8; 32],
            )?)),
            errors.clone(),
            Duration::from_secs(300),
            Duration::from_millis(10),
        )?);
        Ok(Fixture {
            application,
            errors,
            repository,
            key_provider,
            tenant,
            issuer,
            recipient,
            project,
            compiler,
            authorizer,
            references,
        })
    }

    fn context(operation: &str, principal: &str) -> TestResult<RequestContext> {
        Ok(RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new("transport-tenant")?,
                PrincipalId::new(principal)?,
            ),
            OperationId::new(operation)?,
            time(59)?,
            TraceId::new("1234567890abcdef1234567890abcdef")?,
            CancellationToken::default(),
            time(0)?,
        )?)
    }

    struct CallOptions<'a> {
        principal: &'a str,
        dry_run: bool,
        expected_revision: Option<u64>,
        page_cursor: Option<String>,
        page_size: Option<u32>,
    }

    async fn call<O>(
        fixture: &Fixture,
        payload: &O::Request,
        options: CallOptions<'_>,
    ) -> Result<(O::Response, cigar_api::ResponseEnvelope), ApiError>
    where
        O: TypedOperation,
        SpaceHandoffApplication: TypedUnaryService<O>,
    {
        let mut paths: Vec<_> = payload
            .path_bindings()
            .into_iter()
            .map(|(name, value)| PathParameter::new(name, value))
            .collect::<Result<_, _>>()
            .map_err(|_error| {
                fixture
                    .errors
                    .public_error(cigar_protocol::ErrorCode::Internal)
            })?;
        paths.sort_by(|left, right| left.name().cmp(right.name()));
        let contract = cigar_api::operation_by_id(O::OPERATION_ID).ok_or_else(|| {
            fixture
                .errors
                .public_error(cigar_protocol::ErrorCode::Internal)
        })?;
        let idempotency_key = contract
            .mutation
            .then(|| format!("test-{}", O::OPERATION_ID));
        let request = RequestEnvelope::new_with_dry_run(
            O::OPERATION_ID,
            encode_operation_payload(payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES).map_err(
                |_error| {
                    fixture
                        .errors
                        .public_error(cigar_protocol::ErrorCode::Internal)
                },
            )?,
            options.dry_run,
            idempotency_key,
            options.expected_revision.map(|value| value.to_string()),
            options.page_cursor,
            options.page_size,
            paths,
        )
        .map_err(|_error| {
            fixture
                .errors
                .public_error(cigar_protocol::ErrorCode::Internal)
        })?;
        let adapter = TypedUnaryAdapter::<O, SpaceHandoffApplication>::new(
            fixture.application.clone(),
            fixture.errors.clone(),
        );
        let response = adapter
            .call(
                context(O::OPERATION_ID, options.principal).map_err(|_error| {
                    fixture
                        .errors
                        .public_error(cigar_protocol::ErrorCode::Internal)
                })?,
                request,
            )
            .await?;
        let payload = decode_operation_payload(
            response.payload_cbor(),
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
        )
        .map_err(|_error| {
            fixture
                .errors
                .public_error(cigar_protocol::ErrorCode::Internal)
        })?;
        Ok((payload, response))
    }

    fn create_space_payload(project: RecordId) -> TestResult<cigar_api::CreateSpaceRequest> {
        Ok(cigar_api::CreateSpaceRequest {
            workspace_id: record(10)?,
            project_id: project,
            branch_id: record(11)?,
            task_id: record(12)?,
            session_id: record(13)?,
            purpose: "adapter integration space".to_owned(),
        })
    }

    #[tokio::test]
    async fn typed_space_dry_run_pagination_and_restart_are_real() -> TestResult<()> {
        let fixture = fixture()?;
        let (dry, _) = call::<CreateSpaceOperation>(
            &fixture,
            &create_space_payload(fixture.project.clone())?,
            CallOptions {
                principal: "issuer",
                dry_run: true,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let services = fixture
            .application
            .states
            .services(&fixture.tenant, &StoreCancellationToken::default())?;
        assert_eq!(
            services.spaces.head(&dry.space_id).map(|_| ()),
            Err(DurableStateError::from(SpaceError::NotFound))
        );

        let (created, _) = call::<CreateSpaceOperation>(
            &fixture,
            &create_space_payload(fixture.project.clone())?,
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let (fork, _) = call::<ForkSpaceOperation>(
            &fixture,
            &cigar_api::ForkSpaceRequest {
                space_id: created.space_id.clone(),
                fork: SpaceFork::PrivateOverlay {
                    base_commit_id: created.commit_id.clone(),
                    ttl_seconds: 30,
                },
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let overlay_id = match fork {
            SpaceForkResponse::PrivateOverlay { overlay_id, .. } => overlay_id,
            SpaceForkResponse::FocusBranch { .. } => return Err("wrong fork kind".into()),
        };
        let (published, _) = call::<PublishSpaceOperation>(
            &fixture,
            &cigar_api::PublishSpaceRequest {
                space_id: created.space_id.clone(),
                overlay_id,
                purpose: "publish empty preview".to_owned(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert!(matches!(
            published,
            SpacePublishResponse::Deduplicated { .. }
        ));

        for (sequence, event_number) in [(1, 20_001), (2, 20_002)] {
            services.spaces.append_events(
                &created.space_id,
                fixture.project.clone(),
                PublishRequest {
                    expected_head: ExpectedRevision(sequence),
                    actor_id: fixture.issuer.clone(),
                    purpose: "append paged event".to_owned(),
                    policy_snapshot_digest: content(903)?,
                    committed_at: time(10 + u8::try_from(sequence)?)?,
                    event_id: record(event_number)?,
                },
                vec![CoordinationEvent {
                    event_id: record(event_number + 100)?,
                    kind: CoordinationEventKind::TaskCheckpointed,
                    payload_digest: content(event_number)?,
                }],
                &StoreCancellationToken::default(),
            )?;
        }
        let (first_page, first_envelope) = call::<GetSpaceLogOperation>(
            &fixture,
            &SpaceIdRequest {
                space_id: created.space_id.clone(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: Some(1),
            },
        )
        .await?;
        assert_eq!(first_page.commits.len(), 1);
        let next = first_envelope
            .next_page_cursor()
            .ok_or("missing next cursor")?
            .to_owned();
        let (second_page, _) = call::<GetSpaceLogOperation>(
            &fixture,
            &SpaceIdRequest {
                space_id: created.space_id.clone(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: Some(next),
                page_size: Some(1),
            },
        )
        .await?;
        assert_eq!(
            second_page
                .commits
                .first()
                .ok_or("missing second-page commit")?
                .sequence,
            2
        );

        let reopened = RepositorySpaceHandoffStateProvider::new(
            fixture.repository.clone(),
            fixture.key_provider.clone(),
            8,
        )?;
        assert_eq!(
            reopened
                .services(&fixture.tenant, &StoreCancellationToken::default())?
                .spaces
                .log(&created.space_id)?
                .len(),
            3
        );
        Ok(())
    }

    #[tokio::test]
    async fn typed_event_resume_crosses_hidden_project_gap_without_disclosure() -> TestResult<()> {
        let fixture = fixture()?;
        let (space, _) = call::<CreateSpaceOperation>(
            &fixture,
            &create_space_payload(fixture.project.clone())?,
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let services = fixture
            .application
            .states
            .services(&fixture.tenant, &StoreCancellationToken::default())?;
        let hidden_project = record(600)?;
        let hidden_event_id = record(601)?;
        services.spaces.append_events(
            &space.space_id,
            hidden_project,
            PublishRequest {
                expected_head: ExpectedRevision(1),
                actor_id: fixture.issuer.clone(),
                purpose: "hidden project event".to_owned(),
                policy_snapshot_digest: content(903)?,
                committed_at: time(11)?,
                event_id: record(602)?,
            },
            vec![CoordinationEvent {
                event_id: hidden_event_id.clone(),
                kind: CoordinationEventKind::TaskCheckpointed,
                payload_digest: content(601)?,
            }],
            &StoreCancellationToken::default(),
        )?;
        let visible_event_id = record(603)?;
        services.spaces.append_events(
            &space.space_id,
            fixture.project.clone(),
            PublishRequest {
                expected_head: ExpectedRevision(2),
                actor_id: fixture.issuer.clone(),
                purpose: "visible project event".to_owned(),
                policy_snapshot_digest: content(903)?,
                committed_at: time(12)?,
                event_id: record(604)?,
            },
            vec![CoordinationEvent {
                event_id: visible_event_id.clone(),
                kind: CoordinationEventKind::TaskCheckpointed,
                payload_digest: content(603)?,
            }],
            &StoreCancellationToken::default(),
        )?;

        let stream_payload = SpaceIdRequest {
            space_id: space.space_id.clone(),
        };
        let stream_adapter = TypedStreamAdapter::<
            SubscribeSpaceEventsOperation,
            SpaceHandoffApplication,
        >::new(fixture.application.clone(), fixture.errors.clone());
        let initial_request = RequestEnvelope::new_with_dry_run(
            SubscribeSpaceEventsOperation::OPERATION_ID,
            encode_operation_payload(&stream_payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?,
            false,
            None,
            None,
            None,
            Some(1),
            vec![PathParameter::new(
                "space_id",
                stream_payload.space_id.as_str(),
            )?],
        )?;
        let mut initial = stream_adapter
            .subscribe(
                context(SubscribeSpaceEventsOperation::OPERATION_ID, "issuer")?,
                initial_request,
            )
            .await?;
        let genesis = initial.next().await.ok_or("initial stream ended")??;
        assert_ne!(genesis.event_id(), hidden_event_id.as_str());

        let resume_request = RequestEnvelope::new_with_dry_run(
            SubscribeSpaceEventsOperation::OPERATION_ID,
            encode_operation_payload(&stream_payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?,
            false,
            None,
            None,
            Some(genesis.event_id().to_owned()),
            Some(1),
            vec![PathParameter::new(
                "space_id",
                stream_payload.space_id.as_str(),
            )?],
        )?;
        let mut resumed = stream_adapter
            .subscribe(
                context(SubscribeSpaceEventsOperation::OPERATION_ID, "issuer")?,
                resume_request,
            )
            .await?;
        let visible = resumed.next().await.ok_or("resumed stream ended")??;
        assert_eq!(visible.event_id(), visible_event_id.as_str());
        let payload: SpaceEventPayload =
            decode_operation_payload(visible.payload_cbor(), cigar_api::MAX_EVENT_PAYLOAD_BYTES)?;
        assert_eq!(payload.project_id, fixture.project);
        assert_eq!(
            services
                .spaces
                .event_cursor_for_id(
                    &space.space_id,
                    &BTreeSet::from([fixture.project]),
                    &hidden_event_id,
                )
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Space(SpaceError::NotFound))
        );
        Ok(())
    }

    #[tokio::test]
    async fn typed_handoff_accept_result_merge_revoke_and_restart_are_authoritative()
    -> TestResult<()> {
        let fixture = fixture()?;
        let (space, _) = call::<CreateSpaceOperation>(
            &fixture,
            &create_space_payload(fixture.project.clone())?,
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let (fork, _) = call::<ForkSpaceOperation>(
            &fixture,
            &cigar_api::ForkSpaceRequest {
                space_id: space.space_id.clone(),
                fork: SpaceFork::PrivateOverlay {
                    base_commit_id: space.commit_id.clone(),
                    ttl_seconds: 30,
                },
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let overlay_id = match fork {
            SpaceForkResponse::PrivateOverlay { overlay_id, .. } => overlay_id,
            SpaceForkResponse::FocusBranch { .. } => return Err("wrong fork kind".into()),
        };
        let mut requested_capabilities = vec![Capability::ReadContext, Capability::InvokeTool];
        requested_capabilities.sort();
        let (created, _) = call::<CreateHandoffOperation>(
            &fixture,
            &cigar_api::CreateHandoffRequest {
                recipient: RecipientSelector::Principal(fixture.recipient.clone()),
                task: "produce one typed child result".to_owned(),
                acceptance_criteria: vec!["result is evidence backed".to_owned()],
                requested_projects: vec![fixture.project.clone()],
                requested_capabilities,
                budget: Budget {
                    total_input_tokens: 100,
                    output_reserve_tokens: 20,
                    lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 100)]),
                },
                topics: vec![CoordinationTopic::TaskCheckpoint],
                references: HandoffReferences::default(),
                bundle_id: version(400)?,
                audience: "test-runtime".to_owned(),
                ttl_seconds: 20,
                reusable: false,
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(
            created.preview.rejected_capabilities,
            vec![Capability::InvokeTool]
        );
        let (persisted_preview, _) = call::<PreviewHandoffOperation>(
            &fixture,
            &HandoffIdRequest {
                handoff_id: created.capsule.handoff_id.clone(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(persisted_preview, created.preview);

        let accept_payload = cigar_api::AcceptHandoffRequest {
            handoff_id: created.capsule.handoff_id.clone(),
            target_plan_id: record(410)?,
        };
        let (dry_acceptance, _) = call::<AcceptHandoffOperation>(
            &fixture,
            &accept_payload,
            CallOptions {
                principal: "recipient",
                dry_run: true,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let services = fixture
            .application
            .states
            .services(&fixture.tenant, &StoreCancellationToken::default())?;
        assert!(
            services
                .handoffs
                .persisted_acceptance(&dry_acceptance.acceptance_id, &fixture.recipient)
                .is_err()
        );
        let (acceptance, _) = call::<AcceptHandoffOperation>(
            &fixture,
            &accept_payload,
            CallOptions {
                principal: "recipient",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(
            *fixture
                .compiler
                .dry_runs
                .lock()
                .map_err(|_| "compiler lock")?,
            vec![true, false]
        );
        let child_version = version(420)?;
        let (result, _) = call::<RecordHandoffResultOperation>(
            &fixture,
            &cigar_api::RecordHandoffResultRequest {
                handoff_id: created.capsule.handoff_id.clone(),
                base_commit_id: acceptance.bundle_id,
                claims: vec![ResultClaim {
                    claim: "child output is retained".to_owned(),
                    evidence: vec![version(421)?],
                }],
                decisions: Vec::new(),
                artifacts: Vec::new(),
                source_changes: vec![child_version.clone()],
                verifier_receipts: Vec::new(),
                unresolved_questions: Vec::new(),
                blockers: Vec::new(),
                effect_references: Vec::new(),
                requested_followup_capabilities: Vec::new(),
            },
            CallOptions {
                principal: "recipient",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(result.revision, 2);
        fixture
            .references
            .denied
            .lock()
            .map_err(|_| "reference resolver lock")?
            .insert(child_version);
        let merge_payload = cigar_api::MergeHandoffRequest {
            handoff_id: created.capsule.handoff_id.clone(),
            delta_id: result.delta_id.clone(),
            space_id: space.space_id.clone(),
            overlay_id,
        };
        let denied = call::<MergeHandoffOperation>(
            &fixture,
            &merge_payload,
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await;
        let denied = match denied {
            Ok(_) => return Err("unauthorized typed child result unexpectedly merged".into()),
            Err(error) => error,
        };
        assert_eq!(denied.code(), cigar_protocol::ErrorCode::PolicyDenied);
        assert_eq!(services.spaces.head(&space.space_id)?.sequence, 1);
        fixture
            .references
            .denied
            .lock()
            .map_err(|_| "reference resolver lock")?
            .clear();
        let (merged, _) = call::<MergeHandoffOperation>(
            &fixture,
            &merge_payload,
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(
            merged.commit.as_ref().map(|commit| commit.sequence),
            Some(2)
        );
        assert!(merged.conflict_ids.is_empty());

        let reason_digest = content(430)?;
        let (dry_revoke, _) = call::<RevokeHandoffOperation>(
            &fixture,
            &cigar_api::RevokeHandoffRequest {
                handoff_id: created.capsule.handoff_id.clone(),
                reason_digest: reason_digest.clone(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: true,
                expected_revision: Some(2),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(dry_revoke.revision, 3);
        assert!(
            services
                .handoffs
                .persisted_revocation(
                    &created.capsule.handoff_id,
                    &fixture.issuer,
                    &BTreeSet::new(),
                )?
                .is_none()
        );
        let (revoked, _) = call::<RevokeHandoffOperation>(
            &fixture,
            &cigar_api::RevokeHandoffRequest {
                handoff_id: created.capsule.handoff_id.clone(),
                reason_digest: reason_digest.clone(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(2),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(revoked.revision, 3);
        assert_eq!(
            services
                .handoffs
                .persisted_revocation(
                    &created.capsule.handoff_id,
                    &fixture.issuer,
                    &BTreeSet::new(),
                )?
                .and_then(|revocation| revocation.reason_digest),
            Some(reason_digest)
        );

        let reopened = RepositorySpaceHandoffStateProvider::new(
            fixture.repository.clone(),
            fixture.key_provider.clone(),
            8,
        )?;
        let reopened = reopened.services(&fixture.tenant, &StoreCancellationToken::default())?;
        assert_eq!(
            reopened
                .handoffs
                .persisted_result(&result.delta_id, &fixture.issuer)?
                .revision,
            2
        );
        assert_eq!(reopened.spaces.head(&space.space_id)?.sequence, 2);
        Ok(())
    }

    #[tokio::test]
    async fn typed_checkpoint_conflict_resolution_and_stream_reauthorize_each_poll()
    -> TestResult<()> {
        let fixture = fixture()?;
        let (space, _) = call::<CreateSpaceOperation>(
            &fixture,
            &create_space_payload(fixture.project.clone())?,
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let focus_id = record(700)?;
        let focus_payload = cigar_api::ForkSpaceRequest {
            space_id: space.space_id.clone(),
            fork: SpaceFork::FocusBranch {
                focus_id: focus_id.clone(),
                label: "focused adapter work".to_owned(),
                offline: false,
            },
        };
        let focus_request = RequestEnvelope::new_with_dry_run(
            ForkSpaceOperation::OPERATION_ID,
            encode_operation_payload(&focus_payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?,
            false,
            Some("quoted-revision-test".to_owned()),
            Some("\"1\"".to_owned()),
            None,
            None,
            vec![PathParameter::new(
                "space_id",
                focus_payload.space_id.as_str(),
            )?],
        )?;
        let focus_adapter = TypedUnaryAdapter::<ForkSpaceOperation, SpaceHandoffApplication>::new(
            fixture.application.clone(),
            fixture.errors.clone(),
        );
        let focus_envelope = focus_adapter
            .call(
                context(ForkSpaceOperation::OPERATION_ID, "issuer")?,
                focus_request,
            )
            .await?;
        let focus: SpaceForkResponse = decode_operation_payload(
            focus_envelope.payload_cbor(),
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
        )?;
        assert_eq!(focus_envelope.semantic_etag(), Some("\"1\""));
        assert!(matches!(focus, SpaceForkResponse::FocusBranch { .. }));
        let (checkpoint, _) = call::<CreateSpaceCheckpointOperation>(
            &fixture,
            &CheckpointSpaceRequest {
                space_id: space.space_id.clone(),
                focus_id,
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(checkpoint.commit_id, space.commit_id);

        let (first_fork, _) = call::<ForkSpaceOperation>(
            &fixture,
            &cigar_api::ForkSpaceRequest {
                space_id: space.space_id.clone(),
                fork: SpaceFork::PrivateOverlay {
                    base_commit_id: space.commit_id.clone(),
                    ttl_seconds: 30,
                },
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let (second_fork, _) = call::<ForkSpaceOperation>(
            &fixture,
            &cigar_api::ForkSpaceRequest {
                space_id: space.space_id.clone(),
                fork: SpaceFork::PrivateOverlay {
                    base_commit_id: space.commit_id.clone(),
                    ttl_seconds: 30,
                },
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let first_overlay = match first_fork {
            SpaceForkResponse::PrivateOverlay { overlay_id, .. } => overlay_id,
            SpaceForkResponse::FocusBranch { .. } => return Err("wrong first fork".into()),
        };
        let second_overlay = match second_fork {
            SpaceForkResponse::PrivateOverlay { overlay_id, .. } => overlay_id,
            SpaceForkResponse::FocusBranch { .. } => return Err("wrong second fork".into()),
        };
        let services = fixture
            .application
            .states
            .services(&fixture.tenant, &StoreCancellationToken::default())?;
        let key = ResourceKey::new("shared-conflict-key")?;
        services.spaces.propose(
            &space.space_id,
            &first_overlay,
            &fixture.issuer,
            ProposedMutation {
                key: key.clone(),
                mutation: OverlayMutation::Instruction(version(701)?),
            },
            &StoreCancellationToken::default(),
        )?;
        services.spaces.propose(
            &space.space_id,
            &second_overlay,
            &fixture.issuer,
            ProposedMutation {
                key,
                mutation: OverlayMutation::Instruction(version(702)?),
            },
            &StoreCancellationToken::default(),
        )?;
        let (second_publish, _) = call::<PublishSpaceOperation>(
            &fixture,
            &cigar_api::PublishSpaceRequest {
                space_id: space.space_id.clone(),
                overlay_id: second_overlay,
                purpose: "advance canonical conflict key".to_owned(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(1),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert!(matches!(
            second_publish,
            SpacePublishResponse::Published { .. }
        ));
        let (first_publish, _) = call::<PublishSpaceOperation>(
            &fixture,
            &cigar_api::PublishSpaceRequest {
                space_id: space.space_id.clone(),
                overlay_id: first_overlay,
                purpose: "retain typed conflict".to_owned(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(2),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        let conflict_id = match first_publish {
            SpacePublishResponse::Conflicted { conflict_ids } => conflict_ids
                .first()
                .cloned()
                .ok_or("missing persisted conflict")?,
            SpacePublishResponse::Published { .. } | SpacePublishResponse::Deduplicated { .. } => {
                return Err("expected conflict".into());
            }
        };
        let (conflicts, _) = call::<ListSpaceConflictsOperation>(
            &fixture,
            &SpaceIdRequest {
                space_id: space.space_id.clone(),
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: None,
                page_cursor: None,
                page_size: Some(10),
            },
        )
        .await?;
        assert_eq!(conflicts.conflicts.len(), 1);
        assert_eq!(
            conflicts
                .conflicts
                .first()
                .ok_or("missing listed conflict")?
                .conflict_id
                .clone(),
            conflict_id
        );
        let decision = version(703)?;
        fixture
            .references
            .denied
            .lock()
            .map_err(|_| "reference resolver lock")?
            .insert(decision.clone());
        let denied = call::<ResolveSpaceConflictOperation>(
            &fixture,
            &cigar_api::ResolveSpaceConflictRequest {
                space_id: space.space_id.clone(),
                conflict_id: conflict_id.clone(),
                resolution: ConflictResolution::TypedDecision {
                    decision_id: decision.clone(),
                },
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(2),
                page_cursor: None,
                page_size: None,
            },
        )
        .await;
        let denied = match denied {
            Ok(_) => {
                return Err("unauthorized typed decision unexpectedly resolved conflict".into());
            }
            Err(error) => error,
        };
        assert_eq!(denied.code(), cigar_protocol::ErrorCode::PolicyDenied);
        assert_eq!(services.spaces.head(&space.space_id)?.sequence, 2);
        fixture
            .references
            .denied
            .lock()
            .map_err(|_| "reference resolver lock")?
            .clear();
        let (resolution, _) = call::<ResolveSpaceConflictOperation>(
            &fixture,
            &cigar_api::ResolveSpaceConflictRequest {
                space_id: space.space_id.clone(),
                conflict_id,
                resolution: ConflictResolution::TypedDecision {
                    decision_id: decision,
                },
            },
            CallOptions {
                principal: "issuer",
                dry_run: false,
                expected_revision: Some(2),
                page_cursor: None,
                page_size: None,
            },
        )
        .await?;
        assert_eq!(resolution.commit.sequence, 3);

        let stream_payload = SpaceIdRequest {
            space_id: space.space_id,
        };
        let encoded =
            encode_operation_payload(&stream_payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;
        let stream_request = RequestEnvelope::new_with_dry_run(
            SubscribeSpaceEventsOperation::OPERATION_ID,
            encoded,
            false,
            None,
            None,
            None,
            Some(1),
            vec![PathParameter::new(
                "space_id",
                stream_payload.space_id.as_str(),
            )?],
        )?;
        let stream_adapter = TypedStreamAdapter::<
            SubscribeSpaceEventsOperation,
            SpaceHandoffApplication,
        >::new(fixture.application.clone(), fixture.errors.clone());
        let mut stream = stream_adapter
            .subscribe(
                context(SubscribeSpaceEventsOperation::OPERATION_ID, "issuer")?,
                stream_request,
            )
            .await?;
        let first_event = stream.next().await.ok_or("stream ended")??;
        let payload: SpaceEventPayload = decode_operation_payload(
            first_event.payload_cbor(),
            cigar_api::MAX_EVENT_PAYLOAD_BYTES,
        )?;
        assert_eq!(payload.project_id, fixture.project);
        assert!(!first_event.event_id().is_empty());
        let resume_request = RequestEnvelope::new_with_dry_run(
            SubscribeSpaceEventsOperation::OPERATION_ID,
            encode_operation_payload(&stream_payload, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?,
            false,
            None,
            None,
            Some(first_event.event_id().to_owned()),
            Some(1),
            vec![PathParameter::new(
                "space_id",
                stream_payload.space_id.as_str(),
            )?],
        )?;
        let mut resumed = stream_adapter
            .subscribe(
                context(SubscribeSpaceEventsOperation::OPERATION_ID, "issuer")?,
                resume_request,
            )
            .await?;
        let resumed_event = resumed.next().await.ok_or("resumed stream ended")??;
        assert_ne!(resumed_event.event_id(), first_event.event_id());
        fixture.authorizer.deny.store(true, Ordering::Release);
        let denied = stream.next().await.ok_or("stream did not reauthorize")?;
        let denied = match denied {
            Ok(_event) => return Err("stream poll should be denied".into()),
            Err(error) => error,
        };
        assert_eq!(denied.code(), cigar_protocol::ErrorCode::PolicyDenied);
        Ok(())
    }
}
