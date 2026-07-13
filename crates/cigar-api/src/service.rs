//! Transport-neutral service facade and bounded semantic envelopes.

use crate::context::{
    CancellationToken, OperationId, PrincipalId, RequestContext, RequestContextError, TenantId,
    TraceId,
};
use crate::error::ApiError;
use crate::generated::{AuthClass, OPERATIONS, OperationContract, StreamKind};
use cigar_protocol::ErrorCode;
use futures_core::Stream;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum decoded canonical-CBOR request or response payload size.
pub const MAX_OPERATION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum decoded canonical-CBOR payload size for one stream event.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum idempotency key size shared by the HTTP and gRPC bindings.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
/// Maximum expected-revision or semantic-ETag size.
pub const MAX_REVISION_BYTES: usize = 256;
/// Maximum opaque page cursor size on the public wire contracts.
pub const MAX_WIRE_CURSOR_BYTES: usize = 4096;
/// Maximum requested page size before service-specific clamping.
pub const MAX_PAGE_SIZE: u32 = 1000;
/// Maximum resumable stream event identity size.
pub const MAX_EVENT_ID_BYTES: usize = 256;
/// Maximum number of path bindings on one frozen v1 operation.
pub const MAX_PATH_PARAMETERS: usize = 8;
/// Maximum path-parameter name size.
pub const MAX_PATH_PARAMETER_NAME_BYTES: usize = 64;
/// Maximum path-parameter value size.
pub const MAX_PATH_PARAMETER_VALUE_BYTES: usize = 256;

const MAX_AUTHORIZATION_BYTES: usize = 8192;
const MAX_STREAM_BUFFER_CAPACITY: usize = 1024;
const DEFAULT_MAXIMUM_EXPANSION_RATIO: u32 = 64;
const MAX_TRANSPORT_REQUEST_BYTES: usize = 64 * 1024 * 1024;

/// Boxed object-safe future returned by service and authority interfaces.
pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Boxed, bounded-event stream returned by a service facade.
pub type FacadeEventStream =
    Pin<Box<dyn Stream<Item = Result<EventEnvelope, ApiError>> + Send + 'static>>;

/// Tenant and principal identity inserted only after transport-level peer verification.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedClientIdentity {
    tenant: TenantId,
    principal: PrincipalId,
}

impl VerifiedClientIdentity {
    /// Records validated SAN-derived identities after the TLS acceptor verifies the peer.
    pub fn from_verified_tls_peer(
        tenant: impl Into<String>,
        principal: impl Into<String>,
    ) -> Result<Self, RequestContextError> {
        Ok(Self {
            tenant: TenantId::new(tenant)?,
            principal: PrincipalId::new(principal)?,
        })
    }

    /// Returns the verified tenant identity.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the verified principal identity.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }
}

impl fmt::Debug for VerifiedClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedClientIdentity([REDACTED])")
    }
}

/// Failure to normalize or validate a transport semantic envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// A required field is missing or a field is malformed.
    InvalidArgument,
    /// A bounded field exceeds the frozen v1 limit.
    LimitExceeded,
    /// A response or event disagrees with the dispatched operation.
    OperationMismatch,
}

impl EnvelopeError {
    pub(crate) const fn error_code(self) -> ErrorCode {
        match self {
            Self::InvalidArgument | Self::OperationMismatch => ErrorCode::InvalidArgument,
            Self::LimitExceeded => ErrorCode::LimitExceeded,
        }
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidArgument => "service envelope is malformed",
            Self::LimitExceeded => "service envelope exceeds a frozen limit",
            Self::OperationMismatch => "service envelope operation does not match dispatch",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for EnvelopeError {}

fn bounded_optional(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, EnvelopeError> {
    match value {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) if value.len() > maximum => Err(EnvelopeError::LimitExceeded),
        Some(value) if !value.bytes().all(|byte| byte.is_ascii_graphic()) => {
            Err(EnvelopeError::InvalidArgument)
        }
        value => Ok(value),
    }
}

/// One validated, transport-neutral HTTP-template path binding.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PathParameter {
    name: String,
    value: String,
}

impl PathParameter {
    /// Creates a lowercase snake-case name and bounded unreserved ASCII value.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, EnvelopeError> {
        let name = name.into();
        let value = value.into();
        let valid_name = !name.is_empty()
            && name.len() <= MAX_PATH_PARAMETER_NAME_BYTES
            && name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        let valid_value = !value.is_empty()
            && value.len() <= MAX_PATH_PARAMETER_VALUE_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            });
        if !valid_name || !valid_value {
            return Err(EnvelopeError::InvalidArgument);
        }
        Ok(Self { name, value })
    }

    /// Returns the exact template parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact unreserved path value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for PathParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathParameter")
            .field("name", &self.name)
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

/// Transport-normalized request passed to the embedded service facade.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestEnvelope {
    operation_id: OperationId,
    payload_cbor: Vec<u8>,
    dry_run: bool,
    idempotency_key: Option<String>,
    expected_revision: Option<String>,
    page_cursor: Option<String>,
    page_size: Option<u32>,
    path_parameters: Vec<PathParameter>,
}

impl RequestEnvelope {
    /// Creates and validates a frozen v1 request envelope.
    pub fn new(
        operation_id: impl Into<String>,
        payload_cbor: impl Into<Vec<u8>>,
        idempotency_key: Option<String>,
        expected_revision: Option<String>,
        page_cursor: Option<String>,
        page_size: Option<u32>,
        path_parameters: Vec<PathParameter>,
    ) -> Result<Self, EnvelopeError> {
        Self::new_with_dry_run(
            operation_id,
            payload_cbor,
            false,
            idempotency_key,
            expected_revision,
            page_cursor,
            page_size,
            path_parameters,
        )
    }

    /// Creates and validates a frozen v1 request envelope with explicit preview intent.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_dry_run(
        operation_id: impl Into<String>,
        payload_cbor: impl Into<Vec<u8>>,
        dry_run: bool,
        idempotency_key: Option<String>,
        expected_revision: Option<String>,
        page_cursor: Option<String>,
        page_size: Option<u32>,
        path_parameters: Vec<PathParameter>,
    ) -> Result<Self, EnvelopeError> {
        let operation_id =
            OperationId::new(operation_id).map_err(|_| EnvelopeError::InvalidArgument)?;
        let payload_cbor = payload_cbor.into();
        if payload_cbor.len() > MAX_OPERATION_PAYLOAD_BYTES {
            return Err(EnvelopeError::LimitExceeded);
        }
        let idempotency_key = bounded_optional(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
        let expected_revision = bounded_optional(expected_revision, MAX_REVISION_BYTES)?;
        let page_cursor = bounded_optional(page_cursor, MAX_WIRE_CURSOR_BYTES)?;
        if page_size.is_some_and(|size| size == 0 || size > MAX_PAGE_SIZE) {
            return Err(EnvelopeError::InvalidArgument);
        }
        if path_parameters.len() > MAX_PATH_PARAMETERS
            || !path_parameters
                .windows(2)
                .all(|window| match (window.first(), window.get(1)) {
                    (Some(first), Some(second)) => first.name() < second.name(),
                    _ => false,
                })
        {
            return Err(EnvelopeError::InvalidArgument);
        }
        Ok(Self {
            operation_id,
            payload_cbor,
            dry_run,
            idempotency_key,
            expected_revision,
            page_cursor,
            page_size,
            path_parameters,
        })
    }

    /// Returns the exact generated operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the opaque canonical-CBOR request payload.
    #[must_use]
    pub fn payload_cbor(&self) -> &[u8] {
        &self.payload_cbor
    }

    /// Returns whether the caller requested governed preview execution.
    ///
    /// This flag carries intent only. Service governance still decides whether preview is
    /// supported and must not bypass idempotency, revision, policy, or authorization checks.
    #[must_use]
    pub const fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Returns the caller idempotency key, when required by the contract.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    /// Returns the optimistic expected revision, when required by the contract.
    #[must_use]
    pub fn expected_revision(&self) -> Option<&str> {
        self.expected_revision.as_deref()
    }

    /// Returns the opaque page or resume cursor without interpreting it.
    #[must_use]
    pub fn page_cursor(&self) -> Option<&str> {
        self.page_cursor.as_deref()
    }

    /// Returns the requested page size.
    #[must_use]
    pub const fn page_size(&self) -> Option<u32> {
        self.page_size
    }

    /// Returns the sorted unique path bindings used by every transport.
    #[must_use]
    pub fn path_parameters(&self) -> &[PathParameter] {
        &self.path_parameters
    }

    pub(crate) fn validate_contract(
        &self,
        contract: &'static OperationContract,
    ) -> Result<(), EnvelopeError> {
        if self.operation_id.as_str() != contract.operation_id {
            return Err(EnvelopeError::OperationMismatch);
        }
        let expected_path_names = contract_path_parameter_names(contract.http_path);
        if expected_path_names.len() != self.path_parameters.len()
            || expected_path_names
                .iter()
                .zip(&self.path_parameters)
                .any(|(expected, actual)| *expected != actual.name())
        {
            return Err(EnvelopeError::InvalidArgument);
        }
        let requires_idempotency = matches!(
            contract.idempotency_requirement,
            crate::generated::IdempotencyRequirement::Required
        );
        if requires_idempotency != self.idempotency_key.is_some() {
            return Err(EnvelopeError::InvalidArgument);
        }
        let requires_revision = matches!(
            contract.revision_requirement,
            crate::generated::RevisionRequirement::Required
        );
        if requires_revision != self.expected_revision.is_some() {
            return Err(EnvelopeError::InvalidArgument);
        }
        Ok(())
    }
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("operation_id", &self.operation_id)
            .field("payload_bytes", &self.payload_cbor.len())
            .field("dry_run", &self.dry_run)
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .field("has_expected_revision", &self.expected_revision.is_some())
            .field("has_page_cursor", &self.page_cursor.is_some())
            .field("page_size", &self.page_size)
            .field("path_parameter_count", &self.path_parameters.len())
            .finish()
    }
}

/// Transport-neutral bounded unary response from the service facade.
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseEnvelope {
    operation_id: OperationId,
    payload_cbor: Vec<u8>,
    semantic_etag: Option<String>,
    next_page_cursor: Option<String>,
}

impl ResponseEnvelope {
    /// Creates a bounded response with an optional strong semantic ETag.
    pub fn new(
        operation_id: impl Into<String>,
        payload_cbor: impl Into<Vec<u8>>,
        semantic_etag: Option<String>,
        next_page_cursor: Option<String>,
    ) -> Result<Self, EnvelopeError> {
        let operation_id =
            OperationId::new(operation_id).map_err(|_| EnvelopeError::InvalidArgument)?;
        let payload_cbor = payload_cbor.into();
        if payload_cbor.len() > MAX_OPERATION_PAYLOAD_BYTES {
            return Err(EnvelopeError::LimitExceeded);
        }
        let semantic_etag = bounded_optional(semantic_etag, MAX_REVISION_BYTES)?;
        if semantic_etag.as_deref().is_some_and(|etag| {
            etag.starts_with("W/")
                || etag.len() < 3
                || !etag.starts_with('"')
                || !etag.ends_with('"')
        }) {
            return Err(EnvelopeError::InvalidArgument);
        }
        let next_page_cursor = bounded_optional(next_page_cursor, MAX_WIRE_CURSOR_BYTES)?;
        Ok(Self {
            operation_id,
            payload_cbor,
            semantic_etag,
            next_page_cursor,
        })
    }

    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the canonical-CBOR response payload.
    #[must_use]
    pub fn payload_cbor(&self) -> &[u8] {
        &self.payload_cbor
    }

    /// Returns the strong semantic ETag.
    #[must_use]
    pub fn semantic_etag(&self) -> Option<&str> {
        self.semantic_etag.as_deref()
    }

    /// Returns the next opaque page cursor without interpreting it.
    #[must_use]
    pub fn next_page_cursor(&self) -> Option<&str> {
        self.next_page_cursor.as_deref()
    }
}

impl fmt::Debug for ResponseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseEnvelope")
            .field("operation_id", &self.operation_id)
            .field("payload_bytes", &self.payload_cbor.len())
            .field("has_semantic_etag", &self.semantic_etag.is_some())
            .field("has_next_page_cursor", &self.next_page_cursor.is_some())
            .finish()
    }
}

/// One bounded resumable event from the embedded service facade.
#[derive(Clone, Eq, PartialEq)]
pub struct EventEnvelope {
    operation_id: OperationId,
    event_id: String,
    payload_cbor: Vec<u8>,
}

impl EventEnvelope {
    /// Creates a bounded event with a stable, visible ASCII resume identity.
    pub fn new(
        operation_id: impl Into<String>,
        event_id: impl Into<String>,
        payload_cbor: impl Into<Vec<u8>>,
    ) -> Result<Self, EnvelopeError> {
        let operation_id =
            OperationId::new(operation_id).map_err(|_| EnvelopeError::InvalidArgument)?;
        let event_id = event_id.into();
        if event_id.is_empty()
            || event_id.len() > MAX_EVENT_ID_BYTES
            || !event_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(EnvelopeError::InvalidArgument);
        }
        let payload_cbor = payload_cbor.into();
        if payload_cbor.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(EnvelopeError::LimitExceeded);
        }
        Ok(Self {
            operation_id,
            event_id,
            payload_cbor,
        })
    }

    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the resumable event identity.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Returns the canonical-CBOR event payload.
    #[must_use]
    pub fn payload_cbor(&self) -> &[u8] {
        &self.payload_cbor
    }
}

impl fmt::Debug for EventEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventEnvelope")
            .field("operation_id", &self.operation_id)
            .field("event_id_bytes", &self.event_id.len())
            .field("payload_bytes", &self.payload_cbor.len())
            .finish()
    }
}

/// Object-safe embedded execution facade shared by every service transport.
pub trait ServiceFacade: Send + Sync {
    /// Executes one unary operation or returns a content-safe typed failure.
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>>;

    /// Opens one bounded resumable server stream.
    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>>;
}

/// Redacted transport inputs passed to an injected authenticator and context builder.
#[derive(Clone)]
pub struct ContextInput {
    operation_id: OperationId,
    auth_class: AuthClass,
    authorization: Option<String>,
    trace_id: Option<TraceId>,
    timeout: Duration,
    cancellation: CancellationToken,
    verified_client_identity: Option<VerifiedClientIdentity>,
}

impl ContextInput {
    pub(crate) fn new(
        contract: &'static OperationContract,
        authorization: Option<String>,
        trace_id: Option<TraceId>,
        timeout: Duration,
        cancellation: CancellationToken,
        verified_client_identity: Option<VerifiedClientIdentity>,
    ) -> Result<Self, EnvelopeError> {
        if authorization
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_AUTHORIZATION_BYTES)
        {
            return Err(EnvelopeError::LimitExceeded);
        }
        let operation_id =
            OperationId::new(contract.operation_id).map_err(|_| EnvelopeError::InvalidArgument)?;
        Ok(Self {
            operation_id,
            auth_class: contract.auth_class,
            authorization,
            trace_id,
            timeout,
            cancellation,
            verified_client_identity,
        })
    }

    /// Returns the exact generated operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the required authentication class.
    #[must_use]
    pub const fn auth_class(&self) -> AuthClass {
        self.auth_class
    }

    /// Returns the raw credential only to the injected authenticator.
    #[must_use]
    pub fn authorization(&self) -> Option<&str> {
        self.authorization.as_deref()
    }

    /// Returns the caller trace identity, or `None` when the authority must create one.
    #[must_use]
    pub const fn trace_id(&self) -> Option<&TraceId> {
        self.trace_id.as_ref()
    }

    /// Returns the validated and server-clamped requested timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the cooperative request cancellation signal.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Returns the transport-verified TLS peer identity, never a caller-controlled header.
    #[must_use]
    pub const fn verified_client_identity(&self) -> Option<&VerifiedClientIdentity> {
        self.verified_client_identity.as_ref()
    }
}

impl fmt::Debug for ContextInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextInput")
            .field("operation_id", &self.operation_id)
            .field("auth_class", &self.auth_class)
            .field("has_authorization", &self.authorization.is_some())
            .field("trace_id", &self.trace_id)
            .field("timeout", &self.timeout)
            .field("cancellation", &self.cancellation)
            .field(
                "has_verified_client_identity",
                &self.verified_client_identity.is_some(),
            )
            .finish()
    }
}

/// Injected authentication, context, and safe-correlation boundary for transports.
pub trait RequestAuthority: Send + Sync {
    /// Authenticates and constructs the validated request context.
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>>;

    /// Creates a value-free public error with a fresh privileged correlation identity.
    fn public_error(&self, code: ErrorCode) -> ApiError;
}

/// Validated transport bounds shared by HTTP and gRPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    default_timeout: Duration,
    maximum_timeout: Duration,
    stream_buffer_capacity: usize,
    maximum_expansion_ratio: u32,
    maximum_expanded_request_bytes: usize,
}

impl TransportConfig {
    /// Creates transport bounds, rejecting zero or unbounded values.
    pub fn new(
        default_timeout: Duration,
        maximum_timeout: Duration,
        stream_buffer_capacity: usize,
    ) -> Result<Self, EnvelopeError> {
        if default_timeout.is_zero()
            || maximum_timeout.is_zero()
            || default_timeout > maximum_timeout
            || stream_buffer_capacity == 0
            || stream_buffer_capacity > MAX_STREAM_BUFFER_CAPACITY
        {
            return Err(EnvelopeError::InvalidArgument);
        }
        Ok(Self {
            default_timeout,
            maximum_timeout,
            stream_buffer_capacity,
            maximum_expansion_ratio: DEFAULT_MAXIMUM_EXPANSION_RATIO,
            maximum_expanded_request_bytes: MAX_TRANSPORT_REQUEST_BYTES,
        })
    }

    /// Creates transport bounds with an explicit maximum decompression expansion ratio.
    pub fn with_compression_limits(
        default_timeout: Duration,
        maximum_timeout: Duration,
        stream_buffer_capacity: usize,
        maximum_expansion_ratio: u32,
    ) -> Result<Self, EnvelopeError> {
        let mut config = Self::new(default_timeout, maximum_timeout, stream_buffer_capacity)?;
        if maximum_expansion_ratio == 0 || maximum_expansion_ratio > 1024 {
            return Err(EnvelopeError::InvalidArgument);
        }
        config.maximum_expansion_ratio = maximum_expansion_ratio;
        Ok(config)
    }

    /// Applies a deployment-specific cap to the fully expanded HTTP or gRPC request entity.
    pub fn with_maximum_expanded_request_bytes(
        mut self,
        maximum_expanded_request_bytes: usize,
    ) -> Result<Self, EnvelopeError> {
        if maximum_expanded_request_bytes == 0
            || maximum_expanded_request_bytes > MAX_TRANSPORT_REQUEST_BYTES
        {
            return Err(EnvelopeError::InvalidArgument);
        }
        self.maximum_expanded_request_bytes = maximum_expanded_request_bytes;
        Ok(self)
    }

    /// Returns the timeout used when a caller omits one.
    #[must_use]
    pub const fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Returns the maximum caller-controlled timeout.
    #[must_use]
    pub const fn maximum_timeout(&self) -> Duration {
        self.maximum_timeout
    }

    /// Returns the bounded per-subscriber event channel capacity.
    #[must_use]
    pub const fn stream_buffer_capacity(&self) -> usize {
        self.stream_buffer_capacity
    }

    /// Returns the maximum permitted expanded-to-compressed byte ratio.
    #[must_use]
    pub const fn maximum_expansion_ratio(&self) -> u32 {
        self.maximum_expansion_ratio
    }

    /// Returns the deployment-specific fully expanded request-entity cap.
    #[must_use]
    pub const fn maximum_expanded_request_bytes(&self) -> usize {
        self.maximum_expanded_request_bytes
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            maximum_timeout: Duration::from_secs(120),
            stream_buffer_capacity: 32,
            maximum_expansion_ratio: DEFAULT_MAXIMUM_EXPANSION_RATIO,
            maximum_expanded_request_bytes: MAX_TRANSPORT_REQUEST_BYTES,
        }
    }
}

/// Shared embedded dispatcher used by the HTTP and gRPC adapters.
#[derive(Clone)]
pub struct ServiceKernel {
    facade: Arc<dyn ServiceFacade>,
    authority: Arc<dyn RequestAuthority>,
    config: TransportConfig,
}

impl ServiceKernel {
    /// Creates a dispatcher around injected execution and authentication boundaries.
    #[must_use]
    pub fn new(
        facade: Arc<dyn ServiceFacade>,
        authority: Arc<dyn RequestAuthority>,
        config: TransportConfig,
    ) -> Self {
        Self {
            facade,
            authority,
            config,
        }
    }

    /// Returns the shared transport configuration.
    #[must_use]
    pub const fn config(&self) -> TransportConfig {
        self.config
    }

    pub(crate) fn public_error(&self, code: ErrorCode) -> ApiError {
        self.authority.public_error(code)
    }

    pub(crate) async fn resolve_context(
        &self,
        input: ContextInput,
    ) -> Result<RequestContext, ApiError> {
        let operation = input.operation_id.clone();
        let trace_id = input.trace_id.clone();
        let timeout = input.timeout();
        let token = input.cancellation().clone();
        let mut cancellation = CancelOnDrop::new(token);
        let result = tokio::time::timeout(timeout, self.authority.resolve(input)).await;
        let context = match result {
            Ok(result) => {
                cancellation.disarm();
                result?
            }
            Err(_) => return Err(self.public_error(ErrorCode::DeadlineExceeded)),
        };
        if context.operation() != &operation
            || trace_id
                .as_ref()
                .is_some_and(|expected| context.trace_id() != expected)
        {
            return Err(self.public_error(ErrorCode::Internal));
        }
        Ok(context)
    }

    /// Executes an already-authenticated unary embedded request with transport-equivalent checks.
    pub async fn call(
        &self,
        contract: &'static OperationContract,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> Result<ResponseEnvelope, ApiError> {
        if contract.stream_kind != StreamKind::Unary
            || context.operation().as_str() != contract.operation_id
        {
            return Err(self.public_error(ErrorCode::InvalidArgument));
        }
        request
            .validate_contract(contract)
            .map_err(|failure| self.public_error(failure.error_code()))?;
        let Some(remaining) = remaining_until(context.deadline()) else {
            context.cancellation().cancel();
            return Err(self.public_error(ErrorCode::DeadlineExceeded));
        };
        let mut cancellation = CancelOnDrop::new(context.cancellation().clone());
        let response =
            match tokio::time::timeout(remaining, self.facade.call(context, request)).await {
                Ok(result) => {
                    cancellation.disarm();
                    result?
                }
                Err(_) => return Err(self.public_error(ErrorCode::DeadlineExceeded)),
            };
        if response.operation_id().as_str() != contract.operation_id {
            return Err(self.public_error(ErrorCode::Internal));
        }
        Ok(response)
    }

    /// Opens an authenticated stream with transport-equivalent validation and cancellation.
    pub async fn subscribe(
        &self,
        contract: &'static OperationContract,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> Result<FacadeEventStream, ApiError> {
        if contract.stream_kind != StreamKind::ServerStream
            || context.operation().as_str() != contract.operation_id
        {
            return Err(self.public_error(ErrorCode::InvalidArgument));
        }
        request
            .validate_contract(contract)
            .map_err(|failure| self.public_error(failure.error_code()))?;
        let Some(open_timeout) = remaining_until(context.deadline()) else {
            context.cancellation().cancel();
            return Err(self.public_error(ErrorCode::DeadlineExceeded));
        };
        let deadline = context.deadline();
        let token = context.cancellation().clone();
        let mut cancellation = CancelOnDrop::new(token.clone());
        let stream =
            match tokio::time::timeout(open_timeout, self.facade.subscribe(context, request)).await
            {
                Ok(result) => {
                    cancellation.disarm();
                    result?
                }
                Err(_) => return Err(self.public_error(ErrorCode::DeadlineExceeded)),
            };
        let Some(stream_timeout) = remaining_until(deadline) else {
            token.cancel();
            return Err(self.public_error(ErrorCode::DeadlineExceeded));
        };
        let deadline_cancellation = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(stream_timeout).await;
            deadline_cancellation.cancel();
        });
        Ok(Box::pin(ValidatedEventStream {
            inner: stream,
            expected_operation: contract.operation_id,
            authority: Arc::clone(&self.authority),
            cancellation: token,
            deadline: Box::pin(tokio::time::sleep(stream_timeout)),
            ended: false,
        }))
    }
}

fn remaining_until(deadline: cigar_protocol::UtcTimestamp) -> Option<Duration> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let now_nanos = i128::try_from(elapsed.as_nanos()).ok()?;
    let remaining_nanos = deadline.unix_nanos().checked_sub(now_nanos)?;
    if remaining_nanos <= 0 {
        return None;
    }
    let seconds = u64::try_from(remaining_nanos / 1_000_000_000).ok()?;
    let nanoseconds = u32::try_from(remaining_nanos % 1_000_000_000).ok()?;
    Some(Duration::new(seconds, nanoseconds))
}

impl fmt::Debug for ServiceKernel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceKernel")
            .field("facade", &"[INJECTED]")
            .field("authority", &"[INJECTED]")
            .field("config", &self.config)
            .finish()
    }
}

struct CancelOnDrop {
    cancellation: CancellationToken,
    armed: bool,
}

impl CancelOnDrop {
    const fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

struct ValidatedEventStream {
    inner: FacadeEventStream,
    expected_operation: &'static str,
    authority: Arc<dyn RequestAuthority>,
    cancellation: CancellationToken,
    deadline: Pin<Box<tokio::time::Sleep>>,
    ended: bool,
}

impl Stream for ValidatedEventStream {
    type Item = Result<EventEnvelope, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(context).is_ready() {
            self.cancellation.cancel();
            self.ended = true;
            return Poll::Ready(Some(Err(self
                .authority
                .public_error(ErrorCode::DeadlineExceeded))));
        }
        match self.inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(event)))
                if event.operation_id().as_str() != self.expected_operation =>
            {
                self.ended = true;
                Poll::Ready(Some(Err(self.authority.public_error(ErrorCode::Internal))))
            }
            Poll::Ready(Some(Err(error))) => {
                self.ended = true;
                Poll::Ready(Some(Err(error)))
            }
            result => result,
        }
    }
}

impl Drop for ValidatedEventStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Looks up an exact generated operation identity.
#[must_use]
pub fn operation_by_id(operation_id: &str) -> Option<&'static OperationContract> {
    OPERATIONS
        .iter()
        .find(|contract| contract.operation_id == operation_id)
}

/// Looks up an exact generated Protobuf service and RPC pair.
#[must_use]
pub fn operation_by_rpc(service: &str, rpc: &str) -> Option<&'static OperationContract> {
    OPERATIONS
        .iter()
        .find(|contract| contract.service == service && contract.rpc == rpc)
}

/// Returns sorted unique parameter names from one validated generated path template.
#[must_use]
pub fn contract_path_parameter_names(path: &'static str) -> Vec<&'static str> {
    let mut names = path
        .split('{')
        .skip(1)
        .filter_map(|remainder| remainder.split_once('}').map(|(name, _)| name))
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names
}

pub(crate) fn problem_json(error: ApiError) -> (u16, Vec<u8>) {
    let status = error.code().default_http_status();
    let bytes = match error.into_problem() {
        Ok(problem) => match serde_json::to_vec(&problem) {
            Ok(bytes) => bytes,
            Err(_) => br#"{"code":"INTERNAL","message":"internal error"}"#.to_vec(),
        },
        Err(_) => br#"{"code":"INTERNAL","message":"internal error"}"#.to_vec(),
    };
    (status, bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        EnvelopeError, EventEnvelope, MAX_EVENT_PAYLOAD_BYTES, MAX_OPERATION_PAYLOAD_BYTES,
        RequestEnvelope, ResponseEnvelope, TransportConfig,
    };
    use std::time::Duration;

    #[test]
    fn envelopes_enforce_bounds_and_redact_protected_values() {
        let secret = "never-log-this-key";
        let request = RequestEnvelope::new(
            "queryCatalog",
            vec![1, 2, 3],
            Some(secret.to_owned()),
            None,
            Some("cursor".to_owned()),
            Some(10),
            Vec::new(),
        );
        assert!(request.is_ok());
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(secret));
        assert!(matches!(
            RequestEnvelope::new(
                "queryCatalog",
                vec![0; MAX_OPERATION_PAYLOAD_BYTES + 1],
                None,
                None,
                None,
                None,
                Vec::new(),
            ),
            Err(EnvelopeError::LimitExceeded)
        ));
        assert!(matches!(
            EventEnvelope::new(
                "subscribeSpaceEvents",
                "event-1",
                vec![0; MAX_EVENT_PAYLOAD_BYTES + 1],
            ),
            Err(EnvelopeError::LimitExceeded)
        ));
    }

    #[test]
    fn response_rejects_weak_or_unquoted_etags() {
        assert!(
            ResponseEnvelope::new(
                "queryCatalog",
                Vec::new(),
                Some("\"semantic\"".to_owned()),
                None,
            )
            .is_ok()
        );
        for etag in ["W/\"semantic\"", "semantic"] {
            assert!(matches!(
                ResponseEnvelope::new("queryCatalog", Vec::new(), Some(etag.to_owned()), None,),
                Err(EnvelopeError::InvalidArgument)
            ));
        }
    }

    #[test]
    fn transport_configuration_is_bounded() {
        assert!(TransportConfig::new(Duration::from_secs(5), Duration::from_secs(10), 1,).is_ok());
        assert!(
            TransportConfig::new(Duration::from_secs(11), Duration::from_secs(10), 1,).is_err()
        );
        assert!(TransportConfig::new(Duration::from_secs(5), Duration::from_secs(10), 0,).is_err());
    }
}
