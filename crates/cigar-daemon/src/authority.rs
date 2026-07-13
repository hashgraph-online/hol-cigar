//! Request-authority implementations for local IPC, loopback bearer, and shared OIDC.

use crate::{DaemonTelemetry, LocalBearerToken, LocalIdentity, OidcAuthenticator};
use cigar_api::generated::AuthClass;
use cigar_api::{
    ApiError, AuthenticatedIdentity, ContextInput, PrincipalId, RequestAuthority, RequestContext,
    ServiceFuture, TenantId, TraceId,
};
use cigar_crypto::MonotonicUuidV7Generator;
use cigar_protocol::{ErrorCode, RecordId, UtcTimestamp};
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable failure to construct an authority or current request context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    /// A mandatory server-owned identity was invalid.
    InvalidIdentity,
    /// The wall clock was before the Unix epoch or outside protocol range.
    InvalidClock,
    /// Operating-system randomness was unavailable.
    RandomUnavailable,
    /// A generated protocol identity unexpectedly failed validation.
    InvalidGeneratedIdentity,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "request authority identity is invalid",
            Self::InvalidClock => "request authority clock is invalid",
            Self::RandomUnavailable => "request authority randomness is unavailable",
            Self::InvalidGeneratedIdentity => "request authority generated an invalid identity",
        })
    }
}

impl std::error::Error for AuthorityError {}

/// Injected wall clock used to construct server-owned request deadlines.
pub trait AuthorityClock: Send + Sync {
    /// Returns the current protocol timestamp.
    fn now(&self) -> Result<UtcTimestamp, AuthorityError>;

    /// Returns current whole Unix seconds for OIDC temporal validation.
    fn unix_seconds(&self) -> Result<i64, AuthorityError>;
}

/// Production wall clock backed by `SystemTime`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAuthorityClock;

impl AuthorityClock for SystemAuthorityClock {
    fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| AuthorityError::InvalidClock)?;
        let nanos =
            i128::try_from(duration.as_nanos()).map_err(|_error| AuthorityError::InvalidClock)?;
        UtcTimestamp::from_unix_nanos(nanos).map_err(|_error| AuthorityError::InvalidClock)
    }

    fn unix_seconds(&self) -> Result<i64, AuthorityError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| AuthorityError::InvalidClock)?;
        i64::try_from(duration.as_secs()).map_err(|_error| AuthorityError::InvalidClock)
    }
}

/// Explicit operator authorization applied after shared identity verification.
pub trait OperatorAuthorizer: Send + Sync {
    /// Returns true only for a principal authorized to call operator operations.
    fn is_operator(&self, identity: &AuthenticatedIdentity) -> bool;
}

/// Fail-closed operator policy used when no operator mapping is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllOperators;

impl OperatorAuthorizer for DenyAllOperators {
    fn is_operator(&self, _identity: &AuthenticatedIdentity) -> bool {
        false
    }
}

struct AuthorityCore {
    ids: MonotonicUuidV7Generator,
    fallback_correlation: RecordId,
    public_identity: AuthenticatedIdentity,
    clock: Arc<dyn AuthorityClock>,
    telemetry: Arc<DaemonTelemetry>,
}

impl AuthorityCore {
    fn new(
        clock: Arc<dyn AuthorityClock>,
        telemetry: Arc<DaemonTelemetry>,
    ) -> Result<Self, AuthorityError> {
        let public_identity = AuthenticatedIdentity::from_verified_credentials(
            TenantId::new("system").map_err(|_error| AuthorityError::InvalidIdentity)?,
            PrincipalId::new("anonymous").map_err(|_error| AuthorityError::InvalidIdentity)?,
        );
        let fallback_correlation = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")
            .map_err(|_error| AuthorityError::InvalidGeneratedIdentity)?;
        Ok(Self {
            ids: MonotonicUuidV7Generator::default(),
            fallback_correlation,
            public_identity,
            clock,
            telemetry,
        })
    }

    fn correlation(&self) -> RecordId {
        self.ids
            .generate()
            .ok()
            .and_then(|value| RecordId::new(value.to_string()).ok())
            .unwrap_or_else(|| self.fallback_correlation.clone())
    }

    fn trace(&self) -> Result<TraceId, AuthorityError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_error| AuthorityError::RandomUnavailable)?;
        if bytes.iter().all(|byte| *byte == 0) {
            *bytes
                .last_mut()
                .ok_or(AuthorityError::InvalidGeneratedIdentity)? = 1;
        }
        let mut text = String::with_capacity(32);
        for byte in bytes {
            write!(&mut text, "{byte:02x}")
                .map_err(|_error| AuthorityError::InvalidGeneratedIdentity)?;
        }
        TraceId::new(text).map_err(|_error| AuthorityError::InvalidGeneratedIdentity)
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.correlation())
    }

    fn context(
        &self,
        input: ContextInput,
        identity: AuthenticatedIdentity,
    ) -> Result<RequestContext, ApiError> {
        let accepted_at = self
            .clock
            .now()
            .map_err(|_error| self.public_error(ErrorCode::Internal))?;
        let timeout_nanos = i128::try_from(input.timeout().as_nanos())
            .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?;
        let deadline_nanos = accepted_at
            .unix_nanos()
            .checked_add(timeout_nanos)
            .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
        let deadline = UtcTimestamp::from_unix_nanos(deadline_nanos)
            .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?;
        let trace = match input.trace_id() {
            Some(trace) => trace.clone(),
            None => self
                .trace()
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
        };
        RequestContext::new(
            identity,
            input.operation_id().clone(),
            deadline,
            trace,
            input.cancellation().clone(),
            accepted_at,
        )
        .map_err(|_error| self.public_error(ErrorCode::Internal))
    }

    fn public_identity(&self) -> AuthenticatedIdentity {
        self.public_identity.clone()
    }
}

fn is_public(class: AuthClass) -> bool {
    matches!(class, AuthClass::Anonymous | AuthClass::Health)
}

/// Authority for a permission-restricted local IPC endpoint.
pub struct LocalSocketAuthority {
    core: AuthorityCore,
    identity: LocalIdentity,
}

impl LocalSocketAuthority {
    /// Creates a local-socket authority around a server-resolved user identity.
    pub fn new(
        identity: LocalIdentity,
        telemetry: Arc<DaemonTelemetry>,
    ) -> Result<Self, AuthorityError> {
        Self::with_clock(identity, telemetry, Arc::new(SystemAuthorityClock))
    }

    /// Creates an authority with an injected wall clock for deterministic tests.
    pub fn with_clock(
        identity: LocalIdentity,
        telemetry: Arc<DaemonTelemetry>,
        clock: Arc<dyn AuthorityClock>,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            core: AuthorityCore::new(clock, telemetry)?,
            identity,
        })
    }
}

impl RequestAuthority for LocalSocketAuthority {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        Box::pin(async move {
            let identity = if is_public(input.auth_class()) {
                self.core.public_identity()
            } else {
                self.identity.authenticated()
            };
            let result = self.core.context(input, identity);
            if result.is_ok() {
                self.core.telemetry.record_authorized_request();
            } else {
                self.core.telemetry.record_rejected_request();
            }
            result
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.core.public_error(code)
    }
}

impl fmt::Debug for LocalSocketAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalSocketAuthority([PEER-RESTRICTED])")
    }
}

/// Authority for loopback TCP protected by a random file-backed bearer.
pub struct LocalTokenAuthority {
    core: AuthorityCore,
    token: Arc<LocalBearerToken>,
    identity: LocalIdentity,
}

impl LocalTokenAuthority {
    /// Creates a loopback-token authority.
    pub fn new(
        token: Arc<LocalBearerToken>,
        identity: LocalIdentity,
        telemetry: Arc<DaemonTelemetry>,
    ) -> Result<Self, AuthorityError> {
        Self::with_clock(token, identity, telemetry, Arc::new(SystemAuthorityClock))
    }

    /// Creates an authority with an injected wall clock for deterministic tests.
    pub fn with_clock(
        token: Arc<LocalBearerToken>,
        identity: LocalIdentity,
        telemetry: Arc<DaemonTelemetry>,
        clock: Arc<dyn AuthorityClock>,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            core: AuthorityCore::new(clock, telemetry)?,
            token,
            identity,
        })
    }
}

impl RequestAuthority for LocalTokenAuthority {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        Box::pin(async move {
            let identity = if is_public(input.auth_class()) {
                Ok(self.core.public_identity())
            } else {
                input
                    .authorization()
                    .ok_or_else(|| self.core.public_error(ErrorCode::UnknownPrincipal))
                    .and_then(|authorization| {
                        self.token
                            .authenticate(authorization, &self.identity)
                            .map_err(|failure| self.core.public_error(failure.public_code()))
                    })
            };
            let result = identity.and_then(|identity| self.core.context(input, identity));
            if result.is_ok() {
                self.core.telemetry.record_authorized_request();
            } else {
                self.core.telemetry.record_rejected_request();
            }
            result
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.core.public_error(code)
    }
}

impl fmt::Debug for LocalTokenAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalTokenAuthority([REDACTED])")
    }
}

/// Proof that the server composition configured TLS and optional client-CA enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedTransportSecurity {
    mutual_tls: bool,
}

impl SharedTransportSecurity {
    pub(crate) const fn verified(mutual_tls: bool) -> Self {
        Self { mutual_tls }
    }

    /// Returns whether the listener requires a client certificate signed by the configured CA.
    #[must_use]
    pub const fn mutual_tls(self) -> bool {
        self.mutual_tls
    }
}

/// Authority for shared TLS listeners using pinned OIDC and explicit operator authorization.
pub struct SharedOidcAuthority {
    core: AuthorityCore,
    oidc: Arc<OidcAuthenticator>,
    operators: Arc<dyn OperatorAuthorizer>,
    transport: SharedTransportSecurity,
}

impl SharedOidcAuthority {
    pub(crate) fn new(
        oidc: Arc<OidcAuthenticator>,
        operators: Arc<dyn OperatorAuthorizer>,
        transport: SharedTransportSecurity,
        telemetry: Arc<DaemonTelemetry>,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            core: AuthorityCore::new(Arc::new(SystemAuthorityClock), telemetry)?,
            oidc,
            operators,
            transport,
        })
    }

    async fn authenticated_identity(
        &self,
        input: &ContextInput,
    ) -> Result<AuthenticatedIdentity, ApiError> {
        let now = self
            .core
            .clock
            .unix_seconds()
            .map_err(|_error| self.core.public_error(ErrorCode::Internal))?;
        let token = input
            .authorization()
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| self.core.public_error(ErrorCode::UnknownPrincipal))?;
        let certificate = if self.transport.mutual_tls() {
            let peer = input
                .verified_client_identity()
                .ok_or_else(|| self.core.public_error(ErrorCode::UnknownPrincipal))?;
            Some(
                crate::VerifiedClientCertificate::from_verified_san(
                    peer.tenant().as_str(),
                    peer.principal().as_str(),
                )
                .map_err(|failure| self.core.public_error(failure.public_code()))?,
            )
        } else {
            None
        };
        let identity = self
            .oidc
            .authenticate(token, None, certificate.as_ref(), now)
            .await
            .map_err(|failure| self.core.public_error(failure.public_code()))?;
        if input.auth_class() == AuthClass::Operator && !self.operators.is_operator(&identity) {
            Err(self.core.public_error(ErrorCode::PolicyDenied))
        } else {
            Ok(identity)
        }
    }
}

impl RequestAuthority for SharedOidcAuthority {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        Box::pin(async move {
            let identity = if is_public(input.auth_class()) {
                Ok(self.core.public_identity())
            } else {
                self.authenticated_identity(&input).await
            };
            let result = identity.and_then(|identity| self.core.context(input, identity));
            if result.is_ok() {
                self.core.telemetry.record_authorized_request();
            } else {
                self.core.telemetry.record_rejected_request();
            }
            result
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.core.public_error(code)
    }
}

impl fmt::Debug for SharedOidcAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedOidcAuthority")
            .field("oidc", &"[PINNED]")
            .field("mutual_tls", &self.transport.mutual_tls())
            .finish()
    }
}
