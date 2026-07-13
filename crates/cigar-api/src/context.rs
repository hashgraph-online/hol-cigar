//! Authenticated, transport-neutral request context.

use cigar_protocol::UtcTimestamp;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_IDENTITY_BYTES: usize = 128;
const MAX_OPERATION_BYTES: usize = 128;

/// Failure to construct or use an authenticated request context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestContextError {
    /// A bounded identity, operation, or trace field was malformed.
    InvalidField,
    /// The request deadline was not in the future when accepted.
    InvalidDeadline,
    /// The request was explicitly cancelled.
    Cancelled,
    /// The request deadline has elapsed.
    DeadlineExceeded,
}

impl fmt::Display for RequestContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidField => "request context field is invalid",
            Self::InvalidDeadline => "request deadline must be in the future",
            Self::Cancelled => "request was cancelled",
            Self::DeadlineExceeded => "request deadline elapsed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RequestContextError {}

macro_rules! bounded_identity {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
            pub fn new(value: impl Into<String>) -> Result<Self, RequestContextError> {
                let value = value.into();
                let valid = !value.is_empty()
                    && value.len() <= MAX_IDENTITY_BYTES
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
                    });
                if valid {
                    Ok(Self(value))
                } else {
                    Err(RequestContextError::InvalidField)
                }
            }

            /// Returns the normalized identity for exact authorization and storage scoping.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = RequestContextError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

bounded_identity!(
    TenantId,
    "Validated tenant identity resolved by authentication."
);
bounded_identity!(
    PrincipalId,
    "Validated principal identity resolved by authentication."
);

/// Stable generated identifier for one API operation.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    /// Creates a bounded lower-camel-case operation identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, RequestContextError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_OPERATION_BYTES
            && value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric());
        if valid {
            Ok(Self(value))
        } else {
            Err(RequestContextError::InvalidField)
        }
    }

    /// Returns the exact generated operation identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = RequestContextError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// W3C-compatible 16-byte trace identity rendered as lowercase hexadecimal.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct TraceId(String);

impl TraceId {
    /// Parses a nonzero 32-character lowercase hexadecimal trace identity.
    pub fn new(value: impl Into<String>) -> Result<Self, RequestContextError> {
        let value = value.into();
        let valid = value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && value.bytes().any(|byte| byte != b'0');
        if valid {
            Ok(Self(value))
        } else {
            Err(RequestContextError::InvalidField)
        }
    }

    /// Returns the normalized trace identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TraceId([REDACTED])")
    }
}

impl From<TraceId> for String {
    fn from(value: TraceId) -> Self {
        value.0
    }
}

impl TryFrom<String> for TraceId {
    type Error = RequestContextError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Identity produced only after a transport authenticator verifies credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedIdentity {
    tenant: TenantId,
    principal: PrincipalId,
}

impl AuthenticatedIdentity {
    /// Records a tenant and principal after the caller has verified credentials.
    #[must_use]
    pub const fn from_verified_credentials(tenant: TenantId, principal: PrincipalId) -> Self {
        Self { tenant, principal }
    }

    /// Returns the authenticated tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }
}

impl fmt::Debug for AuthenticatedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedIdentity([REDACTED])")
    }
}

/// Cloneable cooperative cancellation signal shared by adapters and services.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Creates a token in the active state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. This operation is idempotent.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Validated authentication, scoping, deadline, trace, and cancellation state.
#[derive(Clone)]
pub struct RequestContext {
    identity: AuthenticatedIdentity,
    operation: OperationId,
    deadline: UtcTimestamp,
    trace_id: TraceId,
    cancellation: CancellationToken,
}

impl RequestContext {
    /// Creates a request context after authentication and rejects an elapsed deadline.
    pub fn new(
        identity: AuthenticatedIdentity,
        operation: OperationId,
        deadline: UtcTimestamp,
        trace_id: TraceId,
        cancellation: CancellationToken,
        accepted_at: UtcTimestamp,
    ) -> Result<Self, RequestContextError> {
        if deadline <= accepted_at {
            return Err(RequestContextError::InvalidDeadline);
        }
        Ok(Self {
            identity,
            operation,
            deadline,
            trace_id,
            cancellation,
        })
    }

    /// Returns the authenticated identity.
    #[must_use]
    pub const fn identity(&self) -> &AuthenticatedIdentity {
        &self.identity
    }

    /// Returns the exact operation being performed.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Returns the effective server-clamped deadline.
    #[must_use]
    pub const fn deadline(&self) -> UtcTimestamp {
        self.deadline
    }

    /// Returns the trace identity.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Returns the cooperative cancellation token.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Fails when the request is cancelled or its deadline has elapsed.
    pub fn check_active(&self, now: UtcTimestamp) -> Result<(), RequestContextError> {
        if self.cancellation.is_cancelled() {
            Err(RequestContextError::Cancelled)
        } else if now >= self.deadline {
            Err(RequestContextError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestContext")
            .field("identity", &self.identity)
            .field("operation", &self.operation)
            .field("deadline", &self.deadline)
            .field("trace_id", &self.trace_id)
            .field("cancellation", &self.cancellation)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticatedIdentity, CancellationToken, OperationId, PrincipalId, RequestContext,
        RequestContextError, TenantId, TraceId,
    };
    use cigar_protocol::UtcTimestamp;

    fn timestamp(value: i128) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
        Ok(UtcTimestamp::from_unix_nanos(value)?)
    }

    #[test]
    fn context_enforces_deadline_and_cancellation() -> Result<(), Box<dyn std::error::Error>> {
        let cancellation = CancellationToken::new();
        let context = RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new("tenant-a")?,
                PrincipalId::new("principal-a")?,
            ),
            OperationId::new("compileBundle")?,
            timestamp(20)?,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            cancellation.clone(),
            timestamp(10)?,
        )?;
        assert!(context.check_active(timestamp(19)?).is_ok());
        assert_eq!(
            context.check_active(timestamp(20)?),
            Err(RequestContextError::DeadlineExceeded)
        );
        cancellation.cancel();
        assert_eq!(
            context.check_active(timestamp(11)?),
            Err(RequestContextError::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn context_rejects_elapsed_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let result = RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new("tenant-a")?,
                PrincipalId::new("principal-a")?,
            ),
            OperationId::new("queryCatalog")?,
            timestamp(10)?,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            CancellationToken::new(),
            timestamp(10)?,
        );
        assert!(matches!(result, Err(RequestContextError::InvalidDeadline)));
        Ok(())
    }

    #[test]
    fn debug_views_redact_authenticated_values() -> Result<(), Box<dyn std::error::Error>> {
        let tenant = "secret-tenant";
        let principal = "secret-principal";
        let trace = "0123456789abcdef0123456789abcdef";
        let context = RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new(tenant)?,
                PrincipalId::new(principal)?,
            ),
            OperationId::new("queryCatalog")?,
            timestamp(20)?,
            TraceId::new(trace)?,
            CancellationToken::new(),
            timestamp(10)?,
        )?;
        let rendered = format!("{context:?}");
        assert!(!rendered.contains(tenant));
        assert!(!rendered.contains(principal));
        assert!(!rendered.contains(trace));
        Ok(())
    }
}
