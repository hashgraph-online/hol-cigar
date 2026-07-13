//! Stable, content-safe SDK failures.

use cigar_protocol::{ErrorCode, Problem, RecordId, RetryClass, Validate};
use std::fmt;

/// Stable SDK-local failure category independent of the selected transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// A builder or call option is absent, contradictory, or outside a bound.
    InvalidConfiguration,
    /// A typed payload or semantic record failed local validation.
    InvalidArgument,
    /// The caller cancelled an in-flight operation.
    Cancelled,
    /// The caller's absolute operation deadline elapsed.
    DeadlineExceeded,
    /// A bounded transport exchange failed before a valid response was available.
    Transport,
    /// The peer returned malformed, mismatched, or unsupported protocol data.
    Protocol,
    /// The server API or protocol line is incompatible with this SDK.
    IncompatibleServer,
    /// A semantic digest, bundle identity, manifest, or delta proof did not verify.
    Integrity,
    /// The server returned one validated public CIGAR problem.
    Api,
}

/// Stable error returned by every Rust SDK API.
#[derive(Clone, Eq, PartialEq)]
pub struct SdkError {
    kind: ErrorKind,
    code: Option<ErrorCode>,
    correlation_id: Option<RecordId>,
    retry: RetryClass,
    message: &'static str,
}

impl SdkError {
    pub(crate) const fn local(kind: ErrorKind, retry: RetryClass, message: &'static str) -> Self {
        Self {
            kind,
            code: None,
            correlation_id: None,
            retry,
            message,
        }
    }

    /// Converts one validated frozen problem into the stable SDK error surface.
    pub fn from_problem(problem: Problem) -> Result<Self, Self> {
        problem.validate().map_err(|_failure| {
            Self::local(
                ErrorKind::Protocol,
                RetryClass::Never,
                "server problem failed frozen validation",
            )
        })?;
        Ok(Self {
            kind: ErrorKind::Api,
            code: Some(problem.code),
            correlation_id: Some(problem.correlation_id),
            retry: problem.retry,
            message: problem.code.definition().message,
        })
    }

    pub(crate) fn from_api(error: cigar_api::ApiError) -> Self {
        let code = error.code();
        Self {
            kind: ErrorKind::Api,
            code: Some(code),
            correlation_id: Some(error.correlation_id().clone()),
            retry: code.default_retry_class(),
            message: code.definition().message,
        }
    }

    /// Creates the content-safe failure an extension transport returns when no valid response
    /// was available. The SDK may retry this only when the exact request is repeat-safe.
    #[must_use]
    pub const fn transport() -> Self {
        Self::local(
            ErrorKind::Transport,
            RetryClass::AfterBackoff,
            "transport exchange failed before a valid response was available",
        )
    }

    /// Creates a content-safe protocol failure for an extension transport.
    #[must_use]
    pub const fn protocol() -> Self {
        Self::local(
            ErrorKind::Protocol,
            RetryClass::Never,
            "peer response disagrees with the frozen protocol",
        )
    }

    /// Creates the stable cooperative-cancellation failure for an extension transport.
    #[must_use]
    pub const fn cancelled() -> Self {
        Self::local(
            ErrorKind::Cancelled,
            RetryClass::Never,
            "operation was cancelled",
        )
    }

    /// Creates the stable elapsed-deadline failure for an extension transport.
    #[must_use]
    pub const fn deadline_exceeded() -> Self {
        Self::local(
            ErrorKind::DeadlineExceeded,
            RetryClass::Never,
            "operation deadline elapsed",
        )
    }

    /// Returns the stable SDK-local error category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the frozen public service error code, when the peer supplied one.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        self.code
    }

    /// Returns the privileged-log correlation identity without protected details.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<&RecordId> {
        self.correlation_id.as_ref()
    }

    /// Returns the frozen retry classification.
    #[must_use]
    pub const fn retry_class(&self) -> RetryClass {
        self.retry
    }

    /// Reports whether no server response is known to have been received.
    #[must_use]
    pub const fn is_transport_failure(&self) -> bool {
        matches!(self.kind, ErrorKind::Transport)
    }
}

impl fmt::Debug for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdkError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .field("correlation_id", &self.correlation_id)
            .field("retry", &self.retry)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for SdkError {}
