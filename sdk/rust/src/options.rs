//! Bounded deadlines, cancellation, pagination, and retry controls.

use crate::{ErrorKind, SdkError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_protocol::{ExpectedRevision, IdempotencyKey, PageCursor, RetryClass};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

const MAX_CALL_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_RETRY_ATTEMPTS: u8 = 5;

/// Validated raw server event identity used only to resume a server stream.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamResumeToken(String);

impl StreamResumeToken {
    /// Creates a token from the exact `event_id` returned by a prior stream event.
    pub fn new(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > cigar_api::MAX_EVENT_ID_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(SdkError::local(
                ErrorKind::InvalidArgument,
                RetryClass::Never,
                "stream resume event identity is invalid",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the exact raw event identity without pagination encoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StreamResumeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamResumeToken")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Cloneable cooperative cancellation signal for unary calls and streams.
#[derive(Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    /// Creates an active token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation and wakes every waiter.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Resolves once cancellation is requested.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
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

/// Automatic retry bounds applied only to repeat-safe operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    maximum_attempts: u8,
    initial_backoff: Duration,
    maximum_backoff: Duration,
}

impl RetryPolicy {
    /// Creates a bounded policy. One attempt disables automatic retry.
    pub fn new(
        maximum_attempts: u8,
        initial_backoff: Duration,
        maximum_backoff: Duration,
    ) -> Result<Self, SdkError> {
        if maximum_attempts == 0
            || maximum_attempts > MAX_RETRY_ATTEMPTS
            || initial_backoff.is_zero()
            || maximum_backoff < initial_backoff
            || maximum_backoff > Duration::from_secs(30)
        {
            return Err(SdkError::local(
                ErrorKind::InvalidConfiguration,
                RetryClass::Never,
                "retry policy is outside the published bounds",
            ));
        }
        Ok(Self {
            maximum_attempts,
            initial_backoff,
            maximum_backoff,
        })
    }

    /// Returns the maximum total attempts, including the initial request.
    #[must_use]
    pub const fn maximum_attempts(self) -> u8 {
        self.maximum_attempts
    }

    pub(crate) fn backoff(self, completed_attempts: u8) -> Duration {
        let shift = u32::from(completed_attempts.saturating_sub(1)).min(16);
        self.initial_backoff
            .saturating_mul(1_u32 << shift)
            .min(self.maximum_backoff)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            maximum_attempts: 3,
            initial_backoff: Duration::from_millis(25),
            maximum_backoff: Duration::from_millis(250),
        }
    }
}

/// Metadata and lifecycle controls shared by every typed operation.
#[derive(Clone)]
pub struct CallOptions {
    pub(crate) timeout: Duration,
    pub(crate) cancellation: CancellationToken,
    pub(crate) idempotency_key: Option<IdempotencyKey>,
    pub(crate) expected_revision: Option<ExpectedRevision>,
    pub(crate) page_cursor: Option<String>,
    pub(crate) page_size: Option<u32>,
    pub(crate) stream_resume: bool,
    pub(crate) dry_run: bool,
    pub(crate) retry: RetryPolicy,
}

impl fmt::Debug for CallOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallOptions")
            .field("timeout", &self.timeout)
            .field("cancellation", &self.cancellation)
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .field("has_expected_revision", &self.expected_revision.is_some())
            .field("has_page_cursor", &self.page_cursor.is_some())
            .field("stream_resume", &self.stream_resume)
            .field("page_size", &self.page_size)
            .field("dry_run", &self.dry_run)
            .field("retry", &self.retry)
            .finish()
    }
}

impl CallOptions {
    /// Creates read-operation options with a 30-second deadline.
    #[must_use]
    pub fn read() -> Self {
        Self::default()
    }

    /// Creates mutation options with a required validated idempotency key.
    #[must_use]
    pub fn mutation(idempotency_key: IdempotencyKey) -> Self {
        Self {
            idempotency_key: Some(idempotency_key),
            ..Self::default()
        }
    }

    /// Creates revisioned mutation options.
    #[must_use]
    pub fn revisioned(
        idempotency_key: IdempotencyKey,
        expected_revision: ExpectedRevision,
    ) -> Self {
        Self {
            idempotency_key: Some(idempotency_key),
            expected_revision: Some(expected_revision),
            ..Self::default()
        }
    }

    /// Sets the relative call deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, SdkError> {
        if timeout.is_zero() || timeout > MAX_CALL_TIMEOUT {
            return Err(SdkError::local(
                ErrorKind::InvalidConfiguration,
                RetryClass::Never,
                "call timeout is outside the published bounds",
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Uses the supplied cooperative cancellation token.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Adds a protocol-native opaque cursor and bounded page size.
    pub fn with_page(mut self, cursor: Option<PageCursor>, size: u32) -> Result<Self, SdkError> {
        if size == 0 || size > cigar_api::MAX_PAGE_SIZE {
            return Err(SdkError::local(
                ErrorKind::InvalidConfiguration,
                RetryClass::Never,
                "page size is outside the frozen API bound",
            ));
        }
        self.page_cursor = cursor.map(|value| URL_SAFE_NO_PAD.encode(value.as_bytes()));
        self.page_size = Some(size);
        self.stream_resume = false;
        Ok(self)
    }

    /// Resumes a stream from the exact raw event identity returned by the prior event.
    #[must_use]
    pub fn with_stream_resume(mut self, resume: StreamResumeToken) -> Self {
        self.page_cursor = Some(resume.0);
        self.stream_resume = true;
        self
    }

    /// Requests governed dry-run execution without bypassing server authority.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Replaces the bounded automatic retry policy.
    #[must_use]
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Returns the cancellation signal attached to this call.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            cancellation: CancellationToken::new(),
            idempotency_key: None,
            expected_revision: None,
            page_cursor: None,
            page_size: None,
            stream_resume: false,
            dry_run: false,
            retry: RetryPolicy::default(),
        }
    }
}
