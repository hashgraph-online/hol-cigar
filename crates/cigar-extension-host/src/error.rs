//! Stable extension-host failures with payload-free diagnostics.

use std::fmt;

/// Closed extension-host failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionHostErrorCode {
    /// A protocol record or configuration failed structural validation.
    InvalidInput,
    /// A publisher key or signature did not authenticate the manifest.
    SignatureInvalid,
    /// Exact implementation, package, input, output, or schema bytes did not match a digest.
    DigestMismatch,
    /// The extension does not support the host ABI or CIGAR version.
    IncompatibleVersion,
    /// Requested authority exceeds operator policy.
    CapabilityDenied,
    /// An opaque handle is unknown, forged, expired, or belongs to another invocation.
    InvalidHandle,
    /// A canonical frame is malformed, noncanonical, trailing, or oversized.
    InvalidFrame,
    /// A configured resource ceiling was exhausted.
    ResourceExhausted,
    /// The invocation deadline elapsed.
    DeadlineExceeded,
    /// The invocation was cancelled.
    Cancelled,
    /// An isolated extension exited or disconnected unexpectedly.
    ExtensionCrashed,
    /// The selected backend is unavailable or cannot provide required isolation.
    BackendUnavailable,
    /// A remote peer did not satisfy its authenticated logical-ABI binding.
    RemoteAuthenticationFailed,
    /// The extension produced a response that failed host validation.
    InvalidResponse,
}

/// Content-free error safe to expose across an API boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExtensionHostError {
    code: ExtensionHostErrorCode,
}

impl ExtensionHostError {
    /// Creates a payload-free failure in one stable category.
    #[must_use]
    pub const fn new(code: ExtensionHostErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ExtensionHostErrorCode {
        self.code
    }
}

impl fmt::Debug for ExtensionHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionHostError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ExtensionHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "extension host failed: {:?}", self.code)
    }
}

impl std::error::Error for ExtensionHostError {}

pub(crate) const fn error(code: ExtensionHostErrorCode) -> ExtensionHostError {
    ExtensionHostError::new(code)
}
