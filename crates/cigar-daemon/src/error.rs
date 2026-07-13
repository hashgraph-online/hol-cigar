//! Stable content-safe daemon composition failures.

use std::fmt;

/// Stable daemon server and process failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonErrorCode {
    /// Configuration parsing or validation failed.
    InvalidConfiguration,
    /// A required production service facade was not supplied.
    MissingServiceFacade,
    /// Trusted storage, policy, key, source, or application composition failed at startup.
    ProductionBootstrapFailed,
    /// A shared deployment lacked its concrete bounded network identity provider.
    SharedProviderUnavailable,
    /// Runtime directory or IPC endpoint permissions were unsafe.
    UnsafeRuntimePath,
    /// Local bearer creation or loading failed.
    CredentialUnavailable,
    /// TLS identity or trust material was missing, unsafe, malformed, or oversized.
    TlsUnavailable,
    /// A requested network or IPC listener could not be bound.
    ListenerBindFailed,
    /// Startup recovery did not complete successfully.
    StartupFailed,
    /// A running listener exited before shutdown was requested.
    ListenerFailed,
    /// Graceful shutdown did not complete within its bound.
    ShutdownIncomplete,
    /// Request-authority construction failed.
    AuthorityUnavailable,
    /// Command-line arguments or configuration input were invalid.
    InvalidCommand,
    /// Configuration input could not be read within its bound.
    ConfigurationIo,
}

/// Content-free daemon error safe for stderr and process supervision.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DaemonError {
    code: DaemonErrorCode,
}

impl DaemonError {
    pub(crate) const fn new(code: DaemonErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> DaemonErrorCode {
        self.code
    }
}

impl fmt::Debug for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "daemon operation failed: {:?}", self.code)
    }
}

impl std::error::Error for DaemonError {}
