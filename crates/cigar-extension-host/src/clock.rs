//! Injected trusted wall and monotonic clock pair.

use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use cigar_protocol::UtcTimestamp;
use std::fmt;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Trusted clock pair used for semantic timestamps and runtime deadline admission.
pub trait HostClock: Send + Sync {
    /// Returns the trusted wall-clock instant used in protocol records.
    fn wall_now(&self) -> Result<UtcTimestamp, ExtensionHostError>;

    /// Returns the paired monotonic instant used only for elapsed-time enforcement.
    fn monotonic_now(&self) -> Instant;
}

/// Operating-system trusted clock pair for production deployments.
#[derive(Clone, Copy, Default)]
pub struct SystemHostClock;

impl fmt::Debug for SystemHostClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemHostClock")
    }
}

impl HostClock for SystemHostClock {
    fn wall_now(&self) -> Result<UtcTimestamp, ExtensionHostError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let nanos = i128::try_from(now.as_nanos())
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        UtcTimestamp::from_unix_nanos(nanos)
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
    }

    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }
}
