//! Object-safe transport boundary shared by embedded runtimes and daemon clients.

use crate::{CancellationToken, SdkError};
use cigar_api::generated::OperationContract;
use cigar_api::{EventEnvelope, RequestEnvelope, ResponseEnvelope};
use futures_core::Stream;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

/// Boxed SDK future used by extension-facing object-safe traits.
pub type SdkFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Boxed raw event stream returned by a transport.
pub type TransportEventStream =
    Pin<Box<dyn Stream<Item = Result<EventEnvelope, SdkError>> + Send + 'static>>;

/// One completely normalized transport request.
#[derive(Clone)]
pub struct TransportCall {
    contract: &'static OperationContract,
    envelope: RequestEnvelope,
    deadline: Instant,
    cancellation: CancellationToken,
}

impl TransportCall {
    pub(crate) const fn new(
        contract: &'static OperationContract,
        envelope: RequestEnvelope,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            contract,
            envelope,
            deadline,
            cancellation,
        }
    }

    /// Returns the frozen operation contract.
    #[must_use]
    pub const fn contract(&self) -> &'static OperationContract {
        self.contract
    }

    /// Returns the exact canonical service envelope.
    #[must_use]
    pub const fn envelope(&self) -> &RequestEnvelope {
        &self.envelope
    }

    /// Returns the absolute monotonic deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns the cooperative cancellation signal.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

impl fmt::Debug for TransportCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportCall")
            .field("operation_id", &self.contract.operation_id)
            .field("envelope", &self.envelope)
            .field("deadline", &self.deadline)
            .field("cancellation", &self.cancellation)
            .finish()
    }
}

/// Object-safe transport interface available to extensions and test harnesses.
pub trait ClientTransport: Send + Sync {
    /// Executes one bounded unary exchange.
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<ResponseEnvelope, SdkError>>;

    /// Opens one bounded resumable server stream.
    fn subscribe<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>>;
}
