//! Connector capability declarations and content-free dispatch observations.

use crate::{EffectError, EffectErrorCode};
use cigar_protocol::{ContentDigest, EffectIntent, RecordId, UtcTimestamp};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum declared operations per connector.
pub const MAX_CONNECTOR_OPERATIONS: usize = 256;

/// One operation's trusted safety properties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorOperation {
    /// Normalized operation selector.
    pub operation: String,
    /// Whether identical idempotency keys guarantee one remote logical effect.
    pub same_key_idempotent: bool,
    /// Whether remote lookup can prove execution or non-execution.
    pub supports_reconciliation: bool,
    /// Whether a separately authorized compensation operation exists.
    pub supports_compensation: bool,
}

/// Bounded connector descriptor; connector code never decides authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorDescriptor {
    /// Stable connector selector.
    pub connector: String,
    /// Sorted unique declared operations.
    pub operations: Vec<ConnectorOperation>,
    /// Maximum dispatch duration in nanoseconds.
    pub maximum_dispatch_nanos: u64,
}

impl ConnectorDescriptor {
    /// Validates names, bounds, and operation uniqueness.
    pub fn validate(&self) -> Result<(), EffectError> {
        let valid_selector = |value: &str| {
            !value.is_empty()
                && value.len() <= 256
                && !value.bytes().any(|byte| byte.is_ascii_control())
        };
        if !valid_selector(&self.connector)
            || self.operations.is_empty()
            || self.operations.len() > MAX_CONNECTOR_OPERATIONS
            || self.maximum_dispatch_nanos == 0
            || self
                .operations
                .iter()
                .any(|item| !valid_selector(&item.operation))
            || !self.operations.windows(2).all(|items| {
                items
                    .first()
                    .zip(items.get(1))
                    .is_some_and(|(a, b)| a.operation < b.operation)
            })
        {
            Err(EffectError::new(EffectErrorCode::InvalidInput))
        } else {
            Ok(())
        }
    }

    /// Resolves one exact declared operation.
    #[must_use]
    pub fn operation(&self, name: &str) -> Option<&ConnectorOperation> {
        self.operations
            .binary_search_by(|item| item.operation.as_str().cmp(name))
            .ok()
            .and_then(|index| self.operations.get(index))
    }
}

/// Connector precondition result bound before send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreconditionReport {
    /// Whether every exact intent precondition currently holds.
    pub satisfied: bool,
    /// Sorted evidence digests.
    pub evidence: BTreeSet<ContentDigest>,
}

/// Fenced connector call context with no authorization decision surface.
#[derive(Clone)]
pub struct DispatchContext<'a> {
    /// Immutable intent.
    pub(crate) intent: &'a EffectIntent,
    /// Attempt identity.
    pub(crate) attempt_id: &'a RecordId,
    /// Active fencing token.
    pub(crate) fencing_token: u64,
    /// Exact request digest committed before this call.
    pub(crate) request_digest: &'a ContentDigest,
    /// Hard deadline.
    pub(crate) deadline: UtcTimestamp,
    pub(crate) seal: KernelDispatchContextSeal,
}

#[derive(Clone)]
pub(crate) struct KernelDispatchContextSeal;

impl DispatchContext<'_> {
    pub(crate) fn verify_kernel_seal(&self) {
        let _sealed = &self.seal;
    }

    /// Returns the immutable, durably authorized intent.
    #[must_use]
    pub const fn intent(&self) -> &EffectIntent {
        self.intent
    }

    /// Returns the durable attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> &RecordId {
        self.attempt_id
    }

    /// Returns the active monotonic fence.
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Returns the exact request digest committed before connector invocation.
    #[must_use]
    pub const fn request_digest(&self) -> &ContentDigest {
        self.request_digest
    }

    /// Returns the hard attempt deadline.
    #[must_use]
    pub const fn deadline(&self) -> UtcTimestamp {
        self.deadline
    }
}

impl fmt::Debug for DispatchContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchContext")
            .field("effect_id", &self.intent.effect_id)
            .field("attempt_id", &self.attempt_id)
            .field("fencing_token", &self.fencing_token)
            .field("request_digest", &self.request_digest)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Result of one connector invocation, including explicit ambiguity classes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchObservation {
    /// Remote mutation and verification succeeded.
    Succeeded {
        /// Stable remote operation identity.
        remote_operation_id: String,
        /// Normalized response digest.
        response_digest: ContentDigest,
        /// Verification evidence digest.
        verification_digest: ContentDigest,
    },
    /// Remote side definitively rejected or failed without ambiguity.
    Failed {
        /// Content-free rejection evidence.
        evidence_digest: ContentDigest,
    },
    /// Request may have executed; reconciliation is mandatory before any unsafe retry.
    Unknown {
        /// Content-free observation evidence.
        evidence_digest: ContentDigest,
        /// Remote identity when learned before response loss.
        remote_operation_id: Option<String>,
    },
    /// Connector proved no request bytes capable of committing were sent.
    ProvenNotSent {
        /// Proof digest for subsequent reconciliation.
        evidence_digest: ContentDigest,
    },
}

/// Reconciliation observation over an ambiguous attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileObservation {
    /// Remote effect is confirmed successful.
    ConfirmedSuccess(ContentDigest),
    /// Remote effect is confirmed failed.
    ConfirmedFailure(ContentDigest),
    /// Connector proved no mutation occurred.
    ProvenNotExecuted(ContentDigest),
    /// Evidence remains ambiguous through the certainty-window end.
    Inconclusive {
        /// Current evidence digest.
        evidence_digest: ContentDigest,
        /// Earliest safe time for another lookup.
        certainty_window_end: UtcTimestamp,
    },
}

/// Connector implementation boundary. Implementations receive no authority to self-approve.
pub trait EffectConnector: Send + Sync {
    /// Returns the immutable capability descriptor.
    fn descriptor(&self) -> ConnectorDescriptor;

    /// Checks exact external preconditions without mutation.
    fn check_preconditions(
        &self,
        intent: &EffectIntent,
        now: UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError>;

    /// Performs one already-authorized fenced dispatch.
    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError>;

    /// Resolves one ambiguous attempt without dispatching again.
    fn reconcile(&self, context: &DispatchContext<'_>)
    -> Result<ReconcileObservation, EffectError>;
}
