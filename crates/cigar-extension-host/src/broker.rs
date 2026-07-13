//! Invocation-scoped capability broker and opaque authority handles.

use crate::clock::HostClock;
use crate::digest::raw_content_digest;
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use crate::manifest::ActivatedExtension;
use cigar_canon::MAX_CANONICAL_INPUT_BYTES;
use cigar_protocol::{
    Classification, ExtensionHandle, ExtensionHostCallKind, ExtensionHostCallV1,
    ExtensionHostCapability, ExtensionId, ExtensionKind, NetworkEndpoint, RecordId, SandboxAccess,
    SandboxPath, SandboxPreopen, SchemaVersion, UtcTimestamp, Validate,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const EMPTY_TRANSCRIPT_JSON_BYTES: usize = 2;
const TRANSCRIPT_METADATA_RESERVATION_BYTES: usize = 4_096;
const WORST_CASE_JSON_BYTES_PER_BYTE: usize = 4;

struct TranscriptBudget {
    maximum_bytes: usize,
    reserved_bytes: AtomicUsize,
}

impl TranscriptBudget {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            maximum_bytes,
            reserved_bytes: AtomicUsize::new(0),
        }
    }

    fn reserve(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<PendingTranscriptReservation, ExtensionHostError> {
        self.reserve_bytes(bytes)?;
        Ok(PendingTranscriptReservation {
            budget: self.clone(),
            bytes,
        })
    }

    fn reserve_bytes(&self, bytes: usize) -> Result<(), ExtensionHostError> {
        let mut current = self.reserved_bytes.load(Ordering::SeqCst);
        loop {
            let next = current
                .checked_add(bytes)
                .filter(|next| *next <= self.maximum_bytes)
                .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
            match self.reserved_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.reserved_bytes.fetch_sub(bytes, Ordering::SeqCst);
    }
}

struct PendingTranscriptReservation {
    budget: Arc<TranscriptBudget>,
    bytes: usize,
}

impl PendingTranscriptReservation {
    fn commit(
        mut self,
        retained: &mut TranscriptReservation,
        bytes: usize,
    ) -> Result<(), ExtensionHostError> {
        if !Arc::ptr_eq(&self.budget, &retained.budget) {
            return Err(error(ExtensionHostErrorCode::BackendUnavailable));
        }
        if bytes > self.bytes {
            let additional = bytes
                .checked_sub(self.bytes)
                .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
            self.budget.reserve_bytes(additional)?;
            self.bytes = self
                .bytes
                .checked_add(additional)
                .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        }
        let retained_bytes = retained
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        let surplus = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
        self.budget.release(surplus);
        self.bytes = 0;
        retained.bytes = retained_bytes;
        Ok(())
    }
}

impl Drop for PendingTranscriptReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

struct TranscriptReservation {
    budget: Arc<TranscriptBudget>,
    bytes: usize,
}

impl TranscriptReservation {
    fn new(budget: Arc<TranscriptBudget>, bytes: usize) -> Result<Self, ExtensionHostError> {
        budget.reserve_bytes(bytes)?;
        Ok(Self { budget, bytes })
    }
}

impl Drop for TranscriptReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

pub(crate) struct TranscriptArchive {
    calls: Vec<ExtensionHostCallV1>,
    _reservation: TranscriptReservation,
}

impl TranscriptArchive {
    pub(crate) fn as_slice(&self) -> &[ExtensionHostCallV1] {
        &self.calls
    }

    pub(crate) fn len(&self) -> usize {
        self.calls.len()
    }

    fn to_vec(&self) -> Vec<ExtensionHostCallV1> {
        self.calls.clone()
    }

    pub(crate) fn into_calls(self) -> Vec<ExtensionHostCallV1> {
        let Self {
            calls,
            _reservation,
        } = self;
        drop(_reservation);
        calls
    }
}

impl PartialEq for TranscriptArchive {
    fn eq(&self, other: &Self) -> bool {
        self.calls == other.calls
    }
}

impl Eq for TranscriptArchive {}

struct TranscriptState {
    calls: Vec<ExtensionHostCallV1>,
    finalized: Option<Arc<TranscriptArchive>>,
    encoded_json_bytes: usize,
    reservation: Option<TranscriptReservation>,
}

impl TranscriptState {
    fn new(budget: Arc<TranscriptBudget>) -> Result<Self, ExtensionHostError> {
        Ok(Self {
            calls: Vec::new(),
            finalized: None,
            encoded_json_bytes: EMPTY_TRANSCRIPT_JSON_BYTES,
            reservation: Some(TranscriptReservation::new(
                budget,
                EMPTY_TRANSCRIPT_JSON_BYTES,
            )?),
        })
    }

    fn len(&self) -> usize {
        self.finalized
            .as_ref()
            .map_or_else(|| self.calls.len(), |calls| calls.len())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn ensure_capacity(
        &self,
        request_bytes: usize,
        maximum_response_bytes: usize,
        maximum_transcript_bytes: usize,
    ) -> Result<PendingTranscriptReservation, ExtensionHostError> {
        if self.finalized.is_some() {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        let payload_reservation = request_bytes
            .checked_add(maximum_response_bytes)
            .and_then(|bytes| bytes.checked_mul(WORST_CASE_JSON_BYTES_PER_BYTE))
            .and_then(|bytes| bytes.checked_add(TRANSCRIPT_METADATA_RESERVATION_BYTES))
            .and_then(|bytes| bytes.checked_add(usize::from(!self.calls.is_empty())))
            .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        let next = self
            .encoded_json_bytes
            .checked_add(payload_reservation)
            .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        if next > maximum_transcript_bytes {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        self.reservation
            .as_ref()
            .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?
            .budget
            .reserve(payload_reservation)
    }

    fn push(
        &mut self,
        call: ExtensionHostCallV1,
        pending: PendingTranscriptReservation,
        maximum_transcript_bytes: usize,
    ) -> Result<(), ExtensionHostError> {
        if self.finalized.is_some() {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        let encoded = serde_json::to_vec(&call)
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let next = self
            .encoded_json_bytes
            .checked_add(encoded.len())
            .and_then(|bytes| bytes.checked_add(usize::from(!self.calls.is_empty())))
            .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        if next > maximum_transcript_bytes {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        let retained = self
            .reservation
            .as_mut()
            .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let retained_delta = next
            .checked_sub(self.encoded_json_bytes)
            .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
        pending.commit(retained, retained_delta)?;
        self.calls.push(call);
        self.encoded_json_bytes = next;
        Ok(())
    }

    fn finalize(&mut self) -> Result<Arc<TranscriptArchive>, ExtensionHostError> {
        if let Some(finalized) = &self.finalized {
            return Ok(finalized.clone());
        }
        let reservation = self
            .reservation
            .take()
            .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let finalized = Arc::new(TranscriptArchive {
            calls: std::mem::take(&mut self.calls),
            _reservation: reservation,
        });
        self.finalized = Some(finalized.clone());
        Ok(finalized)
    }

    fn to_vec(&self) -> Vec<ExtensionHostCallV1> {
        self.finalized
            .as_ref()
            .map_or_else(|| self.calls.clone(), |archive| archive.to_vec())
    }

    #[cfg(test)]
    fn replace_budget(&mut self, budget: Arc<TranscriptBudget>) -> Result<(), ExtensionHostError> {
        if self.finalized.is_some() || !self.calls.is_empty() {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        self.reservation = Some(TranscriptReservation::new(
            budget,
            EMPTY_TRANSCRIPT_JSON_BYTES,
        )?);
        Ok(())
    }
}

fn process_transcript_budget() -> Arc<TranscriptBudget> {
    static BUDGET: OnceLock<Arc<TranscriptBudget>> = OnceLock::new();
    BUDGET
        .get_or_init(|| Arc::new(TranscriptBudget::new(MAX_CANONICAL_INPUT_BYTES)))
        .clone()
}

pub(crate) fn empty_transcript_archive() -> Result<Arc<TranscriptArchive>, ExtensionHostError> {
    Ok(Arc::new(TranscriptArchive {
        calls: Vec::new(),
        _reservation: TranscriptReservation::new(
            process_transcript_budget(),
            EMPTY_TRANSCRIPT_JSON_BYTES,
        )?,
    }))
}

#[cfg(test)]
pub(crate) struct TestTranscriptBudget(Arc<TranscriptBudget>);

#[cfg(test)]
impl TestTranscriptBudget {
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.0.reserved_bytes.load(Ordering::SeqCst)
    }
}

/// Metadata supplied to policy before protected bytes receive a handle.
#[derive(Clone, Copy, Debug)]
pub struct ProtectedDataAuthorization<'a> {
    /// Activated extension identity.
    pub extension_id: &'a ExtensionId,
    /// Extension role used by the invocation.
    pub kind: ExtensionKind,
    /// Declared operation selector.
    pub operation: &'a str,
    /// Declared processor identity.
    pub processor: &'a str,
    /// Source classification of the protected bytes.
    pub classification: Classification,
}

/// Current compile-authorization boundary for protected source and blob data.
pub trait ProtectedDataPolicy: Send + Sync {
    /// Returns true only when current policy permits this exact invocation to receive plaintext.
    fn authorize(&self, request: ProtectedDataAuthorization<'_>) -> bool;
}

/// Operator-owned network boundary; extension code never receives a socket or credential.
pub trait NetworkBoundary: Send + Sync {
    /// Executes a bounded request against one exact manifest-approved endpoint.
    fn request(
        &self,
        endpoint: &NetworkEndpoint,
        protected_request: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ExtensionHostError>;
}

/// Final outbound secret boundary; secret material never crosses back into the extension ABI.
pub trait FinalSecretBoundary: Send + Sync {
    /// Resolves one host-owned reference only while performing the final outbound operation.
    fn dispatch(
        &self,
        secret_reference: &str,
        protected_request: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ExtensionHostError>;
}

enum BrokerResource {
    Source {
        bytes: Vec<u8>,
    },
    Blob {
        bytes: Vec<u8>,
    },
    Iterator {
        values: Vec<Vec<u8>>,
        position: usize,
    },
    Endpoint(NetworkEndpoint),
    Preopen {
        descriptor: SandboxPreopen,
        canonical_root: PathBuf,
    },
    SecretReference(String),
}

impl fmt::Debug for BrokerResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Source { .. } => "source",
            Self::Blob { .. } => "blob",
            Self::Iterator { .. } => "iterator",
            Self::Endpoint(_) => "endpoint",
            Self::Preopen { .. } => "preopen",
            Self::SecretReference(_) => "secret_reference",
        };
        formatter
            .debug_struct("BrokerResource")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// One invocation's least-authority broker. Handles have no meaning outside this value.
pub struct CapabilityBroker {
    activated: ActivatedExtension,
    invocation_id: RecordId,
    kind: ExtensionKind,
    operation: String,
    processor: String,
    capabilities: BTreeSet<ExtensionHostCapability>,
    deterministic_clock: Option<UtcTimestamp>,
    deterministic_random_seed: Vec<u8>,
    random_counter: AtomicU64,
    resources: Mutex<BTreeMap<ExtensionHandle, BrokerResource>>,
    host_calls: AtomicU32,
    cancelled: AtomicBool,
    attempt_claimed: AtomicBool,
    protected_policy: Arc<dyn ProtectedDataPolicy>,
    network_boundary: Arc<dyn NetworkBoundary>,
    secret_boundary: Arc<dyn FinalSecretBoundary>,
    clock: Arc<dyn HostClock>,
    dispatch_lock: Mutex<()>,
    transcript: Mutex<TranscriptState>,
    maximum_transcript_bytes: usize,
}

impl fmt::Debug for CapabilityBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityBroker")
            .field("extension_id", &self.activated.manifest().extension_id)
            .field("invocation_id", &self.invocation_id)
            .field("kind", &self.kind)
            .field("operation_bytes", &self.operation.len())
            .field("processor_bytes", &self.processor.len())
            .field("capability_count", &self.capabilities.len())
            .field(
                "has_deterministic_clock",
                &self.deterministic_clock.is_some(),
            )
            .field("random_seed_bytes", &self.deterministic_random_seed.len())
            .field("host_calls", &self.host_calls.load(Ordering::Relaxed))
            .field("maximum_transcript_bytes", &self.maximum_transcript_bytes)
            .field("cancelled", &self.cancelled.load(Ordering::Relaxed))
            .field(
                "attempt_claimed",
                &self.attempt_claimed.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl CapabilityBroker {
    /// Creates one broker after intersecting the invocation grant with the authenticated manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activated: ActivatedExtension,
        invocation_id: RecordId,
        kind: ExtensionKind,
        operation: impl Into<String>,
        processor: impl Into<String>,
        authorized_capabilities: impl IntoIterator<Item = ExtensionHostCapability>,
        deterministic_clock: Option<UtcTimestamp>,
        deterministic_random_seed: Vec<u8>,
        protected_policy: Arc<dyn ProtectedDataPolicy>,
        network_boundary: Arc<dyn NetworkBoundary>,
        secret_boundary: Arc<dyn FinalSecretBoundary>,
        clock: Arc<dyn HostClock>,
    ) -> Result<Self, ExtensionHostError> {
        let operation = operation.into();
        let processor = processor.into();
        let capabilities: BTreeSet<_> = authorized_capabilities.into_iter().collect();
        let manifest = activated.manifest();
        let declared: BTreeSet<_> = manifest
            .required_host_capabilities
            .iter()
            .copied()
            .collect();
        let has_clock = capabilities.contains(&ExtensionHostCapability::DeterministicClock);
        let has_random = capabilities.contains(&ExtensionHostCapability::DeterministicRandom);
        if !manifest.kinds.contains(&kind)
            || capabilities.iter().any(|value| !declared.contains(value))
            || has_clock != deterministic_clock.is_some()
            || has_random == deterministic_random_seed.is_empty()
            || (!manifest.processors.is_empty() && !manifest.processors.contains(&processor))
        {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let maximum_transcript_bytes = MAX_CANONICAL_INPUT_BYTES;
        let transcript = TranscriptState::new(process_transcript_budget())?;
        Ok(Self {
            activated,
            invocation_id,
            kind,
            operation,
            processor,
            capabilities,
            deterministic_clock,
            deterministic_random_seed,
            random_counter: AtomicU64::new(0),
            resources: Mutex::new(BTreeMap::new()),
            host_calls: AtomicU32::new(0),
            cancelled: AtomicBool::new(false),
            attempt_claimed: AtomicBool::new(false),
            protected_policy,
            network_boundary,
            secret_boundary,
            clock,
            dispatch_lock: Mutex::new(()),
            transcript: Mutex::new(transcript),
            maximum_transcript_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_maximum_transcript_bytes_for_test(&mut self, maximum: usize) {
        self.maximum_transcript_bytes = maximum;
    }

    #[cfg(test)]
    pub(crate) const fn maximum_transcript_bytes_for_test(&self) -> usize {
        self.maximum_transcript_bytes
    }

    #[cfg(test)]
    pub(crate) fn retained_transcript_bytes_for_test(&self) -> Result<usize, ExtensionHostError> {
        self.transcript
            .lock()
            .map(|transcript| transcript.encoded_json_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
    }

    #[cfg(test)]
    pub(crate) fn new_transcript_budget_for_test(maximum: usize) -> TestTranscriptBudget {
        TestTranscriptBudget(Arc::new(TranscriptBudget::new(maximum)))
    }

    #[cfg(test)]
    pub(crate) fn set_transcript_budget_for_test(
        &mut self,
        budget: &TestTranscriptBudget,
    ) -> Result<(), ExtensionHostError> {
        self.transcript
            .get_mut()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
            .replace_budget(budget.0.clone())
    }

    /// Returns the invocation owning every handle created by this broker.
    #[must_use]
    pub const fn invocation_id(&self) -> &RecordId {
        &self.invocation_id
    }

    /// Permanently binds this broker's mutable invocation state to one runtime attempt.
    pub(crate) fn claim_attempt(&self) -> Result<(), ExtensionHostError> {
        let has_transcript = !self
            .transcript
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
            .is_empty();
        if self.host_call_count() != 0 || self.is_cancelled() || has_transcript {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        self.attempt_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_previous| ())
            .map_err(|_previous| error(ExtensionHostErrorCode::InvalidInput))
    }

    /// Cooperatively cancels the invocation and permanently disables subsequent broker calls.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Returns the number of broker calls admitted so far.
    #[must_use]
    pub fn host_call_count(&self) -> u32 {
        self.host_calls.load(Ordering::SeqCst)
    }

    /// Returns true only when a handle is currently owned by this invocation.
    pub fn owns_handle(&self, handle: &ExtensionHandle) -> Result<bool, ExtensionHostError> {
        Ok(self.resources()?.contains_key(handle))
    }

    /// Returns the completed, validated host-call transcript in contiguous ordinal order.
    pub fn transcript(&self) -> Result<Vec<ExtensionHostCallV1>, ExtensionHostError> {
        self.transcript
            .lock()
            .map(|values| values.to_vec())
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
    }

    pub(crate) fn transcript_len(&self) -> Result<usize, ExtensionHostError> {
        self.transcript
            .lock()
            .map(|values| values.len())
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
    }

    pub(crate) fn finalize_transcript(&self) -> Result<Arc<TranscriptArchive>, ExtensionHostError> {
        let _dispatch_guard = self
            .dispatch_lock
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        self.transcript
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
            .finalize()
    }

    /// Dispatches one logical ABI host call and records its exact protected transcript.
    pub fn dispatch_host_call(
        &self,
        kind: ExtensionHostCallKind,
        handle: Option<&ExtensionHandle>,
        request: &[u8],
    ) -> Result<Vec<u8>, ExtensionHostError> {
        let _dispatch_guard = self
            .dispatch_lock
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let maximum_response_bytes = self.maximum_response_reservation(kind, request)?;
        let pending = self
            .transcript
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
            .ensure_capacity(
                request.len(),
                maximum_response_bytes,
                self.maximum_transcript_bytes,
            )?;
        let started_at = self.clock.wall_now()?;
        let response = match kind {
            ExtensionHostCallKind::ReadSource => {
                require_empty(request)?;
                self.read_source(require_handle(handle)?)?
            }
            ExtensionHostCallKind::ReadBlob => {
                require_empty(request)?;
                self.read_blob(require_handle(handle)?)?
            }
            ExtensionHostCallKind::IteratorNext => {
                require_empty(request)?;
                match self.iterator_next(require_handle(handle)?)? {
                    Some(value) => {
                        let mut encoded = Vec::with_capacity(value.len().saturating_add(1));
                        encoded.push(1);
                        encoded.extend_from_slice(&value);
                        encoded
                    }
                    None => vec![0],
                }
            }
            ExtensionHostCallKind::ClockNow => {
                require_empty(request)?;
                serde_json::to_vec(&self.deterministic_clock()?)
                    .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
            }
            ExtensionHostCallKind::RandomFill => {
                let length: [u8; 4] = request
                    .try_into()
                    .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
                self.deterministic_random(
                    usize::try_from(u32::from_be_bytes(length))
                        .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?,
                )?
            }
            ExtensionHostCallKind::Trace => {
                self.begin_call(ExtensionHostCapability::StructuredTracing, 1)?;
                self.check_input(request)?;
                Vec::new()
            }
            ExtensionHostCallKind::CheckCancelled => {
                self.begin_call_allow_cancel(ExtensionHostCapability::Cancellation, 1)?;
                require_empty(request)?;
                vec![u8::from(self.is_cancelled())]
            }
            ExtensionHostCallKind::NetworkRequest => {
                self.network_request(require_handle(handle)?, request)?
            }
            ExtensionHostCallKind::FileRead => {
                let path = std::str::from_utf8(request)
                    .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
                self.file_read(
                    require_handle(handle)?,
                    &SandboxPath::new(path.to_owned())
                        .map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))?,
                )?
            }
            ExtensionHostCallKind::FileWrite => {
                let (path, bytes) = decode_file_write(request)?;
                self.file_write(require_handle(handle)?, &path, bytes)?;
                Vec::new()
            }
            ExtensionHostCallKind::ResolveSecret => {
                self.dispatch_with_secret(require_handle(handle)?, request)?
            }
        };
        let completed_at = self.clock.wall_now()?;
        let ordinal = self.host_call_count();
        let call = ExtensionHostCallV1 {
            schema_version: SchemaVersion::new("cigar.extension-host-call", 1)
                .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?,
            call_id: call_id(&self.invocation_id, ordinal)?,
            invocation_id: self.invocation_id.clone(),
            ordinal,
            kind,
            capability: kind.required_capability(),
            handle: handle.cloned(),
            request_digest: raw_content_digest(request)?,
            request: request.to_vec(),
            response_digest: raw_content_digest(&response)?,
            response: response.clone(),
            started_at,
            completed_at,
        };
        call.validate()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        self.transcript
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
            .push(call, pending, self.maximum_transcript_bytes)?;
        Ok(response)
    }

    fn maximum_response_reservation(
        &self,
        kind: ExtensionHostCallKind,
        request: &[u8],
    ) -> Result<usize, ExtensionHostError> {
        match kind {
            ExtensionHostCallKind::Trace | ExtensionHostCallKind::FileWrite => Ok(0),
            ExtensionHostCallKind::CheckCancelled => Ok(1),
            ExtensionHostCallKind::RandomFill => {
                let length: [u8; 4] = request
                    .try_into()
                    .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
                usize::try_from(u32::from_be_bytes(length))
                    .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))
            }
            _ => usize::try_from(self.activated.manifest().limits.max_output_bytes)
                .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted)),
        }
    }

    /// Grants protected source bytes only after manifest classification and current-policy checks.
    pub fn grant_source(
        &self,
        bytes: Vec<u8>,
        classification: Classification,
    ) -> Result<ExtensionHandle, ExtensionHostError> {
        self.require(ExtensionHostCapability::SourceRead)?;
        self.authorize_protected(classification)?;
        self.insert(BrokerResource::Source { bytes })
    }

    /// Grants protected blob bytes only after manifest classification and current-policy checks.
    pub fn grant_blob(
        &self,
        bytes: Vec<u8>,
        classification: Classification,
    ) -> Result<ExtensionHandle, ExtensionHostError> {
        self.require(ExtensionHostCapability::BlobRead)?;
        self.authorize_protected(classification)?;
        self.insert(BrokerResource::Blob { bytes })
    }

    /// Grants a host-owned iterator whose values remain bounded and opaque until requested.
    pub fn grant_iterator(
        &self,
        values: Vec<Vec<u8>>,
    ) -> Result<ExtensionHandle, ExtensionHostError> {
        self.require(ExtensionHostCapability::BoundedIterator)?;
        let maximum = usize::try_from(self.activated.manifest().limits.max_output_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        if values.iter().any(|value| value.len() > maximum) || values.len() > maximum {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        self.insert(BrokerResource::Iterator {
            values,
            position: 0,
        })
    }

    /// Grants one exact endpoint already present in the signed manifest allowlist.
    pub fn grant_endpoint(
        &self,
        endpoint: NetworkEndpoint,
    ) -> Result<ExtensionHandle, ExtensionHostError> {
        self.require(ExtensionHostCapability::Network)?;
        if self
            .activated
            .manifest()
            .network_allowlist
            .binary_search(&endpoint)
            .is_err()
        {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        self.insert(BrokerResource::Endpoint(endpoint))
    }

    /// Grants one exact manifest preopen rooted at an operator-selected canonical directory.
    pub fn grant_preopen(
        &self,
        descriptor: SandboxPreopen,
        operator_root: &Path,
    ) -> Result<ExtensionHandle, ExtensionHostError> {
        self.require(ExtensionHostCapability::FilesystemRead)?;
        if descriptor.access == SandboxAccess::ReadWrite {
            self.require(ExtensionHostCapability::FilesystemWrite)?;
        }
        if self
            .activated
            .manifest()
            .filesystem_preopens
            .binary_search(&descriptor)
            .is_err()
        {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let canonical_root = operator_root
            .canonicalize()
            .map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))?;
        if !canonical_root.is_absolute() || !canonical_root.is_dir() {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        self.insert(BrokerResource::Preopen {
            descriptor,
            canonical_root,
        })
    }

    /// Grants a host-owned secret reference. The reference and secret are never returned by reads.
    pub fn grant_secret_reference(
        &self,
        secret_reference: impl Into<String>,
    ) -> Result<ExtensionHandle, ExtensionHostError> {
        self.require(ExtensionHostCapability::SecretHandle)?;
        let reference = secret_reference.into();
        if reference.is_empty() || reference.len() > 512 || reference.chars().any(char::is_control)
        {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        self.insert(BrokerResource::SecretReference(reference))
    }

    /// Reads bounded source bytes through one invocation-owned source handle.
    pub fn read_source(&self, handle: &ExtensionHandle) -> Result<Vec<u8>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::SourceRead, 1)?;
        self.read_bytes(handle, true)
    }

    /// Reads bounded blob bytes through one invocation-owned blob handle.
    pub fn read_blob(&self, handle: &ExtensionHandle) -> Result<Vec<u8>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::BlobRead, 1)?;
        self.read_bytes(handle, false)
    }

    /// Advances one bounded host-owned iterator.
    pub fn iterator_next(
        &self,
        handle: &ExtensionHandle,
    ) -> Result<Option<Vec<u8>>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::BoundedIterator, 1)?;
        let mut resources = self.resources()?;
        let Some(BrokerResource::Iterator { values, position }) = resources.get_mut(handle) else {
            return Err(error(ExtensionHostErrorCode::InvalidHandle));
        };
        let value = values.get(*position).cloned();
        if value.is_some() {
            *position = position
                .checked_add(1)
                .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        }
        Ok(value)
    }

    /// Returns the invocation-fixed deterministic clock when explicitly granted.
    pub fn deterministic_clock(&self) -> Result<UtcTimestamp, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::DeterministicClock, 1)?;
        self.deterministic_clock
            .ok_or_else(|| error(ExtensionHostErrorCode::CapabilityDenied))
    }

    /// Fills bytes from a reproducible SHA-256 counter stream when explicitly granted.
    pub fn deterministic_random(&self, length: usize) -> Result<Vec<u8>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::DeterministicRandom, 1)?;
        let maximum = usize::try_from(self.activated.manifest().limits.max_output_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        if length > maximum {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            let counter = self.random_counter.fetch_add(1, Ordering::SeqCst);
            let mut hasher = Sha256::new();
            hasher.update(b"CIGAR-EXTENSION-RANDOM\0v1\0");
            hasher.update(&self.deterministic_random_seed);
            hasher.update(counter.to_be_bytes());
            let block = hasher.finalize();
            let remaining = length - output.len();
            let take = remaining.min(block.len());
            let Some(chunk) = block.get(..take) else {
                return Err(error(ExtensionHostErrorCode::ResourceExhausted));
            };
            output.extend_from_slice(chunk);
        }
        Ok(output)
    }

    /// Sends a request through the operator network boundary for one exact endpoint handle.
    pub fn network_request(
        &self,
        handle: &ExtensionHandle,
        request: &[u8],
    ) -> Result<Vec<u8>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::Network, 1)?;
        self.check_input(request)?;
        let resources = self.resources()?;
        let Some(BrokerResource::Endpoint(endpoint)) = resources.get(handle) else {
            return Err(error(ExtensionHostErrorCode::InvalidHandle));
        };
        let response =
            self.network_boundary
                .request(endpoint, request, self.maximum_output_bytes()?)?;
        self.check_output(&response)?;
        Ok(response)
    }

    /// Reads one existing file beneath an exact preopen, rejecting traversal and symlink escape.
    pub fn file_read(
        &self,
        handle: &ExtensionHandle,
        relative_path: &SandboxPath,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::FilesystemRead, 1)?;
        let resources = self.resources()?;
        let Some(BrokerResource::Preopen { canonical_root, .. }) = resources.get(handle) else {
            return Err(error(ExtensionHostErrorCode::InvalidHandle));
        };
        let target = canonical_root
            .join(relative_path.as_str())
            .canonicalize()
            .map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))?;
        if !target.starts_with(canonical_root) || !target.is_file() {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let bytes =
            fs::read(target).map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))?;
        self.check_output(&bytes)?;
        Ok(bytes)
    }

    /// Writes one existing file beneath a read/write preopen after canonical containment checks.
    pub fn file_write(
        &self,
        handle: &ExtensionHandle,
        relative_path: &SandboxPath,
        bytes: &[u8],
    ) -> Result<(), ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::FilesystemWrite, 1)?;
        self.check_input(bytes)?;
        let resources = self.resources()?;
        let Some(BrokerResource::Preopen {
            descriptor,
            canonical_root,
        }) = resources.get(handle)
        else {
            return Err(error(ExtensionHostErrorCode::InvalidHandle));
        };
        if descriptor.access != SandboxAccess::ReadWrite {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let target = canonical_root
            .join(relative_path.as_str())
            .canonicalize()
            .map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))?;
        if !target.starts_with(canonical_root) || !target.is_file() {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        fs::write(target, bytes).map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))
    }

    /// Resolves a secret handle only inside the final outbound boundary and returns its response.
    pub fn dispatch_with_secret(
        &self,
        handle: &ExtensionHandle,
        request: &[u8],
    ) -> Result<Vec<u8>, ExtensionHostError> {
        self.begin_call(ExtensionHostCapability::SecretHandle, 1)?;
        self.check_input(request)?;
        let resources = self.resources()?;
        let Some(BrokerResource::SecretReference(reference)) = resources.get(handle) else {
            return Err(error(ExtensionHostErrorCode::InvalidHandle));
        };
        let response =
            self.secret_boundary
                .dispatch(reference, request, self.maximum_output_bytes()?)?;
        self.check_output(&response)?;
        Ok(response)
    }

    /// Checks an explicit nested host-call depth before entering extension recursion.
    pub fn check_recursion_depth(&self, depth: u16) -> Result<(), ExtensionHostError> {
        if depth == 0 || depth > self.activated.manifest().limits.max_recursion_depth {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        Ok(())
    }

    fn authorize_protected(
        &self,
        classification: Classification,
    ) -> Result<(), ExtensionHostError> {
        if self
            .activated
            .manifest()
            .source_classifications
            .binary_search(&classification)
            .is_err()
            || !self.protected_policy.authorize(ProtectedDataAuthorization {
                extension_id: &self.activated.manifest().extension_id,
                kind: self.kind,
                operation: &self.operation,
                processor: &self.processor,
                classification,
            })
        {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        Ok(())
    }

    fn insert(&self, resource: BrokerResource) -> Result<ExtensionHandle, ExtensionHostError> {
        let mut resources = self.resources()?;
        if resources.len() >= cigar_protocol::limits::MAX_EXTENSION_HANDLES {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        for _attempt in 0..16 {
            let mut bytes = [0_u8; cigar_protocol::limits::EXTENSION_HANDLE_BYTES];
            getrandom::fill(&mut bytes)
                .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
            let handle = ExtensionHandle::new(bytes);
            if !resources.contains_key(&handle) {
                resources.insert(handle.clone(), resource);
                return Ok(handle);
            }
        }
        Err(error(ExtensionHostErrorCode::BackendUnavailable))
    }

    fn read_bytes(
        &self,
        handle: &ExtensionHandle,
        source: bool,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        let resources = self.resources()?;
        let bytes = match (source, resources.get(handle)) {
            (true, Some(BrokerResource::Source { bytes }))
            | (false, Some(BrokerResource::Blob { bytes })) => bytes,
            _ => return Err(error(ExtensionHostErrorCode::InvalidHandle)),
        };
        self.check_output(bytes)?;
        Ok(bytes.clone())
    }

    fn begin_call(
        &self,
        capability: ExtensionHostCapability,
        depth: u16,
    ) -> Result<(), ExtensionHostError> {
        if self.is_cancelled() {
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        self.require(capability)?;
        self.check_recursion_depth(depth)?;
        let previous = self.host_calls.fetch_add(1, Ordering::SeqCst);
        if previous >= self.activated.manifest().limits.max_host_calls {
            self.host_calls.fetch_sub(1, Ordering::SeqCst);
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        Ok(())
    }

    fn begin_call_allow_cancel(
        &self,
        capability: ExtensionHostCapability,
        depth: u16,
    ) -> Result<(), ExtensionHostError> {
        self.require(capability)?;
        self.check_recursion_depth(depth)?;
        let previous = self.host_calls.fetch_add(1, Ordering::SeqCst);
        if previous >= self.activated.manifest().limits.max_host_calls {
            self.host_calls.fetch_sub(1, Ordering::SeqCst);
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        Ok(())
    }

    fn require(&self, capability: ExtensionHostCapability) -> Result<(), ExtensionHostError> {
        if self.capabilities.contains(&capability) {
            Ok(())
        } else {
            Err(error(ExtensionHostErrorCode::CapabilityDenied))
        }
    }

    fn check_input(&self, bytes: &[u8]) -> Result<(), ExtensionHostError> {
        let maximum = usize::try_from(self.activated.manifest().limits.max_input_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        if bytes.len() > maximum {
            Err(error(ExtensionHostErrorCode::ResourceExhausted))
        } else {
            Ok(())
        }
    }

    fn check_output(&self, bytes: &[u8]) -> Result<(), ExtensionHostError> {
        if bytes.len() > self.maximum_output_bytes()? {
            Err(error(ExtensionHostErrorCode::ResourceExhausted))
        } else {
            Ok(())
        }
    }

    fn maximum_output_bytes(&self) -> Result<usize, ExtensionHostError> {
        usize::try_from(self.activated.manifest().limits.max_output_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))
    }

    fn resources(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, BTreeMap<ExtensionHandle, BrokerResource>>,
        ExtensionHostError,
    > {
        self.resources
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
    }
}

fn require_handle(
    handle: Option<&ExtensionHandle>,
) -> Result<&ExtensionHandle, ExtensionHostError> {
    handle.ok_or_else(|| error(ExtensionHostErrorCode::InvalidHandle))
}

fn require_empty(request: &[u8]) -> Result<(), ExtensionHostError> {
    if request.is_empty() {
        Ok(())
    } else {
        Err(error(ExtensionHostErrorCode::InvalidInput))
    }
}

fn decode_file_write(request: &[u8]) -> Result<(SandboxPath, &[u8]), ExtensionHostError> {
    let length: [u8; 2] = request
        .get(..2)
        .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?
        .try_into()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
    let path_length = usize::from(u16::from_be_bytes(length));
    let path_end = 2_usize
        .checked_add(path_length)
        .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?;
    let path = request
        .get(2..path_end)
        .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?;
    let bytes = request
        .get(path_end..)
        .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?;
    let path =
        std::str::from_utf8(path).map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
    Ok((
        SandboxPath::new(path.to_owned())
            .map_err(|_error| error(ExtensionHostErrorCode::CapabilityDenied))?,
        bytes,
    ))
}

fn call_id(invocation_id: &RecordId, ordinal: u32) -> Result<RecordId, ExtensionHostError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-EXTENSION-HOST-CALL\0v1\0");
    hasher.update(invocation_id.as_str().as_bytes());
    hasher.update(ordinal.to_be_bytes());
    let mut bytes: [u8; 16] = hasher
        .finalize()
        .get(..16)
        .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?
        .try_into()
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    RecordId::new(encoded).map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
}
