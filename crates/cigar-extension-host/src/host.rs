//! Backend-neutral invocation lifecycle, concurrency, deadlines, cancellation, and validation.

use crate::broker::{CapabilityBroker, TranscriptArchive, empty_transcript_archive};
use crate::clock::HostClock;
use crate::digest::{canonical_record_digest, raw_content_digest};
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use crate::manifest::ActivatedExtension;
use cigar_crypto::MonotonicUuidV7Generator;
use cigar_protocol::{
    ContentDigest, ExtensionDeterminism, ExtensionHostCallV1, ExtensionId, ExtensionInvocationV1,
    ExtensionObservationV1, ExtensionResponseOutcome, ExtensionResponseV1, ExtensionRuntimeKind,
    RecordId, SchemaVersion, UtcTimestamp, Validate,
};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cloneable cooperative cancellation authority for one invocation.
#[derive(Clone, Debug)]
pub struct InvocationCancellation {
    cancelled: Arc<AtomicBool>,
}

impl InvocationCancellation {
    /// Requests cancellation. Once set, the state never returns to active.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// One validated logical invocation.
///
/// A request represents exactly one third-party runtime attempt. The v1 host deliberately exposes
/// no caller-controlled automatic-retry flag: operation mutability is not part of the signed
/// extension manifest, so a caller assertion cannot prove that replay is safe. A higher layer may
/// create a new request only after applying its own durable, operation-specific recovery contract.
pub struct InvocationRequest {
    invocation: ExtensionInvocationV1,
    cancellation: InvocationCancellation,
    broker: Option<Arc<CapabilityBroker>>,
}

impl fmt::Debug for InvocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationRequest")
            .field("invocation", &self.invocation)
            .field("cancelled", &self.cancellation.is_cancelled())
            .field("has_broker", &self.broker.is_some())
            .finish_non_exhaustive()
    }
}

impl InvocationRequest {
    /// Creates one request and validates all protocol-level invocation invariants.
    pub fn new(invocation: ExtensionInvocationV1) -> Result<Self, ExtensionHostError> {
        invocation
            .validate()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
        Ok(Self {
            invocation,
            cancellation: InvocationCancellation {
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            broker: None,
        })
    }

    /// Attaches the invocation-scoped capability broker used by runtime host calls.
    ///
    /// Attachment atomically and permanently claims the broker for this one attempt. A dropped,
    /// rejected, crashed, cancelled, or completed request never makes that broker reusable.
    pub fn with_broker(
        mut self,
        broker: Arc<CapabilityBroker>,
    ) -> Result<Self, ExtensionHostError> {
        if broker.invocation_id() != &self.invocation.invocation_id {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        for handle in &self.invocation.handles {
            if !broker.owns_handle(handle)? {
                return Err(error(ExtensionHostErrorCode::InvalidHandle));
            }
        }
        broker.claim_attempt()?;
        self.broker = Some(broker);
        Ok(self)
    }

    /// Returns cancellation authority that remains usable after the request starts executing.
    #[must_use]
    pub fn cancellation(&self) -> InvocationCancellation {
        self.cancellation.clone()
    }

    /// Returns the protected protocol invocation.
    #[must_use]
    pub const fn invocation(&self) -> &ExtensionInvocationV1 {
        &self.invocation
    }
}

/// Tentative backend result. Only a clean backend boundary may become a trusted host response.
#[derive(Clone, Debug)]
pub struct RuntimeResponse {
    response: ExtensionResponseV1,
    completed_cleanly: bool,
}

impl RuntimeResponse {
    /// Records a response followed by a clean isolated-runtime shutdown or authenticated close.
    #[must_use]
    pub const fn completed(response: ExtensionResponseV1) -> Self {
        Self {
            response,
            completed_cleanly: true,
        }
    }

    /// Records a response observed before a crash; the host will reject it.
    #[must_use]
    pub const fn crashed_after_response(response: ExtensionResponseV1) -> Self {
        Self {
            response,
            completed_cleanly: false,
        }
    }
}

/// Isolated execution boundary implementing one authenticated runtime kind.
pub trait ExtensionBackend: Send + Sync {
    /// Returns the exact runtime kind implemented by this backend.
    fn runtime_kind(&self) -> ExtensionRuntimeKind;

    /// Executes one invocation before an absolute monotonic deadline.
    fn invoke(
        &self,
        invocation: &ExtensionInvocationV1,
        deadline: Instant,
        cancellation: InvocationCancellation,
        broker: Option<Arc<CapabilityBroker>>,
    ) -> Result<RuntimeResponse, ExtensionHostError>;
}

/// Fully bound result of one clean, validated extension invocation.
///
/// This is the trusted commit boundary. Backend errors, crashes, malformed responses, and
/// observation-construction failures never produce this value. The invocation and transcript may
/// contain protected bytes; its `Debug` implementation reports only safe metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct InvocationOutcome {
    invocation: ExtensionInvocationV1,
    response: ExtensionResponseV1,
    observation: ExtensionObservationV1,
    host_call_transcript: Arc<TranscriptArchive>,
    response_digest: ContentDigest,
}

impl fmt::Debug for InvocationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationOutcome")
            .field("invocation_id", &self.invocation.invocation_id)
            .field("extension_id", &self.invocation.extension_id)
            .field("determinism", &self.observation.determinism)
            .field("outcome", &self.response.outcome)
            .field("input_digest", &self.invocation.input_digest)
            .field("response_digest", &self.response_digest)
            .field(
                "host_call_transcript_digest",
                &self.observation.host_call_transcript_digest,
            )
            .field("host_call_count", &self.host_call_transcript.len())
            .finish_non_exhaustive()
    }
}

impl InvocationOutcome {
    /// Returns the exact invocation that must be retained for replay.
    #[must_use]
    pub const fn invocation(&self) -> &ExtensionInvocationV1 {
        &self.invocation
    }

    /// Returns the clean, host-validated terminal response.
    #[must_use]
    pub const fn response(&self) -> &ExtensionResponseV1 {
        &self.response
    }

    /// Returns the validated observation binding all replay-relevant metadata.
    #[must_use]
    pub const fn observation(&self) -> &ExtensionObservationV1 {
        &self.observation
    }

    /// Returns the exact ordered protected broker transcript bound by the observation digest.
    #[must_use]
    pub fn host_call_transcript(&self) -> &[ExtensionHostCallV1] {
        self.host_call_transcript.as_slice()
    }

    /// Returns the digest of the complete canonical response record.
    #[must_use]
    pub const fn response_digest(&self) -> &ContentDigest {
        &self.response_digest
    }

    /// Returns whether this outcome must be retained as an explicit replay dependency.
    #[must_use]
    pub fn replay_dependency_required(&self) -> bool {
        self.observation.determinism == ExtensionDeterminism::Nondeterministic
    }

    /// Revalidates every record, digest, ordering constraint, and cross-record binding.
    pub fn validate(&self) -> Result<(), ExtensionHostError> {
        validate_outcome(self)
    }

    /// Decomposes the outcome into records suitable for a trusted durable replay archive.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ExtensionInvocationV1,
        ExtensionResponseV1,
        ExtensionObservationV1,
        Vec<ExtensionHostCallV1>,
        ContentDigest,
    ) {
        let Self {
            invocation,
            response,
            observation,
            host_call_transcript,
            response_digest,
        } = self;
        let transcript = match Arc::try_unwrap(host_call_transcript) {
            Ok(archive) => archive.into_calls(),
            Err(archive) => archive.as_slice().to_vec(),
        };
        (
            invocation,
            response,
            observation,
            transcript,
            response_digest,
        )
    }
}

/// Computes the frozen digest of an exact ordered host-call transcript.
///
/// The digest is the raw SHA-256 multihash of the transcript's strict deterministic-CBOR array.
/// Every call and protected request/response digest is validated before hashing.
pub fn host_call_transcript_digest(
    transcript: &[ExtensionHostCallV1],
) -> Result<ContentDigest, ExtensionHostError> {
    validate_transcript_shape(transcript)?;
    canonical_record_digest(&transcript)
}

/// Computes the frozen digest of a complete extension response record.
///
/// The digest is the raw SHA-256 multihash of the response's strict deterministic-CBOR map.
pub fn extension_response_digest(
    response: &ExtensionResponseV1,
) -> Result<ContentDigest, ExtensionHostError> {
    response
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    validate_response_content_digest(response)?;
    canonical_record_digest(response)
}

struct ExtensionSlot {
    activated: ActivatedExtension,
    backend: Arc<dyn ExtensionBackend>,
    active: AtomicU16,
}

struct InvocationPermit {
    slot: Arc<ExtensionSlot>,
}

impl Drop for InvocationPermit {
    fn drop(&mut self) {
        self.slot.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Registry and lifecycle coordinator for authenticated extension backends.
pub struct ExtensionHost {
    slots: Mutex<BTreeMap<ExtensionId, Arc<ExtensionSlot>>>,
    clock: Arc<dyn HostClock>,
    observation_ids: MonotonicUuidV7Generator,
}

impl fmt::Debug for ExtensionHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.slots.lock().map_or(0, |slots| slots.len());
        formatter
            .debug_struct("ExtensionHost")
            .field("activated_extension_count", &count)
            .finish_non_exhaustive()
    }
}

impl ExtensionHost {
    /// Creates an empty extension registry with an explicit trusted clock pair.
    #[must_use]
    pub fn new(clock: Arc<dyn HostClock>) -> Self {
        Self {
            slots: Mutex::new(BTreeMap::new()),
            clock,
            observation_ids: MonotonicUuidV7Generator::default(),
        }
    }

    /// Registers one already-authenticated extension with an exact matching runtime boundary.
    pub fn register(
        &self,
        activated: ActivatedExtension,
        backend: Arc<dyn ExtensionBackend>,
    ) -> Result<(), ExtensionHostError> {
        if backend.runtime_kind() != activated.manifest().runtime {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        let mut slots = self
            .slots
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        if slots.contains_key(&activated.manifest().extension_id) {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        slots.insert(
            activated.manifest().extension_id.clone(),
            Arc::new(ExtensionSlot {
                activated,
                backend,
                active: AtomicU16::new(0),
            }),
        );
        Ok(())
    }

    /// Runs a deterministic invocation and returns its validated response.
    ///
    /// This compatibility API rejects nondeterministic extensions before execution because their
    /// observation cannot safely be discarded. Use [`Self::invoke_observed`] for every
    /// nondeterministic invocation and whenever an explicit replay record is desired.
    pub fn invoke(
        &self,
        request: InvocationRequest,
    ) -> Result<ExtensionResponseV1, ExtensionHostError> {
        let slot = self.prepare(&request)?;
        if slot.activated.manifest().determinism == ExtensionDeterminism::Nondeterministic {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        self.invoke_prepared(request, slot)
            .map(|outcome| outcome.response)
    }

    /// Runs an invocation and emits its complete validated replay dependency.
    ///
    /// No caller-visible outcome exists until the runtime has closed cleanly and the response,
    /// exact broker transcript, canonical digests, and observation have all validated.
    pub fn invoke_observed(
        &self,
        request: InvocationRequest,
    ) -> Result<InvocationOutcome, ExtensionHostError> {
        let slot = self.prepare(&request)?;
        self.invoke_prepared(request, slot)
    }

    fn prepare(
        &self,
        request: &InvocationRequest,
    ) -> Result<Arc<ExtensionSlot>, ExtensionHostError> {
        let slot = {
            let slots = self
                .slots
                .lock()
                .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
            slots
                .get(&request.invocation.extension_id)
                .cloned()
                .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?
        };
        validate_invocation_binding(&slot.activated, &request.invocation)?;
        Ok(slot)
    }

    fn invoke_prepared(
        &self,
        request: InvocationRequest,
        slot: Arc<ExtensionSlot>,
    ) -> Result<InvocationOutcome, ExtensionHostError> {
        let _permit = acquire(slot.clone())?;
        let deadline = monotonic_deadline(
            self.clock.as_ref(),
            request.invocation.deadline_at.unix_nanos(),
        )?;
        if let Some(broker) = &request.broker {
            broker.bind_attempt_runtime(deadline, request.cancellation.clone())?;
        }
        if request.cancellation.is_cancelled() {
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        let started_at = self.clock.wall_now()?;

        if self.clock.monotonic_now() >= deadline {
            return Err(error(ExtensionHostErrorCode::DeadlineExceeded));
        }
        let runtime = slot.backend.invoke(
            &request.invocation,
            deadline,
            request.cancellation.clone(),
            request.broker.clone(),
        )?;
        if self.clock.monotonic_now() >= deadline {
            return Err(error(ExtensionHostErrorCode::DeadlineExceeded));
        }
        if !runtime.completed_cleanly {
            return Err(error(ExtensionHostErrorCode::ExtensionCrashed));
        }
        validate_response(
            &slot.activated,
            &request.invocation,
            &runtime.response,
            request.broker.as_deref(),
        )?;
        if request.cancellation.is_cancelled()
            && runtime.response.outcome != ExtensionResponseOutcome::Cancelled
        {
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        let completed_at = self.clock.wall_now()?;
        if completed_at < started_at {
            return Err(error(ExtensionHostErrorCode::BackendUnavailable));
        }
        let completed_millis = u64::try_from(
            completed_at
                .unix_nanos()
                .checked_div(1_000_000)
                .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?,
        )
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let observation_id = RecordId::new(
            self.observation_ids
                .generate_at(completed_millis)
                .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?
                .to_string(),
        )
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        build_outcome(
            &slot.activated,
            request.invocation,
            runtime.response,
            request.broker.as_deref(),
            observation_id,
            started_at,
            completed_at,
        )
    }

    pub(crate) fn is_declared_deterministic(
        &self,
        extension_id: &ExtensionId,
        manifest_digest: &ContentDigest,
    ) -> Result<bool, ExtensionHostError> {
        let slots = self
            .slots
            .lock()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let slot = slots
            .get(extension_id)
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?;
        if slot.activated.manifest_digest() != manifest_digest {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        Ok(slot.activated.manifest().determinism == ExtensionDeterminism::Deterministic)
    }
}

fn build_outcome(
    activated: &ActivatedExtension,
    invocation: ExtensionInvocationV1,
    response: ExtensionResponseV1,
    broker: Option<&CapabilityBroker>,
    observation_id: RecordId,
    started_at: UtcTimestamp,
    completed_at: UtcTimestamp,
) -> Result<InvocationOutcome, ExtensionHostError> {
    let transcript: Arc<TranscriptArchive> = match broker {
        Some(broker) => broker.finalize_transcript()?,
        None => empty_transcript_archive()?,
    };
    validate_transcript_binding(&invocation, &response, transcript.as_slice())?;
    let transcript_digest = host_call_transcript_digest(transcript.as_slice())?;
    let response_digest = extension_response_digest(&response)?;
    let manifest = activated.manifest();
    let observation = ExtensionObservationV1 {
        schema_version: SchemaVersion::new("cigar.extension-observation", 1)
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?,
        observation_id,
        invocation_id: invocation.invocation_id.clone(),
        extension_id: manifest.extension_id.clone(),
        extension_version: manifest.extension_version,
        manifest_digest: activated.manifest_digest().clone(),
        implementation_digest: manifest.implementation_digest.clone(),
        package_digest: manifest.package_digest.clone(),
        kind: invocation.kind,
        determinism: manifest.determinism,
        input_digest: invocation.input_digest.clone(),
        effective_limits: invocation.effective_limits.clone(),
        host_call_transcript_digest: transcript_digest,
        host_call_count: response.host_call_count,
        outcome: response.outcome,
        output_schema_digest: response.output_schema_digest.clone(),
        output_digest: response.output_digest.clone(),
        started_at,
        completed_at,
    };
    observation
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    let outcome = InvocationOutcome {
        invocation,
        response,
        observation,
        host_call_transcript: transcript,
        response_digest,
    };
    outcome.validate()?;
    Ok(outcome)
}

fn acquire(slot: Arc<ExtensionSlot>) -> Result<InvocationPermit, ExtensionHostError> {
    let maximum = slot.activated.manifest().limits.max_concurrency;
    let mut observed = slot.active.load(Ordering::SeqCst);
    loop {
        if observed >= maximum {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        match slot.active.compare_exchange(
            observed,
            observed.saturating_add(1),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return Ok(InvocationPermit { slot }),
            Err(current) => observed = current,
        }
    }
}

fn validate_invocation_binding(
    activated: &ActivatedExtension,
    invocation: &ExtensionInvocationV1,
) -> Result<(), ExtensionHostError> {
    let manifest = activated.manifest();
    if invocation.extension_id != manifest.extension_id
        || invocation.extension_version != manifest.extension_version
        || &invocation.manifest_digest != activated.manifest_digest()
        || manifest.kinds.binary_search(&invocation.kind).is_err()
        || invocation.effective_limits != manifest.limits
        || raw_content_digest(&invocation.input)? != invocation.input_digest
        || invocation.authorized_capabilities.iter().any(|capability| {
            manifest
                .required_host_capabilities
                .binary_search(capability)
                .is_err()
        })
    {
        return Err(error(ExtensionHostErrorCode::InvalidInput));
    }
    let Some(binding) = manifest
        .schema_bindings
        .iter()
        .find(|binding| binding.kind == invocation.kind)
    else {
        return Err(error(ExtensionHostErrorCode::InvalidInput));
    };
    if binding.input_schema_digest != invocation.input_schema_digest {
        return Err(error(ExtensionHostErrorCode::DigestMismatch));
    }
    Ok(())
}

fn validate_response(
    activated: &ActivatedExtension,
    invocation: &ExtensionInvocationV1,
    response: &ExtensionResponseV1,
    broker: Option<&CapabilityBroker>,
) -> Result<(), ExtensionHostError> {
    response
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    if response.invocation_id != invocation.invocation_id
        || response.host_call_count > invocation.effective_limits.max_host_calls
        || response.completed_at.unix_nanos() > invocation.deadline_at.unix_nanos()
    {
        return Err(error(ExtensionHostErrorCode::InvalidResponse));
    }
    let expected_host_calls = broker.map_or(0, CapabilityBroker::host_call_count);
    if response.host_call_count != expected_host_calls
        || broker.is_some_and(|broker| broker.transcript_len() != Ok(expected_host_calls as usize))
    {
        return Err(error(ExtensionHostErrorCode::InvalidResponse));
    }
    if response.outcome == ExtensionResponseOutcome::Succeeded {
        let binding = activated
            .manifest()
            .schema_bindings
            .iter()
            .find(|binding| binding.kind == invocation.kind)
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidResponse))?;
        if response.output_schema_digest.as_ref() != Some(&binding.output_schema_digest)
            || response.output_digest.as_ref() != Some(&raw_content_digest(&response.output)?)
            || u64::try_from(response.output.len()).map_or(true, |length| {
                length > invocation.effective_limits.max_output_bytes
            })
        {
            return Err(error(ExtensionHostErrorCode::DigestMismatch));
        }
    }
    Ok(())
}

fn validate_response_content_digest(
    response: &ExtensionResponseV1,
) -> Result<(), ExtensionHostError> {
    if response.outcome == ExtensionResponseOutcome::Succeeded
        && response.output_digest.as_ref() != Some(&raw_content_digest(&response.output)?)
    {
        return Err(error(ExtensionHostErrorCode::DigestMismatch));
    }
    Ok(())
}

fn validate_transcript_shape(transcript: &[ExtensionHostCallV1]) -> Result<(), ExtensionHostError> {
    let mut invocation_id: Option<&RecordId> = None;
    let mut previous_completed = None;
    for (index, call) in transcript.iter().enumerate() {
        call.validate()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
        let ordinal = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
        if call.ordinal != ordinal
            || invocation_id.is_some_and(|expected| expected != &call.invocation_id)
            || previous_completed.is_some_and(|previous| call.started_at < previous)
        {
            return Err(error(ExtensionHostErrorCode::InvalidResponse));
        }
        if call.request_digest != raw_content_digest(&call.request)?
            || call.response_digest != raw_content_digest(&call.response)?
        {
            return Err(error(ExtensionHostErrorCode::DigestMismatch));
        }
        invocation_id = Some(&call.invocation_id);
        previous_completed = Some(call.completed_at);
    }
    Ok(())
}

fn validate_transcript_binding(
    invocation: &ExtensionInvocationV1,
    response: &ExtensionResponseV1,
    transcript: &[ExtensionHostCallV1],
) -> Result<(), ExtensionHostError> {
    validate_transcript_shape(transcript)?;
    if transcript.len() != response.host_call_count as usize {
        return Err(error(ExtensionHostErrorCode::InvalidResponse));
    }
    for call in transcript {
        if call.invocation_id != invocation.invocation_id
            || invocation
                .authorized_capabilities
                .binary_search(&call.capability)
                .is_err()
            || call
                .handle
                .as_ref()
                .is_some_and(|handle| invocation.handles.binary_search(handle).is_err())
        {
            return Err(error(ExtensionHostErrorCode::InvalidResponse));
        }
    }
    Ok(())
}

fn validate_outcome(outcome: &InvocationOutcome) -> Result<(), ExtensionHostError> {
    outcome
        .invocation
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    outcome
        .observation
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    outcome
        .response
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    validate_response_content_digest(&outcome.response)?;
    validate_transcript_binding(
        &outcome.invocation,
        &outcome.response,
        outcome.host_call_transcript.as_slice(),
    )?;
    let observation = &outcome.observation;
    let invocation = &outcome.invocation;
    let response = &outcome.response;
    if observation.invocation_id != invocation.invocation_id
        || observation.extension_id != invocation.extension_id
        || observation.extension_version != invocation.extension_version
        || observation.manifest_digest != invocation.manifest_digest
        || observation.kind != invocation.kind
        || observation.input_digest != invocation.input_digest
        || observation.effective_limits != invocation.effective_limits
        || observation.host_call_count != response.host_call_count
        || observation.outcome != response.outcome
        || observation.output_schema_digest != response.output_schema_digest
        || observation.output_digest != response.output_digest
        || observation.host_call_transcript_digest
            != host_call_transcript_digest(outcome.host_call_transcript.as_slice())?
        || outcome.response_digest != extension_response_digest(response)?
    {
        return Err(error(ExtensionHostErrorCode::InvalidResponse));
    }
    if outcome.host_call_transcript.as_slice().iter().any(|call| {
        call.started_at < observation.started_at || call.completed_at > observation.completed_at
    }) {
        return Err(error(ExtensionHostErrorCode::InvalidResponse));
    }
    Ok(())
}

fn monotonic_deadline(
    clock: &dyn HostClock,
    deadline_unix_nanos: i128,
) -> Result<Instant, ExtensionHostError> {
    let now_nanos = clock.wall_now()?.unix_nanos();
    let remaining = deadline_unix_nanos
        .checked_sub(now_nanos)
        .ok_or_else(|| error(ExtensionHostErrorCode::DeadlineExceeded))?;
    let remaining = u64::try_from(remaining)
        .map_err(|_error| error(ExtensionHostErrorCode::DeadlineExceeded))?;
    clock
        .monotonic_now()
        .checked_add(Duration::from_nanos(remaining))
        .ok_or_else(|| error(ExtensionHostErrorCode::DeadlineExceeded))
}
