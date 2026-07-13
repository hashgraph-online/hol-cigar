//! Bounded deterministic-extension vector execution across fresh host threads.

use crate::digest::raw_content_digest;
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use crate::host::{ExtensionHost, InvocationRequest};
use cigar_protocol::{
    ContentDigest, ExtensionHostCapability, ExtensionInvocationV1, ExtensionKind,
    ExtensionResponseOutcome, ExtensionResponseV1, ExtensionSemanticVersion, Validate,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::thread;

/// Maximum fresh launches admitted by one in-process deterministic vector run.
pub const MAX_DETERMINISM_VECTOR_LAUNCHES: u16 = 64;

/// Published input/output expectation for one deterministic extension vector.
///
/// Invocation identity and wall timestamps may change between launches. Every semantic input,
/// declared deterministic source, output byte, output digest, and host-call count remains exact.
#[derive(Clone, Eq, PartialEq)]
pub struct DeterminismVector {
    extension_id: cigar_protocol::ExtensionId,
    extension_version: ExtensionSemanticVersion,
    manifest_digest: ContentDigest,
    kind: ExtensionKind,
    operation: String,
    input_schema_digest: ContentDigest,
    input_digest: ContentDigest,
    input: Vec<u8>,
    authorized_capabilities: Vec<ExtensionHostCapability>,
    handle_count: usize,
    deterministic_clock: Option<cigar_protocol::UtcTimestamp>,
    deterministic_random_seed: Vec<u8>,
    effective_limits: cigar_protocol::ExtensionLimits,
    expected_output_schema_digest: ContentDigest,
    expected_output_digest: ContentDigest,
    expected_output: Vec<u8>,
    expected_host_call_count: u32,
}

impl fmt::Debug for DeterminismVector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterminismVector")
            .field("extension_id", &self.extension_id)
            .field("extension_version", &self.extension_version)
            .field("manifest_digest", &self.manifest_digest)
            .field("kind", &self.kind)
            .field("operation_bytes", &self.operation.len())
            .field("input_schema_digest", &self.input_schema_digest)
            .field("input_digest", &self.input_digest)
            .field("input_bytes", &self.input.len())
            .field("capability_count", &self.authorized_capabilities.len())
            .field("handle_count", &self.handle_count)
            .field(
                "has_deterministic_clock",
                &self.deterministic_clock.is_some(),
            )
            .field(
                "deterministic_random_seed_bytes",
                &self.deterministic_random_seed.len(),
            )
            .field("expected_output_digest", &self.expected_output_digest)
            .field("expected_output_bytes", &self.expected_output.len())
            .field("expected_host_call_count", &self.expected_host_call_count)
            .finish_non_exhaustive()
    }
}

impl DeterminismVector {
    /// Binds a published vector to one validated invocation and successful expected response.
    pub fn new(
        invocation: &ExtensionInvocationV1,
        expected: &ExtensionResponseV1,
    ) -> Result<Self, ExtensionHostError> {
        invocation
            .validate()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
        expected
            .validate()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
        let output_schema_digest = expected
            .output_schema_digest
            .clone()
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?;
        let output_digest = expected
            .output_digest
            .clone()
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))?;
        if expected.invocation_id != invocation.invocation_id
            || expected.outcome != ExtensionResponseOutcome::Succeeded
            || output_digest != raw_content_digest(&expected.output)?
        {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        Ok(Self {
            extension_id: invocation.extension_id.clone(),
            extension_version: invocation.extension_version,
            manifest_digest: invocation.manifest_digest.clone(),
            kind: invocation.kind,
            operation: invocation.operation.clone(),
            input_schema_digest: invocation.input_schema_digest.clone(),
            input_digest: invocation.input_digest.clone(),
            input: invocation.input.clone(),
            authorized_capabilities: invocation.authorized_capabilities.clone(),
            handle_count: invocation.handles.len(),
            deterministic_clock: invocation.deterministic_clock,
            deterministic_random_seed: invocation.deterministic_random_seed.clone(),
            effective_limits: invocation.effective_limits.clone(),
            expected_output_schema_digest: output_schema_digest,
            expected_output_digest: output_digest,
            expected_output: expected.output.clone(),
            expected_host_call_count: expected.host_call_count,
        })
    }

    fn accepts(&self, invocation: &ExtensionInvocationV1) -> bool {
        self.extension_id == invocation.extension_id
            && self.extension_version == invocation.extension_version
            && self.manifest_digest == invocation.manifest_digest
            && self.kind == invocation.kind
            && self.operation == invocation.operation
            && self.input_schema_digest == invocation.input_schema_digest
            && self.input_digest == invocation.input_digest
            && self.input == invocation.input
            && self.authorized_capabilities == invocation.authorized_capabilities
            && self.handle_count == invocation.handles.len()
            && self.deterministic_clock == invocation.deterministic_clock
            && self.deterministic_random_seed == invocation.deterministic_random_seed
            && self.effective_limits == invocation.effective_limits
    }

    fn accepts_response(&self, response: &ExtensionResponseV1) -> bool {
        response.outcome == ExtensionResponseOutcome::Succeeded
            && response.output_schema_digest.as_ref() == Some(&self.expected_output_schema_digest)
            && response.output_digest.as_ref() == Some(&self.expected_output_digest)
            && response.output == self.expected_output
            && response.host_call_count == self.expected_host_call_count
    }
}

/// Bounded runner that permutes vector ordinals and executes every launch on a fresh host thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicVectorRunner {
    launches: u16,
    schedule_seed: [u8; 32],
}

impl DeterministicVectorRunner {
    /// Creates a runner requiring between two and sixty-four fresh launches.
    pub fn new(launches: u16, schedule_seed: [u8; 32]) -> Result<Self, ExtensionHostError> {
        if !(2..=MAX_DETERMINISM_VECTOR_LAUNCHES).contains(&launches) {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        Ok(Self {
            launches,
            schedule_seed,
        })
    }

    /// Runs a vector in a deterministic shuffled order using a fresh OS thread per launch.
    ///
    /// `request_for_launch` receives a one-based launch ordinal. It must create a fresh broker for
    /// host-call vectors. CI invokes the same published vector under each Tier-1 target and its
    /// locale/timezone matrix; WASI has no ambient environment and native subprocesses are forced
    /// to `C`/`UTC` by their backend.
    pub fn run<F>(
        &self,
        host: &ExtensionHost,
        vector: &DeterminismVector,
        request_for_launch: F,
    ) -> Result<DeterminismVectorReport, ExtensionHostError>
    where
        F: Fn(u16) -> Result<InvocationRequest, ExtensionHostError> + Sync,
    {
        let order = shuffled_launches(self.launches, self.schedule_seed);
        for launch in order {
            let request = request_for_launch(launch)?;
            if !vector.accepts(request.invocation())
                || !host.is_declared_deterministic(
                    &request.invocation().extension_id,
                    &request.invocation().manifest_digest,
                )?
            {
                return Err(error(ExtensionHostErrorCode::InvalidInput));
            }
            let response = thread::scope(|scope| {
                scope
                    .spawn(|| host.invoke(request))
                    .join()
                    .map_err(|_panic| error(ExtensionHostErrorCode::BackendUnavailable))?
            })?;
            if !vector.accepts_response(&response) {
                return Err(error(ExtensionHostErrorCode::DigestMismatch));
            }
        }
        Ok(DeterminismVectorReport {
            launches: self.launches,
            output_digest: vector.expected_output_digest.clone(),
            host_call_count: vector.expected_host_call_count,
        })
    }
}

/// Successful deterministic-vector evidence safe to include in conformance output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterminismVectorReport {
    launches: u16,
    output_digest: ContentDigest,
    host_call_count: u32,
}

impl DeterminismVectorReport {
    /// Returns the number of fresh launches which matched the vector.
    #[must_use]
    pub const fn launches(&self) -> u16 {
        self.launches
    }

    /// Returns the exact published semantic output digest matched by every launch.
    #[must_use]
    pub const fn output_digest(&self) -> &ContentDigest {
        &self.output_digest
    }

    /// Returns the exact host-call count matched by every launch.
    #[must_use]
    pub const fn host_call_count(&self) -> u32 {
        self.host_call_count
    }
}

fn shuffled_launches(launches: u16, seed: [u8; 32]) -> Vec<u16> {
    let mut values: Vec<_> = (1..=launches).collect();
    for upper in (1..values.len()).rev() {
        let mut hasher = Sha256::new();
        hasher.update(b"CIGAR-DETERMINISM-VECTOR-SCHEDULE\0v1\0");
        hasher.update(seed);
        hasher.update(u64::try_from(upper).unwrap_or(u64::MAX).to_be_bytes());
        let block = hasher.finalize();
        let selector_bytes: [u8; 8] = block
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or([0; 8]);
        let selector = u64::from_be_bytes(selector_bytes);
        let bound = u64::try_from(upper + 1).unwrap_or(u64::MAX);
        let selected = usize::try_from(selector % bound).unwrap_or(0);
        values.swap(upper, selected);
    }
    values
}
