//! Compatibility-safe semantic reuse helpers for downstream Honey integrations.

use crate::{ErrorKind, SdkError};
use cigar_api::TraceId;
use cigar_protocol::{ContentDigest, RecordId, RetryClass};
use sha2::{Digest as _, Sha256};
use std::fmt;

const SEMANTIC_REQUEST_KEY_DOMAIN: &[u8] = b"CIGAR-SDK-SEMANTIC-REQUEST-KEY\0v1\0";
const EXECUTION_RECEIPT_DOMAIN: &[u8] = b"CIGAR-SDK-EXECUTION-RECEIPT\0v1\0";

/// Whether every semantic extension is understood and included in the normalized-need digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticExtensionStatus {
    /// No extension is present, or every present extension is understood and included.
    Known,
    /// At least one extension has unknown semantic effect.
    Unknown,
}

/// Whether the downstream caller can prove the exact current authorization domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityStatus {
    /// The authorization commitment is complete and current.
    Certain,
    /// The authorization commitment may be incomplete or stale.
    Uncertain,
}

/// Exact semantic and governance pins that define one reusable compilation request.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticReusePins {
    /// Digest of the normalized context need, including every understood semantic extension.
    pub normalized_need_digest: ContentDigest,
    /// Exact governed catalog/index watermark.
    pub catalog_watermark: ContentDigest,
    /// Commitment to the complete principal authorization domain.
    pub authorization_domain_digest: ContentDigest,
    /// Commitment to the effective disclosure/privacy partition.
    pub disclosure_domain_digest: ContentDigest,
    /// Exact effective policy digest.
    pub policy_digest: ContentDigest,
    /// Exact target profile digest.
    pub target_profile_digest: ContentDigest,
    /// Exact tokenizer fingerprint.
    pub tokenizer_fingerprint: ContentDigest,
    /// Exact materializer fingerprint.
    pub materializer_fingerprint: ContentDigest,
    /// Exact compiler/version/profile fingerprint.
    pub compiler_fingerprint: ContentDigest,
}

impl fmt::Debug for SemanticReusePins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticReusePins")
            .field("fields", &9)
            .finish_non_exhaustive()
    }
}

/// One request to derive or evaluate a stable downstream semantic reuse key.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticReuseRequest {
    /// Exact semantic and governance pins.
    pub pins: SemanticReusePins,
    /// Whether semantic extensions are completely understood.
    pub semantic_extensions: SemanticExtensionStatus,
    /// Whether current authority is known exactly.
    pub authority: AuthorityStatus,
}

impl fmt::Debug for SemanticReuseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticReuseRequest")
            .field("pins", &self.pins)
            .field("semantic_extensions", &self.semantic_extensions)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Stable domain-separated identity for a downstream semantic reuse lookup.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SemanticRequestKey(ContentDigest);

impl SemanticRequestKey {
    /// Returns the SHA-256 multihash commitment.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.0
    }
}

impl fmt::Debug for SemanticRequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SemanticRequestKey([REDACTED])")
    }
}

/// Closed, content-free reuse result suitable for metrics and audit summaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticReuseReason {
    /// Every pin matched and the artifact may be reused.
    Hit,
    /// No candidate existed for the stable key.
    AbsentEntry,
    /// The normalized semantic need differed.
    NormalizedNeedMismatch,
    /// The complete authorization commitment differed.
    AuthorizationMismatch,
    /// The disclosure/privacy partition differed.
    DisclosureMismatch,
    /// The effective policy differed.
    PolicyMismatch,
    /// The catalog/index watermark differed.
    WatermarkMismatch,
    /// The target profile differed.
    TargetMismatch,
    /// The tokenizer fingerprint differed.
    TokenizerMismatch,
    /// The materializer fingerprint differed.
    MaterializerMismatch,
    /// The compiler version/profile differed.
    CompilerMismatch,
    /// A candidate's stable semantic key did not authenticate its pins.
    SemanticKeyMismatch,
    /// An unknown semantic extension made reuse unsafe.
    UnknownSemanticExtension,
    /// Exact current authority could not be established.
    UncertainAuthority,
}

impl SemanticReuseReason {
    /// Returns the closed content-free label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::AbsentEntry => "absent_entry",
            Self::NormalizedNeedMismatch => "normalized_need_mismatch",
            Self::AuthorizationMismatch => "authorization_mismatch",
            Self::DisclosureMismatch => "disclosure_mismatch",
            Self::PolicyMismatch => "policy_mismatch",
            Self::WatermarkMismatch => "watermark_mismatch",
            Self::TargetMismatch => "target_mismatch",
            Self::TokenizerMismatch => "tokenizer_mismatch",
            Self::MaterializerMismatch => "materializer_mismatch",
            Self::CompilerMismatch => "compiler_mismatch",
            Self::SemanticKeyMismatch => "semantic_key_mismatch",
            Self::UnknownSemanticExtension => "unknown_semantic_extension",
            Self::UncertainAuthority => "uncertain_authority",
        }
    }
}

/// Stable-key construction result, including fail-closed bypasses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticRequestKeyDecision {
    /// Reuse lookup is safe under this key.
    Key(SemanticRequestKey),
    /// Reuse must be bypassed for the closed reason.
    Bypass(SemanticReuseReason),
}

/// One previously generated artifact and the exact pins that authorized it.
#[derive(Clone, Eq, PartialEq)]
pub struct ReusableSemanticArtifact {
    /// Stable key stored with the artifact.
    pub semantic_request_key: SemanticRequestKey,
    /// Digest of the complete sealed artifact.
    pub artifact_digest: ContentDigest,
    /// Exact pins stored with the artifact.
    pub pins: SemanticReusePins,
}

impl fmt::Debug for ReusableSemanticArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReusableSemanticArtifact")
            .field("semantic_request_key", &self.semantic_request_key)
            .field("artifact_digest", &"[REDACTED]")
            .field("pins", &self.pins)
            .finish()
    }
}

/// Exact reuse evaluation with no candidate details on a miss or bypass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticReuseEvaluation {
    reason: SemanticReuseReason,
    semantic_request_key: Option<SemanticRequestKey>,
    artifact_digest: Option<ContentDigest>,
}

impl SemanticReuseEvaluation {
    /// Returns the closed content-free decision reason.
    #[must_use]
    pub const fn reason(&self) -> SemanticReuseReason {
        self.reason
    }

    /// Returns the authenticated stable key only on a hit.
    #[must_use]
    pub const fn semantic_request_key(&self) -> Option<&SemanticRequestKey> {
        self.semantic_request_key.as_ref()
    }

    /// Returns the authenticated artifact digest only on a hit.
    #[must_use]
    pub const fn artifact_digest(&self) -> Option<&ContentDigest> {
        self.artifact_digest.as_ref()
    }

    /// Returns whether exact reuse is authorized.
    #[must_use]
    pub const fn is_hit(&self) -> bool {
        matches!(self.reason, SemanticReuseReason::Hit)
    }
}

/// Per-execution correlation kept outside the reusable semantic request identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionCorrelation {
    /// Fresh UUIDv7 identity for this execution receipt.
    pub operation_id: RecordId,
    /// Transport/distributed-trace identity for this execution.
    pub trace_id: TraceId,
    /// Optional protected digest of a downstream run identifier.
    pub run_correlation_digest: Option<ContentDigest>,
    /// Optional protected digest of a downstream job identifier.
    pub job_correlation_digest: Option<ContentDigest>,
}

impl fmt::Debug for ExecutionCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionCorrelation")
            .field("operation_id", &"[REDACTED]")
            .field("trace_id", &self.trace_id)
            .field("has_run", &self.run_correlation_digest.is_some())
            .field("has_job", &self.job_correlation_digest.is_some())
            .finish()
    }
}

/// Whether one execution generated or reused its bound artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionArtifactOutcome {
    /// A new artifact was generated for this execution.
    Generated,
    /// An existing exactly matching artifact was reused.
    Reused,
}

impl ExecutionArtifactOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Reused => "reused",
        }
    }
}

/// Downstream commitment binding one execution to one generated or reused artifact.
///
/// This compatibility helper is not the future protocol's server-signed receipt. A downstream
/// system can sign or persist this commitment under its own evidence policy.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticExecutionReceipt {
    semantic_request_key: SemanticRequestKey,
    artifact_digest: ContentDigest,
    correlation: ExecutionCorrelation,
    outcome: ExecutionArtifactOutcome,
    reason: SemanticReuseReason,
    receipt_digest: ContentDigest,
}

impl SemanticExecutionReceipt {
    /// Returns the stable semantic request key.
    #[must_use]
    pub const fn semantic_request_key(&self) -> &SemanticRequestKey {
        &self.semantic_request_key
    }

    /// Returns the exact generated or reused artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ContentDigest {
        &self.artifact_digest
    }

    /// Returns the unique per-execution correlation.
    #[must_use]
    pub const fn correlation(&self) -> &ExecutionCorrelation {
        &self.correlation
    }

    /// Returns whether the artifact was generated or reused.
    #[must_use]
    pub const fn outcome(&self) -> ExecutionArtifactOutcome {
        self.outcome
    }

    /// Returns the closed content-free reuse/miss/bypass reason.
    #[must_use]
    pub const fn reason(&self) -> SemanticReuseReason {
        self.reason
    }

    /// Returns the commitment over the artifact, semantic key, outcome, reason, and correlation.
    #[must_use]
    pub const fn receipt_digest(&self) -> &ContentDigest {
        &self.receipt_digest
    }
}

impl fmt::Debug for SemanticExecutionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticExecutionReceipt")
            .field("semantic_request_key", &self.semantic_request_key)
            .field("artifact_digest", &"[REDACTED]")
            .field("correlation", &self.correlation)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("receipt_digest", &"[REDACTED]")
            .finish()
    }
}

/// Constructs a stable semantic key or a fail-closed bypass decision.
///
/// Run, job, trace, attempt, timestamp, and idempotency values are deliberately absent from this
/// function's input type and therefore cannot perturb the semantic key.
pub fn semantic_request_key(
    request: &SemanticReuseRequest,
) -> Result<SemanticRequestKeyDecision, SdkError> {
    if matches!(
        request.semantic_extensions,
        SemanticExtensionStatus::Unknown
    ) {
        return Ok(SemanticRequestKeyDecision::Bypass(
            SemanticReuseReason::UnknownSemanticExtension,
        ));
    }
    if matches!(request.authority, AuthorityStatus::Uncertain) {
        return Ok(SemanticRequestKeyDecision::Bypass(
            SemanticReuseReason::UncertainAuthority,
        ));
    }
    Ok(SemanticRequestKeyDecision::Key(SemanticRequestKey(
        pins_digest(&request.pins)?,
    )))
}

/// Evaluates a candidate using exact semantic, authority, disclosure, policy, and component pins.
pub fn evaluate_semantic_reuse(
    request: &SemanticReuseRequest,
    candidate: Option<&ReusableSemanticArtifact>,
) -> Result<SemanticReuseEvaluation, SdkError> {
    let expected_key = match semantic_request_key(request)? {
        SemanticRequestKeyDecision::Bypass(reason) => return Ok(miss(reason)),
        SemanticRequestKeyDecision::Key(key) => key,
    };
    let Some(candidate) = candidate else {
        return Ok(miss(SemanticReuseReason::AbsentEntry));
    };
    let expected = &request.pins;
    let actual = &candidate.pins;
    let mismatch = if actual.normalized_need_digest != expected.normalized_need_digest {
        Some(SemanticReuseReason::NormalizedNeedMismatch)
    } else if actual.authorization_domain_digest != expected.authorization_domain_digest {
        Some(SemanticReuseReason::AuthorizationMismatch)
    } else if actual.disclosure_domain_digest != expected.disclosure_domain_digest {
        Some(SemanticReuseReason::DisclosureMismatch)
    } else if actual.policy_digest != expected.policy_digest {
        Some(SemanticReuseReason::PolicyMismatch)
    } else if actual.catalog_watermark != expected.catalog_watermark {
        Some(SemanticReuseReason::WatermarkMismatch)
    } else if actual.target_profile_digest != expected.target_profile_digest {
        Some(SemanticReuseReason::TargetMismatch)
    } else if actual.tokenizer_fingerprint != expected.tokenizer_fingerprint {
        Some(SemanticReuseReason::TokenizerMismatch)
    } else if actual.materializer_fingerprint != expected.materializer_fingerprint {
        Some(SemanticReuseReason::MaterializerMismatch)
    } else if actual.compiler_fingerprint != expected.compiler_fingerprint {
        Some(SemanticReuseReason::CompilerMismatch)
    } else if candidate.semantic_request_key != expected_key {
        Some(SemanticReuseReason::SemanticKeyMismatch)
    } else {
        None
    };
    if let Some(reason) = mismatch {
        return Ok(miss(reason));
    }
    Ok(SemanticReuseEvaluation {
        reason: SemanticReuseReason::Hit,
        semantic_request_key: Some(expected_key),
        artifact_digest: Some(candidate.artifact_digest.clone()),
    })
}

/// Creates a downstream execution-receipt commitment after an exact hit or a new compilation.
///
/// `Reused` requires `Hit`; `Generated` requires a miss or bypass reason. This prevents a receipt
/// from claiming reuse when the exact reuse evaluator did not authorize it.
pub fn bind_semantic_execution_receipt(
    semantic_request_key: SemanticRequestKey,
    artifact_digest: ContentDigest,
    correlation: ExecutionCorrelation,
    outcome: ExecutionArtifactOutcome,
    reason: SemanticReuseReason,
) -> Result<SemanticExecutionReceipt, SdkError> {
    let valid_pair = matches!(
        (outcome, reason),
        (ExecutionArtifactOutcome::Reused, SemanticReuseReason::Hit)
    ) || (matches!(outcome, ExecutionArtifactOutcome::Generated)
        && !matches!(reason, SemanticReuseReason::Hit));
    if !valid_pair {
        return Err(invalid_receipt());
    }
    let receipt_digest = execution_receipt_digest(
        &semantic_request_key,
        &artifact_digest,
        &correlation,
        outcome,
        reason,
    )?;
    Ok(SemanticExecutionReceipt {
        semantic_request_key,
        artifact_digest,
        correlation,
        outcome,
        reason,
        receipt_digest,
    })
}

fn miss(reason: SemanticReuseReason) -> SemanticReuseEvaluation {
    SemanticReuseEvaluation {
        reason,
        semantic_request_key: None,
        artifact_digest: None,
    }
}

fn pins_digest(pins: &SemanticReusePins) -> Result<ContentDigest, SdkError> {
    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_REQUEST_KEY_DOMAIN);
    update_digest(
        &mut hasher,
        b"normalized_need",
        &pins.normalized_need_digest,
    );
    update_digest(&mut hasher, b"catalog_watermark", &pins.catalog_watermark);
    update_digest(
        &mut hasher,
        b"authorization_domain",
        &pins.authorization_domain_digest,
    );
    update_digest(
        &mut hasher,
        b"disclosure_domain",
        &pins.disclosure_domain_digest,
    );
    update_digest(&mut hasher, b"policy", &pins.policy_digest);
    update_digest(&mut hasher, b"target", &pins.target_profile_digest);
    update_digest(&mut hasher, b"tokenizer", &pins.tokenizer_fingerprint);
    update_digest(&mut hasher, b"materializer", &pins.materializer_fingerprint);
    update_digest(&mut hasher, b"compiler", &pins.compiler_fingerprint);
    multihash(hasher)
}

fn execution_receipt_digest(
    semantic_request_key: &SemanticRequestKey,
    artifact_digest: &ContentDigest,
    correlation: &ExecutionCorrelation,
    outcome: ExecutionArtifactOutcome,
    reason: SemanticReuseReason,
) -> Result<ContentDigest, SdkError> {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_RECEIPT_DOMAIN);
    update_digest(
        &mut hasher,
        b"semantic_request_key",
        semantic_request_key.digest(),
    );
    update_digest(&mut hasher, b"artifact", artifact_digest);
    hasher.update(b"operation\0");
    hasher.update(correlation.operation_id.as_str().as_bytes());
    hasher.update(b"trace\0");
    hasher.update(correlation.trace_id.as_str().as_bytes());
    update_optional_digest(
        &mut hasher,
        b"run",
        correlation.run_correlation_digest.as_ref(),
    );
    update_optional_digest(
        &mut hasher,
        b"job",
        correlation.job_correlation_digest.as_ref(),
    );
    hasher.update(b"outcome\0");
    hasher.update(outcome.as_str().as_bytes());
    hasher.update(b"reason\0");
    hasher.update(reason.as_str().as_bytes());
    multihash(hasher)
}

fn update_digest(hasher: &mut Sha256, label: &[u8], value: &ContentDigest) {
    hasher.update(label);
    hasher.update([0]);
    hasher.update(value.as_str().as_bytes());
    hasher.update([0]);
}

fn update_optional_digest(hasher: &mut Sha256, label: &[u8], value: Option<&ContentDigest>) {
    hasher.update(label);
    hasher.update([0]);
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_str().as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update([0]);
}

fn multihash(hasher: Sha256) -> Result<ContentDigest, SdkError> {
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_failure| reuse_integrity_error())?;
    }
    ContentDigest::new(encoded).map_err(|_failure| reuse_integrity_error())
}

const fn invalid_receipt() -> SdkError {
    SdkError::local(
        ErrorKind::InvalidArgument,
        RetryClass::Never,
        "execution receipt outcome disagrees with reuse reason",
    )
}

const fn reuse_integrity_error() -> SdkError {
    SdkError::local(
        ErrorKind::Integrity,
        RetryClass::Never,
        "semantic reuse commitment construction failed",
    )
}
