//! Core immutable catalog atom and its governed envelopes.

use crate::limits::{
    MAX_GOVERNANCE_SELECTORS, MAX_INLINE_TEXT_BYTES, MAX_RETRIEVAL_TERM_BYTES, MAX_RETRIEVAL_TERMS,
    MAX_SCOPE_PROJECTS, MAX_SELECTOR_BYTES, MAX_SOURCE_REVISION_BYTES,
};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    CanonicalValue, ContentDigest, ExtensionMap, FixedPoint, LineageId, MediaType, RecordId,
    RelativePath, SchemaVersion, SourceUri, UtcTimestamp, Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Closed semantic atom kind registry for v1.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AtomKind {
    /// Governed instruction content.
    Instruction,
    /// Exact source code.
    SourceCode,
    /// Human-facing documentation.
    Documentation,
    /// Durable decision or rationale.
    Decision,
    /// Conversation-derived context.
    Conversation,
    /// Tool observation or result.
    ToolResult,
    /// Machine-readable schema.
    Schema,
    /// Policy source material.
    Policy,
    /// Test or verification material.
    Test,
    /// Build or release artifact metadata.
    Artifact,
}

/// Reference to encrypted content-addressed payload bytes.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    /// Exact content digest.
    pub digest: ContentDigest,
    /// Plaintext payload size before encryption.
    pub size_bytes: u64,
    /// Payload media type.
    pub media_type: MediaType,
}

/// Atom content representation. Null and floating-point payload states are unrepresentable.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AtomPayload {
    /// Exact bounded UTF-8 content.
    InlineText(#[schemars(length(max = MAX_INLINE_TEXT_BYTES))] String),
    /// Structured canonical value without null or floating point.
    Structured(CanonicalValue),
    /// Content-addressed external blob.
    Blob(BlobRef),
}

impl fmt::Debug for AtomPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InlineText(value) => formatter
                .debug_struct("InlineText")
                .field("bytes", &value.len())
                .finish(),
            Self::Structured(value) => formatter.debug_tuple("Structured").field(value).finish(),
            Self::Blob(value) => formatter
                .debug_struct("Blob")
                .field("digest", &value.digest)
                .field("size_bytes", &value.size_bytes)
                .field("media_type", &value.media_type)
                .finish(),
        }
    }
}

/// Immutable source snapshot coordinates for an atom.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDescriptor {
    /// Absolute source URI.
    pub uri: SourceUri,
    /// Exact path bytes relative to the connector root, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<RelativePath>,
    /// Connector-specific immutable source revision.
    #[schemars(length(min = 1, max = MAX_SOURCE_REVISION_BYTES))]
    pub revision: String,
    /// Digest of the atomic source snapshot.
    pub snapshot_digest: ContentDigest,
}

impl fmt::Debug for SourceDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceDescriptor")
            .field("uri", &self.uri)
            .field("has_relative_path", &self.relative_path.is_some())
            .field("revision_bytes", &self.revision.len())
            .field("snapshot_digest", &self.snapshot_digest)
            .finish()
    }
}

/// Tenant and project isolation coordinates.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEnvelope {
    /// Owning tenant identity.
    pub tenant_id: RecordId,
    /// Sorted unique project identities authorized to observe the atom.
    #[schemars(length(min = 1, max = MAX_SCOPE_PROJECTS))]
    pub project_ids: Vec<RecordId>,
}

impl fmt::Debug for ScopeEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopeEnvelope")
            .field("project_count", &self.project_ids.len())
            .finish_non_exhaustive()
    }
}

/// Bitemporal truth envelope for catalog selection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalEnvelope {
    /// Earliest valid semantic time.
    pub valid_from: UtcTimestamp,
    /// Exclusive semantic validity end, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<UtcTimestamp>,
    /// Time at which CIGAR observed this version.
    pub observed_at: UtcTimestamp,
}

/// Closed information-classification states.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Safe for unrestricted publication.
    Public,
    /// Restricted to the owning organization.
    Internal,
    /// Confidential protected context.
    Confidential,
    /// Highest sensitivity requiring explicit grants.
    Restricted,
}

/// Closed instruction-authority levels used by non-bypassable policy gates.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum InstructionAuthority {
    /// Content is data and cannot issue instructions.
    Data,
    /// Advisory material that may inform but cannot override project rules.
    Advisory,
    /// Project-authorized instructions.
    Project,
    /// System-authorized instructions.
    System,
}

/// Governance metadata required before retrieval or compilation.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEnvelope {
    /// Information classification.
    pub classification: Classification,
    /// Sorted unique allowed-purpose selectors.
    #[schemars(length(min = 1, max = MAX_GOVERNANCE_SELECTORS), inner(length(min = 1, max = MAX_SELECTOR_BYTES)))]
    pub allowed_purposes: Vec<String>,
    /// Sorted unique processor constraints.
    #[schemars(length(max = MAX_GOVERNANCE_SELECTORS), inner(length(min = 1, max = MAX_SELECTOR_BYTES)))]
    pub processor_constraints: Vec<String>,
    /// Authority of any instruction-like content.
    pub instruction_authority: InstructionAuthority,
}

impl fmt::Debug for GovernanceEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernanceEnvelope")
            .field("classification", &self.classification)
            .field("allowed_purpose_count", &self.allowed_purposes.len())
            .field(
                "processor_constraint_count",
                &self.processor_constraints.len(),
            )
            .field("instruction_authority", &self.instruction_authority)
            .finish()
    }
}

/// Bounded quality signals used by deterministic planning.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEnvelope {
    /// Fixed-point confidence in millionths.
    pub confidence: FixedPoint,
    /// Fixed-point source coverage in millionths.
    pub coverage: FixedPoint,
    /// Non-zero authority tier; larger is more authoritative.
    pub authority: u16,
}

/// Retrieval-only metadata that never overrides current policy.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalEnvelope {
    /// Sorted unique exact retrieval terms.
    #[schemars(length(max = MAX_RETRIEVAL_TERMS), inner(length(min = 1, max = MAX_RETRIEVAL_TERM_BYTES)))]
    pub exact_terms: Vec<String>,
    /// Whether lexical indexing may include protected content through an authorized index.
    pub lexical_enabled: bool,
    /// Whether policy may permit an embedding request.
    pub embedding_eligible: bool,
}

impl fmt::Debug for RetrievalEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalEnvelope")
            .field("exact_term_count", &self.exact_terms.len())
            .field("lexical_enabled", &self.lexical_enabled)
            .field("embedding_eligible", &self.embedding_eligible)
            .finish()
    }
}

/// Closed immutable atom lifecycle.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Eligible for governed selection.
    Active,
    /// Replaced by another immutable version.
    Superseded,
    /// Logically removed but retained for provenance.
    Tombstoned,
    /// Withheld due to integrity or security concerns.
    Quarantined,
}

/// Immutable v1 catalog atom with complete provenance and governance envelopes.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAtomV1 {
    /// Must be `cigar.atom.v1`.
    pub schema_version: SchemaVersion,
    /// Unique immutable record identity.
    pub atom_id: RecordId,
    /// Stable semantic lineage identity.
    pub lineage_id: LineageId,
    /// Digest-derived semantic version identity.
    pub version_id: VersionId,
    /// Digest of the exact content payload.
    pub content_digest: ContentDigest,
    /// Semantic atom kind.
    pub kind: AtomKind,
    /// Protected payload representation.
    pub payload: AtomPayload,
    /// Immutable source coordinates.
    pub source: SourceDescriptor,
    /// Tenant and project scope.
    pub scope: ScopeEnvelope,
    /// Valid and observation time coordinates.
    pub temporal: TemporalEnvelope,
    /// Governance gates.
    pub governance: GovernanceEnvelope,
    /// Bounded quality signals.
    pub quality: QualityEnvelope,
    /// Policy-subordinate retrieval metadata.
    pub retrieval: RetrievalEnvelope,
    /// Current immutable lifecycle state.
    pub lifecycle: Lifecycle,
    /// Required successor for a superseded record and forbidden otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<VersionId>,
    /// Bounded stable extension map.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for ContextAtomV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextAtomV1")
            .field("schema_version", &self.schema_version)
            .field("atom_id", &self.atom_id)
            .field("lineage_id", &self.lineage_id)
            .field("version_id", &self.version_id)
            .field("content_digest", &self.content_digest)
            .field("kind", &self.kind)
            .field("payload", &self.payload)
            .field("source", &self.source)
            .field("scope", &self.scope)
            .field("temporal", &self.temporal)
            .field("governance", &self.governance)
            .field("quality", &self.quality)
            .field("retrieval", &self.retrieval)
            .field("lifecycle", &self.lifecycle)
            .field("has_successor", &self.superseded_by.is_some())
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Validate for ContextAtomV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if let Err(found) = self.schema_version.require_v1("cigar.atom") {
            errors.merge(found);
        }
        validate_payload(&self.payload, &mut errors);
        validate_source(&self.source, &mut errors);
        validate_scope(&self.scope, &mut errors);
        validate_temporal(&self.temporal, &mut errors);
        validate_governance(&self.governance, &mut errors);
        if self.quality.authority == 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/quality/authority",
                "quality authority must be non-zero",
            ));
        }
        validate_retrieval(&self.retrieval, &mut errors);
        match (self.lifecycle, self.superseded_by.is_some()) {
            (Lifecycle::Superseded, false) => errors.push(issue(
                ValidationCode::InvalidValue,
                "/superseded_by",
                "superseded atom requires a successor version",
            )),
            (Lifecycle::Active | Lifecycle::Tombstoned | Lifecycle::Quarantined, true) => {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    "/superseded_by",
                    "only a superseded atom may name a successor version",
                ));
            }
            (Lifecycle::Superseded, true)
            | (Lifecycle::Active | Lifecycle::Tombstoned | Lifecycle::Quarantined, false) => {}
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
    }
}

fn validate_payload(payload: &AtomPayload, errors: &mut ValidationErrors) {
    match payload {
        AtomPayload::InlineText(value) => {
            if value.is_empty() || value.len() > MAX_INLINE_TEXT_BYTES {
                errors.push(issue(
                    ValidationCode::LimitExceeded,
                    "/payload/value",
                    "inline text must be non-empty and within the byte maximum",
                ));
            }
        }
        AtomPayload::Structured(value) => {
            if let Err(found) = value.validate() {
                errors.merge(found);
            }
        }
        AtomPayload::Blob(value) if value.size_bytes == 0 => errors.push(issue(
            ValidationCode::InvalidValue,
            "/payload/value/size_bytes",
            "blob size must be non-zero",
        )),
        AtomPayload::Blob(_) => {}
    }
}

fn validate_source(source: &SourceDescriptor, errors: &mut ValidationErrors) {
    if source.revision.is_empty() || source.revision.len() > MAX_SOURCE_REVISION_BYTES {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            "/source/revision",
            "source revision must be non-empty and bounded",
        ));
    }
}

fn validate_scope(scope: &ScopeEnvelope, errors: &mut ValidationErrors) {
    if scope.project_ids.is_empty() || scope.project_ids.len() > MAX_SCOPE_PROJECTS {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            "/scope/project_ids",
            "project scope must be non-empty and bounded",
        ));
    }
    if !strictly_sorted_unique(&scope.project_ids) {
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/scope/project_ids",
            "project identities must be sorted and unique",
        ));
    }
}

fn validate_temporal(temporal: &TemporalEnvelope, errors: &mut ValidationErrors) {
    if temporal
        .valid_until
        .is_some_and(|until| until <= temporal.valid_from)
    {
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/temporal/valid_until",
            "valid-until must be later than valid-from",
        ));
    }
    if temporal.observed_at < temporal.valid_from {
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/temporal/observed_at",
            "observation time cannot precede valid-from",
        ));
    }
}

fn validate_governance(governance: &GovernanceEnvelope, errors: &mut ValidationErrors) {
    validate_string_set(
        &governance.allowed_purposes,
        true,
        "/governance/allowed_purposes",
        errors,
    );
    validate_string_set(
        &governance.processor_constraints,
        false,
        "/governance/processor_constraints",
        errors,
    );
}

fn validate_retrieval(retrieval: &RetrievalEnvelope, errors: &mut ValidationErrors) {
    if retrieval.exact_terms.len() > MAX_RETRIEVAL_TERMS {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            "/retrieval/exact_terms",
            "exact retrieval term collection exceeds the maximum",
        ));
    }
    if retrieval
        .exact_terms
        .iter()
        .any(|term| term.is_empty() || term.len() > MAX_RETRIEVAL_TERM_BYTES)
    {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            "/retrieval/exact_terms",
            "an exact retrieval term is empty or exceeds its byte maximum",
        ));
    }
    if !strictly_sorted_unique(&retrieval.exact_terms) {
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/retrieval/exact_terms",
            "exact retrieval terms must be sorted and unique",
        ));
    }
}

fn validate_string_set(
    values: &[String],
    non_empty: bool,
    path: &str,
    errors: &mut ValidationErrors,
) {
    if (non_empty && values.is_empty()) || values.len() > MAX_GOVERNANCE_SELECTORS {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            path,
            "governance selector collection is empty or exceeds the maximum",
        ));
    }
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_SELECTOR_BYTES)
    {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            path,
            "governance selector is empty or exceeds its byte maximum",
        ));
    }
    if !strictly_sorted_unique(values) {
        errors.push(issue(
            ValidationCode::InvalidValue,
            path,
            "governance selectors must be sorted and unique",
        ));
    }
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| {
        let Some(first) = window.first() else {
            return false;
        };
        let Some(second) = window.get(1) else {
            return false;
        };
        first < second
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AtomKind, AtomPayload, Classification, ContextAtomV1, GovernanceEnvelope,
        InstructionAuthority, Lifecycle, QualityEnvelope, RetrievalEnvelope, ScopeEnvelope,
        SourceDescriptor, TemporalEnvelope,
    };
    use crate::{
        ContentDigest, ExtensionMap, FixedPoint, LineageId, RecordId, SchemaVersion, SourceUri,
        UtcTimestamp, Validate, VersionId,
    };

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn valid_atom() -> Result<ContextAtomV1, Box<dyn std::error::Error>> {
        let valid_from = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?;
        let observed_at = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:01Z")?;
        Ok(ContextAtomV1 {
            schema_version: "cigar.atom.v1".parse()?,
            atom_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            lineage_id: LineageId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?,
            version_id: version('a')?,
            content_digest: digest('b')?,
            kind: AtomKind::Documentation,
            payload: AtomPayload::InlineText("safe fixture".to_owned()),
            source: SourceDescriptor {
                uri: SourceUri::new("file:///fixture/readme.md")?,
                relative_path: None,
                revision: "fixture-revision-1".to_owned(),
                snapshot_digest: digest('c')?,
            },
            scope: ScopeEnvelope {
                tenant_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
                project_ids: vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7893")?],
            },
            temporal: TemporalEnvelope {
                valid_from,
                valid_until: None,
                observed_at,
            },
            governance: GovernanceEnvelope {
                classification: Classification::Internal,
                allowed_purposes: vec!["coding".to_owned()],
                processor_constraints: Vec::new(),
                instruction_authority: InstructionAuthority::Data,
            },
            quality: QualityEnvelope {
                confidence: FixedPoint::new(900_000)?,
                coverage: FixedPoint::new(800_000)?,
                authority: 1,
            },
            retrieval: RetrievalEnvelope {
                exact_terms: vec!["cigar".to_owned()],
                lexical_enabled: true,
                embedding_eligible: false,
            },
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn minimal_atom_validates_and_round_trips_json() -> Result<(), Box<dyn std::error::Error>> {
        let atom = valid_atom()?;
        atom.validate()?;
        let json = serde_json::to_string(&atom)?;
        let decoded: ContextAtomV1 = serde_json::from_str(&json)?;
        assert_eq!(decoded, atom);
        decoded.validate()?;
        Ok(())
    }

    #[test]
    fn validation_aggregates_independent_failures() -> Result<(), Box<dyn std::error::Error>> {
        let mut atom = valid_atom()?;
        atom.schema_version = SchemaVersion::new("cigar.atom", 2)?;
        atom.payload = AtomPayload::InlineText(String::new());
        atom.scope.project_ids.clear();
        atom.governance.allowed_purposes.clear();
        atom.quality.authority = 0;
        atom.lifecycle = Lifecycle::Superseded;
        let Err(errors) = atom.validate() else {
            return Err("invalid atom unexpectedly passed".into());
        };
        assert!(errors.len() >= 6);
        Ok(())
    }

    #[test]
    fn lifecycle_successor_invariant_is_bidirectional() -> Result<(), Box<dyn std::error::Error>> {
        let mut atom = valid_atom()?;
        atom.lifecycle = Lifecycle::Superseded;
        assert!(atom.validate().is_err());
        atom.superseded_by = Some(version('d')?);
        assert!(atom.validate().is_ok());
        atom.lifecycle = Lifecycle::Active;
        assert!(atom.validate().is_err());
        Ok(())
    }

    #[test]
    fn atom_debug_never_contains_payload() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "fixture-sensitive-content";
        let mut atom = valid_atom()?;
        atom.payload = AtomPayload::InlineText(secret.to_owned());
        let rendered = format!("{atom:?}");
        assert!(!rendered.contains(secret));
        Ok(())
    }
}
