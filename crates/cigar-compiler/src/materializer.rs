//! Provider materializers and exact versus estimated token accounting.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cigar_protocol::{
    ContentDigest, ContextBlock, ContextBundle, MaterializedContext, MediaType, SchemaVersion,
    Validate, VersionId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Stable materialization failure categories that never contain protected bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationError {
    /// The bundle or one of its inputs is malformed.
    InvalidInput,
    /// A block body is absent or does not match its declared content digest.
    ContentMismatch,
    /// Arithmetic or protocol output bounds were exceeded.
    LimitExceeded,
    /// Stable serialization failed.
    Serialization,
}

impl fmt::Display for MaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "context materialization failed: {self:?}")
    }
}

impl std::error::Error for MaterializationError {}

/// Exact tokenizer used for provider-ready accounting.
pub trait ExactTokenizer {
    /// Returns the immutable tokenizer fingerprint.
    fn fingerprint(&self) -> &ContentDigest;

    /// Counts exact physical tokens in provider-ready bytes.
    fn count_exact(&self, bytes: &[u8]) -> Result<u32, MaterializationError>;
}

/// Deterministic byte tokenizer useful for byte-metered targets and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteTokenizer {
    fingerprint: ContentDigest,
}

impl ByteTokenizer {
    /// Creates a byte tokenizer with an immutable configuration fingerprint.
    #[must_use]
    pub const fn new(fingerprint: ContentDigest) -> Self {
        Self { fingerprint }
    }
}

impl ExactTokenizer for ByteTokenizer {
    fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }

    fn count_exact(&self, bytes: &[u8]) -> Result<u32, MaterializationError> {
        u32::try_from(bytes.len()).map_err(|_error| MaterializationError::LimitExceeded)
    }
}

/// Deterministic Unicode-scalar tokenizer for text-target differential tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnicodeScalarTokenizer {
    fingerprint: ContentDigest,
}

impl UnicodeScalarTokenizer {
    /// Creates a Unicode-scalar tokenizer with an immutable fingerprint.
    #[must_use]
    pub const fn new(fingerprint: ContentDigest) -> Self {
        Self { fingerprint }
    }
}

impl ExactTokenizer for UnicodeScalarTokenizer {
    fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }

    fn count_exact(&self, bytes: &[u8]) -> Result<u32, MaterializationError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_error| MaterializationError::InvalidInput)?;
        u32::try_from(text.chars().count()).map_err(|_error| MaterializationError::LimitExceeded)
    }
}

/// Explicit conservative token estimate that cannot be passed as an exact count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConservativeTokenEstimate {
    /// Central deterministic estimate.
    pub estimated_tokens: u32,
    /// Non-negative upper error bound.
    pub maximum_error_tokens: u32,
}

impl ConservativeTokenEstimate {
    /// Returns the conservative planning upper bound.
    #[must_use]
    pub const fn upper_bound(self) -> u32 {
        self.estimated_tokens
            .saturating_add(self.maximum_error_tokens)
    }
}

/// Conservative estimator profile kept separate from exact tokenizer interfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConservativeEstimator {
    bytes_per_token: u32,
    error_parts_per_million: u32,
}

impl ConservativeEstimator {
    /// Creates a bounded estimator configuration.
    pub fn new(
        bytes_per_token: u32,
        error_parts_per_million: u32,
    ) -> Result<Self, MaterializationError> {
        if bytes_per_token == 0 || error_parts_per_million > 1_000_000 {
            return Err(MaterializationError::InvalidInput);
        }
        Ok(Self {
            bytes_per_token,
            error_parts_per_million,
        })
    }

    /// Estimates tokens with a declared error bound; this is never exact accounting.
    pub fn estimate(
        &self,
        bytes: &[u8],
    ) -> Result<ConservativeTokenEstimate, MaterializationError> {
        let length =
            u64::try_from(bytes.len()).map_err(|_error| MaterializationError::LimitExceeded)?;
        let divisor = u64::from(self.bytes_per_token);
        let estimated = length
            .saturating_add(divisor.saturating_sub(1))
            .checked_div(divisor)
            .ok_or(MaterializationError::LimitExceeded)?;
        let error = estimated
            .saturating_mul(u64::from(self.error_parts_per_million))
            .saturating_add(999_999)
            .checked_div(1_000_000)
            .ok_or(MaterializationError::LimitExceeded)?;
        Ok(ConservativeTokenEstimate {
            estimated_tokens: u32::try_from(estimated)
                .map_err(|_error| MaterializationError::LimitExceeded)?,
            maximum_error_tokens: u32::try_from(error)
                .map_err(|_error| MaterializationError::LimitExceeded)?,
        })
    }
}

/// Supported deterministic provider rendering profiles.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaterializerProfile {
    /// Canonical JSON block array.
    Json,
    /// Markdown-safe semantic records.
    Markdown,
    /// Compact fact-set records.
    FactSet,
    /// Claude prompt content blocks.
    ClaudePrompt,
    /// MCP resource contents.
    McpResource,
}

impl MaterializerProfile {
    fn identifier(self) -> &'static str {
        match self {
            Self::Json => "cigar.materializer.json.v1",
            Self::Markdown => "cigar.materializer.markdown.v1",
            Self::FactSet => "cigar.materializer.fact-set.v1",
            Self::ClaudePrompt => "cigar.materializer.claude-prompt.v1",
            Self::McpResource => "cigar.materializer.mcp-resource.v1",
        }
    }

    fn media_type(self) -> &'static str {
        match self {
            Self::Json | Self::FactSet | Self::ClaudePrompt | Self::McpResource => {
                "application/json"
            }
            Self::Markdown => "text/markdown",
        }
    }
}

/// Every independently meaningful token-accounting field for one request.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TokenAccounting {
    /// Full-context baseline before reuse or omission.
    pub baseline_tokens: u32,
    /// Exact physical tokens sent in this materialization.
    pub physical_input_tokens: u32,
    /// Exact reusable stable-prefix tokens.
    pub stable_prefix_tokens: u32,
    /// Exact delta tokens physically sent.
    pub delta_tokens: u32,
    /// Tokens avoided by exact duplicate elimination.
    pub deduplicated_tokens: u32,
    /// Tokens avoided by extractive representation choice.
    pub extractive_savings_tokens: u32,
    /// Tokens avoided by structural compaction.
    pub structural_savings_tokens: u32,
    /// Tokens avoided by an evidence-backed summary.
    pub summary_savings_tokens: u32,
    /// Tokens omitted because the provider has valid present state.
    pub provider_present_omitted_tokens: u32,
    /// Provider-reported cache-read tokens.
    pub provider_cache_read_tokens: u32,
    /// Provider-reported cache-write tokens.
    pub provider_cache_write_tokens: u32,
    /// Reserved provider output tokens.
    pub output_reserve_tokens: u32,
    /// Reserved runtime/tool tokens.
    pub runtime_reserve_tokens: u32,
    /// Estimated billable input tokens, never substituted for physical tokens.
    pub estimated_billable_input_tokens: u32,
    /// Provider-reported billable input tokens when known.
    pub provider_billable_input_tokens: Option<u32>,
}

/// Exact protected bodies keyed by semantic block identities.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct BlockBodies(BTreeMap<VersionId, Vec<u8>>);

impl fmt::Debug for BlockBodies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockBodies")
            .field("block_count", &self.0.len())
            .field("byte_count", &self.0.values().map(Vec::len).sum::<usize>())
            .finish()
    }
}

impl BlockBodies {
    /// Creates an empty protected-body collection.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Inserts exact bytes for one semantic block.
    pub fn insert(&mut self, block_id: VersionId, bytes: Vec<u8>) -> Option<Vec<u8>> {
        self.0.insert(block_id, bytes)
    }

    fn get(&self, block_id: &VersionId) -> Option<&[u8]> {
        self.0.get(block_id).map(Vec::as_slice)
    }

    fn keys(&self) -> impl Iterator<Item = &VersionId> {
        self.0.keys()
    }
}

#[derive(Serialize)]
struct RenderedBlock<'a> {
    block_id: &'a VersionId,
    lane: cigar_protocol::LaneKind,
    representation: cigar_protocol::RepresentationKind,
    content_digest: &'a ContentDigest,
    token_count: u32,
    provenance: &'a [VersionId],
    body_base64url: String,
}

#[derive(Serialize)]
struct JsonEnvelope<'a> {
    schema: &'static str,
    profile: &'static str,
    bundle_id: &'a VersionId,
    blocks: &'a [RenderedBlock<'a>],
}

/// Materializes every block without interpolation, lane escape, or silent truncation.
pub fn materialize(
    profile: MaterializerProfile,
    bundle: &ContextBundle,
    bodies: &BlockBodies,
    tokenizer: &dyn ExactTokenizer,
) -> Result<(MaterializedContext, TokenAccounting), MaterializationError> {
    bundle
        .validate()
        .map_err(|_error| MaterializationError::InvalidInput)?;
    let expected: BTreeSet<_> = bundle.blocks.iter().map(|block| &block.block_id).collect();
    let supplied: BTreeSet<_> = bodies.keys().collect();
    if expected != supplied {
        return Err(MaterializationError::ContentMismatch);
    }
    let rendered = bundle
        .blocks
        .iter()
        .map(|block| render_block(block, bodies))
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = render_profile(profile, bundle, &rendered)?;
    let token_count = tokenizer.count_exact(&bytes)?;
    if token_count == 0 {
        return Err(MaterializationError::InvalidInput);
    }
    let context = MaterializedContext {
        schema_version: SchemaVersion::new("cigar.materialized-context", 1)
            .map_err(|_error| MaterializationError::Serialization)?,
        bundle_id: bundle.bundle_id.clone(),
        media_type: MediaType::new(profile.media_type())
            .map_err(|_error| MaterializationError::Serialization)?,
        bytes,
        token_count,
        tokenizer_fingerprint: tokenizer.fingerprint().clone(),
        materializer_fingerprint: digest(profile.identifier().as_bytes())?,
    };
    context
        .validate()
        .map_err(|_error| MaterializationError::LimitExceeded)?;
    let accounting = TokenAccounting {
        baseline_tokens: token_count,
        physical_input_tokens: token_count,
        delta_tokens: token_count,
        estimated_billable_input_tokens: token_count,
        ..TokenAccounting::default()
    };
    Ok((context, accounting))
}

fn render_block<'a>(
    block: &'a ContextBlock,
    bodies: &BlockBodies,
) -> Result<RenderedBlock<'a>, MaterializationError> {
    let bytes = bodies
        .get(&block.block_id)
        .ok_or(MaterializationError::ContentMismatch)?;
    if digest(bytes)? != block.content_digest {
        return Err(MaterializationError::ContentMismatch);
    }
    Ok(RenderedBlock {
        block_id: &block.block_id,
        lane: block.lane,
        representation: block.representation,
        content_digest: &block.content_digest,
        token_count: block.token_count,
        provenance: &block.provenance,
        body_base64url: URL_SAFE_NO_PAD.encode(bytes),
    })
}

fn render_profile(
    profile: MaterializerProfile,
    bundle: &ContextBundle,
    blocks: &[RenderedBlock<'_>],
) -> Result<Vec<u8>, MaterializationError> {
    match profile {
        MaterializerProfile::Json => json_bytes(&JsonEnvelope {
            schema: "cigar.materialized.json.v1",
            profile: profile.identifier(),
            bundle_id: &bundle.bundle_id,
            blocks,
        }),
        MaterializerProfile::ClaudePrompt => json_bytes(&serde_json::json!({
            "schema": "cigar.materialized.claude-prompt.v1",
            "bundle_id": bundle.bundle_id,
            "content": blocks,
        })),
        MaterializerProfile::McpResource => json_bytes(&serde_json::json!({
            "schema": "cigar.materialized.mcp-resource.v1",
            "bundle_id": bundle.bundle_id,
            "contents": blocks,
            "mimeType": "application/json",
        })),
        MaterializerProfile::FactSet => json_bytes(&serde_json::json!({
            "schema": "cigar.materialized.fact-set.v1",
            "bundle_id": bundle.bundle_id,
            "facts": blocks,
        })),
        MaterializerProfile::Markdown => {
            let mut output = format!(
                "<!-- cigar.materialized.markdown.v1 bundle={} -->\n",
                bundle.bundle_id.as_str()
            );
            for block in blocks {
                let metadata = json_bytes(block)?;
                let encoded = URL_SAFE_NO_PAD.encode(metadata);
                output.push_str("<cigar-block metadata-base64url=\"");
                output.push_str(&encoded);
                output.push_str("\"></cigar-block>\n");
            }
            Ok(output.into_bytes())
        }
    }
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, MaterializationError> {
    serde_json::to_vec(value).map_err(|_error| MaterializationError::Serialization)
}

pub(crate) fn digest(bytes: &[u8]) -> Result<ContentDigest, MaterializationError> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| MaterializationError::Serialization)?;
    }
    ContentDigest::new(encoded).map_err(|_error| MaterializationError::Serialization)
}
