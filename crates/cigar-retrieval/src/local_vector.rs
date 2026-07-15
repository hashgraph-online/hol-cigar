//! Immutable provider-neutral local quantized vector adapter.
//!
//! This module deliberately contains no model loader, network client, raw-text preprocessor, or
//! durable storage. A trusted processor must produce [`ProcessorApprovedVector`] values before
//! this boundary. Sealing copies only version identifiers and quantized vectors into a bounded
//! immutable map.

use crate::vector::{finish_digest, hash_frame};
use crate::{
    MAX_CANDIDATES, MAX_FEATURE_VALUE, MAX_VECTOR_DIMENSIONS, ProcessorApprovedVector,
    QueryVectorProcessor, RetrievalContext, RetrievalError, RetrievalErrorCode, VectorAdapter,
    VectorIndexBinding, VectorNeighbor, VectorQuery,
};
use cigar_protocol::{ContentDigest, RecordId, VersionId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Version bound into every local adapter processor binding and sealed fingerprint.
pub const LOCAL_VECTOR_ADAPTER_VERSION: &str = "cigar.local-quantized-vector.v1";
/// Built-in deterministic feature-hashing model used by the macOS local production cohort.
pub const DETERMINISTIC_LOCAL_VECTOR_MODEL_ID: &str = "cigar.deterministic-local-feature-hash.v1";
/// Exact normalization and bounded tokenization profile used by the built-in processor.
pub const DETERMINISTIC_LOCAL_VECTOR_PREPROCESSING_ID: &str = "cigar.normalized-term-set.v1";
/// Maximum immutable vectors accepted by one sealed local adapter.
pub const MAX_LOCAL_VECTOR_ENTRIES: usize = 100_000;
/// Maximum bytes in a model or preprocessing identifier.
pub const MAX_LOCAL_VECTOR_IDENTIFIER_BYTES: usize = 256;

/// Supported deterministic integer distance functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalVectorDistanceMetric {
    /// Sum of squared component deltas, normalized against the exact quantized domain maximum.
    SquaredEuclideanV1,
    /// Sum of absolute component deltas, normalized against the exact quantized domain maximum.
    ManhattanV1,
}

impl LocalVectorDistanceMetric {
    pub(crate) const fn identifier(self) -> &'static str {
        match self {
            Self::SquaredEuclideanV1 => "squared-euclidean-v1",
            Self::ManhattanV1 => "manhattan-v1",
        }
    }

    pub(crate) fn from_identifier(value: &str) -> Option<Self> {
        match value {
            "squared-euclidean-v1" => Some(Self::SquaredEuclideanV1),
            "manhattan-v1" => Some(Self::ManhattanV1),
            _ => None,
        }
    }
}

/// Fixed quantization profile supported by the local adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalVectorQuantization {
    /// Symmetric signed int8 values in the exact inclusive range -127 through 127.
    SymmetricInt8V1,
}

impl LocalVectorQuantization {
    pub(crate) const fn identifier(self) -> &'static str {
        match self {
            Self::SymmetricInt8V1 => "symmetric-int8-minus127-plus127-v1",
        }
    }

    pub(crate) fn from_identifier(value: &str) -> Option<Self> {
        match value {
            "symmetric-int8-minus127-plus127-v1" => Some(Self::SymmetricInt8V1),
            _ => None,
        }
    }
}

/// Validated construction parameters for one immutable local vector adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalVectorParameters {
    /// Exact provider-neutral model or embedding-process identity.
    pub model_id: String,
    /// Immutable model artifact/configuration fingerprint asserted by the processor boundary.
    pub model_fingerprint: ContentDigest,
    /// Exact non-zero vector dimension.
    pub dimension: usize,
    /// Exact preprocessing pipeline identity.
    pub preprocessing_id: String,
    /// Immutable preprocessing implementation/configuration fingerprint.
    pub preprocessing_fingerprint: ContentDigest,
    /// Deterministic integer distance function.
    pub distance_metric: LocalVectorDistanceMetric,
    /// Exact quantization domain.
    pub quantization: LocalVectorQuantization,
    /// Projection-domain digest for indexed vectors; queries add the exact policy partition.
    pub partition_digest: ContentDigest,
    /// Immutable identity of the vector projection generation.
    pub index_generation_id: RecordId,
    /// Maximum vectors admitted while sealing.
    pub maximum_entries: usize,
    /// Maximum neighbors admitted in one request.
    pub maximum_neighbors: usize,
}

impl fmt::Debug for LocalVectorParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalVectorParameters")
            .field("model_id_bytes", &self.model_id.len())
            .field("dimension", &self.dimension)
            .field("preprocessing_id_bytes", &self.preprocessing_id.len())
            .field("distance_metric", &self.distance_metric)
            .field("quantization", &self.quantization)
            .field("maximum_entries", &self.maximum_entries)
            .field("maximum_neighbors", &self.maximum_neighbors)
            .finish_non_exhaustive()
    }
}

/// Validated immutable adapter configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalVectorConfiguration {
    parameters: LocalVectorParameters,
    processor_binding: ContentDigest,
}

impl LocalVectorConfiguration {
    /// Validates and binds every processor, partition, generation, and resource parameter.
    pub fn new(parameters: LocalVectorParameters) -> Result<Self, RetrievalError> {
        if !valid_identifier(&parameters.model_id)
            || !valid_identifier(&parameters.preprocessing_id)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        if parameters.dimension == 0 || parameters.dimension > MAX_VECTOR_DIMENSIONS {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        if parameters.maximum_entries == 0
            || parameters.maximum_entries > MAX_LOCAL_VECTOR_ENTRIES
            || parameters.maximum_neighbors == 0
            || parameters.maximum_neighbors > MAX_CANDIDATES
            || parameters.maximum_neighbors > parameters.maximum_entries
        {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        let processor_binding = processor_binding(&parameters)?;
        Ok(Self {
            parameters,
            processor_binding,
        })
    }

    /// Returns the exact binding a processor must attach to every accepted vector.
    #[must_use]
    pub fn processor_binding(&self) -> &ContentDigest {
        &self.processor_binding
    }

    /// Returns the exact configured dimension.
    #[must_use]
    pub const fn dimension(&self) -> usize {
        self.parameters.dimension
    }

    /// Returns the immutable projection-domain digest.
    #[must_use]
    pub const fn partition_digest(&self) -> &ContentDigest {
        &self.parameters.partition_digest
    }

    /// Returns the immutable vector projection generation identity.
    #[must_use]
    pub const fn index_generation_id(&self) -> &RecordId {
        &self.parameters.index_generation_id
    }

    pub(crate) const fn parameters(&self) -> &LocalVectorParameters {
        &self.parameters
    }
}

/// Trusted, model-free local processor for bounded deterministic integer vectors.
///
/// This processor is deliberately simple: it hashes a sorted set of normalized terms into signed
/// integer buckets. It makes no semantic-quality claim and performs no I/O. Index vectors are
/// bound to the configured projection domain; query vectors are additionally bound to the exact
/// authorization partition supplied after policy approval.
#[derive(Clone)]
pub struct DeterministicLocalVectorProcessor {
    configuration: LocalVectorConfiguration,
}

impl DeterministicLocalVectorProcessor {
    /// Constructs the processor from one fully validated immutable configuration.
    #[must_use]
    pub const fn new(configuration: LocalVectorConfiguration) -> Self {
        Self { configuration }
    }

    /// Produces a projection vector for one bounded normalized term set.
    pub fn approve_index_terms(
        &self,
        terms: &BTreeSet<String>,
    ) -> Result<ProcessorApprovedVector, RetrievalError> {
        let values = feature_hash_values(self.configuration.dimension(), terms.iter())?;
        ProcessorApprovedVector::try_from_processor_output(
            self.configuration.processor_binding().clone(),
            &values,
        )
    }

    /// Returns the immutable configuration used by index-generation construction.
    #[must_use]
    pub const fn configuration(&self) -> &LocalVectorConfiguration {
        &self.configuration
    }

    #[cfg(test)]
    pub(crate) fn approve_query_output(
        &self,
        partition_digest: &ContentDigest,
        values: &[i16],
    ) -> Result<ProcessorApprovedVector, RetrievalError> {
        ProcessorApprovedVector::try_from_processor_output(
            query_processor_binding(&self.configuration, partition_digest)?,
            values,
        )
    }
}

impl fmt::Debug for DeterministicLocalVectorProcessor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicLocalVectorProcessor")
            .field("dimension", &self.configuration.dimension())
            .finish_non_exhaustive()
    }
}

impl QueryVectorProcessor for DeterministicLocalVectorProcessor {
    fn approve_query(
        &self,
        partition: &crate::AuthorizedPartition,
        terms: &BTreeSet<String>,
    ) -> Result<ProcessorApprovedVector, RetrievalError> {
        partition.validate()?;
        let values = feature_hash_values(self.configuration.dimension(), terms.iter())?;
        ProcessorApprovedVector::try_from_processor_output(
            query_processor_binding(&self.configuration, partition.partition_digest())?,
            &values,
        )
    }
}

impl fmt::Debug for LocalVectorConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalVectorConfiguration")
            .field("dimension", &self.parameters.dimension)
            .field("distance_metric", &self.parameters.distance_metric)
            .field("quantization", &self.parameters.quantization)
            .field("maximum_entries", &self.parameters.maximum_entries)
            .field("maximum_neighbors", &self.parameters.maximum_neighbors)
            .finish_non_exhaustive()
    }
}

/// One authorized semantic version and its processor-approved quantized representation.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalVectorEntry {
    version_id: VersionId,
    vector: ProcessorApprovedVector,
}

impl LocalVectorEntry {
    /// Creates one immutable sealed-index input without accepting atom payload data.
    #[must_use]
    pub const fn new(version_id: VersionId, vector: ProcessorApprovedVector) -> Self {
        Self { version_id, vector }
    }
}

impl fmt::Debug for LocalVectorEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalVectorEntry")
            .field("vector_dimension", &self.vector.dimension())
            .finish_non_exhaustive()
    }
}

/// Explicit production configuration boundary; the default is disabled.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum LocalVectorAdapterEnablement {
    /// Do not construct or expose a local vector adapter.
    #[default]
    Disabled,
    /// Explicitly construct one immutable adapter from a validated configuration.
    Enabled(LocalVectorConfiguration),
}

/// Immutable in-memory local adapter sealed to one partition and vector generation.
///
/// This type has no mutation or persistence API. Rebuilds must construct a new instance and bind
/// its returned [`VectorIndexBinding`] into the corresponding retrieval index generation.
pub struct SealedLocalVectorAdapter {
    configuration: LocalVectorConfiguration,
    index_binding: VectorIndexBinding,
    vectors: BTreeMap<VersionId, ProcessorApprovedVector>,
}

impl fmt::Debug for SealedLocalVectorAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedLocalVectorAdapter")
            .field("vector_count", &self.vectors.len())
            .finish_non_exhaustive()
    }
}

/// Applies the disabled-by-default boundary and, when enabled, seals a complete local generation.
pub fn configure_local_vector_adapter(
    enablement: LocalVectorAdapterEnablement,
    entries: Vec<LocalVectorEntry>,
) -> Result<Option<SealedLocalVectorAdapter>, RetrievalError> {
    match enablement {
        LocalVectorAdapterEnablement::Disabled if entries.is_empty() => Ok(None),
        LocalVectorAdapterEnablement::Disabled => {
            Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata))
        }
        LocalVectorAdapterEnablement::Enabled(configuration) => {
            SealedLocalVectorAdapter::seal(configuration, entries).map(Some)
        }
    }
}

impl SealedLocalVectorAdapter {
    pub(crate) fn seal(
        configuration: LocalVectorConfiguration,
        entries: Vec<LocalVectorEntry>,
    ) -> Result<Self, RetrievalError> {
        if entries.len() > configuration.parameters.maximum_entries {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        let mut vectors = BTreeMap::new();
        for entry in entries {
            validate_vector(&configuration, &entry.vector)?;
            if vectors.insert(entry.version_id, entry.vector).is_some() {
                return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
            }
        }
        let fingerprint = sealed_fingerprint(&configuration, &vectors)?;
        let index_binding = VectorIndexBinding::new(
            configuration.parameters.index_generation_id.clone(),
            fingerprint,
        );
        Ok(Self {
            configuration,
            index_binding,
            vectors,
        })
    }

    pub(crate) const fn configuration(&self) -> &LocalVectorConfiguration {
        &self.configuration
    }

    pub(crate) const fn vectors(&self) -> &BTreeMap<VersionId, ProcessorApprovedVector> {
        &self.vectors
    }
}

impl VectorAdapter for SealedLocalVectorAdapter {
    fn index_binding(&self) -> &VectorIndexBinding {
        &self.index_binding
    }

    fn authorized_partition_binding(
        &self,
        query: &VectorQuery,
        context: &RetrievalContext,
    ) -> Result<VectorIndexBinding, RetrievalError> {
        context.check()?;
        if query.index_binding != self.index_binding {
            return Err(RetrievalError::new(RetrievalErrorCode::ChannelUnavailable));
        }
        validate_query_vector(
            &self.configuration,
            &query.partition_digest,
            &query.approved_vector,
        )?;
        let mut hasher = Sha256::new();
        hasher.update(b"CIGAR-AUTHORIZED-LOCAL-VECTOR-PARTITION\0v1\0");
        hash_frame(
            &mut hasher,
            self.configuration.processor_binding().as_str().as_bytes(),
        )?;
        hash_frame(&mut hasher, query.partition_digest.as_str().as_bytes())?;
        for version_id in &query.allowed_versions {
            context.check()?;
            if let Some(vector) = self.vectors.get(version_id) {
                hash_frame(&mut hasher, version_id.as_str().as_bytes())?;
                hash_frame(&mut hasher, vector.commitment().as_str().as_bytes())?;
            }
        }
        let fingerprint = finish_digest(hasher)?;
        let generation_id = deterministic_record(&[
            b"CIGAR-AUTHORIZED-LOCAL-VECTOR-GENERATION\0v1\0",
            fingerprint.as_str().as_bytes(),
        ])?;
        Ok(VectorIndexBinding::new(generation_id, fingerprint))
    }

    fn neighbors(
        &self,
        query: &VectorQuery,
        context: &RetrievalContext,
    ) -> Result<Vec<VectorNeighbor>, RetrievalError> {
        context.check()?;
        if query.index_binding != self.index_binding {
            return Err(RetrievalError::new(RetrievalErrorCode::ChannelUnavailable));
        }
        validate_query_vector(
            &self.configuration,
            &query.partition_digest,
            &query.approved_vector,
        )?;
        if query.limit == 0
            || query.limit > self.configuration.parameters.maximum_neighbors
            || query.allowed_versions.len() > MAX_CANDIDATES
        {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }

        let mut neighbors = Vec::with_capacity(query.limit.min(query.allowed_versions.len()));
        for version_id in &query.allowed_versions {
            context.check()?;
            let Some(candidate) = self.vectors.get(version_id) else {
                continue;
            };
            neighbors.push(VectorNeighbor {
                version_id: version_id.clone(),
                similarity: quantized_similarity(
                    self.configuration.parameters.distance_metric,
                    query.approved_vector.values(),
                    candidate.values(),
                    context,
                )?,
            });
        }
        neighbors.sort_by(|left, right| {
            right
                .similarity
                .cmp(&left.similarity)
                .then_with(|| left.version_id.cmp(&right.version_id))
        });
        neighbors.truncate(query.limit);
        Ok(neighbors)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOCAL_VECTOR_IDENTIFIER_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_vector(
    configuration: &LocalVectorConfiguration,
    vector: &ProcessorApprovedVector,
) -> Result<(), RetrievalError> {
    if vector.processor_binding() != &configuration.processor_binding
        || vector.dimension() != configuration.parameters.dimension
    {
        Err(RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))
    } else {
        Ok(())
    }
}

fn validate_query_vector(
    configuration: &LocalVectorConfiguration,
    partition_digest: &ContentDigest,
    vector: &ProcessorApprovedVector,
) -> Result<(), RetrievalError> {
    if vector.processor_binding() != &query_processor_binding(configuration, partition_digest)?
        || vector.dimension() != configuration.parameters.dimension
    {
        Err(RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))
    } else {
        Ok(())
    }
}

fn query_processor_binding(
    configuration: &LocalVectorConfiguration,
    partition_digest: &ContentDigest,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-LOCAL-VECTOR-QUERY-PROCESSOR-BINDING\0v1\0");
    hash_frame(
        &mut hasher,
        configuration.processor_binding().as_str().as_bytes(),
    )?;
    hash_frame(&mut hasher, partition_digest.as_str().as_bytes())?;
    finish_digest(hasher)
}

fn feature_hash_values<'a>(
    dimension: usize,
    terms: impl Iterator<Item = &'a String>,
) -> Result<Vec<i16>, RetrievalError> {
    if dimension == 0 || dimension > MAX_VECTOR_DIMENSIONS {
        return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
    }
    let mut accumulators = vec![0_i64; dimension];
    let mut term_count = 0_usize;
    for term in terms {
        if term.is_empty() || term.len() > 256 || term_count == crate::MAX_QUERY_TERMS {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        term_count = term_count
            .checked_add(1)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        let mut hasher = Sha256::new();
        hasher.update(b"CIGAR-LOCAL-VECTOR-FEATURE\0v1\0");
        hash_frame(&mut hasher, term.as_bytes())?;
        let digest: [u8; 32] = hasher.finalize().into();
        for &[first, second, third, fourth] in digest.as_chunks::<4>().0.iter().take(4) {
            let bucket = usize::from(u16::from_be_bytes([first, second])) % dimension;
            let magnitude = i64::from((third & 0x03) + 1);
            let contribution = if fourth & 1 == 0 {
                magnitude
            } else {
                -magnitude
            };
            let accumulator = accumulators
                .get_mut(bucket)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            *accumulator = accumulator
                .checked_add(contribution)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
    }
    if term_count == 0 {
        return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
    }
    let scale = accumulators
        .iter()
        .map(|value| value.unsigned_abs())
        .max()
        .unwrap_or(1)
        .max(1);
    accumulators
        .into_iter()
        .map(|value| {
            let scaled = i128::from(value)
                .checked_mul(127)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
                / i128::from(scale);
            i16::try_from(scaled)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
        })
        .collect()
}

fn processor_binding(parameters: &LocalVectorParameters) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-LOCAL-VECTOR-PROCESSOR-BINDING\0v1\0");
    hash_frame(&mut hasher, LOCAL_VECTOR_ADAPTER_VERSION.as_bytes())?;
    hash_frame(&mut hasher, parameters.model_id.as_bytes())?;
    hash_frame(
        &mut hasher,
        parameters.model_fingerprint.as_str().as_bytes(),
    )?;
    hash_frame(&mut hasher, &canonical_usize(parameters.dimension)?)?;
    hash_frame(&mut hasher, parameters.preprocessing_id.as_bytes())?;
    hash_frame(
        &mut hasher,
        parameters.preprocessing_fingerprint.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        parameters.distance_metric.identifier().as_bytes(),
    )?;
    hash_frame(&mut hasher, parameters.quantization.identifier().as_bytes())?;
    hash_frame(&mut hasher, parameters.partition_digest.as_str().as_bytes())?;
    finish_digest(hasher)
}

fn sealed_fingerprint(
    configuration: &LocalVectorConfiguration,
    vectors: &BTreeMap<VersionId, ProcessorApprovedVector>,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-SEALED-LOCAL-VECTOR-ADAPTER\0v1\0");
    hash_frame(&mut hasher, LOCAL_VECTOR_ADAPTER_VERSION.as_bytes())?;
    hash_frame(
        &mut hasher,
        configuration.processor_binding.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        configuration
            .parameters
            .index_generation_id
            .as_str()
            .as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        &canonical_usize(configuration.parameters.maximum_entries)?,
    )?;
    hash_frame(
        &mut hasher,
        &canonical_usize(configuration.parameters.maximum_neighbors)?,
    )?;
    hash_frame(&mut hasher, &canonical_usize(vectors.len())?)?;
    for (version_id, vector) in vectors {
        hash_frame(&mut hasher, version_id.as_str().as_bytes())?;
        hash_frame(&mut hasher, vector.commitment().as_str().as_bytes())?;
    }
    finish_digest(hasher)
}

fn canonical_usize(value: usize) -> Result<[u8; 8], RetrievalError> {
    Ok(u64::try_from(value)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
        .to_be_bytes())
}

fn deterministic_record(parts: &[&[u8]]) -> Result<RecordId, RetrievalError> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    RecordId::new(format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    ))
    .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
}

fn quantized_similarity(
    metric: LocalVectorDistanceMetric,
    query: &[i8],
    candidate: &[i8],
    context: &RetrievalContext,
) -> Result<u16, RetrievalError> {
    if query.is_empty() || query.len() != candidate.len() || query.len() > MAX_VECTOR_DIMENSIONS {
        return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
    }
    let maximum_component_distance = match metric {
        LocalVectorDistanceMetric::SquaredEuclideanV1 => 254_u64
            .checked_mul(254)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
        LocalVectorDistanceMetric::ManhattanV1 => 254,
    };
    let dimension = u64::try_from(query.len())
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    let maximum_distance = dimension
        .checked_mul(maximum_component_distance)
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    let mut distance = 0_u64;
    for (index, (left, right)) in query.iter().zip(candidate).enumerate() {
        if index % 256 == 0 {
            context.check()?;
        }
        let delta = i16::from(*left) - i16::from(*right);
        let component = match metric {
            LocalVectorDistanceMetric::SquaredEuclideanV1 => {
                let absolute = u64::from(delta.unsigned_abs());
                absolute
                    .checked_mul(absolute)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            }
            LocalVectorDistanceMetric::ManhattanV1 => u64::from(delta.unsigned_abs()),
        };
        distance = distance
            .checked_add(component)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    }
    if distance > maximum_distance {
        return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
    }
    let numerator = u128::from(maximum_distance - distance)
        .checked_mul(u128::from(MAX_FEATURE_VALUE))
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    let similarity = numerator / u128::from(maximum_distance);
    u16::try_from(similarity)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
}

#[cfg(test)]
mod tests {
    use super::{
        DeterministicLocalVectorProcessor, LocalVectorAdapterEnablement, LocalVectorConfiguration,
        LocalVectorDistanceMetric, LocalVectorEntry, LocalVectorParameters,
        LocalVectorQuantization, MAX_LOCAL_VECTOR_ENTRIES, SealedLocalVectorAdapter,
        configure_local_vector_adapter, quantized_similarity,
    };
    use crate::{
        MAX_FEATURE_VALUE, MAX_VECTOR_DIMENSIONS, ProcessorApprovedVector, RetrievalContext,
        RetrievalErrorCode, VectorAdapter, VectorIndexBinding, VectorQuery,
    };
    use cigar_protocol::{ContentDigest, RecordId, VersionId};
    use cigar_store::CancellationToken;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            format!("{value:02x}").repeat(32)
        ))?)
    }

    fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
        ))?)
    }

    fn version(value: u8) -> Result<VersionId, Box<dyn Error>> {
        Ok(VersionId::new(digest(value)?.as_str())?)
    }

    fn parameters() -> Result<LocalVectorParameters, Box<dyn Error>> {
        Ok(LocalVectorParameters {
            model_id: "provider-neutral/example-model@sha256:0123456789abcdef".to_owned(),
            model_fingerprint: digest(230)?,
            dimension: 4,
            preprocessing_id: "approved-normalize-v1".to_owned(),
            preprocessing_fingerprint: digest(231)?,
            distance_metric: LocalVectorDistanceMetric::SquaredEuclideanV1,
            quantization: LocalVectorQuantization::SymmetricInt8V1,
            partition_digest: digest(240)?,
            index_generation_id: record(900)?,
            maximum_entries: 16,
            maximum_neighbors: 8,
        })
    }

    fn configuration() -> Result<LocalVectorConfiguration, Box<dyn Error>> {
        Ok(LocalVectorConfiguration::new(parameters()?)?)
    }

    fn approved(
        configuration: &LocalVectorConfiguration,
        values: &[i16],
    ) -> Result<ProcessorApprovedVector, Box<dyn Error>> {
        Ok(ProcessorApprovedVector::try_from_processor_output(
            configuration.processor_binding().clone(),
            values,
        )?)
    }

    fn entry(
        configuration: &LocalVectorConfiguration,
        version_value: u8,
        values: &[i16],
    ) -> Result<LocalVectorEntry, Box<dyn Error>> {
        Ok(LocalVectorEntry::new(
            version(version_value)?,
            approved(configuration, values)?,
        ))
    }

    fn adapter() -> Result<SealedLocalVectorAdapter, Box<dyn Error>> {
        let configuration = configuration()?;
        configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(configuration.clone()),
            vec![
                entry(&configuration, 1, &[10, 20, 30, 40])?,
                entry(&configuration, 2, &[10, 20, 30, 40])?,
                entry(&configuration, 3, &[-10, -20, -30, -40])?,
            ],
        )?
        .ok_or_else(|| "enabled adapter was not constructed".into())
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    fn query(adapter: &SealedLocalVectorAdapter) -> Result<VectorQuery, Box<dyn Error>> {
        let partition_digest = adapter.configuration.parameters.partition_digest.clone();
        Ok(VectorQuery {
            partition_digest: partition_digest.clone(),
            index_binding: adapter.index_binding().clone(),
            approved_vector: DeterministicLocalVectorProcessor::new(adapter.configuration.clone())
                .approve_query_output(&partition_digest, &[10, 20, 30, 40])?,
            allowed_versions: [version(1)?, version(2)?, version(3)?]
                .into_iter()
                .collect(),
            limit: 3,
        })
    }

    #[test]
    fn default_boundary_is_disabled_and_rejects_preloaded_entries() -> Result<(), Box<dyn Error>> {
        assert!(configure_local_vector_adapter(Default::default(), Vec::new())?.is_none());
        let configuration = configuration()?;
        assert_eq!(
            configure_local_vector_adapter(
                LocalVectorAdapterEnablement::Disabled,
                vec![entry(&configuration, 1, &[0, 0, 0, 0])?],
            )
            .err()
            .map(|error| error.code()),
            Some(RetrievalErrorCode::InvalidMetadata)
        );
        Ok(())
    }

    #[test]
    fn exact_matches_and_ties_are_deterministic() -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        let neighbors = adapter.neighbors(&query(&adapter)?, &context())?;
        assert_eq!(
            neighbors
                .iter()
                .map(|neighbor| (&neighbor.version_id, neighbor.similarity))
                .collect::<Vec<_>>(),
            vec![
                (&version(1)?, 10_000),
                (&version(2)?, 10_000),
                (&version(3)?, 9_534),
            ]
        );
        Ok(())
    }

    #[test]
    fn allowed_versions_and_cap_are_enforced_exactly() -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        let mut request = query(&adapter)?;
        request.allowed_versions = [version(3)?].into_iter().collect();
        request.limit = 1;
        let neighbors = adapter.neighbors(&request, &context())?;
        assert_eq!(neighbors.len(), 1);
        assert_eq!(
            neighbors
                .first()
                .ok_or("missing allowed neighbor")?
                .version_id,
            version(3)?
        );

        request.limit = adapter.configuration.parameters.maximum_neighbors + 1;
        assert_eq!(
            adapter
                .neighbors(&request, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn fingerprint_generation_partition_dimension_and_processor_mismatches_fail_closed()
    -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        let original = query(&adapter)?;

        let mut wrong = original.clone();
        wrong.index_binding = VectorIndexBinding::new(record(901)?, digest(241)?);
        assert_eq!(
            adapter
                .neighbors(&wrong, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::ChannelUnavailable)
        );

        let mut wrong = original.clone();
        wrong.partition_digest = digest(239)?;
        assert_eq!(
            adapter
                .neighbors(&wrong, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::ChannelUnavailable)
        );

        let mut wrong = original.clone();
        wrong.approved_vector = ProcessorApprovedVector::try_from_processor_output(
            adapter.configuration.processor_binding().clone(),
            &[1, 2, 3],
        )?;
        assert_eq!(
            adapter
                .neighbors(&wrong, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::ChannelUnavailable)
        );

        let mut wrong = original;
        wrong.approved_vector =
            ProcessorApprovedVector::try_from_processor_output(digest(238)?, &[1, 2, 3, 4])?;
        assert_eq!(
            adapter
                .neighbors(&wrong, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::ChannelUnavailable)
        );
        Ok(())
    }

    #[test]
    fn construction_rejects_invalid_configuration_duplicate_versions_and_wrong_vectors()
    -> Result<(), Box<dyn Error>> {
        let mut invalid = parameters()?;
        invalid.model_id = "contains whitespace".to_owned();
        assert_eq!(
            LocalVectorConfiguration::new(invalid).map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );

        let mut invalid = parameters()?;
        invalid.dimension = MAX_VECTOR_DIMENSIONS + 1;
        assert_eq!(
            LocalVectorConfiguration::new(invalid).map_err(|error| error.code()),
            Err(RetrievalErrorCode::LimitExceeded)
        );

        let mut invalid = parameters()?;
        invalid.maximum_entries = MAX_LOCAL_VECTOR_ENTRIES + 1;
        assert_eq!(
            LocalVectorConfiguration::new(invalid).map_err(|error| error.code()),
            Err(RetrievalErrorCode::LimitExceeded)
        );

        let configuration = configuration()?;
        let duplicate = entry(&configuration, 1, &[0, 0, 0, 0])?;
        assert_eq!(
            configure_local_vector_adapter(
                LocalVectorAdapterEnablement::Enabled(configuration.clone()),
                vec![duplicate.clone(), duplicate],
            )
            .err()
            .map(|error| error.code()),
            Some(RetrievalErrorCode::InvalidMetadata)
        );

        let foreign =
            ProcessorApprovedVector::try_from_processor_output(digest(237)?, &[0, 0, 0, 0])?;
        assert_eq!(
            configure_local_vector_adapter(
                LocalVectorAdapterEnablement::Enabled(configuration),
                vec![LocalVectorEntry::new(version(1)?, foreign)],
            )
            .err()
            .map(|error| error.code()),
            Some(RetrievalErrorCode::ChannelUnavailable)
        );
        Ok(())
    }

    #[test]
    fn fingerprint_binds_configuration_generation_and_contents_independent_of_input_order()
    -> Result<(), Box<dyn Error>> {
        let configuration = configuration()?;
        let first = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(configuration.clone()),
            vec![
                entry(&configuration, 1, &[1, 2, 3, 4])?,
                entry(&configuration, 2, &[4, 3, 2, 1])?,
            ],
        )?
        .ok_or("missing first adapter")?;
        let reordered = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(configuration.clone()),
            vec![
                entry(&configuration, 2, &[4, 3, 2, 1])?,
                entry(&configuration, 1, &[1, 2, 3, 4])?,
            ],
        )?
        .ok_or("missing reordered adapter")?;
        assert_eq!(first.index_binding(), reordered.index_binding());

        let changed_contents = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(configuration.clone()),
            vec![
                entry(&configuration, 1, &[1, 2, 3, 5])?,
                entry(&configuration, 2, &[4, 3, 2, 1])?,
            ],
        )?
        .ok_or("missing changed adapter")?;
        assert_ne!(first.index_binding(), changed_contents.index_binding());

        let mut changed_parameters = parameters()?;
        changed_parameters.index_generation_id = record(902)?;
        let changed_configuration = LocalVectorConfiguration::new(changed_parameters)?;
        let changed_generation = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(changed_configuration.clone()),
            vec![
                entry(&changed_configuration, 1, &[1, 2, 3, 4])?,
                entry(&changed_configuration, 2, &[4, 3, 2, 1])?,
            ],
        )?
        .ok_or("missing changed-generation adapter")?;
        assert_ne!(first.index_binding(), changed_generation.index_binding());
        Ok(())
    }

    #[test]
    fn processor_binding_changes_with_every_configurable_processing_dimension()
    -> Result<(), Box<dyn Error>> {
        let baseline_parameters = parameters()?;
        let baseline = LocalVectorConfiguration::new(baseline_parameters.clone())?;
        let mut variants = Vec::new();

        let mut changed = baseline_parameters.clone();
        changed.model_id = "provider-neutral/different-model@sha256:fedcba9876543210".to_owned();
        variants.push(changed);

        let mut changed = baseline_parameters.clone();
        changed.model_fingerprint = digest(232)?;
        variants.push(changed);

        let mut changed = baseline_parameters.clone();
        changed.dimension = 5;
        variants.push(changed);

        let mut changed = baseline_parameters.clone();
        changed.preprocessing_id = "approved-normalize-v2".to_owned();
        variants.push(changed);

        let mut changed = baseline_parameters.clone();
        changed.preprocessing_fingerprint = digest(233)?;
        variants.push(changed);

        let mut changed = baseline_parameters.clone();
        changed.distance_metric = LocalVectorDistanceMetric::ManhattanV1;
        variants.push(changed);

        let mut changed = baseline_parameters;
        changed.partition_digest = digest(236)?;
        variants.push(changed);

        for variant in variants {
            assert_ne!(
                baseline.processor_binding(),
                LocalVectorConfiguration::new(variant)?.processor_binding()
            );
        }
        Ok(())
    }

    #[test]
    fn canonical_binding_and_fingerprint_are_locked_to_u64_big_endian_fields()
    -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        assert_eq!(
            adapter.configuration.processor_binding().as_str(),
            "1220bae6096740e4587e953652d19a480783e3d5754c602eb2afa67c68da03f6b32f"
        );
        assert_eq!(
            adapter.index_binding().fingerprint().as_str(),
            "12201d55580cf1c6be8a8c6fccf4f9e80e57d188a45edb80aae7e5ca7c290fdeb625"
        );
        Ok(())
    }

    #[test]
    fn integer_similarity_properties_hold_across_quantized_domain_samples()
    -> Result<(), Box<dyn Error>> {
        let context = context();
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for _case in 0..512 {
            let mut left = Vec::with_capacity(32);
            let mut right = Vec::with_capacity(32);
            for _dimension in 0..32 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                left.push(i8::try_from(i16::try_from(state % 255)? - 127)?);
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                right.push(i8::try_from(i16::try_from(state % 255)? - 127)?);
            }
            for metric in [
                LocalVectorDistanceMetric::SquaredEuclideanV1,
                LocalVectorDistanceMetric::ManhattanV1,
            ] {
                let forward = quantized_similarity(metric, &left, &right, &context)?;
                let reverse = quantized_similarity(metric, &right, &left, &context)?;
                assert_eq!(forward, reverse);
                assert!(forward <= MAX_FEATURE_VALUE);
                assert_eq!(
                    quantized_similarity(metric, &left, &left, &context)?,
                    MAX_FEATURE_VALUE
                );
            }
        }
        Ok(())
    }

    #[test]
    fn maximum_dimension_extremes_are_overflow_safe() -> Result<(), Box<dyn Error>> {
        let left = vec![-127_i8; MAX_VECTOR_DIMENSIONS];
        let right = vec![127_i8; MAX_VECTOR_DIMENSIONS];
        for metric in [
            LocalVectorDistanceMetric::SquaredEuclideanV1,
            LocalVectorDistanceMetric::ManhattanV1,
        ] {
            assert_eq!(quantized_similarity(metric, &left, &right, &context())?, 0);
        }
        Ok(())
    }

    #[test]
    fn immutable_adapter_is_deterministic_under_concurrent_reads() -> Result<(), Box<dyn Error>> {
        let adapter = Arc::new(adapter()?);
        let expected = adapter.neighbors(&query(&adapter)?, &context())?;
        let mut workers = Vec::new();
        for _worker in 0..8 {
            let adapter = Arc::clone(&adapter);
            let expected = expected.clone();
            workers.push(thread::spawn(move || -> Result<(), String> {
                for _iteration in 0..100 {
                    let request = query(&adapter).map_err(|error| error.to_string())?;
                    let actual = adapter
                        .neighbors(&request, &context())
                        .map_err(|error| error.to_string())?;
                    if actual != expected {
                        return Err("concurrent result changed".to_owned());
                    }
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_panic| "local vector worker panicked")??;
        }
        Ok(())
    }

    #[test]
    fn cancellation_and_deadline_are_checked() -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            adapter
                .neighbors(
                    &query(&adapter)?,
                    &RetrievalContext {
                        cancellation,
                        deadline: Instant::now() + Duration::from_secs(1),
                    },
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::Cancelled)
        );
        assert_eq!(
            adapter
                .neighbors(
                    &query(&adapter)?,
                    &RetrievalContext {
                        cancellation: CancellationToken::default(),
                        deadline: Instant::now(),
                    },
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::DeadlineExceeded)
        );
        Ok(())
    }

    #[test]
    fn query_diagnostics_never_expose_vector_values() -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        let diagnostic = format!("{:?}", query(&adapter)?);
        assert!(!diagnostic.contains("10, 20, 30, 40"));
        assert!(!diagnostic.contains("-10, -20"));
        Ok(())
    }

    #[test]
    fn allowed_version_set_is_order_independent() -> Result<(), Box<dyn Error>> {
        let adapter = adapter()?;
        let mut first = query(&adapter)?;
        first.allowed_versions = [version(3)?, version(1)?, version(2)?]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut second = query(&adapter)?;
        second.allowed_versions = [version(2)?, version(3)?, version(1)?]
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            adapter.neighbors(&first, &context())?,
            adapter.neighbors(&second, &context())?
        );
        Ok(())
    }

    #[test]
    fn denied_partition_vectors_cannot_perturb_authorized_results_or_disclosure_binding()
    -> Result<(), Box<dyn Error>> {
        let baseline_configuration = configuration()?;
        let baseline = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(baseline_configuration.clone()),
            vec![entry(&baseline_configuration, 1, &[10, 20, 30, 40])?],
        )?
        .ok_or("missing baseline adapter")?;

        let mut noisy_parameters = parameters()?;
        noisy_parameters.index_generation_id = record(901)?;
        let noisy_configuration = LocalVectorConfiguration::new(noisy_parameters)?;
        let noisy = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(noisy_configuration.clone()),
            vec![
                entry(&noisy_configuration, 1, &[10, 20, 30, 40])?,
                entry(&noisy_configuration, 2, &[-127, -127, 127, 127])?,
            ],
        )?
        .ok_or("missing noisy adapter")?;

        let exact_partition = digest(239)?;
        let allowed_versions = BTreeSet::from([version(1)?]);
        let baseline_query = VectorQuery {
            partition_digest: exact_partition.clone(),
            index_binding: baseline.index_binding().clone(),
            approved_vector: DeterministicLocalVectorProcessor::new(baseline_configuration)
                .approve_query_output(&exact_partition, &[10, 20, 30, 40])?,
            allowed_versions: allowed_versions.clone(),
            limit: 1,
        };
        let noisy_query = VectorQuery {
            partition_digest: exact_partition.clone(),
            index_binding: noisy.index_binding().clone(),
            approved_vector: DeterministicLocalVectorProcessor::new(noisy_configuration)
                .approve_query_output(&exact_partition, &[10, 20, 30, 40])?,
            allowed_versions,
            limit: 1,
        };

        assert_ne!(baseline.index_binding(), noisy.index_binding());
        assert_eq!(
            baseline.authorized_partition_binding(&baseline_query, &context())?,
            noisy.authorized_partition_binding(&noisy_query, &context())?
        );
        assert_eq!(
            baseline.neighbors(&baseline_query, &context())?,
            noisy.neighbors(&noisy_query, &context())?
        );
        Ok(())
    }
}
