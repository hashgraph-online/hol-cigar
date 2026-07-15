//! Optional fingerprint-bound vector neighbor adapter contracts.

use crate::{AuthorizedPartition, RetrievalContext, RetrievalError, RetrievalErrorCode};
use cigar_protocol::{ContentDigest, RecordId, VersionId};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

/// Maximum dimensions accepted from a processor-approved quantized vector.
pub const MAX_VECTOR_DIMENSIONS: usize = 4_096;
/// Minimum value in the symmetric signed-int8 quantization domain.
pub const MIN_QUANTIZED_VECTOR_VALUE: i16 = -127;
/// Maximum value in the symmetric signed-int8 quantization domain.
pub const MAX_QUANTIZED_VECTOR_VALUE: i16 = 127;

/// Quantized vector emitted by an authorization-approved processor boundary.
///
/// The type intentionally has no public constructor from text, bytes, an atom payload, or raw
/// integer values. Only crate-owned trusted processors and durable verification can construct it;
/// external request builders can move an already-approved value but cannot forge one.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessorApprovedVector {
    processor_binding: ContentDigest,
    commitment: ContentDigest,
    values: Arc<[i8]>,
}

impl ProcessorApprovedVector {
    /// Binds bounded signed integer processor output to the exact processor profile.
    pub(crate) fn try_from_processor_output(
        processor_binding: ContentDigest,
        values: &[i16],
    ) -> Result<Self, RetrievalError> {
        if values.is_empty() || values.len() > MAX_VECTOR_DIMENSIONS {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        let mut quantized = Vec::with_capacity(values.len());
        for value in values {
            if !(MIN_QUANTIZED_VECTOR_VALUE..=MAX_QUANTIZED_VECTOR_VALUE).contains(value) {
                return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
            }
            quantized.push(
                i8::try_from(*value)
                    .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?,
            );
        }
        let values: Arc<[i8]> = quantized.into();
        let commitment = vector_commitment(&processor_binding, &values)?;
        Ok(Self {
            processor_binding,
            commitment,
            values,
        })
    }

    /// Returns the exact model/preprocessing/partition binding asserted by the processor.
    #[must_use]
    pub fn processor_binding(&self) -> &ContentDigest {
        &self.processor_binding
    }

    /// Returns a content commitment without exposing the quantized values.
    #[must_use]
    pub fn commitment(&self) -> &ContentDigest {
        &self.commitment
    }

    /// Returns the exact vector dimension.
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn values(&self) -> &[i8] {
        &self.values
    }
}

impl fmt::Debug for ProcessorApprovedVector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessorApprovedVector")
            .field("dimension", &self.values.len())
            .finish_non_exhaustive()
    }
}

/// Immutable identity of one vector projection generation and its complete adapter fingerprint.
#[derive(Clone, Eq, PartialEq)]
pub struct VectorIndexBinding {
    generation_id: RecordId,
    fingerprint: ContentDigest,
}

impl fmt::Debug for VectorIndexBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VectorIndexBinding([REDACTED])")
    }
}

impl VectorIndexBinding {
    /// Creates an exact generation/fingerprint pair.
    #[must_use]
    pub const fn new(generation_id: RecordId, fingerprint: ContentDigest) -> Self {
        Self {
            generation_id,
            fingerprint,
        }
    }

    /// Returns the immutable vector projection generation.
    #[must_use]
    pub const fn generation_id(&self) -> &RecordId {
        &self.generation_id
    }

    /// Returns the complete adapter and sealed-content fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }
}

/// Authorization-filtered query passed to an optional vector processor.
#[derive(Clone, Eq, PartialEq)]
pub struct VectorQuery {
    /// Exact policy-partition semantics without tenant or project identifiers.
    pub partition_digest: ContentDigest,
    /// Exact sealed vector index generation and fingerprint expected by the caller.
    pub index_binding: VectorIndexBinding,
    /// Bounded quantized query representation approved by the configured processor.
    pub approved_vector: ProcessorApprovedVector,
    /// Only semantic versions already admitted by the hard metadata gate.
    pub allowed_versions: BTreeSet<VersionId>,
    /// Hard neighbor cap.
    pub limit: usize,
}

impl fmt::Debug for VectorQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VectorQuery")
            .field("vector_dimension", &self.approved_vector.dimension())
            .field("allowed_version_count", &self.allowed_versions.len())
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

/// One quantized vector neighbor from an authorized partition.
#[derive(Clone, Eq, PartialEq)]
pub struct VectorNeighbor {
    /// Authorized immutable semantic version.
    pub version_id: VersionId,
    /// Integer similarity in the closed 0 through 10,000 range.
    pub similarity: u16,
}

impl fmt::Debug for VectorNeighbor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VectorNeighbor")
            .field("similarity", &self.similarity)
            .finish_non_exhaustive()
    }
}

/// Optional vector backend; no correctness path depends on its availability.
pub trait VectorAdapter: Send + Sync {
    /// Exact immutable projection generation and adapter fingerprint.
    fn index_binding(&self) -> &VectorIndexBinding;

    /// Derives a disclosure binding from only the exact authorized version set for this query.
    fn authorized_partition_binding(
        &self,
        query: &VectorQuery,
        context: &RetrievalContext,
    ) -> Result<VectorIndexBinding, RetrievalError>;

    /// Returns only neighbors from `query.allowed_versions` under the hard cap.
    fn neighbors(
        &self,
        query: &VectorQuery,
        context: &RetrievalContext,
    ) -> Result<Vec<VectorNeighbor>, RetrievalError>;
}

/// Authorization-after-policy boundary for deterministic query-vector construction.
///
/// Implementations receive the live opaque authorization and normalized bounded terms. They are
/// never invoked until the caller has validated the authorization, and must revalidate it before
/// issuing a value.
pub trait QueryVectorProcessor: Send + Sync {
    /// Produces one processor-bound quantized query representation for the exact partition.
    fn approve_query(
        &self,
        partition: &AuthorizedPartition,
        terms: &BTreeSet<String>,
    ) -> Result<ProcessorApprovedVector, RetrievalError>;
}

fn vector_commitment(
    processor_binding: &ContentDigest,
    values: &[i8],
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PROCESSOR-APPROVED-VECTOR\0v1\0");
    hash_frame(&mut hasher, processor_binding.as_str().as_bytes())?;
    let dimension = u64::try_from(values.len())
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    hash_frame(&mut hasher, &dimension.to_be_bytes())?;
    for value in values {
        hasher.update(value.to_be_bytes());
    }
    finish_digest(hasher)
}

pub(crate) fn hash_frame(hasher: &mut Sha256, value: &[u8]) -> Result<(), RetrievalError> {
    let length = u64::try_from(value.len())
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

pub(crate) fn finish_digest(hasher: Sha256) -> Result<ContentDigest, RetrievalError> {
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
    }
    ContentDigest::new(value)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
}

#[cfg(test)]
mod tests {
    use super::{MAX_VECTOR_DIMENSIONS, ProcessorApprovedVector};
    use crate::RetrievalErrorCode;
    use cigar_protocol::ContentDigest;
    use std::error::Error;

    fn digest(value: char) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            value.to_string().repeat(64)
        ))?)
    }

    #[test]
    fn processor_vector_is_bounded_committed_and_redacted() -> Result<(), Box<dyn Error>> {
        let vector =
            ProcessorApprovedVector::try_from_processor_output(digest('a')?, &[0, -127, 127, 23])?;
        assert_eq!(vector.dimension(), 4);
        assert_eq!(vector, vector.clone());
        let diagnostic = format!("{vector:?}");
        assert!(!diagnostic.contains("-127"));
        assert!(!diagnostic.contains("23"));
        assert_ne!(
            vector.commitment(),
            ProcessorApprovedVector::try_from_processor_output(digest('a')?, &[0, -126, 127, 23])?
                .commitment()
        );
        Ok(())
    }

    #[test]
    fn processor_vector_rejects_empty_oversized_and_out_of_range_values()
    -> Result<(), Box<dyn Error>> {
        let binding = digest('a')?;
        assert_eq!(
            ProcessorApprovedVector::try_from_processor_output(binding.clone(), &[])
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::LimitExceeded)
        );
        assert_eq!(
            ProcessorApprovedVector::try_from_processor_output(
                binding.clone(),
                &vec![0; MAX_VECTOR_DIMENSIONS + 1],
            )
            .map_err(|error| error.code()),
            Err(RetrievalErrorCode::LimitExceeded)
        );
        for invalid in [-128, 128] {
            assert_eq!(
                ProcessorApprovedVector::try_from_processor_output(binding.clone(), &[invalid])
                    .map_err(|error| error.code()),
                Err(RetrievalErrorCode::InvalidMetadata)
            );
        }
        Ok(())
    }
}
