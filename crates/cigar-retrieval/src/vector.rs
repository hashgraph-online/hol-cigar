//! Optional fingerprint-bound vector neighbor adapter contracts.

use crate::{RetrievalContext, RetrievalError};
use cigar_protocol::{ContentDigest, VersionId};
use std::collections::BTreeSet;
use std::fmt;

/// Authorization-filtered query passed to an optional vector processor.
#[derive(Clone, Eq, PartialEq)]
pub struct VectorQuery {
    /// Exact policy-partition semantics without tenant or project identifiers.
    pub partition_digest: ContentDigest,
    /// Normalized bounded query terms approved for the processor.
    pub terms: BTreeSet<String>,
    /// Only semantic versions already admitted by the hard metadata gate.
    pub allowed_versions: BTreeSet<VersionId>,
    /// Hard neighbor cap.
    pub limit: usize,
}

impl fmt::Debug for VectorQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VectorQuery")
            .field("partition_digest", &self.partition_digest)
            .field("term_count", &self.terms.len())
            .field("allowed_version_count", &self.allowed_versions.len())
            .field("limit", &self.limit)
            .finish()
    }
}

/// One quantized vector neighbor from an authorized partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorNeighbor {
    /// Authorized immutable semantic version.
    pub version_id: VersionId,
    /// Integer similarity in the closed 0 through 10,000 range.
    pub similarity: u16,
}

/// Optional vector backend; no correctness path depends on its availability.
pub trait VectorAdapter: Send + Sync {
    /// Exact model, dimensions, normalization, and preprocessing fingerprint.
    fn fingerprint(&self) -> &ContentDigest;

    /// Returns only neighbors from `query.allowed_versions` under the hard cap.
    fn neighbors(
        &self,
        query: &VectorQuery,
        context: &RetrievalContext,
    ) -> Result<Vec<VectorNeighbor>, RetrievalError>;
}
