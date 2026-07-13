//! Deterministic token-bounded symbol, diff, decision, and checkpoint capsules.

use crate::{CodeIntelError, CodeIntelErrorCode, SourceRange, Symbol, SymbolCapsule};
use cigar_protocol::{ContentDigest, RecordId, UtcTimestamp, VersionId};
use sha2::{Digest, Sha256};

/// Exact deterministic capsule token estimator and hard ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleBudget {
    /// Maximum estimated tokens.
    pub max_tokens: u64,
    /// Exact UTF-8 bytes charged per token, rounded upward.
    pub bytes_per_token: u64,
}

impl CapsuleBudget {
    fn estimate(self, bytes: u64) -> Result<u64, CodeIntelError> {
        if self.max_tokens == 0 || self.bytes_per_token == 0 {
            return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata));
        }
        bytes
            .checked_add(self.bytes_per_token - 1)
            .map(|rounded| rounded / self.bytes_per_token)
            .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))
    }
}

/// Content-free deterministic source diff summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffCapsule {
    /// Prior immutable source digest.
    pub base_digest: ContentDigest,
    /// New immutable source digest.
    pub target_digest: ContentDigest,
    /// Sorted changed target ranges.
    pub changed_ranges: Vec<SourceRange>,
    /// Sorted affected semantic symbol versions.
    pub affected_symbols: Vec<ContentDigest>,
    /// Canonical capsule digest.
    pub capsule_digest: ContentDigest,
    /// Exact deterministic token estimate.
    pub token_count: u64,
}

/// Durable decision summary with explicit evidence and temporal validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionCapsule {
    /// Decision atom version.
    pub decision_version: VersionId,
    /// Digest of exact protected rationale.
    pub rationale_digest: ContentDigest,
    /// Sorted supporting or contradicting evidence versions.
    pub evidence_versions: Vec<VersionId>,
    /// Prior decision replaced by this one, if any.
    pub supersedes: Option<VersionId>,
    /// Earliest semantic validity time.
    pub valid_from: UtcTimestamp,
    /// Exclusive semantic validity end.
    pub valid_until: Option<UtcTimestamp>,
    /// Canonical capsule digest.
    pub capsule_digest: ContentDigest,
    /// Exact deterministic token estimate.
    pub token_count: u64,
}

/// Restart-safe checkpoint summary resolving state to a source snapshot and atom set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointCapsule {
    /// Immutable source snapshot identity.
    pub snapshot_id: RecordId,
    /// Snapshot manifest digest.
    pub manifest_digest: ContentDigest,
    /// Sorted active atom versions.
    pub atom_versions: Vec<VersionId>,
    /// Sorted decision capsule digests retained at the checkpoint.
    pub decision_digests: Vec<ContentDigest>,
    /// Sorted verification receipt identities retained at the checkpoint.
    pub verification_receipts: Vec<RecordId>,
    /// Canonical capsule digest.
    pub capsule_digest: ContentDigest,
    /// Exact deterministic token estimate.
    pub token_count: u64,
}

/// Selects signature, contract, implementation, and dependency evidence under an exact budget.
pub fn build_symbol_capsule(
    symbol: &Symbol,
    source: &[u8],
    dependency_ids: Vec<ContentDigest>,
    diff_digest: Option<ContentDigest>,
    budget: CapsuleBudget,
) -> Result<SymbolCapsule, CodeIntelError> {
    symbol.range.validate(source.len())?;
    let mut candidates = Vec::new();
    if let Some(signature) = symbol.signature_range {
        candidates.push(signature);
    }
    if let Some(documentation) = symbol.documentation_range {
        candidates.push(documentation);
    }
    candidates.push(symbol.range);
    candidates.sort();
    candidates.dedup();
    let mut selected_ranges = Vec::new();
    let mut selected_bytes = 0_u64;
    for range in candidates {
        range.validate(source.len())?;
        let bytes = range
            .end_byte
            .checked_sub(range.start_byte)
            .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::InvalidOutput))?;
        let next = selected_bytes
            .checked_add(bytes)
            .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
        if budget.estimate(next)? <= budget.max_tokens {
            selected_bytes = next;
            selected_ranges.push(range);
        }
    }
    if selected_ranges.is_empty() {
        return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
    }
    let mut dependency_ids = dependency_ids;
    dependency_ids.sort();
    dependency_ids.dedup();
    Ok(SymbolCapsule {
        symbol_version: symbol.symbol_version.clone(),
        selected_ranges,
        dependency_ids,
        diff_digest,
        token_count: budget.estimate(selected_bytes)?,
    })
}

/// Builds a deterministic bounded diff capsule.
pub fn build_diff_capsule(
    base_digest: ContentDigest,
    target_digest: ContentDigest,
    mut changed_ranges: Vec<SourceRange>,
    mut affected_symbols: Vec<ContentDigest>,
    budget: CapsuleBudget,
) -> Result<DiffCapsule, CodeIntelError> {
    changed_ranges.sort();
    changed_ranges.dedup();
    affected_symbols.sort();
    affected_symbols.dedup();
    let charged_bytes = u64::try_from(changed_ranges.len())
        .ok()
        .and_then(|count| count.checked_mul(48))
        .and_then(|bytes| {
            u64::try_from(affected_symbols.len())
                .ok()
                .and_then(|count| count.checked_mul(68))
                .and_then(|symbols| bytes.checked_add(symbols))
        })
        .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
    let token_count = budget.estimate(charged_bytes)?;
    if token_count > budget.max_tokens {
        return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
    }
    let capsule_digest = digest_parts(
        b"CIGAR-DIFF-CAPSULE\0v1\0",
        base_digest
            .as_str()
            .as_bytes()
            .iter()
            .chain(target_digest.as_str().as_bytes())
            .copied(),
        &changed_ranges,
        &affected_symbols,
    )?;
    Ok(DiffCapsule {
        base_digest,
        target_digest,
        changed_ranges,
        affected_symbols,
        capsule_digest,
        token_count,
    })
}

/// Builds a deterministic decision capsule after sorting and deduplicating evidence.
pub fn build_decision_capsule(
    decision_version: VersionId,
    rationale_digest: ContentDigest,
    mut evidence_versions: Vec<VersionId>,
    supersedes: Option<VersionId>,
    valid_from: UtcTimestamp,
    valid_until: Option<UtcTimestamp>,
    budget: CapsuleBudget,
) -> Result<DecisionCapsule, CodeIntelError> {
    if valid_until.is_some_and(|until| until <= valid_from) {
        return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata));
    }
    evidence_versions.sort();
    evidence_versions.dedup();
    let charged_bytes = u64::try_from(evidence_versions.len())
        .ok()
        .and_then(|count| count.checked_mul(68))
        .and_then(|bytes| bytes.checked_add(136))
        .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
    let token_count = budget.estimate(charged_bytes)?;
    if token_count > budget.max_tokens {
        return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-DECISION-CAPSULE\0v1\0");
    hasher.update(decision_version.as_str().as_bytes());
    hasher.update(rationale_digest.as_str().as_bytes());
    if let Some(prior) = &supersedes {
        hasher.update([1]);
        hasher.update(prior.as_str().as_bytes());
    } else {
        hasher.update([0]);
    }
    hasher.update(valid_from.unix_nanos().to_be_bytes());
    if let Some(until) = valid_until {
        hasher.update([1]);
        hasher.update(until.unix_nanos().to_be_bytes());
    } else {
        hasher.update([0]);
    }
    for evidence in &evidence_versions {
        hasher.update(evidence.as_str().as_bytes());
    }
    let capsule_digest = finish_digest(hasher)?;
    Ok(DecisionCapsule {
        decision_version,
        rationale_digest,
        evidence_versions,
        supersedes,
        valid_from,
        valid_until,
        capsule_digest,
        token_count,
    })
}

/// Builds a deterministic restart checkpoint capsule.
pub fn build_checkpoint_capsule(
    snapshot_id: RecordId,
    manifest_digest: ContentDigest,
    mut atom_versions: Vec<VersionId>,
    mut decision_digests: Vec<ContentDigest>,
    mut verification_receipts: Vec<RecordId>,
    budget: CapsuleBudget,
) -> Result<CheckpointCapsule, CodeIntelError> {
    atom_versions.sort();
    atom_versions.dedup();
    decision_digests.sort();
    decision_digests.dedup();
    verification_receipts.sort();
    verification_receipts.dedup();
    let identity_count = atom_versions
        .len()
        .checked_add(decision_digests.len())
        .and_then(|count| count.checked_add(verification_receipts.len()))
        .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
    let charged_bytes = u64::try_from(identity_count)
        .ok()
        .and_then(|count| count.checked_mul(68))
        .and_then(|bytes| bytes.checked_add(104))
        .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
    let token_count = budget.estimate(charged_bytes)?;
    if token_count > budget.max_tokens {
        return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-CHECKPOINT-CAPSULE\0v1\0");
    hasher.update(snapshot_id.as_str().as_bytes());
    hasher.update(manifest_digest.as_str().as_bytes());
    for atom in &atom_versions {
        hasher.update(b"atom\0");
        hasher.update(atom.as_str().as_bytes());
    }
    for decision in &decision_digests {
        hasher.update(b"decision\0");
        hasher.update(decision.as_str().as_bytes());
    }
    for receipt in &verification_receipts {
        hasher.update(b"receipt\0");
        hasher.update(receipt.as_str().as_bytes());
    }
    let capsule_digest = finish_digest(hasher)?;
    Ok(CheckpointCapsule {
        snapshot_id,
        manifest_digest,
        atom_versions,
        decision_digests,
        verification_receipts,
        capsule_digest,
        token_count,
    })
}

fn digest_parts(
    domain: &[u8],
    primary: impl Iterator<Item = u8>,
    ranges: &[SourceRange],
    identities: &[ContentDigest],
) -> Result<ContentDigest, CodeIntelError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(primary.collect::<Vec<_>>());
    for range in ranges {
        hasher.update(range.start_byte.to_be_bytes());
        hasher.update(range.end_byte.to_be_bytes());
    }
    for identity in identities {
        hasher.update(identity.as_str().as_bytes());
    }
    finish_digest(hasher)
}

fn finish_digest(hasher: Sha256) -> Result<ContentDigest, CodeIntelError> {
    let digest = hasher.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
    }
    ContentDigest::new(value)
        .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::InvalidOutput))
}

#[cfg(test)]
mod tests {
    use super::{
        CapsuleBudget, build_checkpoint_capsule, build_decision_capsule, build_diff_capsule,
        build_symbol_capsule,
    };
    use crate::{Language, SourceRange, Symbol, SymbolKind};
    use cigar_protocol::{ContentDigest, RecordId, UtcTimestamp, VersionId};

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    #[test]
    fn diff_capsules_are_sorted_deduplicated_and_budgeted() -> Result<(), Box<dyn std::error::Error>>
    {
        let range = SourceRange {
            start_byte: 0,
            end_byte: 2,
            start_line: 0,
            start_column: 0,
            end_line: 0,
            end_column: 2,
        };
        let capsule = build_diff_capsule(
            digest('a')?,
            digest('b')?,
            vec![range, range],
            vec![digest('c')?, digest('c')?],
            CapsuleBudget {
                max_tokens: 100,
                bytes_per_token: 4,
            },
        )?;
        assert_eq!(capsule.changed_ranges, vec![range]);
        assert_eq!(capsule.affected_symbols.len(), 1);
        Ok(())
    }

    #[test]
    fn checkpoint_digest_is_permutation_invariant() -> Result<(), Box<dyn std::error::Error>> {
        let first = VersionId::new(format!("1220{}", "a".repeat(64)))?;
        let second = VersionId::new(format!("1220{}", "b".repeat(64)))?;
        let build = |versions| -> Result<_, Box<dyn std::error::Error>> {
            Ok(build_checkpoint_capsule(
                RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
                digest('c')?,
                versions,
                Vec::new(),
                Vec::new(),
                CapsuleBudget {
                    max_tokens: 1_000,
                    bytes_per_token: 4,
                },
            )?)
        };
        let left = build(vec![first.clone(), second.clone()])?;
        let right = build(vec![second, first])?;
        assert_eq!(left.capsule_digest, right.capsule_digest);
        Ok(())
    }

    #[test]
    fn symbol_and_decision_capsules_enforce_budget_and_temporal_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let range = SourceRange {
            start_byte: 0,
            end_byte: 8,
            start_line: 0,
            start_column: 0,
            end_line: 0,
            end_column: 8,
        };
        let symbol = Symbol {
            symbol_id: digest('a')?,
            symbol_version: digest('b')?,
            language: Language::Rust,
            kind: SymbolKind::Function,
            qualified_name: "fixture".to_owned(),
            range,
            signature_range: Some(range),
            documentation_range: None,
            direct_dependencies: Vec::new(),
        };
        let budget = CapsuleBudget {
            max_tokens: 100,
            bytes_per_token: 4,
        };
        let symbol_capsule =
            build_symbol_capsule(&symbol, b"fn x(){}", vec![digest('c')?], None, budget)?;
        assert_eq!(symbol_capsule.token_count, 2);
        let decision = build_decision_capsule(
            VersionId::new(format!("1220{}", "d".repeat(64)))?,
            digest('e')?,
            vec![
                VersionId::new(format!("1220{}", "f".repeat(64)))?,
                VersionId::new(format!("1220{}", "f".repeat(64)))?,
            ],
            None,
            UtcTimestamp::parse_rfc3339("2026-01-01T00:00:00Z")?,
            Some(UtcTimestamp::parse_rfc3339("2026-02-01T00:00:00Z")?),
            budget,
        )?;
        assert_eq!(decision.evidence_versions.len(), 1);
        assert!(decision.token_count <= budget.max_tokens);
        Ok(())
    }
}
