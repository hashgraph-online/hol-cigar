//! Bounded reverse dependency invalidation with cycle rejection.

use crate::{
    CatalogError, CatalogErrorCode, ConnectorContext, InvalidationBatch, InvalidationWorker,
};
use cigar_protocol::{ContextEdge, EdgeKind, Lifecycle, VersionId};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable validated reverse dependency graph.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DependencyInvalidator {
    dependents: BTreeMap<VersionId, BTreeSet<VersionId>>,
}

impl DependencyInvalidator {
    /// Builds the active dependency graph and rejects every derivation cycle.
    pub fn new(edges: &[ContextEdge]) -> Result<Self, CatalogError> {
        let mut dependents: BTreeMap<VersionId, BTreeSet<VersionId>> = BTreeMap::new();
        let mut forward: BTreeMap<VersionId, BTreeSet<VersionId>> = BTreeMap::new();
        for edge in edges {
            if edge.lifecycle != Lifecycle::Active
                || !matches!(edge.kind, EdgeKind::DependsOn | EdgeKind::DerivedFrom)
            {
                continue;
            }
            dependents
                .entry(edge.to_version.clone())
                .or_default()
                .insert(edge.from_version.clone());
            forward
                .entry(edge.from_version.clone())
                .or_default()
                .insert(edge.to_version.clone());
            forward.entry(edge.to_version.clone()).or_default();
        }
        reject_cycles(&forward)?;
        Ok(Self { dependents })
    }

    /// Creates the initial continuation batch for one changed or revoked version.
    #[must_use]
    pub fn start(
        root: VersionId,
        cause: crate::InvalidationCause,
        prior_version: Option<VersionId>,
        new_version: Option<VersionId>,
        causal_revision: cigar_store::StoreRevision,
    ) -> InvalidationBatch {
        InvalidationBatch {
            root: root.clone(),
            cause,
            prior_version,
            new_version,
            causal_revision,
            frontier: [root].into_iter().collect(),
            invalidated: BTreeSet::new(),
        }
    }
}

impl InvalidationWorker for DependencyInvalidator {
    fn process(
        &self,
        mut batch: InvalidationBatch,
        limit: usize,
        context: &ConnectorContext,
    ) -> Result<InvalidationBatch, CatalogError> {
        if limit == 0 || limit > crate::MAX_CONNECTOR_ITEMS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        for _step in 0..limit {
            context.check()?;
            let Some(current) = batch.frontier.pop_first() else {
                break;
            };
            if !batch.invalidated.insert(current.clone()) {
                continue;
            }
            if let Some(dependents) = self.dependents.get(&current) {
                for dependent in dependents {
                    if !batch.invalidated.contains(dependent) {
                        batch.frontier.insert(dependent.clone());
                    }
                }
            }
        }
        Ok(batch)
    }
}

fn reject_cycles(forward: &BTreeMap<VersionId, BTreeSet<VersionId>>) -> Result<(), CatalogError> {
    let mut indegree: BTreeMap<VersionId, usize> = forward
        .keys()
        .cloned()
        .map(|version| (version, 0))
        .collect();
    for targets in forward.values() {
        for target in targets {
            let degree = indegree
                .get_mut(target)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
            *degree = degree
                .checked_add(1)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        }
    }
    let mut ready: BTreeSet<VersionId> = indegree
        .iter()
        .filter_map(|(version, degree)| (*degree == 0).then_some(version.clone()))
        .collect();
    let mut visited = 0_usize;
    while let Some(version) = ready.pop_first() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        if let Some(targets) = forward.get(&version) {
            for target in targets {
                let degree = indegree
                    .get_mut(target)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                *degree = degree
                    .checked_sub(1)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                if *degree == 0 {
                    ready.insert(target.clone());
                }
            }
        }
    }
    if visited == forward.len() {
        Ok(())
    } else {
        Err(CatalogError::new(CatalogErrorCode::InvalidRecord))
    }
}

#[cfg(test)]
mod tests {
    use super::DependencyInvalidator;
    use crate::{ConnectorContext, InvalidationCause, InvalidationWorker};
    use cigar_protocol::{
        ContentDigest, ContextEdge, EdgeKind, ExtensionMap, Lifecycle, RecordId, VersionId,
    };
    use cigar_store::{CancellationToken, StoreRevision};
    use std::time::{Duration, Instant};

    fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn edge(
        id: &str,
        from: VersionId,
        to: VersionId,
    ) -> Result<ContextEdge, Box<dyn std::error::Error>> {
        Ok(ContextEdge {
            schema_version: "cigar.edge.v1".parse()?,
            edge_id: RecordId::new(id)?,
            from_version: from,
            to_version: to,
            kind: EdgeKind::DerivedFrom,
            provenance_digest: ContentDigest::new(format!("1220{}", "f".repeat(64)))?,
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        })
    }

    fn context() -> ConnectorContext {
        ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(1),
        )
    }

    #[test]
    fn one_root_invalidates_exact_transitive_dependents() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = version('a')?;
        let direct = version('b')?;
        let transitive = version('c')?;
        let unrelated = version('d')?;
        let worker = DependencyInvalidator::new(&[
            edge(
                "01890f47-8e7d-7b42-a1d2-3c4d5e6f7810",
                direct.clone(),
                source.clone(),
            )?,
            edge(
                "01890f47-8e7d-7b42-a1d2-3c4d5e6f7811",
                transitive.clone(),
                direct.clone(),
            )?,
        ])?;
        let batch = DependencyInvalidator::start(
            source.clone(),
            InvalidationCause::SourceChanged,
            Some(source.clone()),
            None,
            StoreRevision(7),
        );
        let batch = worker.process(batch, 100, &context())?;
        assert!(batch.frontier.is_empty());
        assert_eq!(
            batch.invalidated,
            [source, direct, transitive].into_iter().collect()
        );
        assert!(!batch.invalidated.contains(&unrelated));
        Ok(())
    }

    #[test]
    fn derivation_cycle_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let first = version('a')?;
        let second = version('b')?;
        assert!(
            DependencyInvalidator::new(&[
                edge(
                    "01890f47-8e7d-7b42-a1d2-3c4d5e6f7810",
                    first.clone(),
                    second.clone(),
                )?,
                edge("01890f47-8e7d-7b42-a1d2-3c4d5e6f7811", second, first,)?,
            ])
            .is_err()
        );
        Ok(())
    }
}
