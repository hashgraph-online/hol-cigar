//! Provider-present state with target, policy, revocation, and compaction invalidation.

use cigar_protocol::{ContentDigest, VersionId};
use std::collections::BTreeMap;

/// Exact scope for provider-present state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderPresentScope {
    /// Provider session identity.
    pub provider_session: String,
    /// Target configuration fingerprint.
    pub target_fingerprint: ContentDigest,
}

impl ProviderPresentScope {
    /// Creates a scope with a non-empty provider session.
    pub fn new(
        provider_session: impl Into<String>,
        target_fingerprint: ContentDigest,
    ) -> Option<Self> {
        let provider_session = provider_session.into();
        (!provider_session.is_empty()).then_some(Self {
            provider_session,
            target_fingerprint,
        })
    }
}

/// Audited provider-present observation for one exact bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPresentObservation {
    /// Exact bundle confirmed present.
    pub bundle_id: VersionId,
    /// Policy snapshot that authorizes reuse.
    pub policy_digest: ContentDigest,
    /// Revocation epoch that authorizes reuse.
    pub revocation_epoch: u64,
    /// Monotonic provider observation sequence.
    pub observed_sequence: u64,
    /// Confidence in parts per million.
    pub confidence_parts_per_million: u32,
}

/// Bounded present-state registry; protected content is never stored here.
#[derive(Clone, Debug)]
pub struct ProviderPresentRegistry {
    maximum_scopes: usize,
    observations: BTreeMap<ProviderPresentScope, ProviderPresentObservation>,
}

impl ProviderPresentRegistry {
    /// Creates a registry with a non-zero scope bound.
    #[must_use]
    pub fn new(maximum_scopes: usize) -> Option<Self> {
        (maximum_scopes > 0).then_some(Self {
            maximum_scopes,
            observations: BTreeMap::new(),
        })
    }

    /// Records an acknowledged exact bundle and evicts the oldest deterministic observation.
    pub fn observe(
        &mut self,
        scope: ProviderPresentScope,
        observation: ProviderPresentObservation,
    ) -> bool {
        if observation.confidence_parts_per_million > 1_000_000 {
            return false;
        }
        self.observations.insert(scope, observation);
        while self.observations.len() > self.maximum_scopes {
            let victim = self
                .observations
                .iter()
                .min_by(|(left_scope, left), (right_scope, right)| {
                    left.observed_sequence
                        .cmp(&right.observed_sequence)
                        .then_with(|| left_scope.cmp(right_scope))
                })
                .map(|(scope, _observation)| scope.clone());
            let Some(victim) = victim else {
                break;
            };
            self.observations.remove(&victim);
        }
        true
    }

    /// Returns whether the exact bundle remains reusable under current governance state.
    #[must_use]
    pub fn contains(
        &self,
        scope: &ProviderPresentScope,
        bundle_id: &VersionId,
        current_policy_digest: &ContentDigest,
        current_revocation_epoch: u64,
    ) -> bool {
        self.observations.get(scope).is_some_and(|observation| {
            &observation.bundle_id == bundle_id
                && &observation.policy_digest == current_policy_digest
                && observation.revocation_epoch == current_revocation_epoch
                && observation.confidence_parts_per_million == 1_000_000
        })
    }

    /// Invalidates a provider session after reset or compaction.
    pub fn invalidate_session(&mut self, provider_session: &str) -> usize {
        let scopes: Vec<_> = self
            .observations
            .keys()
            .filter(|scope| scope.provider_session == provider_session)
            .cloned()
            .collect();
        let count = scopes.len();
        for scope in scopes {
            self.observations.remove(&scope);
        }
        count
    }

    /// Invalidates an exact obsolete target configuration across sessions.
    pub fn invalidate_target(&mut self, target_fingerprint: &ContentDigest) -> usize {
        let scopes: Vec<_> = self
            .observations
            .keys()
            .filter(|scope| &scope.target_fingerprint == target_fingerprint)
            .cloned()
            .collect();
        let count = scopes.len();
        for scope in scopes {
            self.observations.remove(&scope);
        }
        count
    }

    /// Returns the number of currently tracked scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns whether no provider state is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}
