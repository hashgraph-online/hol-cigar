//! Provider-present state with target, policy, revocation, and compaction invalidation.

use cigar_protocol::{ContentDigest, VersionId};
use std::collections::BTreeMap;
use std::fmt;

/// Exact scope for provider-present state.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderPresentScope {
    /// Provider session identity.
    pub provider_session: String,
    /// Target configuration fingerprint.
    pub target_fingerprint: ContentDigest,
}

impl fmt::Debug for ProviderPresentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPresentScope")
            .field("provider_session", &"[OPAQUE]")
            .field("target_fingerprint", &"[OPAQUE]")
            .finish()
    }
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
#[derive(Clone, Eq, PartialEq)]
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

impl fmt::Debug for ProviderPresentObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPresentObservation")
            .field("bundle_id", &"[OPAQUE]")
            .field("policy_digest", &"[OPAQUE]")
            .field("revocation_epoch", &self.revocation_epoch)
            .field("observed_sequence", &self.observed_sequence)
            .field(
                "confidence_parts_per_million",
                &self.confidence_parts_per_million,
            )
            .finish()
    }
}

/// Bounded present-state registry; protected content is never stored here.
#[derive(Clone)]
pub struct ProviderPresentRegistry {
    maximum_scopes: usize,
    observations: BTreeMap<ProviderPresentScope, ProviderPresentObservation>,
}

impl fmt::Debug for ProviderPresentRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPresentRegistry")
            .field("maximum_scopes", &self.maximum_scopes)
            .field("observations", &self.observations.len())
            .finish()
    }
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
        if observation.observed_sequence == 0
            || observation.confidence_parts_per_million > 1_000_000
        {
            return false;
        }
        if let Some(current) = self.observations.get(&scope) {
            if current == &observation {
                return true;
            }
            if observation.observed_sequence <= current.observed_sequence {
                return false;
            }
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
