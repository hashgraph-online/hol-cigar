//! Bounded governed caches with scope isolation and integrity verification.

use crate::materializer::digest;
use cigar_protocol::ContentDigest;
use std::collections::BTreeMap;

/// Independently governed cache layer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CacheLayer {
    /// Immutable atom decoding.
    Atom,
    /// Deterministic transforms.
    Transform,
    /// Authorized retrieval results.
    Retrieval,
    /// Compiler plans.
    Plan,
    /// Sealed bundles.
    Bundle,
    /// Provider materializations.
    Materialization,
}

/// Fully scoped cache identity; tenant and disclosure domains are mandatory.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CacheKey {
    /// Cache layer.
    pub layer: CacheLayer,
    /// Normalized tenant identity.
    pub tenant: String,
    /// Exact disclosure-domain identity.
    pub disclosure_domain: String,
    /// Immutable source/configuration fingerprint.
    pub fingerprint: ContentDigest,
}

impl CacheKey {
    /// Creates a fully scoped key and rejects empty security domains.
    pub fn new(
        layer: CacheLayer,
        tenant: impl Into<String>,
        disclosure_domain: impl Into<String>,
        fingerprint: ContentDigest,
    ) -> Option<Self> {
        let tenant = tenant.into();
        let disclosure_domain = disclosure_domain.into();
        if tenant.is_empty() || disclosure_domain.is_empty() {
            None
        } else {
            Some(Self {
                layer,
                tenant,
                disclosure_domain,
                fingerprint,
            })
        }
    }
}

#[derive(Clone)]
struct Entry {
    bytes: Vec<u8>,
    integrity: ContentDigest,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
    last_access: u64,
}

/// Bounded deterministic least-recently-used cache.
#[derive(Clone)]
pub struct GovernedCache {
    maximum_entries: usize,
    maximum_bytes: usize,
    resident_bytes: usize,
    access_clock: u64,
    entries: BTreeMap<CacheKey, Entry>,
}

impl std::fmt::Debug for GovernedCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernedCache")
            .field("maximum_entries", &self.maximum_entries)
            .field("maximum_bytes", &self.maximum_bytes)
            .field("resident_bytes", &self.resident_bytes)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl GovernedCache {
    /// Creates a non-empty bounded cache.
    #[must_use]
    pub fn new(maximum_entries: usize, maximum_bytes: usize) -> Option<Self> {
        (maximum_entries > 0 && maximum_bytes > 0).then_some(Self {
            maximum_entries,
            maximum_bytes,
            resident_bytes: 0,
            access_clock: 0,
            entries: BTreeMap::new(),
        })
    }

    /// Stores bytes with the policy/revocation state that authorized their creation.
    pub fn insert(
        &mut self,
        key: CacheKey,
        bytes: Vec<u8>,
        policy_digest: ContentDigest,
        revocation_epoch: u64,
    ) -> bool {
        if bytes.is_empty() || bytes.len() > self.maximum_bytes {
            return false;
        }
        let Ok(integrity) = digest(&bytes) else {
            return false;
        };
        self.access_clock = self.access_clock.saturating_add(1);
        if let Some(replaced) = self.entries.remove(&key) {
            self.resident_bytes = self.resident_bytes.saturating_sub(replaced.bytes.len());
        }
        self.resident_bytes = self.resident_bytes.saturating_add(bytes.len());
        self.entries.insert(
            key,
            Entry {
                bytes,
                integrity,
                policy_digest,
                revocation_epoch,
                last_access: self.access_clock,
            },
        );
        self.evict_to_bounds();
        true
    }

    /// Reads only after exact policy, revocation, integrity, and eligibility checks.
    pub fn get(
        &mut self,
        key: &CacheKey,
        current_policy_digest: &ContentDigest,
        current_revocation_epoch: u64,
        currently_eligible: impl FnOnce(&CacheKey) -> bool,
    ) -> Option<Vec<u8>> {
        let reusable = self.entries.get(key).is_some_and(|entry| {
            &entry.policy_digest == current_policy_digest
                && entry.revocation_epoch == current_revocation_epoch
                && digest(&entry.bytes).is_ok_and(|found| found == entry.integrity)
        });
        if !reusable || !currently_eligible(key) {
            self.remove(key);
            return None;
        }
        self.access_clock = self.access_clock.saturating_add(1);
        let entry = self.entries.get_mut(key)?;
        entry.last_access = self.access_clock;
        Some(entry.bytes.clone())
    }

    /// Returns a governed hit or recomputes and stores a verified miss/corrupt entry.
    pub fn get_or_try_insert_with<E>(
        &mut self,
        key: CacheKey,
        current_policy_digest: ContentDigest,
        current_revocation_epoch: u64,
        currently_eligible: impl Fn(&CacheKey) -> bool,
        recompute: impl FnOnce() -> Result<Vec<u8>, E>,
    ) -> Result<Option<Vec<u8>>, E> {
        if !currently_eligible(&key) {
            self.remove(&key);
            return Ok(None);
        }
        if let Some(hit) = self.get(
            &key,
            &current_policy_digest,
            current_revocation_epoch,
            |_key| true,
        ) {
            return Ok(Some(hit));
        }
        let bytes = recompute()?;
        if self.insert(
            key,
            bytes.clone(),
            current_policy_digest,
            current_revocation_epoch,
        ) {
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    /// Invalidates all entries in one exact tenant/disclosure scope.
    pub fn invalidate_scope(&mut self, tenant: &str, disclosure_domain: &str) -> usize {
        let keys: Vec<_> = self
            .entries
            .keys()
            .filter(|key| key.tenant == tenant && key.disclosure_domain == disclosure_domain)
            .cloned()
            .collect();
        let count = keys.len();
        for key in keys {
            self.remove(&key);
        }
        count
    }

    /// Returns the current bounded entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_for_test(&mut self, key: &CacheKey) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.bytes.push(0xff);
            self.resident_bytes = self.resident_bytes.saturating_add(1);
        }
    }

    fn evict_to_bounds(&mut self) {
        while self.entries.len() > self.maximum_entries || self.resident_bytes > self.maximum_bytes
        {
            let victim = self
                .entries
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.last_access
                        .cmp(&right.last_access)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _entry)| key.clone());
            let Some(victim) = victim else {
                break;
            };
            self.remove(&victim);
        }
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.resident_bytes = self.resident_bytes.saturating_sub(entry.bytes.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheKey, CacheLayer, GovernedCache};
    use cigar_protocol::ContentDigest;

    fn content(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    #[test]
    fn corruption_is_quarantined_as_a_miss() -> Result<(), Box<dyn std::error::Error>> {
        let policy = content('a')?;
        let key = CacheKey::new(
            CacheLayer::Materialization,
            "tenant-a",
            "private",
            content('b')?,
        )
        .ok_or("valid cache key")?;
        let mut cache = GovernedCache::new(4, 1_024).ok_or("valid cache bounds")?;
        assert!(cache.insert(key.clone(), b"protected".to_vec(), policy.clone(), 7));
        cache.corrupt_for_test(&key);
        let recovered = cache.get_or_try_insert_with(
            key.clone(),
            policy.clone(),
            7,
            |_key| true,
            || Ok::<_, std::convert::Infallible>(b"recomputed".to_vec()),
        )?;
        assert_eq!(recovered, Some(b"recomputed".to_vec()));
        assert_eq!(
            cache.get(&key, &policy, 7, |_key| true),
            Some(b"recomputed".to_vec())
        );
        Ok(())
    }
}
