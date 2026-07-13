//! Non-bypassable hard gates and deterministic declarative policy evaluation.

mod capability;
mod contract;
mod engine;
mod redaction;

pub use capability::{CapabilityAuthority, EffectiveCapabilities, SignedCapabilityGrant};
pub use contract::*;
pub use engine::{
    CompiledPolicyEngine, MAX_POLICY_CACHE_ENTRIES, MAX_POLICY_CACHE_ENTRIES_PER_TENANT,
    PolicyCacheStatistics, PolicyEngine,
};
pub use redaction::{RedactedValue, StructuralRedactor};
