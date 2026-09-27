//! Closed broker data types. Bearer credentials are deliberately absent from Debug output.
use crate::{AnswerDraft, ContextError, ContextView, ContextViewSpec};
use serde::{Deserialize, Serialize};

/// Content-free broker failures, separate from the existing worker's error contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    /// Missing, expired, revoked, wrong-owner or wrong-epoch authority.
    AccessDenied,
    /// An evidence version, dependency, ticket or submission no longer matches.
    Stale,
    /// Another source update won the expected revision, or a request key was already used.
    Conflict,
    /// A configured admission or retained-state limit would be exceeded.
    Quota,
    /// Malformed broker input.
    InvalidInput,
    /// Secure randomness or the local clock is unavailable.
    Unavailable,
    /// An existing context invariant rejected the operation.
    Context(ContextError),
}

impl From<ContextError> for BrokerError {
    fn from(value: ContextError) -> Self {
        Self::Context(value)
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "context broker error: {self:?}")
    }
}

impl std::error::Error for BrokerError {}

/// Opt-in evidence storage in a directory private to the host.
/// This stores source text, not agent credentials, reviews or execution authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerStorageOptions {
    /// Absolute host-owned directory. No path discovery or automatic migration.
    pub directory: std::path::PathBuf,
    /// Explicitly create only the final directory with private permissions if absent.
    /// The parent must exist. Existing permissions are validated and never rewritten.
    #[serde(default)]
    pub create_directory: bool,
    /// Maximum canonical checkpoint size (1 KiB..=512 MiB).
    #[serde(default = "default_checkpoint_bytes")]
    pub max_checkpoint_bytes: usize,
    /// Maximum SQLite database size. Rollback journaling needs additional disk space.
    #[serde(default = "default_database_bytes")]
    pub max_database_bytes: usize,
    /// Maximum retained hash-chained mutation receipts (1..=4096).
    #[serde(default = "default_journal_records")]
    pub max_journal_records: usize,
}

const fn default_checkpoint_bytes() -> usize {
    64 * 1024 * 1024
}
const fn default_database_bytes() -> usize {
    256 * 1024 * 1024
}
const fn default_journal_records() -> usize {
    1024
}

impl BrokerStorageOptions {
    /// Construct conservative default bounds around an explicit directory.
    #[must_use]
    pub fn new(directory: impl Into<std::path::PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            create_directory: false,
            max_checkpoint_bytes: default_checkpoint_bytes(),
            max_database_bytes: default_database_bytes(),
            max_journal_records: default_journal_records(),
        }
    }
}

/// Explicit process-wide retention bounds; graph and transport limits apply separately.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrokerLimits {
    /// Maximum simultaneously live grants, at most 128.
    pub max_agents: usize,
    /// Maximum ever-admitted source locators; withdrawal retains revision tombstones.
    pub max_sources: usize,
    /// Maximum retained tickets across all grants.
    pub max_tickets: usize,
    /// Maximum retained proposals and completion receipts across all grants.
    pub max_proposals: usize,
    /// Aggregate encoded bytes of retained tickets, drafts, proposals and receipts.
    /// This is a deterministic admission bound, not a measurement of Rust heap usage.
    pub max_retained_bytes: usize,
    /// Aggregate encoded source provenance bytes, including withdrawn source metadata.
    pub max_provenance_bytes: usize,
    /// Encoded identity metadata for nodes still referenced by live or dangling graph edges.
    pub max_relation_bytes: usize,
}

impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            max_agents: 128,
            max_sources: 4096,
            max_tickets: 1024,
            max_proposals: 1024,
            max_retained_bytes: 128 * 1024 * 1024,
            max_provenance_bytes: 32 * 1024 * 1024,
            max_relation_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Host-assigned per-agent bounds. Clients cannot raise these through a request.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentLimits {
    /// Maximum requested context tokens, including caller reserve.
    pub max_tokens: usize,
    /// Maximum outstanding context tickets for this grant.
    pub max_tickets: usize,
    /// Maximum proposals plus completion receipts for this grant.
    pub max_proposals: usize,
    /// Encoded retained-state budget for this grant.
    pub max_retained_bytes: usize,
    /// Encoded bytes allowed for one proposal, including identifiers and metadata.
    pub max_proposal_bytes: usize,
    /// Maximum input documents in a single proposed source replacement.
    pub max_proposal_documents: usize,
    /// Ticket lifetime in milliseconds, at most one day; never exceeds the grant lease.
    pub ticket_lifetime_ms: u64,
    /// Proposal/receipt retention in milliseconds, at most one day.
    pub proposal_lifetime_ms: u64,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_tokens: 32_768,
            max_tickets: 16,
            max_proposals: 8,
            max_retained_bytes: 8 * 1024 * 1024,
            max_proposal_bytes: 2 * 1024 * 1024,
            max_proposal_documents: 4096,
            ticket_lifetime_ms: 300_000,
            proposal_lifetime_ms: 300_000,
        }
    }
}

/// Host-only grant definition. `view.id` is the agent identity; redefining it revokes old authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantSpec {
    /// Assigned scope and policy; ordinary view validation also applies.
    pub view: ContextViewSpec,
    /// Explicit admission limits.
    pub limits: AgentLimits,
    /// Grant lifetime in milliseconds, at most one day.
    pub lease_ms: u64,
}

/// A bearer credential returned only to the host for deliberate distribution to one agent.
/// It is not an OS sandbox or authority to access host-only broker methods.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCredential {
    /// Fresh broker-instance identity; never reused on recovery.
    pub epoch: String,
    /// Random 256-bit bearer secret. Never log or place in a command-line argument.
    pub secret: String,
}

impl std::fmt::Debug for BrokerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerCredential").finish_non_exhaustive()
    }
}

/// Compare-and-swap source authority, including provenance and edge changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    /// Broker-instance authority epoch, not an upstream publisher's identity.
    pub epoch: String,
    /// Monotonic for this source and epoch; zero means never admitted.
    /// Encoded as a canonical decimal string so JavaScript never rounds a CAS version.
    #[serde(with = "decimal_revision")]
    pub version: u64,
}

mod decimal_revision {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 20
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("invalid source revision"));
        }
        value
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid source revision"))
    }
}

/// A host-declared exact input to derived evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDependency {
    /// Input source locator, which must currently be present and valid.
    pub source: String,
    /// Exact version used; change-back does not make an old dependency current.
    pub revision: SourceRevision,
}

/// Host admission path. Neither value is a semantic truth label or signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOrigin {
    /// Explicit trusted-host ingestion.
    Host,
    /// Host-reviewed agent proposal. The agent could not set this field at proposal creation.
    ReviewedProposal,
}

/// Host-supplied provenance. Digests commit to these declarations but do not authenticate them.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProvenance {
    /// Host-assigned authority or acquisition identity, not inferred from source text.
    pub authority: String,
    /// Publisher version, tool-run identity or other host-supplied observation identifier.
    pub upstream_revision: String,
    /// Wall-clock observation time in Unix milliseconds, supplied by the host.
    pub observed_at_ms: u64,
    /// Optional exclusive validity deadline in Unix milliseconds.
    pub valid_until_ms: Option<u64>,
    /// Admission path, supplied by the host.
    pub origin: SourceOrigin,
    /// Exact derivation dependencies, at most 32 distinct sources.
    pub derived_from: Vec<SourceDependency>,
}

impl std::fmt::Debug for SourceProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceProvenance").finish_non_exhaustive()
    }
}

/// Source-local receipt. It deliberately omits global graph counts/revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReceipt {
    /// New source authority version, or unchanged version for an exact no-op.
    pub revision: SourceRevision,
    /// Newly inserted document IDs.
    pub inserted: usize,
    /// Replaced document IDs.
    pub replaced: usize,
    /// Withdrawn document IDs.
    pub removed: usize,
    /// Retained identical documents.
    pub unchanged: usize,
}

/// One current context and a server-retained owner-bound ticket.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerContext {
    /// Random ticket. Possession alone never bypasses the grant/epoch check.
    pub ticket: String,
    /// Exact existing context shape and snapshot identity.
    pub context: ContextView,
    /// Existing rendered evidence, suitable only for the data/context role.
    pub rendered: String,
}

/// Retained outcome for an agent's proposal, inspectable without retrying the write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalOutcome {
    /// No evidence was changed; a host must explicitly admit the proposal.
    Pending,
    /// Host admission succeeded at this source revision.
    Admitted {
        /// Exact source-local receipt, retained until the proposal deadline or explicit forget.
        receipt: SourceReceipt,
    },
    /// Host rejected the proposal; no evidence was changed by it.
    Rejected,
}

/// Own-proposal status, bound to a caller-chosen request key for outcome reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalStatus {
    /// Random host admission handle, usable only with current owner authority.
    pub proposal_id: String,
    /// Caller-chosen unique request key within the current live grant.
    pub request_key: String,
    /// Current retained outcome.
    pub outcome: ProposalOutcome,
}

/// Exact complete claim set sent to the host review port. No free-form unreviewed prose field.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerSubmission {
    /// Random submission identity; replacing the draft invalidates this identity.
    pub submission_id: String,
    /// Exact draft whose review keys the host must assess.
    pub draft: AnswerDraft,
}
