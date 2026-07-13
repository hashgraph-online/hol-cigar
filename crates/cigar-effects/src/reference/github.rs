use super::support::{
    MAX_REFERENCE_TEXT_BYTES, digest_parts, stable_evidence, validate_bounded_text,
    validate_selector,
};
use crate::{
    ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation, EffectConnector,
    EffectError, EffectErrorCode, PreconditionReport, ReconcileObservation,
};
use cigar_protocol::{ContentDigest, EffectIntent, RetryPolicy};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

const CREATE_ISSUE: &str = "create_issue";

/// Protected normalized arguments for a mock GitHub issue creation.
#[derive(Clone, Eq, PartialEq)]
pub struct GitHubIssueRequest {
    owner: String,
    repository: String,
    title: String,
    body: String,
}

impl GitHubIssueRequest {
    /// Creates a bounded issue request for one `owner/repository` target.
    pub fn new(
        owner: impl Into<String>,
        repository: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self, EffectError> {
        let request = Self {
            owner: owner.into(),
            repository: repository.into(),
            title: title.into(),
            body: body.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the normalized `owner/repository` effect target.
    #[must_use]
    pub fn target(&self) -> String {
        format!("{}/{}", self.owner, self.repository)
    }

    /// Computes the exact normalized argument digest.
    pub fn arguments_digest(&self) -> Result<ContentDigest, EffectError> {
        digest_parts(
            b"github-issue-request",
            &[
                self.owner.as_bytes(),
                self.repository.as_bytes(),
                self.title.as_bytes(),
                self.body.as_bytes(),
            ],
        )
    }

    fn validate(&self) -> Result<(), EffectError> {
        validate_github_name(&self.owner)?;
        validate_github_name(&self.repository)?;
        validate_bounded_text(&self.title, 256)?;
        validate_bounded_text(&self.body, MAX_REFERENCE_TEXT_BYTES)
    }
}

impl fmt::Debug for GitHubIssueRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubIssueRequest")
            .field("owner_bytes", &self.owner.len())
            .field("repository_bytes", &self.repository.len())
            .field("title_bytes", &self.title.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// One-shot behavior for the mock GitHub service's next create call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MockGitHubDispatchMode {
    /// Create the issue and return the response.
    #[default]
    Normal,
    /// Create the issue, then lose the response.
    CommitThenLoseResponse,
    /// Lose the request before commit without transport proof.
    LoseBeforeCommit,
    /// Return a definitive rejection before commit.
    RejectBeforeCommit,
}

/// Content-free projection of one issue in the mock GitHub service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockGitHubIssueSnapshot {
    /// Stable mock issue identity.
    pub issue_id: String,
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub repository: String,
    /// Digest of the protected title.
    pub title_digest: ContentDigest,
    /// Digest of the protected body including the CIGAR marker.
    pub body_digest: ContentDigest,
    /// Public deduplication marker containing only a one-way key digest.
    pub marker: String,
}

#[derive(Default)]
struct MockGitHubState {
    next_issue: u64,
    next_mode: MockGitHubDispatchMode,
    search_available: bool,
    issues: BTreeMap<String, MockGitHubIssueSnapshot>,
}

/// Hermetic GitHub-like issue service with marker search and response-loss faults.
pub struct MockGitHubIssueService {
    state: Mutex<MockGitHubState>,
}

impl Default for MockGitHubIssueService {
    fn default() -> Self {
        Self {
            state: Mutex::new(MockGitHubState {
                search_available: true,
                ..MockGitHubState::default()
            }),
        }
    }
}

impl fmt::Debug for MockGitHubIssueService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (issue_count, search_available) = self.state.lock().map_or((0, false), |state| {
            (state.issues.len(), state.search_available)
        });
        formatter
            .debug_struct("MockGitHubIssueService")
            .field("issue_count", &issue_count)
            .field("search_available", &search_available)
            .finish_non_exhaustive()
    }
}

impl MockGitHubIssueService {
    /// Sets a one-shot fault consumed by the next actual issue creation.
    pub fn set_next_mode(&self, mode: MockGitHubDispatchMode) -> Result<(), EffectError> {
        self.state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .next_mode = mode;
        Ok(())
    }

    /// Controls whether marker search is currently authoritative and available.
    pub fn set_search_available(&self, available: bool) -> Result<(), EffectError> {
        self.state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .search_available = available;
        Ok(())
    }

    /// Returns redacted issue snapshots in stable identifier order.
    pub fn issues(&self) -> Result<Vec<MockGitHubIssueSnapshot>, EffectError> {
        Ok(self
            .state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .issues
            .values()
            .cloned()
            .collect())
    }

    fn search(
        &self,
        owner: &str,
        repository: &str,
        marker: &str,
    ) -> Result<Option<Vec<MockGitHubIssueSnapshot>>, EffectError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if !state.search_available {
            return Ok(None);
        }
        Ok(Some(
            state
                .issues
                .values()
                .filter(|issue| {
                    issue.owner == owner && issue.repository == repository && issue.marker == marker
                })
                .cloned()
                .collect(),
        ))
    }

    fn create(
        &self,
        request: &GitHubIssueRequest,
        marker: &str,
    ) -> Result<MockGitHubCreateObservation, EffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let mode = std::mem::take(&mut state.next_mode);
        match mode {
            MockGitHubDispatchMode::LoseBeforeCommit => {
                Ok(MockGitHubCreateObservation::LostBeforeCommit)
            }
            MockGitHubDispatchMode::RejectBeforeCommit => Ok(MockGitHubCreateObservation::Rejected),
            MockGitHubDispatchMode::Normal | MockGitHubDispatchMode::CommitThenLoseResponse => {
                state.next_issue = state
                    .next_issue
                    .checked_add(1)
                    .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
                let issue_id = format!(
                    "{}/{}/issues/{}",
                    request.owner, request.repository, state.next_issue
                );
                let body_digest = digest_parts(
                    b"github-issue-body",
                    &[request.body.as_bytes(), marker.as_bytes()],
                )?;
                let snapshot = MockGitHubIssueSnapshot {
                    issue_id: issue_id.clone(),
                    owner: request.owner.clone(),
                    repository: request.repository.clone(),
                    title_digest: digest_parts(b"github-issue-title", &[request.title.as_bytes()])?,
                    body_digest,
                    marker: marker.to_owned(),
                };
                state.issues.insert(issue_id, snapshot.clone());
                if mode == MockGitHubDispatchMode::CommitThenLoseResponse {
                    Ok(MockGitHubCreateObservation::CommittedWithoutResponse(
                        snapshot,
                    ))
                } else {
                    Ok(MockGitHubCreateObservation::Committed(snapshot))
                }
            }
        }
    }
}

enum MockGitHubCreateObservation {
    Committed(MockGitHubIssueSnapshot),
    CommittedWithoutResponse(MockGitHubIssueSnapshot),
    LostBeforeCommit,
    Rejected,
}

/// Marker-based mock GitHub connector that never claims same-key API idempotency.
pub struct GitHubIssueConnector {
    connector_name: String,
    service: Arc<MockGitHubIssueService>,
    requests: RwLock<BTreeMap<ContentDigest, GitHubIssueRequest>>,
}

impl fmt::Debug for GitHubIssueConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request_count = self.requests.read().map_or(0, |items| items.len());
        formatter
            .debug_struct("GitHubIssueConnector")
            .field("connector_name", &self.connector_name)
            .field("request_count", &request_count)
            .finish_non_exhaustive()
    }
}

impl GitHubIssueConnector {
    /// Creates a no-network GitHub connector over one mock service.
    pub fn new(
        connector_name: impl Into<String>,
        service: Arc<MockGitHubIssueService>,
    ) -> Result<Self, EffectError> {
        let connector_name = connector_name.into();
        validate_selector(&connector_name)?;
        Ok(Self {
            connector_name,
            service,
            requests: RwLock::new(BTreeMap::new()),
        })
    }

    /// Stages protected issue arguments and returns their exact digest.
    pub fn stage_request(&self, request: GitHubIssueRequest) -> Result<ContentDigest, EffectError> {
        request.validate()?;
        let digest = request.arguments_digest()?;
        let mut requests = self
            .requests
            .write()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if requests
            .get(&digest)
            .is_some_and(|existing| existing != &request)
        {
            return Err(EffectError::new(EffectErrorCode::IdempotencyCollision));
        }
        requests.insert(digest.clone(), request);
        Ok(digest)
    }

    fn request(&self, digest: &ContentDigest) -> Result<GitHubIssueRequest, EffectError> {
        self.requests
            .read()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .get(digest)
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))
    }

    fn validate_intent(&self, intent: &EffectIntent) -> Result<GitHubIssueRequest, EffectError> {
        if intent.connector != self.connector_name
            || intent.operation != CREATE_ISSUE
            || !intent.preconditions.is_empty()
            || !matches!(
                intent.retry_policy,
                RetryPolicy::Never | RetryPolicy::ReconcileBeforeRetry
            )
        {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let request = self.request(&intent.arguments_digest)?;
        if intent.target != request.target() {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        Ok(request)
    }

    fn marker(&self, intent: &EffectIntent) -> Result<String, EffectError> {
        let digest = digest_parts(
            b"github-idempotency-marker",
            &[
                intent.idempotency_scope.as_bytes(),
                intent.idempotency_key.as_str().as_bytes(),
                intent.arguments_digest.as_str().as_bytes(),
            ],
        )?;
        Ok(format!("<!-- cigar-effect:{} -->", digest.as_str()))
    }

    fn search(
        &self,
        request: &GitHubIssueRequest,
        marker: &str,
    ) -> Result<Option<Vec<MockGitHubIssueSnapshot>>, EffectError> {
        self.service
            .search(&request.owner, &request.repository, marker)
    }
}

impl EffectConnector for GitHubIssueConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: self.connector_name.clone(),
            operations: vec![ConnectorOperation {
                operation: CREATE_ISSUE.to_owned(),
                same_key_idempotent: false,
                supports_reconciliation: true,
                supports_compensation: false,
            }],
            maximum_dispatch_nanos: 30_000_000_000,
        }
    }

    fn check_preconditions(
        &self,
        intent: &EffectIntent,
        _now: cigar_protocol::UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        let valid = self.validate_intent(intent).is_ok();
        Ok(PreconditionReport {
            satisfied: valid,
            evidence: BTreeSet::from([stable_evidence(b"github-marker-policy", intent)?]),
        })
    }

    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        let request = self.validate_intent(context.intent)?;
        let marker = self.marker(context.intent)?;
        match self.search(&request, &marker)? {
            None => {
                return Ok(DispatchObservation::Unknown {
                    evidence_digest: stable_evidence(
                        b"github-marker-search-unavailable",
                        context.intent,
                    )?,
                    remote_operation_id: None,
                });
            }
            Some(found) if found.len() == 1 => {
                let Some(issue) = found.first() else {
                    return Err(EffectError::new(EffectErrorCode::Unavailable));
                };
                return github_success(issue);
            }
            Some(found) if !found.is_empty() => {
                return Ok(DispatchObservation::Unknown {
                    evidence_digest: stable_evidence(b"github-duplicate-markers", context.intent)?,
                    remote_operation_id: None,
                });
            }
            Some(_found) => {}
        }

        match self.service.create(&request, &marker)? {
            MockGitHubCreateObservation::Committed(issue) => github_success(&issue),
            MockGitHubCreateObservation::CommittedWithoutResponse(issue) => {
                Ok(DispatchObservation::Unknown {
                    evidence_digest: github_snapshot_digest(b"github-response-lost", &issue)?,
                    remote_operation_id: Some(issue.issue_id),
                })
            }
            MockGitHubCreateObservation::LostBeforeCommit => Ok(DispatchObservation::Unknown {
                evidence_digest: stable_evidence(b"github-request-lost", context.intent)?,
                remote_operation_id: None,
            }),
            MockGitHubCreateObservation::Rejected => Ok(DispatchObservation::Failed {
                evidence_digest: stable_evidence(b"github-rejected", context.intent)?,
            }),
        }
    }

    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        let request = self.validate_intent(context.intent)?;
        let marker = self.marker(context.intent)?;
        match self.search(&request, &marker)? {
            None => Ok(ReconcileObservation::Inconclusive {
                evidence_digest: stable_evidence(
                    b"github-marker-search-unavailable",
                    context.intent,
                )?,
                certainty_window_end: context.deadline,
            }),
            Some(found) if found.is_empty() => Ok(ReconcileObservation::ProvenNotExecuted(
                stable_evidence(b"github-marker-absent", context.intent)?,
            )),
            Some(found) if found.len() == 1 => {
                let Some(issue) = found.first() else {
                    return Err(EffectError::new(EffectErrorCode::Unavailable));
                };
                Ok(ReconcileObservation::ConfirmedSuccess(
                    github_snapshot_digest(b"github-reconciled", issue)?,
                ))
            }
            Some(_found) => Ok(ReconcileObservation::Inconclusive {
                evidence_digest: stable_evidence(b"github-duplicate-markers", context.intent)?,
                certainty_window_end: context.deadline,
            }),
        }
    }
}

fn validate_github_name(value: &str) -> Result<(), EffectError> {
    validate_selector(value)?;
    if value.len() > 100
        || value.starts_with('-')
        || value.ends_with('-')
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        Err(EffectError::new(EffectErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn github_success(issue: &MockGitHubIssueSnapshot) -> Result<DispatchObservation, EffectError> {
    Ok(DispatchObservation::Succeeded {
        remote_operation_id: issue.issue_id.clone(),
        response_digest: github_snapshot_digest(b"github-response", issue)?,
        verification_digest: github_snapshot_digest(b"github-verification", issue)?,
    })
}

fn github_snapshot_digest(
    domain: &[u8],
    issue: &MockGitHubIssueSnapshot,
) -> Result<ContentDigest, EffectError> {
    digest_parts(
        domain,
        &[
            issue.issue_id.as_bytes(),
            issue.owner.as_bytes(),
            issue.repository.as_bytes(),
            issue.title_digest.as_str().as_bytes(),
            issue.body_digest.as_str().as_bytes(),
            issue.marker.as_bytes(),
        ],
    )
}
