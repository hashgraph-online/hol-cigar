use super::support::{
    MAX_REFERENCE_TEXT_BYTES, digest_parts, stable_evidence, validate_bounded_text,
    validate_selector,
};
use crate::{
    ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation, EffectConnector,
    EffectError, EffectErrorCode, PreconditionReport, ReconcileObservation,
};
use cigar_protocol::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

const CREATE_ISSUE: &str = "create_issue";
const PROTECTED_ARGUMENT_SCHEMA: &str = "cigar.effect-arguments.demo-issue.v1";
const MAX_PROTECTED_ARGUMENT_BYTES: usize = 524_288;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DemoIssueArgumentDocument {
    schema_version: String,
    project: String,
    title: String,
    body: String,
}

/// One normalized request staged for the hermetic demo issue service.
#[derive(Clone, Eq, PartialEq)]
pub struct DemoIssueRequest {
    project: String,
    title: String,
    body: String,
}

impl DemoIssueRequest {
    /// Creates a bounded demo issue request.
    pub fn new(
        project: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self, EffectError> {
        let request = Self {
            project: project.into(),
            title: title.into(),
            body: body.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the exact project selector bound to the effect target.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Computes the normalized argument digest used when staging the request.
    pub fn arguments_digest(&self) -> Result<ContentDigest, EffectError> {
        digest_parts(
            b"demo-issue-request",
            &[
                self.project.as_bytes(),
                self.title.as_bytes(),
                self.body.as_bytes(),
            ],
        )
    }

    /// Encodes a deterministic versioned JSON document suitable for encrypted blob storage.
    pub fn encode_protected_document(&self) -> Result<Vec<u8>, EffectError> {
        self.validate()?;
        let document = DemoIssueArgumentDocument {
            schema_version: PROTECTED_ARGUMENT_SCHEMA.to_owned(),
            project: self.project.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
        };
        let bytes = serde_json::to_vec(&document)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if bytes.len() > MAX_PROTECTED_ARGUMENT_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        Ok(bytes)
    }

    /// Decodes a strict versioned JSON document recovered from authenticated encrypted storage.
    pub fn decode_protected_document(bytes: &[u8]) -> Result<Self, EffectError> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_ARGUMENT_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        cigar_canon::parse_strict_json(bytes)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let document: DemoIssueArgumentDocument = serde_json::from_slice(bytes)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        if document.schema_version != PROTECTED_ARGUMENT_SCHEMA {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        Self::new(document.project, document.title, document.body)
    }

    fn validate(&self) -> Result<(), EffectError> {
        validate_selector(&self.project)?;
        validate_bounded_text(&self.title, 256)?;
        validate_bounded_text(&self.body, MAX_REFERENCE_TEXT_BYTES)
    }
}

impl fmt::Debug for DemoIssueRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DemoIssueRequest")
            .field("project_bytes", &self.project.len())
            .field("title_bytes", &self.title.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Deterministic one-shot behavior for the demo service's next new issue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DemoDispatchMode {
    /// Commit the issue and return a complete response.
    #[default]
    Normal,
    /// Commit the issue, then lose the response so the caller must reconcile.
    CommitThenLoseResponse,
    /// Prove that no request capable of committing reached the service.
    ProvenNotSent,
    /// Reject the request without committing an issue.
    RejectBeforeCommit,
}

/// Content-free projection of one issue held by the hermetic service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemoIssueSnapshot {
    /// Stable remote issue identifier.
    pub issue_id: String,
    /// Exact project selector.
    pub project: String,
    /// Digest of the protected title.
    pub title_digest: ContentDigest,
    /// Digest of the protected body.
    pub body_digest: ContentDigest,
    /// Whether the issue remains open.
    pub open: bool,
}

#[derive(Clone)]
struct StoredDemoIssue {
    snapshot: DemoIssueSnapshot,
    request_digest: ContentDigest,
}

#[derive(Default)]
struct DemoIssueState {
    next_issue: u64,
    next_mode: DemoDispatchMode,
    issues: BTreeMap<String, StoredDemoIssue>,
    idempotency: BTreeMap<(String, String), String>,
}

/// Hermetic, thread-safe external issue service used by examples and fault tests.
#[derive(Default)]
pub struct DemoIssueService {
    state: Mutex<DemoIssueState>,
}

impl fmt::Debug for DemoIssueService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let issue_count = self.state.lock().map_or(0, |state| state.issues.len());
        formatter
            .debug_struct("DemoIssueService")
            .field("issue_count", &issue_count)
            .finish_non_exhaustive()
    }
}

impl DemoIssueService {
    /// Sets one deterministic fault mode, consumed by the next new issue dispatch.
    pub fn set_next_mode(&self, mode: DemoDispatchMode) -> Result<(), EffectError> {
        self.state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .next_mode = mode;
        Ok(())
    }

    /// Returns redacted snapshots in stable identifier order.
    pub fn issues(&self) -> Result<Vec<DemoIssueSnapshot>, EffectError> {
        Ok(self
            .state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .issues
            .values()
            .map(|issue| issue.snapshot.clone())
            .collect())
    }

    fn create(
        &self,
        scope: &str,
        key: &str,
        request: &DemoIssueRequest,
        request_digest: &ContentDigest,
    ) -> Result<DemoServiceObservation, EffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let key_tuple = (scope.to_owned(), key.to_owned());
        if let Some(issue_id) = state.idempotency.get(&key_tuple) {
            let Some(issue) = state.issues.get(issue_id) else {
                return Err(EffectError::new(EffectErrorCode::Unavailable));
            };
            return if &issue.request_digest == request_digest {
                Ok(DemoServiceObservation::Committed(issue.snapshot.clone()))
            } else {
                Ok(DemoServiceObservation::Collision)
            };
        }

        let mode = std::mem::take(&mut state.next_mode);
        match mode {
            DemoDispatchMode::ProvenNotSent => Ok(DemoServiceObservation::ProvenNotSent),
            DemoDispatchMode::RejectBeforeCommit => Ok(DemoServiceObservation::Rejected),
            DemoDispatchMode::Normal | DemoDispatchMode::CommitThenLoseResponse => {
                state.next_issue = state
                    .next_issue
                    .checked_add(1)
                    .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
                let issue_id = format!("demo-issue-{}", state.next_issue);
                let snapshot = DemoIssueSnapshot {
                    issue_id: issue_id.clone(),
                    project: request.project.clone(),
                    title_digest: digest_parts(b"demo-issue-title", &[request.title.as_bytes()])?,
                    body_digest: digest_parts(b"demo-issue-body", &[request.body.as_bytes()])?,
                    open: true,
                };
                state.issues.insert(
                    issue_id.clone(),
                    StoredDemoIssue {
                        snapshot: snapshot.clone(),
                        request_digest: request_digest.clone(),
                    },
                );
                state.idempotency.insert(key_tuple, issue_id);
                if mode == DemoDispatchMode::CommitThenLoseResponse {
                    Ok(DemoServiceObservation::CommittedWithoutResponse(snapshot))
                } else {
                    Ok(DemoServiceObservation::Committed(snapshot))
                }
            }
        }
    }

    fn lookup(
        &self,
        scope: &str,
        key: &str,
        request_digest: &ContentDigest,
    ) -> Result<DemoLookup, EffectError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let Some(issue_id) = state.idempotency.get(&(scope.to_owned(), key.to_owned())) else {
            return Ok(DemoLookup::Absent);
        };
        let Some(issue) = state.issues.get(issue_id) else {
            return Err(EffectError::new(EffectErrorCode::Unavailable));
        };
        if &issue.request_digest == request_digest {
            Ok(DemoLookup::Found(issue.snapshot.clone()))
        } else {
            Ok(DemoLookup::Collision)
        }
    }
}

enum DemoServiceObservation {
    Committed(DemoIssueSnapshot),
    CommittedWithoutResponse(DemoIssueSnapshot),
    ProvenNotSent,
    Rejected,
    Collision,
}

enum DemoLookup {
    Found(DemoIssueSnapshot),
    Absent,
    Collision,
}

/// Effect connector for the hermetic demo issue service.
pub struct DemoIssueConnector {
    connector_name: String,
    service: Arc<DemoIssueService>,
    requests: RwLock<BTreeMap<ContentDigest, DemoIssueRequest>>,
}

impl fmt::Debug for DemoIssueConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request_count = self.requests.read().map_or(0, |items| items.len());
        formatter
            .debug_struct("DemoIssueConnector")
            .field("connector_name", &self.connector_name)
            .field("request_count", &request_count)
            .finish_non_exhaustive()
    }
}

impl DemoIssueConnector {
    /// Creates a connector bound to one hermetic service instance.
    pub fn new(
        connector_name: impl Into<String>,
        service: Arc<DemoIssueService>,
    ) -> Result<Self, EffectError> {
        let connector_name = connector_name.into();
        validate_selector(&connector_name)?;
        Ok(Self {
            connector_name,
            service,
            requests: RwLock::new(BTreeMap::new()),
        })
    }

    /// Stages protected normalized arguments and returns their exact digest.
    pub fn stage_request(&self, request: DemoIssueRequest) -> Result<ContentDigest, EffectError> {
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

    fn request(&self, digest: &ContentDigest) -> Result<DemoIssueRequest, EffectError> {
        self.requests
            .read()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .get(digest)
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))
    }

    fn validate_context(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<DemoIssueRequest, EffectError> {
        if context.intent.connector != self.connector_name
            || context.intent.operation != CREATE_ISSUE
            || !context.intent.preconditions.is_empty()
        {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let request = self.request(&context.intent.arguments_digest)?;
        if context.intent.target != request.project {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        Ok(request)
    }
}

impl EffectConnector for DemoIssueConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: self.connector_name.clone(),
            operations: vec![ConnectorOperation {
                operation: CREATE_ISSUE.to_owned(),
                same_key_idempotent: true,
                supports_reconciliation: true,
                supports_compensation: false,
            }],
            maximum_dispatch_nanos: 5_000_000_000,
        }
    }

    fn check_preconditions(
        &self,
        intent: &cigar_protocol::EffectIntent,
        _now: cigar_protocol::UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        let context_matches = intent.connector == self.connector_name
            && intent.operation == CREATE_ISSUE
            && intent.preconditions.is_empty()
            && self
                .request(&intent.arguments_digest)
                .is_ok_and(|request| request.project == intent.target);
        let mut evidence = BTreeSet::new();
        evidence.insert(stable_evidence(b"demo-preconditions", intent)?);
        Ok(PreconditionReport {
            satisfied: context_matches,
            evidence,
        })
    }

    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        let request = self.validate_context(context)?;
        let observation = self.service.create(
            &context.intent.idempotency_scope,
            context.intent.idempotency_key.as_str(),
            &request,
            &context.intent.arguments_digest,
        )?;
        match observation {
            DemoServiceObservation::Committed(issue) => success_observation(&issue),
            DemoServiceObservation::CommittedWithoutResponse(issue) => {
                Ok(DispatchObservation::Unknown {
                    evidence_digest: snapshot_digest(b"demo-response-lost", &issue)?,
                    remote_operation_id: Some(issue.issue_id),
                })
            }
            DemoServiceObservation::ProvenNotSent => Ok(DispatchObservation::ProvenNotSent {
                evidence_digest: stable_evidence(b"demo-proven-not-sent", context.intent)?,
            }),
            DemoServiceObservation::Rejected | DemoServiceObservation::Collision => {
                Ok(DispatchObservation::Failed {
                    evidence_digest: stable_evidence(b"demo-rejected", context.intent)?,
                })
            }
        }
    }

    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        let _request = self.validate_context(context)?;
        match self.service.lookup(
            &context.intent.idempotency_scope,
            context.intent.idempotency_key.as_str(),
            &context.intent.arguments_digest,
        )? {
            DemoLookup::Found(issue) => Ok(ReconcileObservation::ConfirmedSuccess(
                snapshot_digest(b"demo-reconciled", &issue)?,
            )),
            DemoLookup::Absent => Ok(ReconcileObservation::ProvenNotExecuted(stable_evidence(
                b"demo-absent",
                context.intent,
            )?)),
            DemoLookup::Collision => Ok(ReconcileObservation::ConfirmedFailure(stable_evidence(
                b"demo-key-collision",
                context.intent,
            )?)),
        }
    }
}

fn success_observation(issue: &DemoIssueSnapshot) -> Result<DispatchObservation, EffectError> {
    Ok(DispatchObservation::Succeeded {
        remote_operation_id: issue.issue_id.clone(),
        response_digest: snapshot_digest(b"demo-response", issue)?,
        verification_digest: snapshot_digest(b"demo-verification", issue)?,
    })
}

fn snapshot_digest(domain: &[u8], issue: &DemoIssueSnapshot) -> Result<ContentDigest, EffectError> {
    digest_parts(
        domain,
        &[
            issue.issue_id.as_bytes(),
            issue.project.as_bytes(),
            issue.title_digest.as_str().as_bytes(),
            issue.body_digest.as_str().as_bytes(),
            if issue.open { b"open" } else { b"closed" },
        ],
    )
}
