//! WP12 durable effect-kernel integration and safety tests.

use cigar_effects::{
    ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation,
    DurableEffectRecord, EffectAuthorization, EffectConnector, EffectEngine, EffectError,
    EffectErrorCode, EffectOutboxState, EffectRecordAuthenticator, EffectRecordSeal,
    PreconditionReport, ProcessEffectAuthenticator, ReconcileObservation, compensation_spec_digest,
    effect_intent_digest, effect_target_digest,
};
use cigar_protocol::{
    ApprovalKind, BlobRef, Capability, CompensationLink, CompensationSpec, ContentDigest,
    EffectApproval, EffectIntent, EffectJournalEvent, EffectState, ExtensionMap, IdempotencyKey,
    MediaType, ReconciliationOutcome, RecordId, RetryPolicy, RiskLevel, SchemaVersion,
    UtcTimestamp, VersionId,
};
use cigar_store::EffectRecordEnvelope;
use cigar_store::{AccessContext, CancellationToken, InMemoryStore, Repository, WriteTransaction};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn Error>>;
type TestEngine = EffectEngine<InMemoryStore>;
type TestFixture = (Arc<InMemoryStore>, AccessContext, TestEngine);

fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn digest(value: u64) -> Result<ContentDigest, Box<dyn Error>> {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn bytes_digest(value: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let hash = Sha256::digest(value);
    let mut encoded = String::from("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn version(value: u64) -> Result<VersionId, Box<dyn Error>> {
    Ok(VersionId::new(digest(value)?.as_str())?)
}

fn time(second: u8) -> Result<UtcTimestamp, Box<dyn Error>> {
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}

fn authorization(
    actor: u64,
    now: u8,
    capabilities: impl IntoIterator<Item = Capability>,
) -> Result<EffectAuthorization, Box<dyn Error>> {
    Ok(EffectAuthorization {
        actor_id: record(actor)?,
        capabilities: capabilities.into_iter().collect(),
        policy_allows: true,
        now: time(now)?,
    })
}

fn proposal_authorization(now: u8) -> Result<EffectAuthorization, Box<dyn Error>> {
    authorization(900, now, [Capability::ProposeEffect])
}

fn dispatch_authorization(now: u8) -> Result<EffectAuthorization, Box<dyn Error>> {
    authorization(
        901,
        now,
        [
            Capability::ProposeEffect,
            Capability::ApproveEffect,
            Capability::InvokeTool,
            Capability::ReconcileEffect,
        ],
    )
}

fn operation(
    operation: &str,
    same_key_idempotent: bool,
    supports_reconciliation: bool,
    supports_compensation: bool,
) -> ConnectorOperation {
    ConnectorOperation {
        operation: operation.to_owned(),
        same_key_idempotent,
        supports_reconciliation,
        supports_compensation,
    }
}

struct TestConnector {
    descriptor: ConnectorDescriptor,
    preconditions_satisfied: AtomicBool,
    dispatch_observation: DispatchObservation,
    reconciliation_observation: ReconcileObservation,
    dispatch_calls: AtomicUsize,
    reconciliation_calls: AtomicUsize,
}

impl TestConnector {
    fn new(
        connector: &str,
        operations: Vec<ConnectorOperation>,
        dispatch_observation: DispatchObservation,
        reconciliation_observation: ReconcileObservation,
    ) -> Self {
        Self {
            descriptor: ConnectorDescriptor {
                connector: connector.to_owned(),
                operations,
                maximum_dispatch_nanos: 60_000_000_000,
            },
            preconditions_satisfied: AtomicBool::new(true),
            dispatch_observation,
            reconciliation_observation,
            dispatch_calls: AtomicUsize::new(0),
            reconciliation_calls: AtomicUsize::new(0),
        }
    }

    fn success(
        connector: &str,
        operations: Vec<ConnectorOperation>,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self::new(
            connector,
            operations,
            DispatchObservation::Succeeded {
                remote_operation_id: "remote-1".to_owned(),
                response_digest: digest(700)?,
                verification_digest: digest(701)?,
            },
            ReconcileObservation::ConfirmedSuccess(digest(702)?),
        ))
    }

    fn dispatch_calls(&self) -> usize {
        self.dispatch_calls.load(Ordering::Acquire)
    }

    fn reconciliation_calls(&self) -> usize {
        self.reconciliation_calls.load(Ordering::Acquire)
    }
}

impl EffectConnector for TestConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.descriptor.clone()
    }

    fn check_preconditions(
        &self,
        _intent: &EffectIntent,
        _now: UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        Ok(PreconditionReport {
            satisfied: self.preconditions_satisfied.load(Ordering::Acquire),
            evidence: BTreeSet::new(),
        })
    }

    fn dispatch(&self, _context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        self.dispatch_calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.dispatch_observation.clone())
    }

    fn reconcile(
        &self,
        _context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        self.reconciliation_calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.reconciliation_observation.clone())
    }
}

struct DriftingConnector {
    registered_descriptor: ConnectorDescriptor,
    drifted: AtomicBool,
    dispatch_calls: AtomicUsize,
    evidence: ContentDigest,
}

impl DriftingConnector {
    fn new(evidence: ContentDigest) -> Self {
        Self {
            registered_descriptor: ConnectorDescriptor {
                connector: "drifting".to_owned(),
                operations: vec![operation("do", false, true, false)],
                maximum_dispatch_nanos: 60_000_000_000,
            },
            drifted: AtomicBool::new(false),
            dispatch_calls: AtomicUsize::new(0),
            evidence,
        }
    }
}

impl EffectConnector for DriftingConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        let mut descriptor = self.registered_descriptor.clone();
        if self.drifted.load(Ordering::Acquire) {
            for operation in &mut descriptor.operations {
                operation.supports_reconciliation = false;
            }
        }
        descriptor
    }

    fn check_preconditions(
        &self,
        _intent: &EffectIntent,
        _now: UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        Ok(PreconditionReport {
            satisfied: true,
            evidence: BTreeSet::new(),
        })
    }

    fn dispatch(&self, _context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        self.dispatch_calls.fetch_add(1, Ordering::AcqRel);
        Ok(DispatchObservation::Failed {
            evidence_digest: self.evidence.clone(),
        })
    }

    fn reconcile(
        &self,
        _context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        Ok(ReconcileObservation::ConfirmedFailure(
            self.evidence.clone(),
        ))
    }
}

struct OverlapConnector {
    calls: AtomicUsize,
    observation: DispatchObservation,
}

impl OverlapConnector {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            calls: AtomicUsize::new(0),
            observation: DispatchObservation::Succeeded {
                remote_operation_id: "one-remote-mutation".to_owned(),
                response_digest: digest(8_390)?,
                verification_digest: digest(8_391)?,
            },
        })
    }
}

impl EffectConnector for OverlapConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: "overlap".to_owned(),
            operations: vec![operation("do", true, true, false)],
            maximum_dispatch_nanos: 60_000_000_000,
        }
    }

    fn check_preconditions(
        &self,
        _intent: &EffectIntent,
        _now: UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        Ok(PreconditionReport {
            satisfied: true,
            evidence: BTreeSet::new(),
        })
    }

    fn dispatch(&self, _context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let deadline = Instant::now() + Duration::from_millis(250);
        while self.calls.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        Ok(self.observation.clone())
    }

    fn reconcile(
        &self,
        _context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        Ok(ReconcileObservation::ConfirmedSuccess(
            digest(8_392).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
        ))
    }
}

fn intent(
    effect: u64,
    connector: &str,
    operation: &str,
    key: &str,
    risk: RiskLevel,
    retry_policy: RetryPolicy,
    compensation: Option<CompensationSpec>,
) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
        effect_id: record(effect)?,
        connector: connector.to_owned(),
        operation: operation.to_owned(),
        arguments_digest: digest(effect.saturating_add(1_000))?,
        encrypted_arguments: BlobRef {
            digest: digest(effect.saturating_add(2_000))?,
            size_bytes: 64,
            media_type: MediaType::new("application/octet-stream")?,
        },
        target: format!("target-{effect}"),
        preconditions: Vec::new(),
        result_schema_digest: digest(effect.saturating_add(3_000))?,
        risk,
        source_decision_id: version(effect.saturating_add(4_000))?,
        bundle_id: version(effect.saturating_add(5_000))?,
        required_capability: Capability::InvokeTool,
        idempotency_scope: "tenant-a".to_owned(),
        idempotency_key: IdempotencyKey::new(key)?,
        retry_policy,
        created_at: time(1)?,
        expires_at: time(50)?,
        compensation,
        extensions: ExtensionMap::default(),
    })
}

fn compensation_spec() -> Result<CompensationSpec, Box<dyn Error>> {
    Ok(CompensationSpec {
        operation: "undo".to_owned(),
        arguments_digest: digest(8_001)?,
        encrypted_arguments: BlobRef {
            digest: digest(8_002)?,
            size_bytes: 48,
            media_type: MediaType::new("application/octet-stream")?,
        },
    })
}

fn approval(
    record: &DurableEffectRecord,
    approval_id: u64,
    approved_at: u8,
    expires_at: u8,
    kind: ApprovalKind,
) -> Result<EffectApproval, Box<dyn Error>> {
    Ok(EffectApproval {
        schema_version: SchemaVersion::new("cigar.effect-approval", 1)?,
        approval_id: record_id(approval_id)?,
        effect_id: record.intent.effect_id.clone(),
        intent_digest: record.intent_digest.clone(),
        target_digest: effect_target_digest(&record.intent.target)?,
        risk: record.intent.risk,
        bundle_id: record.intent.bundle_id.clone(),
        conditions_digest: digest(8_100)?,
        approver_id: record_id(8_101)?,
        kind,
        approved_at: time(approved_at)?,
        expires_at: time(expires_at)?,
    })
}

fn record_id(value: u64) -> Result<RecordId, Box<dyn Error>> {
    record(value)
}

fn fixture(connector: Arc<TestConnector>) -> Result<TestFixture, Box<dyn Error>> {
    static NEXT_TENANT: AtomicUsize = AtomicUsize::new(100_000);
    let store = Arc::new(InMemoryStore::default());
    let tenant_number = u64::try_from(NEXT_TENANT.fetch_add(1, Ordering::Relaxed))?;
    let access = AccessContext::new(record(tenant_number)?, "wp12-effect-tests")?;
    let engine = EffectEngine::new(store.clone(), access.clone());
    engine.register_connector(connector)?;
    Ok((store, access, engine))
}

fn assert_code<T>(result: Result<T, EffectError>, expected: EffectErrorCode) {
    assert_eq!(result.err().map(EffectError::code), Some(expected));
}

fn prepare_and_authorize_low(
    engine: &EffectEngine<InMemoryStore>,
    intent: EffectIntent,
    event: u64,
) -> Result<DurableEffectRecord, Box<dyn Error>> {
    let prepared = engine
        .prepare(intent, &proposal_authorization(2)?)
        .map_err(|error| std::io::Error::other(format!("prepare low effect: {error}")))?;
    Ok(engine
        .authorize(
            &prepared.intent.effect_id,
            prepared.effect_version,
            record(event)?,
            None,
            &dispatch_authorization(3)?,
        )
        .map_err(|error| std::io::Error::other(format!("authorize low effect: {error}")))?)
}

fn drive_to_unknown(
    engine: &EffectEngine<InMemoryStore>,
    intent: EffectIntent,
    ids: u64,
) -> Result<DurableEffectRecord, Box<dyn Error>> {
    let authorized = prepare_and_authorize_low(engine, intent, ids)
        .map_err(|error| std::io::Error::other(format!("unknown setup authorization: {error}")))?;
    let permit = engine
        .claim_dispatch(
            &authorized.intent.effect_id,
            authorized.effect_version,
            record(ids.saturating_add(1))?,
            record(ids.saturating_add(2))?,
            record(ids.saturating_add(3))?,
            time(40)?,
            &dispatch_authorization(4)?,
        )
        .map_err(|error| std::io::Error::other(format!("unknown setup claim: {error}")))?;
    Ok(engine
        .dispatch(
            permit,
            record(ids.saturating_add(4))?,
            record(ids.saturating_add(5))?,
            &dispatch_authorization(5)?,
        )
        .map_err(|error| std::io::Error::other(format!("unknown setup dispatch: {error}")))?)
}

#[test]
fn dispatch_requires_committed_authorization_attempt_fence_and_outbox() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "durable",
        vec![operation("do", true, true, false)],
    )?);
    let (store, _access, engine) = fixture(connector.clone())?;
    let prepared = engine.prepare(
        intent(
            10,
            "durable",
            "do",
            "durable-10",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    assert_eq!(prepared.state, EffectState::Prepared);
    assert_eq!(prepared.effect_version, 0);
    assert!(prepared.journal.is_empty());
    assert_eq!(connector.dispatch_calls(), 0);

    assert_code(
        engine.claim_dispatch(
            &prepared.intent.effect_id,
            0,
            record(11)?,
            record(12)?,
            record(13)?,
            time(40)?,
            &dispatch_authorization(3)?,
        ),
        EffectErrorCode::InvalidTransition,
    );
    assert_eq!(connector.dispatch_calls(), 0);

    let authorized = engine.authorize(
        &prepared.intent.effect_id,
        0,
        record(14)?,
        None,
        &dispatch_authorization(3)?,
    )?;
    store.fail_next_commit();
    assert_code(
        engine.claim_dispatch(
            &authorized.intent.effect_id,
            authorized.effect_version,
            record(15)?,
            record(16)?,
            record(17)?,
            time(40)?,
            &dispatch_authorization(4)?,
        ),
        EffectErrorCode::Unavailable,
    );
    let after_abort = engine.get(&authorized.intent.effect_id)?;
    assert_eq!(after_abort.state, EffectState::Authorized);
    assert!(after_abort.attempts.is_empty());
    assert!(after_abort.outbox.is_none());
    assert_eq!(connector.dispatch_calls(), 0);

    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(18)?,
        record(19)?,
        record(20)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let durable_claim = engine.get(&authorized.intent.effect_id)?;
    assert_eq!(durable_claim.state, EffectState::Dispatching);
    assert_eq!(durable_claim.attempts.len(), 1);
    assert_eq!(permit.fencing_token(), 1);
    assert_eq!(
        durable_claim.outbox.as_ref().map(|entry| entry.state),
        Some(EffectOutboxState::Claimed)
    );
    assert_eq!(connector.dispatch_calls(), 0);

    let completed = engine.dispatch(
        permit,
        record(21)?,
        record(22)?,
        &dispatch_authorization(5)?,
    )?;
    assert_eq!(completed.state, EffectState::Succeeded);
    assert_eq!(completed.receipts.len(), 1);
    assert_eq!(completed.effect_version, 4);
    assert_eq!(completed.journal.len(), 4);
    assert_eq!(
        completed.outbox.as_ref().map(|entry| entry.state),
        Some(EffectOutboxState::Completed)
    );
    assert_eq!(connector.dispatch_calls(), 1);
    Ok(())
}

#[test]
fn authority_is_rechecked_immediately_before_send() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "authority",
        vec![operation("do", false, false, false)],
    )?);
    let (_store, _access, engine) = fixture(connector.clone())?;
    let authorized = prepare_and_authorize_low(
        &engine,
        intent(
            30,
            "authority",
            "do",
            "authority-30",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        31,
    )?;
    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(32)?,
        record(33)?,
        record(34)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let denied = EffectAuthorization {
        actor_id: record(902)?,
        capabilities: BTreeSet::new(),
        policy_allows: false,
        now: time(5)?,
    };
    let finalized = engine.dispatch(permit, record(35)?, record(36)?, &denied)?;
    assert_eq!(finalized.state, EffectState::Failed);
    assert_eq!(finalized.receipts.len(), 1);
    assert_eq!(connector.dispatch_calls(), 0);
    Ok(())
}

#[test]
fn approval_binding_rejects_stale_version_digest_time_and_provenance() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "approval",
        vec![operation("do", false, false, false)],
    )?);
    let (_store, _access, engine) = fixture(connector)?;
    let prepared = engine.prepare(
        intent(
            40,
            "approval",
            "do",
            "approval-40",
            RiskLevel::Medium,
            RetryPolicy::Never,
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    let pending = engine.request_approval(
        &prepared.intent.effect_id,
        0,
        record(41)?,
        &proposal_authorization(2)?,
    )?;
    let exact = approval(&pending, 42, 2, 20, ApprovalKind::Policy)?;

    assert_code(
        engine.authorize(
            &pending.intent.effect_id,
            0,
            record(43)?,
            Some(exact.clone()),
            &dispatch_authorization(3)?,
        ),
        EffectErrorCode::RevisionConflict,
    );

    let expired = approval(&pending, 44, 2, 5, ApprovalKind::Policy)?;
    assert_code(
        engine.authorize(
            &pending.intent.effect_id,
            pending.effect_version,
            record(45)?,
            Some(expired),
            &dispatch_authorization(5)?,
        ),
        EffectErrorCode::Unauthorized,
    );

    let mut wrong_digest = exact.clone();
    wrong_digest.intent_digest = digest(8_200)?;
    assert_code(
        engine.authorize(
            &pending.intent.effect_id,
            pending.effect_version,
            record(46)?,
            Some(wrong_digest),
            &dispatch_authorization(3)?,
        ),
        EffectErrorCode::Unauthorized,
    );

    let authorized = engine.authorize(
        &pending.intent.effect_id,
        pending.effect_version,
        record(47)?,
        Some(exact),
        &dispatch_authorization(3)?,
    )?;
    assert_eq!(authorized.state, EffectState::Authorized);

    let high = engine.prepare(
        intent(
            48,
            "approval",
            "do",
            "approval-48",
            RiskLevel::High,
            RetryPolicy::Never,
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    let policy_approval = approval(&high, 49, 2, 20, ApprovalKind::Policy)?;
    assert_code(
        engine.authorize(
            &high.intent.effect_id,
            high.effect_version,
            record(50)?,
            Some(policy_approval),
            &dispatch_authorization(3)?,
        ),
        EffectErrorCode::InvalidInput,
    );
    Ok(())
}

#[test]
fn idempotency_keys_bind_exact_normalized_intent() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "keys",
        vec![operation("do", true, true, false)],
    )?);
    let (_store, _access, engine) = fixture(connector)?;
    let first_intent = intent(
        60,
        "keys",
        "do",
        "shared-key",
        RiskLevel::Low,
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        None,
    )?;
    let first = engine.prepare(first_intent.clone(), &proposal_authorization(2)?)?;
    let replay = engine.prepare(first_intent.clone(), &proposal_authorization(2)?)?;
    assert_eq!(replay, first);

    let mut same_id_different_target = first_intent;
    same_id_different_target.target = "another-target".to_owned();
    assert_code(
        engine.prepare(same_id_different_target, &proposal_authorization(2)?),
        EffectErrorCode::IdempotencyCollision,
    );

    assert_code(
        engine.prepare(
            intent(
                61,
                "keys",
                "do",
                "shared-key",
                RiskLevel::Low,
                RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
                None,
            )?,
            &proposal_authorization(2)?,
        ),
        EffectErrorCode::IdempotencyCollision,
    );
    Ok(())
}

#[test]
fn connector_declarations_bound_preconditions_reconciliation_and_retry() -> TestResult {
    let undeclared = Arc::new(TestConnector::new(
        "bounded",
        vec![operation("do", false, false, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_300)?,
            remote_operation_id: None,
        },
        ReconcileObservation::ConfirmedSuccess(digest(8_301)?),
    ));
    let (_store, _access, engine) = fixture(undeclared.clone())?;
    assert_code(
        engine.prepare(
            intent(
                70,
                "bounded",
                "do",
                "bounded-70",
                RiskLevel::Low,
                RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
                None,
            )?,
            &proposal_authorization(2)?,
        ),
        EffectErrorCode::InvalidInput,
    );
    let unknown = drive_to_unknown(
        &engine,
        intent(
            71,
            "bounded",
            "do",
            "bounded-71",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        72,
    )
    .map_err(|error| std::io::Error::other(format!("bounded unknown setup: {error}")))?;
    assert_eq!(unknown.state, EffectState::Unknown);
    assert_code(
        engine.authorize_idempotent_retry(
            &unknown.intent.effect_id,
            unknown.effect_version,
            record(77)?,
            &dispatch_authorization(6)?,
        ),
        EffectErrorCode::UnsafeRetry,
    );
    assert_code(
        engine.reconcile(
            &unknown.intent.effect_id,
            unknown.effect_version,
            record(78)?,
            record(79)?,
            &dispatch_authorization(6)?,
        ),
        EffectErrorCode::UnsafeRetry,
    );
    assert_eq!(undeclared.reconciliation_calls(), 0);

    let blocked = Arc::new(TestConnector::success(
        "preconditions",
        vec![operation("do", false, false, false)],
    )?);
    blocked
        .preconditions_satisfied
        .store(false, Ordering::Release);
    let (_store, _access, blocked_engine) = fixture(blocked.clone())?;
    let authorized = prepare_and_authorize_low(
        &blocked_engine,
        intent(
            80,
            "preconditions",
            "do",
            "preconditions-80",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        81,
    )?;
    let permit = blocked_engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(82)?,
        record(83)?,
        record(84)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let failed = blocked_engine.dispatch(
        permit,
        record(85)?,
        record(86)?,
        &dispatch_authorization(5)?,
    )?;
    assert_eq!(failed.state, EffectState::Failed);
    assert_eq!(blocked.dispatch_calls(), 0);

    let invalid = Arc::new(TestConnector::success(
        "invalid",
        vec![
            operation("z-last", false, false, false),
            operation("a-first", false, false, false),
        ],
    )?);
    let store = Arc::new(InMemoryStore::default());
    let engine = EffectEngine::new(store, AccessContext::new(record(1)?, "invalid-connector")?);
    assert_code(
        engine.register_connector(invalid),
        EffectErrorCode::InvalidInput,
    );
    Ok(())
}

#[test]
fn connector_descriptor_drift_is_rejected_before_remote_dispatch() -> TestResult {
    let connector = Arc::new(DriftingConnector::new(digest(8_350)?));
    let store = Arc::new(InMemoryStore::default());
    let access = AccessContext::new(record(1)?, "descriptor-drift")?;
    let engine = EffectEngine::new(store, access);
    engine.register_connector(connector.clone())?;
    let authorized = prepare_and_authorize_low(
        &engine,
        intent(
            87,
            "drifting",
            "do",
            "drifting-87",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        88,
    )?;
    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(89)?,
        record(90)?,
        record(91)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    connector.drifted.store(true, Ordering::Release);
    assert_code(
        engine.dispatch(
            permit,
            record(92)?,
            record(93)?,
            &dispatch_authorization(5)?,
        ),
        EffectErrorCode::Unavailable,
    );
    assert_eq!(connector.dispatch_calls.load(Ordering::Acquire), 0);
    let stranded = engine.get(&authorized.intent.effect_id)?;
    assert_eq!(stranded.state, EffectState::Dispatching);
    assert_eq!(
        stranded.outbox.as_ref().map(|entry| entry.state),
        Some(EffectOutboxState::Claimed)
    );
    Ok(())
}

#[test]
fn two_workers_cannot_claim_the_same_authorized_version() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "workers",
        vec![operation("do", true, true, false)],
    )?);
    let store = Arc::new(InMemoryStore::default());
    let access = AccessContext::new(record(1)?, "two-worker-claim")?;
    let first_engine = Arc::new(EffectEngine::new(store.clone(), access.clone()));
    let second_engine = Arc::new(EffectEngine::new(store, access));
    first_engine.register_connector(connector.clone())?;
    second_engine.register_connector(connector)?;
    let authorized = prepare_and_authorize_low(
        &first_engine,
        intent(
            90,
            "workers",
            "do",
            "workers-90",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            None,
        )?,
        91,
    )?;

    let (sender, receiver) = mpsc::channel();
    let workers = [
        (
            first_engine.clone(),
            dispatch_authorization(4)?,
            record(92)?,
            record(93)?,
            record(94)?,
            time(40)?,
        ),
        (
            second_engine,
            dispatch_authorization(4)?,
            record(96)?,
            record(97)?,
            record(98)?,
            time(40)?,
        ),
    ];
    std::thread::scope(|scope| {
        for (engine, authorization, attempt_id, message_id, event_id, deadline) in workers {
            let sender = sender.clone();
            let effect_id = authorized.intent.effect_id.clone();
            scope.spawn(move || {
                let result = engine
                    .claim_dispatch(
                        &effect_id,
                        1,
                        attempt_id,
                        message_id,
                        event_id,
                        deadline,
                        &authorization,
                    )
                    .map(|permit| permit.fencing_token());
                let _ignored = sender.send(result);
            });
        }
    });
    drop(sender);

    let mut successes = 0;
    let mut conflicts = 0;
    for result in receiver {
        match result {
            Ok(token) => {
                successes += 1;
                assert_eq!(token, 1);
            }
            Err(error) => {
                assert_eq!(error.code(), EffectErrorCode::RevisionConflict);
                conflicts += 1;
            }
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(conflicts, 1);
    let claimed = first_engine.get(&authorized.intent.effect_id)?;
    assert_eq!(claimed.state, EffectState::Dispatching);
    assert_eq!(claimed.attempts.len(), 1);
    Ok(())
}

#[test]
fn concurrent_workers_cannot_reuse_one_durable_permit_at_connector_entry() -> TestResult {
    let connector = Arc::new(OverlapConnector::new()?);
    let store = Arc::new(InMemoryStore::default());
    let access = AccessContext::new(record(1)?, "two-worker-resume")?;
    let first_engine = Arc::new(EffectEngine::new(store.clone(), access.clone()));
    let second_engine = Arc::new(EffectEngine::new(store, access));
    first_engine.register_connector(connector.clone())?;
    second_engine.register_connector(connector.clone())?;
    let authorized = prepare_and_authorize_low(
        &first_engine,
        intent(
            8_393,
            "overlap",
            "do",
            "overlap-key",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            None,
        )?,
        8_394,
    )?;
    let first_permit = first_engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(8_395)?,
        record(8_396)?,
        record(8_397)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let claimed = first_engine.get(&authorized.intent.effect_id)?;
    let second_permit =
        second_engine.resume_dispatch(&claimed.intent.effect_id, claimed.effect_version)?;

    let (sender, receiver) = mpsc::channel();
    std::thread::scope(|scope| {
        for (engine, permit, receipt, event, authorization) in [
            (
                first_engine,
                first_permit,
                record(8_398)?,
                record(8_399)?,
                dispatch_authorization(5)?,
            ),
            (
                second_engine,
                second_permit,
                record(8_400)?,
                record(8_401)?,
                dispatch_authorization(5)?,
            ),
        ] {
            let sender = sender.clone();
            scope.spawn(move || {
                let result = engine.dispatch(permit, receipt, event, &authorization);
                let _ignored = sender.send(result);
            });
        }
        Ok::<(), Box<dyn Error>>(())
    })?;
    drop(sender);
    let results = receiver.into_iter().collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(connector.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn unreceipted_connector_owner_cannot_retry_or_reconcile_before_deadline() -> TestResult {
    let connector = Arc::new(OverlapConnector::new()?);
    let store = Arc::new(InMemoryStore::default());
    let access = AccessContext::new(record(1)?, "inflight-owner-deadline")?;
    let engine = Arc::new(EffectEngine::new(store, access));
    engine.register_connector(connector.clone())?;
    let authorized = prepare_and_authorize_low(
        &engine,
        intent(
            8_402,
            "overlap",
            "do",
            "inflight-owner-key",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            None,
        )?,
        8_403,
    )?;
    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(8_404)?,
        record(8_405)?,
        record(8_406)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let effect_id = authorized.intent.effect_id.clone();
    std::thread::scope(|scope| {
        let dispatch_engine = engine.clone();
        let handle = scope.spawn(move || {
            dispatch_engine.dispatch(
                permit,
                record(8_407).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
                record(8_408).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
                &dispatch_authorization(5)
                    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
            )
        });
        let wait_end = Instant::now() + Duration::from_secs(1);
        while connector.calls.load(Ordering::Acquire) == 0 && Instant::now() < wait_end {
            std::thread::yield_now();
        }
        if connector.calls.load(Ordering::Acquire) != 1 {
            return Err(std::io::Error::other("connector owner did not enter").into());
        }
        let inflight = engine.get(&effect_id)?;
        assert_eq!(inflight.state, EffectState::Unknown);
        assert_code(
            engine.authorize_idempotent_retry(
                &effect_id,
                inflight.effect_version,
                record(8_409)?,
                &dispatch_authorization(6)?,
            ),
            EffectErrorCode::UnsafeRetry,
        );
        assert_code(
            engine.reconcile(
                &effect_id,
                inflight.effect_version,
                record(8_410)?,
                record(8_411)?,
                &dispatch_authorization(6)?,
            ),
            EffectErrorCode::InvalidTransition,
        );
        handle
            .join()
            .map_err(|_panic| std::io::Error::other("dispatch worker panicked"))??;
        Ok::<(), Box<dyn Error>>(())
    })?;
    assert_eq!(connector.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn unknown_retry_requires_idempotency_or_proven_non_execution() -> TestResult {
    let idempotent = Arc::new(TestConnector::new(
        "idempotent",
        vec![operation("do", true, true, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_400)?,
            remote_operation_id: Some("maybe-remote".to_owned()),
        },
        ReconcileObservation::ConfirmedSuccess(digest(8_401)?),
    ));
    let (_store, _access, engine) = fixture(idempotent)?;
    let unknown = drive_to_unknown(
        &engine,
        intent(
            110,
            "idempotent",
            "do",
            "idempotent-110",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            None,
        )?,
        111,
    )?;
    let retry = engine.authorize_idempotent_retry(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(117)?,
        &dispatch_authorization(6)?,
    )?;
    assert_eq!(retry.state, EffectState::AuthorizedForRetry);
    let second_permit = engine.claim_dispatch(
        &retry.intent.effect_id,
        retry.effect_version,
        record(118)?,
        record(119)?,
        record(120)?,
        time(40)?,
        &dispatch_authorization(7)?,
    )?;
    assert_eq!(second_permit.fencing_token(), 2);

    let reconciling = Arc::new(TestConnector::new(
        "reconciling",
        vec![operation("do", false, true, false)],
        DispatchObservation::ProvenNotSent {
            evidence_digest: digest(8_410)?,
        },
        ReconcileObservation::ProvenNotExecuted(digest(8_411)?),
    ));
    let (_store, _access, reconciling_engine) = fixture(reconciling.clone())?;
    let unknown = drive_to_unknown(
        &reconciling_engine,
        intent(
            130,
            "reconciling",
            "do",
            "reconciling-130",
            RiskLevel::Low,
            RetryPolicy::ReconcileBeforeRetry,
            None,
        )?,
        131,
    )?;
    assert_code(
        reconciling_engine.authorize_idempotent_retry(
            &unknown.intent.effect_id,
            unknown.effect_version,
            record(137)?,
            &dispatch_authorization(6)?,
        ),
        EffectErrorCode::UnsafeRetry,
    );
    let reconciled = reconciling_engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(138)?,
        record(139)?,
        &dispatch_authorization(6)?,
    )?;
    assert_eq!(reconciled.state, EffectState::AuthorizedForRetry);
    assert_eq!(reconciling.reconciliation_calls(), 1);
    let permit = reconciling_engine.claim_dispatch(
        &reconciled.intent.effect_id,
        reconciled.effect_version,
        record(140)?,
        record(141)?,
        record(142)?,
        time(40)?,
        &dispatch_authorization(7)?,
    )?;
    assert_eq!(permit.fencing_token(), 2);
    Ok(())
}

#[test]
fn reconciliation_records_success_failure_and_inconclusive_outcomes() -> TestResult {
    let success_connector = Arc::new(TestConnector::new(
        "reconcile-success",
        vec![operation("do", false, true, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_420)?,
            remote_operation_id: Some("remote-success".to_owned()),
        },
        ReconcileObservation::ConfirmedSuccess(digest(8_421)?),
    ));
    let (_store, _access, success_engine) = fixture(success_connector)?;
    let unknown = drive_to_unknown(
        &success_engine,
        intent(
            143,
            "reconcile-success",
            "do",
            "reconcile-143",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        144,
    )?;
    let succeeded = success_engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(150)?,
        record(151)?,
        &dispatch_authorization(6)?,
    )?;
    assert_eq!(succeeded.state, EffectState::Succeeded);
    assert_eq!(succeeded.reconciliations.len(), 1);

    let failure_connector = Arc::new(TestConnector::new(
        "reconcile-failure",
        vec![operation("do", false, true, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_422)?,
            remote_operation_id: None,
        },
        ReconcileObservation::ConfirmedFailure(digest(8_423)?),
    ));
    let (_store, _access, failure_engine) = fixture(failure_connector)?;
    let unknown = drive_to_unknown(
        &failure_engine,
        intent(
            152,
            "reconcile-failure",
            "do",
            "reconcile-152",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        153,
    )?;
    let failed = failure_engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(159)?,
        record(160)?,
        &dispatch_authorization(6)?,
    )?;
    assert_eq!(failed.state, EffectState::Failed);

    let inconclusive_connector = Arc::new(TestConnector::new(
        "reconcile-inconclusive",
        vec![operation("do", false, true, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_424)?,
            remote_operation_id: None,
        },
        ReconcileObservation::Inconclusive {
            evidence_digest: digest(8_425)?,
            certainty_window_end: time(20)?,
        },
    ));
    let (_store, _access, inconclusive_engine) = fixture(inconclusive_connector)?;
    let unknown = drive_to_unknown(
        &inconclusive_engine,
        intent(
            161,
            "reconcile-inconclusive",
            "do",
            "reconcile-161",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        162,
    )?;
    let still_unknown = inconclusive_engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(168)?,
        record(169)?,
        &dispatch_authorization(6)?,
    )?;
    assert_eq!(still_unknown.state, EffectState::Unknown);
    assert_eq!(still_unknown.reconciliations.len(), 1);
    assert_eq!(
        still_unknown.effect_version,
        unknown.effect_version.saturating_add(1)
    );

    let stale_evidence = digest(8_426)?;
    let stale_connector = Arc::new(TestConnector::new(
        "reconcile-stale-window",
        vec![operation("do", false, true, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_427)?,
            remote_operation_id: None,
        },
        ReconcileObservation::Inconclusive {
            evidence_digest: stale_evidence.clone(),
            certainty_window_end: time(5)?,
        },
    ));
    let (_store, _access, stale_engine) = fixture(stale_connector.clone())?;
    let unknown = drive_to_unknown(
        &stale_engine,
        intent(
            170,
            "reconcile-stale-window",
            "do",
            "reconcile-170",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        171,
    )?;
    let reconciliation_time = time(6)?;
    let persisted = stale_engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(177)?,
        record(178)?,
        &dispatch_authorization(6)?,
    )?;
    let report = persisted
        .reconciliations
        .last()
        .ok_or_else(|| std::io::Error::other("stale reconciliation report was not persisted"))?;
    assert_eq!(persisted.state, EffectState::Unknown);
    assert_eq!(report.outcome, ReconciliationOutcome::Inconclusive);
    assert!(
        report
            .certainty_window_end
            .is_some_and(|window_end| window_end > reconciliation_time)
    );
    assert!(!report.evidence_digests.contains(&stale_evidence));
    assert_eq!(stale_connector.reconciliation_calls(), 1);
    Ok(())
}

#[test]
fn expiry_cancellation_rejection_and_manual_resolution_are_explicit() -> TestResult {
    let connector = Arc::new(TestConnector::new(
        "terminal",
        vec![operation("do", false, true, false)],
        DispatchObservation::Unknown {
            evidence_digest: digest(8_500)?,
            remote_operation_id: None,
        },
        ReconcileObservation::ConfirmedFailure(digest(8_501)?),
    ));
    let (_store, _access, engine) = fixture(connector)?;

    let expiring = engine.prepare(
        intent(
            150,
            "terminal",
            "do",
            "terminal-150",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    assert_code(
        engine.expire(
            &expiring.intent.effect_id,
            0,
            record(151)?,
            record(901)?,
            time(49)?,
        ),
        EffectErrorCode::Expired,
    );
    let expired = engine.expire(
        &expiring.intent.effect_id,
        0,
        record(152)?,
        record(901)?,
        time(50)?,
    )?;
    assert_eq!(expired.state, EffectState::Expired);

    let cancellable = engine.prepare(
        intent(
            160,
            "terminal",
            "do",
            "terminal-160",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    let cancelled = engine.cancel(
        &cancellable.intent.effect_id,
        0,
        record(161)?,
        &proposal_authorization(3)?,
    )?;
    assert_eq!(cancelled.state, EffectState::Cancelled);
    assert_code(
        engine.request_approval(
            &cancelled.intent.effect_id,
            cancelled.effect_version,
            record(162)?,
            &proposal_authorization(4)?,
        ),
        EffectErrorCode::InvalidTransition,
    );

    let pending_source = engine.prepare(
        intent(
            170,
            "terminal",
            "do",
            "terminal-170",
            RiskLevel::Medium,
            RetryPolicy::Never,
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    let pending = engine.request_approval(
        &pending_source.intent.effect_id,
        0,
        record(171)?,
        &proposal_authorization(2)?,
    )?;
    let rejected = engine.reject(
        &pending.intent.effect_id,
        pending.effect_version,
        record(172)?,
        &dispatch_authorization(3)?,
        digest(8_502)?,
    )?;
    assert_eq!(rejected.state, EffectState::Rejected);

    let unknown = drive_to_unknown(
        &engine,
        intent(
            180,
            "terminal",
            "do",
            "terminal-180",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        181,
    )?;
    let resolved = engine.manual_resolution(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(187)?,
        &dispatch_authorization(6)?,
        digest(8_503)?,
    )?;
    assert_eq!(resolved.state, EffectState::ManualResolution);
    assert_code(
        engine.cancel(
            &resolved.intent.effect_id,
            resolved.effect_version,
            record(188)?,
            &proposal_authorization(7)?,
        ),
        EffectErrorCode::InvalidTransition,
    );
    Ok(())
}

#[test]
fn divergent_low_level_journal_is_detected_and_quarantined() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "corruption",
        vec![operation("do", false, false, false)],
    )?);
    let (store, access, engine) = fixture(connector)?;
    let authorized = prepare_and_authorize_low(
        &engine,
        intent(
            200,
            "corruption",
            "do",
            "corruption-200",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        201,
    )?;
    let previous = authorized
        .journal
        .last()
        .ok_or_else(|| std::io::Error::other("authorized journal is empty"))?;
    let forged = EffectJournalEvent {
        schema_version: SchemaVersion::new("cigar.effect-journal-event", 1)?,
        event_id: record(202)?,
        effect_id: authorized.intent.effect_id.clone(),
        sequence: 2,
        expected_effect_version: 1,
        from_state: EffectState::Authorized,
        to_state: EffectState::Dispatching,
        actor_id: record(901)?,
        payload_digest: digest(8_600)?,
        previous_event_digest: Some(previous.event_digest.clone()),
        event_digest: digest(8_601)?,
        recorded_at: time(4)?,
    };
    let mut transaction =
        store.begin_write(access, store.revision()?, CancellationToken::default())?;
    transaction.append_effect_event(forged)?;
    transaction.commit(None)?;
    assert_code(
        engine.get(&authorized.intent.effect_id),
        EffectErrorCode::CorruptJournal,
    );
    Ok(())
}

#[test]
fn storage_writer_cannot_fabricate_an_internally_consistent_effect_record() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "forged-storage-record",
        vec![operation("do", false, false, false)],
    )?);
    let (store, access, engine) = fixture(connector)?;
    let forged_intent = intent(
        8_610,
        "forged-storage-record",
        "do",
        "forged-storage-key",
        RiskLevel::Low,
        RetryPolicy::Never,
        None,
    )?;
    let forged = DurableEffectRecord {
        intent_digest: effect_intent_digest(&forged_intent)?,
        intent: forged_intent,
        state: EffectState::Prepared,
        effect_version: 0,
        approval: None,
        approval_digest: None,
        attempts: Vec::new(),
        receipts: Vec::new(),
        reconciliations: Vec::new(),
        compensation_link: None,
        journal: Vec::new(),
        outbox: None,
    };
    let bytes = serde_json::to_vec(&forged)?;
    let envelope = EffectRecordEnvelope::new(
        forged.intent.effect_id.clone(),
        0,
        bytes_digest(&bytes)?,
        bytes,
    )?;
    let mut transaction =
        store.begin_write(access, store.revision()?, CancellationToken::default())?;
    transaction.put_effect_record(envelope)?;
    transaction.commit(None)?;
    assert_code(
        engine.get(&forged.intent.effect_id),
        EffectErrorCode::CorruptJournal,
    );
    Ok(())
}

#[test]
fn durable_effect_records_require_the_exact_tenant_key_epoch() -> TestResult {
    let store = Arc::new(InMemoryStore::default());
    let access = AccessContext::new(record(8_620)?, "keyed-effect-record")?;
    let signer = Arc::new(ProcessEffectAuthenticator::from_key(
        "tenant-key-2026-07",
        [0x41; 32],
    )?);
    let engine =
        EffectEngine::new_with_authenticator(store.clone(), access.clone(), signer.clone());
    let connector = Arc::new(TestConnector::success(
        "keyed-record",
        vec![operation("do", false, false, false)],
    )?);
    engine.register_connector(connector)?;
    let prepared = engine.prepare(
        intent(
            8_621,
            "keyed-record",
            "do",
            "keyed-record-request",
            RiskLevel::Low,
            RetryPolicy::Never,
            None,
        )?,
        &proposal_authorization(2)?,
    )?;
    let prepared_revision = store.revision()?;
    let authorized = engine.authorize(
        &prepared.intent.effect_id,
        prepared.effect_version,
        record(8_622)?,
        None,
        &dispatch_authorization(3)?,
    )?;

    let matching = EffectEngine::new_with_authenticator(store.clone(), access.clone(), signer);
    assert_eq!(matching.get(&authorized.intent.effect_id)?, authorized);
    assert_eq!(
        matching
            .get_at_revision(&authorized.intent.effect_id, prepared_revision)?
            .state,
        EffectState::Prepared
    );

    let wrong_epoch = Arc::new(ProcessEffectAuthenticator::from_key(
        "tenant-key-revoked",
        [0x42; 32],
    )?);
    let rejected = EffectEngine::new_with_authenticator(store, access, wrong_epoch);
    assert_code(
        rejected.get(&authorized.intent.effect_id),
        EffectErrorCode::CorruptJournal,
    );
    Ok(())
}

#[test]
fn signed_effect_record_seal_retains_bounded_historical_proof() -> TestResult {
    let seal =
        EffectRecordSeal::new_signed("tenant-key-2026-08", digest(8_630)?, 8_631, [0x5a; 64])?;
    let encoded = serde_json::to_vec(&seal)?;
    let decoded = serde_json::from_slice::<EffectRecordSeal>(&encoded)?;
    decoded.validate()?;
    assert_eq!(decoded, seal);
    let Some(proof) = decoded.signed_proof() else {
        return Err("missing historical effect-record signature proof".into());
    };
    assert_eq!(proof.signed_at_unix_nanos(), 8_631);
    assert_eq!(proof.signature(), &[0x5a; 64]);
    assert!(!format!("{decoded:?}").contains("90, 90"));
    assert!(
        EffectRecordSeal::new("tenant-key-2026-08", digest(8_632)?)?
            .signed_proof()
            .is_none()
    );
    Ok(())
}

#[test]
fn effect_record_checkpoint_rejects_identity_swap_and_hmac_proof_malleability() -> TestResult {
    let authenticator = ProcessEffectAuthenticator::from_key("tenant-key", [0x63; 32])?;
    let tenant_id = record(8_640)?;
    let effect_id = record(8_641)?;
    let first_intent = digest(8_642)?;
    let checkpoint = digest(8_643)?;
    authenticator.observe_latest(&tenant_id, &effect_id, &first_intent, 2, &checkpoint)?;
    assert_code(
        authenticator.observe_latest(&tenant_id, &effect_id, &digest(8_644)?, 2, &checkpoint),
        EffectErrorCode::CorruptJournal,
    );

    let canonical_record = b"canonical effect record";
    let hmac_seal = authenticator.seal(&tenant_id, canonical_record)?;
    let forged_proof = EffectRecordSeal::new_signed(
        hmac_seal.key_id(),
        hmac_seal.authenticator().clone(),
        8_645,
        [0x6b; 64],
    )?;
    assert_code(
        authenticator.verify(&tenant_id, canonical_record, &forged_proof),
        EffectErrorCode::CorruptJournal,
    );
    Ok(())
}

#[test]
fn compensation_is_a_separate_effect_bound_to_the_declared_spec() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "compensation",
        vec![
            operation("do", true, true, true),
            operation("undo", true, true, true),
        ],
    )?);
    let (_store, _access, engine) = fixture(connector)?;
    let specification = compensation_spec()?;
    let original = prepare_and_authorize_low(
        &engine,
        intent(
            220,
            "compensation",
            "do",
            "compensation-220",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            Some(specification.clone()),
        )?,
        221,
    )?;
    let permit = engine.claim_dispatch(
        &original.intent.effect_id,
        original.effect_version,
        record(222)?,
        record(223)?,
        record(224)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let succeeded = engine.dispatch(
        permit,
        record(225)?,
        record(226)?,
        &dispatch_authorization(5)?,
    )?;

    let missing_child = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: succeeded.intent.effect_id.clone(),
        compensation_effect_id: record(227)?,
        compensation_spec_digest: compensation_spec_digest(&specification)?,
        created_at: time(6)?,
    };
    assert_code(
        engine.request_compensation(
            &succeeded.intent.effect_id,
            succeeded.effect_version,
            record(228)?,
            &dispatch_authorization(6)?,
            missing_child,
        ),
        EffectErrorCode::NotFound,
    );

    let mut child_intent = intent(
        229,
        "compensation",
        "undo",
        "compensation-229",
        RiskLevel::Low,
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        None,
    )?;
    child_intent.arguments_digest = specification.arguments_digest.clone();
    child_intent.encrypted_arguments = specification.encrypted_arguments.clone();
    let child = engine.prepare(child_intent, &proposal_authorization(6)?)?;
    assert_ne!(child.intent.effect_id, succeeded.intent.effect_id);

    let wrong_spec = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: succeeded.intent.effect_id.clone(),
        compensation_effect_id: child.intent.effect_id.clone(),
        compensation_spec_digest: digest(8_700)?,
        created_at: time(6)?,
    };
    assert_code(
        engine.request_compensation(
            &succeeded.intent.effect_id,
            succeeded.effect_version,
            record(230)?,
            &dispatch_authorization(6)?,
            wrong_spec,
        ),
        EffectErrorCode::Unauthorized,
    );

    let exact_link = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: succeeded.intent.effect_id.clone(),
        compensation_effect_id: child.intent.effect_id.clone(),
        compensation_spec_digest: compensation_spec_digest(&specification)?,
        created_at: time(6)?,
    };
    let pending = engine.request_compensation(
        &succeeded.intent.effect_id,
        succeeded.effect_version,
        record(231)?,
        &dispatch_authorization(6)?,
        exact_link.clone(),
    )?;
    assert_eq!(pending.state, EffectState::CompensationPending);
    assert_eq!(pending.compensation_link, Some(exact_link));
    assert_code(
        engine.begin_compensation(
            &pending.intent.effect_id,
            pending.effect_version,
            record(232)?,
            &dispatch_authorization(7)?,
        ),
        EffectErrorCode::Unauthorized,
    );

    let child_authorized = engine.authorize(
        &child.intent.effect_id,
        child.effect_version,
        record(233)?,
        None,
        &dispatch_authorization(7)?,
    )?;
    let compensating = engine.begin_compensation(
        &pending.intent.effect_id,
        pending.effect_version,
        record(234)?,
        &dispatch_authorization(7)?,
    )?;
    assert_eq!(compensating.state, EffectState::Compensating);
    let child_permit = engine.claim_dispatch(
        &child_authorized.intent.effect_id,
        child_authorized.effect_version,
        record(235)?,
        record(236)?,
        record(237)?,
        time(40)?,
        &dispatch_authorization(8)?,
    )?;
    let child_succeeded = engine.dispatch(
        child_permit,
        record(238)?,
        record(239)?,
        &dispatch_authorization(9)?,
    )?;
    assert_eq!(child_succeeded.state, EffectState::Succeeded);
    let compensated = engine.resolve_compensation(
        &compensating.intent.effect_id,
        compensating.effect_version,
        record(240)?,
        &dispatch_authorization(10)?,
    )?;
    assert_eq!(compensated.state, EffectState::Compensated);
    Ok(())
}

#[test]
fn service_compensation_entry_point_requires_an_already_authorized_child() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "authorized-compensation",
        vec![
            operation("do", true, true, true),
            operation("undo", true, true, true),
        ],
    )?);
    let (_store, _access, engine) = fixture(connector)?;
    let specification = compensation_spec()?;
    let original = prepare_and_authorize_low(
        &engine,
        intent(
            900,
            "authorized-compensation",
            "do",
            "authorized-compensation-900",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            Some(specification.clone()),
        )?,
        901,
    )?;
    let permit = engine.claim_dispatch(
        &original.intent.effect_id,
        original.effect_version,
        record(902)?,
        record(903)?,
        record(904)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let succeeded = engine.dispatch(
        permit,
        record(905)?,
        record(906)?,
        &dispatch_authorization(5)?,
    )?;

    let mut child_intent = intent(
        907,
        "authorized-compensation",
        "undo",
        "authorized-compensation-907",
        RiskLevel::Low,
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        None,
    )?;
    child_intent.arguments_digest = specification.arguments_digest.clone();
    child_intent.encrypted_arguments = specification.encrypted_arguments.clone();
    let child = engine.prepare(child_intent, &proposal_authorization(6)?)?;
    let link = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: succeeded.intent.effect_id.clone(),
        compensation_effect_id: child.intent.effect_id.clone(),
        compensation_spec_digest: compensation_spec_digest(&specification)?,
        created_at: time(6)?,
    };
    assert_code(
        engine.request_authorized_compensation(
            &succeeded.intent.effect_id,
            succeeded.effect_version,
            record(908)?,
            &dispatch_authorization(6)?,
            link.clone(),
        ),
        EffectErrorCode::Unauthorized,
    );

    let authorized_child = engine.authorize(
        &child.intent.effect_id,
        child.effect_version,
        record(909)?,
        None,
        &dispatch_authorization(7)?,
    )?;
    assert_eq!(authorized_child.state, EffectState::Authorized);
    let pending = engine.request_authorized_compensation(
        &succeeded.intent.effect_id,
        succeeded.effect_version,
        record(910)?,
        &dispatch_authorization(7)?,
        link.clone(),
    )?;
    assert_eq!(pending.state, EffectState::CompensationPending);
    assert_eq!(pending.compensation_link, Some(link));
    assert_eq!(authorized_child.state, EffectState::Authorized);
    Ok(())
}

#[test]
fn compensation_child_is_durably_reserved_to_exactly_one_original() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "unique-compensation",
        vec![
            operation("do", true, true, true),
            operation("undo", true, true, true),
        ],
    )?);
    let (_store, _access, engine) = fixture(connector)?;
    let specification = compensation_spec()?;

    let mut succeeded_originals = Vec::new();
    for (effect, id_base, key) in [
        (8_920, 8_921, "first-original"),
        (8_930, 8_931, "second-original"),
    ] {
        let original = prepare_and_authorize_low(
            &engine,
            intent(
                effect,
                "unique-compensation",
                "do",
                key,
                RiskLevel::Low,
                RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
                Some(specification.clone()),
            )?,
            id_base,
        )?;
        let permit = engine.claim_dispatch(
            &original.intent.effect_id,
            original.effect_version,
            record(id_base + 1)?,
            record(id_base + 2)?,
            record(id_base + 3)?,
            time(40)?,
            &dispatch_authorization(4)?,
        )?;
        succeeded_originals.push(engine.dispatch(
            permit,
            record(id_base + 4)?,
            record(id_base + 5)?,
            &dispatch_authorization(5)?,
        )?);
    }

    let mut child_intent = intent(
        8_940,
        "unique-compensation",
        "undo",
        "one-compensation-child",
        RiskLevel::Low,
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        None,
    )?;
    child_intent.arguments_digest = specification.arguments_digest.clone();
    child_intent.encrypted_arguments = specification.encrypted_arguments.clone();
    let child = engine.prepare(child_intent, &proposal_authorization(6)?)?;
    let child = engine.authorize(
        &child.intent.effect_id,
        child.effect_version,
        record(8_941)?,
        None,
        &dispatch_authorization(7)?,
    )?;

    let [first, second] = succeeded_originals.as_slice() else {
        return Err(std::io::Error::other("missing succeeded compensation originals").into());
    };
    let first_link = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: first.intent.effect_id.clone(),
        compensation_effect_id: child.intent.effect_id.clone(),
        compensation_spec_digest: compensation_spec_digest(&specification)?,
        created_at: time(7)?,
    };
    engine.request_authorized_compensation(
        &first.intent.effect_id,
        first.effect_version,
        record(8_942)?,
        &dispatch_authorization(7)?,
        first_link,
    )?;

    let second_link = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: second.intent.effect_id.clone(),
        compensation_effect_id: child.intent.effect_id.clone(),
        compensation_spec_digest: compensation_spec_digest(&specification)?,
        created_at: time(7)?,
    };
    assert_code(
        engine.request_authorized_compensation(
            &second.intent.effect_id,
            second.effect_version,
            record(8_943)?,
            &dispatch_authorization(7)?,
            second_link,
        ),
        EffectErrorCode::IdempotencyCollision,
    );
    Ok(())
}

#[test]
fn ambiguous_compensation_child_projects_explicit_unknown() -> TestResult {
    let connector = Arc::new(TestConnector::success(
        "compensation-unknown",
        vec![
            operation("do", true, true, true),
            operation("undo", true, true, true),
        ],
    )?);
    let (_store, _access, engine) = fixture(connector.clone())?;
    let specification = compensation_spec()?;
    let original = prepare_and_authorize_low(
        &engine,
        intent(
            250,
            "compensation-unknown",
            "do",
            "compensation-250",
            RiskLevel::Low,
            RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
            Some(specification.clone()),
        )?,
        251,
    )?;
    let permit = engine.claim_dispatch(
        &original.intent.effect_id,
        original.effect_version,
        record(252)?,
        record(253)?,
        record(254)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    let succeeded = engine.dispatch(
        permit,
        record(255)?,
        record(256)?,
        &dispatch_authorization(5)?,
    )?;

    let mut child_intent = intent(
        257,
        "compensation-unknown",
        "undo",
        "compensation-257",
        RiskLevel::Low,
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        None,
    )?;
    child_intent.arguments_digest = specification.arguments_digest.clone();
    child_intent.encrypted_arguments = specification.encrypted_arguments.clone();
    let child = engine.prepare(child_intent, &proposal_authorization(6)?)?;
    let link = CompensationLink {
        schema_version: SchemaVersion::new("cigar.compensation-link", 1)?,
        original_effect_id: succeeded.intent.effect_id.clone(),
        compensation_effect_id: child.intent.effect_id.clone(),
        compensation_spec_digest: compensation_spec_digest(&specification)?,
        created_at: time(6)?,
    };
    let pending = engine.request_compensation(
        &succeeded.intent.effect_id,
        succeeded.effect_version,
        record(258)?,
        &dispatch_authorization(6)?,
        link,
    )?;
    let child_authorized = engine.authorize(
        &child.intent.effect_id,
        child.effect_version,
        record(259)?,
        None,
        &dispatch_authorization(7)?,
    )?;
    let compensating = engine.begin_compensation(
        &pending.intent.effect_id,
        pending.effect_version,
        record(260)?,
        &dispatch_authorization(7)?,
    )?;
    let _unconsumed_permit = engine.claim_dispatch(
        &child_authorized.intent.effect_id,
        child_authorized.effect_version,
        record(261)?,
        record(262)?,
        record(263)?,
        time(40)?,
        &dispatch_authorization(8)?,
    )?;
    let claimed_child = engine.get(&child_authorized.intent.effect_id)?;
    let unknown_child = engine.recover_inflight(
        &claimed_child.intent.effect_id,
        claimed_child.effect_version,
        record(264)?,
        record(901)?,
        time(9)?,
        digest(8_800)?,
    )?;
    assert_eq!(unknown_child.state, EffectState::Unknown);
    let unresolved = engine.resolve_compensation(
        &compensating.intent.effect_id,
        compensating.effect_version,
        record(265)?,
        &dispatch_authorization(10)?,
    )?;
    assert_eq!(unresolved.state, EffectState::Unknown);
    assert_eq!(connector.dispatch_calls(), 1);
    Ok(())
}

#[test]
fn protocol_transition_matrix_is_closed() {
    let states = [
        EffectState::Prepared,
        EffectState::PendingApproval,
        EffectState::Authorized,
        EffectState::Dispatching,
        EffectState::Succeeded,
        EffectState::Failed,
        EffectState::Unknown,
        EffectState::AuthorizedForRetry,
        EffectState::ManualResolution,
        EffectState::Rejected,
        EffectState::Expired,
        EffectState::Cancelled,
        EffectState::CompensationPending,
        EffectState::Compensating,
        EffectState::Compensated,
        EffectState::CompensationFailed,
    ];
    for source in states {
        for target in states {
            let expected = matches!(
                (source, target),
                (
                    EffectState::Prepared,
                    EffectState::PendingApproval
                        | EffectState::Authorized
                        | EffectState::Expired
                        | EffectState::Cancelled
                ) | (
                    EffectState::PendingApproval,
                    EffectState::Authorized
                        | EffectState::Rejected
                        | EffectState::Expired
                        | EffectState::Cancelled
                ) | (
                    EffectState::Authorized,
                    EffectState::Dispatching | EffectState::Expired | EffectState::Cancelled
                ) | (
                    EffectState::Dispatching,
                    EffectState::Succeeded | EffectState::Failed | EffectState::Unknown
                ) | (
                    EffectState::Unknown,
                    EffectState::Unknown
                        | EffectState::Succeeded
                        | EffectState::Failed
                        | EffectState::AuthorizedForRetry
                        | EffectState::ManualResolution
                ) | (
                    EffectState::AuthorizedForRetry,
                    EffectState::Dispatching | EffectState::Expired | EffectState::Cancelled
                ) | (EffectState::Succeeded, EffectState::CompensationPending)
                    | (EffectState::CompensationPending, EffectState::Compensating)
                    | (
                        EffectState::Compensating,
                        EffectState::Compensated
                            | EffectState::CompensationFailed
                            | EffectState::Unknown
                    )
            );
            assert_eq!(
                source.can_transition_to(target),
                expected,
                "unexpected transition decision: {source:?} -> {target:?}"
            );
        }
    }
}
