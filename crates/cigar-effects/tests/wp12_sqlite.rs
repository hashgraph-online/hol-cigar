//! WP12 durable SQLite receipt-loss and restart reconciliation coverage.

use cigar_effects::reference::{DemoIssueConnector, DemoIssueRequest, DemoIssueService};
use cigar_effects::{
    ConnectorDescriptor, DispatchContext, DispatchObservation, EffectAuthorization,
    EffectConnector, EffectEngine, EffectError, EffectErrorCode, PreconditionReport,
    ReconcileObservation,
};
use cigar_protocol::{
    BlobRef, Capability, ContentDigest, EffectIntent, ExtensionMap, IdempotencyKey, MediaType,
    RecordId, RetryPolicy, RiskLevel, SchemaVersion, UtcTimestamp, VersionId,
};
use cigar_store::{AccessContext, SqliteFailpoint, SqliteStore};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn remote_commit_before_sqlite_receipt_failure_recovers_without_duplicate() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("effects.sqlite3");
    let service = Arc::new(DemoIssueService::default());
    let connector = DemoIssueConnector::new("demo-sqlite", service.clone())?;
    let arguments_digest = connector.stage_request(DemoIssueRequest::new(
        "wp12",
        "durable receipt loss",
        "the remote issue must exist exactly once",
    )?)?;
    let access = AccessContext::new(record(1)?, "wp12-sqlite-effects")?;

    let store = Arc::new(SqliteStore::open(&database)?);
    let connector = Arc::new(ReceiptCommitFailingConnector {
        inner: connector,
        store: store.clone(),
        armed: AtomicBool::new(true),
    });
    let engine = EffectEngine::new(store.clone(), access.clone());
    engine.register_connector(connector.clone())?;
    let prepared = engine.prepare(intent(arguments_digest)?, &proposal_authorization(2)?)?;
    let authorized = engine.authorize(
        &prepared.intent.effect_id,
        prepared.effect_version,
        record(3)?,
        None,
        &effect_authorization(3)?,
    )?;
    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(4)?,
        record(5)?,
        record(6)?,
        time(8)?,
        &effect_authorization(4)?,
    )?;

    let failure = match engine.dispatch(permit, record(7)?, record(8)?, &effect_authorization(5)?) {
        Ok(_record) => return Err("receipt transaction unexpectedly committed".into()),
        Err(error) => error,
    };
    assert_eq!(failure.code(), EffectErrorCode::Unavailable);
    assert_eq!(service.issues()?.len(), 1);
    drop(engine);
    drop(store);

    let reopened_store = Arc::new(SqliteStore::open(&database)?);
    reopened_store.integrity_check()?;
    let reopened = EffectEngine::new(reopened_store, access);
    reopened.register_connector(connector)?;
    let durable_claim = reopened.get(&authorized.intent.effect_id)?;
    assert_eq!(durable_claim.state, cigar_protocol::EffectState::Unknown);
    assert!(durable_claim.receipts.is_empty());
    let reconciled = reopened.reconcile(
        &durable_claim.intent.effect_id,
        durable_claim.effect_version,
        record(12)?,
        record(13)?,
        &effect_authorization(9)?,
    )?;
    assert_eq!(reconciled.state, cigar_protocol::EffectState::Succeeded);
    assert_eq!(reconciled.attempts.len(), 1);
    assert_eq!(reconciled.receipts.len(), 0);
    assert_eq!(reconciled.reconciliations.len(), 1);
    assert_eq!(service.issues()?.len(), 1);
    Ok(())
}

struct ReceiptCommitFailingConnector {
    inner: DemoIssueConnector,
    store: Arc<SqliteStore>,
    armed: AtomicBool,
}

impl EffectConnector for ReceiptCommitFailingConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.inner.descriptor()
    }

    fn check_preconditions(
        &self,
        intent: &EffectIntent,
        now: UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        self.inner.check_preconditions(intent, now)
    }

    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        let observation = self.inner.dispatch(context)?;
        if self.armed.swap(false, Ordering::AcqRel) {
            self.store
                .inject_failpoint(SqliteFailpoint::BeforeCommit)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        }
        Ok(observation)
    }

    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        self.inner.reconcile(context)
    }
}

fn intent(arguments_digest: ContentDigest) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
        effect_id: record(2)?,
        connector: "demo-sqlite".to_owned(),
        operation: "create_issue".to_owned(),
        arguments_digest,
        encrypted_arguments: BlobRef {
            digest: digest(20)?,
            size_bytes: 64,
            media_type: MediaType::new("application/octet-stream")?,
        },
        target: "wp12".to_owned(),
        preconditions: Vec::new(),
        result_schema_digest: digest(21)?,
        risk: RiskLevel::Low,
        source_decision_id: VersionId::new(digest(22)?.as_str())?,
        bundle_id: VersionId::new(digest(23)?.as_str())?,
        required_capability: Capability::InvokeTool,
        idempotency_scope: "wp12-sqlite".to_owned(),
        idempotency_key: IdempotencyKey::new("receipt-loss")?,
        retry_policy: RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        created_at: time(1)?,
        expires_at: time(50)?,
        compensation: None,
        extensions: ExtensionMap::default(),
    })
}

fn proposal_authorization(second: u8) -> Result<EffectAuthorization, Box<dyn Error>> {
    Ok(EffectAuthorization {
        actor_id: record(30)?,
        capabilities: BTreeSet::from([Capability::ProposeEffect]),
        policy_allows: true,
        now: time(second)?,
    })
}

fn effect_authorization(second: u8) -> Result<EffectAuthorization, Box<dyn Error>> {
    Ok(EffectAuthorization {
        actor_id: record(31)?,
        capabilities: BTreeSet::from([
            Capability::ApproveEffect,
            Capability::InvokeTool,
            Capability::ReconcileEffect,
        ]),
        policy_allows: true,
        now: time(second)?,
    })
}

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

fn time(second: u8) -> Result<UtcTimestamp, Box<dyn Error>> {
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}
