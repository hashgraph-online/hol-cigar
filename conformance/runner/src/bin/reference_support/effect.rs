use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_conformance::CaseOutcome;
use cigar_effects::{
    ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation,
    EffectAuthorization, EffectConnector, EffectEngine, EffectError, EffectErrorCode,
    PreconditionReport, ReconcileObservation,
};
use cigar_protocol::{
    BlobRef, Capability, ContentDigest, EffectIntent, EffectState, ExtensionMap, IdempotencyKey,
    MediaType, RecordId, RetryPolicy, RiskLevel, SchemaVersion, UtcTimestamp, VersionId,
};
use cigar_store::{AccessContext, InMemoryStore};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

type Engine = EffectEngine<InMemoryStore>;

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "effect_durable_dispatch" => durable_dispatch(input),
        "effect_idempotency_collision" => collision_rejection(input),
        _ => Err("unsupported effect conformance operation".into()),
    }
}

fn durable_dispatch(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "effect-durable-dispatch-v1")?;
    let (engine, connector) = engine_fixture()?;
    let prepared = engine.prepare(intent(10, "effect-key-10")?, &proposal_authorization(2)?)?;
    if prepared.state != EffectState::Prepared
        || prepared.effect_version != 0
        || !prepared.journal.is_empty()
        || connector.calls.load(Ordering::Acquire) != 0
    {
        return Err("production effect intent was not durably prepared before dispatch".into());
    }
    let authorized = engine.authorize(
        &prepared.intent.effect_id,
        prepared.effect_version,
        record(11)?,
        None,
        &dispatch_authorization(3)?,
    )?;
    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(12)?,
        record(13)?,
        record(14)?,
        time(40)?,
        &dispatch_authorization(4)?,
    )?;
    if connector.calls.load(Ordering::Acquire) != 0 {
        return Err("production effect connector ran before its durable fence".into());
    }
    let completed = engine.dispatch(
        permit,
        record(15)?,
        record(16)?,
        &dispatch_authorization(5)?,
    )?;
    if completed.state != EffectState::Succeeded
        || completed.effect_version != 4
        || completed.attempts.len() != 1
        || completed.receipts.len() != 1
        || completed.journal.len() != 4
        || connector.calls.load(Ordering::Acquire) != 1
    {
        return Err("production effect durable dispatch projection diverged".into());
    }
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.effect-kernel.v1",
            &[
                completed.intent.effect_id.as_str(),
                completed.intent_digest.as_str(),
                "state=succeeded",
                "effect_version=4",
                "attempts=1",
                "receipts=1",
                "journal=4",
                "connector_calls=1",
            ],
        ),
    ))
}

fn collision_rejection(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "effect-same-key-different-intent-v1")?;
    let (engine, connector) = engine_fixture()?;
    let first = intent(20, "effect-key-20")?;
    let prepared = engine.prepare(first.clone(), &proposal_authorization(2)?)?;
    let replayed = engine.prepare(first.clone(), &proposal_authorization(2)?)?;
    if prepared != replayed {
        return Err("production effect did not replay an identical durable intent".into());
    }
    let mut changed = first;
    changed.target = "different-normalized-target".to_owned();
    let error = engine
        .prepare(changed, &proposal_authorization(2)?)
        .err()
        .ok_or("production effect kernel accepted same identity with different semantics")?;
    if error.code() != EffectErrorCode::IdempotencyCollision
        || connector.calls.load(Ordering::Acquire) != 0
    {
        return Err("production effect collision did not fail before connector dispatch".into());
    }
    Ok((
        CaseOutcome::Rejected,
        rejected_digest("effect_idempotency_collision"),
    ))
}

struct ConformanceConnector {
    calls: AtomicUsize,
}

impl EffectConnector for ConformanceConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: "conformance".to_owned(),
            operations: vec![ConnectorOperation {
                operation: "mutate".to_owned(),
                same_key_idempotent: true,
                supports_reconciliation: true,
                supports_compensation: false,
            }],
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
        Ok(DispatchObservation::Succeeded {
            remote_operation_id: "conformance-remote-operation".to_owned(),
            response_digest: digest(700)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
            verification_digest: digest(701)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
        })
    }

    fn reconcile(
        &self,
        _context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        Ok(ReconcileObservation::ConfirmedSuccess(
            digest(702).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
        ))
    }
}

fn engine_fixture() -> Result<(Engine, Arc<ConformanceConnector>), Box<dyn std::error::Error>> {
    let store = Arc::new(InMemoryStore::default());
    let access = AccessContext::new(record(900)?, "conformance-effects")?;
    let engine = EffectEngine::new(store, access);
    let connector = Arc::new(ConformanceConnector {
        calls: AtomicUsize::new(0),
    });
    engine.register_connector(connector.clone())?;
    Ok((engine, connector))
}

fn intent(effect: u64, key: &str) -> Result<EffectIntent, Box<dyn std::error::Error>> {
    Ok(EffectIntent {
        schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
        effect_id: record(effect)?,
        connector: "conformance".to_owned(),
        operation: "mutate".to_owned(),
        arguments_digest: digest(effect.saturating_add(1_000))?,
        encrypted_arguments: BlobRef {
            digest: digest(effect.saturating_add(2_000))?,
            size_bytes: 64,
            media_type: MediaType::new("application/octet-stream")?,
        },
        target: format!("target-{effect}"),
        preconditions: Vec::new(),
        result_schema_digest: digest(effect.saturating_add(3_000))?,
        risk: RiskLevel::Low,
        source_decision_id: version(effect.saturating_add(4_000))?,
        bundle_id: version(effect.saturating_add(5_000))?,
        required_capability: Capability::InvokeTool,
        idempotency_scope: "tenant-a".to_owned(),
        idempotency_key: IdempotencyKey::new(key)?,
        retry_policy: RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        created_at: time(1)?,
        expires_at: time(50)?,
        compensation: None,
        extensions: ExtensionMap::default(),
    })
}

fn authorization(
    actor: u64,
    now: u8,
    capabilities: impl IntoIterator<Item = Capability>,
) -> Result<EffectAuthorization, Box<dyn std::error::Error>> {
    Ok(EffectAuthorization {
        actor_id: record(actor)?,
        capabilities: capabilities.into_iter().collect(),
        policy_allows: true,
        now: time(now)?,
    })
}

fn proposal_authorization(now: u8) -> Result<EffectAuthorization, Box<dyn std::error::Error>> {
    authorization(901, now, [Capability::ProposeEffect])
}

fn dispatch_authorization(now: u8) -> Result<EffectAuthorization, Box<dyn std::error::Error>> {
    authorization(
        902,
        now,
        [
            Capability::ProposeEffect,
            Capability::ApproveEffect,
            Capability::InvokeTool,
        ],
    )
}

fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn digest(value: u64) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    use std::fmt::Write as _;
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
    Ok(VersionId::new(digest(value)?.as_str())?)
}

fn time(second: u8) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}
