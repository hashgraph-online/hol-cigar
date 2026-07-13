//! Production-repository client phases driven by the WP18 physical failover harness.

use cigar_protocol::{ContentDigest, IdempotencyKey, RecordId};
use cigar_store::{
    AccessContext, CancellationToken, EffectRecordEnvelope, IdempotencyIdentity, OutboxMessage,
    PostgresConfiguration, PostgresStore, ReadTransaction, Repository, StoreErrorCode,
    StoreRevision, WriteTransaction,
};
use postgres::NoTls;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::sync::{Arc, Barrier};
use std::time::Duration;

const TENANT: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7801";
const EFFECT: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7802";
const PRE_OUTBOX: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7803";
const POST_OUTBOX: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7804";

fn digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(ContentDigest::new(format!("1220{suffix}"))?)
}

fn configuration(url: String) -> Result<PostgresConfiguration, Box<dyn Error>> {
    let mut configuration = PostgresConfiguration::new(url)?;
    configuration.minimum_connections = 1;
    configuration.maximum_connections = 16;
    configuration.acquire_timeout = Duration::from_secs(3);
    configuration.statement_timeout = Duration::from_secs(10);
    configuration.lock_timeout = Duration::from_secs(3);
    configuration.idle_transaction_timeout = Duration::from_secs(10);
    Ok(configuration)
}

fn context() -> Result<AccessContext, Box<dyn Error>> {
    Ok(AccessContext::new(
        RecordId::new(TENANT)?,
        "wp18-physical-failover",
    )?)
}

fn effect(version: u64) -> Result<EffectRecordEnvelope, Box<dyn Error>> {
    let bytes = format!("wp18-production-effect-version-{version}").into_bytes();
    Ok(EffectRecordEnvelope::new(
        RecordId::new(EFFECT)?,
        version,
        digest(&bytes)?,
        bytes,
    )?)
}

fn pre_outbox() -> Result<OutboxMessage, Box<dyn Error>> {
    Ok(OutboxMessage {
        message_id: RecordId::new(PRE_OUTBOX)?,
        topic: "effect.dispatch".to_owned(),
        payload_digest: digest(b"wp18-production-effect-version-0")?,
    })
}

fn post_outbox() -> Result<OutboxMessage, Box<dyn Error>> {
    Ok(OutboxMessage {
        message_id: RecordId::new(POST_OUTBOX)?,
        topic: "effect.reconcile".to_owned(),
        payload_digest: digest(b"wp18-production-effect-version-1")?,
    })
}

fn pre_idempotency() -> Result<IdempotencyIdentity, Box<dyn Error>> {
    Ok(IdempotencyIdentity::new(
        "effect.dispatch",
        IdempotencyKey::new("wp18-pre-failover-effect")?,
        digest(b"wp18-pre-failover-normalized-request")?,
    )?)
}

fn stage_pre_effect(store: &PostgresStore) -> Result<cigar_store::CommitReceipt, Box<dyn Error>> {
    let mut write =
        store.begin_write(context()?, StoreRevision(0), CancellationToken::default())?;
    write.put_effect_record(effect(0)?)?;
    write.enqueue_outbox(pre_outbox()?)?;
    Ok(write.commit(Some(pre_idempotency()?))?)
}

fn install_runtime_grants(owner_url: &str) -> Result<(), Box<dyn Error>> {
    let mut owner = postgres::Client::connect(owner_url, NoTls)?;
    owner.batch_execute(
        "REVOKE CREATE ON SCHEMA public FROM cigar_runtime;
         GRANT USAGE ON SCHEMA public TO cigar_runtime;
         GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cigar_runtime;",
    )?;
    Ok(())
}

fn run_before(owner_url: String, runtime_url: String) -> Result<(), Box<dyn Error>> {
    let owner_configuration = configuration(owner_url.clone())?;
    let migration = PostgresStore::migrate(&owner_configuration)?;
    if migration.latest_sequence == 0 || migration.checksums_verified == 0 {
        return Err("embedded PostgreSQL migrations were not installed".into());
    }
    install_runtime_grants(&owner_url)?;
    let store = PostgresStore::connect(configuration(runtime_url)?)?;
    if store.revision()? != StoreRevision(0) {
        return Err("pre-failover repository did not start at revision zero".into());
    }
    let receipt = stage_pre_effect(&store)?;
    if receipt.revision != StoreRevision(1) || receipt.replayed {
        return Err("pre-failover effect commit did not publish exactly once".into());
    }
    let read = store.begin_read(
        context()?,
        cigar_store::SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if read.get_effect_record(&RecordId::new(EFFECT)?)? != Some(effect(0)?) {
        return Err("pre-failover effect projection is not exact".into());
    }
    Ok(())
}

fn run_outage(runtime_url: String) -> Result<(), Box<dyn Error>> {
    let unavailable = PostgresStore::connect(configuration(runtime_url)?)
        .err()
        .map(|error| error.code());
    if unavailable != Some(StoreErrorCode::Unavailable) {
        return Err("primary-only router did not fail the production client closed".into());
    }
    Ok(())
}

fn run_after(runtime_url: String) -> Result<(), Box<dyn Error>> {
    let store = Arc::new(PostgresStore::connect(configuration(runtime_url)?)?);
    if store.revision()? != StoreRevision(1) {
        return Err("promoted primary lost the acknowledged repository revision".into());
    }
    let read = store.begin_read(
        context()?,
        cigar_store::SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if read.get_effect_record(&RecordId::new(EFFECT)?)? != Some(effect(0)?) {
        return Err("promoted primary lost the acknowledged effect projection".into());
    }
    drop(read);

    let replay = stage_pre_effect(store.as_ref())?;
    if replay.revision != StoreRevision(1) || !replay.replayed {
        return Err("post-promotion retry did not return the original idempotent result".into());
    }
    let mut write =
        store.begin_write(context()?, StoreRevision(1), CancellationToken::default())?;
    write.put_effect_record(effect(1)?)?;
    write.enqueue_outbox(post_outbox()?)?;
    let receipt = write.commit(None)?;
    if receipt.revision != StoreRevision(2) || receipt.replayed {
        return Err("post-promotion effect update did not publish exactly once".into());
    }

    let barrier = Arc::new(Barrier::new(8));
    let tenant = RecordId::new(TENANT)?;
    let claimed = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for index in 0..8_u8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let tenant = tenant.clone();
            handles.push(scope.spawn(move || {
                barrier.wait();
                let mut serialization_conflicts = 0_u8;
                loop {
                    match store.claim_wakeups(
                        &tenant,
                        "wp18-failover-worker",
                        &format!("owner-{index}"),
                        1_000,
                        30_000,
                        10,
                    ) {
                        Err(error)
                            if error.code() == StoreErrorCode::RevisionConflict
                                && serialization_conflicts < 31 =>
                        {
                            serialization_conflicts += 1;
                            std::thread::yield_now();
                        }
                        result => break result,
                    }
                }
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    let mut claims = Vec::new();
    for result in claimed {
        claims.extend(result.map_err(|_panic| "wakeup claimer panicked")??);
    }
    claims.sort_by_key(|claim| claim.wakeup.revision);
    let revisions: Vec<_> = claims.iter().map(|claim| claim.wakeup.revision).collect();
    if revisions != [StoreRevision(1), StoreRevision(2)] {
        return Err("SKIP LOCKED produced a lost or duplicate production wakeup claim".into());
    }
    for claim in &claims {
        store.acknowledge_wakeup("wp18-failover-worker", claim)?;
    }
    if !store
        .claim_wakeups(
            &RecordId::new(TENANT)?,
            "wp18-failover-worker",
            "final-owner",
            2_000,
            30_000,
            10,
        )?
        .is_empty()
    {
        return Err("acknowledged production wakeups were claimable twice".into());
    }
    let final_read = store.begin_read(
        context()?,
        cigar_store::SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if final_read.revision() != StoreRevision(2)
        || final_read.get_effect_record(&RecordId::new(EFFECT)?)? != Some(effect(1)?)
        || final_read.outbox()?.len() != 2
    {
        return Err("post-promotion canonical production state is incomplete".into());
    }
    Ok(())
}

#[test]
fn production_repository_survives_physical_failover_phase() -> Result<(), Box<dyn Error>> {
    let phase = match std::env::var("CIGAR_WP18_FAILOVER_PHASE") {
        Ok(value) => value,
        Err(_error) if std::env::var_os("CIGAR_REQUIRE_LIVE_FAILOVER_TESTS").is_none() => {
            return Ok(());
        }
        Err(_error) => return Err("required failover phase is missing".into()),
    };
    let runtime_url = std::env::var("CIGAR_WP18_FAILOVER_RUNTIME_URL")?;
    match phase.as_str() {
        "before" => run_before(std::env::var("CIGAR_WP18_FAILOVER_OWNER_URL")?, runtime_url),
        "outage" => run_outage(runtime_url),
        "after" => run_after(runtime_url),
        _ => Err("invalid failover phase".into()),
    }
}
