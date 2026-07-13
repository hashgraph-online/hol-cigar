//! Handoff, effect reconciliation, and replay routing qualification.

use cigar_sdk::api::{EffectIdRequest, HandoffIdRequest, ReplayIdRequest};
use cigar_sdk::protocol::{ExpectedRevision, IdempotencyKey, RecordId};
use cigar_sdk::{
    CallOptions, Client, ClientTransport, RetryPolicy, SdkError, SdkFuture, TransportCall,
    TransportEventStream,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Routes {
    operations: Mutex<Vec<String>>,
}

impl ClientTransport for Routes {
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<cigar_sdk::api::ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            self.operations
                .lock()
                .map_err(|_failure| SdkError::transport())?
                .push(call.contract().operation_id.to_owned());
            Err(SdkError::transport())
        })
    }

    fn subscribe<'a>(
        &'a self,
        _call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>> {
        Box::pin(async { Err(SdkError::transport()) })
    }
}

fn one_attempt() -> Result<RetryPolicy, SdkError> {
    RetryPolicy::new(1, Duration::from_millis(1), Duration::from_millis(1))
}

#[tokio::test]
async fn high_level_domain_methods_use_frozen_routes() -> Result<(), Box<dyn std::error::Error>> {
    let routes = Arc::new(Routes::default());
    let client = Client::from_transport(routes.clone());
    let handoff_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
    let effect_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?;
    let replay_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?;
    let read = CallOptions::read().with_retry_policy(one_attempt()?);
    let _handoff = client
        .preview_handoff(HandoffIdRequest { handoff_id }, read.clone())
        .await;
    let _effect = client
        .reconcile_effect(
            EffectIdRequest { effect_id },
            CallOptions::revisioned(IdempotencyKey::new("reconcile-key")?, ExpectedRevision(7))
                .with_retry_policy(one_attempt()?),
        )
        .await;
    let _replay = client
        .get_replay_completeness(ReplayIdRequest { replay_id }, read)
        .await;
    let operations = routes
        .operations
        .lock()
        .map_err(|_| "poisoned operation mutex")?;
    assert_eq!(
        operations.as_slice(),
        ["previewHandoff", "reconcileEffect", "getReplayCompleteness"]
    );
    Ok(())
}
