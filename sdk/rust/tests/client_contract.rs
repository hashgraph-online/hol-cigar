//! Frozen operation inventory and retry contract tests.

use cigar_sdk::api::{
    AuthorizeEffectOperation, AuthorizeEffectRequest, DispatchEffectOperation, EffectIdRequest,
    EmptyRequest, GetLivenessOperation, IngestCatalogRequest, LivenessResponse, RequestEnvelope,
    TYPED_OPERATION_MAPPINGS, TypedOperation, encode_operation_payload,
};
use cigar_sdk::protocol::{ContentDigest, ExpectedRevision, IdempotencyKey, RecordId};
use cigar_sdk::{
    CallOptions, Client, ClientTransport, ErrorKind, RUST_OPERATION_COUNT, RUST_OPERATION_IDS,
    SdkError, SdkFuture, TransportCall, TransportEventStream,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const PAYLOAD_SCHEMA: &[u8] =
    include_bytes!("../../../schemas/json/api-payload-types-v1.schema.json");
const SDK_CAPABILITIES: &[u8] = include_bytes!("../../capabilities-v1.json");

#[derive(Deserialize)]
struct PayloadSchema {
    operation_count: usize,
    operations: Vec<PayloadOperation>,
    types: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct PayloadOperation {
    operation_id: String,
    request_type: String,
    response_type: String,
    event_type: Option<String>,
}

#[derive(Deserialize)]
struct CapabilityRegistry {
    operation_count: usize,
    operations: Vec<PayloadOperation>,
    sdks: BTreeMap<String, SdkCapability>,
}

#[derive(Deserialize)]
struct SdkCapability {
    operation_count: usize,
    operations: Vec<String>,
    transport: Vec<String>,
}

#[derive(Default)]
struct RecordingTransport {
    calls: Mutex<Vec<RecordedCall>>,
    fail: bool,
}

#[derive(Clone)]
struct RecordedCall {
    operation_id: String,
    envelope: RequestEnvelope,
    deadline: Instant,
}

impl ClientTransport for RecordingTransport {
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<cigar_sdk::api::ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            self.calls
                .lock()
                .map_err(|_failure| SdkError::transport())?
                .push(RecordedCall {
                    operation_id: call.contract().operation_id.to_owned(),
                    envelope: call.envelope().clone(),
                    deadline: call.deadline(),
                });
            if self.fail {
                return Err(SdkError::transport());
            }
            if call.contract().operation_id != GetLivenessOperation::OPERATION_ID {
                return Err(SdkError::protocol());
            }
            let payload = encode_operation_payload(
                &LivenessResponse { live: true },
                cigar_sdk::api::MAX_OPERATION_PAYLOAD_BYTES,
            )
            .map_err(|_failure| SdkError::protocol())?;
            cigar_sdk::api::ResponseEnvelope::new(
                GetLivenessOperation::OPERATION_ID,
                payload,
                None,
                None,
            )
            .map_err(|_failure| SdkError::protocol())
        })
    }

    fn subscribe<'a>(
        &'a self,
        _call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>> {
        Box::pin(async { Err(SdkError::protocol()) })
    }
}

#[tokio::test]
async fn inventory_and_typed_unary_contract_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(RUST_OPERATION_COUNT, TYPED_OPERATION_MAPPINGS.len());
    assert_eq!(
        RUST_OPERATION_IDS.as_slice(),
        TYPED_OPERATION_MAPPINGS
            .iter()
            .map(|mapping| mapping.operation_id)
            .collect::<Vec<_>>()
    );
    let client = Client::from_transport(Arc::new(RecordingTransport::default()));
    let response = client
        .get_liveness(EmptyRequest {}, CallOptions::read())
        .await?;
    assert!(response.value.live);
    let empty = encode_operation_payload(
        &EmptyRequest {},
        cigar_sdk::api::MAX_OPERATION_PAYLOAD_BYTES,
    )?;
    assert_eq!(empty, [0xa0]);
    Ok(())
}

#[test]
fn generated_payload_schema_matches_every_rust_mapping() -> Result<(), Box<dyn std::error::Error>> {
    let schema: PayloadSchema = serde_json::from_slice(PAYLOAD_SCHEMA)?;
    assert_eq!(schema.operation_count, RUST_OPERATION_COUNT);
    assert_eq!(schema.operations.len(), RUST_OPERATION_COUNT);
    assert_eq!(schema.types.len(), 70);
    for (schema, typed) in schema.operations.iter().zip(TYPED_OPERATION_MAPPINGS) {
        assert_eq!(schema.operation_id, typed.operation_id);
        assert_eq!(schema.request_type, typed.request_schema);
        assert_eq!(schema.response_type, typed.response_schema);
        assert_eq!(schema.event_type.as_deref(), typed.event_schema);
    }
    Ok(())
}

#[test]
fn sdk_capability_authority_matches_every_rust_mapping() -> Result<(), Box<dyn std::error::Error>> {
    let capabilities: CapabilityRegistry = serde_json::from_slice(SDK_CAPABILITIES)?;
    assert_eq!(capabilities.operation_count, RUST_OPERATION_COUNT);
    assert_eq!(capabilities.operations.len(), RUST_OPERATION_COUNT);
    for (capability, typed) in capabilities.operations.iter().zip(TYPED_OPERATION_MAPPINGS) {
        assert_eq!(capability.operation_id, typed.operation_id);
        assert_eq!(capability.request_type, typed.request_schema);
        assert_eq!(capability.response_type, typed.response_schema);
        assert_eq!(capability.event_type.as_deref(), typed.event_schema);
    }
    let rust = capabilities
        .sdks
        .get("rust")
        .ok_or("Rust SDK capability row is missing")?;
    assert_eq!(rust.operation_count, RUST_OPERATION_COUNT);
    assert_eq!(rust.operations.as_slice(), RUST_OPERATION_IDS.as_slice());
    assert_eq!(
        rust.transport,
        vec!["embedded".to_owned(), "http".to_owned()]
    );
    Ok(())
}

#[tokio::test]
async fn repeat_safe_mutation_preserves_one_idempotency_key()
-> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(RecordingTransport {
        calls: Mutex::default(),
        fail: true,
    });
    let client = Client::from_transport(transport.clone());
    let result = client
        .ingest_catalog(
            IngestCatalogRequest {
                source_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
                plan_digest: ContentDigest::new(format!("1220{}", "a".repeat(64)))?,
            },
            CallOptions::mutation(IdempotencyKey::new("stable-ingest-key")?),
        )
        .await;
    let Err(error) = result else {
        return Err("transport unexpectedly succeeded".into());
    };
    assert_eq!(error.kind(), ErrorKind::Transport);
    let calls = transport.calls.lock().map_err(|_| "poisoned test mutex")?;
    assert_eq!(calls.len(), 3);
    assert!(
        calls
            .iter()
            .all(|call| call.envelope.idempotency_key() == Some("stable-ingest-key"))
    );
    Ok(())
}

#[tokio::test]
async fn safe_read_retry_preserves_exact_envelope_and_absolute_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(RecordingTransport {
        calls: Mutex::default(),
        fail: true,
    });
    let client = Client::from_transport(transport.clone());
    let result = client
        .get_liveness(EmptyRequest {}, CallOptions::read())
        .await;
    let Err(error) = result else {
        return Err("transport unexpectedly succeeded".into());
    };
    assert_eq!(error.kind(), ErrorKind::Transport);
    let calls = transport.calls.lock().map_err(|_| "poisoned test mutex")?;
    assert_eq!(calls.len(), 3);
    let Some(first) = calls.first() else {
        return Err("safe read was not attempted".into());
    };
    assert!(calls.iter().all(|call| call.envelope == first.envelope));
    assert!(calls.iter().all(|call| call.deadline == first.deadline));
    Ok(())
}

#[tokio::test]
async fn dispatch_is_never_automatically_retried() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(RecordingTransport {
        calls: Mutex::default(),
        fail: true,
    });
    let client = Client::from_transport(transport.clone());
    let key = IdempotencyKey::new("dispatch-key")?;
    let effect_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
    let result = client
        .dispatch_effect(
            EffectIdRequest { effect_id },
            CallOptions::revisioned(key, ExpectedRevision(1)),
        )
        .await;
    let Err(error) = result else {
        return Err("transport unexpectedly succeeded".into());
    };
    assert_eq!(error.kind(), ErrorKind::Transport);
    let calls = transport.calls.lock().map_err(|_| "poisoned test mutex")?;
    assert_eq!(calls.len(), 1);
    let Some(first) = calls.first() else {
        return Err("dispatch was not attempted".into());
    };
    assert_eq!(first.operation_id, DispatchEffectOperation::OPERATION_ID);
    assert_eq!(first.envelope.idempotency_key(), Some("dispatch-key"));
    Ok(())
}

#[tokio::test]
async fn initial_effect_revision_zero_reaches_authorization_transport()
-> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(RecordingTransport {
        calls: Mutex::default(),
        fail: true,
    });
    let client = Client::from_transport(transport.clone());
    let effect_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
    let result = client
        .authorize_effect(
            AuthorizeEffectRequest {
                effect_id,
                approval: None,
            },
            CallOptions::revisioned(
                IdempotencyKey::new("authorize-initial-effect")?,
                ExpectedRevision(0),
            ),
        )
        .await;
    let Err(error) = result else {
        return Err("transport unexpectedly succeeded".into());
    };
    assert_eq!(error.kind(), ErrorKind::Transport);
    let calls = transport.calls.lock().map_err(|_| "poisoned test mutex")?;
    assert_eq!(calls.len(), 3);
    let Some(first) = calls.first() else {
        return Err("authorization was not attempted".into());
    };
    assert_eq!(first.operation_id, AuthorizeEffectOperation::OPERATION_ID);
    assert_eq!(first.envelope.expected_revision(), Some("0"));
    assert!(
        calls
            .iter()
            .all(|call| call.envelope.expected_revision() == Some("0"))
    );
    Ok(())
}
