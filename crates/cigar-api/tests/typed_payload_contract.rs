//! Exact typed-payload mapping, canonical codec, path, and adapter conformance.

use cigar_api::{
    ApiError, AtomIdRequest, BundleIdRequest, CancellationToken, CheckpointSpaceRequest,
    CompareLiveReplayRequest, CompensateEffectRequest, ConflictResolution,
    DiscoverSourcesOperation, EffectIdRequest, EmptyRequest, FacadeErrorFactory,
    GetLivenessOperation, GetSourceStatusOperation, HandoffIdRequest, IngestCatalogRequest,
    LivenessResponse, MergeHandoffRequest, OperationId, PathParameter, PrincipalId,
    ReplayIdRequest, RequestContext, RequestEnvelope, ResolveSpaceConflictRequest, SourceIdRequest,
    SpaceFork, SpaceIdRequest, StreamOperationHandler, SubscribeSpaceEventsOperation,
    TYPED_OPERATION_MAPPINGS, TenantId, TraceId, TypedEvent, TypedEventStream, TypedPayloadError,
    TypedRequest, TypedResponse, TypedStreamAdapter, TypedStreamService, TypedUnaryAdapter,
    TypedUnaryService, UnaryOperationHandler, decode_operation_payload, decode_typed_request,
    encode_operation_payload,
};
use cigar_canon::{CanonicalNode, to_deterministic_cbor};
use cigar_protocol::{
    ContentDigest, ContextSpaceId, CoordinationEvent, CoordinationEventKind, ErrorCode, RecordId,
    ReplayMode, UtcTimestamp, VersionId,
};
use futures_core::Stream;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const ID_A: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7890";
const ID_B: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7891";
const ID_C: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7892";

#[derive(Deserialize)]
struct PayloadManifest {
    operation_count: usize,
    operations: Vec<PayloadMapping>,
}

#[derive(Deserialize)]
struct PayloadMapping {
    operation_id: String,
    request_schema: String,
    response_schema: String,
    event_schema: Option<String>,
}

fn record(value: &str) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(value)?)
}

fn space(value: &str) -> Result<ContextSpaceId, Box<dyn std::error::Error>> {
    Ok(ContextSpaceId::new(value)?)
}

fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
    Ok(VersionId::new(format!(
        "1220{}",
        character.to_string().repeat(64)
    ))?)
}

fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        character.to_string().repeat(64)
    ))?)
}

fn round_trip<T>(value: &T) -> Result<(), Box<dyn std::error::Error>>
where
    T: cigar_api::OperationPayload + Eq + Debug,
{
    let encoded = encode_operation_payload(value, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;
    let decoded: T = decode_operation_payload(&encoded, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;
    assert_eq!(&decoded, value);
    Ok(())
}

#[test]
fn payload_manifest_and_rust_registry_cover_exactly_the_same_45_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest: PayloadManifest =
        serde_json::from_str(include_str!("../../../spec/api/operation-payloads-v1.json"))?;
    assert_eq!(manifest.operation_count, 45);
    assert_eq!(manifest.operations.len(), 45);
    assert_eq!(TYPED_OPERATION_MAPPINGS.len(), 45);

    let from_manifest: BTreeMap<_, _> = manifest
        .operations
        .iter()
        .map(|mapping| (mapping.operation_id.as_str(), mapping))
        .collect();
    let from_rust: BTreeMap<_, _> = TYPED_OPERATION_MAPPINGS
        .iter()
        .map(|mapping| (mapping.operation_id, mapping))
        .collect();
    assert_eq!(from_manifest.len(), 45);
    assert_eq!(from_rust.len(), 45);
    assert_eq!(
        from_manifest.keys().copied().collect::<BTreeSet<_>>(),
        cigar_api::generated::OPERATIONS
            .iter()
            .map(|operation| operation.operation_id)
            .collect::<BTreeSet<_>>()
    );
    for (operation_id, rust) in from_rust {
        let manifest = from_manifest
            .get(operation_id)
            .ok_or("typed operation absent from payload manifest")?;
        assert_eq!(manifest.request_schema, rust.request_schema);
        assert_eq!(manifest.response_schema, rust.response_schema);
        assert_eq!(manifest.event_schema.as_deref(), rust.event_schema);
    }
    Ok(())
}

#[test]
fn representative_constructible_request_and_response_dtos_round_trip_canonically()
-> Result<(), Box<dyn std::error::Error>> {
    let record_a = record(ID_A)?;
    let record_b = record(ID_B)?;
    let record_c = record(ID_C)?;
    let space_a = space(ID_A)?;
    let version_a = version('1')?;
    let version_b = version('2')?;
    let digest_a = digest('3')?;

    round_trip(&EmptyRequest {})?;
    round_trip(&SourceIdRequest {
        source_id: record_a.clone(),
    })?;
    round_trip(&AtomIdRequest {
        atom_id: record_a.clone(),
    })?;
    round_trip(&BundleIdRequest {
        bundle_id: version_a.clone(),
    })?;
    round_trip(&SpaceIdRequest {
        space_id: space_a.clone(),
    })?;
    round_trip(&HandoffIdRequest {
        handoff_id: record_a.clone(),
    })?;
    round_trip(&EffectIdRequest {
        effect_id: record_a.clone(),
    })?;
    round_trip(&ReplayIdRequest {
        replay_id: record_a.clone(),
    })?;
    round_trip(&IngestCatalogRequest {
        source_id: record_a.clone(),
        plan_digest: digest_a.clone(),
    })?;
    round_trip(&cigar_api::CompileContextBundleRequest {
        plan_id: record_a.clone(),
    })?;
    round_trip(&cigar_api::CompileContextDeltaRequest {
        base_bundle_id: version_a.clone(),
        target_plan_id: record_b.clone(),
    })?;
    round_trip(&cigar_api::ForkSpaceRequest {
        space_id: space_a.clone(),
        fork: SpaceFork::PrivateOverlay {
            base_commit_id: version_a.clone(),
            ttl_seconds: 60,
        },
    })?;
    round_trip(&cigar_api::ForkSpaceRequest {
        space_id: space_a.clone(),
        fork: SpaceFork::FocusBranch {
            focus_id: record_a.clone(),
            label: "investigate".to_owned(),
            offline: false,
        },
    })?;
    round_trip(&CheckpointSpaceRequest {
        space_id: space_a.clone(),
        focus_id: record_a.clone(),
    })?;
    round_trip(&ResolveSpaceConflictRequest {
        space_id: space_a.clone(),
        conflict_id: record_b.clone(),
        resolution: ConflictResolution::TypedDecision {
            decision_id: version_b,
        },
    })?;
    round_trip(&cigar_api::AcceptHandoffRequest {
        handoff_id: record_a.clone(),
        target_plan_id: record_b.clone(),
    })?;
    round_trip(&cigar_api::RevokeHandoffRequest {
        handoff_id: record_a.clone(),
        reason_digest: digest_a.clone(),
    })?;
    round_trip(&MergeHandoffRequest {
        handoff_id: record_a.clone(),
        delta_id: record_b.clone(),
        space_id: space_a,
        overlay_id: record_c,
    })?;
    round_trip(&CompensateEffectRequest {
        effect_id: record_a.clone(),
        compensation_effect_id: record_b.clone(),
        compensation_spec_digest: digest_a,
    })?;
    round_trip(&cigar_api::CreateReplayRequest {
        decision_id: version_a,
        mode: ReplayMode::EvidenceReproduction,
        simulate_effects: true,
    })?;
    round_trip(&CompareLiveReplayRequest {
        replay_id: record_a,
        live_authorization_id: record_b,
    })?;
    round_trip(&cigar_api::LivenessResponse { live: true })?;
    round_trip(&cigar_api::MetricsResponse {
        media_type: "application/openmetrics-text; version=1.0.0; charset=utf-8".to_owned(),
        text: "# EOF\n".to_owned(),
    })?;
    Ok(())
}

#[test]
fn strict_codec_rejects_unknown_duplicate_noncanonical_and_oversized_payloads()
-> Result<(), Box<dyn std::error::Error>> {
    let unknown = to_deterministic_cbor(&CanonicalNode::Map(BTreeMap::from([(
        "unknown".to_owned(),
        CanonicalNode::Boolean(true),
    )])))?;
    assert_eq!(
        decode_operation_payload::<EmptyRequest>(&unknown, cigar_api::MAX_OPERATION_PAYLOAD_BYTES),
        Err(TypedPayloadError::InvalidPayload)
    );

    let duplicate = [0xa2, 0x61, b'x', 0x01, 0x61, b'x', 0x02];
    assert_eq!(
        decode_operation_payload::<EmptyRequest>(
            &duplicate,
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES
        ),
        Err(TypedPayloadError::InvalidPayload)
    );

    let noncanonical_empty_map = [0xb8, 0x00];
    assert_eq!(
        decode_operation_payload::<EmptyRequest>(
            &noncanonical_empty_map,
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES
        ),
        Err(TypedPayloadError::InvalidPayload)
    );

    let oversized = vec![0; cigar_api::MAX_OPERATION_PAYLOAD_BYTES + 1];
    assert_eq!(
        decode_operation_payload::<EmptyRequest>(
            &oversized,
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES
        ),
        Err(TypedPayloadError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn typed_request_rejects_wrong_operation_and_path_copy_mismatch_and_injects_missing_path()
-> Result<(), Box<dyn std::error::Error>> {
    let source_a = record(ID_A)?;
    let source_b = record(ID_B)?;
    let encoded = encode_operation_payload(
        &SourceIdRequest {
            source_id: source_a.clone(),
        },
        cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
    )?;
    let mismatched = RequestEnvelope::new(
        "getSourceStatus",
        encoded,
        None,
        None,
        None,
        None,
        vec![PathParameter::new("source_id", source_b.as_str())?],
    )?;
    assert_eq!(
        decode_typed_request::<GetSourceStatusOperation>(&mismatched),
        Err(TypedPayloadError::PathMismatch)
    );

    let empty_map =
        encode_operation_payload(&EmptyRequest {}, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;
    let injected = RequestEnvelope::new(
        "getSourceStatus",
        empty_map.clone(),
        None,
        None,
        None,
        None,
        vec![PathParameter::new("source_id", source_a.as_str())?],
    )?;
    assert_eq!(
        decode_typed_request::<GetSourceStatusOperation>(&injected)?,
        SourceIdRequest {
            source_id: source_a
        }
    );

    let wrong = RequestEnvelope::new("getVersion", empty_map, None, None, None, None, Vec::new())?;
    assert_eq!(
        decode_typed_request::<GetLivenessOperation>(&wrong),
        Err(TypedPayloadError::WrongOperation)
    );
    Ok(())
}

struct Errors(RecordId);

impl FacadeErrorFactory for Errors {
    fn public_error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.0.clone())
    }
}

struct LivenessHandler;

impl TypedUnaryService<GetLivenessOperation> for LivenessHandler {
    fn call_typed<'a>(
        &'a self,
        _context: RequestContext,
        request: TypedRequest<EmptyRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<LivenessResponse>, ApiError>> {
        Box::pin(async move {
            assert!(request.metadata.dry_run());
            Ok(TypedResponse::new(LivenessResponse { live: true }))
        })
    }
}

struct OneEventStream(Option<TypedEvent<cigar_api::SpaceEventPayload>>);

impl Stream for OneEventStream {
    type Item = Result<TypedEvent<cigar_api::SpaceEventPayload>, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.take().map(Ok))
    }
}

struct SpaceStreamHandler;

impl TypedStreamService<SubscribeSpaceEventsOperation> for SpaceStreamHandler {
    fn subscribe_typed<'a>(
        &'a self,
        _context: RequestContext,
        request: TypedRequest<SpaceIdRequest>,
    ) -> cigar_api::ServiceFuture<
        'a,
        Result<TypedEventStream<cigar_api::SpaceEventPayload>, ApiError>,
    > {
        Box::pin(async move {
            let event = cigar_api::SpaceEventPayload {
                space_id: request.payload.space_id,
                project_id: record(ID_B).map_err(|_error| {
                    ApiError::new(
                        ErrorCode::Internal,
                        RecordId::new(ID_A).unwrap_or_else(|_| unreachable!()),
                    )
                })?,
                event: CoordinationEvent {
                    event_id: record(ID_C).map_err(|_error| {
                        ApiError::new(
                            ErrorCode::Internal,
                            RecordId::new(ID_A).unwrap_or_else(|_| unreachable!()),
                        )
                    })?,
                    kind: CoordinationEventKind::ContextCommitted,
                    payload_digest: digest('4').map_err(|_error| {
                        ApiError::new(
                            ErrorCode::Internal,
                            RecordId::new(ID_A).unwrap_or_else(|_| unreachable!()),
                        )
                    })?,
                },
            };
            Ok(Box::pin(OneEventStream(Some(TypedEvent {
                event_id: "event-1".to_owned(),
                payload: event,
            }))) as TypedEventStream<_>)
        })
    }
}

fn context(operation: &str) -> Result<RequestContext, Box<dyn std::error::Error>> {
    Ok(RequestContext::new(
        cigar_api::AuthenticatedIdentity::from_verified_credentials(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
        ),
        OperationId::new(operation)?,
        UtcTimestamp::from_unix_nanos(100)?,
        TraceId::new("0123456789abcdef0123456789abcdef")?,
        CancellationToken::new(),
        UtcTimestamp::from_unix_nanos(10)?,
    )?)
}

#[tokio::test]
async fn typed_unary_and_stream_adapters_encode_under_marker_constants()
-> Result<(), Box<dyn std::error::Error>> {
    let errors: Arc<dyn FacadeErrorFactory> = Arc::new(Errors(record(ID_A)?));
    let unary = TypedUnaryAdapter::<GetLivenessOperation, _>::new(
        Arc::new(LivenessHandler),
        Arc::clone(&errors),
    );
    assert_eq!(unary.operation_id(), "getLiveness");
    let request = RequestEnvelope::new_with_dry_run(
        "getLiveness",
        encode_operation_payload(&EmptyRequest {}, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?,
        true,
        None,
        None,
        None,
        None,
        Vec::new(),
    )?;
    let response = unary.call(context("getLiveness")?, request).await?;
    assert_eq!(
        decode_operation_payload::<LivenessResponse>(
            response.payload_cbor(),
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES
        )?,
        LivenessResponse { live: true }
    );

    let stream = TypedStreamAdapter::<SubscribeSpaceEventsOperation, _>::new(
        Arc::new(SpaceStreamHandler),
        errors,
    );
    assert_eq!(stream.operation_id(), "subscribeSpaceEvents");
    let space_id = space(ID_A)?;
    let stream_request = RequestEnvelope::new(
        "subscribeSpaceEvents",
        encode_operation_payload(
            &SpaceIdRequest {
                space_id: space_id.clone(),
            },
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
        )?,
        None,
        None,
        None,
        None,
        vec![PathParameter::new("space_id", space_id.as_str())?],
    )?;
    let mut events = stream
        .subscribe(context("subscribeSpaceEvents")?, stream_request)
        .await?;
    let event = poll_fn(|context| events.as_mut().poll_next(context))
        .await
        .ok_or("typed stream event missing")??;
    assert_eq!(event.operation_id().as_str(), "subscribeSpaceEvents");
    assert_eq!(event.event_id(), "event-1");
    Ok(())
}

#[test]
fn marker_identity_is_not_inferred_from_payload_type() {
    assert_eq!(
        <DiscoverSourcesOperation as cigar_api::TypedOperation>::OPERATION_ID,
        "discoverSources"
    );
}
