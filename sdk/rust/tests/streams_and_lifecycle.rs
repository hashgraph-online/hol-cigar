//! Pagination, stream resume, drop cancellation, and call cancellation tests.

use cigar_sdk::api::{
    EmptyRequest, GetSpaceLogOperation, SpaceEventPayload, SpaceIdRequest, SpaceLogResponse,
    SubscribeSpaceEventsOperation, TypedOperation, encode_operation_payload,
};
use cigar_sdk::protocol::{
    ContentDigest, ContextSpaceId, CoordinationEvent, CoordinationEventKind, PageCursor, RecordId,
};
use cigar_sdk::{
    CallOptions, CancellationToken, Client, ClientTransport, ErrorKind, SdkError, SdkFuture,
    StreamResumeToken, TransportCall, TransportEventStream,
};
use futures_util::{StreamExt as _, stream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct StreamTransport {
    cursors: Arc<Mutex<Vec<Option<String>>>>,
}

#[derive(Default)]
struct PaginationTransport {
    cursors: Mutex<Vec<Option<String>>>,
}

impl ClientTransport for PaginationTransport {
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<cigar_sdk::api::ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            if call.contract().operation_id != GetSpaceLogOperation::OPERATION_ID {
                return Err(SdkError::protocol());
            }
            let mut cursors = self
                .cursors
                .lock()
                .map_err(|_failure| SdkError::transport())?;
            cursors.push(call.envelope().page_cursor().map(str::to_owned));
            let next = (cursors.len() == 1).then(|| "bmV4dA".to_owned());
            drop(cursors);
            let payload = encode_operation_payload(
                &SpaceLogResponse {
                    commits: Vec::new(),
                },
                cigar_sdk::api::MAX_OPERATION_PAYLOAD_BYTES,
            )
            .map_err(|_failure| SdkError::protocol())?;
            cigar_sdk::api::ResponseEnvelope::new(
                GetSpaceLogOperation::OPERATION_ID,
                payload,
                Some("\"space-7\"".to_owned()),
                next,
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

impl ClientTransport for StreamTransport {
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<cigar_sdk::api::ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            tokio::select! {
                () = call.cancellation().cancelled() => Err(SdkError::cancelled()),
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
                    Err(SdkError::deadline_exceeded())
                }
            }
        })
    }

    fn subscribe<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>> {
        Box::pin(async move {
            self.cursors
                .lock()
                .map_err(|_failure| SdkError::transport())?
                .push(call.envelope().page_cursor().map(str::to_owned));
            let payload = SpaceEventPayload {
                space_id: ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")
                    .map_err(|_failure| SdkError::protocol())?,
                project_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")
                    .map_err(|_failure| SdkError::protocol())?,
                event: CoordinationEvent {
                    event_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")
                        .map_err(|_failure| SdkError::protocol())?,
                    kind: CoordinationEventKind::ContextCommitted,
                    payload_digest: ContentDigest::new(format!("1220{}", "a".repeat(64)))
                        .map_err(|_failure| SdkError::protocol())?,
                },
            };
            let encoded =
                encode_operation_payload(&payload, cigar_sdk::api::MAX_EVENT_PAYLOAD_BYTES)
                    .map_err(|_failure| SdkError::protocol())?;
            let event = cigar_sdk::api::EventEnvelope::new(
                SubscribeSpaceEventsOperation::OPERATION_ID,
                "event-7",
                encoded,
            )
            .map_err(|_failure| SdkError::protocol())?;
            Ok(Box::pin(stream::iter([Ok(event)])) as TransportEventStream)
        })
    }
}

#[tokio::test]
async fn stream_resume_cursor_and_event_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let cursors = Arc::new(Mutex::new(Vec::new()));
    let client = Client::from_transport(Arc::new(StreamTransport {
        cursors: cursors.clone(),
    }));
    let cancellation = CancellationToken::new();
    let options = CallOptions::read()
        .with_page(None, 32)?
        .with_stream_resume(StreamResumeToken::new("resume-6")?)
        .with_cancellation(cancellation.clone());
    let mut events = client
        .subscribe_space_events(
            SpaceIdRequest {
                space_id: ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            },
            options,
        )
        .await?;
    let Some(event) = events.next().await else {
        return Err("stream ended without event".into());
    };
    let event = event?;
    assert_eq!(event.event_id, "event-7");
    assert_eq!(event.resume_token()?.as_str(), "event-7");
    drop(events);
    assert!(cancellation.is_cancelled());
    let values = cursors.lock().map_err(|_| "poisoned cursor mutex")?;
    assert_eq!(values.first().and_then(Option::as_deref), Some("resume-6"));
    Ok(())
}

#[tokio::test]
async fn unary_cancellation_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_transport(Arc::new(StreamTransport {
        cursors: Arc::new(Mutex::new(Vec::new())),
    }));
    let cancellation = CancellationToken::new();
    let call_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        client
            .get_liveness(
                EmptyRequest {},
                CallOptions::read().with_cancellation(call_cancellation),
            )
            .await
    });
    tokio::task::yield_now().await;
    cancellation.cancel();
    let result = task.await?;
    let Err(error) = result else {
        return Err("cancelled call unexpectedly succeeded".into());
    };
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    Ok(())
}

#[tokio::test]
async fn unary_deadline_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_transport(Arc::new(StreamTransport {
        cursors: Arc::new(Mutex::new(Vec::new())),
    }));
    let result = client
        .get_liveness(
            EmptyRequest {},
            CallOptions::read().with_timeout(Duration::from_millis(5))?,
        )
        .await;
    let Err(error) = result else {
        return Err("expired call unexpectedly succeeded".into());
    };
    assert_eq!(error.kind(), ErrorKind::DeadlineExceeded);
    Ok(())
}

#[tokio::test]
async fn unary_page_decodes_opaque_cursor_and_etag() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(PaginationTransport::default());
    let client = Client::from_transport(transport.clone());
    let mut pages = client.paginate::<GetSpaceLogOperation>(
        SpaceIdRequest {
            space_id: ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        },
        CallOptions::read().with_page(None, 10)?,
    )?;
    let first = pages.next().await.ok_or("missing first page")??;
    assert!(first.value.commits.is_empty());
    assert_eq!(first.semantic_etag.as_deref(), Some("\"space-7\""));
    assert_eq!(
        first.next_cursor.as_ref().map(PageCursor::as_bytes),
        Some(b"next".as_slice())
    );
    let second = pages.next().await.ok_or("missing second page")??;
    assert!(second.next_cursor.is_none());
    assert!(pages.next().await.is_none());
    let cursors = transport
        .cursors
        .lock()
        .map_err(|_| "poisoned page cursor mutex")?;
    assert_eq!(cursors.as_slice(), [None, Some("bmV4dA".to_owned())]);
    Ok(())
}
