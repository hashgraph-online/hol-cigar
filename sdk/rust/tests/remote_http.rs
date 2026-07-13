//! Real loopback HTTP transport and compatibility negotiation qualification.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_sdk::api::{
    CapabilitiesResponse, OperationPayload, SpaceEventPayload, SpaceIdRequest, VersionResponse,
    encode_operation_payload,
};
use cigar_sdk::protocol::{
    ContentDigest, ContextSpaceId, CoordinationEvent, CoordinationEventKind, RecordId,
};
use cigar_sdk::{CallOptions, ErrorKind, RemoteClientBuilder, StreamResumeToken};
use futures_util::StreamExt as _;
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

#[derive(Serialize)]
struct WireResponse<'a> {
    operation_id: &'a str,
    payload_cbor: String,
}

#[derive(Serialize)]
struct WireEvent<'a> {
    operation_id: &'a str,
    event_id: &'a str,
    payload_cbor: String,
}

fn wire<T: OperationPayload>(
    operation_id: &'static str,
    payload: &T,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encoded = encode_operation_payload(payload, cigar_sdk::api::MAX_OPERATION_PAYLOAD_BYTES)?;
    Ok(serde_json::to_vec(&WireResponse {
        operation_id,
        payload_cbor: URL_SAFE_NO_PAD.encode(encoded),
    })?)
}

async fn serve_connection(mut socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1_024];
    loop {
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Err("request ended before headers".into());
        }
        request.extend_from_slice(buffer.get(..read).ok_or("invalid read length")?);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 16 * 1_024 {
            return Err("request headers exceeded test bound".into());
        }
    }
    let text = std::str::from_utf8(&request)?;
    let first = text.lines().next().ok_or("missing request line")?;
    let path_and_query = first.split_whitespace().nth(1).ok_or("missing path")?;
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _query)| path);
    let (response_content_type, body) = match path {
        "/v1/version" => (
            "application/json; charset=utf-8",
            wire(
                "getVersion",
                &VersionResponse {
                    version: "0.1.0".to_owned(),
                    source_revision: "test".to_owned(),
                    protocol_min: "1.0".to_owned(),
                    protocol_max: "1.x".to_owned(),
                    build_profile: "test".to_owned(),
                    enabled_features: Vec::new(),
                },
            )?,
        ),
        "/v1/capabilities" => (
            "application/json; charset=utf-8",
            wire(
                "getCapabilities",
                &CapabilitiesResponse {
                    api_version: "v1".to_owned(),
                    protocol_version: "1.x".to_owned(),
                    profiles: vec!["local".to_owned()],
                    extensions: Vec::new(),
                    max_payload_bytes: u32::try_from(cigar_sdk::api::MAX_OPERATION_PAYLOAD_BYTES)?,
                    max_event_bytes: u32::try_from(cigar_sdk::api::MAX_EVENT_PAYLOAD_BYTES)?,
                    max_page_size: 1_000,
                },
            )?,
        ),
        value if value.starts_with("/v1/spaces/") && value.ends_with("/events") => {
            if !text
                .lines()
                .any(|line| line.eq_ignore_ascii_case("last-event-id: resume-8"))
            {
                return Err("stream resume header was not preserved".into());
            }
            let payload = SpaceEventPayload {
                space_id: ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
                project_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?,
                event: CoordinationEvent {
                    event_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
                    kind: CoordinationEventKind::ContextCommitted,
                    payload_digest: ContentDigest::new(format!("1220{}", "a".repeat(64)))?,
                },
            };
            let encoded =
                encode_operation_payload(&payload, cigar_sdk::api::MAX_EVENT_PAYLOAD_BYTES)?;
            let data = serde_json::to_string(&WireEvent {
                operation_id: "subscribeSpaceEvents",
                event_id: "event-9",
                payload_cbor: URL_SAFE_NO_PAD.encode(encoded),
            })?;
            (
                "text/event-stream",
                format!("id: event-9\ndata: {data}\n\n").into_bytes(),
            )
        }
        _ => return Err(format!("unexpected request path {path}").into()),
    };
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {response_content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(headers.as_bytes()).await?;
    socket.write_all(&body).await?;
    socket.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn loopback_daemon_negotiates_frozen_compatibility() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        for _ordinal in 0..3 {
            let (socket, _peer) = listener.accept().await.map_err(|error| error.to_string())?;
            serve_connection(socket)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<(), String>(())
    });
    let endpoint = format!("http://{address}/");
    let connection = RemoteClientBuilder::new(&endpoint)?
        .allow_insecure_loopback(true)
        .connect()
        .await;
    let Ok((client, compatibility)) = connection else {
        let server_result = server.await?;
        return Err(format!("connection failed; server result: {server_result:?}").into());
    };
    assert_eq!(compatibility.capabilities.api_version, "v1");
    assert_eq!(compatibility.version.protocol_max, "1.x");
    let options = CallOptions::read()
        .with_page(None, 16)?
        .with_stream_resume(StreamResumeToken::new("resume-8")?);
    let mut events = client
        .subscribe_space_events(
            SpaceIdRequest {
                space_id: ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            },
            options,
        )
        .await?;
    let Some(event) = events.next().await else {
        return Err("remote SSE stream ended without an event".into());
    };
    assert_eq!(event?.event_id, "event-9");
    server
        .await?
        .map_err(|error| format!("server failed: {error}"))?;
    Ok(())
}

#[tokio::test]
async fn cleartext_requires_explicit_loopback_opt_in() -> Result<(), Box<dyn std::error::Error>> {
    let result = RemoteClientBuilder::new("http://127.0.0.1:9/")?
        .connect()
        .await;
    let Err(error) = result else {
        return Err("cleartext endpoint unexpectedly connected".into());
    };
    assert_eq!(error.kind(), ErrorKind::InvalidConfiguration);
    Ok(())
}
