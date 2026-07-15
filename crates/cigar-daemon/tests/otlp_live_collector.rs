//! Live loopback qualification for the daemon's bounded OTLP/gRPC pipeline.

use cigar_daemon::{DaemonTelemetry, OtlpConfig};
use cigar_observe::{DAEMON_METRICS, metric_definition};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::{
    TraceService, TraceServiceServer,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use rcgen::{
    BasicConstraints, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const MAX_COLLECTOR_MESSAGE_BYTES: usize = 256 * 1024;

#[derive(Clone, Default)]
struct RecordingCollector {
    traces: Arc<Mutex<Vec<ExportTraceServiceRequest>>>,
    metrics: Arc<Mutex<Vec<ExportMetricsServiceRequest>>>,
}

struct TlsFixture {
    identity: Identity,
    ca_pem: Vec<u8>,
}

#[tonic::async_trait]
impl TraceService for RecordingCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        self.traces
            .lock()
            .map_err(|_error| tonic::Status::internal("collector state unavailable"))?
            .push(request.into_inner());
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

#[tonic::async_trait]
impl MetricsService for RecordingCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        self.metrics
            .lock()
            .map_err(|_error| tonic::Status::internal("collector state unavailable"))?
            .push(request.into_inner());
        Ok(tonic::Response::new(ExportMetricsServiceResponse::default()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_collector_receives_only_closed_daemon_signals() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let collector = RecordingCollector::default();
    let server_collector = collector.clone();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(
                TraceServiceServer::new(server_collector.clone())
                    .max_decoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES),
            )
            .add_service(
                MetricsServiceServer::new(server_collector)
                    .max_decoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ignored = shutdown_receiver.await;
            })
            .await
    });

    let telemetry = Arc::new(DaemonTelemetry::with_otlp(OtlpConfig::new(
        format!("http://{address}"),
        Duration::from_secs(3),
        Duration::from_secs(1),
    )?)?);
    telemetry.record_authorized_request();
    telemetry.record_rejected_request();
    telemetry.record_listener_failure();
    telemetry.record_graceful_shutdown();

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let shutdown_telemetry = Arc::clone(&telemetry);
    tokio::task::spawn_blocking(move || shutdown_telemetry.shutdown_otlp(Duration::from_secs(5)))
        .await??;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !locked(&collector.traces)?.is_empty() && !locked(&collector.metrics)?.is_empty() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "collector did not receive both OTLP signals",
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let trace_requests = locked(&collector.traces)?.clone();
    let metric_requests = locked(&collector.metrics)?.clone();
    let span_names = trace_requests
        .iter()
        .flat_map(|request| &request.resource_spans)
        .flat_map(|resource| &resource.scope_spans)
        .flat_map(|scope| &scope.spans)
        .map(|span| span.name.as_str())
        .collect::<Vec<_>>();
    assert!(span_names.contains(&"cigar.request.authority"));
    assert!(span_names.contains(&"cigar.listener.failure"));

    let metric_names = metric_requests
        .iter()
        .flat_map(|request| &request.resource_metrics)
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
        .map(|metric| metric.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_metric_names = DAEMON_METRICS
        .iter()
        .map(|definition| definition.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(metric_names, expected_metric_names);

    let mut observed_series = BTreeSet::new();
    for metric in metric_requests
        .iter()
        .flat_map(|request| &request.resource_metrics)
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
    {
        let definition = metric_definition(&metric.name)
            .ok_or_else(|| io::Error::other("collector received unknown metric family"))?;
        let attributes = match metric.data.as_ref() {
            Some(Data::Gauge(gauge)) => gauge
                .data_points
                .iter()
                .map(|point| point.attributes.as_slice())
                .collect::<Vec<_>>(),
            Some(Data::Sum(sum)) => sum
                .data_points
                .iter()
                .map(|point| point.attributes.as_slice())
                .collect::<Vec<_>>(),
            _ => return Err(io::Error::other("unexpected OTLP metric data kind").into()),
        };
        for attributes in attributes {
            let label = match definition.label {
                None => {
                    if !attributes.is_empty() {
                        return Err(io::Error::other("unlabelled metric gained attributes").into());
                    }
                    None
                }
                Some(domain) => {
                    let Some(attribute) = attributes
                        .first()
                        .filter(|_attribute| attributes.len() == 1)
                    else {
                        return Err(io::Error::other("closed metric label shape changed").into());
                    };
                    let Some(Value::StringValue(value)) = attribute
                        .value
                        .as_ref()
                        .and_then(|value| value.value.as_ref())
                    else {
                        return Err(io::Error::other("closed metric label was not text").into());
                    };
                    if attribute.key != domain.key || !domain.values.contains(&value.as_str()) {
                        return Err(
                            io::Error::other("closed metric label escaped its domain").into()
                        );
                    }
                    Some(value.clone())
                }
            };
            observed_series.insert((metric.name.clone(), label));
        }
    }
    let expected_series = DAEMON_METRICS
        .iter()
        .flat_map(|definition| match definition.label {
            None => vec![(definition.name.to_owned(), None)],
            Some(domain) => domain
                .values
                .iter()
                .map(|value| (definition.name.to_owned(), Some((*value).to_owned())))
                .collect(),
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(observed_series, expected_series);

    let allowed_attribute_values = ["authorized", "rejected", "listener_failure"];
    for span in trace_requests
        .iter()
        .flat_map(|request| &request.resource_spans)
        .flat_map(|resource| &resource.scope_spans)
        .flat_map(|scope| &scope.spans)
    {
        for attribute in &span.attributes {
            let Some(Value::StringValue(value)) = attribute
                .value
                .as_ref()
                .and_then(|value| value.value.as_ref())
            else {
                return Err(io::Error::other("unexpected OTLP trace attribute type").into());
            };
            assert!(
                allowed_attribute_values.contains(&value.as_str()),
                "unexpected trace attribute value"
            );
        }
    }

    shutdown_sender
        .send(())
        .map_err(|()| io::Error::other("collector server stopped before shutdown"))?;
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_collector_uses_only_the_explicit_matching_ca() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let trusted = tls_fixture("127.0.0.1")?;
    let untrusted = tls_fixture("127.0.0.1")?;
    let collector = RecordingCollector::default();
    let server_collector = collector.clone();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(trusted.identity))?
            .add_service(
                TraceServiceServer::new(server_collector.clone())
                    .max_decoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES),
            )
            .add_service(
                MetricsServiceServer::new(server_collector)
                    .max_decoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_COLLECTOR_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ignored = shutdown_receiver.await;
            })
            .await
    });

    let endpoint = format!("https://{address}");
    let rejected = Arc::new(DaemonTelemetry::with_otlp(
        OtlpConfig::new_with_ca_certificate(
            endpoint.clone(),
            Duration::from_secs(3),
            Duration::from_secs(1),
            untrusted.ca_pem,
        )?,
    )?);
    rejected.record_authorized_request();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let shutdown_rejected = Arc::clone(&rejected);
    let _expected_export_failure = tokio::task::spawn_blocking(move || {
        shutdown_rejected.shutdown_otlp(Duration::from_secs(5))
    })
    .await?;
    assert!(locked(&collector.traces)?.is_empty());
    assert!(locked(&collector.metrics)?.is_empty());

    let accepted = Arc::new(DaemonTelemetry::with_otlp(
        OtlpConfig::new_with_ca_certificate(
            endpoint,
            Duration::from_secs(3),
            Duration::from_secs(1),
            trusted.ca_pem,
        )?,
    )?);
    accepted.record_authorized_request();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let shutdown_accepted = Arc::clone(&accepted);
    tokio::task::spawn_blocking(move || shutdown_accepted.shutdown_otlp(Duration::from_secs(5)))
        .await??;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !locked(&collector.traces)?.is_empty() && !locked(&collector.metrics)?.is_empty() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS collector did not receive both OTLP signals",
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    shutdown_sender
        .send(())
        .map_err(|()| io::Error::other("TLS collector server stopped before shutdown"))?;
    server.await??;
    Ok(())
}

fn tls_fixture(hostname: &str) -> Result<TlsFixture, Box<dyn Error>> {
    let mut ca_parameters = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_parameters, KeyPair::generate()?)?;
    let mut server_parameters = rcgen::CertificateParams::new(vec![hostname.to_owned()])?;
    server_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server_certificate = server_parameters.signed_by(&server_key, &ca)?;
    let certificate_chain = format!("{}{}", server_certificate.pem(), ca.pem());
    Ok(TlsFixture {
        identity: Identity::from_pem(certificate_chain, server_key.serialize_pem()),
        ca_pem: ca.pem().into_bytes(),
    })
}

fn locked<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, io::Error> {
    mutex
        .lock()
        .map_err(|_error| io::Error::other("collector state unavailable"))
}
