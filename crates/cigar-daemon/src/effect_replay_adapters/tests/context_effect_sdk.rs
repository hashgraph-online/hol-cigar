//! Explicit offline SDK-to-Honey integration: real HTTP adapters, SQLite effect kernel and
//! separate native context workers. The deterministic connector never contacts an external tool.

use super::*;
use cigar_api::{
    ApiError, ContextInput, FacadeEventStream, ReconcileEffectOperation, RequestAuthority,
    ResponseEnvelope, ServiceFacade, ServiceFuture, ServiceKernel, TransportConfig, http_router,
};
use serde_json::{Value, json};
use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Authority {
    correlation_id: RecordId,
    now: UtcTimestamp,
    deadline: UtcTimestamp,
}

impl Authority {
    fn context(
        &self,
        operation: &str,
        cancellation: CancellationToken,
    ) -> Result<RequestContext, ApiError> {
        let build = || -> TestResult<RequestContext> {
            Ok(RequestContext::new(
                AuthenticatedIdentity::from_verified_credentials(
                    TenantId::new("transport-tenant")?,
                    PrincipalId::new("transport-principal")?,
                ),
                OperationId::new(operation)?,
                self.deadline,
                TraceId::new("0123456789abcdef0123456789abcdef")?,
                cancellation,
                self.now,
            )?)
        };
        build().map_err(|_error| self.public_error(ErrorCode::Internal))
    }
}

impl RequestAuthority for Authority {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        Box::pin(async move {
            if input.authorization() != Some("Bearer context-effect-sdk-fixture") {
                return Err(self.public_error(ErrorCode::UnknownPrincipal));
            }
            self.context(input.operation_id().as_str(), input.cancellation().clone())
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.correlation_id.clone())
    }
}

struct Facade {
    prepare: TypedUnaryAdapter<PrepareEffectOperation, EffectServiceHandlers<SqliteStore>>,
    get: TypedUnaryAdapter<GetEffectStatusOperation, EffectServiceHandlers<SqliteStore>>,
    authorize: TypedUnaryAdapter<AuthorizeEffectOperation, EffectServiceHandlers<SqliteStore>>,
    dispatch: TypedUnaryAdapter<DispatchEffectOperation, EffectServiceHandlers<SqliteStore>>,
    reconcile: TypedUnaryAdapter<ReconcileEffectOperation, EffectServiceHandlers<SqliteStore>>,
    errors: Arc<dyn FacadeErrorFactory>,
    prepare_calls: AtomicUsize,
    authorize_calls: AtomicUsize,
    dispatch_calls: AtomicUsize,
    reconcile_calls: AtomicUsize,
    lost_ack: bool,
}

impl ServiceFacade for Facade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        Box::pin(async move {
            match request.operation_id().as_str() {
                "prepareEffect" => {
                    self.prepare_calls.fetch_add(1, Ordering::SeqCst);
                    self.prepare.call(context, request).await
                }
                "getEffectStatus" => self.get.call(context, request).await,
                "authorizeEffect" => {
                    self.authorize_calls.fetch_add(1, Ordering::SeqCst);
                    self.authorize.call(context, request).await
                }
                "reconcileEffect" => {
                    self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
                    self.reconcile.call(context, request).await
                }
                "dispatchEffect" => {
                    self.dispatch_calls.fetch_add(1, Ordering::SeqCst);
                    let result = self.dispatch.call(context, request).await?;
                    if self.lost_ack {
                        // Deliberately lose the successful acknowledgement after the real durable
                        // claim. Even a retryable HTTP error must not trigger another adapter send.
                        Err(self.errors.public_error(ErrorCode::IndexUnavailable))
                    } else {
                        Ok(result)
                    }
                }
                _ => Err(self.errors.public_error(ErrorCode::InvalidArgument)),
            }
        })
    }

    fn subscribe<'a>(
        &'a self,
        _context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        Box::pin(async move { Err(self.errors.public_error(ErrorCode::InvalidArgument)) })
    }
}

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Driver {
    child: Child,
    input: ChildStdin,
    output: mpsc::Receiver<Result<Value, String>>,
}

#[derive(Clone, Copy)]
enum Consumer {
    SourceSdk,
    InstalledApplication,
    InstalledGateway,
}

impl Driver {
    fn spawn(
        executable: &Path,
        script: &Path,
        root: &Path,
        consumer: Consumer,
    ) -> TestResult<Self> {
        let mut command = Command::new(executable);
        command.arg(script);
        match consumer {
            Consumer::SourceSdk => {
                command.env("PYTHONPATH", root.join("sdk/python/src"));
            }
            Consumer::InstalledApplication | Consumer::InstalledGateway => {
                // Downstream qualification must resolve its installed SDK. Its explicit driver
                // is responsible for verifying that distribution and its own source inventory.
                command.env_remove("PYTHONPATH");
                command.env("PYTHONNOUSERSITE", "1");
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or("missing consumer stdin")?;
        let output = child.stdout.take().ok_or("missing consumer stdout")?;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            // A bad driver cannot allocate unbounded retained output or leave an unbounded wait.
            for line in std::io::BufReader::new(output.take(32 * 1024)).lines() {
                let result = line.map_err(|error| error.to_string()).and_then(|line| {
                    serde_json::from_str(&line).map_err(|error| error.to_string())
                });
                if sender.send(result).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input,
            output: receiver,
        })
    }

    fn send(&mut self, value: &Value) -> TestResult {
        serde_json::to_writer(&mut self.input, value)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
    }

    fn receive(&self) -> TestResult<Value> {
        self.output
            .recv_timeout(Duration::from_secs(30))?
            .map_err(Into::into)
    }

    fn finish(mut self) -> TestResult {
        self.send(&json!({"action":"close"}))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait()? {
                assert!(status.success(), "SDK consumer failed: {status}");
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("SDK consumer did not terminate".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

struct AmbiguousConnector {
    inner: Arc<Connector>,
    reconciliations: AtomicUsize,
}

impl EffectConnector for AmbiguousConnector {
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
        let _observed = self.inner.dispatch(context)?;
        Ok(DispatchObservation::Unknown {
            evidence_digest: digest(95)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
            remote_operation_id: Some("one-synthetic-send".into()),
        })
    }
    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        self.reconciliations.fetch_add(1, Ordering::SeqCst);
        self.inner.reconcile(context)
    }
}

fn observe(driver: &mut Driver, expected: &cigar_effects::DurableEffectRecord) -> TestResult {
    driver.send(&json!({"action":"observe"}))?;
    let actual = driver.receive()?;
    let state = serde_json::to_value(expected.state)?;
    assert_eq!(actual.get("phase"), Some(&json!("observed")));
    assert_eq!(actual.get("state"), Some(&state));
    assert_eq!(
        actual.get("version"),
        Some(&json!(expected.effect_version.to_string()))
    );
    assert_eq!(
        actual.get("attempts"),
        Some(&json!(expected.attempts.len()))
    );
    assert_eq!(
        actual.get("reconciliations"),
        Some(&json!(expected.reconciliations.len()))
    );
    Ok(())
}

async fn prepare(
    handlers: Arc<EffectServiceHandlers<SqliteStore>>,
    authority: &Authority,
) -> TestResult<EffectStatusResponse> {
    let errors: Arc<dyn FacadeErrorFactory> = errors()?;
    let prepare = TypedUnaryAdapter::<PrepareEffectOperation, _>::new(handlers, errors);
    let response = prepare
        .call(
            authority.context("prepareEffect", CancellationToken::new())?,
            RequestEnvelope::new_with_dry_run(
                "prepareEffect",
                encode_operation_payload(&prepare_payload()?, 16 * 1024 * 1024)?,
                false,
                Some("sdk-prepare".into()),
                None,
                None,
                None,
                vec![],
            )?,
        )
        .await?;
    Ok(decode_operation_payload(
        response.payload_cbor(),
        16 * 1024 * 1024,
    )?)
}

async fn prepare_authorized(
    handlers: Arc<EffectServiceHandlers<SqliteStore>>,
    authority: &Authority,
) -> TestResult<EffectStatusResponse> {
    let prepared = prepare(handlers.clone(), authority).await?;
    let errors: Arc<dyn FacadeErrorFactory> = errors()?;
    let authorize = TypedUnaryAdapter::<AuthorizeEffectOperation, _>::new(handlers, errors);
    let response = authorize
        .call(
            authority.context("authorizeEffect", CancellationToken::new())?,
            RequestEnvelope::new_with_dry_run(
                "authorizeEffect",
                encode_operation_payload(
                    &AuthorizeEffectRequest {
                        effect_id: prepared.effect_id.clone(),
                        approval: None,
                    },
                    16 * 1024 * 1024,
                )?,
                false,
                Some("sdk-authorize".into()),
                Some(prepared.effect_version.to_string()),
                None,
                None,
                vec![PathParameter::new(
                    "effect_id",
                    prepared.effect_id.as_str(),
                )?],
            )?,
        )
        .await?;
    Ok(decode_operation_payload(
        response.payload_cbor(),
        16 * 1024 * 1024,
    )?)
}

async fn read_status(
    handlers: Arc<EffectServiceHandlers<SqliteStore>>,
    authority: &Authority,
    effect_id: &RecordId,
) -> TestResult<EffectStatusResponse> {
    let errors: Arc<dyn FacadeErrorFactory> = errors()?;
    let get = TypedUnaryAdapter::<GetEffectStatusOperation, _>::new(handlers, errors);
    let response = get
        .call(
            authority.context("getEffectStatus", CancellationToken::new())?,
            RequestEnvelope::new_with_dry_run(
                "getEffectStatus",
                encode_operation_payload(
                    &EffectIdRequest {
                        effect_id: effect_id.clone(),
                    },
                    16 * 1024 * 1024,
                )?,
                false,
                None,
                None,
                None,
                None,
                vec![PathParameter::new("effect_id", effect_id.as_str())?],
            )?,
        )
        .await?;
    Ok(decode_operation_payload(
        response.payload_cbor(),
        16 * 1024 * 1024,
    )?)
}

async fn exercise(
    executable: &Path,
    script: &Path,
    root: &Path,
    language: &str,
    scenario: &str,
    consumer: Consumer,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("honey-effects.sqlite3");
    let store = Arc::new(SqliteStore::open(&database)?);
    let connector = Arc::new(Connector::new());
    let gate = Arc::new(Gate(AtomicBool::new(true)));
    let queue = Arc::new(DispatchQueue::default());
    // A frozen per-case authority clock makes effect outcomes deterministic. Anchor its HTTP
    // deadline in the present: the transport checks elapsed wall time independently of Honey.
    let now = UtcTimestamp::from_unix_nanos(i128::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)?;
    let authority = Arc::new(Authority {
        correlation_id: record(65_535)?,
        now,
        deadline: UtcTimestamp::from_unix_nanos(now.unix_nanos() + 60_000_000_000)?,
    });
    let handlers = Arc::new(EffectServiceHandlers::new(EffectServiceDependencies {
        repository: store.clone(),
        identities: Arc::new(FixedIdentity {
            tenant_id: record(10)?,
            principal_id: record(11)?,
        }),
        policy: Arc::new(AllowEffects),
        clock: Arc::new(FixedClock(now)),
        ids: Arc::new(TestIds(AtomicU64::new(
            NEXT_EFFECT_ID_BLOCK.fetch_add(10_000, Ordering::AcqRel),
        ))),
        dispatch_gate: gate.clone(),
        dispatch_queue: queue.clone(),
        argument_vault: Arc::new(OpenArgumentVault::default()),
        blocking_pool: BlockingPool::new(2, 2)?,
        connectors: vec![connector.clone()],
        errors: errors()?,
    })?);
    let application = !matches!(consumer, Consumer::SourceSdk);
    let gateway = matches!(consumer, Consumer::InstalledGateway);
    let initial = if gateway {
        None
    } else if application {
        Some(prepare(handlers.clone(), &authority).await?)
    } else {
        Some(prepare_authorized(handlers.clone(), &authority).await?)
    };
    let errors: Arc<dyn FacadeErrorFactory> = errors()?;
    let facade = Arc::new(Facade {
        prepare: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        get: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        authorize: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        dispatch: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        reconcile: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        errors,
        prepare_calls: AtomicUsize::new(0),
        authorize_calls: AtomicUsize::new(0),
        dispatch_calls: AtomicUsize::new(0),
        reconcile_calls: AtomicUsize::new(0),
        lost_ack: scenario == "lost_ack",
    });
    let kernel = ServiceKernel::new(
        facade.clone(),
        authority.clone(),
        TransportConfig::default(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let _server = Server(tokio::spawn(async move {
        axum::serve(listener, http_router(kernel)).await
    }));
    let mut driver = Driver::spawn(executable, script, root, consumer)?;
    let config = json!({
        "base_url": format!("http://{address}"),
        "scenario": scenario,
        "client_prepares": gateway,
        "effect_id": initial.as_ref().map(|value| value.effect_id.as_str()),
        "intent_digest": initial.as_ref().map(|value| value.intent_digest.as_str()),
        "initial_state": initial.as_ref().map(|value| &value.state),
        "initial_version": initial.as_ref().map(|value| value.effect_version.to_string()),
        "now_unix_ns": now.unix_nanos().to_string(),
        "tenant_id": record(10)?.as_str(),
        "principal_id": record(11)?.as_str()
    });
    driver.send(&config)?;
    let initial = match initial {
        Some(value) => value,
        None => {
            let prepared = driver.receive()?;
            assert_eq!(prepared.get("phase"), Some(&json!("prepared")));
            let declared_id = prepared["effect_id"]
                .as_str()
                .ok_or("missing prepared effect ID")?;
            let effect_id = RecordId::new(declared_id)?;
            // Read the actual service repository before allowing dispatch. The application's
            // prepared-status declaration alone cannot establish that an effect exists.
            let retained = read_status(handlers.clone(), &authority, &effect_id).await?;
            assert_eq!(retained.state, EffectState::Prepared);
            assert_eq!(retained.attempt_count, 0);
            assert_eq!(retained.reconciliation_count, 0);
            assert_eq!(
                prepared.get("intent_digest"),
                Some(&json!(retained.intent_digest.as_str()))
            );
            assert_eq!(facade.prepare_calls.load(Ordering::SeqCst), 1);
            assert_eq!(facade.authorize_calls.load(Ordering::SeqCst), 0);
            assert_eq!(facade.dispatch_calls.load(Ordering::SeqCst), 0);
            assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
            driver.send(&json!({"action":"continue"}))?;
            retained
        }
    };
    let first = driver.receive()?;
    assert_eq!(first.get("phase"), Some(&json!("dispatch")));
    assert_eq!(
        first.get("effect_id"),
        Some(&json!(initial.effect_id.as_str()))
    );
    let refused = matches!(scenario, "stale_context" | "intent_substitution");
    let outcome = if refused {
        "refused"
    } else if scenario == "lost_ack" {
        "uncertain"
    } else {
        "dispatched"
    };
    assert_eq!(first.get("outcome"), Some(&json!(outcome)));
    assert_eq!(
        facade.dispatch_calls.load(Ordering::SeqCst),
        usize::from(!refused)
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        facade.prepare_calls.load(Ordering::SeqCst),
        usize::from(gateway)
    );
    assert_eq!(
        facade.authorize_calls.load(Ordering::SeqCst),
        usize::from(application)
    );

    let verification = EffectEngine::new(
        store.clone(),
        AccessContext::new(record(10)?, "context-sdk-oracle")?,
    );
    verification.register_connector(connector.clone())?;
    if refused {
        assert!(
            queue
                .jobs
                .lock()
                .map_err(|_error| "queue poisoned")?
                .is_empty()
        );
        let retained = verification.get(&initial.effect_id)?;
        assert_eq!(retained.state, EffectState::Authorized);
        assert!(retained.attempts.is_empty());
        observe(&mut driver, &retained)?;
    } else {
        let queued = queue.pop()?;
        let claimed = verification.get(&initial.effect_id)?;
        assert_eq!(claimed.state, EffectState::Dispatching);
        assert_eq!(claimed.attempts.len(), 1);
        let authority = Arc::new(WorkerAuthority::allowed(record(12)?));
        authority
            .allowed
            .store(scenario != "worker_revoked", Ordering::Release);
        let ambiguous = Arc::new(AmbiguousConnector {
            inner: connector.clone(),
            reconciliations: AtomicUsize::new(0),
        });
        let worker_connector: Arc<dyn EffectConnector> = if scenario == "unknown_reconcile" {
            ambiguous.clone()
        } else {
            connector.clone()
        };
        let worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: store.clone(),
            authority,
            clock: Arc::new(FixedClock(now)),
            ids: Arc::new(TestIds(AtomicU64::new(9_000_000))),
            dispatch_gate: gate,
            argument_vault: Arc::new(OpenArgumentVault::default()),
            connectors: vec![worker_connector],
        })?;
        assert_eq!(
            worker.process_job(WorkerKind::Outbox, &queued)?,
            EffectWorkerOutcome::Advanced
        );
        let mut retained = verification.get(&initial.effect_id)?;
        let expected = match scenario {
            "worker_revoked" => EffectState::Failed,
            "unknown_reconcile" => EffectState::Unknown,
            _ => EffectState::Succeeded,
        };
        assert_eq!(retained.state, expected);
        assert_eq!(retained.receipts.len(), 1);
        assert_eq!(
            connector.calls.load(Ordering::SeqCst),
            usize::from(scenario != "worker_revoked")
        );
        observe(&mut driver, &retained)?;
        if scenario == "unknown_reconcile" {
            if application {
                driver.send(&json!({"action":"reconcile"}))?;
                let result = driver.receive()?;
                assert_eq!(result.get("phase"), Some(&json!("reconciled")));
                assert_eq!(result.get("state"), Some(&json!("succeeded")));
            } else {
                assert_eq!(
                    worker.process_reconciliation(&record(10)?, &initial.effect_id, None)?,
                    EffectWorkerOutcome::Advanced
                );
            }
            retained = verification.get(&initial.effect_id)?;
            assert_eq!(retained.state, EffectState::Succeeded);
            assert_eq!(retained.reconciliations.len(), 1);
            assert_eq!(
                ambiguous.reconciliations.load(Ordering::SeqCst),
                usize::from(!application)
            );
            assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
            observe(&mut driver, &retained)?;
        }
        assert_eq!(
            worker.process_job(WorkerKind::Outbox, &queued)?,
            EffectWorkerOutcome::AlreadyComplete
        );
        assert_eq!(retained.attempts.len(), 1);
    }
    driver.finish()?;
    // Include refused cases and verify after application shutdown, so the driver cannot send
    // again during cleanup without invalidating the independent terminal observation.
    let retained = verification.get(&initial.effect_id)?;
    let reopened = EffectEngine::new(
        Arc::new(SqliteStore::open(&database)?),
        AccessContext::new(record(10)?, "reopened-oracle")?,
    );
    reopened.register_connector(connector.clone())?;
    let persisted = reopened.get(&initial.effect_id)?;
    let expected_state = if refused {
        EffectState::Authorized
    } else if scenario == "worker_revoked" {
        EffectState::Failed
    } else {
        EffectState::Succeeded
    };
    assert_eq!(persisted.state, expected_state);
    assert_eq!(persisted.effect_version, retained.effect_version);
    assert_eq!(persisted.intent_digest, initial.intent_digest);
    assert_eq!(persisted.attempts.len(), usize::from(!refused));
    assert_eq!(
        persisted.reconciliations.len(),
        usize::from(scenario == "unknown_reconcile")
    );
    assert_eq!(
        connector.calls.load(Ordering::SeqCst),
        usize::from(!refused && scenario != "worker_revoked")
    );
    assert_eq!(
        facade.authorize_calls.load(Ordering::SeqCst),
        usize::from(application)
    );
    assert_eq!(
        facade.dispatch_calls.load(Ordering::SeqCst),
        usize::from(!refused)
    );
    assert_eq!(
        facade.reconcile_calls.load(Ordering::SeqCst),
        usize::from(application && scenario == "unknown_reconcile")
    );
    assert_eq!(
        facade.prepare_calls.load(Ordering::SeqCst),
        usize::from(gateway)
    );
    let mut observation = json!({"schema":"cigar.context-effect-sdk-observation.v1",
        "language":language,"scenario":scenario,"outcome":outcome,
        "dispatch_calls":facade.dispatch_calls.load(Ordering::SeqCst),
        "connector_calls":connector.calls.load(Ordering::SeqCst),"passed":true});
    if application {
        observation["schema"] = json!("cigar.context-effect-application-observation.v1");
        observation["authorize_calls"] = json!(facade.authorize_calls.load(Ordering::SeqCst));
        observation["reconcile_calls"] = json!(facade.reconcile_calls.load(Ordering::SeqCst));
    }
    if gateway {
        observation["schema"] = json!("cigar.context-gateway-application-observation.v1");
        observation["prepare_calls"] = json!(facade.prepare_calls.load(Ordering::SeqCst));
    }
    eprintln!("{observation}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit SDK integration gate: requires CIGAR_TEST_PYTHON, CIGAR_TEST_NODE, CIGAR_TEST_CONTEXT_EFFECT_NODE and CIGAR_TEST_WORKER"]
async fn checked_context_sdk_honey_terminal_outcomes() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let python = PathBuf::from(std::env::var("CIGAR_TEST_PYTHON")?);
    let node = PathBuf::from(std::env::var("CIGAR_TEST_NODE")?);
    let node_script = PathBuf::from(std::env::var("CIGAR_TEST_CONTEXT_EFFECT_NODE")?);
    let python_script = root.join("sdk/python/tests/fixtures/context_effect_consumer.py");
    let worker = PathBuf::from(std::env::var("CIGAR_TEST_WORKER")?);
    for path in [&python, &node, &node_script, &python_script, &worker] {
        if !path.is_absolute() || !path.is_file() {
            return Err("missing exact SDK integration input".into());
        }
    }
    for (language, executable, script) in [
        ("python", python, python_script),
        ("node", node, node_script),
    ] {
        for scenario in [
            "success",
            "lost_ack",
            "stale_context",
            "intent_substitution",
            "worker_revoked",
            "unknown_reconcile",
        ] {
            exercise(
                &executable,
                &script,
                &root,
                language,
                scenario,
                Consumer::SourceSdk,
            )
            .await?;
        }
    }
    Ok(())
}

/// Separate from SDK qualification: the explicit downstream driver owns its application checks.
/// Honey still independently checks real HTTP call counts and terminal SQLite state here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit installed application gate: requires CIGAR_TEST_APPLICATION_PYTHON, CIGAR_TEST_APPLICATION_DRIVER and CIGAR_TEST_WORKER"]
async fn checked_context_application_honey_terminal_outcomes() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let executable = PathBuf::from(std::env::var("CIGAR_TEST_APPLICATION_PYTHON")?);
    let script = PathBuf::from(std::env::var("CIGAR_TEST_APPLICATION_DRIVER")?);
    let worker = PathBuf::from(std::env::var("CIGAR_TEST_WORKER")?);
    for path in [&executable, &script, &worker] {
        if !path.is_absolute() || !path.is_file() {
            return Err("missing exact application integration input".into());
        }
    }
    for scenario in [
        "success",
        "lost_ack",
        "stale_context",
        "intent_substitution",
        "worker_revoked",
        "unknown_reconcile",
    ] {
        exercise(
            &executable,
            &script,
            &root,
            "installed-application",
            scenario,
            Consumer::InstalledApplication,
        )
        .await?;
    }
    Ok(())
}

/// The gateway lane starts with an empty effect store and requires application-owned preparation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit installed gateway gate: requires CIGAR_TEST_APPLICATION_PYTHON, CIGAR_TEST_APPLICATION_GATEWAY_DRIVER and CIGAR_TEST_WORKER"]
async fn checked_context_gateway_honey_terminal_outcomes() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let executable = PathBuf::from(std::env::var("CIGAR_TEST_APPLICATION_PYTHON")?);
    let script = PathBuf::from(std::env::var("CIGAR_TEST_APPLICATION_GATEWAY_DRIVER")?);
    let worker = PathBuf::from(std::env::var("CIGAR_TEST_WORKER")?);
    for path in [&executable, &script, &worker] {
        if !path.is_absolute() || !path.is_file() {
            return Err("missing exact gateway integration input".into());
        }
    }
    for scenario in [
        "success",
        "lost_ack",
        "stale_context",
        "intent_substitution",
        "worker_revoked",
        "unknown_reconcile",
    ] {
        exercise(
            &executable,
            &script,
            &root,
            "installed-gateway",
            scenario,
            Consumer::InstalledGateway,
        )
        .await?;
    }
    Ok(())
}
