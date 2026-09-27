//! Installed application compensation and revision fences against real Honey adapters.
//! The native owner performs begin/resolve transitions explicitly; this is not an assertion
//! that an application scheduler automatically resolves compensation.

use super::*;
use cigar_api::CompensateEffectOperation;
use cigar_effects::compensation_spec_digest;
use cigar_protocol::CompensationSpec;

struct CompensationConnector(Connector);

impl EffectConnector for CompensationConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        let mut descriptor = self.0.descriptor();
        descriptor.operations = vec![
            ConnectorOperation {
                operation: "send".into(),
                same_key_idempotent: false,
                supports_reconciliation: true,
                supports_compensation: true,
            },
            ConnectorOperation {
                operation: "undo".into(),
                same_key_idempotent: false,
                supports_reconciliation: true,
                supports_compensation: false,
            },
        ];
        descriptor
    }

    fn check_preconditions(
        &self,
        intent: &EffectIntent,
        now: UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        self.0.check_preconditions(intent, now)
    }

    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        self.0.dispatch(context)
    }

    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        self.0.reconcile(context)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Mutation {
    operation: String,
    revision: Option<String>,
    error: Option<ErrorCode>,
}

struct LifecycleFacade {
    inner: Arc<Facade>,
    compensate: TypedUnaryAdapter<CompensateEffectOperation, EffectServiceHandlers<SqliteStore>>,
    mutations: Mutex<Vec<Mutation>>,
}

impl ServiceFacade for LifecycleFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        Box::pin(async move {
            let operation = request.operation_id().as_str().to_owned();
            let revision = request.expected_revision().map(str::to_owned);
            let result = if operation == "compensateEffect" {
                self.compensate.call(context, request).await
            } else {
                self.inner.call(context, request).await
            };
            if operation != "getEffectStatus" {
                self.mutations
                    .lock()
                    .map_err(|_error| self.inner.errors.public_error(ErrorCode::Internal))?
                    .push(Mutation {
                        operation,
                        revision,
                        error: result.as_ref().err().map(ApiError::code),
                    });
            }
            result
        })
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        self.inner.subscribe(context, request)
    }
}

async fn prepare_intent(
    handlers: Arc<EffectServiceHandlers<SqliteStore>>,
    authority: &Authority,
    payload: &PrepareEffectRequest,
    key: &str,
) -> TestResult<EffectStatusResponse> {
    let errors: Arc<dyn FacadeErrorFactory> = errors()?;
    let adapter = TypedUnaryAdapter::<PrepareEffectOperation, _>::new(handlers, errors);
    let response = adapter
        .call(
            authority.context("prepareEffect", CancellationToken::new())?,
            RequestEnvelope::new_with_dry_run(
                "prepareEffect",
                encode_operation_payload(payload, 16 * 1024 * 1024)?,
                false,
                Some(key.into()),
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

fn assert_phase(driver: &Driver, phase: &str) -> TestResult {
    assert_eq!(driver.receive()?, json!({"phase":phase}));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit installed lifecycle gate: requires CIGAR_TEST_APPLICATION_PYTHON, CIGAR_TEST_APPLICATION_LIFECYCLE_DRIVER and CIGAR_TEST_WORKER"]
async fn checked_context_application_compensation_and_revision_fences() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let executable = PathBuf::from(std::env::var("CIGAR_TEST_APPLICATION_PYTHON")?);
    let script = PathBuf::from(std::env::var("CIGAR_TEST_APPLICATION_LIFECYCLE_DRIVER")?);
    let worker_path = PathBuf::from(std::env::var("CIGAR_TEST_WORKER")?);
    for path in [&executable, &script, &worker_path] {
        if !path.is_absolute() || !path.is_file() {
            return Err("missing exact lifecycle integration input".into());
        }
    }
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("lifecycle.sqlite3");
    let store = Arc::new(SqliteStore::open(&database)?);
    let connector = Arc::new(CompensationConnector(Connector::new()));
    let gate = Arc::new(Gate(AtomicBool::new(true)));
    let queue = Arc::new(DispatchQueue::default());
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
    let mut child_payload = prepare_payload()?;
    child_payload.operation = "undo".into();
    child_payload.arguments_digest = digest(101)?;
    child_payload.encrypted_arguments.digest = digest(102)?;
    let compensation = CompensationSpec {
        operation: child_payload.operation.clone(),
        arguments_digest: child_payload.arguments_digest.clone(),
        encrypted_arguments: child_payload.encrypted_arguments.clone(),
    };
    let spec_digest = compensation_spec_digest(&compensation)?;
    let mut parent_payload = prepare_payload()?;
    parent_payload.compensation = Some(compensation);
    let parent = prepare_intent(handlers.clone(), &authority, &parent_payload, "parent").await?;
    let child = prepare_intent(handlers.clone(), &authority, &child_payload, "child").await?;
    assert_ne!(parent.effect_id, child.effect_id);

    let errors: Arc<dyn FacadeErrorFactory> = errors()?;
    let inner = Arc::new(Facade {
        prepare: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        get: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        authorize: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        dispatch: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        reconcile: TypedUnaryAdapter::new(handlers.clone(), errors.clone()),
        errors: errors.clone(),
        prepare_calls: AtomicUsize::new(0),
        authorize_calls: AtomicUsize::new(0),
        dispatch_calls: AtomicUsize::new(0),
        reconcile_calls: AtomicUsize::new(0),
        lost_ack: false,
    });
    let facade = Arc::new(LifecycleFacade {
        inner: inner.clone(),
        compensate: TypedUnaryAdapter::new(handlers, errors),
        mutations: Mutex::new(Vec::new()),
    });
    let missing = Arc::new(Mutex::new(Vec::new()));
    let observed_missing = missing.clone();
    let kernel = ServiceKernel::new(
        facade.clone(),
        authority.clone(),
        TransportConfig::default(),
    );
    let router = http_router(kernel).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let observed = observed_missing.clone();
            async move {
                let no_revision = request.method() == axum::http::Method::POST
                    && !request.headers().contains_key("if-match");
                let operation = request
                    .headers()
                    .get("x-cigar-operation-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let response = next.run(request).await;
                if no_revision {
                    // This observes malformed HTTP before the service-envelope admission gate.
                    if let Ok(mut rows) = observed.lock() {
                        rows.push((operation, response.status().as_u16()));
                    }
                }
                response
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    let mut driver = Driver::spawn(&executable, &script, &root, Consumer::InstalledApplication)?;
    driver.send(&json!({
        "base_url":format!("http://{address}"),
        "tenant_id":record(10)?.as_str(),"principal_id":record(11)?.as_str(),
        "parent":parent,"child":child,"compensation_spec_digest":spec_digest,
        "now_unix_ns":now.unix_nanos().to_string()
    }))?;
    assert_phase(&driver, "original_dispatch")?;
    let reader = EffectEngine::new(
        store.clone(),
        AccessContext::new(record(10)?, "lifecycle-oracle")?,
    );
    reader.register_connector(connector.clone())?;
    let parent_claim = reader.get(&parent.effect_id)?;
    assert_eq!(parent_claim.state, EffectState::Dispatching);
    assert_eq!(parent_claim.attempts.len(), 1);
    assert_eq!(reader.get(&child.effect_id)?.state, EffectState::Prepared);
    assert_eq!(connector.0.calls.load(Ordering::SeqCst), 0);
    let worker_authority = Arc::new(WorkerAuthority::allowed(record(12)?));
    let worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
        repository: store.clone(),
        authority: worker_authority.clone(),
        clock: Arc::new(FixedClock(now)),
        ids: Arc::new(TestIds(AtomicU64::new(9_100_000))),
        dispatch_gate: gate,
        argument_vault: Arc::new(OpenArgumentVault::default()),
        connectors: vec![connector.clone()],
    })?;
    let parent_job = queue.pop()?;
    assert_eq!(
        worker.process_job(WorkerKind::Outbox, &parent_job)?,
        EffectWorkerOutcome::Advanced
    );
    let succeeded = reader.get(&parent.effect_id)?;
    assert_eq!(succeeded.state, EffectState::Succeeded);
    assert_eq!(connector.0.calls.load(Ordering::SeqCst), 1);
    driver.send(&json!({"action":"link"}))?;
    assert_phase(&driver, "linked")?;
    let linked = reader.get(&parent.effect_id)?;
    let authorized_child = reader.get(&child.effect_id)?;
    assert_eq!(linked.state, EffectState::CompensationPending);
    assert_eq!(linked.effect_version, succeeded.effect_version + 1);
    assert_eq!(authorized_child.state, EffectState::Authorized);
    assert!(authorized_child.attempts.is_empty());
    let link = linked
        .compensation_link
        .as_ref()
        .ok_or("missing child link")?;
    assert_eq!(link.compensation_effect_id, child.effect_id);
    assert_eq!(link.compensation_spec_digest, spec_digest);
    assert_eq!(connector.0.calls.load(Ordering::SeqCst), 1);
    assert!(
        queue
            .jobs
            .lock()
            .map_err(|_error| "queue poisoned")?
            .is_empty()
    );

    driver.send(&json!({"action":"dispatch_child"}))?;
    assert_phase(&driver, "child_dispatch")?;
    let child_claim = reader.get(&child.effect_id)?;
    assert_eq!(child_claim.state, EffectState::Dispatching);
    assert_eq!(child_claim.attempts.len(), 1);
    assert_eq!(connector.0.calls.load(Ordering::SeqCst), 1);
    let authorization =
        worker_authority.authorize(&record(10)?, EffectWorkerAction::Dispatch, &linked, now)?;
    // The native owner, not the application facade, owns these two separate transitions.
    let compensating = reader.begin_compensation(
        &parent.effect_id,
        linked.effect_version,
        record(9_200_001)?,
        &authorization,
    )?;
    let child_job = queue.pop()?;
    assert_eq!(
        worker.process_job(WorkerKind::Outbox, &child_job)?,
        EffectWorkerOutcome::Advanced
    );
    let resolved = reader.resolve_compensation(
        &parent.effect_id,
        compensating.effect_version,
        record(9_200_002)?,
        &authorization,
    )?;
    assert_eq!(resolved.state, EffectState::Compensated);
    driver.send(&json!({"action":"observe"}))?;
    assert_phase(&driver, "observed")?;
    driver.finish()?;

    for job in [&parent_job, &child_job] {
        assert_eq!(
            worker.process_job(WorkerKind::Outbox, job)?,
            EffectWorkerOutcome::AlreadyComplete
        );
    }
    let reopened = EffectEngine::new(
        Arc::new(SqliteStore::open(&database)?),
        AccessContext::new(record(10)?, "lifecycle-reopened-oracle")?,
    );
    let final_parent = reopened.get(&parent.effect_id)?;
    let final_child = reopened.get(&child.effect_id)?;
    assert_eq!(final_parent.state, EffectState::Compensated);
    assert_eq!(final_child.state, EffectState::Succeeded);
    assert_eq!(final_parent.intent_digest, parent.intent_digest);
    assert_eq!(final_child.intent_digest, child.intent_digest);
    assert_eq!(final_parent.attempts.len(), 1);
    assert_eq!(final_child.attempts.len(), 1);
    assert_eq!(connector.0.calls.load(Ordering::SeqCst), 2);
    assert_eq!(inner.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.authorize_calls.load(Ordering::SeqCst), 3);
    assert_eq!(inner.dispatch_calls.load(Ordering::SeqCst), 2);
    assert_eq!(inner.reconcile_calls.load(Ordering::SeqCst), 1);
    let missing = missing
        .lock()
        .map_err(|_error| "missing-revision observations poisoned")?;
    assert_eq!(
        missing.as_slice(),
        [
            ("authorizeEffect".to_owned(), 400),
            ("reconcileEffect".to_owned(), 400),
            ("compensateEffect".to_owned(), 400),
        ]
    );
    let mutations = facade
        .mutations
        .lock()
        .map_err(|_error| "mutations poisoned")?;
    let expected = [
        ("authorizeEffect", parent.effect_version, None),
        ("authorizeEffect", 0, Some(ErrorCode::RevisionConflict)),
        ("dispatchEffect", parent_claim.effect_version - 1, None),
        ("reconcileEffect", 0, Some(ErrorCode::RevisionConflict)),
        ("compensateEffect", 0, Some(ErrorCode::RevisionConflict)),
        (
            "compensateEffect",
            succeeded.effect_version,
            Some(ErrorCode::PolicyDenied),
        ),
        ("authorizeEffect", child.effect_version, None),
        ("compensateEffect", succeeded.effect_version, None),
        ("dispatchEffect", authorized_child.effect_version, None),
    ];
    assert_eq!(mutations.len(), expected.len());
    for (observed, (operation, revision, error)) in mutations.iter().zip(expected) {
        assert_eq!(observed.operation, operation);
        assert_eq!(observed.revision, Some(revision.to_string()));
        assert_eq!(observed.error, error);
    }
    eprintln!(
        "{}",
        json!({"schema":"cigar.context-effect-lifecycle-observation.v1",
            "language":"installed-application","parent_state":"compensated",
            "child_state":"succeeded","parent_attempts":1,"child_attempts":1,
            "connector_calls":2,"dispatch_calls":2,"missing_revision_rejections":3,
            "stale_revision_rejections":3,"unauthorized_child_rejections":1,
            "native_owner_resolution":true,"passed":true})
    );
    Ok(())
}
