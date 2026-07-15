//! WP12 hermetic reference connector behavior and safety tests.

use cigar_effects::reference::{
    DemoDispatchMode, DemoIssueConnector, DemoIssueRequest, DemoIssueService,
    FilesystemEffectConnector, FilesystemWriteRequest, GitHubIssueConnector, GitHubIssueRequest,
    HttpLookupObservation, HttpMethod, HttpResourceBindingRequest, HttpResourceScope,
    HttpTransport, HttpTransportObservation, HttpTransportQuery, HttpTransportRequest,
    HttpTransportSecurity, IdempotentHttpConnector, IdempotentHttpRequest, MockGitHubDispatchMode,
    MockGitHubIssueService,
};
use cigar_effects::{
    DurableEffectRecord, EffectAuthorization, EffectConnector, EffectEngine, EffectError,
    EffectErrorCode,
};
use cigar_protocol::{
    BlobRef, Capability, ContentDigest, EffectIntent, EffectState, ExtensionMap, IdempotencyKey,
    MediaType, RecordId, RetryPolicy, RiskLevel, SchemaVersion, UtcTimestamp, VersionId,
};
use cigar_store::{AccessContext, InMemoryStore};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn Error>>;

fn digest(value: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let hash = Sha256::digest(value);
    let mut encoded = String::from("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn intent(
    connector: &str,
    operation: &str,
    arguments_digest: ContentDigest,
    target: String,
    retry_policy: RetryPolicy,
    preconditions: Vec<ContentDigest>,
) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
        effect_id: record(1)?,
        connector: connector.to_owned(),
        operation: operation.to_owned(),
        arguments_digest: arguments_digest.clone(),
        encrypted_arguments: BlobRef {
            digest: arguments_digest,
            size_bytes: 32,
            media_type: MediaType::new("application/octet-stream")?,
        },
        target,
        preconditions,
        result_schema_digest: digest(b"result-schema")?,
        risk: RiskLevel::Low,
        source_decision_id: VersionId::new(digest(b"decision")?.as_str())?,
        bundle_id: VersionId::new(digest(b"bundle")?.as_str())?,
        required_capability: Capability::InvokeTool,
        idempotency_scope: "tenant-a".to_owned(),
        idempotency_key: IdempotencyKey::new("reference-key-1")?,
        retry_policy,
        created_at: UtcTimestamp::from_unix_nanos(1)?,
        expires_at: UtcTimestamp::from_unix_nanos(10_000_000_000)?,
        compensation: None,
        extensions: ExtensionMap::default(),
    })
}

fn authorization(
    actor: u64,
    now: i128,
    capabilities: impl IntoIterator<Item = Capability>,
) -> Result<EffectAuthorization, Box<dyn Error>> {
    Ok(EffectAuthorization {
        actor_id: record(actor)?,
        capabilities: capabilities.into_iter().collect(),
        policy_allows: true,
        now: UtcTimestamp::from_unix_nanos(now)?,
    })
}

fn dispatch_once(
    connector: Arc<dyn EffectConnector>,
    intent: EffectIntent,
    identity_base: u64,
) -> Result<(EffectEngine<InMemoryStore>, DurableEffectRecord), Box<dyn Error>> {
    let engine = EffectEngine::new(
        Arc::new(InMemoryStore::default()),
        AccessContext::new(record(identity_base)?, "reference-connector-test")?,
    );
    engine.register_connector(connector)?;
    let proposal = authorization(
        identity_base.saturating_add(1),
        2,
        [Capability::ProposeEffect],
    )?;
    let dispatch = authorization(
        identity_base.saturating_add(2),
        3,
        [
            Capability::ApproveEffect,
            Capability::InvokeTool,
            Capability::ReconcileEffect,
        ],
    )?;
    let prepared = engine.prepare(intent, &proposal)?;
    let authorized = engine.authorize(
        &prepared.intent.effect_id,
        prepared.effect_version,
        record(identity_base.saturating_add(3))?,
        None,
        &dispatch,
    )?;
    let permit = engine.claim_dispatch(
        &authorized.intent.effect_id,
        authorized.effect_version,
        record(identity_base.saturating_add(4))?,
        record(identity_base.saturating_add(5))?,
        record(identity_base.saturating_add(6))?,
        UtcTimestamp::from_unix_nanos(4_000_000_000)?,
        &EffectAuthorization {
            now: UtcTimestamp::from_unix_nanos(4)?,
            ..dispatch.clone()
        },
    )?;
    let completed = engine.dispatch(
        permit,
        record(identity_base.saturating_add(7))?,
        record(identity_base.saturating_add(8))?,
        &EffectAuthorization {
            now: UtcTimestamp::from_unix_nanos(5)?,
            ..dispatch
        },
    )?;
    Ok((engine, completed))
}

#[test]
fn demo_service_reconciles_commit_after_response_loss_without_duplicate() -> TestResult {
    let service = Arc::new(DemoIssueService::default());
    let connector = DemoIssueConnector::new("reference.demo", service.clone())?;
    let arguments = connector.stage_request(DemoIssueRequest::new(
        "project-a",
        "A bounded title",
        "Protected body",
    )?)?;
    let intent = intent(
        "reference.demo",
        "create_issue",
        arguments,
        "project-a".to_owned(),
        RetryPolicy::SameKeyIdempotent { max_attempts: 3 },
        Vec::new(),
    )?;

    service.set_next_mode(DemoDispatchMode::CommitThenLoseResponse)?;
    let (engine, unknown) = dispatch_once(Arc::new(connector), intent, 100)?;
    assert_eq!(unknown.state, EffectState::Unknown);
    assert_eq!(service.issues()?.len(), 1);
    let reconciled = engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(109)?,
        record(110)?,
        &authorization(111, 6, [Capability::ReconcileEffect])?,
    )?;
    assert_eq!(reconciled.state, EffectState::Succeeded);
    assert_eq!(service.issues()?.len(), 1);
    Ok(())
}

#[test]
fn filesystem_connector_confines_and_atomically_verifies_writes() -> TestResult {
    let root = TemporaryDirectory::new("filesystem")?;
    fs::create_dir(root.path().join("nested"))?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", root.path())?;
    let request = FilesystemWriteRequest::new("nested/result.txt", b"verified".to_vec(), None)?;
    let arguments = connector.stage_write(request)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "nested/result.txt".to_owned(),
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        Vec::new(),
    )?;
    let (_engine, completed) = dispatch_once(Arc::new(connector), intent, 120)?;
    assert_eq!(completed.state, EffectState::Succeeded);
    assert_eq!(
        fs::read(root.path().join("nested/result.txt"))?,
        b"verified"
    );
    assert_eq!(
        FilesystemWriteRequest::new("../escape", Vec::new(), None)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::InvalidInput)
    );
    assert_eq!(
        FilesystemWriteRequest::new(".cigar-effect-write.lock", Vec::new(), None)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn filesystem_connector_binds_exact_existing_content_precondition() -> TestResult {
    let root = TemporaryDirectory::new("filesystem-precondition")?;
    let target = root.path().join("result.txt");
    fs::write(&target, b"expected")?;
    let expected = FilesystemEffectConnector::content_digest(b"expected")?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", root.path())?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "result.txt",
        b"replacement".to_vec(),
        Some(expected.clone()),
    )?)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "result.txt".to_owned(),
        RetryPolicy::Never,
        vec![expected],
    )?;
    assert!(
        connector
            .check_preconditions(&intent, UtcTimestamp::from_unix_nanos(2)?)?
            .satisfied
    );

    fs::write(&target, b"raced")?;
    let (_engine, completed) = dispatch_once(Arc::new(connector), intent, 140)?;
    assert_eq!(completed.state, EffectState::Failed);
    assert_eq!(fs::read(target)?, b"raced");
    Ok(())
}

#[cfg(unix)]
#[test]
fn filesystem_connector_never_mutates_while_the_root_write_fence_is_owned() -> TestResult {
    use rustix::fs::{FlockOperation, flock};

    let root = TemporaryDirectory::new("filesystem-write-fence")?;
    let target = root.path().join("result.txt");
    fs::write(&target, b"expected")?;
    let expected = FilesystemEffectConnector::content_digest(b"expected")?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", root.path())?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "result.txt",
        b"replacement".to_vec(),
        Some(expected.clone()),
    )?)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "result.txt".to_owned(),
        RetryPolicy::Never,
        vec![expected],
    )?;

    let fence = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.path().join(".cigar-effect-write.lock"))?;
    flock(&fence, FlockOperation::NonBlockingLockExclusive)?;
    let (_engine, completed) = dispatch_once(Arc::new(connector), intent, 150)?;
    assert_eq!(completed.state, EffectState::Unknown);
    assert_eq!(fs::read(target)?, b"expected");
    Ok(())
}

#[test]
fn filesystem_connector_exposes_ambiguous_stale_attempt_without_writing() -> TestResult {
    let root = TemporaryDirectory::new("filesystem-ambiguous")?;
    let identity_base = 160_u64;
    let attempt = record(identity_base.saturating_add(4))?;
    let stale_temporary = root
        .path()
        .join(format!(".cigar-{}-1.tmp", attempt.as_str()));
    fs::write(&stale_temporary, b"indeterminate prior attempt")?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", root.path())?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "result.txt",
        b"new value".to_vec(),
        None,
    )?)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "result.txt".to_owned(),
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        Vec::new(),
    )?;
    let (engine, unknown) = dispatch_once(Arc::new(connector), intent, identity_base)?;
    assert_eq!(unknown.state, EffectState::Unknown);
    assert!(!root.path().join("result.txt").exists());
    fs::remove_file(stale_temporary)?;
    fs::write(root.path().join("result.txt"), b"new value")?;
    let reconciled = engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(169)?,
        record(170)?,
        &authorization(171, 6, [Capability::ReconcileEffect])?,
    )?;
    assert_eq!(reconciled.state, EffectState::Succeeded);
    Ok(())
}

#[cfg(unix)]
#[test]
fn filesystem_connector_rejects_symlinked_parent() -> TestResult {
    use std::os::unix::fs::symlink;

    let root = TemporaryDirectory::new("filesystem-root")?;
    let outside = TemporaryDirectory::new("filesystem-outside")?;
    symlink(outside.path(), root.path().join("escape"))?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", root.path())?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "escape/result.txt",
        b"blocked".to_vec(),
        None,
    )?)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "escape/result.txt".to_owned(),
        RetryPolicy::Never,
        Vec::new(),
    )?;

    assert_eq!(
        connector
            .check_preconditions(&intent, UtcTimestamp::from_unix_nanos(2)?)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );
    assert!(!outside.path().join("result.txt").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn filesystem_connector_rejects_symlink_root_and_target() -> TestResult {
    use std::os::unix::fs::symlink;

    let real_root = TemporaryDirectory::new("filesystem-real-root")?;
    let root_link_parent = TemporaryDirectory::new("filesystem-root-link")?;
    let root_link = root_link_parent.path().join("linked-root");
    symlink(real_root.path(), &root_link)?;
    assert_eq!(
        FilesystemEffectConnector::new("reference.filesystem", &root_link)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::InvalidInput)
    );

    let outside = TemporaryDirectory::new("filesystem-target-outside")?;
    fs::write(outside.path().join("outside.txt"), b"outside")?;
    symlink(
        outside.path().join("outside.txt"),
        real_root.path().join("target.txt"),
    )?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", real_root.path())?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "target.txt",
        b"blocked".to_vec(),
        None,
    )?)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "target.txt".to_owned(),
        RetryPolicy::Never,
        Vec::new(),
    )?;
    assert_eq!(
        connector
            .check_preconditions(&intent, UtcTimestamp::from_unix_nanos(2)?)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );
    assert_eq!(fs::read(outside.path().join("outside.txt"))?, b"outside");
    Ok(())
}

#[cfg(unix)]
#[test]
fn filesystem_connector_pins_root_descriptor_across_path_substitution() -> TestResult {
    let container = TemporaryDirectory::new("filesystem-root-substitution")?;
    let configured = container.path().join("configured");
    let original = container.path().join("original");
    fs::create_dir(&configured)?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", &configured)?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "result.txt",
        b"descriptor-pinned".to_vec(),
        None,
    )?)?;
    let intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "result.txt".to_owned(),
        RetryPolicy::Never,
        Vec::new(),
    )?;

    fs::rename(&configured, &original)?;
    fs::create_dir(&configured)?;
    let (_engine, completed) = dispatch_once(Arc::new(connector), intent, 10_180)?;
    assert_eq!(completed.state, EffectState::Succeeded);
    assert_eq!(fs::read(original.join("result.txt"))?, b"descriptor-pinned");
    assert!(!configured.join("result.txt").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn filesystem_connector_rejects_writable_directories_hardlinks_and_fence_substitution() -> TestResult
{
    use std::os::unix::fs::PermissionsExt as _;

    let unsafe_root = TemporaryDirectory::new("filesystem-writable-root")?;
    fs::set_permissions(unsafe_root.path(), fs::Permissions::from_mode(0o770))?;
    assert_eq!(
        FilesystemEffectConnector::new("reference.filesystem", unsafe_root.path())
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );

    let root = TemporaryDirectory::new("filesystem-owned-metadata")?;
    let nested = root.path().join("nested");
    fs::create_dir(&nested)?;
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o770))?;
    let connector = FilesystemEffectConnector::new("reference.filesystem", root.path())?;
    let arguments = connector.stage_write(FilesystemWriteRequest::new(
        "nested/result.txt",
        b"blocked".to_vec(),
        None,
    )?)?;
    let nested_intent = intent(
        "reference.filesystem",
        "write_file",
        arguments,
        "nested/result.txt".to_owned(),
        RetryPolicy::Never,
        Vec::new(),
    )?;
    assert_eq!(
        connector
            .check_preconditions(&nested_intent, UtcTimestamp::from_unix_nanos(2)?)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );

    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))?;
    fs::write(root.path().join("linked.txt"), b"linked")?;
    fs::hard_link(
        root.path().join("linked.txt"),
        root.path().join("linked-copy.txt"),
    )?;
    let linked = FilesystemEffectConnector::content_digest(b"linked")?;
    let linked_arguments = connector.stage_write(FilesystemWriteRequest::new(
        "linked.txt",
        b"replacement".to_vec(),
        Some(linked.clone()),
    )?)?;
    let linked_intent = intent(
        "reference.filesystem",
        "write_file",
        linked_arguments,
        "linked.txt".to_owned(),
        RetryPolicy::Never,
        vec![linked],
    )?;
    assert_eq!(
        connector
            .check_preconditions(&linked_intent, UtcTimestamp::from_unix_nanos(2)?)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );

    fs::remove_file(root.path().join(".cigar-effect-write.lock"))?;
    fs::write(
        root.path().join(".cigar-effect-write.lock"),
        b"replacement-fence",
    )?;
    let clean_arguments = connector.stage_write(FilesystemWriteRequest::new(
        "clean.txt",
        b"must-not-write".to_vec(),
        None,
    )?)?;
    let clean_intent = intent(
        "reference.filesystem",
        "write_file",
        clean_arguments,
        "clean.txt".to_owned(),
        RetryPolicy::Never,
        Vec::new(),
    )?;
    let (_engine, completed) = dispatch_once(Arc::new(connector), clean_intent, 10_200)?;
    assert_eq!(completed.state, EffectState::Unknown);
    assert!(!root.path().join("clean.txt").exists());
    Ok(())
}

struct RecordingHttpTransport {
    sends: Mutex<Vec<(String, HttpMethod, String, usize)>>,
    request_debug: Mutex<Vec<String>>,
    success_digest: ContentDigest,
}

impl HttpTransport for RecordingHttpTransport {
    fn security(&self) -> Result<HttpTransportSecurity, EffectError> {
        HttpTransportSecurity::new(
            "https://example.invalid/fixed",
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            true,
            true,
            true,
        )
    }

    fn validate_resource_binding(
        &self,
        request: &HttpResourceBindingRequest<'_>,
    ) -> Result<(), EffectError> {
        let expected_project =
            record(181).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if request.endpoint() != "https://example.invalid/fixed"
            || request.method() != HttpMethod::Post
            || request.content_type() != "application/json"
            || request.body() != br#"{"safe":true}"#
            || request.resource_scope().project_id() != &expected_project
            || request.resource_scope().resource_id() != "remote-object-1"
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        Ok(())
    }

    fn send(
        &self,
        request: &HttpTransportRequest<'_>,
    ) -> Result<HttpTransportObservation, EffectError> {
        if request.pinned_addresses()
            != &BTreeSet::from([IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            || request.project_id().as_str()
                != record(181)
                    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
                    .as_str()
            || request.resource_id() != "remote-object-1"
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        self.request_debug
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .push(format!("{request:?}"));
        self.sends
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .push((
                request.endpoint().to_owned(),
                request.method(),
                request.idempotency_key().as_str().to_owned(),
                request.body().len(),
            ));
        Ok(HttpTransportObservation::Succeeded {
            remote_operation_id: "remote-http-1".to_owned(),
            response_digest: self.success_digest.clone(),
            verification_digest: self.success_digest.clone(),
        })
    }

    fn lookup(
        &self,
        _query: &HttpTransportQuery<'_>,
    ) -> Result<HttpLookupObservation, EffectError> {
        Ok(HttpLookupObservation::ConfirmedSuccess(
            self.success_digest.clone(),
        ))
    }
}

#[test]
fn http_connector_uses_only_the_fixed_endpoint_and_exact_idempotency_key() -> TestResult {
    let transport = Arc::new(RecordingHttpTransport {
        sends: Mutex::new(Vec::new()),
        request_debug: Mutex::new(Vec::new()),
        success_digest: digest(b"http-success")?,
    });
    let connector = IdempotentHttpConnector::new(
        "reference.http",
        "https://example.invalid/fixed",
        transport.clone(),
    )?;
    let request = IdempotentHttpRequest::new_scoped(
        HttpMethod::Post,
        "application/json",
        br#"{"safe":true}"#.to_vec(),
        HttpResourceScope::new(record(181)?, "remote-object-1")?,
    )?;
    let target = request.authorization_target("https://example.invalid/fixed")?;
    let arguments = connector.stage_request(request)?;
    let intent = intent(
        "reference.http",
        "send",
        arguments,
        target,
        RetryPolicy::SameKeyIdempotent { max_attempts: 3 },
        Vec::new(),
    )?;
    let mut wrong_object_authority = intent.clone();
    wrong_object_authority.target = "https://example.invalid/fixed".to_owned();
    assert!(
        !connector
            .check_preconditions(&wrong_object_authority, UtcTimestamp::from_unix_nanos(2)?)?
            .satisfied
    );
    let debug = format!("{connector:?}");
    assert!(!debug.contains("reference-key-1"));
    assert!(!debug.contains(r#"{"safe":true}"#));
    let (_engine, completed) = dispatch_once(Arc::new(connector), intent, 180)?;
    assert_eq!(completed.state, EffectState::Succeeded);
    let sends = transport
        .sends
        .lock()
        .map_err(|_error| std::io::Error::other("recording transport poisoned"))?;
    assert_eq!(
        sends.first(),
        Some(&(
            "https://example.invalid/fixed".to_owned(),
            HttpMethod::Post,
            "reference-key-1".to_owned(),
            13,
        ))
    );
    let request_debug = transport
        .request_debug
        .lock()
        .map_err(|_error| std::io::Error::other("recording transport poisoned"))?;
    let Some(request_debug) = request_debug.first() else {
        return Err(std::io::Error::other("missing HTTP transport debug value").into());
    };
    assert!(!request_debug.contains("reference-key-1"));
    assert!(!request_debug.contains(r#"{"safe":true}"#));
    assert_eq!(
        IdempotentHttpConnector::new("reference.http", "http://unsafe.invalid", transport.clone(),)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::InvalidInput)
    );
    for invalid in [
        "https://127.0.0.1/fixed",
        "https://169.254.169.254/latest/meta-data",
        "https://user@example.invalid/fixed",
        "https://example.invalid/fixed?query=1",
        "https://example.invalid/fixed#fragment",
        "https://example.invalid/a/../fixed",
        "https://example.invalid/%2e/fixed",
        "https://example.invalid\\fixed",
        "https://EXAMPLE.invalid/fixed",
        "https://example.invalid//fixed",
        "https://example.invalid:443/fixed",
        "https://éxample.invalid/fixed",
    ] {
        assert_eq!(
            IdempotentHttpConnector::new("reference.http", invalid, transport.clone())
                .err()
                .map(EffectError::code),
            Some(EffectErrorCode::InvalidInput),
            "endpoint should be rejected: {invalid}"
        );
    }
    Ok(())
}

#[test]
fn http_connector_rejects_opaque_body_without_a_typed_resource_scope() -> TestResult {
    assert_eq!(
        IdempotentHttpRequest::new(
            HttpMethod::Post,
            "application/json",
            br#"{"project_id":"01890f47-8e7d-7b42-a1d2-3c4d5e6f7890"}"#.to_vec(),
        )
        .err()
        .map(EffectError::code),
        Some(EffectErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn http_connector_rejects_body_that_does_not_match_the_declared_resource() -> TestResult {
    let transport = Arc::new(RecordingHttpTransport {
        sends: Mutex::new(Vec::new()),
        request_debug: Mutex::new(Vec::new()),
        success_digest: digest(b"http-success")?,
    });
    let connector =
        IdempotentHttpConnector::new("reference.http", "https://example.invalid/fixed", transport)?;
    let mismatched = IdempotentHttpRequest::new_scoped(
        HttpMethod::Post,
        "application/json",
        br#"{"safe":false}"#.to_vec(),
        HttpResourceScope::new(record(181)?, "remote-object-1")?,
    )?;
    assert_eq!(
        connector
            .stage_request(mismatched)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );
    Ok(())
}

struct UnattestedHttpTransport;

impl HttpTransport for UnattestedHttpTransport {
    fn send(
        &self,
        _request: &HttpTransportRequest<'_>,
    ) -> Result<HttpTransportObservation, EffectError> {
        Err(EffectError::new(EffectErrorCode::Unavailable))
    }

    fn lookup(
        &self,
        _query: &HttpTransportQuery<'_>,
    ) -> Result<HttpLookupObservation, EffectError> {
        Err(EffectError::new(EffectErrorCode::Unavailable))
    }
}

#[test]
fn http_connector_requires_pinned_public_no_redirect_idempotency_evidence() -> TestResult {
    let endpoint = "https://example.invalid/fixed";
    assert_eq!(
        IdempotentHttpConnector::new(
            "reference.http.unattested",
            endpoint,
            Arc::new(UnattestedHttpTransport),
        )
        .err()
        .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );
    for evidence in [
        HttpTransportSecurity::new(
            endpoint,
            [IpAddr::V4(Ipv4Addr::LOCALHOST)],
            true,
            true,
            true,
        ),
        HttpTransportSecurity::new(
            endpoint,
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            false,
            true,
            true,
        ),
        HttpTransportSecurity::new(
            endpoint,
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            true,
            false,
            true,
        ),
        HttpTransportSecurity::new(
            endpoint,
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            true,
            true,
            false,
        ),
    ] {
        assert_eq!(
            evidence.err().map(EffectError::code),
            Some(EffectErrorCode::Unauthorized)
        );
    }
    for unsafe_address in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "::ffff:169.254.169.254",
        "64:ff9b::169.254.169.254",
        "100::1",
        "2001::1",
        "2001:2::1",
        "2001:db8::1",
        "2002::1",
        "3fff::1",
        "fc00::1",
        "fe80::1",
        "ff00::1",
    ] {
        let address = unsafe_address.parse::<IpAddr>()?;
        assert_eq!(
            HttpTransportSecurity::new(endpoint, [address], true, true, true)
                .err()
                .map(EffectError::code),
            Some(EffectErrorCode::Unauthorized),
            "non-public target should be rejected: {unsafe_address}"
        );
    }
    let public_ipv6 = "2606:4700:4700::1111".parse::<IpAddr>()?;
    assert!(HttpTransportSecurity::new(endpoint, [public_ipv6], true, true, true).is_ok());
    let excessive_addresses = (1_u8..=17)
        .map(|host| IpAddr::V4(Ipv4Addr::new(93, 184, 216, host)))
        .collect::<Vec<_>>();
    assert_eq!(
        HttpTransportSecurity::new(endpoint, excessive_addresses, true, true, true)
            .err()
            .map(EffectError::code),
        Some(EffectErrorCode::Unauthorized)
    );
    Ok(())
}

struct ErrorHttpTransport;

impl HttpTransport for ErrorHttpTransport {
    fn security(&self) -> Result<HttpTransportSecurity, EffectError> {
        HttpTransportSecurity::new(
            "https://example.invalid/fixed",
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            true,
            true,
            true,
        )
    }

    fn validate_resource_binding(
        &self,
        request: &HttpResourceBindingRequest<'_>,
    ) -> Result<(), EffectError> {
        let expected_project =
            record(201).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if request.endpoint() != "https://example.invalid/fixed"
            || request.method() != HttpMethod::Put
            || request.content_type() != "application/octet-stream"
            || request.body() != b"protected"
            || request.resource_scope().project_id() != &expected_project
            || request.resource_scope().resource_id() != "remote-object-2"
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        Ok(())
    }

    fn send(
        &self,
        _request: &HttpTransportRequest<'_>,
    ) -> Result<HttpTransportObservation, EffectError> {
        Err(EffectError::new(EffectErrorCode::Unavailable))
    }

    fn lookup(
        &self,
        _query: &HttpTransportQuery<'_>,
    ) -> Result<HttpLookupObservation, EffectError> {
        Err(EffectError::new(EffectErrorCode::Unavailable))
    }
}

#[test]
fn engine_converts_http_transport_error_to_explicit_unknown() -> TestResult {
    let connector = IdempotentHttpConnector::new(
        "reference.http.error",
        "https://example.invalid/fixed",
        Arc::new(ErrorHttpTransport),
    )?;
    let request = IdempotentHttpRequest::new_scoped(
        HttpMethod::Put,
        "application/octet-stream",
        b"protected".to_vec(),
        HttpResourceScope::new(record(201)?, "remote-object-2")?,
    )?;
    let target = request.authorization_target("https://example.invalid/fixed")?;
    let arguments = connector.stage_request(request)?;
    let intent = intent(
        "reference.http.error",
        "send",
        arguments,
        target,
        RetryPolicy::SameKeyIdempotent { max_attempts: 2 },
        Vec::new(),
    )?;
    let (_engine, completed) = dispatch_once(Arc::new(connector), intent, 200)?;
    assert_eq!(completed.state, EffectState::Unknown);
    assert_eq!(completed.receipts.len(), 1);
    Ok(())
}

#[test]
fn github_connector_searches_a_hashed_marker_before_any_retry() -> TestResult {
    let service = Arc::new(MockGitHubIssueService::default());
    let connector = GitHubIssueConnector::new("reference.github", service.clone())?;
    let request = GitHubIssueRequest::new("cigar", "honey", "Fault", "Protected details")?;
    let target = request.target();
    let arguments = connector.stage_request(request)?;
    let intent = intent(
        "reference.github",
        "create_issue",
        arguments,
        target,
        RetryPolicy::ReconcileBeforeRetry,
        Vec::new(),
    )?;
    service.set_next_mode(MockGitHubDispatchMode::LoseBeforeCommit)?;
    let (engine, unknown) = dispatch_once(Arc::new(connector), intent, 220)?;
    assert_eq!(unknown.state, EffectState::Unknown);
    assert!(service.issues()?.is_empty());
    let reconciliation_authorization = authorization(229, 6, [Capability::ReconcileEffect])?;
    let retry_authorized = engine.reconcile(
        &unknown.intent.effect_id,
        unknown.effect_version,
        record(230)?,
        record(231)?,
        &reconciliation_authorization,
    )?;
    assert_eq!(retry_authorized.state, EffectState::AuthorizedForRetry);
    let retry_dispatch_authorization =
        authorization(232, 7, [Capability::ApproveEffect, Capability::InvokeTool])?;
    let retry_permit = engine.claim_dispatch(
        &retry_authorized.intent.effect_id,
        retry_authorized.effect_version,
        record(233)?,
        record(234)?,
        record(235)?,
        UtcTimestamp::from_unix_nanos(5_000_000_000)?,
        &retry_dispatch_authorization,
    )?;
    let succeeded = engine.dispatch(
        retry_permit,
        record(236)?,
        record(237)?,
        &EffectAuthorization {
            now: UtcTimestamp::from_unix_nanos(8)?,
            ..retry_dispatch_authorization
        },
    )?;
    assert_eq!(succeeded.state, EffectState::Succeeded);
    let issues = service.issues()?;
    assert_eq!(issues.len(), 1);
    let Some(issue) = issues.first() else {
        return Err(std::io::Error::other("missing mock issue").into());
    };
    assert!(
        !issue
            .marker
            .contains(succeeded.intent.idempotency_key.as_str())
    );
    Ok(())
}

static NEXT_TEMPORARY_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Result<Self, std::io::Error> {
        for _attempt in 0..100 {
            let sequence = NEXT_TEMPORARY_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cigar-effects-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate temporary test directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.path);
    }
}
