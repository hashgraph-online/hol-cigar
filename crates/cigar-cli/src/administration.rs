//! Durable local administration and installed-component entry points.

use crate::arguments::{ParsedInvocation, TargetKind};
use crate::client::OperationResponse;
use crate::configuration::EffectiveConfiguration;
use crate::error::CliError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_crypto::{EncryptedDevelopmentKeystore, KeyProvider, KeyPurpose, KeyRef, SecretBytes};
use cigar_store::{
    BACKUP_DATABASE_FILE, BACKUP_EFFECT_CHECKPOINT_FILE, BackupError, BackupErrorCode,
    BackupIdentity, GarbageCollectionPlanError, GarbageCollectionPlanErrorCode,
    GarbageCollectionPlanIdentity, GarbageCollectionPlanSignatureIdentity, GarbageCollectionPolicy,
    MultiTenantLocalRepositoryBlobStore, RepositoryBlobStore, SignedGarbageCollectionPlan,
    SqliteStore, StoreError, StoreErrorCode, create_backup_with_effect_checkpoint,
    restore_backup_trusted, sign_garbage_collection_plan, verify_backup_trusted,
    verify_garbage_collection_plan_trusted,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

const MAX_BLOCKING_ADMINISTRATION_TASKS: usize = 4;

const STATE_SCHEMA: &str = "cigar.cli-administration.v1";
const STATE_FILE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ADMIN_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_SECRET_BYTES: u64 = 16 * 1024;
const MAX_GC_FILES: usize = 1_000_000;
const DEFAULT_GC_FILES: usize = 1_000;
const MAX_SIGNED_GC_PLAN_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GcPolicyDocument {
    schema_version: GcPolicySchema,
    retention_satisfied: bool,
    legal_hold: bool,
    backup_complete: bool,
    #[serde(default = "default_gc_files")]
    max_files: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum GcPolicySchema {
    #[serde(rename = "cigar.gc-policy.v1")]
    V1,
}

const fn default_gc_files() -> usize {
    DEFAULT_GC_FILES
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectListCursorDocument {
    schema_version: String,
    tenant_id: cigar_protocol::RecordId,
    revision: Option<u64>,
    last_effect_id: Option<cigar_protocol::RecordId>,
}

const EFFECT_LIST_CURSOR_SCHEMA: &str = "cigar.cli-effect-list-cursor.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PolicyCheckDocument {
    resource: cigar_policy::PolicyResource,
    input_digest: cigar_protocol::ContentDigest,
    principal_id: cigar_protocol::RecordId,
    principal_active: bool,
    tenant_id: cigar_protocol::RecordId,
    authenticated_tenant_id: cigar_protocol::RecordId,
    project_id: Option<cigar_protocol::RecordId>,
    allowed_project_ids: BTreeSet<cigar_protocol::RecordId>,
    purpose: String,
    allowed_purposes: BTreeSet<String>,
    processor: Option<String>,
    allowed_processors: BTreeSet<String>,
    classification: cigar_protocol::Classification,
    maximum_classification: cigar_protocol::Classification,
    residency_allowed: bool,
    egress_allowed: bool,
    lifecycle: cigar_protocol::Lifecycle,
    integrity_verified: bool,
    valid_at: cigar_protocol::UtcTimestamp,
    valid_from: cigar_protocol::UtcTimestamp,
    valid_until: Option<cigar_protocol::UtcTimestamp>,
    observed_at: cigar_protocol::UtcTimestamp,
    observed_as_of: cigar_protocol::UtcTimestamp,
    freshness_expires_at: Option<cigar_protocol::UtcTimestamp>,
    instruction_authority: cigar_protocol::InstructionAuthority,
    maximum_instruction_authority: cigar_protocol::InstructionAuthority,
    excluded: bool,
    modality_supported: bool,
    capability: Option<PolicyCapabilityDocument>,
    required_capability: Option<cigar_protocol::Capability>,
    bound_policy_digest: Option<cigar_protocol::ContentDigest>,
    effect_risk: Option<cigar_protocol::RiskLevel>,
    effect_approved: bool,
    effect_constraints_satisfied: bool,
    fencing_required: bool,
    fencing_verified: bool,
    decision_expires_at: cigar_protocol::UtcTimestamp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PolicyCapabilityDocument {
    subject_id: cigar_protocol::RecordId,
    grant_id: Option<cigar_protocol::RecordId>,
    capabilities: BTreeSet<cigar_protocol::Capability>,
    project_ids: BTreeSet<cigar_protocol::RecordId>,
    processors: BTreeSet<String>,
    expires_at: cigar_protocol::UtcTimestamp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalState {
    schema_version: String,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_focus: Option<String>,
    projects: BTreeMap<String, ProjectEntry>,
    sources: BTreeMap<String, SourceEntry>,
    links: BTreeSet<ProjectLink>,
}

impl Default for LocalState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA.to_owned(),
            generation: 1,
            active_project: None,
            active_focus: None,
            projects: BTreeMap::new(),
            sources: BTreeMap::new(),
            links: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectEntry {
    path: PathBuf,
    attached: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceEntry {
    path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectLink {
    from: String,
    to: String,
}

#[derive(Clone, Debug)]
pub(crate) struct BlockingCancellation(Arc<AtomicBool>);

impl BlockingCancellation {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn checkpoint(&self) -> Result<(), CliError> {
        if self.0.load(Ordering::Acquire) {
            Err(CliError::interrupted())
        } else {
            Ok(())
        }
    }
}

struct CancelBlockingOnDrop(BlockingCancellation);

impl Drop for CancelBlockingOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) async fn execute(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<OperationResponse, CliError> {
    if configuration.target() == TargetKind::Remote {
        return Err(CliError::unsupported_surface());
    }
    let path = invocation.command.path();
    let result = match path {
        "serve" => serve(invocation, configuration).await?,
        "mcp.serve" => mcp_serve(invocation).await?,
        "plugin.install" => crate::claude_plugin::install(invocation).await?,
        "plugin.uninstall" => crate::claude_plugin::uninstall(invocation).await?,
        "plugin.doctor" => crate::claude_plugin::doctor(invocation).await?,
        "release.verify" => release_verify(invocation).await?,
        _ => {
            return execute_blocking_bounded(invocation.clone(), configuration.clone()).await;
        }
    };
    Ok(operation_response(path, result, None))
}

async fn execute_blocking_bounded(
    invocation: ParsedInvocation,
    configuration: EffectiveConfiguration,
) -> Result<OperationResponse, CliError> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let cancellation = BlockingCancellation::new();
    let cancel_on_drop = CancelBlockingOnDrop(cancellation.clone());
    let slots = Arc::clone(SLOTS.get_or_init(|| {
        Arc::new(tokio::sync::Semaphore::new(
            MAX_BLOCKING_ADMINISTRATION_TASKS,
        ))
    }));
    let permit = slots
        .acquire_owned()
        .await
        .map_err(|_closed| CliError::state_unavailable())?;
    cancellation.checkpoint()?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker_cancellation = cancellation.clone();
    std::thread::Builder::new()
        .name("cigar-cli-administration".to_owned())
        .spawn(move || {
            let result = execute_blocking(&invocation, &configuration, &worker_cancellation);
            let _ignored = sender.send(result);
            drop(permit);
        })
        .map_err(|_error| CliError::state_unavailable())?;
    let result = receiver
        .await
        .map_err(|_closed| CliError::state_unavailable())?;
    drop(cancel_on_drop);
    result
}

fn execute_blocking(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<OperationResponse, CliError> {
    cancellation.checkpoint()?;
    let path = invocation.command.path();
    let mut next_page_cursor = None;
    let result = match path {
        "init" => initialize(invocation, configuration, cancellation)?,
        "source.add" => source_add(invocation, configuration, cancellation)?,
        "source.list" => source_list(invocation, configuration)?,
        "source.remove" => source_remove(invocation, configuration, cancellation)?,
        "project.list" => project_list(invocation, configuration)?,
        "project.attach" => project_attach(invocation, configuration, cancellation)?,
        "project.detach" => project_detach(invocation, configuration, cancellation)?,
        "project.switch" => project_switch(invocation, configuration, cancellation)?,
        "project.link" => project_link(invocation, configuration, cancellation)?,
        "project.unlink" => project_unlink(invocation, configuration, cancellation)?,
        "focus.switch" => focus_switch(invocation, configuration, cancellation)?,
        "focus.close" => focus_close(invocation, configuration, cancellation)?,
        "backup.create" => backup_create(invocation, configuration, cancellation)?,
        "backup.verify" => backup_verify(invocation, configuration)?,
        "backup.restore" => backup_restore(invocation, configuration, cancellation)?,
        "gc.plan" => gc_plan(invocation, configuration, cancellation)?,
        "gc.run" => gc_run(invocation, configuration, cancellation)?,
        "diagnostics.bundle" => diagnostics_bundle(invocation, configuration, cancellation)?,
        "state.inspect-beta" => inspect_beta_state(invocation)?,
        #[cfg(unix)]
        "state.import-beta" => import_beta_state(invocation, configuration, cancellation)?,
        #[cfg(unix)]
        "state.restore-beta" => restore_beta_state(invocation, configuration, cancellation)?,
        "effect.list" => {
            let (result, cursor) = effect_list(invocation, configuration)?;
            next_page_cursor = cursor;
            result
        }
        "policy.check" => policy_check(invocation, configuration, false)?,
        "policy.explain" => policy_check(invocation, configuration, true)?,
        "doctor" if invocation.options.security || invocation.options.deep => {
            security_doctor(invocation, configuration)?
        }
        _ => return Err(CliError::invalid_command()),
    };
    cancellation.checkpoint()?;
    Ok(operation_response(path, result, next_page_cursor))
}

fn inspect_beta_state(invocation: &ParsedInvocation) -> Result<Value, CliError> {
    if invocation.options.yes
        || invocation.options.input.is_some()
        || invocation.options.idempotency_key.is_some()
        || invocation.options.expected_revision.is_some()
        || invocation.options.page_cursor.is_some()
        || invocation.options.page_size.is_some()
    {
        return Err(CliError::invalid_command());
    }
    let path = Path::new(exact_one(&invocation.positionals)?);
    let bytes = read_frozen_beta_state_file(path)?;
    let state = crate::beta_state_compat::decode_frozen_beta_state(&bytes)
        .map_err(|_error| CliError::beta_state_invalid())?;
    let summary = state.summary();
    let byte_count = u64::try_from(bytes.len()).map_err(|_error| CliError::beta_state_invalid())?;
    let digest = sha256_digest(&bytes);

    Ok(json!({
        "schema_version": "cigar.beta-state-transition-plan.v1",
        "source": {
            "release": crate::beta_state_compat::FROZEN_BETA_RELEASE,
            "state_schema": crate::beta_state_compat::FROZEN_BETA_STATE_SCHEMA,
            "sha256": digest,
            "byte_count": byte_count,
            "generation": summary.generation,
            "project_count": summary.project_count,
            "source_count": summary.source_count,
            "link_count": summary.link_count,
            "active_project_present": summary.has_active_project,
            "active_focus_present": summary.has_active_focus
        },
        "inspection": {
            "status": "validated",
            "mode": "read-only",
            "content_free": true,
            "identifiers_emitted": false,
            "paths_emitted": false,
            "input_bytes_preserved": true,
            "identifiers_preserved": true,
            "paths_preserved": true,
            "generation_preserved": true
        },
        "transition": {
            "application": {
                "status": "explicit-command-required",
                "command": "state.import-beta",
                "precondition": "verified-exact-byte-backup"
            },
            "downgrade": {
                "status": "blocked",
                "reason_code": "BETA_DOWNGRADE_NOT_SUPPORTED"
            },
            "mutation_performed": false
        }
    }))
}

#[cfg(unix)]
fn import_beta_state(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    require_beta_transition_options(invocation)?;
    let [source, backup] = exact_two(&invocation.positionals)?;
    crate::beta_state_transition::import_beta_state(
        Path::new(source),
        Path::new(backup),
        configuration.project_state_directory(),
        invocation.options.dry_run,
        cancellation,
    )
}

#[cfg(unix)]
fn restore_beta_state(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    require_beta_transition_options(invocation)?;
    let [backup, recovery_target] = exact_two(&invocation.positionals)?;
    crate::beta_state_transition::restore_beta_backup(
        Path::new(backup),
        Path::new(recovery_target),
        configuration.project_state_directory(),
        invocation.options.dry_run,
        cancellation,
    )
}

#[cfg(unix)]
fn require_beta_transition_options(invocation: &ParsedInvocation) -> Result<(), CliError> {
    if invocation.options.input.is_some()
        || invocation.options.idempotency_key.is_some()
        || invocation.options.expected_revision.is_some()
        || invocation.options.page_cursor.is_some()
        || invocation.options.page_size.is_some()
    {
        Err(CliError::invalid_command())
    } else {
        Ok(())
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut value, "{byte:02x}");
    }
    value
}

pub(crate) fn read_frozen_beta_state_file(path: &Path) -> Result<Vec<u8>, CliError> {
    let mut file = open_frozen_beta_state_nofollow(path)?;
    let before = file
        .metadata()
        .map_err(|_error| CliError::beta_state_invalid())?;
    validate_frozen_beta_state_metadata(&before)?;
    let capacity =
        usize::try_from(before.len()).map_err(|_error| CliError::beta_state_invalid())?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(crate::beta_state_compat::MAX_FROZEN_BETA_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::beta_state_invalid())?;
    let after = file
        .metadata()
        .map_err(|_error| CliError::beta_state_invalid())?;
    validate_frozen_beta_state_metadata(&after)?;
    ensure_same_frozen_beta_file(&before, &after)?;
    if u64::try_from(bytes.len()).ok() != Some(before.len()) {
        return Err(CliError::beta_state_invalid());
    }
    Ok(bytes)
}

fn validate_frozen_beta_state_metadata(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > crate::beta_state_compat::MAX_FROZEN_BETA_STATE_BYTES
    {
        return Err(CliError::beta_state_invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(CliError::beta_state_invalid());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_frozen_beta_state_nofollow(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;

    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if names.is_empty() && !absolute => absolute = true,
            Component::Normal(name) => names.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(CliError::beta_state_invalid());
            }
        }
    }
    let (file_name, ancestors) = names
        .split_last()
        .ok_or_else(CliError::beta_state_invalid)?;
    let base = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = open(
        base,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::beta_state_invalid())?;
    validate_frozen_beta_ancestor_metadata(
        &directory
            .metadata()
            .map_err(|_error| CliError::beta_state_invalid())?,
    )?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            *ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_error| CliError::beta_state_invalid())?;
        validate_frozen_beta_ancestor_metadata(
            &directory
                .metadata()
                .map_err(|_error| CliError::beta_state_invalid())?,
        )?;
    }
    #[cfg(test)]
    swap_beta_state_ancestor_after_open_for_test(path)?;
    openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::beta_state_invalid())
}

#[cfg(unix)]
fn validate_frozen_beta_ancestor_metadata(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if !metadata.is_dir()
        || (owner != 0 && owner != rustix::process::geteuid().as_raw())
        || (writable_by_others && !protected_sticky_root)
    {
        Err(CliError::beta_state_invalid())
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
struct BetaStateAncestorSwapProbe {
    parent: PathBuf,
    displaced: PathBuf,
    replacement: PathBuf,
}

#[cfg(all(test, unix))]
static BETA_STATE_ANCESTOR_SWAP_PROBE: std::sync::Mutex<Option<BetaStateAncestorSwapProbe>> =
    std::sync::Mutex::new(None);

#[cfg(all(test, unix))]
fn swap_beta_state_ancestor_after_open_for_test(path: &Path) -> Result<(), CliError> {
    let Some(parent) = path.parent() else {
        return Err(CliError::beta_state_invalid());
    };
    let mut slot = BETA_STATE_ANCESTOR_SWAP_PROBE
        .lock()
        .map_err(|_error| CliError::beta_state_invalid())?;
    let probe = if slot.as_ref().is_some_and(|probe| probe.parent == parent) {
        slot.take()
    } else {
        None
    };
    drop(slot);
    let Some(probe) = probe else {
        return Ok(());
    };
    std::fs::rename(&probe.parent, &probe.displaced)
        .map_err(|_error| CliError::beta_state_invalid())?;
    std::fs::rename(&probe.replacement, &probe.parent)
        .map_err(|_error| CliError::beta_state_invalid())
}

#[cfg(not(unix))]
fn open_frozen_beta_state_nofollow(path: &Path) -> Result<File, CliError> {
    File::open(path).map_err(|_error| CliError::beta_state_invalid())
}

fn ensure_same_frozen_beta_file(
    expected: &std::fs::Metadata,
    observed: &std::fs::Metadata,
) -> Result<(), CliError> {
    if expected.len() != observed.len() {
        return Err(CliError::beta_state_invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if expected.dev() != observed.dev()
            || expected.ino() != observed.ino()
            || expected.mtime() != observed.mtime()
            || expected.mtime_nsec() != observed.mtime_nsec()
            || expected.ctime() != observed.ctime()
            || expected.ctime_nsec() != observed.ctime_nsec()
        {
            return Err(CliError::beta_state_invalid());
        }
    }
    Ok(())
}

fn operation_response(
    path: &str,
    result: Value,
    next_page_cursor: Option<String>,
) -> OperationResponse {
    OperationResponse {
        operation_id: format!("cigar.cli.{}.v1", path.replace('.', "-")),
        result,
        semantic_etag: None,
        next_page_cursor,
    }
}

fn initialize(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    if invocation.positionals.len() > 1 {
        return Err(CliError::invalid_command());
    }
    let state_directory = if let Some(root) = invocation.positionals.first() {
        canonical_directory(Path::new(root))?.join(".cigar")
    } else {
        configuration.project_state_directory().to_path_buf()
    };
    let state_file = state_directory.join(STATE_FILE);
    if state_file.exists() {
        let state = read_state(&state_directory)?;
        return Ok(json!({
            "initialized": false,
            "generation": state.generation,
            "state_directory": state_directory
        }));
    }
    if !invocation.options.dry_run {
        cancellation.checkpoint()?;
        create_private_directory(&state_directory)?;
        cancellation.checkpoint()?;
        write_state(&state_directory, &LocalState::default())?;
    }
    Ok(json!({
        "initialized": !invocation.options.dry_run,
        "planned": invocation.options.dry_run,
        "generation": 1,
        "state_directory": state_directory
    }))
}

fn source_add(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [source_id, path] = exact_two(&invocation.positionals)?;
    validate_name(source_id)?;
    let path = canonical_directory(Path::new(path))?;
    let mut state = read_state(configuration.project_state_directory())?;
    if state.sources.contains_key(source_id) {
        return Err(CliError::state_conflict());
    }
    state
        .sources
        .insert(source_id.clone(), SourceEntry { path: path.clone() });
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({"source_id": source_id, "path": path, "generation": state.generation}))
}

fn source_list(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    let state = read_state(configuration.project_state_directory())?;
    let sources = state
        .sources
        .into_iter()
        .map(|(source_id, source)| json!({"source_id": source_id, "path": source.path}))
        .collect::<Vec<_>>();
    Ok(json!({"sources": sources, "generation": state.generation}))
}

fn source_remove(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let source_id = exact_one(&invocation.positionals)?;
    let mut state = read_state(configuration.project_state_directory())?;
    if state.sources.remove(source_id).is_none() {
        return Err(CliError::state_conflict());
    }
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(
        json!({"source_id": source_id, "removed": !invocation.options.dry_run, "generation": state.generation}),
    )
}

fn project_list(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    let state = read_state(configuration.project_state_directory())?;
    let projects = state
        .projects
        .into_iter()
        .map(|(project_id, project)| {
            json!({
                "project_id": project_id,
                "path": project.path,
                "attached": project.attached,
                "active": state.active_project.as_ref() == Some(&project_id)
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"projects": projects, "generation": state.generation}))
}

fn project_attach(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [project_id, path] = exact_two(&invocation.positionals)?;
    validate_name(project_id)?;
    let path = canonical_directory(Path::new(path))?;
    let mut state = read_state(configuration.project_state_directory())?;
    match state.projects.get(project_id) {
        Some(existing) if existing.path != path || existing.attached => {
            return Err(CliError::state_conflict());
        }
        _ => {}
    }
    state.projects.insert(
        project_id.clone(),
        ProjectEntry {
            path: path.clone(),
            attached: true,
        },
    );
    if state.active_project.is_none() {
        state.active_project = Some(project_id.clone());
    }
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(
        json!({"project_id": project_id, "path": path, "attached": true, "generation": state.generation}),
    )
}

fn project_detach(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let project_id = exact_one(&invocation.positionals)?;
    let mut state = read_state(configuration.project_state_directory())?;
    let project = state
        .projects
        .get_mut(project_id)
        .filter(|project| project.attached)
        .ok_or_else(CliError::state_conflict)?;
    project.attached = false;
    if state.active_project.as_deref() == Some(project_id) {
        state.active_project = None;
    }
    state
        .links
        .retain(|link| link.from != *project_id && link.to != *project_id);
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({"project_id": project_id, "attached": false, "generation": state.generation}))
}

fn project_switch(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let project_id = exact_one(&invocation.positionals)?;
    let mut state = read_state(configuration.project_state_directory())?;
    if !state
        .projects
        .get(project_id)
        .is_some_and(|project| project.attached)
    {
        return Err(CliError::state_conflict());
    }
    state.active_project = Some(project_id.clone());
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({"active_project": project_id, "generation": state.generation}))
}

fn project_link(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [from, to] = exact_two(&invocation.positionals)?;
    if from == to {
        return Err(CliError::state_conflict());
    }
    let mut state = read_state(configuration.project_state_directory())?;
    if ![from, to].into_iter().all(|project| {
        state
            .projects
            .get(project)
            .is_some_and(|entry| entry.attached)
    }) {
        return Err(CliError::state_conflict());
    }
    if !state.links.insert(ProjectLink {
        from: from.clone(),
        to: to.clone(),
    }) {
        return Err(CliError::state_conflict());
    }
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({"from": from, "to": to, "linked": true, "generation": state.generation}))
}

fn project_unlink(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [from, to] = exact_two(&invocation.positionals)?;
    let mut state = read_state(configuration.project_state_directory())?;
    if !state.links.remove(&ProjectLink {
        from: from.clone(),
        to: to.clone(),
    }) {
        return Err(CliError::state_conflict());
    }
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({"from": from, "to": to, "linked": false, "generation": state.generation}))
}

fn focus_switch(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let focus_id = exact_one(&invocation.positionals)?;
    validate_name(focus_id)?;
    let mut state = read_state(configuration.project_state_directory())?;
    state.active_focus = Some(focus_id.clone());
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({"active_focus": focus_id, "generation": state.generation}))
}

fn focus_close(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    if invocation.positionals.len() > 1 {
        return Err(CliError::invalid_command());
    }
    let mut state = read_state(configuration.project_state_directory())?;
    let active = state
        .active_focus
        .as_deref()
        .ok_or_else(CliError::state_conflict)?;
    if invocation
        .positionals
        .first()
        .is_some_and(|expected| expected != active)
    {
        return Err(CliError::state_conflict());
    }
    let closed = active.to_owned();
    state.active_focus = None;
    persist_mutation(invocation, configuration, &mut state, cancellation)?;
    Ok(json!({
        "closed_focus": closed,
        "generation": state.generation,
        "planned": invocation.options.dry_run
    }))
}

fn effect_list(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<(Value, Option<String>), CliError> {
    require_no_positionals(invocation)?;
    let config = production_configuration(configuration)?;
    let authority_bytes =
        read_bounded_regular(&config.production.authority_file, MAX_ADMIN_INPUT_BYTES)
            .map_err(|_error| CliError::state_unavailable())?;
    let authority = cigar_daemon::ProductionAuthorityConfiguration::from_json(&authority_bytes)
        .map_err(|_error| CliError::state_corrupt())?;
    let repository = cigar_store::SqliteStore::open_with_capacity_profile(
        &config.production.metadata_database,
        config.local_sqlite_capacity_profile,
    )
    .map_err(|_error| CliError::state_unavailable())?;
    let cancellation = cigar_store::CancellationToken::default();
    let limit = usize::try_from(invocation.options.page_size.unwrap_or(100))
        .map_err(|_error| CliError::invalid_input())?;
    let decoded_cursor = invocation
        .options
        .page_cursor
        .as_deref()
        .map(decode_effect_list_cursor)
        .transpose()?;
    let mut tenants = authority
        .tenants
        .into_iter()
        .filter(|tenant| tenant.active)
        .map(|tenant| tenant.tenant_id)
        .collect::<Vec<_>>();
    tenants.sort();
    tenants.dedup();
    let start = decoded_cursor.as_ref().map_or(Ok(0), |cursor| {
        tenants
            .binary_search(&cursor.tenant_id)
            .map_err(|_error| CliError::invalid_input())
    })?;
    let mut effects = Vec::new();
    let mut next_page_cursor = None;
    for (tenant_index, tenant_id) in tenants.iter().enumerate().skip(start) {
        let mut cursor = if tenant_index == start {
            decoded_cursor
                .as_ref()
                .and_then(|cursor| cursor.revision.zip(cursor.last_effect_id.as_ref()))
                .map(|(revision, last_effect_id)| {
                    cigar_store::EffectRecoveryCursor::resume(
                        tenant_id.clone(),
                        cigar_store::StoreRevision(revision),
                        last_effect_id.clone(),
                    )
                    .map_err(|_error| CliError::invalid_input())
                })
                .transpose()?
        } else {
            None
        };
        loop {
            use cigar_store::ServiceRepository as _;
            let remaining = limit.saturating_sub(effects.len());
            if remaining == 0 {
                next_page_cursor = Some(encode_effect_list_cursor(
                    tenant_id.clone(),
                    cursor.as_ref(),
                )?);
                break;
            }
            let query = cigar_store::EffectRecoveryQuery::new(tenant_id.clone(), remaining, cursor)
                .map_err(|_error| CliError::state_corrupt())?;
            let page = repository
                .effect_recovery(&query, &cancellation)
                .map_err(|_error| CliError::state_unavailable())?;
            for item in page.items {
                let record: cigar_effects::DurableEffectRecord =
                    serde_json::from_slice(item.record.bytes())
                        .map_err(|_error| CliError::state_corrupt())?;
                let reencoded =
                    serde_json::to_vec(&record).map_err(|_error| CliError::state_corrupt())?;
                if reencoded != item.record.bytes()
                    || record.intent.effect_id != item.record.effect_id
                    || record.effect_version != item.record.effect_version
                {
                    return Err(CliError::state_corrupt());
                }
                effects.push(json!({
                    "tenant_id": tenant_id,
                    "effect_id": item.record.effect_id,
                    "effect_version": item.record.effect_version,
                    "state": record.state,
                    "requires_reconciliation": record.state == cigar_protocol::EffectState::Unknown
                }));
            }
            let Some(next) = page.next else {
                if effects.len() == limit
                    && let Some(next_tenant) = tenants.get(tenant_index.saturating_add(1))
                {
                    next_page_cursor = Some(encode_effect_list_cursor(next_tenant.clone(), None)?);
                }
                break;
            };
            if effects.len() == limit {
                next_page_cursor = Some(encode_effect_list_cursor(tenant_id.clone(), Some(&next))?);
                break;
            }
            cursor = Some(next);
        }
        if next_page_cursor.is_some() || effects.len() == limit {
            break;
        }
    }
    Ok((
        json!({"effects": effects, "count": effects.len()}),
        next_page_cursor,
    ))
}

fn decode_effect_list_cursor(value: &str) -> Result<EffectListCursorDocument, CliError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_error| CliError::invalid_input())?;
    if bytes.len() > 1024 {
        return Err(CliError::invalid_input());
    }
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::invalid_input())?;
    let cursor: EffectListCursorDocument =
        serde_json::from_slice(&bytes).map_err(|_error| CliError::invalid_input())?;
    if cursor.schema_version != EFFECT_LIST_CURSOR_SCHEMA
        || cursor.revision.is_some() != cursor.last_effect_id.is_some()
        || cursor.revision == Some(0)
    {
        Err(CliError::invalid_input())
    } else {
        Ok(cursor)
    }
}

fn encode_effect_list_cursor(
    tenant_id: cigar_protocol::RecordId,
    cursor: Option<&cigar_store::EffectRecoveryCursor>,
) -> Result<String, CliError> {
    let document = EffectListCursorDocument {
        schema_version: EFFECT_LIST_CURSOR_SCHEMA.to_owned(),
        tenant_id,
        revision: cursor.map(|cursor| cursor.snapshot_revision().0),
        last_effect_id: cursor.map(|cursor| cursor.last_effect_id().clone()),
    };
    let bytes = serde_json::to_vec(&document).map_err(|_error| CliError::state_corrupt())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn policy_check(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    explain: bool,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    let config = production_configuration(configuration)?;
    let policy_bytes = read_bounded_regular(
        &config.production.policy_profile_file,
        MAX_ADMIN_INPUT_BYTES,
    )
    .map_err(|_error| CliError::state_unavailable())?;
    cigar_canon::parse_strict_json(&policy_bytes).map_err(|_error| CliError::state_corrupt())?;
    let profile: cigar_policy::PolicyProfile =
        serde_json::from_slice(&policy_bytes).map_err(|_error| CliError::state_corrupt())?;
    let engine = cigar_policy::CompiledPolicyEngine::default();
    let activated_at = current_timestamp()?;
    let snapshot = engine
        .install_json(&policy_bytes, activated_at)
        .map_err(|_error| CliError::state_corrupt())?;
    let Some(input_path) = invocation.options.input.as_deref() else {
        if !explain {
            return Err(CliError::input_required());
        }
        let rules = profile
            .rules
            .into_iter()
            .map(|rule| {
                json!({
                    "id": rule.id,
                    "priority": rule.priority,
                    "depends_on": rule.depends_on,
                    "resources": rule.resources,
                    "action": rule.action,
                    "condition_count": rule.conditions.len(),
                    "redaction_count": rule.redaction_paths.len()
                })
            })
            .collect::<Vec<_>>();
        return Ok(json!({
            "policy_revision": snapshot.revision,
            "policy_digest": snapshot.policy_digest,
            "protected": snapshot.protected,
            "rules": rules
        }));
    };
    let bytes = read_bounded_regular(input_path, MAX_ADMIN_INPUT_BYTES)
        .map_err(|_error| CliError::invalid_input())?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::invalid_input())?;
    let document: PolicyCheckDocument =
        serde_json::from_slice(&bytes).map_err(|_error| CliError::invalid_input())?;
    let resource = document.resource;
    let request = document.into_request();
    use cigar_policy::PolicyEngine as _;
    let decision = match resource {
        cigar_policy::PolicyResource::Partition => engine.authorize_partition(&request),
        cigar_policy::PolicyResource::Metadata => engine.authorize_metadata(&request),
        cigar_policy::PolicyResource::Content => engine.authorize_content(&request),
        cigar_policy::PolicyResource::Processor => engine.authorize_processor(&request),
        cigar_policy::PolicyResource::Bundle => engine.authorize_bundle(&request),
        cigar_policy::PolicyResource::Handoff => engine.authorize_handoff(&request),
        cigar_policy::PolicyResource::Effect => engine.authorize_effect(&request),
    }
    .map_err(|_error| CliError::state_unavailable())?;
    let caller = decision.caller_view();
    if explain {
        Ok(json!({
            "resource": resource,
            "outcome": decision.outcome,
            "reason": decision.reason,
            "input_digest": decision.input_digest,
            "policy_digest": decision.policy_digest,
            "redaction_paths": decision.redaction_paths,
            "conditions": decision.conditions,
            "expires_at": decision.expires_at,
            "disclosure": decision.disclosure,
            "timing_class": decision.timing_class,
            "caller_disposition": format!("{:?}", caller.disposition).to_ascii_lowercase(),
            "caller_reason": caller.reason,
        }))
    } else {
        Ok(json!({
            "resource": resource,
            "outcome": decision.outcome,
            "caller_disposition": format!("{:?}", caller.disposition).to_ascii_lowercase(),
            "policy_digest": decision.policy_digest,
            "expires_at": decision.expires_at
        }))
    }
}

fn security_doctor(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    collect_security_diagnostics(configuration, invocation.options.deep)
}

fn collect_security_diagnostics(
    configuration: &EffectiveConfiguration,
    deep: bool,
) -> Result<Value, CliError> {
    let context = production_backup_context(configuration)?;
    let _backup_signer = backup_creation_identity(&context)?;
    validate_backup_source(&context.configuration)?;
    let repository = production_gc_repository(&context)?;
    let store = SqliteStore::open_with_capacity_profile(
        &context.configuration.production.metadata_database,
        context.configuration.local_sqlite_capacity_profile,
    )
    .map_err(map_store_error)?;
    store.integrity_check().map_err(map_store_error)?;
    store.verify_migration_level().map_err(map_store_error)?;
    let sqlite = store.configuration().map_err(map_store_error)?;
    let storage = store.storage_statistics().map_err(map_store_error)?;

    let policy_bytes = read_bounded_regular(
        &context.configuration.production.policy_profile_file,
        MAX_ADMIN_INPUT_BYTES,
    )?;
    let policy = Arc::new(cigar_policy::CompiledPolicyEngine::default());
    match context
        .configuration
        .production
        .policy_profile_file
        .extension()
        .and_then(OsStr::to_str)
    {
        Some("json") => policy
            .install_json(&policy_bytes, current_timestamp()?)
            .map_err(|_error| CliError::state_corrupt())?,
        Some("toml") => {
            let text =
                std::str::from_utf8(&policy_bytes).map_err(|_error| CliError::state_corrupt())?;
            policy
                .install_toml(text, current_timestamp()?)
                .map_err(|_error| CliError::state_corrupt())?
        }
        _ => return Err(CliError::invalid_configuration()),
    };
    let sources = read_bounded_regular(
        &context.configuration.production.source_registry_file,
        MAX_ADMIN_INPUT_BYTES,
    )?;
    cigar_daemon::ProductionSourceRegistry::from_json(
        &sources,
        &context.configuration.production.project_directory,
    )
    .map_err(|_error| CliError::state_corrupt())?;
    let effects = read_bounded_regular(
        &context.configuration.production.effect_registry_file,
        MAX_ADMIN_INPUT_BYTES,
    )?;
    cigar_daemon::ProductionEffectRegistry::from_json(&effects)
        .map_err(|_error| CliError::state_corrupt())?;

    let mut checks = vec![
        "configuration",
        "transport",
        "keystore",
        "backup_signer",
        "policy",
        "authority",
        "source_registry",
        "effect_registry",
        "sqlite_integrity",
        "sqlite_migrations",
        "encrypted_blob_roots",
    ];
    let deep_integrity = if deep {
        let keys: Arc<dyn KeyProvider> = context.keys.clone();
        let clock: Arc<dyn cigar_daemon::AuthorityClock> =
            Arc::new(cigar_daemon::SystemAuthorityClock);
        let authority = Arc::new(
            cigar_daemon::ProductionDomainAuthority::new(
                context.authority.clone(),
                Arc::clone(&policy),
                keys,
                clock,
            )
            .map_err(|_error| CliError::state_corrupt())?,
        );
        let signatures: Arc<dyn cigar_daemon::EffectRecordSignatureAuthority> = authority;
        let effect_authenticator =
            cigar_daemon::ProductionEffectRecordAuthenticator::open_read_only(
                signatures,
                context
                    .configuration
                    .production
                    .effect_checkpoint_file
                    .clone(),
            )
            .map_err(|error| match error.code() {
                cigar_effects::EffectErrorCode::Unavailable => CliError::state_unavailable(),
                _ => CliError::state_corrupt(),
            })?;
        let report = store
            .deep_integrity_check_authenticated(repository.as_ref(), |tenant_id, envelope| {
                cigar_effects::verify_persisted_effect_record(
                    tenant_id,
                    envelope,
                    &effect_authenticator,
                )
                .is_ok()
            })
            .map_err(map_store_error)?;
        checks.extend([
            "snapshot_hashes",
            "journal_chains",
            "effect_record_signatures",
            "effect_external_checkpoints",
            "atom_projection",
            "fts_projection",
            "effect_ambiguity",
        ]);
        Some(json!({
            "revision": report.revision.0,
            "tenant_count": report.tenant_count,
            "atom_count": report.atom_count,
            "projection_atom_count": report.projection_atom_count,
            "effect_journal_event_count": report.effect_journal_event_count,
            "effect_record_count": report.effect_record_count,
            "verified_effect_record_count": report.verified_effect_record_count,
            "blob_reference_count": report.blob_reference_count,
            "verified_blob_count": report.verified_blob_count,
            "unknown_effect_count": report.unknown_effect_count,
        }))
    } else {
        None
    };
    Ok(json!({
        "schema_version": "cigar.deep-doctor.v1",
        "checks": checks,
        "deep": deep,
        "deep_integrity": deep_integrity,
        "ready": true,
        "security": true,
        "storage": {
            "database_bytes": storage.database_bytes,
            "page_count": storage.page_count,
            "max_page_count": storage.max_page_count,
            "retained_snapshots": storage.retained_snapshots,
            "latest_snapshot_bytes": storage.latest_snapshot_bytes,
        },
        "sqlite": {
            "journal_mode": sqlite.journal_mode,
            "synchronous": sqlite.synchronous,
            "foreign_keys": sqlite.foreign_keys,
            "full_text_search": sqlite.full_text_search,
            "defensive": sqlite.defensive,
            "cache_kibibytes": sqlite.cache_kibibytes,
            "max_database_bytes": sqlite.max_database_bytes,
            "version": sqlite.sqlite_version,
        }
    }))
}

const MAX_SUPPORT_FILES: usize = 16;
const MAX_SUPPORT_ENTRY_BYTES: usize = 1024 * 1024;
const MAX_SUPPORT_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;

struct SupportArchiveEntry {
    name: String,
    bytes: Vec<u8>,
}

fn diagnostics_bundle(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let requested = Path::new(exact_one(&invocation.positionals)?);
    let archive_path = absolute_new_path(requested)?;
    cancellation.checkpoint()?;
    let diagnostics = collect_security_diagnostics(configuration, true)?;
    let mut entries = vec![
        SupportArchiveEntry {
            name: "build.json".to_owned(),
            bytes: stable_build_document(),
        },
        SupportArchiveEntry {
            name: "configuration.json".to_owned(),
            bytes: json_document(&json!({
                "schema_version": "cigar.support-configuration.v1",
                "target": configuration.target().as_str(),
                "local_socket_configured": configuration.local_socket().is_some(),
                "windows_named_pipe_configured": configuration.windows_named_pipe().is_some(),
                "daemon_configuration_configured": configuration.daemon_config().is_some(),
            }))?,
        },
        SupportArchiveEntry {
            name: "diagnostics.json".to_owned(),
            bytes: json_document(&diagnostics)?,
        },
        SupportArchiveEntry {
            name: "platform.json".to_owned(),
            bytes: json_document(&json!({
                "schema_version": "cigar.support-platform.v1",
                "architecture": std::env::consts::ARCH,
                "family": std::env::consts::FAMILY,
                "operating_system": std::env::consts::OS,
            }))?,
        },
    ];
    let payload_inventory = support_inventory(&entries)?;
    entries.insert(
        0,
        SupportArchiveEntry {
            name: "inventory.json".to_owned(),
            bytes: json_document(&json!({
                "schema_version": "cigar.support-inventory.v1",
                "content_free": true,
                "payload_files": payload_inventory,
            }))?,
        },
    );
    let files = support_inventory(&entries)?;
    let archive = render_support_tar(&entries)?;
    cancellation.checkpoint()?;
    if !invocation.options.dry_run {
        write_new_private_file(&archive_path, &archive)?;
    }
    cancellation.checkpoint()?;
    Ok(json!({
        "schema_version": "cigar.support-bundle-result.v1",
        "archive": archive_path,
        "archive_bytes": archive.len(),
        "archive_digest": support_digest(&archive),
        "content_free": true,
        "created": !invocation.options.dry_run,
        "files": files,
    }))
}

fn stable_build_document() -> Vec<u8> {
    let mut bytes = cigar_protocol::BuildMetadata::current(env!("CARGO_PKG_VERSION"))
        .to_stable_json()
        .into_bytes();
    bytes.push(b'\n');
    bytes
}

fn json_document(value: &Value) -> Result<Vec<u8>, CliError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_error| CliError::state_corrupt())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_SUPPORT_ENTRY_BYTES {
        return Err(CliError::state_unavailable());
    }
    Ok(bytes)
}

fn support_inventory(entries: &[SupportArchiveEntry]) -> Result<Vec<Value>, CliError> {
    if entries.len() > MAX_SUPPORT_FILES {
        return Err(CliError::state_unavailable());
    }
    entries
        .iter()
        .map(|entry| {
            if entry.bytes.len() > MAX_SUPPORT_ENTRY_BYTES {
                return Err(CliError::state_unavailable());
            }
            Ok(json!({
                "path": entry.name,
                "bytes": entry.bytes.len(),
                "digest": support_digest(&entry.bytes),
            }))
        })
        .collect()
}

fn support_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut value, "{byte:02x}");
    }
    value
}

fn render_support_tar(entries: &[SupportArchiveEntry]) -> Result<Vec<u8>, CliError> {
    if entries.is_empty() || entries.len() > MAX_SUPPORT_FILES {
        return Err(CliError::state_unavailable());
    }
    let mut archive = Vec::new();
    for entry in entries {
        if entry.name.is_empty()
            || entry.name.len() > 100
            || !entry
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || entry.bytes.len() > MAX_SUPPORT_ENTRY_BYTES
        {
            return Err(CliError::state_unavailable());
        }
        let mut header = [0_u8; 512];
        copy_tar_field(&mut header, 0..100, entry.name.as_bytes())?;
        write_tar_octal(&mut header, 100..108, 0o600)?;
        write_tar_octal(&mut header, 108..116, 0)?;
        write_tar_octal(&mut header, 116..124, 0)?;
        write_tar_octal(
            &mut header,
            124..136,
            u64::try_from(entry.bytes.len()).map_err(|_error| CliError::state_unavailable())?,
        )?;
        write_tar_octal(&mut header, 136..148, 0)?;
        header
            .get_mut(148..156)
            .ok_or_else(CliError::state_unavailable)?
            .fill(b' ');
        *header
            .get_mut(156)
            .ok_or_else(CliError::state_unavailable)? = b'0';
        copy_tar_field(&mut header, 257..263, b"ustar\0")?;
        copy_tar_field(&mut header, 263..265, b"00")?;
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let checksum = format!("{checksum:06o}\0 ");
        copy_tar_field(&mut header, 148..156, checksum.as_bytes())?;
        archive.extend_from_slice(&header);
        archive.extend_from_slice(&entry.bytes);
        let remainder = entry.bytes.len() % 512;
        if remainder != 0 {
            archive.resize(
                archive
                    .len()
                    .checked_add(512 - remainder)
                    .ok_or_else(CliError::state_unavailable)?,
                0,
            );
        }
        if archive.len() > MAX_SUPPORT_ARCHIVE_BYTES {
            return Err(CliError::state_unavailable());
        }
    }
    archive.resize(
        archive
            .len()
            .checked_add(1024)
            .ok_or_else(CliError::state_unavailable)?,
        0,
    );
    if archive.len() > MAX_SUPPORT_ARCHIVE_BYTES {
        return Err(CliError::state_unavailable());
    }
    Ok(archive)
}

fn copy_tar_field(
    header: &mut [u8; 512],
    range: std::ops::Range<usize>,
    bytes: &[u8],
) -> Result<(), CliError> {
    let field = header
        .get_mut(range)
        .ok_or_else(CliError::state_unavailable)?;
    let destination = field
        .get_mut(..bytes.len())
        .ok_or_else(CliError::state_unavailable)?;
    destination.copy_from_slice(bytes);
    Ok(())
}

fn write_tar_octal(
    header: &mut [u8; 512],
    range: std::ops::Range<usize>,
    value: u64,
) -> Result<(), CliError> {
    let width = range
        .len()
        .checked_sub(1)
        .ok_or_else(CliError::state_unavailable)?;
    let rendered = format!("{value:0width$o}\0");
    if rendered.len() != range.len() {
        return Err(CliError::state_unavailable());
    }
    copy_tar_field(header, range, rendered.as_bytes())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(CliError::invalid_input)?;
    let temporary = parent.join(format!(
        ".cigar-support-{}-{}",
        std::process::id(),
        random_suffix()?
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|_error| CliError::state_unavailable())?;
        file.write_all(bytes)
            .map_err(|_error| CliError::state_unavailable())?;
        file.sync_all()
            .map_err(|_error| CliError::state_unavailable())?;
        std::fs::hard_link(&temporary, path).map_err(|_error| CliError::state_unavailable())?;
        std::fs::remove_file(&temporary).map_err(|_error| CliError::state_unavailable())?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ignored = std::fs::remove_file(&temporary);
    }
    result
}

impl PolicyCheckDocument {
    fn into_request(self) -> cigar_policy::PolicyRequest {
        cigar_policy::PolicyRequest {
            resource: self.resource,
            input_digest: self.input_digest,
            principal_id: self.principal_id,
            principal_active: self.principal_active,
            tenant_id: self.tenant_id,
            authenticated_tenant_id: self.authenticated_tenant_id,
            project_id: self.project_id,
            allowed_project_ids: self.allowed_project_ids,
            purpose: self.purpose,
            allowed_purposes: self.allowed_purposes,
            processor: self.processor,
            allowed_processors: self.allowed_processors,
            classification: self.classification,
            maximum_classification: self.maximum_classification,
            residency_allowed: self.residency_allowed,
            egress_allowed: self.egress_allowed,
            lifecycle: self.lifecycle,
            integrity_verified: self.integrity_verified,
            valid_at: self.valid_at,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            observed_at: self.observed_at,
            observed_as_of: self.observed_as_of,
            freshness_expires_at: self.freshness_expires_at,
            instruction_authority: self.instruction_authority,
            maximum_instruction_authority: self.maximum_instruction_authority,
            excluded: self.excluded,
            modality_supported: self.modality_supported,
            capability: self.capability.map(PolicyCapabilityDocument::into_context),
            required_capability: self.required_capability,
            bound_policy_digest: self.bound_policy_digest,
            effect_risk: self.effect_risk,
            effect_approved: self.effect_approved,
            effect_constraints_satisfied: self.effect_constraints_satisfied,
            fencing_required: self.fencing_required,
            fencing_verified: self.fencing_verified,
            decision_expires_at: self.decision_expires_at,
        }
    }
}

impl PolicyCapabilityDocument {
    fn into_context(self) -> cigar_policy::CapabilityContext {
        cigar_policy::CapabilityContext {
            subject_id: self.subject_id,
            grant_id: self.grant_id,
            capabilities: self.capabilities,
            project_ids: self.project_ids,
            processors: self.processors,
            expires_at: self.expires_at,
        }
    }
}

fn production_configuration(
    configuration: &EffectiveConfiguration,
) -> Result<cigar_daemon::DaemonConfig, CliError> {
    let path = configuration
        .daemon_config()
        .ok_or_else(CliError::invalid_configuration)?;
    let config = cigar_daemon::load_configuration(path)
        .map_err(|_error| CliError::invalid_configuration())?;
    if config.mode != cigar_daemon::DeploymentMode::Local {
        return Err(CliError::unsupported_surface());
    }
    Ok(config)
}

fn current_timestamp() -> Result<cigar_protocol::UtcTimestamp, CliError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
        .ok_or_else(CliError::state_unavailable)?;
    cigar_protocol::UtcTimestamp::from_unix_nanos(nanos)
        .map_err(|_error| CliError::state_unavailable())
}

struct ProductionBackupContext {
    configuration: cigar_daemon::DaemonConfig,
    keys: Arc<EncryptedDevelopmentKeystore>,
    authority: cigar_daemon::ProductionAuthorityConfiguration,
    now: i128,
}

struct BackupCreationIdentity {
    signing_key: KeyRef,
    tenant: String,
    signer: String,
}

fn production_backup_context(
    configuration: &EffectiveConfiguration,
) -> Result<ProductionBackupContext, CliError> {
    let configuration = production_configuration(configuration)?;
    validate_existing_regular(&configuration.production.keystore_file)?;
    let passphrase = SecretBytes::new(read_backup_secret(
        &configuration.production.keystore_passphrase_file,
    )?);
    let keys = Arc::new(
        EncryptedDevelopmentKeystore::open(&configuration.production.keystore_file, passphrase)
            .map_err(|_error| CliError::credential_unavailable())?,
    );
    let authority_bytes = read_bounded_regular(
        &configuration.production.authority_file,
        MAX_ADMIN_INPUT_BYTES,
    )?;
    let authority = cigar_daemon::ProductionAuthorityConfiguration::from_json(&authority_bytes)
        .map_err(|_error| CliError::invalid_configuration())?;
    Ok(ProductionBackupContext {
        configuration,
        keys,
        authority,
        now: current_timestamp()?.unix_nanos(),
    })
}

fn backup_creation_identity(
    context: &ProductionBackupContext,
) -> Result<BackupCreationIdentity, CliError> {
    let now = cigar_protocol::UtcTimestamp::from_unix_nanos(context.now)
        .map_err(|_error| CliError::state_unavailable())?;
    let mut eligible_operators = context
        .authority
        .tenants
        .iter()
        .filter(|tenant| tenant.active)
        .flat_map(|tenant| {
            tenant.principals.iter().filter_map(move |principal| {
                if principal.active
                    && principal.operator
                    && principal.not_before <= now
                    && now < principal.expires_at
                {
                    Some((tenant, principal))
                } else {
                    None
                }
            })
        });
    let (tenant, principal) = eligible_operators
        .next()
        .ok_or_else(CliError::credential_unavailable)?;
    if eligible_operators.next().is_some() {
        return Err(CliError::credential_unavailable());
    }
    let tenant_id = tenant.tenant_id.as_str().to_owned();
    let signer = principal.principal_id.as_str().to_owned();
    let signing_key = tenant.issuer_key_ref.clone();
    context
        .keys
        .resolve(&signing_key, &tenant_id, KeyPurpose::Signing, context.now)
        .map_err(|_error| CliError::credential_unavailable())?;
    Ok(BackupCreationIdentity {
        signing_key,
        tenant: tenant_id,
        signer,
    })
}

fn backup_identity_trusted(
    authority: &cigar_daemon::ProductionAuthorityConfiguration,
    identity: &cigar_store::BackupSignatureIdentity,
) -> bool {
    authority.tenants.iter().any(|tenant| {
        tenant.active
            && tenant.tenant_id.as_str() == identity.tenant
            && !tenant.revoked_key_refs.contains(&identity.signing_key)
            && tenant.principals.iter().any(|principal| {
                principal.active
                    && principal.operator
                    && principal.principal_id.as_str() == identity.signer
                    && !tenant
                        .revoked_principal_ids
                        .contains(&principal.principal_id)
                    && principal.not_before.unix_nanos() <= identity.signed_at_unix_nanos
                    && identity.signed_at_unix_nanos < principal.expires_at.unix_nanos()
            })
    })
}

fn gc_plan_identity_trusted(
    authority: &cigar_daemon::ProductionAuthorityConfiguration,
    identity: &GarbageCollectionPlanSignatureIdentity,
) -> bool {
    authority.tenants.iter().any(|tenant| {
        tenant.active
            && tenant.tenant_id.as_str() == identity.tenant
            && !tenant.revoked_key_refs.contains(&identity.signing_key)
            && tenant.principals.iter().any(|principal| {
                principal.active
                    && principal.operator
                    && principal.principal_id.as_str() == identity.signer
                    && !tenant
                        .revoked_principal_ids
                        .contains(&principal.principal_id)
                    && principal.not_before.unix_nanos() <= identity.signed_at_unix_nanos
                    && identity.signed_at_unix_nanos < principal.expires_at.unix_nanos()
            })
    })
}

fn validate_backup_source(configuration: &cigar_daemon::DaemonConfig) -> Result<(), CliError> {
    validate_existing_regular(&configuration.production.metadata_database)?;
    let _blob_root = canonical_directory(&configuration.production.blob_directory)?;
    Ok(())
}

fn validate_existing_regular(path: &Path) -> Result<(), CliError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || std::fs::canonicalize(path).map_err(|_error| CliError::state_unavailable())? != path
    {
        Err(CliError::state_corrupt())
    } else {
        Ok(())
    }
}

fn validate_private_regular(path: &Path) -> Result<(), CliError> {
    validate_existing_regular(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata =
            std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(CliError::state_corrupt());
        }
    }
    Ok(())
}

fn read_backup_secret(path: &Path) -> Result<Vec<u8>, CliError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_error| CliError::credential_unavailable())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SECRET_BYTES
        || std::fs::canonicalize(path).map_err(|_error| CliError::credential_unavailable())? != path
    {
        return Err(CliError::credential_unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::credential_unavailable());
        }
    }
    let bytes = read_bounded_regular(path, MAX_SECRET_BYTES)
        .map_err(|_error| CliError::credential_unavailable())?;
    if bytes.is_empty() {
        Err(CliError::credential_unavailable())
    } else {
        Ok(bytes)
    }
}

fn map_backup_error(error: BackupError) -> CliError {
    match error.code() {
        BackupErrorCode::Corrupt | BackupErrorCode::InvalidMetadata => CliError::state_corrupt(),
        BackupErrorCode::DestinationNotEmpty => CliError::state_conflict(),
        BackupErrorCode::KeyUnavailable | BackupErrorCode::UntrustedSigner => {
            CliError::credential_unavailable()
        }
        BackupErrorCode::Unavailable
        | BackupErrorCode::LimitExceeded
        | BackupErrorCode::InjectedAbort => CliError::state_unavailable(),
    }
}

fn backup_checkpoint_error_code(error: cigar_effects::EffectError) -> BackupErrorCode {
    match error.code() {
        cigar_effects::EffectErrorCode::CorruptJournal
        | cigar_effects::EffectErrorCode::InvalidInput => BackupErrorCode::Corrupt,
        cigar_effects::EffectErrorCode::LimitExceeded => BackupErrorCode::LimitExceeded,
        _ => BackupErrorCode::Unavailable,
    }
}

fn map_backup_checkpoint_error(error: cigar_effects::EffectError) -> CliError {
    match backup_checkpoint_error_code(error) {
        BackupErrorCode::Corrupt | BackupErrorCode::InvalidMetadata => CliError::state_corrupt(),
        BackupErrorCode::LimitExceeded | BackupErrorCode::Unavailable => {
            CliError::state_unavailable()
        }
        BackupErrorCode::DestinationNotEmpty
        | BackupErrorCode::KeyUnavailable
        | BackupErrorCode::UntrustedSigner
        | BackupErrorCode::InjectedAbort => CliError::state_unavailable(),
    }
}

fn require_complete_effect_backup(
    backup: &Path,
    manifest: &cigar_store::BackupManifest,
) -> Result<(), CliError> {
    if manifest.format_version != 2 {
        return Err(CliError::state_corrupt());
    }
    cigar_daemon::EffectCheckpointFile::verify_backup_snapshot(
        backup.join(BACKUP_DATABASE_FILE),
        backup.join(BACKUP_EFFECT_CHECKPOINT_FILE),
    )
    .map_err(map_backup_checkpoint_error)
}

fn backup_manifest_result(
    path: &Path,
    manifest: &cigar_store::BackupManifest,
    action: &str,
) -> Value {
    json!({
        "action": action,
        "backup": path,
        "canonical_root": manifest.canonical_root,
        "files": manifest.files.len(),
        "format_version": manifest.format_version,
        "repository_revision": manifest.repository_revision,
        "schema_version": manifest.schema_version,
        "signed": true,
        "verified": true
    })
}

fn backup_create(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let destination = absolute_new_path(Path::new(exact_one(&invocation.positionals)?))?;
    if destination.exists() {
        return Err(CliError::state_conflict());
    }
    let context = production_backup_context(configuration)?;
    validate_backup_source(&context.configuration)?;
    let signer = backup_creation_identity(&context)?;
    let store = SqliteStore::open_with_capacity_profile(
        &context.configuration.production.metadata_database,
        context.configuration.local_sqlite_capacity_profile,
    )
    .map_err(|_error| CliError::state_unavailable())?;
    if invocation.options.dry_run {
        cigar_daemon::EffectCheckpointFile::verify_backup_snapshot(
            &context.configuration.production.metadata_database,
            context
                .configuration
                .production
                .effect_checkpoint_file
                .clone(),
        )
        .map_err(map_backup_checkpoint_error)?;
        context
            .keys
            .resolve(
                &signer.signing_key,
                &signer.tenant,
                KeyPurpose::Signing,
                context.now,
            )
            .map_err(|_error| CliError::credential_unavailable())?;
        return Ok(json!({
            "destination": destination,
            "planned": true,
            "signed": true
        }));
    }
    let identity = BackupIdentity {
        signing_key: &signer.signing_key,
        tenant: &signer.tenant,
        signer: &signer.signer,
        created_at_unix_nanos: context.now,
    };
    let checkpoints = cigar_daemon::EffectCheckpointFile::open(
        context
            .configuration
            .production
            .effect_checkpoint_file
            .clone(),
        false,
    )
    .map_err(map_backup_checkpoint_error)?;
    cancellation.checkpoint()?;
    let manifest = create_backup_with_effect_checkpoint(
        &store,
        &context.configuration.production.blob_directory,
        &destination,
        context.keys.as_ref(),
        identity,
        |database, checkpoint| {
            checkpoints
                .capture_backup_snapshot(database, checkpoint)
                .map_err(backup_checkpoint_error_code)
        },
    )
    .map_err(map_backup_error)?;
    let verified = verify_backup_trusted(
        &destination,
        context.keys.as_ref(),
        context.now,
        |identity| backup_identity_trusted(&context.authority, identity),
    )
    .map_err(map_backup_error)?;
    if verified.manifest != manifest {
        return Err(CliError::state_corrupt());
    }
    require_complete_effect_backup(&destination, &manifest)?;
    Ok(backup_manifest_result(&destination, &manifest, "created"))
}

fn backup_verify(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<Value, CliError> {
    let backup = canonical_directory(Path::new(exact_one(&invocation.positionals)?))?;
    let context = production_backup_context(configuration)?;
    let verified = verify_backup_trusted(&backup, context.keys.as_ref(), context.now, |identity| {
        backup_identity_trusted(&context.authority, identity)
    })
    .map_err(map_backup_error)?;
    require_complete_effect_backup(&backup, &verified.manifest)?;
    Ok(backup_manifest_result(
        &backup,
        &verified.manifest,
        "verified",
    ))
}

fn backup_restore(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [backup, destination] = exact_two(&invocation.positionals)?;
    let backup = canonical_directory(Path::new(backup))?;
    let destination = absolute_new_path(Path::new(destination))?;
    let context = production_backup_context(configuration)?;
    let verified = verify_backup_trusted(&backup, context.keys.as_ref(), context.now, |identity| {
        backup_identity_trusted(&context.authority, identity)
    })
    .map_err(map_backup_error)?;
    let manifest = verified.manifest;
    require_complete_effect_backup(&backup, &manifest)?;
    let current_checkpoint = context
        .configuration
        .production
        .effect_checkpoint_file
        .clone();
    if invocation.options.dry_run {
        if destination.exists()
            && (!destination.is_dir()
                || std::fs::read_dir(&destination)
                    .map_err(|_error| CliError::state_unavailable())?
                    .next()
                    .is_some())
        {
            return Err(CliError::state_conflict());
        }
        cigar_daemon::EffectCheckpointFile::verify_exact_backup_snapshot_read_only(
            current_checkpoint,
            backup.join(BACKUP_EFFECT_CHECKPOINT_FILE),
        )
        .map_err(map_backup_checkpoint_error)?;
        return Ok(json!({
            "backup": backup,
            "destination": destination,
            "files": manifest.files.len(),
            "planned": true,
            "verified": true
        }));
    }
    let checkpoints = cigar_daemon::EffectCheckpointFile::open(current_checkpoint, false)
        .map_err(map_backup_checkpoint_error)?;
    cancellation.checkpoint()?;
    let checkpoint_guard = checkpoints
        .lock_exact_backup_snapshot(backup.join(BACKUP_EFFECT_CHECKPOINT_FILE))
        .map_err(map_backup_checkpoint_error)?;
    let restored = restore_backup_trusted(
        &backup,
        &destination,
        context.keys.as_ref(),
        context.now,
        |identity| backup_identity_trusted(&context.authority, identity),
    )
    .map_err(map_backup_error)?;
    if restored.manifest != manifest {
        return Err(CliError::state_corrupt());
    }
    require_complete_effect_backup(&destination, &restored.manifest)?;
    drop(checkpoint_guard);
    Ok(json!({
        "backup": backup,
        "canonical_root": manifest.canonical_root,
        "destination": destination,
        "files": manifest.files.len(),
        "repository_revision": manifest.repository_revision,
        "restored": true,
        "schema_version": manifest.schema_version,
        "verified": true
    }))
}

fn gc_plan(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let destination = absolute_new_path(Path::new(exact_one(&invocation.positionals)?))?;
    if destination.exists() {
        return Err(CliError::state_conflict());
    }
    let policy = gc_policy(invocation, false)?;
    let context = production_backup_context(configuration)?;
    let signer = backup_creation_identity(&context)?;
    let repository = production_gc_repository(&context)?;
    cancellation.checkpoint()?;
    let plan = SqliteStore::plan_garbage_collection_at_with_capacity_profile(
        &context.configuration.production.metadata_database,
        repository,
        policy.into(),
        policy.max_files,
        context.now,
        context.configuration.local_sqlite_capacity_profile,
    )
    .map_err(map_store_error)?;
    let signed = sign_garbage_collection_plan(
        plan,
        context.keys.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signer.signing_key,
            tenant: &signer.tenant,
            signer: &signer.signer,
        },
    )
    .map_err(map_gc_plan_error)?;
    let bytes = serde_json::to_vec(&signed).map_err(|_error| CliError::state_unavailable())?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|size| size > MAX_SIGNED_GC_PLAN_BYTES)
    {
        return Err(CliError::state_unavailable());
    }
    if !invocation.options.dry_run {
        cancellation.checkpoint()?;
        write_new_private_file(&destination, &bytes)?;
    }
    Ok(gc_plan_result(
        signed.unverified_plan(),
        policy,
        &destination,
        invocation.options.dry_run,
    ))
}

fn gc_run(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let plan_path = absolute_new_path(Path::new(exact_one(&invocation.positionals)?))?;
    if invocation.options.input.is_some() {
        return Err(CliError::invalid_input());
    }
    validate_private_regular(&plan_path)?;
    let bytes = read_bounded_regular(&plan_path, MAX_SIGNED_GC_PLAN_BYTES)?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::state_corrupt())?;
    let signed: SignedGarbageCollectionPlan =
        serde_json::from_slice(&bytes).map_err(|_error| CliError::state_corrupt())?;
    let context = production_backup_context(configuration)?;
    let verified = verify_garbage_collection_plan_trusted(
        signed,
        context.keys.as_ref(),
        context.now,
        |identity| gc_plan_identity_trusted(&context.authority, identity),
    )
    .map_err(map_gc_plan_error)?;
    let policy = gc_policy_from_plan(verified.plan());
    let blockers = gc_blockers(policy);
    if !invocation.options.dry_run && !blockers.is_empty() {
        return Err(CliError::state_conflict());
    }
    let repository = production_gc_repository(&context)?;
    cancellation.checkpoint()?;
    let report = SqliteStore::run_garbage_collection_plan_at_with_capacity_profile(
        &context.configuration.production.metadata_database,
        repository,
        &verified,
        invocation.options.dry_run,
        context.configuration.local_sqlite_capacity_profile,
    )
    .map_err(map_store_error)?;
    Ok(gc_report_result(
        &report,
        policy,
        invocation.options.dry_run,
    ))
}

fn gc_policy(invocation: &ParsedInvocation, required: bool) -> Result<GcPolicyDocument, CliError> {
    let Some(path) = invocation.options.input.as_deref() else {
        if required {
            return Err(CliError::input_required());
        }
        return Ok(GcPolicyDocument {
            schema_version: GcPolicySchema::V1,
            retention_satisfied: false,
            legal_hold: true,
            backup_complete: false,
            max_files: DEFAULT_GC_FILES,
        });
    };
    let bytes = read_bounded_regular(path, MAX_ADMIN_INPUT_BYTES)
        .map_err(|_error| CliError::invalid_input())?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::invalid_input())?;
    let policy: GcPolicyDocument =
        serde_json::from_slice(&bytes).map_err(|_error| CliError::invalid_input())?;
    if policy.max_files == 0 || policy.max_files > MAX_GC_FILES {
        return Err(CliError::invalid_input());
    }
    Ok(policy)
}

impl From<GcPolicyDocument> for GarbageCollectionPolicy {
    fn from(value: GcPolicyDocument) -> Self {
        Self {
            retention_satisfied: value.retention_satisfied,
            legal_hold: value.legal_hold,
            backup_complete: value.backup_complete,
        }
    }
}

fn gc_policy_from_plan(plan: &cigar_store::GarbageCollectionPlan) -> GcPolicyDocument {
    GcPolicyDocument {
        schema_version: GcPolicySchema::V1,
        retention_satisfied: plan.policy().retention_satisfied,
        legal_hold: plan.policy().legal_hold,
        backup_complete: plan.policy().backup_complete,
        max_files: plan.maximum_candidates(),
    }
}

fn production_gc_repository(
    context: &ProductionBackupContext,
) -> Result<Arc<dyn RepositoryBlobStore>, CliError> {
    validate_backup_source(&context.configuration)?;
    let _key_root = canonical_directory(
        &context
            .configuration
            .production
            .blob_key_reference_directory,
    )?;
    let repository = Arc::new(
        MultiTenantLocalRepositoryBlobStore::open(
            &context.configuration.production.blob_directory,
            &context
                .configuration
                .production
                .blob_key_reference_directory,
            Arc::clone(&context.keys),
            context.now,
        )
        .map_err(map_store_error)?,
    );
    let repository: Arc<dyn RepositoryBlobStore> = repository;
    Ok(repository)
}

fn map_store_error(error: StoreError) -> CliError {
    match error.code() {
        StoreErrorCode::InvalidContext | StoreErrorCode::LimitExceeded => CliError::invalid_input(),
        StoreErrorCode::RevisionConflict => CliError::state_conflict(),
        StoreErrorCode::InvalidRecord | StoreErrorCode::MixedSnapshot => CliError::state_corrupt(),
        StoreErrorCode::NotFound
        | StoreErrorCode::Cancelled
        | StoreErrorCode::InjectedAbort
        | StoreErrorCode::Unavailable => CliError::state_unavailable(),
    }
}

fn map_gc_plan_error(error: GarbageCollectionPlanError) -> CliError {
    match error.code() {
        GarbageCollectionPlanErrorCode::InvalidMetadata
        | GarbageCollectionPlanErrorCode::Corrupt => CliError::state_corrupt(),
        GarbageCollectionPlanErrorCode::KeyUnavailable
        | GarbageCollectionPlanErrorCode::UntrustedSigner => CliError::credential_unavailable(),
    }
}

fn gc_blockers(policy: GcPolicyDocument) -> Vec<&'static str> {
    let mut blockers = Vec::new();
    if !policy.retention_satisfied {
        blockers.push("retention_or_replay_window");
    }
    if policy.legal_hold {
        blockers.push("legal_hold");
    }
    if !policy.backup_complete {
        blockers.push("backup_policy");
    }
    blockers
}

fn gc_report_result(
    report: &cigar_store::RepositoryGarbageCollectionReport,
    policy: GcPolicyDocument,
    planned: bool,
) -> Value {
    let blockers = gc_blockers(policy);
    let candidates = report
        .eligible
        .iter()
        .map(|candidate| {
            json!({
                "tenant_id": candidate.tenant_id,
                "digest": candidate.digest
            })
        })
        .collect::<Vec<_>>();
    json!({
        "blockers": blockers,
        "candidate_count": candidates.len(),
        "candidates": candidates,
        "deleted": report.deleted,
        "deletion_allowed": blockers.is_empty(),
        "max_files": policy.max_files,
        "planned": planned,
        "tombstone_visibility": "repository-owned live-root evaluation"
    })
}

fn gc_plan_result(
    plan: &cigar_store::GarbageCollectionPlan,
    policy: GcPolicyDocument,
    path: &Path,
    dry_run: bool,
) -> Value {
    let blockers = gc_blockers(policy);
    json!({
        "blockers": blockers,
        "candidate_count": plan.candidates().len(),
        "candidate_root": plan.candidate_root(),
        "deletion_allowed": blockers.is_empty(),
        "maximum_candidates": plan.maximum_candidates(),
        "plan": path,
        "planned": true,
        "repository_revision": plan.repository_revision().0,
        "signed": true,
        "written": !dry_run
    })
}

async fn serve(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    let config = configuration
        .daemon_config()
        .ok_or_else(CliError::invalid_configuration)?;
    if invocation.options.dry_run {
        let _validated = cigar_daemon::load_configuration(config)
            .map_err(|_error| CliError::invalid_configuration())?;
        return Ok(json!({
            "component": "cigard",
            "config": config,
            "planned": true
        }));
    }
    run_installed(
        "cigard",
        &[
            OsStr::new("serve"),
            OsStr::new("--config"),
            config.as_os_str(),
        ],
        None,
    )
    .await?;
    Ok(json!({"component": "cigard", "stopped": true}))
}

async fn mcp_serve(invocation: &ParsedInvocation) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    if invocation.options.dry_run {
        return Ok(json!({"component": "cigar-mcp", "planned": true}));
    }
    run_installed("cigar-mcp", &[OsStr::new("serve")], None).await?;
    Ok(json!({"component": "cigar-mcp", "stopped": true}))
}

async fn release_verify(invocation: &ParsedInvocation) -> Result<Value, CliError> {
    let directory = exact_one(&invocation.positionals)?;
    run_installed(
        "cargo",
        &[
            OsStr::new("xtask"),
            OsStr::new("release-verify"),
            OsStr::new(directory),
        ],
        Some(invocation.options.deadline),
    )
    .await?;
    Ok(json!({"directory": directory, "verified": true}))
}

async fn run_installed(
    program: &str,
    arguments: &[&OsStr],
    deadline: Option<std::time::Duration>,
) -> Result<(), CliError> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let status = if let Some(deadline) = deadline {
        tokio::time::timeout(deadline, command.status())
            .await
            .map_err(|_elapsed| CliError::deadline_exceeded())?
            .map_err(|_error| CliError::target_unavailable())?
    } else {
        command
            .status()
            .await
            .map_err(|_error| CliError::target_unavailable())?
    };
    if status.success() {
        Ok(())
    } else {
        Err(CliError::external_command_failed())
    }
}

fn persist_mutation(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    state: &mut LocalState,
    cancellation: &BlockingCancellation,
) -> Result<(), CliError> {
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(CliError::state_corrupt)?;
    validate_state(state)?;
    cancellation.checkpoint()?;
    if !invocation.options.dry_run {
        write_state(configuration.project_state_directory(), state)?;
    }
    Ok(())
}

fn read_state(directory: &Path) -> Result<LocalState, CliError> {
    let bytes = read_bounded_regular(&directory.join(STATE_FILE), MAX_STATE_BYTES)?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::state_corrupt())?;
    let state: LocalState =
        serde_json::from_slice(&bytes).map_err(|_error| CliError::state_corrupt())?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &LocalState) -> Result<(), CliError> {
    if !supported_local_state_schema(&state.schema_version) || state.generation == 0 {
        return Err(CliError::state_corrupt());
    }
    for (name, project) in &state.projects {
        validate_name(name)?;
        validate_absolute_stored_path(&project.path)?;
    }
    for (name, source) in &state.sources {
        validate_name(name)?;
        validate_absolute_stored_path(&source.path)?;
    }
    if state.active_project.as_ref().is_some_and(|active| {
        !state
            .projects
            .get(active)
            .is_some_and(|project| project.attached)
    }) || state
        .active_focus
        .as_ref()
        .is_some_and(|focus| validate_name(focus).is_err())
        || state.links.iter().any(|link| {
            link.from == link.to
                || !state
                    .projects
                    .get(&link.from)
                    .is_some_and(|project| project.attached)
                || !state
                    .projects
                    .get(&link.to)
                    .is_some_and(|project| project.attached)
        })
    {
        return Err(CliError::state_corrupt());
    }
    Ok(())
}

fn supported_local_state_schema(schema: &str) -> bool {
    if schema == STATE_SCHEMA {
        return true;
    }
    #[cfg(unix)]
    {
        schema == crate::beta_state_transition::IMPORTED_FULL_STATE_SCHEMA
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn write_state(directory: &Path, state: &LocalState) -> Result<(), CliError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_error| CliError::state_corrupt())?;
    atomic_write(&directory.join(STATE_FILE), &bytes)
}

fn validate_name(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(CliError::invalid_input())
    } else {
        Ok(())
    }
}

fn validate_absolute_stored_path(path: &Path) -> Result<(), CliError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        Err(CliError::state_corrupt())
    } else {
        Ok(())
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, CliError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_error| CliError::state_unavailable())?
            .join(path)
    };
    let metadata =
        std::fs::symlink_metadata(&absolute).map_err(|_error| CliError::state_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::state_unavailable());
    }
    let canonical =
        std::fs::canonicalize(&absolute).map_err(|_error| CliError::state_unavailable())?;
    validate_absolute_stored_path(&canonical)?;
    if canonical
        .to_str()
        .is_none_or(|value| value.chars().any(char::is_control))
    {
        return Err(CliError::invalid_input());
    }
    Ok(canonical)
}

fn exact_one(values: &[String]) -> Result<&String, CliError> {
    let [value] = values else {
        return Err(CliError::invalid_command());
    };
    Ok(value)
}

fn exact_two(values: &[String]) -> Result<&[String; 2], CliError> {
    <&[String; 2]>::try_from(values).map_err(|_error| CliError::invalid_command())
}

fn require_no_positionals(invocation: &ParsedInvocation) -> Result<(), CliError> {
    if invocation.positionals.is_empty() {
        Ok(())
    } else {
        Err(CliError::invalid_command())
    }
}

fn create_private_directory(path: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(path).map_err(|_error| CliError::state_unavailable())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_error| CliError::state_unavailable())?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(CliError::state_unavailable)?;
    create_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".cigar-tmp-{}-{}",
        std::process::id(),
        random_suffix()?
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|_error| CliError::state_unavailable())?;
        file.write_all(bytes)
            .map_err(|_error| CliError::state_unavailable())?;
        file.sync_all()
            .map_err(|_error| CliError::state_unavailable())?;
        std::fs::rename(&temporary, path).map_err(|_error| CliError::state_unavailable())?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ignored = std::fs::remove_file(&temporary);
    }
    result
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let link = std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
    if link.file_type().is_symlink() || !link.is_file() || link.len() > maximum {
        return Err(CliError::state_corrupt());
    }
    let file = File::open(path).map_err(|_error| CliError::state_unavailable())?;
    let metadata = file
        .metadata()
        .map_err(|_error| CliError::state_unavailable())?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(CliError::state_corrupt());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_error| CliError::state_corrupt())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::state_unavailable())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(CliError::state_corrupt());
    }
    Ok(bytes)
}

fn absolute_new_path(path: &Path) -> Result<PathBuf, CliError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_error| CliError::state_unavailable())?
            .join(path)
    };
    let name = absolute.file_name().ok_or_else(CliError::invalid_input)?;
    let parent = absolute.parent().ok_or_else(CliError::invalid_input)?;
    let parent = canonical_directory(parent)?;
    Ok(parent.join(name))
}

fn random_suffix() -> Result<String, CliError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_error| CliError::state_unavailable())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CliError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_error| CliError::state_unavailable())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), CliError> {
    // Rust's portable file API cannot open directory handles on Windows. File bytes are flushed
    // before the no-clobber hard-link publication; the directory durability barrier is Unix-only.
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{BETA_STATE_ANCESTOR_SWAP_PROBE, BetaStateAncestorSwapProbe};
    use super::{
        LocalState, SupportArchiveEntry, decode_effect_list_cursor, encode_effect_list_cursor,
        inspect_beta_state, read_frozen_beta_state_file, read_state, render_support_tar,
        require_complete_effect_backup, validate_private_regular, write_new_private_file,
        write_state,
    };
    use crate::arguments::{GlobalOptions, ParsedInvocation};
    use std::path::Path;

    #[test]
    fn production_backup_rejects_legacy_manifest_without_effect_checkpoint() {
        let manifest = cigar_store::BackupManifest {
            format_version: 1,
            schema_version: 3,
            repository_revision: 0,
            created_at_unix_nanos: 1,
            files: Vec::new(),
            key_references: vec!["legacy-key".to_owned()],
            canonical_root: format!("1220{}", "0".repeat(64)),
        };
        assert!(require_complete_effect_backup(Path::new("."), &manifest).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn signed_gc_plan_file_publication_is_private_and_no_clobber()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let path = root.join("gc-plan.json");
        write_new_private_file(&path, b"first signed plan")?;
        let metadata = std::fs::symlink_metadata(&path)?;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        validate_private_regular(&path)?;
        assert!(write_new_private_file(&path, b"replacement plan").is_err());
        assert_eq!(std::fs::read(path)?, b"first signed plan");
        Ok(())
    }

    #[test]
    fn local_state_round_trips_unicode_paths_and_rejects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let state_directory = directory.path().join("state with 🐝");
        std::fs::create_dir(&state_directory)?;
        assert!(write_state(&state_directory, &LocalState::default()).is_ok());
        let bytes = std::fs::read(state_directory.join("state.json"))?;
        assert!(cigar_canon::parse_strict_json(&bytes).is_ok());
        assert!(serde_json::from_slice::<LocalState>(&bytes).is_ok());
        let loaded = read_state(&state_directory);
        assert!(loaded.is_ok());
        assert_eq!(loaded?, LocalState::default());
        std::fs::write(state_directory.join("state.json"), b"{\"generation\":0}")?;
        assert!(read_state(&state_directory).is_err());
        Ok(())
    }

    #[test]
    fn effect_list_cursor_is_versioned_bounded_and_snapshot_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000901")?;
        let effect = cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000902")?;
        let repository_cursor = cigar_store::EffectRecoveryCursor::resume(
            tenant.clone(),
            cigar_store::StoreRevision(7),
            effect.clone(),
        )?;
        let encoded = encode_effect_list_cursor(tenant.clone(), Some(&repository_cursor))?;
        let decoded = decode_effect_list_cursor(&encoded)?;
        assert_eq!(decoded.tenant_id, tenant);
        assert_eq!(decoded.revision, Some(7));
        assert_eq!(decoded.last_effect_id, Some(effect));
        assert!(decode_effect_list_cursor("not-base64!").is_err());
        Ok(())
    }

    #[test]
    fn support_tar_is_deterministic_bounded_and_rejects_unsafe_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let canary = b"private-catalog-content-must-not-escape";
        let entries = vec![
            SupportArchiveEntry {
                name: "inventory.json".to_owned(),
                bytes: br#"{"content_free":true}"#.to_vec(),
            },
            SupportArchiveEntry {
                name: "diagnostics.json".to_owned(),
                bytes: br#"{"ready":true}"#.to_vec(),
            },
        ];
        let first = render_support_tar(&entries)?;
        let second = render_support_tar(&entries)?;
        assert_eq!(first, second);
        assert_eq!(first.len() % 512, 0);
        assert!(first.ends_with(&[0_u8; 1024]));
        assert_eq!(first.get(..14), Some(b"inventory.json".as_slice()));
        assert_eq!(first.get(257..263), Some(b"ustar\0".as_slice()));
        assert!(!first.windows(canary.len()).any(|window| window == canary));

        let unsafe_entry = SupportArchiveEntry {
            name: "../private.json".to_owned(),
            bytes: canary.to_vec(),
        };
        assert!(render_support_tar(&[unsafe_entry]).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn beta_state_plan_is_content_free_read_only_and_blocks_both_directions()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/beta-state-v0.1.0-beta.1/valid.json"
        ))?;
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let state_path = root.join("state.json");
        std::fs::write(&state_path, &fixture)?;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))?;
        let invocation = ParsedInvocation {
            command: crate::command::lookup("state.inspect-beta").ok_or("missing command")?,
            positionals: vec![state_path.to_string_lossy().into_owned()],
            options: GlobalOptions::default(),
        };

        let plan = inspect_beta_state(&invocation)?;
        assert_eq!(std::fs::read(&state_path)?, fixture);
        assert_eq!(
            plan.pointer("/source/generation"),
            Some(&serde_json::json!(41))
        );
        assert_eq!(
            plan.pointer("/source/project_count"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(
            plan.pointer("/transition/application/status"),
            Some(&serde_json::json!("explicit-command-required"))
        );
        assert_eq!(
            plan.pointer("/transition/downgrade/status"),
            Some(&serde_json::json!("blocked"))
        );
        let rendered = serde_json::to_string(&plan)?;
        for private_value in [
            "project.alpha",
            "project-beta",
            "source_docs",
            "/Users/example",
            state_path.to_str().ok_or("state path")?,
        ] {
            assert!(
                !rendered.contains(private_value),
                "content-free plan leaked {private_value}"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn beta_state_reader_rejects_unsafe_permissions_hard_links_and_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/beta-state-v0.1.0-beta.1/valid-min.json"
        ))?;
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let state_path = root.join("state.json");
        std::fs::write(&state_path, &fixture)?;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(read_frozen_beta_state_file(&state_path)?, fixture);

        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640))?;
        assert!(read_frozen_beta_state_file(&state_path).is_err());
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))?;

        let hard_link = root.join("hard-link.json");
        std::fs::hard_link(&state_path, &hard_link)?;
        assert!(read_frozen_beta_state_file(&state_path).is_err());
        std::fs::remove_file(hard_link)?;
        assert_eq!(read_frozen_beta_state_file(&state_path)?, fixture);

        let symlink = root.join("symlink.json");
        std::os::unix::fs::symlink(&state_path, &symlink)?;
        assert!(read_frozen_beta_state_file(&symlink).is_err());
        assert_eq!(std::fs::read(&state_path)?, fixture);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn beta_state_reader_rejects_symlinked_ancestors_and_stays_bound_during_ancestor_swap()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let original_bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/beta-state-v0.1.0-beta.1/valid-min.json"
        ))?;
        let replacement_bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/beta-state-v0.1.0-beta.1/valid.json"
        ))?;
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let pinned = root.join("pinned");
        let replacement = root.join("replacement");
        std::fs::create_dir(&pinned)?;
        std::fs::create_dir(&replacement)?;
        std::fs::set_permissions(&pinned, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700))?;
        for (parent, bytes) in [
            (&pinned, &original_bytes),
            (&replacement, &replacement_bytes),
        ] {
            let state = parent.join("state.json");
            std::fs::write(&state, bytes)?;
            std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o600))?;
        }

        let symlinked_parent = root.join("symlinked-parent");
        std::os::unix::fs::symlink(&pinned, &symlinked_parent)?;
        assert!(read_frozen_beta_state_file(&symlinked_parent.join("state.json")).is_err());

        let displaced = root.join("displaced");
        *BETA_STATE_ANCESTOR_SWAP_PROBE
            .lock()
            .map_err(|_error| std::io::Error::other("swap probe poisoned"))? =
            Some(BetaStateAncestorSwapProbe {
                parent: pinned.clone(),
                displaced: displaced.clone(),
                replacement: replacement.clone(),
            });
        let observed = read_frozen_beta_state_file(&pinned.join("state.json"))?;
        assert_eq!(observed, original_bytes);
        assert_eq!(std::fs::read(pinned.join("state.json"))?, replacement_bytes);
        assert_eq!(std::fs::read(displaced.join("state.json"))?, original_bytes);
        Ok(())
    }
}
