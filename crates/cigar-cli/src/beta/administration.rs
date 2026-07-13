//! Transport-free embedded-local administration for the initial beta.

use crate::arguments::ParsedInvocation;
use crate::client::OperationResponse;
use crate::configuration::EffectiveConfiguration;
use crate::error::CliError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

const MAX_BLOCKING_ADMINISTRATION_TASKS: usize = 4;
const STATE_SCHEMA: &str = "cigar.cli-administration.v1";
const STATE_FILE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

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
struct BlockingCancellation(Arc<AtomicBool>);

impl BlockingCancellation {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn checkpoint(&self) -> Result<(), CliError> {
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

struct StateDirectoryLock {
    directory: File,
    path: PathBuf,
}

impl StateDirectoryLock {
    fn acquire(
        path: &Path,
        exclusive: bool,
        cancellation: &BlockingCancellation,
    ) -> Result<Self, CliError> {
        validate_private_directory(path)?;
        let expected =
            std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
        let directory = open_directory_nofollow(path)?;
        let opened = directory
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        if !opened.is_dir() {
            return Err(CliError::state_unavailable());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if opened.dev() != expected.dev()
                || opened.ino() != expected.ino()
                || opened.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(CliError::state_unavailable());
            }
        }
        loop {
            cancellation.checkpoint()?;
            let result = if exclusive {
                directory.try_lock()
            } else {
                directory.try_lock_shared()
            };
            match result {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::Error(_error)) => {
                    return Err(CliError::state_unavailable());
                }
            }
        }
        Ok(Self {
            directory,
            path: path.to_path_buf(),
        })
    }

    fn ensure_path_binding(&self) -> Result<(), CliError> {
        let current = open_directory_nofollow(&self.path)?;
        let expected = self
            .directory
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        let observed = current
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let owner = rustix::process::geteuid().as_raw();
            if expected.dev() != observed.dev()
                || expected.ino() != observed.ino()
                || expected.uid() != owner
                || observed.uid() != owner
                || expected.mode() & 0o077 != 0
                || observed.mode() & 0o077 != 0
            {
                return Err(CliError::state_unavailable());
            }
        }
        Ok(())
    }

    fn state_exists(&self) -> Result<bool, CliError> {
        self.ensure_path_binding()?;
        match self.open_state_read() {
            Ok(_file) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_error) => Err(CliError::state_corrupt()),
        }
    }

    #[cfg(unix)]
    fn open_state_read(&self) -> std::io::Result<File> {
        use rustix::fs::{Mode, OFlags, openat};

        openat(
            &self.directory,
            STATE_FILE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
    }

    #[cfg(not(unix))]
    fn open_state_read(&self) -> std::io::Result<File> {
        File::open(self.path.join(STATE_FILE))
    }

    fn read_bytes(&self, maximum: u64) -> Result<Vec<u8>, CliError> {
        self.ensure_path_binding()?;
        let mut file = self.open_state_read().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CliError::state_unavailable()
            } else {
                CliError::state_corrupt()
            }
        })?;
        let before = file
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        validate_state_file_metadata(&before, maximum)?;
        let capacity = usize::try_from(before.len()).map_err(|_error| CliError::state_corrupt())?;
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_error| CliError::state_unavailable())?;
        let after = file
            .metadata()
            .map_err(|_error| CliError::state_unavailable())?;
        validate_state_file_metadata(&after, maximum)?;
        if u64::try_from(bytes.len()).ok() != Some(before.len()) || before.len() != after.len() {
            return Err(CliError::state_corrupt());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(CliError::state_corrupt());
            }
        }
        self.ensure_path_binding()?;
        Ok(bytes)
    }

    fn write_bytes(&self, bytes: &[u8]) -> Result<(), CliError> {
        self.ensure_path_binding()?;
        let temporary = format!(
            ".cigar-beta-tmp-{}-{}",
            std::process::id(),
            random_suffix()?
        );
        self.write_bytes_to_temporary(&temporary, bytes)
    }

    #[cfg(unix)]
    fn write_bytes_to_temporary(&self, temporary: &str, bytes: &[u8]) -> Result<(), CliError> {
        use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};

        let owned = openat(
            &self.directory,
            temporary,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_error| CliError::state_unavailable())?;
        let mut file = File::from(owned);
        let result = (|| {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_error| CliError::state_unavailable())?;
            validate_state_file_metadata(
                &file
                    .metadata()
                    .map_err(|_error| CliError::state_unavailable())?,
                MAX_STATE_BYTES,
            )?;
            file.write_all(bytes)
                .map_err(|_error| CliError::state_unavailable())?;
            file.sync_all()
                .map_err(|_error| CliError::state_unavailable())?;
            self.ensure_path_binding()?;
            renameat(&self.directory, temporary, &self.directory, STATE_FILE)
                .map_err(|_error| CliError::state_unavailable())?;
            self.directory
                .sync_all()
                .map_err(|_error| CliError::state_unavailable())?;
            self.ensure_path_binding()
        })();
        if result.is_err() {
            let _ignored = unlinkat(&self.directory, temporary, AtFlags::empty());
        }
        result
    }

    #[cfg(not(unix))]
    fn write_bytes_to_temporary(&self, temporary: &str, bytes: &[u8]) -> Result<(), CliError> {
        let path = self.path.join(temporary);
        let mut options = std::fs::OpenOptions::new();
        let result = (|| {
            let mut file = options
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_error| CliError::state_unavailable())?;
            file.write_all(bytes)
                .map_err(|_error| CliError::state_unavailable())?;
            file.sync_all()
                .map_err(|_error| CliError::state_unavailable())?;
            self.ensure_path_binding()?;
            std::fs::rename(&path, self.path.join(STATE_FILE))
                .map_err(|_error| CliError::state_unavailable())?;
            self.directory
                .sync_all()
                .map_err(|_error| CliError::state_unavailable())?;
            self.ensure_path_binding()
        })();
        if result.is_err() {
            let _ignored = std::fs::remove_file(path);
        }
        result
    }
}

pub(crate) async fn execute(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    deadline_at: tokio::time::Instant,
) -> Result<OperationResponse, CliError> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let cancellation = BlockingCancellation::new();
    let cancel_on_drop = CancelBlockingOnDrop(cancellation.clone());
    let slots = Arc::clone(SLOTS.get_or_init(|| {
        Arc::new(tokio::sync::Semaphore::new(
            MAX_BLOCKING_ADMINISTRATION_TASKS,
        ))
    }));
    let permit = tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => {
            let _ignored = signal;
            return Err(CliError::interrupted());
        }
        _ = tokio::time::sleep_until(deadline_at) => {
            return Err(CliError::deadline_exceeded());
        }
        permit = slots.acquire_owned() => {
            permit.map_err(|_closed| CliError::state_unavailable())?
        }
    };
    cancellation.checkpoint()?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let invocation = invocation.clone();
    let configuration = configuration.clone();
    let worker_cancellation = cancellation.clone();
    std::thread::Builder::new()
        .name("cigar-beta-embedded-administration".to_owned())
        .spawn(move || {
            let result = execute_blocking(&invocation, &configuration, &worker_cancellation);
            let _ignored = sender.send(result);
            drop(permit);
        })
        .map_err(|_error| CliError::state_unavailable())?;
    let mut receiver = receiver;
    enum StopReason {
        Interrupted,
        Deadline,
    }
    let stop_reason = tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => {
            let _ignored = signal;
            Some(StopReason::Interrupted)
        }
        _ = tokio::time::sleep_until(deadline_at) => Some(StopReason::Deadline),
        result = &mut receiver => {
            drop(cancel_on_drop);
            return result.map_err(|_closed| CliError::state_unavailable())?;
        }
    };

    cancellation.cancel();
    let settled = receiver.await;
    drop(cancel_on_drop);
    if let Ok(Ok(response)) = settled {
        // The update crossed its commit boundary before cancellation. Report the committed
        // result instead of returning an ambiguous timeout while work continues in the background.
        return Ok(response);
    }
    match stop_reason {
        Some(StopReason::Interrupted) => Err(CliError::interrupted()),
        Some(StopReason::Deadline) => Err(CliError::deadline_exceeded()),
        None => Err(CliError::state_unavailable()),
    }
}

fn execute_blocking(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<OperationResponse, CliError> {
    cancellation.checkpoint()?;
    let path = invocation.command.path();
    if path == "init" {
        let result = initialize(invocation, configuration, cancellation)?;
        cancellation.checkpoint()?;
        return Ok(OperationResponse {
            operation_id: "cigar.cli.beta-embedded.init.v1".to_owned(),
            result,
            semantic_etag: None,
            next_page_cursor: None,
        });
    }
    let state = StateDirectoryLock::acquire(
        configuration.project_state_directory(),
        invocation.command.mutates() && !invocation.options.dry_run,
        cancellation,
    )?;
    let result = match path {
        "source.add" => source_add(invocation, &state, cancellation)?,
        "source.list" => source_list(invocation, &state)?,
        "source.remove" => source_remove(invocation, &state, cancellation)?,
        "project.list" => project_list(invocation, &state)?,
        "project.attach" => project_attach(invocation, &state, cancellation)?,
        "project.detach" => project_detach(invocation, &state, cancellation)?,
        "project.switch" => project_switch(invocation, &state, cancellation)?,
        "project.link" => project_link(invocation, &state, cancellation)?,
        "project.unlink" => project_unlink(invocation, &state, cancellation)?,
        "focus.switch" => focus_switch(invocation, &state, cancellation)?,
        "focus.close" => focus_close(invocation, &state, cancellation)?,
        _ => return Err(CliError::invalid_command()),
    };
    cancellation.checkpoint()?;
    Ok(OperationResponse {
        operation_id: format!("cigar.cli.beta-embedded.{}.v1", path.replace('.', "-")),
        result,
        semantic_etag: None,
        next_page_cursor: None,
    })
}

fn initialize(
    invocation: &ParsedInvocation,
    configuration: &EffectiveConfiguration,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    if invocation.positionals.len() > 1
        || (invocation.options.config.is_some() && !invocation.positionals.is_empty())
    {
        return Err(CliError::invalid_command());
    }
    let state_directory = if let Some(root) = invocation.positionals.first() {
        canonical_directory(Path::new(root))?.join(".cigar")
    } else {
        configuration.project_state_directory().to_path_buf()
    };
    let exists = match std::fs::symlink_metadata(&state_directory) {
        Ok(_metadata) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_error) => return Err(CliError::state_unavailable()),
    };
    if !exists && invocation.options.dry_run {
        return Ok(json!({
            "initialized": false,
            "planned": true,
            "generation": 1,
            "state_directory": state_directory
        }));
    }
    if !exists {
        cancellation.checkpoint()?;
        create_private_directory(&state_directory)?;
    }
    let state =
        StateDirectoryLock::acquire(&state_directory, !invocation.options.dry_run, cancellation)?;
    cancellation.checkpoint()?;
    if state.state_exists()? {
        let existing = read_state(&state)?;
        return Ok(json!({
            "initialized": false,
            "generation": existing.generation,
            "state_directory": state_directory
        }));
    }
    if !invocation.options.dry_run {
        write_state(&state, &LocalState::default())?;
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
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [source_id, path] = exact_two(&invocation.positionals)?;
    validate_name(source_id)?;
    let path = canonical_directory(Path::new(path))?;
    let mut state = read_state(store)?;
    if state.sources.contains_key(source_id) {
        return Err(CliError::state_conflict());
    }
    state
        .sources
        .insert(source_id.clone(), SourceEntry { path: path.clone() });
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({"source_id": source_id, "path": path, "generation": state.generation}))
}

fn source_list(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    let state = read_state(store)?;
    let sources = state
        .sources
        .into_iter()
        .map(|(source_id, source)| json!({"source_id": source_id, "path": source.path}))
        .collect::<Vec<_>>();
    Ok(json!({"sources": sources, "generation": state.generation}))
}

fn source_remove(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let source_id = exact_one(&invocation.positionals)?;
    let mut state = read_state(store)?;
    if state.sources.remove(source_id).is_none() {
        return Err(CliError::state_conflict());
    }
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({
        "source_id": source_id,
        "removed": !invocation.options.dry_run,
        "generation": state.generation
    }))
}

fn project_list(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
) -> Result<Value, CliError> {
    require_no_positionals(invocation)?;
    let state = read_state(store)?;
    let projects = state
        .projects
        .iter()
        .map(|(project_id, project)| {
            json!({
                "project_id": project_id,
                "path": project.path,
                "attached": project.attached,
                "active": state.active_project.as_ref() == Some(project_id)
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"projects": projects, "generation": state.generation}))
}

fn project_attach(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [project_id, path] = exact_two(&invocation.positionals)?;
    validate_name(project_id)?;
    let path = canonical_directory(Path::new(path))?;
    let mut state = read_state(store)?;
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
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({
        "project_id": project_id,
        "path": path,
        "attached": true,
        "generation": state.generation
    }))
}

fn project_detach(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let project_id = exact_one(&invocation.positionals)?;
    let mut state = read_state(store)?;
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
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({
        "project_id": project_id,
        "attached": false,
        "generation": state.generation
    }))
}

fn project_switch(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let project_id = exact_one(&invocation.positionals)?;
    let mut state = read_state(store)?;
    if !state
        .projects
        .get(project_id)
        .is_some_and(|project| project.attached)
    {
        return Err(CliError::state_conflict());
    }
    state.active_project = Some(project_id.clone());
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({"active_project": project_id, "generation": state.generation}))
}

fn project_link(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [from, to] = exact_two(&invocation.positionals)?;
    if from == to {
        return Err(CliError::state_conflict());
    }
    let mut state = read_state(store)?;
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
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({"from": from, "to": to, "linked": true, "generation": state.generation}))
}

fn project_unlink(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let [from, to] = exact_two(&invocation.positionals)?;
    let mut state = read_state(store)?;
    if !state.links.remove(&ProjectLink {
        from: from.clone(),
        to: to.clone(),
    }) {
        return Err(CliError::state_conflict());
    }
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({"from": from, "to": to, "linked": false, "generation": state.generation}))
}

fn focus_switch(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    let focus_id = exact_one(&invocation.positionals)?;
    validate_name(focus_id)?;
    let mut state = read_state(store)?;
    state.active_focus = Some(focus_id.clone());
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({"active_focus": focus_id, "generation": state.generation}))
}

fn focus_close(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
    cancellation: &BlockingCancellation,
) -> Result<Value, CliError> {
    if invocation.positionals.len() > 1 {
        return Err(CliError::invalid_command());
    }
    let mut state = read_state(store)?;
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
    persist_mutation(invocation, store, &mut state, cancellation)?;
    Ok(json!({
        "closed_focus": closed,
        "generation": state.generation,
        "planned": invocation.options.dry_run
    }))
}

fn persist_mutation(
    invocation: &ParsedInvocation,
    store: &StateDirectoryLock,
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
        write_state(store, state)?;
    }
    Ok(())
}

fn read_state(store: &StateDirectoryLock) -> Result<LocalState, CliError> {
    let bytes = store.read_bytes(MAX_STATE_BYTES)?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::state_corrupt())?;
    let state: LocalState =
        serde_json::from_slice(&bytes).map_err(|_error| CliError::state_corrupt())?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &LocalState) -> Result<(), CliError> {
    if state.schema_version != STATE_SCHEMA || state.generation == 0 {
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

fn write_state(store: &StateDirectoryLock, state: &LocalState) -> Result<(), CliError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_error| CliError::state_corrupt())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_STATE_BYTES) {
        return Err(CliError::state_corrupt());
    }
    store.write_bytes(&bytes)
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
        || path
            .to_str()
            .is_none_or(|value| value.chars().any(char::is_control))
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
    if path.exists() {
        validate_private_directory(path)?;
        return Ok(());
    }
    let parent = path.parent().ok_or_else(CliError::state_unavailable)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_error| CliError::state_unavailable())?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(CliError::state_unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if parent_metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(CliError::state_unavailable());
        }
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|_error| CliError::state_unavailable())?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_error| CliError::state_unavailable())?;
    }
    #[cfg(not(unix))]
    builder
        .create(path)
        .map_err(|_error| CliError::state_unavailable())?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), CliError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::state_unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(CliError::state_unavailable());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::state_unavailable())
}

#[cfg(not(unix))]
fn open_directory_nofollow(path: &Path) -> Result<File, CliError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::state_unavailable());
    }
    File::open(path).map_err(|_error| CliError::state_unavailable())
}

fn validate_state_file_metadata(
    metadata: &std::fs::Metadata,
    maximum: u64,
) -> Result<(), CliError> {
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(CliError::state_corrupt());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            return Err(CliError::state_corrupt());
        }
    }
    Ok(())
}

fn random_suffix() -> Result<String, CliError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_error| CliError::state_unavailable())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        BlockingCancellation, LocalState, StateDirectoryLock, create_private_directory, read_state,
        write_state,
    };

    #[test]
    fn descriptor_relative_state_rejects_a_locked_directory_swap()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let configured = root.path().join("configured");
        let replacement = root.path().join("replacement");
        let displaced = root.path().join("displaced");
        create_private_directory(&configured).map_err(|error| error.to_string())?;
        create_private_directory(&replacement).map_err(|error| error.to_string())?;
        let cancellation = BlockingCancellation::new();
        let configured_lock = StateDirectoryLock::acquire(&configured, true, &cancellation)
            .map_err(|error| error.to_string())?;
        let replacement_lock = StateDirectoryLock::acquire(&replacement, true, &cancellation)
            .map_err(|error| error.to_string())?;
        write_state(&configured_lock, &LocalState::default()).map_err(|error| error.to_string())?;
        let replacement_state = LocalState {
            generation: 7,
            ..LocalState::default()
        };
        write_state(&replacement_lock, &replacement_state).map_err(|error| error.to_string())?;

        std::fs::rename(&configured, &displaced)?;
        std::fs::rename(&replacement, &configured)?;
        let redirected_mutation = LocalState {
            generation: 2,
            ..LocalState::default()
        };
        assert!(write_state(&configured_lock, &redirected_mutation).is_err());

        drop(replacement_lock);
        drop(configured_lock);
        let observed = StateDirectoryLock::acquire(&configured, false, &cancellation)
            .map_err(|error| error.to_string())?;
        assert_eq!(
            read_state(&observed)
                .map_err(|error| error.to_string())?
                .generation,
            7
        );
        Ok(())
    }

    #[test]
    fn locked_state_rejects_permissions_widened_after_acquisition()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir()?;
        let configured = root.path().join("configured");
        create_private_directory(&configured).map_err(|error| error.to_string())?;
        let cancellation = BlockingCancellation::new();
        let lock = StateDirectoryLock::acquire(&configured, true, &cancellation)
            .map_err(|error| error.to_string())?;
        write_state(&lock, &LocalState::default()).map_err(|error| error.to_string())?;

        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o750))?;
        assert!(read_state(&lock).is_err());
        assert!(write_state(&lock, &LocalState::default()).is_err());

        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
}
