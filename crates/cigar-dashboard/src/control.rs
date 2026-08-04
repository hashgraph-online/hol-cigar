//! Fixed-profile native macOS child supervision for optional dashboard controls.

use crate::history::{
    RecoverableRun, RunProcessIdentity, RunResourceReservation, RunResourceUsage,
};
use crate::{
    AvailabilityState, DashboardConfig, EvidenceCategory, EvidenceDescriptor, EvidenceStatus,
    HistoryClient, ReceiptError, ReceiptVerifier, RunProfile, RunProfileRegistry, RunRecord,
    RunState, SafeEventAttribute, SafeEventAttributes, SafeEventBroker, SafeEventKind,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use zeroize::Zeroizing;

const SUPERVISOR_RECEIPT_SCHEMA: &str = "cigar.dashboard-supervisor-receipt.v1";
const SUPERVISOR_RECEIPT_NAME: &str = "dashboard-supervisor-receipt.v1.json";
const LIVENESS_LOCK_NAME: &str = "dashboard-child.liveness";
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PS_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_SOURCE_REVISION_BYTES: usize = 128;
const MAX_READ_ONLY_JOBS: usize = 4;
const PS_DEADLINE: Duration = Duration::from_secs(2);
const OUTPUT_SETTLEMENT_GRACE: Duration = Duration::from_secs(2);
const RESOURCE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DISK_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_ENTRIES: usize = 100_000;
const MAX_TOOL_VERSION_BYTES: u64 = 4096;
const TOOL_VERSION_DEADLINE: Duration = Duration::from_secs(2);
const MAX_CHILD_OPEN_FILES: u64 = 1024;
const MAX_SOURCE_INPUTS: usize = 100_000;
const MAX_SOURCE_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SOURCE_TOTAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const GIT_DEADLINE: Duration = Duration::from_secs(120);
const SNAPSHOT_DIRECTORY_NAME: &str = "source-snapshot";

/// Stable content-free control-plane failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    /// Control is disabled or the requested profile is not available in this cohort.
    Unavailable,
    /// The profile ID or stored run identity is invalid.
    InvalidRequest,
    /// A configured root or captured executable failed filesystem verification.
    UnsafePath,
    /// The exact configured source revision is not checked out.
    SourceMismatch,
    /// The bounded global or concurrency-group capacity is exhausted.
    Capacity,
    /// Run lifecycle persistence was unavailable.
    Persistence,
    /// Startup found an active row whose prior child could not be safely disproved.
    RecoveryRequired,
    /// The reviewed process could not be created.
    SpawnFailed,
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "dashboard control profile is unavailable",
            Self::InvalidRequest => "dashboard control request is invalid",
            Self::UnsafePath => "dashboard control path is unsafe",
            Self::SourceMismatch => "dashboard control source binding is invalid",
            Self::Capacity => "dashboard control capacity is exhausted",
            Self::Persistence => "dashboard control persistence is unavailable",
            Self::RecoveryRequired => "dashboard control recovery requires operator settlement",
            Self::SpawnFailed => "dashboard reviewed process could not be started",
        })
    }
}

impl std::error::Error for ControlError {}

#[derive(Clone, Debug)]
struct ExecutableIdentity {
    bytes: u64,
    device: u64,
    path: PathBuf,
    digest: String,
    inode: u64,
    lineage: Vec<PathIdentity>,
    mode: u32,
    owner_uid: u32,
}

#[derive(Clone, Debug)]
struct PathIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    path: PathBuf,
}

impl ExecutableIdentity {
    fn capture(path: &Path) -> Result<Self, ControlError> {
        let canonical = path
            .canonicalize()
            .map_err(|_error| ControlError::UnsafePath)?;
        let lineage = capture_path_lineage(&canonical)?;
        let metadata =
            fs::symlink_metadata(&canonical).map_err(|_error| ControlError::UnsafePath)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err(ControlError::UnsafePath);
        }
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ControlError::UnsafePath);
        }
        let digest = digest_file(&canonical, MAX_EXECUTABLE_BYTES)?;
        verify_path_lineage(&lineage)?;
        #[cfg(not(unix))]
        return Err(ControlError::Unavailable);
        #[cfg(unix)]
        let identity = Self {
            bytes: metadata.len(),
            device: metadata.dev(),
            path: canonical,
            digest,
            inode: metadata.ino(),
            lineage,
            mode: metadata.mode(),
            owner_uid: metadata.uid(),
        };
        identity.verify()?;
        Ok(identity)
    }

    fn verify(&self) -> Result<(), ControlError> {
        verify_path_lineage(&self.lineage)?;
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|_error| ControlError::UnsafePath)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != self.bytes
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.mode() != self.mode
                || metadata.uid() != self.owner_uid
            {
                return Err(ControlError::UnsafePath);
            }
        }
        if digest_file(&self.path, MAX_EXECUTABLE_BYTES)? == self.digest {
            Ok(())
        } else {
            Err(ControlError::UnsafePath)
        }
    }
}

fn capture_path_lineage(path: &Path) -> Result<Vec<PathIdentity>, ControlError> {
    let parent = path.parent().ok_or(ControlError::UnsafePath)?;
    let mut current = PathBuf::from("/");
    let root_metadata =
        fs::symlink_metadata(&current).map_err(|_error| ControlError::UnsafePath)?;
    let mut lineage = vec![path_identity(&current, &root_metadata)?];
    for component in parent.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(name) => current.push(name),
            _ => return Err(ControlError::UnsafePath),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_error| ControlError::UnsafePath)?;
        lineage.push(path_identity(&current, &metadata)?);
    }
    Ok(lineage)
}

fn path_identity(path: &Path, metadata: &fs::Metadata) -> Result<PathIdentity, ControlError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = metadata.mode() & 0o7777;
        let owner_uid = metadata.uid();
        let sticky_private_tmp =
            path == Path::new("/private/tmp") && owner_uid == 0 && mode & 0o1777 == 0o1777;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || owner_uid != 0 && owner_uid != rustix::process::geteuid().as_raw()
            || mode & 0o022 != 0 && !sticky_private_tmp
        {
            return Err(ControlError::UnsafePath);
        }
        Ok(PathIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode,
            owner_uid,
            path: path.to_owned(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ignored = (path, metadata);
        Err(ControlError::Unavailable)
    }
}

fn verify_path_lineage(lineage: &[PathIdentity]) -> Result<(), ControlError> {
    if lineage.is_empty() {
        return Err(ControlError::UnsafePath);
    }
    for expected in lineage {
        let metadata =
            fs::symlink_metadata(&expected.path).map_err(|_error| ControlError::UnsafePath)?;
        let observed = path_identity(&expected.path, &metadata)?;
        if observed.device != expected.device
            || observed.inode != expected.inode
            || observed.mode != expected.mode
            || observed.owner_uid != expected.owner_uid
        {
            return Err(ControlError::UnsafePath);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ExecutionInput {
    bytes: u64,
    mode: u32,
    owner_uid: u32,
    path: String,
    role: &'static str,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GitTreeEntry {
    mode: u32,
    path: String,
}

#[derive(Clone, Debug)]
struct SourceStatus {
    clean: bool,
    revision: String,
}

#[derive(Debug)]
struct ExecutionSnapshot {
    inputs: Vec<ExecutionInput>,
    root: PathBuf,
    source_tree_sha256: String,
    tree_entries: Vec<GitTreeEntry>,
}

#[derive(Clone, Debug)]
struct CapturedToolchain {
    launcher: ExecutableIdentity,
    python3: Option<ExecutableIdentity>,
    python3_version_sha256: Option<String>,
    git: ExecutableIdentity,
    ps: ExecutableIdentity,
    captured: BTreeMap<String, ExecutableIdentity>,
    safe_path: OsString,
}

impl CapturedToolchain {
    fn capture(private_root: &Path) -> Result<Self, ControlError> {
        #[cfg(not(test))]
        let launcher = ExecutableIdentity::capture(
            &std::env::current_exe().map_err(|_error| ControlError::Unavailable)?,
        )?;
        let source_path = std::env::var_os("PATH").ok_or(ControlError::UnsafePath)?;
        let captured = capture_available_programs(&source_path);
        let git = captured
            .get("git")
            .ok_or(ControlError::Unavailable)?
            .clone();
        let python3 = captured.get("python3").cloned();
        // Unit-test binaries can be atomically replaced by a concurrent Cargo build after the
        // process starts. Unit tests bypass the self-launcher, while the separate binary
        // integration suite exercises its real identity and limits, so avoid binding this
        // otherwise-unused test-only field to the mutable test artifact.
        #[cfg(test)]
        let launcher = python3.clone().ok_or(ControlError::Unavailable)?;
        let ps = captured.get("ps").ok_or(ControlError::Unavailable)?.clone();
        let shim = create_toolchain_shim(private_root, &captured)?;
        let safe_path = std::env::join_paths([shim]).map_err(|_error| ControlError::UnsafePath)?;
        let python3_version_sha256 = python3.as_ref().map(capture_tool_version).transpose()?;
        Ok(Self {
            launcher,
            python3,
            python3_version_sha256,
            git,
            ps,
            captured,
            safe_path,
        })
    }

    fn for_profile(&self, profile: &RunProfile) -> Option<&ExecutableIdentity> {
        match profile.executable() {
            crate::ProfileExecutable::Python3 => self.python3.as_ref(),
            crate::ProfileExecutable::Cargo | crate::ProfileExecutable::CigarSoak => None,
        }
    }

    fn version_digest_for_profile(&self, profile: &RunProfile) -> Option<&str> {
        match profile.executable() {
            crate::ProfileExecutable::Python3 => self.python3_version_sha256.as_deref(),
            crate::ProfileExecutable::Cargo | crate::ProfileExecutable::CigarSoak => None,
        }
    }

    fn has_profile_tools(&self, profile: &RunProfile) -> bool {
        let required: &[&str] = match profile.id() {
            "dashboard-contracts" => &["python3"],
            "security-matrix" => &["bash", "cargo", "cargo-nextest", "python3", "rustc"],
            "compatibility-matrix" => &[
                "bash",
                "cargo",
                "cargo-nextest",
                "corepack",
                "go",
                "node",
                "python3",
                "rustc",
                "uv",
            ],
            _ => return false,
        };
        required
            .iter()
            .all(|name| self.captured.contains_key(*name))
    }

    fn source_status(&self, workspace_root: &Path) -> Result<SourceStatus, ControlError> {
        self.verify_all()?;
        let output = run_git_capture(
            self,
            workspace_root,
            &["rev-parse", "--verify", "HEAD"],
            MAX_SOURCE_REVISION_BYTES as u64 + 1,
        )?;
        if output.is_empty() || output.len() > MAX_SOURCE_REVISION_BYTES + 1 {
            return Err(ControlError::SourceMismatch);
        }
        let revision = std::str::from_utf8(&output)
            .map_err(|_error| ControlError::SourceMismatch)?
            .trim();
        if !(revision.len() == 40 || revision.len() == 64)
            || !revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ControlError::SourceMismatch);
        }
        let status = run_git_capture(
            self,
            workspace_root,
            &[
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.ignoreStat=false",
                "-c",
                "core.untrackedCache=false",
                "status",
                "--porcelain=v2",
                "--untracked-files=normal",
            ],
            MAX_GIT_OUTPUT_BYTES,
        )?;
        let index = run_git_capture(
            self,
            workspace_root,
            &["ls-files", "-v", "-z", "--"],
            MAX_GIT_OUTPUT_BYTES,
        )?;
        let index_is_plain = !index.is_empty()
            && index
                .split(|byte| *byte == 0)
                .filter(|record| !record.is_empty())
                .all(|record| record.starts_with(b"H "));
        Ok(SourceStatus {
            clean: status.is_empty() && index_is_plain,
            revision: revision.to_owned(),
        })
    }

    fn verify_all(&self) -> Result<(), ControlError> {
        self.launcher.verify()?;
        self.captured
            .values()
            .try_for_each(ExecutableIdentity::verify)
    }
}

fn capture_available_programs(source_path: &OsString) -> BTreeMap<String, ExecutableIdentity> {
    let mut captured = BTreeMap::new();
    for name in [
        "bash",
        "cargo",
        "cargo-nextest",
        "cc",
        "clang",
        "corepack",
        "git",
        "go",
        "ld",
        "node",
        "python3",
        "ps",
        "rustc",
        "rustdoc",
        "sh",
        "uv",
        "xcrun",
    ] {
        if let Some(path) = resolve_program(source_path, name)
            && let Ok(identity) = ExecutableIdentity::capture(&path)
        {
            captured.insert(name.to_owned(), identity);
        }
    }
    captured
}

impl ExecutionSnapshot {
    fn capture(
        toolchain: &CapturedToolchain,
        workspace_root: &Path,
        sandbox_directory: &Path,
        profile: &RunProfile,
        source_revision: &str,
    ) -> Result<Self, ControlError> {
        validate_python_closure(profile)?;
        validate_git_security_configuration(toolchain, workspace_root)?;
        let tree_entries = git_tree_entries(toolchain, workspace_root, source_revision)?;
        let live_inputs = read_tracked_inputs(workspace_root, &tree_entries, profile)?;
        let snapshot_path = sandbox_directory.join(SNAPSHOT_DIRECTORY_NAME);
        clone_exact_source(toolchain, workspace_root, &snapshot_path, source_revision)?;
        let snapshot_status = toolchain.source_status(&snapshot_path)?;
        if !snapshot_status.clean || snapshot_status.revision != source_revision {
            return Err(ControlError::SourceMismatch);
        }
        let snapshot_entries = git_tree_entries(toolchain, &snapshot_path, source_revision)?;
        if snapshot_entries != tree_entries {
            return Err(ControlError::SourceMismatch);
        }
        let snapshot_inputs = read_tracked_inputs(&snapshot_path, &tree_entries, profile)?;
        if snapshot_inputs != live_inputs {
            return Err(ControlError::SourceMismatch);
        }
        let source_tree_sha256 = digest_json(&snapshot_inputs);
        let mut inputs = snapshot_inputs;
        inputs.extend(toolchain_execution_inputs(toolchain)?);
        inputs.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        if inputs.len() > MAX_SOURCE_INPUTS
            || inputs
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left.path == right.path))
        {
            return Err(ControlError::SourceMismatch);
        }
        let snapshot = Self {
            inputs,
            root: snapshot_path,
            source_tree_sha256,
            tree_entries,
        };
        snapshot.verify(toolchain, profile)?;
        Ok(snapshot)
    }

    fn verify(
        &self,
        toolchain: &CapturedToolchain,
        profile: &RunProfile,
    ) -> Result<(), ControlError> {
        let source_inputs = read_tracked_inputs(&self.root, &self.tree_entries, profile)?;
        if digest_json(&source_inputs) != self.source_tree_sha256 {
            return Err(ControlError::SourceMismatch);
        }
        let mut inputs = source_inputs;
        inputs.extend(toolchain_execution_inputs(toolchain)?);
        inputs.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        if inputs == self.inputs {
            Ok(())
        } else {
            Err(ControlError::SourceMismatch)
        }
    }

    fn verify_live_source(
        &self,
        workspace_root: &Path,
        profile: &RunProfile,
    ) -> Result<(), ControlError> {
        let inputs = read_tracked_inputs(workspace_root, &self.tree_entries, profile)?;
        if digest_json(&inputs) == self.source_tree_sha256 {
            Ok(())
        } else {
            Err(ControlError::SourceMismatch)
        }
    }
}

#[derive(Debug)]
struct ActiveJob {
    concurrency_group: String,
    cancel: watch::Sender<bool>,
}

#[derive(Default, Debug)]
struct ActiveJobs {
    jobs: BTreeMap<String, ActiveJob>,
}

impl ActiveJobs {
    fn permits(&self, group: &str, maximum: usize) -> bool {
        if self.jobs.len() >= maximum {
            return false;
        }
        let group_count = self
            .jobs
            .values()
            .filter(|job| job.concurrency_group == group)
            .count();
        if group == "read-only" {
            group_count < MAX_READ_ONLY_JOBS.min(maximum)
        } else {
            group_count == 0
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryDisposition {
    Unstarted,
    NoLiveProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LivenessState {
    Missing,
    Free,
    Held,
}

fn process_spawn_gate() -> &'static Mutex<()> {
    static GATE: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
}

fn set_liveness_inheritable(file: &File, inheritable: bool) -> Result<(), ControlError> {
    let mut flags = rustix::io::fcntl_getfd(file).map_err(|_error| ControlError::UnsafePath)?;
    if inheritable {
        flags.remove(rustix::io::FdFlags::CLOEXEC);
    } else {
        flags.insert(rustix::io::FdFlags::CLOEXEC);
    }
    rustix::io::fcntl_setfd(file, flags).map_err(|_error| ControlError::UnsafePath)
}

fn create_liveness_lock(sandbox_directory: &Path) -> Result<File, ControlError> {
    let path = sandbox_directory.join(LIVENESS_LOCK_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|_error| ControlError::UnsafePath)?;
    validate_private_lock(&path, &file)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_error| ControlError::UnsafePath)?;
    set_liveness_inheritable(&file, true)?;
    file.sync_all()
        .map_err(|_error| ControlError::Persistence)?;
    sync_directory(sandbox_directory)?;
    Ok(file)
}

fn probe_liveness_lock(path: &Path) -> Result<LivenessState, ControlError> {
    let parent = path.parent().ok_or(ControlError::UnsafePath)?;
    match fs::symlink_metadata(parent) {
        Ok(_) => validate_existing_private_directory(parent)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LivenessState::Missing);
        }
        Err(_error) => return Err(ControlError::UnsafePath),
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LivenessState::Missing);
        }
        Err(_error) => return Err(ControlError::UnsafePath),
    }
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| ControlError::UnsafePath)?;
    let file = File::from(descriptor);
    validate_private_lock(path, &file)?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(LivenessState::Free),
        Err(error)
            if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
        {
            Ok(LivenessState::Held)
        }
        Err(_error) => Err(ControlError::UnsafePath),
    }
}

fn validate_private_lock(path: &Path, file: &File) -> Result<(), ControlError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_error| ControlError::UnsafePath)?;
    let file_metadata = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || !file_metadata.is_file()
        || path_metadata.len() != 0
        || file_metadata.len() != 0
    {
        return Err(ControlError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let expected_uid = rustix::process::geteuid().as_raw();
        if path_metadata.uid() != expected_uid
            || file_metadata.uid() != expected_uid
            || path_metadata.permissions().mode() & 0o777 != 0o600
            || file_metadata.permissions().mode() & 0o777 != 0o600
            || path_metadata.nlink() != 1
            || file_metadata.nlink() != 1
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(ControlError::UnsafePath);
        }
    }
    Ok(())
}

fn validate_existing_private_directory(path: &Path) -> Result<(), ControlError> {
    let metadata = fs::symlink_metadata(path).map_err(|_error| ControlError::UnsafePath)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ControlError::UnsafePath);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_error| ControlError::UnsafePath)?;
    if canonical != path {
        return Err(ControlError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(ControlError::UnsafePath);
        }
    }
    Ok(())
}

struct ControlInner {
    registry: Arc<RunProfileRegistry>,
    history: HistoryClient,
    events: SafeEventBroker,
    workspace_root: PathBuf,
    evidence_root: PathBuf,
    sandbox_root: PathBuf,
    toolchain: CapturedToolchain,
    source_clean_at_startup: bool,
    maximum_concurrent: usize,
    active: Mutex<ActiveJobs>,
}

/// Optional fixed-profile control plane. No browser input becomes argv, env, cwd, or a path.
#[derive(Clone)]
pub struct ControlPlane {
    inner: Arc<ControlInner>,
}

impl fmt::Debug for ControlPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlane")
            .field("registry_digest", &self.inner.registry.digest_hex())
            .field("maximum_concurrent", &self.inner.maximum_concurrent)
            .field(
                "active_count",
                &self
                    .inner
                    .active
                    .lock()
                    .map_or(0, |active| active.jobs.len()),
            )
            .finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// Captures immutable tools and canonical private roots for an enabled configuration.
    pub fn initialize(
        config: &DashboardConfig,
        registry: Arc<RunProfileRegistry>,
        history: HistoryClient,
        events: SafeEventBroker,
    ) -> Result<Self, ControlError> {
        if !config.control.enabled || !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            return Err(ControlError::Unavailable);
        }
        let workspace_root = canonical_directory(
            config
                .control
                .workspace_root
                .as_deref()
                .ok_or(ControlError::Unavailable)?,
            false,
        )?;
        let evidence_root = canonical_directory(
            config
                .control
                .evidence_directory
                .as_deref()
                .ok_or(ControlError::Unavailable)?,
            true,
        )?;
        let sandbox_root = canonical_directory(
            config
                .control
                .sandbox_directory
                .as_deref()
                .ok_or(ControlError::Unavailable)?,
            true,
        )?;
        if evidence_root.starts_with(&workspace_root)
            || sandbox_root.starts_with(&workspace_root)
            || workspace_root.starts_with(&evidence_root)
            || workspace_root.starts_with(&sandbox_root)
            || evidence_root == sandbox_root
        {
            return Err(ControlError::UnsafePath);
        }
        let toolchain = CapturedToolchain::capture(&sandbox_root)?;
        let source_status = toolchain.source_status(&workspace_root)?;
        if source_status.revision != registry.source_revision() {
            return Err(ControlError::SourceMismatch);
        }
        let plane = Self {
            inner: Arc::new(ControlInner {
                registry,
                history,
                events,
                workspace_root,
                evidence_root,
                sandbox_root,
                toolchain,
                source_clean_at_startup: source_status.clean,
                maximum_concurrent: config.control.max_concurrent_runs,
                active: Mutex::new(ActiveJobs::default()),
            }),
        };
        plane.reconcile_active_runs()?;
        Ok(plane)
    }

    fn reconcile_active_runs(&self) -> Result<(), ControlError> {
        let active = self
            .inner
            .history
            .recoverable_runs()
            .map_err(|_error| ControlError::Persistence)?;
        let mut dispositions = Vec::with_capacity(active.len());
        for recovered in &active {
            dispositions.push(self.recovery_disposition(recovered)?);
        }
        for (recovered, disposition) in active.iter().zip(dispositions) {
            let run = recovered.run();
            let terminal = match disposition {
                RecoveryDisposition::Unstarted => {
                    let executable_digest = self.recovery_executable_digest(run)?;
                    self.inner
                        .history
                        .transition_run(
                            run.run_id(),
                            RunState::Preparing,
                            Some(&executable_digest),
                            None,
                            None,
                        )
                        .and_then(|_| {
                            self.inner.history.transition_run(
                                run.run_id(),
                                RunState::Lost,
                                None,
                                None,
                                Some("run.recovery_unstarted"),
                            )
                        })
                }
                RecoveryDisposition::NoLiveProcess => self.inner.history.transition_run(
                    run.run_id(),
                    RunState::Lost,
                    None,
                    None,
                    Some("run.recovered_without_live_child"),
                ),
            }
            .map_err(|_error| ControlError::Persistence)?;
            publish_run_event(&self.inner.events, &terminal, terminal.failure_code());
        }
        Ok(())
    }

    fn recovery_disposition(
        &self,
        recovered: &RecoverableRun,
    ) -> Result<RecoveryDisposition, ControlError> {
        if recovered.supervisor_generation() != 1 || !recovered.resources_reserved() {
            return Err(ControlError::RecoveryRequired);
        }
        match recovered.run().state() {
            RunState::Queued => Ok(RecoveryDisposition::Unstarted),
            RunState::Preparing => Err(ControlError::RecoveryRequired),
            RunState::Running | RunState::Cancelling => {
                let process = recovered.process().ok_or(ControlError::RecoveryRequired)?;
                let lock_path = self
                    .inner
                    .sandbox_root
                    .join(recovered.run().run_id())
                    .join(LIVENESS_LOCK_NAME);
                if probe_liveness_lock(&lock_path)? == LivenessState::Held {
                    return Err(ControlError::RecoveryRequired);
                }
                let observed = observe_process_identity(&self.inner.toolchain.ps, process.pid())?;
                if observed.as_deref() == Some(process.identity_sha256())
                    || process_group_has_members(
                        &self.inner.toolchain.ps,
                        process.process_group_id(),
                    )?
                {
                    return Err(ControlError::RecoveryRequired);
                }
                Ok(RecoveryDisposition::NoLiveProcess)
            }
            RunState::Cancelled
            | RunState::Passed
            | RunState::Failed
            | RunState::TimedOut
            | RunState::Lost => Err(ControlError::Persistence),
        }
    }

    fn recovery_executable_digest(&self, run: &RunRecord) -> Result<String, ControlError> {
        if run.registry_digest() != self.inner.registry.digest_hex()
            || run.source_revision() != self.inner.registry.source_revision()
        {
            return Err(ControlError::RecoveryRequired);
        }
        let profile = self
            .inner
            .registry
            .profiles()
            .iter()
            .find(|profile| profile.id() == run.profile_id())
            .ok_or(ControlError::RecoveryRequired)?;
        if profile
            .digest_hex()
            .map_err(|_error| ControlError::RecoveryRequired)?
            != run.profile_digest()
        {
            return Err(ControlError::RecoveryRequired);
        }
        let executable = self
            .inner
            .toolchain
            .for_profile(profile)
            .ok_or(ControlError::RecoveryRequired)?;
        executable.verify()?;
        Ok(executable.digest.clone())
    }

    /// Returns immutable profiles narrowed by this exact startup environment.
    pub fn public_profiles(&self) -> Vec<RunProfile> {
        self.inner
            .registry
            .profiles()
            .iter()
            .map(|profile| {
                let availability = if profile.availability_state() != AvailabilityState::Available {
                    profile.availability_state()
                } else if !profile.supports_macos() {
                    AvailabilityState::PlatformUnsupported
                } else if !self.inner.source_clean_at_startup {
                    AvailabilityState::SourceCheckoutRequired
                } else if profile.is_soak() || profile.receipt_relative_path().is_none() {
                    AvailabilityState::CommandNotImplemented
                } else if self.inner.toolchain.for_profile(profile).is_none()
                    || !self.inner.toolchain.has_profile_tools(profile)
                {
                    AvailabilityState::ToolMissing
                } else {
                    AvailabilityState::Available
                };
                profile.with_availability(availability)
            })
            .collect()
    }

    /// Resolves and starts one exact reviewed profile. No other request field is accepted.
    pub fn start(&self, profile_id: &str) -> Result<RunRecord, ControlError> {
        let profile = self
            .public_profiles()
            .into_iter()
            .find(|profile| profile.id() == profile_id)
            .ok_or(ControlError::InvalidRequest)?;
        if profile.availability_state() != AvailabilityState::Available || profile.is_soak() {
            return Err(ControlError::Unavailable);
        }
        ensure_disk_capacity(&self.inner.evidence_root, profile.maximum_evidence_bytes())?;
        let executable = self
            .inner
            .toolchain
            .for_profile(&profile)
            .ok_or(ControlError::Unavailable)?
            .clone();
        let tool_version_sha256 = self
            .inner
            .toolchain
            .version_digest_for_profile(&profile)
            .ok_or(ControlError::Unavailable)?
            .to_owned();
        self.inner.toolchain.verify_all()?;
        executable.verify()?;
        let source_status = self
            .inner
            .toolchain
            .source_status(&self.inner.workspace_root)?;
        if !source_status.clean || source_status.revision != self.inner.registry.source_revision() {
            return Err(ControlError::SourceMismatch);
        }
        let profile_digest = profile
            .digest_hex()
            .map_err(|_error| ControlError::InvalidRequest)?;
        let registry_digest = self.inner.registry.digest_hex();
        let mut run = RunRecord::queued(
            profile.id(),
            &profile_digest,
            &registry_digest,
            self.inner.registry.source_revision(),
        )
        .map_err(|_error| ControlError::InvalidRequest)?;
        let (cancel, cancellation) = watch::channel(false);
        {
            let mut active = self
                .inner
                .active
                .lock()
                .map_err(|_poisoned| ControlError::Capacity)?;
            if !active.permits(profile.concurrency_group(), self.inner.maximum_concurrent) {
                return Err(ControlError::Capacity);
            }
            active.jobs.insert(
                run.run_id().to_owned(),
                ActiveJob {
                    concurrency_group: profile.concurrency_group().to_owned(),
                    cancel,
                },
            );
        }
        let reservation = RunResourceReservation::new(
            profile.maximum_output_bytes(),
            profile.maximum_evidence_bytes(),
        )
        .map_err(|_error| ControlError::InvalidRequest)?;
        if self
            .inner
            .history
            .create_run_with_resources(run.clone(), reservation)
            .is_err()
        {
            self.remove_active(run.run_id());
            return Err(ControlError::Persistence);
        }
        run = match self.inner.history.transition_run(
            run.run_id(),
            RunState::Preparing,
            Some(&executable.digest),
            None,
            None,
        ) {
            Ok(preparing) => preparing,
            Err(_error) => {
                self.remove_active(run.run_id());
                return Err(ControlError::Persistence);
            }
        };
        let evidence_directory = create_run_directory(&self.inner.evidence_root, run.run_id())
            .inspect_err(|_error| {
                let _ignored = self.inner.history.transition_run(
                    run.run_id(),
                    RunState::Lost,
                    None,
                    None,
                    Some("run.evidence_root_failed"),
                );
                self.remove_active(run.run_id());
            })?;
        let sandbox_directory = create_run_directory(&self.inner.sandbox_root, run.run_id())
            .inspect_err(|_error| {
                let _ignored = self.inner.history.transition_run(
                    run.run_id(),
                    RunState::Lost,
                    None,
                    None,
                    Some("run.sandbox_failed"),
                );
                self.remove_active(run.run_id());
            })?;
        let snapshot = ExecutionSnapshot::capture(
            &self.inner.toolchain,
            &self.inner.workspace_root,
            &sandbox_directory,
            &profile,
            self.inner.registry.source_revision(),
        )
        .inspect_err(|_error| {
            let _ignored = self.inner.history.transition_run(
                run.run_id(),
                RunState::Lost,
                None,
                None,
                Some("run.source_snapshot_failed"),
            );
            self.remove_active(run.run_id());
        })?;
        let spawn_guard = process_spawn_gate().lock().map_err(|_poisoned| {
            let _ignored = self.inner.history.transition_run(
                run.run_id(),
                RunState::Lost,
                None,
                None,
                Some("run.spawn_gate_failed"),
            );
            self.remove_active(run.run_id());
            ControlError::SpawnFailed
        })?;
        let liveness_lock = create_liveness_lock(&sandbox_directory).inspect_err(|_error| {
            let _ignored = self.inner.history.transition_run(
                run.run_id(),
                RunState::Lost,
                None,
                None,
                Some("run.liveness_lock_failed"),
            );
            self.remove_active(run.run_id());
        })?;
        let environment = child_environment(
            &self.inner.toolchain.safe_path,
            &evidence_directory,
            self.inner.registry.source_revision(),
        );
        let effective_argv = effective_argv(&profile)?;
        let limits = ChildResourceLimits::from_profile(&profile)?;
        let mut command = if cfg!(test) {
            let mut command = Command::new(&executable.path);
            command.args(&effective_argv);
            command
        } else {
            let mut command = Command::new(&self.inner.toolchain.launcher.path);
            command
                .arg("--internal-resource-launcher-v1")
                .arg(limits.cpu_seconds.to_string())
                .arg(limits.file_bytes.to_string())
                .arg(limits.open_files.to_string())
                .arg(&executable.path)
                .arg(&executable.digest)
                .arg("--")
                .args(&effective_argv);
            command
        };
        command
            .current_dir(&snapshot.root)
            .env_clear()
            .envs(environment.iter())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
        }
        snapshot
            .verify_live_source(&self.inner.workspace_root, &profile)
            .inspect_err(|_error| {
                let _ignored = self.inner.history.transition_run(
                    run.run_id(),
                    RunState::Lost,
                    None,
                    None,
                    Some("run.source_changed_before_launch"),
                );
                self.remove_active(run.run_id());
            })?;
        let started_at = now_rfc3339()?;
        let started_monotonic = tokio::time::Instant::now();
        let mut child = command.spawn().map_err(|_error| {
            let _ignored = self.inner.history.transition_run(
                run.run_id(),
                RunState::Lost,
                None,
                None,
                Some("run.spawn_failed"),
            );
            self.remove_active(run.run_id());
            ControlError::SpawnFailed
        })?;
        let child_id = child.id();
        let descriptor_restored = set_liveness_inheritable(&liveness_lock, false);
        if let Err(error) = descriptor_restored {
            if let Some(child_id) = child_id {
                signal_process_group(child_id, rustix::process::Signal::KILL);
                let _ignored = child.start_kill();
                self.spawn_activation_cleanup(
                    run.run_id().to_owned(),
                    child,
                    child_id,
                    "run.liveness_descriptor_failed",
                );
            } else {
                let _ignored = child.start_kill();
                publish_supervisor_failure(
                    &self.inner.events,
                    run.run_id(),
                    "run.liveness_descriptor_failed",
                );
            }
            return Err(error);
        }
        drop(spawn_guard);
        let Some(child_id) = child_id else {
            let _ignored = child.start_kill();
            publish_supervisor_failure(
                &self.inner.events,
                run.run_id(),
                "run.process_identity_failed",
            );
            return Err(ControlError::SpawnFailed);
        };
        let process = match capture_process_identity(&self.inner.toolchain.ps, child_id) {
            Ok(process) => process,
            Err(error) => {
                signal_process_group(child_id, rustix::process::Signal::KILL);
                let _ignored = child.start_kill();
                self.spawn_activation_cleanup(
                    run.run_id().to_owned(),
                    child,
                    child_id,
                    "run.process_identity_failed",
                );
                return Err(error);
            }
        };
        run = match self.inner.history.activate_run(run.run_id(), process) {
            Ok(running) => running,
            Err(_error) => {
                signal_process_group(child_id, rustix::process::Signal::KILL);
                let _ignored = child.start_kill();
                self.spawn_activation_cleanup(
                    run.run_id().to_owned(),
                    child,
                    child_id,
                    "run.activation_persistence_failed",
                );
                return Err(ControlError::Persistence);
            }
        };
        drop(liveness_lock);
        publish_run_event(&self.inner.events, &run, None);
        let context = JobContext {
            plane: self.clone(),
            run_id: run.run_id().to_owned(),
            profile,
            profile_digest,
            effective_argv,
            executable,
            environment_digest: digest_environment(&environment),
            tool_version_sha256,
            evidence_directory,
            _sandbox_directory: sandbox_directory,
            snapshot,
            child_id,
            started_at,
            started_monotonic,
        };
        tokio::spawn(supervise(context, child, cancellation));
        Ok(run)
    }

    fn remove_active(&self, run_id: &str) {
        if let Ok(mut active) = self.inner.active.lock() {
            active.jobs.remove(run_id);
        }
    }

    fn spawn_activation_cleanup(
        &self,
        run_id: String,
        mut child: Child,
        child_id: u32,
        failure_code: &'static str,
    ) {
        let plane = self.clone();
        tokio::spawn(async move {
            let waited = tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .is_ok_and(|result| result.is_ok());
            let group_clear = wait_for_empty_process_group(
                plane.inner.toolchain.ps.clone(),
                child_id,
                Duration::from_secs(5),
            )
            .await;
            if waited && group_clear {
                let terminal = plane
                    .inner
                    .history
                    .get_run(&run_id)
                    .ok()
                    .filter(|current| !current.state().is_terminal())
                    .and_then(|_current| {
                        plane
                            .inner
                            .history
                            .transition_run(&run_id, RunState::Lost, None, None, Some(failure_code))
                            .ok()
                    });
                if let Some(terminal) = terminal {
                    publish_run_event(&plane.inner.events, &terminal, Some(failure_code));
                }
                plane.remove_active(&run_id);
            }
        });
    }

    /// Requests idempotent cancellation of one active reviewed run.
    pub fn cancel(&self, run_id: &str) -> Result<RunRecord, ControlError> {
        let mut run = self
            .inner
            .history
            .get_run(run_id)
            .map_err(|_error| ControlError::InvalidRequest)?;
        if run.state().is_terminal() {
            return Ok(run);
        }
        let cancel = {
            let active = self
                .inner
                .active
                .lock()
                .map_err(|_poisoned| ControlError::Capacity)?;
            active
                .jobs
                .get(run_id)
                .ok_or(ControlError::Unavailable)?
                .cancel
                .clone()
        };
        if run.state() == RunState::Running {
            run = match self.inner.history.transition_run(
                run_id,
                RunState::Cancelling,
                None,
                None,
                None,
            ) {
                Ok(cancelling) => cancelling,
                Err(_error) => {
                    let current = self
                        .inner
                        .history
                        .get_run(run_id)
                        .map_err(|_error| ControlError::Persistence)?;
                    if current.state().is_terminal() {
                        return Ok(current);
                    }
                    return Err(ControlError::Persistence);
                }
            };
            publish_run_event(&self.inner.events, &run, None);
        } else if run.state() != RunState::Cancelling {
            return Err(ControlError::Unavailable);
        }
        let _ignored = cancel.send(true);
        Ok(run)
    }

    /// Cancels all owned process groups and waits a bounded interval for settlement.
    pub async fn shutdown(&self, deadline: Duration) {
        if let Ok(active) = self.inner.active.lock() {
            for job in active.jobs.values() {
                let _ignored = job.cancel.send(true);
            }
        }
        let settle = async {
            loop {
                let empty = self
                    .inner
                    .active
                    .lock()
                    .is_ok_and(|active| active.jobs.is_empty());
                if empty {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        };
        let _ignored = tokio::time::timeout(deadline, settle).await;
    }
}

struct JobContext {
    plane: ControlPlane,
    run_id: String,
    profile: RunProfile,
    profile_digest: String,
    effective_argv: Vec<String>,
    executable: ExecutableIdentity,
    environment_digest: String,
    tool_version_sha256: String,
    evidence_directory: PathBuf,
    _sandbox_directory: PathBuf,
    snapshot: ExecutionSnapshot,
    child_id: u32,
    started_at: String,
    started_monotonic: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StopReason {
    Exited,
    Cancelled,
    TimedOut,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResourceViolation {
    Memory,
    ProcessCount,
    Probe,
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: u64,
    digest: String,
    exceeded: bool,
}

#[derive(Serialize)]
struct SupervisorReceipt<'a> {
    argv_sha256: String,
    dashboard_sha256: &'a str,
    environment_sha256: &'a str,
    executable_sha256: &'a str,
    execution_inputs: &'a [ExecutionInput],
    exit_code: Option<i32>,
    finished_at: &'a str,
    monotonic_elapsed_ns: u64,
    profile_id: &'a str,
    profile_sha256: &'a str,
    registry_sha256: String,
    run_id: &'a str,
    schema_version: &'static str,
    source_clean: bool,
    source_revision: &'a str,
    source_tree_sha256: &'a str,
    started_at: &'a str,
    stderr: SupervisorStream<'a>,
    stdout: SupervisorStream<'a>,
    stop_reason: StopReason,
    tool_version_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_violation: Option<ResourceViolation>,
}

#[derive(Serialize)]
struct SupervisorStream<'a> {
    bytes: u64,
    exceeded: bool,
    sha256: &'a str,
}

async fn supervise(context: JobContext, mut child: Child, mut cancellation: watch::Receiver<bool>) {
    let output_bound = context.profile.maximum_output_bytes();
    let aggregate_output = Arc::new(AtomicU64::new(0));
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_task = tokio::spawn(capture_output(
        stdout,
        output_bound,
        Arc::clone(&aggregate_output),
    ));
    let stderr_task = tokio::spawn(capture_output(stderr, output_bound, aggregate_output));
    let mut resource_task = tokio::spawn(monitor_process_group_resources(
        context.plane.inner.toolchain.ps.clone(),
        context.child_id,
        context.profile.maximum_processes(),
        context.profile.maximum_memory_mib(),
    ));
    let maximum = Duration::from_secs(context.profile.maximum_duration_seconds());
    let stop = tokio::select! {
        status = child.wait() => {
            let settled = settle_remaining_process_group(
                context.plane.inner.toolchain.ps.clone(),
                context.child_id,
                context.profile.cancellation_grace_seconds(),
            ).await;
            (StopReason::Exited, status.ok(), settled, None)
        },
        _ = wait_for_cancellation(&mut cancellation) => {
            let (status, settled) = terminate_child_group(
                &mut child,
                context.plane.inner.toolchain.ps.clone(),
                context.child_id,
                context.profile.cancellation_grace_seconds(),
            ).await;
            (StopReason::Cancelled, status, settled, None)
        }
        _ = tokio::time::sleep(maximum) => {
            let (status, settled) = terminate_child_group(
                &mut child,
                context.plane.inner.toolchain.ps.clone(),
                context.child_id,
                context.profile.cancellation_grace_seconds(),
            ).await;
            (StopReason::TimedOut, status, settled, None)
        }
        violation = &mut resource_task => {
            let violation = violation.unwrap_or(ResourceViolation::Probe);
            let (status, settled) = terminate_child_group(
                &mut child,
                context.plane.inner.toolchain.ps.clone(),
                context.child_id,
                context.profile.cancellation_grace_seconds(),
            ).await;
            (StopReason::ResourceLimit, status, settled, Some(violation))
        }
    };
    resource_task.abort();
    let _ignored = resource_task.await;
    let (stdout, stdout_settled) = bounded_capture_join(stdout_task).await;
    let (stderr, stderr_settled) = bounded_capture_join(stderr_task).await;
    if !stop.2 || !stdout_settled || !stderr_settled {
        publish_supervisor_failure(
            &context.plane.inner.events,
            &context.run_id,
            "run.descendant_settlement",
        );
        return;
    }
    let exit_code = stop.1.and_then(|status| status.code());
    let process_succeeded = stop.0 == StopReason::Exited
        && stop.1.is_some_and(|status| status.success())
        && !stdout.exceeded
        && !stderr.exceeded;
    let finished_at = match now_rfc3339() {
        Ok(value) => value,
        Err(_error) => {
            publish_supervisor_failure(
                &context.plane.inner.events,
                &context.run_id,
                "run.supervisor_clock_failed",
            );
            return;
        }
    };
    let monotonic_elapsed_ns =
        u64::try_from(context.started_monotonic.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let snapshot_verified = context
        .snapshot
        .verify(&context.plane.inner.toolchain, &context.profile)
        .is_ok();
    let verifier = ReceiptVerifier::new(
        &context.evidence_directory,
        &context.snapshot.root,
        context.profile.maximum_evidence_bytes(),
    );
    let verified = verifier.and_then(|verifier| {
        verifier.verify(
            &context.profile,
            context.plane.inner.registry.source_revision(),
            process_succeeded,
        )
    });
    let supervisor = SupervisorReceipt {
        argv_sha256: digest_json(&context.effective_argv),
        dashboard_sha256: &context.plane.inner.toolchain.launcher.digest,
        environment_sha256: &context.environment_digest,
        executable_sha256: &context.executable.digest,
        execution_inputs: &context.snapshot.inputs,
        exit_code,
        finished_at: &finished_at,
        monotonic_elapsed_ns,
        profile_id: context.profile.id(),
        profile_sha256: &context.profile_digest,
        registry_sha256: context.plane.inner.registry.digest_hex(),
        run_id: &context.run_id,
        schema_version: SUPERVISOR_RECEIPT_SCHEMA,
        source_clean: true,
        source_revision: context.plane.inner.registry.source_revision(),
        source_tree_sha256: &context.snapshot.source_tree_sha256,
        started_at: &context.started_at,
        stderr: SupervisorStream {
            bytes: stderr.bytes,
            exceeded: stderr.exceeded,
            sha256: &stderr.digest,
        },
        stdout: SupervisorStream {
            bytes: stdout.bytes,
            exceeded: stdout.exceeded,
            sha256: &stdout.digest,
        },
        stop_reason: stop.0,
        tool_version_sha256: &context.tool_version_sha256,
        resource_violation: stop.3,
    };
    let supervisor_source = supervisor_receipt_bytes(&supervisor);
    let initial_measurement = measure_evidence_tree(&context.evidence_directory);
    let (mut evidence_bytes, mut evidence_failure) = match initial_measurement {
        Ok(measurement) => (
            measurement,
            (!snapshot_verified).then_some("run.source_snapshot_mutated"),
        ),
        Err(code) => {
            settle_indeterminate(&context, code);
            return;
        }
    };
    let mut supervisor_digest = None;
    let mut supervisor_binding = None;
    let mut persisted_supervisor_source = None;
    if let Ok(source) = supervisor_source {
        let proposed = evidence_bytes.checked_add(u64::try_from(source.len()).unwrap_or(u64::MAX));
        if proposed.is_none_or(|bytes| bytes > context.profile.maximum_evidence_bytes()) {
            evidence_failure = Some("run.evidence_limit");
        } else {
            match write_supervisor_receipt(&context.evidence_directory, &source) {
                Ok(binding) => {
                    supervisor_digest = Some(binding.digest.clone());
                    supervisor_binding = Some(binding);
                    persisted_supervisor_source = Some(source);
                }
                Err(ReceiptWriteError::DiskFull) => {
                    evidence_failure = Some("run.evidence_disk_full");
                }
                Err(ReceiptWriteError::Unavailable) => {
                    evidence_failure = Some("run.supervisor_receipt_persistence");
                }
            }
            evidence_bytes = match measure_evidence_tree(&context.evidence_directory) {
                Ok(measurement) => measurement,
                Err(code) => {
                    settle_indeterminate(&context, code);
                    return;
                }
            };
            if evidence_bytes > context.profile.maximum_evidence_bytes() {
                evidence_failure = Some("run.evidence_limit");
            } else if supervisor_digest.is_some() && proposed != Some(evidence_bytes) {
                evidence_failure = Some("run.evidence_mutated");
            }
        }
    } else {
        evidence_failure = Some("run.supervisor_receipt_persistence");
    }
    if let (Some(source), Some(binding)) = (
        persisted_supervisor_source.as_deref(),
        supervisor_binding.as_ref(),
    ) && verify_supervisor_receipt(&context.evidence_directory, source, binding).is_err()
    {
        evidence_failure = Some("run.supervisor_receipt_mutated");
        supervisor_digest = None;
    }
    let supervisor_id = supervisor_digest
        .as_deref()
        .map(|digest| format!("receipt-{}", &digest[..32]));
    let (mut state, mut receipt_id, mut failure_code) = terminal_classification(
        stop.0,
        stdout.exceeded || stderr.exceeded,
        stop.3,
        evidence_failure,
        &verified,
        supervisor_id.as_deref(),
    );
    let output_bytes = stdout.bytes.saturating_add(stderr.bytes);
    let resources = match RunResourceUsage::new(output_bytes, evidence_bytes) {
        Ok(resources) => resources,
        Err(_error) => {
            settle_indeterminate(&context, "run.resource_ledger_overflow");
            return;
        }
    };
    let mut descriptors = Vec::with_capacity(2);
    let product_descriptor = verified.as_ref().ok().and_then(|receipt| {
        receipt
            .descriptor(
                &context.run_id,
                context.plane.inner.registry.source_revision(),
            )
            .ok()
    });
    if let Some(descriptor) = product_descriptor {
        descriptors.push(descriptor);
    }
    let supervisor_descriptor = supervisor_digest.as_deref().and_then(|digest| {
        EvidenceDescriptor::verified(
            &context.run_id,
            SUPERVISOR_RECEIPT_SCHEMA,
            EvidenceCategory::Development,
            if verified.is_ok() && evidence_failure.is_none() {
                EvidenceStatus::Valid
            } else {
                EvidenceStatus::Partial
            },
            digest,
            context.plane.inner.registry.source_revision(),
            None,
        )
        .ok()
    });
    if let Some(descriptor) = supervisor_descriptor {
        descriptors.push(descriptor);
    }
    let final_supervisor_valid = persisted_supervisor_source
        .as_deref()
        .zip(supervisor_binding.as_ref())
        .is_some_and(|(source, binding)| {
            verify_supervisor_receipt(&context.evidence_directory, source, binding).is_ok()
        });
    if !final_supervisor_valid {
        state = RunState::Failed;
        receipt_id = None;
        failure_code = Some("run.supervisor_receipt_mutated");
        descriptors.retain(|descriptor| descriptor.schema_id() != SUPERVISOR_RECEIPT_SCHEMA);
    }
    let terminal = context.plane.inner.history.complete_run(
        &context.run_id,
        state,
        receipt_id,
        failure_code,
        resources,
        descriptors,
    );
    if let Ok(run) = terminal {
        publish_run_event(&context.plane.inner.events, &run, failure_code);
        if let Ok(mut active) = context.plane.inner.active.lock() {
            active.jobs.remove(&context.run_id);
        }
    } else {
        publish_supervisor_failure(
            &context.plane.inner.events,
            &context.run_id,
            "run.terminal_persistence_failed",
        );
    }
}

fn terminal_classification<'a>(
    stop: StopReason,
    output_exceeded: bool,
    resource_violation: Option<ResourceViolation>,
    evidence_failure: Option<&'static str>,
    verified: &'a Result<crate::VerifiedReceipt, ReceiptError>,
    supervisor_receipt: Option<&'a str>,
) -> (RunState, Option<&'a str>, Option<&'static str>) {
    if let Some(violation) = resource_violation {
        let code = match violation {
            ResourceViolation::Memory => "run.memory_limit",
            ResourceViolation::ProcessCount => "run.process_limit",
            ResourceViolation::Probe => "run.resource_probe_failed",
        };
        return (RunState::Failed, supervisor_receipt, Some(code));
    }
    if let Some(code) = evidence_failure {
        return (RunState::Failed, supervisor_receipt, Some(code));
    }
    if supervisor_receipt.is_none() {
        return (
            RunState::Failed,
            None,
            Some("run.supervisor_receipt_persistence"),
        );
    }
    if output_exceeded {
        return (
            RunState::Failed,
            supervisor_receipt,
            Some("run.output_limit"),
        );
    }
    if stop == StopReason::Cancelled {
        return (RunState::Cancelled, supervisor_receipt, None);
    }
    if stop == StopReason::TimedOut {
        return (RunState::TimedOut, supervisor_receipt, Some("run.timeout"));
    }
    if stop == StopReason::ResourceLimit {
        return (
            RunState::Failed,
            supervisor_receipt,
            Some("run.resource_probe_failed"),
        );
    }
    match verified {
        Ok(receipt) if receipt.passed() => (RunState::Passed, Some(receipt.receipt_id()), None),
        Ok(receipt) => (
            RunState::Failed,
            Some(receipt.receipt_id()),
            Some("run.product_failure"),
        ),
        Err(error) => (
            RunState::Failed,
            supervisor_receipt,
            Some(receipt_failure_code(*error)),
        ),
    }
}

const fn receipt_failure_code(error: ReceiptError) -> &'static str {
    match error {
        ReceiptError::Missing => "run.receipt_missing",
        ReceiptError::UnsafePath => "run.receipt_path_unsafe",
        ReceiptError::LimitExceeded => "run.receipt_limit",
        ReceiptError::BindingMismatch => "run.receipt_binding",
        ReceiptError::OutcomeMismatch => "run.receipt_outcome",
        ReceiptError::UnsupportedSchema | ReceiptError::InvalidReceipt => "run.receipt_invalid",
    }
}

fn settle_indeterminate(context: &JobContext, failure_code: &'static str) {
    match context.plane.inner.history.transition_run(
        &context.run_id,
        RunState::Failed,
        None,
        None,
        Some(failure_code),
    ) {
        Ok(run) => {
            publish_run_event(&context.plane.inner.events, &run, Some(failure_code));
            context.plane.remove_active(&context.run_id);
        }
        Err(_error) => publish_supervisor_failure(
            &context.plane.inner.events,
            &context.run_id,
            "run.terminal_persistence_failed",
        ),
    }
}

fn now_rfc3339() -> Result<String, ControlError> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_error| ControlError::Persistence)
}

#[derive(Clone, Copy)]
struct ChildResourceLimits {
    cpu_seconds: u64,
    file_bytes: u64,
    open_files: u64,
}

impl ChildResourceLimits {
    fn from_profile(profile: &RunProfile) -> Result<Self, ControlError> {
        let cpu_seconds = profile
            .maximum_duration_seconds()
            .checked_add(profile.cancellation_grace_seconds())
            .and_then(|value| value.checked_add(5))
            .ok_or(ControlError::InvalidRequest)?;
        Ok(Self {
            cpu_seconds,
            file_bytes: profile.maximum_evidence_bytes(),
            open_files: MAX_CHILD_OPEN_FILES,
        })
    }
}

#[cfg(unix)]
fn apply_child_resource_limits(limits: ChildResourceLimits) -> std::io::Result<()> {
    use rustix::process::{Resource, Rlimit};

    let apply = |resource, value| {
        rustix::process::setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
    };
    apply(Resource::Core, 0)?;
    apply(Resource::Cpu, limits.cpu_seconds)?;
    apply(Resource::Fsize, limits.file_bytes)?;
    apply(Resource::Nofile, limits.open_files)
}

/// Executes the private child-only resource launcher mode before normal CLI parsing.
///
/// This is public only because the package binary is a separate Rust crate. It grants no authority:
/// the launcher runs as the invoking user, clears no security boundary, and only lowers its own
/// inherited limits before executing one digest-checked path.
#[doc(hidden)]
pub fn run_internal_resource_launcher_if_requested() -> Option<i32> {
    let mut arguments = std::env::args_os().skip(1);
    let marker = arguments.next()?;
    if marker != "--internal-resource-launcher-v1" {
        return None;
    }
    Some(run_internal_resource_launcher(arguments.collect()))
}

fn run_internal_resource_launcher(arguments: Vec<OsString>) -> i32 {
    if !(7..=71).contains(&arguments.len()) {
        return 64;
    }
    let Some(separator) = arguments.get(5) else {
        return 64;
    };
    if separator != "--" {
        return 64;
    }
    let Some(cpu_seconds) = arguments
        .first()
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 64;
    };
    let Some(file_bytes) = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 64;
    };
    let Some(open_files) = arguments
        .get(2)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 64;
    };
    if cpu_seconds == 0
        || cpu_seconds > 605_105
        || !(1024..=10_737_418_240).contains(&file_bytes)
        || open_files != MAX_CHILD_OPEN_FILES
    {
        return 64;
    }
    let Some(path) = arguments.get(3).map(PathBuf::from) else {
        return 64;
    };
    let Some(expected_digest) = arguments.get(4).and_then(|value| value.to_str()) else {
        return 64;
    };
    let Ok(identity) = ExecutableIdentity::capture(&path) else {
        return 126;
    };
    if identity.digest != expected_digest {
        return 126;
    }
    let limits = ChildResourceLimits {
        cpu_seconds,
        file_bytes,
        open_files,
    };
    if apply_child_resource_limits(limits).is_err() {
        return 125;
    }
    std::process::Command::new(&identity.path)
        .args(arguments.iter().skip(6))
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .ok()
        .and_then(|status| status.code())
        .unwrap_or(1)
}

fn ensure_disk_capacity(root: &Path, evidence_limit: u64) -> Result<(), ControlError> {
    let statistics = rustix::fs::statvfs(root).map_err(|_error| ControlError::UnsafePath)?;
    let block_size = if statistics.f_frsize == 0 {
        statistics.f_bsize
    } else {
        statistics.f_frsize
    };
    let available = statistics.f_bavail.saturating_mul(block_size);
    let required = evidence_limit
        .checked_add(DISK_HEADROOM_BYTES)
        .ok_or(ControlError::InvalidRequest)?;
    if available < required {
        return Err(ControlError::Persistence);
    }
    Ok(())
}

fn supervisor_receipt_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ControlError> {
    let source =
        serde_json::to_string_pretty(value).map_err(|_error| ControlError::Persistence)? + "\n";
    Ok(source.into_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptWriteError {
    DiskFull,
    Unavailable,
}

#[derive(Clone, Debug)]
struct SupervisorReceiptBinding {
    device: u64,
    digest: String,
    inode: u64,
}

fn write_supervisor_receipt(
    root: &Path,
    source: &[u8],
) -> Result<SupervisorReceiptBinding, ReceiptWriteError> {
    let path = root.join(SUPERVISOR_RECEIPT_NAME);
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        &path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| {
        classify_receipt_write_error(std::io::Error::from_raw_os_error(error.raw_os_error()))
    })?;
    let mut file = File::from(descriptor);
    file.write_all(source)
        .and_then(|()| file.sync_all())
        .map_err(classify_receipt_write_error)?;
    let metadata = file.metadata().map_err(classify_receipt_write_error)?;
    validate_supervisor_receipt_metadata(&metadata, source.len())?;
    #[cfg(unix)]
    let binding = {
        use std::os::unix::fs::MetadataExt as _;
        SupervisorReceiptBinding {
            device: metadata.dev(),
            digest: hex_digest(source),
            inode: metadata.ino(),
        }
    };
    #[cfg(not(unix))]
    return Err(ReceiptWriteError::Unavailable);
    sync_directory(root).map_err(|_error| ReceiptWriteError::Unavailable)?;
    drop(file);
    verify_supervisor_receipt(root, source, &binding)?;
    Ok(binding)
}

fn verify_supervisor_receipt(
    root: &Path,
    source: &[u8],
    binding: &SupervisorReceiptBinding,
) -> Result<(), ReceiptWriteError> {
    validate_existing_private_directory(root).map_err(|_error| ReceiptWriteError::Unavailable)?;
    let path = root.join(SUPERVISOR_RECEIPT_NAME);
    let named_before = fs::symlink_metadata(&path).map_err(classify_receipt_write_error)?;
    validate_supervisor_receipt_metadata(&named_before, source.len())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if named_before.dev() != binding.device || named_before.ino() != binding.inode {
            return Err(ReceiptWriteError::Unavailable);
        }
    }
    let root_descriptor = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| ReceiptWriteError::Unavailable)?;
    let root_file = File::from(root_descriptor);
    let descriptor = rustix::fs::openat(
        &root_file,
        SUPERVISOR_RECEIPT_NAME,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| ReceiptWriteError::Unavailable)?;
    let mut file = File::from(descriptor);
    let opened_before = file.metadata().map_err(classify_receipt_write_error)?;
    validate_supervisor_receipt_metadata(&opened_before, source.len())?;
    if !same_identity(&named_before, &opened_before) {
        return Err(ReceiptWriteError::Unavailable);
    }
    let mut observed = Vec::with_capacity(source.len());
    std::io::Read::by_ref(&mut file)
        .take(
            u64::try_from(source.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut observed)
        .map_err(classify_receipt_write_error)?;
    let opened_after = file.metadata().map_err(classify_receipt_write_error)?;
    let named_after = fs::symlink_metadata(&path).map_err(classify_receipt_write_error)?;
    validate_supervisor_receipt_metadata(&opened_after, source.len())?;
    validate_supervisor_receipt_metadata(&named_after, source.len())?;
    if observed != source
        || !same_regular_snapshot(&opened_before, &opened_after)
        || !same_identity(&named_before, &named_after)
        || !same_identity(&opened_after, &named_after)
    {
        return Err(ReceiptWriteError::Unavailable);
    }
    if hex_digest(&observed) != binding.digest {
        return Err(ReceiptWriteError::Unavailable);
    }
    Ok(())
}

fn validate_supervisor_receipt_metadata(
    metadata: &fs::Metadata,
    expected_length: usize,
) -> Result<(), ReceiptWriteError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != u64::try_from(expected_length).unwrap_or(u64::MAX)
        {
            return Err(ReceiptWriteError::Unavailable);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ignored = (metadata, expected_length);
        Err(ReceiptWriteError::Unavailable)
    }
}

fn classify_receipt_write_error(error: std::io::Error) -> ReceiptWriteError {
    if error.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error()) {
        ReceiptWriteError::DiskFull
    } else {
        ReceiptWriteError::Unavailable
    }
}

fn measure_evidence_tree(root: &Path) -> Result<u64, &'static str> {
    validate_existing_private_directory(root).map_err(|_error| "run.evidence_ledger_unsafe")?;
    let root_before = fs::symlink_metadata(root).map_err(|_error| "run.evidence_ledger_unsafe")?;
    let mut directories = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(directory) = directories.pop() {
        validate_existing_private_directory(&directory)
            .map_err(|_error| "run.evidence_ledger_unsafe")?;
        let before =
            fs::symlink_metadata(&directory).map_err(|_error| "run.evidence_ledger_unsafe")?;
        let mut children = fs::read_dir(&directory)
            .map_err(|_error| "run.evidence_ledger_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_error| "run.evidence_ledger_unavailable")?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            entries = entries.checked_add(1).ok_or("run.evidence_entry_limit")?;
            if entries > MAX_EVIDENCE_ENTRIES {
                return Err("run.evidence_entry_limit");
            }
            let path = child.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_error| "run.evidence_ledger_unsafe")?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(path);
            } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                bytes = bytes
                    .checked_add(measure_private_regular(&path)?)
                    .ok_or("run.evidence_ledger_overflow")?;
            } else {
                return Err("run.evidence_ledger_unsafe");
            }
        }
        let after =
            fs::symlink_metadata(&directory).map_err(|_error| "run.evidence_ledger_unsafe")?;
        validate_existing_private_directory(&directory)
            .map_err(|_error| "run.evidence_ledger_unsafe")?;
        if !same_directory_snapshot(&before, &after) {
            return Err("run.evidence_ledger_unsafe");
        }
    }
    let root_after = fs::symlink_metadata(root).map_err(|_error| "run.evidence_ledger_unsafe")?;
    validate_existing_private_directory(root).map_err(|_error| "run.evidence_ledger_unsafe")?;
    if !same_directory_snapshot(&root_before, &root_after) {
        return Err("run.evidence_ledger_unsafe");
    }
    Ok(bytes)
}

fn measure_private_regular(path: &Path) -> Result<u64, &'static str> {
    let before = fs::symlink_metadata(path).map_err(|_error| "run.evidence_ledger_unsafe")?;
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| "run.evidence_ledger_unsafe")?;
    let file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_error| "run.evidence_ledger_unsafe")?;
    if !private_evidence_file(&before)
        || !private_evidence_file(&opened)
        || !same_identity(&before, &opened)
    {
        return Err("run.evidence_ledger_unsafe");
    }
    let after = fs::symlink_metadata(path).map_err(|_error| "run.evidence_ledger_unsafe")?;
    let opened_after = file
        .metadata()
        .map_err(|_error| "run.evidence_ledger_unsafe")?;
    if !private_evidence_file(&after)
        || !private_evidence_file(&opened_after)
        || !same_regular_snapshot(&before, &after)
        || !same_identity(&opened, &opened_after)
        || before.len() != after.len()
        || opened.len() != opened_after.len()
    {
        return Err("run.evidence_ledger_unsafe");
    }
    Ok(opened.len())
}

#[cfg(unix)]
fn private_evidence_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_evidence_file(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn same_directory_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    same_identity(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_directory_snapshot(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_regular_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    same_identity(left, right)
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_regular_snapshot(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

#[cfg(not(unix))]
fn same_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

async fn wait_for_cancellation(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn capture_output<R>(
    reader: Option<R>,
    maximum: u64,
    aggregate: Arc<AtomicU64>,
) -> Result<CapturedOutput, std::io::Error>
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return Ok(empty_failed_output());
    };
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).unwrap_or(u64::MAX);
        bytes = bytes.saturating_add(read_u64);
        let mut observed = aggregate.load(Ordering::Acquire);
        let previous = loop {
            let updated = observed.saturating_add(read_u64);
            match aggregate.compare_exchange_weak(
                observed,
                updated,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(previous) => break previous,
                Err(current) => observed = current,
            }
        };
        let aggregate_bytes = previous.saturating_add(read_u64);
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| std::io::Error::other("read exceeded the capture buffer"))?;
        digest.update(chunk);
        if aggregate_bytes > maximum {
            return Ok(CapturedOutput {
                bytes,
                digest: hex_bytes(&digest.finalize()),
                exceeded: true,
            });
        }
    }
    Ok(CapturedOutput {
        bytes,
        digest: hex_bytes(&digest.finalize()),
        exceeded: false,
    })
}

fn empty_failed_output() -> CapturedOutput {
    CapturedOutput {
        bytes: 0,
        digest: hex_digest(&[]),
        exceeded: true,
    }
}

async fn bounded_capture_join(
    mut task: tokio::task::JoinHandle<Result<CapturedOutput, std::io::Error>>,
) -> (CapturedOutput, bool) {
    match tokio::time::timeout(OUTPUT_SETTLEMENT_GRACE, &mut task).await {
        Ok(Ok(Ok(output))) => (output, true),
        Ok(Ok(Err(_))) | Ok(Err(_)) => (empty_failed_output(), true),
        Err(_elapsed) => {
            task.abort();
            let _ignored = task.await;
            (empty_failed_output(), false)
        }
    }
}

async fn terminate_child_group(
    child: &mut Child,
    ps: ExecutableIdentity,
    child_id: u32,
    grace_seconds: u64,
) -> (Option<std::process::ExitStatus>, bool) {
    signal_process_group(child_id, rustix::process::Signal::TERM);
    if let Ok(result) = tokio::time::timeout(Duration::from_secs(grace_seconds), child.wait()).await
    {
        let status = result.ok();
        let settled = settle_remaining_process_group(ps, child_id, grace_seconds).await;
        return (status, settled);
    }
    signal_process_group(child_id, rustix::process::Signal::KILL);
    let status = tokio::time::timeout(OUTPUT_SETTLEMENT_GRACE, child.wait())
        .await
        .ok()
        .and_then(Result::ok);
    let settled = wait_for_empty_process_group(ps, child_id, OUTPUT_SETTLEMENT_GRACE).await;
    (status, settled)
}

fn signal_process_group(process_group_id: u32, signal: rustix::process::Signal) {
    #[cfg(unix)]
    if let Some(pid) = i32::try_from(process_group_id)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ignored = rustix::process::kill_process_group(pid, signal);
    }
}

async fn settle_remaining_process_group(
    ps: ExecutableIdentity,
    process_group_id: u32,
    grace_seconds: u64,
) -> bool {
    if wait_for_empty_process_group(ps.clone(), process_group_id, Duration::from_millis(25)).await {
        return true;
    }
    signal_process_group(process_group_id, rustix::process::Signal::TERM);
    if wait_for_empty_process_group(
        ps.clone(),
        process_group_id,
        Duration::from_secs(grace_seconds),
    )
    .await
    {
        return true;
    }
    signal_process_group(process_group_id, rustix::process::Signal::KILL);
    wait_for_empty_process_group(ps, process_group_id, OUTPUT_SETTLEMENT_GRACE).await
}

async fn wait_for_empty_process_group(
    ps: ExecutableIdentity,
    process_group_id: u32,
    deadline: Duration,
) -> bool {
    let started = tokio::time::Instant::now();
    loop {
        let probe = ps.clone();
        let empty = tokio::task::spawn_blocking(move || {
            process_group_has_members(&probe, process_group_id).map(|has_members| !has_members)
        })
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
        if empty {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn monitor_process_group_resources(
    ps: ExecutableIdentity,
    process_group_id: u32,
    maximum_processes: u16,
    maximum_memory_mib: u64,
) -> ResourceViolation {
    let maximum_memory_bytes = maximum_memory_mib.saturating_mul(1024 * 1024);
    loop {
        tokio::time::sleep(RESOURCE_POLL_INTERVAL).await;
        let probe = ps.clone();
        let usage =
            tokio::task::spawn_blocking(move || process_group_usage(&probe, process_group_id))
                .await;
        let usage = match usage {
            Ok(Ok(usage)) => usage,
            Ok(Err(_error)) => return ResourceViolation::Probe,
            Err(_error) => return ResourceViolation::Probe,
        };
        if usage.members > u64::from(maximum_processes) {
            return ResourceViolation::ProcessCount;
        }
        if usage.resident_bytes > maximum_memory_bytes {
            return ResourceViolation::Memory;
        }
    }
}

fn publish_run_event(events: &SafeEventBroker, run: &RunRecord, failure_code: Option<&str>) {
    let mut attributes = SafeEventAttributes::new();
    attributes.insert(
        "profile_id".to_owned(),
        SafeEventAttribute::Text(run.profile_id().to_owned()),
    );
    attributes.insert(
        "state".to_owned(),
        SafeEventAttribute::Text(run.state().as_str().to_owned()),
    );
    if let Some(code) = failure_code {
        attributes.insert(
            "failure_code".to_owned(),
            SafeEventAttribute::Text(code.to_owned()),
        );
    }
    let _ignored = events.publish(
        SafeEventKind::Run,
        "run.state.changed",
        Some(run.run_id()),
        attributes,
    );
}

fn publish_supervisor_failure(events: &SafeEventBroker, run_id: &str, failure_code: &str) {
    let mut attributes = SafeEventAttributes::new();
    attributes.insert(
        "failure_code".to_owned(),
        SafeEventAttribute::Text(failure_code.to_owned()),
    );
    let _ignored = events.publish(
        SafeEventKind::Run,
        "run.supervisor.failed",
        Some(run_id),
        attributes,
    );
}

fn child_environment(
    safe_path: &OsString,
    evidence_directory: &Path,
    source_revision: &str,
) -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (
            OsString::from("CIGAR_EVIDENCE_DIR"),
            evidence_directory.as_os_str().to_owned(),
        ),
        (
            OsString::from("CIGAR_SOURCE_REVISION"),
            OsString::from(source_revision),
        ),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("PATH"), safe_path.clone()),
        (
            OsString::from("PYTHONDONTWRITEBYTECODE"),
            OsString::from("1"),
        ),
        (OsString::from("PYTHONNOUSERSITE"), OsString::from("1")),
        (OsString::from("PYTHONSAFEPATH"), OsString::from("1")),
        (OsString::from("TZ"), OsString::from("UTC")),
    ])
}

fn digest_environment(environment: &BTreeMap<OsString, OsString>) -> String {
    let mut digest = Sha256::new();
    for (name, value) in environment {
        let name = name.to_string_lossy();
        let value = if name == "CIGAR_EVIDENCE_DIR" {
            Zeroizing::new("[RUN-PRIVATE-EVIDENCE-ROOT]".to_owned())
        } else {
            Zeroizing::new(value.to_string_lossy().into_owned())
        };
        digest.update(name.len().to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    hex_bytes(&digest.finalize())
}

fn validate_python_closure(profile: &RunProfile) -> Result<(), ControlError> {
    if profile.executable() != crate::ProfileExecutable::Python3 {
        return Err(ControlError::Unavailable);
    }
    let entrypoint = profile
        .argv()
        .iter()
        .find(|argument| argument.ends_with(".py"))
        .ok_or(ControlError::InvalidRequest)?;
    match entrypoint.as_str() {
        "tests/dashboard/validate_schemas.py" | "tools/quality/run_matrix.py" => Ok(()),
        _ => Err(ControlError::Unavailable),
    }
}

fn effective_argv(profile: &RunProfile) -> Result<Vec<String>, ControlError> {
    validate_python_closure(profile)?;
    let mut arguments = Vec::with_capacity(profile.argv().len() + 2);
    arguments.push("-I".to_owned());
    arguments.push("-B".to_owned());
    arguments.extend(profile.argv().iter().cloned());
    Ok(arguments)
}

fn python_closure(profile: &RunProfile) -> Result<&'static [&'static str], ControlError> {
    let entrypoint = profile
        .argv()
        .iter()
        .find(|argument| argument.ends_with(".py"))
        .ok_or(ControlError::InvalidRequest)?;
    match entrypoint.as_str() {
        "tests/dashboard/validate_schemas.py" => Ok(&["tests/dashboard/validate_schemas.py"]),
        "tools/quality/run_matrix.py" => Ok(&[
            "tools/quality/run_matrix.py",
            "scripts/release/evidence_workspace.py",
        ]),
        _ => Err(ControlError::Unavailable),
    }
}

fn source_input_role(profile: &RunProfile, path: &str) -> Result<&'static str, ControlError> {
    let closure = python_closure(profile)?;
    if closure
        .first()
        .is_some_and(|entrypoint| *entrypoint == path)
    {
        return Ok("python-entrypoint");
    }
    if closure.iter().skip(1).any(|import| *import == path) {
        return Ok("python-import");
    }
    if profile
        .argv()
        .windows(2)
        .any(|arguments| matches!(arguments, [flag, value] if flag == "--matrix" && value == path))
    {
        return Ok("profile-configuration");
    }
    Ok("source-input")
}

fn git_tree_entries(
    toolchain: &CapturedToolchain,
    workspace_root: &Path,
    source_revision: &str,
) -> Result<Vec<GitTreeEntry>, ControlError> {
    let output = run_git_capture(
        toolchain,
        workspace_root,
        &["ls-tree", "-r", "-z", "--full-tree", source_revision],
        MAX_GIT_OUTPUT_BYTES,
    )?;
    let mut entries = Vec::new();
    let mut prior: Option<&str> = None;
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let text = std::str::from_utf8(record).map_err(|_error| ControlError::SourceMismatch)?;
        let (metadata, path) = text.split_once('\t').ok_or(ControlError::SourceMismatch)?;
        let mut fields = metadata.split(' ');
        let mode = fields.next().ok_or(ControlError::SourceMismatch)?;
        let kind = fields.next().ok_or(ControlError::SourceMismatch)?;
        let object = fields.next().ok_or(ControlError::SourceMismatch)?;
        if fields.next().is_some()
            || !matches!(mode, "100644" | "100755")
            || kind != "blob"
            || !(object.len() == 40 || object.len() == 64)
            || !object
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !safe_source_relative(path)
            || Path::new(path)
                .file_name()
                .is_some_and(|name| name == OsStr::new(".gitattributes"))
            || prior.is_some_and(|prior| prior.as_bytes() >= path.as_bytes())
        {
            return Err(ControlError::SourceMismatch);
        }
        entries.push(GitTreeEntry {
            mode: if mode == "100755" { 0o755 } else { 0o644 },
            path: path.to_owned(),
        });
        prior = entries.last().map(|entry| entry.path.as_str());
        if entries.len() > MAX_SOURCE_INPUTS {
            return Err(ControlError::SourceMismatch);
        }
    }
    if entries.is_empty() {
        return Err(ControlError::SourceMismatch);
    }
    Ok(entries)
}

fn validate_git_security_configuration(
    toolchain: &CapturedToolchain,
    workspace_root: &Path,
) -> Result<(), ControlError> {
    let configuration = run_git_capture(
        toolchain,
        workspace_root,
        &["config", "--local", "--null", "--list"],
        MAX_GIT_OUTPUT_BYTES,
    )?;
    let mut filemode = None;
    for record in configuration
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let text = std::str::from_utf8(record).map_err(|_error| ControlError::SourceMismatch)?;
        let (key, value) = text.split_once('\n').ok_or(ControlError::SourceMismatch)?;
        let normalized = key.to_ascii_lowercase();
        if normalized == "core.filemode" {
            filemode = Some(value == "true");
        }
        if [
            "include.",
            "filter.",
            "core.attributesfile",
            "core.autocrlf",
            "core.eol",
            "core.fsmonitor",
            "core.hookspath",
            "core.ignorestat",
            "core.safecrlf",
            "core.sparsecheckout",
            "core.splitindex",
            "core.symlinks",
            "core.untrackedcache",
            "extensions.worktreeconfig",
            "index.sparse",
        ]
        .iter()
        .any(|unsafe_key| normalized == *unsafe_key || normalized.starts_with(unsafe_key))
        {
            return Err(ControlError::SourceMismatch);
        }
    }
    if filemode != Some(true) {
        return Err(ControlError::SourceMismatch);
    }
    let shared_index = run_git_capture(
        toolchain,
        workspace_root,
        &["rev-parse", "--shared-index-path"],
        MAX_SOURCE_REVISION_BYTES as u64 + 1,
    )?;
    if !shared_index.is_empty() {
        return Err(ControlError::SourceMismatch);
    }
    Ok(())
}

fn safe_source_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['\\', '\0'])
        && !Path::new(value).is_absolute()
        && Path::new(value).components().all(|component| {
            matches!(component, std::path::Component::Normal(name) if name != OsStr::new(".git"))
        })
}

fn read_tracked_inputs(
    root: &Path,
    entries: &[GitTreeEntry],
    profile: &RunProfile,
) -> Result<Vec<ExecutionInput>, ControlError> {
    let root = root
        .canonicalize()
        .map_err(|_error| ControlError::UnsafePath)?;
    let descriptor = rustix::fs::open(
        &root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| ControlError::UnsafePath)?;
    let root_file = File::from(descriptor);
    validate_source_directory(&root_file)?;
    let root_metadata = root_file
        .metadata()
        .map_err(|_error| ControlError::UnsafePath)?;
    let mut total = 0_u64;
    let mut inputs = Vec::with_capacity(entries.len());
    for entry in entries {
        let (bytes, mode, owner_uid, digest) =
            securely_read_relative(&root, Some(&root_file), Some(entry))?;
        total = total
            .checked_add(bytes)
            .ok_or(ControlError::SourceMismatch)?;
        if total > MAX_SOURCE_TOTAL_BYTES {
            return Err(ControlError::SourceMismatch);
        }
        inputs.push(ExecutionInput {
            bytes,
            mode,
            owner_uid,
            path: entry.path.clone(),
            role: source_input_role(profile, &entry.path)?,
            sha256: digest,
        });
    }
    let rebound = File::open(&root).map_err(|_error| ControlError::UnsafePath)?;
    if !same_identity(
        &root_metadata,
        &rebound
            .metadata()
            .map_err(|_error| ControlError::UnsafePath)?,
    ) {
        return Err(ControlError::UnsafePath);
    }
    validate_python_closure_bytes(&root, &root_file, entries, profile)?;
    Ok(inputs)
}

fn validate_python_closure_bytes(
    root: &Path,
    root_file: &File,
    entries: &[GitTreeEntry],
    profile: &RunProfile,
) -> Result<(), ControlError> {
    const ALLOWED: &[&str] = &[
        "__future__",
        "argparse",
        "dataclasses",
        "datetime",
        "evidence_workspace",
        "hashlib",
        "json",
        "math",
        "os",
        "pathlib",
        "platform",
        "re",
        "secrets",
        "signal",
        "stat",
        "subprocess",
        "sys",
        "tempfile",
        "time",
        "typing",
        "unicodedata",
    ];
    for relative in python_closure(profile)? {
        let entry = entries
            .iter()
            .find(|entry| entry.path == *relative)
            .ok_or(ControlError::SourceMismatch)?;
        let (source, _metadata) = securely_read_relative_bytes(root, root_file, entry)?;
        let text = std::str::from_utf8(&source).map_err(|_error| ControlError::SourceMismatch)?;
        if ["__import__", "importlib", "runpy", "eval(", "exec("]
            .iter()
            .any(|forbidden| text.contains(forbidden))
        {
            return Err(ControlError::SourceMismatch);
        }
        for line in text.lines().map(str::trim_start) {
            let module = if let Some(rest) = line.strip_prefix("import ") {
                rest.split(|character: char| character == ',' || character.is_whitespace())
                    .next()
            } else if let Some(rest) = line.strip_prefix("from ") {
                rest.split_whitespace().next()
            } else {
                None
            };
            if module.is_some_and(|module| {
                let root = module.split('.').next().unwrap_or(module);
                !ALLOWED.contains(&root)
            }) {
                return Err(ControlError::SourceMismatch);
            }
        }
    }
    Ok(())
}

fn securely_read_relative(
    root: &Path,
    root_file: Option<&File>,
    entry: Option<&GitTreeEntry>,
) -> Result<(u64, u32, u32, String), ControlError> {
    let root_file = root_file.ok_or(ControlError::UnsafePath)?;
    let entry = entry.ok_or(ControlError::UnsafePath)?;
    let (source, metadata) = securely_read_relative_bytes(root, root_file, entry)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok((
            u64::try_from(source.len()).map_err(|_error| ControlError::SourceMismatch)?,
            metadata.mode() & 0o777,
            metadata.uid(),
            hex_digest(&source),
        ))
    }
    #[cfg(not(unix))]
    {
        let _ignored = (root, metadata);
        Err(ControlError::Unavailable)
    }
}

fn securely_read_relative_bytes(
    _root: &Path,
    root_file: &File,
    entry: &GitTreeEntry,
) -> Result<(Vec<u8>, fs::Metadata), ControlError> {
    let mut file = securely_open_relative(root_file, entry)?;
    let before = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    let mut source = Vec::with_capacity(
        usize::try_from(before.len())
            .unwrap_or(64 * 1024)
            .min(64 * 1024),
    );
    std::io::Read::by_ref(&mut file)
        .take(MAX_SOURCE_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut source)
        .map_err(|_error| ControlError::UnsafePath)?;
    let after = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    if u64::try_from(source.len()).unwrap_or(u64::MAX) > MAX_SOURCE_INPUT_BYTES
        || !same_regular_snapshot(&before, &after)
    {
        return Err(ControlError::UnsafePath);
    }
    Ok((source, after))
}

fn securely_open_relative(root_file: &File, entry: &GitTreeEntry) -> Result<File, ControlError> {
    let path = Path::new(&entry.path);
    let mut components = path.components().peekable();
    let mut directory = root_file
        .try_clone()
        .map_err(|_error| ControlError::UnsafePath)?;
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(ControlError::UnsafePath);
        };
        if components.peek().is_some() {
            let descriptor = rustix::fs::openat(
                &directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_error| ControlError::UnsafePath)?;
            directory = File::from(descriptor);
            validate_source_directory(&directory)?;
            continue;
        }
        let descriptor = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_error| ControlError::UnsafePath)?;
        let file = File::from(descriptor);
        validate_source_file(&file, entry.mode)?;
        return Ok(file);
    }
    Err(ControlError::UnsafePath)
}

fn validate_source_directory(file: &File) -> Result<(), ControlError> {
    let metadata = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(ControlError::UnsafePath);
        }
    }
    Ok(())
}

fn validate_source_file(file: &File, expected_mode: u32) -> Result<(), ControlError> {
    let metadata = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode() & 0o777;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.len() > MAX_SOURCE_INPUT_BYTES
            || mode & 0o022 != 0
            || (mode & 0o111 != 0) != (expected_mode & 0o111 != 0)
        {
            return Err(ControlError::UnsafePath);
        }
    }
    Ok(())
}

fn toolchain_execution_inputs(
    toolchain: &CapturedToolchain,
) -> Result<Vec<ExecutionInput>, ControlError> {
    let mut inputs = Vec::with_capacity(toolchain.captured.len() + 1);
    for (name, identity) in &toolchain.captured {
        inputs.push(executable_execution_input(name, identity)?);
    }
    if !toolchain
        .captured
        .values()
        .any(|identity| identity.path == toolchain.launcher.path)
    {
        inputs.push(executable_execution_input(
            "dashboard-launcher",
            &toolchain.launcher,
        )?);
    }
    Ok(inputs)
}

fn executable_execution_input(
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<ExecutionInput, ControlError> {
    identity.verify()?;
    let metadata = fs::metadata(&identity.path).map_err(|_error| ControlError::UnsafePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.is_file()
            || metadata.nlink() == 0
            || metadata.uid() != 0 && metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(ControlError::UnsafePath);
        }
        Ok(ExecutionInput {
            bytes: metadata.len(),
            mode: metadata.permissions().mode() & 0o777,
            owner_uid: metadata.uid(),
            path: format!("@toolchain/{name}:{}", identity.path.display()),
            role: "executable",
            sha256: identity.digest.clone(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ignored = (name, metadata);
        Err(ControlError::Unavailable)
    }
}

fn clone_exact_source(
    toolchain: &CapturedToolchain,
    workspace_root: &Path,
    snapshot_path: &Path,
    source_revision: &str,
) -> Result<(), ControlError> {
    if snapshot_path.exists() {
        return Err(ControlError::UnsafePath);
    }
    let clone_arguments = vec![
        OsString::from("clone"),
        OsString::from("--local"),
        OsString::from("--no-hardlinks"),
        OsString::from("--no-checkout"),
        OsString::from("--quiet"),
        OsString::from("--"),
        workspace_root.as_os_str().to_owned(),
        snapshot_path.as_os_str().to_owned(),
    ];
    run_git_quiet(toolchain, &clone_arguments)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(snapshot_path, fs::Permissions::from_mode(0o700))
            .map_err(|_error| ControlError::UnsafePath)?;
    }
    let checkout_arguments = vec![
        OsString::from("-C"),
        snapshot_path.as_os_str().to_owned(),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
        OsString::from("checkout"),
        OsString::from("--detach"),
        OsString::from("--force"),
        OsString::from("--quiet"),
        OsString::from(source_revision),
    ];
    run_git_quiet(toolchain, &checkout_arguments)?;
    canonical_directory(snapshot_path, true).map(|_path| ())
}

fn run_git_capture(
    toolchain: &CapturedToolchain,
    workspace_root: &Path,
    arguments: &[&str],
    maximum: u64,
) -> Result<Vec<u8>, ControlError> {
    let mut complete = Vec::with_capacity(arguments.len() + 2);
    complete.push(OsString::from("-C"));
    complete.push(workspace_root.as_os_str().to_owned());
    complete.extend(arguments.iter().map(OsString::from));
    run_git_command(toolchain, &complete, Some(maximum))
}

fn run_git_quiet(
    toolchain: &CapturedToolchain,
    arguments: &[OsString],
) -> Result<(), ControlError> {
    run_git_command(toolchain, arguments, None).map(|_output| ())
}

fn run_git_command(
    toolchain: &CapturedToolchain,
    arguments: &[OsString],
    capture_maximum: Option<u64>,
) -> Result<Vec<u8>, ControlError> {
    toolchain.git.verify()?;
    let spawn_guard = process_spawn_gate()
        .lock()
        .map_err(|_poisoned| ControlError::SourceMismatch)?;
    let mut command = std::process::Command::new(&toolchain.git.path);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", &toolchain.safe_path)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if capture_maximum.is_some() {
        command.stdout(Stdio::piped());
    } else {
        command.stdout(Stdio::null());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_error| ControlError::SourceMismatch)?;
    drop(spawn_guard);
    let reader = if let Some(maximum) = capture_maximum {
        let stdout = child.stdout.take().ok_or(ControlError::SourceMismatch)?;
        Some(spawn_bounded_reader(
            stdout,
            "cigar-dashboard-git-reader",
            maximum,
        )?)
    } else {
        None
    };
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < GIT_DEADLINE => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) | Err(_) => {
                signal_process_group(child.id(), rustix::process::Signal::KILL);
                let _ignored = child.kill();
                let _ignored = child.wait();
                return Err(ControlError::SourceMismatch);
            }
        }
    };
    if !status.success() {
        return Err(ControlError::SourceMismatch);
    }
    let Some((receiver, handle)) = reader else {
        return Ok(Vec::new());
    };
    let remaining = GIT_DEADLINE.saturating_sub(started.elapsed());
    let output = receiver
        .recv_timeout(remaining)
        .map_err(|_error| ControlError::SourceMismatch)?
        .map_err(|_error| ControlError::SourceMismatch)?;
    handle
        .join()
        .map_err(|_panic| ControlError::SourceMismatch)?;
    if u64::try_from(output.len()).unwrap_or(u64::MAX) > capture_maximum.unwrap_or_default() {
        return Err(ControlError::SourceMismatch);
    }
    Ok(output)
}

fn canonical_directory(path: &Path, create: bool) -> Result<PathBuf, ControlError> {
    if !path.is_absolute() {
        return Err(ControlError::UnsafePath);
    }
    if create && !path.exists() {
        fs::create_dir(path).map_err(|_error| ControlError::UnsafePath)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_error| ControlError::UnsafePath)?;
        }
    }
    let canonical = path
        .canonicalize()
        .map_err(|_error| ControlError::UnsafePath)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|_error| ControlError::UnsafePath)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ControlError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if create
            && (metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o777 != 0o700)
        {
            return Err(ControlError::UnsafePath);
        }
    }
    Ok(canonical)
}

fn create_run_directory(root: &Path, run_id: &str) -> Result<PathBuf, ControlError> {
    let path = root.join(run_id);
    fs::create_dir(&path).map_err(|_error| ControlError::UnsafePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_error| ControlError::UnsafePath)?;
    }
    sync_directory(root)?;
    canonical_directory(&path, true)
}

fn create_toolchain_shim(
    private_root: &Path,
    captured: &BTreeMap<String, ExecutableIdentity>,
) -> Result<PathBuf, ControlError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_error| ControlError::UnsafePath)?;
    let suffix = hex_bytes(&random);
    let directory = private_root.join(format!("toolchain-{suffix}"));
    fs::create_dir(&directory).map_err(|_error| ControlError::UnsafePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_error| ControlError::UnsafePath)?;
        for (name, identity) in captured {
            symlink(&identity.path, directory.join(name))
                .map_err(|_error| ControlError::UnsafePath)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ignored = captured;
        return Err(ControlError::Unavailable);
    }
    sync_directory(&directory)?;
    sync_directory(private_root)?;
    Ok(directory)
}

fn resolve_program(path: &OsString, name: &str) -> Option<PathBuf> {
    let protected = match name {
        "git" => Some(PathBuf::from("/usr/bin/git")),
        "python3" => Some(PathBuf::from("/usr/bin/python3")),
        "ps" => Some(PathBuf::from("/bin/ps")),
        _ => None,
    };
    if protected
        .as_ref()
        .is_some_and(|candidate| candidate.is_file())
    {
        return protected;
    }
    std::env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn capture_process_identity(
    ps: &ExecutableIdentity,
    pid: u32,
) -> Result<RunProcessIdentity, ControlError> {
    let digest = observe_process_identity(ps, pid)?.ok_or(ControlError::SpawnFailed)?;
    RunProcessIdentity::new(pid, pid, digest).map_err(|_error| ControlError::SpawnFailed)
}

fn observe_process_identity(
    ps: &ExecutableIdentity,
    pid: u32,
) -> Result<Option<String>, ControlError> {
    let pid_text = pid.to_string();
    let (status, output) = run_ps(
        ps,
        &[
            "-p", &pid_text, "-o", "pid=", "-o", "pgid=", "-o", "lstart=", "-o", "uid=", "-o",
            "comm=",
        ],
    )?;
    let source = std::str::from_utf8(&output).map_err(|_error| ControlError::RecoveryRequired)?;
    let mut lines = source.lines().filter(|line| !line.trim().is_empty());
    let Some(line) = lines.next() else {
        return if status.success() || output.is_empty() {
            Ok(None)
        } else {
            Err(ControlError::RecoveryRequired)
        };
    };
    if !status.success() || lines.next().is_some() || line.len() > 4096 {
        return Err(ControlError::RecoveryRequired);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    let [
        pid_field,
        group_field,
        _weekday,
        _month,
        _day,
        _clock,
        _year,
        uid_field,
        command @ ..,
    ] = fields.as_slice()
    else {
        return Err(ControlError::RecoveryRequired);
    };
    if command.is_empty()
        || pid_field.parse::<u32>().ok() != Some(pid)
        || group_field.parse::<u32>().ok() != Some(pid)
        || uid_field.parse::<u32>().ok() != Some(rustix::process::geteuid().as_raw())
    {
        return Err(ControlError::RecoveryRequired);
    }
    Ok(Some(hex_digest(line.trim().as_bytes())))
}

fn process_group_has_members(
    ps: &ExecutableIdentity,
    process_group_id: u32,
) -> Result<bool, ControlError> {
    Ok(process_group_usage(ps, process_group_id)?.members != 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessGroupUsage {
    members: u64,
    resident_bytes: u64,
}

fn process_group_usage(
    ps: &ExecutableIdentity,
    process_group_id: u32,
) -> Result<ProcessGroupUsage, ControlError> {
    let group_text = process_group_id.to_string();
    let (status, output) = run_ps(
        ps,
        &[
            "-g",
            &group_text,
            "-o",
            "pid=",
            "-o",
            "pgid=",
            "-o",
            "uid=",
            "-o",
            "rss=",
        ],
    )?;
    let source = std::str::from_utf8(&output).map_err(|_error| ControlError::RecoveryRequired)?;
    let mut members = 0_u64;
    let mut resident_bytes = 0_u64;
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [pid_field, group_field, uid_field, rss_kib_field] = fields.as_slice() else {
            return Err(ControlError::RecoveryRequired);
        };
        let rss_kib = rss_kib_field
            .parse::<u64>()
            .map_err(|_error| ControlError::RecoveryRequired)?;
        if pid_field.parse::<u32>().is_err()
            || group_field.parse::<u32>().ok() != Some(process_group_id)
            || uid_field.parse::<u32>().ok() != Some(rustix::process::geteuid().as_raw())
        {
            return Err(ControlError::RecoveryRequired);
        }
        members = members
            .checked_add(1)
            .ok_or(ControlError::RecoveryRequired)?;
        resident_bytes = resident_bytes
            .checked_add(
                rss_kib
                    .checked_mul(1024)
                    .ok_or(ControlError::RecoveryRequired)?,
            )
            .ok_or(ControlError::RecoveryRequired)?;
    }
    if !status.success() && members != 0 {
        return Err(ControlError::RecoveryRequired);
    }
    Ok(ProcessGroupUsage {
        members,
        resident_bytes,
    })
}

fn capture_tool_version(executable: &ExecutableIdentity) -> Result<String, ControlError> {
    executable.verify()?;
    let spawn_guard = process_spawn_gate()
        .lock()
        .map_err(|_poisoned| ControlError::Unavailable)?;
    let mut child = std::process::Command::new(&executable.path)
        .arg("--version")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_error| ControlError::Unavailable)?;
    drop(spawn_guard);
    let stdout = child.stdout.take().ok_or(ControlError::Unavailable)?;
    let stderr = child.stderr.take().ok_or(ControlError::Unavailable)?;
    let (stdout_receiver, stdout_reader) = spawn_bounded_reader(
        stdout,
        "cigar-dashboard-tool-version-stdout",
        MAX_TOOL_VERSION_BYTES,
    )?;
    let (stderr_receiver, stderr_reader) = spawn_bounded_reader(
        stderr,
        "cigar-dashboard-tool-version-stderr",
        MAX_TOOL_VERSION_BYTES,
    )?;
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < TOOL_VERSION_DEADLINE => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) | Err(_) => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                return Err(ControlError::Unavailable);
            }
        }
    };
    let remaining = TOOL_VERSION_DEADLINE.saturating_sub(started.elapsed());
    let stdout = stdout_receiver
        .recv_timeout(remaining)
        .map_err(|_error| ControlError::Unavailable)?
        .map_err(|_error| ControlError::Unavailable)?;
    let remaining = TOOL_VERSION_DEADLINE.saturating_sub(started.elapsed());
    let stderr = stderr_receiver
        .recv_timeout(remaining)
        .map_err(|_error| ControlError::Unavailable)?
        .map_err(|_error| ControlError::Unavailable)?;
    stdout_reader
        .join()
        .map_err(|_panic| ControlError::Unavailable)?;
    stderr_reader
        .join()
        .map_err(|_panic| ControlError::Unavailable)?;
    let total = stdout
        .len()
        .checked_add(stderr.len())
        .ok_or(ControlError::Unavailable)?;
    if !status.success()
        || total == 0
        || u64::try_from(total).unwrap_or(u64::MAX) > MAX_TOOL_VERSION_BYTES
    {
        return Err(ControlError::Unavailable);
    }
    let mut digest = Sha256::new();
    digest.update(stdout.len().to_be_bytes());
    digest.update(&stdout);
    digest.update(stderr.len().to_be_bytes());
    digest.update(&stderr);
    Ok(hex_bytes(&digest.finalize()))
}

type BoundedReader = (
    std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    std::thread::JoinHandle<()>,
);

fn spawn_bounded_reader<R>(
    mut reader: R,
    name: &str,
    maximum: u64,
) -> Result<BoundedReader, ControlError>
where
    R: std::io::Read + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            let result = reader
                .by_ref()
                .take(maximum.saturating_add(1))
                .read_to_end(&mut output)
                .map(|_count| output);
            let _ignored = sender.send(result);
        })
        .map_err(|_error| ControlError::Unavailable)?;
    Ok((receiver, handle))
}

fn run_ps(
    ps: &ExecutableIdentity,
    arguments: &[&str],
) -> Result<(std::process::ExitStatus, Vec<u8>), ControlError> {
    ps.verify()?;
    let spawn_guard = process_spawn_gate()
        .lock()
        .map_err(|_poisoned| ControlError::RecoveryRequired)?;
    let mut child = std::process::Command::new(&ps.path)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_error| ControlError::RecoveryRequired)?;
    drop(spawn_guard);
    let stdout = child.stdout.take().ok_or(ControlError::RecoveryRequired)?;
    let (send_output, receive_output) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name("cigar-dashboard-ps-reader".to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            let result = stdout
                .take(MAX_PS_OUTPUT_BYTES.saturating_add(1))
                .read_to_end(&mut output)
                .map(|_bytes| output);
            let _ignored = send_output.send(result);
        })
        .map_err(|_error| {
            let _ignored = child.kill();
            let _ignored = child.wait();
            ControlError::RecoveryRequired
        })?;
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PS_DEADLINE => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) | Err(_) => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                return Err(ControlError::RecoveryRequired);
            }
        }
    };
    let remaining = PS_DEADLINE.saturating_sub(started.elapsed());
    let output = receive_output
        .recv_timeout(remaining)
        .map_err(|_error| ControlError::RecoveryRequired)?
        .map_err(|_error| ControlError::RecoveryRequired)?;
    reader
        .join()
        .map_err(|_panic| ControlError::RecoveryRequired)?;
    if u64::try_from(output.len()).unwrap_or(u64::MAX) > MAX_PS_OUTPUT_BYTES {
        return Err(ControlError::RecoveryRequired);
    }
    Ok((status, output))
}

fn digest_file(path: &Path, maximum: u64) -> Result<String, ControlError> {
    let before = fs::symlink_metadata(path).map_err(|_error| ControlError::UnsafePath)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > maximum {
        return Err(ControlError::UnsafePath);
    }
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| ControlError::UnsafePath)?;
    let mut file = File::from(descriptor);
    let opened = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    if !same_regular_snapshot(&before, &opened) {
        return Err(ControlError::UnsafePath);
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_error| ControlError::UnsafePath)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_error| ControlError::UnsafePath)?)
            .ok_or(ControlError::UnsafePath)?;
        if total > maximum {
            return Err(ControlError::UnsafePath);
        }
        let chunk = buffer.get(..read).ok_or(ControlError::UnsafePath)?;
        digest.update(chunk);
    }
    let opened_after = file.metadata().map_err(|_error| ControlError::UnsafePath)?;
    let named_after = fs::symlink_metadata(path).map_err(|_error| ControlError::UnsafePath)?;
    if !same_regular_snapshot(&opened, &opened_after)
        || !same_regular_snapshot(&before, &named_after)
        || !same_identity(&opened_after, &named_after)
    {
        return Err(ControlError::UnsafePath);
    }
    Ok(hex_bytes(&digest.finalize()))
}

fn digest_json<T: Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_vec(value).map_or_else(|_error| hex_digest(&[]), |source| hex_digest(&source))
}

fn hex_digest(source: &[u8]) -> String {
    hex_bytes(&Sha256::digest(source))
}

fn hex_bytes(source: &[u8]) -> String {
    source.iter().fold(
        String::with_capacity(source.len() * 2),
        |mut output, byte| {
            use std::fmt::Write as _;
            if write!(output, "{byte:02x}").is_err() {
                return String::new();
            }
            output
        },
    )
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ControlError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| ControlError::Persistence)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ControlError> {
    Err(ControlError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        CapturedToolchain, ControlError, ControlPlane, ExecutableIdentity, ExecutionSnapshot,
        LIVENESS_LOCK_NAME, LivenessState, ReceiptWriteError, ResourceViolation,
        SUPERVISOR_RECEIPT_NAME, StopReason, capture_available_programs, capture_output,
        classify_receipt_write_error, measure_evidence_tree, monitor_process_group_resources,
        probe_liveness_lock, signal_process_group, terminal_classification,
        verify_supervisor_receipt, wait_for_empty_process_group, write_supervisor_receipt,
    };
    use crate::history::{RunProcessIdentity, RunResourceReservation};
    use crate::{
        DashboardConfig, HistoryStore, ReceiptError, RunProfileRegistry, RunRecord, RunState,
        SafeEventBroker,
    };
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, Instant};

    const VALID: &str = include_str!("../../../tests/dashboard/fixtures/dashboard-valid.toml");
    const REGISTRY: &[u8] = include_bytes!("../../../tests/dashboard/run-profiles-v1.json");

    type SnapshotFixture = (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        String,
        CapturedToolchain,
        crate::RunProfile,
    );

    fn initialize_git_fixture(
        root: &std::path::Path,
        files: &[(&str, &[u8])],
    ) -> Result<String, Box<dyn std::error::Error>> {
        for (relative, source) in files {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().ok_or("fixture parent unavailable")?)?;
            fs::write(path, source)?;
        }
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "CIGAR dashboard test"],
            vec!["config", "user.email", "dashboard-test@invalid"],
            vec!["add", "--all"],
            vec!["commit", "--quiet", "-m", "dashboard fixture"],
        ] {
            let status = std::process::Command::new("/usr/bin/git")
                .args(arguments)
                .current_dir(root)
                .status()?;
            if !status.success() {
                return Err("git fixture creation failed".into());
            }
        }
        let revision = std::process::Command::new("/usr/bin/git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()?;
        if !revision.status.success() {
            return Err("git fixture revision failed".into());
        }
        Ok(std::str::from_utf8(&revision.stdout)?.trim().to_owned())
    }

    fn test_profile(id: &str) -> Result<crate::RunProfile, Box<dyn std::error::Error>> {
        RunProfileRegistry::from_json(REGISTRY)?
            .profiles()
            .iter()
            .find(|profile| profile.id() == id)
            .cloned()
            .ok_or_else(|| "test profile unavailable".into())
    }

    fn snapshot_fixture(
        files: &[(&str, &[u8])],
        profile_id: &str,
    ) -> Result<SnapshotFixture, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let workspace = directory.path().join("workspace");
        let sandbox = directory.path().join("sandbox");
        fs::create_dir(&workspace)?;
        fs::create_dir(&sandbox)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o700))?;
        let revision = initialize_git_fixture(&workspace, files)?;
        let toolchain = CapturedToolchain::capture(&sandbox)?;
        let profile = test_profile(profile_id)?;
        Ok((directory, workspace, sandbox, revision, toolchain, profile))
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn control_fixture(
        root: &std::path::Path,
        dashboard_script: &[u8],
    ) -> Result<(DashboardConfig, Arc<RunProfileRegistry>), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let workspace = root.join("workspace");
        let evidence = root.join("evidence");
        let sandbox = root.join("sandbox");
        for directory in [&workspace, &evidence, &sandbox] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let revision = initialize_git_fixture(
            &workspace,
            &[("tests/dashboard/validate_schemas.py", dashboard_script)],
        )?;
        let mut registry_value: serde_json::Value = serde_json::from_slice(REGISTRY)?;
        let registry_object = registry_value
            .as_object_mut()
            .ok_or("registry root is not an object")?;
        let source_revision = registry_object
            .get_mut("source_revision")
            .ok_or("registry source revision is missing")?;
        *source_revision = serde_json::Value::String(revision);
        let registry_source = serde_json::to_vec_pretty(&registry_value)?;
        let registry_path = root.join("run-profiles-v1.json");
        fs::write(&registry_path, &registry_source)?;
        fs::set_permissions(&registry_path, fs::Permissions::from_mode(0o600))?;
        let control = format!(
            "enabled = true\nworkspace_root = \"{}\"\nprofile_registry = \"{}\"\nevidence_directory = \"{}\"\nsandbox_directory = \"{}\"\nmax_concurrent_runs = 1",
            workspace.display(),
            registry_path.display(),
            evidence.display(),
            sandbox.display(),
        );
        let source = VALID
            .replace("enabled = false\nmax_concurrent_runs = 1", &control)
            .replace(
                "/tmp/cigar-dashboard/history.sqlite3",
                &root.join("history.sqlite3").to_string_lossy(),
            );
        Ok((
            DashboardConfig::from_toml(&source)?,
            Arc::new(RunProfileRegistry::from_json(&registry_source)?),
        ))
    }

    #[test]
    fn missing_or_mismatched_receipts_can_never_be_passing() {
        for error in [
            ReceiptError::Missing,
            ReceiptError::InvalidReceipt,
            ReceiptError::BindingMismatch,
            ReceiptError::OutcomeMismatch,
        ] {
            let (state, _receipt, failure) = terminal_classification(
                StopReason::Exited,
                false,
                None,
                None,
                &Err(error),
                Some("receipt-supervisor"),
            );
            assert_eq!(state, RunState::Failed);
            assert!(failure.is_some());
        }
    }

    #[test]
    fn supervisor_and_resource_failures_override_product_outcomes() {
        let invalid = Err(ReceiptError::Missing);
        let missing_supervisor =
            terminal_classification(StopReason::Exited, false, None, None, &invalid, None);
        assert_eq!(missing_supervisor.0, RunState::Failed);
        assert_eq!(
            missing_supervisor.2,
            Some("run.supervisor_receipt_persistence")
        );

        let memory = terminal_classification(
            StopReason::ResourceLimit,
            false,
            Some(ResourceViolation::Memory),
            None,
            &invalid,
            Some("receipt-supervisor"),
        );
        assert_eq!(memory.0, RunState::Failed);
        assert_eq!(memory.2, Some("run.memory_limit"));

        let cancelled_flood = terminal_classification(
            StopReason::Cancelled,
            true,
            None,
            None,
            &invalid,
            Some("receipt-supervisor"),
        );
        assert_eq!(cancelled_flood.0, RunState::Failed);
        assert_eq!(cancelled_flood.2, Some("run.output_limit"));

        let disk_full = std::io::Error::from_raw_os_error(rustix::io::Errno::NOSPC.raw_os_error());
        assert_eq!(
            classify_receipt_write_error(disk_full),
            ReceiptWriteError::DiskFull
        );
    }

    #[test]
    fn supervisor_receipt_rejects_same_size_mutation_and_inode_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let root = directory.path().canonicalize()?;
        let source = b"{\n  \"schema_version\": \"receipt-a\"\n}\n";
        let binding = write_supervisor_receipt(&root, source)
            .map_err(|error| format!("cannot write supervisor receipt fixture: {error:?}"))?;
        assert!(verify_supervisor_receipt(&root, source, &binding).is_ok());

        let path = root.join(SUPERVISOR_RECEIPT_NAME);
        let mutated = b"{\n  \"schema_version\": \"receipt-b\"\n}\n";
        assert_eq!(mutated.len(), source.len());
        fs::write(&path, mutated)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            verify_supervisor_receipt(&root, source, &binding).err(),
            Some(ReceiptWriteError::Unavailable)
        );

        fs::remove_file(&path)?;
        fs::write(&path, source)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            verify_supervisor_receipt(&root, source, &binding).err(),
            Some(ReceiptWriteError::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn same_head_dirty_entrypoint_and_imported_module_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        const DASHBOARD: &[u8] = b"from __future__ import annotations\nimport json\n";
        let (_directory, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[("tests/dashboard/validate_schemas.py", DASHBOARD)],
            "dashboard-contracts",
        )?;
        fs::write(
            workspace.join("tests/dashboard/validate_schemas.py"),
            b"from __future__ import annotations\nimport hashlib\n",
        )?;
        assert_eq!(
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision,)
                .err(),
            Some(ControlError::SourceMismatch)
        );

        const RUNNER: &[u8] = b"from __future__ import annotations\nimport hashlib\nfrom evidence_workspace import EvidenceWorkspace\n";
        const IMPORT: &[u8] = b"from __future__ import annotations\nimport hashlib\n";
        let (_directory, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[
                ("tools/quality/run_matrix.py", RUNNER),
                ("scripts/release/evidence_workspace.py", IMPORT),
                ("tests/compatibility/matrix-v1.json", b"{}\n"),
            ],
            "compatibility-matrix",
        )?;
        fs::write(
            workspace.join("scripts/release/evidence_workspace.py"),
            b"from __future__ import annotations\nimport secrets\n",
        )?;
        assert_eq!(
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision,)
                .err(),
            Some(ControlError::SourceMismatch)
        );
        Ok(())
    }

    #[test]
    fn capture_to_launch_swap_and_snapshot_mutation_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        const DASHBOARD: &[u8] = b"from __future__ import annotations\nimport json\n";
        let (_directory, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[("tests/dashboard/validate_schemas.py", DASHBOARD)],
            "dashboard-contracts",
        )?;
        let snapshot =
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision)?;
        fs::write(
            workspace.join("tests/dashboard/validate_schemas.py"),
            b"from __future__ import annotations\nimport hashlib\n",
        )?;
        assert_eq!(
            snapshot.verify_live_source(&workspace, &profile).err(),
            Some(ControlError::SourceMismatch)
        );
        assert!(snapshot.verify(&toolchain, &profile).is_ok());
        fs::write(
            snapshot.root.join("tests/dashboard/validate_schemas.py"),
            b"from __future__ import annotations\nimport secrets\n",
        )?;
        assert_eq!(
            snapshot.verify(&toolchain, &profile).err(),
            Some(ControlError::SourceMismatch)
        );
        Ok(())
    }

    #[test]
    fn execution_input_omission_extra_and_digest_substitution_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        const DASHBOARD: &[u8] = b"from __future__ import annotations\nimport json\n";
        let (_directory, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[("tests/dashboard/validate_schemas.py", DASHBOARD)],
            "dashboard-contracts",
        )?;
        let mut snapshot =
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision)?;
        let original_inputs = snapshot.inputs.clone();
        let removed = snapshot.inputs.pop().ok_or("execution inputs are empty")?;
        assert_eq!(
            snapshot.verify(&toolchain, &profile).err(),
            Some(ControlError::SourceMismatch)
        );
        snapshot.inputs.push(removed.clone());
        snapshot.inputs.push(removed);
        snapshot
            .inputs
            .sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        assert_eq!(
            snapshot.verify(&toolchain, &profile).err(),
            Some(ControlError::SourceMismatch)
        );
        snapshot.inputs = original_inputs;
        let first = snapshot
            .inputs
            .first_mut()
            .ok_or("execution inputs are empty")?;
        first.sha256 = "0".repeat(64);
        assert_eq!(
            snapshot.verify(&toolchain, &profile).err(),
            Some(ControlError::SourceMismatch)
        );
        Ok(())
    }

    #[test]
    fn source_links_unreviewed_imports_and_unsafe_executable_ancestors_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let (_directory, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[(
                "tests/dashboard/validate_schemas.py",
                b"from __future__ import annotations\nimport local_unreviewed\n",
            )],
            "dashboard-contracts",
        )?;
        assert_eq!(
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision,)
                .err(),
            Some(ControlError::SourceMismatch)
        );

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let unsafe_parent = directory.path().join("unsafe");
        fs::create_dir(&unsafe_parent)?;
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
        let executable = unsafe_parent.join("tool");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            ExecutableIdentity::capture(&executable).err(),
            Some(ControlError::UnsafePath)
        );

        let safe_parent = directory.path().join("safe");
        fs::create_dir(&safe_parent)?;
        fs::set_permissions(&safe_parent, fs::Permissions::from_mode(0o700))?;
        let safe_node = safe_parent.join("node");
        fs::write(&safe_node, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&safe_node, fs::Permissions::from_mode(0o700))?;
        let unsafe_go = unsafe_parent.join("go");
        fs::write(&unsafe_go, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&unsafe_go, fs::Permissions::from_mode(0o700))?;
        let search_path = std::env::join_paths([safe_parent.clone(), unsafe_parent.clone()])?;
        let optional = capture_available_programs(&search_path);
        assert!(optional.contains_key("node"));
        assert!(!optional.contains_key("go"));

        let node_identity = optional.get("node").ok_or("safe node was not captured")?;
        let displaced_parent = directory.path().join("safe-displaced");
        fs::rename(&safe_parent, &displaced_parent)?;
        fs::create_dir(&safe_parent)?;
        fs::set_permissions(&safe_parent, fs::Permissions::from_mode(0o700))?;
        fs::write(&safe_node, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&safe_node, fs::Permissions::from_mode(0o700))?;
        assert_eq!(node_identity.verify().err(), Some(ControlError::UnsafePath));

        const DASHBOARD: &[u8] = b"from __future__ import annotations\nimport json\n";
        let (_fixture, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[("tests/dashboard/validate_schemas.py", DASHBOARD)],
            "dashboard-contracts",
        )?;
        let script = workspace.join("tests/dashboard/validate_schemas.py");
        let linked = workspace.join("tests/dashboard/linked.py");
        fs::hard_link(&script, &linked)?;
        assert_eq!(
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision,)
                .err(),
            Some(ControlError::UnsafePath)
        );

        let (_fixture, workspace, sandbox, revision, toolchain, profile) = snapshot_fixture(
            &[("tests/dashboard/validate_schemas.py", DASHBOARD)],
            "dashboard-contracts",
        )?;
        let script = workspace.join("tests/dashboard/validate_schemas.py");
        let replacement = workspace.join("replacement.py");
        fs::write(&replacement, DASHBOARD)?;
        fs::remove_file(&script)?;
        symlink(&replacement, &script)?;
        assert_eq!(
            ExecutionSnapshot::capture(&toolchain, &workspace, &sandbox, &profile, &revision,)
                .err(),
            Some(ControlError::UnsafePath)
        );
        Ok(())
    }

    #[tokio::test]
    async fn output_ceiling_is_shared_across_both_content_opaque_streams()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncWriteExt as _;

        let aggregate = Arc::new(AtomicU64::new(0));
        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(64);
        let (mut stderr_writer, stderr_reader) = tokio::io::duplex(64);
        stdout_writer.write_all(b"123456").await?;
        stderr_writer.write_all(b"abcdef").await?;
        stdout_writer.shutdown().await?;
        stderr_writer.shutdown().await?;
        let (stdout, stderr) = tokio::join!(
            capture_output(Some(stdout_reader), 10, Arc::clone(&aggregate)),
            capture_output(Some(stderr_reader), 10, aggregate),
        );
        let stdout = stdout?;
        let stderr = stderr?;
        assert_eq!(stdout.bytes + stderr.bytes, 12);
        assert!(stdout.exceeded || stderr.exceeded);
        Ok(())
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[tokio::test]
    async fn aggregate_process_and_resident_memory_ceilings_stop_owned_groups()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::process::CommandExt as _;

        let ps = ExecutableIdentity::capture(std::path::Path::new("/bin/ps"))?;
        let cases = [
            (
                "import subprocess,time; subprocess.Popen(['/bin/sleep','30']); time.sleep(30)",
                1,
                65_536,
                ResourceViolation::ProcessCount,
            ),
            (
                "import time; payload=bytearray(16 * 1024 * 1024); time.sleep(30)",
                8,
                1,
                ResourceViolation::Memory,
            ),
        ];
        for (script, maximum_processes, maximum_memory_mib, expected) in cases {
            let mut command = tokio::process::Command::new("/usr/bin/python3");
            command
                .args(["-I", "-B", "-c", script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            command.as_std_mut().process_group(0);
            let mut child = command.spawn()?;
            let process_group_id = child.id().ok_or("resource test child has no pid")?;
            let observed = tokio::time::timeout(
                Duration::from_secs(5),
                monitor_process_group_resources(
                    ps.clone(),
                    process_group_id,
                    maximum_processes,
                    maximum_memory_mib,
                ),
            )
            .await;
            signal_process_group(process_group_id, rustix::process::Signal::KILL);
            let _ignored = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            assert!(
                wait_for_empty_process_group(ps.clone(), process_group_id, Duration::from_secs(5),)
                    .await
            );
            assert_eq!(observed?, expected);
        }
        Ok(())
    }

    #[test]
    fn evidence_ledger_rejects_links_and_counts_nested_regular_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let root = directory.path().canonicalize()?;
        let nested = root.join("reports");
        fs::create_dir(&nested)?;
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))?;
        let first = root.join("first.json");
        let second = nested.join("second.json");
        fs::write(&first, b"abc")?;
        fs::write(&second, b"defg")?;
        fs::set_permissions(&first, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&second, fs::Permissions::from_mode(0o600))?;
        assert_eq!(measure_evidence_tree(&root)?, 7);

        let linked = nested.join("linked.json");
        fs::hard_link(&first, &linked)?;
        assert_eq!(
            measure_evidence_tree(&root).err(),
            Some("run.evidence_ledger_unsafe")
        );
        fs::remove_file(&linked)?;
        let symlinked = nested.join("symlinked.json");
        symlink(&first, &symlinked)?;
        assert_eq!(
            measure_evidence_tree(&root).err(),
            Some("run.evidence_ledger_unsafe")
        );
        Ok(())
    }

    #[test]
    fn cancellation_and_timeout_are_distinct_terminal_states() {
        let invalid = Err(ReceiptError::Missing);
        assert_eq!(
            terminal_classification(
                StopReason::Cancelled,
                false,
                None,
                None,
                &invalid,
                Some("receipt-supervisor"),
            )
            .0,
            RunState::Cancelled
        );
        assert_eq!(
            terminal_classification(
                StopReason::TimedOut,
                false,
                None,
                None,
                &invalid,
                Some("receipt-supervisor"),
            )
            .0,
            RunState::TimedOut
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn supervisor_process_crash_helper() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let Some(root) = std::env::var_os("CIGAR_DASHBOARD_CRASH_FIXTURE_ROOT") else {
            return Ok(());
        };
        let root = std::path::PathBuf::from(root).canonicalize()?;
        let source = fs::read_to_string(root.join("crash-config.toml"))?;
        let config = DashboardConfig::from_toml(&source)?;
        let registry = Arc::new(RunProfileRegistry::load(
            &root.join("run-profiles-v1.json"),
        )?);
        let history = HistoryStore::open(&config.history, config.server.max_event_bytes)?;
        let events = SafeEventBroker::new(
            config.history.max_events_per_run.min(10_000),
            config.history.max_bytes,
            config.server.max_event_bytes,
            config.server.max_sse_subscribers,
        )?;
        events.attach_sink(history.sink())?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let outcome: Result<(), ControlError> = runtime.block_on(async {
            let plane = ControlPlane::initialize(&config, registry, history.client(), events)?;
            let run = plane.start("dashboard-contracts")?;
            if run.state() != RunState::Running
                || probe_liveness_lock(
                    &plane
                        .inner
                        .sandbox_root
                        .join(run.run_id())
                        .join(LIVENESS_LOCK_NAME),
                )? != LivenessState::Held
            {
                return Err(ControlError::RecoveryRequired);
            }
            let run_id_path = root.join("crashed-run-id");
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = options
                .open(&run_id_path)
                .map_err(|_error| ControlError::Persistence)?;
            file.write_all(run.run_id().as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_error| ControlError::Persistence)?;
            fs::set_permissions(&run_id_path, fs::Permissions::from_mode(0o600))
                .map_err(|_error| ControlError::Persistence)?;
            // This intentionally bypasses every destructor to model the sidecar process dying.
            std::process::exit(73);
        });
        outcome?;
        Ok(())
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn supervisor_process_crash_reconciles_only_after_child_identity_is_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        const SLEEPING_SCRIPT: &[u8] =
            b"from __future__ import annotations\nimport time\ntime.sleep(60)\n";
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let (config, registry) = control_fixture(directory.path(), SLEEPING_SCRIPT)?;
        let config_path = directory.path().join("crash-config.toml");
        fs::write(&config_path, toml::to_string(&config)?)?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        let helper = std::env::current_exe()?;
        let status = std::process::Command::new(helper)
            .args([
                "--exact",
                "control::tests::supervisor_process_crash_helper",
                "--nocapture",
            ])
            .env(
                "CIGAR_DASHBOARD_CRASH_FIXTURE_ROOT",
                directory.path().canonicalize()?,
            )
            .status()?;
        assert_eq!(status.code(), Some(73));
        let run_id = fs::read_to_string(directory.path().join("crashed-run-id"))?;

        // The orphan is still alive and holds the inherited lock. A new sidecar must refuse to
        // adopt, signal, or mark it lost while either liveness or process identity is ambiguous.
        let first = HistoryStore::open(&config.history, config.server.max_event_bytes)?;
        let first_events = SafeEventBroker::new(
            config.history.max_events_per_run.min(10_000),
            config.history.max_bytes,
            config.server.max_event_bytes,
            config.server.max_sse_subscribers,
        )?;
        first_events.attach_sink(first.sink())?;
        assert_eq!(
            ControlPlane::initialize(&config, Arc::clone(&registry), first.client(), first_events,)
                .err(),
            Some(ControlError::RecoveryRequired)
        );
        let process_group_id = first
            .client()
            .recoverable_runs()?
            .iter()
            .find(|recovered| recovered.run().run_id() == run_id)
            .and_then(|recovered| recovered.process())
            .map(RunProcessIdentity::process_group_id)
            .ok_or("crashed child process identity is unavailable")?;
        first.shutdown()?;
        drop(first);
        let process_group_id = i32::try_from(process_group_id)?;
        let process_group_id =
            rustix::process::Pid::from_raw(process_group_id).ok_or("invalid process group")?;
        rustix::process::kill_process_group(process_group_id, rustix::process::Signal::KILL)?;

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let reopened = HistoryStore::open(&config.history, config.server.max_event_bytes)?;
            let events = SafeEventBroker::new(
                config.history.max_events_per_run.min(10_000),
                config.history.max_bytes,
                config.server.max_event_bytes,
                config.server.max_sse_subscribers,
            )?;
            events.attach_sink(reopened.sink())?;
            match ControlPlane::initialize(
                &config,
                Arc::clone(&registry),
                reopened.client(),
                events,
            ) {
                Ok(plane) => {
                    assert_eq!(reopened.client().get_run(&run_id)?.state(), RunState::Lost);
                    drop(plane);
                    reopened.shutdown()?;
                    break;
                }
                Err(ControlError::RecoveryRequired) if Instant::now() < deadline => {
                    reopened.shutdown()?;
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let connection = rusqlite::Connection::open(&config.history.database_file)?;
        let settled: (String, bool) = connection.query_row(
            "SELECT l.accounting_state, p.settled_at IS NOT NULL
             FROM run_resource_ledgers l JOIN run_processes p USING (run_id)
             WHERE l.run_id = ?1",
            [&run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(settled, ("indeterminate".to_owned(), true));
        Ok(())
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[tokio::test]
    async fn reviewed_dashboard_contract_profile_produces_verified_bound_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let evidence = directory.path().join("evidence");
        let sandbox = directory.path().join("sandbox");
        fs::create_dir(&evidence)?;
        fs::create_dir(&sandbox)?;
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o700))?;
        let source_workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("workspace root unavailable")?
            .canonicalize()?;
        let workspace = directory.path().join("workspace");
        fs::create_dir_all(workspace.join("tests/dashboard"))?;
        fs::create_dir_all(workspace.join("schemas/dashboard"))?;
        fs::copy(
            source_workspace.join("tests/dashboard/validate_schemas.py"),
            workspace.join("tests/dashboard/validate_schemas.py"),
        )?;
        for entry in fs::read_dir(source_workspace.join("schemas/dashboard"))? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".schema.json"))
            {
                fs::copy(
                    entry.path(),
                    workspace.join("schemas/dashboard").join(entry.file_name()),
                )?;
            }
        }
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "CIGAR dashboard test"],
            vec!["config", "user.email", "dashboard-test@invalid"],
            vec!["add", "--all"],
            vec!["commit", "--quiet", "-m", "dashboard fixture"],
        ] {
            let status = std::process::Command::new("git")
                .args(arguments)
                .current_dir(&workspace)
                .status()?;
            if !status.success() {
                return Err("clean test workspace creation failed".into());
            }
        }
        let revision = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&workspace)
            .output()?;
        if !revision.status.success() {
            return Err("clean test workspace revision failed".into());
        }
        let revision = std::str::from_utf8(&revision.stdout)?.trim();
        let registry_source = std::str::from_utf8(REGISTRY)?
            .replace("56a5a1346bdfd362f67c279f4f8cd5d4ba7c46b2", revision)
            .into_bytes();
        let registry_path = directory.path().join("run-profiles-v1.json");
        fs::write(&registry_path, &registry_source)?;
        let control = format!(
            "enabled = true\nworkspace_root = \"{}\"\nprofile_registry = \"{}\"\nevidence_directory = \"{}\"\nsandbox_directory = \"{}\"\nmax_concurrent_runs = 1",
            workspace.display(),
            registry_path.display(),
            evidence.display(),
            sandbox.display(),
        );
        let source = VALID
            .replace("enabled = false\nmax_concurrent_runs = 1", &control)
            .replace(
                "/tmp/cigar-dashboard/history.sqlite3",
                &directory.path().join("history.sqlite3").to_string_lossy(),
            );
        let config = DashboardConfig::from_toml(&source)?;
        let registry = Arc::new(RunProfileRegistry::from_json(&registry_source)?);
        let history = HistoryStore::open(&config.history, config.server.max_event_bytes)?;
        let events = SafeEventBroker::new(
            config.history.max_events_per_run.min(10_000),
            config.history.max_bytes,
            config.server.max_event_bytes,
            config.server.max_sse_subscribers,
        )?;
        events.attach_sink(history.sink())?;
        let mut plane =
            ControlPlane::initialize(&config, registry.clone(), history.client(), events.clone())?;
        let security_before = plane
            .public_profiles()
            .into_iter()
            .find(|profile| profile.id() == "security-matrix")
            .ok_or("security profile missing")?
            .availability_state();
        let inner = Arc::get_mut(&mut plane.inner).ok_or("control plane unexpectedly shared")?;
        for optional in ["corepack", "go", "node", "uv"] {
            inner.toolchain.captured.remove(optional);
        }
        let narrowed = plane.public_profiles();
        assert_eq!(
            narrowed
                .iter()
                .find(|profile| profile.id() == "dashboard-contracts")
                .ok_or("dashboard profile missing")?
                .availability_state(),
            crate::AvailabilityState::Available
        );
        assert_eq!(
            narrowed
                .iter()
                .find(|profile| profile.id() == "compatibility-matrix")
                .ok_or("compatibility profile missing")?
                .availability_state(),
            crate::AvailabilityState::ToolMissing
        );
        assert_eq!(
            narrowed
                .iter()
                .find(|profile| profile.id() == "security-matrix")
                .ok_or("security profile missing")?
                .availability_state(),
            security_before
        );
        let started = plane.start("dashboard-contracts")?;
        assert_eq!(
            probe_liveness_lock(
                &plane
                    .inner
                    .sandbox_root
                    .join(started.run_id())
                    .join(LIVENESS_LOCK_NAME),
            )?,
            LivenessState::Held
        );
        assert_eq!(
            ControlPlane::initialize(&config, registry.clone(), history.client(), events.clone(),)
                .err(),
            Some(ControlError::RecoveryRequired)
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let observed = history.client().get_run(started.run_id())?;
            if observed.state().is_terminal() {
                assert_eq!(
                    observed.state(),
                    RunState::Passed,
                    "unexpected terminal failure: {:?}",
                    observed.failure_code()
                );
                break;
            }
            if Instant::now() >= deadline {
                return Err("dashboard contract profile did not settle".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        plane.shutdown(Duration::from_secs(2)).await;
        let descriptors = history.client().list_evidence(10)?;
        assert_eq!(descriptors.len(), 2);
        assert!(
            descriptors.iter().all(|descriptor| {
                descriptor.category() == crate::EvidenceCategory::Development
            })
        );
        let run_directory = evidence.join(started.run_id());
        assert!(
            run_directory
                .join("dashboard-schema-check.v1.json")
                .is_file()
        );
        assert!(
            run_directory
                .join("dashboard-supervisor-receipt.v1.json")
                .is_file()
        );
        let supervisor: serde_json::Value = serde_json::from_slice(&fs::read(
            run_directory.join("dashboard-supervisor-receipt.v1.json"),
        )?)?;
        assert_eq!(
            supervisor
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("cigar.dashboard-supervisor-receipt.v1")
        );
        assert!(
            supervisor
                .get("monotonic_elapsed_ns")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|value| value > 0)
        );
        assert!(
            supervisor
                .get("tool_version_sha256")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.len() == 64)
        );
        assert!(supervisor.get("resource_violation").is_none());
        assert_eq!(
            supervisor
                .get("source_clean")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            supervisor
                .get("source_tree_sha256")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.len() == 64)
        );
        assert_eq!(
            supervisor
                .get("profile_sha256")
                .and_then(serde_json::Value::as_str),
            Some(started.profile_digest())
        );
        assert!(
            supervisor
                .get("dashboard_sha256")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.len() == 64)
        );
        let execution_inputs = supervisor
            .get("execution_inputs")
            .and_then(serde_json::Value::as_array)
            .ok_or("supervisor execution inputs missing")?;
        assert!(!execution_inputs.is_empty());
        let input_paths = execution_inputs
            .iter()
            .map(|input| {
                let object = input
                    .as_object()
                    .ok_or("execution input is not an object")?;
                let fields = object
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>();
                if fields
                    != ["bytes", "mode", "owner_uid", "path", "role", "sha256"]
                        .into_iter()
                        .collect()
                {
                    return Err("execution input fields are not exact");
                }
                let digest = object
                    .get("sha256")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("execution input digest missing")?;
                if digest.len() != 64 {
                    return Err("execution input digest is invalid");
                }
                object
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("execution input path missing")
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            input_paths
                .windows(2)
                .all(|pair| matches!(pair, [left, right] if left < right))
        );
        let supervisor_schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/dashboard/dashboard-supervisor-receipt-v1.schema.json"
        ))?;
        let required = supervisor_schema
            .get("required")
            .and_then(serde_json::Value::as_array)
            .ok_or("supervisor schema required fields missing")?
            .iter()
            .map(|value| value.as_str().ok_or("invalid required field"))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let properties = supervisor_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .ok_or("supervisor schema properties missing")?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let observed = supervisor
            .as_object()
            .ok_or("supervisor receipt is not an object")?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(observed, required);
        assert_eq!(
            properties
                .difference(&required)
                .copied()
                .collect::<Vec<_>>(),
            vec!["resource_violation"]
        );
        let measured_evidence = measure_evidence_tree(&run_directory.canonicalize()?)?;
        let connection = rusqlite::Connection::open(directory.path().join("history.sqlite3"))?;
        let ledger: (i64, i64, String) = connection.query_row(
            "SELECT output_bytes, evidence_bytes, accounting_state
             FROM run_resource_ledgers WHERE run_id = ?1",
            [started.run_id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert!(ledger.0 > 0);
        assert_eq!(u64::try_from(ledger.1)?, measured_evidence);
        assert_eq!(ledger.2, "settled");

        let profile = registry
            .profiles()
            .iter()
            .find(|profile| profile.id() == "dashboard-contracts")
            .ok_or("dashboard profile unavailable")?;
        let fake = RunRecord::queued(
            profile.id(),
            &profile.digest_hex()?,
            &registry.digest_hex(),
            registry.source_revision(),
        )?;
        let fake_id = fake.run_id().to_owned();
        history.client().create_run_with_resources(
            fake,
            RunResourceReservation::new(
                profile.maximum_output_bytes(),
                profile.maximum_evidence_bytes(),
            )?,
        )?;
        let executable_digest = plane
            .inner
            .toolchain
            .python3
            .as_ref()
            .ok_or("python unavailable")?
            .digest
            .clone();
        history.client().transition_run(
            &fake_id,
            RunState::Preparing,
            Some(&executable_digest),
            None,
            None,
        )?;
        history.client().activate_run(
            &fake_id,
            RunProcessIdentity::new(
                i32::MAX as u32,
                i32::MAX as u32,
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
            )?,
        )?;
        let recovered = ControlPlane::initialize(&config, registry, history.client(), events)?;
        assert_eq!(history.client().get_run(&fake_id)?.state(), RunState::Lost);
        drop(recovered);
        Ok(())
    }
}
