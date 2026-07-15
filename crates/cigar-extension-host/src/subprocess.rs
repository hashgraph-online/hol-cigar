//! One-process-per-invocation native backend with fail-closed operating-system isolation.

use crate::broker::CapabilityBroker;
use crate::digest::raw_content_digest;
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use crate::frame::FrameCodec;
use crate::host::{ExtensionBackend, InvocationCancellation, RuntimeResponse};
use crate::manifest::ActivatedExtension;
use cigar_canon::MAX_CANONICAL_INPUT_BYTES;
use cigar_protocol::{
    ExtensionComputeBudget, ExtensionHandle, ExtensionHostCallKind, ExtensionInvocationV1,
    ExtensionResponseV1, ExtensionRuntimeKind, RecordId,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const MAX_STDERR_BYTES: usize = 65_536;
#[cfg(target_os = "linux")]
const MAX_NATIVE_PROCESSES: u8 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Clone)]
enum SandboxLauncher {
    #[cfg(target_os = "macos")]
    MacOsSandboxExec { profile: String },
    #[cfg(target_os = "linux")]
    LinuxBubblewrap {
        executable: PathBuf,
        limiter: PathBuf,
    },
    #[cfg(test)]
    DirectFixture { arguments: Vec<String> },
}

/// Verified operating-system sandbox configuration for one native package.
#[derive(Clone)]
pub struct SubprocessSandbox {
    snapshot: Arc<ExecutableSnapshot>,
    launcher: SandboxLauncher,
    maximum_memory_bytes: u64,
    maximum_cpu_seconds: u64,
}

struct ExecutableSnapshot {
    directory: tempfile::TempDir,
    executable: PathBuf,
}

impl fmt::Debug for SubprocessSandbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let launcher = match &self.launcher {
            #[cfg(target_os = "macos")]
            SandboxLauncher::MacOsSandboxExec { .. } => "macos_sandbox_exec",
            #[cfg(target_os = "linux")]
            SandboxLauncher::LinuxBubblewrap { .. } => "linux_bubblewrap",
            #[cfg(test)]
            SandboxLauncher::DirectFixture { .. } => "test_direct_fixture",
        };
        formatter
            .debug_struct("SubprocessSandbox")
            .field("launcher", &launcher)
            .field(
                "snapshot_directory_depth",
                &self.snapshot.directory.path().components().count(),
            )
            .field(
                "executable_depth",
                &self.snapshot.executable.components().count(),
            )
            .finish_non_exhaustive()
    }
}

impl SubprocessSandbox {
    /// Resolves and verifies an extension entry point and selects a fail-closed Tier-1 sandbox.
    pub fn for_current_platform(
        activated: &ActivatedExtension,
        package_root: &Path,
    ) -> Result<Self, ExtensionHostError> {
        if activated.manifest().runtime != ExtensionRuntimeKind::IsolatedSubprocess {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let snapshot = verified_snapshot(activated, package_root)?;
        #[cfg(target_os = "macos")]
        let launcher = {
            let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
            if !sandbox_exec.is_file() {
                return Err(error(ExtensionHostErrorCode::BackendUnavailable));
            }
            SandboxLauncher::MacOsSandboxExec {
                profile: macos_profile(&snapshot.executable),
            }
        };
        #[cfg(target_os = "linux")]
        let launcher = {
            let candidate = [Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")]
                .into_iter()
                .find(|path| path.is_file())
                .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
            SandboxLauncher::LinuxBubblewrap {
                executable: candidate.to_path_buf(),
                limiter: [Path::new("/usr/bin/prlimit"), Path::new("/bin/prlimit")]
                    .into_iter()
                    .find(|path| path.is_file())
                    .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?
                    .to_path_buf(),
            }
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(error(ExtensionHostErrorCode::BackendUnavailable));

        let (maximum_memory_bytes, maximum_cpu_seconds) = native_limits(activated)?;
        Ok(Self {
            snapshot,
            launcher,
            maximum_memory_bytes,
            maximum_cpu_seconds,
        })
    }

    #[cfg(test)]
    pub(crate) fn direct_fixture(
        activated: &ActivatedExtension,
        package_root: &Path,
        arguments: Vec<String>,
    ) -> Result<Self, ExtensionHostError> {
        let snapshot = verified_snapshot(activated, package_root)?;
        let (maximum_memory_bytes, maximum_cpu_seconds) = native_limits(activated)?;
        Ok(Self {
            snapshot,
            launcher: SandboxLauncher::DirectFixture { arguments },
            maximum_memory_bytes,
            maximum_cpu_seconds,
        })
    }

    fn command(&self) -> Command {
        let mut command = match &self.launcher {
            #[cfg(target_os = "macos")]
            SandboxLauncher::MacOsSandboxExec { profile } => {
                let mut command = Command::new("/bin/sh");
                command
                    .arg("-c")
                    .arg(concat!(
                        "cpu=$1; shift; ",
                        "ulimit -t \"$cpu\" || exit 125; exec \"$@\""
                    ))
                    .arg("cigar-native-limits")
                    .arg(self.maximum_cpu_seconds.to_string())
                    .arg("/usr/bin/sandbox-exec")
                    .arg("-p")
                    .arg(profile)
                    .arg(&self.snapshot.executable);
                command
            }
            #[cfg(target_os = "linux")]
            SandboxLauncher::LinuxBubblewrap {
                executable,
                limiter,
            } => {
                let mut command = Command::new(limiter);
                command
                    .arg(format!("--as={}", self.maximum_memory_bytes))
                    .arg(format!("--cpu={}", self.maximum_cpu_seconds))
                    .arg("--")
                    .arg(executable)
                    .arg("--die-with-parent")
                    .arg("--unshare-user")
                    .arg("--unshare-pid")
                    .arg("--unshare-net")
                    .arg("--unshare-ipc")
                    .arg("--unshare-uts")
                    .arg("--new-session")
                    .arg("--clearenv")
                    .arg("--cap-drop")
                    .arg("ALL")
                    .arg("--uid")
                    .arg("65534")
                    .arg("--gid")
                    .arg("65534")
                    .arg("--setenv")
                    .arg("LANG")
                    .arg("C")
                    .arg("--setenv")
                    .arg("LC_ALL")
                    .arg("C")
                    .arg("--setenv")
                    .arg("TZ")
                    .arg("UTC")
                    .arg("--dir")
                    .arg("/cigar")
                    .arg("--ro-bind")
                    .arg(&self.snapshot.executable)
                    .arg("/cigar/extension")
                    .arg("--ro-bind")
                    .arg(limiter)
                    .arg("/cigar/prlimit")
                    .arg("--dir")
                    .arg("/tmp")
                    .arg("--dir")
                    .arg("/dev")
                    .arg("--ro-bind")
                    .arg("/dev/null")
                    .arg("/dev/null");
                for system_root in ["/usr/lib", "/usr/lib64", "/lib", "/lib64"] {
                    if Path::new(system_root).exists() {
                        command.arg("--ro-bind").arg(system_root).arg(system_root);
                    }
                }
                command
                    .arg("--chdir")
                    .arg("/cigar")
                    .arg("--")
                    .arg("/cigar/prlimit")
                    .arg(format!(
                        "--nproc={MAX_NATIVE_PROCESSES}:{MAX_NATIVE_PROCESSES}"
                    ))
                    .arg("--")
                    .arg("/cigar/extension");
                command
            }
            #[cfg(test)]
            SandboxLauncher::DirectFixture { arguments } => {
                let mut command = Command::new(&self.snapshot.executable);
                command.args(arguments);
                command
            }
        };
        command
            .current_dir(self.snapshot.directory.path())
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

fn native_limits(activated: &ActivatedExtension) -> Result<(u64, u64), ExtensionHostError> {
    let ExtensionComputeBudget::CpuTime { duration } = activated.manifest().limits.compute else {
        return Err(error(ExtensionHostErrorCode::InvalidInput));
    };
    let maximum_cpu_seconds = duration
        .get()
        .checked_add(999_999_999)
        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?
        / 1_000_000_000;
    Ok((
        activated.manifest().limits.max_memory_bytes,
        maximum_cpu_seconds.max(1),
    ))
}

/// Canonical framed native backend that requires a clean process exit after every response.
#[derive(Clone, Debug)]
pub struct IsolatedSubprocessBackend {
    sandbox: SubprocessSandbox,
    codec: FrameCodec,
}

impl IsolatedSubprocessBackend {
    /// Creates a backend from a verified, fail-closed operating-system sandbox.
    pub fn new(sandbox: SubprocessSandbox) -> Result<Self, ExtensionHostError> {
        Ok(Self {
            sandbox,
            codec: FrameCodec::new(MAX_CANONICAL_INPUT_BYTES)?,
        })
    }
}

impl ExtensionBackend for IsolatedSubprocessBackend {
    fn runtime_kind(&self) -> ExtensionRuntimeKind {
        ExtensionRuntimeKind::IsolatedSubprocess
    }

    fn invoke(
        &self,
        invocation: &ExtensionInvocationV1,
        deadline: Instant,
        cancellation: InvocationCancellation,
        broker: Option<Arc<CapabilityBroker>>,
    ) -> Result<RuntimeResponse, ExtensionHostError> {
        if cancellation.is_cancelled() {
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        let request = self.codec.encode(invocation)?;
        let mut child = self
            .sandbox
            .command()
            .spawn()
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let result = run_child(
            &mut child,
            request,
            self.codec,
            deadline,
            cancellation,
            broker,
            invocation.invocation_id.clone(),
            invocation.effective_limits.max_host_calls,
            cumulative_limit(invocation)?,
            self.sandbox.maximum_memory_bytes,
        );
        if result.is_err() {
            terminate(&mut child);
        }
        result
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum GuestMessage {
    HostCall(GuestHostCallRequest),
    Response(ExtensionResponseV1),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestHostCallRequest {
    pub(crate) invocation_id: RecordId,
    pub(crate) ordinal: u32,
    pub(crate) kind: ExtensionHostCallKind,
    pub(crate) handle: Option<ExtensionHandle>,
    pub(crate) request: Vec<u8>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostCallReply {
    pub(crate) invocation_id: RecordId,
    pub(crate) ordinal: u32,
    pub(crate) error_code: u16,
    pub(crate) response: Vec<u8>,
}

fn verified_snapshot(
    activated: &ActivatedExtension,
    package_root: &Path,
) -> Result<Arc<ExecutableSnapshot>, ExtensionHostError> {
    let package_root = package_root
        .canonicalize()
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    if !package_root.is_dir() {
        return Err(error(ExtensionHostErrorCode::BackendUnavailable));
    }
    let executable = package_root
        .join(activated.manifest().entry_point.as_str())
        .canonicalize()
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    if !executable.starts_with(&package_root) || !executable.is_file() {
        return Err(error(ExtensionHostErrorCode::CapabilityDenied));
    }
    let bytes = fs::read(&executable)
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    if raw_content_digest(&bytes)? != activated.manifest().implementation_digest {
        return Err(error(ExtensionHostErrorCode::DigestMismatch));
    }
    let directory = tempfile::Builder::new()
        .prefix("cigar-extension-")
        .tempdir()
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    let snapshot_path = directory.path().join("extension");
    fs::write(&snapshot_path, &bytes)
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    #[cfg(unix)]
    fs::set_permissions(&snapshot_path, fs::Permissions::from_mode(0o500))
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    let snapshot_path = snapshot_path
        .canonicalize()
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    let snapshot_bytes = fs::read(&snapshot_path)
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    if raw_content_digest(&snapshot_bytes)? != activated.manifest().implementation_digest {
        return Err(error(ExtensionHostErrorCode::DigestMismatch));
    }
    Ok(Arc::new(ExecutableSnapshot {
        directory,
        executable: snapshot_path,
    }))
}

#[cfg(target_os = "macos")]
fn macos_profile(executable: &Path) -> String {
    let executable = sandbox_literal(executable);
    format!(
        concat!(
            "(version 1)",
            "(deny default)",
            "(allow process-exec (literal {}))",
            "(allow process-info*)",
            "(allow sysctl-read)",
            "(allow file-read* (subpath \"/System\") (subpath \"/usr/lib\") ",
            "(literal \"/\") (literal \"/dev/null\") (literal {}))",
            "(allow file-write* (literal \"/dev/null\"))",
        ),
        executable, executable,
    )
}

#[cfg(target_os = "macos")]
fn sandbox_literal(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    let escaped = rendered.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[allow(clippy::too_many_arguments)]
fn run_child(
    child: &mut Child,
    request: Vec<u8>,
    codec: FrameCodec,
    deadline: Instant,
    cancellation: InvocationCancellation,
    broker: Option<Arc<CapabilityBroker>>,
    invocation_id: RecordId,
    maximum_host_calls: u32,
    maximum_cumulative_bytes: usize,
    _maximum_memory_bytes: u64,
) -> Result<RuntimeResponse, ExtensionHostError> {
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| error(ExtensionHostErrorCode::BackendUnavailable))?;

    let (io_tx, io_rx) = mpsc::sync_channel(1);
    let io_thread = thread::spawn(move || {
        let result = run_framed_loop(
            stdin,
            &mut stdout,
            &request,
            codec,
            broker.as_deref(),
            &invocation_id,
            maximum_host_calls,
            maximum_cumulative_bytes,
        );
        let _ignored = io_tx.send(result);
    });
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    let stderr_reader = thread::spawn(move || {
        let result = read_bounded_stderr(&mut stderr);
        let _ignored = stderr_tx.send(result);
    });

    let mut io_result = None;
    let mut stderr_result = None;
    let mut exit_status = None;
    #[cfg(target_os = "macos")]
    let mut memory_monitor = MacOsMemoryMonitor::new(child.id());
    while io_result.is_none() || stderr_result.is_none() || exit_status.is_none() {
        if cancellation.is_cancelled() {
            terminate(child);
            join_threads(io_thread, stderr_reader)?;
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        if Instant::now() >= deadline {
            terminate(child);
            join_threads(io_thread, stderr_reader)?;
            return Err(error(ExtensionHostErrorCode::DeadlineExceeded));
        }
        #[cfg(target_os = "macos")]
        if memory_monitor.exceeds(_maximum_memory_bytes) {
            terminate(child);
            join_threads(io_thread, stderr_reader)?;
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        receive(&io_rx, &mut io_result)?;
        receive(&stderr_rx, &mut stderr_result)?;
        if exit_status.is_none() {
            exit_status = child
                .try_wait()
                .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        }
        thread::sleep(POLL_INTERVAL);
    }
    join_threads(io_thread, stderr_reader)?;
    stderr_result.ok_or_else(|| error(ExtensionHostErrorCode::ExtensionCrashed))??;
    let response = io_result.ok_or_else(|| error(ExtensionHostErrorCode::ExtensionCrashed))??;
    let status = exit_status.ok_or_else(|| error(ExtensionHostErrorCode::ExtensionCrashed))?;
    if status.success() {
        Ok(RuntimeResponse::completed(response))
    } else {
        Ok(RuntimeResponse::crashed_after_response(response))
    }
}

#[cfg(target_os = "macos")]
struct MacOsMemoryMonitor {
    system: System,
    pid: Pid,
}

#[cfg(target_os = "macos")]
impl MacOsMemoryMonitor {
    fn new(pid: u32) -> Self {
        Self {
            system: System::new(),
            pid: Pid::from_u32(pid),
        }
    }

    fn exceeds(&mut self, maximum_memory_bytes: u64) -> bool {
        let pids = [self.pid];
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&pids),
            true,
            ProcessRefreshKind::nothing().with_memory().without_tasks(),
        );
        self.system
            .process(self.pid)
            .is_some_and(|process| process.memory() > maximum_memory_bytes)
    }
}

fn receive<T>(
    receiver: &mpsc::Receiver<T>,
    destination: &mut Option<T>,
) -> Result<(), ExtensionHostError> {
    if destination.is_some() {
        return Ok(());
    }
    match receiver.try_recv() {
        Ok(value) => {
            *destination = Some(value);
            Ok(())
        }
        Err(TryRecvError::Empty) => Ok(()),
        Err(TryRecvError::Disconnected) => Err(error(ExtensionHostErrorCode::ExtensionCrashed)),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_framed_loop(
    mut stdin: impl Write,
    stdout: &mut impl Read,
    invocation_frame: &[u8],
    codec: FrameCodec,
    broker: Option<&CapabilityBroker>,
    invocation_id: &RecordId,
    maximum_host_calls: u32,
    maximum_cumulative_bytes: usize,
) -> Result<ExtensionResponseV1, ExtensionHostError> {
    stdin
        .write_all(invocation_frame)
        .and_then(|()| stdin.flush())
        .map_err(|_error| error(ExtensionHostErrorCode::ExtensionCrashed))?;
    let mut cumulative = invocation_frame.len();
    let mut wire_calls = 0_u32;
    let mut denied_host_call = false;
    loop {
        let message: GuestMessage = codec.read_value(stdout)?;
        match message {
            GuestMessage::Response(response) => {
                if denied_host_call {
                    return Err(error(ExtensionHostErrorCode::CapabilityDenied));
                }
                drop(stdin);
                let mut trailing = [0_u8; 1];
                return match stdout.read(&mut trailing) {
                    Ok(0) => Ok(response),
                    Ok(_) => Err(error(ExtensionHostErrorCode::InvalidFrame)),
                    Err(failure) if failure.kind() == ErrorKind::UnexpectedEof => Ok(response),
                    Err(_failure) => Err(error(ExtensionHostErrorCode::ExtensionCrashed)),
                };
            }
            GuestMessage::HostCall(call) => {
                wire_calls = wire_calls
                    .checked_add(1)
                    .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
                if wire_calls > maximum_host_calls
                    || &call.invocation_id != invocation_id
                    || call.ordinal != wire_calls
                    || !handle_shape_valid(call.kind, call.handle.as_ref())
                {
                    return Err(error(ExtensionHostErrorCode::InvalidFrame));
                }
                cumulative = cumulative
                    .checked_add(call.request.len())
                    .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
                if cumulative > maximum_cumulative_bytes {
                    return Err(error(ExtensionHostErrorCode::ResourceExhausted));
                }
                let result = broker
                    .ok_or_else(|| error(ExtensionHostErrorCode::CapabilityDenied))
                    .and_then(|broker| {
                        broker.dispatch_host_call(call.kind, call.handle.as_ref(), &call.request)
                    });
                let (error_code, response) = match result {
                    Ok(response) => (0, response),
                    Err(failure) => {
                        denied_host_call = true;
                        (wire_error_code(failure.code()), Vec::new())
                    }
                };
                cumulative = cumulative
                    .checked_add(response.len())
                    .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
                if cumulative > maximum_cumulative_bytes {
                    return Err(error(ExtensionHostErrorCode::ResourceExhausted));
                }
                let reply = codec.encode_value(&HostCallReply {
                    invocation_id: invocation_id.clone(),
                    ordinal: call.ordinal,
                    error_code,
                    response,
                })?;
                cumulative = cumulative
                    .checked_add(reply.len())
                    .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
                if cumulative > maximum_cumulative_bytes {
                    return Err(error(ExtensionHostErrorCode::ResourceExhausted));
                }
                stdin
                    .write_all(&reply)
                    .and_then(|()| stdin.flush())
                    .map_err(|_error| error(ExtensionHostErrorCode::ExtensionCrashed))?;
            }
        }
    }
}

pub(crate) fn handle_shape_valid(
    kind: ExtensionHostCallKind,
    handle: Option<&ExtensionHandle>,
) -> bool {
    let required = matches!(
        kind,
        ExtensionHostCallKind::ReadSource
            | ExtensionHostCallKind::ReadBlob
            | ExtensionHostCallKind::IteratorNext
            | ExtensionHostCallKind::NetworkRequest
            | ExtensionHostCallKind::FileRead
            | ExtensionHostCallKind::FileWrite
            | ExtensionHostCallKind::ResolveSecret
    );
    required == handle.is_some()
}

pub(crate) fn wire_error_code(code: ExtensionHostErrorCode) -> u16 {
    match code {
        ExtensionHostErrorCode::InvalidInput => 1,
        ExtensionHostErrorCode::SignatureInvalid => 2,
        ExtensionHostErrorCode::DigestMismatch => 3,
        ExtensionHostErrorCode::IncompatibleVersion => 4,
        ExtensionHostErrorCode::CapabilityDenied => 5,
        ExtensionHostErrorCode::InvalidHandle => 6,
        ExtensionHostErrorCode::InvalidFrame => 7,
        ExtensionHostErrorCode::ResourceExhausted => 8,
        ExtensionHostErrorCode::DeadlineExceeded => 9,
        ExtensionHostErrorCode::Cancelled => 10,
        ExtensionHostErrorCode::ExtensionCrashed => 11,
        ExtensionHostErrorCode::BackendUnavailable => 12,
        ExtensionHostErrorCode::RemoteAuthenticationFailed => 13,
        ExtensionHostErrorCode::InvalidResponse => 14,
    }
}

pub(crate) fn cumulative_limit(
    invocation: &ExtensionInvocationV1,
) -> Result<usize, ExtensionHostError> {
    let per_exchange = invocation
        .effective_limits
        .max_input_bytes
        .checked_add(invocation.effective_limits.max_output_bytes)
        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
    let exchanges = u64::from(invocation.effective_limits.max_host_calls)
        .checked_add(1)
        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
    let maximum = per_exchange
        .checked_mul(exchanges)
        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
    usize::try_from(maximum.min(cigar_canon::MAX_CANONICAL_INPUT_BYTES as u64))
        .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))
}

fn read_bounded_stderr(stderr: &mut impl Read) -> Result<(), ExtensionHostError> {
    let mut bytes = Vec::new();
    let mut limited = stderr.take(u64::try_from(MAX_STDERR_BYTES + 1).unwrap_or(u64::MAX));
    limited
        .read_to_end(&mut bytes)
        .map_err(|_error| error(ExtensionHostErrorCode::ExtensionCrashed))?;
    if bytes.len() > MAX_STDERR_BYTES {
        return Err(error(ExtensionHostErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn terminate(child: &mut Child) {
    let _ignored = child.kill();
    let _ignored = child.wait();
}

fn join_threads(
    io_thread: thread::JoinHandle<()>,
    stderr_reader: thread::JoinHandle<()>,
) -> Result<(), ExtensionHostError> {
    io_thread
        .join()
        .map_err(|_panic| error(ExtensionHostErrorCode::ExtensionCrashed))?;
    stderr_reader
        .join()
        .map_err(|_panic| error(ExtensionHostErrorCode::ExtensionCrashed))?;
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod macos_sandbox_tests {
    use super::macos_profile;
    use std::fs;
    use std::net::TcpListener;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    #[test]
    fn deny_default_profile_blocks_network_files_environment_and_processes()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let package = tempfile::tempdir()?;
        let source = package.path().join("probe.c");
        let executable = package.path().join("probe");
        fs::write(
            &source,
            format!(
                concat!(
                    "#include <arpa/inet.h>\n#include <fcntl.h>\n#include <stdlib.h>\n",
                    "#include <sys/socket.h>\n#include <sys/wait.h>\n#include <unistd.h>\n",
                    "int main(void) {{\n",
                    "  if (open(\"/etc/passwd\", O_RDONLY) >= 0) return 11;\n",
                    "  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);\n",
                    "  if (socket_fd >= 0) {{\n",
                    "    struct sockaddr_in address = {{0}}; address.sin_family = AF_INET;\n",
                    "    address.sin_port = htons({}); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);\n",
                    "    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) == 0) return 12;\n",
                    "  }}\n",
                    "  if (getenv(\"HOME\") != NULL || getenv(\"CIGAR_SECRET_CANARY\") != NULL) return 13;\n",
                    "  pid_t child = fork();\n",
                    "  if (child >= 0) {{\n",
                    "    if (child == 0) _exit(0);\n",
                    "    (void)waitpid(child, NULL, 0); return 14;\n",
                    "  }}\n",
                    "  return 0;\n}}\n"
                ),
                listener.local_addr()?.port()
            ),
        )?;
        let compiler = Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()?;
        if !compiler.success() {
            return Err("failed to compile macOS sandbox probe".into());
        }
        let executable = executable.canonicalize()?;
        let output = Command::new(Path::new("/usr/bin/sandbox-exec"))
            .arg("-p")
            .arg(macos_profile(&executable))
            .arg(&executable)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "sandbox probe failed with status {:?}, signal {:?}, and {} stderr bytes",
                output.status.code(),
                output.status.signal(),
                output.stderr.len()
            )
            .into());
        }
        Ok(())
    }
}
