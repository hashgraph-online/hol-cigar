"""Local platform and worker diagnostics; no service or credential discovery."""

from __future__ import annotations

import hashlib
import json
import platform
import sysconfig
from pathlib import Path
from typing import Literal, TypedDict

from cigar_sdk.native_platforms import NATIVE_PLATFORMS

LOCAL_CONTEXT_PROTOCOL = "cigar.context-worker.v1"
LOCAL_CONTEXT_CORE_VERSION = "0.12.0"

_GUIDANCE = {
    "WorkerUnavailable": (
        "The local worker is missing or cannot execute. Install the wheel for this platform, or supply an absolute "
        "trusted worker_path built from matching 0.12.0 sources. HOL services and API keys are not required."
    ),
    "UnsupportedPlatform": (
        "This runtime has no bundled local worker. Use a supported Python platform, or supply an absolute trusted "
        "worker_path built from matching 0.12.0 sources. HOL services are not required."
    ),
    "WorkerIntegrity": (
        "The bundled worker does not match its versioned manifest. Reinstall the verified wheel; "
        "do not bypass the integrity check."
    ),
    "IncompatibleWorker": (
        "The executable does not implement the matching 0.12.0 worker protocol. "
        "Use the worker shipped with this package or build the matching source."
    ),
}


class LocalContextError(Exception):
    """Stable, content-free error code with actionable local-runtime guidance."""

    def __init__(self, code: str) -> None:
        self.code = code
        suffix = f". {_GUIDANCE[code]}" if code in _GUIDANCE else ""
        super().__init__(f"local context error: {code}{suffix}")


class LocalContextCapabilities(TypedDict):
    package_version: str
    core_version: str
    protocol: str
    runtime: str
    platform: str
    supported_platforms: list[str]
    worker_source: Literal["bundled", "explicit"]
    worker_available: bool
    error_code: str | None
    guidance: str
    requires_hol_services: Literal[False]


def local_platform() -> str:
    """Determine the process ABI without executing programs or contacting services."""
    machine = platform.machine().lower()
    machine = {"aarch64": "arm64", "amd64": "x64", "x86_64": "x64"}.get(machine, machine)
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}.get(platform.system(), "unknown")
    result = f"{system}-{machine}"
    if system != "linux":
        return result
    libc = platform.libc_ver()[0].lower()
    if libc == "glibc":
        return result + "-gnu"
    # musl Python builds identify their ABI in MULTIARCH/HOST_GNU_TYPE even when
    # platform.libc_ver() cannot recognize the executable's static strings.
    abi = " ".join(str(sysconfig.get_config_var(key) or "") for key in ("MULTIARCH", "HOST_GNU_TYPE", "SOABI"))
    return result + ("-musl" if libc == "musl" or "musl" in abi else "-unknown")


def bundled_worker() -> Path:
    identity = local_platform()
    metadata = NATIVE_PLATFORMS.get(identity)
    if metadata is None:
        raise LocalContextError("UnsupportedPlatform")
    directory = Path(__file__).parent / "_native" / identity
    binary = directory / metadata["executable"]
    try:
        manifest = json.loads((directory / "manifest.json").read_bytes())
        valid = (
            isinstance(manifest, dict)
            and manifest.get("protocol") == LOCAL_CONTEXT_PROTOCOL
            and manifest.get("core_version") == LOCAL_CONTEXT_CORE_VERSION
            and manifest.get("target") == metadata["target"]
            and manifest.get("sha256") == _sha256_file(binary)
        )
    except OSError, ValueError, TypeError:
        raise LocalContextError("WorkerUnavailable") from None
    if not valid:
        raise LocalContextError("WorkerIntegrity")
    return binary


def _sha256_file(path: Path) -> str:
    """Reverify every launch using bounded memory, including on short reads."""
    digest = hashlib.sha256()
    buffer = bytearray(1024 * 1024)
    view = memoryview(buffer)
    with path.open("rb") as handle:
        while size := handle.readinto(buffer):
            digest.update(view[:size])
    return digest.hexdigest()


def resolve_local_worker(worker_path: str | Path | None = None) -> Path:
    if worker_path is None:
        return bundled_worker()
    try:
        binary = Path(worker_path)
        if not binary.is_absolute() or not binary.is_file():
            raise ValueError
    except OSError, TypeError, ValueError:
        raise LocalContextError("WorkerUnavailable") from None
    return binary


def get_local_context_capabilities(*, worker_path: str | Path | None = None) -> LocalContextCapabilities:
    """Inspect platform and bytes without spawning; doctor also runs a real compile."""
    failure: LocalContextError | None = None
    try:
        resolve_local_worker(worker_path)
    except LocalContextError as error:
        failure = error
    return {
        "package_version": LOCAL_CONTEXT_CORE_VERSION,
        "core_version": LOCAL_CONTEXT_CORE_VERSION,
        "protocol": LOCAL_CONTEXT_PROTOCOL,
        "runtime": f"python {platform.python_version()}",
        "platform": local_platform(),
        "supported_platforms": list(NATIVE_PLATFORMS),
        "worker_source": "bundled" if worker_path is None else "explicit",
        "worker_available": failure is None,
        "error_code": failure.code if failure else None,
        "guidance": str(failure)
        if failure
        else "Local worker is available. No HOL service, account or API key is required.",
        "requires_hol_services": False,
    }
