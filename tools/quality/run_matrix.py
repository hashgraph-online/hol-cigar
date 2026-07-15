#!/usr/bin/env python3
"""Run a versioned CIGAR quality matrix and emit content-free evidence.

The runner never invokes a shell. Test output is reduced to byte counts and
SHA-256 digests so release evidence cannot accidentally serialize protected
repository content. Optional private logs are mode 0600 and must be requested
explicitly; they are unavailable for external release-evidence runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RELEASE_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "release"
if str(RELEASE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(RELEASE_SCRIPTS))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path,
)


SCHEMA_VERSION = "cigar.test-matrix.v1"
RESULT_SCHEMA_VERSION = "cigar.test-matrix-result.v1"
DEFAULT_OUTPUT = Path("reports/test-matrix-result.v1.json")
ALLOWED_PROGRAMS = {"bash", "cargo", "corepack", "go", "python3", "uv"}
FORBIDDEN_ARGUMENTS = {"--ignored", "--include-ignored", "--no-run", "--skip"}
IDENTIFIER = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,95}$")
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,95}$")
SUPPORTED_PLATFORMS = {"linux", "macos", "windows"}
SYNTHETIC_CANARY = "CIGAR_CANARY_V1_4d8a2d4d0ecb46ecb1a3_NEVER_EMIT"


class MatrixError(Exception):
    """A fail-closed matrix validation error."""


@dataclass(frozen=True)
class LoadedMatrix:
    path: Path
    digest: str
    document: dict[str, Any]


@dataclass(frozen=True)
class CommandCapture:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def host_platform() -> str:
    value = sys.platform
    if value.startswith("linux"):
        return "linux"
    if value == "darwin":
        return "macos"
    if value in {"win32", "cygwin"}:
        return "windows"
    raise MatrixError(f"unsupported host platform: {value}")


def source_identity(root: Path) -> dict[str, Any]:
    revision = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    committed = revision.returncode == 0
    revision_text = (
        revision.stdout.decode("ascii", errors="strict").strip() if committed else None
    )
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    clean = status.returncode == 0 and not status.stdout
    return {
        "kind": "git" if committed else "workspace",
        "revision": revision_text,
        "committed": committed,
        "clean": clean,
    }


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise MatrixError(f"{location} must be a non-empty string")
    return value


def require_string_list(value: Any, location: str, *, unique: bool = True) -> list[str]:
    if not isinstance(value, list) or not value:
        raise MatrixError(f"{location} must be a non-empty array")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(require_string(item, f"{location}[{index}]"))
    if unique and len(result) != len(set(result)):
        raise MatrixError(f"{location} contains duplicates")
    return result


def validate_case(case: Any, index: int) -> None:
    location = f"cases[{index}]"
    if not isinstance(case, dict):
        raise MatrixError(f"{location} must be an object")
    allowed = {
        "id",
        "title",
        "command",
        "timeout_seconds",
        "profiles",
        "platforms",
        "requirements",
        "required_environment",
        "isolate_home",
    }
    unknown = sorted(set(case) - allowed)
    if unknown:
        raise MatrixError(f"{location} has unknown fields: {', '.join(unknown)}")
    case_id = require_string(case.get("id"), f"{location}.id")
    if not IDENTIFIER.fullmatch(case_id):
        raise MatrixError(f"{location}.id is not a stable identifier")
    require_string(case.get("title"), f"{location}.title")
    command = require_string_list(
        case.get("command"), f"{location}.command", unique=False
    )
    if command[0] not in ALLOWED_PROGRAMS:
        raise MatrixError(
            f"{location}.command program is not allowlisted: {command[0]}"
        )
    if command[:2] == ["cargo", "test"]:
        raise MatrixError(
            f"{location}.command must use cargo nextest so an empty test selection fails closed"
        )
    if any(argument in FORBIDDEN_ARGUMENTS for argument in command[1:]):
        raise MatrixError(f"{location}.command may not skip or suppress test execution")
    if any("\x00" in argument for argument in command):
        raise MatrixError(f"{location}.command contains NUL")
    timeout = case.get("timeout_seconds")
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 86_400
    ):
        raise MatrixError(f"{location}.timeout_seconds must be in 1..86400")
    profiles = require_string_list(case.get("profiles"), f"{location}.profiles")
    if any(not IDENTIFIER.fullmatch(profile_name) for profile_name in profiles):
        raise MatrixError(f"{location}.profiles contains an invalid profile")
    platforms = require_string_list(case.get("platforms"), f"{location}.platforms")
    invalid_platforms = sorted(set(platforms) - SUPPORTED_PLATFORMS)
    if invalid_platforms:
        raise MatrixError(
            f"{location}.platforms is invalid: {', '.join(invalid_platforms)}"
        )
    requirements = require_string_list(
        case.get("requirements"), f"{location}.requirements"
    )
    if any(not IDENTIFIER.fullmatch(requirement) for requirement in requirements):
        raise MatrixError(f"{location}.requirements contains an invalid identifier")
    required_environment = case.get("required_environment", [])
    if not isinstance(required_environment, list):
        raise MatrixError(f"{location}.required_environment must be an array")
    for env_index, name in enumerate(required_environment):
        name = require_string(name, f"{location}.required_environment[{env_index}]")
        if not ENVIRONMENT_NAME.fullmatch(name):
            raise MatrixError(
                f"{location}.required_environment contains an invalid name"
            )
    if len(required_environment) != len(set(required_environment)):
        raise MatrixError(f"{location}.required_environment contains duplicates")
    if not isinstance(case.get("isolate_home", False), bool):
        raise MatrixError(f"{location}.isolate_home must be a boolean")


def load_matrix(path: Path) -> LoadedMatrix:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"matrix is not strict UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise MatrixError("matrix root must be an object")
    allowed = {"schema_version", "suite", "description", "cases"}
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise MatrixError(f"matrix has unknown fields: {', '.join(unknown)}")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise MatrixError(f"schema_version must equal {SCHEMA_VERSION}")
    suite = require_string(document.get("suite"), "suite")
    if not IDENTIFIER.fullmatch(suite):
        raise MatrixError("suite is not a stable identifier")
    require_string(document.get("description"), "description")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise MatrixError("cases must be a non-empty array")
    for index, case in enumerate(cases):
        validate_case(case, index)
    identifiers = [case["id"] for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise MatrixError("case identifiers must be unique")
    if identifiers != sorted(identifiers):
        raise MatrixError("cases must be sorted by id")
    return LoadedMatrix(path=path, digest=sha256_bytes(raw), document=document)


def sanitized_environment(
    suite: str, profile_name: str, isolated_home: Path | None
) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "CIGAR_TEST_MATRIX": suite,
            "CIGAR_TEST_PROFILE": profile_name,
            "CIGAR_TEST_SECRET_CANARY": SYNTHETIC_CANARY,
            "CARGO_NET_OFFLINE": "true",
            "TZ": "UTC",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
    )
    if isolated_home is not None:
        original_home = Path.home()
        environment.setdefault("CARGO_HOME", str(original_home / ".cargo"))
        environment.setdefault("RUSTUP_HOME", str(original_home / ".rustup"))
        environment["HOME"] = str(isolated_home)
        environment["XDG_CACHE_HOME"] = str(isolated_home / ".cache")
        environment["XDG_CONFIG_HOME"] = str(isolated_home / ".config")
        environment["XDG_DATA_HOME"] = str(isolated_home / ".local" / "share")
    return environment


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_captured_command(
    command: list[str],
    *,
    root: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> CommandCapture:
    """Run one bounded no-shell command while retaining output only in memory."""

    process = subprocess.Popen(
        command,
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_tree(process)
        stdout, stderr = process.communicate()
    return CommandCapture(
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


def capture_summary(capture: CommandCapture) -> str:
    """Describe command output without including any command output bytes."""

    return (
        f"exit_code={capture.exit_code}; "
        f"stdout_bytes={len(capture.stdout)}; stdout_sha256={sha256_bytes(capture.stdout)}; "
        f"stderr_bytes={len(capture.stderr)}; stderr_sha256={sha256_bytes(capture.stderr)}"
    )


def prepare_cargo_cache(root: Path) -> None:
    """Explicitly hydrate locked Cargo inputs outside an offline evidence run."""

    capture = run_captured_command(
        ["cargo", "fetch", "--locked"],
        root=root,
        environment=dict(os.environ),
        timeout_seconds=900,
    )
    if capture.timed_out:
        raise MatrixError("Cargo cache preparation timed out after 900 seconds")
    if capture.exit_code != 0:
        raise MatrixError(
            "Cargo cache preparation failed; output was suppressed ("
            f"{capture_summary(capture)}). Run `cargo fetch --locked` directly for private diagnostics."
        )


def preflight_offline_cargo(root: Path, cases: list[dict[str, Any]]) -> None:
    """Fail once, before evidence execution, when locked Cargo metadata is unavailable offline."""

    if not any(case["command"][0] == "cargo" for case in cases):
        return
    environment = sanitized_environment(
        "quality-preflight", "offline-cargo-metadata", isolated_home=None
    )
    capture = run_captured_command(
        [
            "cargo",
            "metadata",
            "--format-version=1",
            "--all-features",
            "--locked",
            "--offline",
        ],
        root=root,
        environment=environment,
        timeout_seconds=180,
    )
    if capture.timed_out:
        raise MatrixError(
            "offline Cargo metadata preflight timed out after 180 seconds"
        )
    if capture.exit_code != 0:
        raise MatrixError(
            "offline Cargo metadata preflight failed; the locked dependency cache may be incomplete "
            "or Cargo.lock may be inconsistent. No test cases were started and command output was "
            f"suppressed ({capture_summary(capture)}). Run this command once with "
            "`--prepare-cargo-cache`, then retry the matrix."
        )


def write_private_log(log_dir: Path, case_id: str, stream: str, value: bytes) -> None:
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Private logs can contain diagnostics excluded from content-free release receipts.
    os.chmod(log_dir, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    path = log_dir / f"{case_id}.{stream}.log"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def content_free_stream(stream: bytes) -> dict[str, Any]:
    return {"bytes": len(stream), "sha256": sha256_bytes(stream)}


def run_case(
    root: Path,
    suite: str,
    profile_name: str,
    case: dict[str, Any],
    log_dir: Path | None,
    *,
    isolate_evidence_environment: bool = False,
) -> dict[str, Any]:
    command: list[str] = case["command"]
    missing = [
        name
        for name in case.get("required_environment", [])
        if not os.environ.get(name)
    ]
    command_digest = sha256_bytes(
        json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    if missing:
        return {
            "id": case["id"],
            "status": "failed",
            "failure_kind": "missing-required-environment",
            "missing_environment": missing,
            "command_sha256": command_digest,
            "duration_ms": 0,
            "exit_code": None,
            "stdout": content_free_stream(b""),
            "stderr": content_free_stream(b""),
            "canary_scan": "passed",
        }

    temporary_home: tempfile.TemporaryDirectory[str] | None = None
    if case.get("isolate_home", False):
        temporary_home = tempfile.TemporaryDirectory(
            prefix=f"cigar-{suite}-{case['id']}-"
        )
    isolated_home = Path(temporary_home.name) if temporary_home else None
    environment = sanitized_environment(suite, profile_name, isolated_home)
    if isolate_evidence_environment:
        # The runner owns the pinned evidence workspace. Test children receive
        # no ambient pathname they could use to bypass create-new, dirfd-bound
        # publication or to mix protected output into a content-free receipt.
        environment.pop("CIGAR_EVIDENCE_DIR", None)
    started = time.monotonic()
    timed_out = False
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        try:
            stdout, stderr = process.communicate(timeout=case["timeout_seconds"])
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_tree(process)
            stdout, stderr = process.communicate()
        exit_code = process.returncode
    finally:
        if temporary_home is not None:
            temporary_home.cleanup()
    duration_ms = round((time.monotonic() - started) * 1000)
    leaked = (
        SYNTHETIC_CANARY.encode("utf-8") in stdout
        or SYNTHETIC_CANARY.encode("utf-8") in stderr
    )
    if log_dir is not None:
        write_private_log(log_dir, case["id"], "stdout", stdout)
        write_private_log(log_dir, case["id"], "stderr", stderr)
    status = "passed" if exit_code == 0 and not timed_out and not leaked else "failed"
    if timed_out:
        failure_kind: str | None = "timeout"
    elif leaked:
        failure_kind = "canary-leak"
    elif exit_code != 0:
        failure_kind = "nonzero-exit"
    else:
        failure_kind = None
    result: dict[str, Any] = {
        "id": case["id"],
        "status": status,
        "command_sha256": command_digest,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "stdout": content_free_stream(stdout),
        "stderr": content_free_stream(stderr),
        "canary_scan": "failed" if leaked else "passed",
    }
    if failure_kind is not None:
        result["failure_kind"] = failure_kind
    return result


def atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    """Select exactly one external evidence root without resolving path components."""

    argument_value = arguments.evidence_dir
    environment_value = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument_value is not None and environment_value:
        if Path(argument_value) != Path(environment_value):
            raise MatrixError(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide only one location"
            )
    raw = argument_value if argument_value is not None else environment_value
    if raw is None or os.fspath(raw) == "":
        if arguments.profile == "release":
            raise MatrixError(
                "release profile requires --evidence-dir or CIGAR_EVIDENCE_DIR"
            )
        if getattr(arguments, "require_evidence", False):
            raise MatrixError(
                "this execution requires --evidence-dir or CIGAR_EVIDENCE_DIR"
            )
        return None
    selected = Path(raw)
    if not selected.is_absolute():
        raise MatrixError("evidence directory must be an absolute path")
    return selected


def open_evidence_workspace(
    arguments: argparse.Namespace, root: Path
) -> EvidenceWorkspace | None:
    """Open and pin an optional secure workspace before any matrix case runs."""

    selected = selected_evidence_directory(arguments)
    if selected is None:
        return None
    if arguments.log_dir is not None:
        raise MatrixError(
            "--log-dir is unavailable with an evidence workspace; release evidence is content-free"
        )
    output = os.fspath(arguments.output)
    try:
        safe_relative_path(output)
        return EvidenceWorkspace.create(selected, repository_root=root)
    except EvidenceWorkspaceError as error:
        raise MatrixError(f"unsafe evidence workspace: {error}") from error


def write_matrix_result(
    arguments: argparse.Namespace,
    document: dict[str, Any],
    workspace: EvidenceWorkspace | None,
) -> None:
    """Publish one result, using create-new external storage when configured."""

    if workspace is None:
        atomic_write_json(arguments.output.resolve(), document)
        return
    try:
        workspace.write_json(os.fspath(arguments.output), document)
    except EvidenceWorkspaceError as error:
        raise MatrixError(f"cannot publish matrix evidence: {error}") from error


def execute(arguments: argparse.Namespace) -> int:
    root = arguments.root.resolve()
    loaded = load_matrix(arguments.matrix.resolve())
    if arguments.validate_only and arguments.prepare_cargo_cache:
        raise MatrixError(
            "--validate-only and --prepare-cargo-cache are mutually exclusive"
        )
    if arguments.validate_only:
        print(
            f"validated {loaded.document['suite']}: {len(loaded.document['cases'])} cases"
        )
        return 0
    if arguments.prepare_cargo_cache:
        prepare_cargo_cache(root)
        print("prepared locked Cargo dependencies for a separate offline matrix run")
        return 0
    source = source_identity(root)
    if arguments.profile == "release" and (
        source["committed"] is not True or source["clean"] is not True
    ):
        raise MatrixError("release profile requires a clean committed Git candidate")
    selected_ids = set(arguments.case or [])
    known_ids = {case["id"] for case in loaded.document["cases"]}
    unknown_ids = sorted(selected_ids - known_ids)
    if unknown_ids:
        raise MatrixError(f"unknown requested cases: {', '.join(unknown_ids)}")
    current_platform = host_platform()
    runnable_cases = [
        case
        for case in loaded.document["cases"]
        if (not selected_ids or case["id"] in selected_ids)
        and (arguments.profile == "all" or arguments.profile in case["profiles"])
        and current_platform in case["platforms"]
    ]
    if not runnable_cases:
        raise MatrixError("selection contains no runnable cases on this host")
    workspace = open_evidence_workspace(arguments, root)
    try:
        cargo_preflight_cases = [
            case
            for case in runnable_cases
            if all(
                os.environ.get(name) for name in case.get("required_environment", [])
            )
        ]
        preflight_offline_cargo(root, cargo_preflight_cases)
        started_at = utc_now()
        results: list[dict[str, Any]] = []
        for case in runnable_cases:
            print(f"running {case['id']}", flush=True)
            result = run_case(
                root,
                loaded.document["suite"],
                arguments.profile,
                case,
                arguments.log_dir,
                isolate_evidence_environment=getattr(
                    arguments, "isolate_evidence_environment", False
                ),
            )
            results.append(result)
            print(f"{case['id']}: {result['status']}", flush=True)
        passed = sum(result["status"] == "passed" for result in results)
        failed = len(results) - passed
        document = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "suite": loaded.document["suite"],
            "profile": arguments.profile,
            "matrix": {
                "path": str(loaded.path.relative_to(root)),
                "sha256": loaded.digest,
            },
            "source": source,
            "host": {
                "platform": current_platform,
                "architecture": platform.machine().lower(),
                "python": platform.python_version(),
            },
            "started_at": started_at,
            "finished_at": utc_now(),
            "status": "passed" if failed == 0 else "failed",
            "release_eligible": bool(
                arguments.profile == "release"
                and source["committed"] is True
                and source["clean"] is True
                and failed == 0
            ),
            "selected_case_count": len(results),
            "passed_case_count": passed,
            "failed_case_count": failed,
            "cases": results,
        }
        write_matrix_result(arguments, document, workspace)
        return 0 if failed == 0 else 1
    finally:
        if workspace is not None:
            workspace.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--matrix", type=Path, required=True)
    result.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    result.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external output directory (or set CIGAR_EVIDENCE_DIR)",
    )
    result.add_argument(
        "--require-evidence",
        action="store_true",
        help="require secure external evidence even for a non-release profile",
    )
    result.add_argument(
        "--isolate-evidence-environment",
        action="store_true",
        help="withhold CIGAR_EVIDENCE_DIR from matrix child processes",
    )
    result.add_argument("--root", type=Path, default=Path.cwd())
    result.add_argument("--profile", default="local")
    result.add_argument("--case", action="append")
    result.add_argument("--validate-only", action="store_true")
    result.add_argument(
        "--prepare-cargo-cache",
        action="store_true",
        help="hydrate Cargo.lock inputs, emit no evidence, and exit before the offline matrix run",
    )
    result.add_argument("--log-dir", type=Path)
    return result


def main() -> int:
    try:
        return execute(parser().parse_args())
    except (MatrixError, OSError, ValueError) as error:
        print(f"matrix error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
