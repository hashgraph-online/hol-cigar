#!/usr/bin/env python3
"""Shared, fail-closed release helpers with no network or third-party dependencies."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import tempfile
import threading
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


class ReleaseError(RuntimeError):
    """A release invariant failed."""


_MAX_JSON_BYTES = 64 * 1024 * 1024


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ReleaseError(f"non-finite JSON number is forbidden: {value}")


def _reject_nonfinite_numbers(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ReleaseError("non-finite JSON number is forbidden")
    if isinstance(value, list):
        for item in value:
            _reject_nonfinite_numbers(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite_numbers(item)
    return value


def load_json(path: Path) -> Any:
    try:
        size = path.stat().st_size
        if size < 0 or size > _MAX_JSON_BYTES:
            raise ReleaseError(f"strict JSON exceeds {_MAX_JSON_BYTES} bytes: {path}")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
        return _reject_nonfinite_numbers(value)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"cannot read strict JSON {path}: {error}") from error


def load_json_bytes(payload: bytes, label: str) -> Any:
    try:
        if len(payload) > _MAX_JSON_BYTES:
            raise ReleaseError(f"strict JSON exceeds {_MAX_JSON_BYTES} bytes: {label}")
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
        return _reject_nonfinite_numbers(value)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"cannot read strict JSON {label}: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    try:
        serialized = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise ReleaseError(f"value cannot be encoded as canonical JSON: {error}") from error
    return (serialized + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    write_bytes(path, canonical_json_bytes(value))


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def require_distinct_output(output: Path, inputs: Iterable[Path], label: str) -> None:
    """Prevent a report/generator output from replacing one of the inputs it just qualified."""
    resolved_output = output.resolve()
    for supplied in inputs:
        if resolved_output == supplied.resolve():
            raise ReleaseError(f"{label} output must not replace an input: {supplied}")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def run_bounded(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 300,
    max_stdout: int = 4 * 1024 * 1024,
    max_stderr: int = 4 * 1024 * 1024,
) -> subprocess.CompletedProcess[bytes]:
    """Run without a shell while draining both streams and killing on a byte-limit violation."""
    if not arguments or not all(isinstance(value, str) and value for value in arguments):
        raise ReleaseError("bounded process arguments are invalid")
    if timeout <= 0 or max_stdout < 0 or max_stderr < 0:
        raise ReleaseError("bounded process limits are invalid")
    try:
        creation_flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) if os.name == "nt" else 0
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name != "nt",
            creationflags=creation_flags,
        )
    except OSError as error:
        raise ReleaseError(f"cannot execute {arguments[0]}: {error}") from error
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise ReleaseError("bounded process did not expose output streams")
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    failures: list[str] = []
    kill_lock = threading.Lock()

    def kill_tree() -> None:
        with kill_lock:
            try:
                if os.name == "nt":
                    killer = subprocess.Popen(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        shell=False,
                    )
                    killer.wait(timeout=5)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (OSError, subprocess.SubprocessError):
                try:
                    process.kill()
                except OSError:
                    return

    def drain(stream: Any, destination: bytearray, maximum: int, label: str) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                remaining = maximum + 1 - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(destination) > maximum or len(chunk) > remaining:
                    failures.append(f"{label} exceeded {maximum} bytes")
                    overflow.set()
                    kill_tree()
                    return
        except OSError as error:
            failures.append(f"cannot read {label}: {error}")
            overflow.set()
            kill_tree()
        finally:
            stream.close()

    threads = [
        threading.Thread(target=drain, args=(process.stdout, stdout, max_stdout, "stdout"), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr, max_stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        kill_tree()
        process.wait()
        for thread in threads:
            thread.join(timeout=5)
        raise subprocess.TimeoutExpired(arguments, timeout, bytes(stdout), bytes(stderr)) from error
    for thread in threads:
        thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        kill_tree()
        for thread in threads:
            thread.join(timeout=5)
        raise ReleaseError("bounded process output readers did not terminate")
    if overflow.is_set():
        raise ReleaseError(f"bounded process output limit exceeded: {'; '.join(failures)}")
    return subprocess.CompletedProcess(arguments, returncode, bytes(stdout), bytes(stderr))


def process_failure_summary(result: subprocess.CompletedProcess[bytes], label: str) -> str:
    """Describe a failed child without copying potentially sensitive child output into release logs."""
    stdout = result.stdout or b""
    stderr = result.stderr or b""
    return (
        f"{label} exited {result.returncode}; "
        f"stdout_bytes={len(stdout)} stdout_sha256={sha256_bytes(stdout)}; "
        f"stderr_bytes={len(stderr)} stderr_sha256={sha256_bytes(stderr)}"
    )


def safe_relative_path(value: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 4096
        or "\\" in value
        or ":" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 0x7F for character in value)
    ):
        raise ReleaseError(f"unsafe path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseError(f"unsafe path: {value!r}")
    windows_reserved = {
        "con", "prn", "aux", "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
    if any(
        len(part.encode("utf-8")) > 255
        or part.endswith((" ", "."))
        or part.split(".", 1)[0].casefold() in windows_reserved
        for part in path.parts
    ):
        raise ReleaseError(f"path is not portable to supported platforms: {value!r}")
    normalized = path.as_posix()
    if normalized != value:
        raise ReleaseError(f"non-canonical path: {value!r}")
    return normalized


_REQUIRED_RELEASE_EVIDENCE_CATEGORIES = frozenset({
    "test", "traceability", "toolchain", "work-packet", "coverage", "mutation", "fuzz",
    "sanitizer", "model", "chaos", "migration", "scale", "soak", "conformance", "benchmark",
    "package", "install", "uninstall", "offline", "upgrade", "license", "sbom-spdx",
    "sbom-cyclonedx", "signature", "provenance", "reproducibility", "docs", "demo",
    "operations", "security",
})
_REQUIRED_SIGNED_BASENAMES = frozenset({
    "SHA256SUMS", "release-evidence.json", "sbom.spdx.json", "sbom.cyclonedx.json",
    "sbom-artifacts.json", "provenance.json",
})
_PROHIBITED_RELEASE_STATUSES = frozenset({"failed", "skipped", "waived", "quarantined", "unknown"})
_RELEASE_REQUIREMENTS_V1_SHA256 = "5452202ea3c258d2ebb551ba0352433bcf820cac625c9cf95b9451608338739f"
_QUALIFICATION_CATEGORY_MAP_V1_SHA256 = "23b8f288415d5a5c1be5da67a78e94812114f9fb2a6037f34f271e6988a82f32"


def validate_qualification_policy(mapping: Any) -> None:
    """Reject an altered v1 artifact-to-evidence map before assembly or offline verification."""
    if (
        not isinstance(mapping, dict)
        or set(mapping) != {
            "schema_version", "qualifications", "universal_requirements", "additional_requirements",
        }
        or mapping.get("schema_version") != "cigar.qualification-category-map.v1"
    ):
        raise ReleaseError("qualification category map has an unexpected shape")
    if sha256_bytes(canonical_json_bytes(mapping)) != _QUALIFICATION_CATEGORY_MAP_V1_SHA256:
        raise ReleaseError("qualification category map v1 differs from the verifier's pinned policy digest")


def validate_release_policy_documents(matrix: Any, requirements: Any, gaps: Any) -> None:
    """Reject malformed or weakened v1 release policy before it can become a verification bypass."""
    if not isinstance(matrix, dict) or matrix.get("schema_version") != "cigar.artifact-matrix.v1":
        raise ReleaseError("unsupported artifact matrix")
    if matrix.get("release_state") not in {"development", "release"}:
        raise ReleaseError("artifact matrix release state is invalid")
    if not isinstance(matrix.get("product_version"), str) or re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", matrix["product_version"]) is None:
        raise ReleaseError("artifact matrix product version is invalid")
    if matrix.get("context_abi") != "cigar.context.v1":
        raise ReleaseError("artifact matrix Context ABI is invalid")
    artifacts = matrix.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseError("artifact matrix has no artifacts")
    identifiers: set[str] = set()
    filenames: set[str] = set()
    portable_filenames: set[str] = set()
    required_artifact_keys = {"id", "kind", "filename", "contract", "required_for_release", "qualification"}
    allowed_artifact_keys = required_artifact_keys | {"producer", "platform", "ecosystem"}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not required_artifact_keys.issubset(artifact) or not set(artifact).issubset(allowed_artifact_keys):
            raise ReleaseError("artifact matrix entry has an unexpected shape")
        identifier = artifact.get("id")
        filename = artifact.get("filename")
        contract = artifact.get("contract")
        qualifications = artifact.get("qualification")
        if not isinstance(identifier, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", identifier) is None or identifier in identifiers:
            raise ReleaseError("artifact matrix has an invalid or duplicate artifact id")
        if (
            not isinstance(filename, str)
            or PurePosixPath(filename).name != filename
            or filename in filenames
            or filename.casefold() in portable_filenames
        ):
            raise ReleaseError("artifact matrix has an invalid or duplicate filename")
        safe_relative_path(filename)
        if not isinstance(contract, str) or not contract.startswith("contracts/"):
            raise ReleaseError(f"artifact matrix contract path is invalid: {identifier}")
        safe_relative_path(contract)
        if not isinstance(artifact.get("kind"), str) or not artifact["kind"] or not isinstance(artifact.get("required_for_release"), bool):
            raise ReleaseError(f"artifact matrix fields are invalid: {identifier}")
        if not isinstance(qualifications, list) or not qualifications or not all(isinstance(value, str) and value for value in qualifications) or len(set(qualifications)) != len(qualifications):
            raise ReleaseError(f"artifact matrix qualifications are invalid: {identifier}")
        identifiers.add(identifier)
        filenames.add(filename)
        portable_filenames.add(filename.casefold())
    if not any(artifact["required_for_release"] is True for artifact in artifacts):
        raise ReleaseError("artifact matrix has no release-required artifact")

    required_requirement_keys = {
        "schema_version", "required_evidence_categories", "required_artifact_ids_from",
        "qualification_category_map", "required_source_state", "required_signed_basenames",
        "required_signed_evidence_categories", "prohibited_statuses", "metric_gates",
    }
    if not isinstance(requirements, dict) or set(requirements) != required_requirement_keys or requirements.get("schema_version") != "cigar.release-requirements.v1":
        raise ReleaseError("release requirements have an unexpected shape")
    if sha256_bytes(canonical_json_bytes(requirements)) != _RELEASE_REQUIREMENTS_V1_SHA256:
        raise ReleaseError("release requirements v1 differ from the verifier's pinned policy digest")
    categories = requirements.get("required_evidence_categories")
    if not isinstance(categories, list) or len(categories) != len(set(categories)) or set(categories) != _REQUIRED_RELEASE_EVIDENCE_CATEGORIES:
        raise ReleaseError("release evidence category policy is missing or weakened")
    if requirements.get("required_artifact_ids_from") != "packaging/artifact-matrix.v1.json":
        raise ReleaseError("release artifact source policy is invalid")
    safe_relative_path(requirements.get("qualification_category_map", ""))
    if requirements.get("required_source_state") != {"committed": True, "clean": True, "tagged": False}:
        raise ReleaseError("release source-state policy is invalid")
    signed_basenames = requirements.get("required_signed_basenames")
    if not isinstance(signed_basenames, list) or len(signed_basenames) != len(set(signed_basenames)) or not _REQUIRED_SIGNED_BASENAMES.issubset(signed_basenames):
        raise ReleaseError("release signature payload policy is missing or weakened")
    signed_categories = requirements.get("required_signed_evidence_categories")
    if not isinstance(signed_categories, list) or len(signed_categories) != len(set(signed_categories)) or not {"conformance", "benchmark"}.issubset(signed_categories):
        raise ReleaseError("direct evidence signature policy is missing or weakened")
    prohibited = requirements.get("prohibited_statuses")
    if not isinstance(prohibited, list) or set(prohibited) != _PROHIBITED_RELEASE_STATUSES or len(prohibited) != len(_PROHIBITED_RELEASE_STATUSES):
        raise ReleaseError("prohibited release status policy is missing or weakened")
    if not isinstance(requirements.get("metric_gates"), list) or not requirements["metric_gates"]:
        raise ReleaseError("release metric policy is empty")

    if not isinstance(gaps, dict) or gaps.get("schema_version") != "cigar.qualification-gaps.v1" or not isinstance(gaps.get("gaps"), list):
        raise ReleaseError("qualification gap inventory is invalid")
    gap_ids: set[str] = set()
    for gap in gaps["gaps"]:
        if not isinstance(gap, dict) or set(gap) != {"id", "release_blocking", "owner", "condition", "closure"}:
            raise ReleaseError("qualification gap has an unexpected shape")
        identifier = gap.get("id")
        if not isinstance(identifier, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]*", identifier) is None or identifier in gap_ids:
            raise ReleaseError("qualification gap has an invalid or duplicate id")
        if not isinstance(gap.get("release_blocking"), bool) or not all(isinstance(gap.get(field), str) and gap[field] for field in ("owner", "condition", "closure")):
            raise ReleaseError(f"qualification gap fields are invalid: {identifier}")
        gap_ids.add(identifier)


def resolve_beneath(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    relative = safe_relative_path(relative)
    root = root.resolve()
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as error:
        raise ReleaseError(f"cannot resolve {relative}: {error}") from error
    if resolved != root and root not in resolved.parents:
        raise ReleaseError(f"path escapes root: {relative}")
    return resolved


def matches(path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        candidate = pattern
        while True:
            if fnmatch.fnmatchcase(path, candidate):
                return True
            if not candidate.startswith("**/"):
                break
            candidate = candidate.removeprefix("**/")
    return False


_PRUNE_NAMES = {
    ".git", ".idea", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tmp", ".venv", ".vscode",
    "__pycache__", "node_modules", "target"
}


def expand_files(root: Path, includes: list[str], excludes: list[str]) -> list[tuple[str, Path]]:
    """Expand allowlisted files without traversing common build/VCS trees."""
    found: list[tuple[str, Path]] = []
    root = root.resolve()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(root).as_posix()
        kept_directories: list[str] = []
        for directory in sorted(directories):
            candidate = directory if relative_dir == "." else f"{relative_dir}/{directory}"
            if directory in _PRUNE_NAMES or matches(candidate, excludes) or matches(f"{candidate}/x", excludes):
                continue
            path = current_path / directory
            if path.is_symlink():
                if matches(f"{candidate}/x", includes):
                    raise ReleaseError(f"included directory is a symlink: {candidate}")
                continue
            kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in sorted(files):
            path = current_path / filename
            relative = path.relative_to(root).as_posix()
            safe_relative_path(relative)
            if not matches(relative, includes) or matches(relative, excludes):
                continue
            if path.is_symlink():
                raise ReleaseError(f"included file is a symlink: {relative}")
            if not path.is_file():
                raise ReleaseError(f"included path is not a regular file: {relative}")
            found.append((relative, path))
    found.sort(key=lambda item: item[0].encode("utf-8"))
    if len({relative for relative, _ in found}) != len(found):
        raise ReleaseError("duplicate expanded path")
    return found


def normalized_mode(relative: str) -> int:
    executable_suffixes = (".sh", ".bash", ".zsh", ".fish", ".ps1")
    if relative.startswith("scripts/") or relative.endswith(executable_suffixes):
        return 0o755
    return 0o644


def tree_digest(files: Iterable[tuple[str, Path]]) -> str:
    digest = hashlib.sha256()
    for relative, path in files:
        stat = path.stat()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b"\x00")
        digest.update(f"{normalized_mode(relative):04o}".encode("ascii"))
        digest.update(b"\x00")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\n")
    return digest.hexdigest()


def git_state(root: Path, fallback_tree_digest: str) -> dict[str, Any]:
    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        raw = run_bounded(
            ["git", *arguments], cwd=root, timeout=60,
            max_stdout=32 * 1024 * 1024, max_stderr=1024 * 1024,
        )
        return subprocess.CompletedProcess(
            raw.args,
            raw.returncode,
            raw.stdout.decode("utf-8", errors="replace"),
            raw.stderr.decode("utf-8", errors="replace"),
        )

    revision_result = run("rev-parse", "--verify", "HEAD")
    committed = revision_result.returncode == 0
    revision = revision_result.stdout.strip() if committed else f"unborn:{fallback_tree_digest}"
    status = run("status", "--porcelain=v1", "--untracked-files=all")
    clean = status.returncode == 0 and not status.stdout.strip()
    return {
        "revision": revision,
        "tree_sha256": fallback_tree_digest,
        "committed": committed,
        "clean": clean,
    }


def require_source_date_epoch(value: str | None) -> int:
    raw = value if value is not None else os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        raise ReleaseError("SOURCE_DATE_EPOCH is required")
    try:
        epoch = int(raw, 10)
    except ValueError as error:
        raise ReleaseError("SOURCE_DATE_EPOCH must be a base-10 integer") from error
    if epoch < 0 or epoch > 4_294_967_295:
        raise ReleaseError("SOURCE_DATE_EPOCH is outside the portable archive range")
    return epoch


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key", re.compile(br"-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(br"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(br"gh[pousr]_[A-Za-z0-9]{20,255}")),
    ("slack-token", re.compile(br"xox[baprs]-[A-Za-z0-9-]{20,255}")),
)
_DEVELOPER_PATH_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("macos-developer-path", re.compile(br"/Users/[A-Za-z0-9._-]{1,255}/")),
    ("linux-developer-path", re.compile(br"/home/[A-Za-z0-9._-]{1,255}/")),
    ("windows-developer-path", re.compile(br"[A-Za-z]:\\Users\\[A-Za-z0-9._ -]{1,255}\\")),
)


def scan_payload(relative: str, payload: bytes, exemptions: list[dict[str, str]]) -> list[str]:
    if any(matches(relative, [entry["pattern"]]) for entry in exemptions):
        return []
    findings: list[str] = []
    for name, pattern in (*_SECRET_PATTERNS, *_DEVELOPER_PATH_PATTERNS):
        match = pattern.search(payload)
        if match is None:
            continue
        if name == "aws-access-key" and match.group(0) == b"AKIAIOSFODNN7EXAMPLE":
            continue
        findings.append(name)
    return findings


def file_reference(path: Path, relative_to: Path) -> dict[str, Any]:
    relative = path.resolve().relative_to(relative_to.resolve()).as_posix()
    safe_relative_path(relative)
    return {"path": relative, "sha256": sha256_file(path), "bytes": path.stat().st_size}
