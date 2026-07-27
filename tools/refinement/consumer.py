"""Strict candidate/champion launcher for CIGARBench v2 consumers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, BinaryIO, Sequence

from .canonical import (
    canonical_bytes,
    identity,
    load_file,
    loads,
    multihash_bytes,
    secure_read,
)
from .commands import sanitized_environment
from .schema import SchemaRegistry

MAX_ASSIGNMENT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 256 * 1024
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 3600
REQUIRED_TOOLS = (
    "discoverSources",
    "ingestCatalog",
    "createContextPlan",
    "compileContextBundle",
    "getContextBundleManifest",
    "explainContextBundle",
    "materializeContextBundle",
)
REQUIRED_PHASES = (
    "fixture",
    "setup",
    "ingest",
    "index",
    "plan",
    "compile",
    "explain",
    "materialize",
    "optional_flows",
)
REQUIRED_ARTIFACTS = (
    "plan",
    "bundle",
    "manifest",
    "explanation",
    "materialization",
)
PAIR_INVARIANT_FIELDS = (
    "schema_version",
    "run_id",
    "pair_id",
    "task_id",
    "consumer_mode",
    "archive_path",
    "archive_digest",
    "query",
    "job_goal",
    "semantic_type",
    "token_budget",
    "output_reserve_tokens",
    "max_context_tokens",
    "excluded_prefixes",
    "flows",
    "model",
    "prompt_digest",
)
MEDIA_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".json": "application/json",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".toml": "application/toml",
    ".xml": "application/xml",
    ".proto": "text/x-protobuf",
    ".rs": "text/x-rust",
    ".ts": "text/typescript",
    ".tsx": "text/typescript",
    ".js": "text/javascript",
    ".jsx": "text/javascript",
    ".py": "text/x-python",
    ".go": "text/x-go",
    ".java": "text/x-java",
    ".c": "text/x-c",
    ".h": "text/x-c",
    ".cc": "text/x-c++",
    ".cpp": "text/x-c++",
    ".cxx": "text/x-c++",
    ".hh": "text/x-c++",
    ".hpp": "text/x-c++",
    ".hxx": "text/x-c++",
}


class ConsumerError(RuntimeError):
    """A consumer assignment, process, or observation failed closed."""


def _real_input(path: Path, kind: str) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ConsumerError(f"{kind} must be an absolute non-symlink path")
    try:
        if path.resolve(strict=True) != path:
            raise ConsumerError(f"{kind} must not contain path aliases")
    except OSError as error:
        raise ConsumerError(f"{kind} is unavailable") from error


def _executable(path: Path) -> tuple[Path, str]:
    _real_input(path, "consumer executable")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ConsumerError("consumer executable is unavailable") from error
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(path, os.X_OK)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 1 <= metadata.st_size <= MAX_EXECUTABLE_BYTES
    ):
        raise ConsumerError("consumer executable metadata is unsafe")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").digest()
    return path, "1220" + digest.hex()


def _validate_archive(
    assignment: dict[str, Any], registry: SchemaRegistry
) -> None:
    archive = Path(assignment["archive_path"])
    _real_input(archive, "fixture archive")
    try:
        payload = secure_read(archive, maximum_bytes=MAX_ARCHIVE_BYTES)
        value = loads(payload, maximum_bytes=MAX_ARCHIVE_BYTES)
        registry.validate("fixture-archive-v1.schema.json", value)
    except (OSError, ValueError) as error:
        raise ConsumerError("fixture archive violates its contract") from error
    if (
        canonical_bytes(value) != payload
        or multihash_bytes(payload) != assignment["archive_digest"]
    ):
        raise ConsumerError("fixture archive canonical digest binding is invalid")
    paths = [entry["path"] for entry in value["files"]]
    if paths != sorted(set(paths)):
        raise ConsumerError("fixture archive paths are not sorted and unique")
    total = 0
    for entry in value["files"]:
        expected_media_type = MEDIA_TYPES.get(Path(entry["path"]).suffix)
        if expected_media_type != entry["media_type"]:
            raise ConsumerError("fixture archive path/media binding is invalid")
        encoded = entry["bytes_base64url"]
        try:
            decoded = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (TypeError, ValueError) as error:
            raise ConsumerError("fixture archive content is not strict base64url") from error
        if "=" in encoded or not 1 <= len(decoded) <= MAX_ARCHIVE_FILE_BYTES:
            raise ConsumerError("fixture archive file exceeds its bound")
        total += len(decoded)
        if total > MAX_ARCHIVE_BYTES:
            raise ConsumerError("fixture archive content exceeds its aggregate bound")


def _validate_assignment_semantics(
    value: dict[str, Any], registry: SchemaRegistry
) -> None:
    if (
        value["max_context_tokens"]
        < value["token_budget"] + value["output_reserve_tokens"]
        or any(
            not text
            or any(ord(character) < 32 or ord(character) == 127 for character in text)
            for text in (value["query"], value["job_goal"])
        )
        or value["excluded_prefixes"] != sorted(set(value["excluded_prefixes"]))
    ):
        raise ConsumerError("assignment semantic constraints are invalid")
    _validate_archive(value, registry)


def load_assignment(
    path: Path, registry: SchemaRegistry
) -> tuple[dict[str, Any], bytes]:
    _real_input(path, "assignment")
    try:
        payload = secure_read(path, maximum_bytes=MAX_ASSIGNMENT_BYTES)
        value = load_file(path, maximum_bytes=MAX_ASSIGNMENT_BYTES)
    except (OSError, ValueError) as error:
        raise ConsumerError("assignment is not bounded strict JSON") from error
    if canonical_bytes(value) != payload:
        raise ConsumerError("assignment is not canonical JSON")
    try:
        registry.validate("assignment-v2.schema.json", value)
    except ValueError as error:
        raise ConsumerError("assignment does not satisfy the v2 contract") from error
    if not isinstance(value, dict):
        raise ConsumerError("assignment root is not an object")
    _validate_assignment_semantics(value, registry)
    return value, payload


def _validate_pair(
    champion: dict[str, Any], candidate: dict[str, Any]
) -> None:
    if champion["treatment"] != "champion":
        raise ConsumerError("champion assignment has the wrong treatment")
    if candidate["treatment"] != "candidate":
        raise ConsumerError("candidate assignment has the wrong treatment")
    for field in PAIR_INVARIANT_FIELDS:
        if champion[field] != candidate[field]:
            raise ConsumerError("paired assignments differ outside treatment/source")


def _kill_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        if process.poll() is None:
            process.kill()
            return True
        return False


def _read_bounded(
    stream: BinaryIO,
    destination: bytearray,
    limit: int,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            permitted = max(0, limit - len(destination))
            destination.extend(chunk[:permitted])
            if len(chunk) > permitted:
                overflow.set()
                _kill_group(process)
                return
    except OSError:
        overflow.set()
        _kill_group(process)
    finally:
        stream.close()


def _write_stdin(
    stream: BinaryIO,
    payload: bytes,
    failed: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        stream.write(payload)
        stream.flush()
    except (BrokenPipeError, OSError):
        failed.set()
        _kill_group(process)
    finally:
        stream.close()


def _run_process(
    executable: Path,
    assignment_bytes: bytes,
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> tuple[bytes, bytes]:
    try:
        process = subprocess.Popen(
            [str(executable)],
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ConsumerError("consumer process could not be started") from error
    assert (
        process.stdin is not None
        and process.stdout is not None
        and process.stderr is not None
    )
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    write_failed = threading.Event()
    threads = (
        threading.Thread(
            target=_write_stdin,
            args=(process.stdin, assignment_bytes, write_failed, process),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(
                process.stdout,
                stdout,
                MAX_STDOUT_BYTES,
                overflow,
                process,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(
                process.stderr,
                stderr,
                MAX_STDERR_BYTES,
                overflow,
                process,
            ),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise ConsumerError("consumer process group did not terminate") from error
    descendant_cleanup_required = False
    if not timed_out:
        descendant_cleanup_required = _kill_group(process)
    for thread in threads:
        thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        _kill_group(process)
        raise ConsumerError("consumer process streams did not terminate")
    if timed_out:
        raise ConsumerError("consumer process exceeded its time bound")
    if descendant_cleanup_required:
        raise ConsumerError("consumer process left a descendant")
    if overflow.is_set():
        raise ConsumerError("consumer process exceeded its output bound")
    if write_failed.is_set():
        raise ConsumerError("consumer process rejected its assignment stream")
    if process.returncode != 0:
        raise ConsumerError("consumer process failed")
    if stderr:
        raise ConsumerError("successful consumer emitted stderr")
    return bytes(stdout), bytes(stderr)


def _decode_artifacts(observation: dict[str, Any]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for artifact in observation["artifacts"]:
        kind = artifact["kind"]
        if kind in decoded:
            raise ConsumerError("observation has duplicate artifact kinds")
        encoded = artifact["retained_base64url"]
        padding = "=" * (-len(encoded) % 4)
        try:
            retained = base64.b64decode(
                encoded + padding,
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, TypeError) as error:
            raise ConsumerError("observation artifact is not strict base64url") from error
        if (
            "=" in encoded
            or len(retained) != artifact["bytes"]
            or multihash_bytes(retained) != artifact["digest"]
        ):
            raise ConsumerError("observation artifact binding is invalid")
        try:
            value = loads(retained)
        except ValueError as error:
            raise ConsumerError("observation artifact is not JSON") from error
        if canonical_bytes(value) != retained:
            raise ConsumerError("observation artifact is not canonical JSON")
        decoded[kind] = value
    return decoded


def _validate_reproduction(
    observation: dict[str, Any],
    decoded: dict[str, Any],
) -> None:
    if not set(REQUIRED_ARTIFACTS).issubset(decoded):
        raise ConsumerError("observation lacks a core reproduction artifact")
    plan = decoded["plan"]
    bundle = decoded["bundle"]
    manifest = decoded["manifest"]
    explanation = decoded["explanation"]
    materialization = decoded["materialization"]
    if (
        plan.get("contract_digest") != bundle.get("contract_digest")
        or bundle.get("contract_digest") != manifest.get("contract_digest")
        or bundle.get("manifest_digest") != manifest.get("manifest_id")
        or materialization.get("bundle_id") != bundle.get("bundle_id")
        or materialization.get("content_digest") != observation["output_digest"]
        or materialization.get("physical_input_tokens")
        != observation["resources"]["physical_input_tokens"]
        or materialization.get("tokenizer_fingerprint")
        != observation["pins"]["tokenizer"]
        or materialization.get("materializer_fingerprint")
        != observation["pins"]["materializer"]
    ):
        raise ConsumerError("observation reproduction bindings disagree")
    manifest_versions = [entry.get("version_id") for entry in manifest.get("entries", [])]
    explained_versions = [
        entry.get("version_id") for entry in explanation.get("entries", [])
    ]
    if (
        manifest_versions != sorted(set(manifest_versions))
        or explained_versions != manifest_versions
    ):
        raise ConsumerError("observation explanation does not reproduce its manifest")
    blocks = bundle.get("blocks", [])
    selected = observation["selected_blocks"]
    if len(blocks) != len(selected):
        raise ConsumerError("observation selected blocks do not reproduce its bundle")
    for rank, (block, raw) in enumerate(zip(blocks, selected, strict=True), 1):
        if (
            raw["rank"] != rank
            or raw["block_id"] != block.get("block_id")
            or raw["lane"] != block.get("lane")
            or raw["representation"] != block.get("representation")
            or raw["provenance_ids"] != block.get("provenance")
            or raw["tokens"] != block.get("token_count")
        ):
            raise ConsumerError("observation selected block binding disagrees")


def validate_observation(
    stdout: bytes,
    *,
    assignment: dict[str, Any],
    assignment_bytes: bytes,
    executable_digest: str,
    registry: SchemaRegistry,
) -> dict[str, Any]:
    if not stdout.endswith(b"\n") or stdout.endswith(b"\n\n"):
        raise ConsumerError("consumer stdout is not one newline-terminated record")
    record = stdout[:-1]
    if b"\n" in record or not record:
        raise ConsumerError("consumer stdout contains more than one record")
    try:
        value = loads(record)
    except ValueError as error:
        raise ConsumerError("consumer stdout is not strict JSON") from error
    if not isinstance(value, dict) or canonical_bytes(value) != record:
        raise ConsumerError("consumer observation is not canonical JSON")
    try:
        registry.validate("observation-v2.schema.json", value)
    except ValueError as error:
        raise ConsumerError("consumer observation violates its schema") from error
    body = dict(value)
    observation_id = body.pop("observation_id")
    if identity(body) != observation_id:
        raise ConsumerError("consumer observation identity is invalid")
    expected = {
        "run_id": assignment["run_id"],
        "pair_id": assignment["pair_id"],
        "task_id": assignment["task_id"],
        "treatment": assignment["treatment"],
        "consumer_mode": assignment["consumer_mode"],
        "source": assignment["source"],
        "assignment_digest": multihash_bytes(assignment_bytes),
        "archive_digest": assignment["archive_digest"],
        "input_digest": multihash_bytes(assignment_bytes),
    }
    if any(value[field] != expected_value for field, expected_value in expected.items()):
        raise ConsumerError("consumer observation does not match its assignment")
    if (
        value["pins"]["consumer"] != executable_digest
        or value["pins"]["model"] != assignment["model"]
        or value["pins"]["prompt"] != assignment["prompt_digest"]
        or value["status"] != "completed"
    ):
        raise ConsumerError("consumer observation pins or status are invalid")
    if tuple(item["tool"] for item in value["tool_observations"]) != REQUIRED_TOOLS:
        raise ConsumerError("consumer observation has an incomplete production call trace")
    if tuple(item["phase"] for item in value["phases"]) != REQUIRED_PHASES:
        raise ConsumerError("consumer observation has an incomplete phase trace")
    if value["consumer_mode"] == "recorded" and (
        any(item["duration_ms"] != 0 for item in value["phases"])
        or value["resources"]["latency_ms"] != 0
    ):
        raise ConsumerError("recorded observation contains nondeterministic timing")
    decoded = _decode_artifacts(value)
    expected_artifacts = set(REQUIRED_ARTIFACTS)
    expected_artifacts.update(
        name
        for name, enabled in assignment["flows"].items()
        if enabled
    )
    if set(decoded) != expected_artifacts:
        raise ConsumerError("consumer observation artifact set disagrees with assignment")
    _validate_reproduction(value, decoded)
    return value


def _order_key(champion: dict[str, Any]) -> bool:
    identity_fields = {
        "run_id": champion["run_id"],
        "pair_id": champion["pair_id"],
        "task_id": champion["task_id"],
    }
    return hashlib.sha256(canonical_bytes(identity_fields)).digest()[0] & 1 == 1


def run_pair(
    *,
    champion_assignment_path: Path,
    candidate_assignment_path: Path,
    champion_executable_path: Path,
    candidate_executable_path: Path,
    cwd: Path,
    state: Path,
    schemas: Path,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise ConsumerError("consumer timeout is outside its bound")
    if not cwd.is_absolute() or cwd.is_symlink() or cwd.resolve(strict=True) != cwd:
        raise ConsumerError("consumer cwd must be an absolute real directory")
    registry = SchemaRegistry(schemas)
    champion, champion_bytes = load_assignment(champion_assignment_path, registry)
    candidate, candidate_bytes = load_assignment(candidate_assignment_path, registry)
    _validate_pair(champion, candidate)
    champion_executable, champion_digest = _executable(champion_executable_path)
    candidate_executable, candidate_digest = _executable(candidate_executable_path)
    environment = sanitized_environment(state)
    treatments: dict[
        str, tuple[dict[str, Any], bytes, Path, str]
    ] = {
        "champion": (
            champion,
            champion_bytes,
            champion_executable,
            champion_digest,
        ),
        "candidate": (
            candidate,
            candidate_bytes,
            candidate_executable,
            candidate_digest,
        ),
    }
    order = (
        ("candidate", "champion")
        if _order_key(champion)
        else ("champion", "candidate")
    )
    observations: dict[str, dict[str, Any]] = {}
    for treatment in order:
        assignment, assignment_bytes, executable, executable_digest = treatments[
            treatment
        ]
        stdout, _stderr = _run_process(
            executable,
            assignment_bytes,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        observations[treatment] = validate_observation(
            stdout,
            assignment=assignment,
            assignment_bytes=assignment_bytes,
            executable_digest=executable_digest,
            registry=registry,
        )
    result: dict[str, Any] = {
        "schema_version": "cigar.benchmark-pair.v1",
        "pair_result_id": "",
        "run_id": champion["run_id"],
        "pair_id": champion["pair_id"],
        "task_id": champion["task_id"],
        "order": list(order),
        "assignment_digests": {
            "champion": multihash_bytes(champion_bytes),
            "candidate": multihash_bytes(candidate_bytes),
        },
        "consumer_digests": {
            "champion": champion_digest,
            "candidate": candidate_digest,
        },
        "observation_ids": {
            treatment: observations[treatment]["observation_id"]
            for treatment in ("champion", "candidate")
        },
        "observations": [
            observations[treatment] for treatment in ("champion", "candidate")
        ],
    }
    unsigned = dict(result)
    unsigned.pop("pair_result_id")
    result["pair_result_id"] = identity(unsigned)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one bounded CIGARBench v2 champion/candidate pair."
    )
    parser.add_argument("--champion-assignment", required=True, type=Path)
    parser.add_argument("--candidate-assignment", required=True, type=Path)
    parser.add_argument("--champion-consumer", required=True, type=Path)
    parser.add_argument("--candidate-consumer", required=True, type=Path)
    parser.add_argument("--cwd", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--schemas", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = run_pair(
            champion_assignment_path=arguments.champion_assignment,
            candidate_assignment_path=arguments.candidate_assignment,
            champion_executable_path=arguments.champion_consumer,
            candidate_executable_path=arguments.candidate_consumer,
            cwd=arguments.cwd,
            state=arguments.state,
            schemas=arguments.schemas,
            timeout_seconds=arguments.timeout_seconds,
        )
    except (ConsumerError, OSError, ValueError):
        print("cigarbench pair rejected", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
