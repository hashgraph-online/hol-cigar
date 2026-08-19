"""Independent, source-bound CIGARBench v2 evaluator and attestation."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, BinaryIO, Sequence

from .canonical import (
    canonical_bytes,
    identity,
    loads,
    multihash_bytes,
    safe_relative_path,
    secure_read,
)
from .commands import LAUNCHER, sanitized_environment
from .consumer import ConsumerError, load_observation
from .schema import SchemaRegistry

MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_KEY_BYTES = 128
MIN_KEY_BYTES = 32
MAX_ENVIRONMENT_FILES = 4096
MAX_ENVIRONMENT_BYTES = 64 * 1024 * 1024
MAX_VERIFIER_STDOUT = 4 * 1024 * 1024
MAX_VERIFIER_STDERR = 1024 * 1024
MAX_VERIFIER_MEMORY = 1024 * 1024 * 1024
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")


class EvaluatorError(RuntimeError):
    """Evaluator evidence is invalid, unbound, or cannot be isolated."""


def _real_path(path: Path, kind: str) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise EvaluatorError(f"{kind} must be an absolute non-symlink path")
    try:
        if path.resolve(strict=True) != path:
            raise EvaluatorError(f"{kind} must not contain path aliases")
    except OSError as error:
        raise EvaluatorError(f"{kind} is unavailable") from error


def _load_record(
    path: Path,
    *,
    schema: str,
    registry: SchemaRegistry,
    identity_field: str | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    _real_path(path, schema)
    try:
        payload = secure_read(path, maximum_bytes=MAX_RECORD_BYTES)
        value = loads(payload, maximum_bytes=MAX_RECORD_BYTES)
        registry.validate(schema, value)
    except (OSError, ValueError) as error:
        raise EvaluatorError("evaluator input violates its strict contract") from error
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise EvaluatorError("evaluator input is not canonical JSON")
    digest = multihash_bytes(payload)
    if identity_field is not None:
        body = dict(value)
        claimed = body.pop(identity_field)
        if identity(body) != claimed:
            raise EvaluatorError("evaluator input self-identity is invalid")
    return value, payload, digest


def _load_key(
    path: Path,
    *,
    repository_root: Path,
    assignment_seed_digest: str,
) -> tuple[bytes, str]:
    _real_path(path, "attestation key")
    if path.is_relative_to(repository_root):
        raise EvaluatorError("attestation key custody is not repository-independent")
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        or not MIN_KEY_BYTES <= metadata.st_size <= MAX_KEY_BYTES
    ):
        raise EvaluatorError("attestation key metadata violates custody policy")
    key = secure_read(path, maximum_bytes=MAX_KEY_BYTES)
    fingerprint = multihash_bytes(key)
    if fingerprint == assignment_seed_digest:
        raise EvaluatorError("attestation key reuses the assignment seed")
    return key, fingerprint


def _environment_inventory(root: Path) -> tuple[list[dict[str, Any]], str]:
    _real_path(root, "task environment")
    if not root.is_dir():
        raise EvaluatorError("task environment is not a directory")
    files: list[dict[str, Any]] = []
    total = 0
    for candidate in sorted(root.rglob("*"), key=lambda path: path.as_posix()):
        metadata = candidate.stat(follow_symlinks=False)
        if candidate.is_symlink():
            raise EvaluatorError("task environment contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise EvaluatorError("task environment contains a non-regular entry")
        relative = candidate.relative_to(root).as_posix()
        try:
            safe_relative_path(relative)
        except ValueError as error:
            raise EvaluatorError("task environment path is unsafe") from error
        if len(files) >= MAX_ENVIRONMENT_FILES:
            raise EvaluatorError("task environment exceeds its file bound")
        payload = secure_read(candidate, maximum_bytes=MAX_ENVIRONMENT_BYTES)
        total += len(payload)
        if total > MAX_ENVIRONMENT_BYTES:
            raise EvaluatorError("task environment exceeds its byte bound")
        files.append(
            {
                "path": relative,
                "digest": multihash_bytes(payload),
                "bytes": len(payload),
                "executable": bool(stat.S_IMODE(metadata.st_mode) & 0o111),
            }
        )
    if not files:
        raise EvaluatorError("task environment is empty")
    record = {
        "schema_version": "cigar.task-environment.v1",
        "files": files,
    }
    return files, identity(record)


def task_environment_digest(root: Path) -> str:
    """Returns the setup digest expected in a task source record."""

    return _environment_inventory(root)[1]


def _copy_environment(
    source: Path,
    destination: Path,
    inventory: list[dict[str, Any]],
) -> None:
    for record in inventory:
        relative = Path(record["path"])
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source_file = source / relative
        with source_file.open("rb") as incoming, target.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, length=64 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        target.chmod(0o500 if record["executable"] else 0o400)


def _digest_file(path: Path) -> str:
    _real_path(path, "digest input")
    return multihash_bytes(secure_read(path, maximum_bytes=MAX_ENVIRONMENT_BYTES))


def _seatbelt_literal(path: Path) -> str:
    rendered = str(path).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{rendered}"'


def _sandbox_command(
    command: list[str],
    *,
    isolated_root: Path,
    python_executable: Path,
) -> tuple[list[str], dict[str, Any]]:
    if platform.system() != "Darwin":
        raise EvaluatorError("no reviewed verifier sandbox is available on this host")
    _real_path(SANDBOX_EXEC, "sandbox launcher")
    python_install = next(
        (
            parent
            for parent in python_executable.parents
            if parent.name.startswith("python@")
        ),
        None,
    )
    if python_install is None:
        raise EvaluatorError("Python installation root is not sandbox-addressable")
    python_launchers = [python_executable]
    application_launchers = sorted(
        python_install.glob(
            "*/Frameworks/Python.framework/Versions/*/Resources/"
            "Python.app/Contents/MacOS/Python"
        )
    )
    for launcher in application_launchers:
        resolved_launcher = launcher.resolve(strict=True)
        _real_path(resolved_launcher, "Python application launcher")
        if resolved_launcher not in python_launchers:
            python_launchers.append(resolved_launcher)
    read_roots = [
        Path("/System"),
        Path("/usr/lib"),
        python_install,
        isolated_root,
    ]
    read_literals = [
        Path("/"),
        Path("/dev/null"),
        Path("/dev/urandom"),
        LAUNCHER,
        *python_launchers,
    ]
    metadata_paths: set[Path] = set()
    for path in [*read_roots, *read_literals]:
        metadata_paths.update(path.parents)
        metadata_paths.add(path)
    profile = "\n".join(
        [
            "(version 1)",
            "(deny default)",
            "(allow syscall*)",
            "(allow mach-bootstrap)",
            "(allow sysctl-read)",
            "(allow process-fork)",
            "(allow process-info* (target self))",
            "(allow signal (target self))",
            "(allow process-exec",
            *[f"  (literal {_seatbelt_literal(path)})" for path in python_launchers],
            ")",
            "(allow file-read* file-test-existence file-map-executable",
            *[f"  (subpath {_seatbelt_literal(path)})" for path in read_roots],
            *[f"  (literal {_seatbelt_literal(path)})" for path in read_literals],
            ")",
            "(allow file-read-metadata file-test-existence",
            *[
                f"  (literal {_seatbelt_literal(path)})"
                for path in sorted(metadata_paths, key=os.fspath)
            ],
            ")",
            "(allow file-write*",
            f"  (subpath {_seatbelt_literal(isolated_root)})",
            '  (literal "/dev/null")',
            ")",
            "(deny network*)",
        ]
    )
    enforcement = {
        "schema_version": "cigar.verifier-sandbox.v1",
        "engine": "darwin-seatbelt-deny-default-v1",
        "deny_default": True,
        "deny_network_star": True,
        "isolated_root_only": True,
        "profile_sha256": hashlib.sha256(
            profile.replace(str(isolated_root), "<TASK_ROOT>").encode()
        ).hexdigest(),
        "binary_digest": _digest_file(SANDBOX_EXEC),
    }
    return [str(SANDBOX_EXEC), "-p", profile, *command], enforcement


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


def _drain(
    stream: BinaryIO,
    destination: bytearray,
    limit: int,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            available = max(0, limit - len(destination))
            destination.extend(chunk[:available])
            if len(chunk) > available:
                overflow.set()
                _kill_group(process)
                return
    except OSError:
        overflow.set()
        _kill_group(process)
    finally:
        stream.close()


def _write(
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


def _bounded_process(
    argv: list[str],
    payload: bytes,
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> bytes:
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvaluatorError("verifier process could not be started") from error
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
            target=_write,
            args=(process.stdin, payload, write_failed, process),
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(
                process.stdout,
                stdout,
                MAX_VERIFIER_STDOUT,
                overflow,
                process,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(
                process.stderr,
                stderr,
                MAX_VERIFIER_STDERR,
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
        process.wait(timeout=5)
    descendant = False if timed_out else _kill_group(process)
    for thread in threads:
        thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        _kill_group(process)
        raise EvaluatorError("verifier process streams did not terminate")
    if timed_out:
        raise EvaluatorError("verifier exceeded its time bound")
    if descendant:
        raise EvaluatorError("verifier left a descendant process")
    if overflow.is_set():
        raise EvaluatorError("verifier exceeded its output bound")
    if write_failed.is_set():
        raise EvaluatorError("verifier rejected its input")
    if process.returncode != 0:
        raise EvaluatorError("verifier exited unsuccessfully")
    if stderr:
        raise EvaluatorError("successful verifier emitted stderr")
    return bytes(stdout)


def _verifier_result(
    *,
    task: dict[str, Any],
    oracle: dict[str, Any],
    observation: dict[str, Any],
    task_environment: Path,
    state: Path,
    registry: SchemaRegistry,
    expected_verifier_digest: str,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    inventory, environment_digest = _environment_inventory(task_environment)
    if environment_digest != task["source"]["setup_digest"]:
        raise EvaluatorError("task environment digest does not match task setup")
    verifier_relative = oracle["deterministic_verifier"]
    verifier_source = task_environment / verifier_relative
    _real_path(verifier_source, "deterministic verifier")
    verifier_digest = _digest_file(verifier_source)
    if verifier_digest != expected_verifier_digest:
        raise EvaluatorError("deterministic verifier digest was substituted")
    environment = sanitized_environment(state)
    with tempfile.TemporaryDirectory(dir=state, prefix="evaluation-") as raw:
        isolated = Path(raw).resolve(strict=True)
        isolated.chmod(0o700)
        _copy_environment(task_environment, isolated, inventory)
        copied_verifier = isolated / verifier_relative
        verifier_input = {
            "schema_version": "cigar.verifier-input.v1",
            "observation_id": observation["observation_id"],
            "task_id": task["task_id"],
            "output_digest": observation["output_digest"],
            "selected_block_ids": [
                block["block_id"] for block in observation["selected_blocks"]
            ],
            "selected_provenance_ids": sorted(
                {
                    provenance
                    for block in observation["selected_blocks"]
                    for provenance in block["provenance_ids"]
                }
            ),
            "expected_artifacts": oracle["expected_artifacts"],
        }
        python_executable = Path(sys.executable).resolve(strict=True)
        command = [
            str(python_executable),
            str(LAUNCHER),
            str(task["execution"]["timeout_seconds"]),
            str(MAX_VERIFIER_MEMORY),
            str(python_executable),
            str(python_executable),
            "-I",
            "-S",
            str(copied_verifier),
        ]
        sandboxed, enforcement = _sandbox_command(
            command,
            isolated_root=isolated,
            python_executable=python_executable,
        )
        stdout = _bounded_process(
            sandboxed,
            canonical_bytes(verifier_input),
            cwd=isolated,
            environment=environment,
            timeout_seconds=task["execution"]["timeout_seconds"] + 5,
        )
    if not stdout.endswith(b"\n") or stdout.endswith(b"\n\n"):
        raise EvaluatorError("verifier did not emit one canonical record")
    record = stdout[:-1]
    try:
        result = loads(record, maximum_bytes=MAX_VERIFIER_STDOUT)
        registry.validate("verifier-result-v1.schema.json", result)
    except ValueError as error:
        raise EvaluatorError("verifier result violates its contract") from error
    if not isinstance(result, dict) or canonical_bytes(result) != record:
        raise EvaluatorError("verifier result is not canonical JSON")
    check_ids = [check["check_id"] for check in result["checks"]]
    if check_ids != sorted(set(check_ids)) or result["passed"] != all(
        check["passed"] for check in result["checks"]
    ):
        raise EvaluatorError("verifier result is internally inconsistent")
    launcher_record = {
        "sandbox": enforcement,
        "bounded_launcher": _digest_file(LAUNCHER),
        "python": _digest_file(python_executable),
    }
    isolation = {
        "engine": enforcement["engine"],
        "network_denied": bool(enforcement["deny_network_star"]),
        "disposable_root": True,
        "environment_digest": environment_digest,
        "launcher_digest": identity(launcher_record),
    }
    return result, verifier_digest, isolation


def _metric(
    name: str,
    numerator: int | float,
    denominator: int | float,
    unit: str,
    sources: Sequence[str],
    *,
    applicable: bool = True,
    value: int | float | None = None,
) -> dict[str, Any]:
    if not applicable:
        numerator = 0
        denominator = 0
        selected_value: int | float = 0
    elif value is not None:
        selected_value = value
    elif unit in {"ratio", "boolean"}:
        selected_value = numerator / denominator if denominator else 0
    else:
        selected_value = numerator
    return {
        "name": name,
        "numerator": numerator,
        "denominator": denominator,
        "value": selected_value,
        "unit": unit,
        "applicable": applicable,
        "source_attachment_ids": sorted(set(sources)),
    }


def _evidence_aliases(oracle: dict[str, Any]) -> dict[str, set[str]]:
    aliases: dict[str, set[str]] = {}
    for item in oracle["critical_evidence"]:
        aliases[item["evidence_id"]] = {
            item["evidence_id"],
            item["version_or_span"],
        }
    for evidence_id in oracle["relevant_evidence"] + oracle["prohibited_evidence"]:
        aliases.setdefault(evidence_id, {evidence_id})
    return aliases


def _present(
    evidence_id: str,
    aliases: dict[str, set[str]],
    selected: set[str],
) -> bool:
    return bool(aliases.get(evidence_id, {evidence_id}) & selected)


def _human_agreement(adjudication: dict[str, Any] | None) -> tuple[int, int]:
    if adjudication is None:
        return 0, 0
    agreements = 0
    votes = 0
    reviewer_ids = adjudication["reviewer_ids"]
    if reviewer_ids != sorted(set(reviewer_ids)):
        raise EvaluatorError("adjudication reviewers are not sorted and unique")
    previous: tuple[str, str] | None = None
    for judgment in adjudication["judgments"]:
        key = (judgment["criterion"], judgment["subject_id"])
        if previous is not None and previous >= key:
            raise EvaluatorError("adjudication judgments are not sorted and unique")
        previous = key
        vote_reviewers = [vote["reviewer_id"] for vote in judgment["votes"]]
        if vote_reviewers != reviewer_ids:
            raise EvaluatorError("adjudication votes do not cover exact reviewers")
        counts: dict[str, int] = {}
        for vote in judgment["votes"]:
            counts[vote["outcome"]] = counts.get(vote["outcome"], 0) + 1
        agreements += max(counts.values())
        votes += len(judgment["votes"])
    return agreements, votes


def _derive_metrics(
    *,
    observation: dict[str, Any],
    task: dict[str, Any],
    oracle: dict[str, Any],
    claims: dict[str, Any] | None,
    adjudication: dict[str, Any] | None,
    verifier: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected_blocks = observation["selected_blocks"]
    selected = {
        provenance
        for block in selected_blocks
        for provenance in block["provenance_ids"]
    }
    aliases = _evidence_aliases(oracle)
    critical = oracle["critical_evidence"]
    critical_weight = sum(item["weight"] for item in critical)
    present_weight = sum(
        item["weight"]
        for item in critical
        if _present(item["evidence_id"], aliases, selected)
    )
    relevant_ids = set(oracle["relevant_evidence"]) | {
        item["evidence_id"] for item in critical
    }
    prohibited_ids = set(oracle["prohibited_evidence"])

    def block_matches(block: dict[str, Any], evidence_ids: set[str]) -> bool:
        provenance = set(block["provenance_ids"])
        return any(
            bool(aliases.get(evidence_id, {evidence_id}) & provenance)
            for evidence_id in evidence_ids
        )

    evidence_blocks = [
        block for block in selected_blocks if block["lane"] == "evidence"
    ]
    relevant_blocks = [
        block for block in evidence_blocks if block_matches(block, relevant_ids)
    ]
    prohibited_blocks = [
        block for block in evidence_blocks if block_matches(block, prohibited_ids)
    ]
    total_evidence_tokens = sum(block["tokens"] for block in evidence_blocks)
    relevant_tokens = sum(block["tokens"] for block in relevant_blocks)
    prohibited_tokens = sum(block["tokens"] for block in prohibited_blocks)
    first_rank = next(
        (
            block["rank"]
            for block in selected_blocks
            if any(
                _present(item["evidence_id"], aliases, set(block["provenance_ids"]))
                for item in critical
            )
        ),
        len(selected_blocks) + 1 if critical else 0,
    )
    required_claims = {claim["claim_id"]: claim for claim in oracle["required_claims"]}
    sufficient_claims = sum(
        all(
            _present(evidence_id, aliases, selected)
            for evidence_id in claim["evidence_ids"]
        )
        for claim in required_claims.values()
    )
    claim_rows = [] if claims is None else claims["claims"]
    citation_total = 0
    citation_valid = 0
    cited_gold_claims: set[str] = set()
    unsupported = 0
    for claim in claim_rows:
        gold = required_claims.get(claim["claim_id"])
        valid_for_claim = 0
        citation_total += len(claim["citations"])
        for citation in claim["citations"]:
            valid = (
                gold is not None
                and citation in gold["evidence_ids"]
                and _present(citation, aliases, selected)
            )
            citation_valid += int(valid)
            valid_for_claim += int(valid)
        if gold is not None and valid_for_claim:
            cited_gold_claims.add(claim["claim_id"])
        if gold is None or valid_for_claim == 0:
            unsupported += 1
    temporal = task["stratum"] == "Temporal-Truth" or "temporal" in task["sub_strata"]
    conflict = "conflict" in task["sub_strata"]
    all_critical = bool(critical) and present_weight == critical_weight
    claims_sources = ["observation", "oracle"] + (
        ["claims"] if claims is not None else []
    )
    agreement_numerator, agreement_denominator = _human_agreement(adjudication)
    metrics = [
        _metric(
            "verified_task_success",
            int(verifier["passed"]),
            1,
            "boolean",
            ["verifier-result"],
        ),
        _metric(
            "critical_context_recall",
            present_weight,
            critical_weight,
            "ratio",
            ["observation", "oracle"],
            applicable=critical_weight > 0,
        ),
        _metric(
            "evidence_token_precision",
            relevant_tokens,
            total_evidence_tokens,
            "ratio",
            ["observation", "oracle"],
            applicable=total_evidence_tokens > 0,
        ),
        _metric(
            "evidence_item_precision",
            len(relevant_blocks),
            len(evidence_blocks),
            "ratio",
            ["observation", "oracle"],
            applicable=bool(evidence_blocks),
        ),
        _metric(
            "citation_recall",
            len(cited_gold_claims),
            len(required_claims),
            "ratio",
            claims_sources,
            applicable=claims is not None and bool(required_claims),
        ),
        _metric(
            "citation_precision",
            citation_valid,
            citation_total,
            "ratio",
            claims_sources,
            applicable=claims is not None and citation_total > 0,
        ),
        _metric(
            "unsupported_claim_rate",
            unsupported,
            len(claim_rows),
            "ratio",
            claims_sources,
            applicable=claims is not None and bool(claim_rows),
        ),
        _metric(
            "temporal_correctness",
            int(all_critical),
            1,
            "boolean",
            ["observation", "oracle"],
            applicable=temporal,
        ),
        _metric(
            "conflict_correctness",
            int(all_critical),
            1,
            "boolean",
            ["observation", "oracle"],
            applicable=conflict,
        ),
        _metric(
            "abstention_correctness",
            int(
                claims is not None
                and claims["answer_status"] in {"abstained", "insufficient_evidence"}
            ),
            1,
            "boolean",
            claims_sources,
            applicable=oracle["allowed_abstention"] and claims is not None,
        ),
        _metric(
            "first_useful_evidence_rank",
            first_rank,
            1,
            "rank",
            ["observation", "oracle"],
            applicable=bool(critical),
        ),
        _metric(
            "evidence_sufficiency",
            sufficient_claims,
            len(required_claims),
            "ratio",
            ["observation", "oracle"],
            applicable=bool(required_claims),
        ),
        _metric(
            "selected_provenance_coverage",
            sum(bool(block["provenance_ids"]) for block in selected_blocks),
            len(selected_blocks),
            "ratio",
            ["observation"],
            applicable=bool(selected_blocks),
        ),
        _metric(
            "authorization_violations",
            len(prohibited_blocks),
            1,
            "count",
            ["observation", "oracle"],
        ),
        _metric(
            "prohibited_materialized_tokens",
            prohibited_tokens,
            1,
            "tokens",
            ["observation", "oracle"],
        ),
        _metric("digest_mismatches", 0, 1, "count", ["observation"]),
        _metric(
            "unsafe_effect_retries",
            observation["effect_replay"]["unsafe_retries"],
            1,
            "count",
            ["observation"],
        ),
        _metric(
            "budget_overflow",
            int(
                sum(block["tokens"] for block in selected_blocks)
                > task["contract"]["token_budget"]
            ),
            1,
            "count",
            ["observation", "task"],
        ),
        _metric(
            "physical_input_tokens",
            observation["resources"]["physical_input_tokens"],
            1,
            "tokens",
            ["observation"],
        ),
        _metric(
            "cache_read_tokens",
            observation["resources"]["cache_read_tokens"],
            1,
            "tokens",
            ["observation"],
        ),
        _metric(
            "cache_write_tokens",
            observation["resources"]["cache_write_tokens"],
            1,
            "tokens",
            ["observation"],
        ),
        _metric(
            "output_tokens",
            observation["resources"]["output_tokens"],
            1,
            "tokens",
            ["observation"],
        ),
        _metric(
            "latency_ms",
            observation["resources"]["latency_ms"],
            1,
            "milliseconds",
            ["observation"],
        ),
        _metric(
            "cpu_ms",
            observation["resources"]["cpu_ms"],
            1,
            "milliseconds",
            ["observation"],
            applicable=observation["resources"]["cpu_measured"],
        ),
        _metric(
            "peak_rss_bytes",
            observation["resources"]["peak_rss_bytes"],
            1,
            "bytes",
            ["observation"],
            applicable=observation["resources"]["peak_rss_measured"],
        ),
        _metric(
            "cost_usd", observation["resources"]["cost_usd"], 1, "usd", ["observation"]
        ),
        _metric(
            "handoffs",
            observation["effect_replay"]["handoffs"],
            1,
            "count",
            ["observation"],
        ),
        _metric(
            "effects",
            observation["effect_replay"]["effects"],
            1,
            "count",
            ["observation"],
        ),
        _metric(
            "replay_dispatches",
            observation["effect_replay"]["replay_dispatches"],
            1,
            "count",
            ["observation"],
        ),
        _metric(
            "human_agreement",
            agreement_numerator,
            agreement_denominator,
            "ratio",
            ["adjudication"] if adjudication is not None else ["oracle"],
            applicable=adjudication is not None and agreement_denominator > 0,
        ),
    ]
    for phase in observation["phases"]:
        metrics.append(
            _metric(
                f"phase_{phase['phase']}_ms",
                phase["duration_ms"],
                1,
                "milliseconds",
                ["observation"],
            )
        )
    metrics.sort(key=lambda metric: metric["name"])
    violations = []
    for block in prohibited_blocks:
        violations.append(
            {
                "code": "prohibited_evidence_selected",
                "severity": "hard",
                "evidence_id": block["block_id"],
            }
        )
    if observation["effect_replay"]["unsafe_retries"]:
        violations.append(
            {
                "code": "unsafe_effect_retry",
                "severity": "hard",
                "evidence_id": "observation",
            }
        )
    if (
        sum(block["tokens"] for block in selected_blocks)
        > task["contract"]["token_budget"]
    ):
        violations.append(
            {
                "code": "budget_overflow",
                "severity": "hard",
                "evidence_id": "observation",
            }
        )
    if not verifier["passed"]:
        violations.append(
            {
                "code": "postcondition_failed",
                "severity": "warning",
                "evidence_id": "verifier-result",
            }
        )
    violations.sort(key=lambda violation: (violation["code"], violation["evidence_id"]))
    return metrics, violations


def _attachment(identifier: str, kind: str, digest: str) -> dict[str, str]:
    return {"attachment_id": identifier, "kind": kind, "digest": digest}


def _evaluation_body(evaluation: dict[str, Any]) -> dict[str, Any]:
    body = dict(evaluation)
    body.pop("evaluation_id", None)
    attestation = dict(body["attestation"])
    attestation.pop("mac", None)
    body["attestation"] = attestation
    return body


def _unsigned_evaluation(evaluation: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(evaluation)
    attestation = dict(unsigned["attestation"])
    attestation.pop("mac", None)
    unsigned["attestation"] = attestation
    return unsigned


def evaluate(
    *,
    observation_path: Path,
    task_path: Path,
    oracle_path: Path,
    claims_path: Path | None,
    adjudication_path: Path | None,
    task_environment: Path,
    state: Path,
    schemas: Path,
    repository_root: Path,
    key_path: Path,
    key_id: str,
    assignment_seed_digest: str,
    expected_oracle_digest: str,
    expected_verifier_digest: str,
    expected_claims_digest: str | None,
    evidence_class: str,
) -> dict[str, Any]:
    registry = SchemaRegistry(schemas)
    key, key_fingerprint = _load_key(
        key_path,
        repository_root=repository_root,
        assignment_seed_digest=assignment_seed_digest,
    )
    try:
        observation, observation_bytes, _artifacts = load_observation(
            observation_path, registry
        )
    except ConsumerError as error:
        raise EvaluatorError("raw observation failed independent validation") from error
    task, task_bytes, task_digest = _load_record(
        task_path,
        schema="task-v1.schema.json",
        registry=registry,
    )
    if task["task_id"] != observation["task_id"]:
        raise EvaluatorError("task identity does not match observation")
    if (
        task["source"]["archive_digest"] != observation["archive_digest"]
        or task["source"]["immutable_revision"] != observation["source"]["revision"]
    ):
        raise EvaluatorError("task source does not match observation")
    oracle, _oracle_bytes, oracle_digest = _load_record(
        oracle_path,
        schema="oracle-v1.schema.json",
        registry=registry,
        identity_field="oracle_id",
    )
    if (
        oracle["task_id"] != task["task_id"]
        or oracle_digest != task["oracle_digest"]
        or oracle_digest != expected_oracle_digest
    ):
        raise EvaluatorError("hidden oracle digest was substituted")
    claims: dict[str, Any] | None = None
    claims_digest: str | None = None
    if claims_path is not None:
        claims, _claims_bytes, claims_digest = _load_record(
            claims_path,
            schema="claims-v1.schema.json",
            registry=registry,
            identity_field="claims_id",
        )
        if (
            claims["observation_id"] != observation["observation_id"]
            or claims["output_digest"] != observation["output_digest"]
            or expected_claims_digest is None
            or claims_digest != expected_claims_digest
        ):
            raise EvaluatorError("claims attachment binding is invalid")
        claim_ids = [claim["claim_id"] for claim in claims["claims"]]
        if claim_ids != sorted(set(claim_ids)):
            raise EvaluatorError("claims are not sorted and unique")
    elif expected_claims_digest is not None:
        raise EvaluatorError("expected claims attachment is missing")
    adjudication: dict[str, Any] | None = None
    adjudication_digest: str | None = None
    if adjudication_path is not None:
        adjudication, _bytes, adjudication_digest = _load_record(
            adjudication_path,
            schema="adjudication-v1.schema.json",
            registry=registry,
            identity_field="adjudication_id",
        )
        if adjudication["observation_id"] != observation["observation_id"]:
            raise EvaluatorError("adjudication does not match observation")
    verifier_result, verifier_digest, isolation = _verifier_result(
        task=task,
        oracle=oracle,
        observation=observation,
        task_environment=task_environment,
        state=state,
        registry=registry,
        expected_verifier_digest=expected_verifier_digest,
    )
    verifier_result_bytes = canonical_bytes(verifier_result)
    verifier_result_digest = multihash_bytes(verifier_result_bytes)
    evaluator_digest = _digest_file(Path(__file__).resolve(strict=True))
    attachments = [
        _attachment("evaluator", "evaluator", evaluator_digest),
        _attachment("observation", "observation", multihash_bytes(observation_bytes)),
        _attachment("oracle", "oracle", oracle_digest),
        _attachment("task", "task", task_digest),
        _attachment("verifier", "verifier", verifier_digest),
        _attachment("verifier-result", "verifier-result", verifier_result_digest),
    ]
    if claims_digest is not None:
        attachments.append(_attachment("claims", "claims", claims_digest))
    if adjudication_digest is not None:
        attachments.append(
            _attachment("adjudication", "adjudication", adjudication_digest)
        )
    attachments.sort(key=lambda attachment: attachment["attachment_id"])
    metrics, violations = _derive_metrics(
        observation=observation,
        task=task,
        oracle=oracle,
        claims=claims,
        adjudication=adjudication,
        verifier=verifier_result,
    )
    checks_passed = sum(check["passed"] for check in verifier_result["checks"])
    evaluation: dict[str, Any] = {
        "schema_version": "cigar.benchmark-evaluation.v2",
        "evaluation_id": "",
        "observation_id": observation["observation_id"],
        "task_id": task["task_id"],
        "task_digest": task_digest,
        "oracle_digest": oracle_digest,
        "evaluator_digest": evaluator_digest,
        "claims_digest": claims_digest,
        "verifier_digest": verifier_digest,
        "adjudication_digest": adjudication_digest,
        "evidence_class": evidence_class,
        "status": "valid",
        "attachments": attachments,
        "metrics": metrics,
        "violations": violations,
        "postcondition": {
            "result_digest": verifier_result_digest,
            "passed": verifier_result["passed"],
            "checks_passed": checks_passed,
            "checks_total": len(verifier_result["checks"]),
            "isolation": isolation,
        },
        "attestation": {
            "algorithm": "hmac-sha256-v1",
            "key_id": key_id,
            "key_fingerprint": key_fingerprint,
            "custody": "external-independent",
            "assignment_seed_reused": False,
            "mac": "",
        },
    }
    evaluation["evaluation_id"] = identity(_evaluation_body(evaluation))
    evaluation["attestation"]["mac"] = hmac.new(
        key,
        canonical_bytes(_unsigned_evaluation(evaluation)),
        hashlib.sha256,
    ).hexdigest()
    try:
        registry.validate("evaluation-v2.schema.json", evaluation)
    except ValueError as error:
        raise EvaluatorError("derived evaluation violates its schema") from error
    verify_attestation(
        evaluation,
        key=key,
        registry=registry,
        expected_key_fingerprint=key_fingerprint,
    )
    return evaluation


def verify_attestation(
    evaluation: dict[str, Any],
    *,
    key: bytes,
    registry: SchemaRegistry,
    expected_key_fingerprint: str | None = None,
) -> None:
    try:
        registry.validate("evaluation-v2.schema.json", evaluation)
    except ValueError as error:
        raise EvaluatorError("evaluation violates its schema") from error
    if identity(_evaluation_body(evaluation)) != evaluation["evaluation_id"]:
        raise EvaluatorError("evaluation identity is invalid")
    key_fingerprint = multihash_bytes(key)
    if (
        evaluation["attestation"]["key_fingerprint"] != key_fingerprint
        or expected_key_fingerprint is not None
        and key_fingerprint != expected_key_fingerprint
    ):
        raise EvaluatorError("evaluation key fingerprint is invalid")
    expected = hmac.new(
        key,
        canonical_bytes(_unsigned_evaluation(evaluation)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, evaluation["attestation"]["mac"]):
        raise EvaluatorError("evaluation attestation is invalid")
    attachment_ids = [
        attachment["attachment_id"] for attachment in evaluation["attachments"]
    ]
    if attachment_ids != sorted(set(attachment_ids)):
        raise EvaluatorError("evaluation attachments are not sorted and unique")
    attachment_set = set(attachment_ids)
    attachments = {
        attachment["attachment_id"]: attachment["digest"]
        for attachment in evaluation["attachments"]
    }
    required_bindings = {
        "task": evaluation["task_digest"],
        "oracle": evaluation["oracle_digest"],
        "evaluator": evaluation["evaluator_digest"],
        "verifier": evaluation["verifier_digest"],
        "verifier-result": evaluation["postcondition"]["result_digest"],
    }
    if evaluation["claims_digest"] is not None:
        required_bindings["claims"] = evaluation["claims_digest"]
    if evaluation["adjudication_digest"] is not None:
        required_bindings["adjudication"] = evaluation["adjudication_digest"]
    if any(
        attachments.get(name) != digest for name, digest in required_bindings.items()
    ):
        raise EvaluatorError("evaluation attachment digest binding is invalid")
    metric_names = [metric["name"] for metric in evaluation["metrics"]]
    if metric_names != sorted(set(metric_names)):
        raise EvaluatorError("evaluation metrics are not sorted and unique")
    for metric in evaluation["metrics"]:
        sources = metric["source_attachment_ids"]
        if sources != sorted(set(sources)) or not set(sources).issubset(attachment_set):
            raise EvaluatorError("metric cites an absent source attachment")
        if not metric["applicable"]:
            if any(
                metric[field] != 0 for field in ("numerator", "denominator", "value")
            ):
                raise EvaluatorError("inapplicable metric contains a value")
            continue
        if metric["unit"] in {"ratio", "boolean"}:
            if (
                metric["denominator"] <= 0
                or metric["numerator"] > metric["denominator"]
                or metric["value"] != metric["numerator"] / metric["denominator"]
            ):
                raise EvaluatorError("ratio metric arithmetic is invalid")
        elif metric["value"] != metric["numerator"]:
            raise EvaluatorError("scalar metric arithmetic is invalid")
    violation_keys = [
        (violation["code"], violation["evidence_id"])
        for violation in evaluation["violations"]
    ]
    if violation_keys != sorted(set(violation_keys)):
        raise EvaluatorError("evaluation violations are not sorted and unique")


def replay(expected: dict[str, Any], **arguments: Any) -> dict[str, Any]:
    reproduced = evaluate(**arguments)
    if canonical_bytes(reproduced) != canonical_bytes(expected):
        raise EvaluatorError("evaluation replay differs")
    return reproduced


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Independent CIGARBench v2 evaluator")
    parser.add_argument("command", choices=("evaluate", "replay", "verify"))
    parser.add_argument("--evaluation", type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--task", type=Path)
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--claims", type=Path)
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--task-environment", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--schemas", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--assignment-seed-digest", required=True)
    parser.add_argument("--expected-oracle-digest")
    parser.add_argument("--expected-verifier-digest")
    parser.add_argument("--expected-claims-digest")
    parser.add_argument("--evidence-class", default="diagnostic")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    registry = SchemaRegistry(arguments.schemas)
    try:
        key, fingerprint = _load_key(
            arguments.key,
            repository_root=arguments.repository_root,
            assignment_seed_digest=arguments.assignment_seed_digest,
        )
        if arguments.command == "verify":
            if arguments.evaluation is None:
                raise EvaluatorError("verify requires --evaluation")
            evaluation, _payload, _digest = _load_record(
                arguments.evaluation,
                schema="evaluation-v2.schema.json",
                registry=registry,
            )
            verify_attestation(
                evaluation,
                key=key,
                registry=registry,
                expected_key_fingerprint=fingerprint,
            )
            return 0
        required = (
            arguments.observation,
            arguments.task,
            arguments.oracle,
            arguments.task_environment,
            arguments.state,
            arguments.expected_oracle_digest,
            arguments.expected_verifier_digest,
        )
        if any(value is None for value in required):
            raise EvaluatorError("evaluate/replay inputs are incomplete")
        call = {
            "observation_path": arguments.observation,
            "task_path": arguments.task,
            "oracle_path": arguments.oracle,
            "claims_path": arguments.claims,
            "adjudication_path": arguments.adjudication,
            "task_environment": arguments.task_environment,
            "state": arguments.state,
            "schemas": arguments.schemas,
            "repository_root": arguments.repository_root,
            "key_path": arguments.key,
            "key_id": arguments.key_id,
            "assignment_seed_digest": arguments.assignment_seed_digest,
            "expected_oracle_digest": arguments.expected_oracle_digest,
            "expected_verifier_digest": arguments.expected_verifier_digest,
            "expected_claims_digest": arguments.expected_claims_digest,
            "evidence_class": arguments.evidence_class,
        }
        if arguments.command == "evaluate":
            result = evaluate(**call)
            sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
            return 0
        if arguments.evaluation is None:
            raise EvaluatorError("replay requires --evaluation")
        expected, _payload, _digest = _load_record(
            arguments.evaluation,
            schema="evaluation-v2.schema.json",
            registry=registry,
        )
        replay(expected, **call)
        return 0
    except (EvaluatorError, OSError, ValueError):
        print("cigarbench evaluator rejected", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
