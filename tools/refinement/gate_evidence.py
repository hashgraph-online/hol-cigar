"""Run the closed Cycle B Tier-1 gate set and emit authenticated receipts."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from .canonical import canonical_bytes, identity, load_file, multihash_bytes
from .commands import CommandError, default_registry, run_named
from .corpus import _write_canonical
from .intelligence import (
    IntelligenceError,
    _attestation_key,
    _git_source,
    _seal,
)
from .schema import SchemaRegistry
from .source_build import SourceBuildError, load_source_consumers
from .statistics import load_policy

GATE_COMMANDS: dict[str, tuple[str, ...]] = {
    "api-sdk-compatibility": ("python-sdk-tests",),
    "conformance": ("conformance-tests",),
    "deterministic-repeat": (
        "refinement-profile-tests",
        "cigarbench-consumer-tests",
    ),
    "effect-journal-durability": ("effect-journal-tests",),
    "prompt-injection-authority": ("cigarbench-consumer-tests",),
    "required-tests": (
        "refinement-contracts",
        "retrieval-tests",
        "compiler-tests",
    ),
    "security-findings": (),
    "silent-merge-conflicts": ("workspace-check",),
}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAXIMUM_COMMAND_STATE_PATH_BYTES = 64


class GateEvidenceError(RuntimeError):
    """Gate execution or receipt construction failed closed."""


def _short_command_state_root(source: dict[str, str]) -> Path:
    candidates = [Path("/private/tmp"), Path(tempfile.gettempdir()).absolute()]
    temporary_root = None
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = candidate.stat(follow_symlinks=False)
        except OSError:
            continue
        writable_by_others = bool(stat.S_IMODE(metadata.st_mode) & 0o022)
        sticky = bool(stat.S_IMODE(metadata.st_mode) & stat.S_ISVTX)
        if (
            candidate == resolved
            and stat.S_ISDIR(metadata.st_mode)
            and (not writable_by_others or sticky)
            and os.access(candidate, os.W_OK | os.X_OK)
        ):
            temporary_root = candidate
            break
    if temporary_root is None:
        raise GateEvidenceError("no bounded temporary root is available")
    state_root = Path(
        tempfile.mkdtemp(
            prefix=f"cgr-t1-{source['revision'][:8]}-", dir=temporary_root
        )
    )
    metadata = state_root.stat(follow_symlinks=False)
    if (
        state_root.is_symlink()
        or state_root.resolve(strict=True) != state_root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or len(os.fsencode(state_root)) > MAXIMUM_COMMAND_STATE_PATH_BYTES
    ):
        raise GateEvidenceError("Tier-1 command state root is unsafe or too long")
    return state_root


def _project_result(result: dict[str, Any]) -> dict[str, Any]:
    if (
        result.get("status") != "passed"
        or result.get("exit_code") != 0
        or result.get("timed_out")
        or result.get("output_overflow")
        or result.get("descendant_cleanup_required")
    ):
        raise GateEvidenceError("a named Tier-1 command did not pass")
    body = {
        "command_id": result["command_id"],
        "command_sha256": result["command_sha256"],
        "tool_digest": identity(
            {
                "command_sha256": result["command_sha256"],
                "environment_sha256": result["environment_sha256"],
                "executable_sha256": result["executable_sha256"],
                "launcher_python_sha256": result["launcher_python_sha256"],
                "launcher_sha256": result["launcher_sha256"],
            }
        ),
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "output_overflow": result["output_overflow"],
        "stdout_bytes": result["stdout_bytes"],
        "stdout_sha256": result["stdout_sha256"],
        "stderr_bytes": result["stderr_bytes"],
        "stderr_sha256": result["stderr_sha256"],
        "status": result["status"],
    }
    return {**body, "result_id": identity(body)}


def _git_consistency_result(
    repository_root: Path, champion_revision: str, candidate_revision: str
) -> dict[str, Any]:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    commands = (
        ["git", "merge-base", "--is-ancestor", champion_revision, candidate_revision],
        ["git", "diff", "--check", f"{champion_revision}..{candidate_revision}"],
    )
    combined = []
    for argv in commands:
        completed = subprocess.run(
            argv,
            cwd=repository_root,
            env=environment,
            check=False,
            capture_output=True,
            timeout=120,
        )
        if completed.returncode or completed.stdout or completed.stderr:
            raise GateEvidenceError("candidate source is not conflict-clean")
        combined.append(argv)
    body = {
        "command_id": "git-merge-consistency",
        "command_sha256": hashlib.sha256(canonical_bytes(combined)).hexdigest(),
        "tool_digest": identity(
            {
                "commands": combined,
                "producer": multihash_bytes(Path(__file__).read_bytes()),
            }
        ),
        "exit_code": 0,
        "timed_out": False,
        "output_overflow": False,
        "stdout_bytes": 0,
        "stdout_sha256": EMPTY_SHA256,
        "stderr_bytes": 0,
        "stderr_sha256": EMPTY_SHA256,
        "status": "passed",
    }
    return {**body, "result_id": identity(body)}


def _security_scan_result(
    scan_root: Path, source: dict[str, str]
) -> tuple[dict[str, Any], list[str]]:
    if not scan_root.is_absolute() or scan_root.is_symlink():
        raise GateEvidenceError("security scan root must be canonical")
    scan_root = scan_root.resolve(strict=True)
    manifest_path = scan_root / "scan-manifest.json"
    findings_path = scan_root / "findings.json"
    coverage_path = scan_root / "coverage.json"
    for path in (manifest_path, findings_path, coverage_path):
        if path.is_symlink() or path.resolve(strict=True).parent != scan_root:
            raise GateEvidenceError("security scan artifact escaped custody")
    manifest = load_file(manifest_path, maximum_bytes=16 * 1024 * 1024)
    findings = load_file(findings_path, maximum_bytes=64 * 1024 * 1024)
    coverage = load_file(coverage_path, maximum_bytes=16 * 1024 * 1024)
    scan = manifest.get("scan", {})
    target = scan.get("target", {})
    if (
        scan.get("status") != "completed"
        or scan.get("sealedAt") != scan.get("completedAt")
        or target.get("kind") != "git_diff"
        or target.get("headRevision") != source["revision"]
        or coverage.get("completeness") != "complete"
        or coverage.get("mode") != "branch_diff"
        or findings.get("findings") != []
    ):
        raise GateEvidenceError("security scan is not a clean exact-source seal")
    artifact_rows = {item["path"]: item for item in scan.get("artifacts", [])}
    for relative in ("findings.json", "coverage.json"):
        path = scan_root / relative
        row = artifact_rows.get(relative)
        if row is None or hashlib.sha256(path.read_bytes()).hexdigest() != row.get(
            "sha256"
        ):
            raise GateEvidenceError("security scan seal is internally inconsistent")
    attachments = sorted(
        multihash_bytes(path.read_bytes())
        for path in (manifest_path, findings_path, coverage_path)
    )
    body = {
        "command_id": "codex-security-sealed-diff-scan",
        "command_sha256": hashlib.sha256(
            canonical_bytes(["codex-security", "sealed-diff-scan", "no-findings"])
        ).hexdigest(),
        "tool_digest": identity(
            {
                "contract": manifest["documentType"],
                "schema_version": manifest["schemaVersion"],
                "producer": multihash_bytes(Path(__file__).read_bytes()),
            }
        ),
        "exit_code": 0,
        "timed_out": False,
        "output_overflow": False,
        "stdout_bytes": 0,
        "stdout_sha256": EMPTY_SHA256,
        "stderr_bytes": 0,
        "stderr_sha256": EMPTY_SHA256,
        "status": "passed",
    }
    return {**body, "result_id": identity(body)}, attachments


def create_gate_evidence(
    *,
    repository_root: Path,
    plan_path: Path,
    build_root: Path,
    security_scan_root: Path,
    gate_key_path: Path,
    key_id: str,
    output_path: Path,
) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    source_before = _git_source(repository_root, require_clean=True)
    registry = SchemaRegistry(repository_root / "schemas/refinement")
    plan, receipt, _executables = load_source_consumers(
        repository_root=repository_root,
        plan_path=plan_path.resolve(strict=True),
        build_root=build_root.resolve(strict=True),
    )
    if source_before != plan["product_sources"]["candidate"]:
        raise GateEvidenceError("gate source differs from the exact-source plan")
    policy, policy_digest = load_policy(
        (repository_root / "refinement/policy/promotion-v1.json").resolve(strict=True),
        registry,
    )
    if set(policy["tier1_external_checks"]) != set(GATE_COMMANDS):
        raise GateEvidenceError("Tier-1 policy and producer inventory disagree")
    key, key_fingerprint = _attestation_key(
        gate_key_path.resolve(strict=True), repository_root
    )
    state_root = _short_command_state_root(source_before)
    command_results: dict[str, tuple[dict[str, Any], str]] = {}
    named = default_registry()
    try:
        for command_id in sorted(
            {item for commands in GATE_COMMANDS.values() for item in commands}
        ):
            source_at_start = _git_source(repository_root, require_clean=True)
            result = run_named(
                named,
                command_id,
                cwd=repository_root,
                state=state_root / command_id,
            )
            if _git_source(repository_root, require_clean=True) != source_at_start:
                raise GateEvidenceError("a Tier-1 command changed candidate source")
            command_results[command_id] = (_project_result(result), result["result_id"])
        security_result, security_attachments = _security_scan_result(
            security_scan_root, source_before
        )
        consistency = _git_consistency_result(
            repository_root,
            plan["product_sources"]["champion"]["revision"],
            plan["product_sources"]["candidate"]["revision"],
        )
        receipts = []
        for gate_id in sorted(GATE_COMMANDS):
            results = [command_results[item][0] for item in GATE_COMMANDS[gate_id]]
            attachments = sorted(
                command_results[item][1] for item in GATE_COMMANDS[gate_id]
            )
            if gate_id == "security-findings":
                results = [security_result]
                attachments = security_attachments
            elif gate_id == "silent-merge-conflicts":
                results = [*results, consistency]
            results.sort(key=lambda item: item["command_id"])
            body = {
                "schema_version": "cigar.intelligence-gate-receipt.v1",
                "purpose": "private-candidate-tier1-gate",
                "gate_id": gate_id,
                "source": source_before,
                "plan_id": plan["plan_id"],
                "build_set_id": receipt["build_set_id"],
                "policy_digest": policy_digest,
                "command_results": results,
                "attachment_digests": attachments,
                "status": "passed",
            }
            sealed = _seal(
                body,
                identity_field="receipt_id",
                key=key,
                key_id=key_id,
                key_fingerprint=key_fingerprint,
            )
            registry.validate("intelligence-gate-receipt-v1.schema.json", sealed)
            receipts.append(sealed)
        evidence_body = {
            "schema_version": "cigar.intelligence-gate-evidence.v2",
            "purpose": "private-candidate-nomination-only",
            "source": source_before,
            "plan_id": plan["plan_id"],
            "build_set_id": receipt["build_set_id"],
            "policy_digest": policy_digest,
            "receipts": receipts,
        }
        evidence = {**evidence_body, "evidence_id": identity(evidence_body)}
        registry.validate("intelligence-gate-evidence-v2.schema.json", evidence)
        if _git_source(repository_root, require_clean=True) != source_before:
            raise GateEvidenceError("candidate source changed during Tier-1 gates")
        if (
            not output_path.is_absolute()
            or output_path.exists()
            or output_path.is_symlink()
            or output_path.parent.resolve(strict=True) != output_path.parent
        ):
            raise GateEvidenceError("gate evidence output must be external create-new")
        _write_canonical(output_path, evidence)
        output_path.chmod(0o400)
        return evidence
    finally:
        # The state contains only bounded command metadata, but leave it private for audit.
        if state_root.exists():
            metadata = state_root.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise GateEvidenceError("gate command state custody changed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--security-scan-root", required=True, type=Path)
    parser.add_argument("--gate-key", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = create_gate_evidence(
            repository_root=arguments.repository_root,
            plan_path=arguments.plan,
            build_root=arguments.build_root,
            security_scan_root=arguments.security_scan_root,
            gate_key_path=arguments.gate_key,
            key_id=arguments.key_id,
            output_path=arguments.output,
        )
    except (
        CommandError,
        GateEvidenceError,
        IntelligenceError,
        OSError,
        SourceBuildError,
        ValueError,
    ) as error:
        print(f"Tier-1 gate evidence failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "evidence_id": result["evidence_id"],
                "receipts": len(result["receipts"]),
                "status": "passed",
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
