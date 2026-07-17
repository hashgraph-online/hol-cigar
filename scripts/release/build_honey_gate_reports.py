#!/usr/bin/env python3
"""Produce the three closed Honey source/security gate reports.

The reports bind one clean Git tree and the exact 13 assembled candidate
attachments.  They contain digests of bounded command output, never source,
prompt, credential, or test-log content.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
from typing import Any, Iterable, Sequence

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    matches,
    repo_root,
    run_bounded,
    scan_payload,
    sha256_bytes,
    sha256_file,
)
from source_descriptor import SourceDescriptorError, validate_source_descriptor
from verify_honey_release import verify as verify_honey_release
from verify_package import verify as verify_package


VERSION = "0.9.0-honey.1"
CONTEXT_ABI = "cigar.context.v1"
REPORT_SCHEMA = "cigar.honey.gate-report.v1"
PRODUCER_PATH = "scripts/release/build_honey_gate_reports.py"
MATRIX_PATH = "packaging/honey/artifact-matrix.v1.json"
SOURCE_CONTRACT_PATH = "packaging/honey/contracts/source-archive.v1.json"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


CHECKS: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
    (
        "cargo-fmt",
        (("cargo", "fmt", "--all", "--", "--check"),),
    ),
    (
        "cargo-clippy",
        (
            (
                "cargo",
                "clippy",
                "--offline",
                "-p",
                "cigar-cli",
                "--all-targets",
                "--no-default-features",
                "--features",
                "full",
                "--",
                "-D",
                "warnings",
            ),
            (
                "cargo",
                "clippy",
                "--offline",
                "-p",
                "cigar-daemon",
                "-p",
                "cigar-mcp",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ),
        ),
    ),
    (
        "focused-tests",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-catalog",
                "-p",
                "cigar-compiler",
                "-p",
                "cigar-policy",
                "-p",
                "cigar-store",
                "-p",
                "cigar-space",
                "-p",
                "cigar-effects",
                "-p",
                "cigar-replay",
                "-p",
                "cigar-api",
                "-p",
                "cigar-daemon",
                "-p",
                "cigar-mcp",
            ),
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-cli",
                "--no-default-features",
                "--features",
                "full",
            ),
        ),
    ),
    (
        "protocol-parity",
        (
            ("python3", "scripts/release/product_version.py", "check"),
            ("python3", "scripts/release/honey_profile.py", "check"),
            ("python3", "scripts/release/development_protocol_baseline.py", "check"),
            ("python3", "sdk/generate_clients.py", "--check"),
        ),
    ),
    (
        "canonical-schema-vectors",
        (("cargo", "test", "--offline", "-p", "cigar-conformance"),),
    ),
    (
        "two-agent-acceptance-reauthorization",
        (("cargo", "test", "--offline", "-p", "cigar-space", "--test", "handoff"),),
    ),
    (
        "policy-denied-nondisclosure",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-policy",
                "--test",
                "policy",
                "denied_existence_noninterference_processor_confinement_and_timing_classes",
            ),
        ),
    ),
    (
        "effect-pre-intent-unreachable",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-effects",
                "--test",
                "wp12_effects",
                "dispatch_requires_committed_authorization_attempt_fence_and_outbox",
            ),
        ),
    ),
    (
        "effect-unknown-no-blind-retry",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-effects",
                "--test",
                "wp12_effects",
                "unknown_retry_requires_idempotency_or_proven_non_execution",
            ),
        ),
    ),
    (
        "effect-duplicate-delivery",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-effects",
                "--test",
                "wp12_faults",
                "one_hundred_thousand_possible_commit_campaign_has_no_duplicate_or_blind_retry",
            ),
        ),
    ),
    (
        "malformed-api-mcp",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-api",
                "--test",
                "typed_payload_contract",
                "strict_codec_rejects_unknown_duplicate_noncanonical_and_oversized_payloads",
            ),
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-mcp",
                "--test",
                "process",
                "serve_process_enforces_inventory_ids_duplicates_and_frame_bounds",
            ),
        ),
    ),
    (
        "package-negative-verification",
        (("python3", "-m", "unittest", "scripts.release.tests.test_verify_package"),),
    ),
    (
        "local-admin-loopback-default",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-daemon",
                "local_public_bind_fails_closed",
            ),
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-daemon",
                "loopback_tcp_requires_file_protected_token",
            ),
        ),
    ),
    (
        "demos-observational-no-egress",
        (
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "cigar-replay",
                "--test",
                "wp13_no_egress",
            ),
        ),
    ),
)


class HoneyGateReportError(ReleaseError):
    """A required Honey source/security gate cannot be evidenced."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--source-descriptor", type=Path, required=True)
    parser.add_argument("--typescript-receipt", type=Path, required=True)
    parser.add_argument("--python-receipt", type=Path, required=True)
    parser.add_argument("--rust-receipt", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path)
    return parser.parse_args()


def _git(root: Path, *arguments: str) -> bytes:
    result = run_bounded(
        ["git", "--no-replace-objects", *arguments],
        cwd=root,
        timeout=60,
        max_stdout=32 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if result.returncode != 0:
        raise HoneyGateReportError("cannot inspect the Honey source tree")
    return result.stdout


def _source(root: Path, descriptor_path: Path) -> dict[str, Any]:
    descriptor = load_json(descriptor_path)
    try:
        validate_source_descriptor(descriptor)
    except SourceDescriptorError as error:
        raise HoneyGateReportError(f"source descriptor is invalid: {error}") from error
    git = descriptor["git"]
    revision = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if (
        status
        or git["revision"] != revision
        or git["tree"] != tree
        or git["clean"] is not True
    ):
        raise HoneyGateReportError(
            "gate reports require the descriptor's exact clean Git tree"
        )
    return {"revision": revision, "tree": tree, "committed": True, "clean": True}


def _candidate(
    root: Path, candidate: Path
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    result = verify_honey_release(candidate, root)
    if result.get("status") != "passed-artifact-integrity":
        raise HoneyGateReportError(
            "candidate did not pass public artifact verification"
        )
    matrix = load_json(root / MATRIX_PATH)
    manifest = load_json(candidate / "honey-release-manifest.json")
    rows: list[dict[str, Any]] = []
    for artifact in matrix["artifacts"]:
        path = candidate / artifact["filename"]
        rows.append(
            {
                "id": artifact["id"],
                "filename": artifact["filename"],
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    if [row["id"] for row in rows] != [row["id"] for row in matrix["artifacts"]]:
        raise HoneyGateReportError("candidate artifact inventory changed")
    return rows, manifest, matrix["artifacts"]


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        upper = name.upper()
        if (
            upper.endswith("_PROXY")
            or upper in {"ALL_PROXY", "NO_PROXY", "SSH_AUTH_SOCK", "CIGAR_EVIDENCE_DIR"}
            or "TOKEN" in upper
            or "PASSWORD" in upper
            or "SECRET" in upper
            or "CREDENTIAL" in upper
        ):
            environment.pop(name, None)
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NPM_CONFIG_OFFLINE": "true",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "UV_OFFLINE": "1",
        }
    )
    return environment


def _bounded_checks(root: Path) -> dict[str, Any]:
    environment = _environment()
    records: list[dict[str, Any]] = []
    for identifier, commands in CHECKS:
        command_argv = [list(command) for command in commands]
        stdout = hashlib.sha256()
        stderr = hashlib.sha256()
        for command in command_argv:
            result = run_bounded(
                command,
                cwd=root,
                env=environment,
                timeout=1_800,
                max_stdout=MAX_OUTPUT_BYTES,
                max_stderr=MAX_OUTPUT_BYTES,
            )
            stdout.update(len(result.stdout).to_bytes(8, "big"))
            stdout.update(result.stdout)
            stderr.update(len(result.stderr).to_bytes(8, "big"))
            stderr.update(result.stderr)
            if result.returncode != 0:
                raise HoneyGateReportError(f"bounded Honey check failed: {identifier}")
        records.append(
            {
                "id": identifier,
                "status": "passed",
                "exit_code": 0,
                "command_sha256": sha256_bytes(canonical_json_bytes(command_argv)),
                "stdout_sha256": stdout.hexdigest(),
                "stderr_sha256": stderr.hexdigest(),
            }
        )
    return {"checks": records, "failed_checks": 0}


def _suppression(
    path: str, finding: str, exemptions: Sequence[dict[str, Any]]
) -> dict[str, str] | None:
    for exemption in exemptions:
        if not matches(path, [exemption["pattern"]]):
            continue
        findings = exemption.get("findings")
        if findings is None or finding in findings:
            return {
                "path": path,
                "finding": finding,
                "authority_pattern": exemption["pattern"],
                "authority_reason": exemption["reason"],
            }
    return None


def _tar_members(path: Path) -> Iterable[tuple[str, bytes]]:
    with tarfile.open(path, mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise HoneyGateReportError("source member exceeds the scan bound")
            handle = archive.extractfile(member)
            if handle is None:
                raise HoneyGateReportError("source member cannot be read")
            payload = handle.read(member.size + 1)
            if len(payload) != member.size:
                raise HoneyGateReportError("source member changed while scanned")
            yield member.name, payload


def _secret_scan(
    root: Path,
    candidate: Path,
    matrix_rows: Sequence[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_contract = load_json(root / SOURCE_CONTRACT_PATH)
    exemptions = source_contract["content_scan_exemptions"]
    source_artifact = next(row for row in matrix_rows if row["id"] == "source")
    source_archive = candidate / source_artifact["filename"]
    suppression_records: list[dict[str, str]] = []
    files_scanned = 0
    bytes_scanned = 0
    for path, payload in _tar_members(source_archive):
        files_scanned += 1
        bytes_scanned += len(payload)
        findings = scan_payload(path, payload, [])
        unresolved = scan_payload(path, payload, exemptions)
        if unresolved:
            raise HoneyGateReportError(
                f"unresolved source content finding in {path}: {sorted(unresolved)}"
            )
        for finding in findings:
            record = _suppression(path, finding, exemptions)
            if record is None:
                raise HoneyGateReportError(
                    "source scan suppression is not authoritative"
                )
            suppression_records.append(record)

    for artifact in matrix_rows:
        path = candidate / artifact["filename"]
        contract = artifact.get("contract")
        if contract is not None:
            verification = verify_package(
                path,
                root / contract,
                VERSION,
                CONTEXT_ABI,
            )
            if verification.get("status") != "passed":
                raise HoneyGateReportError(
                    f"artifact content scan failed: {artifact['id']}"
                )
        else:
            payload = path.read_bytes()
            files_scanned += 1
            bytes_scanned += len(payload)
            findings = scan_payload(path.name, payload, [])
            if findings:
                raise HoneyGateReportError(
                    f"raw attachment content scan failed: {artifact['id']}"
                )
    suppression_records.sort(
        key=lambda row: (
            row["path"].encode("utf-8"),
            row["finding"].encode("utf-8"),
            row["authority_pattern"].encode("utf-8"),
        )
    )
    if len({tuple(row.values()) for row in suppression_records}) != len(
        suppression_records
    ):
        raise HoneyGateReportError("source scan produced duplicate suppressions")
    assertions = {
        "source_scanned": True,
        "artifacts_scanned": True,
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "findings": 0,
        "suppressions": len(suppression_records),
        "suppression_records": suppression_records,
    }
    tool = {
        "name": "cigar-package-content-scanner",
        "version": "1",
        "database_updated_at": None,
        "database_freshness": "not-applicable",
        "offline": True,
    }
    return assertions, tool


def _receipt(path: Path, schema: str, statuses: set[str]) -> dict[str, Any]:
    payload = path.read_bytes()
    receipt = load_json_bytes(payload, path.name)
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != schema
        or receipt.get("status") not in statuses
        or canonical_json_bytes(receipt) != payload
    ):
        raise HoneyGateReportError(f"SDK receipt is malformed: {path.name}")
    return receipt


def _receipt_binding(
    manifest: dict[str, Any], artifact_ids: set[str], receipt_path: Path
) -> None:
    references = [
        row["producer_receipt"]
        for row in manifest["artifacts"]
        if row["id"] in artifact_ids
    ]
    if not references or any(
        reference["sha256"] != sha256_file(receipt_path)
        or reference["bytes"] != receipt_path.stat().st_size
        for reference in references
    ):
        raise HoneyGateReportError("SDK receipt is not bound by the candidate manifest")


def _audit_tool(root: Path) -> tuple[dict[str, Any], bool]:
    version = run_bounded(
        ["cargo", "audit", "--version"],
        cwd=root,
        env=_environment(),
        timeout=30,
        max_stdout=4096,
        max_stderr=4096,
    )
    if version.returncode != 0:
        return (
            {
                "name": "cigar-offline-lock-validator",
                "version": "1",
                "database_updated_at": None,
                "database_freshness": "not-applicable",
                "offline": True,
            },
            False,
        )
    audit = run_bounded(
        ["cargo", "audit", "--no-fetch", "--json"],
        cwd=root,
        env=_environment(),
        timeout=120,
        max_stdout=32 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if audit.returncode != 0:
        raise HoneyGateReportError("cached Rust advisory audit failed")
    document = load_json_bytes(audit.stdout, "cargo audit report")
    if document.get("vulnerabilities", {}).get("found") is not False:
        raise HoneyGateReportError("cached Rust advisory audit found a vulnerability")
    advisory_root = Path.home() / ".cargo/advisory-db"
    updated = run_bounded(
        ["git", "-C", os.fspath(advisory_root), "log", "-1", "--format=%cI"],
        cwd=root,
        timeout=30,
        max_stdout=4096,
        max_stderr=4096,
    )
    if updated.returncode != 0:
        return (
            {
                "name": "cargo-audit",
                "version": version.stdout.decode("utf-8", errors="strict").strip(),
                "database_updated_at": None,
                "database_freshness": "not-applicable",
                "offline": True,
            },
            True,
        )
    parsed = datetime.fromisoformat(updated.stdout.decode().strip()).astimezone(
        timezone.utc
    )
    timestamp = parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        {
            "name": "cargo-audit",
            "version": version.stdout.decode("utf-8", errors="strict").strip(),
            "database_updated_at": timestamp,
            "database_freshness": "current",
            "offline": True,
        },
        True,
    )


def _offline_dependencies(
    root: Path,
    manifest: dict[str, Any],
    typescript_receipt: Path,
    python_receipt: Path,
    rust_receipt: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    typescript = _receipt(
        typescript_receipt,
        "cigar.development-typescript-sdk-build.v1",
        {"built-unqualified"},
    )
    python = _receipt(
        python_receipt,
        "cigar.development-python-sdk-build.v1",
        {"built-unqualified"},
    )
    rust = _receipt(
        rust_receipt,
        "cigar.honey-rust-sdk-local-registry-build.v1",
        {"honey-built-unqualified"},
    )
    _receipt_binding(manifest, {"typescript-sdk"}, typescript_receipt)
    _receipt_binding(manifest, {"python-sdk-wheel", "python-sdk-sdist"}, python_receipt)
    _receipt_binding(manifest, {"rust-sdk-local-registry"}, rust_receipt)
    if (
        typescript.get("clean_install_validation", {}).get("status")
        != "passed-semantic-workflow"
        or python.get("clean_install_validation", {}).get("status") != "passed"
        or rust.get("kit_validation", {}).get("qualification", {}).get("status")
        != "passed"
    ):
        raise HoneyGateReportError("one SDK offline consumer qualification is absent")

    cargo_lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    uv_lock = tomllib.loads((root / "sdk/python/uv.lock").read_text(encoding="utf-8"))
    pnpm_text = (root / "pnpm-lock.yaml").read_text(encoding="utf-8")
    cargo_count = len(cargo_lock.get("package", []))
    python_count = len(uv_lock.get("package", []))
    npm_count = len(re.findall(r"^  [^ #][^:]*:\s*$", pnpm_text, flags=re.MULTILINE))
    resolved = cargo_count + python_count + npm_count
    if cargo_count <= 0 or python_count <= 0 or npm_count <= 0:
        raise HoneyGateReportError("one selected lockfile has no dependency inventory")
    metadata = run_bounded(
        [
            "cargo",
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
            "--no-deps",
        ],
        cwd=root,
        env=_environment(),
        timeout=300,
        max_stdout=64 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if metadata.returncode != 0:
        raise HoneyGateReportError("Cargo.lock does not resolve offline and locked")
    tool, database_available = _audit_tool(root)
    return (
        {
            "lockfiles": ["Cargo.lock", "pnpm-lock.yaml", "sdk/python/uv.lock"],
            "ecosystems": ["cargo", "npm", "python"],
            "lock_integrity_passed": True,
            "offline_resolution_passed": True,
            "resolved_dependencies": resolved,
            "unresolved_dependencies": 0,
            "advisory_database_available": database_available,
        },
        tool,
    )


def _report(
    kind: str,
    source: dict[str, Any],
    artifacts: list[dict[str, Any]],
    assertions: dict[str, Any],
    tool: dict[str, Any] | None,
    root: Path,
) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA,
        "report_kind": kind,
        "status": "passed",
        "product_version": VERSION,
        "context_abi": CONTEXT_ABI,
        "source": source,
        "artifacts": artifacts,
        "producer": {
            "path": PRODUCER_PATH,
            "sha256": sha256_file(root / PRODUCER_PATH),
        },
        "tool": tool,
        "assertions": assertions,
    }


def produce(arguments: argparse.Namespace) -> dict[str, dict[str, Any]]:
    root = arguments.root.resolve(strict=True)
    candidate = arguments.candidate.resolve(strict=True)
    descriptor_path = arguments.source_descriptor.resolve(strict=True)
    source = _source(root, descriptor_path)
    artifacts, manifest, matrix_rows = _candidate(root, candidate)
    bounded = _bounded_checks(root)
    if _source(root, descriptor_path) != source:
        raise HoneyGateReportError("source tree changed during bounded safety checks")
    secret, secret_tool = _secret_scan(root, candidate, matrix_rows)
    dependencies, dependency_tool = _offline_dependencies(
        root,
        manifest,
        arguments.typescript_receipt.resolve(strict=True),
        arguments.python_receipt.resolve(strict=True),
        arguments.rust_receipt.resolve(strict=True),
    )
    reports = {
        "bounded-safety-report.json": _report(
            "bounded-safety", source, artifacts, bounded, None, root
        ),
        "secret-scan.json": _report(
            "secret-scan", source, artifacts, secret, secret_tool, root
        ),
        "offline-dependency-check.json": _report(
            "offline-dependency-check",
            source,
            artifacts,
            dependencies,
            dependency_tool,
            root,
        ),
    }
    output = arguments.evidence_dir
    if output is None:
        environment = os.environ.get("CIGAR_EVIDENCE_DIR")
        output = Path(environment) if environment else None
    if output is None:
        raise HoneyGateReportError("--evidence-dir or CIGAR_EVIDENCE_DIR is required")
    with EvidenceWorkspace.create(output, repository_root=root) as workspace:
        workspace.read_files(set(), strict_read_only=False)
        for name, report in reports.items():
            workspace.write_json(name, report)
        workspace.read_files(set(reports), strict_read_only=True)
    if _source(root, descriptor_path) != source:
        raise HoneyGateReportError(
            "source tree changed while gate reports were published"
        )
    return reports


def main() -> int:
    reports = produce(parse_arguments())
    summary = {
        "schema_version": "cigar.honey.gate-report-build.v1",
        "status": "passed",
        "reports": sorted(reports),
    }
    print(canonical_json_bytes(summary).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        HoneyGateReportError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"Honey gate report build failed: {error}") from error
