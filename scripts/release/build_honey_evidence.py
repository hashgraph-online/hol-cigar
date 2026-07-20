#!/usr/bin/env python3
"""Build or non-mutatingly check the internal CIGAR Honey evidence ledger.

The ledger is deliberately not a public release attachment.  It is an internal,
content-bound qualification input that records exactly which source, candidate
bytes, and bounded reports justify the Honey developer-preview claim.  All
inputs and outputs live in create-new, owner-only ``EvidenceWorkspace`` roots;
the source repository is authority only and is never used as an evidence sink.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import honey_efficiency_contract

from evidence_workspace import (
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    canonical_json_bytes as workspace_canonical_json_bytes,
    safe_relative_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    matches,
    repo_root,
    selected_evidence_directory,
    validate_content_scan_exemptions,
)
from source_descriptor import SourceDescriptorError, validate_source_descriptor


LEDGER_SCHEMA_VERSION = "cigar.honey.evidence.v1"
INPUT_SCHEMA_VERSION = "cigar.honey.evidence-input.v1"
CHECK_SCHEMA_VERSION = "cigar.honey.evidence-check.v1"
LEDGER_NAME = "honey-evidence.json"
INPUT_NAME = "honey-evidence-input.json"
EXPECTED_VERSION = "0.9.1-honey.1"
EXPECTED_ABI = "cigar.context.v1"
EXPECTED_STATE = "developer-preview"
EXPECTED_PROFILE = "cigar.honey.local-developer-preview.macos-arm64.v1"
EVIDENCE_ROOT_DOMAIN = b"cigar.honey.evidence-root.v1\x00"
QUICKSTART_IDENTITY = (
    "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"
)
GATE_REPORT_SCHEMA = "cigar.honey.gate-report.v1"
GATE_REPORT_PRODUCER = "scripts/release/build_honey_gate_reports.py"

PRODUCT_PATH = "packaging/product-version.v1.json"
PROFILE_PATH = "packaging/honey/capability-profile.v1.json"
OWNERSHIP_PATH = "packaging/honey/capability-ownership.v1.json"
MATRIX_PATH = "packaging/honey/artifact-matrix.v1.json"
REQUIREMENTS_PATH = "packaging/honey/release-requirements.v1.json"
SCHEMA_PATH = "packaging/honey/schemas/honey-evidence.v1.schema.json"

AUTHORITY_PATHS = {
    "artifact-matrix": MATRIX_PATH,
    "capability-ownership": OWNERSHIP_PATH,
    "capability-profile": PROFILE_PATH,
    "honey-evidence-schema": SCHEMA_PATH,
    "product-version": PRODUCT_PATH,
    "release-requirements": REQUIREMENTS_PATH,
}

# This inventory is intentionally closed.  It is the concrete Honey projection
# of artifact-matrix internal inputs plus the three bounded security checks
# required by HNY-810.  A caller cannot make an extra report release-authoritative
# merely by adding it to an input document.
REQUIRED_EVIDENCE: dict[str, str] = {
    "bounded-safety-report": "tests",
    "claude-lifecycle-report": "integration",
    "documentation-report": "docs",
    "efficiency-reliability-report": "workflow",
    "installed-runtime-report": "workflow",
    "license-inventory": "security",
    "offline-dependency-check": "security",
    "other-demo-reports": "demo",
    "python-clean-install": "integration",
    "qualification-tools": "tests",
    "rust-clean-consumer": "integration",
    "secret-scan": "security",
    "two-agent-demo-report": "demo",
    "typescript-clean-install": "integration",
}

ACCEPTED_REPORT_SCHEMAS = {
    "bounded-safety-report": GATE_REPORT_SCHEMA,
    "claude-lifecycle-report": (
        "cigar.development-claude-plugin-installed-qualification.v2"
    ),
    "documentation-report": "cigar.docs-check.v1",
    "efficiency-reliability-report": (honey_efficiency_contract.REPORT_SCHEMA_VERSION),
    "installed-runtime-report": "cigar.install-qualification.v1",
    "license-inventory": "cigar.third-party-license-inventory.v1",
    "offline-dependency-check": GATE_REPORT_SCHEMA,
    "other-demo-reports": "cigar.honey-installed-demo-report.v1",
    "python-clean-install": "cigar.development-python-sdk-build.v1",
    "qualification-tools": "cigar.conformance-result.v1",
    "rust-clean-consumer": "cigar.honey-rust-sdk-local-registry-build.v1",
    "secret-scan": GATE_REPORT_SCHEMA,
    "two-agent-demo-report": "cigar.honey-installed-demo-report.v1",
    "typescript-clean-install": "cigar.development-typescript-sdk-build.v1",
}

BOUNDED_SAFETY_CHECKS = (
    "cargo-fmt",
    "cargo-clippy",
    "focused-tests",
    "protocol-parity",
    "canonical-schema-vectors",
    "two-agent-acceptance-reauthorization",
    "policy-denied-nondisclosure",
    "effect-pre-intent-unreachable",
    "effect-unknown-no-blind-retry",
    "effect-duplicate-delivery",
    "malformed-api-mcp",
    "package-negative-verification",
    "local-admin-loopback-default",
    "demos-observational-no-egress",
)

# Each report must justify this exact gate set.  The ledger rejects both omitted
# bindings and caller-selected cross-domain promotion (for example, using a docs
# report as conformance proof).
EVIDENCE_GATE_POLICY: dict[str, frozenset[str]] = {
    "bounded-safety-report": frozenset(
        {
            "authority-drift",
            "clean-committed-source",
            "focused-tests",
            "archive-contracts",
            "policy-nondisclosure",
            "effect-unknown-recovery",
            "offline-replay",
            "prompt-injection-defense",
            "artifact-checksums",
        }
    ),
    "claude-lifecycle-report": frozenset(
        {"claude-lifecycle", "archive-contracts", "policy-nondisclosure"}
    ),
    "documentation-report": frozenset({"docs-commands-links"}),
    "efficiency-reliability-report": frozenset(
        {
            "storage-format-v5",
            "v4-v5-migration",
            "revision-recovery",
            "storage-amplification",
            "serial-latency",
            "startup-readiness",
            "context-quality-efficiency",
        }
    ),
    "installed-runtime-report": frozenset(
        {
            "installed-runtime",
            "archive-contracts",
            "policy-nondisclosure",
            "effect-unknown-recovery",
            "offline-replay",
        }
    ),
    "license-inventory": frozenset({"license-notice"}),
    "offline-dependency-check": frozenset(
        {"clean-committed-source", "archive-contracts"}
    ),
    "other-demo-reports": frozenset(
        {"effect-unknown-recovery", "offline-replay", "prompt-injection-defense"}
    ),
    "python-clean-install": frozenset({"sdk-clean-installs", "archive-contracts"}),
    "qualification-tools": frozenset({"protocol-drift", "conformance"}),
    "rust-clean-consumer": frozenset({"sdk-clean-installs", "archive-contracts"}),
    "secret-scan": frozenset({"policy-nondisclosure"}),
    "two-agent-demo-report": frozenset(
        {"two-agent-authority", "prompt-injection-defense"}
    ),
    "typescript-clean-install": frozenset({"sdk-clean-installs", "archive-contracts"}),
}

ALL_HONEY_ARTIFACT_IDS = frozenset(
    {
        "source",
        "docs",
        "schemas-conformance",
        "macos-runtime-aarch64",
        "typescript-sdk",
        "python-sdk-wheel",
        "python-sdk-sdist",
        "rust-sdk-local-registry",
        "claude-code-plugin",
        "honey-demos",
        "release-notes",
        "release-manifest",
        "checksums",
    }
)
EVIDENCE_ARTIFACT_POLICY: dict[str, frozenset[str]] = {
    "bounded-safety-report": ALL_HONEY_ARTIFACT_IDS,
    "claude-lifecycle-report": frozenset(
        {"macos-runtime-aarch64", "claude-code-plugin"}
    ),
    "documentation-report": frozenset({"docs", "release-notes"}),
    "efficiency-reliability-report": frozenset(
        {"macos-runtime-aarch64", "release-manifest"}
    ),
    "installed-runtime-report": frozenset({"macos-runtime-aarch64"}),
    "license-inventory": ALL_HONEY_ARTIFACT_IDS,
    "offline-dependency-check": ALL_HONEY_ARTIFACT_IDS,
    "other-demo-reports": frozenset(
        {"macos-runtime-aarch64", "claude-code-plugin", "honey-demos"}
    ),
    "python-clean-install": frozenset({"python-sdk-wheel", "python-sdk-sdist"}),
    "qualification-tools": frozenset({"schemas-conformance"}),
    "rust-clean-consumer": frozenset({"rust-sdk-local-registry"}),
    "secret-scan": ALL_HONEY_ARTIFACT_IDS,
    "two-agent-demo-report": frozenset(
        {"macos-runtime-aarch64", "python-sdk-wheel", "honey-demos"}
    ),
    "typescript-clean-install": frozenset({"typescript-sdk"}),
}

PRODUCTION_TRUE_KEYS = frozenset(
    {
        "apple_notarized",
        "ga",
        "notarized",
        "production_qualified",
        "production_ready",
        "production_supported",
        "public_multi_tenant_safe",
        "qualified",
        "release",
        "release_ready",
        "supported",
        "v1_qualified",
        "v1_supported",
    }
)
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z")
SCHEMA_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
MAX_FILE_BYTES = 64 * 1024 * 1024
# Public Honey attachments are already constrained by the closed artifact
# contracts and verifier to 512 MiB each. Give only the candidate workspace
# that bounded headroom; authority, source, and report inputs keep the tighter
# EvidenceLimits defaults.
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_CANDIDATE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
CANDIDATE_WORKSPACE_LIMITS = EvidenceLimits(
    max_files=13,
    max_directories=1,
    max_file_bytes=MAX_ARTIFACT_BYTES,
    max_total_bytes=MAX_CANDIDATE_TOTAL_BYTES,
    max_path_depth=1,
)


class HoneyEvidenceError(RuntimeError):
    """The Honey evidence projection is incomplete, stale, or unsafe."""


@dataclass(frozen=True)
class Authority:
    root: Path
    product: dict[str, Any]
    profile: dict[str, Any]
    ownership: dict[str, Any]
    matrix: dict[str, Any]
    requirements: dict[str, Any]
    bindings: dict[str, dict[str, object]]


@dataclass(frozen=True)
class WorkspaceSelection:
    name: str
    path: Path


def _fail(message: str) -> None:
    raise HoneyEvidenceError(message)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _binding(payload: bytes, **fields: object) -> dict[str, object]:
    return {**fields, "sha256": _digest(payload), "bytes": len(payload)}


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _safe_path(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a relative path")
    try:
        return "/".join(safe_relative_path(value))
    except EvidenceWorkspaceError as error:
        raise HoneyEvidenceError(f"{label} is unsafe: {error}") from error


def _canonical_document(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = load_json_bytes(payload, label)
    except ReleaseError as error:
        raise HoneyEvidenceError(str(error)) from error
    if not isinstance(document, dict):
        _fail(f"{label} must be a JSON object")
    if payload != canonical_json_bytes(document):
        _fail(f"{label} is not canonical JSON")
    return document


def _authority_document(root: Path, relative: str) -> tuple[dict[str, Any], bytes]:
    path = root / relative
    try:
        payload = path.read_bytes()
        document = load_json(path)
    except (OSError, ReleaseError) as error:
        raise HoneyEvidenceError(
            f"cannot load Honey authority {relative}: {error}"
        ) from error
    if not isinstance(document, dict):
        _fail(f"Honey authority is not a JSON object: {relative}")
    return document, payload


def _unique_rows(
    value: object,
    *,
    label: str,
    expected_keys: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    rows: list[dict[str, Any]] = []
    indexed: dict[str, dict[str, Any]] = {}
    aliases: set[str] = set()
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            _fail(f"{label}[{index}] must be an object")
        if expected_keys is not None and set(row) != expected_keys:
            _fail(f"{label}[{index}] has an unexpected shape")
        identifier = row.get("id")
        if not _is_identifier(identifier):
            _fail(f"{label}[{index}] has an invalid id")
        alias = identifier.casefold()
        if alias in aliases:
            _fail(
                f"{label} contains a duplicate or portable-colliding id: {identifier}"
            )
        aliases.add(alias)
        rows.append(row)
        indexed[identifier] = row
    return rows, indexed


def _load_authority(root: Path) -> Authority:
    documents: dict[str, dict[str, Any]] = {}
    bindings: dict[str, dict[str, object]] = {}
    for identifier, relative in AUTHORITY_PATHS.items():
        document, payload = _authority_document(root, relative)
        documents[identifier] = document
        bindings[identifier] = _binding(payload, path=relative)

    product = documents["product-version"]
    profile = documents["capability-profile"]
    ownership = documents["capability-ownership"]
    matrix = documents["artifact-matrix"]
    requirements = documents["release-requirements"]
    for identifier, document in documents.items():
        claim_path = _has_true_production_claim(document)
        if claim_path is not None:
            _fail(
                f"Honey authority {identifier} asserts a production claim at {claim_path}"
            )

    expected_product = {
        "schema_version": "cigar.product-version.v1",
        "product": "cigar",
        "version": EXPECTED_VERSION,
        "target_release_version": "0.9.1",
        "context_abi": EXPECTED_ABI,
        "release_state": EXPECTED_STATE,
        "channel": "honey",
        "prerelease": True,
        "published": False,
        "supported": False,
        "tag": f"v{EXPECTED_VERSION}",
    }
    if product != expected_product:
        _fail("product-version authority is not the exact Honey developer preview")
    identity = profile.get("identity")
    if (
        profile.get("schema_version") != "cigar.honey.capability-profile.v1"
        or profile.get("profile_id") != EXPECTED_PROFILE
        or profile.get("fail_closed") is not True
        or not isinstance(identity, dict)
        or identity.get("product_version") != EXPECTED_VERSION
        or identity.get("context_abi") != EXPECTED_ABI
        or identity.get("release_state") != EXPECTED_STATE
        or identity.get("prerelease") is not True
        or identity.get("published") is not False
        or identity.get("supported") is not False
        or identity.get("production_qualified") is not False
    ):
        _fail("capability profile is stale or asserts a production claim")
    if (
        matrix.get("schema_version") != "cigar.honey.artifact-matrix.v1"
        or matrix.get("profile_id") != EXPECTED_PROFILE
        or matrix.get("product_version") != EXPECTED_VERSION
        or matrix.get("context_abi") != EXPECTED_ABI
        or matrix.get("release_state") != EXPECTED_STATE
        or matrix.get("fail_closed") is not True
    ):
        _fail("artifact matrix is stale relative to Honey authority")
    if (
        requirements.get("schema_version") != "cigar.honey.release-requirements.v1"
        or requirements.get("profile_id") != EXPECTED_PROFILE
        or requirements.get("evidence_class") != EXPECTED_STATE
        or requirements.get("fail_closed") is not True
        or requirements.get("machine_claims")
        != {
            "prerelease": True,
            "production_qualified": False,
            "supported": False,
        }
    ):
        _fail("release requirements are stale or assert a production claim")
    if (
        ownership.get("schema_version") != "cigar.honey.capability-ownership.v1"
        or ownership.get("profile_id") != EXPECTED_PROFILE
        or ownership.get("fail_closed") is not True
    ):
        _fail("capability ownership authority is stale")

    expected_authority = {
        "artifact_matrix": {
            "path": MATRIX_PATH,
            "sha256": bindings["artifact-matrix"]["sha256"],
        },
        "capability_profile": {
            "path": PROFILE_PATH,
            "sha256": bindings["capability-profile"]["sha256"],
        },
    }
    if requirements.get("authority_bindings") != expected_authority:
        _fail("release-requirements authority bindings are stale")
    if ownership.get("authority_bindings") != expected_authority:
        _fail("capability-ownership authority bindings are stale")

    profile_caps, profile_by_id = _unique_rows(
        profile.get("capabilities"), label="capability profile capabilities"
    )
    ownership_rows, ownership_by_id = _unique_rows(
        ownership.get("surfaces"), label="capability ownership surfaces"
    )
    if [row["id"] for row in profile_caps] != [row["id"] for row in ownership_rows]:
        _fail("capability profile and ownership inventories differ or are reordered")
    for identifier, row in profile_by_id.items():
        if row != {
            "id": identifier,
            "status": "required",
            "support_level": "developer-preview",
        }:
            _fail(
                f"capability {identifier} is not a required developer-preview surface"
            )
        owned = ownership_by_id[identifier]
        if set(owned) != {
            "id",
            "implementation_paths",
            "artifact_ids",
            "guide_paths",
            "demo_ids",
            "fast_acceptance_tests",
        }:
            _fail(f"capability ownership row {identifier} has an unexpected shape")

    artifact_rows, artifact_by_id = _unique_rows(
        matrix.get("artifacts"), label="Honey artifact matrix"
    )
    if len(artifact_rows) != 13 or profile.get("artifact_ids") != [
        row["id"] for row in artifact_rows
    ]:
        _fail("Honey authority must select the exact ordered 13-artifact projection")
    if set(artifact_by_id) != ALL_HONEY_ARTIFACT_IDS:
        _fail("Honey artifact authority differs from the evidence policy inventory")
    filenames: set[str] = set()
    orders: list[int] = []
    for row in artifact_rows:
        required = {
            "id",
            "kind",
            "filename",
            "contract",
            "producer",
            "workspace",
            "generated_by_assembler",
            "public_attachment",
            "required",
            "receipt",
            "qualification_gate_ids",
            "sha256_required",
            "order",
        }
        if set(row) != required:
            _fail(f"artifact matrix row {row['id']} has an unexpected shape")
        filename = _safe_path(row.get("filename"), f"artifact {row['id']} filename")
        if "/" in filename:
            _fail(f"artifact {row['id']} filename must be a basename")
        alias = filename.casefold()
        if alias in filenames:
            _fail(f"artifact filename is duplicated or colliding: {filename}")
        filenames.add(alias)
        if row.get("public_attachment") is not True or row.get("required") is not True:
            _fail(f"artifact {row['id']} is not a required public attachment")
        if row.get("sha256_required") is not True:
            _fail(f"artifact {row['id']} does not require a SHA-256 binding")
        order = row.get("order")
        if isinstance(order, bool) or not isinstance(order, int):
            _fail(f"artifact {row['id']} order is invalid")
        orders.append(order)
    if orders != list(range(1, 14)):
        _fail("artifact matrix order must be the exact sequence 1..13")
    for row in ownership_rows:
        ids = row.get("artifact_ids")
        if (
            not isinstance(ids, list)
            or not ids
            or any(identifier not in artifact_by_id for identifier in ids)
            or len(ids) != len(set(ids))
        ):
            _fail(f"capability {row['id']} has stale artifact references")

    return Authority(
        root=root,
        product=product,
        profile=profile,
        ownership=ownership,
        matrix=matrix,
        requirements=requirements,
        bindings=bindings,
    )


def _parse_workspace(value: str) -> WorkspaceSelection:
    try:
        name, raw_path = value.split("=", 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "workspace must use NAME=/absolute/path"
        ) from error
    if not _is_identifier(name):
        raise argparse.ArgumentTypeError("workspace name is not a safe identifier")
    path = Path(raw_path)
    if not path.is_absolute() or os.path.normpath(raw_path) != raw_path:
        raise argparse.ArgumentTypeError(
            "workspace path must be canonical and absolute"
        )
    return WorkspaceSelection(name=name, path=path)


def _workspace_map(
    selections: Sequence[WorkspaceSelection], *, reserved: set[str] | None = None
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    paths: set[str] = set()
    for selection in selections:
        if selection.name in result or (reserved and selection.name in reserved):
            _fail(f"workspace name is duplicated or reserved: {selection.name}")
        lexical = os.fspath(selection.path)
        if lexical in paths:
            _fail(f"workspace path is selected more than once: {lexical}")
        paths.add(lexical)
        result[selection.name] = selection.path
    return result


def _open_exact_workspace(
    stack: ExitStack,
    root: Path,
    repository: Path,
    expected: set[str],
    *,
    limits: EvidenceLimits | None = None,
) -> tuple[EvidenceWorkspace, dict[str, bytes]]:
    try:
        workspace = stack.enter_context(
            EvidenceWorkspace.create(
                root,
                repository_root=repository,
                limits=limits,
            )
        )
        payloads = workspace.read_files(frozenset(expected))
    except EvidenceWorkspaceError as error:
        raise HoneyEvidenceError(
            f"unsafe evidence workspace {root}: {error}"
        ) from error
    return workspace, payloads


def _validate_control(document: dict[str, Any], authority: Authority) -> None:
    if set(document) != {"schema_version", "source", "artifacts", "evidence"}:
        _fail("Honey evidence input has an unexpected shape")
    if document.get("schema_version") != INPUT_SCHEMA_VERSION:
        _fail("Honey evidence input schema identity is invalid")
    source = document.get("source")
    if not isinstance(source, dict) or set(source) != {"workspace", "path"}:
        _fail("Honey evidence input source reference is malformed")
    if not _is_identifier(source.get("workspace")):
        _fail("source workspace name is invalid")
    _safe_path(source.get("path"), "source descriptor path")

    artifacts, artifact_by_id = _unique_rows(
        document.get("artifacts"),
        label="Honey evidence input artifacts",
        expected_keys={"id", "workspace", "path"},
    )
    expected_artifacts = [row["id"] for row in authority.matrix["artifacts"]]
    if [row["id"] for row in artifacts] != expected_artifacts:
        _fail("Honey evidence input artifact inventory is missing, extra, or reordered")
    for expected in authority.matrix["artifacts"]:
        row = artifact_by_id[expected["id"]]
        if not _is_identifier(row.get("workspace")):
            _fail(f"artifact {expected['id']} workspace is invalid")
        path = _safe_path(row.get("path"), f"artifact {expected['id']} path")
        if path.rsplit("/", 1)[-1] != expected["filename"]:
            _fail(f"artifact {expected['id']} path does not name the selected bytes")

    records, record_by_id = _unique_rows(
        document.get("evidence"),
        label="Honey evidence input reports",
        expected_keys={
            "id",
            "category",
            "workspace",
            "path",
            "schema_version",
            "artifact_ids",
            "capability_ids",
            "mandatory_gate_ids",
            "tool",
        },
    )
    if set(record_by_id) != set(REQUIRED_EVIDENCE):
        _fail(
            "Honey evidence report inventory is missing or extra; "
            f"missing={sorted(set(REQUIRED_EVIDENCE) - set(record_by_id))}, "
            f"extra={sorted(set(record_by_id) - set(REQUIRED_EVIDENCE))}"
        )
    if [row["id"] for row in records] != sorted(REQUIRED_EVIDENCE):
        _fail("Honey evidence reports are not byte-sorted by id")

    capability_ids = {row["id"] for row in authority.profile["capabilities"]}
    gate_ids = {row["id"] for row in authority.requirements["mandatory_gates"]}
    artifact_ids = set(artifact_by_id)
    referenced_caps: set[str] = set()
    referenced_gates: set[str] = set()
    referenced_artifacts: set[str] = set()
    report_locations: set[tuple[str, str]] = set()
    for row in records:
        identifier = row["id"]
        if row.get("category") != REQUIRED_EVIDENCE[identifier]:
            _fail(f"evidence report {identifier} category is stale")
        if not _is_identifier(row.get("workspace")):
            _fail(f"evidence report {identifier} workspace is invalid")
        path = _safe_path(row.get("path"), f"evidence report {identifier} path")
        location = (row["workspace"], path)
        if location in report_locations:
            _fail(f"evidence report path is referenced more than once: {path}")
        report_locations.add(location)
        schema = row.get("schema_version")
        if not isinstance(schema, str) or SCHEMA_IDENTIFIER.fullmatch(schema) is None:
            _fail(f"evidence report {identifier} schema identity is invalid")
        if schema != ACCEPTED_REPORT_SCHEMAS[identifier]:
            _fail(
                f"evidence report {identifier} must use the closed accepted schema "
                f"{ACCEPTED_REPORT_SCHEMAS[identifier]}"
            )
        for key, allowed in (
            ("artifact_ids", artifact_ids),
            ("capability_ids", capability_ids),
            ("mandatory_gate_ids", gate_ids),
        ):
            values = row.get(key)
            if (
                not isinstance(values, list)
                or not values
                or any(
                    not isinstance(value, str) or value not in allowed
                    for value in values
                )
                or len(values) != len(set(values))
                or values != sorted(values, key=lambda value: value.encode("utf-8"))
            ):
                _fail(f"evidence report {identifier} has invalid {key}")
        referenced_artifacts.update(row["artifact_ids"])
        referenced_caps.update(row["capability_ids"])
        referenced_gates.update(row["mandatory_gate_ids"])
        if not set(row["mandatory_gate_ids"]).issubset(
            EVIDENCE_GATE_POLICY[identifier]
        ):
            _fail(f"evidence report {identifier} claims an unrelated mandatory gate")
        if set(row["mandatory_gate_ids"]) != EVIDENCE_GATE_POLICY[identifier]:
            _fail(f"evidence report {identifier} has a stale mandatory-gate policy")
        if set(row["artifact_ids"]) != EVIDENCE_ARTIFACT_POLICY[identifier]:
            _fail(f"evidence report {identifier} has a stale artifact binding policy")
        tool = row.get("tool")
        if row["category"] == "security":
            if not isinstance(tool, dict) or set(tool) != {
                "name",
                "version",
                "database_updated_at",
                "database_freshness",
                "offline",
            }:
                _fail(f"security evidence report {identifier} lacks tool freshness")
            if (
                not isinstance(tool.get("name"), str)
                or not tool["name"]
                or not isinstance(tool.get("version"), str)
                or not tool["version"]
                or tool.get("database_freshness") not in {"current", "not-applicable"}
                or tool.get("offline") is not True
            ):
                _fail(f"security evidence report {identifier} tool metadata is invalid")
            updated = tool.get("database_updated_at")
            if tool["database_freshness"] == "current":
                if (
                    not isinstance(updated, str)
                    or UTC_TIMESTAMP.fullmatch(updated) is None
                ):
                    _fail(
                        f"security evidence report {identifier} database timestamp is invalid"
                    )
            elif updated is not None:
                _fail(
                    f"security evidence report {identifier} non-database tool has a timestamp"
                )
        elif tool is not None:
            _fail(
                f"non-security evidence report {identifier} must use null tool metadata"
            )

    for label, actual, expected in (
        ("artifacts", referenced_artifacts, artifact_ids),
        ("capabilities", referenced_caps, capability_ids),
        ("mandatory gates", referenced_gates, gate_ids),
    ):
        if actual != expected:
            _fail(
                f"evidence report {label} coverage is incomplete or stale; "
                f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
            )


def _requested_files(document: dict[str, Any]) -> dict[str, set[str]]:
    requested: dict[str, set[str]] = {}

    def add(workspace: object, path: object, label: str) -> None:
        if not isinstance(workspace, str):
            _fail(f"{label} workspace is invalid")
        canonical = _safe_path(path, f"{label} path")
        files = requested.setdefault(workspace, set())
        if canonical in files:
            _fail(f"duplicate file reference in workspace {workspace}: {canonical}")
        files.add(canonical)

    source = document["source"]
    add(source["workspace"], source["path"], "source")
    for row in document["artifacts"]:
        add(row["workspace"], row["path"], f"artifact {row['id']}")
    for row in document["evidence"]:
        add(row["workspace"], row["path"], f"report {row['id']}")
    return requested


def _has_true_production_claim(value: object) -> str | None:
    stack: list[tuple[str, object]] = [("$", value)]
    while stack:
        path, current = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                normalized = key.casefold().replace("-", "_")
                child_path = f"{path}.{key}"
                if normalized in PRODUCTION_TRUE_KEYS and child is True:
                    return child_path
                if normalized in {"claim", "claims"}:
                    strings = [child] if isinstance(child, str) else child
                    if isinstance(strings, list):
                        for item in strings:
                            if isinstance(item, str) and item.casefold() in {
                                "production-ready",
                                "production-supported",
                                "production-qualified",
                                "ga",
                            }:
                                return child_path
                stack.append((child_path, child))
        elif isinstance(current, list):
            for index, child in enumerate(current):
                stack.append((f"{path}[{index}]", child))
    return None


def _positive_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _source_matches(value: object, source_git: Mapping[str, Any]) -> bool:
    return (
        isinstance(value, dict)
        and value.get("revision") == source_git["revision"]
        and value.get("committed") is True
        and value.get("clean") is True
    )


def _attachment_matches(
    value: object, artifact: Mapping[str, object], *, require_path: bool = True
) -> bool:
    if not isinstance(value, dict):
        return False
    keys = {"sha256", "bytes", *(["path"] if require_path else [])}
    if set(value) != keys:
        return False
    return (
        (not require_path or value.get("path") == artifact["filename"])
        and value.get("sha256") == artifact["sha256"]
        and value.get("bytes") == artifact["bytes"]
    )


def _require_claims_false(
    report: Mapping[str, Any], names: set[str], label: str
) -> None:
    claims = report.get("claims")
    if not isinstance(claims, dict) or any(
        claims.get(name) is not False for name in names
    ):
        _fail(f"{label} does not preserve required false release claims")


def _validate_installed_runtime(
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
) -> None:
    try:
        from qualify_install import _validate_report as validate_install_report

        validate_install_report(report)
    except (ImportError, ReleaseError) as error:
        raise HoneyEvidenceError(
            f"installed runtime report is invalid: {error}"
        ) from error
    runtime = artifacts["macos-runtime-aarch64"]
    if (
        report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or report.get("artifact_id") != "macos-runtime-aarch64"
        or report.get("artifact_sha256") != runtime["sha256"]
        or report.get("artifact_bytes") != runtime["bytes"]
        or report.get("source_revision") != source_git["revision"]
    ):
        _fail("installed runtime report is bound to stale source or artifact bytes")


def _validate_typescript(
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
) -> None:
    clean = report.get("clean_install_validation")
    dependency = clean.get("dependency") if isinstance(clean, dict) else None
    if (
        report.get("schema_version") != "cigar.development-typescript-sdk-build.v1"
        or report.get("status") != "built-unqualified"
        or report.get("artifact_id") != "typescript-sdk"
        or report.get("target") != "aarch64-apple-darwin"
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or not _source_matches(report.get("source"), source_git)
        or not _attachment_matches(report.get("archive"), artifacts["typescript-sdk"])
        or report.get("producer_declared_in_artifact_matrix") is not True
        or not isinstance(clean, dict)
        or set(clean)
        != {
            "schema_version",
            "status",
            "offline",
            "scripts",
            "dependency_mode",
            "package",
            "package_payload_tree_sha256",
            "dependency",
            "semantic_bundle_identity",
            "checks",
        }
        or clean.get("schema_version") != "cigar.typescript-sdk-clean-install.v1"
        or clean.get("status") != "passed-semantic-workflow"
        or clean.get("offline") is not True
        or clean.get("scripts") is not False
        or clean.get("dependency_mode") != "local-reviewed-package-archive"
        or clean.get("package") != f"@cigar/sdk@{EXPECTED_VERSION}"
        or not _sha256(clean.get("package_payload_tree_sha256"))
        or clean.get("semantic_bundle_identity") != QUICKSTART_IDENTITY
        or clean.get("checks")
        != {
            "materialized-package": "passed",
            "public-import": "passed",
            "release-assets": "passed",
            "semantic-workflow": "passed",
        }
        or not isinstance(dependency, dict)
        or dependency.get("name") != "@bufbuild/protobuf"
        or dependency.get("version") != "2.12.1"
        or not _sha256(dependency.get("sha256"))
        or not _positive_integer(dependency.get("bytes"))
        or not isinstance(report.get("package_verification"), dict)
        or report["package_verification"].get("status") != "passed"
    ):
        _fail(
            "TypeScript evidence is not the closed artifact-bound clean-install receipt"
        )
    claims = report.get("claims")
    if not isinstance(claims, dict) or claims.get("development_build") is not True:
        _fail("TypeScript receipt does not prove a development build")
    _require_claims_false(
        report,
        {
            "registry_signature",
            "distribution_signed",
            "installed_compatibility",
            "qualified",
            "published",
            "supported",
            "release",
        },
        "TypeScript receipt",
    )


def _validate_python(
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
) -> None:
    clean = report.get("clean_install_validation")
    clean_artifacts = clean.get("artifacts") if isinstance(clean, dict) else None
    packaged = report.get("artifacts")
    expected_ids = ["python-sdk-sdist", "python-sdk-wheel"]
    if (
        report.get("schema_version") != "cigar.development-python-sdk-build.v1"
        or report.get("status") != "built-unqualified"
        or report.get("artifact_ids") != expected_ids
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or not _source_matches(report.get("source"), source_git)
        or not isinstance(packaged, dict)
        or set(packaged) != {"sdist", "wheel"}
        or not _attachment_matches(packaged.get("sdist"), artifacts["python-sdk-sdist"])
        or not _attachment_matches(packaged.get("wheel"), artifacts["python-sdk-wheel"])
        or not isinstance(clean, dict)
        or set(clean)
        != {
            "schema_version",
            "status",
            "offline",
            "dependency_mode",
            "runtime_dependencies",
            "runtime",
            "artifacts",
        }
        or clean.get("schema_version") != "cigar.python-sdk-clean-install.v1"
        or clean.get("status") != "passed"
        or clean.get("offline") is not True
        or clean.get("dependency_mode") != "offline-exact-runtime-dependencies"
        or clean.get("runtime_dependencies") != {"protobuf": "6.33.5"}
        or clean.get("runtime") != "cpython-3.14-macos-arm64"
        or not isinstance(clean_artifacts, dict)
        or set(clean_artifacts) != {"sdist", "wheel"}
    ):
        _fail("Python evidence is not the closed artifact-bound clean-install receipt")
    for kind, identifier in (
        ("sdist", "python-sdk-sdist"),
        ("wheel", "python-sdk-wheel"),
    ):
        result = clean_artifacts[kind]
        artifact = artifacts[identifier]
        if result != {
            "artifact_sha256": artifact["sha256"],
            "artifact_bytes": artifact["bytes"],
            "identity": QUICKSTART_IDENTITY,
            "public_import": "passed",
            "agent_b_example": "passed-help",
            "status": "passed",
        }:
            _fail(f"Python {kind} clean-install evidence is stale")
    verifications = report.get("package_contract_verification")
    if (
        not isinstance(verifications, dict)
        or set(verifications) != set(expected_ids)
        or any(
            not isinstance(value, dict) or value.get("status") != "passed"
            for value in verifications.values()
        )
    ):
        _fail("Python package-contract verification evidence is incomplete")
    claims = report.get("claims")
    if not isinstance(claims, dict) or claims.get("development_build") is not True:
        _fail("Python receipt does not prove a development build")
    _require_claims_false(
        report,
        {
            "installed_compatibility",
            "distribution_signed",
            "qualified",
            "published",
            "supported",
            "release",
        },
        "Python receipt",
    )


def _validate_rust(
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
) -> None:
    kit = report.get("kit_validation")
    construction = kit.get("construction") if isinstance(kit, dict) else None
    qualification = kit.get("qualification") if isinstance(kit, dict) else None
    if (
        report.get("schema_version") != "cigar.honey-rust-sdk-local-registry-build.v1"
        or report.get("status") != "honey-built-unqualified"
        or report.get("artifact_id") != "rust-sdk-local-registry"
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or not _source_matches(report.get("source"), source_git)
        or not _attachment_matches(
            report.get("archive"), artifacts["rust-sdk-local-registry"]
        )
        or not isinstance(kit, dict)
        or set(kit) != {"construction", "qualification"}
        or not isinstance(construction, dict)
        or construction.get("status") != "built"
        or construction.get("semantic_bundle_identity") != QUICKSTART_IDENTITY
        or not isinstance(qualification, dict)
        or qualification.get("schema_version")
        != "cigar.honey-rust-sdk-kit-validation.v1"
        or qualification.get("status") != "passed"
        or qualification.get("offline") is not True
        or qualification.get("network_proxy") != "deny-loopback"
        or qualification.get("cargo_check") != "passed"
        or qualification.get("cargo_test") != "passed"
        or qualification.get("semantic_workflow") != "passed"
        or qualification.get("semantic_bundle_identity") != QUICKSTART_IDENTITY
        or not isinstance(report.get("package_verification"), dict)
        or report["package_verification"].get("status") != "passed"
    ):
        _fail("Rust evidence is not the closed artifact-bound local-consumer receipt")
    claims = report.get("claims")
    if (
        not isinstance(claims, dict)
        or claims.get("developer_preview") is not True
        or claims.get("package_contract_verified") is not True
        or claims.get("self_contained_local_registry") is not True
        or claims.get("offline_consumer_check") is not True
        or claims.get("offline_consumer_test") is not True
        or claims.get("semantic_workflow_verified") is not True
    ):
        _fail("Rust local-consumer success claims are incomplete")
    _require_claims_false(
        report,
        {
            "registry_signature",
            "distribution_signed",
            "signed",
            "notarized",
            "published",
            "supported",
            "production_qualified",
            "release",
        },
        "Rust receipt",
    )


def _validate_claude(
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
) -> None:
    source = report.get("source")
    runtime = report.get("runtime_archive")
    plugin = report.get("plugin_archive")
    failures = report.get("failure_probes")
    preservation = report.get("preservation")
    if (
        report.get("schema_version")
        != "cigar.development-claude-plugin-installed-qualification.v2"
        or report.get("status") != "passed-unqualified"
        or report.get("artifact_id") != "claude-code-plugin"
        or report.get("target") != "aarch64-apple-darwin"
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or not _source_matches(source, source_git)
        or not isinstance(runtime, dict)
        or runtime.get("sha256") != artifacts["macos-runtime-aarch64"]["sha256"]
        or runtime.get("bytes") != artifacts["macos-runtime-aarch64"]["bytes"]
        or runtime.get("verification_status") != "passed"
        or not isinstance(plugin, dict)
        or plugin.get("sha256") != artifacts["claude-code-plugin"]["sha256"]
        or plugin.get("bytes") != artifacts["claude-code-plugin"]["bytes"]
        or plugin.get("verification_status") != "passed"
        or not isinstance(failures, dict)
        or set(failures)
        != {
            "partial_plugin_denied",
            "malformed_plugin_denied",
            "daemon_unavailable_denied",
            "unauthorized_scope_denied",
            "prompt_injected_effect_denied",
            "malformed_mcp_denied",
            "malformed_hook_denied",
        }
        or any(value is not True for value in failures.values())
        or not isinstance(preservation, dict)
        or preservation.get("before_after_identical") is not True
        or not isinstance(report.get("checks"), list)
        or not report["checks"]
        or len(report["checks"]) != len(set(report["checks"]))
    ):
        _fail("Claude evidence is not the closed installed lifecycle qualification")
    claims = report.get("claims")
    if (
        not isinstance(claims, dict)
        or claims.get("development_installed_exercise") is not True
        or claims.get("exact_packaged_runtime_binaries") is not True
        or claims.get("exact_packaged_plugin_bytes") is not True
        or claims.get("no_egress_enforced") is not True
    ):
        _fail("Claude lifecycle artifact/no-egress claims are incomplete")
    _require_claims_false(
        report,
        {
            "real_claude_compatibility_qualified",
            "distribution_signed",
            "notarized",
            "candidate_qualified",
            "non_admin_qualified",
            "qualified",
            "published",
            "supported",
            "release",
        },
        "Claude qualification",
    )


def _validate_demo(
    identifier: str,
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
) -> None:
    expected_scenarios = (
        ["two-agent"]
        if identifier == "two-agent-demo-report"
        else ["offline-context", "effect-recovery-replay", "claude-mcp"]
    )
    scenarios = report.get("scenarios")
    supporting = report.get("supporting_artifacts")
    projection = dict(report)
    observed_digest = projection.pop("report_digest", None)
    expected_digest = (
        "1220"
        + hashlib.sha256(
            json.dumps(projection, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    if (
        set(report)
        != {
            "schema_version",
            "status",
            "product_version",
            "context_abi",
            "evidence_class",
            "suite",
            "selected_scenarios",
            "runtime",
            "source",
            "supporting_artifacts",
            "scenarios",
            "installed_artifact_qualified",
            "report_digest",
        }
        or report.get("schema_version") != "cigar.honey-installed-demo-report.v1"
        or report.get("status") != "installed_demo_passed"
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or report.get("evidence_class") != "cigar.honey-installed-demo.v1"
        or report.get("selected_scenarios") != expected_scenarios
        or report.get("installed_artifact_qualified") is not True
        or not _source_matches(report.get("source"), source_git)
        or not _attachment_matches(
            report.get("runtime"),
            artifacts["macos-runtime-aarch64"],
            require_path=False,
        )
        or not isinstance(scenarios, list)
        or [row.get("scenario_id") for row in scenarios if isinstance(row, dict)]
        != expected_scenarios
        or any(
            not isinstance(row, dict)
            or row.get("status") != "installed_story_passed_twice"
            or not isinstance(row.get("components"), list)
            or not row["components"]
            or any(
                not isinstance(component, dict)
                or component.get("status") != "installed_component_passed_twice"
                for component in row["components"]
            )
            for row in scenarios
        )
        or observed_digest != expected_digest
        or not isinstance(supporting, dict)
    ):
        _fail(f"{identifier} is not the closed installed Honey demo result")
    if identifier == "two-agent-demo-report":
        if set(supporting) != {"python_wheel"} or not _attachment_matches(
            supporting["python_wheel"],
            artifacts["python-sdk-wheel"],
            require_path=False,
        ):
            _fail("two-agent demo is not bound to the exact Python wheel")
    elif set(supporting) != {"claude_plugin"} or not _attachment_matches(
        supporting["claude_plugin"],
        artifacts["claude-code-plugin"],
        require_path=False,
    ):
        _fail("other Honey demos are not bound to the exact Claude plugin")


def _validate_docs(report: dict[str, Any]) -> None:
    if (
        set(report)
        != {
            "schema_version",
            "status",
            "product_version",
            "context_abi",
            "pages",
            "links",
            "code_blocks",
            "declared_commands",
            "executed_commands",
            "failed_commands",
            "executed_modes",
        }
        or report.get("schema_version") != "cigar.docs-check.v1"
        or report.get("status") != "passed"
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or not _positive_integer(report.get("pages"))
        or not _positive_integer(report.get("declared_commands"))
        or not _positive_integer(report.get("executed_commands"))
        or report.get("failed_commands") != 0
        or not isinstance(report.get("executed_modes"), list)
        or "installed-candidate" not in report["executed_modes"]
    ):
        _fail("documentation evidence is not the installed-candidate docs check")


def _validate_license(report: dict[str, Any]) -> None:
    components = report.get("components")
    if (
        set(report)
        != {
            "schema_version",
            "policy_sha256",
            "upstream_evidence_sha256",
            "upstream_evidence_record_count",
            "status",
            "component_count",
            "review_required_count",
            "components",
        }
        or report.get("schema_version") != "cigar.third-party-license-inventory.v1"
        or report.get("status") != "complete"
        or report.get("review_required_count") != 0
        or not _positive_integer(report.get("component_count"))
        or not isinstance(components, list)
        or len(components) != report["component_count"]
        or any(
            not isinstance(component, dict)
            or component.get("policy_status") != "accepted-by-policy"
            for component in components
        )
        or not _sha256(report.get("policy_sha256"))
        or not _sha256(report.get("upstream_evidence_sha256"))
    ):
        _fail("license evidence is not a complete policy-accepted locked inventory")


def _validate_conformance(report: dict[str, Any]) -> None:
    cases = report.get("cases")
    projection = dict(report)
    observed = projection.pop("result_digest", None)
    expected = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(projection, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    if (
        report.get("schema_version") != "cigar.conformance-result.v1"
        or report.get("overall") != "passed"
        or report.get("release_qualified") is not True
        or report.get("isolation") != "strict_local"
        or report.get("integrity_errors") != []
        or not isinstance(cases, list)
        or len(cases) != 24
        or any(
            not isinstance(case, dict)
            or case.get("required") is not True
            or case.get("status") != "passed"
            or case.get("actual_outcome") != case.get("expected_outcome")
            or case.get("actual_public_digest") != case.get("expected_public_digest")
            or case.get("redacted_diagnostic") is not None
            for case in cases
        )
        or observed != expected
    ):
        _fail("conformance evidence is not the complete self-bound 24-case result")


def _gate_artifact_rows(
    artifacts: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    return [
        {
            "id": artifact["id"],
            "filename": artifact["filename"],
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
        }
        for artifact in artifacts.values()
    ]


def _validate_gate_report(
    identifier: str,
    report: dict[str, Any],
    reference: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
    authority: Authority,
) -> None:
    expected_kind = {
        "bounded-safety-report": "bounded-safety",
        "secret-scan": "secret-scan",
        "offline-dependency-check": "offline-dependency-check",
    }[identifier]
    producer_path = authority.root / GATE_REPORT_PRODUCER
    try:
        producer_payload = producer_path.read_bytes()
    except OSError as error:
        raise HoneyEvidenceError(
            f"required Honey gate-report producer is unavailable: {GATE_REPORT_PRODUCER}"
        ) from error
    expected_producer = {
        "path": GATE_REPORT_PRODUCER,
        "sha256": _digest(producer_payload),
    }
    if (
        set(report)
        != {
            "schema_version",
            "report_kind",
            "status",
            "product_version",
            "context_abi",
            "source",
            "artifacts",
            "producer",
            "tool",
            "assertions",
        }
        or report.get("schema_version") != GATE_REPORT_SCHEMA
        or report.get("report_kind") != expected_kind
        or report.get("status") != "passed"
        or report.get("product_version") != EXPECTED_VERSION
        or report.get("context_abi") != EXPECTED_ABI
        or report.get("source")
        != {
            "revision": source_git["revision"],
            "tree": source_git["tree"],
            "committed": True,
            "clean": True,
        }
        or report.get("artifacts") != _gate_artifact_rows(artifacts)
        or report.get("producer") != expected_producer
        or report.get("tool") != reference["tool"]
    ):
        _fail(f"{identifier} is not the exact source/artifact-bound Honey gate report")
    assertions = report.get("assertions")
    if not isinstance(assertions, dict):
        _fail(f"{identifier} assertions are missing")
    if expected_kind == "bounded-safety":
        checks = assertions.get("checks")
        if (
            set(assertions) != {"checks", "failed_checks"}
            or assertions.get("failed_checks") != 0
            or not isinstance(checks, list)
            or [row.get("id") for row in checks if isinstance(row, dict)]
            != list(BOUNDED_SAFETY_CHECKS)
            or any(
                not isinstance(row, dict)
                or set(row)
                != {
                    "id",
                    "status",
                    "exit_code",
                    "command_sha256",
                    "stdout_sha256",
                    "stderr_sha256",
                }
                or row.get("status") != "passed"
                or row.get("exit_code") != 0
                or any(
                    not _sha256(row.get(field))
                    for field in ("command_sha256", "stdout_sha256", "stderr_sha256")
                )
                for row in checks
            )
        ):
            _fail(
                "bounded-safety report does not prove the closed Honey check inventory"
            )
    elif expected_kind == "offline-dependency-check":
        if (
            set(assertions)
            != {
                "lockfiles",
                "ecosystems",
                "lock_integrity_passed",
                "offline_resolution_passed",
                "resolved_dependencies",
                "unresolved_dependencies",
                "advisory_database_available",
            }
            or assertions.get("lockfiles")
            != ["Cargo.lock", "pnpm-lock.yaml", "sdk/python/uv.lock"]
            or assertions.get("ecosystems") != ["cargo", "npm", "python"]
            or assertions.get("lock_integrity_passed") is not True
            or assertions.get("offline_resolution_passed") is not True
            or not _positive_integer(assertions.get("resolved_dependencies"))
            or assertions.get("unresolved_dependencies") != 0
            or not isinstance(assertions.get("advisory_database_available"), bool)
        ):
            _fail("offline dependency report does not prove exact locked resolution")
    else:
        records = assertions.get("suppression_records")
        if (
            set(assertions)
            != {
                "source_scanned",
                "artifacts_scanned",
                "files_scanned",
                "bytes_scanned",
                "findings",
                "suppressions",
                "suppression_records",
            }
            or assertions.get("source_scanned") is not True
            or assertions.get("artifacts_scanned") is not True
            or not _positive_integer(assertions.get("files_scanned"))
            or not _positive_integer(assertions.get("bytes_scanned"))
            or assertions.get("findings") != 0
            or not isinstance(records, list)
            or assertions.get("suppressions") != len(records)
        ):
            _fail("secret scan report does not prove zero unsuppressed findings")
        contract = load_json(
            authority.root / "packaging/honey/contracts/source-archive.v1.json"
        )
        try:
            exemptions = validate_content_scan_exemptions(
                contract.get("content_scan_exemptions")
                if isinstance(contract, dict)
                else None
            )
        except ReleaseError as error:
            raise HoneyEvidenceError(
                f"Honey source scan exemptions are invalid: {error}"
            ) from error
        normalized: list[tuple[str, str, str]] = []
        for row in records:
            if not isinstance(row, dict) or set(row) != {
                "path",
                "finding",
                "authority_pattern",
                "authority_reason",
            }:
                _fail("secret scan suppression record shape is invalid")
            path = _safe_path(row.get("path"), "secret suppression path")
            matching = [
                exemption
                for exemption in exemptions
                if exemption["pattern"] == row.get("authority_pattern")
                and exemption["reason"] == row.get("authority_reason")
                and matches(path, [exemption["pattern"]])
                and (
                    "findings" not in exemption
                    or row.get("finding") in exemption["findings"]
                )
            ]
            if len(matching) != 1 or not _is_identifier(row.get("finding")):
                _fail(
                    "secret scan suppression is not authorized by the Honey source contract"
                )
            normalized.append(
                (path, str(row["finding"]), str(row["authority_pattern"]))
            )
        if normalized != sorted(normalized) or len(normalized) != len(set(normalized)):
            _fail("secret scan suppression records are duplicated or not byte-sorted")


def _validate_efficiency_report(
    report: dict[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
    authority: Authority,
    installed_runtime_report: Mapping[str, Any] | None,
) -> None:
    try:
        honey_efficiency_contract.validate_authorities(authority.root)
        fixtures, fixture_payload = honey_efficiency_contract.load_json(
            authority.root / honey_efficiency_contract.FIXTURE_PATH
        )
        profile, profile_payload = honey_efficiency_contract.load_json(
            authority.root / honey_efficiency_contract.PROFILE_PATH
        )
        honey_efficiency_contract.validate_fixture_manifest(fixtures, fixture_payload)
        honey_efficiency_contract.validate_qualification_profile(
            profile, profile_payload
        )
        honey_efficiency_contract.validate_report(report, fixtures, profile)
    except honey_efficiency_contract.EfficiencyContractError as error:
        raise HoneyEvidenceError(
            f"efficiency/reliability report is invalid: {error}"
        ) from error
    manifest = artifacts["release-manifest"]
    installed_binaries = (
        installed_runtime_report.get("installed_binary_sha256")
        if isinstance(installed_runtime_report, Mapping)
        else None
    )
    if (
        report.get("overall_status") != "pass"
        or report.get("source")
        != {
            "commit": source_git["revision"],
            "tree": source_git["tree"],
            "clean": True,
        }
        or report.get("candidate", {}).get("manifest_sha256") != manifest["sha256"]
        or not isinstance(installed_binaries, Mapping)
        or report.get("candidate", {}).get("installed_runtime_sha256")
        != installed_binaries.get("cigar")
    ):
        _fail(
            "efficiency/reliability report is not passing or bound to exact "
            "source/candidate/installed runtime bytes"
        )


def _validate_evidence_report(
    identifier: str,
    report: dict[str, Any],
    reference: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, object]],
    source_git: Mapping[str, Any],
    authority: Authority,
    evidence_reports: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    if report.get("schema_version") != ACCEPTED_REPORT_SCHEMAS[identifier]:
        _fail(f"report {identifier} does not use its closed accepted schema")
    if identifier in {
        "bounded-safety-report",
        "secret-scan",
        "offline-dependency-check",
    }:
        _validate_gate_report(
            identifier, report, reference, artifacts, source_git, authority
        )
    elif identifier == "installed-runtime-report":
        _validate_installed_runtime(report, artifacts, source_git)
    elif identifier == "typescript-clean-install":
        _validate_typescript(report, artifacts, source_git)
    elif identifier == "python-clean-install":
        _validate_python(report, artifacts, source_git)
    elif identifier == "rust-clean-consumer":
        _validate_rust(report, artifacts, source_git)
    elif identifier == "claude-lifecycle-report":
        _validate_claude(report, artifacts, source_git)
    elif identifier in {"two-agent-demo-report", "other-demo-reports"}:
        _validate_demo(identifier, report, artifacts, source_git)
    elif identifier == "documentation-report":
        _validate_docs(report)
    elif identifier == "efficiency-reliability-report":
        _validate_efficiency_report(
            report,
            artifacts,
            source_git,
            authority,
            (
                evidence_reports.get("installed-runtime-report")
                if evidence_reports is not None
                else None
            ),
        )
    elif identifier == "license-inventory":
        _validate_license(report)
    elif identifier == "qualification-tools":
        _validate_conformance(report)
    else:  # pragma: no cover - closed inventory makes this unreachable
        _fail(f"report {identifier} has no evidence-specific validator")


def _validate_checksum_attachment(
    artifacts: Sequence[Mapping[str, object]], payload: bytes
) -> None:
    expected_rows = sorted(
        (row for row in artifacts if row.get("id") != "checksums"),
        key=lambda row: str(row["filename"]).encode("utf-8"),
    )
    expected = b"".join(
        f"{row['sha256']}  {row['filename']}\n".encode("ascii") for row in expected_rows
    )
    if payload != expected:
        _fail(
            "SHA256SUMS does not bind the exact byte-sorted Honey attachment "
            "inventory or includes itself"
        )


def _read_inputs(
    *,
    root: Path,
    control_root: Path,
    selections: Sequence[WorkspaceSelection],
    authority: Authority,
) -> tuple[dict[str, Any], dict[str, dict[str, bytes]]]:
    with ExitStack() as stack:
        _, control_payloads = _open_exact_workspace(
            stack, control_root, root, {INPUT_NAME}
        )
        control = _canonical_document(control_payloads[INPUT_NAME], INPUT_NAME)
        _validate_control(control, authority)
        requested = _requested_files(control)
        paths = _workspace_map(selections, reserved={"control"})
        if set(paths) != set(requested):
            _fail(
                "input workspace selection is missing or extra; "
                f"missing={sorted(set(requested) - set(paths))}, "
                f"extra={sorted(set(paths) - set(requested))}"
            )
        payloads: dict[str, dict[str, bytes]] = {}
        resolved: set[Path] = {control_root.resolve(strict=True)}
        for name in sorted(paths):
            _, snapshot = _open_exact_workspace(
                stack,
                paths[name],
                root,
                requested[name],
                limits=(CANDIDATE_WORKSPACE_LIMITS if name == "candidate" else None),
            )
            real = paths[name].resolve(strict=True)
            if real in resolved:
                _fail(
                    f"evidence workspace aliases another selected root: {paths[name]}"
                )
            resolved.add(real)
            payloads[name] = snapshot
        return control, payloads


def _payload(
    payloads: Mapping[str, Mapping[str, bytes]], reference: Mapping[str, Any]
) -> bytes:
    return payloads[str(reference["workspace"])][str(reference["path"])]


def _string_array(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        _fail(f"{label} must be a non-empty unique string array")
    return list(value)


def _build_ledger(
    authority: Authority,
    control: dict[str, Any],
    payloads: dict[str, dict[str, bytes]],
) -> dict[str, Any]:
    source_ref = control["source"]
    source_payload = _payload(payloads, source_ref)
    source_document = _canonical_document(source_payload, "source descriptor")
    try:
        validate_source_descriptor(source_document)
    except SourceDescriptorError as error:
        raise HoneyEvidenceError(f"invalid source descriptor: {error}") from error
    source_git = source_document["git"]
    if source_git["committed"] is not True or source_git["clean"] is not True:
        _fail("Honey evidence requires a clean committed source descriptor")

    matrix_by_id = {row["id"]: row for row in authority.matrix["artifacts"]}
    artifacts: list[dict[str, object]] = []
    for reference in control["artifacts"]:
        row = matrix_by_id[reference["id"]]
        payload = _payload(payloads, reference)
        if not payload:
            _fail(f"artifact {row['id']} is empty")
        artifacts.append(
            _binding(
                payload,
                id=row["id"],
                kind=row["kind"],
                filename=row["filename"],
                source_revision=source_git["revision"],
                source_tree=source_git["tree"],
            )
        )
    artifact_by_id = {str(row["id"]): row for row in artifacts}
    checksum_reference = next(
        row for row in control["artifacts"] if row["id"] == "checksums"
    )
    _validate_checksum_attachment(artifacts, _payload(payloads, checksum_reference))
    source_archive = source_document["source_archive"]
    source_artifact = artifact_by_id["source"]
    if source_archive != {
        "name": source_artifact["filename"],
        "sha256": source_artifact["sha256"],
        "bytes": source_artifact["bytes"],
    }:
        _fail("source descriptor does not bind the exact Honey source attachment")

    evidence_reports: dict[str, dict[str, Any]] = {}
    evidence_payloads: dict[str, bytes] = {}
    for reference in control["evidence"]:
        report_payload = _payload(payloads, reference)
        report = _canonical_document(report_payload, f"report {reference['id']}")
        if report.get("schema_version") != reference["schema_version"]:
            _fail(f"report {reference['id']} schema identity is stale")
        claim_path = _has_true_production_claim(report)
        if claim_path is not None:
            _fail(
                f"report {reference['id']} asserts a production claim at {claim_path}"
            )
        evidence_reports[reference["id"]] = report
        evidence_payloads[reference["id"]] = report_payload

    evidence: list[dict[str, object]] = []
    for reference in control["evidence"]:
        report_payload = evidence_payloads[reference["id"]]
        report = evidence_reports[reference["id"]]
        _validate_evidence_report(
            reference["id"],
            report,
            reference,
            artifact_by_id,
            source_git,
            authority,
            evidence_reports,
        )
        report_binding = _binding(
            report_payload,
            workspace=reference["workspace"],
            path=reference["path"],
            schema_version=reference["schema_version"],
        )
        evidence.append(
            {
                "id": reference["id"],
                "category": reference["category"],
                "status": "passed",
                "report": report_binding,
                "artifact_ids": reference["artifact_ids"],
                "capability_ids": reference["capability_ids"],
                "mandatory_gate_ids": reference["mandatory_gate_ids"],
                "source_revision": source_git["revision"],
                "source_tree": source_git["tree"],
                "tool": reference["tool"],
            }
        )

    evidence_by_capability: dict[str, list[str]] = {}
    evidence_by_gate: dict[str, list[str]] = {}
    for record in evidence:
        for capability in record["capability_ids"]:  # type: ignore[union-attr]
            evidence_by_capability.setdefault(capability, []).append(str(record["id"]))
        for gate in record["mandatory_gate_ids"]:  # type: ignore[union-attr]
            evidence_by_gate.setdefault(gate, []).append(str(record["id"]))

    ownership_by_id = {row["id"]: row for row in authority.ownership["surfaces"]}
    capabilities: list[dict[str, object]] = []
    for profile_row in authority.profile["capabilities"]:
        identifier = profile_row["id"]
        owned = ownership_by_id[identifier]
        capability_artifacts = _string_array(
            owned["artifact_ids"], f"capability {identifier} artifacts"
        )
        for artifact_id in capability_artifacts:
            if artifact_id not in artifact_by_id:
                _fail(f"capability {identifier} references an absent artifact")
        records = sorted(evidence_by_capability.get(identifier, []))
        if not records:
            _fail(f"capability {identifier} has no Honey smoke evidence")
        capabilities.append(
            {
                "id": identifier,
                "implementation_paths": _string_array(
                    owned["implementation_paths"],
                    f"capability {identifier} implementation paths",
                ),
                "artifact_ids": capability_artifacts,
                "guide_paths": _string_array(
                    owned["guide_paths"], f"capability {identifier} guide paths"
                ),
                "demo_ids": _string_array(
                    owned["demo_ids"], f"capability {identifier} demo ids"
                ),
                "fast_acceptance_tests": _string_array(
                    owned["fast_acceptance_tests"],
                    f"capability {identifier} fast acceptance tests",
                ),
                "evidence_ids": records,
                "stages": {
                    "specified": True,
                    "implemented_source": True,
                    "integrated": True,
                    "packaged": True,
                    "honey_smoke_passed": True,
                    "v1_qualified": False,
                    "v1_supported": False,
                },
            }
        )

    mandatory_gates: list[dict[str, object]] = []
    for gate in authority.requirements["mandatory_gates"]:
        if gate != {
            "id": gate.get("id"),
            "required": True,
            "evidence_status": "required-not-implied",
        }:
            _fail(f"mandatory gate authority is malformed: {gate.get('id')}")
        records = sorted(evidence_by_gate.get(gate["id"], []))
        if not records:
            _fail(f"mandatory gate {gate['id']} has no passing evidence")
        mandatory_gates.append(
            {"id": gate["id"], "status": "passed", "evidence_ids": records}
        )

    deferred_gates: list[dict[str, object]] = []
    for gate in authority.requirements["deferred_gates"]:
        if (
            set(gate)
            != {
                "id",
                "required_for_honey",
                "may_be_reported_as_passed_without_evidence",
            }
            or gate.get("required_for_honey") is not False
            or gate.get("may_be_reported_as_passed_without_evidence") is not False
        ):
            _fail(f"deferred gate authority is malformed: {gate.get('id')}")
        deferred_gates.append(
            {
                "id": gate["id"],
                "status": "not-run-deferred",
                "required_for_honey": False,
            }
        )

    prohibited = authority.requirements.get("prohibited_claims")
    if (
        not isinstance(prohibited, list)
        or not prohibited
        or any(not _is_identifier(item) for item in prohibited)
        or len(prohibited) != len(set(prohibited))
    ):
        _fail("release requirements prohibited-claim inventory is invalid")
    limitations = [
        {"id": identifier, "status": "not-claimed"} for identifier in prohibited
    ]

    ledger: dict[str, Any] = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "product": {
            "version": EXPECTED_VERSION,
            "context_abi": EXPECTED_ABI,
            "release_state": EXPECTED_STATE,
            "channel": "honey",
            "profile_id": EXPECTED_PROFILE,
            "prerelease": True,
            "published": False,
            "supported": False,
            "production_ready": False,
            "production_qualified": False,
        },
        "authorities": authority.bindings,
        "source": {
            "descriptor": _binding(
                source_payload,
                workspace=source_ref["workspace"],
                path=source_ref["path"],
                schema_version="cigar.source-descriptor.v1",
            ),
            "revision": source_git["revision"],
            "tree": source_git["tree"],
            "committed": True,
            "clean": True,
        },
        "artifacts": artifacts,
        "evidence": evidence,
        "capabilities": capabilities,
        "mandatory_gates": mandatory_gates,
        "deferred_gates": deferred_gates,
        "limitations": limitations,
        "aggregate": {
            "algorithm": "sha256",
            "domain": "cigar.honey.evidence-root.v1",
            "sha256": "0" * 64,
        },
        "fail_closed": True,
    }
    root_projection = dict(ledger)
    root_projection.pop("aggregate")
    ledger["aggregate"]["sha256"] = hashlib.sha256(
        EVIDENCE_ROOT_DOMAIN + canonical_json_bytes(root_projection)
    ).hexdigest()
    _validate_ledger(ledger, authority)
    return ledger


def _validate_binding(value: object, label: str, *, with_schema: bool = False) -> None:
    required = {"workspace", "path", "sha256", "bytes"}
    if with_schema:
        required.add("schema_version")
    if not isinstance(value, dict) or set(value) != required:
        _fail(f"{label} binding has an unexpected shape")
    if not _is_identifier(value.get("workspace")):
        _fail(f"{label} workspace is invalid")
    _safe_path(value.get("path"), f"{label} path")
    if (
        not isinstance(value.get("sha256"), str)
        or SHA256.fullmatch(value["sha256"]) is None
    ):
        _fail(f"{label} SHA-256 is invalid")
    size = value.get("bytes")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 <= size <= MAX_FILE_BYTES
    ):
        _fail(f"{label} byte count is invalid")
    if with_schema and (
        not isinstance(value.get("schema_version"), str)
        or SCHEMA_IDENTIFIER.fullmatch(value["schema_version"]) is None
    ):
        _fail(f"{label} schema identity is invalid")


def _validate_ledger(ledger: object, authority: Authority) -> None:
    top_keys = {
        "schema_version",
        "product",
        "authorities",
        "source",
        "artifacts",
        "evidence",
        "capabilities",
        "mandatory_gates",
        "deferred_gates",
        "limitations",
        "aggregate",
        "fail_closed",
    }
    if not isinstance(ledger, dict) or set(ledger) != top_keys:
        _fail("Honey evidence ledger has an unexpected top-level shape")
    if (
        ledger.get("schema_version") != LEDGER_SCHEMA_VERSION
        or ledger.get("fail_closed") is not True
    ):
        _fail("Honey evidence ledger identity or fail-closed flag is invalid")
    if ledger.get("product") != {
        "version": EXPECTED_VERSION,
        "context_abi": EXPECTED_ABI,
        "release_state": EXPECTED_STATE,
        "channel": "honey",
        "profile_id": EXPECTED_PROFILE,
        "prerelease": True,
        "published": False,
        "supported": False,
        "production_ready": False,
        "production_qualified": False,
    }:
        _fail("Honey evidence product claims are stale or unsafe")
    if ledger.get("authorities") != authority.bindings:
        _fail("Honey evidence authority bindings are stale")
    source = ledger.get("source")
    if not isinstance(source, dict) or set(source) != {
        "descriptor",
        "revision",
        "tree",
        "committed",
        "clean",
    }:
        _fail("Honey evidence source binding is malformed")
    _validate_binding(source["descriptor"], "source descriptor", with_schema=True)
    if source["descriptor"]["schema_version"] != "cigar.source-descriptor.v1":
        _fail("Honey evidence source descriptor schema is stale")
    if (
        not isinstance(source.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"]) is None
        or not isinstance(source.get("tree"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["tree"]) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        _fail("Honey evidence source identity is invalid")
    claim_path = _has_true_production_claim(ledger)
    if claim_path is not None:
        _fail(f"Honey evidence ledger asserts a production claim at {claim_path}")
    aggregate = ledger.get("aggregate")
    if not isinstance(aggregate, dict) or set(aggregate) != {
        "algorithm",
        "domain",
        "sha256",
    }:
        _fail("Honey evidence aggregate is malformed")
    if (
        aggregate.get("algorithm") != "sha256"
        or aggregate.get("domain") != "cigar.honey.evidence-root.v1"
    ):
        _fail("Honey evidence aggregate algorithm/domain is stale")
    projection = dict(ledger)
    projection.pop("aggregate")
    expected_root = hashlib.sha256(
        EVIDENCE_ROOT_DOMAIN + canonical_json_bytes(projection)
    ).hexdigest()
    if aggregate.get("sha256") != expected_root:
        _fail("Honey evidence aggregate digest is stale")


def _expected_ledger(
    arguments: argparse.Namespace,
) -> tuple[Authority, dict[str, Any]]:
    root = arguments.root.resolve(strict=True)
    authority = _load_authority(root)
    control, payloads = _read_inputs(
        root=root,
        control_root=arguments.control_workspace,
        selections=arguments.workspace,
        authority=authority,
    )
    return authority, _build_ledger(authority, control, payloads)


def _build(arguments: argparse.Namespace) -> dict[str, Any]:
    authority, ledger = _expected_ledger(arguments)
    _validate_ledger(ledger, authority)
    selected = selected_evidence_directory(arguments.evidence_dir)
    if selected is None:
        _fail("build requires --evidence-dir or CIGAR_EVIDENCE_DIR")
    root = arguments.root.resolve(strict=True)
    input_roots = {
        arguments.control_workspace.resolve(strict=True),
        *(selection.path.resolve(strict=True) for selection in arguments.workspace),
    }
    try:
        with EvidenceWorkspace.create(selected, repository_root=root) as output:
            if output.root in input_roots:
                _fail("output evidence workspace aliases an input workspace")
            output.read_files(frozenset(), strict_read_only=False)
            output.write_json(arguments.out, ledger)
            stored = output.read_files(frozenset({arguments.out}))[arguments.out]
    except EvidenceWorkspaceError as error:
        raise HoneyEvidenceError(
            f"cannot publish Honey evidence ledger: {error}"
        ) from error
    if stored != canonical_json_bytes(ledger):
        _fail("published Honey evidence ledger differs from the validated bytes")
    return ledger


def _check(arguments: argparse.Namespace) -> dict[str, Any]:
    if os.environ.get("CIGAR_EVIDENCE_DIR"):
        _fail("check is non-mutating; CIGAR_EVIDENCE_DIR is not applicable")
    authority, expected = _expected_ledger(arguments)
    root = arguments.root.resolve(strict=True)
    try:
        with EvidenceWorkspace.create(
            arguments.ledger_workspace, repository_root=root
        ) as workspace:
            payload = workspace.read_files(frozenset({arguments.ledger}))[
                arguments.ledger
            ]
    except EvidenceWorkspaceError as error:
        raise HoneyEvidenceError(
            f"cannot read Honey evidence ledger: {error}"
        ) from error
    actual = _canonical_document(payload, arguments.ledger)
    _validate_ledger(actual, authority)
    if payload != canonical_json_bytes(expected) or actual != expected:
        _fail("Honey evidence ledger is stale relative to exact input bytes")
    return {
        "schema_version": CHECK_SCHEMA_VERSION,
        "status": "passed-developer-preview",
        "ledger": _binding(payload, filename=arguments.ledger),
        "evidence_root": actual["aggregate"]["sha256"],
        "production_qualified": False,
        "supported": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--root", type=Path, default=repo_root())
        command.add_argument("--control-workspace", type=Path, required=True)
        command.add_argument(
            "--workspace",
            action="append",
            type=_parse_workspace,
            default=[],
            metavar="NAME=/ABSOLUTE/PATH",
            help="exact owner-only input workspace; repeat for every logical workspace",
        )

    build = subparsers.add_parser("build", help="create a new Honey evidence ledger")
    common(build)
    build.add_argument("--evidence-dir", type=Path)
    build.add_argument(
        "--out",
        default=LEDGER_NAME,
        type=lambda value: _safe_path(value, "output path"),
    )
    build.set_defaults(handler=_build)

    check = subparsers.add_parser(
        "check", help="non-mutating exact-byte ledger validation"
    )
    common(check)
    check.add_argument("--ledger-workspace", type=Path, required=True)
    check.add_argument(
        "--ledger",
        default=LEDGER_NAME,
        type=lambda value: _safe_path(value, "ledger path"),
    )
    check.set_defaults(handler=_check)
    return parser


def main() -> int:
    try:
        arguments = _parser().parse_args()
        result = arguments.handler(arguments)
        sys.stdout.buffer.write(workspace_canonical_json_bytes(result))
        return 0
    except (HoneyEvidenceError, EvidenceWorkspaceError, OSError, ReleaseError) as error:
        print(f"honey evidence error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
