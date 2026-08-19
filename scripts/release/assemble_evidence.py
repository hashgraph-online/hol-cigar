#!/usr/bin/env python3
"""Assemble release-evidence.json and reject incomplete, stale, skipped, or tampered inputs."""

from __future__ import annotations

import argparse
import math
import os
import re
from pathlib import Path
from typing import Any

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    file_reference,
    load_json,
    repo_root,
    resolve_beneath,
    safe_relative_path,
    selected_evidence_directory,
    sha256_file,
    validate_qualification_policy,
    validate_release_policy_documents,
    write_json,
)
from verify_package import verify as verify_package


EXPECTED_FUZZ_TARGET_COUNT = 19


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--build-manifest", default="build-manifest.json")
    parser.add_argument("--evidence-directory", default="evidence")
    parser.add_argument("--signature-directory", default="signatures")
    parser.add_argument("--matrix", default="packaging/artifact-matrix.v1.json")
    parser.add_argument(
        "--requirements", default="packaging/release-requirements.v1.json"
    )
    parser.add_argument("--out", default="release-evidence.json")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external output workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--allow-development", action="store_true")
    return parser.parse_args()


def _inside(base: Path, supplied: str) -> Path:
    return resolve_beneath(base, supplied)


def _publish_assembled(
    arguments: argparse.Namespace,
    *,
    root: Path,
    dist: Path,
    occupied_paths: set[Path],
    document: dict[str, Any],
) -> None:
    """Publish to pinned external evidence or the legacy distribution path."""

    selected = selected_evidence_directory(arguments.evidence_dir)
    if selected is None:
        output_path = dist / safe_relative_path(arguments.out)
        if output_path.resolve() in occupied_paths:
            raise ReleaseError("release evidence output overlaps an input payload")
        write_json(output_path, document)
        return

    try:
        parts = safe_evidence_path(os.fspath(arguments.out))
        workspace = EvidenceWorkspace.create(selected, repository_root=root)
    except EvidenceWorkspaceError as error:
        raise ReleaseError(f"unsafe evidence workspace: {error}") from error
    try:
        output_path = workspace.root.joinpath(*parts)
        if output_path.resolve(strict=False) in occupied_paths:
            raise ReleaseError("release evidence output overlaps an input payload")
        workspace.write_json("/".join(parts), document)
    except EvidenceWorkspaceError as error:
        raise ReleaseError(f"cannot publish release evidence: {error}") from error
    finally:
        workspace.close()


def _artifact_ids(matrix: dict[str, Any]) -> set[str]:
    result = {
        entry["id"]
        for entry in matrix.get("artifacts", [])
        if entry.get("required_for_release") is True
    }
    if not result:
        raise ReleaseError("artifact matrix has no required artifacts")
    return result


def _validate_receipt(
    receipt: Any,
    path: Path,
    dist: Path,
    source_revision: str,
    artifact_ids: set[str],
    prohibited: set[str],
) -> dict[str, Any]:
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != "cigar.qualification-evidence.v1"
    ):
        raise ReleaseError(f"unsupported evidence receipt: {path}")
    required = {
        "schema_version",
        "id",
        "category",
        "source_revision",
        "status",
        "artifact_ids",
        "producer",
        "checks",
        "metrics",
        "attachments",
    }
    if set(receipt) != required:
        raise ReleaseError(f"evidence receipt has an unexpected shape: {path}")
    if receipt["source_revision"] != source_revision:
        raise ReleaseError(f"evidence is for the wrong source revision: {path}")
    if receipt["status"] in prohibited or receipt["status"] != "passed":
        raise ReleaseError(f"evidence is not passing: {path}")
    referenced = receipt["artifact_ids"]
    if (
        not isinstance(referenced, list)
        or not referenced
        or len(set(referenced)) != len(referenced)
        or any(value not in artifact_ids for value in referenced)
    ):
        raise ReleaseError(f"evidence references an unknown artifact: {path}")
    checks = receipt["checks"]
    if (
        not isinstance(checks, list)
        or not checks
        or any(
            not isinstance(check, dict)
            or set(check) != {"id", "status"}
            or check.get("status") != "passed"
            for check in checks
        )
    ):
        raise ReleaseError(
            f"evidence contains a non-passing or empty check set: {path}"
        )
    check_ids = [check["id"] for check in checks]
    if not all(isinstance(value, str) and value for value in check_ids) or len(
        set(check_ids)
    ) != len(check_ids):
        raise ReleaseError(f"evidence contains invalid or duplicate check ids: {path}")
    metrics = receipt["metrics"]
    if not isinstance(metrics, dict) or any(
        not isinstance(name, str)
        or not name
        or not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        for name, value in metrics.items()
    ):
        raise ReleaseError(f"evidence metrics are invalid: {path}")
    producer = receipt["producer"]
    if not isinstance(producer, dict) or set(producer) != {
        "name",
        "version",
        "tool_sha256",
        "command",
        "arguments_redacted",
    }:
        raise ReleaseError(f"evidence producer is invalid: {path}")
    if (
        not all(
            isinstance(producer.get(name), str)
            and producer[name]
            and len(producer[name].encode("utf-8")) <= 128
            for name in ("name", "version")
        )
        or any(
            any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in producer[name]
            )
            for name in ("name", "version")
        )
        or not isinstance(producer.get("tool_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", producer["tool_sha256"]) is None
        or not isinstance(producer.get("command"), list)
        or not producer["command"]
        or not all(
            isinstance(value, str) and value and len(value.encode("utf-8")) <= 1024
            for value in producer["command"]
        )
        or any(
            any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            for value in producer["command"]
        )
        or producer.get("arguments_redacted") is not True
    ):
        raise ReleaseError(f"evidence producer fields are invalid: {path}")
    attachments = receipt["attachments"]
    if not isinstance(attachments, list) or not attachments:
        raise ReleaseError(f"evidence attachments are empty: {path}")
    attachment_paths: set[str] = set()
    for reference in attachments:
        if not isinstance(reference, dict) or set(reference) != {
            "path",
            "sha256",
            "bytes",
            "media_type",
        }:
            raise ReleaseError(f"evidence attachment reference is invalid: {path}")
        relative = safe_relative_path(reference.get("path", ""))
        if relative in attachment_paths:
            raise ReleaseError(f"evidence attachment path is duplicated: {relative}")
        attachment_paths.add(relative)
        attachment = resolve_beneath(dist, relative)
        if attachment == path.resolve() or not attachment.is_file():
            raise ReleaseError(
                f"evidence attachment is missing or self-referential: {relative}"
            )
        if (
            sha256_file(attachment) != reference.get("sha256")
            or attachment.stat().st_size != reference.get("bytes")
            or attachment.stat().st_size <= 0
        ):
            raise ReleaseError(
                f"evidence attachment digest or size mismatch: {relative}"
            )
        media_type = reference.get("media_type")
        if (
            not isinstance(media_type, str)
            or re.fullmatch(
                r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*(?:;[a-z0-9=._+-]+)?",
                media_type,
            )
            is None
        ):
            raise ReleaseError(f"evidence attachment media type is invalid: {relative}")
    return receipt


def _enforce_metric_gates(
    receipts: list[dict[str, Any]], requirements: dict[str, Any]
) -> dict[str, float]:
    gates = requirements.get("metric_gates")
    if not isinstance(gates, list) or not gates:
        raise ReleaseError("release metric gates are missing")
    _enforce_fuzz_metric_shape(receipts, gates)
    _enforce_mutation_metric_shape(receipts, gates)
    observed: dict[str, float] = {}
    seen: set[tuple[str, str]] = set()
    for gate in gates:
        required = {"name", "category", "aggregation", "comparison", "threshold"}
        allowed = required | {"valid_min", "valid_max"}
        if (
            not isinstance(gate, dict)
            or not required.issubset(gate)
            or not set(gate).issubset(allowed)
        ):
            raise ReleaseError("release metric gate has an unexpected shape")
        name = gate["name"]
        category = gate["category"]
        key = (category, name)
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(category, str)
            or not category
            or key in seen
        ):
            raise ReleaseError(
                "release metric gate has an invalid or duplicate identity"
            )
        seen.add(key)
        values = [
            float(receipt["metrics"][name])
            for receipt in receipts
            if receipt["category"] == category and name in receipt["metrics"]
        ]
        if not values or any(not math.isfinite(value) for value in values):
            raise ReleaseError(
                f"required metric {category}:{name} is missing or non-finite"
            )
        valid_min = gate.get("valid_min")
        valid_max = gate.get("valid_max")
        for label, bound in (("valid_min", valid_min), ("valid_max", valid_max)):
            if bound is not None and (
                not isinstance(bound, (int, float))
                or isinstance(bound, bool)
                or not math.isfinite(float(bound))
            ):
                raise ReleaseError(f"metric gate {label} is invalid: {category}:{name}")
        if (
            valid_min is not None
            and valid_max is not None
            and float(valid_min) > float(valid_max)
        ):
            raise ReleaseError(
                f"metric gate valid range is inverted: {category}:{name}"
            )
        if any(
            (valid_min is not None and value < float(valid_min))
            or (valid_max is not None and value > float(valid_max))
            for value in values
        ):
            raise ReleaseError(f"metric {category}:{name} is outside its valid range")
        aggregation = gate["aggregation"]
        if aggregation == "max":
            value = max(values)
        elif aggregation == "min":
            value = min(values)
        elif aggregation == "sum":
            value = sum(values)
        else:
            raise ReleaseError(
                f"metric gate uses an unsupported aggregation: {aggregation}"
            )
        if not math.isfinite(value):
            raise ReleaseError(
                f"metric gate aggregation is non-finite: {category}:{name}"
            )
        threshold = gate["threshold"]
        if (
            not isinstance(threshold, (int, float))
            or isinstance(threshold, bool)
            or not math.isfinite(float(threshold))
        ):
            raise ReleaseError(f"metric gate threshold is invalid: {category}:{name}")
        comparison = gate["comparison"]
        passed = (comparison == "gte" and value >= float(threshold)) or (
            comparison == "lte" and value <= float(threshold)
        )
        if comparison not in {"gte", "lte"}:
            raise ReleaseError(
                f"metric gate uses an unsupported comparison: {comparison}"
            )
        if not passed:
            raise ReleaseError(
                f"required metric {category}:{name} observed {value}, expected {comparison} {threshold}"
            )
        observed[f"{category}:{name}"] = value
    return observed


def _enforce_fuzz_metric_shape(
    receipts: list[dict[str, Any]], gates: list[object]
) -> None:
    """Require one reconciled per-target fuzz ledger summary.

    Generic numeric aggregation is intentionally insufficient here: without an
    exact target inventory, one long-running target (or duplicate summaries of
    the same ledger) could satisfy an aggregate seven-day threshold while the
    other governed harnesses never ran.
    """

    fuzz_gates = [
        gate
        for gate in gates
        if isinstance(gate, dict) and gate.get("category") == "fuzz"
    ]
    fuzz_receipts = [
        receipt for receipt in receipts if receipt.get("category") == "fuzz"
    ]
    if not fuzz_gates and not fuzz_receipts:
        return
    if not fuzz_gates:
        raise ReleaseError(
            "fuzz evidence exists without an authoritative metric policy"
        )
    if len(fuzz_receipts) != 1:
        raise ReleaseError(
            "release fuzz evidence must contain exactly one verified ledger summary"
        )

    gate_names = [gate.get("name") for gate in fuzz_gates]
    target_prefix = "fuzz.target_seconds."
    target_names = [
        name
        for name in gate_names
        if isinstance(name, str) and name.startswith(target_prefix)
    ]
    expected_control_names = {"fuzz.total_seconds", "fuzz.unresolved_defect_count"}
    if (
        len(target_names) != EXPECTED_FUZZ_TARGET_COUNT
        or len(set(target_names)) != EXPECTED_FUZZ_TARGET_COUNT
        or set(gate_names) != set(target_names) | expected_control_names
        or any(
            re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name.removeprefix(target_prefix))
            is None
            for name in target_names
        )
    ):
        raise ReleaseError(
            f"release fuzz policy does not name exactly {EXPECTED_FUZZ_TARGET_COUNT} targets"
        )

    metrics = fuzz_receipts[0].get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != set(gate_names):
        raise ReleaseError(
            "fuzz ledger summary metrics do not exactly match the governed target inventory"
        )
    for name in target_names:
        value = metrics[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReleaseError(
                f"fuzz target duration is not a nonnegative integer: {name}"
            )
    total = metrics["fuzz.total_seconds"]
    defects = metrics["fuzz.unresolved_defect_count"]
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total != sum(metrics[name] for name in target_names)
        or isinstance(defects, bool)
        or not isinstance(defects, int)
        or defects < 0
    ):
        raise ReleaseError("fuzz ledger aggregate or defect count does not reconcile")


def _enforce_mutation_metric_shape(
    receipts: list[dict[str, Any]], gates: list[object]
) -> None:
    """Require one complete production mutation campaign result.

    A duration sum across representative or interrupted runs must not satisfy
    the four-hour release-candidate campaign gate.
    """

    mutation_gates = [
        gate
        for gate in gates
        if isinstance(gate, dict) and gate.get("category") == "mutation"
    ]
    mutation_receipts = [
        receipt for receipt in receipts if receipt.get("category") == "mutation"
    ]
    if not mutation_gates and not mutation_receipts:
        return
    if not mutation_gates:
        raise ReleaseError(
            "mutation evidence exists without an authoritative metric policy"
        )
    if len(mutation_receipts) != 1:
        raise ReleaseError(
            "release mutation evidence must contain exactly one complete campaign"
        )
    expected_names = {
        "mutation.score_percent",
        "mutation.duration_seconds",
        "mutation.production_package_fraction",
        "mutation.timeout_count",
        "mutation.critical_viable_survivor_count",
    }
    if {gate.get("name") for gate in mutation_gates} != expected_names:
        raise ReleaseError("release mutation policy has an unexpected metric inventory")
    metrics = mutation_receipts[0].get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != expected_names:
        raise ReleaseError(
            "mutation campaign metrics do not exactly match the governed inventory"
        )
    score = metrics["mutation.score_percent"]
    fraction = metrics["mutation.production_package_fraction"]
    duration = metrics["mutation.duration_seconds"]
    timeouts = metrics["mutation.timeout_count"]
    critical = metrics["mutation.critical_viable_survivor_count"]
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
        or isinstance(fraction, bool)
        or not isinstance(fraction, (int, float))
        or not math.isfinite(float(fraction))
        or isinstance(duration, bool)
        or not isinstance(duration, int)
        or isinstance(timeouts, bool)
        or not isinstance(timeouts, int)
        or isinstance(critical, bool)
        or not isinstance(critical, int)
    ):
        raise ReleaseError("mutation campaign metrics have invalid numeric types")


def _mapped_requirements(specification: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(specification, dict):
        raise ReleaseError(f"qualification mapping is invalid: {label}")
    values = specification.get("requirements")
    if values is None:
        values = [specification]
    if not isinstance(values, list) or not values:
        raise ReleaseError(f"qualification mapping is empty: {label}")
    for value in values:
        if (
            not isinstance(value, dict)
            or set(value) != {"category", "check"}
            or not all(isinstance(item, str) and item for item in value.values())
        ):
            raise ReleaseError(f"qualification mapping requirement is invalid: {label}")
    return values


def _require_artifact_qualification(
    matrix_entries: dict[str, dict[str, Any]],
    built_ids: set[str],
    receipts: list[dict[str, Any]],
    mapping: dict[str, Any],
) -> None:
    qualifications = mapping.get("qualifications")
    additional = mapping.get("additional_requirements")
    universal = mapping.get("universal_requirements", [])
    if (
        not isinstance(qualifications, dict)
        or not isinstance(additional, list)
        or not isinstance(universal, list)
    ):
        raise ReleaseError("qualification category map is invalid")

    def present(identifier: str, requirement: dict[str, str]) -> bool:
        return any(
            receipt["category"] == requirement["category"]
            and identifier in receipt["artifact_ids"]
            and any(
                check.get("id") == requirement["check"]
                and check.get("status") == "passed"
                for check in receipt["checks"]
            )
            for receipt in receipts
        )

    for identifier in sorted(built_ids):
        entry = matrix_entries[identifier]
        for requirement in universal:
            if not isinstance(requirement, dict) or set(requirement) != {
                "category",
                "check",
            }:
                raise ReleaseError(
                    "universal artifact qualification mapping is invalid"
                )
            if not present(identifier, requirement):
                raise ReleaseError(
                    f"artifact {identifier} lacks {requirement['category']}:{requirement['check']} evidence"
                )
        for qualification in entry.get("qualification", []):
            if qualification not in qualifications:
                raise ReleaseError(
                    f"artifact {identifier} uses unmapped qualification {qualification}"
                )
            for requirement in _mapped_requirements(
                qualifications[qualification], qualification
            ):
                if not present(identifier, requirement):
                    raise ReleaseError(
                        f"artifact {identifier} lacks {requirement['category']}:{requirement['check']} evidence"
                    )
        for requirement in additional:
            if not isinstance(requirement, dict) or set(requirement) != {
                "artifact_kind",
                "category",
                "check",
            }:
                raise ReleaseError(
                    "additional artifact qualification mapping is invalid"
                )
            if requirement["artifact_kind"] == entry.get("kind") and not present(
                identifier, requirement
            ):
                raise ReleaseError(
                    f"artifact {identifier} lacks {requirement['category']}:{requirement['check']} evidence"
                )


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    dist = arguments.dist.resolve()
    if not dist.is_dir():
        raise ReleaseError(f"distribution directory does not exist: {dist}")
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise ReleaseError(
                f"distribution directory contains a symlink: {path.relative_to(dist)}"
            )
    matrix = load_json(resolve_beneath(root, arguments.matrix))
    requirements = load_json(resolve_beneath(root, arguments.requirements))
    gaps = load_json(root / "packaging/qualification-gaps.v1.json")
    validate_release_policy_documents(matrix, requirements, gaps)
    if not arguments.allow_development:
        if matrix.get("release_state") != "release":
            raise ReleaseError(
                "production evidence requires an artifact matrix in release state"
            )
        blocking = [
            entry.get("id")
            for entry in gaps.get("gaps", [])
            if isinstance(entry, dict) and entry.get("release_blocking") is True
        ]
        if blocking:
            raise ReleaseError(
                f"production evidence cannot be assembled with open qualification gaps: {blocking}"
            )
    qualification_mapping = load_json(
        resolve_beneath(root, requirements["qualification_category_map"])
    )
    validate_qualification_policy(qualification_mapping)
    build_manifest_path = _inside(dist, arguments.build_manifest)
    build = load_json(build_manifest_path)
    expected_build_keys = {
        "schema_version",
        "product_version",
        "context_abi",
        "source_date_epoch",
        "source",
        "artifacts",
    }
    if (
        not isinstance(build, dict)
        or set(build) != expected_build_keys
        or build.get("schema_version")
        not in {"cigar.local-archive-build.v1", "cigar.release-build.v1"}
    ):
        raise ReleaseError("unsupported build manifest")
    if (
        not arguments.allow_development
        and build["schema_version"] != "cigar.release-build.v1"
    ):
        raise ReleaseError("production evidence requires a release build manifest")
    if build.get("product_version") != matrix.get("product_version") or build.get(
        "context_abi"
    ) != matrix.get("context_abi"):
        raise ReleaseError(
            "build version or Context ABI disagrees with artifact matrix"
        )
    if (
        not isinstance(build.get("source_date_epoch"), int)
        or isinstance(build["source_date_epoch"], bool)
        or build["source_date_epoch"] < 0
        or build["source_date_epoch"] > 4_294_967_295
    ):
        raise ReleaseError("build manifest source date epoch is invalid")
    source = build.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or not isinstance(source.get("revision"), str)
        or re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64}|unborn:[0-9a-f]{64})", source["revision"]
        )
        is None
        or not isinstance(source.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", source["tree_sha256"]) is None
        or not isinstance(source.get("committed"), bool)
        or not isinstance(source.get("clean"), bool)
    ):
        raise ReleaseError("build manifest source identity is invalid")
    if not arguments.allow_development and (
        source.get("committed") is not True or source.get("clean") is not True
    ):
        raise ReleaseError(
            "production evidence requires a committed, clean source revision"
        )

    matrix_entries = {entry["id"]: entry for entry in matrix["artifacts"]}
    required_artifacts = _artifact_ids(matrix)
    artifact_records = build.get("artifacts")
    if not isinstance(artifact_records, list):
        raise ReleaseError("build manifest artifact list is invalid")
    typed_artifact_records: list[dict[str, Any]] = []
    built_ids: set[str] = set()
    for entry in artifact_records:
        if not isinstance(entry, dict):
            raise ReleaseError("build manifest contains a non-object artifact record")
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in built_ids:
            raise ReleaseError(
                "build manifest contains duplicate or invalid artifact ids"
            )
        built_ids.add(identifier)
        typed_artifact_records.append(entry)
    if not arguments.allow_development and built_ids != required_artifacts:
        missing = sorted(required_artifacts - built_ids)
        extra = sorted(built_ids - required_artifacts)
        raise ReleaseError(
            f"artifact matrix mismatch; missing={missing}, extra={extra}"
        )
    if not built_ids:
        raise ReleaseError("build manifest has invalid artifact ids")

    artifacts: list[dict[str, Any]] = []
    artifact_paths: set[Path] = set()
    for record in sorted(typed_artifact_records, key=lambda item: str(item["id"])):
        identifier_value = record.get("id")
        if not isinstance(identifier_value, str):
            raise ReleaseError("build manifest has an invalid artifact id")
        identifier = identifier_value
        if identifier not in matrix_entries:
            raise ReleaseError(
                f"build manifest contains unknown artifact id: {identifier}"
            )
        if set(record) != {"id", "path", "sha256", "bytes", "contract"}:
            raise ReleaseError(
                f"build manifest artifact record has an unexpected shape: {identifier}"
            )
        if (
            not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or not isinstance(record.get("bytes"), int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] <= 0
        ):
            raise ReleaseError(
                f"build manifest artifact digest or size is invalid: {identifier}"
            )
        relative = safe_relative_path(record.get("path", ""))
        if Path(relative).name != matrix_entries[identifier].get("filename"):
            raise ReleaseError(
                f"build artifact filename disagrees with the matrix: {identifier}"
            )
        path = _inside(dist, relative)
        if path.resolve() in artifact_paths:
            raise ReleaseError(
                f"multiple artifact ids reference the same payload: {relative}"
            )
        artifact_paths.add(path.resolve())
        if sha256_file(path) != record.get(
            "sha256"
        ) or path.stat().st_size != record.get("bytes"):
            raise ReleaseError(
                f"artifact digest or size changed after build: {relative}"
            )
        contract_relative = matrix_entries[identifier]["contract"]
        expected_contract = f"packaging/{contract_relative}"
        if record.get("contract") != expected_contract:
            raise ReleaseError(
                f"build artifact contract disagrees with the matrix: {identifier}"
            )
        contract_path = resolve_beneath(root, f"packaging/{contract_relative}")
        verify_package(
            path,
            contract_path,
            matrix["product_version"],
            matrix["context_abi"],
            build["source_date_epoch"],
        )
        artifacts.append(
            {
                "id": identifier,
                "path": relative,
                "sha256": record["sha256"],
                "bytes": record["bytes"],
                "contract": f"packaging/{contract_relative}",
                "status": "passed",
            }
        )

    evidence_directory = _inside(dist, arguments.evidence_directory)
    prohibited = set(requirements.get("prohibited_statuses", []))
    receipts: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(evidence_directory.glob("*.json"), key=lambda value: value.name):
        receipt = _validate_receipt(
            load_json(path), path, dist, source["revision"], built_ids, prohibited
        )
        receipts.append((path, receipt))
    if not receipts:
        raise ReleaseError("no qualification evidence receipts were found")
    receipt_file_paths = {path.resolve() for path, _ in receipts}
    for _, receipt in receipts:
        for reference in receipt["attachments"]:
            attachment = resolve_beneath(dist, reference["path"]).resolve()
            if attachment in artifact_paths or attachment in receipt_file_paths:
                raise ReleaseError(
                    "evidence attachment overlaps an artifact or receipt"
                )
    identifiers = [receipt["id"] for _, receipt in receipts]
    if len(set(identifiers)) != len(identifiers):
        raise ReleaseError("duplicate qualification evidence id")
    required_categories = set(requirements.get("required_evidence_categories", []))
    found_categories = {receipt["category"] for _, receipt in receipts}
    if not arguments.allow_development and found_categories != required_categories:
        raise ReleaseError(
            f"evidence category mismatch; missing={sorted(required_categories - found_categories)}, extra={sorted(found_categories - required_categories)}"
        )
    if not arguments.allow_development:
        _enforce_metric_gates([receipt for _, receipt in receipts], requirements)
        _require_artifact_qualification(
            matrix_entries,
            built_ids,
            [receipt for _, receipt in receipts],
            qualification_mapping,
        )

    evidence = []
    for path, receipt in receipts:
        reference = file_reference(path, dist)
        evidence.append(
            {
                **reference,
                "id": receipt["id"],
                "category": receipt["category"],
                "source_revision": receipt["source_revision"],
                "status": receipt["status"],
                "artifact_ids": sorted(receipt["artifact_ids"]),
                "metrics": receipt["metrics"],
            }
        )

    signature_directory = _inside(dist, arguments.signature_directory)
    signature_paths = sorted(
        signature_directory.glob("*.sig.json"), key=lambda value: value.name
    )
    if not signature_paths and not arguments.allow_development:
        raise ReleaseError("no detached signature envelopes were found")
    signatures = [file_reference(path, dist) for path in signature_paths]
    occupied_paths = (
        artifact_paths
        | receipt_file_paths
        | {
            resolve_beneath(dist, reference["path"]).resolve()
            for _, receipt in receipts
            for reference in receipt["attachments"]
        }
        | {path.resolve() for path in signature_paths}
        | {build_manifest_path.resolve()}
    )
    assembled = {
        "schema_version": "cigar.release-evidence.v1",
        "product_version": matrix["product_version"],
        "context_abi": matrix["context_abi"],
        "source_date_epoch": build["source_date_epoch"],
        "source": source,
        "build": file_reference(build_manifest_path, dist),
        "artifacts": artifacts,
        "evidence": evidence,
        "signatures": signatures,
    }
    _publish_assembled(
        arguments,
        root=root,
        dist=dist,
        occupied_paths=occupied_paths,
        document=assembled,
    )
    print(
        f"assembled {len(artifacts)} artifacts, {len(evidence)} evidence receipts, and {len(signatures)} signatures"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"release evidence assembly failed: {error}") from error
