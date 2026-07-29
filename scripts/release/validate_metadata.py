#!/usr/bin/env python3
"""Validate packaging metadata, version/ABI agreement, contracts, and release schema inventory."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from beta_profile import validate as validate_beta_profile
from development_macos_profile import validate as validate_development_macos_profile
from development_protocol_baseline import (
    validate as validate_development_protocol_baseline,
)
from post_beta_profile import validate as validate_post_beta_profile
from product_version import VersionError as ProductVersionError
from product_version import check as validate_product_version
from product_version import python_distribution_version
from release_lib import (
    ReleaseError,
    load_json,
    reject_evidence_directory,
    repo_root,
    resolve_beneath,
    sha256_file,
    validate_content_scan_exemptions,
    validate_qualification_policy,
    validate_release_policy_documents,
)
from verify_package import _validate_contract


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument(
        "--release",
        action="store_true",
        help="also require external candidate prerequisites",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
            "metadata validation is stdout-only and emits no candidate-bound report"
        ),
    )
    return parser.parse_args()


def _require_string_list(
    value: Any, label: str, *, nonempty: bool = False
) -> list[str]:
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ReleaseError(
            f"{label} must be {'a non-empty ' if nonempty else ''}list of strings"
        )
    return value


def _unique(values: list[str], label: str) -> None:
    if len(set(values)) != len(values):
        raise ReleaseError(f"{label} contains duplicates")


def main() -> int:
    arguments = parse_arguments()
    reject_evidence_directory(arguments.evidence_dir, "metadata validation")
    root = arguments.root.resolve()
    try:
        validate_product_version(root)
    except ProductVersionError as error:
        raise ReleaseError(f"product version metadata is invalid: {error}") from error
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    if matrix.get("schema_version") != "cigar.artifact-matrix.v1":
        raise ReleaseError("unsupported artifact matrix")
    version = matrix.get("product_version")
    abi = matrix.get("context_abi")
    if not isinstance(version, str) or not re.fullmatch(
        r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version
    ):
        raise ReleaseError("artifact matrix product version is invalid")
    if abi != "cigar.context.v1":
        raise ReleaseError("artifact matrix Context ABI is not v1")
    artifacts = matrix.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseError("artifact matrix is empty")
    artifact_ids = [entry.get("id") for entry in artifacts]
    filenames = [entry.get("filename") for entry in artifacts]
    if not all(isinstance(value, str) and value for value in artifact_ids + filenames):
        raise ReleaseError("artifact matrix ids and filenames must be strings")
    _unique(artifact_ids, "artifact ids")
    _unique(filenames, "artifact filenames")

    support = tomllib.loads((root / "support.toml").read_text(encoding="utf-8"))
    supported_targets = set(support["targets"]["tier1"]) | set(
        support["targets"]["tier2"]
    )
    referenced_contract_paths: set[Path] = set()
    for entry in artifacts:
        contract_relative = entry.get("contract")
        if not isinstance(contract_relative, str):
            raise ReleaseError(f"artifact {entry['id']} has no contract")
        contract_path = resolve_beneath(root, f"packaging/{contract_relative}")
        referenced_contract_paths.add(contract_path)
        contract = _validate_contract(load_json(contract_path))
        required_contract_keys = {
            "schema_version",
            "id",
            "formats",
            "allow",
            "deny",
            "required",
            "symlinks",
            "line_endings",
            "modes",
            "max_entries",
            "max_member_bytes",
            "max_total_bytes",
            "content_scan",
            "content_scan_exemptions",
        }
        optional_contract_keys = {
            "required_any",
            "required_patterns",
            "version_binding",
            "abi_binding",
            "checksum_manifest",
            "max_layer_uncompressed_bytes",
        }
        if not required_contract_keys.issubset(contract) or not set(contract).issubset(
            required_contract_keys | optional_contract_keys
        ):
            raise ReleaseError(
                f"artifact {entry['id']} contract has missing or unexpected fields"
            )
        _require_string_list(
            contract.get("formats"), f"{contract_path}: formats", nonempty=True
        )
        _require_string_list(
            contract.get("allow"), f"{contract_path}: allow", nonempty=True
        )
        _require_string_list(contract.get("deny"), f"{contract_path}: deny")
        _require_string_list(
            contract.get("modes"), f"{contract_path}: modes", nonempty=True
        )
        limits = [
            contract.get("max_entries"),
            contract.get("max_member_bytes"),
            contract.get("max_total_bytes"),
        ]
        if (
            not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in limits
            )
            or contract["max_member_bytes"] > contract["max_total_bytes"]
        ):
            raise ReleaseError(
                f"artifact {entry['id']} contract has invalid resource limits"
            )
        if (
            contract.get("symlinks") != "forbid"
            or contract.get("line_endings") != "lf"
            or contract.get("content_scan") is not True
        ):
            raise ReleaseError(
                f"artifact {entry['id']} contract weakens a mandatory package policy"
            )
        layer_limit = contract.get("max_layer_uncompressed_bytes")
        if contract.get("id") == "oci-image-v1":
            if (
                not isinstance(layer_limit, int)
                or isinstance(layer_limit, bool)
                or layer_limit <= 0
            ):
                raise ReleaseError(
                    "OCI package contract has no valid uncompressed-layer limit"
                )
        elif layer_limit is not None:
            raise ReleaseError(
                f"non-OCI artifact {entry['id']} declares an OCI layer limit"
            )
        try:
            validate_content_scan_exemptions(contract.get("content_scan_exemptions"))
        except ReleaseError as error:
            raise ReleaseError(
                f"artifact {entry['id']} contract has invalid content-scan exemptions"
            ) from error
        platform = entry.get("platform")
        if entry.get("kind") == "binary-archive" and platform not in supported_targets:
            raise ReleaseError(
                f"binary artifact {entry['id']} claims unsupported target {platform}"
            )
    discovered_contract_paths = {
        path.resolve() for path in (root / "packaging/contracts").glob("*.json")
    }
    if discovered_contract_paths != referenced_contract_paths:
        missing = sorted(
            path.name for path in referenced_contract_paths - discovered_contract_paths
        )
        orphaned = sorted(
            path.name for path in discovered_contract_paths - referenced_contract_paths
        )
        raise ReleaseError(
            f"package contract inventory mismatch; missing={missing}, orphaned={orphaned}"
        )

    local = load_json(root / "packaging/local-archives.v1.json")
    if local.get("product_version") != version or local.get("context_abi") != abi:
        raise ReleaseError("local archive manifest version/ABI mismatch")
    matrix_by_id = {entry["id"]: entry for entry in artifacts}
    local_ids: list[str] = []
    for entry in local.get("archives", []):
        identifier = entry.get("id")
        local_ids.append(identifier)
        if identifier not in matrix_by_id:
            raise ReleaseError(
                f"local archive {identifier} is absent from artifact matrix"
            )
        if entry.get("filename") != matrix_by_id[identifier].get("filename"):
            raise ReleaseError(
                f"local archive {identifier} filename disagrees with artifact matrix"
            )
        resolve_beneath(root, entry["contract"])
        _require_string_list(
            entry.get("include"), f"local archive {identifier} include", nonempty=True
        )
    _unique(local_ids, "local archive ids")

    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    rust_sdk = tomllib.loads((root / "sdk/rust/Cargo.toml").read_text(encoding="utf-8"))
    python_sdk = tomllib.loads(
        (root / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    )
    workspace_package = load_json(root / "package.json")
    typescript_sdk = load_json(root / "sdk/typescript/package.json")
    plugin = load_json(root / "adapters/claude-code/.claude-plugin/plugin.json")
    versions = {
        "Cargo workspace": cargo["workspace"]["package"]["version"],
        "Rust SDK": rust_sdk["package"]["version"],
        "TypeScript SDK": typescript_sdk["version"],
        "Python SDK": python_sdk["project"]["version"],
        "Claude Code plugin": plugin["version"],
    }
    expected_versions = {
        name: (
            python_distribution_version(version)
            if name == "Python SDK"
            else version
        )
        for name in versions
    }
    inconsistent = {
        name: {"actual": found, "expected": expected_versions[name]}
        for name, found in versions.items()
        if found != expected_versions[name]
    }
    if inconsistent:
        raise ReleaseError(f"semantic version mismatch: {inconsistent}")
    root_package_manager = workspace_package.get("packageManager")
    sdk_package_manager = typescript_sdk.get("packageManager")
    expected_pnpm = f"pnpm@{support['toolchains']['pnpm']}"
    pnpm_mismatch = (
        root_package_manager != expected_pnpm or sdk_package_manager != expected_pnpm
    )
    if arguments.release and pnpm_mismatch:
        raise ReleaseError(
            f"pnpm pin mismatch: support={expected_pnpm}, root={root_package_manager}, sdk={sdk_package_manager}"
        )

    requirements = load_json(root / "packaging/release-requirements.v1.json")
    categories = _require_string_list(
        requirements.get("required_evidence_categories"),
        "required evidence categories",
        nonempty=True,
    )
    _unique(categories, "required evidence categories")
    category_set = set(categories)
    signed_categories = _require_string_list(
        requirements.get("required_signed_evidence_categories"),
        "directly signed evidence categories",
        nonempty=True,
    )
    _unique(signed_categories, "directly signed evidence categories")
    if not set(signed_categories).issubset(category_set):
        raise ReleaseError(
            "directly signed evidence categories are not required evidence categories"
        )
    gates = requirements.get("metric_gates")
    if not isinstance(gates, list) or not gates:
        raise ReleaseError("release metric gates are missing")
    gate_keys: list[tuple[str, str]] = []
    for gate in gates:
        required_gate_keys = {
            "name",
            "category",
            "aggregation",
            "comparison",
            "threshold",
        }
        allowed_gate_keys = required_gate_keys | {"valid_min", "valid_max"}
        if (
            not isinstance(gate, dict)
            or not required_gate_keys.issubset(gate)
            or not set(gate).issubset(allowed_gate_keys)
        ):
            raise ReleaseError("release metric gate has an unexpected shape")
        if (
            gate.get("category") not in category_set
            or gate.get("aggregation") not in {"max", "min", "sum"}
            or gate.get("comparison") not in {"gte", "lte"}
        ):
            raise ReleaseError(
                "release metric gate has an invalid category or operation"
            )
        if (
            not isinstance(gate.get("name"), str)
            or not gate["name"]
            or not isinstance(gate.get("threshold"), (int, float))
            or isinstance(gate["threshold"], bool)
        ):
            raise ReleaseError("release metric gate has an invalid name or threshold")
        for bound in (gate.get("valid_min"), gate.get("valid_max")):
            if bound is not None and (
                not isinstance(bound, (int, float)) or isinstance(bound, bool)
            ):
                raise ReleaseError("release metric gate has an invalid valid range")
        if (
            gate.get("valid_min") is not None
            and gate.get("valid_max") is not None
            and gate["valid_min"] > gate["valid_max"]
        ):
            raise ReleaseError("release metric gate has an inverted valid range")
        gate_keys.append((gate["category"], gate["name"]))
    if len(set(gate_keys)) != len(gate_keys):
        raise ReleaseError("release metric gates contain duplicates")
    qualification_map = load_json(
        resolve_beneath(root, requirements["qualification_category_map"])
    )
    validate_qualification_policy(qualification_map)
    mappings = qualification_map.get("qualifications")
    if not isinstance(mappings, dict) or not mappings:
        raise ReleaseError("qualification category map is empty")
    used_qualifications = {
        value for entry in artifacts for value in entry.get("qualification", [])
    }
    if not used_qualifications.issubset(mappings):
        raise ReleaseError(
            f"artifact qualifications are unmapped: {sorted(used_qualifications - set(mappings))}"
        )
    for name, specification in mappings.items():
        requirements_list = (
            specification.get("requirements", [specification])
            if isinstance(specification, dict)
            else []
        )
        if not isinstance(requirements_list, list) or not requirements_list:
            raise ReleaseError(f"qualification mapping is invalid: {name}")
        for mapped in requirements_list:
            if (
                not isinstance(mapped, dict)
                or mapped.get("category") not in category_set
                or not isinstance(mapped.get("check"), str)
            ):
                raise ReleaseError(
                    f"qualification mapping references an unknown category: {name}"
                )
    artifact_kinds = {entry["kind"] for entry in artifacts}
    universal = qualification_map.get("universal_requirements")
    if not isinstance(universal, list) or not universal:
        raise ReleaseError("universal artifact qualification requirements are missing")
    for mapped in universal:
        if (
            not isinstance(mapped, dict)
            or set(mapped) != {"category", "check"}
            or mapped.get("category") not in category_set
            or not isinstance(mapped.get("check"), str)
        ):
            raise ReleaseError("universal artifact qualification mapping is invalid")
    for mapped in qualification_map.get("additional_requirements", []):
        if (
            not isinstance(mapped, dict)
            or mapped.get("artifact_kind") not in artifact_kinds
            or mapped.get("category") not in category_set
        ):
            raise ReleaseError("additional qualification mapping is invalid")
    gaps_document = load_json(root / "packaging/qualification-gaps.v1.json")
    validate_release_policy_documents(matrix, requirements, gaps_document)
    gaps = gaps_document.get("gaps", [])
    gap_ids = [entry.get("id") for entry in gaps]
    if not gap_ids or not all(isinstance(value, str) for value in gap_ids):
        raise ReleaseError("qualification gap inventory is invalid")
    _unique(gap_ids, "qualification gap ids")

    required_release_schemas = {
        "artifact-matrix.v1.schema.json",
        "docs-check.v1.schema.json",
        "install-qualification.v1.schema.json",
        "installed-driver.v1.schema.json",
        "locked-upstream-license-evidence.v1.schema.json",
        "operation-exercise-summary.v1.schema.json",
        "operation-exercise.v1.schema.json",
        "package-contract.v1.schema.json",
        "post-beta-capability-ownership.v1.schema.json",
        "post-beta-capability-profile.v1.schema.json",
        "provenance.v1.schema.json",
        "qualification-evidence.v1.schema.json",
        "release-build.v1.schema.json",
        "release-evidence.v1.schema.json",
        "release-metadata.v1.schema.json",
        "release-trust-policy.v1.schema.json",
        "release-verification.v1.schema.json",
        "reproducibility-report.v1.schema.json",
        "sbom-artifacts.v1.schema.json",
        "signature-envelope.v1.schema.json",
        "source-descriptor.v1.schema.json",
        "wp20-local-readiness.v1.schema.json",
        "wp21-local-qualification.v1.schema.json",
    }
    schema_paths = sorted((root / "packaging/schemas").glob("*.json"))
    if {path.name for path in schema_paths} != required_release_schemas:
        missing = sorted(
            required_release_schemas - {path.name for path in schema_paths}
        )
        extra = sorted({path.name for path in schema_paths} - required_release_schemas)
        raise ReleaseError(
            f"release schema inventory mismatch; missing={missing}, extra={extra}"
        )
    for path in schema_paths:
        schema = load_json(path)
        if schema.get(
            "$schema"
        ) != "https://json-schema.org/draft/2020-12/schema" or not schema.get("$id"):
            raise ReleaseError(f"release schema is missing draft/id metadata: {path}")
    validate_beta_profile(root)
    validate_post_beta_profile(root)
    product_version = load_json(root / "packaging/product-version.v1.json")
    if product_version.get("channel") == "development":
        validate_development_macos_profile(root)
    elif product_version.get("channel") != "honey":
        raise ReleaseError("unsupported product-version channel")
    validate_development_protocol_baseline(root)
    wp20_schema = load_json(
        root / "packaging/schemas/wp20-local-readiness.v1.schema.json"
    )
    if (
        wp20_schema.get("properties", {}).get("schema_version", {}).get("const")
        != "cigar.wp20-local-readiness.v1"
    ):
        raise ReleaseError(
            "WP20 local-readiness schema identity is missing or collides"
        )
    docs = load_json(root / "docs/site-manifest.v1.json")
    if docs.get("product_version") != version or docs.get("context_abi") != abi:
        raise ReleaseError("documentation version/ABI mismatch")
    for required in _require_string_list(
        docs.get("required_pages"), "required documentation pages", nonempty=True
    ):
        resolve_beneath(root, required)

    license_path = root / "packaging/licenses/Apache-2.0.txt"
    if (
        "Apache License" not in license_path.read_text(encoding="utf-8")
        or sha256_file(license_path) == "0" * 64
    ):
        raise ReleaseError("packaged Apache-2.0 license text is invalid")
    license_policy_path = root / "packaging/licenses/third-party-policy.v1.json"
    upstream_license_evidence_path = (
        root / "packaging/licenses/locked-upstream-license-evidence.v1.json"
    )
    upstream_license_evidence = load_json(upstream_license_evidence_path)
    upstream_license_records = upstream_license_evidence.get("records")
    inventory = load_json(root / "packaging/licenses/third-party-inventory.v1.json")
    if (
        inventory.get("schema_version") != "cigar.third-party-license-inventory.v1"
        or inventory.get("policy_sha256") != sha256_file(license_policy_path)
        or inventory.get("upstream_evidence_sha256")
        != sha256_file(upstream_license_evidence_path)
    ):
        raise ReleaseError("third-party license inventory is missing or stale")
    if (
        upstream_license_evidence.get("schema_version")
        != "cigar.locked-upstream-license-evidence.v1"
        or not isinstance(upstream_license_records, list)
        or not upstream_license_records
        or inventory.get("upstream_evidence_record_count")
        != len(upstream_license_records)
    ):
        raise ReleaseError("locked upstream license evidence is invalid")
    if (
        not isinstance(inventory.get("component_count"), int)
        or inventory["component_count"] <= 0
    ):
        raise ReleaseError("third-party license inventory is empty")
    if arguments.release:
        if not (root / "LICENSE").is_file():
            raise ReleaseError("release requires a root LICENSE file")
        if matrix.get("release_state") == "development":
            raise ReleaseError("artifact matrix remains in development state")
        if (
            inventory.get("review_required_count") != 0
            or inventory.get("status") != "complete"
        ):
            raise ReleaseError(
                "release requires a fully reviewed third-party license inventory"
            )
        blocking_gaps = [
            entry["id"] for entry in gaps if entry.get("release_blocking") is True
        ]
        if blocking_gaps:
            raise ReleaseError(
                f"release qualification gaps remain open: {blocking_gaps}"
            )
    suffix = " (development warning: pnpm pins disagree)" if pnpm_mismatch else ""
    print(
        f"validated {len(artifacts)} artifacts, {len(set(entry['contract'] for entry in artifacts))} contracts, {len(categories)} evidence categories, version {version}, ABI {abi}{suffix}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        ReleaseError,
    ) as error:
        raise SystemExit(f"release metadata validation failed: {error}") from error
