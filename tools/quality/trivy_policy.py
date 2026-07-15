#!/usr/bin/env python3
"""Run and evaluate CIGAR's fail-closed Trivy dependency policy.

The scanner always sees the complete checkout. This policy has no dependency
finding dispositions: every HIGH or CRITICAL result blocks release eligibility.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = Path(__file__).with_name("trivy-policy.v1.json")
MAX_POLICY_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_SCANNER_STDERR_BYTES = 4 * 1024 * 1024
HEX_DIGITS = frozenset("0123456789abcdef")
FINDING_FIELDS = (
    "target",
    "vulnerability_id",
    "package_name",
    "installed_version",
    "fixed_version",
    "severity",
)


class PolicyError(RuntimeError):
    """The policy, source authority, scanner, or result failed closed."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PolicyError(f"{label} has an unexpected shape")
    return value


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{label} is missing")
    return value


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in HEX_DIGITS for character in value)
    ):
        raise PolicyError(f"{label} is not a lowercase SHA-256 digest")
    return value


def safe_relative_path(value: Any, label: str) -> str:
    path = _nonempty_string(value, label)
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or path != pure.as_posix()
        or "\\" in path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise PolicyError(f"{label} is not a safe repository-relative path")
    return path


def resolve_repository_file(root: Path, relative: str, label: str) -> Path:
    repository = root.resolve(strict=True)
    candidate = repository.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise PolicyError(f"cannot resolve {label}: {error}") from error
    if repository not in resolved.parents or not resolved.is_file():
        raise PolicyError(f"{label} is not a regular file beneath the repository")
    return resolved


def read_bounded(path: Path, maximum: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise PolicyError(f"cannot inspect {label}: {error}") from error
    if size < 0 or size > maximum:
        raise PolicyError(f"{label} exceeds the {maximum}-byte bound")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise PolicyError(f"cannot read {label}: {error}") from error
    if len(payload) != size:
        raise PolicyError(f"{label} changed while it was read")
    return payload


def _package_descriptor(value: Any, label: str) -> tuple[str, str]:
    descriptor = _exact_keys(value, {"name", "version"}, label)
    return (
        _nonempty_string(descriptor["name"], f"{label} name"),
        _nonempty_string(descriptor["version"], f"{label} version"),
    )


def _finding_descriptor(value: Any, label: str) -> dict[str, str]:
    descriptor = _exact_keys(
        value,
        {
            "fixed_version",
            "installed_version",
            "package_name",
            "severity",
            "vulnerability_id",
        },
        label,
    )
    normalized = {
        key: _nonempty_string(descriptor[key], f"{label} {key}") for key in descriptor
    }
    if normalized["severity"] not in {"HIGH", "CRITICAL"}:
        raise PolicyError(f"{label} severity is outside the release-blocking policy")
    return normalized


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    payload = read_bounded(path, MAX_POLICY_BYTES, "Trivy policy")
    try:
        policy = json.loads(payload)
    except json.JSONDecodeError as error:
        raise PolicyError(f"cannot parse Trivy policy: {error}") from error
    policy = _exact_keys(
        policy,
        {
            "candidate_dispositions",
            "distribution_reachability",
            "required_scan_targets",
            "scan",
            "scanner",
            "schema_version",
            "source_reachability",
        },
        "Trivy policy",
    )
    if policy["schema_version"] != "cigar.trivy-policy.v1":
        raise PolicyError("unsupported Trivy policy schema")

    scanner = _exact_keys(
        policy["scanner"],
        {"max_database_age_hours", "name", "version"},
        "Trivy scanner authority",
    )
    if scanner["name"] != "trivy":
        raise PolicyError("Trivy scanner identity changed")
    _nonempty_string(scanner["version"], "Trivy scanner version")
    if (
        not isinstance(scanner["max_database_age_hours"], int)
        or not 1 <= scanner["max_database_age_hours"] <= 72
    ):
        raise PolicyError("Trivy database age limit is invalid")

    scan = _exact_keys(
        policy["scan"],
        {
            "detection_priority",
            "ignore_unfixed",
            "include_development_dependencies",
            "offline_dependency_resolution",
            "scanners",
            "severities",
            "skip_directories",
            "skip_files",
            "timeout_seconds",
        },
        "Trivy scan authority",
    )
    if (
        scan["detection_priority"] != "precise"
        or scan["ignore_unfixed"] is not False
        or scan["include_development_dependencies"] is not False
        or scan["offline_dependency_resolution"] is not True
        or scan["scanners"] != ["vuln"]
        or scan["severities"] != ["HIGH", "CRITICAL"]
        or scan["skip_directories"] != []
        or scan["skip_files"] != []
        or not isinstance(scan["timeout_seconds"], int)
        or not 60 <= scan["timeout_seconds"] <= 1800
    ):
        raise PolicyError(
            "Trivy scan authority weakens the reviewed full-source policy"
        )

    targets = policy["required_scan_targets"]
    if not isinstance(targets, list) or not targets:
        raise PolicyError("Trivy required target inventory is missing")
    target_identities: set[tuple[str, str, str]] = set()
    for index, raw_target in enumerate(targets):
        target = _exact_keys(
            raw_target,
            {"class", "path", "type"},
            f"Trivy required target {index}",
        )
        identity = (
            safe_relative_path(target["path"], f"Trivy required target {index} path"),
            _nonempty_string(target["class"], f"Trivy required target {index} class"),
            _nonempty_string(target["type"], f"Trivy required target {index} type"),
        )
        if identity in target_identities:
            raise PolicyError("Trivy required target inventory contains a duplicate")
        target_identities.add(identity)

    reachability = _exact_keys(
        policy["source_reachability"],
        {
            "beta_source_contract",
            "development_source_manifest",
            "patched_package",
            "resolved_lock",
            "snapshot",
            "workspace_manifest",
        },
        "Trivy source reachability authority",
    )
    snapshot = _exact_keys(
        reachability["snapshot"],
        {
            "manifest_bytes",
            "manifest_path",
            "manifest_sha256",
            "package_name",
            "package_version",
        },
        "upstream snapshot authority",
    )
    safe_relative_path(snapshot["manifest_path"], "snapshot manifest path")
    _digest(snapshot["manifest_sha256"], "snapshot manifest digest")
    if (
        not isinstance(snapshot["manifest_bytes"], int)
        or snapshot["manifest_bytes"] <= 0
    ):
        raise PolicyError("snapshot manifest_bytes is invalid")
    _nonempty_string(snapshot["package_name"], "snapshot package name")
    _nonempty_string(snapshot["package_version"], "snapshot package version")

    workspace = _exact_keys(
        reachability["workspace_manifest"],
        {"excluded_path", "path"},
        "workspace exclusion authority",
    )
    safe_relative_path(workspace["path"], "workspace manifest path")
    safe_relative_path(workspace["excluded_path"], "workspace excluded path")
    patched = _exact_keys(
        reachability["patched_package"],
        {"manifest", "name", "version"},
        "patched package authority",
    )
    safe_relative_path(patched["manifest"], "patched package manifest")
    _nonempty_string(patched["name"], "patched package name")
    _nonempty_string(patched["version"], "patched package version")
    resolved_lock = _exact_keys(
        reachability["resolved_lock"],
        {"forbidden_package_versions", "path", "required_package_versions"},
        "resolved lock authority",
    )
    safe_relative_path(resolved_lock["path"], "resolved lock path")
    for field in ("forbidden_package_versions", "required_package_versions"):
        values = resolved_lock[field]
        if not isinstance(values, list) or not values:
            raise PolicyError(f"resolved lock {field} is missing")
        identities = {
            _package_descriptor(item, f"resolved lock {field} entry") for item in values
        }
        if len(identities) != len(values):
            raise PolicyError(f"resolved lock {field} contains a duplicate")
    for field, boolean_field in (
        ("beta_source_contract", "snapshot_must_be_excluded"),
        ("development_source_manifest", "snapshot_must_be_included"),
    ):
        descriptor = _exact_keys(
            reachability[field], {"path", boolean_field}, f"{field} authority"
        )
        safe_relative_path(descriptor["path"], f"{field} path")
        if descriptor[boolean_field] is not True:
            raise PolicyError(f"{field} expectation changed")

    distribution = _exact_keys(
        policy["distribution_reachability"],
        {
            "artifact_dependency_classes",
            "artifact_matrix",
            "development_profile",
            "sbom",
            "source_archive",
            "stale_lock_path",
        },
        "Trivy distribution reachability authority",
    )
    stale_lock_path = safe_relative_path(
        distribution["stale_lock_path"], "stale nested lock path"
    )
    if stale_lock_path != "vendor/aws-creds-0.39.1/Cargo.lock":
        raise PolicyError("stale nested lock authority changed")

    matrix_authority = _exact_keys(
        distribution["artifact_matrix"], {"path"}, "artifact matrix authority"
    )
    safe_relative_path(matrix_authority["path"], "artifact matrix path")
    profile_authority = _exact_keys(
        distribution["development_profile"],
        {"path", "profile_id", "selected_artifact_ids", "target_triple"},
        "development artifact profile authority",
    )
    safe_relative_path(profile_authority["path"], "development profile path")
    if (
        profile_authority["profile_id"] != "cigar.development.local.macos-aarch64.v1"
        or profile_authority["target_triple"] != "aarch64-apple-darwin"
    ):
        raise PolicyError("development artifact profile identity changed")
    selected_artifact_ids = profile_authority["selected_artifact_ids"]
    if (
        not isinstance(selected_artifact_ids, list)
        or len(selected_artifact_ids) != 17
        or any(
            not isinstance(value, str) or not value for value in selected_artifact_ids
        )
        or len(set(selected_artifact_ids)) != len(selected_artifact_ids)
    ):
        raise PolicyError(
            "development selected artifact authority is not exactly 17 IDs"
        )

    dependency_classes = _exact_keys(
        distribution["artifact_dependency_classes"],
        {
            "non_rust_payload",
            "root_cargo_graph_bound",
            "root_cargo_graph_reference_only",
            "source_projection",
        },
        "artifact dependency classes",
    )
    classified: list[str] = []
    for name, values in dependency_classes.items():
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
            or len(set(values)) != len(values)
        ):
            raise PolicyError(f"artifact dependency class {name} is malformed")
        classified.extend(values)
    if len(classified) != len(set(classified)) or set(classified) != set(
        selected_artifact_ids
    ):
        raise PolicyError(
            "artifact dependency classes do not partition all selected IDs"
        )
    if dependency_classes["source_projection"] != ["source"]:
        raise PolicyError("source artifact dependency class changed")

    source_authority = _exact_keys(
        distribution["source_archive"],
        {
            "artifact_id",
            "builder_path",
            "builder_sha256",
            "manifest_path",
        },
        "development source archive authority",
    )
    if source_authority["artifact_id"] != "source":
        raise PolicyError("development source artifact identity changed")
    for field in ("builder_path", "manifest_path"):
        safe_relative_path(source_authority[field], f"source archive {field}")
    _digest(source_authority["builder_sha256"], "source archive builder digest")

    sbom_authority = _exact_keys(
        distribution["sbom"],
        {"component_functions", "generator_path", "generator_sha256"},
        "SBOM reachability authority",
    )
    safe_relative_path(sbom_authority["generator_path"], "SBOM generator path")
    _digest(sbom_authority["generator_sha256"], "SBOM generator digest")
    if sbom_authority["component_functions"] != [
        "_cargo_components",
        "_npm_components",
        "_python_components",
        "_go_components",
    ]:
        raise PolicyError("SBOM dependency component function authority changed")

    candidates = policy["candidate_dispositions"]
    if candidates != []:
        raise PolicyError(
            "this remediated policy permits no dependency finding dispositions"
        )
    return policy


def _parse_toml(path: Path, label: str) -> dict[str, Any]:
    payload = read_bounded(path, MAX_REPORT_BYTES, label)
    try:
        parsed = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyError(f"cannot parse {label}: {error}") from error
    if not isinstance(parsed, dict):
        raise PolicyError(f"{label} is not a TOML object")
    return parsed


def _package_versions(lock: dict[str, Any], label: str) -> set[tuple[str, str]]:
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise PolicyError(f"{label} has no package inventory")
    result: set[tuple[str, str]] = set()
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise PolicyError(f"{label} package {index} is malformed")
        result.add(
            (
                _nonempty_string(package.get("name"), f"{label} package name"),
                _nonempty_string(package.get("version"), f"{label} package version"),
            )
        )
    return result


def matches(path: str, patterns: Iterable[str]) -> bool:
    """Match release allowlists with the same leading-** behavior as release_lib."""

    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise PolicyError("source package pattern is malformed")
        candidate = pattern
        while True:
            if fnmatch.fnmatchcase(path, candidate):
                return True
            if not candidate.startswith("**/"):
                break
            candidate = candidate.removeprefix("**/")
    return False


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    payload = read_bounded(path, MAX_REPORT_BYTES, label)
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise PolicyError(f"cannot parse {label}: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{label} is not a JSON object")
    return value


def require_absent_repository_path(root: Path, relative: str, label: str) -> None:
    """Prove an absent leaf without accepting a symlinked parent."""

    repository = root.resolve(strict=True)
    parts = PurePosixPath(safe_relative_path(relative, label)).parts
    current = repository
    for part in parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise PolicyError(f"cannot inspect {label} parent: {error}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PolicyError(f"{label} parent is not a real directory")
    leaf = current / parts[-1]
    try:
        leaf.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise PolicyError(f"cannot inspect {label}: {error}") from error
    raise PolicyError(f"{label} must be absent")


def _load_reviewed_sbom_generator(
    path: Path, expected_sha256: str
) -> tuple[Any, dict[str, Any]]:
    payload = read_bounded(path, MAX_REPORT_BYTES, "SBOM generator")
    digest = sha256_bytes(payload)
    if digest != expected_sha256:
        raise PolicyError("the reviewed SBOM generator changed")
    module_name = f"_cigar_sbom_reachability_{digest[:16]}"
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        raise PolicyError("cannot load the reviewed SBOM generator")
    module = importlib.util.module_from_spec(specification)
    script_directory = str(path.parent)
    sys.path.insert(0, script_directory)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        specification.loader.exec_module(module)
    except BaseException as error:
        raise PolicyError(
            f"cannot execute the reviewed SBOM generator: {error}"
        ) from error
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
        if sys.path and sys.path[0] == script_directory:
            sys.path.pop(0)
        else:
            try:
                sys.path.remove(script_directory)
            except ValueError:
                pass
    return module, {"bytes": len(payload), "sha256": digest}


def distribution_reachability_evidence(
    policy: dict[str, Any], root: Path = ROOT
) -> dict[str, Any]:
    """Prove stale snapshot dependencies cannot reach selected artifacts or SBOMs."""

    repository = root.resolve(strict=True)
    distribution = policy["distribution_reachability"]
    stale_lock_path = distribution["stale_lock_path"]
    require_absent_repository_path(
        repository, stale_lock_path, "stale provenance snapshot lock"
    )

    profile_authority = distribution["development_profile"]
    profile = _load_json_object(
        resolve_repository_file(
            repository, profile_authority["path"], "development artifact profile"
        ),
        "development artifact profile",
    )
    target = profile.get("target")
    selected = profile.get("selected_artifacts")
    if (
        profile.get("schema_version") != "cigar.development-artifact-profile.v1"
        or profile.get("profile_id") != profile_authority["profile_id"]
        or profile.get("release_state") != "development"
        or profile.get("published") is not False
        or profile.get("supported") is not False
        or not isinstance(target, dict)
        or target.get("host_os") != "macos"
        or target.get("host_arch") != "arm64"
        or target.get("target_triple") != profile_authority["target_triple"]
        or not isinstance(selected, list)
    ):
        raise PolicyError("development artifact profile identity is invalid")
    selected_ids: list[str] = []
    for index, entry in enumerate(selected):
        if (
            not isinstance(entry, dict)
            or set(entry) != {"built", "id", "qualified", "selection_group", "status"}
            or not isinstance(entry.get("id"), str)
            or not entry["id"]
            or entry.get("status") != "planned"
            or entry.get("built") is not False
            or entry.get("qualified") is not False
        ):
            raise PolicyError(f"development selected artifact {index} is malformed")
        selected_ids.append(entry["id"])
    if selected_ids != profile_authority["selected_artifact_ids"]:
        raise PolicyError("development profile no longer selects the reviewed 17 IDs")

    matrix_authority = distribution["artifact_matrix"]
    matrix = _load_json_object(
        resolve_repository_file(
            repository, matrix_authority["path"], "development artifact matrix"
        ),
        "development artifact matrix",
    )
    matrix_entries = matrix.get("artifacts")
    if (
        matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("release_state") != "development"
        or not isinstance(matrix_entries, list)
    ):
        raise PolicyError("development artifact matrix identity is invalid")
    rows: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(matrix_entries):
        if not isinstance(entry, dict):
            raise PolicyError(f"artifact matrix row {index} is malformed")
        identifier = _nonempty_string(
            entry.get("id"), f"artifact matrix row {index} id"
        )
        if identifier in rows:
            raise PolicyError("artifact matrix contains a duplicate ID")
        rows[identifier] = entry
    if any(identifier not in rows for identifier in selected_ids):
        raise PolicyError("artifact matrix omits a selected macOS artifact")

    source_authority = distribution["source_archive"]
    source_builder_path = resolve_repository_file(
        repository, source_authority["builder_path"], "source archive builder"
    )
    source_builder_payload = read_bounded(
        source_builder_path, MAX_REPORT_BYTES, "source archive builder"
    )
    if sha256_bytes(source_builder_payload) != source_authority["builder_sha256"]:
        raise PolicyError("the reviewed source archive builder changed")

    source_manifest = _load_json_object(
        resolve_repository_file(
            repository, source_authority["manifest_path"], "source archive manifest"
        ),
        "source archive manifest",
    )
    source_archives = [
        entry
        for entry in source_manifest.get("archives", [])
        if isinstance(entry, dict)
        and entry.get("id") == source_authority["artifact_id"]
    ]
    if len(source_archives) != 1 or not isinstance(
        source_archives[0].get("include"), list
    ):
        raise PolicyError("source archive manifest is ambiguous")

    snapshot_manifest_path = policy["source_reachability"]["snapshot"]["manifest_path"]
    stale_lock_contract_ids: list[str] = []
    snapshot_source_contract_ids: list[str] = []
    contracts: list[dict[str, Any]] = []
    for identifier in selected_ids:
        row = rows[identifier]
        producer = _nonempty_string(
            row.get("producer"), f"selected artifact {identifier} producer"
        )
        contract_value = safe_relative_path(
            row.get("contract"), f"selected artifact {identifier} contract"
        )
        contract_relative = f"packaging/{contract_value}"
        contract = _load_json_object(
            resolve_repository_file(
                repository,
                contract_relative,
                f"selected artifact {identifier} contract",
            ),
            f"selected artifact {identifier} contract",
        )
        allow = contract.get("allow")
        deny = contract.get("deny")
        if not isinstance(allow, list) or not isinstance(deny, list):
            raise PolicyError(f"selected artifact {identifier} contract is malformed")
        stale_selected = matches(stale_lock_path, allow) and not matches(
            stale_lock_path, deny
        )
        snapshot_selected = matches(snapshot_manifest_path, allow) and not matches(
            snapshot_manifest_path, deny
        )
        if stale_selected:
            stale_lock_contract_ids.append(identifier)
        if snapshot_selected:
            snapshot_source_contract_ids.append(identifier)
        contracts.append(
            {
                "contract": contract_relative,
                "id": identifier,
                "producer": producer,
                "snapshot_source_selectable": snapshot_selected,
                "stale_lock_selectable": stale_selected,
            }
        )
    if stale_lock_contract_ids != [source_authority["artifact_id"]]:
        raise PolicyError(
            "the stale nested lock is selectable by an unexpected artifact"
        )
    if snapshot_source_contract_ids != [source_authority["artifact_id"]]:
        raise PolicyError(
            "the provenance snapshot source reaches an unexpected artifact"
        )
    source_include = source_archives[0]["include"]
    if not matches(stale_lock_path, source_include) or not matches(
        snapshot_manifest_path, source_include
    ):
        raise PolicyError(
            "source archive selection no longer records vendor provenance"
        )

    sbom_authority = distribution["sbom"]
    generator_path = resolve_repository_file(
        repository, sbom_authority["generator_path"], "SBOM generator"
    )
    generator, generator_evidence = _load_reviewed_sbom_generator(
        generator_path, sbom_authority["generator_sha256"]
    )
    components: list[dict[str, Any]] = []
    component_function_counts: dict[str, int] = {}
    for function_name in sbom_authority["component_functions"]:
        function = getattr(generator, function_name, None)
        if not callable(function):
            raise PolicyError(
                f"SBOM component function is unavailable: {function_name}"
            )
        try:
            result = function(repository)
        except BaseException as error:
            raise PolicyError(
                f"SBOM component function failed: {function_name}: {error}"
            ) from error
        if not isinstance(result, list):
            raise PolicyError(f"SBOM component function is malformed: {function_name}")
        component_function_counts[function_name] = len(result)
        for index, component in enumerate(result):
            if not isinstance(component, dict):
                raise PolicyError(
                    f"SBOM component {function_name}[{index}] is malformed"
                )
            _nonempty_string(component.get("ecosystem"), "SBOM component ecosystem")
            _nonempty_string(component.get("name"), "SBOM component name")
            _nonempty_string(component.get("version"), "SBOM component version")
            _nonempty_string(component.get("purl"), "SBOM component purl")
            components.append(component)
    component_keys = [
        (component["ecosystem"], component["name"], component["version"])
        for component in components
    ]
    if len(component_keys) != len(set(component_keys)):
        raise PolicyError(
            "SBOM dependency inputs contain ambiguous duplicate identities"
        )
    component_versions = {
        (component["name"], component["version"]) for component in components
    }
    resolved_authority = policy["source_reachability"]["resolved_lock"]
    forbidden = {
        _package_descriptor(value, "forbidden SBOM package")
        for value in resolved_authority["forbidden_package_versions"]
    }
    required = {
        _package_descriptor(value, "required SBOM package")
        for value in resolved_authority["required_package_versions"]
    }
    if forbidden.intersection(component_versions):
        raise PolicyError(
            "the generated SBOM dependency union contains a stale package"
        )
    if not required.issubset(component_versions):
        raise PolicyError(
            "the generated SBOM dependency union lost a reviewed replacement"
        )
    component_identity = [
        {"ecosystem": ecosystem, "name": name, "version": version}
        for ecosystem, name, version in sorted(component_keys)
    ]

    dependency_classes = distribution["artifact_dependency_classes"]
    return {
        "artifact_contracts": contracts,
        "artifact_dependency_classes": dependency_classes,
        "profile": {
            "id": profile_authority["profile_id"],
            "selected_artifact_count": len(selected_ids),
            "selected_artifact_ids": selected_ids,
            "target_triple": profile_authority["target_triple"],
        },
        "sbom": {
            "component_count": len(components),
            "component_function_counts": component_function_counts,
            "component_identity_sha256": sha256_bytes(
                canonical_json_bytes(component_identity)
            ),
            "forbidden_versions_present": False,
            "generator": generator_evidence,
            "required_replacements_present": True,
        },
        "snapshot_distribution": {
            "source_artifact_ids": snapshot_source_contract_ids,
            "stale_lock_artifact_contract_ids": stale_lock_contract_ids,
            "stale_lock_present": False,
        },
        "source_archive_builder": {
            "bytes": len(source_builder_payload),
            "sha256": sha256_bytes(source_builder_payload),
        },
    }


def verify_repository_authority(
    policy: dict[str, Any], root: Path = ROOT
) -> dict[str, Any]:
    """Prove the inert source snapshot is not a resolved CIGAR package."""

    repository = root.resolve(strict=True)
    authority = policy["source_reachability"]
    snapshot = authority["snapshot"]
    manifest_path = resolve_repository_file(
        repository, snapshot["manifest_path"], "upstream snapshot manifest"
    )
    snapshot_manifest_payload = read_bounded(
        manifest_path, MAX_REPORT_BYTES, "upstream snapshot manifest"
    )
    if (
        len(snapshot_manifest_payload) != snapshot["manifest_bytes"]
        or sha256_bytes(snapshot_manifest_payload) != snapshot["manifest_sha256"]
    ):
        raise PolicyError("the pinned upstream provenance snapshot changed")

    upstream_manifest = _parse_toml(manifest_path, "upstream snapshot manifest")
    upstream_package = upstream_manifest.get("package")
    if not isinstance(upstream_package, dict) or (
        upstream_package.get("name"),
        upstream_package.get("version"),
    ) != (snapshot["package_name"], snapshot["package_version"]):
        raise PolicyError("the upstream snapshot package identity changed")

    workspace_authority = authority["workspace_manifest"]
    workspace_path = resolve_repository_file(
        repository, workspace_authority["path"], "workspace manifest"
    )
    workspace_manifest = _parse_toml(workspace_path, "workspace manifest")
    workspace = workspace_manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise PolicyError("workspace manifest has no workspace authority")
    excluded = workspace.get("exclude")
    members = workspace.get("members")
    excluded_path = workspace_authority["excluded_path"]
    if (
        not isinstance(excluded, list)
        or excluded_path not in excluded
        or not isinstance(members, list)
        or excluded_path in members
    ):
        raise PolicyError(
            "the upstream snapshot is no longer excluded from the workspace"
        )

    resolved_authority = authority["resolved_lock"]
    resolved_path = resolve_repository_file(
        repository, resolved_authority["path"], "resolved CIGAR lock"
    )
    resolved_packages = _package_versions(
        _parse_toml(resolved_path, "resolved CIGAR lock"), "resolved CIGAR lock"
    )
    forbidden = {
        _package_descriptor(value, "forbidden resolved package")
        for value in resolved_authority["forbidden_package_versions"]
    }
    required = {
        _package_descriptor(value, "required resolved package")
        for value in resolved_authority["required_package_versions"]
    }
    if forbidden.intersection(resolved_packages):
        raise PolicyError(
            "a provenance-only package version entered the resolved CIGAR lock"
        )
    if not required.issubset(resolved_packages):
        raise PolicyError(
            "the resolved CIGAR lock no longer contains the reviewed replacements"
        )

    patched_authority = authority["patched_package"]
    patched_manifest_path = resolve_repository_file(
        repository, patched_authority["manifest"], "patched package manifest"
    )
    patched_manifest = _parse_toml(patched_manifest_path, "patched package manifest")
    patched_package = patched_manifest.get("package")
    if not isinstance(patched_package, dict) or (
        patched_package.get("name"),
        patched_package.get("version"),
    ) != (patched_authority["name"], patched_authority["version"]):
        raise PolicyError("the patched package identity changed")

    beta_authority = authority["beta_source_contract"]
    beta_contract = _load_json_object(
        resolve_repository_file(
            repository, beta_authority["path"], "beta source contract"
        ),
        "beta source contract",
    )
    beta_allow = beta_contract.get("allow")
    if not isinstance(beta_allow, list) or matches(
        snapshot["manifest_path"], beta_allow
    ):
        raise PolicyError(
            "the beta source package now includes the provenance snapshot"
        )

    development_authority = authority["development_source_manifest"]
    development_manifest = _load_json_object(
        resolve_repository_file(
            repository,
            development_authority["path"],
            "development source manifest",
        ),
        "development source manifest",
    )
    archives = development_manifest.get("archives")
    if not isinstance(archives, list):
        raise PolicyError("development source manifest has no archive inventory")
    source_archives = [
        archive
        for archive in archives
        if isinstance(archive, dict) and archive.get("id") == "source"
    ]
    if len(source_archives) != 1 or not isinstance(
        source_archives[0].get("include"), list
    ):
        raise PolicyError("development source archive authority is ambiguous")
    if not matches(snapshot["manifest_path"], source_archives[0]["include"]):
        raise PolicyError(
            "development source archive no longer records snapshot provenance"
        )

    return {
        "beta_source_contains_snapshot": False,
        "development_source_contains_snapshot": True,
        "patched_package": {
            "name": patched_authority["name"],
            "version": patched_authority["version"],
        },
        "resolved_lock_forbidden_versions_present": False,
        "snapshot": {
            "manifest_bytes": len(snapshot_manifest_payload),
            "manifest_sha256": sha256_bytes(snapshot_manifest_payload),
        },
        "workspace_excluded": True,
    }


def cargo_metadata_evidence(
    policy: dict[str, Any], root: Path = ROOT, executable: str = "cargo"
) -> dict[str, Any]:
    """Ask Cargo to prove that no snapshot package is in the resolved graph."""

    repository = root.resolve(strict=True)
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    command = [
        executable,
        "metadata",
        "--locked",
        "--offline",
        "--format-version=1",
    ]
    try:
        process = subprocess.run(
            command,
            cwd=repository,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PolicyError(
            f"cannot run locked offline Cargo metadata: {error}"
        ) from error
    if process.returncode != 0:
        raise PolicyError(
            "locked offline Cargo metadata failed: "
            f"stderr_bytes={len(process.stderr)} "
            f"stderr_sha256={sha256_bytes(process.stderr)}"
        )
    if len(process.stdout) > MAX_REPORT_BYTES:
        raise PolicyError("Cargo metadata exceeds its output bound")
    try:
        metadata = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise PolicyError(f"Cargo metadata is not valid JSON: {error}") from error
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise PolicyError("Cargo metadata has no package inventory")

    authority = policy["source_reachability"]
    forbidden = {
        _package_descriptor(value, "forbidden metadata package")
        for value in authority["resolved_lock"]["forbidden_package_versions"]
    }
    patched = authority["patched_package"]
    package_versions: set[tuple[str, str]] = set()
    patched_ids: set[str] = set()
    snapshot_root = repository / authority["workspace_manifest"]["excluded_path"]
    for index, package in enumerate(metadata["packages"]):
        if not isinstance(package, dict):
            raise PolicyError(f"Cargo metadata package {index} is malformed")
        identity = (
            _nonempty_string(package.get("name"), "Cargo metadata package name"),
            _nonempty_string(package.get("version"), "Cargo metadata package version"),
        )
        package_versions.add(identity)
        manifest_value = _nonempty_string(
            package.get("manifest_path"), "Cargo metadata manifest path"
        )
        try:
            manifest = Path(manifest_value).resolve(strict=True)
        except OSError as error:
            raise PolicyError(
                f"cannot resolve Cargo metadata manifest: {error}"
            ) from error
        if manifest == snapshot_root or snapshot_root in manifest.parents:
            raise PolicyError("Cargo resolved a package from the provenance snapshot")
        if identity == (patched["name"], patched["version"]):
            patched_ids.add(
                _nonempty_string(package.get("id"), "patched Cargo package id")
            )
    if forbidden.intersection(package_versions):
        raise PolicyError("Cargo metadata resolved a provenance-only package version")
    if len(patched_ids) != 1:
        raise PolicyError("Cargo metadata does not contain exactly one patched package")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(workspace_members, list) or not patched_ids.issubset(
        set(workspace_members)
    ):
        raise PolicyError("the patched package is not a Cargo workspace member")
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise PolicyError("Cargo metadata omitted the resolved dependency graph")
    return {
        "command": command,
        "forbidden_versions_present": False,
        "package_count": len(metadata["packages"]),
        "patched_package_resolved": True,
        "workspace_member_count": len(workspace_members),
    }


def scanner_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("TRIVY_")
    }
    environment["NO_COLOR"] = "1"
    return environment


def scanner_metadata(executable: str, expected_version: str) -> dict[str, Any]:
    try:
        process = subprocess.run(
            [executable, "--version", "--format", "json"],
            env=scanner_environment(),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PolicyError(f"cannot determine Trivy version: {error}") from error
    if process.returncode != 0 or len(process.stdout) > MAX_POLICY_BYTES:
        raise PolicyError("Trivy did not return bounded version metadata")
    try:
        metadata = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise PolicyError(f"Trivy version metadata is invalid: {error}") from error
    if not isinstance(metadata, dict) or metadata.get("Version") != expected_version:
        raise PolicyError(
            f"Trivy version mismatch: expected {expected_version}, "
            f"got {metadata.get('Version') if isinstance(metadata, dict) else None}"
        )
    return metadata


def validate_database_metadata(
    metadata: dict[str, Any], maximum_age_hours: int
) -> dict[str, Any]:
    database = metadata.get("VulnerabilityDB")
    if not isinstance(database, dict) or database.get("Version") != 2:
        raise PolicyError("Trivy vulnerability database metadata is missing")
    updated_raw = database.get("UpdatedAt")
    downloaded_raw = database.get("DownloadedAt")
    if not isinstance(updated_raw, str) or not isinstance(downloaded_raw, str):
        raise PolicyError("Trivy vulnerability database timestamps are missing")
    try:
        updated = dt.datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
        downloaded = dt.datetime.fromisoformat(downloaded_raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise PolicyError(
            "Trivy vulnerability database timestamps are invalid"
        ) from error
    if updated.tzinfo is None or downloaded.tzinfo is None:
        raise PolicyError("Trivy vulnerability database timestamps have no timezone")
    now = dt.datetime.now(dt.timezone.utc)
    age = now - updated.astimezone(dt.timezone.utc)
    if age < dt.timedelta(minutes=-15) or age > dt.timedelta(hours=maximum_age_hours):
        raise PolicyError("Trivy vulnerability database is stale or from the future")
    if downloaded.astimezone(dt.timezone.utc) < updated.astimezone(dt.timezone.utc):
        raise PolicyError("Trivy vulnerability database download predates its update")
    return {
        "downloaded_at": downloaded_raw,
        "updated_at": updated_raw,
        "version": database["Version"],
    }


def build_scan_command(
    executable: str,
    policy: dict[str, Any],
    config: Path,
    ignorefile: Path,
    report: Path,
) -> list[str]:
    scan = policy["scan"]
    command = [
        executable,
        "--config",
        str(config),
        "fs",
        "--scanners",
        ",".join(scan["scanners"]),
        "--severity",
        ",".join(scan["severities"]),
        "--detection-priority",
        scan["detection_priority"],
        "--offline-scan",
        "--format",
        "json",
        "--output",
        str(report),
        "--ignorefile",
        str(ignorefile),
        "--list-all-pkgs",
        "--exit-code",
        "0",
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
        "--timeout",
        f"{scan['timeout_seconds']}s",
        ".",
    ]
    if scan["include_development_dependencies"]:
        command.insert(-1, "--include-dev-deps")
    if scan["ignore_unfixed"]:
        command.insert(-1, "--ignore-unfixed")
    for directory in scan["skip_directories"]:
        command[-1:-1] = ["--skip-dirs", directory]
    for path in scan["skip_files"]:
        command[-1:-1] = ["--skip-files", path]
    return command


def _report_finding(target: str, vulnerability: Any) -> tuple[str, ...]:
    if not isinstance(vulnerability, dict):
        raise PolicyError(f"Trivy finding for {target} is malformed")
    values = {
        "target": target,
        "vulnerability_id": vulnerability.get("VulnerabilityID"),
        "package_name": vulnerability.get("PkgName"),
        "installed_version": vulnerability.get("InstalledVersion"),
        "fixed_version": vulnerability.get("FixedVersion"),
        "severity": vulnerability.get("Severity"),
    }
    for field, value in values.items():
        if field == "fixed_version":
            if not isinstance(value, str):
                raise PolicyError("Trivy finding fixed_version is not a string")
        else:
            _nonempty_string(value, f"Trivy finding {field}")
    return tuple(values[field] for field in FINDING_FIELDS)  # type: ignore[misc]


def validate_report(
    report: dict[str, Any], policy: dict[str, Any]
) -> tuple[set[tuple[str, ...]], set[tuple[str, str, str]]]:
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "repository":
        raise PolicyError("Trivy report identity is unsupported")
    results = report.get("Results")
    if not isinstance(results, list):
        raise PolicyError("Trivy report has no result inventory")
    findings: set[tuple[str, ...]] = set()
    targets: set[tuple[str, str, str]] = set()
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise PolicyError(f"Trivy result {index} is malformed")
        target = safe_relative_path(
            result.get("Target"), f"Trivy result {index} target"
        )
        result_class = _nonempty_string(result.get("Class"), "Trivy result class")
        result_type = _nonempty_string(result.get("Type"), "Trivy result type")
        targets.add((target, result_class, result_type))
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise PolicyError(f"Trivy vulnerabilities for {target} are malformed")
        for vulnerability in vulnerabilities:
            finding = _report_finding(target, vulnerability)
            if finding[-1] not in policy["scan"]["severities"]:
                raise PolicyError(
                    "Trivy returned a finding outside the requested severities"
                )
            if finding in findings:
                raise PolicyError("Trivy returned a duplicate finding")
            findings.add(finding)
    required_targets = {
        (target["path"], target["class"], target["type"])
        for target in policy["required_scan_targets"]
    }
    missing_targets = required_targets - targets
    if missing_targets:
        rendered = ", ".join(sorted(target[0] for target in missing_targets))
        raise PolicyError(f"Trivy omitted required dependency targets: {rendered}")
    return findings, targets


def candidate_findings(policy: dict[str, Any]) -> set[tuple[str, ...]]:
    return {
        (
            candidate["target"],
            finding["vulnerability_id"],
            finding["package_name"],
            finding["installed_version"],
            finding["fixed_version"],
            finding["severity"],
        )
        for candidate in policy["candidate_dispositions"]
        for finding in candidate["findings"]
    }


def _render_findings(values: set[tuple[str, ...]]) -> list[dict[str, str]]:
    return [
        dict(zip(FINDING_FIELDS, finding, strict=True)) for finding in sorted(values)
    ]


def evaluate_report(
    report: dict[str, Any], policy: dict[str, Any], *, source_clean: bool
) -> dict[str, Any]:
    findings, targets = validate_report(report, policy)
    expected = candidate_findings(policy)
    matched = findings.intersection(expected)
    unclassified = findings - expected
    missing = expected - findings
    if unclassified:
        status = "blocked_unclassified_findings"
    elif missing:
        status = "blocked_stale_candidate_assessment"
    elif findings:
        status = "blocked_pending_approval"
    elif not source_clean:
        status = "diagnostic_dirty_source"
    else:
        status = "eligible"
    release_eligible = status == "eligible"
    return {
        "candidate_matches": _render_findings(matched),
        "finding_count": len(findings),
        "missing_candidate_findings": _render_findings(missing),
        "release_eligible": release_eligible,
        "required_target_count": len(policy["required_scan_targets"]),
        "scanned_target_count": len(targets),
        "status": status,
        "unclassified_findings": _render_findings(unclassified),
    }


def require_external(path: Path, repository: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repository.resolve(strict=True))
    except ValueError:
        return resolved
    raise PolicyError(f"{label} must be outside the source checkout")


def require_private_directory(path: Path, label: str) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        metadata = path.stat()
    except OSError as error:
        raise PolicyError(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PolicyError(f"{label} must be an owner-private directory")


def write_new_private(path: Path, payload: bytes) -> None:
    require_private_directory(path.parent, "evidence output parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PolicyError(
            f"refusing non-new evidence output {path}: {error}"
        ) from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def git_source(repository: Path) -> dict[str, Any]:
    def run(*arguments: str) -> bytes:
        process = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if process.returncode != 0:
            raise PolicyError(f"git {' '.join(arguments)} failed")
        return process.stdout

    commit = run("rev-parse", "HEAD").decode("ascii").strip()
    if len(commit) != 40 or any(character not in HEX_DIGITS for character in commit):
        raise PolicyError("git commit identity is invalid")
    dirty_output = run("status", "--porcelain=v1", "--untracked-files=all")
    return {"clean": not dirty_output, "commit": commit}


def run_scan(
    *,
    repository: Path,
    policy: dict[str, Any],
    report_path: Path,
    receipt_path: Path,
    trivy: str,
    cargo: str,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    policy_payload = read_bounded(POLICY_PATH, MAX_POLICY_BYTES, "Trivy policy")
    report_path = require_external(report_path, repository, "Trivy report")
    receipt_path = require_external(receipt_path, repository, "Trivy receipt")
    if report_path == receipt_path:
        raise PolicyError("Trivy report and receipt paths must differ")
    if report_path.exists() or receipt_path.exists():
        raise PolicyError("Trivy evidence outputs must be new files")

    repository_evidence = verify_repository_authority(policy, repository)
    distribution_evidence = distribution_reachability_evidence(policy, repository)
    metadata_evidence = cargo_metadata_evidence(policy, repository, cargo)
    source = git_source(repository)
    expected_version = policy["scanner"]["version"]
    scanner_metadata(trivy, expected_version)

    require_private_directory(report_path.parent, "Trivy report parent")
    require_private_directory(receipt_path.parent, "Trivy receipt parent")
    with tempfile.TemporaryDirectory(
        prefix=".cigar-trivy-", dir=report_path.parent
    ) as raw_temporary:
        temporary = Path(raw_temporary)
        # Raw dependency inventory is security evidence and remains owner-private.
        # fmt: off
        os.chmod(temporary, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        # fmt: on
        config = temporary / "trivy.yaml"
        ignorefile = temporary / ".trivyignore"
        raw_report = temporary / "report.json"
        config.write_bytes(b"{}\n")
        ignorefile.write_bytes(b"")
        os.chmod(config, 0o600)
        os.chmod(ignorefile, 0o600)
        command = build_scan_command(trivy, policy, config, ignorefile, raw_report)
        try:
            process = subprocess.run(
                command,
                cwd=repository,
                env=scanner_environment(),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=policy["scan"]["timeout_seconds"] + 120,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PolicyError(f"cannot complete Trivy scan: {error}") from error
        if len(process.stderr) > MAX_SCANNER_STDERR_BYTES:
            raise PolicyError("Trivy diagnostics exceeded their output bound")
        if process.returncode != 0:
            raise PolicyError(
                f"Trivy failed with status {process.returncode}: "
                f"stderr_bytes={len(process.stderr)} "
                f"stderr_sha256={sha256_bytes(process.stderr)}"
            )
        report_payload = read_bounded(raw_report, MAX_REPORT_BYTES, "Trivy report")
        try:
            report = json.loads(report_payload)
        except json.JSONDecodeError as error:
            raise PolicyError(f"Trivy report is invalid JSON: {error}") from error
        if not isinstance(report, dict):
            raise PolicyError("Trivy report is not a JSON object")

    final_scanner_metadata = scanner_metadata(trivy, expected_version)
    database = validate_database_metadata(
        final_scanner_metadata, policy["scanner"]["max_database_age_hours"]
    )
    assessment = evaluate_report(report, policy, source_clean=source["clean"])
    if verify_repository_authority(policy, repository) != repository_evidence:
        raise PolicyError("dependency reachability authority changed during the scan")
    if distribution_reachability_evidence(policy, repository) != distribution_evidence:
        raise PolicyError(
            "artifact or SBOM reachability authority changed during the scan"
        )
    if git_source(repository) != source:
        raise PolicyError("git source state changed during the scan")
    if read_bounded(POLICY_PATH, MAX_POLICY_BYTES, "Trivy policy") != policy_payload:
        raise PolicyError("Trivy policy changed during the scan")
    receipt = {
        "assessment": assessment,
        "cargo_metadata": metadata_evidence,
        "distribution_reachability": distribution_evidence,
        "policy": {
            "path": POLICY_PATH.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(policy_payload),
        },
        "report": {
            "bytes": len(report_payload),
            "sha256": sha256_bytes(report_payload),
        },
        "repository_evidence": repository_evidence,
        "scanner": {
            "database": database,
            "name": policy["scanner"]["name"],
            "version": expected_version,
        },
        "schema_version": "cigar.trivy-scan-receipt.v1",
        "source": source,
    }
    write_new_private(report_path, report_payload)
    write_new_private(receipt_path, canonical_json_bytes(receipt))
    return receipt


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("scan", "verify-authority"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--trivy", default="trivy")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--receipt", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        policy = load_policy()
        if arguments.command == "verify-authority":
            if arguments.report is not None or arguments.receipt is not None:
                raise PolicyError("verify-authority does not accept evidence outputs")
            verify_repository_authority(policy, arguments.root)
            distribution_reachability_evidence(policy, arguments.root)
            cargo_metadata_evidence(policy, arguments.root, arguments.cargo)
            print("Trivy source reachability authority verified")
            return 0
        if arguments.report is None or arguments.receipt is None:
            raise PolicyError("scan requires --report and --receipt")
        receipt = run_scan(
            repository=arguments.root,
            policy=policy,
            report_path=arguments.report,
            receipt_path=arguments.receipt,
            trivy=arguments.trivy,
            cargo=arguments.cargo,
        )
        assessment = receipt["assessment"]
        print(
            "Trivy dependency policy: "
            f"status={assessment['status']} "
            f"findings={assessment['finding_count']} "
            f"release_eligible={str(assessment['release_eligible']).lower()}"
        )
        return 0 if assessment["release_eligible"] else 3
    except PolicyError as error:
        print(f"Trivy policy failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
