#!/usr/bin/env python3
"""Policy and independent raw-outcome validation for the full Rust mutation gate.

The authoritative xtask command owns process execution and evidence publication.
This module keeps package scope, command construction, and cargo-mutants 27.1.0
outcome validation deterministic and directly unit-testable without running a
mutation campaign.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import math
import re
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts" / "release"
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from release_lib import ReleaseError, load_json, matches, sha256_file  # noqa: E402


POLICY_PATH = "packaging/mutation-policy.v1.json"
REQUIREMENTS_PATH = "packaging/release-requirements.v1.json"
SAFE_PACKAGE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
EXPECTED_PRODUCTION_PACKAGES = (
    "cigar-api",
    "cigar-aws-creds",
    "cigar-canon",
    "cigar-catalog",
    "cigar-claude-hook",
    "cigar-cli",
    "cigar-code-intel",
    "cigar-compiler",
    "cigar-conformance",
    "cigar-crypto",
    "cigar-daemon",
    "cigar-dashboard",
    "cigar-effects",
    "cigar-extension-host",
    "cigar-mcp",
    "cigar-observe",
    "cigar-policy",
    "cigar-protocol",
    "cigar-replay",
    "cigar-retrieval",
    "cigar-rust-s3",
    "cigar-sdk",
    "cigar-space",
    "cigar-store",
)
EXPECTED_EXCLUDED_PACKAGES = (
    "cigar-sim",
    "cigar-soak",
    "cigar-testkit",
    "cigar-windows-ipc",
    "cigarbench-consumer",
    "xtask",
)
EXPECTED_EXCLUDED_SOURCE_GLOBS = (
    "**/benches/**",
    "**/examples/**",
    "**/generated/**",
    "**/tests/**",
    "vendor/**",
)
EXPECTED_CRITICAL_PACKAGES = (
    "cigar-canon",
    "cigar-catalog",
    "cigar-compiler",
    "cigar-crypto",
    "cigar-effects",
    "cigar-policy",
    "cigar-protocol",
    "cigar-replay",
    "cigar-retrieval",
    "cigar-space",
    "cigar-store",
)
EXPECTED_CRITICAL_SOURCE_GLOBS = (
    "crates/cigar-api/src/auth*.rs",
    "crates/cigar-daemon/src/*auth*.rs",
    "crates/cigar-daemon/src/effect*.rs",
    "crates/cigar-extension-host/src/**",
)
OUTCOME_TOP_LEVEL_FIELDS = {
    "outcomes",
    "total_mutants",
    "missed",
    "caught",
    "timeout",
    "unviable",
    "success",
    "start_time",
    "end_time",
    "cargo_mutants_version",
}
MUTANT_FIELDS = {
    "name",
    "package",
    "file",
    "function",
    "span",
    "replacement",
    "genre",
}
OUTCOME_FIELDS = {"scenario", "summary", "log_path", "diff_path", "phase_results"}
PHASE_FIELDS = {"phase", "duration", "process_status", "argv"}


class MutationCampaignError(RuntimeError):
    """A mutation policy, package scope, or raw outcome failed validation."""


def _safe_glob(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(("/", "-"))
        or "\\" in value
        or "\0" in value
        or any(part == ".." for part in PurePosixPath(value).parts)
    ):
        raise MutationCampaignError("mutation policy contains an unsafe glob")
    return value


def load_policy(root: Path = ROOT) -> dict[str, Any]:
    try:
        policy = load_json(root / POLICY_PATH)
        requirements = load_json(root / REQUIREMENTS_PATH)
    except (OSError, ReleaseError) as error:
        raise MutationCampaignError(f"cannot read mutation policy: {error}") from error
    expected_fields = {
        "schema_version",
        "platform_scope",
        "cargo_mutants_version",
        "minimum_campaign_seconds",
        "minimum_score_percent",
        "maximum_timeout_count",
        "maximum_critical_viable_survivor_count",
        "jobs",
        "per_command_timeout_seconds",
        "minimum_test_timeout_seconds",
        "production_packages",
        "excluded_packages",
        "excluded_source_globs",
        "critical_packages",
        "critical_source_globs",
    }
    if not isinstance(policy, dict) or set(policy) != expected_fields:
        raise MutationCampaignError("mutation policy has an unexpected shape")
    production = policy.get("production_packages")
    excluded = policy.get("excluded_packages")
    critical = policy.get("critical_packages")
    critical_globs = policy.get("critical_source_globs")
    if (
        policy.get("schema_version") != "cigar.mutation-policy.v1"
        or policy.get("platform_scope") != ["macos-arm64"]
        or policy.get("cargo_mutants_version") != "27.1.0"
        or policy.get("minimum_campaign_seconds") != 14_400
        or policy.get("minimum_score_percent") != 90.0
        or policy.get("maximum_timeout_count") != 0
        or policy.get("maximum_critical_viable_survivor_count") != 0
        or policy.get("jobs") != 4
        or policy.get("per_command_timeout_seconds") != 120
        or policy.get("minimum_test_timeout_seconds") != 20
        or not isinstance(production, list)
        or tuple(production) != EXPECTED_PRODUCTION_PACKAGES
        or len(production) != len(set(production))
        or any(
            not isinstance(name, str) or SAFE_PACKAGE.fullmatch(name) is None
            for name in production
        )
        or not isinstance(excluded, list)
        or not excluded
        or not isinstance(critical, list)
        or tuple(critical) != EXPECTED_CRITICAL_PACKAGES
        or not set(critical).issubset(production)
        or not isinstance(critical_globs, list)
        or not critical_globs
    ):
        raise MutationCampaignError("mutation policy is malformed or weakened")
    exclusion_names: list[str] = []
    for exclusion in excluded:
        if (
            not isinstance(exclusion, dict)
            or set(exclusion) != {"name", "reason"}
            or not isinstance(exclusion.get("name"), str)
            or SAFE_PACKAGE.fullmatch(exclusion["name"]) is None
            or not isinstance(exclusion.get("reason"), str)
            or not exclusion["reason"]
        ):
            raise MutationCampaignError("mutation package exclusion is invalid")
        exclusion_names.append(exclusion["name"])
    if exclusion_names != sorted(exclusion_names) or len(exclusion_names) != len(
        set(exclusion_names)
    ):
        raise MutationCampaignError(
            "mutation package exclusions are duplicated or unordered"
        )
    if tuple(exclusion_names) != EXPECTED_EXCLUDED_PACKAGES:
        raise MutationCampaignError("mutation package exclusions were weakened")
    if set(exclusion_names).intersection(production):
        raise MutationCampaignError("mutation production and excluded packages overlap")
    source_globs = tuple(_safe_glob(value) for value in policy["excluded_source_globs"])
    if source_globs != EXPECTED_EXCLUDED_SOURCE_GLOBS:
        raise MutationCampaignError(
            "mutation generated/vendor/test exclusions were weakened"
        )
    normalized_critical_globs = tuple(_safe_glob(value) for value in critical_globs)
    if normalized_critical_globs != EXPECTED_CRITICAL_SOURCE_GLOBS:
        raise MutationCampaignError("mutation critical source scope was weakened")

    gates = {
        gate.get("name"): gate
        for gate in requirements.get("metric_gates", [])
        if isinstance(gate, dict) and gate.get("category") == "mutation"
    }
    expected_gates = {
        "mutation.score_percent": ("gte", 90.0),
        "mutation.duration_seconds": ("gte", 14_400),
        "mutation.production_package_fraction": ("gte", 1.0),
        "mutation.timeout_count": ("lte", 0),
        "mutation.critical_viable_survivor_count": ("lte", 0),
    }
    if set(gates) != set(expected_gates) or any(
        gates[name].get("comparison") != comparison
        or float(gates[name].get("threshold", math.nan)) != threshold
        for name, (comparison, threshold) in expected_gates.items()
    ):
        raise MutationCampaignError(
            "release mutation metric policy disagrees with campaign policy"
        )
    return {
        **policy,
        "excluded_package_names": exclusion_names,
        "policy_sha256": sha256_file(root / POLICY_PATH),
        "requirements_sha256": sha256_file(root / REQUIREMENTS_PATH),
    }


def workspace_package_inventory(
    root: Path, metadata: object, policy: Mapping[str, Any]
) -> dict[str, Path]:
    if not isinstance(metadata, dict):
        raise MutationCampaignError("mutation Cargo metadata root is invalid")
    packages = metadata.get("packages")
    members = metadata.get("workspace_members")
    workspace_root = metadata.get("workspace_root")
    if (
        not isinstance(packages, list)
        or not isinstance(members, list)
        or not all(isinstance(member, str) for member in members)
        or workspace_root != str(root)
    ):
        raise MutationCampaignError(
            "mutation Cargo metadata workspace identity is invalid"
        )
    member_ids = set(members)
    inventory: dict[str, Path] = {}
    for package in packages:
        if not isinstance(package, dict) or package.get("id") not in member_ids:
            continue
        name = package.get("name")
        manifest = package.get("manifest_path")
        if (
            not isinstance(name, str)
            or not isinstance(manifest, str)
            or name in inventory
        ):
            raise MutationCampaignError(
                "mutation workspace package metadata is invalid"
            )
        try:
            path = Path(manifest).resolve(strict=True)
            path.relative_to(root)
        except (OSError, ValueError) as error:
            raise MutationCampaignError(
                f"mutation package {name} is outside the repository"
            ) from error
        if path.name != "Cargo.toml":
            raise MutationCampaignError(f"mutation package {name} manifest is invalid")
        inventory[name] = path.parent
    if len(inventory) != len(member_ids):
        raise MutationCampaignError(
            "mutation workspace package inventory is incomplete"
        )
    expected = set(policy["production_packages"]) | set(
        policy["excluded_package_names"]
    )
    if set(inventory) != expected:
        raise MutationCampaignError(
            "mutation package policy omits or invents workspace packages; "
            f"missing={sorted(set(inventory) - expected)}, stale={sorted(expected - set(inventory))}"
        )
    return inventory


def scope_arguments(policy: Mapping[str, Any]) -> list[str]:
    arguments = ["--workspace"]
    for package in policy["production_packages"]:
        arguments.extend(["--package", package])
    for pattern in policy["excluded_source_globs"]:
        arguments.extend(["--exclude", pattern])
    return arguments


def list_files_command(policy: Mapping[str, Any]) -> list[str]:
    return [
        "cargo",
        "mutants",
        "--no-config",
        "--copy-vcs=false",
        "--gitignore=true",
        *scope_arguments(policy),
        "--list-files",
        "--json",
        "--colors",
        "never",
    ]


def campaign_command(policy: Mapping[str, Any], output_parent: Path) -> list[str]:
    return [
        "cargo",
        "mutants",
        "--no-config",
        "--copy-vcs=false",
        "--gitignore=true",
        *scope_arguments(policy),
        "--cargo-arg=--locked",
        "--cargo-arg=--offline",
        "--baseline",
        "run",
        "--test-tool",
        "nextest",
        "--jobs",
        str(policy["jobs"]),
        "--timeout",
        str(policy["per_command_timeout_seconds"]),
        "--minimum-test-timeout",
        str(policy["minimum_test_timeout_seconds"]),
        "--no-shuffle",
        "--colors",
        "never",
        "--annotations",
        "none",
        "--output",
        str(output_parent),
    ]


def _parse_utc(value: object, label: str) -> dt.datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
            value,
        )
        is None
    ):
        raise MutationCampaignError(f"cargo-mutants {label} timestamp is invalid")
    integral, dot, fractional = value.removesuffix("Z").partition(".")
    normalized = (
        integral + (f".{fractional[:6].ljust(6, '0')}" if dot else "") + "+00:00"
    )
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise MutationCampaignError(
            f"cargo-mutants {label} timestamp is invalid"
        ) from error
    return parsed


def _safe_relative_source(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise MutationCampaignError("cargo-mutants source path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise MutationCampaignError("cargo-mutants source path is unsafe")
    return path.as_posix()


def _safe_output_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise MutationCampaignError(f"cargo-mutants {label} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise MutationCampaignError(f"cargo-mutants {label} path is unsafe")
    return path.as_posix()


def _position(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, dict) or set(value) != {"line", "column"}:
        raise MutationCampaignError(f"cargo-mutants {label} position is invalid")
    line = value.get("line")
    column = value.get("column")
    if (
        isinstance(line, bool)
        or not isinstance(line, int)
        or line <= 0
        or isinstance(column, bool)
        or not isinstance(column, int)
        or column <= 0
    ):
        raise MutationCampaignError(f"cargo-mutants {label} position is invalid")
    return line, column


def _span(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"start", "end"}:
        raise MutationCampaignError(f"cargo-mutants {label} span is invalid")
    start = _position(value.get("start"), f"{label} start")
    end = _position(value.get("end"), f"{label} end")
    if end <= start:
        raise MutationCampaignError(f"cargo-mutants {label} span is empty or reversed")


def _validate_mutant_shape(mutant: Mapping[str, Any]) -> None:
    name = mutant.get("name")
    source = _safe_relative_source(mutant.get("file"))
    replacement = mutant.get("replacement")
    genre = mutant.get("genre")
    if (
        not isinstance(name, str)
        or not name
        or "\0" in name
        or not name.startswith(f"{source}:")
        or not isinstance(replacement, str)
        or "\0" in replacement
        or not isinstance(genre, str)
        or not genre
    ):
        raise MutationCampaignError("cargo-mutants mutant fields are malformed")
    _span(mutant.get("span"), "mutant")
    function = mutant.get("function")
    if function is not None:
        if not isinstance(function, dict) or set(function) != {
            "function_name",
            "return_type",
            "span",
        }:
            raise MutationCampaignError("cargo-mutants function identity is malformed")
        if (
            not isinstance(function.get("function_name"), str)
            or not function["function_name"]
            or not isinstance(function.get("return_type"), str)
        ):
            raise MutationCampaignError("cargo-mutants function identity is malformed")
        _span(function.get("span"), "function")


def _process_status_kind(value: object) -> str:
    if isinstance(value, str) and value in {"Success", "Timeout", "Other"}:
        return value
    if isinstance(value, dict) and len(value) == 1:
        key, status = next(iter(value.items()))
        if (
            key in {"Failure", "Signalled"}
            and isinstance(status, int)
            and not isinstance(status, bool)
        ):
            return str(key)
    raise MutationCampaignError("cargo-mutants phase process status is malformed")


def _derived_summary(outcome: Mapping[str, Any], *, baseline: bool) -> str:
    phase_results = outcome.get("phase_results")
    if not isinstance(phase_results, list) or not phase_results:
        raise MutationCampaignError("cargo-mutants phase result list is empty")
    ordered_phases = {"Check": 0, "Build": 1, "Test": 2}
    previous = -1
    parsed: list[tuple[str, str]] = []
    for phase_result in phase_results:
        if not isinstance(phase_result, dict) or set(phase_result) != PHASE_FIELDS:
            raise MutationCampaignError("cargo-mutants phase result is malformed")
        phase = phase_result.get("phase")
        duration = phase_result.get("duration")
        argv = phase_result.get("argv")
        if (
            phase not in ordered_phases
            or ordered_phases[str(phase)] <= previous
            or isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration))
            or float(duration) < 0
            or not isinstance(argv, list)
            or not argv
            or any(
                not isinstance(argument, str) or "\0" in argument for argument in argv
            )
        ):
            raise MutationCampaignError("cargo-mutants phase result is malformed")
        previous = ordered_phases[str(phase)]
        parsed.append(
            (str(phase), _process_status_kind(phase_result["process_status"]))
        )
    statuses = [status for _, status in parsed]
    if "Timeout" in statuses:
        return "Timeout"
    if baseline:
        return "Success" if statuses[-1] == "Success" else "Failure"
    if any(phase != "Test" and status == "Failure" for phase, status in parsed):
        return "Unviable"
    last_phase, last_status = parsed[-1]
    if last_phase == "Test" and last_status == "Failure":
        return "CaughtMutant"
    if last_phase == "Test" and last_status == "Success":
        return "MissedMutant"
    if last_status == "Success":
        return "Success"
    return "Failure"


def _source_is_excluded(path: str, policy: Mapping[str, Any]) -> bool:
    return matches(path, policy["excluded_source_globs"])


def _critical_mutant(mutant: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return mutant.get("package") in policy["critical_packages"] or any(
        fnmatch.fnmatchcase(str(mutant.get("file")), pattern)
        for pattern in policy["critical_source_globs"]
    )


def _mutant_identity(mutant: object, policy: Mapping[str, Any]) -> tuple[str, str, str]:
    if not isinstance(mutant, dict) or set(mutant) != MUTANT_FIELDS:
        raise MutationCampaignError(
            "cargo-mutants mutant identity has an unexpected shape"
        )
    package = mutant.get("package")
    name = mutant.get("name")
    source = _safe_relative_source(mutant.get("file"))
    _validate_mutant_shape(mutant)
    if (
        package not in policy["production_packages"]
        or not isinstance(name, str)
        or not name
        or _source_is_excluded(source, policy)
    ):
        raise MutationCampaignError(
            "cargo-mutants selected an excluded or unknown source"
        )
    return str(package), source, name


def validate_source_files(
    source_files: object,
    inventory: Mapping[str, Path],
    policy: Mapping[str, Any],
) -> list[dict[str, str]]:
    if not isinstance(source_files, list) or not source_files:
        raise MutationCampaignError("cargo-mutants source-file inventory is empty")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    packages: set[str] = set()
    for entry in source_files:
        if not isinstance(entry, dict) or set(entry) != {"path", "package"}:
            raise MutationCampaignError("cargo-mutants source-file entry is invalid")
        package = entry.get("package")
        path = _safe_relative_source(entry.get("path"))
        if package not in policy["production_packages"] or _source_is_excluded(
            path, policy
        ):
            raise MutationCampaignError(
                "cargo-mutants source-file scope includes an excluded path"
            )
        package_root = inventory.get(str(package))
        if package_root is None:
            raise MutationCampaignError(
                "cargo-mutants source file names an unknown package"
            )
        try:
            (ROOT / path).resolve(strict=True).relative_to(package_root)
        except (OSError, ValueError) as error:
            raise MutationCampaignError(
                "cargo-mutants source file has the wrong package owner"
            ) from error
        identity = (str(package), path)
        if identity in seen:
            raise MutationCampaignError(
                "cargo-mutants source-file inventory is duplicated"
            )
        seen.add(identity)
        packages.add(str(package))
        normalized.append({"package": str(package), "path": path})
    missing = sorted(set(policy["production_packages"]) - packages)
    if missing:
        raise MutationCampaignError(
            f"cargo-mutants source-file inventory omits packages: {missing}"
        )
    return sorted(normalized, key=lambda entry: (entry["package"], entry["path"]))


def validate_campaign_documents(
    *,
    outcomes: object,
    discovered_mutants: object,
    source_files: object,
    inventory: Mapping[str, Path],
    policy: Mapping[str, Any],
    observed_duration_seconds: float,
) -> tuple[dict[str, int | float], dict[str, Any]]:
    normalized_sources = validate_source_files(source_files, inventory, policy)
    source_identities = {
        (entry["package"], entry["path"]) for entry in normalized_sources
    }
    if not isinstance(discovered_mutants, list) or not discovered_mutants:
        raise MutationCampaignError("cargo-mutants discovered no mutation candidates")
    discovered: dict[tuple[str, str, str], dict[str, Any]] = {}
    normalized_mutants: list[dict[str, Any]] = []
    for raw in discovered_mutants:
        if not isinstance(raw, dict) or set(raw) != MUTANT_FIELDS | {"diff"}:
            raise MutationCampaignError(
                "cargo-mutants discovered mutant has an unexpected shape"
            )
        normalized = {key: raw[key] for key in MUTANT_FIELDS}
        identity = _mutant_identity(normalized, policy)
        if (identity[0], identity[1]) not in source_identities:
            raise MutationCampaignError(
                "cargo-mutants discovered a mutant outside its source-file inventory"
            )
        if identity in discovered:
            raise MutationCampaignError(
                "cargo-mutants discovered duplicate mutant identities"
            )
        discovered[identity] = normalized
        normalized_mutants.append(normalized)
    discovered_packages = {identity[0] for identity in discovered}
    missing_mutant_packages = sorted(
        set(policy["production_packages"]) - discovered_packages
    )
    if missing_mutant_packages:
        raise MutationCampaignError(
            "cargo-mutants discovered no candidates for production packages: "
            f"{missing_mutant_packages}"
        )
    if not isinstance(outcomes, dict) or set(outcomes) != OUTCOME_TOP_LEVEL_FIELDS:
        raise MutationCampaignError(
            "cargo-mutants outcome document has an unexpected shape"
        )
    if outcomes.get("cargo_mutants_version") != policy["cargo_mutants_version"]:
        raise MutationCampaignError(
            "cargo-mutants outcome version is stale or substituted"
        )
    raw_outcomes = outcomes.get("outcomes")
    if not isinstance(raw_outcomes, list) or not raw_outcomes:
        raise MutationCampaignError("cargo-mutants outcome list is empty")
    start = _parse_utc(outcomes.get("start_time"), "start")
    end = _parse_utc(outcomes.get("end_time"), "end")
    duration = (end - start).total_seconds()
    if (
        not math.isfinite(duration)
        or duration < 0
        or not math.isfinite(observed_duration_seconds)
        or observed_duration_seconds < 0
        or duration > observed_duration_seconds + 5.0
    ):
        raise MutationCampaignError(
            "cargo-mutants recorded and observed durations do not reconcile"
        )
    counts = {
        name: 0 for name in ("caught", "missed", "timeout", "unviable", "success")
    }
    baseline_count = 0
    seen_outcomes: set[tuple[str, str, str]] = set()
    critical_survivors: list[tuple[str, str, str]] = []
    for outcome in raw_outcomes:
        if not isinstance(outcome, dict) or set(outcome) != OUTCOME_FIELDS:
            raise MutationCampaignError(
                "cargo-mutants scenario outcome has an unexpected shape"
            )
        scenario = outcome.get("scenario")
        summary = outcome.get("summary")
        _safe_output_path(outcome.get("log_path"), "log")
        if scenario == "Baseline":
            baseline_count += 1
            if outcome.get("diff_path") is not None:
                raise MutationCampaignError("cargo-mutants baseline has a diff path")
            if (
                summary != _derived_summary(outcome, baseline=True)
                or summary != "Success"
            ):
                raise MutationCampaignError("cargo-mutants baseline did not pass")
            continue
        if not isinstance(scenario, dict) or set(scenario) != {"Mutant"}:
            raise MutationCampaignError("cargo-mutants scenario identity is invalid")
        mutant = scenario["Mutant"]
        identity = _mutant_identity(mutant, policy)
        _safe_output_path(outcome.get("diff_path"), "diff")
        if (
            identity in seen_outcomes
            or identity not in discovered
            or mutant != discovered[identity]
        ):
            raise MutationCampaignError(
                "cargo-mutants outcome is duplicate or absent from discovery"
            )
        seen_outcomes.add(identity)
        summary_to_count = {
            "CaughtMutant": "caught",
            "MissedMutant": "missed",
            "Timeout": "timeout",
            "Unviable": "unviable",
            "Success": "success",
        }
        count_name = summary_to_count.get(summary)
        if count_name is None or summary != _derived_summary(outcome, baseline=False):
            raise MutationCampaignError("cargo-mutants scenario summary is unsupported")
        counts[count_name] += 1
        if summary == "MissedMutant" and _critical_mutant(mutant, policy):
            critical_survivors.append(identity)
    if baseline_count != 1 or seen_outcomes != set(discovered):
        raise MutationCampaignError(
            "cargo-mutants outcomes omit the baseline or discovered mutants"
        )
    for name, derived in counts.items():
        claimed = outcomes.get(name)
        if (
            isinstance(claimed, bool)
            or not isinstance(claimed, int)
            or claimed != derived
        ):
            raise MutationCampaignError(
                f"cargo-mutants {name} count does not reconcile"
            )
    total = outcomes.get("total_mutants")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total != sum(counts.values())
    ):
        raise MutationCampaignError(
            "cargo-mutants total mutant count does not reconcile"
        )
    denominator = counts["caught"] + counts["missed"] + counts["timeout"]
    if denominator <= 0 or counts["success"] != 0:
        raise MutationCampaignError(
            "cargo-mutants viable denominator is empty or malformed"
        )
    score = round(100.0 * counts["caught"] / denominator, 6)
    metrics: dict[str, int | float] = {
        "mutation.score_percent": score,
        "mutation.duration_seconds": int(duration),
        "mutation.production_package_fraction": 1.0,
        "mutation.timeout_count": counts["timeout"],
        "mutation.critical_viable_survivor_count": len(critical_survivors),
    }
    failures: list[str] = []
    if score < float(policy["minimum_score_percent"]):
        failures.append("score")
    if duration < int(policy["minimum_campaign_seconds"]):
        failures.append("duration")
    if counts["timeout"] > int(policy["maximum_timeout_count"]):
        failures.append("timeouts")
    if len(critical_survivors) > int(policy["maximum_critical_viable_survivor_count"]):
        failures.append("critical-survivors")
    if failures:
        raise MutationCampaignError(
            "mutation campaign does not satisfy release thresholds: "
            + ", ".join(failures)
        )
    return metrics, {
        "policy": {
            "path": POLICY_PATH,
            "sha256": policy["policy_sha256"],
            "release_requirements_sha256": policy["requirements_sha256"],
        },
        "production_packages": list(policy["production_packages"]),
        "excluded_packages": [dict(item) for item in policy["excluded_packages"]],
        "excluded_source_globs": list(policy["excluded_source_globs"]),
        "source_files": normalized_sources,
        "discovered_mutants": sorted(
            normalized_mutants,
            key=lambda mutant: (
                str(mutant["package"]),
                str(mutant["file"]),
                str(mutant["name"]),
            ),
        ),
        "outcomes": outcomes,
        "counts": counts,
        "viable_denominator": denominator,
        "critical_survivor_identities": [
            {"package": package, "file": path, "name": name}
            for package, path, name in sorted(critical_survivors)
        ],
    }


if __name__ == "__main__":
    try:
        selected = load_policy()
    except MutationCampaignError as error:
        print(f"mutation policy failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    print(
        f"validated {len(selected['production_packages'])} production packages; "
        "no mutation campaign executed"
    )
