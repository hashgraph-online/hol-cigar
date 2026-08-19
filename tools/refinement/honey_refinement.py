"""Validate and plan the private Honey 0.9.2 three-way refinement cohort."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from .canonical import canonical_bytes, identity, load_file
from .schema import SchemaRegistry
from .source_build import SourceBuildError, build_source_consumers

PROFILE_PATH = Path("refinement/profiles/honey-0.9.2-refinement-profile.v1.json")
PROFILE_SCHEMA = "honey-refinement-profile-v1.schema.json"
COHORT_SCHEMA = "three-way-cohort-v1.schema.json"
PLAN_SCHEMA = "honey-evaluation-plan-v1.schema.json"
BUILD_SCHEMA = "source-consumer-build-set-v1.schema.json"
EXPECTED_PROFILE_ID = "cigar.honey.0.9.2-h1.refinement.macos-arm64.v1"
EXPECTED_SOURCES = ("published-honey", "champion", "candidate")
EXPECTED_LANES = (
    "kernel-source",
    "source-sidecar",
    "installed-sidecar",
    "humidor-source",
    "humidor-installed",
)
EXPECTED_WORKFLOWS = (
    "marketing_campaign",
    "product_requirements_document",
    "code_review",
    "executive_briefing",
    "customer_escalation",
    "employee_onboarding",
)
EXPECTED_SCENARIOS = (
    "large-catalogs-and-long-documents",
    "duplicate-and-near-duplicate-evidence",
    "mandatory-and-conflicting-sources",
    "revoked-or-expired-authorization",
    "poisoned-and-prompt-injection-content",
    "sparse-graphs-and-pruned-indexes",
    "restart-and-crash-recovery",
    "storage-migration-and-compaction",
    "warm-and-cold-semantic-reuse",
    "missing-corrupt-and-stale-evidence",
    "agent-handoff-recipient-binding",
    "effect-ambiguity-and-reconciliation",
)
EXPECTED_THRESHOLDS: dict[str, tuple[str, float | str, str, str]] = {
    "workflow-completion": ("exactly", 1.0, "ratio", "global-and-workflow"),
    "required-source-coverage": ("exactly", 1.0, "ratio", "global-and-workflow"),
    "citation-resolvability": ("at-least", 0.99, "ratio", "global-and-workflow"),
    "duplicate-selected-content": ("at-most", 0.05, "ratio", "global-and-workflow"),
    "budget-displaced-to-selected": ("less-than", 10.0, "ratio", "global-and-workflow"),
    "latency-slope": ("at-most", 10.0, "milliseconds-per-request", "global"),
    "startup-at-retention-ceiling": ("at-most", 30.0, "seconds", "global"),
    "steady-state-storage-growth": (
        "less-than",
        1048576,
        "bytes-per-compilation",
        "global",
    ),
    "lineage-diversity-delta": ("nonnegative", 0.0, "ratio", "global-and-workflow"),
    "hard-invariants": ("all-pass", "pass", "status", "global"),
    "protected-strata": ("all-pass", "pass", "status", "protected-stratum"),
    "public-v1-operation-count": ("unchanged", 45, "count", "protocol"),
    "public-v1-payload-count": ("unchanged", 70, "count", "protocol"),
}
CONTROL_PATH_PREFIXES = (
    "benches/cigarbench/consumer/",
    "refinement/cohorts/",
    "refinement/profiles/honey-0.9.2-refinement-profile.v1.json",
    "schemas/refinement/honey-evaluation-plan-v1.schema.json",
    "schemas/refinement/honey-refinement-profile-v1.schema.json",
    "schemas/refinement/honey-three-way-execution-attachment-v1.schema.json",
    "schemas/refinement/honey-three-way-qualification-v1.schema.json",
    "schemas/refinement/honey-treatment-failure-evaluation-v1.schema.json",
    "schemas/refinement/assignment-v2.schema.json",
    "schemas/refinement/benchmark-three-way-v1.schema.json",
    "schemas/refinement/intelligence-profile-evaluation-v1.schema.json",
    "schemas/refinement/observation-v2.schema.json",
    "schemas/refinement/source-consumer-build-set-v1.schema.json",
    "schemas/refinement/three-way-cohort-v1.schema.json",
    "tools/refinement/honey_refinement.py",
    "tools/refinement/consumer.py",
    "tools/refinement/intelligence.py",
    "tools/refinement/source_build.py",
    "tools/refinement/three_way.py",
    "tools/refinement/tests/test_r03_consumer.py",
    "tools/refinement/tests/test_r14_honey_refinement.py",
    "refinement/README.md",
    "refinement/CONTINUOUS_REFINEMENT.md",
)


class HoneyRefinementError(ValueError):
    """A refinement authority, source, cohort, or plan failed closed."""


def _canonical_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise HoneyRefinementError(f"{label} must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise HoneyRefinementError(f"{label} is unavailable") from error
    if resolved != path or not path.is_dir():
        raise HoneyRefinementError(f"{label} must be a canonical directory")
    return resolved


def _git(
    root: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("git")
    if executable is None:
        raise HoneyRefinementError("Git is unavailable")
    try:
        return subprocess.run(  # noqa: S603
            [executable, "-C", os.fspath(root), *arguments],
            check=check,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise HoneyRefinementError("Git identity operation failed") from error


def _git_text(root: Path, *arguments: str) -> str:
    try:
        return _git(root, *arguments).stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise HoneyRefinementError("Git returned non-UTF-8 output") from error


def _source(root: Path, revision: str) -> dict[str, str]:
    commit = _git_text(root, "rev-parse", f"{revision}^{{commit}}")
    return {
        "revision": commit,
        "tree": _git_text(root, "rev-parse", f"{commit}^{{tree}}"),
    }


def _sha256(path: Path) -> str:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise HoneyRefinementError("artifact is not a single-link regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat(follow_symlinks=False)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise HoneyRefinementError("artifact changed while it was hashed")
    return digest.hexdigest()


def _verify_artifact(root: Path, artifact: dict[str, Any]) -> None:
    path = root / artifact["path"]
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise HoneyRefinementError(
            f"artifact is unavailable: {artifact['artifact_id']}"
        ) from error
    if path.is_symlink() or not resolved.is_relative_to(root):
        raise HoneyRefinementError(
            f"artifact escaped its repository: {artifact['artifact_id']}"
        )
    if (
        resolved.stat().st_size != artifact["bytes"]
        or _sha256(resolved) != artifact["sha256"]
    ):
        raise HoneyRefinementError(
            f"artifact identity drifted: {artifact['artifact_id']}"
        )


def _verify_external_artifact(
    root: Path,
    source: dict[str, str],
    artifact: dict[str, Any],
) -> None:
    payload = _git(root, "show", f"{source['revision']}:{artifact['path']}").stdout
    if (
        len(payload) != artifact["bytes"]
        or hashlib.sha256(payload).hexdigest() != artifact["sha256"]
    ):
        raise HoneyRefinementError(
            f"external artifact identity drifted: {artifact['artifact_id']}"
        )


def _assert_source(root: Path, expected: dict[str, str], label: str) -> None:
    observed = _source(root, expected["revision"])
    if observed != expected:
        raise HoneyRefinementError(f"{label} source identity drifted")


def _assert_origin(root: Path, expected: str, label: str) -> None:
    try:
        observed = _git_text(root, "remote", "get-url", "origin")
    except HoneyRefinementError as error:
        raise HoneyRefinementError(f"{label} origin is unavailable") from error
    slug = expected.removeprefix("https://github.com/").removesuffix(".git")
    accepted = {
        expected,
        f"git@github.com:{slug}.git",
        f"ssh://git@github.com/{slug}.git",
    }
    if observed not in accepted:
        raise HoneyRefinementError(
            f"{label} origin does not match the frozen repository"
        )


def _assert_clean_head(root: Path, expected: dict[str, str], label: str) -> None:
    if _source(root, "HEAD") != expected:
        raise HoneyRefinementError(f"{label} checkout does not match its frozen source")
    if _git_text(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise HoneyRefinementError(f"{label} checkout is not clean")


def load_authority(repository_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root = _canonical_directory(repository_root, "Shadow CIGAR root")
    registry = SchemaRegistry(root / "schemas/refinement")
    profile = load_file((root / PROFILE_PATH).resolve(strict=True))
    registry.validate(PROFILE_SCHEMA, profile)
    cohort_path = (root / profile["evaluation"]["cohort"]["path"]).resolve(strict=True)
    cohort = load_file(cohort_path)
    registry.validate(COHORT_SCHEMA, cohort)
    unsigned_cohort = dict(cohort)
    claimed_cohort_id = unsigned_cohort.pop("cohort_id")
    if identity(unsigned_cohort) != claimed_cohort_id:
        raise HoneyRefinementError("three-way cohort identity is invalid")
    if (
        profile["profile_id"] != EXPECTED_PROFILE_ID
        or cohort["profile_id"] != EXPECTED_PROFILE_ID
    ):
        raise HoneyRefinementError("Honey refinement profile identity drifted")
    for artifact in profile["evaluation"].values():
        if isinstance(artifact, dict):
            _verify_artifact(root, artifact)
    for artifact in cohort["kernel"].values():
        if isinstance(artifact, dict):
            _verify_artifact(root, artifact)
    thresholds = {
        row["id"]: (row["operator"], row["value"], row["unit"], row["scope"])
        for row in profile["promotion_thresholds"]
    }
    if thresholds != EXPECTED_THRESHOLDS:
        raise HoneyRefinementError("Honey promotion thresholds drifted")
    if tuple(row["id"] for row in profile["cycles"]) != (
        "cycle-a",
        "cycle-b",
        "cycle-c",
    ):
        raise HoneyRefinementError("bounded refinement cycle order drifted")
    if tuple(cohort["execution_matrix"]["source_roles"]) != EXPECTED_SOURCES:
        raise HoneyRefinementError("three-way source role order drifted")
    if tuple(cohort["execution_matrix"]["lanes"]) != EXPECTED_LANES:
        raise HoneyRefinementError("evaluation lane order drifted")
    if tuple(cohort["downstream"]["workflows"]) != EXPECTED_WORKFLOWS:
        raise HoneyRefinementError("the frozen six-workflow set drifted")
    if tuple(row["id"] for row in cohort["scenario_classes"]) != EXPECTED_SCENARIOS:
        raise HoneyRefinementError("the adversarial scenario set drifted")
    return profile, cohort


def validate(
    *,
    repository_root: Path,
    core_root: Path | None = None,
    cedar_root: Path | None = None,
    require_external_clean_heads: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = _canonical_directory(repository_root, "Shadow CIGAR root")
    profile, cohort = load_authority(root)
    honey = profile["frozen_sources"]["published_honey"]
    champion = profile["frozen_sources"]["champion"]
    _assert_source(root, honey["source"], "published Honey")
    _assert_source(root, champion["source"], "private champion")
    if _git(
        root,
        "merge-base",
        "--is-ancestor",
        champion["source"]["revision"],
        "refs/heads/main",
        check=False,
    ).returncode:
        raise HoneyRefinementError(
            "Shadow main does not descend from the frozen champion"
        )
    if _git_text(root, "remote", "get-url", "public") != honey["repository"]:
        raise HoneyRefinementError("public distribution fetch remote drifted")
    if _git_text(root, "remote", "get-url", "--push", "public") != "DISABLED":
        raise HoneyRefinementError("public distribution push is not disabled")
    _assert_origin(root, champion["repository"], "Shadow CIGAR")
    if core_root is not None:
        core = _canonical_directory(core_root, "HUMIDOR Core root")
        core_source = cohort["downstream"]["humidor_source"]
        _assert_origin(core, core_source["repository"], "HUMIDOR")
        _assert_source(core, core_source["source"], "HUMIDOR")
        for artifact in cohort["downstream"]["fixtures"]:
            if artifact["repository_role"] == "humidor":
                _verify_external_artifact(core, core_source["source"], artifact)
        if require_external_clean_heads:
            _assert_clean_head(core, core_source["source"], "HUMIDOR")
    if cedar_root is not None:
        cedar = _canonical_directory(cedar_root, "CEDAR root")
        cedar_source = cohort["downstream"]["cedar_source"]
        _assert_origin(cedar, cedar_source["repository"], "CEDAR")
        _assert_source(cedar, cedar_source["source"], "CEDAR")
        for artifact in cohort["downstream"]["fixtures"]:
            if artifact["repository_role"] == "cedar":
                _verify_external_artifact(cedar, cedar_source["source"], artifact)
        if require_external_clean_heads:
            _assert_clean_head(cedar, cedar_source["source"], "CEDAR")
    return profile, cohort


def _cycle_a_scope(root: Path, champion: str, candidate: str) -> None:
    changed = _git_text(
        root, "diff", "--name-only", f"{champion}..{candidate}"
    ).splitlines()
    if not changed:
        raise HoneyRefinementError("Cycle A candidate contains no harness correction")
    forbidden = [
        path
        for path in changed
        if not any(
            path == prefix or path.startswith(prefix)
            for prefix in CONTROL_PATH_PREFIXES
        )
    ]
    if forbidden:
        raise HoneyRefinementError(
            "Cycle A candidate changes product or unscoped control paths"
        )


def _current_clean_descendant_source(
    root: Path, frozen: dict[str, Any], label: str
) -> dict[str, str]:
    repository = _canonical_directory(root, f"{label} root")
    _assert_origin(repository, frozen["repository"], label)
    if _git_text(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise HoneyRefinementError(f"{label} checkout is not clean")
    current = _source(repository, "HEAD")
    if _git(
        repository,
        "merge-base",
        "--is-ancestor",
        frozen["source"]["revision"],
        current["revision"],
        check=False,
    ).returncode:
        raise HoneyRefinementError(f"{label} no longer descends from the frozen cohort")
    return current


def create_plan(
    *,
    repository_root: Path,
    core_root: Path,
    cedar_root: Path,
    candidate_revision: str,
    cycle: str,
    champion_revision: str | None = None,
    hypothesis_id: str | None = None,
    champion_profile: str = "balanced.v1",
    candidate_profile: str = "balanced.v2-candidate.1",
) -> dict[str, Any]:
    root = _canonical_directory(repository_root, "Shadow CIGAR root")
    if cycle not in {"cycle-a", "cycle-b"}:
        raise HoneyRefinementError(
            "only sequential Cycle A and Cycle B planning is currently qualified"
        )
    profile, cohort = validate(
        repository_root=root,
        core_root=core_root,
        cedar_root=cedar_root,
        require_external_clean_heads=cycle == "cycle-a",
    )
    if _git_text(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise HoneyRefinementError("Shadow CIGAR must be clean before planning")
    branch = _git_text(root, "branch", "--show-current")
    if re.fullmatch(profile["candidate_policy"]["branch_pattern"], branch) is None:
        raise HoneyRefinementError(
            "candidate branch is outside the Honey refinement namespace"
        )
    candidate = _source(root, candidate_revision)
    if candidate != _source(root, "HEAD"):
        raise HoneyRefinementError(
            "candidate revision must be the clean checked-out HEAD"
        )
    if cycle == "cycle-a":
        if champion_revision is not None or hypothesis_id is not None:
            raise HoneyRefinementError("Cycle A does not accept hypothesis overrides")
        champion = profile["frozen_sources"]["champion"]["source"]
    else:
        if (
            champion_revision is None
            or not hypothesis_id
            or (champion_profile, candidate_profile)
            not in {
                ("balanced.v1", "balanced.v2-candidate.1"),
                ("balanced.v2-candidate.1", "balanced.v2-candidate.1"),
                ("balanced.v2-candidate.1", "balanced.v2-candidate.2"),
                ("balanced.v2-candidate.2", "balanced.v3"),
            }
        ):
            raise HoneyRefinementError(
                "Cycle B requires one identified sequential profile hypothesis"
            )
        champion = _source(root, champion_revision)
        if champion != _source(root, "refs/heads/main"):
            raise HoneyRefinementError("Cycle B champion must be current private main")
    if _git(
        root,
        "merge-base",
        "--is-ancestor",
        champion["revision"],
        candidate["revision"],
        check=False,
    ).returncode:
        raise HoneyRefinementError(
            "candidate does not descend from the immutable champion"
        )
    if cycle == "cycle-a":
        _cycle_a_scope(root, champion["revision"], candidate["revision"])
        external_sources = {
            "humidor": cohort["downstream"]["humidor_source"]["source"],
            "cedar": cohort["downstream"]["cedar_source"]["source"],
        }
    else:
        external_sources = {
            "humidor": _current_clean_descendant_source(
                core_root, cohort["downstream"]["humidor_source"], "HUMIDOR"
            ),
            "cedar": _current_clean_descendant_source(
                cedar_root, cohort["downstream"]["cedar_source"], "CEDAR"
            ),
        }
    cells = [
        {
            "cell_id": f"{source_role}-{lane}",
            "source_role": source_role,
            "lane": lane,
            "fresh_root": True,
            "status": "planned",
        }
        for source_role in EXPECTED_SOURCES
        for lane in EXPECTED_LANES
    ]
    body: dict[str, Any] = {
        "schema_version": "cigar.honey-evaluation-plan.v1",
        "profile_id": profile["profile_id"],
        "cohort_id": cohort["cohort_id"],
        "cycle": cycle,
        "evidence_class": "development",
        "harness_source": candidate if cycle == "cycle-a" else champion,
        "product_sources": {
            "published_honey": profile["frozen_sources"]["published_honey"]["source"],
            "champion": champion,
            "candidate": candidate,
        },
        "external_sources": external_sources,
        "cells": cells,
        "gates": sorted(
            [row["id"] for row in profile["hard_invariants"]]
            + [row["id"] for row in profile["promotion_thresholds"]]
        ),
        "authority": {
            "execute_tests": True,
            "edit_product": False,
            "create_pull_request": False,
            "merge": False,
            "release": False,
            "publish": False,
            "push_public": False,
        },
    }
    if cycle == "cycle-b":
        body["hypothesis_id"] = hypothesis_id
        body["intelligence_profiles"] = {
            "honey": "balanced.v1",
            "champion": champion_profile,
            "candidate": candidate_profile,
        }
    plan = {**body, "plan_id": identity(body)}
    SchemaRegistry(root / "schemas/refinement").validate(PLAN_SCHEMA, plan)
    return plan


def _create_new(path: Path, payload: bytes) -> None:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise HoneyRefinementError("plan output must be an absolute create-new path")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate_parser = commands.add_parser("validate")
    validate_parser.add_argument("--repository-root", required=True, type=Path)
    validate_parser.add_argument("--core-root", type=Path)
    validate_parser.add_argument("--cedar-root", type=Path)
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--repository-root", required=True, type=Path)
    plan_parser.add_argument("--core-root", required=True, type=Path)
    plan_parser.add_argument("--cedar-root", required=True, type=Path)
    plan_parser.add_argument("--candidate-revision", default="HEAD")
    plan_parser.add_argument(
        "--cycle", choices=("cycle-a", "cycle-b", "cycle-c"), default="cycle-a"
    )
    plan_parser.add_argument("--champion-revision")
    plan_parser.add_argument("--hypothesis-id")
    plan_parser.add_argument(
        "--champion-profile",
        choices=("balanced.v1", "balanced.v2-candidate.1", "balanced.v2-candidate.2"),
        default="balanced.v1",
    )
    plan_parser.add_argument(
        "--candidate-profile",
        choices=("balanced.v2-candidate.1", "balanced.v2-candidate.2", "balanced.v3"),
        default="balanced.v2-candidate.1",
    )
    plan_parser.add_argument("--output", required=True, type=Path)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--repository-root", required=True, type=Path)
    build_parser.add_argument("--plan", required=True, type=Path)
    build_parser.add_argument("--output-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            profile, cohort = validate(
                repository_root=arguments.repository_root,
                core_root=arguments.core_root,
                cedar_root=arguments.cedar_root,
            )
            result = {
                "status": "valid",
                "profile_id": profile["profile_id"],
                "cohort_id": cohort["cohort_id"],
            }
        elif arguments.command == "plan":
            result = create_plan(
                repository_root=arguments.repository_root,
                core_root=arguments.core_root,
                cedar_root=arguments.cedar_root,
                candidate_revision=arguments.candidate_revision,
                cycle=arguments.cycle,
                champion_revision=arguments.champion_revision,
                hypothesis_id=arguments.hypothesis_id,
                champion_profile=arguments.champion_profile,
                candidate_profile=arguments.candidate_profile,
            )
            _create_new(arguments.output, canonical_bytes(result))
        else:
            validate(repository_root=arguments.repository_root)
            result = build_source_consumers(
                repository_root=arguments.repository_root,
                plan_path=arguments.plan,
                output_root=arguments.output_root,
            )
    except (HoneyRefinementError, SourceBuildError, OSError, ValueError):
        print("Honey refinement authority rejected", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
