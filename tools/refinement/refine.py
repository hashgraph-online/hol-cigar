#!/usr/bin/env python3
"""Operate the bounded CIGAR continuous-refinement control plane."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement import config
from tools.refinement.canonical import canonical_bytes
from tools.refinement.capture_r00_baseline import capture as capture_baseline
from tools.refinement.commands import (
    CommandError,
    default_registry,
    run_named,
)
from tools.refinement.trials import TrialError, TrialStore
from tools.refinement.workspace import (
    DiffPolicy,
    WorkspaceError,
    clean_worktree,
    cleanup_preview,
    inspect_worktree,
    plan_worktree,
    repository_identity,
    retained_branch_revision,
    validate_diff,
    worktree_snapshot,
)


class RefineError(RuntimeError):
    """The requested control-plane operation cannot be completed safely."""


def _absolute(path: Path, label: str, *, must_exist: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise RefineError(f"{label} must be an absolute real path")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise RefineError(f"{label} cannot be resolved") from error
    if resolved != path:
        raise RefineError(f"{label} must not contain aliases or symlinks")
    return resolved


def _load_common(arguments: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    repository = _absolute(arguments.repository, "repository", must_exist=True)
    loaded = config.load(_absolute(arguments.config, "config", must_exist=True))
    return repository, loaded


def _store(arguments: argparse.Namespace, repository: Path) -> TrialStore:
    state_root = _absolute(arguments.state_root, "state root", must_exist=False)
    return TrialStore(state_root, repository_root=repository)


def doctor(arguments: argparse.Namespace) -> dict[str, Any]:
    repository, loaded = _load_common(arguments)
    source = repository_identity(repository, require_clean=True)
    registry = default_registry()
    _store(arguments, repository)
    worktree_root = _absolute(arguments.worktree_root, "worktree root", must_exist=True)
    if (
        worktree_root == repository
        or repository in worktree_root.parents
        or worktree_root in repository.parents
    ):
        raise RefineError("worktree root must be disjoint from the repository")
    return {
        "schema_version": "cigar.refinement-doctor.v1",
        "status": "passed",
        "source": source,
        "config_profile": loaded["profile_id"],
        "evidence_class": loaded["evidence"]["class"],
        "named_commands": list(registry.identifiers),
        "state_root": str(arguments.state_root),
        "worktree_root": str(worktree_root),
        "credentials_resolved": False,
    }


def baseline(arguments: argparse.Namespace) -> dict[str, Any]:
    repository, _ = _load_common(arguments)
    evidence = _absolute(
        arguments.baseline_evidence_dir,
        "baseline evidence directory",
        must_exist=False,
    )
    receipt = capture_baseline(repository, evidence)
    return {
        "schema_version": "cigar.refinement-baseline-command.v1",
        "status": receipt["status"],
        "receipt_id": receipt["receipt_id"],
        "source": receipt["source"],
    }


def trial_create(arguments: argparse.Namespace) -> dict[str, Any]:
    repository, loaded = _load_common(arguments)
    store = _store(arguments, repository)
    states = store.load(arguments.trial_id)
    if states:
        intent = states[0]["worktree"]
    else:
        intent = plan_worktree(
            repository,
            _absolute(arguments.worktree_root, "worktree root", must_exist=True),
            trial_id=arguments.trial_id,
            champion_ref=arguments.champion_ref,
        )
    allowed = arguments.allowed_path or []
    forbidden = arguments.forbidden_path or []
    if not allowed:
        raise RefineError("at least one --allowed-path is required")
    state = store.create_or_resume(
        champion_repository=repository,
        intent=intent,
        hypothesis=arguments.hypothesis,
        allowed_paths=allowed,
        forbidden_paths=forbidden,
        maximum_files=loaded["limits"]["max_files_changed"],
        maximum_lines=loaded["limits"]["max_lines_changed"],
        evidence_class=loaded["evidence"]["class"],
    )
    return {
        "schema_version": "cigar.refinement-trial-command.v1",
        "status": state["phase"],
        "trial_id": arguments.trial_id,
        "state_id": state["state_id"],
        "worktree": state["worktree"],
    }


def trial_inspect(arguments: argparse.Namespace) -> dict[str, Any]:
    repository, _ = _load_common(arguments)
    store = _store(arguments, repository)
    states = store.load(arguments.trial_id)
    if not states:
        raise RefineError("trial does not exist")
    latest = states[-1]
    inspection = inspect_worktree(repository, latest["worktree"])
    diff: dict[str, Any] | None = None
    if inspection["status"] == "present":
        policy = DiffPolicy(
            allowed_paths=tuple(latest["allowed_paths"]),
            forbidden_paths=tuple(latest["forbidden_paths"]),
            maximum_files=latest["maximum_files"],
            maximum_lines=latest["maximum_lines"],
        )
        try:
            diff = validate_diff(Path(latest["worktree"]["worktree_path"]), policy)
        except WorkspaceError as error:
            diff = {"status": "failed", "reason": str(error)}
    return {
        "schema_version": "cigar.refinement-trial-inspection.v1",
        "trial_id": arguments.trial_id,
        "phase": latest["phase"],
        "state_id": latest["state_id"],
        "state_count": len(states),
        "inspection": inspection,
        "diff": diff,
    }


def trial_clean(arguments: argparse.Namespace) -> dict[str, Any]:
    repository, _ = _load_common(arguments)
    store = _store(arguments, repository)
    states = store.load(arguments.trial_id)
    if not states:
        raise RefineError("trial does not exist")
    latest = states[-1]
    if latest["phase"] == "cleaned":
        return {
            "schema_version": "cigar.refinement-cleanup-result.v1",
            "status": "cleaned",
            "trial_id": arguments.trial_id,
            "state_id": latest["state_id"],
            "branch_retained": latest["worktree"]["branch"],
        }
    preview = cleanup_preview(repository, latest["worktree"])
    if not arguments.execute:
        return {
            "schema_version": "cigar.refinement-cleanup-preview.v1",
            "status": "preview",
            **preview,
        }
    if latest["phase"] not in {"created", "resumable", "cleaning"}:
        raise RefineError("trial phase cannot enter cleanup")
    if latest["phase"] != "cleaning":
        if not preview["executable"]:
            raise RefineError("worktree cleanup is not safe to execute")
        latest = store.append(
            phase="cleaning",
            trial_id=latest["trial_id"],
            hypothesis=latest["hypothesis"],
            worktree=latest["worktree"],
            allowed_paths=latest["allowed_paths"],
            forbidden_paths=latest["forbidden_paths"],
            maximum_files=latest["maximum_files"],
            maximum_lines=latest["maximum_lines"],
            evidence_class=latest["evidence_class"],
            reason="operator_requested_clean_worktree",
        )
    if preview["inspection"]["status"] == "present":
        result = clean_worktree(repository, latest["worktree"])
    elif preview["inspection"]["status"] == "missing":
        retained_branch_revision(repository, latest["worktree"])
        result = {
            "status": "cleaned",
            "branch_retained": latest["worktree"]["branch"],
        }
    else:
        raise RefineError("cleanup restart state is ambiguous")
    state = store.append(
        phase="cleaned",
        trial_id=latest["trial_id"],
        hypothesis=latest["hypothesis"],
        worktree=latest["worktree"],
        allowed_paths=latest["allowed_paths"],
        forbidden_paths=latest["forbidden_paths"],
        maximum_files=latest["maximum_files"],
        maximum_lines=latest["maximum_lines"],
        evidence_class=latest["evidence_class"],
        reason="worktree_cleanup_completed",
    )
    return {
        "schema_version": "cigar.refinement-cleanup-result.v1",
        "status": result["status"],
        "trial_id": arguments.trial_id,
        "state_id": state["state_id"],
        "branch_retained": result["branch_retained"],
    }


def gate_run(arguments: argparse.Namespace) -> dict[str, Any]:
    repository, _ = _load_common(arguments)
    store = _store(arguments, repository)
    states = store.load(arguments.trial_id)
    if not states:
        raise RefineError("trial does not exist")
    latest = states[-1]
    inspection = inspect_worktree(repository, latest["worktree"])
    if not inspection["resumable"]:
        raise RefineError("trial worktree is not resumable")
    worktree = Path(latest["worktree"]["worktree_path"])
    before = worktree_snapshot(worktree)
    state = _absolute(arguments.command_state, "command state", must_exist=False)
    result = run_named(default_registry(), arguments.gate, cwd=worktree, state=state)
    after = worktree_snapshot(worktree)
    return {
        "schema_version": "cigar.refinement-gate-command.v1",
        "trial_id": arguments.trial_id,
        "gate": arguments.gate,
        "before": before,
        "after": after,
        "source_changed": before["snapshot_id"] != after["snapshot_id"],
        "result": result,
    }


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--worktree-root", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    doctor_parser = commands.add_parser("doctor")
    _common(doctor_parser)
    doctor_parser.set_defaults(handler=doctor)

    baseline_parser = commands.add_parser("baseline")
    _common(baseline_parser)
    baseline_parser.add_argument("--baseline-evidence-dir", type=Path, required=True)
    baseline_parser.set_defaults(handler=baseline)

    trial_parser = commands.add_parser("trial")
    trial_commands = trial_parser.add_subparsers(dest="trial_command", required=True)
    create_parser = trial_commands.add_parser("create")
    _common(create_parser)
    create_parser.add_argument("--trial-id", required=True)
    create_parser.add_argument("--champion-ref", default="HEAD")
    create_parser.add_argument("--hypothesis", required=True)
    create_parser.add_argument("--allowed-path", action="append")
    create_parser.add_argument("--forbidden-path", action="append")
    create_parser.set_defaults(handler=trial_create)
    inspect_parser = trial_commands.add_parser("inspect")
    _common(inspect_parser)
    inspect_parser.add_argument("--trial-id", required=True)
    inspect_parser.set_defaults(handler=trial_inspect)
    clean_parser = trial_commands.add_parser("clean")
    _common(clean_parser)
    clean_parser.add_argument("--trial-id", required=True)
    clean_parser.add_argument("--execute", action="store_true")
    clean_parser.set_defaults(handler=trial_clean)

    gate_parser = commands.add_parser("gate")
    _common(gate_parser)
    gate_parser.add_argument("--trial-id", required=True)
    gate_parser.add_argument("--gate", required=True)
    gate_parser.add_argument("--command-state", type=Path, required=True)
    gate_parser.set_defaults(handler=gate_run)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        result = arguments.handler(arguments)
    except (
        CommandError,
        RefineError,
        TrialError,
        WorkspaceError,
        config.ConfigError,
        OSError,
    ) as error:
        print(f"refine: {error}", file=sys.stderr)
        return 2
    print(canonical_bytes(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
