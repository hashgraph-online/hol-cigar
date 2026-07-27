"""Deterministic promotion decision and append-only Pareto research archive."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from .canonical import canonical_bytes, identity, loads, secure_read
from .schema import SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts/release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError

ENTRY = re.compile(r"^([0-9]{20})\.json$")
ARCHIVABLE = {
    "reject_inferior",
    "reject_no_meaningful_improvement",
    "reject_overfit_or_inconsistent",
    "reject_performance",
    "needs_human_review",
}


class PromotionError(RuntimeError):
    """Promotion evidence, decision, or research archive is invalid."""


def _load(path: Path) -> tuple[dict[str, Any], bytes]:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.resolve(strict=True) != path
    ):
        raise PromotionError("promotion input must be a real absolute path")
    payload = secure_read(path)
    value = loads(payload)
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise PromotionError("promotion input must be canonical JSON")
    return value, payload


def _verify_identity(value: dict[str, Any], field: str) -> None:
    body = dict(value)
    claimed = body.pop(field)
    if identity(body) != claimed:
        raise PromotionError(f"{field} does not match record content")


def decide(comparison: dict[str, Any], registry: SchemaRegistry) -> dict[str, Any]:
    registry.validate("comparison-v1.schema.json", comparison)
    _verify_identity(comparison, "comparison_id")
    reasons = set(comparison["reasons"])
    if comparison["verdict"] == "invalid":
        outcome = "reject_invalid_evidence"
    elif any(not gate["passed"] for gate in comparison["hard_constraints"]):
        outcome = "reject_hard_invariant"
    elif "performance-regression" in reasons:
        outcome = "reject_performance"
    elif "seed-inconsistent" in reasons:
        outcome = "reject_overfit_or_inconsistent"
    elif "primary-inferiority" in reasons or "protected-stratum" in reasons:
        outcome = "reject_inferior"
    elif "no-meaningful-improvement" in reasons:
        outcome = "reject_no_meaningful_improvement"
    elif comparison["verdict"] == "needs_human_review":
        outcome = "needs_human_review"
    elif comparison["verdict"] == "eligible":
        outcome = "promote"
    else:
        raise PromotionError("comparison verdict has no deterministic decision")
    gate_rows = comparison["evidence_validity"] + comparison["hard_constraints"]
    passed = sorted(gate["gate_id"] for gate in gate_rows if gate["passed"])
    failed = sorted(gate["gate_id"] for gate in gate_rows if not gate["passed"])
    decision_reasons = sorted(reasons) or ["all-promotion-constraints-passed"]
    body = {
        "schema_version": "cigar.refinement-decision.v1",
        "trial_id": comparison["trial_id"],
        "comparison_id": comparison["comparison_id"],
        "champion_source": comparison["champion_source"],
        "candidate_source": comparison["candidate_source"],
        "policy_digest": comparison["policy_digest"],
        "decision": outcome,
        "reasons": decision_reasons,
        "passed_gates": passed,
        "failed_gates": failed,
        "human_review": None,
    }
    result = {**body, "decision_id": identity(body)}
    registry.validate("decision-v1.schema.json", result)
    return result


def decision_from_path(
    comparison_path: Path, schemas: Path
) -> dict[str, Any]:
    registry = SchemaRegistry(schemas)
    comparison, _payload = _load(comparison_path)
    return decide(comparison, registry)


def replay(
    expected_path: Path, comparison_path: Path, schemas: Path
) -> dict[str, Any]:
    expected, payload = _load(expected_path)
    registry = SchemaRegistry(schemas)
    registry.validate("decision-v1.schema.json", expected)
    _verify_identity(expected, "decision_id")
    reproduced = decision_from_path(comparison_path, schemas)
    if canonical_bytes(reproduced) != payload:
        raise PromotionError("promotion decision replay differs")
    return reproduced


def _dominates(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_values = {
        item["name"]: (item["direction"], float(item["value"]))
        for item in left["objectives"]
    }
    right_values = {
        item["name"]: (item["direction"], float(item["value"]))
        for item in right["objectives"]
    }
    if set(left_values) != set(right_values):
        raise PromotionError("Pareto objective inventories differ")
    better = False
    for name in sorted(left_values):
        left_direction, left_value = left_values[name]
        right_direction, right_value = right_values[name]
        if left_direction != right_direction:
            raise PromotionError("Pareto objective directions differ")
        if left_direction == "higher":
            if left_value < right_value:
                return False
            better |= left_value > right_value
        else:
            if left_value > right_value:
                return False
            better |= left_value < right_value
    return better


class ParetoArchive:
    def __init__(self, root: Path, repository_root: Path, schemas: Path) -> None:
        self.root = root
        self.repository_root = repository_root.resolve(strict=True)
        self.registry = SchemaRegistry(schemas)

    def _inventory(self) -> list[str]:
        if not self.root.exists():
            return []
        metadata = self.root.stat(follow_symlinks=False)
        if (
            self.root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise PromotionError("Pareto archive root must be owner-only")
        names = []
        with os.scandir(self.root) as iterator:
            for item in iterator:
                match = ENTRY.fullmatch(item.name)
                metadata = item.stat(follow_symlinks=False)
                if (
                    match is None
                    or item.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o400
                ):
                    raise PromotionError("Pareto archive contains an unsafe entry")
                names.append(item.name)
        names.sort()
        if names != [f"{index:020d}.json" for index in range(len(names))]:
            raise PromotionError("Pareto archive sequence is not contiguous")
        return names

    def replay(self) -> list[dict[str, Any]]:
        names = self._inventory()
        if not names:
            return []
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                payloads = workspace.read_files(set(names), strict_read_only=True)
        except EvidenceWorkspaceError as error:
            raise PromotionError("Pareto archive workspace is unsafe") from error
        records = []
        frontier: list[dict[str, Any]] = []
        previous = None
        for sequence, name in enumerate(names):
            value = loads(payloads[name])
            self.registry.validate("pareto-record-v1.schema.json", value)
            _verify_identity(value, "record_id")
            if (
                value["sequence"] != sequence
                or value["previous_record_id"] != previous
            ):
                raise PromotionError("Pareto archive chain is invalid")
            dominated_by = sorted(
                item["comparison_id"]
                for item in frontier
                if _dominates(item, value)
            )
            if value["dominated_by"] != dominated_by:
                raise PromotionError("Pareto domination evidence does not replay")
            if dominated_by:
                expected_frontier = sorted(item["comparison_id"] for item in frontier)
            else:
                frontier = [
                    item for item in frontier if not _dominates(value, item)
                ]
                frontier.append(value)
                expected_frontier = sorted(item["comparison_id"] for item in frontier)
            if value["frontier_after"] != expected_frontier:
                raise PromotionError("Pareto frontier snapshot does not replay")
            records.append(value)
            previous = value["record_id"]
        return records

    def append(
        self, comparison: dict[str, Any], decision: dict[str, Any]
    ) -> dict[str, Any]:
        if decision["decision"] not in ARCHIVABLE:
            raise PromotionError("decision is not eligible for research archiving")
        records = self.replay()
        frontier_ids = records[-1]["frontier_after"] if records else []
        if any(
            record["comparison_id"] == comparison["comparison_id"]
            for record in records
        ):
            raise PromotionError("comparison is already present in Pareto archive")
        by_id = {record["comparison_id"]: record for record in records}
        frontier = [by_id[record_id] for record_id in frontier_ids]
        objectives = [
            {
                "name": row["name"],
                "direction": row["direction"],
                "value": row["candidate"],
            }
            for row in comparison["metrics"]
            if row["direction"] in {"higher", "lower"}
        ]
        objectives.extend(
            {
                "name": row["name"],
                "direction": "lower",
                "value": row["candidate"],
            }
            for row in comparison["performance"]
            if row["name"] not in {item["name"] for item in objectives}
        )
        objectives.sort(key=lambda item: item["name"])
        provisional = {
            "objectives": objectives,
        }
        dominated_by = sorted(
            item["comparison_id"]
            for item in frontier
            if _dominates(item, provisional)
        )
        body = {
            "schema_version": "cigar.pareto-record.v1",
            "sequence": len(records),
            "previous_record_id": records[-1]["record_id"] if records else None,
            "comparison_id": comparison["comparison_id"],
            "candidate_source": comparison["candidate_source"],
            "decision": decision["decision"],
            "objectives": objectives,
            "dominated_by": dominated_by,
            "frontier_after": [],
        }
        if dominated_by:
            frontier_after = sorted(frontier_ids)
        else:
            frontier_after = sorted(
                [
                    item["comparison_id"]
                    for item in frontier
                    if not _dominates(provisional, item)
                ]
                + [comparison["comparison_id"]]
            )
        body["frontier_after"] = frontier_after
        record = {**body, "record_id": identity(body)}
        self.registry.validate("pareto-record-v1.schema.json", record)
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                expected = {f"{index:020d}.json" for index in range(len(records))}
                if set(self._inventory()) != expected:
                    raise PromotionError("Pareto archive changed during append")
                workspace.write_json(f"{len(records):020d}.json", record)
        except EvidenceWorkspaceError as error:
            raise PromotionError("Pareto record publication failed") from error
        if self.replay()[-1] != record:
            raise PromotionError("Pareto record did not replay")
        return record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("decide", "replay", "archive"))
    parser.add_argument("--comparison", required=True, type=Path)
    parser.add_argument("--schemas", required=True, type=Path)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--decision", type=Path)
    parser.add_argument("--archive-root", type=Path)
    parser.add_argument("--repository-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "decide":
            result = decision_from_path(arguments.comparison, arguments.schemas)
        elif arguments.command == "replay":
            if arguments.expected is None:
                raise PromotionError("decision replay requires --expected")
            result = replay(
                arguments.expected, arguments.comparison, arguments.schemas
            )
        else:
            if (
                arguments.decision is None
                or arguments.archive_root is None
                or arguments.repository_root is None
            ):
                raise PromotionError("archive inputs are incomplete")
            comparison, _ = _load(arguments.comparison)
            decision, _ = _load(arguments.decision)
            result = ParetoArchive(
                arguments.archive_root,
                arguments.repository_root,
                arguments.schemas,
            ).append(comparison, decision)
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0
    except (PromotionError, OSError, ValueError) as error:
        print(f"promotion: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
