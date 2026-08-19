"""Read-only operational projections derived from verified ledger bindings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import identity, load_file
from .ledger import Ledger
from .schema import SchemaRegistry

FACTS_SCHEMA = "dashboard-facts-v1.schema.json"
PROJECTION_SCHEMA = "dashboard-projection-v1.schema.json"


class DashboardError(RuntimeError):
    """Dashboard inputs are malformed or do not bind to authoritative evidence."""


def _verify_identity(value: dict[str, Any], field: str) -> None:
    unsigned = dict(value)
    unsigned.pop(field)
    if value[field] != identity(unsigned):
        raise DashboardError(f"dashboard {field} identity is invalid")


def project(
    *,
    repository_root: Path,
    ledger_root: Path,
    facts_path: Path,
) -> dict[str, Any]:
    """Return a pure projection; neither ledger nor facts are ever modified."""

    repository_root = repository_root.resolve(strict=True)
    registry = SchemaRegistry(repository_root / "schemas" / "refinement")
    try:
        facts = load_file(facts_path)
        registry.validate(FACTS_SCHEMA, facts)
    except (OSError, ValueError) as error:
        raise DashboardError("dashboard facts are malformed") from error
    if not isinstance(facts, dict):
        raise DashboardError("dashboard facts are not an object")
    _verify_identity(facts, "facts_id")
    entries = Ledger(ledger_root, repository_root=repository_root).replay()
    by_id = {entry["entry_id"]: entry for entry in entries}
    if facts["ledger_head"] != (entries[-1]["entry_id"] if entries else None):
        raise DashboardError("dashboard facts do not bind the current ledger head")

    normalized: list[dict[str, Any]] = []
    seen_iterations: set[str] = set()
    for fact in facts["facts"]:
        _verify_identity(fact, "fact_id")
        entry = by_id.get(fact["ledger_entry_id"])
        if entry is None or entry["iteration_id"] != fact["iteration_id"]:
            raise DashboardError("dashboard fact does not bind its ledger iteration")
        source_ids = set(fact["source_artifact_ids"])
        if not source_ids.issubset(set(entry["artifact_ids"])):
            raise DashboardError("dashboard fact cites an unledgered artifact")
        for identifier in (fact["comparison_id"], fact["decision_id"]):
            if identifier is not None and identifier not in source_ids:
                raise DashboardError("dashboard decision binding is incomplete")
        terminal = {
            "promoted": "trial_promoted",
            "rejected": "trial_rejected",
            "stopped": "controller_stopped",
        }.get(fact["status"])
        if terminal is not None and entry["event_type"] != terminal:
            raise DashboardError("dashboard status disagrees with its ledger event")
        if fact["status"] == "promoted" and fact["decision_id"] is None:
            raise DashboardError("promoted dashboard fact lacks a decision")
        if fact["iteration_id"] in seen_iterations:
            raise DashboardError("dashboard has duplicate terminal trial facts")
        seen_iterations.add(fact["iteration_id"])
        normalized.append({"fact": fact, "entry": entry})

    normalized.sort(key=lambda row: row["entry"]["sequence"])
    champion: dict[str, Any] | None = None
    trials: list[dict[str, Any]] = []
    kpis: list[dict[str, Any]] = []
    provider_totals: dict[str, dict[str, int]] = {}
    failures: dict[str, int] = {}
    for row in normalized:
        fact = row["fact"]
        entry = row["entry"]
        trial = {
            "iteration_id": fact["iteration_id"],
            "status": fact["status"],
            "family_id": fact["family_id"],
            "adapter": fact["adapter"],
            "provider_id": fact["provider_id"],
            "ledger_entry_id": entry["entry_id"],
            "failure_class": fact["failure_class"],
            "comparison_id": fact["comparison_id"],
            "decision_id": fact["decision_id"],
        }
        trials.append(trial)
        for metric in fact["metrics"]:
            kpis.append(
                {
                    "iteration_id": fact["iteration_id"],
                    "ledger_sequence": entry["sequence"],
                    **metric,
                }
            )
        totals = provider_totals.setdefault(
            fact["provider_id"],
            {
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_microusd": 0,
                "compute_milliseconds": 0,
                "trials": 0,
            },
        )
        totals["trials"] += 1
        for resource in (
            "input_tokens",
            "output_tokens",
            "cost_microusd",
            "compute_milliseconds",
        ):
            totals[resource] += fact["resources"][resource]
        if fact["failure_class"] is not None:
            failures[fact["failure_class"]] = failures.get(fact["failure_class"], 0) + 1
        if fact["status"] == "promoted":
            champion = {
                "iteration_id": fact["iteration_id"],
                "revision": entry["source_revision"],
                "tree": entry["source_tree"],
                "ledger_entry_id": entry["entry_id"],
                "comparison_id": fact["comparison_id"],
                "decision_id": fact["decision_id"],
                "source_artifact_ids": fact["source_artifact_ids"],
            }
    body = {
        "schema_version": "cigar.refinement-dashboard-projection.v1",
        "projection_id": "",
        "ledger": {
            "entry_count": len(entries),
            "head": entries[-1]["entry_id"] if entries else None,
        },
        "champion": champion,
        "trials": trials,
        "kpi_trends": kpis,
        "provider_costs": [
            {"provider_id": provider, **provider_totals[provider]}
            for provider in sorted(provider_totals)
        ],
        "failure_classes": [
            {"failure_class": name, "count": failures[name]}
            for name in sorted(failures)
        ],
        "source_facts_id": facts["facts_id"],
    }
    unsigned = dict(body)
    unsigned.pop("projection_id")
    body["projection_id"] = identity(unsigned)
    registry.validate(PROJECTION_SCHEMA, body)
    return body
