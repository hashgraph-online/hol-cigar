"""Validate independent evidence before preparing a development-branch update."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import identity
from .schema import SchemaRegistry


class DevelopmentPromotionError(RuntimeError):
    """A loop result is not eligible for an approved development update."""


def _verify_id(value: dict[str, Any], field: str) -> None:
    unsigned = dict(value)
    claimed = unsigned.pop(field, None)
    if claimed != identity(unsigned):
        raise DevelopmentPromotionError(f"{field} does not match record content")


def prepare_development_update(
    *,
    terminal: dict[str, Any],
    evaluation: dict[str, Any],
    decision: dict[str, Any],
    schema_root: Path,
) -> dict[str, Any]:
    """Return a non-executable intent only for a nominated, independently approved commit."""

    registry = SchemaRegistry(schema_root)
    try:
        registry.validate("loop-evaluation-v1.schema.json", evaluation)
        registry.validate("decision-v1.schema.json", decision)
    except ValueError as error:
        raise DevelopmentPromotionError("promotion input fails its schema") from error
    _verify_id(evaluation, "evaluation_id")
    _verify_id(decision, "decision_id")
    expected_terminal_fields = {
        "schema_version",
        "trial_id",
        "decision",
        "mode",
        "candidate",
        "review_payload",
        "no_promotion",
    }
    terminal_fields = frozenset(terminal) if isinstance(terminal, dict) else frozenset()
    if (
        not isinstance(terminal, dict)
        or terminal_fields
        not in {
            frozenset(expected_terminal_fields),
            frozenset(expected_terminal_fields | {"early_rejection_id"}),
        }
        or terminal["schema_version"] != "cigar.refinement-loop-terminal.v1"
        or terminal["no_promotion"] is not True
    ):
        raise DevelopmentPromotionError("loop terminal record is malformed")
    candidate = terminal["candidate"]
    if (
        terminal["decision"] != "nominate"
        or evaluation["decision"] != "nominate"
        or evaluation["failure_category"] is not None
        or any(
            invariant["status"] != "passed"
            for invariant in evaluation["hard_invariants"]
        )
        or candidate is None
    ):
        raise DevelopmentPromotionError("rejected or uncommitted trial cannot promote")
    if (
        decision["decision"] != "promote"
        or decision["failed_gates"]
        or decision["human_review"] is None
        or decision["trial_id"] != terminal["trial_id"]
        or evaluation["trial_id"] != terminal["trial_id"]
    ):
        raise DevelopmentPromotionError(
            "independent promotion decision does not approve this trial"
        )
    champion_source = decision["champion_source"]
    candidate_source = {
        "revision": candidate["revision"],
        "tree": candidate["tree"],
    }
    if (
        decision["candidate_source"] != candidate_source
        or candidate["parent_revision"] != champion_source["revision"]
    ):
        raise DevelopmentPromotionError(
            "promotion decision does not bind the exact candidate lineage"
        )
    body = {
        "schema_version": "cigar.refinement-development-promotion.v1",
        "trial_id": terminal["trial_id"],
        "target_branch": "refinement/development",
        "champion_source": champion_source,
        "candidate_source": candidate_source,
        "evaluation_id": evaluation["evaluation_id"],
        "decision_id": decision["decision_id"],
        "operation": "prepare-development-branch-update-only",
        "required_environment": "refinement-development",
        "branch_update_authority": False,
        "merge_authority": False,
        "publication_authority": False,
    }
    result = {**body, "intent_id": identity(body)}
    registry.validate("development-promotion-v1.schema.json", result)
    return result
