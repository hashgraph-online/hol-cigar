"""Deterministic opportunity mining, learning, and one-packet scheduling."""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from pathlib import Path
from typing import Any

from .canonical import identity, load_file
from .schema import SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas/refinement"
FAMILIES = ROOT / "refinement/profiles/intervention-families.v1.json"
TERMINAL_EVENTS = frozenset(
    {"trial_rejected", "trial_nominated", "trial_promoted", "controller_stopped"}
)
TRIAL_CLASS = frozenset({"product", "infrastructure"})
SAFE_FAILURE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PUBLIC_STRATA = frozenset(
    {
        "Agent-Handoff",
        "CatalogMutation",
        "CrossRuntime-Replay",
        "EffectCrash",
        "LongRepo-Change",
        "MultiProject-Switch",
        "Needle-and-Distractor",
        "PolicyBoundary",
        "Temporal-Truth",
    }
)


class ExperimentError(RuntimeError):
    """Signals or scheduling state cannot safely produce one experiment."""


def _verify_id(record: dict[str, Any], field: str) -> None:
    unsigned = dict(record)
    claimed = unsigned.pop(field)
    if identity(unsigned) != claimed:
        raise ExperimentError(f"{field} does not match record content")


def make_signal(
    *,
    source_kind: str,
    visibility: str,
    summary: str | None,
    source_commitment: str,
    owner_hint: str | None,
    metric: str,
    magnitude: float,
    estimated_cost: float,
    strata: list[str],
    reproducible: bool,
) -> dict[str, Any]:
    body = {
        "schema_version": "cigar.refinement-opportunity-signal.v1",
        "source_kind": source_kind,
        "visibility": visibility,
        "summary": summary,
        "source_commitment": source_commitment,
        "owner_hint": owner_hint,
        "metric": metric,
        "magnitude": magnitude,
        "estimated_cost": estimated_cost,
        "strata": sorted(strata),
        "reproducible": reproducible,
    }
    result = {**body, "signal_id": identity(body)}
    validate_signal(result)
    return result


def validate_signal(signal: dict[str, Any]) -> None:
    try:
        SchemaRegistry(SCHEMAS).validate("opportunity-signal-v1.schema.json", signal)
    except ValueError as error:
        raise ExperimentError("opportunity signal is malformed") from error
    _verify_id(signal, "signal_id")
    if signal["visibility"] == "aggregate_hidden" and (
        signal["summary"] is not None or signal["owner_hint"] is not None
    ):
        raise ExperimentError(
            "hidden-partition signal must be content-free and aggregate-only"
        )
    if signal["visibility"] == "aggregate_hidden" and not set(
        signal["strata"]
    ).issubset(PUBLIC_STRATA):
        raise ExperimentError("hidden signal contains an undeclared stratum")
    if signal["visibility"] == "public" and signal["summary"] is None:
        raise ExperimentError("public signal requires a diagnostic summary")
    if (
        signal["source_kind"] in {"test_failure", "mutation_survivor", "issue"}
        and not signal["reproducible"]
    ):
        raise ExperimentError("defect-shaped signal must be reproducible")


def load_families(path: Path = FAMILIES) -> list[dict[str, Any]]:
    value = load_file(path.resolve(strict=True))
    registry = SchemaRegistry(SCHEMAS)
    try:
        registry.validate("intervention-families-v1.schema.json", value)
    except ValueError as error:
        raise ExperimentError("intervention family registry is malformed") from error
    families = value["families"]
    identifiers = [family["family_id"] for family in families]
    if len(identifiers) != len(set(identifiers)):
        raise ExperimentError("intervention family IDs are not unique")
    for family in families:
        allowed = family["allowed_paths"]
        forbidden = family["forbidden_paths"]
        if family["trial_class"] == "product":
            required = {
                "refinement",
                "schemas/refinement",
                ".github",
                "scripts/release",
                "Cargo.lock",
            }
            if not required.issubset(forbidden):
                raise ExperimentError("product family does not forbid control surfaces")
            if any(
                path.startswith(("refinement", "schemas/refinement", ".github"))
                for path in allowed
            ):
                raise ExperimentError("product family can edit a control surface")
        else:
            if "crates" not in forbidden or "sdk/python" not in forbidden:
                raise ExperimentError(
                    "infrastructure family does not forbid product surfaces"
                )
            if any(path.startswith(("crates/", "sdk/")) for path in allowed):
                raise ExperimentError("infrastructure family can edit product code")
    return families


def ingest_signals(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate and deterministically deduplicate standardized source records."""
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        validate_signal(record)
        unique[record["signal_id"]] = dict(record)
    return [unique[identifier] for identifier in sorted(unique)]


def hypothesis_fingerprint(
    family_id: str, metric: str, intervention: str, trial_class: str
) -> str:
    normalized = " ".join(
        unicodedata.normalize("NFKC", intervention).casefold().split()
    )
    return identity(
        {
            "family_id": family_id,
            "metric": metric.casefold(),
            "intervention": normalized,
            "trial_class": trial_class,
        }
    )


def patch_fingerprints(patch: bytes) -> tuple[str, str]:
    if not isinstance(patch, bytes) or not patch or len(patch) > 16 * 1024 * 1024:
        raise ExperimentError("patch is empty or oversized")
    try:
        text = patch.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ExperimentError("patch is not UTF-8") from error
    if not text.startswith("diff --git "):
        raise ExperimentError("patch is not a Git unified diff")
    semantic_lines = []
    for line in text.splitlines():
        if line.startswith(("index ", "@@")):
            continue
        semantic_lines.append(line.rstrip())
    exact = "1220" + hashlib.sha256(patch).hexdigest()
    semantic = identity({"normalized_patch": "\n".join(semantic_lines)})
    return exact, semantic


def deduplicate_patches(
    patches: list[bytes], prior_fingerprints: set[str]
) -> list[bytes]:
    accepted: list[bytes] = []
    seen = set(prior_fingerprints)
    for patch in patches:
        exact, semantic = patch_fingerprints(patch)
        if exact in seen or semantic in seen:
            continue
        seen.update({exact, semantic})
        accepted.append(patch)
    return accepted


def _family_for(
    signal: dict[str, Any],
    families: list[dict[str, Any]],
    trial_class: str,
) -> dict[str, Any] | None:
    eligible = [
        family
        for family in families
        if family["trial_class"] == trial_class
        and signal["source_kind"] in family["source_kinds"]
        and (
            signal["owner_hint"] in family["owner_hints"]
            if signal["owner_hint"] is not None
            else signal["metric"] in family["metrics"]
        )
    ]
    if not eligible and signal["owner_hint"] is not None:
        eligible = [
            family
            for family in families
            if family["trial_class"] == trial_class
            and signal["source_kind"] in family["source_kinds"]
            and signal["metric"] in family["metrics"]
        ]
    if not eligible:
        return None
    return sorted(
        eligible, key=lambda item: (-item["base_priority"], item["family_id"])
    )[0]


def _history_stats(
    family_id: str, history: list[dict[str, Any]]
) -> dict[str, float | int]:
    rows = [item for item in history if item["family_id"] == family_id]
    attempts = len(rows)
    rejected = sum(item["outcome"] == "rejected" for item in rows)
    invalid = sum(item["outcome"] == "invalid" for item in rows)
    promoted = sum(item["outcome"] == "promoted" for item in rows)
    mean_effect = (
        sum(float(item["primary_effect"]) for item in rows) / attempts
        if attempts
        else 0.0
    )
    mean_cost = (
        sum(float(item["evaluation_cost"]) for item in rows) / attempts
        if attempts
        else 0.0
    )
    return {
        "attempts": attempts,
        "rejected": rejected,
        "invalid": invalid,
        "promoted": promoted,
        "mean_effect": mean_effect,
        "mean_cost": mean_cost,
    }


def _score(
    signal: dict[str, Any],
    family: dict[str, Any],
    stats: dict[str, float | int],
    total_attempts: int,
) -> tuple[float, dict[str, float]]:
    attempts = int(stats["attempts"])
    components = {
        "base_priority": float(family["base_priority"]),
        "impact": round(float(signal["magnitude"]) * 10.0, 6),
        "reproducibility": 2.0 if signal["reproducible"] else -2.0,
        "exploration": round(
            4.0 * math.sqrt(math.log(total_attempts + 2.0) / (attempts + 1.0)), 6
        ),
        "observed_effect": round(float(stats["mean_effect"]) * 5.0, 6),
        "signal_cost": round(-math.log1p(float(signal["estimated_cost"])), 6),
        "history_cost": round(-0.25 * math.log1p(float(stats["mean_cost"])), 6),
        "rejection_penalty": -2.0 * int(stats["rejected"]),
        "invalid_penalty": -4.0 * int(stats["invalid"]),
    }
    return round(sum(components.values()), 6), components


def _packet(
    *,
    signal: dict[str, Any],
    family: dict[str, Any],
    champion: dict[str, str],
    hypothesis: str,
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    failure_cluster = (
        signal["summary"]
        if signal["visibility"] == "public"
        else f"aggregate {signal['metric']} gap committed by {signal['source_commitment']}"
    )
    prior = []
    for category in sorted(
        {
            item["failure_category"]
            for item in history
            if item["family_id"] == family["family_id"]
            and item["failure_category"] is not None
        }
    ):
        if SAFE_FAILURE.fullmatch(category) is None:
            raise ExperimentError("trial history contains a disclosure-shaped category")
        prior.append(f"{family['family_id']}:{category}")
    body: dict[str, Any] = {
        "schema_version": "cigar.refinement-task-packet.v1",
        "packet_id": "",
        "champion": champion,
        "architecture_summary": family["architecture_summary"],
        "failure_cluster": failure_cluster,
        "hypothesis": hypothesis,
        "constraints": [
            f"trial_class={family['trial_class']}",
            "Preserve authorization, nondisclosure, integrity, determinism, and compatibility.",
            "Do not edit a test, evaluator, corpus, promotion policy, CI permission, or release surface to make a product trial pass.",
            "Use only named gates and controller-owned tools.",
        ],
        "allowed_paths": family["allowed_paths"],
        "forbidden_paths": family["forbidden_paths"],
        "budgets": family["budgets"],
        "named_gates": family["named_gates"],
        "public_examples": [],
        "prior_rejections": prior[:256],
        "required_final_schema": "schemas/refinement/model-action-v1.schema.json",
    }
    unsigned = dict(body)
    unsigned.pop("packet_id")
    body["packet_id"] = identity(unsigned)
    SchemaRegistry(SCHEMAS).validate("task-packet-v1.schema.json", body)
    return body


def schedule(
    *,
    signals: list[dict[str, Any]],
    history: list[dict[str, Any]],
    ledger_entries: list[dict[str, Any]],
    champion: dict[str, str],
    trial_class: str,
    maximum_estimated_cost: float,
    families_path: Path = FAMILIES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if trial_class not in TRIAL_CLASS:
        raise ExperimentError("trial class is invalid")
    if (
        isinstance(maximum_estimated_cost, bool)
        or not isinstance(maximum_estimated_cost, (int, float))
        or maximum_estimated_cost <= 0
    ):
        raise ExperimentError("scheduler budget is invalid")
    registry = SchemaRegistry(SCHEMAS)
    for signal in signals:
        validate_signal(signal)
    for record in history:
        try:
            registry.validate("trial-history-v1.schema.json", record)
        except ValueError as error:
            raise ExperimentError("trial history is malformed") from error
    signals = ingest_signals(signals)
    families = load_families(families_path)
    completed = {
        entry["iteration_id"]
        for entry in ledger_entries
        if entry.get("event_type") in TERMINAL_EVENTS
    }
    known_hypotheses = {item["hypothesis_fingerprint"] for item in history}
    total_attempts = len(history)
    candidates: list[dict[str, Any]] = []
    candidate_fingerprints: set[str] = set()
    excluded: list[str] = []
    for signal in sorted(signals, key=lambda item: item["signal_id"]):
        family = _family_for(signal, families, trial_class)
        if family is None:
            excluded.append(f"{signal['signal_id']}:no-family")
            continue
        if signal["estimated_cost"] > maximum_estimated_cost:
            excluded.append(f"{signal['signal_id']}:over-budget")
            continue
        intervention = family["intervention_template"].format(metric=signal["metric"])
        hypothesis = (
            f"Observed failure: {signal['summary']}; proposed intervention: {intervention}"
            if signal["visibility"] == "public"
            else f"Observed aggregate {signal['metric']} gap; proposed intervention: {intervention}"
        )
        fingerprint = hypothesis_fingerprint(
            family["family_id"], signal["metric"], intervention, trial_class
        )
        trial_id = "trial-" + fingerprint[4:20]
        if fingerprint in known_hypotheses:
            excluded.append(f"{signal['signal_id']}:duplicate-hypothesis")
            continue
        if fingerprint in candidate_fingerprints:
            excluded.append(f"{signal['signal_id']}:duplicate-hypothesis")
            continue
        if trial_id in completed:
            excluded.append(f"{signal['signal_id']}:completed-ledger-trial")
            continue
        stats = _history_stats(family["family_id"], history)
        score, components = _score(signal, family, stats, total_attempts)
        candidate_id = identity(
            {
                "signal_id": signal["signal_id"],
                "family_id": family["family_id"],
                "hypothesis_fingerprint": fingerprint,
                "score": score,
            }
        )
        candidates.append(
            {
                "candidate_id": candidate_id,
                "signal": signal,
                "family": family,
                "hypothesis": hypothesis,
                "hypothesis_fingerprint": fingerprint,
                "trial_id": trial_id,
                "score": score,
                "components": components,
                "stats": stats,
            }
        )
        candidate_fingerprints.add(fingerprint)
    if not candidates:
        raise ExperimentError("no eligible opportunity remains")
    candidates.sort(key=lambda item: (-item["score"], item["candidate_id"]))
    selected = candidates[0]
    packet = _packet(
        signal=selected["signal"],
        family=selected["family"],
        champion=champion,
        hypothesis=selected["hypothesis"],
        history=history,
    )
    explanation = (
        f"selected {selected['trial_id']} family={selected['family']['family_id']} "
        f"score={selected['score']}; components={selected['components']}; "
        f"family_history={selected['stats']}; candidates={len(candidates)} "
        f"excluded={len(excluded)}"
    )
    body = {
        "schema_version": "cigar.refinement-schedule-decision.v1",
        "selected_trial_id": selected["trial_id"],
        "selected_family_id": selected["family"]["family_id"],
        "selected_hypothesis_fingerprint": selected["hypothesis_fingerprint"],
        "task_packet_id": packet["packet_id"],
        "score": selected["score"],
        "explanation": explanation,
        "ranked_candidates": [item["candidate_id"] for item in candidates],
        "excluded": sorted(excluded),
    }
    decision = {**body, "decision_id": identity(body)}
    registry.validate("schedule-decision-v1.schema.json", decision)
    return decision, packet
