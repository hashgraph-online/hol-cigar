"""Deterministic paired task-cluster bootstrap and constrained Pareto comparison."""

from __future__ import annotations

import argparse
import hashlib
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Sequence

from .canonical import canonical_bytes, identity, loads, multihash_bytes, secure_read
from .schema import SchemaRegistry

MAX_INPUT_BYTES = 16 * 1024 * 1024
REQUIRED_METRICS = {
    "abstention_correctness",
    "authorization_violations",
    "budget_overflow",
    "cache_read_tokens",
    "cache_write_tokens",
    "citation_precision",
    "citation_recall",
    "conflict_correctness",
    "cost_usd",
    "cpu_ms",
    "critical_context_recall",
    "digest_mismatches",
    "effects",
    "evidence_item_precision",
    "evidence_sufficiency",
    "evidence_token_precision",
    "first_useful_evidence_rank",
    "handoffs",
    "human_agreement",
    "latency_ms",
    "output_tokens",
    "peak_rss_bytes",
    "physical_input_tokens",
    "prohibited_materialized_tokens",
    "replay_dispatches",
    "selected_provenance_coverage",
    "temporal_correctness",
    "unsafe_effect_retries",
    "unsupported_claim_rate",
    "verified_task_success",
}


class StatisticsError(RuntimeError):
    """Comparison evidence or statistical policy is invalid."""


def _load(path: Path, maximum: int = MAX_INPUT_BYTES) -> tuple[Any, bytes]:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.resolve(strict=True) != path
    ):
        raise StatisticsError("comparison input must be a real absolute path")
    payload = secure_read(path, maximum_bytes=maximum)
    value = loads(payload, maximum_bytes=maximum)
    return value, payload


def load_policy(path: Path, registry: SchemaRegistry) -> tuple[dict[str, Any], str]:
    value, _payload = _load(path)
    registry.validate("promotion-policy-v1.schema.json", value)
    if not isinstance(value, dict):
        raise StatisticsError("promotion policy must be an object")
    for field in (
        "tier0_checks",
        "tier1_external_checks",
        "protected_strata",
    ):
        if value[field] != sorted(set(value[field])):
            raise StatisticsError(f"promotion policy {field} is not canonical")
    for field in (
        "evidence_minimums",
        "tier1_metric_constraints",
        "primary_metrics",
        "performance_metrics",
    ):
        key = "evidence_class" if field == "evidence_minimums" else "name"
        keys = [item[key] for item in value[field]]
        if keys != sorted(set(keys)):
            raise StatisticsError(f"promotion policy {field} is not canonical")
    return value, identity(value)


def load_input(
    path: Path, registry: SchemaRegistry
) -> tuple[dict[str, Any], bytes, str]:
    value, payload = _load(path)
    registry.validate("comparison-input-v1.schema.json", value)
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise StatisticsError("comparison input must be canonical JSON")
    body = dict(value)
    claimed = body.pop("input_id")
    if identity(body) != claimed:
        raise StatisticsError("comparison input self-identity is invalid")
    return value, payload, multihash_bytes(payload)


def _rounded(value: float) -> float:
    result = round(float(value), 9)
    return 0.0 if result == 0 else result


def _mean(values: Sequence[float]) -> float:
    if not values:
        raise StatisticsError("cannot average an empty metric sample")
    return statistics.fmean(values)


def _percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise StatisticsError("cannot take a percentile of an empty sample")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _rng(input_id: str, domain: str) -> random.Random:
    digest = hashlib.sha256(
        b"CIGAR\x00comparison-v1\x00"
        + input_id.encode("ascii")
        + b"\x00"
        + domain.encode("utf-8")
    ).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _metric_map(treatment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = treatment["metrics"]
    names = [row["name"] for row in rows]
    if names != sorted(set(names)) or not REQUIRED_METRICS.issubset(names):
        raise StatisticsError("treatment metric inventory is incomplete or noncanonical")
    result = {}
    for row in rows:
        if row["applicable"]:
            if row["denominator"] <= 0:
                raise StatisticsError("applicable metric has no denominator")
            expected = (
                row["numerator"] / row["denominator"]
                if row["unit"] == "ratio"
                else row["numerator"]
            )
            if not math.isclose(row["value"], expected, abs_tol=1e-12):
                raise StatisticsError("metric arithmetic differs from raw numerator")
        elif any(row[field] != 0 for field in ("numerator", "denominator", "value")):
            raise StatisticsError("inapplicable metric is not exactly zero")
        result[row["name"]] = row
    return result


def _prepare_pairs(
    value: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, set[str]], list[int]]:
    raw_pairs = value["pairs"]
    pair_ids = [pair["pair_id"] for pair in raw_pairs]
    if pair_ids != sorted(set(pair_ids)):
        raise StatisticsError("comparison pairs are not canonical and unique")
    strata: dict[str, set[str]] = defaultdict(set)
    expected_seed_indexes = list(range(len(value["assignment_seed_digests"])))
    task_seeds: dict[tuple[str, str], set[int]] = defaultdict(set)
    pairs = []
    for raw_pair in raw_pairs:
        pair = dict(raw_pair)
        maps = {
            treatment: _metric_map(pair[treatment])
            for treatment in ("champion", "candidate", "honey")
        }
        names = set(maps["champion"])
        if any(set(metric_map) != names for metric_map in maps.values()):
            raise StatisticsError("paired treatments have different metric inventories")
        for name in names:
            applicability = {
                maps[treatment][name]["applicable"]
                for treatment in ("champion", "candidate", "honey")
            }
            if len(applicability) != 1:
                raise StatisticsError("paired metric applicability differs")
        pair["_metric_maps"] = maps
        pairs.append(pair)
        stratum = pair["stratum"]
        lineage = pair["task_lineage_id"]
        strata[stratum].add(lineage)
        key = (stratum, lineage)
        if pair["seed_index"] in task_seeds[key]:
            raise StatisticsError("task repeats an assignment seed")
        task_seeds[key].add(pair["seed_index"])
    expected = set(expected_seed_indexes)
    if any(seeds != expected for seeds in task_seeds.values()):
        raise StatisticsError("each task must cover every declared assignment seed")
    return pairs, strata, expected_seed_indexes


def _values(
    pairs: Sequence[dict[str, Any]],
    metric: str,
    treatment: str,
) -> list[float]:
    return [
        float(pair["_metric_maps"][treatment][metric]["value"])
        for pair in pairs
        if pair["_metric_maps"][treatment][metric]["applicable"]
    ]


def _benefit(
    pairs: Sequence[dict[str, Any]],
    metric: str,
    reference: str,
    direction: str,
    *,
    relative: bool = False,
) -> float:
    candidate = _values(pairs, metric, "candidate")
    baseline = _values(pairs, metric, reference)
    if not candidate or len(candidate) != len(baseline):
        raise StatisticsError("metric has no complete applicable paired sample")
    candidate_mean = _mean(candidate)
    baseline_mean = _mean(baseline)
    benefit = (
        candidate_mean - baseline_mean
        if direction == "higher"
        else baseline_mean - candidate_mean
    )
    if relative:
        if baseline_mean < 0:
            raise StatisticsError("relative comparison baseline must be positive")
        if baseline_mean == 0:
            return 0.0 if candidate_mean == 0 else -1.0
        benefit /= baseline_mean
    return benefit


def _resample_values(
    pairs: Sequence[dict[str, Any]],
    statistic: Callable[[Sequence[dict[str, Any]]], float],
    repetitions: int,
    rng: random.Random,
) -> list[float]:
    clusters_by_stratum: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for pair in pairs:
        clusters_by_stratum[pair["stratum"]][pair["task_lineage_id"]].append(pair)
    if not clusters_by_stratum or any(
        len(clusters) < 2 for clusters in clusters_by_stratum.values()
    ):
        return []
    original = statistic(pairs)
    # Constant task effects have an exact degenerate cluster-bootstrap distribution.
    task_effects = []
    for stratum in sorted(clusters_by_stratum):
        for lineage in sorted(clusters_by_stratum[stratum]):
            task_effects.append(
                statistic(clusters_by_stratum[stratum][lineage])
            )
    if task_effects and all(
        math.isclose(value, task_effects[0], abs_tol=1e-15)
        for value in task_effects
    ):
        return [original] * repetitions
    values = []
    for _ in range(repetitions):
        sample = []
        for stratum in sorted(clusters_by_stratum):
            clusters = [
                clusters_by_stratum[stratum][lineage]
                for lineage in sorted(clusters_by_stratum[stratum])
            ]
            for _slot in clusters:
                sample.extend(clusters[rng.randrange(len(clusters))])
        result = statistic(sample)
        if math.isfinite(result):
            values.append(result)
    if len(values) != repetitions:
        raise StatisticsError("bootstrap statistic produced a non-finite value")
    return values


def _interval(values: Sequence[float], confidence_percent: int) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    alpha = (100 - confidence_percent) / 100
    return (
        _rounded(_percentile(values, alpha / 2)),
        _rounded(_percentile(values, 1 - alpha / 2)),
    )


def _p_value_ppm(values: Sequence[float], threshold: float) -> int:
    if not values:
        return 1_000_000
    failures = sum(value < threshold for value in values)
    return math.ceil((failures + 1) * 1_000_000 / (len(values) + 1))


def _check_rows(
    supplied: list[dict[str, Any]], required: list[str], kind: str
) -> list[dict[str, Any]]:
    ids = [item["check_id"] for item in supplied]
    if ids != required:
        raise StatisticsError(f"{kind} check inventory differs from policy")
    return [
        {
            "gate_id": item["check_id"],
            "passed": item["passed"],
            "source_digest": item["attachment_digest"],
        }
        for item in supplied
    ]


def _metric_constraint_rows(
    policy: dict[str, Any], pairs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    result = []
    for constraint in policy["tier1_metric_constraints"]:
        values = _values(pairs, constraint["name"], "candidate")
        aggregate = min(values) if constraint["aggregation"] == "minimum" else max(values)
        passed = (
            aggregate >= constraint["limit"]
            if constraint["operator"] == "at_least"
            else aggregate <= constraint["limit"]
        )
        result.append(
            {
                "gate_id": f"metric-{constraint['name']}",
                "passed": passed,
                "source_digest": identity(
                    [
                        pair["candidate"]["evaluation_digest"]
                        for pair in pairs
                    ]
                ),
            }
        )
    return result


def _minimums(
    policy: dict[str, Any], evidence_class: str
) -> dict[str, Any]:
    return next(
        item
        for item in policy["evidence_minimums"]
        if item["evidence_class"] == evidence_class
    )


def compare(
    *,
    input_value: dict[str, Any],
    input_digest: str,
    policy: dict[str, Any],
    policy_digest: str,
    honey_anchor: dict[str, Any],
    honey_anchor_bytes: bytes,
    registry: SchemaRegistry,
) -> dict[str, Any]:
    if input_value["policy_digest"] != policy_digest:
        raise StatisticsError("comparison input does not bind the policy")
    if multihash_bytes(honey_anchor_bytes) != policy["honey_anchor_digest"]:
        raise StatisticsError("Honey anchor bytes differ from policy")
    honey_source = {
        "revision": honey_anchor["source"]["release_commit"],
        "tree": honey_anchor["source"]["tree"],
    }
    if input_value["honey_source"] != honey_source:
        raise StatisticsError("comparison does not use the immutable Honey source")
    pairs, strata, seed_indexes = _prepare_pairs(input_value)
    minimums = _minimums(policy, input_value["evidence_class"])
    counts_ok = set(strata) == set(policy["protected_strata"]) and all(
        len(strata[stratum]) >= minimums["tasks_per_stratum"]
        for stratum in policy["protected_strata"]
    )
    statistics_ok = (
        input_value["bootstrap_repetitions"] >= minimums["bootstrap_repetitions"]
        and input_value["confidence_percent"] == minimums["confidence_percent"]
        and len(seed_indexes) >= minimums["assignment_seeds"]
    )
    evidence = _check_rows(
        input_value["tier0_checks"], policy["tier0_checks"], "Tier 0"
    )
    derived_evidence_digest = identity(
        {
            "counts": {key: len(value) for key, value in sorted(strata.items())},
            "seeds": len(seed_indexes),
            "statistics": {
                "bootstrap": input_value["bootstrap_repetitions"],
                "confidence": input_value["confidence_percent"],
            },
        }
    )
    evidence.extend(
        [
            {
                "gate_id": "sample-requirements",
                "passed": counts_ok,
                "source_digest": derived_evidence_digest,
            },
            {
                "gate_id": "statistical-requirements",
                "passed": statistics_ok,
                "source_digest": derived_evidence_digest,
            },
        ]
    )
    evidence.sort(key=lambda item: item["gate_id"])
    hard = _check_rows(
        input_value["tier1_checks"],
        policy["tier1_external_checks"],
        "Tier 1",
    )
    hard.extend(_metric_constraint_rows(policy, pairs))
    hard.sort(key=lambda item: item["gate_id"])
    primary = {item["name"]: item for item in policy["primary_metrics"]}
    all_names = sorted(pairs[0]["_metric_maps"]["candidate"])
    metric_rows = []
    bootstrap_cache: dict[str, list[float]] = {}
    for name in all_names:
        spec = primary.get(name)
        direction = "neutral" if spec is None else spec["direction"]
        applicable = _values(pairs, name, "candidate")
        if not applicable:
            metric_rows.append(
                {
                    "name": name,
                    "direction": direction,
                    "blocking": bool(spec and spec["blocking"]),
                    "samples": 0,
                    "champion": 0,
                    "candidate": 0,
                    "honey": 0,
                    "benefit": 0,
                    "lower": 0,
                    "upper": 0,
                    "honey_benefit": 0,
                    "honey_lower": 0,
                    "honey_upper": 0,
                    "noninferior_champion": not bool(spec and spec["blocking"]),
                    "noninferior_honey": not bool(spec and spec["blocking"]),
                    "absolute_slo_passed": not bool(spec and spec["blocking"]),
                    "meaningful": False,
                    "p_value_ppm": 1_000_000,
                    "holm_threshold_ppm": 0,
                    "holm_passed": False,
                    "seed_consistent": False,
                    "decision": "insufficient" if spec else "diagnostic",
                }
            )
            continue
        champion = _mean(_values(pairs, name, "champion"))
        candidate = _mean(applicable)
        honey = _mean(_values(pairs, name, "honey"))
        if spec is None:
            metric_rows.append(
                {
                    "name": name,
                    "direction": "neutral",
                    "blocking": False,
                    "samples": len(applicable),
                    "champion": _rounded(champion),
                    "candidate": _rounded(candidate),
                    "honey": _rounded(honey),
                    "benefit": 0,
                    "lower": 0,
                    "upper": 0,
                    "honey_benefit": 0,
                    "honey_lower": 0,
                    "honey_upper": 0,
                    "noninferior_champion": True,
                    "noninferior_honey": True,
                    "absolute_slo_passed": True,
                    "meaningful": False,
                    "p_value_ppm": 1_000_000,
                    "holm_threshold_ppm": 0,
                    "holm_passed": False,
                    "seed_consistent": True,
                    "decision": "diagnostic",
                }
            )
            continue
        metric_pairs = [
            pair
            for pair in pairs
            if pair["_metric_maps"]["candidate"][name]["applicable"]
        ]
        statistic = lambda sample, n=name, d=direction: _benefit(
            sample, n, "champion", d
        )
        honey_statistic = lambda sample, n=name, d=direction: _benefit(
            sample, n, "honey", d
        )
        benefit = statistic(metric_pairs)
        honey_benefit = honey_statistic(metric_pairs)
        boot = _resample_values(
            metric_pairs,
            statistic,
            input_value["bootstrap_repetitions"],
            _rng(input_value["input_id"], f"metric:{name}:champion"),
        )
        honey_boot = _resample_values(
            metric_pairs,
            honey_statistic,
            input_value["bootstrap_repetitions"],
            _rng(input_value["input_id"], f"metric:{name}:honey"),
        )
        bootstrap_cache[name] = boot
        lower, upper = _interval(boot, input_value["confidence_percent"])
        honey_lower, honey_upper = _interval(
            honey_boot, input_value["confidence_percent"]
        )
        seed_benefits = [
            statistic(
                [pair for pair in metric_pairs if pair["seed_index"] == seed]
            )
            for seed in seed_indexes
        ]
        floor = spec["absolute_floor"]
        ceiling = spec["absolute_ceiling"]
        absolute_passed = (
            (floor is None or candidate >= floor)
            and (ceiling is None or candidate <= ceiling)
        )
        noninferior_champion = bool(boot) and lower >= -spec["noninferiority_margin"]
        noninferior_honey = bool(honey_boot) and honey_lower >= -spec["noninferiority_margin"]
        p_value = _p_value_ppm(boot, spec["meaningful_delta"])
        metric_rows.append(
            {
                "name": name,
                "direction": direction,
                "blocking": spec["blocking"],
                "samples": len(applicable),
                "champion": _rounded(champion),
                "candidate": _rounded(candidate),
                "honey": _rounded(honey),
                "benefit": _rounded(benefit),
                "lower": lower,
                "upper": upper,
                "honey_benefit": _rounded(honey_benefit),
                "honey_lower": honey_lower,
                "honey_upper": honey_upper,
                "noninferior_champion": noninferior_champion,
                "noninferior_honey": noninferior_honey,
                "absolute_slo_passed": absolute_passed,
                "meaningful": False,
                "p_value_ppm": p_value,
                "holm_threshold_ppm": 0,
                "holm_passed": False,
                "seed_consistent": all(value > 0 for value in seed_benefits),
                "decision": (
                    "inferior"
                    if spec["blocking"]
                    and (
                        not noninferior_champion
                        or not noninferior_honey
                        or not absolute_passed
                    )
                    else "noninferior"
                ),
            }
        )
    # Holm step-down across the declared applicable primary family.
    family = sorted(
        (row for row in metric_rows if row["name"] in primary and row["samples"]),
        key=lambda row: (row["p_value_ppm"], row["name"]),
    )
    alpha_ppm = (100 - input_value["confidence_percent"]) * 10_000
    still_rejecting = True
    for rank, row in enumerate(family):
        threshold = alpha_ppm // (len(family) - rank)
        row["holm_threshold_ppm"] = threshold
        passed = still_rejecting and row["p_value_ppm"] <= threshold
        row["holm_passed"] = passed
        if not passed:
            still_rejecting = False
        spec = primary[row["name"]]
        row["meaningful"] = bool(
            passed
            and row["lower"] >= spec["meaningful_delta"]
            and row["honey_lower"] >= -spec["noninferiority_margin"]
            and row["seed_consistent"]
            and row["absolute_slo_passed"]
        )
        if row["meaningful"]:
            row["decision"] = "improved"
    metric_rows.sort(key=lambda row: row["name"])
    performance = []
    for spec in policy["performance_metrics"]:
        name = spec["name"]
        metric_pairs = [
            pair
            for pair in pairs
            if pair["_metric_maps"]["candidate"][name]["applicable"]
        ]
        if not metric_pairs:
            performance.append(
                {
                    "name": name,
                    "champion": 0,
                    "candidate": 0,
                    "relative_benefit": 0,
                    "lower": 0,
                    "upper": 0,
                    "relative_regression_limit": spec["relative_regression_limit"],
                    "meaningful_relative_delta": spec[
                        "meaningful_relative_delta"
                    ],
                    "absolute_slo_passed": spec["absolute_ceiling"] is None,
                    "noninferior": True,
                    "meaningful": False,
                }
            )
            continue
        statistic = lambda sample, n=name: _benefit(
            sample, n, "champion", "lower", relative=True
        )
        champion = _mean(_values(metric_pairs, name, "champion"))
        candidate = _mean(_values(metric_pairs, name, "candidate"))
        benefit = statistic(metric_pairs)
        boot = _resample_values(
            metric_pairs,
            statistic,
            input_value["bootstrap_repetitions"],
            _rng(input_value["input_id"], f"performance:{name}"),
        )
        lower, upper = _interval(boot, input_value["confidence_percent"])
        absolute_passed = (
            spec["absolute_ceiling"] is None
            or candidate <= spec["absolute_ceiling"]
        )
        noninferior = bool(boot) and lower >= -spec["relative_regression_limit"]
        performance.append(
            {
                "name": name,
                "champion": _rounded(champion),
                "candidate": _rounded(candidate),
                "relative_benefit": _rounded(benefit),
                "lower": lower,
                "upper": upper,
                "relative_regression_limit": spec["relative_regression_limit"],
                "meaningful_relative_delta": spec["meaningful_relative_delta"],
                "absolute_slo_passed": absolute_passed,
                "noninferior": noninferior,
                "meaningful": bool(
                    noninferior
                    and absolute_passed
                    and lower >= spec["meaningful_relative_delta"]
                ),
            }
        )
    protected = []
    for stratum in policy["protected_strata"]:
        sample = [pair for pair in pairs if pair["stratum"] == stratum]
        reasons = []
        tasks = len({pair["task_lineage_id"] for pair in sample})
        if tasks < minimums["tasks_per_stratum"]:
            status = "insufficient"
            reasons.append("insufficient-tasks")
        else:
            for spec in policy["primary_metrics"]:
                if not spec["blocking"]:
                    continue
                name = spec["name"]
                if not _values(sample, name, "candidate"):
                    reasons.append(f"{name}-insufficient")
                    continue
                champion_boot = _resample_values(
                    sample,
                    lambda rows, n=name, d=spec["direction"]: _benefit(
                        rows, n, "champion", d
                    ),
                    input_value["bootstrap_repetitions"],
                    _rng(input_value["input_id"], f"stratum:{stratum}:{name}:champion"),
                )
                honey_boot = _resample_values(
                    sample,
                    lambda rows, n=name, d=spec["direction"]: _benefit(
                        rows, n, "honey", d
                    ),
                    input_value["bootstrap_repetitions"],
                    _rng(input_value["input_id"], f"stratum:{stratum}:{name}:honey"),
                )
                champion_lower, _ = _interval(
                    champion_boot, input_value["confidence_percent"]
                )
                honey_lower, _ = _interval(
                    honey_boot, input_value["confidence_percent"]
                )
                if (
                    not champion_boot
                    or not honey_boot
                    or champion_lower < -spec["noninferiority_margin"]
                    or honey_lower < -spec["noninferiority_margin"]
                ):
                    reasons.append(f"{name}-inferior")
            status = "passed" if not reasons else "failed"
        protected.append(
            {
                "stratum": stratum,
                "tasks": tasks,
                "status": status,
                "reasons": sorted(set(reasons)),
            }
        )
    meaningful = sorted(
        [row["name"] for row in metric_rows if row["meaningful"]]
        + [row["name"] for row in performance if row["meaningful"]]
    )
    reasons = []
    if not all(item["passed"] for item in evidence):
        verdict = "invalid"
        reasons.append("invalid-evidence")
    elif not all(item["passed"] for item in hard):
        verdict = "ineligible"
        reasons.append("hard-invariant")
    elif any(
        row["blocking"]
        and (
            not row["noninferior_champion"]
            or not row["noninferior_honey"]
            or not row["absolute_slo_passed"]
        )
        for row in metric_rows
    ):
        verdict = "ineligible"
        reasons.append("primary-inferiority")
    elif any(item["status"] != "passed" for item in protected):
        verdict = "ineligible"
        reasons.append("protected-stratum")
    elif any(
        not item["noninferior"] or not item["absolute_slo_passed"]
        for item in performance
    ):
        verdict = "ineligible"
        reasons.append("performance-regression")
    elif any(
        row["holm_passed"]
        and row["lower"] > 0
        and not row["seed_consistent"]
        for row in metric_rows
    ):
        verdict = "ineligible"
        reasons.append("seed-inconsistent")
    elif not meaningful:
        verdict = "ineligible"
        reasons.append("no-meaningful-improvement")
    else:
        verdict = "eligible"
    body = {
        "schema_version": "cigar.refinement-comparison.v1",
        "input_id": input_value["input_id"],
        "input_digest": input_digest,
        "trial_id": input_value["trial_id"],
        "evidence_class": input_value["evidence_class"],
        "champion_source": input_value["champion_source"],
        "candidate_source": input_value["candidate_source"],
        "honey_source": input_value["honey_source"],
        "dataset_epoch": input_value["dataset_epoch"],
        "policy_digest": policy_digest,
        "bootstrap_repetitions": input_value["bootstrap_repetitions"],
        "assignment_seeds": len(input_value["assignment_seed_digests"]),
        "confidence_percent": input_value["confidence_percent"],
        "holm_correction": True,
        "evidence_validity": evidence,
        "hard_constraints": hard,
        "metrics": metric_rows,
        "performance": performance,
        "protected_strata": protected,
        "meaningful_improvements": meaningful,
        "reasons": sorted(set(reasons)),
        "verdict": verdict,
    }
    comparison = {**body, "comparison_id": identity(body)}
    registry.validate("comparison-v1.schema.json", comparison)
    return comparison


def comparison_from_paths(
    input_path: Path,
    policy_path: Path,
    honey_anchor_path: Path,
    schemas: Path,
) -> dict[str, Any]:
    registry = SchemaRegistry(schemas)
    input_value, _payload, input_digest = load_input(input_path, registry)
    policy, policy_digest = load_policy(policy_path, registry)
    honey_anchor, honey_bytes = _load(honey_anchor_path)
    return compare(
        input_value=input_value,
        input_digest=input_digest,
        policy=policy,
        policy_digest=policy_digest,
        honey_anchor=honey_anchor,
        honey_anchor_bytes=honey_bytes,
        registry=registry,
    )


def replay(expected_path: Path, **arguments: Any) -> dict[str, Any]:
    expected, payload = _load(expected_path)
    registry = SchemaRegistry(arguments["schemas"])
    registry.validate("comparison-v1.schema.json", expected)
    reproduced = comparison_from_paths(**arguments)
    if canonical_bytes(reproduced) != payload:
        raise StatisticsError("comparison replay differs from retained record")
    return reproduced


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("compare", "replay"))
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--honey-anchor", required=True, type=Path)
    parser.add_argument("--schemas", required=True, type=Path)
    parser.add_argument("--expected", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    call = {
        "input_path": arguments.input,
        "policy_path": arguments.policy,
        "honey_anchor_path": arguments.honey_anchor,
        "schemas": arguments.schemas,
    }
    try:
        if arguments.command == "compare":
            result = comparison_from_paths(**call)
        else:
            if arguments.expected is None:
                raise StatisticsError("comparison replay requires --expected")
            result = replay(arguments.expected, **call)
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0
    except (StatisticsError, OSError, ValueError) as error:
        print(f"statistics: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
