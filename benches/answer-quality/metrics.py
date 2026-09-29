#!/usr/bin/env python3
"""Offline metrics for independently annotated displayed answers, with explicit denominators.

No model/judge calls. Do not feed gate verdicts back as supposedly independent gold labels.
Each JSONL row is one distinct episode/treatment; repeated samples must be aggregated or
clustered upstream. Run --help and read README.md for the schema and interpretation.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import random
import statistics

LABELS = {"supported", "unsupported", "contradicted", "unknown"}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def validate(rows):
    """Reject ambiguous/missing annotations rather than silently improving a denominator."""
    if not rows:
        raise ValueError("empty evaluation")
    seen = set()
    for row in rows:
        for key in ("episode_id", "treatment", "stratum"):
            if not isinstance(row.get(key), str) or not row[key]:
                raise ValueError(f"missing {key}")
        key = (row["episode_id"], row["treatment"])
        if key in seen:
            raise ValueError("duplicate episode/treatment; cluster repetitions upstream")
        seen.add(key)
        if type(row.get("answerable")) is not bool or type(row.get("abstained")) is not bool:
            raise ValueError("answerable and abstained require explicit boolean labels")
        facts = row.get("gold_facts")
        if (not isinstance(facts, list) or any(not isinstance(fact, str) or not fact for fact in facts)
                or len(set(facts)) != len(facts) or (row["answerable"] and not facts)):
            raise ValueError("answerable episodes need distinct gold facts")
        claims = row.get("claims")
        if not isinstance(claims, list) or (row["abstained"] and claims) or (not row["abstained"] and not claims):
            raise ValueError("displayed claims and abstention are inconsistent")
        ids = set()
        for claim in claims:
            if not isinstance(claim.get("id"), str) or not claim["id"] or claim["id"] in ids:
                raise ValueError("invalid/duplicate atomic claim ID")
            ids.add(claim["id"])
            if claim.get("label") not in LABELS:
                raise ValueError("every claim requires an independent support label")
            if "confidence" not in claim:
                raise ValueError("confidence must be explicitly null when unavailable")
            p = claim["confidence"]
            if p is not None and (not finite(p) or not 0 <= p <= 1):
                raise ValueError("confidence must be finite probability or null")
            citations = claim.get("citation_labels")
            if not isinstance(citations, list) or any(label not in LABELS for label in citations):
                raise ValueError("citation_labels must independently label each cited claim/source pair")
            fact = claim.get("fact_id")
            if fact is not None and (not isinstance(fact, str) or fact not in facts):
                raise ValueError("fact_id must map to a gold fact or be null")
        if type(row.get("context_tokens")) is not int or row["context_tokens"] < 0:
            raise ValueError("context_tokens must be a nonnegative exact token count")
        if not finite(row.get("latency_ms")) or row["latency_ms"] < 0:
            raise ValueError("latency_ms must be finite and nonnegative")


def useful_facts(row):
    return {c["fact_id"] for c in row["claims"] if c["label"] == "supported" and c.get("fact_id") is not None}


def correct_answer(row):
    return (row["answerable"] and not row["abstained"]
            and all(c["label"] == "supported" for c in row["claims"])
            and useful_facts(row) == set(row["gold_facts"]))


def confident_error_episode(row, threshold=.8):
    return any(c["label"] in {"unsupported", "contradicted"} and c["confidence"] is not None
               and c["confidence"] >= threshold for c in row["claims"])


def summarize(rows, threshold=0.8):
    claims = [claim for row in rows for claim in row["claims"]]
    n = len(claims)
    supported = sum(c["label"] == "supported" for c in claims)
    errors = sum(c["label"] in {"unsupported", "contradicted"} for c in claims)
    unknown = sum(c["label"] == "unknown" for c in claims)
    confident = [c for c in claims if c["confidence"] is not None and c["confidence"] >= threshold]
    confident_errors = sum(c["label"] in {"unsupported", "contradicted"} for c in confident)
    calibrated = [c for c in claims if c["confidence"] is not None and c["label"] != "unknown"]
    bins = []
    for index in range(10):
        values = [c for c in calibrated if min(9, int(c["confidence"] * 10)) == index]
        bins.append({"lower": index / 10, "upper": (index + 1) / 10, "count": len(values),
                     "confidence": statistics.mean(c["confidence"] for c in values) if values else None,
                     "accuracy": ratio(sum(c["label"] == "supported" for c in values), len(values))})
    citation_labels = [label for c in claims for label in c["citation_labels"]]
    answerable = [row for row in rows if row["answerable"]]
    unanswerable = [row for row in rows if not row["answerable"]]
    answered = [row for row in rows if not row["abstained"]]
    useful = sum(len(useful_facts(row)) for row in rows)
    risk_coverage = []
    for cutoff in [0, .5, .8, .9, .95, 1]:
        accepted = [c for c in calibrated if c["confidence"] >= cutoff]
        risk_coverage.append({"threshold": cutoff, "claims": len(accepted),
                              "coverage_all_claims": ratio(len(accepted), n),
                              "error_rate": ratio(sum(c["label"] != "supported" for c in accepted), len(accepted))})
    timings = sorted(row["latency_ms"] for row in rows)
    return {
        "episodes": len(rows), "answered_episodes": len(answered), "claims": n,
        "supported_claims": supported, "unsupported_or_contradicted_claims": errors, "unknown_claims": unknown,
        "factual_precision": ratio(supported, n), "known_error_rate": ratio(errors, n - unknown),
        "unverified_rate": ratio(n - supported, n), "annotation_coverage": ratio(n - unknown, n),
        "high_confidence_threshold": threshold, "confident_claims": len(confident),
        "confident_errors": confident_errors, "confident_error_rate_all_claims": ratio(confident_errors, n),
        "confident_error_episode_rate": ratio(sum(confident_error_episode(row, threshold) for row in rows), len(rows)),
        "confident_error_rate_confident_claims": ratio(confident_errors, len(confident)),
        "confident_unknown_claims": sum(c["label"] == "unknown" for c in confident),
        "confidence_coverage": ratio(sum(c["confidence"] is not None for c in claims), n),
        "calibration_claims": len(calibrated),
        "brier": statistics.mean((c["confidence"] - int(c["label"] == "supported")) ** 2 for c in calibrated) if calibrated else None,
        "ece_10": sum(b["count"] * abs(b["confidence"] - b["accuracy"]) for b in bins if b["count"]) / len(calibrated) if calibrated else None,
        "calibration_bins": bins, "risk_coverage": risk_coverage,
        "citation_pairs": len(citation_labels),
        "citation_precision": ratio(citation_labels.count("supported"), len(citation_labels)),
        "citation_completeness": ratio(sum("supported" in c["citation_labels"] for c in claims), n),
        "answer_coverage": ratio(len(answered), len(rows)),
        "correct_answer_yield": ratio(sum(correct_answer(row) for row in rows), len(rows)),
        "answerable_success_rate": ratio(sum(correct_answer(row) for row in answerable), len(answerable)),
        "answerable_refusal_rate": ratio(sum(row["abstained"] for row in answerable), len(answerable)),
        "unanswerable_abstention_rate": ratio(sum(row["abstained"] for row in unanswerable), len(unanswerable)),
        "useful_fact_recall": ratio(useful, sum(len(row["gold_facts"]) for row in rows)),
        "supported_useful_facts": useful,
        "context_tokens": sum(row["context_tokens"] for row in rows),
        "context_tokens_per_supported_useful_fact": ratio(sum(row["context_tokens"] for row in rows), useful),
        "latency_p50_ms": statistics.median(timings),
        "latency_p95_ms": timings[math.ceil(.95 * len(timings)) - 1],
    }


def paired_interval(rows, baseline, candidate, draws=2000):
    """Paired episode bootstrap for complete supported answer yield, not claim-level resampling."""
    groups = {name: {r["episode_id"]: r for r in rows if r["treatment"] == name} for name in (baseline, candidate)}
    left, right = groups[baseline], groups[candidate]
    if not left or left.keys() != right.keys():
        raise ValueError("paired comparison needs identical nonempty episode sets")
    for key in left:
        if any(left[key][field] != right[key][field] for field in ("answerable", "gold_facts", "stratum")):
            raise ValueError("paired gold/stratum drift")
    deltas = [int(correct_answer(right[key])) - int(correct_answer(left[key])) for key in sorted(left)]
    rng = random.Random(1100)
    samples = sorted(statistics.mean(rng.choices(deltas, k=len(deltas))) for _ in range(draws))
    error_deltas = [int(confident_error_episode(right[key])) - int(confident_error_episode(left[key])) for key in sorted(left)]
    error_samples = sorted(statistics.mean(rng.choices(error_deltas, k=len(error_deltas))) for _ in range(draws))
    return {"metric": "correct_answer_yield", "baseline": baseline, "candidate": candidate,
            "paired_episodes": len(deltas), "delta": statistics.mean(deltas),
            "ci95_percentile": [samples[int(.025 * draws)], samples[min(draws - 1, math.ceil(.975 * draws) - 1)]],
            "draws": draws, "seed": 1100,
            "confident_error_episode_rate": {"delta": statistics.mean(error_deltas),
                "ci95_percentile": [error_samples[int(.025 * draws)], error_samples[min(draws - 1, math.ceil(.975 * draws) - 1)]]},
            "limitation": "Episodes must be independent sampling units; fixed authored fixtures are not a population sample."}


def evaluate(rows):
    validate(rows)
    groups = defaultdict(list)
    strata = defaultdict(lambda: defaultdict(list))
    for row in rows:
        groups[row["treatment"]].append(row)
        strata[row["treatment"]][row["stratum"]].append(row)
    return {"schema": "cigar.answer-quality.v1", "treatments": {key: summarize(value) for key, value in sorted(groups.items())},
            "strata": {key: {name: summarize(values) for name, values in sorted(parts.items())} for key, parts in sorted(strata.items())},
            "limitation": "Metrics reflect supplied independent annotations, not automatic fact checking. Null denominators are not perfect scores."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--candidate")
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    result = evaluate(rows)
    if args.baseline or args.candidate:
        if not args.baseline or not args.candidate or args.baseline == args.candidate:
            parser.error("provide two distinct paired treatment names")
        result["paired"] = paired_interval(rows, args.baseline, args.candidate)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
