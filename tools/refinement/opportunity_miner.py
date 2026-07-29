#!/usr/bin/env python3
"""Mine, independently review, and publish deterministic opportunity signals."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
import hashlib
import hmac
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import (
    canonical_bytes,
    identity,
    load_file,
    multihash_bytes,
    secure_read,
)
from tools.refinement.dashboard import DashboardError, project
from tools.refinement.experiment import ExperimentError, make_signal, validate_signal
from tools.refinement.promotion import ParetoArchive, PromotionError
from tools.refinement.schema import SchemaRegistry

POLICY_SCHEMA = "opportunity-mining-policy-v1.schema.json"
CANDIDATES_SCHEMA = "opportunity-candidates-v1.schema.json"
REVIEW_SCHEMA = "opportunity-review-v1.schema.json"


class OpportunityMiningError(RuntimeError):
    """Mining or review evidence is malformed, ambiguous, or unapproved."""


def _absolute(path: Path, label: str, *, directory: bool = False) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise OpportunityMiningError(f"{label} must be an absolute real path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise OpportunityMiningError(f"{label} cannot be resolved") from error
    if resolved != path or (directory and not path.is_dir()):
        raise OpportunityMiningError(f"{label} must not contain aliases")
    return path


def _verify_identity(value: dict[str, Any], field: str) -> None:
    unsigned = dict(value)
    claimed = unsigned.pop(field, None)
    if claimed != identity(unsigned):
        raise OpportunityMiningError(f"{field} does not match record content")


def _registry(repository_root: Path) -> SchemaRegistry:
    return SchemaRegistry(repository_root / "schemas" / "refinement")


def load_policy(repository_root: Path, policy_path: Path) -> dict[str, Any]:
    try:
        value = load_file(policy_path)
        _registry(repository_root).validate(POLICY_SCHEMA, value)
    except (OSError, ValueError) as error:
        raise OpportunityMiningError(
            "opportunity mining policy is malformed"
        ) from error
    if not isinstance(value, dict):
        raise OpportunityMiningError("opportunity mining policy is not an object")
    _verify_identity(value, "policy_id")
    rule_ids = [
        rule["rule_id"]
        for group in ("kpi_rules", "failure_rules", "pareto_rules")
        for rule in value[group]
    ]
    if len(rule_ids) != len(set(rule_ids)):
        raise OpportunityMiningError("opportunity mining rule IDs are not unique")
    for group in ("kpi_rules", "failure_rules", "pareto_rules"):
        for rule in value[group]:
            if rule["target"]["strata"] != sorted(rule["target"]["strata"]):
                raise OpportunityMiningError("opportunity policy strata are not sorted")
    return value


def _candidate(
    *,
    rule_id: str,
    derivation_kind: str,
    signal: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "rule_id": rule_id,
        "derivation_kind": derivation_kind,
        "signal": signal,
        "evidence": evidence,
    }
    return {**body, "candidate_id": identity(body)}


def _signal(
    *,
    source_kind: str,
    projection_id: str | None,
    pareto_head: str | None,
    policy_id: str,
    rule: dict[str, Any],
    evidence: dict[str, Any],
    summary: str,
    magnitude: float,
) -> dict[str, Any]:
    target = rule["target"]
    commitment_source = {
        "policy_id": policy_id,
        "rule_id": rule["rule_id"],
        "evidence": evidence,
    }
    if projection_id is not None:
        commitment_source["projection_id"] = projection_id
    if pareto_head is not None:
        commitment_source["pareto_head"] = pareto_head
    commitment = identity(commitment_source)
    return make_signal(
        source_kind=source_kind,
        visibility="public",
        summary=summary,
        source_commitment=commitment,
        owner_hint=target["owner_hint"],
        metric=target["signal_metric"],
        magnitude=min(1.0, max(0.0, magnitude)),
        estimated_cost=float(target["estimated_cost"]),
        strata=list(target["strata"]),
        reproducible=True,
    )


def _mine_kpis(
    projection: dict[str, Any],
    policy: dict[str, Any],
    pareto_head: str | None,
) -> list[dict[str, Any]]:
    by_metric: dict[str, list[dict[str, Any]]] = {}
    for row in projection["kpi_trends"]:
        by_metric.setdefault(row["name"], []).append(row)
    result: list[dict[str, Any]] = []
    for rule in policy["kpi_rules"]:
        rows = sorted(
            by_metric.get(rule["source_metric"], []),
            key=lambda item: (item["ledger_sequence"], item["iteration_id"]),
        )
        if len(rows) < 2:
            continue
        directions = {row["direction"] for row in rows}
        if directions != {rule["direction"]}:
            raise OpportunityMiningError(
                f"KPI direction is inconsistent for {rule['source_metric']}"
            )
        latest = rows[-1]
        prior = rows[max(0, len(rows) - policy["kpi_lookback"] - 1) : -1]
        reference = (
            max(prior, key=lambda item: (item["value_ppm"], item["ledger_sequence"]))
            if rule["direction"] == "higher"
            else min(
                prior, key=lambda item: (item["value_ppm"], -item["ledger_sequence"])
            )
        )
        regression = (
            reference["value_ppm"] - latest["value_ppm"]
            if rule["direction"] == "higher"
            else latest["value_ppm"] - reference["value_ppm"]
        )
        if regression < rule["minimum_regression_ppm"]:
            continue
        evidence = {
            "kind": "kpi_regression",
            "metric": rule["source_metric"],
            "direction": rule["direction"],
            "reference_ppm": reference["value_ppm"],
            "latest_ppm": latest["value_ppm"],
            "regression_ppm": regression,
            "reference_iteration_id": reference["iteration_id"],
            "latest_iteration_id": latest["iteration_id"],
        }
        signal = _signal(
            source_kind="kpi_cluster",
            projection_id=projection["projection_id"],
            pareto_head=pareto_head,
            policy_id=policy["policy_id"],
            rule=rule,
            evidence=evidence,
            summary=(
                f"{rule['source_metric']} regressed by {regression} ppm from "
                f"{reference['iteration_id']} to {latest['iteration_id']}."
            ),
            magnitude=regression / rule["full_scale_ppm"],
        )
        result.append(
            _candidate(
                rule_id=rule["rule_id"],
                derivation_kind="kpi_regression",
                signal=signal,
                evidence=evidence,
            )
        )
    return result


def _mine_failures(
    projection: dict[str, Any],
    policy: dict[str, Any],
    pareto_head: str | None,
) -> list[dict[str, Any]]:
    failures: dict[str, int] = {}
    for row in projection["failure_classes"]:
        if row["failure_class"] in failures:
            raise OpportunityMiningError("dashboard repeats a failure class")
        failures[row["failure_class"]] = row["count"]
    result: list[dict[str, Any]] = []
    for rule in policy["failure_rules"]:
        count = failures.get(rule["failure_class"], 0)
        if count < rule["minimum_count"]:
            continue
        evidence = {
            "kind": "failure_cluster",
            "failure_class": rule["failure_class"],
            "count": count,
        }
        signal = _signal(
            source_kind="test_failure",
            projection_id=projection["projection_id"],
            pareto_head=pareto_head,
            policy_id=policy["policy_id"],
            rule=rule,
            evidence=evidence,
            summary=(
                f"Replayed dashboard evidence contains {count} "
                f"{rule['failure_class']} failures."
            ),
            magnitude=count / rule["full_scale_count"],
        )
        result.append(
            _candidate(
                rule_id=rule["rule_id"],
                derivation_kind="failure_cluster",
                signal=signal,
                evidence=evidence,
            )
        )
    return result


def _mine_pareto(
    projection: dict[str, Any],
    policy: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not records:
        return []
    by_comparison = {row["comparison_id"]: row for row in records}
    frontier = [by_comparison[item] for item in records[-1]["frontier_after"]]
    result: list[dict[str, Any]] = []
    for rule in policy["pareto_rules"]:
        matches: list[tuple[float, dict[str, Any]]] = []
        for record in frontier:
            rows = [
                row for row in record["objectives"] if row["name"] == rule["objective"]
            ]
            if len(rows) != 1 or rows[0]["direction"] != rule["direction"]:
                raise OpportunityMiningError(
                    f"Pareto objective is missing or inconsistent: {rule['objective']}"
                )
            matches.append((float(rows[0]["value"]), record))
        best_value, best_record = (
            max(matches, key=lambda item: (item[0], item[1]["comparison_id"]))
            if rule["direction"] == "higher"
            else min(matches, key=lambda item: (item[0], item[1]["comparison_id"]))
        )
        gap = (
            float(rule["goal"]) - best_value
            if rule["direction"] == "higher"
            else best_value - float(rule["goal"])
        )
        if gap < float(rule["minimum_gap"]):
            continue
        evidence = {
            "kind": "pareto_gap",
            "objective": rule["objective"],
            "direction": rule["direction"],
            "goal": rule["goal"],
            "frontier_value": best_value,
            "gap": gap,
            "comparison_id": best_record["comparison_id"],
            "record_id": best_record["record_id"],
        }
        signal = _signal(
            source_kind="kpi_cluster",
            projection_id=None,
            pareto_head=records[-1]["record_id"],
            policy_id=policy["policy_id"],
            rule=rule,
            evidence=evidence,
            summary=(
                f"The replayed Pareto frontier leaves a {gap:g} gap to the "
                f"{rule['objective']} goal {float(rule['goal']):g}."
            ),
            magnitude=gap / float(rule["full_scale_gap"]),
        )
        result.append(
            _candidate(
                rule_id=rule["rule_id"],
                derivation_kind="pareto_gap",
                signal=signal,
                evidence=evidence,
            )
        )
    return result


def verify_candidate_set(repository_root: Path, candidate_set: dict[str, Any]) -> None:
    try:
        _registry(repository_root).validate(CANDIDATES_SCHEMA, candidate_set)
    except ValueError as error:
        raise OpportunityMiningError(
            "opportunity candidate set is malformed"
        ) from error
    _verify_identity(candidate_set, "candidate_set_id")
    identifiers: list[str] = []
    signals: list[str] = []
    for candidate in candidate_set["candidates"]:
        _verify_identity(candidate, "candidate_id")
        validate_signal(candidate["signal"])
        if candidate["derivation_kind"] != candidate["evidence"]["kind"]:
            raise OpportunityMiningError("candidate derivation does not match evidence")
        identifiers.append(candidate["candidate_id"])
        signals.append(candidate["signal"]["signal_id"])
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise OpportunityMiningError("candidate IDs are not sorted and unique")
    if len(signals) != len(set(signals)):
        raise OpportunityMiningError("candidate signals are not unique")


def mine(
    *,
    repository_root: Path,
    ledger_root: Path,
    facts_path: Path,
    policy_path: Path,
    pareto_root: Path | None,
) -> dict[str, Any]:
    """Derive a content-addressed, non-authoritative review candidate set."""

    repository_root = _absolute(repository_root, "repository", directory=True)
    ledger_root = _absolute(ledger_root, "ledger root", directory=True)
    facts_path = _absolute(facts_path, "dashboard facts")
    policy_path = _absolute(policy_path, "opportunity policy")
    policy = load_policy(repository_root, policy_path)
    projection = project(
        repository_root=repository_root,
        ledger_root=ledger_root,
        facts_path=facts_path,
    )
    records: list[dict[str, Any]] = []
    if policy["pareto_rules"]:
        if pareto_root is None:
            raise OpportunityMiningError("Pareto rules require a Pareto archive root")
        pareto_root = _absolute(pareto_root, "Pareto archive root", directory=True)
        records = ParetoArchive(
            pareto_root,
            repository_root,
            repository_root / "schemas" / "refinement",
        ).replay()
    pareto_head = records[-1]["record_id"] if records else None
    candidates = (
        _mine_kpis(projection, policy, None)
        + _mine_failures(projection, policy, None)
        + _mine_pareto(projection, policy, records)
    )
    candidates.sort(key=lambda item: item["candidate_id"])
    body = {
        "schema_version": "cigar.refinement-opportunity-candidates.v1",
        "policy_id": policy["policy_id"],
        "producer_id": policy["producer_id"],
        "projection_id": projection["projection_id"],
        "pareto_head": pareto_head,
        "candidates": candidates,
    }
    result = {**body, "candidate_set_id": identity(body)}
    verify_candidate_set(repository_root, result)
    return result


def _review_body(
    candidate_set: dict[str, Any],
    *,
    reviewer_id: str,
    accepted: set[str],
    rejected: dict[str, str],
) -> dict[str, Any]:
    available = {candidate["candidate_id"] for candidate in candidate_set["candidates"]}
    if reviewer_id == candidate_set["producer_id"]:
        raise OpportunityMiningError("opportunity reviewer must be independent")
    if accepted & set(rejected):
        raise OpportunityMiningError("a candidate has conflicting review decisions")
    if accepted | set(rejected) != available:
        raise OpportunityMiningError("review must disposition every exact candidate")
    dispositions = []
    for candidate_id in sorted(available):
        if candidate_id in accepted:
            dispositions.append(
                {"candidate_id": candidate_id, "decision": "accept", "reason": None}
            )
        else:
            raw_reason = rejected[candidate_id]
            if not isinstance(raw_reason, str) or not raw_reason.strip():
                raise OpportunityMiningError("rejection reason must not be empty")
            dispositions.append(
                {
                    "candidate_id": candidate_id,
                    "decision": "reject",
                    "reason": raw_reason.strip(),
                }
            )
    return {
        "schema_version": "cigar.refinement-opportunity-review.v1",
        "candidate_set_id": candidate_set["candidate_set_id"],
        "producer_id": candidate_set["producer_id"],
        "reviewer_id": reviewer_id,
        "dispositions": dispositions,
    }


def attest_review(
    *,
    repository_root: Path,
    candidate_set: dict[str, Any],
    reviewer_id: str,
    accepted: set[str],
    rejected: dict[str, str],
    key_id: str,
    key: bytes,
) -> dict[str, Any]:
    verify_candidate_set(repository_root, candidate_set)
    if len(key) < 32:
        raise OpportunityMiningError("review attestation key is shorter than 32 bytes")
    body = _review_body(
        candidate_set,
        reviewer_id=reviewer_id,
        accepted=accepted,
        rejected=rejected,
    )
    review_id = identity(body)
    signed = {**body, "review_id": review_id}
    result = {
        **signed,
        "attestation": {
            "algorithm": "hmac-sha256",
            "key_id": key_id,
            "key_fingerprint": multihash_bytes(key),
            "mac": hmac.new(key, canonical_bytes(signed), hashlib.sha256).hexdigest(),
        },
    }
    try:
        _registry(repository_root).validate(REVIEW_SCHEMA, result)
    except ValueError as error:
        raise OpportunityMiningError("opportunity review is malformed") from error
    return result


def verify_review(
    *,
    repository_root: Path,
    candidate_set: dict[str, Any],
    review: dict[str, Any],
    key: bytes,
) -> None:
    verify_candidate_set(repository_root, candidate_set)
    try:
        _registry(repository_root).validate(REVIEW_SCHEMA, review)
    except ValueError as error:
        raise OpportunityMiningError("opportunity review is malformed") from error
    unsigned = dict(review)
    attestation = unsigned.pop("attestation")
    review_id = unsigned.pop("review_id")
    if (
        review_id != identity(unsigned)
        or review["candidate_set_id"] != candidate_set["candidate_set_id"]
        or review["producer_id"] != candidate_set["producer_id"]
        or review["reviewer_id"] == candidate_set["producer_id"]
    ):
        raise OpportunityMiningError("opportunity review identity is invalid")
    expected_body = _review_body(
        candidate_set,
        reviewer_id=review["reviewer_id"],
        accepted={
            row["candidate_id"]
            for row in review["dispositions"]
            if row["decision"] == "accept"
        },
        rejected={
            row["candidate_id"]: row["reason"]
            for row in review["dispositions"]
            if row["decision"] == "reject"
        },
    )
    if expected_body != unsigned:
        raise OpportunityMiningError("opportunity review dispositions are invalid")
    if (
        len(key) < 32
        or attestation["key_fingerprint"] != multihash_bytes(key)
        or not hmac.compare_digest(
            attestation["mac"],
            hmac.new(
                key,
                canonical_bytes({**unsigned, "review_id": review_id}),
                hashlib.sha256,
            ).hexdigest(),
        )
    ):
        raise OpportunityMiningError("opportunity review attestation is invalid")


def publish(
    *,
    repository_root: Path,
    candidate_set: dict[str, Any],
    review: dict[str, Any],
    key: bytes,
) -> dict[str, Any]:
    """Publish only the exact signals accepted by a verified independent review."""

    verify_review(
        repository_root=repository_root,
        candidate_set=candidate_set,
        review=review,
        key=key,
    )
    accepted = {
        row["candidate_id"]
        for row in review["dispositions"]
        if row["decision"] == "accept"
    }
    signals = [
        candidate["signal"]
        for candidate in candidate_set["candidates"]
        if candidate["candidate_id"] in accepted
    ]
    signals.sort(key=lambda item: item["signal_id"])
    if not signals:
        raise OpportunityMiningError("review accepted no schedulable opportunity")
    body = {
        "schema_version": "cigar.refinement-opportunities.v1",
        "signals": signals,
    }
    result = {**body, "registry_id": identity(body)}
    try:
        _registry(repository_root).validate("opportunities-v1.schema.json", result)
    except ValueError as error:
        raise OpportunityMiningError(
            "reviewed opportunity registry is malformed"
        ) from error
    return result


def _create_new(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.parent.is_dir():
        raise OpportunityMiningError("output must be an absolute create-new path")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o400)
        payload += b"\n"
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OpportunityMiningError("output write was incomplete")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
        ):
            raise OpportunityMiningError("output metadata is unsafe")
    except OSError as error:
        raise OpportunityMiningError("output cannot be published create-new") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = load_file(_absolute(path, label))
    except (OSError, ValueError) as error:
        raise OpportunityMiningError(f"{label} is malformed") from error
    if not isinstance(value, dict):
        raise OpportunityMiningError(f"{label} is not an object")
    return value


def _parse_rejections(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        candidate_id, separator, reason = value.partition("=")
        if not separator or not candidate_id or candidate_id in result:
            raise OpportunityMiningError(
                "rejection must use one unique candidate_id=reason"
            )
        result[candidate_id] = reason
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    mine_parser = commands.add_parser("mine")
    mine_parser.add_argument("--repository", type=Path, default=ROOT)
    mine_parser.add_argument("--ledger-root", type=Path, required=True)
    mine_parser.add_argument("--facts", type=Path, required=True)
    mine_parser.add_argument("--policy", type=Path, required=True)
    mine_parser.add_argument("--pareto-root", type=Path)
    mine_parser.add_argument("--output", type=Path)

    review_parser = commands.add_parser("review")
    review_parser.add_argument("--repository", type=Path, default=ROOT)
    review_parser.add_argument("--candidates", type=Path, required=True)
    review_parser.add_argument("--reviewer-id", required=True)
    review_parser.add_argument("--key-id", required=True)
    review_parser.add_argument("--attestation-key", type=Path, required=True)
    review_parser.add_argument("--accept-all", action="store_true")
    review_parser.add_argument("--accept", action="append", default=[])
    review_parser.add_argument("--reject", action="append", default=[])
    review_parser.add_argument("--output", type=Path)

    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--repository", type=Path, default=ROOT)
    publish_parser.add_argument("--candidates", type=Path, required=True)
    publish_parser.add_argument("--review", type=Path, required=True)
    publish_parser.add_argument("--attestation-key", type=Path, required=True)
    publish_parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository = _absolute(arguments.repository, "repository", directory=True)
        if arguments.command == "mine":
            result = mine(
                repository_root=repository,
                ledger_root=arguments.ledger_root,
                facts_path=arguments.facts,
                policy_path=arguments.policy,
                pareto_root=arguments.pareto_root,
            )
        else:
            candidate_set = _load_object(arguments.candidates, "candidate set")
            key = secure_read(
                _absolute(arguments.attestation_key, "attestation key"),
                maximum_bytes=1024,
            )
            if arguments.command == "review":
                if arguments.accept_all and (arguments.accept or arguments.reject):
                    raise OpportunityMiningError(
                        "--accept-all cannot be combined with dispositions"
                    )
                available = {
                    row["candidate_id"] for row in candidate_set.get("candidates", [])
                }
                accepted = available if arguments.accept_all else set(arguments.accept)
                if len(accepted) != len(arguments.accept) and not arguments.accept_all:
                    raise OpportunityMiningError("accepted candidate ID is duplicated")
                result = attest_review(
                    repository_root=repository,
                    candidate_set=candidate_set,
                    reviewer_id=arguments.reviewer_id,
                    accepted=accepted,
                    rejected=_parse_rejections(arguments.reject),
                    key_id=arguments.key_id,
                    key=key,
                )
            else:
                result = publish(
                    repository_root=repository,
                    candidate_set=candidate_set,
                    review=_load_object(arguments.review, "opportunity review"),
                    key=key,
                )
        payload = canonical_bytes(result)
        if arguments.output is not None:
            _create_new(arguments.output, payload)
        sys.stdout.buffer.write(payload + b"\n")
        return 0
    except (
        DashboardError,
        ExperimentError,
        OpportunityMiningError,
        PromotionError,
        OSError,
        ValueError,
    ) as error:
        print(f"opportunity miner: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
