"""Execute and evaluate exact-source Honey/champion/candidate CIGARBench cases."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from .canonical import (
    canonical_bytes,
    identity,
    load_file,
    multihash_bytes,
)
from .consumer import ConsumerError, run_three_way
from .corpus import _write_canonical
from .intelligence import (
    DEFAULT_TOKEN_BUDGET,
    PROFILE_V1,
    IntelligenceError,
    _attestation_key,
    _evaluate_observation,
    _external_output,
    _failed_evaluation,
    _git_source,
    _load_records,
    _mean_integer,
    _mean_ppm,
    _qualification_token_budget,
    _real_file,
    _seal,
    _selected_tasks,
)
from .schema import SchemaRegistry
from .statistics import StatisticsError, compare, load_policy

TREATMENTS = ("honey", "champion", "candidate")
BUILD_SCHEMA = "source-consumer-build-set-v1.schema.json"
PLAN_SCHEMA = "honey-evaluation-plan-v1.schema.json"
QUALIFICATION_SCHEMA = "honey-three-way-qualification-v1.schema.json"
ATTACHMENT_SCHEMA = "honey-three-way-execution-attachment-v1.schema.json"
MAX_BUILD_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_PLAN_BYTES = 4 * 1024 * 1024


class ThreeWayError(RuntimeError):
    """Three-way build custody, execution, or evaluation failed closed."""


def _identified(value: dict[str, Any], identity_field: str) -> bool:
    body = dict(value)
    claimed = body.pop(identity_field)
    return identity(body) == claimed


def _canonical_record(
    path: Path, label: str, maximum_bytes: int
) -> tuple[dict[str, Any], bytes]:
    payload = _real_file(path, label, maximum_bytes)
    value = load_file(path, maximum_bytes=maximum_bytes)
    if canonical_bytes(value) != payload or not isinstance(value, dict):
        raise ThreeWayError(f"{label} is not one canonical object")
    return value, payload


def _load_build_custody(
    *,
    repository_root: Path,
    plan_path: Path,
    build_root: Path,
    registry: SchemaRegistry,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Path]]:
    if not build_root.is_absolute() or build_root.is_symlink():
        raise ThreeWayError("build root must be an absolute non-symlink directory")
    build_root = build_root.resolve(strict=True)
    plan, _plan_bytes = _canonical_record(plan_path, "evaluation plan", MAX_PLAN_BYTES)
    receipt_path = (build_root / "build-set.v1.json").resolve(strict=True)
    if receipt_path.parent != build_root:
        raise ThreeWayError("build receipt escaped its custody root")
    receipt, _receipt_bytes = _canonical_record(
        receipt_path, "source build receipt", MAX_BUILD_RECEIPT_BYTES
    )
    registry.validate(PLAN_SCHEMA, plan)
    registry.validate(BUILD_SCHEMA, receipt)
    if not _identified(plan, "plan_id") or not _identified(receipt, "build_set_id"):
        raise ThreeWayError("plan or build receipt identity is invalid")
    if (
        receipt["plan_id"] != plan["plan_id"]
        or receipt["harness_source"] != plan["harness_source"]
        or receipt["build_profile"] != "release"
    ):
        raise ThreeWayError("build receipt does not bind the evaluation plan")
    plan_sources = {
        "honey": plan["product_sources"]["published_honey"],
        "champion": plan["product_sources"]["champion"],
        "candidate": plan["product_sources"]["candidate"],
    }
    role_to_treatment = {
        "published-honey": "honey",
        "champion": "champion",
        "candidate": "candidate",
    }
    rows = {role_to_treatment[row["source_role"]]: row for row in receipt["builds"]}
    if tuple(rows) != TREATMENTS:
        raise ThreeWayError("build receipt treatment inventory is invalid")
    executables: dict[str, Path] = {}
    for treatment in TREATMENTS:
        row = rows[treatment]
        if row["product_source"] != plan_sources[treatment]:
            raise ThreeWayError("build receipt source identity drifted")
        relative = Path(row["executable_path"])
        unresolved_executable = build_root / relative
        executable = unresolved_executable.resolve(strict=True)
        if (
            relative.is_absolute()
            or unresolved_executable.is_symlink()
            or not executable.is_relative_to(build_root)
        ):
            raise ThreeWayError("consumer executable escaped build custody")
        payload = _real_file(executable, f"{treatment} consumer", 1024 * 1024 * 1024)
        if (
            len(payload) != row["executable_bytes"]
            or hashlib.sha256(payload).hexdigest() != row["executable_sha256"]
            or multihash_bytes(payload) != row["executable_digest"]
        ):
            raise ThreeWayError(
                "consumer executable bytes drifted from the build receipt"
            )
        executables[treatment] = executable
    return plan, receipt, executables


def _three_way_case(
    *,
    schemas: Path,
    sources: dict[str, dict[str, str]],
    executables: dict[str, Path],
    expected_consumer_digests: dict[str, str],
    manifest_id: str,
    task: dict[str, Any],
    prompt: dict[str, Any],
    oracle: dict[str, Any],
    fixture: dict[str, Any],
    seed_index: int,
    token_budget: int,
    scratch: Path,
    registry: SchemaRegistry,
    key: bytes,
    key_id: str,
    key_fingerprint: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    pair_id = (
        "three-"
        + hashlib.sha256(
            canonical_bytes({"task_id": task["task_id"], "seed_index": seed_index})
        ).hexdigest()[:24]
    )
    with tempfile.TemporaryDirectory(dir=scratch, prefix=f"{pair_id}-") as raw:
        root = Path(raw).resolve(strict=True)
        archive_path = root / "archive.json"
        _write_canonical(archive_path, fixture["archive"])
        prohibited_paths = {
            item["path"]
            for item in fixture["evidence_index"]
            if item["class"] == "prohibited"
        }
        prohibited_paths.update(
            item["path"]
            for item in fixture["archive"]["files"]
            if item["path"].startswith("legacy/")
        )
        common = {
            "schema_version": "cigar.benchmark-assignment.v2",
            "run_id": f"run-{pair_id}",
            "pair_id": pair_id,
            "task_id": task["task_id"],
            "consumer_mode": "production",
            "archive_path": str(archive_path),
            "archive_digest": task["source"]["archive_digest"],
            "query": prompt["text"],
            "job_goal": "Compile authorized evidence for the corpus task.",
            "semantic_type": "documentation",
            "token_budget": token_budget,
            "output_reserve_tokens": task["contract"]["output_budget"],
            "max_context_tokens": task["contract"]["token_budget"]
            + task["contract"]["output_budget"],
            "excluded_prefixes": sorted(prohibited_paths),
            "flows": {"effect": False, "handoff": False, "replay": False},
            "model": "deterministic-recorded-v1",
            "prompt_digest": prompt["prompt_digest"],
            "intelligence_profile": PROFILE_V1,
        }
        assignments: dict[str, Path] = {}
        for treatment in TREATMENTS:
            assignment_path = root / f"{treatment}-assignment.json"
            _write_canonical(
                assignment_path,
                {
                    **common,
                    "treatment": treatment,
                    "source": sources[treatment],
                },
            )
            assignments[treatment] = assignment_path
        try:
            result = run_three_way(
                honey_assignment_path=assignments["honey"],
                champion_assignment_path=assignments["champion"],
                candidate_assignment_path=assignments["candidate"],
                honey_executable_path=executables["honey"],
                champion_executable_path=executables["champion"],
                candidate_executable_path=executables["candidate"],
                cwd=root,
                state=root / "consumer-state",
                schemas=schemas,
                timeout_seconds=task["execution"]["timeout_seconds"],
            )
        except ConsumerError as error:
            raise ThreeWayError(
                f"consumer run failed in stratum {task['stratum']}"
            ) from error
        if result["consumer_digests"] != expected_consumer_digests:
            raise ThreeWayError("consumer run is not bound to the build receipt")
        if fixture["canary"].encode("utf-8") in canonical_bytes(result):
            raise ThreeWayError("three-way run disclosed a corpus canary")
        observations = {
            observation["treatment"]: observation
            for observation in result["observations"]
        }
        if set(observations) != {
            treatment
            for treatment in TREATMENTS
            if result["outcomes"][treatment]["status"] == "completed"
        }:
            raise ThreeWayError("three-way observation/outcome inventory drifted")
        evaluations: dict[str, dict[str, Any]] = {}
        for treatment in TREATMENTS:
            outcome = result["outcomes"][treatment]
            if outcome["status"] == "completed":
                evaluations[treatment] = _evaluate_observation(
                    observation=observations[treatment],
                    task=task,
                    oracle=oracle,
                    fixture=fixture,
                    manifest_id=manifest_id,
                    seed_index=seed_index,
                    token_budget=token_budget,
                    root=root,
                    registry=registry,
                    key=key,
                    key_id=key_id,
                    key_fingerprint=key_fingerprint,
                    profile_id=PROFILE_V1,
                )
            else:
                evaluations[treatment] = _failed_evaluation(
                    treatment=treatment,
                    profile_id=PROFILE_V1,
                    source=sources[treatment],
                    assignment_digest=result["assignment_digests"][treatment],
                    consumer_digest=result["consumer_digests"][treatment],
                    failure=outcome["failure"],
                    task=task,
                    oracle=oracle,
                    manifest_id=manifest_id,
                    seed_index=seed_index,
                    registry=registry,
                    key=key,
                    key_id=key_id,
                    key_fingerprint=key_fingerprint,
                )
    return evaluations, result


def _checks(
    identifiers: Sequence[str], attachment_digest: str, *, passed: bool
) -> list[dict[str, Any]]:
    return [
        {
            "check_id": identifier,
            "passed": passed,
            "attachment_digest": attachment_digest,
        }
        for identifier in identifiers
    ]


def qualify(
    *,
    repository_root: Path,
    private_root: Path,
    manifest_path: Path,
    plan_path: Path,
    build_root: Path,
    evidence_dir: Path,
    key_path: Path,
    key_id: str,
    per_stratum: int,
    seeds: int,
    token_budget: int | None,
    bootstrap_repetitions: int,
    confidence_percent: int,
) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    private_root = private_root.resolve(strict=True)
    manifest_path = manifest_path.resolve(strict=True)
    schemas = repository_root / "schemas/refinement"
    registry = SchemaRegistry(schemas)
    if (
        per_stratum < 2
        or seeds < 2
        or seeds > 16
        or (token_budget is not None and token_budget <= 0)
        or bootstrap_repetitions < 100
        or confidence_percent != 95
    ):
        raise ThreeWayError("Cycle A development minimums cannot be weakened")
    source = _git_source(repository_root, require_clean=True)
    plan, receipt, executables = _load_build_custody(
        repository_root=repository_root,
        plan_path=plan_path,
        build_root=build_root,
        registry=registry,
    )
    if source != plan["harness_source"]:
        raise ThreeWayError("checked-out harness source differs from the plan")
    key, key_fingerprint = _attestation_key(key_path, repository_root)
    output = _external_output(evidence_dir, repository_root)
    for name in ("evaluations", "runs", "scratch"):
        (output / name).mkdir(mode=0o700)
    manifest, records = _load_records(
        repository_root=repository_root,
        private_root=private_root,
        manifest_path=manifest_path,
    )
    if manifest["partition"] != "development":
        raise ThreeWayError("Cycle A requires the frozen development partition")
    task_ids = _selected_tasks(records, per_stratum)
    qualification_token_budget = _qualification_token_budget(
        records, task_ids, token_budget
    )
    policy_path = (repository_root / "refinement/policy/promotion-v1.json").resolve(
        strict=True
    )
    policy, policy_digest = load_policy(policy_path, registry)
    honey_path = (
        repository_root / "refinement/baselines/honey-anchor.v1.json"
    ).resolve(strict=True)
    honey_bytes = _real_file(honey_path, "Honey anchor", 1024 * 1024)
    honey = load_file(honey_path)
    sources = {
        "honey": plan["product_sources"]["published_honey"],
        "champion": plan["product_sources"]["champion"],
        "candidate": plan["product_sources"]["candidate"],
    }
    consumer_digests = {
        {"published-honey": "honey"}.get(row["source_role"], row["source_role"]): row[
            "executable_digest"
        ]
        for row in receipt["builds"]
    }
    assignment_seed_digests = [
        identity(
            {
                "manifest_id": manifest["manifest_id"],
                "build_set_id": receipt["build_set_id"],
                "seed_index": seed_index,
            }
        )
        for seed_index in range(seeds)
    ]
    evaluations: list[dict[str, Any]] = []
    run_ids: list[str] = []
    pairs: list[dict[str, Any]] = []
    for task_id in task_ids:
        task = records["tasks"][task_id]
        for seed_index in range(seeds):
            case_evaluations, run = _three_way_case(
                schemas=schemas,
                sources=sources,
                executables=executables,
                expected_consumer_digests=consumer_digests,
                manifest_id=manifest["manifest_id"],
                task=task,
                prompt=records["prompts"][task_id],
                oracle=records["oracles"][task_id],
                fixture=records["fixtures"][task_id],
                seed_index=seed_index,
                token_budget=qualification_token_budget,
                scratch=output / "scratch",
                registry=registry,
                key=key,
                key_id=key_id,
                key_fingerprint=key_fingerprint,
            )
            _write_canonical(
                output / "runs" / f"{run['three_way_result_id']}.json", run
            )
            run_ids.append(run["three_way_result_id"])
            for treatment in TREATMENTS:
                evaluation = case_evaluations[treatment]
                _write_canonical(
                    output / "evaluations" / f"{evaluation['evaluation_id']}.json",
                    evaluation,
                )
                evaluations.append(evaluation)
            pairs.append(
                {
                    "pair_id": run["pair_id"],
                    "task_id": task["task_id"],
                    "task_lineage_id": task["task_lineage_id"],
                    "stratum": task["stratum"],
                    "seed_index": seed_index,
                    **{
                        treatment: {
                            "evaluation_digest": case_evaluations[treatment][
                                "evaluation_id"
                            ],
                            "metrics": case_evaluations[treatment]["metrics"],
                        }
                        for treatment in TREATMENTS
                    },
                }
            )
    pairs.sort(key=lambda item: item["pair_id"])
    evaluation_ids_digest = identity(
        sorted(evaluation["evaluation_id"] for evaluation in evaluations)
    )
    run_ids_digest = identity(sorted(run_ids))
    attachment_body = {
        "schema_version": "cigar.honey-three-way-execution-attachment.v1",
        "plan_id": plan["plan_id"],
        "build_set_id": receipt["build_set_id"],
        "manifest_id": manifest["manifest_id"],
        "key_fingerprint": key_fingerprint,
        "evaluation_ids_digest": evaluation_ids_digest,
        "run_ids_digest": run_ids_digest,
        "evaluations": len(evaluations),
        "runs": len(run_ids),
        "tier0_checks": policy["tier0_checks"],
        "status": "passed",
    }
    attachment = {
        **attachment_body,
        "attachment_id": identity(attachment_body),
    }
    registry.validate(ATTACHMENT_SCHEMA, attachment)
    _write_canonical(output / "tier0-attachment.json", attachment)
    attachment_digest = attachment["attachment_id"]
    comparison_body = {
        "schema_version": "cigar.comparison-input.v1",
        "trial_id": f"trial-honey-three-{source['revision'][:12]}",
        "evidence_class": "development",
        "champion_source": sources["champion"],
        "candidate_source": sources["candidate"],
        "honey_source": sources["honey"],
        "dataset_epoch": manifest["manifest_id"],
        "policy_digest": policy_digest,
        "bootstrap_repetitions": bootstrap_repetitions,
        "confidence_percent": confidence_percent,
        "assignment_seed_digests": assignment_seed_digests,
        "tier0_checks": _checks(policy["tier0_checks"], attachment_digest, passed=True),
        "tier1_checks": _checks(
            policy["tier1_external_checks"], attachment_digest, passed=False
        ),
        "pairs": pairs,
    }
    comparison_input = {
        **comparison_body,
        "input_id": identity(comparison_body),
    }
    registry.validate("comparison-input-v1.schema.json", comparison_input)
    comparison_input_bytes = canonical_bytes(comparison_input)
    comparison = compare(
        input_value=comparison_input,
        input_digest=multihash_bytes(comparison_input_bytes),
        policy=policy,
        policy_digest=policy_digest,
        honey_anchor=honey,
        honey_anchor_bytes=honey_bytes,
        registry=registry,
    )
    _write_canonical(output / "comparison-input.json", comparison_input)
    _write_canonical(output / "comparison.json", comparison)
    aggregate = [
        {
            "treatment": treatment,
            "critical_context_recall_ppm": _mean_ppm(
                evaluations, treatment, "critical_context_recall"
            ),
            "evidence_item_precision_ppm": _mean_ppm(
                evaluations, treatment, "evidence_item_precision"
            ),
            "evidence_token_precision_ppm": _mean_ppm(
                evaluations, treatment, "evidence_token_precision"
            ),
            "verified_task_success_ppm": _mean_ppm(
                evaluations, treatment, "verified_task_success"
            ),
            "mean_selected_tokens": _mean_integer(
                evaluations, treatment, "physical_input_tokens"
            ),
        }
        for treatment in TREATMENTS
    ]
    body = {
        "schema_version": "cigar.honey-three-way-qualification.v1",
        "trial_id": comparison_input["trial_id"],
        "evidence_class": "development",
        "partition": "development",
        "plan_id": plan["plan_id"],
        "build_set_id": receipt["build_set_id"],
        "manifest_id": manifest["manifest_id"],
        "tier0_attachment_id": attachment["attachment_id"],
        "sources": sources,
        "consumer_digests": consumer_digests,
        "intelligence_profile": PROFILE_V1,
        "token_budget": qualification_token_budget,
        "tasks": len(task_ids),
        "assignment_seeds": seeds,
        "evaluation_count": len(evaluations),
        "evaluation_ids_digest": evaluation_ids_digest,
        "run_ids_digest": run_ids_digest,
        "comparison_input_id": comparison_input["input_id"],
        "comparison_id": comparison["comparison_id"],
        "comparison_verdict": comparison["verdict"],
        "tier1_complete": False,
        "aggregate": aggregate,
    }
    qualification = _seal(
        body,
        identity_field="qualification_id",
        key=key,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
    )
    registry.validate(QUALIFICATION_SCHEMA, qualification)
    _write_canonical(output / "qualification.json", qualification)
    return qualification


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--attestation-key", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--per-stratum", required=True, type=int)
    parser.add_argument("--seeds", required=True, type=int)
    parser.add_argument(
        "--token-budget",
        type=int,
        default=DEFAULT_TOKEN_BUDGET,
        help=(
            "optional lower-budget stress override; official qualification inherits "
            "the frozen task contract"
        ),
    )
    parser.add_argument("--bootstrap-repetitions", required=True, type=int)
    parser.add_argument("--confidence-percent", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = qualify(
            repository_root=arguments.repository_root,
            private_root=arguments.private_root,
            manifest_path=arguments.manifest,
            plan_path=arguments.plan,
            build_root=arguments.build_root,
            evidence_dir=arguments.evidence_dir,
            key_path=arguments.attestation_key,
            key_id=arguments.key_id,
            per_stratum=arguments.per_stratum,
            seeds=arguments.seeds,
            token_budget=arguments.token_budget,
            bootstrap_repetitions=arguments.bootstrap_repetitions,
            confidence_percent=arguments.confidence_percent,
        )
    except (
        ConsumerError,
        IntelligenceError,
        OSError,
        StatisticsError,
        ThreeWayError,
        ValueError,
    ) as error:
        print(f"three-way qualification failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "comparison_id": result["comparison_id"],
                "qualification_id": result["qualification_id"],
                "status": result["comparison_verdict"],
                "tasks": result["tasks"],
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
