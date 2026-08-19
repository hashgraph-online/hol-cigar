#!/usr/bin/env python3
"""Validate, schedule, and verify deterministic actual-workflow qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Never

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).with_name("workflows.v1.json")
WORKFLOW_IDS = (
    "solo",
    "consensus-node",
    "blocknode-tss",
    "json-rpc",
    "evm-tx-liveness",
)
MODES = ("embedded", "local_sidecar")
NEGATIVE_CASES = (
    "retrieved_prompt_injection",
    "forged_citation",
    "stale_bundle",
    "revoked_source",
    "cross_project_alias",
    "poisoned_tool_output",
    "replay_substitution",
    "provider_timeout",
    "ambiguous_effect_result",
)
MUTATION_AXES = (
    "evidence_source",
    "requirement",
    "authorization_rule",
    "tool_result",
    "source_generation",
)
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_DRIVER_OUTPUT_BYTES = 8 * 1024 * 1024


class WorkflowQualificationError(RuntimeError):
    """A stable, content-free workflow qualification rejection."""


def fail(message: str) -> Never:
    raise WorkflowQualificationError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("workflow JSON contains duplicate keys")
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        status = path.lstat()
    except OSError as error:
        raise WorkflowQualificationError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_size <= 0
        or status.st_size > maximum
    ):
        fail(f"{label} is not one bounded regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise WorkflowQualificationError(f"{label} is unreadable") from error


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields do not match the registered contract")
    return value


def identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not value[0].isalnum()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in value
        )
    ):
        fail(f"{label} is invalid")
    return value


def identifier_list(value: Any, label: str, minimum: int, maximum: int) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        fail(f"{label} has invalid cardinality")
    output = [identifier(item, label) for item in value]
    if len(set(output)) != len(output):
        fail(f"{label} contains duplicates")
    return output


def validate_fixtures(value: Any) -> dict[str, Any]:
    value = exact_keys(
        value,
        {
            "schema_version",
            "fixture_set_id",
            "provider",
            "execution",
            "negative_cases",
            "mutation_axes",
            "workflows",
        },
        "fixture set",
    )
    if (
        value["schema_version"] != "cigar.workflow-efficacy.workflows.v1"
        or value["fixture_set_id"] != "hiero-deterministic-actual-workflows-v1"
    ):
        fail("workflow fixture authority is unsupported")
    provider = exact_keys(
        value["provider"],
        {
            "mode",
            "configuration_id",
            "tape_digest",
            "model_id",
            "temperature_millionths",
            "maximum_output_tokens",
        },
        "provider",
    )
    if provider["mode"] != "recorded" or provider["temperature_millionths"] != 0:
        fail(
            "deterministic qualification requires a zero-temperature recorded provider"
        )
    identifier(provider["configuration_id"], "provider configuration")
    identifier(provider["model_id"], "provider model")
    if (
        not isinstance(provider["tape_digest"], str)
        or len(provider["tape_digest"]) != 68
        or not provider["tape_digest"].startswith("1220")
        or any(
            character not in "0123456789abcdef" for character in provider["tape_digest"]
        )
    ):
        fail("provider tape digest is invalid")
    if (
        not isinstance(provider["maximum_output_tokens"], int)
        or not 1 <= provider["maximum_output_tokens"] <= 8192
    ):
        fail("provider output bound is invalid")

    execution = exact_keys(
        value["execution"],
        {
            "modes",
            "mode_rule",
            "no_egress",
            "context_cycles",
            "minimum_deltas",
            "maximum_turns",
            "maximum_cigar_tokens",
            "maximum_provider_tokens",
            "maximum_wall_time_ms",
        },
        "execution",
    )
    if (
        tuple(execution["modes"]) != MODES
        or execution["mode_rule"] != "trial_mod_2"
        or execution["no_egress"] is not True
        or execution["context_cycles"] != 3
        or execution["minimum_deltas"] != 2
        or execution["maximum_turns"] < 3
    ):
        fail("workflow execution contract is unsafe or incomplete")
    for field in (
        "maximum_cigar_tokens",
        "maximum_provider_tokens",
        "maximum_wall_time_ms",
    ):
        if (
            not isinstance(execution[field], int)
            or not 0 < execution[field] <= 1_000_000
        ):
            fail("workflow execution bound is invalid")
    if tuple(value["negative_cases"]) != NEGATIVE_CASES:
        fail("negative-case matrix drifted")
    if tuple(value["mutation_axes"]) != MUTATION_AXES:
        fail("mutation-axis matrix drifted")
    workflows = value["workflows"]
    if not isinstance(workflows, list) or len(workflows) != len(WORKFLOW_IDS):
        fail("fixture set must contain exactly five workflows")
    if (
        tuple(item.get("id") for item in workflows if isinstance(item, dict))
        != WORKFLOW_IDS
    ):
        fail("workflow identities are duplicated, missing, or reordered")
    for workflow in workflows:
        validate_workflow(workflow)
    return value


def validate_workflow(value: Any) -> None:
    value = exact_keys(
        value,
        {
            "id",
            "governed_source",
            "task_id",
            "requirements",
            "alternative_evidence_sets",
            "tools",
            "terminal",
            "citation_oracle",
            "policy_denials",
            "restart_points",
        },
        "workflow",
    )
    identifier(value["task_id"], "task identity")
    source = exact_keys(
        value["governed_source"],
        {"relative_path", "sha256", "generation"},
        "governed source",
    )
    path = source["relative_path"]
    if (
        not isinstance(path, str)
        or Path(path).is_absolute()
        or ".." in PurePosixPath(path).parts
        or len(path) > 256
    ):
        fail("governed source path is unsafe")
    if (
        not isinstance(source["sha256"], str)
        or len(source["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in source["sha256"])
        or not isinstance(source["generation"], int)
        or source["generation"] < 1
    ):
        fail("governed source binding is invalid")
    requirements = value["requirements"]
    if not isinstance(requirements, list) or not 2 <= len(requirements) <= 16:
        fail("workflow requirements are unbounded")
    classes: list[str] = []
    evidence: set[str] = set()
    for requirement in requirements:
        requirement = exact_keys(
            requirement, {"id", "class", "evidence"}, "requirement"
        )
        identifier(requirement["id"], "requirement identity")
        if requirement["class"] not in {"blocking", "effect_adjacent"}:
            fail("requirement class is invalid")
        classes.append(requirement["class"])
        evidence.update(
            identifier_list(requirement["evidence"], "requirement evidence", 2, 8)
        )
    if set(classes) != {"blocking", "effect_adjacent"}:
        fail("workflow omits a blocking or effect-adjacent requirement")
    alternatives = value["alternative_evidence_sets"]
    if not isinstance(alternatives, list) or not 2 <= len(alternatives) <= 8:
        fail("alternative evidence sets are invalid")
    for alternative in alternatives:
        identifier_list(alternative, "alternative evidence", 2, 8)
    tools = value["tools"]
    if not isinstance(tools, list) or not 2 <= len(tools) <= 16:
        fail("tool contract is invalid")
    effect_classes: set[bool] = set()
    for tool in tools:
        tool = exact_keys(tool, {"id", "effect", "argument_schema"}, "tool")
        identifier(tool["id"], "tool identity")
        identifier(tool["argument_schema"], "tool argument schema")
        if not isinstance(tool["effect"], bool):
            fail("tool effect class is invalid")
        effect_classes.add(tool["effect"])
    if effect_classes != {False, True}:
        fail("workflow must contain both a read tool and an effect")
    terminal = exact_keys(
        value["terminal"], {"outcome", "assertions"}, "terminal outcome"
    )
    identifier(terminal["outcome"], "terminal outcome")
    if terminal["assertions"] != [
        "all_blocking_covered",
        "citation_resolved",
        "effect_exactly_once",
    ]:
        fail("terminal assertions drifted")
    oracle = set(identifier_list(value["citation_oracle"], "citation oracle", 2, 16))
    if not oracle.issubset(evidence):
        fail("citation oracle is not backed by critical evidence")
    identifier_list(value["policy_denials"], "policy denials", 2, 16)
    identifier_list(value["restart_points"], "restart points", 3, 16)


def load_fixtures(path: Path = FIXTURES) -> tuple[dict[str, Any], str]:
    payload = regular_file(path, MAX_FIXTURE_BYTES, "workflow fixture")
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkflowQualificationError(
            "workflow fixture is not strict JSON"
        ) from error
    return validate_fixtures(value), sha256_bytes(canonical(value))


def verify_governed_sources(
    fixture: dict[str, Any], hiero_root: Path
) -> dict[str, str]:
    root = hiero_root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        fail("Hiero root is unavailable")
    digests: dict[str, str] = {}
    for workflow in fixture["workflows"]:
        source = workflow["governed_source"]
        candidate = root / source["relative_path"]
        payload = regular_file(candidate, 16 * 1024 * 1024, "governed Hiero source")
        observed = sha256_bytes(payload)
        if observed != source["sha256"]:
            fail("governed Hiero source digest drifted")
        digests[workflow["id"]] = observed
    return digests


@dataclass(frozen=True)
class ScheduledTrial:
    workflow: str
    trial: int
    mode: str
    restart_point: str
    mutation_axis: str


def schedule(fixture: dict[str, Any], trials: int) -> list[ScheduledTrial]:
    if not 1 <= trials <= 10_000:
        fail("trial count is outside the qualification bound")
    output: list[ScheduledTrial] = []
    for workflow in fixture["workflows"]:
        restart_points = workflow["restart_points"]
        for trial in range(trials):
            output.append(
                ScheduledTrial(
                    workflow=workflow["id"],
                    trial=trial,
                    mode=MODES[trial % len(MODES)],
                    restart_point=restart_points[trial % len(restart_points)],
                    mutation_axis=MUTATION_AXES[trial % len(MUTATION_AXES)],
                )
            )
    return output


def verify_observation(value: Any, fixture: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "workflow",
        "trial",
        "mode",
        "restart_point",
        "mutation_axis",
        "terminal_outcome",
        "turn_count",
        "context_cycles",
        "delta_count",
        "materialization_count",
        "revalidation_count",
        "effect_count",
        "checkpoint_count",
        "critical_evidence_coverage",
        "citation_resolvability_rate",
        "bundle_roots_verified",
        "replay_verified",
        "negative_cases_passed",
        "cigar_supplied_tokens",
        "provider_input_tokens",
        "provider_output_tokens",
        "cigar_latency_ns",
        "provider_latency_ns",
        "fail_closed",
    }
    value = exact_keys(value, expected, "workflow observation")
    workflow = next(
        (item for item in fixture["workflows"] if item["id"] == value["workflow"]), None
    )
    if workflow is None or not isinstance(value["trial"], int) or value["trial"] < 0:
        fail("workflow observation identity is invalid")
    scheduled = next(
        item
        for item in schedule(fixture, value["trial"] + 1)
        if item.workflow == value["workflow"] and item.trial == value["trial"]
    )
    if (
        value["mode"] != scheduled.mode
        or value["restart_point"] != scheduled.restart_point
        or value["mutation_axis"] != scheduled.mutation_axis
        or value["terminal_outcome"] != workflow["terminal"]["outcome"]
    ):
        fail("workflow observation schedule or outcome drifted")
    execution = fixture["execution"]
    exact_counts = {
        "turn_count": execution["maximum_turns"],
        "context_cycles": execution["context_cycles"],
        "delta_count": execution["minimum_deltas"],
        "materialization_count": execution["context_cycles"],
        "revalidation_count": 1,
        "effect_count": 1,
        "checkpoint_count": execution["context_cycles"],
        "negative_cases_passed": len(NEGATIVE_CASES),
    }
    if any(value[field] != count for field, count in exact_counts.items()):
        fail("workflow observation count invariant failed")
    if (
        value["critical_evidence_coverage"] != 1.0
        or value["citation_resolvability_rate"] != 1.0
        or value["bundle_roots_verified"] is not True
        or value["replay_verified"] is not True
        or value["fail_closed"] is not True
    ):
        fail("workflow observation correctness invariant failed")
    for field in (
        "cigar_supplied_tokens",
        "provider_input_tokens",
        "provider_output_tokens",
        "cigar_latency_ns",
        "provider_latency_ns",
    ):
        if not isinstance(value[field], int) or value[field] < 0:
            fail("workflow observation accounting is invalid")
    if value["cigar_supplied_tokens"] > execution["maximum_cigar_tokens"]:
        fail("workflow exceeded the CIGAR token bound")
    if (
        value["provider_input_tokens"] + value["provider_output_tokens"]
        > execution["maximum_provider_tokens"]
    ):
        fail("workflow exceeded the provider token bound")
    return value


def command_validate(arguments: argparse.Namespace) -> dict[str, Any]:
    fixture, digest = load_fixtures(arguments.fixtures)
    result: dict[str, Any] = {
        "fixture_sha256": digest,
        "workflow_count": len(fixture["workflows"]),
    }
    if arguments.hiero_root is not None:
        result["governed_sources"] = verify_governed_sources(
            fixture, arguments.hiero_root
        )
    return result


def command_schedule(arguments: argparse.Namespace) -> dict[str, Any]:
    fixture, digest = load_fixtures(arguments.fixtures)
    scheduled = schedule(fixture, arguments.trials)
    return {
        "schema_version": "cigar.workflow-efficacy.schedule.v1",
        "fixture_sha256": digest,
        "trial_count": len(scheduled),
        "trials": [item.__dict__ for item in scheduled],
    }


def command_verify_observation(arguments: argparse.Namespace) -> dict[str, Any]:
    fixture, digest = load_fixtures(arguments.fixtures)
    payload = regular_file(
        arguments.observation, MAX_DRIVER_OUTPUT_BYTES, "driver observation"
    )
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkflowQualificationError(
            "driver observation is not strict JSON"
        ) from error
    verified = verify_observation(value, fixture)
    return {
        "fixture_sha256": digest,
        "observation_sha256": sha256_bytes(canonical(verified)),
        "status": "pass",
    }


def parser() -> argparse.ArgumentParser:
    output = argparse.ArgumentParser(description=__doc__)
    commands = output.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--fixtures", type=Path, default=FIXTURES)
    validate.add_argument("--hiero-root", type=Path)
    validate.set_defaults(handler=command_validate)
    schedule_parser = commands.add_parser("schedule")
    schedule_parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    schedule_parser.add_argument("--trials", type=int, required=True)
    schedule_parser.set_defaults(handler=command_schedule)
    observation = commands.add_parser("verify-observation")
    observation.add_argument("--fixtures", type=Path, default=FIXTURES)
    observation.add_argument("--observation", type=Path, required=True)
    observation.set_defaults(handler=command_verify_observation)
    return output


def main() -> int:
    arguments = parser().parse_args()
    try:
        result = arguments.handler(arguments)
    except (WorkflowQualificationError, OSError, ValueError) as error:
        print(f"workflow qualification rejected: {error}", file=sys.stderr)
        return 1
    os.write(sys.stdout.fileno(), canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
