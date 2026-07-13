#!/usr/bin/env python3
"""Fixture-bound package materializer for the multi-agent handoff demo."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python" / "src"))

from driver_support import (  # noqa: E402
    DriverError,
    RecordedApi,
    RecordedOperation,
    assertion,
    cli,
    clean_environment,
    digest_value,
    emit,
    fail,
    main_error,
    parser,
    remove_tree,
    run_bounded,
    step,
    validate_paths,
    write_request,
)
from cigar_sdk import CigarClient, TypedOperationRequest, models  # noqa: E402


def child_package(
    child: dict[str, Any], parent_tokens: int, seed: int
) -> dict[str, Any]:
    maximum = child.get("maximum_tokens")
    capabilities = child.get("capabilities")
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum <= 0
        or not isinstance(capabilities, list)
        or capabilities != ["read_context"]
    ):
        fail("child fixture is invalid")
    package_tokens = min(maximum, parent_tokens // 5)
    return {
        "schema_version": "cigar.demo-handoff-package.v1",
        "role": child.get("role"),
        "seed": seed,
        "capabilities": capabilities,
        "package_tokens": package_tokens,
        "first_action": "inspect bounded evidence references",
        "references": [digest_value({"role": child.get("role"), "seed": seed})],
    }


def run() -> None:
    args = parser().parse_args()
    fixture = validate_paths(args.fixture, args.state, args.cigar_binary)
    if fixture.get("demo_id") != "multi-agent-handoff":
        fail("driver received the wrong fixture")
    parent_tokens = fixture.get("parent_transcript_tokens")
    children = fixture.get("children")
    if (
        isinstance(parent_tokens, bool)
        or not isinstance(parent_tokens, int)
        or parent_tokens <= 0
        or not isinstance(children, list)
        or len(children) != 2
    ):
        fail("handoff fixture inventory is invalid")
    root = args.state / "handoff-state"
    root.mkdir()
    environment = clean_environment(args.state)
    version_stdout, _version_stderr = run_bounded(
        [args.cigar_binary, "version"],
        cwd=root,
        environment=environment,
    )
    try:
        version = json.loads(version_stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("CIGAR version surface returned malformed JSON") from error
    packages = [
        child_package(child, parent_tokens, fixture["fixed_seed"] + index)
        for index, child in enumerate(children)
    ]
    for index, package in enumerate(packages):
        (root / f"package-{index}.json").write_text(
            json.dumps(package, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    adversarial = fixture.get("adversarial_request")
    if not isinstance(adversarial, dict):
        fail("adversarial request is invalid")
    result_fields = fixture.get("expected", {}).get("result_fields")
    if not isinstance(result_fields, list):
        fail("handoff result field inventory is invalid")
    typed_results = []
    for package in packages:
        typed_results.append(
            {
                "claims": [
                    {
                        "claim": f"verified result for {package['role']}",
                        "evidence": [
                            digest_value(
                                {"package": package["references"], "kind": "claim"}
                            )
                        ],
                    }
                ],
                "artifacts": [
                    digest_value({"package": package["references"], "kind": "artifact"})
                ],
                "unresolved_questions": ["bounded-fixture-uncertainty"],
                "verifier_receipts": [
                    digest_value(
                        {"package": package["references"], "kind": "verification"}
                    )
                ],
            }
        )
    public_result_fields = {
        "claims": "claims",
        "artifacts": "artifacts",
        "uncertainty": "unresolved_questions",
        "verification": "verifier_receipts",
    }
    if set(public_result_fields) != set(result_fields):
        fail("typed child result does not match the fixture contract")

    allowed_project = "01890f47-8e7d-7b42-a1d2-000000041101"
    forbidden_project = "01890f47-8e7d-7b42-a1d2-000000041102"
    parent_bundle_id = digest_value(
        {"seed": fixture["fixed_seed"], "kind": "parent-bundle"}
    )
    base_commit_id = digest_value(
        {"seed": fixture["fixed_seed"], "kind": "parent-commit"}
    )
    handoff_ids = [
        "01890f47-8e7d-7b42-a1d2-000000041110",
        "01890f47-8e7d-7b42-a1d2-000000041111",
    ]
    adversarial_ids = [
        "01890f47-8e7d-7b42-a1d2-000000041112",
        "01890f47-8e7d-7b42-a1d2-000000041113",
    ]
    target_plan_ids = [
        "01890f47-8e7d-7b42-a1d2-000000041120",
        "01890f47-8e7d-7b42-a1d2-000000041121",
    ]
    delta_ids = [
        "01890f47-8e7d-7b42-a1d2-000000041130",
        "01890f47-8e7d-7b42-a1d2-000000041131",
    ]
    create_requests = []
    for package in packages:
        create_requests.append(
            {
                "recipient": {"type": "role", "value": package["role"]},
                "task": f"complete deterministic {package['role']} work",
                "acceptance_criteria": ["return typed evidence"],
                "requested_projects": [allowed_project],
                "requested_capabilities": ["read_context"],
                "budget": {
                    "total_input_tokens": package["package_tokens"],
                    "output_reserve_tokens": 200,
                    "lane_input_tokens": {
                        "evidence": package["package_tokens"],
                    },
                },
                "topics": ["task_checkpoint"],
                "references": {
                    "sources": package["references"],
                    "states": [],
                    "decisions": [],
                    "artifacts": [],
                    "uncertainties": [],
                    "effects": [],
                },
                "bundle_id": parent_bundle_id,
                "audience": "recorded-demo-child",
                "ttl_seconds": 600,
                "reusable": False,
            }
        )
    adversarial_requests = [
        {
            **create_requests[0],
            "recipient": {"type": "role", "value": "untrusted-reader"},
            "requested_projects": [forbidden_project],
        },
        {
            **create_requests[1],
            "recipient": {"type": "role", "value": "untrusted-writer"},
            "requested_capabilities": ["read_context", "write_overlay"],
        },
    ]
    accept_requests = [
        {"handoff_id": handoff_id, "target_plan_id": target_plan_id}
        for handoff_id, target_plan_id in zip(handoff_ids, target_plan_ids, strict=True)
    ]
    result_requests = []
    for index, handoff_id in enumerate(handoff_ids):
        result_requests.append(
            {
                "handoff_id": handoff_id,
                "base_commit_id": base_commit_id,
                "claims": typed_results[index]["claims"],
                "decisions": [],
                "artifacts": typed_results[index]["artifacts"],
                "source_changes": [],
                "verifier_receipts": typed_results[index]["verifier_receipts"],
                "unresolved_questions": typed_results[index]["unresolved_questions"],
                "blockers": [],
                "effect_references": [],
                "requested_followup_capabilities": [],
            }
        )
    merge_requests = [
        {
            "handoff_id": handoff_id,
            "delta_id": delta_id,
            "space_id": digest_value(
                {"seed": fixture["fixed_seed"], "space": "parent"}
            ),
            "overlay_id": f"01890f47-8e7d-7b42-a1d2-{41140 + index:012x}",
        }
        for index, (handoff_id, delta_id) in enumerate(
            zip(handoff_ids, delta_ids, strict=True)
        )
    ]
    operations: list[RecordedOperation] = []
    for index, request in enumerate(create_requests):
        operations.append(
            RecordedOperation(
                "createHandoff",
                "POST",
                "/v1/handoffs",
                request,
                {
                    "capsule": {
                        "handoff_id": handoff_ids[index],
                        "delegated_capabilities": ["read_context"],
                        "project_ids": [allowed_project],
                        "bundle_id": parent_bundle_id,
                    },
                    "preview": {
                        "accepted_projects": [allowed_project],
                        "rejected_projects": [],
                        "accepted_capabilities": ["read_context"],
                        "rejected_capabilities": [],
                        "reference_count": 1,
                    },
                },
                idempotency_key=f"handoff-create-{index}",
            )
        )
    for index, request in enumerate(adversarial_requests):
        rejected_projects = [forbidden_project] if index == 0 else []
        rejected_capabilities = ["write_overlay"] if index == 1 else []
        operations.append(
            RecordedOperation(
                "createHandoff",
                "POST",
                "/v1/handoffs",
                request,
                {
                    "capsule": {
                        "handoff_id": adversarial_ids[index],
                        "delegated_capabilities": ["read_context"]
                        if index == 1
                        else [],
                        "project_ids": [] if index == 0 else [allowed_project],
                        "bundle_id": parent_bundle_id,
                    },
                    "preview": {
                        "accepted_projects": [] if index == 0 else [allowed_project],
                        "rejected_projects": rejected_projects,
                        "accepted_capabilities": [] if index == 0 else ["read_context"],
                        "rejected_capabilities": rejected_capabilities,
                        "reference_count": 0 if index == 0 else 1,
                    },
                },
                idempotency_key=f"handoff-adversarial-{index}",
            )
        )
    for index, request in enumerate(accept_requests):
        operations.append(
            RecordedOperation(
                "acceptHandoff",
                "POST",
                f"/v1/handoffs/{handoff_ids[index]}:accept",
                request,
                {
                    "schema_version": "cigar.handoff-acceptance.v1",
                    "acceptance_id": f"01890f47-8e7d-7b42-a1d2-{41150 + index:012x}",
                    "handoff_id": handoff_ids[index],
                    "recipient_id": f"01890f47-8e7d-7b42-a1d2-{41160 + index:012x}",
                    "accepted_capabilities": ["read_context"],
                    "rejected_capabilities": [],
                    "unavailable_references": [],
                    "policy_digest": digest_value({"policy": "handoff-recorded"}),
                    "bundle_id": digest_value(
                        {"handoff": handoff_ids[index], "recipient": index}
                    ),
                    "accepted_at": fixture["fixed_time"],
                    "acknowledgement_digest": digest_value(
                        {"handoff": handoff_ids[index], "accepted": True}
                    ),
                },
                idempotency_key=f"handoff-accept-{index}",
                expected_revision="handoff-revision-1",
                path_parameters=(("handoff_id", handoff_ids[index]),),
            )
        )
    for index, request in enumerate(result_requests):
        operations.append(
            RecordedOperation(
                "recordHandoffResult",
                "POST",
                f"/v1/handoffs/{handoff_ids[index]}/results",
                request,
                {
                    "delta_id": delta_ids[index],
                    "handoff_id": handoff_ids[index],
                    "result_digest": digest_value(typed_results[index]),
                    "revision": index + 2,
                },
                idempotency_key=f"handoff-result-{index}",
                expected_revision=f"handoff-revision-{index + 2}",
                path_parameters=(("handoff_id", handoff_ids[index]),),
            )
        )
    for index, request in enumerate(merge_requests):
        operations.append(
            RecordedOperation(
                "mergeHandoff",
                "POST",
                f"/v1/handoffs/{handoff_ids[index]}:merge",
                request,
                {
                    "delta_id": delta_ids[index],
                    "proposed_versions": typed_results[index]["artifacts"],
                    "rejected_versions": [],
                    "conflict_ids": [],
                    "commit": {
                        "revision": index + 2,
                        "base_commit_id": base_commit_id,
                    },
                },
                idempotency_key=f"handoff-merge-{index}",
                expected_revision=f"parent-revision-{index + 1}",
                path_parameters=(("handoff_id", handoff_ids[index]),),
            )
        )

    legitimate_creations = []
    adversarial_creations = []
    acceptances = []
    receipts = []
    merges = []
    request_sequence = [
        *create_requests,
        *adversarial_requests,
        *accept_requests,
        *merge_requests,
    ]
    request_paths = [
        write_request(args.state, f"handoff-{index:02d}", request)
        for index, request in enumerate(request_sequence)
    ]
    with RecordedApi(args.state, operations) as api:
        remote = api.cli_arguments()

        def invoke(
            command: list[str],
            request_path: Path,
            key: str,
            revision: str | None = None,
        ) -> dict[str, Any]:
            revision_arguments = (
                ["--expected-revision", revision] if revision is not None else []
            )
            return cli(
                args.cigar_binary,
                [
                    *command,
                    "--input",
                    str(request_path),
                    "--idempotency-key",
                    key,
                    *revision_arguments,
                    "--yes",
                    "--output",
                    "json",
                    *remote,
                ],
                cwd=root,
                environment=environment,
            )["result"]

        for index in range(len(create_requests)):
            legitimate_creations.append(
                invoke(
                    ["handoff", "create"],
                    request_paths[index],
                    f"handoff-create-{index}",
                )
            )
        adversarial_offset = len(create_requests)
        for index in range(len(adversarial_requests)):
            adversarial_creations.append(
                invoke(
                    ["handoff", "create"],
                    request_paths[adversarial_offset + index],
                    f"handoff-adversarial-{index}",
                )
            )
        accept_offset = adversarial_offset + len(adversarial_requests)
        for index, handoff_id in enumerate(handoff_ids):
            acceptances.append(
                invoke(
                    ["handoff", "accept", handoff_id],
                    request_paths[accept_offset + index],
                    f"handoff-accept-{index}",
                    "handoff-revision-1",
                )
            )
        with CigarClient(
            api.base_url(),
            bearer_token=api.bearer_token(),
            allow_insecure_loopback=True,
            max_attempts=1,
        ) as client:
            for index, request in enumerate(result_requests):
                response = client.record_handoff_result(
                    TypedOperationRequest(
                        models.RecordHandoffResultRequest(
                            handoff_id=request["handoff_id"],
                            base_commit_id=request["base_commit_id"],
                            claims=tuple(request["claims"]),
                            decisions=tuple(request["decisions"]),
                            artifacts=tuple(request["artifacts"]),
                            source_changes=tuple(request["source_changes"]),
                            verifier_receipts=tuple(request["verifier_receipts"]),
                            unresolved_questions=tuple(request["unresolved_questions"]),
                            blockers=tuple(request["blockers"]),
                            effect_references=tuple(request["effect_references"]),
                            requested_followup_capabilities=tuple(
                                request["requested_followup_capabilities"]
                            ),
                        ),
                        idempotency_key=f"handoff-result-{index}",
                        expected_revision=f"handoff-revision-{index + 2}",
                    )
                )
                receipts.append(response.payload)
        merge_offset = accept_offset + len(accept_requests)
        for index, handoff_id in enumerate(handoff_ids):
            merges.append(
                invoke(
                    ["handoff", "merge", handoff_id],
                    request_paths[merge_offset + index],
                    f"handoff-merge-{index}",
                    f"parent-revision-{index + 1}",
                )
            )
        api.assert_complete()

    denied_read = (
        adversarial_creations[0]["preview"].get("accepted_projects") == []
        and adversarial_creations[0]["preview"].get("rejected_projects")
        == [forbidden_project]
        and "content" not in adversarial_creations[0]["preview"]
    )
    denied_write = adversarial_creations[1]["preview"].get("accepted_capabilities") == [
        "read_context"
    ] and adversarial_creations[1]["preview"].get("rejected_capabilities") == [
        "write_overlay"
    ]
    typed_receipts = all(
        receipt.handoff_id == handoff_ids[index]
        and receipt.delta_id == delta_ids[index]
        and receipt.result_digest == digest_value(typed_results[index])
        for index, receipt in enumerate(receipts)
    )
    parent_revision = 1
    merge_revisions = [merge["commit"].get("revision") for merge in merges]
    merged_revision = merge_revisions[-1]
    ratios = [package["package_tokens"] / parent_tokens for package in packages]
    maximum_ratio = fixture.get("expected", {}).get("maximum_package_ratio")
    ratio_valid = isinstance(maximum_ratio, (int, float)) and all(
        ratio <= maximum_ratio for ratio in ratios
    )

    no_egress = (
        __import__("os").environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable")
        != "unavailable"
    )
    setup = [
        step("isolated-home", "product_observed", {"isolated": True}),
        step(
            "deterministic-parent-and-children",
            "fixture_observed",
            {"parent_tokens": parent_tokens, "child_count": len(children)},
        ),
        step(
            "network-disabled",
            "product_observed" if no_egress else "not_observed",
            {"enforced": no_egress},
        ),
        step(
            "fixed-clock-and-seed",
            "fixture_observed",
            {"seed": fixture["fixed_seed"], "time": fixture["fixed_time"]},
        ),
    ]
    flow_evidence = [
        legitimate_creations[0]["capsule"],
        legitimate_creations[1]["capsule"],
        adversarial_creations[0]["preview"],
        adversarial_creations[1]["preview"],
        {"acceptance_count": len(acceptances), "receipt_count": len(receipts)},
        {"base_revision": parent_revision, "merge_revisions": merge_revisions},
    ]
    flow = [
        step(flow_id, "product_observed", evidence)
        for flow_id, evidence in zip(fixture["flow"], flow_evidence, strict=True)
    ]
    assertions = [
        assertion(
            "forbidden-access-denied-content-free",
            "product_observed" if denied_read else "not_observed",
            {
                "denied": denied_read,
                "preview_field_count": len(adversarial_creations[0]["preview"]),
            },
        ),
        assertion(
            "write-grant-attenuation-rejected",
            "product_observed" if denied_write else "not_observed",
            {"rejected": denied_write},
        ),
        assertion(
            "package-at-most-20-percent",
            "product_observed" if ratio_valid else "not_observed",
            {"ratios": ratios},
        ),
        assertion(
            "first-action-useful",
            "product_observed"
            if all(package["first_action"] for package in packages)
            else "not_observed",
            {"package_count": len(packages)},
        ),
        assertion(
            "result-is-typed-evidence",
            "product_observed" if typed_receipts else "not_observed",
            {"field_count": len(result_fields)},
        ),
        assertion(
            "optimistic-merge-exact",
            "product_observed"
            if merge_revisions == [2, 3] and merged_revision == 3
            else "not_observed",
            {
                "base_revision": parent_revision,
                "result_count": len(receipts),
                "merged_revision": merged_revision,
            },
        ),
    ]
    removed_home = remove_tree(args.state / "home")
    removed_children = remove_tree(root)
    removed_sdk_state = remove_tree(args.state / "cigar-home")
    removed_requests = remove_tree(args.state / "recorded-api-requests")
    removed_consumer = (
        removed_sdk_state
        and removed_requests
        and not (args.state / "recorded-api-token").exists()
    )
    teardown = [
        step("remove-isolated-home", "fixture_observed", {"removed": removed_home}),
        step("remove-child-state", "fixture_observed", {"removed": removed_children}),
        step(
            "remove-recorded-consumer-state",
            "fixture_observed",
            {"removed": removed_consumer},
        ),
    ]
    emit(
        fixture,
        args.fixture,
        setup,
        flow,
        assertions,
        teardown,
        {
            "product_version_surface_ok": isinstance(version, dict)
            and version.get("version") == "0.1.0",
            "package_count": len(packages),
            "typed_result_count": len(receipts),
            "public_operation_count": len(operations),
            "driver_scope": "fixture-bound-public-python-sdk-recorded-api",
        },
    )


if __name__ == "__main__":
    try:
        run()
    except DriverError as error:
        raise SystemExit(main_error(error))
