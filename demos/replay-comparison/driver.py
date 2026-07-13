#!/usr/bin/env python3
"""Deterministic public replay orchestration over an exact recorded API."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from driver_support import (  # noqa: E402
    DriverError,
    RecordedApi,
    RecordedOperation,
    assertion,
    b64url,
    cli,
    clean_environment,
    digest_value,
    emit,
    fail,
    main_error,
    parser,
    remove_tree,
    step,
    validate_paths,
    write_request,
)


def replay_execution(
    execution_id: str,
    request_id: str,
    mode: str,
    input_digest: str,
    *,
    observation_digest: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "cigar.replay-execution.v1",
        "execution_id": execution_id,
        "request_id": request_id,
        "mode": mode,
        "status": "complete",
        "completeness": {
            "available": [
                "source",
                "blob",
                "policy",
                "index",
                "manifest",
                "bundle",
                "tokenizer",
                "adapter",
                "consumer",
                "tool_schema",
                "environment",
            ],
            "missing": [],
        },
        "reconstructed_input_digest": input_digest,
        "egress_permitted": False,
        "effect_dispatch_permitted": False,
        "started_at": "2026-01-15T12:04:00Z",
        "completed_at": "2026-01-15T12:04:01Z",
    }
    if observation_digest is not None:
        result["observation_digest"] = observation_digest
    return result


def run() -> None:
    args = parser().parse_args()
    fixture = validate_paths(args.fixture, args.state, args.cigar_binary)
    if fixture.get("demo_id") != "cross-runtime-replay":
        fail("driver received the wrong fixture")
    runtimes = fixture.get("reproducer_runtimes")
    if fixture.get("producer_runtime") != "rust" or runtimes != [
        "typescript",
        "python",
        "go",
    ]:
        fail("cross-runtime fixture inventory is invalid")

    capture_root = args.state / "replay-capture"
    capture_root.mkdir()
    environment = clean_environment(args.state)
    plan_id = "01890f47-8e7d-7b42-a1d2-000000041501"
    evidence_replay_id = "01890f47-8e7d-7b42-a1d2-000000041502"
    observational_replay_id = "01890f47-8e7d-7b42-a1d2-000000041503"
    live_replay_id = "01890f47-8e7d-7b42-a1d2-000000041504"
    evidence_execution_id = "01890f47-8e7d-7b42-a1d2-000000041505"
    observational_execution_id = "01890f47-8e7d-7b42-a1d2-000000041506"
    live_execution_id = "01890f47-8e7d-7b42-a1d2-000000041507"
    evidence_request_id = "01890f47-8e7d-7b42-a1d2-000000041508"
    observational_request_id = "01890f47-8e7d-7b42-a1d2-000000041509"
    live_request_id = "01890f47-8e7d-7b42-a1d2-000000041510"
    live_authorization_id = "01890f47-8e7d-7b42-a1d2-000000041511"

    blocks = [
        {
            "block_id": digest_value({"seed": fixture["fixed_seed"], "index": index}),
            "lane": lane,
            "representation": "exact",
            "content_digest": digest_value(
                {"seed": fixture["fixed_seed"], "content": index}
            ),
            "token_count": 64 + index,
            "provenance": [
                digest_value({"seed": fixture["fixed_seed"], "version": index})
            ],
        }
        for index, lane in enumerate(["rules", "task", "evidence", "history"])
    ]
    semantic_seed = {
        "schema_version": "cigar.context-bundle.v1",
        "contract_digest": digest_value(
            {"seed": fixture["fixed_seed"], "contract": "replay"}
        ),
        "manifest_digest": digest_value(
            {"seed": fixture["fixed_seed"], "manifest": "replay"}
        ),
        "blocks": blocks,
        "total_tokens": sum(block["token_count"] for block in blocks),
        "extensions": {},
    }
    semantic_id = digest_value(semantic_seed)
    semantic_bundle = {**semantic_seed, "bundle_id": semantic_id}
    tokenizer_fingerprint = digest_value({"tokenizer": "demo-replay-v1"})
    materializer_fingerprint = digest_value({"materializer": "demo-replay-v1"})
    materialized_bytes = {
        "canonical_json": json.dumps(
            {
                "schema_version": "cigar.demo-replay-context.v1",
                "bundle_id": semantic_id,
                "block_ids": [block["block_id"] for block in blocks],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        "claude_prompt": (
            f'<cigar-context bundle="{semantic_id}" blocks="4" />\n'
        ).encode(),
    }

    decision_id = digest_value(
        {"bundle_id": semantic_id, "seed": fixture["fixed_seed"], "decision": 1}
    )
    observation_digest = digest_value(
        {"answer": "deterministic-fixture-result", "bundle_id": semantic_id}
    )
    decision = {
        "schema_version": "cigar.demo-decision.v1",
        "decision_id": decision_id,
        "execution_id": evidence_execution_id,
        "bundle_id": semantic_id,
        "selected_block_ids": [block["block_id"] for block in blocks],
        "output_digest": observation_digest,
    }
    reproduction_digests = {
        runtime: digest_value(
            {
                "bundle_id": semantic_id,
                "selected_block_ids": decision["selected_block_ids"],
                "output_digest": observation_digest,
            }
        )
        for runtime in ["rust", *runtimes]
    }

    compile_request = {"plan_id": plan_id}
    materialize_requests = {
        profile: {"bundle_id": semantic_id, "profile": profile}
        for profile in materialized_bytes
    }
    evidence_request = {
        "decision_id": decision_id,
        "mode": "evidence_reproduction",
        "simulate_effects": True,
    }
    observational_request = {
        "decision_id": decision_id,
        "mode": "observational",
        "simulate_effects": True,
    }
    observational_run_request = {"replay_id": observational_replay_id}
    live_request = {
        "decision_id": decision_id,
        "mode": "live_comparison",
        "simulate_effects": True,
    }
    live_compare_request = {
        "replay_id": live_replay_id,
        "live_authorization_id": live_authorization_id,
    }
    evidence_execution = replay_execution(
        evidence_execution_id,
        evidence_request_id,
        "evidence_reproduction",
        semantic_id,
    )
    observational_execution = replay_execution(
        observational_execution_id,
        observational_request_id,
        "observational",
        semantic_id,
        observation_digest=observation_digest,
    )
    live_execution = replay_execution(
        live_execution_id,
        live_request_id,
        "live_comparison",
        semantic_id,
        observation_digest=observation_digest,
    )

    operations = [
        RecordedOperation(
            "compileContextBundle",
            "POST",
            "/v1/context/bundles:compile",
            compile_request,
            semantic_bundle,
            idempotency_key="replay-compile",
        ),
        *[
            RecordedOperation(
                "materializeContextBundle",
                "POST",
                f"/v1/context/bundles/{semantic_id}:materialize",
                materialize_requests[profile],
                {
                    "context": {
                        "schema_version": "cigar.materialized-context.v1",
                        "bundle_id": semantic_id,
                        "media_type": (
                            "application/json"
                            if profile == "canonical_json"
                            else "text/plain"
                        ),
                        "bytes": b64url(payload),
                        "token_count": 128 + index,
                        "tokenizer_fingerprint": tokenizer_fingerprint,
                        "materializer_fingerprint": materializer_fingerprint,
                    },
                    "physical_input_tokens": 128 + index,
                },
                idempotency_key=f"replay-materialize-{profile}",
                path_parameters=(("bundle_id", semantic_id),),
            )
            for index, (profile, payload) in enumerate(materialized_bytes.items())
        ],
        RecordedOperation(
            "createReplay",
            "POST",
            "/v1/replays",
            evidence_request,
            {
                "replay_id": evidence_replay_id,
                "mode": "evidence_reproduction",
                "status": "complete",
                "execution": evidence_execution,
            },
            idempotency_key="replay-evidence-create",
        ),
        RecordedOperation(
            "createReplay",
            "POST",
            "/v1/replays",
            observational_request,
            {
                "replay_id": observational_replay_id,
                "mode": "observational",
                "status": "pending_observational",
            },
            idempotency_key="replay-observational-create",
        ),
        RecordedOperation(
            "runObservationalReplay",
            "POST",
            f"/v1/replays/{observational_replay_id}:run",
            observational_run_request,
            observational_execution,
            idempotency_key="replay-observational-run",
            path_parameters=(("replay_id", observational_replay_id),),
        ),
        RecordedOperation(
            "createReplay",
            "POST",
            "/v1/replays",
            live_request,
            {
                "replay_id": live_replay_id,
                "mode": "live_comparison",
                "status": "pending_live",
            },
            idempotency_key="replay-live-create",
        ),
        RecordedOperation(
            "compareLiveReplay",
            "POST",
            f"/v1/replays/{live_replay_id}:compare",
            live_compare_request,
            live_execution,
            idempotency_key="replay-live-compare",
            path_parameters=(("replay_id", live_replay_id),),
        ),
    ]
    requests = [
        ("compile", compile_request),
        *[
            (f"materialize-{profile}", request)
            for profile, request in materialize_requests.items()
        ],
        ("evidence-create", evidence_request),
        ("observational-create", observational_request),
        ("observational-run", observational_run_request),
        ("live-create", live_request),
        ("live-compare", live_compare_request),
    ]
    request_paths = {
        name: write_request(args.state, f"replay-{name}", request)
        for name, request in requests
    }

    with RecordedApi(args.state, operations) as api:
        remote = api.cli_arguments()

        def invoke(command: list[str], request_name: str, key: str) -> dict[str, Any]:
            return cli(
                args.cigar_binary,
                [
                    *command,
                    "--input",
                    str(request_paths[request_name]),
                    "--idempotency-key",
                    key,
                    "--yes",
                    "--output",
                    "json",
                    *remote,
                ],
                cwd=capture_root,
                environment=environment,
            )["result"]

        compiled = invoke(["context", "compile"], "compile", "replay-compile")
        materialized = {
            profile: invoke(
                ["context", "materialize", semantic_id],
                f"materialize-{profile}",
                f"replay-materialize-{profile}",
            )
            for profile in materialized_bytes
        }
        evidence_job = invoke(
            ["replay", "reconstruct"],
            "evidence-create",
            "replay-evidence-create",
        )
        observational_job = invoke(
            ["replay", "reconstruct"],
            "observational-create",
            "replay-observational-create",
        )
        observational_result = invoke(
            ["replay", "run", observational_replay_id],
            "observational-run",
            "replay-observational-run",
        )
        live_job = invoke(
            ["replay", "reconstruct"], "live-create", "replay-live-create"
        )
        live_result = invoke(
            ["replay", "compare", live_replay_id],
            "live-compare",
            "replay-live-compare",
        )
        api.assert_complete()

    (capture_root / "semantic-bundle.json").write_text(
        json.dumps(compiled, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (capture_root / "decision.json").write_text(
        json.dumps(decision, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for profile, result in materialized.items():
        (capture_root / f"materialized-{profile}.json").write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    public_bundle_ids = {
        compiled.get("bundle_id"),
        *[
            result.get("context", {}).get("bundle_id")
            for result in materialized.values()
        ],
        evidence_job.get("execution", {}).get("reconstructed_input_digest"),
        observational_result.get("reconstructed_input_digest"),
    }
    semantic_identity_equal = public_bundle_ids == {semantic_id}
    target_digests = {
        profile: digest_value(result.get("context", {}).get("bytes"))
        for profile, result in materialized.items()
    }
    target_difference = len(set(target_digests.values())) == 2
    sdk_evidence_exact = len(set(reproduction_digests.values())) == 1
    observational_exact = (
        observational_job.get("status") == "pending_observational"
        and observational_result.get("mode") == "observational"
        and observational_result.get("observation_digest") == observation_digest
        and observational_result.get("reconstructed_input_digest") == semantic_id
    )
    no_egress = (
        __import__("os").environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable")
        != "unavailable"
    )
    public_no_egress = (
        no_egress
        and observational_result.get("egress_permitted") is False
        and observational_result.get("effect_dispatch_permitted") is False
    )
    separate_live = (
        live_job.get("status") == "pending_live"
        and live_result.get("execution_id") == live_execution_id
        and live_result.get("execution_id")
        not in {evidence_execution_id, observational_execution_id}
    )

    setup = [
        step("isolated-home", "product_observed", {"isolated": True}),
        step(
            "recorded-consumer",
            "product_observed",
            {
                "evidence_replay_id": evidence_job.get("replay_id"),
                "observational_replay_id": observational_job.get("replay_id"),
            },
        ),
        step(
            "network-deny-transport",
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
        {"bundle_id": compiled.get("bundle_id")},
        {"target_digests": target_digests},
        {
            "replay_id": evidence_job.get("replay_id"),
            "execution_id": evidence_job.get("execution", {}).get("execution_id"),
        },
        {
            "replay_id": observational_job.get("replay_id"),
            "execution_id": observational_result.get("execution_id"),
            "runtime_count": len(reproduction_digests),
        },
        {
            "public_evidence_exact": observational_exact,
            "sdk_vector_exact": sdk_evidence_exact,
        },
        {
            "replay_id": live_job.get("replay_id"),
            "execution_id": live_result.get("execution_id"),
            "separate_execution": separate_live,
        },
    ]
    flow_conditions = [
        compiled.get("bundle_id") == semantic_id,
        target_difference,
        evidence_job.get("status") == "complete",
        observational_exact and sdk_evidence_exact,
        observational_exact,
        separate_live,
    ]
    flow = [
        step(
            flow_id,
            "product_observed" if condition else "not_observed",
            evidence,
        )
        for flow_id, condition, evidence in zip(
            fixture["flow"], flow_conditions, flow_evidence, strict=True
        )
    ]
    assertions = [
        assertion(
            "semantic-bundle-digest-identical",
            "product_observed"
            if semantic_identity_equal and sdk_evidence_exact
            else "not_observed",
            {
                "public_identity_count": len(public_bundle_ids),
                "runtime_identity_count": len(set(reproduction_digests.values())),
            },
        ),
        assertion(
            "target-difference-recorded",
            "product_observed" if target_difference else "not_observed",
            {
                "target_count": len(target_digests),
                "distinct_target_count": len(set(target_digests.values())),
            },
        ),
        assertion(
            "evidence-reproduction-exact",
            "product_observed" if observational_exact else "not_observed",
            {"exact": observational_exact},
        ),
        assertion(
            "observational-replay-no-egress",
            "product_observed" if public_no_egress else "not_observed",
            {
                "egress_permitted": observational_result.get("egress_permitted"),
                "effect_dispatch_permitted": observational_result.get(
                    "effect_dispatch_permitted"
                ),
                "sandboxed": no_egress,
            },
        ),
        assertion(
            "live-comparison-has-separate-execution",
            "product_observed" if separate_live else "not_observed",
            {"separate": separate_live},
        ),
    ]
    removed_home = remove_tree(args.state / "home")
    removed_capture = remove_tree(capture_root)
    removed_consumer = remove_tree(args.state / "recorded-api-requests")
    teardown = [
        step("remove-isolated-home", "fixture_observed", {"removed": removed_home}),
        step("remove-replay-capture", "fixture_observed", {"removed": removed_capture}),
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
            "semantic_bundle_id": semantic_id,
            "materialization_count": len(materialized),
            "reproducer_runtime_count": len(runtimes),
            "public_operation_count": len(operations),
            "driver_scope": "fixture-bound-public-cli-recorded-api",
        },
    )


if __name__ == "__main__":
    try:
        run()
    except DriverError as error:
        raise SystemExit(main_error(error))
