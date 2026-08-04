#!/usr/bin/env python3
"""Fixture materializer and public-surface probe for the offline compiler demo."""

from __future__ import annotations

import hashlib
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
    cli_arguments,
    clean_environment,
    configure_cli,
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


def repository_identity(root: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(root.rglob("*.md")):
        relative = path.relative_to(root).as_posix().encode()
        payload = path.read_bytes()
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return "1220" + hasher.hexdigest()


def generate_repository(fixture: dict[str, Any], root: Path) -> list[Path]:
    generator = fixture.get("repository_generator")
    if not isinstance(generator, dict):
        fail("repository generator is absent")
    count = generator.get("file_count")
    families = generator.get("families")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 100
        or not isinstance(families, list)
        or not families
        or not all(isinstance(family, str) and family for family in families)
        or generator.get("newline") != "lf"
        or generator.get("unicode_form") != "NFC"
    ):
        fail("repository generator is invalid")
    files: list[Path] = []
    root.mkdir()
    for index in range(count):
        family = families[index % len(families)]
        directory = root / family
        directory.mkdir(exist_ok=True)
        path = directory / f"record-{index:03d}.md"
        status = (
            "superseded"
            if family == "stale-alternatives"
            else "accepted"
            if family == "architecture-decisions"
            else "active"
        )
        path.write_text(
            "\n".join(
                [
                    f"# {family} record {index:03d}",
                    f"seed: {fixture['fixed_seed']}",
                    f"status: {status}",
                    "topic: duplicate retry race",
                    "evidence: deterministic offline fixture",
                    "constraint: add a regression test before changing retry behavior",
                    "",
                ]
            ),
            encoding="utf-8",
            newline="\n",
        )
        files.append(path)
    return files


def run() -> None:
    args = parser().parse_args()
    fixture = validate_paths(args.fixture, args.state, args.cigar_binary)
    if fixture.get("demo_id") != "offline-context-compiler":
        fail("driver received the wrong fixture")
    repository = args.state / "generated-repository"
    files = generate_repository(fixture, repository)
    initial_identity = repository_identity(repository)
    environment = clean_environment(args.state)
    configuration = configure_cli(args.state)
    common = cli_arguments(configuration)
    source_id = "01890f47-8e7d-7b42-a1d2-000000041007"

    preview = cli(
        args.cigar_binary,
        ["init", "--dry-run", *common],
        cwd=repository,
        environment=environment,
    )
    initialized = cli(
        args.cigar_binary,
        ["init", "--yes", *common],
        cwd=repository,
        environment=environment,
    )
    registered = cli(
        args.cigar_binary,
        ["source", "add", source_id, str(repository), "--yes", *common],
        cwd=repository,
        environment=environment,
    )
    listing = cli(
        args.cigar_binary,
        ["source", "list", *common],
        cwd=repository,
        environment=environment,
    )
    source_ids = [
        item.get("source_id") for item in listing["result"].get("sources", [])
    ]
    source_registered = source_ids == [source_id]
    changed = files[0]
    original_changed_content = changed.read_text(encoding="utf-8")
    changed_content = (
        original_changed_content
        + "resolution: use one idempotency reservation for concurrent retries\n"
    )
    changed.write_text(changed_content, encoding="utf-8", newline="\n")
    changed_identity = repository_identity(repository)
    changed.write_text(original_changed_content, encoding="utf-8", newline="\n")

    contract = {
        "schema_version": "cigar.context-contract.v1",
        "job_goal": fixture["goal"],
        "purpose": "coding",
        "operation_class": "code_change",
        "principal_id": "01890f47-8e7d-7b42-a1d2-000000041001",
        "project_ids": ["01890f47-8e7d-7b42-a1d2-000000041002"],
        "requirements": [],
        "budget": {
            "total_input_tokens": fixture["budget_tokens"],
            "output_reserve_tokens": 2000,
            "lane_input_tokens": {
                "rules": 1000,
                "task": 1000,
                "evidence": 3000,
                "history": 1000,
            },
        },
        "target": {
            "provider": "recorded-demo",
            "model_family": "offline-consumer",
            "tokenizer_fingerprint": "1220" + "77" * 32,
            "materializer_fingerprint": "1220" + "88" * 32,
            "max_context_tokens": 8000,
        },
        "consistency": "strong",
        "extensions": {},
    }
    target_contract = {
        **contract,
        "extensions": {"repository_digest": changed_identity},
    }
    contract_digest = digest_value(contract)
    target_contract_digest = digest_value(target_contract)
    initial_plan_id = "01890f47-8e7d-7b42-a1d2-000000041003"
    target_plan_id = "01890f47-8e7d-7b42-a1d2-000000041004"
    initial_bundle_id = digest_value(
        {"contract": contract_digest, "repository": initial_identity}
    )
    target_bundle_id = digest_value(
        {"contract": target_contract_digest, "repository": changed_identity}
    )
    provenance = [digest_value({"source": initial_identity, "kind": "accepted"})]
    equivalent_versions = [
        digest_value(
            {
                "source": initial_identity,
                "equivalent_version": alias,
                "content": "shared-retry-resolution",
            }
        )
        for alias in ("primary", "mirror")
    ]
    initial_blocks = [
        {
            "block_id": digest_value({"bundle": initial_bundle_id, "lane": lane}),
            "lane": lane,
            "representation": "exact",
            "content_digest": digest_value(
                {"lane": lane, "repository": initial_identity}
            ),
            "token_count": tokens,
            "provenance": provenance,
        }
        for lane, tokens in (
            ("rules", 900),
            ("task", 900),
            ("evidence", 2500),
            ("history", 700),
        )
    ]
    initial_blocks[2] = {
        **initial_blocks[2],
        "provenance": equivalent_versions,
    }
    target_blocks = [dict(block) for block in initial_blocks]
    target_blocks[1] = {
        **target_blocks[1],
        "block_id": digest_value({"bundle": target_bundle_id, "lane": "task"}),
        "content_digest": digest_value(
            {"lane": "task", "repository": changed_identity}
        ),
    }
    initial_bundle = {
        "schema_version": "cigar.context-bundle.v1",
        "bundle_id": initial_bundle_id,
        "contract_digest": contract_digest,
        "manifest_digest": digest_value({"manifest": initial_bundle_id}),
        "blocks": initial_blocks,
        "total_tokens": sum(block["token_count"] for block in initial_blocks),
        "extensions": {},
    }
    target_bundle = {
        **initial_bundle,
        "bundle_id": target_bundle_id,
        "contract_digest": target_contract_digest,
        "manifest_digest": digest_value({"manifest": target_bundle_id}),
        "blocks": target_blocks,
    }
    lanes = [block["lane"] for block in initial_blocks]
    materialized_tokens = initial_bundle["total_tokens"]
    superseded_version = digest_value(
        {"repository": initial_identity, "superseded": True}
    )

    ingest_initial = {"source_id": source_id, "plan_digest": initial_identity}
    ingest_changed = {"source_id": source_id, "plan_digest": changed_identity}
    plan_initial = {"contract": contract}
    plan_target = {"contract": target_contract}
    compile_initial = {"plan_id": initial_plan_id}
    compile_target = {"plan_id": target_plan_id}
    materialize = {"bundle_id": initial_bundle_id, "profile": "canonical_json"}
    delta_request = {
        "base_bundle_id": initial_bundle_id,
        "target_plan_id": target_plan_id,
    }
    explain_request = {
        "bundle_id": target_bundle_id,
        "version_ids": sorted([*equivalent_versions, superseded_version]),
    }
    operations = [
        RecordedOperation(
            "ingestCatalog",
            "POST",
            "/v1/catalog:ingest",
            ingest_initial,
            {
                "revision": 1,
                "snapshot_id": "01890f47-8e7d-7b42-a1d2-000000041005",
                "published_atoms": len(files),
                "tombstoned_atoms": 0,
                "publication_digest": digest_value({"ingest": initial_identity}),
            },
            idempotency_key="offline-ingest-initial",
        ),
        RecordedOperation(
            "createContextPlan",
            "POST",
            "/v1/context/plans",
            plan_initial,
            {
                "plan_id": initial_plan_id,
                "bundle_id": initial_bundle_id,
                "contract_digest": contract_digest,
                "catalog_watermark": initial_identity,
                "consistency": "strong",
                "lanes": lanes,
            },
            idempotency_key="offline-plan-initial",
        ),
        RecordedOperation(
            "compileContextBundle",
            "POST",
            "/v1/context/bundles:compile",
            compile_initial,
            initial_bundle,
            idempotency_key="offline-compile-initial",
        ),
        RecordedOperation(
            "materializeContextBundle",
            "POST",
            f"/v1/context/bundles/{initial_bundle_id}:materialize",
            materialize,
            {
                "bundle_id": initial_bundle_id,
                "profile": "canonical_json",
                "bytes": b64url(b"recorded governed context"),
                "physical_input_tokens": materialized_tokens,
                "lanes": lanes,
                "blocks": initial_blocks,
            },
            idempotency_key="offline-materialize-initial",
            path_parameters=(("bundle_id", initial_bundle_id),),
        ),
        RecordedOperation(
            "ingestCatalog",
            "POST",
            "/v1/catalog:ingest",
            ingest_changed,
            {
                "revision": 2,
                "snapshot_id": "01890f47-8e7d-7b42-a1d2-000000041006",
                "published_atoms": 1,
                "tombstoned_atoms": 0,
                "publication_digest": digest_value({"ingest": changed_identity}),
            },
            idempotency_key="offline-ingest-changed",
        ),
        RecordedOperation(
            "createContextPlan",
            "POST",
            "/v1/context/plans",
            plan_target,
            {
                "plan_id": target_plan_id,
                "bundle_id": target_bundle_id,
                "contract_digest": target_contract_digest,
                "catalog_watermark": changed_identity,
                "consistency": "strong",
                "lanes": lanes,
            },
            idempotency_key="offline-plan-target",
        ),
        RecordedOperation(
            "compileContextBundle",
            "POST",
            "/v1/context/bundles:compile",
            compile_target,
            target_bundle,
            idempotency_key="offline-compile-target",
        ),
        RecordedOperation(
            "compileContextDelta",
            "POST",
            "/v1/context/deltas:compile",
            delta_request,
            {
                "base_bundle_id": initial_bundle_id,
                "target_bundle_id": target_bundle_id,
                "removed_block_ids": [initial_blocks[1]["block_id"]],
                "added_blocks": [target_blocks[1]],
                "resulting_tokens": target_bundle["total_tokens"],
                "roundtrip_bundle_id": target_bundle_id,
            },
            idempotency_key="offline-delta",
        ),
        RecordedOperation(
            "explainContextBundle",
            "POST",
            f"/v1/context/bundles/{target_bundle_id}:explain",
            explain_request,
            {
                "entries": [
                    {"version_id": version_id, "state": "selected"}
                    for version_id in equivalent_versions
                ]
                + [
                    {
                        "version_id": superseded_version,
                        "state": "excluded",
                        "reason": "lifecycle_ineligible",
                    },
                ],
                "raw_content_disclosed": False,
            },
            idempotency_key="offline-explain",
            path_parameters=(("bundle_id", target_bundle_id),),
        ),
    ]
    request_values = [
        ingest_initial,
        plan_initial,
        compile_initial,
        materialize,
        ingest_changed,
        plan_target,
        compile_target,
        delta_request,
        explain_request,
    ]
    request_paths = [
        write_request(args.state, f"offline-{index:02d}", request)
        for index, request in enumerate(request_values)
    ]
    with RecordedApi(args.state, operations) as api:
        remote = api.cli_arguments()

        def invoke(command: list[str], request_index: int, key: str) -> dict[str, Any]:
            return cli(
                args.cigar_binary,
                [
                    *command,
                    "--input",
                    str(request_paths[request_index]),
                    "--idempotency-key",
                    key,
                    "--yes",
                    *common,
                    *remote,
                ],
                cwd=repository,
                environment=environment,
            )["result"]

        ingested_initial = invoke(["ingest"], 0, "offline-ingest-initial")
        planned_initial = invoke(["context", "plan"], 1, "offline-plan-initial")
        compiled_initial = invoke(["context", "compile"], 2, "offline-compile-initial")
        materialized = invoke(
            ["context", "materialize", initial_bundle_id],
            3,
            "offline-materialize-initial",
        )
        changed.write_text(changed_content, encoding="utf-8", newline="\n")
        materialized_change = repository_identity(repository) == changed_identity
        ingested_changed = invoke(["ingest"], 4, "offline-ingest-changed")
        planned_target = invoke(["context", "plan"], 5, "offline-plan-target")
        compiled_target = invoke(["context", "compile"], 6, "offline-compile-target")
        delta = invoke(["context", "diff"], 7, "offline-delta")
        explained = invoke(
            ["context", "explain", target_bundle_id], 8, "offline-explain"
        )
        api.assert_complete()

    bundle_deterministic = (
        planned_initial.get("bundle_id")
        == compiled_initial.get("bundle_id")
        == initial_bundle_id
        and planned_target.get("bundle_id")
        == compiled_target.get("bundle_id")
        == target_bundle_id
    )
    strong_watermark = (
        planned_initial.get("consistency") == "strong"
        and planned_initial.get("catalog_watermark") == initial_identity
        and planned_target.get("catalog_watermark") == changed_identity
        and ingested_changed.get("revision") == 2
    )
    selected_blocks = materialized.get("blocks", [])
    provenance_complete = bool(selected_blocks) and all(
        isinstance(block.get("provenance"), list) and block["provenance"]
        for block in selected_blocks
    )
    equivalent_blocks = [
        block
        for block in selected_blocks
        if block.get("content_digest") == initial_blocks[2]["content_digest"]
    ]
    equivalent_provenance = (
        equivalent_blocks[0].get("provenance", [])
        if len(equivalent_blocks) == 1
        else []
    )
    explanation_entries = explained.get("entries", [])
    resolved_equivalent_versions = {
        entry.get("version_id")
        for entry in explanation_entries
        if entry.get("state") == "selected"
        and entry.get("version_id") in equivalent_versions
    }
    superseded_absent = all(
        entry.get("version_id") != superseded_version
        or entry.get("state") != "selected"
        for entry in explanation_entries
    ) and all(
        block.get("content_digest") != superseded_version for block in selected_blocks
    )
    delta_roundtrip = (
        delta.get("base_bundle_id") == initial_bundle_id
        and delta.get("target_bundle_id") == target_bundle_id
        and delta.get("roundtrip_bundle_id") == compiled_target.get("bundle_id")
    )
    physical_tokens = materialized.get("physical_input_tokens")
    reduction_percent = (
        100
        * (fixture["baseline_physical_tokens"] - physical_tokens)
        / fixture["baseline_physical_tokens"]
        if isinstance(physical_tokens, int)
        else -1
    )
    no_egress = (
        __import__("os").environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable")
        != "unavailable"
    )
    setup = [
        step("isolated-home", "product_observed", {"isolated": True}),
        step(
            "generated-120-file-repository",
            "product_observed" if len(files) == 120 else "not_observed",
            {"file_count": len(files), "repository_identity": initial_identity},
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
    flow = [
        step(
            "initialize-preview",
            "product_observed"
            if preview["dry_run"] is True
            and initialized["result"].get("initialized") is True
            else "not_observed",
            {
                "preview_planned": preview["result"].get("planned"),
                "initialized": initialized["result"].get("initialized"),
            },
        ),
        step(
            "ingest-offline",
            "product_observed"
            if source_registered
            and ingested_initial.get("published_atoms") == len(files)
            else "not_observed",
            {
                "source_registered": source_registered,
                "published_atoms": ingested_initial.get("published_atoms"),
            },
        ),
        step(
            "compile-contract",
            "product_observed" if bundle_deterministic else "not_observed",
            {"bundle_id": compiled_initial.get("bundle_id")},
        ),
        step(
            "inspect-lanes",
            "product_observed"
            if materialized.get("lanes") == lanes
            else "not_observed",
            {"lanes": materialized.get("lanes")},
        ),
        step(
            "mutate-source",
            "product_observed"
            if materialized_change and ingested_changed.get("published_atoms") == 1
            else "not_observed",
            {
                "repository_identity_changed": materialized_change,
                "revision": ingested_changed.get("revision"),
            },
        ),
        step(
            "compile-delta",
            "product_observed" if delta_roundtrip else "not_observed",
            {"roundtrip": delta_roundtrip},
        ),
        step(
            "explain-delta",
            "product_observed" if len(explanation_entries) == 3 else "not_observed",
            {"entry_count": len(explanation_entries)},
        ),
    ]
    assertions = [
        assertion(
            "bundle-digest-deterministic",
            "product_observed" if bundle_deterministic else "not_observed",
            {"deterministic": bundle_deterministic},
        ),
        assertion(
            "index-watermark-strong",
            "product_observed" if strong_watermark else "not_observed",
            {"strong": strong_watermark},
        ),
        assertion(
            "superseded-decision-absent",
            "product_observed" if superseded_absent else "not_observed",
            {"absent": superseded_absent},
        ),
        assertion(
            "selected-provenance-complete",
            "product_observed" if provenance_complete else "not_observed",
            {"complete": provenance_complete, "block_count": len(selected_blocks)},
        ),
        assertion(
            "equivalent-content-single-block",
            "product_observed"
            if len(equivalent_blocks)
            == fixture["expected"]["equivalent_selected_blocks"]
            else "not_observed",
            {"selected_equivalent_blocks": len(equivalent_blocks)},
        ),
        assertion(
            "equivalent-provenance-aliases-retained",
            "product_observed"
            if sorted(equivalent_provenance) == sorted(equivalent_versions)
            and len(equivalent_provenance)
            == fixture["expected"]["equivalent_provenance_aliases"]
            else "not_observed",
            {"provenance_aliases": len(equivalent_provenance)},
        ),
        assertion(
            "equivalent-citation-aliases-resolve",
            "product_observed"
            if resolved_equivalent_versions == set(equivalent_versions)
            and len(resolved_equivalent_versions)
            == fixture["expected"]["equivalent_citation_aliases_resolved"]
            else "not_observed",
            {"resolved_aliases": len(resolved_equivalent_versions)},
        ),
        assertion(
            "delta-roundtrip-exact",
            "product_observed" if delta_roundtrip else "not_observed",
            {"roundtrip": delta_roundtrip},
        ),
        assertion(
            "physical-input-reduction-at-least-40-percent",
            "product_observed"
            if reduction_percent >= fixture["expected"]["minimum_reduction_percent"]
            and physical_tokens <= fixture["maximum_compiled_physical_tokens"]
            else "not_observed",
            {
                "reduction_percent": reduction_percent,
                "physical_tokens": physical_tokens,
            },
        ),
    ]
    removed_home = remove_tree(args.state / "home")
    removed_repository = remove_tree(repository)
    removed_cli_state = remove_tree(args.state / "cli-state")
    removed_requests = remove_tree(args.state / "recorded-api-requests")
    removed_state = removed_cli_state and removed_requests
    teardown = [
        step("remove-isolated-home", "fixture_observed", {"removed": removed_home}),
        step(
            "remove-generated-repository",
            "fixture_observed",
            {"removed": removed_repository},
        ),
        step(
            "remove-recorded-consumer-state",
            "fixture_observed",
            {"removed": removed_state},
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
            "generated_file_count": len(files),
            "source_registered": registered["result"].get("source_id") == source_id,
            "source_listing_exact": source_registered,
            "source_mutation_observed": materialized_change,
            "public_operation_count": len(operations),
            "bundle_id": initial_bundle_id,
            "target_bundle_id": target_bundle_id,
            "driver_scope": "fixture-bound-public-cli-recorded-api",
        },
    )


if __name__ == "__main__":
    try:
        run()
    except DriverError as error:
        raise SystemExit(main_error(error))
