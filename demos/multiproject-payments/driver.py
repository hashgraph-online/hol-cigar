#!/usr/bin/env python3
"""Fixture-bound public-CLI driver for the multi-project isolation demo."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from driver_support import (  # noqa: E402
    DriverError,
    RecordedApi,
    RecordedOperation,
    assertion,
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

IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")


def tree_identity(path: Path) -> str:
    hasher = hashlib.sha256()
    for entry in sorted(path.rglob("*")):
        relative = entry.relative_to(path).as_posix().encode()
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        if entry.is_file():
            payload = entry.read_bytes()
            hasher.update(len(payload).to_bytes(8, "big"))
            hasher.update(payload)
    return "1220" + hasher.hexdigest()


def checked_projects(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    projects = fixture.get("projects")
    if not isinstance(projects, list) or len(projects) != 4:
        fail("multi-project fixture inventory is invalid")
    result: list[dict[str, Any]] = []
    for project in projects:
        if (
            not isinstance(project, dict)
            or set(project) != {"id", "attached", "permitted"}
            or not isinstance(project.get("id"), str)
            or not IDENTIFIER.fullmatch(project["id"])
            or not isinstance(project.get("attached"), bool)
            or not isinstance(project.get("permitted"), bool)
        ):
            fail("multi-project fixture entry is invalid")
        result.append(project)
    if len({project["id"] for project in result}) != len(result):
        fail("multi-project fixture ids are duplicated")
    return result


def run() -> None:
    args = parser().parse_args()
    fixture = validate_paths(args.fixture, args.state, args.cigar_binary)
    if fixture.get("demo_id") != "multi-project-isolation":
        fail("driver received the wrong fixture")
    projects = checked_projects(fixture)
    workspace = args.state / "workspace"
    workspace.mkdir()
    before: dict[str, str] = {}
    for project in projects:
        root = workspace / project["id"]
        root.mkdir()
        (root / "shared-name.txt").write_text(
            f"project={project['id']}\nseed={fixture['fixed_seed']}\n",
            encoding="utf-8",
            newline="\n",
        )
        before[project["id"]] = tree_identity(root)

    environment = clean_environment(args.state)
    configuration = configure_cli(args.state)
    common = cli_arguments(configuration)
    initialized = cli(
        args.cigar_binary,
        ["init", "--yes", *common],
        cwd=workspace,
        environment=environment,
    )
    attached = [
        project for project in projects if project["attached"] and project["permitted"]
    ]
    for project in attached:
        response = cli(
            args.cigar_binary,
            [
                "project",
                "attach",
                project["id"],
                str(workspace / project["id"]),
                "--yes",
                *common,
            ],
            cwd=workspace,
            environment=environment,
        )
        if response["result"].get("project_id") != project["id"]:
            fail("project attach returned the wrong identity")

    linked: list[tuple[str, str]] = []
    for source, target in zip(attached, attached[1:]):
        response = cli(
            args.cigar_binary,
            [
                "project",
                "link",
                source["id"],
                target["id"],
                "--yes",
                *common,
            ],
            cwd=workspace,
            environment=environment,
        )
        if response["result"].get("linked") is not True:
            fail("project link was not committed")
        linked.append((source["id"], target["id"]))

    focus_sequence = fixture.get("focus_sequence")
    if not isinstance(focus_sequence, list) or focus_sequence != [
        project["id"] for project in attached
    ] + [attached[0]["id"]]:
        fail("multi-project focus sequence is invalid")
    focus_observations: list[dict[str, Any]] = []
    for project_id in focus_sequence:
        switched = cli(
            args.cigar_binary,
            ["project", "switch", project_id, "--yes", *common],
            cwd=workspace,
            environment=environment,
        )["result"]
        focused = cli(
            args.cigar_binary,
            ["focus", "switch", f"task-{project_id}", "--yes", *common],
            cwd=workspace,
            environment=environment,
        )["result"]
        if (
            switched.get("active_project") != project_id
            or focused.get("active_focus") != f"task-{project_id}"
        ):
            fail("focus switch did not expose the requested current state")
        focus_observations.append(
            {
                "project": switched["active_project"],
                "focus": focused["active_focus"],
                "generation": focused.get("generation"),
            }
        )

    listing = cli(
        args.cigar_binary,
        ["project", "list", *common],
        cwd=workspace,
        environment=environment,
    )["result"]
    visible = [project.get("project_id") for project in listing.get("projects", [])]
    expected_visible = fixture.get("expected", {}).get("visible_projects")
    visible_exact = (
        isinstance(expected_visible, list)
        and len(visible) == len(expected_visible)
        and set(visible) == set(expected_visible)
    )
    hidden = {project["id"] for project in projects} - set(visible)
    forbidden = {
        project["id"]
        for project in projects
        if not project["permitted"] or not project["attached"]
    }
    generations = [item["generation"] for item in focus_observations]
    generation_current = all(
        isinstance(value, int) and not isinstance(value, bool) for value in generations
    ) and all(left < right for left, right in zip(generations, generations[1:]))

    state_document = json.loads(
        (args.state / "cli-state" / "state.json").read_text(encoding="utf-8")
    )
    final_only = (
        state_document.get("active_project") == focus_sequence[-1]
        and state_document.get("active_focus") == f"task-{focus_sequence[-1]}"
        and not any(
            key in state_document for key in ("previous_focus", "focus_history")
        )
    )
    after = {
        project["id"]: tree_identity(workspace / project["id"]) for project in projects
    }
    authority_unchanged = before == after
    project_records = {
        project["id"]: f"01890f47-8e7d-7b42-a1d2-{41020 + index:012x}"
        for index, project in enumerate(projects)
    }
    workspace_id = "01890f47-8e7d-7b42-a1d2-000000041030"
    expected_visible = fixture["expected"]["visible_projects"]
    focus_requests = [
        {
            "workspace_id": workspace_id,
            "project_id": project_records[project_id],
            "branch_id": f"01890f47-8e7d-7b42-a1d2-{41040 + index:012x}",
            "task_id": f"01890f47-8e7d-7b42-a1d2-{41050 + index:012x}",
            "session_id": f"01890f47-8e7d-7b42-a1d2-{41060 + index:012x}",
            "purpose": f"recorded focus for {project_id}",
        }
        for index, project_id in enumerate(focus_sequence)
    ]
    focus_operations = [
        RecordedOperation(
            "createSpace",
            "POST",
            "/v1/spaces",
            request,
            {
                "space_id": digest_value(
                    {"seed": fixture["fixed_seed"], "focus_index": index}
                ),
                "project_id": project_id,
                "revision": index + 1,
                "source_generation": focus_observations[index]["generation"],
                "visible_projects": expected_visible,
                "candidate_projects": expected_visible,
                "context_detail_projects": [project_id],
            },
            idempotency_key=f"multiproject-focus-{index}",
        )
        for index, (project_id, request) in enumerate(
            zip(focus_sequence, focus_requests, strict=True)
        )
    ]
    request_paths = [
        write_request(args.state, f"multiproject-focus-{index}", request)
        for index, request in enumerate(focus_requests)
    ]
    public_focus: list[dict[str, Any]] = []
    with RecordedApi(args.state, focus_operations) as api:
        for index, request_path in enumerate(request_paths):
            response = cli(
                args.cigar_binary,
                [
                    "focus",
                    "new",
                    "--input",
                    str(request_path),
                    "--idempotency-key",
                    f"multiproject-focus-{index}",
                    "--yes",
                    *common,
                    *api.cli_arguments(),
                ],
                cwd=workspace,
                environment=environment,
            )["result"]
            if (
                response.get("project_id") != focus_sequence[index]
                or response.get("source_generation")
                != focus_observations[index]["generation"]
            ):
                fail("public focus orchestration disagrees with local project state")
            public_focus.append(response)
        api.assert_complete()

    public_visibility_exact = all(
        response.get("visible_projects") == expected_visible
        and response.get("candidate_projects") == expected_visible
        for response in public_focus
    )
    old_focus_removed = all(
        response.get("context_detail_projects") == [focus_sequence[index]]
        for index, response in enumerate(public_focus)
    )
    resumed_current = (
        public_focus[-1].get("project_id") == focus_sequence[0]
        and public_focus[-1].get("revision", 0) > public_focus[0].get("revision", 0)
        and public_focus[-1].get("source_generation") == generations[-1]
    )

    no_egress = __import__("os").environ.get("CIGAR_DEMO_NO_EGRESS") != ""
    no_egress = (
        no_egress
        and __import__("os").environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable")
        != "unavailable"
    )
    setup = [
        step("isolated-home", "product_observed", {"home_under_state": True}),
        step(
            "four-project-workspace",
            "product_observed",
            {"project_count": len(projects), "tree_ids": before},
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
        step("link-permitted-dependencies", "product_observed", linked),
        *[
            step(
                flow_id,
                "product_observed"
                if public.get("project_id") == observation["project"]
                else "not_observed",
                {"local": observation, "public": public},
            )
            for flow_id, observation, public in zip(
                fixture["flow"][1:],
                focus_observations,
                public_focus,
                strict=True,
            )
        ],
    ]
    assertions = [
        assertion(
            "unattached-project-hidden",
            "product_observed"
            if visible_exact and forbidden <= hidden and public_visibility_exact
            else "not_observed",
            {"visible": visible, "hidden_count": len(hidden)},
        ),
        assertion(
            "forbidden-project-hidden",
            "product_observed"
            if forbidden <= hidden and public_visibility_exact
            else "not_observed",
            {
                "visible_count": len(visible),
                "forbidden_visible_count": len(forbidden & set(visible)),
            },
        ),
        assertion(
            "old-focus-detail-removed",
            "product_observed" if final_only and old_focus_removed else "not_observed",
            {
                "single_active_focus": final_only,
                "public_context_replaced": old_focus_removed,
            },
        ),
        assertion(
            "resume-uses-current-revision",
            "product_observed"
            if generation_current and resumed_current
            else "not_observed",
            {
                "generation_count": len(generations),
                "strictly_increasing": generation_current,
                "public_resume_current": resumed_current,
            },
        ),
        assertion(
            "filesystem-authority-unchanged",
            "product_observed" if authority_unchanged else "not_observed",
            {"tree_identity_unchanged": authority_unchanged},
        ),
    ]
    removed_workspace = remove_tree(workspace)
    removed_home = remove_tree(args.state / "home")
    removed_state = remove_tree(args.state / "cli-state") and remove_tree(
        args.state / "recorded-api-requests"
    )
    teardown = [
        step("remove-isolated-home", "fixture_observed", {"removed": removed_home}),
        step("remove-workspace", "fixture_observed", {"removed": removed_workspace}),
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
            "initialized": initialized["result"].get("initialized") is True,
            "attached_project_count": len(attached),
            "visible_project_count": len(visible),
            "focus_transition_count": len(focus_observations),
            "workspace_removed": removed_workspace,
            "public_focus_count": len(public_focus),
            "driver_scope": "fixture-bound-local-and-public-cli-recorded-api",
        },
    )


if __name__ == "__main__":
    try:
        run()
    except DriverError as error:
        raise SystemExit(main_error(error))
