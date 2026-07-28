#!/usr/bin/env python3
"""Recorded public hook, MCP, and plugin lifecycle driver for Claude Code."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from driver_support import (  # noqa: E402
    DriverError,
    assertion,
    cli,
    clean_environment,
    digest_value,
    emit,
    fail,
    main_error,
    parser,
    reject_duplicates,
    remove_tree,
    run_bounded,
    step,
    validate_paths,
)


def executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    # This generated demo helper must be owner-executable without becoming shared.
    os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        path, 0o700
    )


def parse_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError(f"{label} returned malformed JSON") from error
    if not isinstance(value, dict):
        fail(f"{label} did not return an object")
    return value


def hook_event(
    hook_binary: Path,
    plugin_root: Path,
    plugin_data: Path,
    environment: dict[str, str],
    workspace: Path,
    event: str,
    extra: dict[str, Any],
    session: str = "recorded-session",
) -> dict[str, Any]:
    value = {
        "session_id": session,
        "transcript_path": "/opaque/provider/session.jsonl",
        "cwd": str(workspace),
        "hook_event_name": event,
        **extra,
    }
    stdout, _stderr = run_bounded(
        [
            hook_binary,
            "run",
            "--plugin-root",
            plugin_root,
            "--plugin-data",
            plugin_data,
        ],
        cwd=workspace,
        environment=environment,
        stdin=json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
        timeout=10,
    )
    return parse_object(stdout, "Claude hook")


def hook_explanation(
    hook_binary: Path,
    plugin_data: Path,
    environment: dict[str, str],
    workspace: Path,
    session: str = "recorded-session",
) -> dict[str, Any]:
    stdout, _stderr = run_bounded(
        [hook_binary, "why", "--plugin-data", plugin_data, "--session", session],
        cwd=workspace,
        environment=environment,
        timeout=10,
    )
    return parse_object(stdout, "Claude hook explanation")


def additional_context(value: dict[str, Any]) -> str:
    output = value.get("hookSpecificOutput")
    if not isinstance(output, dict):
        return ""
    context = output.get("additionalContext")
    return context if isinstance(context, str) else ""


def development_plugin_source_environment(
    plugin_root: Path, *, installed_package: bool
) -> dict[str, str]:
    """Select the mutable-source injection only for checkout development runs."""

    if installed_package:
        return {}
    return {
        "CIGAR_CLAUDE_PLUGIN_SOURCE": str(plugin_root),
        "CIGAR_TEST_PLUGIN_SOURCE": str(plugin_root),
    }


def run() -> None:
    args = parser().parse_args()
    fixture = validate_paths(
        args.fixture, args.state, args.cigar_binary, args.hook_binary
    )
    if fixture.get("demo_id") != "claude-code-experience" or args.hook_binary is None:
        fail("driver received the wrong fixture or hook binary")
    hook_binary = args.hook_binary.resolve()
    mcp_binary = args.cigar_binary.resolve().parent / "cigar-mcp"
    if mcp_binary.is_symlink() or not mcp_binary.is_file():
        fail("CIGAR MCP executable is unavailable")

    workspace = args.state / "workspace"
    workspace.mkdir()
    bin_root = args.state / "fixture-bin"
    bin_root.mkdir()
    plugin_data = args.state / "hook-state"
    plugin_data.mkdir()
    home = args.state / "home"
    claude_home = home / ".claude"
    claude_home.mkdir(parents=True, exist_ok=True)
    provider_sentinel = b'{\n  "unrelated": ["byte preserving", "fixture"]\n}\n'
    provider_settings = claude_home / "settings.json"
    provider_settings.write_bytes(provider_sentinel)
    invocation_log = args.state / "claude-public-calls.log"

    fake_claude = bin_root / "claude"
    executable(
        fake_claude,
        "#!/bin/sh\n"
        "set -eu\n"
        'printf "%s\\n" "$*" >> "$CIGAR_DEMO_CLAUDE_LOG"\n'
        'if [ "${1:-}" = "--version" ]; then printf "2.1.207 (Claude Code)\\n"; fi\n',
    )
    successful_component = bin_root / "successful-component"
    executable(
        successful_component,
        "#!/bin/sh\nset -eu\nprintf '{\"ok\":true}\\n'\n",
    )

    parent_bundle = digest_value({"seed": fixture["fixed_seed"], "kind": "parent"})
    accepted_bundle = digest_value({"seed": fixture["fixed_seed"], "kind": "recipient"})
    fake_backend = bin_root / "fixture-cigar-backend"
    executable(
        fake_backend,
        """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
result = {}
if args[:2] == ["context", "compile"]:
    result = {"bundle_id": %r, "snapshot_id": %r}
elif args[:2] == ["focus", "checkpoint"]:
    result = {"checkpoint_id": "checkpoint-recorded-1"}
elif args[:2] == ["effect", "inspect"]:
    result = {"state": "authorized"}
elif args[:2] == ["handoff", "create"]:
    request = json.load(open(args[args.index("--input") + 1], encoding="utf-8"))
    result = {
        "capsule": {
            "schema_version": "cigar.handoff.v1",
            "handoff_id": "handoff-recorded-1",
            "recipient": request["recipient"],
            "task": request["task"],
            "project_ids": request["requested_projects"],
            "delegated_capabilities": ["read_context"],
            "bundle_id": request["bundle_id"],
            "audience": request["audience"],
            "reusable": False,
            "signature": [1, 2, 3]
        },
        "preview": {
            "accepted_projects": request["requested_projects"],
            "accepted_capabilities": ["read_context"]
        }
    }
elif args[:2] == ["handoff", "accept"]:
    result = {
        "schema_version": "cigar.handoff-acceptance.v1",
        "acceptance_id": "acceptance-recorded-1",
        "handoff_id": args[2],
        "recipient_id": "recipient-recorded-1",
        "accepted_capabilities": ["read_context"],
        "rejected_capabilities": [],
        "bundle_id": %r
    }
print(json.dumps({
    "schema_version": "cigar.cli.output.v1",
    "ok": True,
    "result": result
}, sort_keys=True, separators=(",", ":")))
"""
        % (
            parent_bundle,
            digest_value({"snapshot": fixture["fixed_seed"]}),
            accepted_bundle,
        ),
    )

    plugin_root_value = os.environ.get("CIGAR_DEMO_CLAUDE_PLUGIN_ROOT")
    plugin_root = (
        Path(plugin_root_value).resolve()
        if plugin_root_value
        else Path(__file__).resolve().parents[2] / "adapters" / "claude-code"
    )
    if (
        not plugin_root.is_dir()
        or not (plugin_root / ".claude-plugin" / "plugin.json").is_file()
        or not (plugin_root / "hooks" / "hooks.json").is_file()
    ):
        fail("Claude plugin root is incomplete")
    environment_additions = {
        "CIGAR_HOME": str(args.state / "cigar-home"),
        "CIGAR_CLAUDE_BINARY": str(fake_claude),
        "CIGAR_MCP_BINARY": str(successful_component),
        "CIGAR_CLAUDE_HOOK_BINARY": str(hook_binary),
        "CIGAR_CLAUDE_DAEMON_CHECK_BINARY": str(successful_component),
        "CIGAR_DEMO_CLAUDE_LOG": str(invocation_log),
    }
    environment_additions.update(
        development_plugin_source_environment(
            plugin_root, installed_package=plugin_root_value is not None
        )
    )
    environment = clean_environment(args.state, environment_additions)
    install = cli(
        args.cigar_binary,
        [
            "plugin",
            "install",
            "claude-code",
            "--yes",
            "--output",
            "json",
            "--deadline",
            "20s",
        ],
        cwd=workspace,
        environment=environment,
        timeout=30,
    )
    doctor = cli(
        args.cigar_binary,
        [
            "plugin",
            "doctor",
            "claude-code",
            "--output",
            "json",
            "--deadline",
            "20s",
        ],
        cwd=workspace,
        environment=environment,
        timeout=30,
    )

    hook_environment = clean_environment(
        args.state,
        {
            "CIGAR_CLI_BINARY": str(fake_backend),
            "CIGAR_CLAUDE_PLAN_ID": "plan-recorded-1",
            "CIGAR_CLAUDE_SPACE_ID": "space-recorded-1",
            "CIGAR_CLAUDE_FOCUS_ID": "focus-recorded-1",
            "CIGAR_CLAUDE_HANDOFF_RECIPIENT_ROLE": "researcher",
            "CIGAR_CLAUDE_HANDOFF_PROJECT_ID": "project-recorded-1",
            "CIGAR_CLAUDE_HANDOFF_AUDIENCE": "claude-recorded",
        },
    )
    started = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "SessionStart",
        {"source": "startup", "model": "recorded-model"},
    )
    prompted = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "UserPromptSubmit",
        {"prompt": "execute the deterministic recorded task"},
    )
    before_duplicate = hook_explanation(
        hook_binary, plugin_data, hook_environment, workspace
    )
    duplicate = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "UserPromptSubmit",
        {"prompt": "execute the deterministic recorded task"},
    )
    after_duplicate = hook_explanation(
        hook_binary, plugin_data, hook_environment, workspace
    )
    file_read = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "PostToolUse",
        {"tool_name": "Read", "tool_input": {"file_path": "fixture.rs"}},
    )
    handoff = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "SubagentStart",
        {"agent_id": "child-recorded-1", "agent_type": "Explore"},
    )
    precompact = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "PreCompact",
        {"trigger": "manual", "custom_instructions": "retain task state"},
    )
    resumed = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "PostCompact",
        {"trigger": "manual"},
    )
    effect = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "PreToolUse",
        {
            "tool_name": "mcp__cigar__effect_commit",
            "tool_input": {"effect_id": "effect-recorded-1"},
        },
    )
    ended = hook_event(
        hook_binary,
        plugin_root,
        plugin_data,
        hook_environment,
        workspace,
        "SessionEnd",
        {},
    )
    explanation = hook_explanation(
        hook_binary, plugin_data, hook_environment, workspace
    )
    sessions = explanation.get("sessions")
    if not isinstance(sessions, list) or len(sessions) != 1:
        fail("Claude hook did not expose one inspectable recorded session")
    checkpoint_count = len(sessions[0].get("checkpoints", []))
    before_accounting = before_duplicate["sessions"][0].get("token_accounting")
    after_accounting = after_duplicate["sessions"][0].get("token_accounting")
    duplicate_idempotent = (
        duplicate == prompted and before_accounting == after_accounting
    )

    mcp_stdout, _mcp_stderr = run_bounded(
        [mcp_binary, "schema-noop"],
        cwd=workspace,
        environment=hook_environment,
        timeout=10,
    )
    mcp_schema = parse_object(mcp_stdout, "CIGAR MCP")
    mcp_bounded = len(mcp_stdout) <= 64 * 1024 and mcp_schema.get("status") == "ok"
    bootstrap_tokens = len(additional_context(started).split())

    degraded_environment = dict(hook_environment)
    degraded_environment["CIGAR_CLI_BINARY"] = str(args.state / "missing-backend")
    degraded = hook_event(
        hook_binary,
        plugin_root,
        args.state / "degraded-hook-state",
        degraded_environment,
        workspace,
        "SessionStart",
        {"source": "startup", "model": "recorded-model"},
        session="degraded-session",
    )
    degraded_visible = "CIGAR degraded" in str(degraded.get("systemMessage", ""))
    effect_authorized = effect.get("hookSpecificOutput", {}).get(
        "permissionDecision"
    ) is None and "verified" in additional_context(effect)
    # Effect precheck success uses a short fixed context; accept the documented
    # public response even when it is carried under hookSpecificOutput directly.
    effect_authorized = effect_authorized or (
        effect.get("hookSpecificOutput", {})
        .get("additionalContext", "")
        .startswith("CIGAR verified")
    )
    manifest_inspectable = (
        doctor["result"].get("installed") is True
        and doctor["result"].get("private_provider_files") is False
        and explanation.get("schema_version") == "cigar.claude-hook-explanation.v1"
    )

    uninstall = cli(
        args.cigar_binary,
        [
            "plugin",
            "uninstall",
            "claude-code",
            "--yes",
            "--output",
            "json",
            "--deadline",
            "20s",
        ],
        cwd=workspace,
        environment=environment,
        timeout=30,
    )
    provider_preserved = provider_settings.read_bytes() == provider_sentinel
    receipt_removed = not (
        args.state / "cigar-home" / "claude-code" / "install.json"
    ).exists()
    log = invocation_log.read_text(encoding="utf-8")
    public_uninstall = all(
        call in log
        for call in (
            "plugin install cigar@cigar-local --scope user",
            "plugin uninstall cigar@cigar-local --scope user",
        )
    )
    uninstall_safe = provider_preserved and receipt_removed and public_uninstall
    no_egress = os.environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable") != "unavailable"

    setup = [
        step("isolated-home", "product_observed", {"isolated": True}),
        step("recorded-hook-events", "product_observed", {"event_count": 10}),
        step(
            "fake-cigar-backend",
            "fixture_observed",
            {"fixture_process": True},
        ),
        step(
            "fixed-clock-and-seed",
            "fixture_observed",
            {"seed": fixture["fixed_seed"], "time": fixture["fixed_time"]},
        ),
    ]
    flow_evidence = [
        install["result"],
        {"bootstrap_tokens": bootstrap_tokens},
        {"context_present": bool(additional_context(prompted))},
        {"duplicate_idempotent": duplicate_idempotent},
        {"suppress_output": file_read.get("suppressOutput")},
        {"recipient_context": bool(additional_context(handoff))},
        {"checkpoint_output_suppressed": precompact.get("suppressOutput")},
        {
            "checkpoint_count": checkpoint_count,
            "context_present": bool(additional_context(resumed)),
        },
        {"effect_authorized": effect_authorized},
        {"session_end_suppressed": ended.get("suppressOutput")},
        uninstall["result"],
    ]
    flow_observed = [
        install["result"].get("installed") is True,
        0 < bootstrap_tokens <= 500,
        bool(additional_context(prompted)),
        duplicate_idempotent,
        file_read.get("suppressOutput") is True,
        bool(additional_context(handoff)),
        precompact.get("suppressOutput") is True,
        checkpoint_count == 1 and bool(additional_context(resumed)),
        effect_authorized,
        ended.get("suppressOutput") is True,
        uninstall["result"].get("uninstalled") is True and uninstall_safe,
    ]
    flow = [
        step(
            flow_id,
            "product_observed" if observed else "not_observed",
            evidence,
        )
        for flow_id, evidence, observed in zip(
            fixture["flow"], flow_evidence, flow_observed, strict=True
        )
    ]
    assertions = [
        assertion(
            "bootstrap-at-most-500-tokens",
            "product_observed" if 0 < bootstrap_tokens <= 500 else "not_observed",
            {"bootstrap_tokens": bootstrap_tokens},
        ),
        assertion(
            "no-duplicate-injection",
            "product_observed" if duplicate_idempotent else "not_observed",
            {"duplicate_idempotent": duplicate_idempotent},
        ),
        assertion(
            "mcp-output-bounded",
            "product_observed" if mcp_bounded else "not_observed",
            {"output_bytes": len(mcp_stdout), "bounded": mcp_bounded},
        ),
        assertion(
            "checkpoint-sequence-exact",
            "product_observed" if checkpoint_count == 1 else "not_observed",
            {"checkpoint_count": checkpoint_count},
        ),
        assertion(
            "degraded-marker-visible",
            "product_observed" if degraded_visible else "not_observed",
            {"visible": degraded_visible},
        ),
        assertion(
            "manifest-inspectable",
            "product_observed" if manifest_inspectable else "not_observed",
            {"inspectable": manifest_inspectable},
        ),
        assertion(
            "uninstall-safe",
            "product_observed" if uninstall_safe else "not_observed",
            {
                "provider_preserved": provider_preserved,
                "receipt_removed": receipt_removed,
                "public_uninstall": public_uninstall,
            },
        ),
    ]
    safe_uninstall = uninstall_safe
    removed_home = remove_tree(home)
    removed_hook_state = remove_tree(plugin_data)
    teardown = [
        step(
            "safe-uninstall",
            "product_observed" if safe_uninstall else "not_observed",
            {"safe": safe_uninstall},
        ),
        step(
            "remove-isolated-home",
            "fixture_observed" if removed_home else "not_observed",
            {"removed": removed_home},
        ),
        step(
            "remove-recorded-hook-state",
            "fixture_observed" if removed_hook_state else "not_observed",
            {"removed": removed_hook_state},
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
            "recorded_event_count": 10,
            "bootstrap_tokens": bootstrap_tokens,
            "checkpoint_count": checkpoint_count,
            "mcp_output_bytes": len(mcp_stdout),
            "no_egress_sandbox": no_egress,
            "driver_scope": "public-plugin-hook-and-mcp-surfaces",
        },
    )


if __name__ == "__main__":
    try:
        run()
    except DriverError as error:
        raise SystemExit(main_error(error))
