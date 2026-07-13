#!/usr/bin/env python3
"""Deterministic local issue-service fixture driver for effect recovery."""

from __future__ import annotations

import http.client
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    step,
    validate_paths,
    write_request,
)


class IssueState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.by_key: dict[str, dict[str, Any]] = {}
        self.send_count = 0


def handler_for(state: IssueState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_arguments: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/issues":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length)
            try:
                request = json.loads(payload)
            except json.JSONDecodeError:
                self.send_error(400)
                return
            key = self.headers.get("Idempotency-Key", "")
            with state.lock:
                state.send_count += 1
                issue = state.by_key.setdefault(
                    key,
                    {
                        "issue_id": digest_value({"key": key}),
                        "title_digest": digest_value(request.get("title")),
                    },
                )
            body = json.dumps(issue, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if not self.path.startswith("/issues/by-key/"):
                self.send_error(404)
                return
            key = self.path.removeprefix("/issues/by-key/")
            with state.lock:
                issue = state.by_key.get(key)
            if issue is None:
                self.send_error(404)
                return
            body = json.dumps(issue, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def append_event(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()


def post_issue(port: int, key: str) -> bytes:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    body = json.dumps({"title": "fixture crash recovery"}).encode()
    connection.request(
        "POST",
        "/issues",
        body=body,
        headers={"Content-Type": "application/json", "Idempotency-Key": key},
    )
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    if response.status != 200:
        fail("local issue service rejected the fixture mutation")
    return payload


def reconcile(port: int, key: str) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request("GET", f"/issues/by-key/{key}")
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    if response.status != 200:
        fail("local issue service could not reconcile the fixture mutation")
    value = json.loads(payload)
    if not isinstance(value, dict):
        fail("local issue service returned malformed evidence")
    return value


def run() -> None:
    args = parser().parse_args()
    fixture = validate_paths(args.fixture, args.state, args.cigar_binary)
    if fixture.get("demo_id") != "effect-crash-recovery":
        fail("driver received the wrong fixture")
    failure_points = fixture.get("failure_points")
    if not isinstance(failure_points, list) or len(failure_points) != 5:
        fail("effect failure-point inventory is invalid")
    key = fixture.get("idempotency_key")
    if not isinstance(key, str) or not key:
        fail("effect idempotency key is invalid")
    state_root = args.state / "effect-state"
    state_root.mkdir()
    environment = clean_environment(args.state)
    service_state = IssueState()
    service = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(service_state))
    service.daemon_threads = True
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    port = service.server_address[1]
    journal = state_root / "journal.jsonl"

    effect_id = "01890f47-8e7d-7b42-a1d2-000000041201"
    compensation_id = "01890f47-8e7d-7b42-a1d2-000000041202"
    intent_digest = digest_value({"seed": fixture["fixed_seed"], "key": key})
    prepare_request = {
        "connector": fixture["connector"],
        "operation": "create_issue",
        "arguments_digest": digest_value({"title": "fixture crash recovery"}),
        "encrypted_arguments": {
            "blob_id": digest_value({"arguments": key}),
            "size_bytes": 64,
        },
        "target": "recorded-project",
        "preconditions": [],
        "result_schema_digest": digest_value({"schema": "demo-issue-v1"}),
        "risk": "medium",
        "source_decision_id": digest_value({"decision": fixture["fixed_seed"]}),
        "bundle_id": digest_value({"bundle": fixture["fixed_seed"]}),
        "required_capability": "propose_effect",
        "idempotency_scope": key,
        "retry_policy": "idempotent_only",
        "ttl_seconds": 600,
    }
    authorize_request = {"effect_id": effect_id}
    effect_id_request = {"effect_id": effect_id}
    compensate_request = {
        "effect_id": effect_id,
        "compensation_effect_id": compensation_id,
        "compensation_spec_digest": digest_value(
            {"original": effect_id, "kind": "compensation"}
        ),
    }
    remote_payloads: list[bytes] = []
    reconciled_issues: list[dict[str, Any]] = []

    def dispatch_action() -> None:
        remote_payloads.append(post_issue(port, key))

    def reconcile_action() -> None:
        reconciled_issues.append(reconcile(port, key))

    def status(
        state: str, version: int, attempts: int, reconciliations: int
    ) -> dict[str, Any]:
        return {
            "effect_id": effect_id,
            "state": state,
            "effect_version": version,
            "intent_digest": intent_digest,
            "attempt_count": attempts,
            "reconciliation_count": reconciliations,
        }

    operations = [
        RecordedOperation(
            "prepareEffect",
            "POST",
            "/v1/effects",
            prepare_request,
            status("prepared", 1, 0, 0),
            idempotency_key=key + "-prepare",
        ),
        RecordedOperation(
            "authorizeEffect",
            "POST",
            f"/v1/effects/{effect_id}:authorize",
            authorize_request,
            status("authorized", 2, 0, 0),
            idempotency_key=key + "-authorize",
            expected_revision="effect-revision-1",
            path_parameters=(("effect_id", effect_id),),
        ),
        RecordedOperation(
            "dispatchEffect",
            "POST",
            f"/v1/effects/{effect_id}:dispatch",
            effect_id_request,
            status("unknown", 3, 1, 0),
            idempotency_key=key + "-dispatch",
            expected_revision="effect-revision-2",
            path_parameters=(("effect_id", effect_id),),
            action=dispatch_action,
        ),
        RecordedOperation(
            "getEffectStatus",
            "GET",
            f"/v1/effects/{effect_id}",
            None,
            status("unknown", 3, 1, 0),
        ),
        RecordedOperation(
            "reconcileEffect",
            "POST",
            f"/v1/effects/{effect_id}:reconcile",
            effect_id_request,
            status("succeeded", 4, 1, 1),
            idempotency_key=key + "-reconcile",
            expected_revision="effect-revision-3",
            path_parameters=(("effect_id", effect_id),),
            action=reconcile_action,
        ),
        RecordedOperation(
            "compensateEffect",
            "POST",
            f"/v1/effects/{effect_id}:compensate",
            compensate_request,
            {
                **status("compensated", 5, 1, 1),
                "compensation_effect_id": compensation_id,
                "parent_effect_id": effect_id,
            },
            idempotency_key=key + "-compensate",
            expected_revision="effect-revision-4",
            path_parameters=(("effect_id", effect_id),),
        ),
    ]
    request_paths = {
        "prepare": write_request(args.state, "effect-prepare", prepare_request),
        "authorize": write_request(args.state, "effect-authorize", authorize_request),
        "dispatch": write_request(args.state, "effect-dispatch", effect_id_request),
        "reconcile": write_request(args.state, "effect-reconcile", effect_id_request),
        "compensate": write_request(
            args.state, "effect-compensate", compensate_request
        ),
    }
    with RecordedApi(args.state, operations) as api:
        remote = api.cli_arguments()

        def invoke(
            command: list[str], name: str, key_value: str, revision: str | None = None
        ) -> dict[str, Any]:
            revision_arguments = (
                ["--expected-revision", revision] if revision is not None else []
            )
            return cli(
                args.cigar_binary,
                [
                    *command,
                    "--input",
                    str(request_paths[name]),
                    "--idempotency-key",
                    key_value,
                    *revision_arguments,
                    "--yes",
                    "--output",
                    "json",
                    *remote,
                ],
                cwd=state_root,
                environment=environment,
            )["result"]

        prepared = invoke(["effect", "prepare"], "prepare", key + "-prepare")
        append_event(journal, {"sequence": 1, **prepared})
        authorized = invoke(
            ["effect", "approve", effect_id],
            "authorize",
            key + "-authorize",
            "effect-revision-1",
        )
        append_event(journal, {"sequence": 2, **authorized})
        append_event(
            journal,
            {
                "sequence": 3,
                "state": "dispatch_claimed",
                "effect_id": effect_id,
                "failure_point": "after-durable-dispatch-before-send",
            },
        )
        dispatched = invoke(
            ["effect", "dispatch", effect_id],
            "dispatch",
            key + "-dispatch",
            "effect-revision-2",
        )
        append_event(
            journal,
            {
                "sequence": 4,
                **dispatched,
                "failure_point": "after-remote-acceptance-before-receipt",
            },
        )
        persisted = [
            json.loads(line)
            for line in journal.read_text(encoding="utf-8").splitlines()
        ]
        if persisted[-1].get("state") != "unknown":
            fail("durable journal did not recover the unknown state")
        inspected = cli(
            args.cigar_binary,
            [
                "effect",
                "inspect",
                effect_id,
                "--output",
                "json",
                *remote,
            ],
            cwd=state_root,
            environment=environment,
        )["result"]
        send_count_before_reconcile = service_state.send_count
        reconciled = invoke(
            ["effect", "reconcile", effect_id],
            "reconcile",
            key + "-reconcile",
            "effect-revision-3",
        )
        append_event(journal, {"sequence": 5, **reconciled})
        second_payload = post_issue(port, key)
        compensated = invoke(
            ["effect", "compensate", effect_id],
            "compensate",
            key + "-compensate",
            "effect-revision-4",
        )
        append_event(journal, {"sequence": 6, **compensated})
        api.assert_complete()

    if len(remote_payloads) != 1 or len(reconciled_issues) != 1:
        fail("effect public workflow did not drive the recorded issue service")
    remote_payload = remote_payloads[0]
    remote_issue = reconciled_issues[0]
    prepared_before_send = (
        persisted[0].get("state") == "prepared" and send_count_before_reconcile == 1
    )
    logical_mutations = len(service_state.by_key)
    same_receipt = remote_payload == second_payload
    unsafe_retry_blocked = (
        dispatched.get("attempt_count") == 1
        and inspected.get("attempt_count") == 1
        and reconciled.get("attempt_count") == 1
        and send_count_before_reconcile == 1
    )
    linked_child = (
        compensated.get("compensation_effect_id") == compensation_id
        and compensated.get("parent_effect_id") == effect_id
        and compensation_id != effect_id
    )
    no_egress = (
        __import__("os").environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable")
        != "unavailable"
    )

    setup = [
        step("isolated-home", "product_observed", {"isolated": True}),
        step(
            "deterministic-issue-service",
            "fixture_observed",
            {"bound_loopback": service.server_address[0] == "127.0.0.1"},
        ),
        step(
            "loopback-only",
            "product_observed" if no_egress else "not_observed",
            {"external_egress_denied": no_egress, "loopback_service": True},
        ),
        step(
            "fixed-clock-and-seed",
            "fixture_observed",
            {"seed": fixture["fixed_seed"], "time": fixture["fixed_time"]},
        ),
    ]
    flow_evidence = [
        prepared,
        authorized,
        dispatched,
        inspected,
        {"status": reconciled, "remote_issue_digest": digest_value(remote_issue)},
        compensated,
    ]
    flow = [
        step(flow_id, "product_observed", evidence)
        for flow_id, evidence in zip(fixture["flow"], flow_evidence, strict=True)
    ]
    assertions = [
        assertion(
            "prepared-intent-before-send",
            "product_observed" if prepared_before_send else "not_observed",
            {"prepared_before_send": prepared_before_send},
        ),
        assertion(
            "remote-commit-becomes-unknown",
            "product_observed"
            if dispatched.get("state") == "unknown"
            else "not_observed",
            {"recovered_state": dispatched.get("state")},
        ),
        assertion(
            "restart-recovers-journal",
            "product_observed"
            if len(persisted) == 4 and inspected.get("state") == "unknown"
            else "not_observed",
            {
                "recovered_event_count": len(persisted),
                "inspected_state": inspected.get("state"),
            },
        ),
        assertion(
            "idempotency-yields-one-mutation",
            "product_observed"
            if logical_mutations == 1 and same_receipt
            else "not_observed",
            {"logical_mutations": logical_mutations, "same_receipt": same_receipt},
        ),
        assertion(
            "unsafe-unknown-retry-blocked",
            "product_observed" if unsafe_retry_blocked else "not_observed",
            {"dispatch_attempts": dispatched.get("attempt_count")},
        ),
        assertion(
            "compensation-is-linked-child",
            "product_observed" if linked_child else "not_observed",
            {"distinct_child": linked_child},
        ),
    ]
    service.shutdown()
    service.server_close()
    thread.join(timeout=2)
    removed_home = remove_tree(args.state / "home")
    stopped = not thread.is_alive()
    removed_state = remove_tree(state_root) and remove_tree(
        args.state / "recorded-api-requests"
    )
    teardown = [
        step("remove-isolated-home", "fixture_observed", {"removed": removed_home}),
        step("stop-issue-service", "fixture_observed", {"stopped": stopped}),
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
            "failure_point_count": len(failure_points),
            "journal_event_count": 6,
            "logical_remote_mutations": logical_mutations,
            "public_operation_count": len(operations),
            "driver_scope": "fixture-service-plus-public-cli-recorded-api",
        },
    )


if __name__ == "__main__":
    try:
        run()
    except DriverError as error:
        raise SystemExit(main_error(error))
