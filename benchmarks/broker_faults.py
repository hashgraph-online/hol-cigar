"""Deterministic real-process fault schedule, separate from load denominators.

These authored invariants exercise the production SDK and worker. A private
Python protocol driver holds incomplete authenticated connections; it is never
counted as one of the measured application clients. No model/provider is used.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time

from broker_load import (
    CONFIG,
    PROVENANCE,
    Consumer,
    cleanup,
    fixture,
    no_credentials,
    runtime_for,
)
from broker_storage import encoded


class ScheduleFailure(RuntimeError):
    pass


class Transcript:
    def __init__(self):
        self.events = []

    def check(self, name, observed, expected=None):
        no_credentials(observed)
        expected = {"status": "ok"} if expected is None else expected
        passed = isinstance(observed, dict) and all(
            observed.get(key) == value for key, value in expected.items()
        )
        self.events.append(
            {"name": name, "expected": expected, "observed": observed, "passed": passed}
        )
        if not passed:
            raise ScheduleFailure(name)
        return observed

    def require(self, name, condition, **details):
        self.check(name, {"status": "ok" if condition else "failed", **details})

    def auth_denied(self, name, outcome):
        self.require(
            name,
            outcome.get("status") == "error"
            and outcome.get("code") in {"Authentication", "Transport", "AccessDenied"}
            and outcome.get("dispatched") is False,
            outcome=outcome,
        )


def host_observed(operation):
    from cigar_sdk import LocalBrokerError

    start = time.perf_counter_ns()
    try:
        value = operation()
        result = {"status": "ok", "value": value}
    except LocalBrokerError as error:
        result = {"status": "error", "code": error.code, "dispatched": error.dispatched}
    return {**result, "elapsed_ms": (time.perf_counter_ns() - start) / 1e6}


def run_faults(args):
    from cigar_sdk import LocalContextBroker

    configuration = json.loads(CONFIG.read_text())
    workload = fixture(configuration, args.agents)
    transcript = Transcript()
    actors, extra_actors, connections = [], [], []
    broker = None
    failure = None
    initial_identity = hashlib.sha256(encoded(workload)).hexdigest()

    def check_actor(agent, name, command, expected=None):
        return transcript.check(
            f"agent-{agent}:{name}", actors[agent].request(command), expected
        )

    def retain(agent, slot):
        response = actors[agent].request({"op": "retain", "slot": slot})
        ticket = response.pop("private_ticket", None)
        transcript.check(f"agent-{agent}:retain-{slot}", response)
        transcript.require(
            f"agent-{agent}:private-ticket-{slot}",
            isinstance(ticket, str) and len(ticket) == 64,
        )
        return ticket

    def current_documents(agent):
        return [
            document
            for source in workload["agents"][agent]["view"]["allowed_sources"]
            for document in workload["documents"][source]
        ]

    def configure(agent, connection):
        oracle = workload["agents"][agent]
        check_actor(
            agent,
            "explicit-configure",
            {
                "op": "configure",
                "connection": connection.export(),
                "required_documents": oracle["required_documents"],
                "request": oracle["request"],
                "scope_documents": len(current_documents(agent)),
            },
        )

    def verify_all(phase):
        # Dispatch every independent actor before collecting its result.
        for agent, actor in enumerate(actors):
            documents = current_documents(agent)
            actor.send(
                {
                    "op": "verify_documents",
                    "documents": documents,
                    "scope_documents": len(documents),
                }
            )
        results = []
        for agent, actor in enumerate(actors):
            value = transcript.check(
                f"agent-{agent}:all-documents-{phase}",
                actor.receive(),
                {"status": "ok", "documents": len(current_documents(agent))},
            )
            results.append(value)
        return results

    def review(agent, slot, ticket, phase):
        submission = check_actor(
            agent, f"submit-{phase}", {"op": "submit", "slot": slot}
        )["submission_id"]
        details = broker.submission(ticket)
        transcript.require(
            f"submission-identity-{phase}", details["submission_id"] == submission
        )
        labels = [
            {"claim_key": key, "verdict": "supported"} for key in details["review_keys"]
        ]
        unreviewed = broker.check_answer(ticket, submission, [])
        transcript.require(
            f"missing-review-abstains-{phase}",
            unreviewed["assessment"]["decision"] == "abstain",
        )
        checked = broker.check_answer(ticket, submission, labels)
        transcript.require(
            f"host-reviewed-release-{phase}",
            checked["assessment"]["decision"] == "release",
        )
        return submission, labels

    with tempfile.TemporaryDirectory(prefix="cigar-broker-faults-") as temporary:
        storage = (
            {"directory": str(Path(temporary) / "store"), "create_directory": True}
            if args.storage == "sqlite"
            else None
        )
        options = {
            "worker_path": args.worker,
            "storage": storage,
            "transport": {
                "max_connections": 64,
                "max_connections_per_agent": 4,
                "frame_timeout_ms": 3000,
            },
        }
        try:
            broker = LocalContextBroker("broker-faults", **options)
            for source, documents in workload["documents"].items():
                if documents:
                    broker.replace_source(
                        source, broker.source_revision(source), documents, PROVENANCE
                    )
            for agent, oracle in enumerate(workload["agents"]):
                connection = broker.grant(oracle["view"])
                connections.append(connection)
                initial = {key: value for key, value in oracle.items() if key != "view"}
                initial.update(
                    connection=connection.export(),
                    call_timeout_ms=configuration["call_timeout_ms"],
                )
                actors.append(
                    Consumer(
                        runtime_for(args.runtime, agent),
                        args.node,
                        args.node_sdk,
                        args.python_sdk,
                        initial,
                    )
                )
            verify_all("initial")
            tickets = [retain(agent, "initial") for agent in range(args.agents)]
            old_submission, old_reviews = review(0, "initial", tickets[0], "initial")

            # A disallowed known ID and a nonexistent ID have the same content-free failure.
            for agent in range(args.agents):
                for node in ("sealed-0000", "no-such-document"):
                    request = {
                        **workload["agents"][agent]["request"],
                        "required": [node],
                    }
                    check_actor(
                        agent,
                        f"denied-required-{node}",
                        {"op": "compile_probe", "request": request},
                        {
                            "status": "error",
                            "code": "RequiredUnavailable",
                            "dispatched": True,
                        },
                    )
                if args.agents > 1:
                    check_actor(
                        agent,
                        "cross-owner-ticket",
                        {
                            "op": "foreign_ticket",
                            "private_ticket": tickets[(agent + 1) % args.agents],
                        },
                        {"status": "error", "code": "AccessDenied", "dispatched": True},
                    )

            source = "private-000"
            original = workload["documents"][source]
            revision = broker.source_revision(source)
            changed = copy.deepcopy(original)
            changed[0]["text"] = (
                "Changed private evidence; old instructions no longer apply."
            )
            for phase, documents in (
                ("changed", changed),
                ("withdrawn", []),
                ("change-back", original),
            ):
                receipt = broker.replace_source(
                    source,
                    revision,
                    documents,
                    {**PROVENANCE, "upstream_revision": phase},
                )
                transcript.require(
                    f"private-revision-{phase}",
                    int(receipt["revision"]["version"]) == int(revision["version"]) + 1,
                )
                revision = receipt["revision"]
                for agent in range(args.agents):
                    check_actor(
                        agent,
                        f"unaffected-or-stale-{phase}",
                        {"op": "revalidate", "slot": "initial"},
                        {"status": "error", "code": "Stale", "dispatched": True}
                        if agent == 0
                        else {"status": "ok"},
                    )
                transcript.check(
                    f"old-review-denied-{phase}",
                    host_observed(
                        lambda: broker.check_answer(
                            tickets[0], old_submission, old_reviews
                        )
                    ),
                    {"status": "error", "code": "Stale", "dispatched": True},
                )
                if phase == "withdrawn":
                    check_actor(
                        0,
                        "withdrawn-required",
                        {
                            "op": "compile_probe",
                            "request": workload["agents"][0]["request"],
                        },
                        {
                            "status": "error",
                            "code": "RequiredUnavailable",
                            "dispatched": True,
                        },
                    )

            # Two different proposals compare against one exact revision. Only the host admits.
            competition = broker.source_revision("competition")
            candidates = [
                {
                    "id": f"proposal-{name}",
                    "source": "competition",
                    "text": f"Evidence admitted from {name}.",
                }
                for name in ("winner", "loser")
            ]
            owners = [0, min(1, args.agents - 1)]
            proposals = []
            for index, owner in enumerate(owners):
                actors[owner].send(
                    {
                        "op": "proposal",
                        "request_key": f"cas-{index}",
                        "source": "competition",
                        "expected": competition,
                        "documents": [candidates[index]],
                    }
                )
                if owners[0] == owners[1]:
                    proposals.append(
                        transcript.check(f"proposal-{index}", actors[owner].receive())[
                            "proposal"
                        ]
                    )
            if owners[0] != owners[1]:
                for index, owner in enumerate(owners):
                    proposals.append(
                        transcript.check(f"proposal-{index}", actors[owner].receive())[
                            "proposal"
                        ]
                    )
            for index, proposal in enumerate(proposals):
                transcript.require(
                    f"proposal-{index}-pending",
                    proposal["outcome"]["status"] == "pending",
                )
            check_actor(
                0,
                "proposal-invisible-before-admission",
                {
                    "op": "compile_probe",
                    "request": {
                        **configuration["request"],
                        "required": [candidates[0]["id"]],
                    },
                },
                {"status": "error", "code": "RequiredUnavailable", "dispatched": True},
            )
            receipt = broker.admit_proposal(
                proposals[0]["proposal_id"],
                {**PROVENANCE, "origin": "reviewed_proposal"},
            )
            transcript.require(
                "one-committed-cas",
                int(receipt["revision"]["version"]) == int(competition["version"]) + 1,
            )
            transcript.check(
                "losing-cas-conflict",
                host_observed(
                    lambda: broker.admit_proposal(
                        proposals[1]["proposal_id"],
                        {**PROVENANCE, "origin": "reviewed_proposal"},
                    )
                ),
                {"status": "error", "code": "Conflict", "dispatched": True},
            )
            admitted = check_actor(
                owners[0],
                "winner-receipt",
                {"op": "proposal_status", "request_key": "cas-0"},
            )["proposal"]
            transcript.require(
                "winner-receipt-exact",
                admitted["outcome"] == {"status": "admitted", "receipt": receipt},
            )
            pending = check_actor(
                owners[1],
                "loser-still-pending",
                {"op": "proposal_status", "request_key": "cas-1"},
            )["proposal"]
            transcript.require(
                "conflict-did-not-admit-loser",
                pending["outcome"]["status"] == "pending",
            )
            broker.reject_proposal(proposals[1]["proposal_id"])
            rejected = check_actor(
                owners[1],
                "loser-reconciled",
                {"op": "proposal_status", "request_key": "cas-1"},
            )["proposal"]
            transcript.require(
                "loser-explicitly-rejected", rejected["outcome"]["status"] == "rejected"
            )
            workload["documents"]["competition"] = [candidates[0]]
            for agent in range(args.agents):
                configure(agent, connections[agent])
                check_actor(
                    agent,
                    "loser-never-visible",
                    {
                        "op": "compile_probe",
                        "request": {
                            **configuration["request"],
                            "required": [candidates[1]["id"]],
                        },
                    },
                    {
                        "status": "error",
                        "code": "RequiredUnavailable",
                        "dispatched": True,
                    },
                )

            transcript.require(
                "host-revokes-grant",
                broker.revoke(workload["agents"][0]["view"]["id"]) is True,
            )
            transcript.auth_denied(
                "revoked-grant-denied",
                actors[0].request(
                    {"op": "compile_probe", "request": workload["agents"][0]["request"]}
                ),
            )
            connections[0] = broker.grant(workload["agents"][0]["view"])
            configure(0, connections[0])
            check_actor(
                0,
                "redefined-grant-cannot-revive-ticket",
                {"op": "revalidate", "slot": "initial"},
                {"status": "error", "code": "AccessDenied", "dispatched": True},
            )
            for agent in range(1, args.agents):
                check_actor(
                    agent, "forget-old-ticket", {"op": "forget", "slot": "initial"}
                )

            # Retention quota is separate from connection/scheduler saturation.
            fresh_tickets = [retain(agent, "fresh") for agent in range(args.agents)]
            for index in range(15):
                retain(0, f"quota-{index}")
            check_actor(
                0,
                "bounded-ticket-quota",
                {"op": "compile_probe", "request": workload["agents"][0]["request"]},
                {"status": "error", "code": "Quota", "dispatched": True},
            )
            for agent in range(1, args.agents):
                check_actor(
                    agent,
                    "other-client-during-ticket-quota",
                    {"op": "warmup", "cycles": 1},
                )
            transcript.check(
                "host-progress-during-ticket-quota",
                host_observed(lambda: broker.source_revision("common")),
            )
            for index in range(15):
                check_actor(
                    0, "release-quota", {"op": "forget", "slot": f"quota-{index}"}
                )
            check_actor(
                0, "client-progress-after-ticket-quota", {"op": "warmup", "cycles": 1}
            )

            oracle = workload["agents"][0]
            attack_connection = broker.grant(
                {**oracle["view"], "id": "protocol-fault-driver"}
            )
            attacker = Consumer(
                "python",
                args.node,
                args.node_sdk,
                args.python_sdk,
                {
                    "connection": attack_connection.export(),
                    "call_timeout_ms": configuration["call_timeout_ms"],
                    "request": oracle["request"],
                    "required_documents": oracle["required_documents"],
                    "scope_documents": len(current_documents(0)),
                },
            )
            extra_actors.append(attacker)
            transcript.check(
                "incomplete-authenticated-connections",
                attacker.request({"op": "hold_connections"}),
                {"status": "ok", "attempted": 5, "held": 4, "rejected": 1},
            )
            for actor in actors:
                actor.send({"op": "warmup", "cycles": 1})
            for agent, actor in enumerate(actors):
                transcript.check(
                    f"agent-{agent}:progress-during-connection-quota", actor.receive()
                )
            transcript.check(
                "host-progress-during-connection-quota",
                host_observed(lambda: broker.source_revision("common")),
            )
            transcript.check(
                "connections-still-held",
                attacker.request({"op": "held_status"}),
                {"status": "ok", "held": 4},
            )
            transcript.check(
                "abandoned-driver-fully-reaped", attacker.terminate_for_fault()
            )
            for agent in range(args.agents):
                check_actor(
                    agent, "progress-after-driver-crash", {"op": "warmup", "cycles": 1}
                )
            transcript.require(
                "host-revokes-abandoned-grant",
                broker.revoke("protocol-fault-driver") is True,
            )

            before = verify_all("before-restart")
            if storage is not None:
                identity, reviews = review(
                    0, "fresh", fresh_tickets[0], "before-restart"
                )
                revisions = {
                    source: broker.source_revision(source)
                    for source in workload["documents"]
                }
                provenances = {
                    source: broker.provenance(source)
                    for source in workload["documents"]
                }
                staged = broker.begin_source_replace(
                    "common", revisions["common"], PROVENANCE
                )
                broker.append_source_documents(
                    staged,
                    [
                        {
                            "id": "uncommitted",
                            "source": "common",
                            "text": "Must never appear.",
                        }
                    ],
                )
                pending_key = "restart-pending"
                pending_owner = args.agents - 1
                check_actor(
                    pending_owner,
                    "proposal-before-restart",
                    {
                        "op": "proposal",
                        "request_key": pending_key,
                        "source": "competition",
                        "expected": revisions["competition"],
                        "documents": [candidates[1]],
                    },
                )
                broker._process.kill()
                broker._process.wait(timeout=5)
                broker.close()
                transcript.require("killed-worker-reaped", broker.cleanup_complete)
                broker = LocalContextBroker("broker-faults", **options)
                transcript.require(
                    "durable-checkpoint-restored",
                    broker.capabilities()["storage"]["restored"] is True,
                )
                for source, previous in revisions.items():
                    current = broker.source_revision(source)
                    transcript.require(
                        f"restored-revision-{source}",
                        current["version"] == previous["version"]
                        and current["epoch"] != previous["epoch"],
                    )
                    transcript.require(
                        f"restored-provenance-{source}",
                        broker.provenance(source) == provenances[source],
                    )
                transcript.check(
                    "old-source-authority-rejected",
                    host_observed(
                        lambda: broker.replace_source(
                            "common", revisions["common"], [], PROVENANCE
                        )
                    ),
                    {"status": "error", "code": "Conflict", "dispatched": True},
                )
                transcript.check(
                    "staged-write-never-restored",
                    host_observed(lambda: broker.commit_source_replace(staged)),
                    {"status": "error", "code": "Stale", "dispatched": True},
                )
                transcript.check(
                    "old-review-never-restored",
                    host_observed(
                        lambda: broker.check_answer(fresh_tickets[0], identity, reviews)
                    ),
                    {"status": "error", "code": "AccessDenied", "dispatched": True},
                )
                from cigar_sdk import LocalBrokerConnection

                stale_connection = LocalBrokerConnection(
                    broker.capabilities()["port"],
                    connections[0].epoch,
                    connections[0].secret,
                )
                configure(0, stale_connection)
                transcript.auth_denied(
                    "old-grant-at-new-listener-denied",
                    actors[0].request(
                        {"op": "compile_probe", "request": oracle["request"]}
                    ),
                )
                for agent in range(args.agents):
                    connections[agent] = broker.grant(workload["agents"][agent]["view"])
                    configure(agent, connections[agent])
                    check_actor(
                        agent,
                        "old-ticket-after-restart",
                        {"op": "revalidate", "slot": "fresh"},
                        {"status": "error", "code": "AccessDenied", "dispatched": True},
                    )
                check_actor(
                    pending_owner,
                    "pending-proposal-not-restored",
                    {"op": "proposal_status", "request_key": pending_key},
                    {"status": "error", "code": "AccessDenied", "dispatched": True},
                )
                after = verify_all("after-restart")
                transcript.require(
                    "all-admitted-source-text-survived",
                    before == after,
                    checked_documents=sum(row["documents"] for row in after),
                )
                check_actor(
                    0,
                    "staged-document-absent",
                    {
                        "op": "compile_probe",
                        "request": {
                            **configuration["request"],
                            "required": ["uncommitted"],
                        },
                    },
                    {
                        "status": "error",
                        "code": "RequiredUnavailable",
                        "dispatched": True,
                    },
                )
        except Exception as error:
            failure = {
                "kind": type(error).__name__,
                "failed_event": transcript.events[-1]["name"]
                if transcript.events
                else None,
            }
        finally:
            try:
                cleanup([*actors, *extra_actors], broker)
            except Exception as error:
                failure = {
                    "kind": type(error).__name__,
                    "phase": "cleanup",
                    "prior_failure": failure,
                }
    result = {
        "schema": "cigar.broker-fault-cell.v1",
        "agents": args.agents,
        "runtime": args.runtime,
        "storage": args.storage,
        "fixture_sha256": initial_identity,
        "events": transcript.events,
        "cross_owner_applicable": args.agents > 1,
        "durable_restart_applicable": args.storage == "sqlite",
        "protocol_fault_driver": "independent Python process; excluded from load metrics",
        "result": {
            "status": "passed" if failure is None else "failed",
            "failure": failure,
        },
    }
    no_credentials(result)
    return result
