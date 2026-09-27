"""Frozen, continuous twelve-process broker soak; no model or external service.

One SQLite broker serves six Python and six Node actors. Actor processes remain
alive across explicit grant renewal and planned worker restarts. Raw observations
are appended and flushed throughout the run; interrupted runs cannot resume.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback

from broker_faults import Transcript, host_observed
from broker_load import (
    CONFIG,
    PROVENANCE,
    Consumer,
    cleanup,
    copy_tree,
    fixture,
    no_credentials,
    runtime_for,
    validate_observation,
)
from broker_storage import Sampler, encoded, file_hash

ROOT = Path(__file__).resolve().parents[1]
HARNESSES = (
    "broker_soak.py",
    "broker_load.py",
    "broker_load_actor.py",
    "broker_load_actor.mjs",
    "broker_load.v1.json",
    "broker_faults.py",
    "broker_storage.py",
    "shared_views.py",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def configuration(seconds):
    require(type(seconds) is int and 60 <= seconds <= 86400, "invalid soak duration")
    full = seconds == 86400
    return {
        "seconds": seconds,
        "mode": "24-hour-soak" if full else "smoke-only",
        "agents": 12,
        "runtime": "mixed",
        "storage": "sqlite",
        "cadence_seconds": 1,
        "max_unexplained_gap_seconds": 5,
        "max_maintenance_seconds": 30,
        "max_total_rss_bytes": 2 * 1024**3,
        "max_observation_bytes": 2 * 1024**3,
        "lease_ms": 300_000,
        "periods_seconds": {
            "mutation": 60 if full else 5,
            "proposal": 300 if full else 10,
            "revocation": 600 if full else 15,
            "renewal": 120 if full else 20,
            "restart": 3600 if full else 30,
        },
    }


def freeze(args):
    require(
        all(
            p.is_absolute()
            for p in (
                args.worker,
                args.python_sdk,
                args.node_sdk,
                args.node,
                args.directory,
            )
        ),
        "absolute artifact paths required",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.sdk_commit) is not None,
        "exact SDK commit required",
    )
    config = configuration(args.seconds)
    native = json.loads(args.native_build.read_bytes())
    require(
        native["status"] == "native-tested"
        and native["source_binding"]["clean"] is True
        and native["worker"]["sha256"] == file_hash(args.worker),
        "worker differs from its successful native build receipt",
    )
    output = args.directory
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(args.worker, output / "worker")
    shutil.copyfile(args.native_build, output / "native-build.json")
    (output / "python").mkdir()
    python_files = copy_tree(
        args.python_sdk, output / "python/cigar_sdk", {"__pycache__", "_native"}
    )
    node_files = copy_tree(args.node_sdk, output / "typescript", {"tests"})
    metadata = output / "typescript/package.json"
    if metadata.exists():
        require(
            json.loads(metadata.read_bytes()).get("type") == "module",
            "Node SDK is not ESM",
        )
    else:
        metadata.write_bytes(encoded({"type": "module"}))
    node_files["package.json"] = file_hash(metadata)
    (output / "harness").mkdir()
    for name in HARNESSES:
        shutil.copyfile(Path(__file__).with_name(name), output / "harness" / name)
    plan_path = ROOT / "docs/proposals/context-broker-qualification-0.14.0.md"
    shutil.copyfile(plan_path, output / "harness/plan.md")
    inputs = {
        "worker": file_hash(output / "worker"),
        "native-build.json": file_hash(output / "native-build.json"),
        **{"python/cigar_sdk/" + name: value for name, value in python_files.items()},
        **{"typescript/" + name: value for name, value in node_files.items()},
        **{
            "harness/" + name: file_hash(output / "harness" / name)
            for name in (*HARNESSES, "plan.md")
        },
    }
    plan = {
        "schema": "cigar.broker-soak-plan.v1",
        "configuration": config,
        "fixture_sha256": hashlib.sha256(
            encoded(fixture(json.loads(CONFIG.read_bytes()), 12))
        ).hexdigest(),
        "sdk_commit": args.sdk_commit,
        "worker_commit": native["source_binding"]["commit"],
        "inputs": inputs,
        "python_executable_sha256": file_hash(Path(sys.executable).resolve()),
        "node_executable": str(args.node),
        "node_executable_sha256": file_hash(args.node),
        "python": sys.version,
        "node": subprocess.check_output(
            [str(args.node), "--version"], text=True
        ).strip(),
        "host": platform.platform(),
        "model_mode": "none",
        "network": "explicit authenticated loopback only; no OS-denial claim",
        "evidence_class": "authored-invariant-and-persistent-process-soak",
    }
    with (output / "plan.json").open("xb") as stream:
        stream.write(encoded(plan))
    print(
        json.dumps(
            {"directory": str(output), "plan_sha256": file_hash(output / "plan.json")}
        )
    )


def validate_inputs(directory):
    plan = json.loads((directory / "plan.json").read_bytes())
    require(
        plan["configuration"] == configuration(plan["configuration"]["seconds"]),
        "soak configuration drift",
    )
    for name, digest in plan["inputs"].items():
        require(
            file_hash(directory / name) == digest, "frozen soak input changed: " + name
        )
    require(
        file_hash(Path(__file__)) == plan["inputs"]["harness/broker_soak.py"],
        "run the frozen harness",
    )
    require(
        file_hash(Path(sys.executable).resolve()) == plan["python_executable_sha256"],
        "Python interpreter drift",
    )
    require(
        file_hash(Path(plan["node_executable"])) == plan["node_executable_sha256"],
        "Node interpreter drift",
    )
    return plan


class Journal:
    def __init__(self, path, maximum):
        self.stream = path.open("xb")
        self.maximum = maximum
        self.count = 0
        self.bytes = 0
        self.digest = hashlib.sha256()

    def append(self, value):
        no_credentials(value)
        payload = encoded({"sequence": self.count, **value})
        require(
            len(payload) <= 4 * 1024**2 and self.bytes + len(payload) <= self.maximum,
            "soak evidence bound exceeded",
        )
        self.stream.write(payload)
        self.stream.flush()
        self.digest.update(payload)
        self.count += 1
        self.bytes += len(payload)

    def close(self):
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()


def check_cycle(value):
    no_credentials(value)
    require(
        set(value) == {"status", "compile", "forget", "rendered_sha256"}
        and value["status"] == "ok",
        "invalid cycle record",
    )
    for operation in ("compile", "forget"):
        validate_observation(value[operation])
        require(
            value[operation]["status"] == "ok", "unexpected cycle operation failure"
        )
    require(
        re.fullmatch(r"[0-9a-f]{64}", value["rendered_sha256"] or "") is not None,
        "missing context identity",
    )


def check_events(events):
    require(isinstance(events, list) and events, "missing maintenance checks")
    for event in events:
        require(
            event["passed"] is True
            and all(
                event["observed"].get(key) == value
                for key, value in event["expected"].items()
            ),
            "failed or inconsistent maintenance check",
        )


def replay(directory, plan):
    """Recompute completion from bounded raw records, never from a success flag."""
    config = plan["configuration"]
    counts = {kind: 0 for kind in config["periods_seconds"]}
    cycles, previous, progress, maximum_gap = 0, 0.0, 0.0, 0.0
    maintenance, completed, final = None, None, False
    actor_pids = None
    digest = hashlib.sha256()
    size = 0
    with (directory / "observations.jsonl").open("rb") as stream:
        index = 0
        while payload := stream.readline(4 * 1024**2 + 1):
            size += len(payload)
            require(
                len(payload) <= 4 * 1024**2
                and payload.endswith(b"\n")
                and size <= config["max_observation_bytes"],
                "invalid observation framing",
            )
            digest.update(payload)
            row = json.loads(payload)
            no_credentials(row)
            require(row["sequence"] == index, "missing or duplicate observation")
            elapsed = row["elapsed_seconds"]
            require(
                type(elapsed) in (int, float)
                and math.isfinite(elapsed)
                and elapsed >= previous,
                "invalid monotonic observation time",
            )
            previous = elapsed
            kind = row["kind"]
            if index == 0:
                require(kind == "start" and elapsed == 0, "missing soak start")
                actor_pids = row["actor_pids"]
                require(
                    len(actor_pids) == len(set(actor_pids)) == 12,
                    "invalid actor identities",
                )
                check_events(row["initial_checks"])
            elif kind == "maintenance-end":
                require(
                    maintenance is not None
                    and row["phase"] == maintenance[0]
                    and row["number"] == counts[row["phase"]],
                    "unpaired maintenance",
                )
                duration = elapsed - maintenance[1]
                require(
                    0 <= duration <= config["max_maintenance_seconds"]
                    and abs(duration - row["duration_seconds"]) <= 0.01,
                    "invalid maintenance duration",
                )
                check_events(row["checks"])
                maintenance = None
                progress = elapsed
            elif kind == "final-verification":
                require(
                    completed is not None
                    and not final
                    and elapsed - completed <= config["max_maintenance_seconds"],
                    "invalid final verification",
                )
                check_events(row["checks"])
                final = True
            else:
                require(
                    maintenance is None and not final and completed is None,
                    "unexpected observation order",
                )
                gap = elapsed - progress
                maximum_gap = max(maximum_gap, gap)
                require(
                    gap <= config["max_unexplained_gap_seconds"],
                    "unexplained observation gap",
                )
                progress = elapsed
                if kind == "cycle":
                    require(len(row["observations"]) == 12, "missing actor cycle")
                    for value in row["observations"]:
                        check_cycle(value)
                    rss = row["rss_bytes"]
                    require(
                        len(rss) == 14
                        and all(type(value) is int and value > 0 for value in rss)
                        and sum(rss) <= config["max_total_rss_bytes"],
                        "invalid or excessive RSS",
                    )
                    cycles += 1
                elif kind == "maintenance-start":
                    phase = row["phase"]
                    require(
                        phase in counts and row["number"] == counts[phase] + 1,
                        "invalid maintenance sequence",
                    )
                    counts[phase] += 1
                    require(
                        elapsed >= counts[phase] * config["periods_seconds"][phase],
                        "maintenance ran before its schedule",
                    )
                    maintenance = (phase, elapsed)
                elif kind == "duration-complete":
                    require(elapsed >= config["seconds"], "incomplete soak duration")
                    completed = elapsed
                else:
                    raise ValueError("failed or unknown soak observation")
            index += 1
    require(final and maintenance is None and cycles > 0, "incomplete soak transcript")
    for phase, period in config["periods_seconds"].items():
        require(
            counts[phase]
            >= int((config["seconds"] - config["max_maintenance_seconds"]) // period),
            "missing maintenance phase",
        )
    return {
        "elapsed_seconds": completed,
        "cycles_per_actor": cycles,
        "total_cycles": cycles * 12,
        "maintenance": counts,
        "maximum_unexplained_gap_seconds": maximum_gap,
        "actor_pids": actor_pids,
        "observations_sha256": digest.hexdigest(),
        "observation_records": index,
        "observation_bytes": size,
    }


class Soak:
    def __init__(self, directory, plan, journal):
        self.directory, self.plan, self.journal = directory, plan, journal
        self.config = plan["configuration"]
        self.workload = fixture(json.loads(CONFIG.read_bytes()), 12)
        require(
            hashlib.sha256(encoded(self.workload)).hexdigest()
            == plan["fixture_sha256"],
            "fixture drift",
        )
        self.actors, self.connections = [], []
        self.broker = None
        self.transcript = Transcript()
        self.restarts = 0
        self.options = {
            "worker_path": directory / "worker",
            "storage": {
                "directory": str(directory / "store"),
                "create_directory": True,
            },
            "transport": {
                "max_connections": 64,
                "max_connections_per_agent": 4,
                "frame_timeout_ms": 3000,
            },
        }

    def start(self):
        from cigar_sdk import LocalContextBroker

        self.broker = LocalContextBroker("broker-soak", **self.options)
        for source, documents in self.workload["documents"].items():
            if documents:
                self.broker.replace_source(
                    source, self.broker.source_revision(source), documents, PROVENANCE
                )
        for agent, oracle in enumerate(self.workload["agents"]):
            connection = self.broker.grant(
                oracle["view"], lease_ms=self.config["lease_ms"]
            )
            self.connections.append(connection)
            initial = self.client_config(agent, connection)
            initial.pop("op")
            initial["call_timeout_ms"] = 5000
            self.actors.append(
                Consumer(
                    runtime_for("mixed", agent),
                    Path(self.plan["node_executable"]),
                    self.directory / "typescript",
                    self.directory / "python",
                    initial,
                )
            )
        self.actor_pids = [actor.process.pid for actor in self.actors]
        self.sampler = Sampler(self.broker._process.pid)
        # No sampling thread: collect bounded simultaneous samples per cycle.
        self.verify_all()
        for actor in self.actors:
            self.transcript.check(
                "warmup", actor.request({"op": "warmup", "cycles": 2})
            )

    def documents(self, agent):
        return [
            document
            for source in self.workload["agents"][agent]["view"]["allowed_sources"]
            for document in self.workload["documents"][source]
        ]

    def client_config(self, agent, connection):
        oracle = self.workload["agents"][agent]
        required = [
            self.workload["documents"][source][0]
            for source in oracle["view"]["allowed_sources"]
            if source != "competition"
        ]
        return {
            "op": "configure",
            "connection": connection.export(),
            "required_documents": required,
            "request": oracle["request"],
            "scope_documents": len(self.documents(agent)),
        }

    def configure(self, agent):
        self.transcript.check(
            "configure",
            self.actors[agent].request(
                self.client_config(agent, self.connections[agent])
            ),
        )

    def check(self, agent, command, expected=None):
        return self.transcript.check(
            f"agent-{agent}:{command['op']}",
            self.actors[agent].request(command),
            expected,
        )

    def retain(self, agent, slot):
        result = self.actors[agent].request({"op": "retain", "slot": slot})
        ticket = result.pop("private_ticket", None)
        self.transcript.check(f"agent-{agent}:retain", result)
        require(isinstance(ticket, str) and len(ticket) == 64, "missing private ticket")
        return ticket

    def review(self, agent, slot, ticket):
        identity = self.check(agent, {"op": "submit", "slot": slot})["submission_id"]
        submission = self.broker.submission(ticket)
        require(submission["submission_id"] == identity, "submission identity drift")
        labels = [
            {"claim_key": key, "verdict": "supported"}
            for key in submission["review_keys"]
        ]
        self.transcript.require(
            "missing-review-abstains",
            self.broker.check_answer(ticket, identity, [])["assessment"]["decision"]
            == "abstain",
        )
        self.transcript.require(
            "host-review-releases",
            self.broker.check_answer(ticket, identity, labels)["assessment"]["decision"]
            == "release",
        )
        return identity, labels

    def verify_all(self):
        for agent, actor in enumerate(self.actors):
            docs = self.documents(agent)
            actor.send(
                {
                    "op": "verify_documents",
                    "documents": docs,
                    "scope_documents": len(docs),
                }
            )
        return [
            self.transcript.check(
                f"agent-{agent}:all-documents",
                actor.receive(),
                {"status": "ok", "documents": len(self.documents(agent))},
            )
            for agent, actor in enumerate(self.actors)
        ]

    def mutation(self, number):
        agent = (number - 1) % 12
        tickets = [self.retain(i, "mutation") for i in range(12)]
        identity, labels = self.review(agent, "mutation", tickets[agent])
        source = f"private-{agent:03d}"
        documents = copy.deepcopy(self.workload["documents"][source])
        documents[0]["text"] = (
            f"Host-admitted private evidence revision {number} for agent {agent}."
        )
        old = self.broker.source_revision(source)
        receipt = self.broker.replace_source(
            source, old, documents, {**PROVENANCE, "upstream_revision": str(number)}
        )
        self.transcript.require(
            "mutation-revision",
            int(receipt["revision"]["version"]) == int(old["version"]) + 1,
        )
        self.workload["documents"][source] = documents
        for i in range(12):
            self.check(
                i,
                {"op": "revalidate", "slot": "mutation"},
                {"status": "error", "code": "Stale", "dispatched": True}
                if i == agent
                else {"status": "ok"},
            )
        self.transcript.check(
            "old-review-stale",
            host_observed(
                lambda: self.broker.check_answer(tickets[agent], identity, labels)
            ),
            {"status": "error", "code": "Stale", "dispatched": True},
        )
        for i in range(12):
            self.check(i, {"op": "forget", "slot": "mutation"})
        self.configure(agent)

    def proposal(self, number):
        revision = self.broker.source_revision("competition")
        proposals = []
        documents = [
            {
                "id": f"proposed-{i}",
                "source": "competition",
                "text": f"Reviewed proposal {number} from actor {i}.",
            }
            for i in range(2)
        ]
        for i in range(2):
            proposals.append(
                self.check(
                    i,
                    {
                        "op": "proposal",
                        "request_key": "soak-cas",
                        "source": "competition",
                        "expected": revision,
                        "documents": [documents[i]],
                    },
                )["proposal"]
            )
        self.broker.admit_proposal(
            proposals[0]["proposal_id"],
            {
                **PROVENANCE,
                "origin": "reviewed_proposal",
                "upstream_revision": str(number),
            },
        )
        self.transcript.check(
            "losing-proposal-conflicts",
            host_observed(
                lambda: self.broker.admit_proposal(
                    proposals[1]["proposal_id"],
                    {**PROVENANCE, "origin": "reviewed_proposal"},
                )
            ),
            {"status": "error", "code": "Conflict", "dispatched": True},
        )
        self.broker.reject_proposal(proposals[1]["proposal_id"])
        for i, expected in enumerate(("admitted", "rejected")):
            outcome = self.check(
                i, {"op": "proposal_status", "request_key": "soak-cas"}
            )["proposal"]["outcome"]
            self.transcript.require("proposal-receipt", outcome["status"] == expected)
            self.check(i, {"op": "forget_proposal", "request_key": "soak-cas"})
        self.workload["documents"]["competition"] = [documents[0]]
        for i in range(12):
            self.configure(i)
        self.check(
            0,
            {
                "op": "compile_probe",
                "request": {
                    "query": "proposal",
                    "required": [documents[0]["id"]],
                    "max_tokens": 1024,
                    "max_blocks": 1,
                },
                "required_documents": [documents[0]],
                "scope_documents": len(self.documents(0)),
            },
        )
        self.check(
            1,
            {
                "op": "compile_probe",
                "request": {"required": [documents[1]["id"]], "max_tokens": 1024},
            },
            {"status": "error", "code": "RequiredUnavailable", "dispatched": True},
        )

    def renew(self, agents, revoke=False):
        for agent in agents:
            self.retain(agent, "renewal")
            oracle = self.workload["agents"][agent]
            if revoke:
                self.transcript.require(
                    "explicit-revoke", self.broker.revoke(oracle["view"]["id"]) is True
                )
                self.transcript.auth_denied(
                    "revoked-grant",
                    self.actors[agent].request(
                        {"op": "compile_probe", "request": oracle["request"]}
                    ),
                )
            self.connections[agent] = self.broker.grant(
                oracle["view"], lease_ms=self.config["lease_ms"]
            )
            self.transcript.auth_denied(
                "replaced-grant",
                self.actors[agent].request(
                    {"op": "compile_probe", "request": oracle["request"]}
                ),
            )
            self.configure(agent)
            self.check(
                agent,
                {"op": "revalidate", "slot": "renewal"},
                {"status": "error", "code": "AccessDenied", "dispatched": True},
            )

    def restart(self):
        from cigar_sdk import LocalBrokerConnection, LocalContextBroker

        before = self.verify_all()
        tickets = [self.retain(i, "restart") for i in range(12)]
        identity, labels = self.review(0, "restart", tickets[0])
        revisions = {
            source: self.broker.source_revision(source)
            for source in self.workload["documents"]
        }
        provenance = {source: self.broker.provenance(source) for source in revisions}
        staged = self.broker.begin_source_replace(
            "common", revisions["common"], PROVENANCE
        )
        self.broker.append_source_documents(
            staged,
            [{"id": "uncommitted", "source": "common", "text": "Never admitted."}],
        )
        self.broker._process.kill()
        self.broker._process.wait(timeout=5)
        self.broker.close()
        self.transcript.require("old-worker-reaped", self.broker.cleanup_complete)
        self.broker = LocalContextBroker("broker-soak", **self.options)
        self.transcript.require(
            "checkpoint-restored",
            self.broker.capabilities()["storage"]["restored"] is True,
        )
        for source, previous in revisions.items():
            current = self.broker.source_revision(source)
            self.transcript.require(
                "source-restored",
                current["version"] == previous["version"]
                and current["epoch"] != previous["epoch"]
                and self.broker.provenance(source) == provenance[source],
            )
        self.transcript.check(
            "old-write-authority",
            host_observed(
                lambda: self.broker.replace_source(
                    "common", revisions["common"], [], PROVENANCE
                )
            ),
            {"status": "error", "code": "Conflict", "dispatched": True},
        )
        self.transcript.check(
            "staging-not-restored",
            host_observed(lambda: self.broker.commit_source_replace(staged)),
            {"status": "error", "code": "Stale", "dispatched": True},
        )
        self.transcript.check(
            "review-not-restored",
            host_observed(
                lambda: self.broker.check_answer(tickets[0], identity, labels)
            ),
            {"status": "error", "code": "AccessDenied", "dispatched": True},
        )
        stale = LocalBrokerConnection(
            self.broker.capabilities()["port"],
            self.connections[0].epoch,
            self.connections[0].secret,
        )
        self.transcript.check(
            "old-epoch-configure", self.actors[0].request(self.client_config(0, stale))
        )
        self.transcript.auth_denied(
            "old-epoch-denied",
            self.actors[0].request(
                {
                    "op": "compile_probe",
                    "request": self.workload["agents"][0]["request"],
                }
            ),
        )
        for i, oracle in enumerate(self.workload["agents"]):
            self.connections[i] = self.broker.grant(
                oracle["view"], lease_ms=self.config["lease_ms"]
            )
            self.configure(i)
            self.check(
                i,
                {"op": "revalidate", "slot": "restart"},
                {"status": "error", "code": "AccessDenied", "dispatched": True},
            )
        self.transcript.require(
            "all-source-bytes-restored", self.verify_all() == before
        )
        self.restarts += 1

    def cycle(self):
        require(
            [actor.process.pid for actor in self.actors] == self.actor_pids
            and all(actor.process.poll() is None for actor in self.actors),
            "actor process was lost or replaced",
        )
        require(self.broker._process.poll() is None, "unplanned worker exit")
        for actor in self.actors:
            actor.send({"op": "cycle"})
        results = [actor.receive() for actor in self.actors]
        # Retain failed replies before validation raises. No retry or suppression.
        rss = [
            self.sampler.resident(pid)
            for pid in (os.getpid(), self.broker._process.pid, *self.actor_pids)
        ]
        self.journal.append(
            {
                "kind": "cycle",
                "elapsed_seconds": time.monotonic() - self.started,
                "observations": results,
                "rss_bytes": rss,
                "worker_pid": self.broker._process.pid,
            }
        )
        for result in results:
            check_cycle(result)
        require(
            sum(rss) <= self.config["max_total_rss_bytes"], "soak RSS bound exceeded"
        )

    def run(self):
        self.started = time.monotonic()
        self.journal.append(
            {
                "kind": "start",
                "elapsed_seconds": 0,
                "wall_time_ns": time.time_ns(),
                "actor_pids": self.actor_pids,
                "worker_pid": self.broker._process.pid,
                "initial_checks": self.transcript.events,
            }
        )
        self.transcript = Transcript()
        counts = {kind: 0 for kind in self.config["periods_seconds"]}
        cycles, maximum_gap = 0, 0.0
        last_progress = self.started
        next_cycle = self.started
        while time.monotonic() - self.started < self.config["seconds"]:
            now = time.monotonic()
            time.sleep(
                max(0, min(next_cycle, self.started + self.config["seconds"]) - now)
            )
            now = time.monotonic()
            gap = now - last_progress
            maximum_gap = max(maximum_gap, gap)
            require(
                gap <= self.config["max_unexplained_gap_seconds"],
                "unexplained soak progress gap",
            )
            if now - self.started >= self.config["seconds"]:
                break
            self.cycle()
            cycles += 1
            gap = time.monotonic() - last_progress
            maximum_gap = max(maximum_gap, gap)
            require(
                gap <= self.config["max_unexplained_gap_seconds"],
                "cycle exceeded progress deadline",
            )
            last_progress = time.monotonic()
            for kind, period in self.config["periods_seconds"].items():
                if time.monotonic() - self.started < (counts[kind] + 1) * period:
                    continue
                counts[kind] += 1
                begin = time.monotonic()
                self.journal.append(
                    {
                        "kind": "maintenance-start",
                        "phase": kind,
                        "number": counts[kind],
                        "elapsed_seconds": begin - self.started,
                    }
                )
                self.transcript = Transcript()
                try:
                    if kind == "mutation":
                        self.mutation(counts[kind])
                    elif kind == "proposal":
                        self.proposal(counts[kind])
                    elif kind == "revocation":
                        self.renew([(counts[kind] - 1) % 12], revoke=True)
                    elif kind == "renewal":
                        self.renew(range(12))
                    else:
                        self.restart()
                finally:
                    elapsed = time.monotonic() - begin
                    self.journal.append(
                        {
                            "kind": "maintenance-end",
                            "phase": kind,
                            "number": counts[kind],
                            "elapsed_seconds": time.monotonic() - self.started,
                            "duration_seconds": elapsed,
                            "checks": self.transcript.events,
                        }
                    )
                require(
                    elapsed <= self.config["max_maintenance_seconds"],
                    "maintenance exceeded its registered gap",
                )
                last_progress = time.monotonic()
            next_cycle = max(next_cycle + self.config["cadence_seconds"], last_progress)
            if cycles % 60 == 0:
                print(
                    json.dumps(
                        {
                            "cycles_per_actor": cycles,
                            "elapsed_seconds": time.monotonic() - self.started,
                            "maintenance": counts,
                        }
                    ),
                    flush=True,
                )
        elapsed = time.monotonic() - self.started
        require(elapsed >= self.config["seconds"], "incomplete duration")
        self.journal.append({"kind": "duration-complete", "elapsed_seconds": elapsed})
        for kind, period in self.config["periods_seconds"].items():
            require(
                counts[kind]
                >= int(
                    (self.config["seconds"] - self.config["max_maintenance_seconds"])
                    // period
                ),
                "missing scheduled maintenance",
            )
        self.transcript = Transcript()
        self.verify_all()
        self.journal.append(
            {
                "kind": "final-verification",
                "elapsed_seconds": time.monotonic() - self.started,
                "checks": self.transcript.events,
            }
        )
        return {
            "elapsed_seconds": elapsed,
            "cycles_per_actor": cycles,
            "total_cycles": cycles * 12,
            "maximum_unexplained_gap_seconds": maximum_gap,
            "maintenance": counts,
            "actor_pids": self.actor_pids,
        }


def run(directory):
    plan = validate_inputs(directory)
    sys.path.insert(0, str(directory / "python"))
    journal = Journal(
        directory / "observations.jsonl", plan["configuration"]["max_observation_bytes"]
    )
    soak = Soak(directory, plan, journal)
    result, failure = None, None

    def stop(_signal, _frame):
        raise InterruptedError("soak interrupted")

    signal.signal(signal.SIGTERM, stop)
    try:
        soak.start()
        result = soak.run()
        validate_inputs(directory)
    except BaseException as error:
        # Function/line locations aid diagnosis without retaining exception text
        # or locals, either of which could contain a credential.
        failure = {
            "kind": type(error).__name__,
            "frames": [
                {
                    "file": Path(frame.filename).name,
                    "line": frame.lineno,
                    "function": frame.name,
                }
                for frame in traceback.extract_tb(error.__traceback__)
            ],
        }
        journal.append(
            {"kind": "failure", "failure": failure, "checks": soak.transcript.events}
        )
    finally:
        try:
            cleanup(soak.actors, soak.broker)
        except Exception as error:
            failure = {
                "kind": type(error).__name__,
                "phase": "cleanup",
                "prior_failure": failure,
            }
        journal.close()
    if failure is None:
        try:
            result = replay(directory, plan)
            require(
                result["observations_sha256"] == journal.digest.hexdigest(),
                "retained observations changed",
            )
        except Exception as error:
            failure = {"kind": type(error).__name__, "phase": "observation-replay"}
    report = {
        "schema": "cigar.broker-soak-result.v1",
        "plan_sha256": file_hash(directory / "plan.json"),
        "observations_sha256": journal.digest.hexdigest(),
        "observation_records": journal.count,
        "observation_bytes": journal.bytes,
        "status": "passed" if failure is None else "incomplete",
        "qualifies_24_hours": failure is None
        and plan["configuration"]["mode"] == "24-hour-soak",
        "failure": failure,
        "measurements": result,
        "model_calls": 0,
    }
    with (directory / "result.json").open("xb") as stream:
        stream.write(encoded(report))
    print(json.dumps(report), flush=True)
    if failure is not None:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("freeze")
    setup.add_argument("--directory", type=Path, required=True)
    setup.add_argument("--worker", type=Path, required=True)
    setup.add_argument("--native-build", type=Path, required=True)
    setup.add_argument(
        "--python-sdk", type=Path, required=True, help="cigar_sdk package directory"
    )
    setup.add_argument("--node-sdk", type=Path, required=True)
    setup.add_argument("--node", type=Path, required=True)
    setup.add_argument("--sdk-commit", required=True)
    setup.add_argument("--seconds", type=int, default=86400)
    execute = sub.add_parser("run")
    execute.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze(args)
    else:
        run(args.directory.absolute())


if __name__ == "__main__":
    main()
