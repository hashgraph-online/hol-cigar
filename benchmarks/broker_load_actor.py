"""Private-stdio independent Python consumer for the registered broker load fixture.

Only the first stdin record contains a grant. Neither normal output nor failures
echo it. Returned context tickets are confined to explicit private host IPC;
the coordinator must not put them in retained observations.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import select
import socket
import sys
import threading
import time

from cigar_sdk import LocalBrokerConnection, LocalBrokerError, LocalContextClient
import cigar_sdk.broker as broker_module


LIMIT = 4 * 1024 * 1024
original_result = broker_module._result
reply_timing = threading.local()


def timed_result(reply, request_id):
    try:
        result = original_result(reply, request_id)
    except LocalBrokerError:
        reply_timing.value = reply["timing"]
        raise
    reply_timing.value = reply["timing"]
    return result


# Capture only timing from replies the real SDK has fully validated.
broker_module._result = timed_result


def receive():
    value = sys.stdin.buffer.readline(LIMIT + 1)
    if not value:
        return None
    if len(value) > LIMIT or not value.endswith(b"\n"):
        raise ValueError("invalid private control frame")
    result = json.loads(value)
    if not isinstance(result, dict):
        raise ValueError("invalid private control envelope")
    return result


def emit(value):
    text = json.dumps(value, separators=(",", ":"), allow_nan=False)
    if len(text) > 16 * 1024 * 1024:
        raise ValueError("bounded observation response exceeded")
    print(text, flush=True)


def check_context(result, expected, count, budget):
    snapshot = result["context"]["snapshot"]
    selected = {}
    for block in snapshot["blocks"]:
        for citation in block["citations"]:
            node = citation["node_id"]
            if node in selected or node not in expected:
                raise AssertionError("unexpected selected evidence")
            document = expected[node]
            if (
                block["text"] != document["text"]
                or citation["source"] != document["source"]
            ):
                raise AssertionError("source-bound text mismatch")
            selected[node] = citation["document_digest"]
    if (
        set(selected) != set(expected)
        or snapshot["stats"]["documents"] != count
        or snapshot["stats"]["rendered_tokens"] > budget
    ):
        raise AssertionError("scope or budget mismatch")
    return hashlib.sha256(result["rendered"].encode()).hexdigest()


def observed(operation):
    reply_timing.value = None
    start = time.perf_counter_ns()
    try:
        result = operation()
        status = {"status": "ok"}
    except LocalBrokerError as error:
        result = None
        status = {"status": "error", "code": error.code, "dispatched": error.dispatched}
    except Exception as error:
        result = None
        status = {"status": "harness_error", "kind": type(error).__name__}
    return result, {
        **status,
        "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
        "timing": reply_timing.value,
    }


class Actor:
    def __init__(self, config):
        self.timeout = config["call_timeout_ms"] / 1000
        self.client = self.connect(config["connection"])
        self.request = config["request"]
        self.expected = {
            document["id"]: document for document in config["required_documents"]
        }
        self.count = config["scope_documents"]
        self.retained = {}
        self.contexts = {}
        self.held = []

    def connect(self, config):
        return LocalContextClient(
            LocalBrokerConnection.from_config(config),
            timeout=self.timeout,
            max_pending=4,
        )

    def compile(self):
        context = self.client.compile(self.request)
        try:
            digest = check_context(
                context, self.expected, self.count, self.request["max_tokens"]
            )
        except BaseException:
            self.client.forget_ticket(context["ticket"])
            raise
        return context, digest

    def measure(self, command):
        duration = command["duration_ms"] / 1000
        if (
            not 0.1 <= duration <= 30
            or command["parallelism"] not in (1, 4)
            or not 1 <= command["max_cycles"] <= 10000
        ):
            raise ValueError("unregistered load bounds")
        delay = command["start_at_ms"] / 1000 - time.time()
        if not 0 < delay <= 5:
            raise ValueError("start deadline missed")
        start_at = time.monotonic() + delay
        deadline = start_at + duration
        samples = []
        lock = threading.Lock()
        next_cycle = 0
        starts = []

        def lane(lane_id):
            nonlocal next_cycle
            time.sleep(max(0, start_at - time.monotonic()))
            first_at = time.time() * 1000
            with lock:
                starts.append(first_at)
            while time.monotonic() < deadline:
                with lock:
                    if next_cycle >= command["max_cycles"]:
                        return
                    sequence = next_cycle
                    next_cycle += 1
                value, compile_observation = observed(self.compile)
                forget_observation = None
                digest = None
                if value is not None:
                    context, digest = value
                    _, forget_observation = observed(
                        lambda: self.client.forget_ticket(context["ticket"])
                    )
                with lock:
                    samples.append(
                        {
                            "sequence": sequence,
                            "lane": lane_id,
                            "compile": compile_observation,
                            "forget": forget_observation,
                            "rendered_sha256": digest,
                        }
                    )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=command["parallelism"]
        ) as pool:
            list(pool.map(lane, range(command["parallelism"])))
        return {
            "status": "ok",
            "kind": "measure",
            "samples": sorted(samples, key=lambda row: row["sequence"]),
            "actual_start_ms": min(starts),
            "finish_ms": time.time() * 1000,
            "monotonic_window_ms": (time.monotonic() - start_at) * 1000,
            "capped": next_cycle >= command["max_cycles"],
            "duration_ms": command["duration_ms"],
            "native_timing": "validated-reply",
            "attempted": next_cycle,
        }

    def command(self, command):
        op = command["op"]
        if op == "hold_connections":
            # A protocol fault driver, not a new SDK API or timing treatment.
            # The production SDK performs the real mutual proof; no copied proof algorithm.
            if self.held:
                raise ValueError("connections already held")
            closed = set()
            try:
                for _ in range(5):
                    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.held.append(stream)
                    stream.settimeout(2)
                    stream.connect(("127.0.0.1", self.client._connection.port))
                    self.client._authenticate(stream, time.monotonic() + 2)
                    stream.sendall(b"\x00")  # Abandon an incomplete command prefix.
                deadline = time.monotonic() + 1
                while not closed and time.monotonic() < deadline:
                    ready, _, _ = select.select(self.held, [], [], 0.02)
                    for stream in ready:
                        try:
                            value = stream.recv(1)
                        except ConnectionResetError:
                            value = b""
                        if value:
                            raise AssertionError("unexpected bytes before a command")
                        closed.add(stream)
                if len(closed) != 1:
                    raise AssertionError("per-grant connection capacity not enforced")
                for stream in closed:
                    stream.close()
                    self.held.remove(stream)
                return {"status": "ok", "attempted": 5, "held": 4, "rejected": 1}
            except BaseException:
                for stream in self.held:
                    stream.close()
                self.held.clear()
                raise
        if op == "release_connections":
            for stream in self.held:
                stream.close()
            self.held.clear()
            return {"status": "ok"}
        if op == "held_status":
            ready, _, _ = select.select(self.held, [], [], 0)
            if len(self.held) != 4 or ready:
                raise AssertionError("held sockets closed before the isolation check")
            return {"status": "ok", "held": len(self.held)}
        if op == "verify_documents":
            documents = command["documents"]
            if not documents or len(documents) > 4096:
                raise ValueError("unregistered verification size")
            digests = []
            for offset in range(0, len(documents), 16):
                batch = documents[offset : offset + 16]
                request = {
                    "query": "evidence",
                    "required": [value["id"] for value in batch],
                    "max_tokens": 16384,
                    "max_blocks": len(batch),
                }
                context = self.client.compile(request)
                try:
                    digests.append(
                        check_context(
                            context,
                            {value["id"]: value for value in batch},
                            command["scope_documents"],
                            request["max_tokens"],
                        )
                    )
                finally:
                    self.client.forget_ticket(context["ticket"])
            return {
                "status": "ok",
                "documents": len(documents),
                "batch_digests": digests,
            }
        if op == "measure":
            return self.measure(command)
        if op == "warmup":
            for _ in range(command["cycles"]):
                context, _ = self.compile()
                self.client.forget_ticket(context["ticket"])
            return {"status": "ok"}
        if op == "retain":
            context, digest = self.compile()
            self.retained[command["slot"]] = context["ticket"]
            self.contexts[command["slot"]] = context
            return {
                "status": "ok",
                "rendered_sha256": digest,
                "private_ticket": context["ticket"],
            }
        if op == "revalidate":
            _, outcome = observed(
                lambda: self.client.revalidate(self.retained[command["slot"]])
            )
            return outcome
        if op == "foreign_ticket":
            _, outcome = observed(
                lambda: self.client.revalidate(command["private_ticket"])
            )
            return outcome
        if op == "compile_probe":

            def probe():
                context = self.client.compile(command["request"])
                try:
                    if "required_documents" in command:
                        return check_context(
                            context,
                            {
                                document["id"]: document
                                for document in command["required_documents"]
                            },
                            command["scope_documents"],
                            command["request"]["max_tokens"],
                        )
                    return hashlib.sha256(context["rendered"].encode()).hexdigest()
                finally:
                    self.client.forget_ticket(context["ticket"])

            digest, outcome = observed(probe)
            return {**outcome, "rendered_sha256": digest}
        if op == "submit":
            context = self.contexts[command["slot"]]
            document = next(iter(self.expected.values()))
            draft = {
                "snapshot_id": context["context"]["snapshot"]["id"],
                "claims": [
                    {
                        "text": document["text"],
                        "citations": [document["id"]],
                        "confidence_bps": 9900,
                    }
                ],
            }
            identity, outcome = observed(
                lambda: self.client.submit_answer(context["ticket"], draft)
            )
            return {**outcome, "submission_id": identity}
        if op == "configure":
            self.client = self.connect(command["connection"])
            self.expected = {
                document["id"]: document for document in command["required_documents"]
            }
            self.count = command["scope_documents"]
            if "request" in command:
                self.request = command["request"]
            return {"status": "ok"}
        if op == "proposal":
            result, outcome = observed(
                lambda: self.client.propose_source(
                    command["request_key"],
                    command["source"],
                    command["expected"],
                    command["documents"],
                )
            )
            return {**outcome, "proposal": result}
        if op == "proposal_status":
            result, outcome = observed(
                lambda: self.client.proposal_status(command["request_key"])
            )
            return {**outcome, "proposal": result}
        if op == "forget":
            self.client.forget_ticket(self.retained.pop(command["slot"]))
            self.contexts.pop(command["slot"])
            return {"status": "ok"}
        if op == "forget_proposal":
            _, outcome = observed(
                lambda: self.client.forget_proposal(command["request_key"])
            )
            return outcome
        raise ValueError("unknown private control operation")


def main():
    config = receive()
    if config is None:
        return
    actor = Actor(config)
    emit(
        {
            "status": "ready",
            "pid": os.getpid(),
            "runtime": "python",
            "version": platform.python_version(),
        }
    )
    while (command := receive()) is not None:
        if command.get("op") == "close":
            emit({"status": "closed"})
            return
        try:
            result = actor.command(command)
        except Exception as error:
            result = {"status": "harness_error", "kind": type(error).__name__}
        emit(result)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"status": "harness_error", "kind": type(error).__name__})
        raise SystemExit(1) from None
