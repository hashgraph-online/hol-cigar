"""Real broker host, independent consumers and hostile loopback peers; no provider calls."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from cigar_sdk import LocalBrokerConnection, LocalBrokerError, LocalContextBroker, LocalContextClient, context
from cigar_sdk.broker import _read, _send, _strict_loads


@pytest.fixture
def broker():
    with LocalContextBroker("broker-sdk", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as value:
        yield value
    assert value.cleanup_complete


def provenance(origin="host"):
    return {
        "authority": "fixture-host",
        "upstream_revision": "v1",
        "observed_at_ms": 1,
        "valid_until_ms": None,
        "origin": origin,
        "derived_from": [],
    }


def grant(broker, agent, sources, writable=()):
    return broker.grant(
        {
            "id": agent,
            "allowed_sources": list(sources),
            "writable_sources": list(writable),
            "policy_revision": "host-policy",
        }
    )


def ingest(broker, source, node, text):
    return broker.replace_source(
        source, broker.source_revision(source), [{"id": node, "source": source, "text": text}], provenance()
    )


def execution_fixture(broker):
    ingest(broker, "docs", "fact", "Retry at most three times.")
    client = LocalContextClient(grant(broker, "execution-agent", ["docs"]))
    context = client.compile({"query": "retry", "required": ["fact"]})
    draft = {
        "snapshot_id": context["context"]["snapshot"]["id"],
        "claims": [{"text": "Retry at most three times.", "citations": ["fact"], "confidence_bps": 9900}],
    }
    submission = client.submit_answer(context["ticket"], draft)
    review = {
        "authority_revision": "reviewer-policy-one",
        "reviews": [
            {"claim_key": key, "verdict": "supported"} for key in broker.submission(context["ticket"])["review_keys"]
        ],
        "policy": {},
    }
    return client, context, draft, submission, review


def test_execution_handoff_consumes_once_without_granting_agent_dispatch_authority(broker):
    client, context, _, submission, review = execution_fixture(broker)
    intent = "1220" + "a" * 64
    binding = broker.bind_execution(context["ticket"], submission, "prepared-effect", intent, review)
    assert binding["intent_digest"] == intent and binding["epoch"] == broker.capabilities()["epoch"]
    assert not hasattr(client, "bind_execution") and not hasattr(client, "take_execution_handoff")
    with pytest.raises(LocalBrokerError, match="Stale"):
        broker.take_execution_handoff(dict(binding, effect_id="substituted-effect"), review)
    ingest(broker, "unrelated", "private", "unrelated private update")

    def take():
        try:
            return broker.take_execution_handoff(binding, review)
        except LocalBrokerError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: take(), range(2)))
    handoffs = [value for value in outcomes if isinstance(value, dict)]
    assert len(handoffs) == 1 and outcomes.count("Conflict") == 1
    assert handoffs[0]["binding"] == binding and handoffs[0]["checked"]["assessment"]["decision"] == "release"


@pytest.mark.parametrize("change", ["source", "metadata", "submission", "revoke", "reviewer", "policy", "verdict"])
def test_execution_handoff_revalidates_all_current_context_and_review_inputs(broker, change):
    client, context, draft, submission, review = execution_fixture(broker)
    binding = broker.bind_execution(context["ticket"], submission, "prepared-effect", "1220" + "a" * 64, review)
    if change == "source":
        ingest(broker, "docs", "fact", "Changed retry rule.")
    elif change == "metadata":
        broker.replace_source(
            "docs",
            broker.source_revision("docs"),
            [{"id": "fact", "source": "docs", "text": "Retry at most three times."}],
            dict(provenance(), upstream_revision="two"),
        )
    elif change == "submission":
        client.submit_answer(context["ticket"], draft)
    elif change == "revoke":
        broker.revoke("execution-agent")
    elif change == "reviewer":
        review["authority_revision"] = "revoked-reviewer"
    elif change == "policy":
        review["policy"] = {"min_sources": 2}
    else:
        review["reviews"][0]["verdict"] = "unknown"
    with pytest.raises(LocalBrokerError):
        broker.take_execution_handoff(binding, review)


def test_execution_handoff_requires_review_and_explicit_worker_capability(broker):
    _, context, _, submission, review = execution_fixture(broker)
    with pytest.raises(LocalBrokerError, match="AccessDenied"):
        broker.bind_execution(
            context["ticket"], submission, "prepared-effect", "1220" + "a" * 64, dict(review, reviews=[])
        )
    binding = broker.bind_execution(context["ticket"], submission, "prepared-effect", "1220" + "a" * 64, review)
    hello = broker._hello
    broker._hello = dict(hello, capabilities=[x for x in hello["capabilities"] if x != "execution_handoff.v1"])
    with patch.object(broker, "_call", side_effect=AssertionError("unsupported host command was sent")):
        with pytest.raises(LocalBrokerError, match="IncompatibleWorker"):
            broker.bind_execution(context["ticket"], submission, "prepared-effect", "1220" + "a" * 64, review)
        with pytest.raises(LocalBrokerError, match="IncompatibleWorker"):
            broker.take_execution_handoff(binding, review)
    broker._hello = hello
    assert broker.take_execution_handoff(binding, review)["checked"]["assessment"]["decision"] == "release"


@pytest.mark.parametrize("agents", [1, 5, 12])
def test_independent_agent_processes_share_exact_scopes_and_preserve_unaffected_work(broker, agents):
    ingest(broker, "shared", "common", "common evidence")
    connections = []
    for i in range(agents):
        source = f"private-{i}"
        ingest(broker, source, f"doc-{i}", f"PRIVATE_AGENT_{i}_ evidence")
        connections.append(grant(broker, f"agent-{i}", ["shared", source], [source]))

    def run(i):
        # CI may add a compiled Node child; otherwise this remains independent Python processes.
        node_agent = os.environ.get("CIGAR_TEST_NODE_AGENT")
        command = (
            [os.environ.get("CIGAR_TEST_NODE", "node"), node_agent]
            if node_agent and i % 2
            else [sys.executable, str(Path(__file__).parent / "fixtures/broker_agent.py")]
        )
        result = subprocess.run(
            command,
            input=json.dumps(
                {
                    "connection": connections[i].export(),
                    "request": {"query": "evidence", "required": ["common", f"doc-{i}"]},
                }
            ),
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=agents) as pool:
        results = list(pool.map(run, range(agents)))
    for i, result in enumerate(results):
        assert f"PRIVATE_AGENT_{i}_" in result["rendered"]
        assert "common evidence" in result["rendered"]
        for j in range(agents):
            if i != j:
                assert f"PRIVATE_AGENT_{j}_" not in result["rendered"]
        assert result["context"]["snapshot"]["stats"]["documents"] == 2
    ingest(broker, "private-0", "doc-0", "changed evidence")
    for i, connection in enumerate(connections):
        client = LocalContextClient(connection)
        if i == 0:
            with pytest.raises(LocalBrokerError) as caught:
                client.revalidate(results[i]["ticket"])
            assert caught.value.code == "Stale" and caught.value.dispatched is True
        else:
            client.revalidate(results[i]["ticket"])
            with pytest.raises(LocalBrokerError, match="AccessDenied"):
                client.revalidate(results[0]["ticket"])


def test_proposals_require_host_admission_and_cas_conflicts_are_reconcilable(broker):
    a = LocalContextClient(grant(broker, "a", ["docs"], ["docs"]))
    b = LocalContextClient(grant(broker, "b", ["docs"], ["docs"]))
    revision = a.source_revision("docs")
    assert revision["version"] == "0"
    pa = a.propose_source("a-1", "docs", revision, [{"id": "a", "source": "docs", "text": "alpha evidence"}])
    pb = b.propose_source("b-1", "docs", revision, [{"id": "b", "source": "docs", "text": "beta evidence"}])
    assert not a.compile({"query": "evidence"})["context"]["snapshot"]["blocks"]
    assert broker.proposal(pa["proposal_id"])["documents"][0]["id"] == "a"
    receipt = broker.admit_proposal(pa["proposal_id"], provenance("reviewed_proposal"))
    assert receipt["revision"]["version"] == "1"
    with pytest.raises(LocalBrokerError, match="Conflict"):
        broker.admit_proposal(pb["proposal_id"], provenance("reviewed_proposal"))
    assert a.proposal_status("a-1")["outcome"]["status"] == "admitted"
    broker.reject_proposal(pb["proposal_id"])
    assert b.proposal_status("b-1")["outcome"]["status"] == "rejected"
    b.forget_proposal("b-1")
    with pytest.raises(LocalBrokerError, match="AccessDenied"):
        b.proposal_status("b-1")
    assert "alpha evidence" in b.compile({"query": "evidence"})["rendered"]


def test_exact_submission_review_is_host_only_and_rechecks_freshness(broker):
    ingest(broker, "docs", "fact", "Retry at most three times.")
    client = LocalContextClient(grant(broker, "writer", ["docs"]))
    context = client.compile({"query": "retry", "required": ["fact"]})
    draft = {
        "snapshot_id": context["context"]["snapshot"]["id"],
        "claims": [{"text": "Retry at most three times.", "citations": ["fact"], "confidence_bps": 9900}],
    }
    identity = client.submit_answer(context["ticket"], draft)
    submission = broker.submission(context["ticket"])
    assert submission["submission_id"] == identity and submission["draft"]["claims"] == draft["claims"]
    reviews = [{"claim_key": key, "verdict": "supported"} for key in submission["review_keys"]]
    assert broker.check_answer(context["ticket"], identity, [])["assessment"]["decision"] == "abstain"
    assert broker.check_answer(context["ticket"], identity, reviews)["assessment"]["decision"] == "release"
    assert not hasattr(client, "check_answer") and not hasattr(client, "replace_source")
    assert client.citations(context["ticket"], "fact")[0]["source"] == "docs"
    other = dict(draft, claims=[dict(draft["claims"][0], text="Retry four times.")])
    client.submit_answer(context["ticket"], other)
    with pytest.raises(LocalBrokerError, match="Stale"):
        broker.check_answer(context["ticket"], identity, reviews)
    ingest(broker, "docs", "fact", "Retry at most two times.")
    with pytest.raises(LocalBrokerError, match="Stale"):
        broker.submission(context["ticket"])


def test_connection_export_is_explicit_redacted_and_literal_loopback_only(broker):
    connection = grant(broker, "agent", ["docs"])
    assert connection.secret not in repr(connection)
    assert LocalBrokerConnection.from_config(connection.export()) == connection
    for changes in [{"host": "localhost"}, {"host": "192.0.2.1"}, {"port": True}, {"epoch": "bad"}, {"unexpected": 1}]:
        with pytest.raises(LocalBrokerError, match="InvalidInput"):
            LocalBrokerConnection.from_config(dict(connection.export(), **changes))
    hello = broker.capabilities()
    hello["capabilities"].clear()
    assert "mutual_grant_proof.v1" in broker.capabilities()["capabilities"]
    client = LocalContextClient(connection)
    with patch("cigar_sdk.broker.os.getpid", return_value=-1), pytest.raises(LocalBrokerError, match="ForkedProcess"):
        client.source_revision("docs")
    broker.revoke("agent")
    with pytest.raises(LocalBrokerError) as caught:
        client.source_revision("docs")
    assert caught.value.dispatched is False


def fake_peer(handler):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    errors = []

    def serve():
        try:
            with server:
                stream, _ = server.accept()
                with stream:
                    stream.settimeout(3)
                    handler(stream)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    return server.getsockname()[1], thread, errors


def test_fake_broker_gets_no_secret_proof_or_context():
    observed = []
    secret = "a" * 64

    def fake(stream):
        deadline = time.monotonic() + 3
        hello = _strict_loads(_read(stream, 1024, deadline))
        observed.append(hello)
        proof = {
            "protocol": hello["protocol"],
            "epoch": hello["epoch"],
            "grant_id": hello["grant_id"],
            "client_nonce": hello["nonce"],
            "server_nonce": "b" * 64,
            "proof": "0" * 64,
        }
        _send(stream, json.dumps(proof).encode(), deadline)
        observed.append(stream.recv(1024))

    port, thread, errors = fake_peer(fake)
    client = LocalContextClient(LocalBrokerConnection(port, "e" * 64, secret))
    with pytest.raises(LocalBrokerError, match="Authentication") as caught:
        client.compile({"query": "PRIVATE_CONTEXT_CANARY"})
    thread.join(5)
    assert not thread.is_alive() and not errors
    assert caught.value.dispatched is False and observed[1] == b""
    assert secret not in json.dumps(observed[0]) and "PRIVATE_CONTEXT_CANARY" not in json.dumps(observed[0])


def authenticated_command(stream):
    """A test server authenticates both peers and receives one command."""
    secret, epoch = "a" * 64, "e" * 64
    deadline = time.monotonic() + 3
    hello = _strict_loads(_read(stream, 1024, deadline))
    grant_id = hashlib.sha256(b"cigar.broker-grant-id.v1\0" + epoch.encode() + secret.encode()).hexdigest()
    transcript = (epoch + grant_id + hello["nonce"] + "b" * 64).encode()
    proof = hmac.digest(bytes.fromhex(secret), b"cigar.broker-server-proof.v1\0" + transcript, "sha256").hex()
    _send(
        stream,
        json.dumps(
            {
                "protocol": hello["protocol"],
                "epoch": epoch,
                "grant_id": grant_id,
                "client_nonce": hello["nonce"],
                "server_nonce": "b" * 64,
                "proof": proof,
            }
        ).encode(),
        deadline,
    )
    client = _strict_loads(_read(stream, 1024, deadline))
    expected = hmac.digest(bytes.fromhex(secret), b"cigar.broker-client-proof.v1\0" + transcript, "sha256").hex()
    assert client == {"protocol": hello["protocol"], "proof": expected}
    return _strict_loads(_read(stream, 2 * 1024 * 1024, deadline))


def test_lost_reply_is_unknown_and_does_not_retry():
    commands = []

    def fake(stream):
        commands.append(authenticated_command(stream))

    port, thread, errors = fake_peer(fake)
    client = LocalContextClient(LocalBrokerConnection(port, "e" * 64, "a" * 64))
    with pytest.raises(LocalBrokerError) as caught:
        client.propose_source("once", "docs", {"epoch": "e" * 64, "version": "0"}, [])
    thread.join(5)
    assert not thread.is_alive() and not errors
    assert caught.value.code == "Transport" and caught.value.dispatched is None
    assert len(commands) == 1 and commands[0]["command"]["request_key"] == "once"
    assert "credential" not in commands[0]


def test_deadline_bounds_incomplete_handshake():
    def fake(stream):
        stream.recv(1024)
        time.sleep(0.15)

    port, thread, errors = fake_peer(fake)
    client = LocalContextClient(LocalBrokerConnection(port, "e" * 64, "a" * 64), timeout=0.05)
    with pytest.raises(LocalBrokerError) as caught:
        client.source_revision("docs")
    thread.join(5)
    assert not errors and not thread.is_alive()
    assert caught.value.code == "Timeout" and caught.value.dispatched is False


def test_invalid_local_requests_do_not_consume_grants_or_kill_other_clients(broker):
    connection = grant(broker, "agent", ["docs"])
    client = LocalContextClient(connection, max_pending=1)
    with client._slots, pytest.raises(LocalBrokerError, match="Busy"):
        client.compile({"query": "evidence"})
    for value in [float("nan"), object(), "\ud800"]:
        with pytest.raises(LocalBrokerError, match="InvalidInput"):
            client.compile({"query": value})
    with pytest.raises(LocalBrokerError, match="LimitExceeded"):
        client.compile({"query": "x" * (2 * 1024 * 1024)})
    assert client.source_revision("docs")["version"] == "0"


@pytest.mark.parametrize(
    "corruption",
    ["duplicate", "nonfinite", "id", "timing-shape", "timing-value", "outcome-shape", "unknown-error"],
)
def test_host_malformed_reply_closes_worker_without_echo(broker, corruption):
    reply = {
        "protocol": "cigar.context-broker.v1",
        "id": 2,
        "timing": {"queue_us": 0, "service_us": 0},
        "outcome": {"status": "ok", "result": None},
    }
    if corruption == "id":
        reply["id"] = True
    elif corruption == "timing-shape":
        reply["timing"] = {}
    elif corruption == "timing-value":
        reply["timing"]["queue_us"] = 0.5
    elif corruption == "outcome-shape":
        reply["outcome"] = []
    elif corruption == "unknown-error":
        reply["outcome"] = {"status": "error", "error": "PRIVATE_PATH", "dispatched": False}
    wire = json.dumps(reply).encode()
    if corruption == "duplicate":
        wire = wire[:-1] + b',"id":2}'
    elif corruption == "nonfinite":
        wire = wire.replace(b'"result": null', b'"result": NaN')
    original = broker._jobs.put_nowait

    def receive(job):
        if job is None:
            return original(job)
        job[1].put_nowait(wire + b"\n")

    with patch.object(broker._jobs, "put_nowait", side_effect=receive):
        with pytest.raises(LocalBrokerError) as caught:
            broker.source_revision("PRIVATE_PATH")
    assert caught.value.code == "Transport" and caught.value.dispatched is None
    assert "PRIVATE_PATH" not in str(caught.value)
    assert broker.cleanup_complete
    with pytest.raises(LocalBrokerError, match="Closed"):
        broker.capabilities()
    with pytest.raises(LocalBrokerError) as closed:
        broker.source_revision("docs")
    assert closed.value.code == "Closed" and closed.value.dispatched is False


@pytest.mark.parametrize("field", ["core_version", "capabilities"])
def test_incompatible_broker_hello_reaps_worker(broker, field):
    hello = broker.capabilities()
    hello[field] = "old" if field == "core_version" else []
    created = []
    original = context.subprocess.Popen

    def spawn(*args, **kwargs):
        process = original(*args, **kwargs)
        created.append(process)
        return process

    with (
        patch.object(context.subprocess, "Popen", side_effect=spawn),
        patch.object(LocalContextBroker, "_call", return_value=hello),
        pytest.raises(LocalBrokerError, match="IncompatibleWorker"),
    ):
        LocalContextBroker("incompatible", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    assert len(created) == 1
    assert created[0].poll() is not None and created[0].stdin.closed and created[0].stdout.closed


def test_launch_failure_is_content_free_and_malformed_grant_closes_host(broker):
    with patch.object(context.subprocess, "Popen", side_effect=OSError("PRIVATE_EXECUTABLE")):
        with pytest.raises(LocalBrokerError) as caught:
            LocalContextBroker("launch", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    assert caught.value.code == "WorkerUnavailable" and caught.value.dispatched is False
    assert "PRIVATE_EXECUTABLE" not in str(caught.value)
    with patch.object(broker, "_call", return_value={"epoch": "wrong", "secret": "a" * 64}):
        with pytest.raises(LocalBrokerError) as caught:
            grant(broker, "agent", ["docs"])
    assert caught.value.code == "Transport" and caught.value.dispatched is None
    assert broker.cleanup_complete


def test_provenance_and_edge_changes_invalidate_tickets_and_forgotten_tickets_are_denied(broker):
    ingest(broker, "docs", "first", "the first fact")
    ingest(broker, "other", "second", "the supporting fact")
    assert broker.provenance("docs") == provenance()
    client = LocalContextClient(grant(broker, "agent", ["docs", "other"]))
    before = client.compile({"query": "fact", "required": ["first"]})
    versions = {source: broker.source_revision(source) for source in ["docs", "other"]}
    # Directed edges change only the source of the first endpoint. Extra CAS
    # entries are rejected atomically; contradictions require both sources.
    with pytest.raises(LocalBrokerError, match="InvalidInput"):
        broker.set_edge("first", "second", "requires", True, versions)
    client.revalidate(before["ticket"])
    updated = broker.set_edge("first", "second", "requires", True, {"docs": versions["docs"]})
    assert updated["docs"] != versions["docs"]
    with pytest.raises(LocalBrokerError, match="Stale"):
        client.revalidate(before["ticket"])
    after = client.compile({"query": "fact", "required": ["first"]})
    client.revalidate(after["ticket"])
    client.forget_ticket(after["ticket"])
    with pytest.raises(LocalBrokerError, match="AccessDenied"):
        client.revalidate(after["ticket"])


@pytest.mark.parametrize(
    "options",
    [
        {"timeout": "30"},
        {"timeout": True},
        {"timeout": float("inf")},
        {"timeout": 10**400},
        {"queue_timeout_ms": False},
        {"max_pending": 0},
    ],
)
def test_invalid_client_options_are_rejected_before_socket_creation(options):
    connection = LocalBrokerConnection(12345, "e" * 64, "a" * 64)
    with patch("cigar_sdk.broker.socket.socket") as socket_factory:
        with pytest.raises(LocalBrokerError, match="InvalidInput"):
            LocalContextClient(connection, **options)
    socket_factory.assert_not_called()


def test_deadline_includes_request_encoding():
    connection = LocalBrokerConnection(12345, "e" * 64, "a" * 64)
    client = LocalContextClient(connection, timeout=1)
    # The clock advances while encoding, before connect or authentication can occur.
    with patch("cigar_sdk.broker.time.monotonic", side_effect=[0, 2]):
        with pytest.raises(LocalBrokerError) as caught:
            client.source_revision("docs")
    assert caught.value.code == "Timeout" and caught.value.dispatched is False


@pytest.mark.parametrize("wire", [b"{}", b"[]", b"null", b'{"proof":"bad"}'])
def test_malformed_server_identity_gets_no_proof_or_context(wire):
    observed = []

    def fake(stream):
        deadline = time.monotonic() + 3
        _read(stream, 1024, deadline)
        _send(stream, wire, deadline)
        observed.append(stream.recv(1024))

    port, thread, errors = fake_peer(fake)
    client = LocalContextClient(LocalBrokerConnection(port, "e" * 64, "a" * 64))
    with pytest.raises(LocalBrokerError) as caught:
        client.compile({"query": "PRIVATE_CONTEXT"})
    thread.join(5)
    assert not errors and not thread.is_alive() and observed == [b""]
    assert caught.value.code == "Authentication" and caught.value.dispatched is False


@pytest.mark.parametrize("failure", ["oversized", "partial-prefix", "malformed"])
def test_authenticated_response_failure_is_unknown_without_redispatch(failure):
    commands = []

    def fake(stream):
        commands.append(authenticated_command(stream))
        if failure == "oversized":
            stream.sendall((8 * 1024 * 1024 + 1).to_bytes(4, "big"))
        elif failure == "partial-prefix":
            stream.sendall(b"\x00")
            time.sleep(0.4)
        else:
            _send(stream, b"{not-json}", time.monotonic() + 3)

    port, thread, errors = fake_peer(fake)
    client = LocalContextClient(LocalBrokerConnection(port, "e" * 64, "a" * 64), timeout=0.2)
    with pytest.raises(LocalBrokerError) as caught:
        client.propose_source("once", "docs", {"epoch": "e" * 64, "version": "0"}, [])
    thread.join(5)
    assert not errors and not thread.is_alive() and len(commands) == 1
    assert caught.value.code == ("Timeout" if failure == "partial-prefix" else "Transport")
    assert caught.value.dispatched is None
