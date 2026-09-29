"""Explicit same-host broker. No discovery, public binds, provider calls or automatic retries."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
import secrets
import socket
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self, cast

from cigar_sdk.broker_types import (
    LocalBrokerAgentLimits,
    LocalBrokerAgentQueueLimits,
    LocalBrokerCapabilities,
    LocalBrokerConnectionConfig,
    LocalBrokerContext,
    LocalBrokerExecutionBinding,
    LocalBrokerExecutionHandoff,
    LocalBrokerExecutionReview,
    LocalBrokerLimits,
    LocalBrokerProposal,
    LocalBrokerProposalStatus,
    LocalBrokerQueueLimits,
    LocalBrokerSourceProvenance,
    LocalBrokerSourceReceipt,
    LocalBrokerSourceRevision,
    LocalBrokerSourceTransaction,
    LocalBrokerStorageOptions,
    LocalBrokerSubmission,
    LocalBrokerTransportLimits,
)
from cigar_sdk.context import _WorkerChannel
from cigar_sdk.context_types import (
    LocalAnswerDraft,
    LocalAnswerPolicy,
    LocalCitation,
    LocalClaimReview,
    LocalContextLimits,
    LocalContextRequest,
    LocalDocument,
    LocalEdgeKind,
    LocalSelectionExplanation,
    LocalViewAssessment,
    LocalViewSpec,
)
from cigar_sdk.local_runtime import LOCAL_CONTEXT_CORE_VERSION, LocalContextError

_PROTOCOL = "cigar.context-broker.v1"
_MAX_FRAME = 2 * 1024 * 1024
_MAX_RESPONSE = 8 * 1024 * 1024
_MAX_HANDSHAKE = 1024
_ERRORS = frozenset(
    {
        "AccessDenied",
        "Stale",
        "Conflict",
        "Quota",
        "InvalidInput",
        "Unavailable",
        "LimitExceeded",
        "RequiredUnavailable",
        "BudgetUnsatisfiable",
        "Tokenizer",
        "Integrity",
        "BaseMismatch",
        "Expired",
        "Cancelled",
        "Closed",
    }
)


class LocalBrokerError(LocalContextError):
    """Content-free failure. dispatched=None means the sent operation's outcome is unknown.

    False proves no operation was dispatched; True accompanies a known server failure.
    No outcome causes this library to retry a command automatically.
    """

    def __init__(self, code: str, *, dispatched: bool | None = False) -> None:
        self.dispatched = dispatched
        super().__init__(code)


def _hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _strict_loads(frame: bytes) -> Any:
    def members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def nonfinite(_: str) -> Any:
        raise ValueError

    return json.loads(frame.decode("utf-8"), object_pairs_hook=members, parse_constant=nonfinite)


def _result(reply: Any, request_id: int) -> Any:
    if (
        not isinstance(reply, dict)
        or set(reply) != {"protocol", "id", "outcome", "timing"}
        or reply["protocol"] != _PROTOCOL
        or type(reply["id"]) is not int
        or reply["id"] != request_id
    ):
        raise ValueError
    timing = reply["timing"]
    if not isinstance(timing, dict) or set(timing) != {"queue_us", "service_us"}:
        raise ValueError
    if any(type(value) is not int or not 0 <= value <= 9_007_199_254_740_991 for value in timing.values()):
        raise ValueError
    outcome = reply["outcome"]
    if not isinstance(outcome, dict):
        raise ValueError
    if outcome.get("status") == "ok" and set(outcome) == {"status", "result"}:
        return outcome["result"]
    if (
        set(outcome) != {"status", "error", "dispatched"}
        or outcome["status"] != "error"
        or outcome["error"] not in _ERRORS
        or type(outcome["dispatched"]) is not bool
    ):
        raise ValueError
    raise LocalBrokerError(outcome["error"], dispatched=outcome["dispatched"])


@dataclass(frozen=True, slots=True, repr=False)
class LocalBrokerConnection:
    """One host-issued grant. Repr is redacted; export() is sensitive protected-IPC material."""

    port: int
    epoch: str
    secret: str

    def __post_init__(self) -> None:
        if type(self.port) is not int or not 1 <= self.port <= 65535 or not _hex(self.epoch) or not _hex(self.secret):
            raise LocalBrokerError("InvalidInput")

    def __repr__(self) -> str:
        return "LocalBrokerConnection(<redacted>)"

    def export(self) -> LocalBrokerConnectionConfig:
        """Copy credentials for protected IPC to one agent. Never log the returned dictionary."""
        return {
            "schema": "cigar.broker-client.v1",
            "host": "127.0.0.1",
            "port": self.port,
            "epoch": self.epoch,
            "secret": self.secret,
        }

    @classmethod
    def from_config(cls, config: LocalBrokerConnectionConfig) -> Self:
        if (
            not isinstance(config, dict)
            or set(config) != {"schema", "host", "port", "epoch", "secret"}
            or config.get("schema") != "cigar.broker-client.v1"
            or config.get("host") != "127.0.0.1"
        ):
            raise LocalBrokerError("InvalidInput")
        return cls(config["port"], config["epoch"], config["secret"])


class LocalContextBroker(_WorkerChannel):
    """Trusted owner of one shared graph. Keep this object and its pipes outside agent control.

    Uses the existing PID guard and bounded, non-masking process cleanup. A host transport
    failure closes the broker because the host mutation may have completed. No restart/retry.
    """

    def __init__(
        self,
        domain: str,
        *,
        worker_path: str | Path | None = None,
        timeout: float = 30.0,
        graph: LocalContextLimits | None = None,
        retention: LocalBrokerLimits | None = None,
        queues: LocalBrokerQueueLimits | None = None,
        transport: LocalBrokerTransportLimits | None = None,
        storage: LocalBrokerStorageOptions | None = None,
    ) -> None:
        try:
            super().__init__(worker_path, timeout, ("--broker",))
        except LocalContextError as error:
            raise LocalBrokerError(error.code) from None
        try:
            hello = self._call(
                {
                    "op": "init",
                    "domain": domain,
                    "graph": graph or {},
                    "retention": retention or {},
                    "queues": queues or {},
                    "transport": transport or {},
                    **({"storage": storage} if storage is not None else {}),
                }
            )
            if (
                not isinstance(hello, dict)
                or hello.get("protocol") != _PROTOCOL
                or hello.get("core_version") != LOCAL_CONTEXT_CORE_VERSION
                or hello.get("host") != "127.0.0.1"
                or type(hello.get("port")) is not int
                or not 1 <= hello["port"] <= 65535
                or not _hex(hello.get("epoch"))
                or hello.get("max_frame_bytes") != _MAX_FRAME
                or hello.get("max_response_bytes") != _MAX_RESPONSE
                or hello.get("host_max_frame_bytes") != 32 * 1024 * 1024
                or hello.get("host_max_response_bytes") != 64 * 1024 * 1024
                or hello.get("requires_hol_services") is not False
                or hello.get("execution") != "single-owner-fair-dispatch"
            ):
                raise LocalBrokerError("IncompatibleWorker", dispatched=None)
            features = hello.get("capabilities")
            if (
                not isinstance(features, list)
                or any(not isinstance(value, str) for value in features)
                or "mutual_grant_proof.v1" not in features
            ):
                raise LocalBrokerError("IncompatibleWorker", dispatched=None)
            self._hello = cast(LocalBrokerCapabilities, copy.deepcopy(hello))
            if storage is not None:
                stored = hello.get("storage")
                if (
                    not isinstance(stored, dict)
                    or set(stored) != {"mode", "restored"}
                    or stored["mode"] != "sqlite-checkpoint.v1"
                    or type(stored["restored"]) is not bool
                ):
                    raise LocalBrokerError("IncompatibleWorker", dispatched=None)
        except BaseException:
            self.close()
            raise

    def _load_reply(self, value: bytes) -> Any:
        return _strict_loads(value)

    def _decode_reply(self, reply: Any, request_id: int) -> Any:
        return _result(reply, request_id)

    def _call(self, command: dict[str, Any]) -> Any:
        try:
            return super()._call(command)
        except LocalBrokerError:
            raise
        except LocalContextError as error:
            uncertain = error.code in {"Transport", "Timeout"}
            raise LocalBrokerError(error.code, dispatched=None if uncertain else False) from None

    def capabilities(self) -> LocalBrokerCapabilities:
        self._ensure_process_owner()
        if self._closed:
            raise LocalBrokerError("Closed")
        return copy.deepcopy(self._hello)

    def grant(
        self,
        view: LocalViewSpec,
        *,
        limits: LocalBrokerAgentLimits | None = None,
        queue: LocalBrokerAgentQueueLimits | None = None,
        lease_ms: int = 300_000,
    ) -> LocalBrokerConnection:
        result = self._call(
            {"op": "grant", "spec": {"view": view, "limits": limits or {}, "lease_ms": lease_ms}, "queue": queue or {}}
        )
        try:
            if (
                not isinstance(result, dict)
                or set(result) != {"epoch", "secret"}
                or result["epoch"] != self._hello["epoch"]
            ):
                raise ValueError
            return LocalBrokerConnection(self._hello["port"], result["epoch"], result["secret"])
        except (ValueError, TypeError, KeyError, LocalBrokerError):  # fmt: skip
            self.close()
            raise LocalBrokerError("Transport", dispatched=None) from None

    def revoke(self, agent: str) -> bool:
        return cast(bool, self._call({"op": "revoke", "agent": agent}))

    def source_revision(self, source: str) -> LocalBrokerSourceRevision:
        return cast(LocalBrokerSourceRevision, self._call({"op": "source_revision", "source": source}))

    def replace_source(
        self,
        source: str,
        expected: LocalBrokerSourceRevision,
        documents: list[LocalDocument],
        provenance: LocalBrokerSourceProvenance,
    ) -> LocalBrokerSourceReceipt:
        return cast(
            LocalBrokerSourceReceipt,
            self._call(
                {
                    "op": "replace_source",
                    "source": source,
                    "expected": expected,
                    "documents": documents,
                    "provenance": provenance,
                }
            ),
        )

    def begin_source_replace(
        self,
        source: str,
        expected: LocalBrokerSourceRevision,
        provenance: LocalBrokerSourceProvenance,
        *,
        lease_ms: int = 60_000,
    ) -> LocalBrokerSourceTransaction:
        """Stage an atomic replacement privately; old evidence remains visible until commit."""
        self._require_source_batches()
        return cast(
            LocalBrokerSourceTransaction,
            self._call(
                {
                    "op": "begin_source_replace",
                    "source": source,
                    "expected": expected,
                    "provenance": provenance,
                    "lease_ms": lease_ms,
                }
            ),
        )

    def append_source_documents(self, transaction: LocalBrokerSourceTransaction, documents: list[LocalDocument]) -> int:
        """Append a nonempty batch atomically; return the total staged document count."""
        self._require_source_batches()
        return cast(
            int,
            self._call({"op": "append_source_documents", "transaction": transaction, "documents": documents}),
        )

    def commit_source_replace(self, transaction: LocalBrokerSourceTransaction) -> LocalBrokerSourceReceipt:
        """Consume staging and recheck source CAS/provenance before one atomic replacement."""
        self._require_source_batches()
        return cast(LocalBrokerSourceReceipt, self._call({"op": "commit_source_replace", "transaction": transaction}))

    def abort_source_replace(self, transaction: LocalBrokerSourceTransaction) -> bool:
        """Discard staging without changing evidence. An absent or wrong-epoch handle returns False."""
        self._require_source_batches()
        return cast(bool, self._call({"op": "abort_source_replace", "transaction": transaction}))

    def replace_source_batches(
        self,
        source: str,
        expected: LocalBrokerSourceRevision,
        batches: Iterable[list[LocalDocument]],
        provenance: LocalBrokerSourceProvenance,
        *,
        lease_ms: int = 60_000,
    ) -> LocalBrokerSourceReceipt:
        """Consume bounded batches then commit once. An empty iterable withdraws the source.

        Staging shares retention with tickets/proposals and expires within five minutes.
        On failure, best-effort abort preserves the primary exception. No automatic retry;
        a lost commit acknowledgement still has an unknown outcome and closes the owner.
        """
        transaction = self.begin_source_replace(source, expected, provenance, lease_ms=lease_ms)
        try:
            for batch in batches:
                self.append_source_documents(transaction, batch)
            return self.commit_source_replace(transaction)
        except BaseException:
            try:
                self.abort_source_replace(transaction)
            except BaseException:
                # Cleanup must never mask a caller failure or an uncertain commit outcome.
                pass
            raise

    def _require_source_batches(self) -> None:
        if "source_batches.v1" not in self.capabilities()["capabilities"]:
            raise LocalBrokerError("IncompatibleWorker")

    def provenance(self, source: str) -> LocalBrokerSourceProvenance | None:
        return cast(LocalBrokerSourceProvenance | None, self._call({"op": "provenance", "source": source}))

    def chunks_at_lines(self, document: LocalDocument, starts: list[int]) -> list[LocalDocument]:
        """Host-only preprocessing; does not admit evidence or change its provenance."""
        if "document_boundaries.v1" not in self.capabilities()["capabilities"]:
            raise LocalBrokerError("IncompatibleWorker")
        return cast(list[LocalDocument], self._call({"op": "chunks_at_lines", "document": document, "starts": starts}))

    def set_edge(
        self,
        from_id: str,
        to_id: str,
        kind: LocalEdgeKind,
        present: bool,
        expected: dict[str, LocalBrokerSourceRevision],
    ) -> dict[str, LocalBrokerSourceRevision]:
        return cast(
            dict[str, LocalBrokerSourceRevision],
            self._call(
                {"op": "set_edge", "from": from_id, "to": to_id, "kind": kind, "present": present, "expected": expected}
            ),
        )

    def proposal(self, proposal_id: str) -> LocalBrokerProposal:
        return cast(LocalBrokerProposal, self._call({"op": "proposal", "proposal_id": proposal_id}))

    def admit_proposal(self, proposal_id: str, provenance: LocalBrokerSourceProvenance) -> LocalBrokerSourceReceipt:
        return cast(
            LocalBrokerSourceReceipt,
            self._call({"op": "admit_proposal", "proposal_id": proposal_id, "provenance": provenance}),
        )

    def reject_proposal(self, proposal_id: str) -> None:
        self._call({"op": "reject_proposal", "proposal_id": proposal_id})

    def submission(self, ticket: str) -> LocalBrokerSubmission:
        return cast(LocalBrokerSubmission, self._call({"op": "submission", "ticket": ticket}))

    def check_answer(
        self, ticket: str, submission_id: str, reviews: list[LocalClaimReview], policy: LocalAnswerPolicy | None = None
    ) -> LocalViewAssessment:
        return cast(
            LocalViewAssessment,
            self._call(
                {
                    "op": "check_answer",
                    "ticket": ticket,
                    "submission_id": submission_id,
                    "reviews": reviews,
                    "policy": policy or {},
                }
            ),
        )

    def bind_execution(
        self, ticket: str, submission_id: str, effect_id: str, intent_digest: str, review: LocalBrokerExecutionReview
    ) -> LocalBrokerExecutionBinding:
        """Bind the exact existing effect intent to current reviewed context. Does not authorize or send."""
        self._require_execution_handoff()
        return cast(
            LocalBrokerExecutionBinding,
            self._call(
                {
                    "op": "bind_execution",
                    "ticket": ticket,
                    "submission_id": submission_id,
                    "effect_id": effect_id,
                    "intent_digest": intent_digest,
                    "review": review,
                }
            ),
        )

    def take_execution_handoff(
        self, binding: LocalBrokerExecutionBinding, review: LocalBrokerExecutionReview
    ) -> LocalBrokerExecutionHandoff:
        """Consume once with current host review authority. Uncertain outcomes require effect reconciliation."""
        self._require_execution_handoff()
        return cast(
            LocalBrokerExecutionHandoff,
            self._call(
                {
                    "op": "take_execution_handoff",
                    "binding": binding,
                    "review": review,
                }
            ),
        )

    def _require_execution_handoff(self) -> None:
        if "execution_handoff.v1" not in self.capabilities()["capabilities"]:
            raise LocalBrokerError("IncompatibleWorker")


class LocalContextClient:
    """Restricted per-agent client. One fresh mutually authenticated connection per operation.

    Requests have a total deadline and bounded concurrency. No persistent socket or worker is
    owned by the client. Construct a fresh client after fork; send only its connection export
    through protected IPC. Losing one client does not close the host's graph.
    """

    def __init__(
        self,
        connection: LocalBrokerConnection,
        *,
        timeout: float = 30.0,
        queue_timeout_ms: int = 30_000,
        max_pending: int = 4,
    ) -> None:
        if (
            not isinstance(connection, LocalBrokerConnection)
            or type(timeout) not in {int, float}
            or not 0 < timeout <= 300
            or not math.isfinite(timeout)
            or type(queue_timeout_ms) is not int
            or not 1 <= queue_timeout_ms <= 86_400_000
            or type(max_pending) is not int
            or not 1 <= max_pending <= 128
        ):
            raise LocalBrokerError("InvalidInput")
        self._connection = connection
        self._timeout = timeout
        self._queue_timeout = queue_timeout_ms
        self._owner_pid = os.getpid()
        self._slots = threading.BoundedSemaphore(max_pending)

    def _call(self, command: dict[str, Any]) -> Any:
        if os.getpid() != self._owner_pid:
            raise LocalBrokerError("ForkedProcess")
        if not self._slots.acquire(blocking=False):
            raise LocalBrokerError("Busy")
        sent = False
        deadline = time.monotonic() + self._timeout
        try:
            try:
                frame = json.dumps(
                    {"protocol": _PROTOCOL, "id": 1, "wait_ms": self._queue_timeout, "command": command},
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            except (ValueError, TypeError, UnicodeError, RecursionError):  # fmt: skip
                raise LocalBrokerError("InvalidInput") from None
            if len(frame) > _MAX_FRAME:
                raise LocalBrokerError("LimitExceeded")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
                stream.settimeout(_remaining(deadline))
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                stream.connect(("127.0.0.1", self._connection.port))
                self._authenticate(stream, deadline)
                # Mark uncertain before sending any command bytes, including a partial prefix.
                sent = True
                _send(stream, frame, deadline)
                return _result(_strict_loads(_read(stream, _MAX_RESPONSE, deadline)), 1)
        except LocalBrokerError:
            raise
        except TimeoutError:
            raise LocalBrokerError("Timeout", dispatched=None if sent else False) from None
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):  # fmt: skip
            raise LocalBrokerError("Transport", dispatched=None if sent else False) from None
        finally:
            self._slots.release()

    def _authenticate(self, stream: socket.socket, deadline: float) -> None:
        connection = self._connection
        grant = hashlib.sha256(
            b"cigar.broker-grant-id.v1\0" + connection.epoch.encode() + connection.secret.encode()
        ).hexdigest()
        nonce = secrets.token_hex(32)
        hello = {"protocol": _PROTOCOL, "epoch": connection.epoch, "grant_id": grant, "nonce": nonce}
        _send(stream, json.dumps(hello, separators=(",", ":")).encode(), deadline)
        server = _strict_loads(_read(stream, _MAX_HANDSHAKE, deadline))
        if (
            not isinstance(server, dict)
            or set(server) != {"protocol", "epoch", "grant_id", "client_nonce", "server_nonce", "proof"}
            or server["protocol"] != _PROTOCOL
            or server["epoch"] != connection.epoch
            or server["grant_id"] != grant
            or server["client_nonce"] != nonce
            or not _hex(server["server_nonce"])
            or not _hex(server["proof"])
        ):
            raise LocalBrokerError("Authentication")
        transcript = (connection.epoch + grant + nonce + server["server_nonce"]).encode("ascii")
        key = bytes.fromhex(connection.secret)
        expected = hmac.digest(key, b"cigar.broker-server-proof.v1\0" + transcript, "sha256").hex()
        if not hmac.compare_digest(expected, server["proof"]):
            raise LocalBrokerError("Authentication")
        proof = hmac.digest(key, b"cigar.broker-client-proof.v1\0" + transcript, "sha256").hex()
        _send(stream, json.dumps({"protocol": _PROTOCOL, "proof": proof}, separators=(",", ":")).encode(), deadline)

    def compile(self, request: LocalContextRequest) -> LocalBrokerContext:
        return cast(LocalBrokerContext, self._call({"op": "compile", "request": request}))

    def revalidate(self, ticket: str) -> None:
        self._call({"op": "revalidate", "ticket": ticket})

    def explain(self, ticket: str) -> LocalSelectionExplanation:
        """Explain own selected evidence after current grant, provenance and ticket checks."""
        return cast(LocalSelectionExplanation, self._call({"op": "explain", "ticket": ticket}))

    def citations(self, ticket: str, node_id: str) -> list[LocalCitation]:
        return cast(list[LocalCitation], self._call({"op": "citations", "ticket": ticket, "node_id": node_id}))

    def source_revision(self, source: str) -> LocalBrokerSourceRevision:
        return cast(LocalBrokerSourceRevision, self._call({"op": "source_revision", "source": source}))

    def propose_source(
        self, request_key: str, source: str, expected: LocalBrokerSourceRevision, documents: list[LocalDocument]
    ) -> LocalBrokerProposalStatus:
        return cast(
            LocalBrokerProposalStatus,
            self._call(
                {
                    "op": "propose_source",
                    "request_key": request_key,
                    "source": source,
                    "expected": expected,
                    "documents": documents,
                }
            ),
        )

    def proposal_status(self, request_key: str) -> LocalBrokerProposalStatus:
        return cast(LocalBrokerProposalStatus, self._call({"op": "proposal_status", "request_key": request_key}))

    def forget_proposal(self, request_key: str) -> None:
        self._call({"op": "forget_proposal", "request_key": request_key})

    def forget_ticket(self, ticket: str) -> None:
        self._call({"op": "forget_ticket", "ticket": ticket})

    def submit_answer(self, ticket: str, draft: LocalAnswerDraft) -> str:
        return cast(str, self._call({"op": "submit_answer", "ticket": ticket, "draft": draft})["submission_id"])


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _send(stream: socket.socket, frame: bytes, deadline: float) -> None:
    stream.settimeout(_remaining(deadline))
    stream.sendall(len(frame).to_bytes(4, "big") + frame)


def _read(stream: socket.socket, limit: int, deadline: float) -> bytes:
    def exact(length: int) -> bytearray:
        data = bytearray(length)
        view = memoryview(data)
        read = 0
        while read < length:
            stream.settimeout(_remaining(deadline))
            count = stream.recv_into(view[read:])
            if count == 0:
                raise OSError
            read += count
        return data

    length = int.from_bytes(exact(4), "big")
    if not 0 < length <= limit:
        raise ValueError
    return bytes(exact(length))
