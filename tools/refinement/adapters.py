"""Provider-neutral, bounded proposal-model adapters.

Adapters only exchange strict JSON records. They never receive a repository path
and never execute a model-requested filesystem, Git, or command operation.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import select
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .canonical import CanonicalError, canonical_bytes, identity, loads, sha256_bytes
from .schema import SchemaError, SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas/refinement"
MAX_ACTION_BYTES = 1024 * 1024
MAX_TOOL_RESULT_BYTES = 1024 * 1024
HANDLE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
RETRYABLE = frozenset({408, 409, 429, 500, 502, 503, 504})
ADAPTERS = frozenset(
    {
        "recorded-proposal-v1",
        "subprocess-jsonl-v1",
        "patch-json-v1",
        "openai-compatible-tools-v1",
        "openai-responses-tools-v1",
    }
)


class AdapterError(RuntimeError):
    """A provider violated the bounded proposal transport contract."""


class ProviderFailure(AdapterError):
    """A bounded provider request failed after the configured retry policy."""


@dataclass
class Session:
    session_id: str
    packet: dict[str, Any]
    started: float
    turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    terminal: bool = False
    cancelled: bool = False
    seen_actions: set[str] = field(default_factory=set)
    provider_id: str | None = None
    pending_call_id: str | None = None
    history: list[Any] = field(default_factory=list)
    process: subprocess.Popen[bytes] | None = None


def _schema_validate(filename: str, value: Any) -> None:
    try:
        SchemaRegistry(SCHEMAS).validate(filename, value)
    except SchemaError as error:
        raise AdapterError(f"record failed {filename}") from error


def validate_action(value: Any, *, session_id: str | None = None) -> dict[str, Any]:
    """Validate schema plus the exact non-null field matrix for an action."""
    _schema_validate("model-action-v1.schema.json", value)
    assert isinstance(value, dict)
    required: dict[str, frozenset[str]] = {
        "search": frozenset({"query", "path"}),
        "read": frozenset({"path", "start_line", "max_lines"}),
        "inspect_git": frozenset({"query"}),
        "apply_patch": frozenset({"patch"}),
        "run_gate": frozenset({"gate"}),
        "request_context": frozenset({"resource"}),
        "finish": frozenset({"summary"}),
        "abandon": frozenset({"reason"}),
    }
    payload_fields = {
        "query",
        "path",
        "start_line",
        "max_lines",
        "patch",
        "gate",
        "resource",
        "summary",
        "reason",
    }
    expected = required[value["kind"]]
    actual = {field for field in payload_fields if value[field] is not None}
    if actual != expected:
        raise AdapterError("model action has an invalid field matrix")
    if session_id is not None and value["session_id"] != session_id:
        raise AdapterError("model action belongs to another session")
    if value["kind"] == "search" and not value["query"].strip():
        raise AdapterError("search query is empty")
    if value["kind"] == "apply_patch" and not value["patch"].startswith("diff --git "):
        raise AdapterError("apply_patch is not a Git unified diff")
    return dict(value)


def parse_action(payload: bytes, *, session_id: str) -> dict[str, Any]:
    try:
        value = loads(payload, maximum_bytes=MAX_ACTION_BYTES)
    except CanonicalError as error:
        raise AdapterError("provider action is not bounded strict JSON") from error
    return validate_action(value, session_id=session_id)


def _session_id(adapter_id: str, packet: dict[str, Any]) -> str:
    return (
        "session-"
        + hashlib.sha256(
            canonical_bytes({"adapter": adapter_id, "packet": packet})
        ).hexdigest()[:32]
    )


class BaseAdapter:
    adapter_id = ""

    def __init__(self, *, maximum_turns: int = 64) -> None:
        if not 1 <= maximum_turns <= 1000:
            raise AdapterError("maximum turns is outside its bound")
        self.maximum_turns = maximum_turns
        self._sessions: dict[str, Session] = {}

    def describe(self) -> dict[str, Any]:
        return {
            "schema_version": "cigar.refinement-adapter-description.v1",
            "adapter": self.adapter_id,
            "capabilities": ["strict-model-actions", "cancel", "usage"],
            "maximum_turns": self.maximum_turns,
        }

    def start(self, task_packet: dict[str, Any]) -> str:
        _schema_validate("task-packet-v1.schema.json", task_packet)
        session_id = _session_id(self.adapter_id, task_packet)
        if session_id in self._sessions:
            raise AdapterError("session already exists")
        self._sessions[session_id] = Session(
            session_id=session_id,
            packet=dict(task_packet),
            started=time.monotonic(),
        )
        return session_id

    def _before_next(self, session_id: str) -> Session:
        try:
            session = self._sessions[session_id]
        except KeyError as error:
            raise AdapterError("unknown adapter session") from error
        if session.terminal or session.cancelled:
            raise AdapterError("adapter session is terminal")
        if session.turns >= self.maximum_turns:
            self.cancel(session_id)
            raise AdapterError("adapter turn limit exceeded")
        session.turns += 1
        return session

    def _accept(self, session: Session, action: dict[str, Any]) -> dict[str, Any]:
        action = validate_action(action, session_id=session.session_id)
        if action["action_id"] in session.seen_actions:
            raise AdapterError("adapter repeated an action ID")
        session.seen_actions.add(action["action_id"])
        if action["kind"] in {"finish", "abandon"}:
            session.terminal = True
            process = session.process
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
        return action

    def next(
        self, session_id: str, tool_result: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    def cancel(self, session_id: str) -> dict[str, Any]:
        try:
            session = self._sessions[session_id]
        except KeyError as error:
            raise AdapterError("unknown adapter session") from error
        if session.process is not None and session.process.poll() is None:
            try:
                os.killpg(session.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            session.process.wait(timeout=5)
        if session.process is not None:
            if session.process.stdin is not None and not session.process.stdin.closed:
                session.process.stdin.close()
            if session.process.stdout is not None:
                session.process.stdout.close()
        session.cancelled = True
        session.terminal = True
        return {"session_id": session_id, "status": "cancelled"}

    def usage(self, session_id: str) -> dict[str, Any]:
        try:
            session = self._sessions[session_id]
        except KeyError as error:
            raise AdapterError("unknown adapter session") from error
        record = {
            "schema_version": "cigar.refinement-adapter-usage.v1",
            "adapter": self.adapter_id,
            "session_id": session_id,
            "turns": session.turns,
            "input_tokens": session.input_tokens,
            "output_tokens": session.output_tokens,
            "cost_usd": round(session.cost_usd, 8),
            "elapsed_seconds": round(time.monotonic() - session.started, 6),
            "cancelled": session.cancelled,
            "terminal": session.terminal,
        }
        record["usage_id"] = identity(record)
        return record


class RecordedAdapter(BaseAdapter):
    adapter_id = "recorded-proposal-v1"

    def __init__(
        self, actions: list[dict[str, Any]], *, maximum_turns: int = 64
    ) -> None:
        super().__init__(maximum_turns=maximum_turns)
        self._actions = [dict(action) for action in actions]
        self._positions: dict[str, int] = {}

    def start(self, task_packet: dict[str, Any]) -> str:
        session_id = super().start(task_packet)
        self._positions[session_id] = 0
        return session_id

    def next(
        self, session_id: str, tool_result: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        session = self._before_next(session_id)
        position = self._positions[session_id]
        if position >= len(self._actions):
            raise AdapterError("recorded action stream ended without a terminal action")
        self._positions[session_id] = position + 1
        action = dict(self._actions[position])
        action["session_id"] = session_id
        return self._accept(session, action)


def _executable_identity(path: Path) -> tuple[str, str]:
    if not path.is_absolute() or path.is_symlink():
        raise AdapterError("adapter executable must be an absolute real file")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(resolved, os.X_OK)
    ):
        raise AdapterError("adapter executable metadata is unsafe")
    with resolved.open("rb") as stream:
        return str(resolved), hashlib.file_digest(stream, "sha256").hexdigest()


class SubprocessJsonlAdapter(BaseAdapter):
    adapter_id = "subprocess-jsonl-v1"

    def __init__(
        self,
        executable: Path,
        arguments: tuple[str, ...] = (),
        *,
        maximum_turns: int = 64,
        timeout_seconds: int = 60,
    ) -> None:
        super().__init__(maximum_turns=maximum_turns)
        self.executable, self.executable_sha256 = _executable_identity(executable)
        if len(arguments) > 128 or any(
            not item or "\x00" in item or len(item) > 4096 for item in arguments
        ):
            raise AdapterError("subprocess arguments are invalid")
        if not 1 <= timeout_seconds <= 3600:
            raise AdapterError("subprocess timeout is invalid")
        self.arguments = tuple(arguments)
        self.timeout_seconds = timeout_seconds

    def describe(self) -> dict[str, Any]:
        result = super().describe()
        result.update(
            {
                "executable": self.executable,
                "executable_sha256": self.executable_sha256,
                "arguments_sha256": sha256_bytes(canonical_bytes(list(self.arguments))),
            }
        )
        return result

    def start(self, task_packet: dict[str, Any]) -> str:
        session_id = super().start(task_packet)
        environment = {
            key: os.environ[key]
            for key in ("LANG", "LC_ALL", "PATH", "SYSTEMROOT", "TZ", "WINDIR")
            if key in os.environ
        }
        environment.update({"CI": "true", "NO_COLOR": "1", "PYTHONHASHSEED": "0"})
        try:
            process = subprocess.Popen(
                [self.executable, *self.arguments],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                shell=False,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            self._sessions.pop(session_id, None)
            raise AdapterError("proposal subprocess could not start") from error
        self._sessions[session_id].process = process
        assert process.stdin is not None
        process.stdin.write(
            canonical_bytes(
                {
                    "schema_version": "cigar.refinement-adapter-start.v1",
                    "session_id": session_id,
                    "task_packet": task_packet,
                }
            )
            + b"\n"
        )
        process.stdin.flush()
        return session_id

    def next(
        self, session_id: str, tool_result: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        session = self._before_next(session_id)
        process = session.process
        assert (
            process is not None
            and process.stdin is not None
            and process.stdout is not None
        )
        if tool_result is not None:
            _schema_validate("tool-result-v1.schema.json", tool_result)
            process.stdin.write(canonical_bytes(tool_result) + b"\n")
            process.stdin.flush()
        ready, _, _ = select.select([process.stdout], [], [], self.timeout_seconds)
        if not ready:
            self.cancel(session_id)
            raise ProviderFailure("proposal subprocess timed out")
        line = process.stdout.readline(MAX_ACTION_BYTES + 2)
        if not line or len(line) > MAX_ACTION_BYTES + 1 or not line.endswith(b"\n"):
            self.cancel(session_id)
            raise AdapterError("proposal subprocess emitted an invalid JSONL record")
        action = parse_action(line[:-1], session_id=session_id)
        return self._accept(session, action)


PatchProvider = Callable[[dict[str, Any]], bytes]


class PatchJsonAdapter(BaseAdapter):
    adapter_id = "patch-json-v1"

    def __init__(self, provider: PatchProvider, *, maximum_turns: int = 2) -> None:
        super().__init__(maximum_turns=maximum_turns)
        self.provider = provider
        self._queues: dict[str, list[dict[str, Any]]] = {}

    def start(self, task_packet: dict[str, Any]) -> str:
        session_id = super().start(task_packet)
        try:
            response = loads(
                self.provider(dict(task_packet)), maximum_bytes=MAX_ACTION_BYTES
            )
        except (CanonicalError, OSError) as error:
            raise AdapterError("patch-only provider response is invalid") from error
        if not isinstance(response, dict) or set(response) != {
            "hypothesis",
            "patch",
            "summary",
        }:
            raise AdapterError("patch-only response has an invalid shape")
        if (
            response["hypothesis"] != task_packet["hypothesis"]
            or not isinstance(response["patch"], str)
            or not isinstance(response["summary"], str)
        ):
            raise AdapterError("patch-only response changed the hypothesis")
        base = {
            "schema_version": "cigar.refinement-model-action.v1",
            "session_id": session_id,
            "query": None,
            "path": None,
            "start_line": None,
            "max_lines": None,
            "gate": None,
            "resource": None,
            "reason": None,
        }
        self._queues[session_id] = [
            {
                **base,
                "action_id": "patch-1",
                "kind": "apply_patch",
                "patch": response["patch"],
                "summary": None,
            },
            {
                **base,
                "action_id": "finish-1",
                "kind": "finish",
                "patch": None,
                "summary": response["summary"],
            },
        ]
        return session_id

    def next(
        self, session_id: str, tool_result: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        session = self._before_next(session_id)
        queue = self._queues[session_id]
        if not queue:
            raise AdapterError("patch-only action stream is exhausted")
        return self._accept(session, queue.pop(0))


Transport = Callable[
    [str, dict[str, str], bytes, int], tuple[int, dict[str, str], bytes]
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _stdlib_transport(
    endpoint: str, headers: dict[str, str], body: bytes, timeout: int
) -> tuple[int, dict[str, str], bytes]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(
        endpoint, data=body, headers=headers, method="POST"
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(MAX_ACTION_BYTES + 1)
            return response.status, dict(response.headers.items()), payload
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read(MAX_ACTION_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as error:
        raise ProviderFailure("provider transport failed") from error


def _validate_endpoint(endpoint: str, *, hosted: bool) -> None:
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/responses"
    ):
        raise AdapterError("provider endpoint is not an exact Responses endpoint")
    if hosted:
        if endpoint != "https://api.openai.com/v1/responses":
            raise AdapterError(
                "hosted endpoint must be the official Responses endpoint"
            )
    elif not (
        parsed.scheme == "https"
        or (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "::1"}
            and parsed.port is not None
        )
    ):
        raise AdapterError(
            "compatible HTTP endpoint must use HTTPS or explicit loopback"
        )


ACTION_PARAMETERS: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "action_id",
        "session_id",
        "kind",
        "query",
        "path",
        "start_line",
        "max_lines",
        "patch",
        "gate",
        "resource",
        "summary",
        "reason",
    ],
    "properties": {
        "schema_version": {
            "type": "string",
            "const": "cigar.refinement-model-action.v1",
        },
        "action_id": {"type": "string", "maxLength": 128},
        "session_id": {"type": "string", "maxLength": 128},
        "kind": {
            "type": "string",
            "enum": [
                "search",
                "read",
                "inspect_git",
                "apply_patch",
                "run_gate",
                "request_context",
                "finish",
                "abandon",
            ],
        },
        "query": {"type": ["string", "null"], "maxLength": 16384},
        "path": {"type": ["string", "null"], "maxLength": 4096},
        "start_line": {"type": ["integer", "null"], "minimum": 1, "maximum": 100000000},
        "max_lines": {"type": ["integer", "null"], "minimum": 1, "maximum": 10000},
        "patch": {"type": ["string", "null"], "maxLength": 1048576},
        "gate": {"type": ["string", "null"], "maxLength": 16384},
        "resource": {"type": ["string", "null"], "maxLength": 16384},
        "summary": {"type": ["string", "null"], "maxLength": 16384},
        "reason": {"type": ["string", "null"], "maxLength": 16384},
    },
}


class ResponsesAdapter(BaseAdapter):
    adapter_id = "openai-compatible-tools-v1"

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        instructions: str,
        credential_handle: str | None = None,
        hosted: bool = False,
        transport: Transport = _stdlib_transport,
        maximum_turns: int = 64,
        timeout_seconds: int = 60,
        maximum_retries: int = 2,
        maximum_response_bytes: int = MAX_ACTION_BYTES,
        temperature: float | None = None,
        reasoning_effort: str | None = None,
    ) -> None:
        super().__init__(maximum_turns=maximum_turns)
        _validate_endpoint(endpoint, hosted=hosted)
        if (
            not model
            or len(model) > 256
            or not instructions
            or len(instructions.encode()) > MAX_ACTION_BYTES
            or credential_handle is not None
            and HANDLE.fullmatch(credential_handle) is None
            or not 1 <= timeout_seconds <= 3600
            or not 0 <= maximum_retries <= 8
            or not 1 <= maximum_response_bytes <= MAX_ACTION_BYTES
            or temperature is not None
            and (
                isinstance(temperature, bool)
                or not isinstance(temperature, (int, float))
                or not 0 <= temperature <= 2
            )
            or reasoning_effort
            not in {None, "none", "low", "medium", "high", "xhigh", "max"}
        ):
            raise AdapterError("Responses adapter configuration is invalid")
        self.endpoint = endpoint
        self.model = model
        self.instructions = instructions
        self.credential_handle = credential_handle
        self.hosted = hosted
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.maximum_retries = maximum_retries
        self.maximum_response_bytes = maximum_response_bytes
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort

    def describe(self) -> dict[str, Any]:
        result = super().describe()
        result.update(
            {
                "endpoint": self.endpoint,
                "model": self.model,
                "credential_handle": self.credential_handle,
                "instructions_sha256": hashlib.sha256(
                    self.instructions.encode()
                ).hexdigest(),
                "credential_resolved": False,
                "temperature": self.temperature,
                "reasoning_effort": self.reasoning_effort,
            }
        )
        return result

    def _request(
        self, session: Session, tool_result: dict[str, Any] | None
    ) -> dict[str, Any]:
        if tool_result is None:
            if session.history:
                raise AdapterError("initial provider request has existing history")
            session.history.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": canonical_bytes(
                                {
                                    "session_id": session.session_id,
                                    "task_packet": session.packet,
                                }
                            ).decode(),
                        }
                    ],
                }
            )
            model_input: Any = list(session.history)
        else:
            _schema_validate("tool-result-v1.schema.json", tool_result)
            if session.pending_call_id is None:
                raise AdapterError("tool result has no pending provider call")
            session.history.append(
                {
                    "type": "function_call_output",
                    "call_id": session.pending_call_id,
                    "output": canonical_bytes(tool_result).decode(),
                }
            )
            model_input = list(session.history)
        request: dict[str, Any] = {
            "model": self.model,
            "instructions": self.instructions,
            "input": model_input,
            "tools": [
                {
                    "type": "function",
                    "name": "model_action",
                    "description": "Emit exactly one bounded CIGAR ModelAction.",
                    "parameters": ACTION_PARAMETERS,
                    "strict": True,
                }
            ],
            "tool_choice": {"type": "function", "name": "model_action"},
            "parallel_tool_calls": False,
            "store": False,
        }
        if self.temperature is not None:
            request["temperature"] = self.temperature
        if self.reasoning_effort is not None:
            request["reasoning"] = {"effort": self.reasoning_effort}
        body = canonical_bytes(request)
        headers = {"Content-Type": "application/json"}
        if self.credential_handle is not None:
            credential = os.environ.get(self.credential_handle)
            if not credential:
                raise ProviderFailure("configured credential handle is unavailable")
            headers["Authorization"] = "Bearer " + credential
        last_status = 0
        for attempt in range(self.maximum_retries + 1):
            status, _, payload = self.transport(
                self.endpoint, headers, body, self.timeout_seconds
            )
            last_status = status
            if len(payload) > self.maximum_response_bytes:
                raise ProviderFailure("provider response exceeded its byte bound")
            if status == 200:
                try:
                    response = loads(payload, maximum_bytes=self.maximum_response_bytes)
                except CanonicalError as error:
                    raise AdapterError(
                        "provider response is not strict JSON"
                    ) from error
                if not isinstance(response, dict):
                    raise AdapterError("provider response root is not an object")
                return response
            if status not in RETRYABLE or attempt == self.maximum_retries:
                break
        raise ProviderFailure(f"provider request failed with HTTP {last_status}")

    def next(
        self, session_id: str, tool_result: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        session = self._before_next(session_id)
        response = self._request(session, tool_result)
        provider_id = response.get("id")
        output = response.get("output")
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or not isinstance(output, list)
        ):
            raise AdapterError("provider response envelope is malformed")
        calls = [
            item
            for item in output
            if isinstance(item, dict)
            and item.get("type") == "function_call"
            and item.get("name") == "model_action"
        ]
        if len(calls) != 1:
            raise AdapterError("provider must return exactly one model_action call")
        call = calls[0]
        call_id, arguments = call.get("call_id"), call.get("arguments")
        if (
            not isinstance(call_id, str)
            or not call_id
            or not isinstance(arguments, str)
        ):
            raise AdapterError("provider function call is malformed")
        usage = response.get("usage", {})
        if isinstance(usage, dict):
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            if (
                isinstance(input_tokens, int)
                and not isinstance(input_tokens, bool)
                and input_tokens >= 0
                and isinstance(output_tokens, int)
                and not isinstance(output_tokens, bool)
                and output_tokens >= 0
            ):
                session.input_tokens += input_tokens
                session.output_tokens += output_tokens
        session.provider_id = provider_id
        session.pending_call_id = call_id
        session.history.extend(output)
        action = parse_action(arguments.encode(), session_id=session_id)
        return self._accept(session, action)


class OpenAICompatibleAdapter(ResponsesAdapter):
    adapter_id = "openai-compatible-tools-v1"


class OpenAIResponsesAdapter(ResponsesAdapter):
    adapter_id = "openai-responses-tools-v1"

    def __init__(self, **kwargs: Any) -> None:
        kwargs["endpoint"] = "https://api.openai.com/v1/responses"
        kwargs["hosted"] = True
        super().__init__(**kwargs)
