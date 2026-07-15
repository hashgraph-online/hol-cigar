#!/usr/bin/env python3
"""Shared, bounded helpers for fixture-bound release-demo drivers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unicodedata
from pathlib import Path
from typing import Any, Callable, Never, Sequence

MAX_JSON = 8 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
DRIVER_SCHEMA = "cigar.demo-driver-result.v1"
MAX_RECORDED_OPERATIONS = 64
LOCAL_AUTHORIZATION = "Bearer cigar-demo-recorded-local-token"


class DriverError(Exception):
    """A content-free scenario-driver failure."""


def fail(message: str) -> Never:
    raise DriverError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON contains duplicate object keys")
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise DriverError("driver value cannot be canonicalized") from error


def digest_bytes(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def digest_value(value: Any) -> str:
    return digest_bytes(canonical(value))


def _cbor_head(major: int, argument: int) -> bytes:
    if argument < 0 or argument > 0xFFFF_FFFF_FFFF_FFFF:
        fail("recorded API integer exceeds its canonical bound")
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    for maximum, additional, width in (
        (0xFF, 24, 1),
        (0xFFFF, 25, 2),
        (0xFFFF_FFFF, 26, 4),
        (0xFFFF_FFFF_FFFF_FFFF, 27, 8),
    ):
        if argument <= maximum:
            return bytes([prefix | additional]) + argument.to_bytes(width, "big")
    fail("recorded API integer exceeds its canonical bound")


def deterministic_cbor(
    value: Any, depth: int = 0, budget: list[int] | None = None
) -> bytes:
    """Encode the bounded JSON subset used by frozen operation payloads."""
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        fail("recorded API payload exceeds canonical bounds")
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        if value < -(1 << 63):
            fail("recorded API integer is below i64")
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, str):
        encoded = unicodedata.normalize("NFC", value).encode("utf-8")
        return _cbor_head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(
            deterministic_cbor(item, depth + 1, budget) for item in value
        )
    if isinstance(value, dict):
        entries: list[tuple[bytes, Any]] = []
        for key, child in value.items():
            if not isinstance(key, str):
                fail("recorded API map key is not text")
            encoded_key = deterministic_cbor(
                unicodedata.normalize("NFC", key), depth + 1, budget
            )
            entries.append((encoded_key, child))
        entries.sort(key=lambda item: item[0])
        return _cbor_head(5, len(entries)) + b"".join(
            key + deterministic_cbor(child, depth + 1, budget) for key, child in entries
        )
    fail("recorded API payload contains a non-canonical value")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class RecordedOperation:
    """One exact unary exchange expected from the public CLI transport."""

    def __init__(
        self,
        operation_id: str,
        method: str,
        path: str,
        request: dict[str, Any] | None,
        response: dict[str, Any],
        *,
        idempotency_key: str | None = None,
        expected_revision: str | None = None,
        path_parameters: Sequence[tuple[str, str]] = (),
        action: Callable[[], None] | None = None,
    ) -> None:
        if (
            not operation_id
            or method not in {"GET", "POST"}
            or not path.startswith("/")
            or "?" in path
            or (method == "POST") != (request is not None)
            or not isinstance(response, dict)
            or len(path_parameters) > 8
        ):
            fail("recorded API operation is invalid")
        deterministic_cbor(response)
        if request is not None:
            deterministic_cbor(request)
        self.operation_id = operation_id
        self.method = method
        self.path = path
        self.request = request
        self.response = response
        self.idempotency_key = idempotency_key
        self.expected_revision = expected_revision
        self.path_parameters = list(path_parameters)
        self.action = action


class _RecordedServer(http.server.HTTPServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, operations: Sequence[RecordedOperation]) -> None:
        self.operations = list(operations)
        self.position = 0
        self.failure: str | None = None
        super().__init__(("127.0.0.1", 0), _RecordedHandler, bind_and_activate=True)

    def fail(self, message: str) -> None:
        if self.failure is None:
            self.failure = message


class _RecordedHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _RecordedServer

    def log_message(self, _format: str, *_arguments: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        self._exchange("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._exchange("POST")

    def _reject(self, message: str) -> None:
        self.server.fail(message)
        self.send_response(503)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True

    def _exchange(self, method: str) -> None:
        if self.server.failure is not None:
            self._reject("recorded API received a request after failure")
            return
        if self.server.position >= len(self.server.operations):
            self._reject("recorded API received an extra operation")
            return
        operation = self.server.operations[self.server.position]
        self.server.position += 1
        try:
            self._validate(operation, method)
        except (DriverError, OSError, ValueError):
            self._reject("recorded API request validation failed")
            return
        try:
            if operation.action is not None:
                operation.action()
        except (DriverError, OSError, ValueError):
            self._reject("recorded API operation action failed")
            return
        try:
            payload = canonical(
                {
                    "operation_id": operation.operation_id,
                    "payload_cbor": b64url(deterministic_cbor(operation.response)),
                }
            )
        except (DriverError, OSError, ValueError):
            self._reject("recorded API response encoding failed")
            return
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def _validate(self, operation: RecordedOperation, method: str) -> None:
        if (
            method != operation.method
            or self.path != operation.path
            or self.headers.get("x-cigar-operation-id") != operation.operation_id
            or self.headers.get("authorization") != LOCAL_AUTHORIZATION
        ):
            fail("recorded API method, path, operation, or authorization differs")
        timeout = self.headers.get("x-cigar-timeout-ms", "")
        if (
            not timeout.isascii()
            or not timeout.isdigit()
            or not 1 <= int(timeout) <= 300_000
        ):
            fail("recorded API timeout header is invalid")
        if self.headers.get("idempotency-key") != operation.idempotency_key:
            fail("recorded API idempotency header differs")
        if self.headers.get("if-match") != operation.expected_revision:
            fail("recorded API revision header differs")
        if method == "GET":
            if self.headers.get("content-length") not in {None, "0"}:
                fail("recorded API GET unexpectedly contains a body")
            return
        content_type = self.headers.get("content-type", "").split(";", 1)[0].strip()
        length_text = self.headers.get("content-length", "")
        if (
            content_type.lower() != "application/json"
            or not length_text.isdigit()
            or not 1 <= int(length_text) <= MAX_JSON
        ):
            fail("recorded API request framing is invalid")
        body = self.rfile.read(int(length_text))
        try:
            wire = json.loads(body, object_pairs_hook=reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DriverError("recorded API request is not strict JSON") from error
        expected_wire: dict[str, Any] = {
            "operation_id": operation.operation_id,
            "payload_cbor": b64url(deterministic_cbor(operation.request)),
            "dry_run": False,
            "path_parameters": [
                {"name": name, "value": value}
                for name, value in operation.path_parameters
            ],
        }
        if operation.idempotency_key is not None:
            expected_wire["idempotency_key"] = operation.idempotency_key
        if operation.expected_revision is not None:
            expected_wire["expected_revision"] = operation.expected_revision
        if wire != expected_wire:
            fail("recorded API canonical request differs from its fixture")


class RecordedApi:
    """Bounded loopback API that validates real CLI HTTP transport exchanges."""

    def __init__(self, state: Path, operations: Sequence[RecordedOperation]) -> None:
        if not operations or len(operations) > MAX_RECORDED_OPERATIONS:
            fail("recorded API operation count is outside bounds")
        self._server = _RecordedServer(operations)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="cigar-demo-recorded-api",
            daemon=True,
        )
        self._authorization = state / "recorded-api-token"
        try:
            _write_private_new(
                self._authorization, (LOCAL_AUTHORIZATION + "\n").encode("ascii")
            )
        except (DriverError, OSError):
            self._server.server_close()
            raise

    def __enter__(self) -> RecordedApi:
        self._thread.start()
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
        self._authorization.unlink(missing_ok=True)

    def cli_arguments(self) -> list[str]:
        return [
            "--target",
            "local",
            "--endpoint",
            self.base_url(),
            "--authorization-file",
            str(self._authorization),
        ]

    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    @staticmethod
    def bearer_token() -> str:
        return LOCAL_AUTHORIZATION.removeprefix("Bearer ")

    def assert_complete(self) -> None:
        if (
            self._server.failure is not None
            or self._server.position != len(self._server.operations)
            or not self._thread.is_alive()
        ):
            fail("recorded API workflow did not complete exactly")


def write_request(state: Path, name: str, value: dict[str, Any]) -> Path:
    if not name or "/" in name or "\\" in name:
        fail("recorded API request name is invalid")
    directory = state / "recorded-api-requests"
    directory.mkdir(exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        fail("recorded API request directory is unsafe")
    # Recorded requests can contain governed inputs and must deny group/world traversal.
    os.chmod(directory, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    path = directory / f"{name}.json"
    _write_private_new(path, canonical(value) + b"\n")
    return path


def _write_private_new(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise DriverError("recorded API private file already exists") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def load_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        fail("driver input must be a bounded regular file")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("driver input is not strict UTF-8 JSON") from error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--fixture", type=Path, required=True)
    result.add_argument("--state", type=Path, required=True)
    result.add_argument("--cigar-binary", type=Path, required=True)
    result.add_argument("--hook-binary", type=Path)
    return result


def validate_paths(
    fixture_path: Path,
    state: Path,
    cigar_binary: Path,
    hook_binary: Path | None = None,
) -> dict[str, Any]:
    fixture_candidate = fixture_path
    state_candidate = state
    cigar_candidate = cigar_binary
    fixture_path = fixture_candidate.resolve()
    state = state_candidate.resolve()
    cigar_binary = cigar_candidate.resolve()
    if not fixture_path.is_file() or fixture_candidate.is_symlink():
        fail("fixture is unavailable")
    if not state.is_dir() or state_candidate.is_symlink():
        fail("driver state root is unavailable")
    if not cigar_binary.is_file() or cigar_candidate.is_symlink():
        fail("CIGAR executable is unavailable")
    if hook_binary is not None:
        hook_candidate = hook_binary
        hook_binary = hook_candidate.resolve()
        if not hook_binary.is_file() or hook_candidate.is_symlink():
            fail("Claude hook executable is unavailable")
    fixture = load_json(fixture_path)
    if not isinstance(fixture, dict):
        fail("fixture must be an object")
    return fixture


def clean_environment(
    state: Path, additions: dict[str, str] | None = None
) -> dict[str, str]:
    allowed = {"PATH", "TMPDIR", "SYSTEMROOT", "WINDIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    home = state / "home"
    temporary = state / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    temporary.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "CIGAR_HOME": str(state / "cigar-home"),
            "CIGAR_CONFIG": str(state / "cigar.toml"),
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    if additions:
        environment.update(additions)
    return environment


def run_bounded(
    command: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path,
    environment: dict[str, str],
    stdin: bytes | None = None,
    timeout: int = 60,
    expected_status: int = 0,
) -> tuple[bytes, bytes]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                [os.fspath(part) for part in command],
                cwd=cwd,
                env=environment,
                input=stdin,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DriverError("product command did not complete") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
            fail("product command exceeded its output bound")
        stdout.seek(0)
        stderr.seek(0)
        stdout_payload = stdout.read()
        stderr_payload = stderr.read()
    if completed.returncode != expected_status:
        fail("product command returned an unexpected status")
    return stdout_payload, stderr_payload


def cli(
    binary: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int = 60,
) -> dict[str, Any]:
    stdout, _stderr = run_bounded(
        [binary, *arguments], cwd=cwd, environment=environment, timeout=timeout
    )
    try:
        value = json.loads(stdout, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("CIGAR returned malformed JSON") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "cigar.cli.output.v1"
        or value.get("ok") is not True
        or not isinstance(value.get("result"), dict)
    ):
        fail("CIGAR returned an unsuccessful result")
    return value


def configure_cli(state: Path) -> Path:
    configuration = state / "cli.toml"
    state_directory = state / "cli-state"
    configuration.write_text(
        "schema_version = 1\n"
        + "project_state_directory = "
        + json.dumps(str(state_directory))
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(configuration, 0o600)
    return configuration


def cli_arguments(configuration: Path) -> list[str]:
    return ["--config", str(configuration), "--output", "json"]


def remove_tree(path: Path) -> bool:
    if path.exists():
        shutil.rmtree(path)
    return not path.exists()


def step(step_id: str, grade: str, evidence: Any) -> dict[str, Any]:
    if grade not in {"product_observed", "fixture_observed", "not_observed"}:
        fail("driver supplied an invalid evidence grade")
    return {
        "step": step_id,
        "status": grade,
        "evidence_digest": digest_value(evidence),
    }


def assertion(assertion_id: str, grade: str, evidence: Any) -> dict[str, Any]:
    if grade not in {"product_observed", "fixture_observed", "not_observed"}:
        fail("driver supplied an invalid evidence grade")
    return {
        "assertion_id": assertion_id,
        "status": grade,
        "evidence_digest": digest_value(evidence),
    }


def emit(
    fixture: dict[str, Any],
    fixture_path: Path,
    setup: list[dict[str, Any]],
    flow: list[dict[str, Any]],
    assertions: list[dict[str, Any]],
    teardown: list[dict[str, Any]],
    observations: dict[str, Any],
) -> None:
    result = {
        "schema_version": DRIVER_SCHEMA,
        "demo_id": fixture.get("demo_id"),
        "fixed_seed": fixture.get("fixed_seed"),
        "fixture_digest": digest_bytes(fixture_path.read_bytes()),
        "no_egress_enforcement": os.environ.get("CIGAR_DEMO_NO_EGRESS", "unavailable"),
        "setup": setup,
        "flow": flow,
        "assertions": assertions,
        "teardown": teardown,
        "observations": observations,
    }
    result["result_digest"] = digest_value(result)
    print(canonical(result).decode("utf-8"))


def main_error(error: DriverError) -> int:
    print(f"cigar-demo-driver: {error}", file=os.sys.stderr)
    return 2
