#!/usr/bin/env python3
"""Run the same recorded ingest/compile/manifest workflow through all four SDKs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Never, Sequence

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("quickstarts.json")
IDENTITY = re.compile(r"^1220[0-9a-f]{64}$")
LANGUAGES = {"rust", "typescript", "python", "go"}
MAX_OUTPUT = 8 * 1024 * 1024


class QuickstartError(Exception):
    pass


def fail(message: str) -> Never:
    raise QuickstartError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("quickstart JSON contains duplicate keys")
        result[key] = value
    return result


def clean_environment(state: Path) -> dict[str, str]:
    allowed = {
        "PATH",
        "TMPDIR",
        "SYSTEMROOT",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "HOME": str(state / "home"),
            "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
            "COREPACK_HOME": os.environ.get(
                "COREPACK_HOME", str(Path.home() / ".cache" / "node" / "corepack")
            ),
            "UV_CACHE_DIR": os.environ.get(
                "UV_CACHE_DIR", str(Path.home() / ".cache" / "uv")
            ),
            "GOMODCACHE": os.environ.get(
                "GOMODCACHE", str(Path.home() / "go" / "pkg" / "mod")
            ),
            "GOCACHE": str(state / "go-build-cache"),
            "CARGO_NET_OFFLINE": "true",
            "UV_OFFLINE": "1",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GONOSUMDB": "*",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    for key in (
        "CIGAR_URL",
        "CIGAR_TOKEN",
        "CIGAR_PLAN_ID",
        "CIGAR_GRPC_TARGET",
        "CIGAR_GRPC_INSECURE_LOOPBACK",
    ):
        environment.pop(key, None)
    return environment


def command(
    parts: list[str], cwd: Path, state: Path, expect_identity: bool
) -> str | None:
    if not parts or parts[0] not in {"cargo", "pnpm", "node", "uv", "go"}:
        fail("quickstart command is not allowlisted")
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                parts,
                cwd=cwd,
                env=clean_environment(state),
                stdout=stdout,
                stderr=stderr,
                timeout=900,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise QuickstartError("quickstart process did not complete") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
            fail("quickstart process exceeded its output bound")
        stdout.seek(0)
        stdout_payload = stdout.read()
    if completed.returncode != 0:
        fail("quickstart process returned a non-zero status")
    if not expect_identity:
        return None
    try:
        lines = [
            line.strip()
            for line in stdout_payload.decode("utf-8").splitlines()
            if line.strip()
        ]
    except UnicodeDecodeError as error:
        raise QuickstartError("quickstart output is not UTF-8") from error
    if len(lines) != 1 or not IDENTITY.fullmatch(lines[0]):
        fail("quickstart did not emit exactly one bundle identity")
    return lines[0]


def load_manifest() -> dict[str, Any]:
    try:
        value = json.loads(
            MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
        )
    except (OSError, json.JSONDecodeError) as error:
        raise QuickstartError("quickstart manifest is unreadable") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "cigar.sdk-quickstarts.v1"
    ):
        fail("quickstart manifest schema is unsupported")
    fixture = value.get("fixture")
    expected = value.get("expected_bundle_id")
    entries = value.get("quickstarts")
    if (
        not isinstance(fixture, str)
        or Path(fixture).is_absolute()
        or ".." in Path(fixture).parts
    ):
        fail("quickstart fixture path is unsafe")
    if not isinstance(expected, str) or not IDENTITY.fullmatch(expected):
        fail("quickstart expected identity is invalid")
    if not isinstance(entries, list) or len(entries) != 4:
        fail("quickstart manifest must declare four runtimes")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "language",
            "mode",
            "working_directory",
            "prepare",
            "command",
        }:
            fail("quickstart entry fields do not match v1")
        language = entry["language"]
        if language not in LANGUAGES or language in seen:
            fail("quickstart languages are unknown or duplicated")
        seen.add(language)
        for key in ("prepare", "command"):
            parts = entry[key]
            if not isinstance(parts, list) or not all(
                isinstance(part, str) and 0 < len(part) <= 256 for part in parts
            ):
                fail("quickstart command arguments are invalid")
        working = entry["working_directory"]
        if (
            not isinstance(working, str)
            or Path(working).is_absolute()
            or ".." in Path(working).parts
        ):
            fail("quickstart working directory is unsafe")
    if seen != LANGUAGES:
        fail("quickstart runtime inventory is incomplete")
    fixture_path = (ROOT / fixture).resolve()
    if (
        not fixture_path.is_file()
        or fixture_path.is_symlink()
        or ROOT not in fixture_path.parents
    ):
        fail("quickstart fixture is not a regular repository file")
    fixture_value = json.loads(
        fixture_path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    expected_operations = [
        "discoverSources",
        "ingestCatalog",
        "createContextPlan",
        "compileContextBundle",
        "getContextBundleManifest",
    ]
    if (
        not isinstance(fixture_value, dict)
        or fixture_value.get("schema_version") != "cigar.sdk-recorded-workflow.v1"
        or fixture_value.get("expected_bundle_id") != expected
        or fixture_value.get("expected_operations") != expected_operations
        or not isinstance(fixture_value.get("expected_manifest_id"), str)
        or not IDENTITY.fullmatch(fixture_value["expected_manifest_id"])
        or not isinstance(fixture_value.get("expected_contract_digest"), str)
        or not IDENTITY.fullmatch(fixture_value["expected_contract_digest"])
    ):
        fail("quickstart fixture identity disagrees with the manifest")
    operations = fixture_value.get("operations")
    if (
        not isinstance(operations, list)
        or [item.get("operation_id") for item in operations if isinstance(item, dict)]
        != expected_operations
    ):
        fail("quickstart fixture operation inventory is incomplete")
    for operation in operations:
        if set(operation) != {
            "operation_id",
            "idempotency_key",
            "path_parameters",
            "request",
            "request_cbor_base64url",
            "response",
            "response_cbor_base64url",
        }:
            fail("quickstart fixture operation fields do not match v1")
        for field in ("request_cbor_base64url", "response_cbor_base64url"):
            encoded = operation[field]
            if (
                not isinstance(encoded, str)
                or len(encoded) > 32 * 1024 * 1024
                or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None
            ):
                fail("quickstart fixture CBOR encoding is invalid")
    value["expected_manifest_id"] = fixture_value["expected_manifest_id"]
    value["expected_contract_digest"] = fixture_value["expected_contract_digest"]
    value["expected_operations"] = expected_operations
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--language", action="append", choices=sorted(LANGUAGES), default=[]
    )
    result.add_argument("--output", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        manifest = load_manifest()
        selected = args.language or sorted(LANGUAGES)
        if len(selected) != len(set(selected)):
            fail("quickstart selection is duplicated")
        records = []
        with tempfile.TemporaryDirectory(prefix="cigar-sdk-source-") as temporary:
            state = Path(temporary)
            (state / "home").mkdir()
            for entry in manifest["quickstarts"]:
                if entry["language"] not in selected:
                    continue
                cwd = (ROOT / entry["working_directory"]).resolve()
                if entry["prepare"]:
                    command(entry["prepare"], cwd, state, False)
                identity = command(entry["command"], cwd, state, True)
                if identity != manifest["expected_bundle_id"]:
                    fail("quickstart bundle identities differ")
                records.append(
                    {
                        "language": entry["language"],
                        "mode": entry["mode"],
                        "bundle_id": identity,
                        "manifest_id": manifest["expected_manifest_id"],
                        "operations": manifest["expected_operations"],
                        "status": "recorded_workflow_passed",
                    }
                )
        all_languages_executed = set(selected) == LANGUAGES
        report: dict[str, Any] = {
            "schema_version": "cigar.sdk-quickstart-report.v1",
            "artifact_mode": "source-checkout",
            "evidence_class": "deterministic-recorded-fixture",
            "qualification_scope": "recorded-ingest-compile-manifest",
            "sdk_workflow_qualified": all_languages_executed,
            "installed_artifact_qualified": False,
            "release_qualified": False,
            "manifest_digest": digest(MANIFEST.read_bytes()),
            "fixture_digest": digest((ROOT / manifest["fixture"]).read_bytes()),
            "bundle_id": manifest["expected_bundle_id"],
            "selection_manifest_id": manifest["expected_manifest_id"],
            "contract_digest": manifest["expected_contract_digest"],
            "operations": manifest["expected_operations"],
            "quickstarts": sorted(records, key=lambda item: item["language"]),
        }
        report["report_digest"] = digest(canonical(report))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = canonical(report) + b"\n"
            temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, args.output)
            finally:
                temporary.unlink(missing_ok=True)
        print(manifest["expected_bundle_id"])
        return 0
    except QuickstartError as error:
        print(f"sdk-quickstart: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("sdk-quickstart: local artifact operation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
