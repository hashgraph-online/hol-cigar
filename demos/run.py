#!/usr/bin/env python3
"""Run fixture-bound deterministic execution for the seven product demos."""

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

ROOT = Path(__file__).resolve().parents[1]
RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)

DEMO_SCHEMA = "cigar.demo-manifest.v1"
FIXTURE_SCHEMA = "cigar.demo-fixture.v1"
RECORD_SCHEMA = "cigar.demo-record.v1"
DRIVER_SCHEMA = "cigar.demo-driver-result.v1"
MAX_JSON = 8 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
MAX_STATE_SCAN = 256 * 1024 * 1024
MAX_CHECKS = 16
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
MULTIHASH = re.compile(r"^1220[0-9a-f]{64}$")
TEST_RESULT = re.compile(r"test result: ok\. ([0-9]+) passed;")
GO_VERSION = re.compile(r"^go (1\.[0-9]+\.[0-9]+)$", re.MULTILINE)
DRIVER_ITEM_KEYS = {"step", "status", "evidence_digest"}
DRIVER_ASSERTION_KEYS = {"assertion_id", "status", "evidence_digest"}
DRIVER_GRADES = {"product_observed", "fixture_observed", "not_observed"}
DRIVER_KEYS = {
    "schema_version",
    "demo_id",
    "fixed_seed",
    "fixture_digest",
    "no_egress_enforcement",
    "setup",
    "flow",
    "assertions",
    "teardown",
    "observations",
    "result_digest",
}
_BUILT_PACKAGES: set[str] = set()
DEFAULT_OUTPUT_DIRECTORY = ROOT / "demos" / "reports"
DEFAULT_EVIDENCE_PREFIX = "demos/reports"


class DemoError(Exception):
    """A bounded content-free demo failure."""


def fail(message: str) -> Never:
    raise DemoError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON contains duplicate object keys")
        result[key] = value
    return result


def pinned_go_toolchain() -> str:
    versions: set[str] = set()
    for module in (
        ROOT / "sdk" / "go" / "go.mod",
        ROOT / "demos" / "sdk-clients" / "go-workflow" / "go.mod",
    ):
        try:
            payload = module.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise DemoError("Go toolchain pin is unreadable") from error
        matches = GO_VERSION.findall(payload)
        if len(matches) != 1:
            fail("Go toolchain pin is invalid")
        versions.add(matches[0])
    if len(versions) != 1:
        fail("Go toolchain pins do not match")
    return f"go{versions.pop()}"


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
        raise DemoError("value cannot be canonicalized") from error


def digest(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def load_json(path: Path, maximum: int = MAX_JSON) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        fail("demo input must be a bounded regular file")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DemoError("demo input is not strict UTF-8 JSON") from error


def ident(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        fail(f"{label} is not a bounded identifier")
    return value


MANIFEST_KEYS = {
    "schema_version",
    "demo_id",
    "title",
    "fixed_seed",
    "fixture",
    "fixture_digest",
    "driver",
    "driver_digest",
    "driver_support_digest",
    "recorded_mode",
    "setup",
    "expected_assertions",
    "checks",
    "teardown",
    "ci_smoke_command",
    "canary_ids",
    "live_mode",
}
CHECK_KEYS = {
    "check_id",
    "command",
    "timeout_seconds",
    "minimum_passed_tests",
    "assertions",
}


def validate_manifest(value: Any, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != MANIFEST_KEYS:
        fail("demo manifest fields do not match v1")
    if value["schema_version"] != DEMO_SCHEMA:
        fail("demo manifest version is unsupported")
    ident(value["demo_id"], "demo id")
    if not isinstance(value["title"], str) or not (1 <= len(value["title"]) <= 160):
        fail("demo title is outside bounds")
    if isinstance(value["fixed_seed"], bool) or not isinstance(
        value["fixed_seed"], int
    ):
        fail("demo seed must be an integer")
    fixture = value["fixture"]
    if (
        not isinstance(fixture, str)
        or Path(fixture).is_absolute()
        or ".." in Path(fixture).parts
    ):
        fail("demo fixture path is unsafe")
    if not isinstance(value["fixture_digest"], str) or not MULTIHASH.fullmatch(
        value["fixture_digest"]
    ):
        fail("demo fixture digest is invalid")
    driver = value["driver"]
    if (
        not isinstance(driver, str)
        or Path(driver).is_absolute()
        or ".." in Path(driver).parts
    ):
        fail("demo driver path is unsafe")
    for key in ("driver_digest", "driver_support_digest"):
        if not isinstance(value[key], str) or not MULTIHASH.fullmatch(value[key]):
            fail("demo driver digest is invalid")
    if value["recorded_mode"] is not True:
        fail("recorded mode must be enabled")
    for key in ("setup", "expected_assertions", "teardown", "canary_ids"):
        if not isinstance(value[key], list) or not value[key]:
            fail(f"demo {key} must be a non-empty list")
        for item in value[key]:
            ident(item, f"demo {key} item")
    if len(set(value["expected_assertions"])) != len(value["expected_assertions"]):
        fail("demo assertion ids must be unique")
    checks = value["checks"]
    if not isinstance(checks, list) or not (1 <= len(checks) <= MAX_CHECKS):
        fail("demo check count is outside bounds")
    check_ids: set[str] = set()
    covered_assertions: set[str] = set()
    for check in checks:
        validate_check(check)
        if check["check_id"] in check_ids:
            fail("demo check ids must be unique")
        check_ids.add(check["check_id"])
        covered_assertions.update(check["assertions"])
    if covered_assertions != set(value["expected_assertions"]):
        fail("demo product checks do not cover the exact assertion inventory")
    if (
        not isinstance(value["ci_smoke_command"], str)
        or len(value["ci_smoke_command"]) > 512
    ):
        fail("demo CI command is outside bounds")
    live = value["live_mode"]
    if not isinstance(live, dict) or set(live) != {
        "enabled",
        "required_environment",
        "check",
    }:
        fail("demo live mode fields do not match v1")
    if not isinstance(live["enabled"], bool) or not isinstance(
        live["required_environment"], list
    ):
        fail("demo live mode is invalid")
    for environment_name in live["required_environment"]:
        if not isinstance(environment_name, str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,63}", environment_name
        ):
            fail("demo live environment name is invalid")
    if live["enabled"]:
        validate_check(live["check"])
    elif live["check"] is not None:
        fail("disabled live mode cannot define a check")
    fixture_candidate = path.parent / fixture
    fixture_path = fixture_candidate.resolve()
    if (
        fixture_path.parent != path.parent.resolve()
        or fixture_candidate.is_symlink()
        or not fixture_path.is_file()
    ):
        fail("demo fixture must be a regular manifest sibling")
    payload = fixture_path.read_bytes()
    if digest(payload) != value["fixture_digest"]:
        fail("demo fixture digest does not match its manifest")
    fixture_value = load_json(fixture_path)
    if (
        not isinstance(fixture_value, dict)
        or fixture_value.get("schema_version") != FIXTURE_SCHEMA
    ):
        fail("demo fixture schema is unsupported")
    if (
        fixture_value.get("demo_id") != value["demo_id"]
        or fixture_value.get("fixed_seed") != value["fixed_seed"]
    ):
        fail("demo fixture identity or seed does not match its manifest")
    driver_candidate = path.parent / driver
    driver_path = driver_candidate.resolve()
    support_path = ROOT / "demos" / "driver_support.py"
    if (
        driver_path.parent != path.parent.resolve()
        or driver_candidate.is_symlink()
        or not driver_path.is_file()
        or driver_path.stat().st_size > MAX_JSON
        or digest(driver_path.read_bytes()) != value["driver_digest"]
        or support_path.is_symlink()
        or not support_path.is_file()
        or support_path.stat().st_size > MAX_JSON
        or digest(support_path.read_bytes()) != value["driver_support_digest"]
    ):
        fail("demo scenario driver does not match its manifest")
    return value


def validate_check(check: Any) -> dict[str, Any]:
    if not isinstance(check, dict) or set(check) != CHECK_KEYS:
        fail("demo check fields do not match v1")
    ident(check["check_id"], "check id")
    command = check["command"]
    if not isinstance(command, list) or not (1 <= len(command) <= 32):
        fail("demo check command is outside bounds")
    if not all(
        isinstance(part, str) and 0 < len(part) <= 256 and "\x00" not in part
        for part in command
    ):
        fail("demo check command contains an invalid argument")
    if command[0] not in {"cargo", "bash", "python3"}:
        fail("demo check executable is not allowlisted")
    timeout = check["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not (1 <= timeout <= 900)
    ):
        fail("demo check timeout is outside bounds")
    minimum = check["minimum_passed_tests"]
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
        fail("demo minimum test count is invalid")
    assertions = check["assertions"]
    if not isinstance(assertions, list) or not all(
        isinstance(assertion, str) and IDENTIFIER.fullmatch(assertion)
        for assertion in assertions
    ):
        fail("demo check assertion mappings are invalid")
    if len(assertions) != len(set(assertions)):
        fail("demo check assertion mappings are duplicated")
    return check


def validate_fixture_claims(fixture: dict[str, Any]) -> None:
    flow = fixture.get("flow")
    if (
        not isinstance(flow, list)
        or not (1 <= len(flow) <= 32)
        or not all(
            isinstance(step, str) and IDENTIFIER.fullmatch(step) for step in flow
        )
        or len(flow) != len(set(flow))
    ):
        fail("demo fixture flow is invalid")
    demo_id = fixture.get("demo_id")
    expected = fixture.get("expected")
    if not isinstance(expected, dict):
        fail("demo fixture expected outcomes are invalid")
    try:
        if demo_id == "offline-context-compiler":
            baseline = int(fixture["baseline_physical_tokens"])
            compiled = int(fixture["maximum_compiled_physical_tokens"])
            reduction = 100.0 * (baseline - compiled) / baseline
            valid = (
                int(fixture["repository_generator"]["file_count"]) >= 100
                and baseline > 0
                and compiled >= 0
                and reduction >= float(expected["minimum_reduction_percent"])
                and expected["strong_index_watermark"] is True
                and expected["selected_provenance_rate"] == 1.0
                and expected["superseded_decision_selected"] is False
                and expected["delta_roundtrip"] is True
            )
        elif demo_id == "multi-project-isolation":
            projects = fixture["projects"]
            forbidden = [
                project for project in projects if project["id"] == "hr-private"
            ]
            valid = (
                len(projects) == 4
                and len(forbidden) == 1
                and forbidden[0]["attached"] is False
                and forbidden[0]["permitted"] is False
                and "hr-private" not in expected["visible_projects"]
                and expected["forbidden_candidate_count"] == 0
                and expected["resumed_revision_is_current"] is True
                and expected["filesystem_authority_changed"] is False
            )
        elif demo_id == "multi-agent-handoff":
            parent = int(fixture["parent_transcript_tokens"])
            children = fixture["children"]
            valid = (
                parent > 0
                and len(children) == 2
                and all(
                    int(child["maximum_tokens"]) / parent
                    <= float(expected["maximum_package_ratio"])
                    for child in children
                )
                and fixture["adversarial_request"]["capability"] == "write_overlay"
                and expected["adversarial_request_denied"] is True
                and expected["denial_discloses_source"] is False
                and expected["grant_amplified"] is False
                and set(expected["result_fields"])
                == {"claims", "artifacts", "uncertainty", "verification"}
            )
        elif demo_id == "effect-crash-recovery":
            valid = (
                len(fixture["failure_points"]) == 5
                and expected["prepared_before_send"] is True
                and expected["possible_remote_commit_state"] == "unknown"
                and expected["logical_remote_mutations"] == 1
                and expected["non_idempotent_unknown_auto_retry"] is False
                and expected["compensation_is_linked_child"] is True
            )
        elif demo_id == "cross-runtime-replay":
            valid = (
                fixture["producer_runtime"] == "rust"
                and set(fixture["reproducer_runtimes"])
                == {"typescript", "python", "go"}
                and fixture["mode"] == "evidence_reproduction"
                and expected["semantic_bundle_identity_equal"] is True
                and expected["evidence_reproduction_exact"] is True
                and expected["network_calls"] == 0
                and expected["connector_calls"] == 0
                and expected["live_execution_reuses_execution_id"] is False
            )
        elif demo_id == "prompt-injection-defense":
            documents = fixture["documents"]
            approved = [
                document for document in documents if document["authority"] == "project"
            ]
            valid = (
                len(documents) == 3
                and len(approved) == 1
                and approved[0]["path"] == ".cigar/instructions.md"
                and expected["hostile_content_grants_tools"] is False
                and expected["hostile_content_becomes_instruction"] is False
                and expected["secret_exposed"] is False
                and expected["approved_instruction_exact"] is True
                and expected["approved_instruction_mandatory"] is True
            )
        elif demo_id == "claude-code-experience":
            valid = (
                len(flow) == 11
                and expected["bootstrap_max_tokens"] <= 500
                and expected["duplicate_injection_count"] == 0
                and expected["mcp_output_bounded"] is True
                and expected["checkpoints_exact"] is True
                and expected["degraded_marker_visible"] is True
                and expected["manifest_inspectable"] is True
                and expected["uninstall_byte_preserving"] is True
            )
        else:
            valid = False
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        valid = False
    if not valid:
        fail("demo fixture claims are internally inconsistent")


def canaries() -> dict[str, bytes]:
    value = load_json(ROOT / "demos" / "canaries.json", 1024 * 1024)
    if not isinstance(value, dict) or set(value) != {"schema_version", "canaries"}:
        fail("demo canary registry is invalid")
    if value["schema_version"] != "cigar.demo-canaries.v1" or not isinstance(
        value["canaries"], list
    ):
        fail("demo canary registry version is unsupported")
    result: dict[str, bytes] = {}
    for item in value["canaries"]:
        if not isinstance(item, dict) or set(item) != {"id", "value"}:
            fail("demo canary entry is invalid")
        canary_id = ident(item["id"], "canary id")
        if canary_id in result or not isinstance(item["value"], str):
            fail("demo canary entry is duplicated or malformed")
        encoded = item["value"].encode("utf-8")
        if not (16 <= len(encoded) <= 1024):
            fail("demo canary is outside bounds")
        result[canary_id] = encoded
    return result


def scan(payload: bytes, ids: Sequence[str], registry: dict[str, bytes]) -> None:
    for canary_id in ids:
        if canary_id not in registry:
            fail("demo refers to an unregistered canary")
        if registry[canary_id] in payload:
            fail(f"registered demo canary {canary_id} reached observable output")


def scan_tree(root: Path, registry: dict[str, bytes]) -> None:
    scanned = 0
    overlap = max((len(value) for value in registry.values()), default=1) - 1
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            fail("demo temporary state contains an unsafe link")
        if path.is_dir():
            continue
        if not path.is_file():
            fail("demo temporary state contains a special file")
        scanned += path.stat().st_size
        if scanned > MAX_STATE_SCAN:
            fail("demo temporary state exceeds its scan bound")
        tail = b""
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                payload = tail + chunk
                scan(payload, sorted(registry), registry)
                tail = payload[-overlap:] if overlap else b""


def clean_environment(
    state: Path, extra_environment: Sequence[str] = ()
) -> dict[str, str]:
    allowed = {
        "PATH",
        "TMPDIR",
        "SYSTEMROOT",
        "WINDIR",
        "TERM",
        "CI",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    for key in extra_environment:
        if key in os.environ:
            environment[key] = os.environ[key]
    environment.update(
        {
            "HOME": str(state / "home"),
            # Toolchains and the read-through offline registry are test
            # infrastructure; product and user state remain temporary.
            "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
            "GOMODCACHE": os.environ.get(
                "GOMODCACHE", str(Path.home() / "go" / "pkg" / "mod")
            ),
            "GOCACHE": str(state / "go-build-cache"),
            "CARGO_NET_OFFLINE": "true",
            "UV_OFFLINE": "1",
            "GOTOOLCHAIN": pinned_go_toolchain(),
            "GOWORK": "off",
            "GOPROXY": "off",
            "GOSUMDB": "sum.golang.org",
            "GONOSUMDB": "",
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
    return environment


def run_check(
    check: dict[str, Any],
    state: Path,
    canary_ids: Sequence[str],
    registry: dict[str, bytes],
    extra_environment: Sequence[str] = (),
) -> dict[str, Any]:
    if any(canary_id not in registry for canary_id in canary_ids):
        fail("demo check refers to an unregistered canary")
    command = list(check["command"])
    (state / "home").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=clean_environment(state, extra_environment),
                stdout=stdout,
                stderr=stderr,
                timeout=check["timeout_seconds"],
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DemoError(
                f"demo check {check['check_id']} did not complete"
            ) from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
            fail(f"demo check {check['check_id']} exceeded its output bound")
        stdout.seek(0)
        stderr.seek(0)
        stdout_payload = stdout.read()
        stderr_payload = stderr.read()
    scan(stdout_payload, sorted(registry), registry)
    scan(stderr_payload, sorted(registry), registry)
    if completed.returncode != 0:
        fail(f"demo check {check['check_id']} failed")
    combined = (stdout_payload + b"\n" + stderr_payload).decode(
        "utf-8", errors="replace"
    )
    passed = sum(int(match.group(1)) for match in TEST_RESULT.finditer(combined))
    if passed < check["minimum_passed_tests"]:
        fail(f"demo check {check['check_id']} did not execute its required tests")
    return {
        "check_id": check["check_id"],
        "status": "component_check_passed",
        "passed_tests": passed,
        "assertions": check["assertions"],
    }


def run_bounded_process(
    command: Sequence[str],
    state: Path,
    registry: dict[str, bytes],
    *,
    timeout: int,
    environment: dict[str, str] | None = None,
) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                list(command),
                cwd=ROOT,
                env=environment or clean_environment(state),
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DemoError("demo product process did not complete") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
            fail("demo product process exceeded its output bound")
        stdout.seek(0)
        stderr.seek(0)
        stdout_payload = stdout.read()
        stderr_payload = stderr.read()
    scan(stdout_payload, sorted(registry), registry)
    scan(stderr_payload, sorted(registry), registry)
    if completed.returncode != 0:
        fail("demo product process failed")
    return stdout_payload


def ensure_product_binaries(
    demo_id: str, state: Path, registry: dict[str, bytes]
) -> dict[str, Path]:
    packages = {"cigar-cli"}
    if demo_id == "claude-code-experience":
        packages.update({"cigar-claude-hook", "cigar-mcp"})
    missing = sorted(packages - _BUILT_PACKAGES)
    if missing:
        command = ["cargo", "build", "--offline", "--quiet"]
        for package in missing:
            command.extend(["-p", package])
        run_bounded_process(command, state, registry, timeout=900)
        _BUILT_PACKAGES.update(missing)
    binaries = {"cigar": ROOT / "target" / "debug" / "cigar"}
    if demo_id == "claude-code-experience":
        binaries.update(
            {
                "hook": ROOT / "target" / "debug" / "cigar-claude-hook",
                "mcp": ROOT / "target" / "debug" / "cigar-mcp",
            }
        )
    for binary in binaries.values():
        if (
            binary.is_symlink()
            or not binary.is_file()
            or not os.access(binary, os.X_OK)
        ):
            fail("a required demo product executable is unavailable")
    return binaries


def sandboxed_driver_command(command: list[str]) -> tuple[list[str], str]:
    sandbox = Path("/usr/bin/sandbox-exec")
    if sys.platform == "darwin" and sandbox.is_file() and not sandbox.is_symlink():
        policy = "".join(
            [
                "(version 1)",
                "(allow default)",
                "(deny network*)",
                '(allow network* (local ip "localhost:*"))',
                '(allow network* (remote ip "localhost:*"))',
            ]
        )
        return [str(sandbox), "-p", policy, *command], "darwin-loopback-only-v1"
    return command, "unavailable"


def validate_driver_items(
    items: Any,
    expected: Sequence[str],
    *,
    assertion_items: bool = False,
) -> list[dict[str, Any]]:
    if not isinstance(items, list) or len(items) != len(expected):
        fail("demo driver evidence inventory is incomplete")
    key = "assertion_id" if assertion_items else "step"
    expected_keys = DRIVER_ASSERTION_KEYS if assertion_items else DRIVER_ITEM_KEYS
    for item, expected_id in zip(items, expected, strict=True):
        if (
            not isinstance(item, dict)
            or set(item) != expected_keys
            or item.get(key) != expected_id
            or item.get("status") not in DRIVER_GRADES
            or not isinstance(item.get("evidence_digest"), str)
            or not MULTIHASH.fullmatch(item["evidence_digest"])
        ):
            fail("demo driver evidence item is invalid")
    return items


def validate_driver_result(
    value: Any,
    fixture_path: Path,
    fixture: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != DRIVER_KEYS:
        fail("demo driver result fields do not match v1")
    if (
        value["schema_version"] != DRIVER_SCHEMA
        or value["demo_id"] != manifest["demo_id"]
        or value["fixed_seed"] != manifest["fixed_seed"]
        or value["fixture_digest"] != digest(fixture_path.read_bytes())
        or not isinstance(value["no_egress_enforcement"], str)
        or len(value["no_egress_enforcement"]) > 64
        or not isinstance(value["observations"], dict)
        or not isinstance(value["result_digest"], str)
        or not MULTIHASH.fullmatch(value["result_digest"])
    ):
        fail("demo driver identity or result metadata is invalid")
    unsigned = dict(value)
    result_digest = unsigned.pop("result_digest")
    if digest(canonical(unsigned)) != result_digest:
        fail("demo driver result digest does not verify")
    canonical(value["observations"])
    validate_driver_items(value["setup"], manifest["setup"])
    validate_driver_items(value["flow"], fixture["flow"])
    validate_driver_items(
        value["assertions"], manifest["expected_assertions"], assertion_items=True
    )
    validate_driver_items(value["teardown"], manifest["teardown"])
    return value


def run_scenario_driver(
    manifest_path: Path,
    manifest: dict[str, Any],
    fixture_path: Path,
    fixture: dict[str, Any],
    state: Path,
    registry: dict[str, bytes],
) -> dict[str, Any]:
    driver = manifest_path.parent / manifest["driver"]
    support = ROOT / "demos" / "driver_support.py"
    for path in (driver, support):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
            fail("demo scenario driver is unavailable")
    binaries = ensure_product_binaries(manifest["demo_id"], state, registry)
    driver_state = state / "scenario-driver"
    driver_state.mkdir()
    command = [
        sys.executable,
        str(driver),
        "--fixture",
        str(fixture_path),
        "--state",
        str(driver_state),
        "--cigar-binary",
        str(binaries["cigar"]),
    ]
    if "hook" in binaries:
        command.extend(["--hook-binary", str(binaries["hook"])])
    command, enforcement = sandboxed_driver_command(command)
    environment = clean_environment(driver_state)
    environment["CIGAR_DEMO_NO_EGRESS"] = enforcement
    payload = run_bounded_process(
        command, driver_state, registry, timeout=300, environment=environment
    )
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DemoError("demo driver returned malformed JSON") from error
    result = validate_driver_result(value, fixture_path, fixture, manifest)
    if result["no_egress_enforcement"] != enforcement:
        fail("demo driver no-egress evidence disagrees with the process boundary")
    result["driver_bundle_digest"] = digest(
        canonical(
            {
                "driver": manifest["driver_digest"],
                "support": manifest["driver_support_digest"],
            }
        )
    )
    return result


def driver_release_qualified(driver: dict[str, Any]) -> bool:
    setup_and_teardown = [*driver["setup"], *driver["teardown"]]
    return (
        driver.get("no_egress_enforcement") not in {None, "", "unavailable"}
        and all(item["status"] != "not_observed" for item in setup_and_teardown)
        and all(item["status"] == "product_observed" for item in driver["flow"])
        and all(item["status"] == "product_observed" for item in driver["assertions"])
    )


def manifest_paths() -> list[Path]:
    return sorted((ROOT / "demos").glob("*/demo.json"))


def load_manifests() -> dict[str, tuple[Path, dict[str, Any]]]:
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in manifest_paths():
        manifest = validate_manifest(load_json(path), path)
        demo_id = manifest["demo_id"]
        if demo_id in result:
            fail("demo ids are not unique")
        result[demo_id] = (path, manifest)
    if len(result) != 7:
        fail("the release demo inventory must contain exactly seven demos")
    return result


def write_record(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical(value) + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run_demo(
    path: Path,
    manifest: dict[str, Any],
    output_directory: Path,
    validate_only: bool,
    live: bool,
    registry: dict[str, bytes],
    *,
    evidence_workspace: EvidenceWorkspace | None = None,
    evidence_prefix: str | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    driver: dict[str, Any] | None = None
    fixture_path = path.parent / manifest["fixture"]
    fixture = load_json(fixture_path)
    validate_fixture_claims(fixture)
    if len(manifest["canary_ids"]) != 1 or fixture.get("secret_canary") != registry[
        manifest["canary_ids"][0]
    ].decode("utf-8"):
        fail("demo fixture canary does not match the registry")
    with tempfile.TemporaryDirectory(
        prefix=f"cigar-demo-{manifest['demo_id']}-"
    ) as temporary:
        state = Path(temporary)
        if not validate_only:
            for check in manifest["checks"]:
                checks.append(run_check(check, state, manifest["canary_ids"], registry))
            driver = run_scenario_driver(
                path, manifest, fixture_path, fixture, state, registry
            )
            if live:
                live_mode = manifest["live_mode"]
                if not live_mode["enabled"]:
                    fail(f"demo {manifest['demo_id']} has no live mode")
                if any(
                    not os.environ.get(name)
                    for name in live_mode["required_environment"]
                ):
                    fail(f"demo {manifest['demo_id']} live prerequisites are absent")
                checks.append(
                    run_check(
                        live_mode["check"],
                        state,
                        manifest["canary_ids"],
                        registry,
                        live_mode["required_environment"],
                    )
                )
            scan_tree(state, registry)
    release_demo_qualified = driver is not None and driver_release_qualified(driver)
    if validate_only:
        mode = "validation_only"
    elif release_demo_qualified:
        mode = "live_release_demo" if live else "release_demo"
    else:
        mode = "live_partial_fixture_evidence" if live else "partial_fixture_evidence"
    record: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA,
        "demo_id": manifest["demo_id"],
        "mode": mode,
        "release_demo_qualified": release_demo_qualified,
        "fixed_seed": manifest["fixed_seed"],
        "manifest_digest": digest(path.read_bytes()),
        "fixture_digest": digest(fixture_path.read_bytes()),
        "checks": checks,
        "scenario_driver": driver,
        "setup": [
            {
                "step": step,
                "status": "validated"
                if validate_only
                else driver["setup"][index]["status"],
            }
            for index, step in enumerate(manifest["setup"])
        ],
        "flow": [
            {
                "step": step,
                "status": "validated"
                if validate_only
                else driver["flow"][index]["status"],
            }
            for index, step in enumerate(fixture["flow"])
        ],
        "assertions": [
            {
                "assertion_id": assertion,
                "status": "validated"
                if validate_only
                else (
                    "independently_observed"
                    if driver["assertions"][index]["status"] == "product_observed"
                    and any(assertion in check["assertions"] for check in checks)
                    else (
                        "fixture_observed_with_component_evidence"
                        if driver["assertions"][index]["status"] == "fixture_observed"
                        and any(assertion in check["assertions"] for check in checks)
                        else (
                            "component_check_passed"
                            if any(assertion in check["assertions"] for check in checks)
                            else "not_run"
                        )
                    )
                ),
            }
            for index, assertion in enumerate(manifest["expected_assertions"])
        ],
        "teardown": [
            {
                "step": step,
                "status": "validated"
                if validate_only
                else driver["teardown"][index]["status"],
            }
            for index, step in enumerate(manifest["teardown"])
        ],
    }
    record["record_digest"] = digest(canonical(record))
    payload = canonical(record)
    scan(payload, sorted(registry), registry)
    if evidence_workspace is None:
        output = output_directory / f"{manifest['demo_id']}.json"
        write_record(output, record)
    else:
        if evidence_prefix is None:
            fail("demo evidence prefix is missing")
        evidence_workspace.write_json(
            f"{evidence_prefix}/{manifest['demo_id']}.json", record
        )
    return record


def selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment and Path(argument) != Path(environment):
        fail("--evidence-dir conflicts with CIGAR_EVIDENCE_DIR")
    selected = argument if argument is not None else environment
    if selected is None or os.fspath(selected) == "":
        return None
    path = Path(selected)
    if not path.is_absolute():
        fail("demo evidence directory must be absolute")
    return path


def selected_evidence_prefix(arguments: argparse.Namespace) -> str:
    output = arguments.output_dir
    if output == DEFAULT_OUTPUT_DIRECTORY:
        return DEFAULT_EVIDENCE_PREFIX
    if output.is_absolute():
        fail("--output-dir must be relative when an evidence workspace is selected")
    try:
        return "/".join(safe_evidence_path(os.fspath(output)))
    except EvidenceWorkspaceError as error:
        raise DemoError("demo evidence output path is unsafe") from error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="demo id; repeat to select several",
    )
    result.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIRECTORY)
    result.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external evidence workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    result.add_argument(
        "--validate-only",
        action="store_true",
        help="validate assets without running product checks",
    )
    result.add_argument(
        "--live",
        action="store_true",
        help="run a separately declared optional live check",
    )
    result.add_argument("--list", action="store_true")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    workspace: EvidenceWorkspace | None = None
    try:
        manifests = load_manifests()
        selected_evidence = selected_evidence_directory(args)
        if args.list:
            for demo_id in manifests:
                print(demo_id)
            return 0
        selected = args.scenario or list(manifests)
        if len(selected) != len(set(selected)) or any(
            demo_id not in manifests for demo_id in selected
        ):
            fail("demo selection is unknown or duplicated")
        registry = canaries()
        records = []
        evidence_prefix: str | None = None
        if selected_evidence is not None:
            evidence_prefix = selected_evidence_prefix(args)
            workspace = EvidenceWorkspace.create(
                selected_evidence, repository_root=ROOT
            )
        for demo_id in selected:
            path, manifest = manifests[demo_id]
            records.append(
                run_demo(
                    path,
                    manifest,
                    args.output_dir,
                    args.validate_only,
                    args.live,
                    registry,
                    evidence_workspace=workspace,
                    evidence_prefix=evidence_prefix,
                )
            )
        qualified = bool(records) and all(
            record["release_demo_qualified"] for record in records
        )
        summary = {
            "schema_version": "cigar.demo-run-summary.v1",
            "result_class": "validation_only"
            if args.validate_only
            else ("release_demo" if qualified else "mixed_fixture_evidence"),
            "completed": selected,
            "release_demo_qualified": qualified,
        }
        if workspace is not None:
            assert evidence_prefix is not None
            workspace.write_json(f"{evidence_prefix}/summary.json", summary)
        print(json.dumps(summary, separators=(",", ":")))
        return 0
    except DemoError as error:
        print(f"cigar-demo: {error}", file=sys.stderr)
        return 2
    except (EvidenceWorkspaceError, OSError):
        print("cigar-demo: local artifact operation failed", file=sys.stderr)
        return 2
    finally:
        if workspace is not None:
            workspace.close()


if __name__ == "__main__":
    raise SystemExit(main())
