#!/usr/bin/env python3
"""Validate bounded WP20 fixtures and create a non-release local receipt.

The generated receipt proves only that the checked-in local harness evidence is
internally consistent. It is never candidate-bound and can never satisfy WP20.
All evidence inputs are opened without following symlinks and parsed and hashed
from the same file-descriptor bytes.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = REPOSITORY_ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)


SCHEMA_VERSION = "cigar.wp20-local-readiness.v1"
DRY_RUN_SCHEMA_VERSION = "cigar.wp20-local-qualification.v1"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_EVENTS = 1_000_000
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")
MULTIHASH_RE = re.compile(r"^1220[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
UNITTEST_COUNT_RE = re.compile(r"^Ran ([0-9]+) tests? in ", re.MULTILINE)
UNITTEST_DURATION_RE = re.compile(rb"^(Ran [0-9]+ tests? in )[^\r\n]+", re.MULTILINE)
ALLOWED_NO_EGRESS = frozenset({"darwin-loopback-only-v1"})
EXPECTED_DEMO_PATHS = {
    "claude-code-experience": "demos/claude-code",
    "cross-runtime-replay": "demos/replay-comparison",
    "effect-crash-recovery": "demos/effect-recovery",
    "multi-agent-handoff": "demos/agent-handoff",
    "multi-project-isolation": "demos/multiproject-payments",
    "offline-context-compiler": "demos/quickstart",
    "prompt-injection-defense": "demos/prompt-injection-defense",
}
EXPECTED_LANGUAGES = ("go", "python", "rust", "typescript")
EXPECTED_SDK_MODES = {
    "go": "grpc-client-recorded",
    "python": "async-http-client-recorded",
    "rust": "embedded-recorded",
    "typescript": "http-client-recorded",
}
EXPECTED_OPERATIONS = (
    "discoverSources",
    "ingestCatalog",
    "createContextPlan",
    "compileContextBundle",
    "getContextBundleManifest",
)
DEMO_RECORD_KEYS = {
    "schema_version",
    "demo_id",
    "mode",
    "release_demo_qualified",
    "fixed_seed",
    "manifest_digest",
    "fixture_digest",
    "checks",
    "scenario_driver",
    "setup",
    "flow",
    "assertions",
    "teardown",
    "record_digest",
}
DEMO_DRIVER_KEYS = {
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
    "driver_bundle_digest",
}
DEMO_MANIFEST_KEYS = {
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
SDK_REPORT_KEYS = {
    "schema_version",
    "artifact_mode",
    "qualification_scope",
    "evidence_class",
    "sdk_workflow_qualified",
    "installed_artifact_qualified",
    "release_qualified",
    "manifest_digest",
    "fixture_digest",
    "bundle_id",
    "selection_manifest_id",
    "contract_digest",
    "operations",
    "quickstarts",
    "report_digest",
}
SDK_RESULT_KEYS = {
    "language",
    "mode",
    "status",
    "operations",
    "bundle_id",
    "manifest_id",
}
PLAN_KEYS = {
    "schema_version",
    "seed_commitment",
    "dataset_manifest_digest",
    "baseline_manifest_digest",
    "canary_registry_digest",
    "assignments",
    "assignment_digest",
}
ASSIGNMENT_KEYS = {
    "run_id",
    "pair_id",
    "dataset_id",
    "task_id",
    "stratum",
    "baseline_id",
    "sample_index",
    "evidence_class",
    "pins",
    "environment_digest",
    "treatment",
    "order",
}
EVENT_KEYS = {
    "schema_version",
    "event_id",
    "run_id",
    "pair_id",
    "dataset_id",
    "task_id",
    "stratum",
    "treatment",
    "baseline_id",
    "order",
    "sample_index",
    "warmup",
    "evidence_class",
    "pins",
    "metrics",
    "environment_digest",
    "assignment_digest",
    "seed_commitment",
    "attestation",
}
REPORT_KEYS = {
    "schema_version",
    "input_digest",
    "input_manifests",
    "seed_commitment",
    "bootstrap_repetitions",
    "comparison",
    "qualification",
    "global",
    "per_stratum",
    "decision",
    "report_digest",
}
DRY_RECEIPT_KEYS = {
    "schema_version",
    "scope",
    "status",
    "decision",
    "eligible_reasons",
    "ineligible_reasons",
    "claims",
    "counts",
    "qualification",
    "limitations",
    "evidence",
    "report_digest",
    "seed_commitment",
}
MATRIX_RECEIPT_KEYS = {
    "schema_version",
    "scope",
    "status",
    "comparator_count",
    "comparator_inventory",
    "bootstrap_repetitions_requested_per_report",
    "distinct_assignment_digests",
    "shared_seed_commitment",
    "paired_randomized_execution",
    "raw_report_replay",
    "canary_scan",
    "hidden_seed_handling",
    "qualification",
    "reports",
    "evidence",
}


class ReadinessError(RuntimeError):
    """An input is missing, malformed, unsafe, stale, or overclaims scope."""


@dataclass(frozen=True)
class Asset:
    relative: str
    payload: bytes
    size: int
    sha256: str

    def record(self) -> dict[str, Any]:
        return {"bytes": self.size, "path": self.relative, "sha256": self.sha256}


@dataclass
class OutputTarget:
    parent_fd: int
    root_fd: int
    name: str

    def close(self) -> None:
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ReadinessError(message)


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _expect(
        isinstance(value, dict) and set(value) == keys,
        f"{label} has an unexpected shape",
    )
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    _expect(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        f"{label} is not a valid integer",
    )
    return value


def _multihash(value: Any, label: str) -> str:
    _expect(
        isinstance(value, str) and bool(MULTIHASH_RE.fullmatch(value)),
        f"{label} is not a SHA-256 multihash",
    )
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ReadinessError("evidence cannot be canonically encoded") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_multihash(payload: bytes) -> str:
    return "1220" + _sha256(payload)


def _reject_constant(value: str) -> None:
    raise ReadinessError(f"JSON contains a non-finite number: {value}")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadinessError(f"JSON contains a duplicate key: {key}")
        result[key] = value
    return result


def _parse_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReadinessError(f"{label} is not strict JSON") from error
    _expect(isinstance(value, dict), f"{label} must contain an object")
    return value


def _relative_parts(relative: str) -> tuple[str, ...]:
    pure = PurePosixPath(relative)
    _expect(
        not pure.is_absolute()
        and bool(pure.parts)
        and "\\" not in relative
        and all(part not in ("", ".", "..") for part in pure.parts),
        f"unsafe repository-relative path: {relative!r}",
    )
    return pure.parts


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_absolute_directory(path: Path) -> int:
    _expect(path.is_absolute(), f"directory path must be absolute: {path}")
    parts = path.parts
    _expect(bool(parts), f"directory path is empty: {path}")
    _expect(
        all(part not in ("", ".", "..") for part in parts[1:]),
        f"directory path contains a navigation component: {path}",
    )
    descriptor = os.open(path.anchor, _directory_flags())
    try:
        for part in parts[1:]:
            next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        _expect(stat.S_ISDIR(metadata.st_mode), f"path is not a directory: {path}")
        return descriptor
    except (OSError, ReadinessError) as error:
        os.close(descriptor)
        if isinstance(error, ReadinessError):
            raise
        raise ReadinessError(
            f"directory contains a symlink or is unavailable: {path}"
        ) from error


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _directory_is_within(directory_fd: int, root_fd: int) -> bool:
    """Compare opened directory identities without resolving path-string symlinks."""

    root_metadata = os.fstat(root_fd)
    descriptor = os.dup(directory_fd)
    try:
        # A valid absolute path cannot approach this depth on supported hosts,
        # but keep hostile descriptor traversal explicitly bounded.
        for _ in range(4096):
            metadata = os.fstat(descriptor)
            if _same_directory(metadata, root_metadata):
                return True
            parent = os.open("..", _directory_flags(), dir_fd=descriptor)
            parent_metadata = os.fstat(parent)
            if _same_directory(metadata, parent_metadata):
                os.close(parent)
                return False
            os.close(descriptor)
            descriptor = parent
    except OSError as error:
        raise ReadinessError(
            "unable to prove the evidence directory is outside the source repository"
        ) from error
    finally:
        os.close(descriptor)
    raise ReadinessError("evidence directory ancestry exceeds the safety bound")


def _open_relative_directory(root: Path, relative: str) -> int:
    descriptor = _open_absolute_directory(root)
    try:
        for part in _relative_parts(relative):
            next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ReadinessError(
            f"evidence directory contains a symlink or is missing: {relative}"
        ) from error


def _read_relative(
    root: Path, relative: str, maximum_bytes: int = MAX_JSON_BYTES
) -> Asset:
    parts = _relative_parts(relative)
    directory = _open_absolute_directory(root)
    descriptor = -1
    try:
        for part in parts[:-1]:
            next_directory = os.open(part, _directory_flags(), dir_fd=directory)
            os.close(directory)
            directory = next_directory
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(parts[-1], flags, dir_fd=directory)
        before = os.fstat(descriptor)
        _expect(
            stat.S_ISREG(before.st_mode), f"evidence is not a regular file: {relative}"
        )
        _expect(
            0 <= before.st_size <= maximum_bytes,
            f"evidence exceeds its byte bound: {relative}",
        )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            _expect(bool(chunk), f"evidence was truncated while reading: {relative}")
            chunks.append(chunk)
            remaining -= len(chunk)
        _expect(
            os.read(descriptor, 1) == b"", f"evidence grew while reading: {relative}"
        )
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        _expect(
            identity_before == identity_after,
            f"evidence changed while reading: {relative}",
        )
        payload = b"".join(chunks)
        return Asset(relative, payload, len(payload), _sha256(payload))
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
            raise ReadinessError(
                f"evidence contains a symlink or is missing: {relative}"
            ) from error
        raise ReadinessError(f"unable to read evidence: {relative}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _json_relative(root: Path, relative: str) -> tuple[dict[str, Any], Asset]:
    asset = _read_relative(root, relative)
    return _parse_json(asset.payload, relative), asset


def _list_relative(root: Path, relative: str) -> set[str]:
    descriptor = _open_relative_directory(root, relative)
    try:
        names = os.listdir(descriptor)
    finally:
        os.close(descriptor)
    _expect(
        all(isinstance(name, str) and name not in ("", ".", "..") for name in names),
        f"invalid directory entry in {relative}",
    )
    return set(names)


def _validate_digest_field(value: dict[str, Any], field: str, label: str) -> None:
    supplied = _multihash(value.get(field), f"{label} {field}")
    unsigned = dict(value)
    unsigned.pop(field)
    _expect(
        _sha256_multihash(_canonical(unsigned)) == supplied,
        f"{label} {field} does not bind its fields",
    )


def _validate_demo_item_list(
    outer: Any,
    driver: Any,
    expected_ids: Any,
    key: str,
    label: str,
    *,
    require_product: bool,
) -> None:
    _expect(
        isinstance(expected_ids, list) and expected_ids, f"{label} inventory is invalid"
    )
    _expect(
        isinstance(outer, list) and isinstance(driver, list),
        f"{label} evidence is missing",
    )
    _expect(
        len(outer) == len(driver) == len(expected_ids),
        f"{label} evidence count differs from its assets",
    )
    for expected, outer_item, driver_item in zip(
        expected_ids, outer, driver, strict=True
    ):
        _exact(outer_item, {key, "status"}, f"{label} outer item")
        _exact(driver_item, {key, "status", "evidence_digest"}, f"{label} driver item")
        _expect(
            outer_item[key] == driver_item[key] == expected,
            f"{label} identity mismatch",
        )
        _multihash(driver_item["evidence_digest"], f"{label} evidence digest")
        status = driver_item["status"]
        _expect(
            status in {"product_observed", "fixture_observed"},
            f"{label} contains unobserved evidence",
        )
        if require_product:
            _expect(status == "product_observed", f"{label} is not product-observed")
        _expect(
            outer_item["status"] == status, f"{label} outer and driver status disagree"
        )


def _validate_demo(
    root: Path, demo_id: str, asset_directory: str
) -> tuple[dict[str, Any], str]:
    report_relative = f"reports/demos/{demo_id}.json"
    report, report_asset = _json_relative(root, report_relative)
    _exact(report, DEMO_RECORD_KEYS, f"demo record {demo_id}")
    _expect(
        report["schema_version"] == "cigar.demo-record.v1",
        f"demo record schema mismatch: {demo_id}",
    )
    _expect(
        report["demo_id"] == demo_id and report["mode"] == "release_demo",
        f"demo record identity/mode mismatch: {demo_id}",
    )
    _expect(
        report["release_demo_qualified"] is True,
        f"demo record is not locally qualified: {demo_id}",
    )
    _integer(report["fixed_seed"], f"demo seed {demo_id}")
    _validate_digest_field(report, "record_digest", f"demo record {demo_id}")

    manifest_relative = f"{asset_directory}/demo.json"
    manifest, manifest_asset = _json_relative(root, manifest_relative)
    _exact(manifest, DEMO_MANIFEST_KEYS, f"demo manifest {demo_id}")
    _expect(
        manifest["schema_version"] == "cigar.demo-manifest.v1"
        and manifest["demo_id"] == demo_id,
        f"demo manifest identity mismatch: {demo_id}",
    )
    _expect(
        manifest["recorded_mode"] is True
        and manifest["fixed_seed"] == report["fixed_seed"],
        f"demo manifest mode/seed mismatch: {demo_id}",
    )
    _expect(
        report["manifest_digest"] == _sha256_multihash(manifest_asset.payload),
        f"demo record does not bind current manifest: {demo_id}",
    )

    for field in ("fixture", "driver"):
        path = manifest[field]
        _expect(
            isinstance(path, str) and PurePosixPath(path).name == path,
            f"demo {field} path is unsafe: {demo_id}",
        )
    fixture_relative = f"{asset_directory}/{manifest['fixture']}"
    driver_relative = f"{asset_directory}/{manifest['driver']}"
    fixture, fixture_asset = _json_relative(root, fixture_relative)
    driver_asset = _read_relative(root, driver_relative)
    support_asset = _read_relative(root, "demos/driver_support.py")
    _expect(
        fixture.get("schema_version") == "cigar.demo-fixture.v1"
        and fixture.get("demo_id") == demo_id,
        f"demo fixture identity mismatch: {demo_id}",
    )
    _expect(
        fixture.get("fixed_seed") == manifest["fixed_seed"],
        f"demo fixture seed mismatch: {demo_id}",
    )
    _expect(
        manifest["fixture_digest"]
        == report["fixture_digest"]
        == _sha256_multihash(fixture_asset.payload),
        f"demo fixture digest mismatch: {demo_id}",
    )
    _expect(
        manifest["driver_digest"] == _sha256_multihash(driver_asset.payload),
        f"demo driver digest mismatch: {demo_id}",
    )
    _expect(
        manifest["driver_support_digest"] == _sha256_multihash(support_asset.payload),
        f"demo support digest mismatch: {demo_id}",
    )

    driver = report["scenario_driver"]
    _exact(driver, DEMO_DRIVER_KEYS, f"demo driver result {demo_id}")
    _expect(
        driver["schema_version"] == "cigar.demo-driver-result.v1"
        and driver["demo_id"] == demo_id,
        f"demo driver result identity mismatch: {demo_id}",
    )
    _expect(
        driver["fixed_seed"] == manifest["fixed_seed"]
        and driver["fixture_digest"] == manifest["fixture_digest"],
        f"demo driver asset binding mismatch: {demo_id}",
    )
    boundary = driver["no_egress_enforcement"]
    _expect(
        boundary in ALLOWED_NO_EGRESS,
        f"demo no-egress evidence is not allowlisted: {demo_id}",
    )
    bundle = _sha256_multihash(
        _canonical(
            {
                "driver": manifest["driver_digest"],
                "support": manifest["driver_support_digest"],
            }
        )
    )
    _expect(
        driver["driver_bundle_digest"] == bundle,
        f"demo driver bundle is not current: {demo_id}",
    )
    unsigned_driver = dict(driver)
    unsigned_driver.pop("driver_bundle_digest")
    _validate_digest_field(
        unsigned_driver, "result_digest", f"demo driver result {demo_id}"
    )
    _expect(
        isinstance(driver["observations"], dict),
        f"demo observations are invalid: {demo_id}",
    )
    _canonical(driver["observations"])

    flow = fixture.get("flow")
    _validate_demo_item_list(
        report["setup"],
        driver["setup"],
        manifest["setup"],
        "step",
        f"demo setup {demo_id}",
        require_product=False,
    )
    _validate_demo_item_list(
        report["flow"],
        driver["flow"],
        flow,
        "step",
        f"demo flow {demo_id}",
        require_product=True,
    )
    _validate_demo_item_list(
        report["teardown"],
        driver["teardown"],
        manifest["teardown"],
        "step",
        f"demo teardown {demo_id}",
        require_product=False,
    )

    expected_assertions = manifest["expected_assertions"]
    outer_assertions = report["assertions"]
    driver_assertions = driver["assertions"]
    _expect(
        isinstance(expected_assertions, list)
        and len(outer_assertions) == len(driver_assertions) == len(expected_assertions),
        f"demo assertion inventory mismatch: {demo_id}",
    )
    for expected, outer, observed in zip(
        expected_assertions, outer_assertions, driver_assertions, strict=True
    ):
        _exact(outer, {"assertion_id", "status"}, f"demo outer assertion {demo_id}")
        _exact(
            observed,
            {"assertion_id", "status", "evidence_digest"},
            f"demo driver assertion {demo_id}",
        )
        _expect(
            outer["assertion_id"] == observed["assertion_id"] == expected,
            f"demo assertion identity mismatch: {demo_id}",
        )
        _expect(
            outer["status"] == "independently_observed"
            and observed["status"] == "product_observed",
            f"demo assertion is not independently product-observed: {demo_id}",
        )
        _multihash(observed["evidence_digest"], f"demo assertion digest {demo_id}")

    manifest_checks = manifest["checks"]
    record_checks = report["checks"]
    _expect(
        isinstance(manifest_checks, list)
        and len(record_checks) == len(manifest_checks),
        f"demo check inventory mismatch: {demo_id}",
    )
    for expected, observed in zip(manifest_checks, record_checks, strict=True):
        _expect(
            isinstance(expected, dict)
            and set(expected)
            == {
                "check_id",
                "command",
                "timeout_seconds",
                "minimum_passed_tests",
                "assertions",
            },
            f"demo manifest check shape mismatch: {demo_id}",
        )
        _exact(
            observed,
            {"check_id", "status", "passed_tests", "assertions"},
            f"demo record check {demo_id}",
        )
        _expect(
            observed["check_id"] == expected["check_id"]
            and observed["assertions"] == expected["assertions"],
            f"demo check identity mismatch: {demo_id}",
        )
        _expect(
            observed["status"] == "component_check_passed",
            f"demo component check failed: {demo_id}",
        )
        _expect(
            _integer(
                observed["passed_tests"], f"demo passed test count {demo_id}", minimum=1
            )
            >= _integer(
                expected["minimum_passed_tests"],
                f"demo minimum test count {demo_id}",
                minimum=1,
            ),
            f"demo component test count is insufficient: {demo_id}",
        )

    return (
        {
            **report_asset.record(),
            "demo_id": demo_id,
            "driver_sha256": driver_asset.sha256,
            "driver_support_sha256": support_asset.sha256,
            "fixture_sha256": fixture_asset.sha256,
            "manifest_sha256": manifest_asset.sha256,
        },
        boundary,
    )


def _demo_evidence(root: Path) -> dict[str, Any]:
    expected_files = {f"{identifier}.json" for identifier in EXPECTED_DEMO_PATHS} | {
        "sdk-quickstarts.json"
    }
    _expect(
        _list_relative(root, "reports/demos") == expected_files,
        "demo report directory has missing or extra entries",
    )
    records: list[dict[str, Any]] = []
    boundaries: set[str] = set()
    for demo_id, asset_directory in sorted(EXPECTED_DEMO_PATHS.items()):
        record, boundary = _validate_demo(root, demo_id, asset_directory)
        records.append(record)
        boundaries.add(boundary)
    _expect(len(boundaries) == 1, "demo records disagree on no-egress enforcement")
    return {
        "byte_identical_repeat": False,
        "directory": "reports/demos",
        "no_egress_enforcement": next(iter(boundaries)),
        "qualified_records": len(records),
        "records": records,
        "repeat_evidence": "not_present",
    }


def _sdk_evidence(root: Path) -> dict[str, Any]:
    report, report_asset = _json_relative(root, "reports/demos/sdk-quickstarts.json")
    _exact(report, SDK_REPORT_KEYS, "SDK quickstart report")
    _expect(
        report["schema_version"] == "cigar.sdk-quickstart-report.v1",
        "SDK report schema mismatch",
    )
    _expect(
        report["artifact_mode"] == "source-checkout"
        and report["qualification_scope"] == "recorded-ingest-compile-manifest"
        and report["evidence_class"] == "deterministic-recorded-fixture",
        "SDK report scope mismatch",
    )
    _expect(
        report["sdk_workflow_qualified"] is True
        and report["installed_artifact_qualified"] is False
        and report["release_qualified"] is False,
        "SDK report overclaims qualification",
    )
    _expect(
        tuple(report["operations"]) == EXPECTED_OPERATIONS,
        "SDK report operation inventory mismatch",
    )
    _validate_digest_field(report, "report_digest", "SDK report")

    manifest, manifest_asset = _json_relative(
        root, "demos/sdk-clients/quickstarts.json"
    )
    _exact(
        manifest,
        {"schema_version", "fixture", "expected_bundle_id", "quickstarts"},
        "SDK manifest",
    )
    _expect(
        manifest["schema_version"] == "cigar.sdk-quickstarts.v1",
        "SDK manifest schema mismatch",
    )
    _expect(
        report["manifest_digest"] == _sha256_multihash(manifest_asset.payload),
        "SDK report does not bind the current manifest",
    )
    fixture_path = manifest["fixture"]
    _expect(
        fixture_path == "demos/sdk-clients/workflow-fixture-v1.json",
        "SDK fixture path is not the pinned v1 asset",
    )
    fixture, fixture_asset = _json_relative(root, fixture_path)
    _exact(
        fixture,
        {
            "schema_version",
            "expected_bundle_id",
            "expected_manifest_id",
            "expected_contract_digest",
            "expected_operations",
            "operations",
        },
        "SDK workflow fixture",
    )
    _expect(
        fixture["schema_version"] == "cigar.sdk-recorded-workflow.v1",
        "SDK workflow fixture schema mismatch",
    )
    _expect(
        report["fixture_digest"] == _sha256_multihash(fixture_asset.payload),
        "SDK report does not bind the current fixture",
    )
    for field in ("bundle_id", "selection_manifest_id", "contract_digest"):
        _multihash(report[field], f"SDK {field}")
    _expect(
        manifest["expected_bundle_id"]
        == fixture["expected_bundle_id"]
        == report["bundle_id"],
        "SDK bundle identities disagree",
    )
    _expect(
        fixture["expected_manifest_id"] == report["selection_manifest_id"],
        "SDK manifest identities disagree",
    )
    _expect(
        fixture["expected_contract_digest"] == report["contract_digest"],
        "SDK contract identities disagree",
    )
    _expect(
        tuple(fixture["expected_operations"]) == EXPECTED_OPERATIONS,
        "SDK fixture operations mismatch",
    )

    declared = manifest["quickstarts"]
    observed = report["quickstarts"]
    _expect(
        isinstance(declared, list)
        and isinstance(observed, list)
        and len(declared) == len(observed) == 4,
        "SDK runtime inventory must contain four entries",
    )
    declared_modes: dict[str, str] = {}
    for entry in declared:
        _exact(
            entry,
            {"language", "mode", "working_directory", "prepare", "command"},
            "SDK manifest runtime",
        )
        _expect(
            isinstance(entry["language"], str) and isinstance(entry["mode"], str),
            "SDK manifest runtime identity is invalid",
        )
        _expect(
            entry["language"] not in declared_modes, "SDK manifest duplicates a runtime"
        )
        declared_modes[entry["language"]] = entry["mode"]
    _expect(
        declared_modes == EXPECTED_SDK_MODES,
        "SDK manifest modes differ from the pinned runtime modes",
    )
    seen: set[str] = set()
    for result in observed:
        _exact(result, SDK_RESULT_KEYS, "SDK result")
        language = result["language"]
        _expect(
            language in EXPECTED_SDK_MODES and language not in seen,
            "SDK result runtime is unknown or duplicated",
        )
        seen.add(language)
        _expect(
            result["mode"] == EXPECTED_SDK_MODES[language]
            and result["status"] == "recorded_workflow_passed",
            "SDK runtime mode/status mismatch",
        )
        _expect(
            tuple(result["operations"]) == EXPECTED_OPERATIONS,
            "SDK runtime operations mismatch",
        )
        _expect(
            result["bundle_id"] == report["bundle_id"]
            and result["manifest_id"] == report["selection_manifest_id"],
            "SDK runtime identities disagree",
        )
    _expect(
        tuple(sorted(seen)) == EXPECTED_LANGUAGES,
        "SDK result runtime inventory is incomplete",
    )
    return {
        **report_asset.record(),
        "bundle_id": report["bundle_id"],
        "installed_artifact_qualified": False,
        "manifest_id": report["selection_manifest_id"],
        "release_qualified": False,
        "runtime_count": 4,
        "source_workflow_qualified": True,
    }


def _evidence_record(value: Any, label: str) -> dict[str, Any]:
    record = _exact(value, {"bytes", "sha256"}, label)
    _integer(record["bytes"], f"{label} bytes")
    _expect(
        isinstance(record["sha256"], str)
        and bool(SHA256_RE.fullmatch(record["sha256"])),
        f"{label} SHA-256 is invalid",
    )
    return record


def _validate_plan(plan: dict[str, Any], label: str) -> list[dict[str, Any]]:
    _exact(plan, PLAN_KEYS, f"{label} plan")
    _expect(
        plan["schema_version"] == "cigar.benchmark-plan.v1",
        f"{label} plan schema mismatch",
    )
    _validate_digest_field(plan, "assignment_digest", f"{label} plan")
    for key in (
        "seed_commitment",
        "dataset_manifest_digest",
        "baseline_manifest_digest",
        "canary_registry_digest",
    ):
        _multihash(plan[key], f"{label} plan {key}")
    assignments = plan["assignments"]
    _expect(
        isinstance(assignments, list) and assignments,
        f"{label} plan assignments are empty",
    )
    identities: set[tuple[str, str]] = set()
    for assignment in assignments:
        _exact(assignment, ASSIGNMENT_KEYS, f"{label} assignment")
        for key in (
            "run_id",
            "pair_id",
            "dataset_id",
            "task_id",
            "stratum",
            "baseline_id",
        ):
            _expect(
                isinstance(assignment[key], str)
                and bool(IDENTIFIER_RE.fullmatch(assignment[key])),
                f"{label} assignment {key} is invalid",
            )
        _expect(
            assignment["treatment"] in ("baseline", "cigar")
            and assignment["order"] in (1, 2),
            f"{label} assignment treatment/order is invalid",
        )
        _integer(assignment["sample_index"], f"{label} assignment sample index")
        _expect(
            assignment["evidence_class"] == "harness_smoke",
            f"{label} assignment is not harness smoke evidence",
        )
        _multihash(assignment["environment_digest"], f"{label} assignment environment")
        identity = (assignment["pair_id"], assignment["treatment"])
        _expect(identity not in identities, f"{label} plan repeats an assignment")
        identities.add(identity)
    _expect(len(assignments) % 2 == 0, f"{label} plan has an odd assignment count")
    return assignments


def _parse_events(asset: Asset, label: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    identities: set[str] = set()
    for line_number, raw in enumerate(asset.payload.splitlines(), 1):
        if not raw.strip():
            continue
        _expect(len(raw) <= MAX_EVENT_BYTES, f"{label} event line exceeds its bound")
        event = _parse_json(raw, f"{label} event line {line_number}")
        _exact(event, EVENT_KEYS, f"{label} event")
        _expect(
            event["schema_version"] == "cigar.benchmark-event.v1",
            f"{label} event schema mismatch",
        )
        _validate_digest_field(event, "event_id", f"{label} event")
        _expect(
            event["event_id"] not in identities, f"{label} repeats an event identity"
        )
        identities.add(event["event_id"])
        _expect(
            event["evidence_class"] == "harness_smoke" and event["warmup"] is False,
            f"{label} event is not post-warm harness evidence",
        )
        _multihash(event["assignment_digest"], f"{label} event assignment digest")
        _multihash(event["seed_commitment"], f"{label} event seed commitment")
        events.append(event)
        _expect(len(events) <= MAX_EVENTS, f"{label} event count exceeds its bound")
    _expect(bool(events), f"{label} event stream is empty")
    return events


def _validate_benchmark_bundle(
    root: Path,
    directory: str,
    comparator: str,
    *,
    additional_files: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    expected_files = {"events.jsonl", "plan.json", "report.json"} | set(
        additional_files
    )
    _expect(
        _list_relative(root, directory) == expected_files,
        f"{directory} has missing or extra attachments",
    )
    plan, plan_asset = _json_relative(root, f"{directory}/plan.json")
    assignments = _validate_plan(plan, comparator)
    events_asset = _read_relative(root, f"{directory}/events.jsonl")
    events = _parse_events(events_asset, comparator)
    _expect(
        len(events) == len(assignments),
        f"{comparator} event and assignment counts disagree",
    )
    assignment_map = {
        (entry["pair_id"], entry["treatment"]): entry for entry in assignments
    }
    for event in events:
        identity = (event["pair_id"], event["treatment"])
        _expect(
            identity in assignment_map, f"{comparator} event is absent from its plan"
        )
        projection = {key: event[key] for key in ASSIGNMENT_KEYS}
        _expect(
            _canonical(projection) == _canonical(assignment_map[identity]),
            f"{comparator} event differs from its plan",
        )
        _expect(
            event["assignment_digest"] == plan["assignment_digest"]
            and event["seed_commitment"] == plan["seed_commitment"],
            f"{comparator} event commitments disagree with its plan",
        )
    _expect(
        {entry["baseline_id"] for entry in assignments} == {comparator},
        f"{comparator} plan uses a different comparator",
    )

    report, report_asset = _json_relative(root, f"{directory}/report.json")
    _exact(report, REPORT_KEYS, f"{comparator} report")
    _expect(
        report["schema_version"] == "cigar.benchmark-report.v1"
        and report["decision"] == "insufficient_evidence",
        f"{comparator} report schema/decision mismatch",
    )
    _validate_digest_field(report, "report_digest", f"{comparator} report")
    _expect(
        report["input_digest"] == _sha256_multihash(events_asset.payload),
        f"{comparator} report does not bind its events",
    )
    manifests = _exact(
        report["input_manifests"],
        {"plan", "datasets", "baselines", "canaries", "environment"},
        f"{comparator} report input manifests",
    )
    _expect(
        manifests["plan"] == plan["assignment_digest"],
        f"{comparator} report does not bind its plan",
    )
    _expect(
        report["seed_commitment"] == plan["seed_commitment"],
        f"{comparator} report seed differs from its plan",
    )
    comparison = _exact(
        report["comparison"],
        {"comparator_id", "evidence_class", "pins"},
        f"{comparator} comparison",
    )
    _expect(
        comparison["comparator_id"] == comparator
        and comparison["evidence_class"] == "harness_smoke",
        f"{comparator} report comparison mismatch",
    )
    qualification = report["qualification"]
    _expect(
        isinstance(qualification, dict)
        and qualification.get("eligible") is False
        and isinstance(qualification.get("reasons"), list),
        f"{comparator} report qualification mismatch",
    )
    global_report = _exact(
        report["global"], {"gates", "metrics"}, f"{comparator} global report"
    )
    metrics = global_report["metrics"]
    _expect(isinstance(metrics, dict), f"{comparator} metrics are invalid")
    pair_count = _integer(
        metrics.get("pair_count"), f"{comparator} pair count", minimum=1
    )
    _expect(
        pair_count * 2 == len(events),
        f"{comparator} report pair count disagrees with events",
    )
    per_stratum = report["per_stratum"]
    _expect(
        isinstance(per_stratum, dict) and len(per_stratum) == 9,
        f"{comparator} report does not contain nine strata",
    )
    return {
        "attachments": [
            events_asset.record(),
            plan_asset.record(),
            report_asset.record(),
        ],
        "assignment_digest": plan["assignment_digest"],
        "bootstrap_repetitions": _integer(
            report["bootstrap_repetitions"],
            f"{comparator} bootstrap repetitions",
            minimum=100,
        ),
        "event_count": len(events),
        "ineligible_reasons": qualification["reasons"],
        "pair_count": pair_count,
        "per_stratum_reports": len(per_stratum),
        "report_digest": report["report_digest"],
        "seed_commitment": plan["seed_commitment"],
    }


def _attachment_set_digest(records: list[dict[str, Any]]) -> str:
    return _sha256(_canonical(sorted(records, key=lambda entry: entry["path"])))


def _benchmark_evidence(root: Path) -> dict[str, Any]:
    dry_directory = "reports/cigarbench/local-dry-run"
    _expect(
        _list_relative(root, dry_directory)
        == {"events.jsonl", "plan.json", "qualification.json", "report.json"},
        "release-shaped dry-run directory has missing or extra entries",
    )
    dry_receipt, dry_receipt_asset = _json_relative(
        root, f"{dry_directory}/qualification.json"
    )
    _exact(dry_receipt, DRY_RECEIPT_KEYS, "release-shaped dry-run receipt")
    _expect(
        dry_receipt["schema_version"] == DRY_RUN_SCHEMA_VERSION
        and dry_receipt["schema_version"] != SCHEMA_VERSION,
        "dry-run and aggregate schemas collide",
    )
    _expect(
        dry_receipt["scope"] == "source-fixture-release-shaped-dry-run"
        and dry_receipt["status"] == "passed-ineligible"
        and dry_receipt["decision"] == "insufficient_evidence",
        "release-shaped dry-run scope/status mismatch",
    )
    qualification = dry_receipt["qualification"]
    _expect(
        isinstance(qualification, dict) and qualification.get("eligible") is False,
        "release-shaped dry-run is not explicitly ineligible",
    )
    reasons = dry_receipt["ineligible_reasons"]
    _expect(
        isinstance(reasons, list) and reasons == qualification.get("reasons"),
        "release-shaped dry-run reasons disagree",
    )
    evidence = _exact(
        dry_receipt["evidence"],
        {"events", "plan", "report"},
        "release-shaped dry-run evidence",
    )
    for logical in sorted(evidence):
        expected = _evidence_record(evidence[logical], f"release-shaped {logical}")
        filename = {
            "events": "events.jsonl",
            "plan": "plan.json",
            "report": "report.json",
        }[logical]
        actual = _read_relative(root, f"{dry_directory}/{filename}")
        _expect(
            expected == {"bytes": actual.size, "sha256": actual.sha256},
            f"release-shaped {logical} attachment record mismatch",
        )
    bundle = _validate_benchmark_bundle(
        root,
        dry_directory,
        "full-transcript-project",
        additional_files=frozenset({"qualification.json"}),
    )
    counts = dry_receipt["counts"]
    _expect(isinstance(counts, dict), "release-shaped count block is invalid")
    expected_counts = {
        "events": bundle["event_count"],
        "global_pairs": bundle["pair_count"],
        "strata": bundle["per_stratum_reports"],
        "bootstrap_repetitions_requested": bundle["bootstrap_repetitions"],
    }
    for key, expected in expected_counts.items():
        _expect(
            _integer(counts.get(key), f"release-shaped {key}") == expected,
            f"release-shaped {key} disagrees with attachments",
        )
    _expect(
        dry_receipt["report_digest"] == bundle["report_digest"]
        and dry_receipt["seed_commitment"] == bundle["seed_commitment"],
        "release-shaped receipt does not bind its report/plan",
    )
    dry_attachments = sorted(bundle["attachments"], key=lambda entry: entry["path"])

    matrix_directory = "reports/cigarbench/local-matrix-dry-run-v1"
    matrix_receipt, matrix_asset = _json_relative(
        root, f"{matrix_directory}/matrix-receipt.json"
    )
    _exact(matrix_receipt, MATRIX_RECEIPT_KEYS, "comparator matrix receipt")
    _expect(
        matrix_receipt["schema_version"] == "cigar.wp20-local-matrix-dry-run.v1"
        and matrix_receipt["status"] == "passed-ineligible"
        and matrix_receipt["scope"] == "recorded-consumer-protocol-only",
        "comparator matrix scope/status mismatch",
    )
    baseline_manifest, _ = _json_relative(root, "baselines/cigarbench/manifest.json")
    _exact(
        baseline_manifest,
        {"schema_version", "baselines", "ablations"},
        "comparator manifest",
    )
    _expect(
        baseline_manifest["schema_version"] == "cigar.benchmark-baselines.v1",
        "comparator manifest schema mismatch",
    )
    baselines = baseline_manifest["baselines"]
    ablations = baseline_manifest["ablations"]
    _expect(
        isinstance(baselines, list)
        and len(baselines) == 7
        and isinstance(ablations, list)
        and len(ablations) == 5,
        "comparator manifest must contain seven baselines and five ablations",
    )
    comparators = sorted(
        [entry.get("baseline_id") for entry in baselines if isinstance(entry, dict)]
        + ablations
    )
    _expect(
        len(comparators) == 12
        and all(isinstance(value, str) for value in comparators)
        and len(set(comparators)) == 12,
        "comparator IDs are invalid",
    )
    _expect(
        matrix_receipt["comparator_inventory"] == comparators
        and matrix_receipt["comparator_count"] == 12,
        "comparator matrix inventory mismatch",
    )
    _expect(
        _list_relative(root, matrix_directory) == {"matrix-receipt.json", *comparators},
        "comparator matrix directory has missing or extra entries",
    )
    expected_evidence_names = {
        f"{comparator}/{filename}"
        for comparator in comparators
        for filename in ("events.jsonl", "plan.json", "report.json")
    }
    matrix_evidence = matrix_receipt["evidence"]
    _expect(
        isinstance(matrix_evidence, dict)
        and set(matrix_evidence) == expected_evidence_names,
        "comparator attachment inventory is not exact",
    )
    reports = matrix_receipt["reports"]
    _expect(
        isinstance(reports, dict) and set(reports) == set(comparators),
        "comparator report summary inventory is not exact",
    )
    matrix_attachments: list[dict[str, Any]] = []
    assignment_digests: set[str] = set()
    seed_commitments: set[str] = set()
    requested = _integer(
        matrix_receipt["bootstrap_repetitions_requested_per_report"],
        "matrix bootstrap repetitions",
        minimum=100,
    )
    for comparator in comparators:
        bundle = _validate_benchmark_bundle(
            root, f"{matrix_directory}/{comparator}", comparator
        )
        matrix_attachments.extend(bundle["attachments"])
        assignment_digests.add(bundle["assignment_digest"])
        seed_commitments.add(bundle["seed_commitment"])
        _expect(
            bundle["bootstrap_repetitions"] == requested,
            f"{comparator} bootstrap repetitions disagree with matrix receipt",
        )
        summary = _exact(
            reports[comparator],
            {
                "decision",
                "event_count",
                "pair_count",
                "per_stratum_reports",
                "ineligible_reasons",
                "report_digest",
            },
            f"{comparator} matrix summary",
        )
        expected_summary = {
            "decision": "insufficient_evidence",
            "event_count": bundle["event_count"],
            "pair_count": bundle["pair_count"],
            "per_stratum_reports": bundle["per_stratum_reports"],
            "ineligible_reasons": bundle["ineligible_reasons"],
            "report_digest": bundle["report_digest"],
        }
        _expect(
            summary == expected_summary,
            f"{comparator} matrix summary does not bind its attachments",
        )
        for attachment in bundle["attachments"]:
            suffix = attachment["path"].removeprefix(f"{matrix_directory}/")
            expected = _evidence_record(
                matrix_evidence[suffix], f"matrix attachment {suffix}"
            )
            _expect(
                expected
                == {"bytes": attachment["bytes"], "sha256": attachment["sha256"]},
                f"matrix attachment record mismatch: {suffix}",
            )
    _expect(
        matrix_receipt["distinct_assignment_digests"] == len(assignment_digests) == 12,
        "matrix assignment digest count mismatch",
    )
    _expect(
        len(seed_commitments) == 1
        and matrix_receipt["shared_seed_commitment"] in seed_commitments,
        "matrix shared seed commitment mismatch",
    )
    _expect(
        matrix_receipt["paired_randomized_execution"] == "passed"
        and matrix_receipt["raw_report_replay"] == "passed_all_comparators"
        and matrix_receipt["canary_scan"] == "passed",
        "matrix protocol checks did not pass",
    )
    matrix_qualification = matrix_receipt["qualification"]
    _expect(
        isinstance(matrix_qualification, dict)
        and matrix_qualification.get("eligible") is False
        and isinstance(matrix_qualification.get("analyzer_reasons"), list)
        and isinstance(matrix_qualification.get("scope_reasons"), list),
        "matrix qualification block is invalid",
    )
    matrix_attachments.sort(key=lambda entry: entry["path"])
    return {
        "comparator_matrix_dry_run": {
            **matrix_asset.record(),
            "attachment_count": len(matrix_attachments),
            "attachment_set_sha256": _attachment_set_digest(matrix_attachments),
            "attachments": matrix_attachments,
            "comparator_count": 12,
            "decision": "passed-ineligible",
            "eligible": False,
            "ineligible_reasons": list(
                dict.fromkeys(
                    matrix_qualification["analyzer_reasons"]
                    + matrix_qualification["scope_reasons"]
                )
            ),
        },
        "release_shaped_dry_run": {
            **dry_receipt_asset.record(),
            "attachment_count": len(dry_attachments),
            "attachment_set_sha256": _attachment_set_digest(dry_attachments),
            "attachments": dry_attachments,
            "decision": "insufficient_evidence",
            "eligible": False,
            "ineligible_reasons": reasons,
        },
    }


def _sanitized_environment(home: Path) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PYTHONHASHSEED": "0",
        "TMPDIR": str(home),
        "TZ": "UTC",
    }
    user_home = Path(os.environ.get("HOME", str(Path.home()))).expanduser().absolute()
    if sys.platform == "darwin":
        pnpm_store = user_home / "Library/pnpm/store/v10"
    elif os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        pnpm_store = (
            Path(local) / "pnpm/store/v10"
            if local
            else user_home / "AppData/Local/pnpm/store/v10"
        )
    else:
        data_home = os.environ.get("XDG_DATA_HOME")
        pnpm_store = (
            Path(data_home) / "pnpm/store/v10"
            if data_home
            else user_home / ".local/share/pnpm/store/v10"
        )
    cache_defaults = {
        "CARGO_HOME": user_home / ".cargo",
        "RUSTUP_HOME": user_home / ".rustup",
        "COREPACK_HOME": user_home / ".cache/node/corepack",
        "NPM_CONFIG_STORE_DIR": pnpm_store,
        "UV_CACHE_DIR": user_home / ".cache/uv",
        "GOMODCACHE": user_home / "go/pkg/mod",
    }
    for name, default in cache_defaults.items():
        configured = Path(os.environ.get(name, str(default))).expanduser()
        _expect(configured.is_absolute(), f"{name} must be an absolute cache path")
        environment[name] = str(configured)
    search_directories = [
        str(Path(environment["CARGO_HOME"]) / "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    trusted_search = os.pathsep.join(search_directories)
    executable_directories: list[str] = []
    for name in (
        "cargo",
        "rustc",
        "rustdoc",
        "rustup",
        "pnpm",
        "node",
        "uv",
        "go",
        "python3",
        "git",
        "cc",
        "sh",
    ):
        discovered = shutil.which(name, path=trusted_search)
        _expect(
            discovered is not None, f"required test executable is unavailable: {name}"
        )
        configured = Path(discovered).absolute()
        resolved = configured.resolve(strict=True)
        _expect(resolved.is_file(), f"required test executable is not regular: {name}")
        directory = str(configured.parent)
        if directory not in executable_directories:
            executable_directories.append(directory)
    environment["PATH"] = os.pathsep.join(executable_directories)
    return environment


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    max_total: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    _expect(
        bool(command) and all(isinstance(value, str) and value for value in command),
        f"{label} command is invalid",
    )
    _expect(
        timeout > 0
        and max_stdout >= 0
        and max_stderr >= 0
        and max_total >= 0
        and max_total <= max_stdout + max_stderr,
        f"{label} process limits are invalid",
    )
    creation_flags = (
        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if os.name == "nt"
        else 0
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name != "nt",
            creationflags=creation_flags,
        )
    except OSError as error:
        raise ReadinessError(f"unable to start {label}") from error
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise ReadinessError(f"{label} did not expose bounded output streams")

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    output_lock = threading.Lock()
    kill_lock = threading.Lock()

    def kill_tree() -> bool:
        with kill_lock:
            try:
                if os.name == "nt":
                    killer = subprocess.Popen(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        shell=False,
                    )
                    return killer.wait(timeout=5) == 0
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                    return True
            except (OSError, subprocess.SubprocessError):
                if process.poll() is not None:
                    return False
                try:
                    process.kill()
                    return True
                except OSError:
                    return False

    def drain(stream: Any, destination: bytearray, stream_limit: int) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                with output_lock:
                    stream_remaining = max(0, stream_limit - len(destination))
                    total_remaining = max(0, max_total - len(stdout) - len(stderr))
                    retained = min(len(chunk), stream_remaining, total_remaining)
                    destination.extend(chunk[:retained])
                    exceeded = retained != len(chunk)
                if exceeded:
                    overflow.set()
                    kill_tree()
                    return
        except OSError:
            overflow.set()
            kill_tree()
        finally:
            stream.close()

    readers = [
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout, max_stdout),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr, max_stderr),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        kill_tree()
        process.wait()
        for reader in readers:
            reader.join(timeout=5)
        raise ReadinessError(f"{label} exceeded its timeout") from error
    lingering_processes = kill_tree()
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        kill_tree()
        for reader in readers:
            reader.join(timeout=5)
        raise ReadinessError(f"{label} output readers did not terminate")
    if overflow.is_set():
        raise ReadinessError(f"{label} output exceeded its bound")
    if lingering_processes:
        raise ReadinessError(f"{label} left descendant processes running")
    return subprocess.CompletedProcess(
        command, returncode, bytes(stdout), bytes(stderr)
    )


def _run_git(root: Path, *arguments: str, allow_failure: bool = False) -> bytes:
    with tempfile.TemporaryDirectory(prefix="cigar-wp20-git-") as directory:
        environment = _sanitized_environment(Path(directory))
        result = _run_bounded(
            ["git", *arguments],
            cwd=root,
            environment=environment,
            timeout=60,
            max_stdout=32 * 1024 * 1024,
            max_stderr=1024 * 1024,
            max_total=33 * 1024 * 1024,
            label="Git state command",
        )
    if result.returncode != 0:
        if allow_failure:
            return b""
        raise ReadinessError("Git state command failed")
    return result.stdout


def git_source_binding(root: Path) -> dict[str, Any]:
    top_level = _run_git(root, "rev-parse", "--show-toplevel").decode().strip()
    _expect(Path(top_level).absolute() == root, "--root is not the Git top level")
    revision = (
        _run_git(root, "rev-parse", "--verify", "HEAD^{commit}", allow_failure=True)
        .decode()
        .strip()
    )
    committed = bool(revision)
    tree: str | None = None
    if committed:
        _expect(
            bool(GIT_OBJECT_RE.fullmatch(revision)), "Git returned an invalid commit ID"
        )
        tree = _run_git(root, "rev-parse", "HEAD^{tree}").decode().strip()
        _expect(bool(GIT_OBJECT_RE.fullmatch(tree)), "Git returned an invalid tree ID")
    status = _run_git(
        root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"
    )
    dirty_count = len([entry for entry in status.split(b"\0") if entry])
    clean = dirty_count == 0
    if not committed:
        reason = "repository_has_no_HEAD_and_inputs_are_not_candidate_bound"
    elif not clean:
        reason = "working_tree_not_clean_and_inputs_are_not_candidate_bound"
    else:
        reason = "local_inputs_do_not_embed_a_candidate_revision"
    return {
        "clean": clean,
        "committed": committed,
        "committed_candidate": False,
        "dirty_path_count": dirty_count,
        "evidence_source_bound": False,
        "git_tree": tree,
        "reason": reason,
        "revision": revision or None,
    }


def _normalized_output_record(payload: bytes) -> dict[str, Any]:
    normalized = UNITTEST_DURATION_RE.sub(rb"\1<duration>", payload)
    return {
        "bytes": len(payload),
        "normalization": "unittest-duration-v1",
        "normalized_sha256": _sha256(normalized),
    }


def _python_identity(executable: Path) -> dict[str, str]:
    return {
        "executable": str(executable),
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
    }


def _run_test_suite(root: Path, identifier: str, relative: str) -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    _expect(
        executable.is_file() and not executable.is_symlink(),
        "Python executable is not a regular resolved file",
    )
    command = [str(executable), "-m", "unittest", "discover", "-s", relative, "-v"]
    with tempfile.TemporaryDirectory(prefix=f"cigar-wp20-{identifier}-") as directory:
        environment = _sanitized_environment(Path(directory))
        result = _run_bounded(
            command,
            cwd=root,
            environment=environment,
            timeout=900,
            max_stdout=16 * 1024 * 1024,
            max_stderr=16 * 1024 * 1024,
            max_total=32 * 1024 * 1024,
            label=f"{identifier} test suite",
        )
    _expect(result.returncode == 0, f"{identifier} test suite failed")
    combined = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")
    matches = UNITTEST_COUNT_RE.findall(combined)
    _expect(
        len(matches) == 1 and int(matches[0]) > 0,
        f"{identifier} test suite emitted no unambiguous count",
    )
    return {
        "command_sha256": _sha256(_canonical(command)),
        "id": identifier,
        "producer": _python_identity(executable),
        "status": "passed",
        "stderr": _normalized_output_record(result.stderr),
        "stdout": _normalized_output_record(result.stdout),
        "tests": int(matches[0]),
    }


def run_harness_tests(root: Path) -> list[dict[str, Any]]:
    return [
        _run_test_suite(root, "cigarbench", "benches/cigarbench/tests"),
        _run_test_suite(root, "comparator-matrix", "baselines/cigarbench/tests"),
        _run_test_suite(root, "demos", "demos/tests"),
    ]


def build_receipt(
    root: Path, source: dict[str, Any], suites: list[dict[str, Any]]
) -> dict[str, Any]:
    _expect(
        SCHEMA_VERSION != DRY_RUN_SCHEMA_VERSION,
        "aggregate and dry-run schema versions collide",
    )
    demos = _demo_evidence(root)
    sdk = _sdk_evidence(root)
    benchmarks = _benchmark_evidence(root)
    total_tests = sum(
        _integer(suite.get("tests"), "suite test count", minimum=1) for suite in suites
    )
    return {
        "benchmark_evidence": benchmarks,
        "checks": [
            {
                "detail": f"{total_tests} sanitized harness tests passed",
                "id": "harness-unit-tests",
                "status": "passed",
            },
            {
                "detail": "7/7 current-asset demo records and embedded drivers verified",
                "id": "seven-source-demos",
                "status": "passed",
            },
            {
                "detail": "no independently retained second demo report set is present",
                "id": "demo-repeatability",
                "status": "not-evidenced",
            },
            {
                "detail": "four source SDK workflows share their pinned bundle and manifest identities",
                "id": "four-sdk-source-workflows",
                "status": "passed",
            },
            {
                "detail": "release-shaped fixture protocol passed but is statistically ineligible",
                "id": "release-shaped-paired-dry-run",
                "status": "passed-ineligible",
            },
            {
                "detail": "all twelve comparator protocol bundles verified but execute recorded fixtures",
                "id": "twelve-comparator-protocol-dry-run",
                "status": "passed-ineligible",
            },
            {
                "detail": "installed native and SDK artifact evidence is absent",
                "id": "installed-artifact-mode",
                "status": "not-executed",
            },
            {
                "detail": "independent task adjudication and evaluator attestation are absent",
                "id": "independent-outcome-evaluation",
                "status": "not-executed",
            },
            {
                "detail": "installed-daemon pinned-host performance evidence is absent",
                "id": "performance-qualification",
                "status": "not-executed",
            },
        ],
        "demo_evidence": demos,
        "harness_test_evidence": {
            "status": "passed",
            "suites": suites,
            "total_tests": total_tests,
        },
        "packet": "WP20",
        "release_blocking_gaps": [
            "committed-candidate-source-binding",
            "source-demo-repeatability-receipt",
            "installed-native-and-sdk-artifact-demo",
            "thirty-independent-adjudicated-tasks-per-stratum",
            "real-baseline-and-ablation-implementations-and-runs",
            "independent-human-outcome-evaluator-attestation",
            "pinned-host-installed-daemon-performance-evidence",
            "performance-and-outcome-gates",
        ],
        "release_ready": False,
        "schema_version": SCHEMA_VERSION,
        "scope": "locally-testable-source-demos-and-benchmark-harness",
        "sdk_evidence": sdk,
        "source_binding": source,
        "status": "passed-local-scope",
        "wp20_exit_satisfied": False,
    }


def canonical_json(receipt: dict[str, Any]) -> bytes:
    return _canonical(receipt) + b"\n"


def _open_output_target(root: Path, requested_output: Path | str) -> OutputTarget:
    raw_output = os.path.expanduser(os.fspath(requested_output))
    _expect(
        all(part not in (".", "..") for part in re.split(r"[/\\]", raw_output)),
        "--out contains a navigation component",
    )
    output = Path(raw_output)
    _expect(output.is_absolute(), "--out must be an absolute path")
    _expect(
        all(part not in ("", ".", "..") for part in output.parts[1:]),
        "--out contains a navigation component",
    )
    _expect(
        output.name not in ("", ".", "..") and output.parent != output,
        "--out has no safe filename",
    )
    root_text = os.path.normcase(os.path.abspath(root))
    output_text = os.path.normcase(os.path.abspath(output))
    try:
        inside = os.path.commonpath((root_text, output_text)) == root_text
    except ValueError as error:
        raise ReadinessError("--out cannot be compared with the source root") from error
    _expect(not inside, "--out must be outside the source repository")
    root_fd = _open_absolute_directory(root)
    try:
        parent_fd = _open_absolute_directory(output.parent)
    except Exception:
        os.close(root_fd)
        raise
    try:
        _expect(
            not _directory_is_within(parent_fd, root_fd),
            "--out must be outside the source repository",
        )
        metadata = os.fstat(parent_fd)
        _expect(
            stat.S_IMODE(metadata.st_mode) == 0o700,
            "evidence directory mode must be exactly 0700",
        )
        if hasattr(os, "geteuid"):
            _expect(
                metadata.st_uid == os.geteuid(),
                "evidence directory must be owned by the current user",
            )
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ReadinessError("refusing to overwrite an existing output path")
        return OutputTarget(parent_fd, root_fd, output.name)
    except Exception:
        os.close(parent_fd)
        os.close(root_fd)
        raise


def _write_receipt(target: OutputTarget, payload: bytes) -> None:
    _expect(
        not _directory_is_within(target.parent_fd, target.root_fd),
        "evidence directory moved inside the source repository before write",
    )
    metadata = os.fstat(target.parent_fd)
    _expect(
        stat.S_IMODE(metadata.st_mode) == 0o700,
        "evidence directory mode changed before write",
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    created = False
    try:
        descriptor = os.open(target.name, flags, 0o600, dir_fd=target.parent_fd)
        created = True
        _expect(
            not _directory_is_within(target.parent_fd, target.root_fd),
            "evidence directory moved inside the source repository during write",
        )
        os.fchmod(descriptor, 0o600)
        _expect(
            stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600,
            "receipt mode is not exactly 0600",
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            _expect(written > 0, "receipt write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        _expect(
            not _directory_is_within(target.parent_fd, target.root_fd),
            "evidence directory moved inside the source repository during write",
        )
        os.close(descriptor)
        descriptor = -1
        os.fsync(target.parent_fd)
    except (OSError, ReadinessError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.unlink(target.name, dir_fd=target.parent_fd)
                os.fsync(target.parent_fd)
            except OSError:
                pass
        if isinstance(error, ReadinessError):
            raise
        raise ReadinessError(
            "unable to create the receipt without overwrite"
        ) from error


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).absolute().parents[2]
    )
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external evidence workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    return parser.parse_args(argv)


def _selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment and Path(argument) != Path(environment):
        raise ReadinessError("--evidence-dir conflicts with CIGAR_EVIDENCE_DIR")
    selected = argument if argument is not None else environment
    if selected is None or os.fspath(selected) == "":
        return None
    path = Path(selected)
    _expect(path.is_absolute(), "evidence directory must be absolute")
    return path


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    root = arguments.root.expanduser().absolute()
    root_fd = _open_absolute_directory(root)
    os.close(root_fd)
    selected = _selected_evidence_directory(arguments)
    target: OutputTarget | None = None
    workspace: EvidenceWorkspace | None = None
    try:
        if selected is None:
            target = _open_output_target(root, arguments.out)
        else:
            try:
                output = "/".join(safe_evidence_path(os.fspath(arguments.out)))
                workspace = EvidenceWorkspace.create(selected, repository_root=root)
            except EvidenceWorkspaceError as error:
                raise ReadinessError("external evidence workspace is unsafe") from error
        suites = run_harness_tests(root)
        source = git_source_binding(root)
        receipt = build_receipt(root, source, suites)
        if workspace is not None:
            try:
                workspace.write_json(output, receipt)
            except EvidenceWorkspaceError as error:
                raise ReadinessError("external evidence workspace is unsafe") from error
        else:
            assert target is not None
            _write_receipt(target, canonical_json(receipt))
    finally:
        if target is not None:
            target.close()
        if workspace is not None:
            workspace.close()
    print(
        f"WP20 local readiness passed {receipt['harness_test_evidence']['total_tests']} sanitized tests; WP20 exit satisfied=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, ReadinessError) as error:
        raise SystemExit(f"WP20 local readiness failed: {error}") from error
