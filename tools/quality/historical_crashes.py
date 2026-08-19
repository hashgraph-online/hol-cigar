#!/usr/bin/env python3
"""Verify and run every preserved historical crash as an ordinary regression.

This command never starts libFuzzer, a soak workload, or a mutation campaign. It
validates a closed-world fixture inventory and then runs only exact Nextest test
selectors under the native Apple-silicon macOS qualification profile.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import stat
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
QUALITY = Path(__file__).resolve().parent
if str(QUALITY) not in sys.path:
    sys.path.insert(0, str(QUALITY))

from bounded_process import BoundedProcessError, run_bounded  # noqa: E402


SCHEMA_VERSION = "cigar.historical-crash-regressions.v1"
RESULT_SCHEMA_VERSION = "cigar.historical-crash-regression-result.v1"
MANIFEST_PATH = ROOT / "fuzz" / "historical-crashes.v1.json"
TARGET_TRIPLE = "aarch64-apple-darwin"
MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
MAXIMUM_TREE_FILES = 25_000
MAXIMUM_TREE_DEPTH = 8
MAXIMUM_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
TEST_TIMEOUT_SECONDS = 600
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{2,95}$")
SAFE_TARGET = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
EXPECTED_CAMPAIGN_TARGET_COUNT = 19
EXPECTED_ARTIFACT_PREFIXES = (
    "crash-",
    "leak-",
    "oom-",
    "slow-unit-",
    "timeout-",
)
EXPECTED_REGRESSION_ROOTS = ("fuzz/regressions",)
EXPECTED_ARTIFACT_ROOTS = ("fuzz/artifacts",)
REQUIRED_SOURCE_BINDINGS = frozenset(
    {
        ".cargo/config.toml",
        ".config/nextest.toml",
        "Cargo.lock",
        "Cargo.toml",
        "crates/cigar-mcp/Cargo.toml",
        "crates/cigar-mcp/src/backend.rs",
        "crates/cigar-mcp/src/generated/operation_mappings.rs",
        "crates/cigar-mcp/src/json.rs",
        "crates/cigar-mcp/src/lib.rs",
        "crates/cigar-mcp/src/server.rs",
        "fuzz/artifacts/.gitkeep",
        "rust-toolchain.toml",
        "tools/quality/bounded_process.py",
        "tools/quality/historical_crashes.py",
    }
)
REQUIRED_REGRESSIONS = {
    "mcp-nonfinite-backend-number": {
        "target": "mcp_messages",
        "origin": "named-regression-fixture",
        "fixture": "fuzz/regressions/mcp_messages/backend-nonfinite-number.json",
        "selector": "test(=server::tests::exact_nonfinite_backend_number_fixture_fails_closed)",
    },
    "mcp-out-of-range-numeric-id": {
        "target": "mcp_messages",
        "origin": "minimized-libfuzzer-regression",
        "fixture": "fuzz/corpus/mcp_messages/out-of-range-numeric-id",
        "selector": "test(=server::tests::exact_out_of_range_numeric_id_corpus_fixture_fails_closed)",
    },
}
ALLOWED_ORIGINS = frozenset(
    {
        "minimized-libfuzzer-regression",
        "named-regression-fixture",
        "preserved-crash-artifact",
        "preserved-corpus-crash",
    }
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class HistoricalCrashError(RuntimeError):
    """The historical-crash inventory or deterministic regression failed."""


@dataclass(frozen=True)
class StableFile:
    path: str
    body: bytes
    sha256: str
    size: int


@dataclass(frozen=True)
class ValidatedManifest:
    path: Path
    sha256: str
    document: dict[str, Any]
    source_binding_sha256: str


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha1(value: bytes) -> str:
    # SHA-1 is retained only to identify historical libFuzzer corpus filenames.
    return hashlib.sha1(value, usedforsecurity=False).hexdigest()  # fmt: skip  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _portable_name(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise HistoricalCrashError(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HistoricalCrashError(f"{label} is not a safe relative path")
    if any(unicodedata.normalize("NFC", part) != part for part in path.parts):
        raise HistoricalCrashError(f"{label} is not NFC-normalized")
    return path.as_posix()


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_directory(path: Path, label: str) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise HistoricalCrashError(f"cannot inspect {label}: {error}") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise HistoricalCrashError(
            f"{label} must be an owner-controlled non-symlink directory"
        )


def _require_exact_child(parent: Path, name: str, label: str) -> None:
    try:
        names = os.listdir(parent)
    except OSError as error:
        raise HistoricalCrashError(f"cannot enumerate {label}: {error}") from error
    if len(names) > MAXIMUM_TREE_FILES:
        raise HistoricalCrashError(f"{label} exceeds its directory-entry bound")
    aliases = [
        observed
        for observed in names
        if _portable_name(observed) == _portable_name(name)
    ]
    if aliases != [name]:
        raise HistoricalCrashError(
            f"{label} is missing, case-aliased, or Unicode-aliased"
        )


def _walk_relative_directories(root: Path, relative: str, label: str) -> Path:
    _validate_directory(root, "repository root")
    current = root
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts[:-1]):
        _require_exact_child(current, part, f"{label} parent component {index}")
        current /= part
        _validate_directory(current, f"{label} parent component {index}")
    _require_exact_child(current, parts[-1], label)
    return root.joinpath(*parts)


def _stable_file(root: Path, relative_value: object, label: str) -> StableFile:
    relative = _relative_path(relative_value, label)
    path = _walk_relative_directories(root, relative, label)
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise HistoricalCrashError(f"cannot inspect {label}: {error}") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or not 0 < before.st_size <= MAXIMUM_FILE_BYTES
    ):
        raise HistoricalCrashError(
            f"{label} has an unsafe type, owner, mode, link count, or size"
        )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NONBLOCK,
        )
    except OSError as error:
        raise HistoricalCrashError(f"cannot open {label}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if _metadata_identity(opened) != _metadata_identity(before):
            raise HistoricalCrashError(f"{label} was substituted while it was opened")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, MAXIMUM_FILE_BYTES + 1 - observed)
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAXIMUM_FILE_BYTES:
                raise HistoricalCrashError(f"{label} exceeds its byte bound")
        body = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise HistoricalCrashError(f"cannot recheck {label}: {error}") from error
    if (
        _metadata_identity(after) != _metadata_identity(before)
        or _metadata_identity(named_after) != _metadata_identity(before)
        or len(body) != before.st_size
    ):
        raise HistoricalCrashError(f"{label} changed while it was read")
    return StableFile(
        path=relative,
        body=body,
        sha256=_sha256(body),
        size=len(body),
    )


def _require_exact_keys(
    value: object, expected: set[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise HistoricalCrashError(f"{label} has an unexpected shape")
    return value


def _binding(root: Path, value: object, label: str) -> StableFile:
    binding = _require_exact_keys(value, {"path", "sha256", "size"}, label)
    file = _stable_file(root, binding["path"], label)
    if (
        binding.get("path") != file.path
        or binding.get("sha256") != file.sha256
        or isinstance(binding.get("size"), bool)
        or binding.get("size") != file.size
    ):
        raise HistoricalCrashError(f"{label} is stale or was tampered with")
    return file


def _decode_json(file: StableFile, label: str) -> dict[str, Any]:
    try:
        document = json.loads(file.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HistoricalCrashError(
            f"{label} is not strict UTF-8 JSON: {error}"
        ) from error
    if not isinstance(document, dict):
        raise HistoricalCrashError(f"{label} must contain a JSON object")
    return document


def _scan_tree(root: Path, relative_root: str, label: str) -> list[str]:
    relative_root = _relative_path(relative_root, label)
    directory = root
    for index, part in enumerate(PurePosixPath(relative_root).parts):
        _require_exact_child(directory, part, f"{label} root component {index}")
        directory /= part
        _validate_directory(directory, f"{label} root component {index}")
    _validate_directory(directory, label)
    results: list[str] = []

    def visit(current: Path, relative: PurePosixPath, depth: int) -> None:
        if depth > MAXIMUM_TREE_DEPTH:
            raise HistoricalCrashError(f"{label} exceeds its directory-depth bound")
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            raise HistoricalCrashError(f"cannot enumerate {label}: {error}") from error
        aliases: dict[str, str] = {}
        for entry in entries:
            portable = _portable_name(entry.name)
            prior = aliases.setdefault(portable, entry.name)
            if prior != entry.name:
                raise HistoricalCrashError(f"{label} contains case or Unicode aliases")
        for entry in sorted(entries, key=lambda candidate: candidate.name):
            child_relative = relative / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise HistoricalCrashError(
                    f"cannot inspect {child_relative.as_posix()}: {error}"
                ) from error
            if entry.is_symlink():
                raise HistoricalCrashError(
                    f"{child_relative.as_posix()} is an unsafe symlink"
                )
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                    raise HistoricalCrashError(
                        f"{child_relative.as_posix()} is an unsafe directory"
                    )
                visit(Path(entry.path), child_relative, depth + 1)
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o022
                or not 0 < metadata.st_size <= MAXIMUM_FILE_BYTES
            ):
                raise HistoricalCrashError(
                    f"{child_relative.as_posix()} is an unsafe fixture"
                )
            results.append(child_relative.as_posix())
            if len(results) > MAXIMUM_TREE_FILES:
                raise HistoricalCrashError(f"{label} exceeds its file-count bound")

    visit(directory, PurePosixPath(relative_root), 0)
    return results


def _expected_command(selector: str) -> list[str]:
    return [
        "cargo",
        "nextest",
        "run",
        "--locked",
        "--offline",
        "--config-file",
        ".config/nextest.toml",
        "--user-config-file",
        "none",
        "-P",
        "macos-qualification",
        "--no-tests",
        "fail",
        "-p",
        "cigar-mcp",
        "--lib",
        "-E",
        selector,
    ]


def _corpus_inventory(
    root: Path,
    campaign: Mapping[str, Any],
    policy: Mapping[str, Any],
    regression_roots: Sequence[str],
    artifact_roots: Sequence[str],
) -> dict[str, tuple[str, str]]:
    targets = campaign.get("targets")
    if (
        campaign.get("schema_version") != "cigar.fuzz-campaign.v1"
        or not isinstance(targets, list)
        or len(targets) != EXPECTED_CAMPAIGN_TARGET_COUNT
        or len(set(targets)) != EXPECTED_CAMPAIGN_TARGET_COUNT
        or any(
            not isinstance(target, str) or SAFE_TARGET.fullmatch(target) is None
            for target in targets
        )
    ):
        raise HistoricalCrashError("fuzz campaign target inventory is malformed")
    policy_targets = policy.get("targets")
    if (
        policy.get("schema_version") != "cigar.fuzz-corpus-policy.v1"
        or policy.get("artifact_prefixes") != list(EXPECTED_ARTIFACT_PREFIXES)
        or not isinstance(policy_targets, dict)
        or set(policy_targets) != set(targets)
    ):
        raise HistoricalCrashError("fuzz corpus policy is malformed or incomplete")

    discovered: dict[str, tuple[str, str]] = {}
    named_paths: set[str] = set()
    for target in targets:
        target_policy = _require_exact_keys(
            policy_targets[target], {"named_fixtures"}, f"corpus policy target {target}"
        )
        fixtures = target_policy.get("named_fixtures")
        if not isinstance(fixtures, list) or not fixtures:
            raise HistoricalCrashError(
                f"corpus policy target {target} has no named fixtures"
            )
        names: set[str] = set()
        for index, fixture in enumerate(fixtures):
            fixture = _require_exact_keys(
                fixture,
                {"classification", "name", "sha1", "sha256"},
                f"corpus policy fixture {target}[{index}]",
            )
            name = fixture.get("name")
            classification = fixture.get("classification")
            if (
                not isinstance(name, str)
                or not name
                or "/" in name
                or "\\" in name
                or name in names
                or classification not in {"hand-authored-seed", "minimized-regression"}
                or HEX_40.fullmatch(str(fixture.get("sha1"))) is None
                or HEX_64.fullmatch(str(fixture.get("sha256"))) is None
            ):
                raise HistoricalCrashError(
                    f"corpus policy fixture {target}[{index}] is malformed"
                )
            names.add(name)
            path = f"fuzz/corpus/{target}/{name}"
            named_paths.add(path)
            if classification == "minimized-regression":
                discovered[path] = ("minimized-libfuzzer-regression", target)

    for regression_root in regression_roots:
        for path in _scan_tree(root, regression_root, "named regression fixtures"):
            parts = PurePosixPath(path).parts
            if len(parts) < 4 or parts[2] not in policy_targets:
                raise HistoricalCrashError(
                    f"named regression fixture has no fuzz target mapping: {path}"
                )
            discovered[path] = ("named-regression-fixture", parts[2])

    for artifact_root in artifact_roots:
        for path in _scan_tree(root, artifact_root, "preserved crash artifacts"):
            if path == f"{artifact_root}/.gitkeep":
                continue
            parts = PurePosixPath(path).parts
            if len(parts) < 4 or parts[2] not in policy_targets:
                raise HistoricalCrashError(
                    f"preserved crash artifact has no fuzz target mapping: {path}"
                )
            discovered[path] = ("preserved-crash-artifact", parts[2])

    for path in _scan_tree(root, "fuzz/corpus", "checked-in fuzz corpus"):
        name = PurePosixPath(path).name
        looks_like_fault = name.casefold().find("regression") >= 0 or any(
            name.startswith(prefix) for prefix in EXPECTED_ARTIFACT_PREFIXES
        )
        if looks_like_fault and path not in named_paths:
            target = PurePosixPath(path).parts[2]
            discovered[path] = ("preserved-corpus-crash", target)
    return discovered


def validate_manifest(
    *, root: Path = ROOT, manifest_path: Path = MANIFEST_PATH
) -> ValidatedManifest:
    try:
        relative_manifest = manifest_path.relative_to(root).as_posix()
    except ValueError as error:
        raise HistoricalCrashError(
            "historical-crash manifest must be inside the repository"
        ) from error
    manifest_file = _stable_file(root, relative_manifest, "historical-crash manifest")
    document = _decode_json(manifest_file, "historical-crash manifest")
    if _canonical_json(document) != manifest_file.body:
        raise HistoricalCrashError("historical-crash manifest is not canonical JSON")
    document = dict(
        _require_exact_keys(
            document,
            {
                "schema_version",
                "supported_target",
                "campaign",
                "corpus_policy",
                "regression_fixture_roots",
                "artifact_roots",
                "source_bindings",
                "regressions",
            },
            "historical-crash manifest",
        )
    )
    if document.get("schema_version") != SCHEMA_VERSION:
        raise HistoricalCrashError("historical-crash manifest schema is unsupported")
    if document.get("supported_target") != TARGET_TRIPLE:
        raise HistoricalCrashError("historical-crash manifest target was weakened")

    campaign_file = _binding(root, document.get("campaign"), "fuzz campaign binding")
    policy_file = _binding(root, document.get("corpus_policy"), "corpus policy binding")
    campaign = _decode_json(campaign_file, "fuzz campaign")
    policy = _decode_json(policy_file, "fuzz corpus policy")

    regression_roots = document.get("regression_fixture_roots")
    artifact_roots = document.get("artifact_roots")
    if regression_roots != list(EXPECTED_REGRESSION_ROOTS):
        raise HistoricalCrashError("named regression fixture roots were weakened")
    if artifact_roots != list(EXPECTED_ARTIFACT_ROOTS):
        raise HistoricalCrashError("crash artifact roots were weakened")
    discovered = _corpus_inventory(
        root, campaign, policy, regression_roots, artifact_roots
    )

    source_bindings = document.get("source_bindings")
    if not isinstance(source_bindings, list) or not source_bindings:
        raise HistoricalCrashError("source bindings must be a non-empty array")
    bound_sources: dict[str, dict[str, Any]] = {}
    for index, raw_binding in enumerate(source_bindings):
        binding_file = _binding(root, raw_binding, f"source binding {index}")
        if binding_file.path in bound_sources:
            raise HistoricalCrashError("source bindings contain a duplicate path")
        bound_sources[binding_file.path] = {
            "path": binding_file.path,
            "sha256": binding_file.sha256,
            "size": binding_file.size,
        }
    if set(bound_sources) != REQUIRED_SOURCE_BINDINGS:
        raise HistoricalCrashError(
            "source binding inventory is missing or has extra files"
        )

    regressions = document.get("regressions")
    if not isinstance(regressions, list) or not regressions:
        raise HistoricalCrashError("historical regressions must be a non-empty array")
    identifiers: set[str] = set()
    fixture_paths: set[str] = set()
    selectors: set[str] = set()
    commands: set[bytes] = set()
    manifest_inventory: dict[str, tuple[str, str]] = {}
    for index, raw_regression in enumerate(regressions):
        regression = _require_exact_keys(
            raw_regression,
            {
                "id",
                "target",
                "origin",
                "fixture",
                "test_source",
                "test_selector",
                "test_command",
            },
            f"regression {index}",
        )
        identifier = regression.get("id")
        target = regression.get("target")
        origin = regression.get("origin")
        selector = regression.get("test_selector")
        if (
            not isinstance(identifier, str)
            or SAFE_ID.fullmatch(identifier) is None
            or identifier in identifiers
            or not isinstance(target, str)
            or SAFE_TARGET.fullmatch(target) is None
            or origin not in ALLOWED_ORIGINS
            or not isinstance(selector, str)
            or selector in selectors
        ):
            raise HistoricalCrashError(
                f"regression {index} identity is invalid or duplicated"
            )
        identifiers.add(identifier)
        selectors.add(selector)
        test_source = _relative_path(
            regression.get("test_source"), f"regression {index} test source"
        )
        if test_source not in bound_sources:
            raise HistoricalCrashError(
                f"regression {index} test source is not source-bound"
            )
        command = regression.get("test_command")
        if command != _expected_command(selector):
            raise HistoricalCrashError(
                f"regression {index} command or exact selector was weakened"
            )
        command_encoding = _canonical_json(command)
        if command_encoding in commands:
            raise HistoricalCrashError(
                "historical regressions contain a duplicate command"
            )
        commands.add(command_encoding)

        fixture = _require_exact_keys(
            regression.get("fixture"),
            {"path", "encoding", "bytes", "size", "sha1", "sha256"},
            f"regression {index} fixture",
        )
        fixture_file = _stable_file(
            root, fixture.get("path"), f"regression {index} fixture"
        )
        if fixture_file.path in fixture_paths:
            raise HistoricalCrashError(
                "historical regressions contain a duplicate fixture"
            )
        fixture_paths.add(fixture_file.path)
        if fixture.get("encoding") != "base64" or not isinstance(
            fixture.get("bytes"), str
        ):
            raise HistoricalCrashError(
                f"regression {index} fixture encoding is invalid"
            )
        try:
            immutable_bytes = base64.b64decode(fixture["bytes"], validate=True)
        except (ValueError, TypeError) as error:
            raise HistoricalCrashError(
                f"regression {index} fixture bytes are invalid"
            ) from error
        if (
            immutable_bytes != fixture_file.body
            or isinstance(fixture.get("size"), bool)
            or fixture.get("size") != fixture_file.size
            or fixture.get("sha1") != _sha1(fixture_file.body)
            or fixture.get("sha256") != fixture_file.sha256
        ):
            raise HistoricalCrashError(
                f"regression {index} immutable fixture bytes were tampered with"
            )
        expected_discovery = discovered.get(fixture_file.path)
        if expected_discovery != (origin, target):
            raise HistoricalCrashError(
                f"regression {index} is not mapped to its discovered origin and target"
            )
        manifest_inventory[fixture_file.path] = (str(origin), target)

        if origin == "minimized-libfuzzer-regression":
            policy_fixture = next(
                (
                    item
                    for item in policy["targets"][target]["named_fixtures"]
                    if item["name"] == PurePosixPath(fixture_file.path).name
                ),
                None,
            )
            if (
                policy_fixture is None
                or policy_fixture.get("classification") != "minimized-regression"
                or policy_fixture.get("sha1") != fixture.get("sha1")
                or policy_fixture.get("sha256") != fixture.get("sha256")
            ):
                raise HistoricalCrashError(
                    f"regression {index} disagrees with corpus policy"
                )

    if manifest_inventory != discovered:
        missing = sorted(set(discovered) - set(manifest_inventory))
        extra = sorted(set(manifest_inventory) - set(discovered))
        raise HistoricalCrashError(
            f"historical fixture inventory is not closed; unmapped={missing}, extra={extra}"
        )
    by_identifier = {entry["id"]: entry for entry in regressions}
    if not REQUIRED_REGRESSIONS.keys() <= by_identifier.keys():
        raise HistoricalCrashError("required MCP historical regressions are missing")
    for identifier, expected in REQUIRED_REGRESSIONS.items():
        entry = by_identifier[identifier]
        if (
            entry.get("target") != expected["target"]
            or entry.get("origin") != expected["origin"]
            or entry.get("fixture", {}).get("path") != expected["fixture"]
            or entry.get("test_selector") != expected["selector"]
            or entry.get("test_source") != "crates/cigar-mcp/src/server.rs"
        ):
            raise HistoricalCrashError(f"required regression {identifier} was remapped")

    source_binding_sha256 = _sha256(
        _canonical_json([bound_sources[path] for path in sorted(bound_sources)])
    )
    return ValidatedManifest(
        path=manifest_path,
        sha256=manifest_file.sha256,
        document=document,
        source_binding_sha256=source_binding_sha256,
    )


def _native_macos() -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise HistoricalCrashError(
            "historical crash execution requires native Apple-silicon macOS"
        )


def _test_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "TMPDIR",
            "SDKROOT",
            "DEVELOPER_DIR",
        )
        if key in os.environ
    }
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "CARGO_INCREMENTAL": "0",
            "CARGO_TERM_COLOR": "never",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NEXTEST_HIDE_PROGRESS_BAR": "1",
            "NO_COLOR": "1",
            "RUST_BACKTRACE": "0",
            "TZ": "UTC",
        }
    )
    return environment


def run_regressions(
    *, root: Path = ROOT, manifest_path: Path = MANIFEST_PATH
) -> dict[str, Any]:
    _native_macos()
    before = validate_manifest(root=root, manifest_path=manifest_path)
    results: list[dict[str, Any]] = []
    environment = _test_environment()
    with tempfile.TemporaryDirectory(prefix="cigar-historical-crashes-") as raw:
        scratch = Path(raw)
        # Historical-crash replay inputs can contain unpublished minimized bytes.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            scratch, 0o700
        )
        for index, regression in enumerate(before.document["regressions"]):
            identifier = regression["id"]
            command = regression["test_command"]
            result = run_bounded(
                command,
                cwd=root,
                env=environment,
                log_path=scratch / f"{index:03d}-{identifier}.log",
                timeout_seconds=TEST_TIMEOUT_SECONDS,
                maximum_output_bytes=MAXIMUM_PROCESS_OUTPUT_BYTES,
            )
            current = validate_manifest(root=root, manifest_path=manifest_path)
            if (
                current.sha256 != before.sha256
                or current.source_binding_sha256 != before.source_binding_sha256
            ):
                raise HistoricalCrashError(
                    f"historical regression {identifier} changed bound source or fixtures"
                )
            if (
                result["exit_code"] != 0
                or result["timed_out"] is not False
                or result["output_overflow"] is not False
                or result["descendant_cleanup_required"] is not False
            ):
                raise HistoricalCrashError(
                    f"historical regression {identifier} failed; output remained private"
                )
            results.append(
                {
                    "id": identifier,
                    "target": regression["target"],
                    "fixture_sha256": regression["fixture"]["sha256"],
                    "test_selector": regression["test_selector"],
                    "command_sha256": _sha256(_canonical_json(command)),
                    "exit_code": 0,
                    "captured_output_bytes": result["captured_output_bytes"],
                    "captured_output_sha256": result["log_sha256"],
                }
            )
    after = validate_manifest(root=root, manifest_path=manifest_path)
    if (
        after.sha256 != before.sha256
        or after.source_binding_sha256 != before.source_binding_sha256
    ):
        raise HistoricalCrashError(
            "historical crash source or manifest changed during execution"
        )
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "passed",
        "release_eligible": False,
        "supported_target": TARGET_TRIPLE,
        "manifest": {
            "path": manifest_path.relative_to(root).as_posix(),
            "sha256": before.sha256,
        },
        "source_binding_sha256": before.source_binding_sha256,
        "regression_count": len(results),
        "results": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "run"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.action == "verify":
        manifest = validate_manifest()
        document = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "status": "verified",
            "release_eligible": False,
            "supported_target": TARGET_TRIPLE,
            "manifest": {
                "path": manifest.path.relative_to(ROOT).as_posix(),
                "sha256": manifest.sha256,
            },
            "source_binding_sha256": manifest.source_binding_sha256,
            "regression_count": len(manifest.document["regressions"]),
        }
    else:
        document = run_regressions()
    print(_canonical_json(document).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BoundedProcessError, HistoricalCrashError, OSError, ValueError) as error:
        print(f"historical crash regression failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
