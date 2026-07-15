#!/usr/bin/env python3
"""Fail-closed native-macOS preflight for the CIGAR local-scale gate.

The local repository uses the v4 normalized authoritative atom/edge catalog and
an explicit immutable ``large_local`` capacity profile. This tool binds that
architecture and its hard quotas to the exact CBOR sizes of valid deterministic
atom and edge fixtures. It also verifies that the host meets the 300-GiB
activation precondition before a separate physical qualification is attempted.

It publishes a source-bound, create-new receipt in an external owner-private
evidence directory.  A blocked receipt is evidence of a release blocker, never
evidence that the scale target passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Never

REPOSITORY = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = REPOSITORY / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path,
)

SCHEMA_VERSION = "cigar.local-scale-preflight.v1"
PROBE_SCHEMA_VERSION = "cigar.local-scale-record-probe.v1"
TARGET_ATOMS = 1_000_000
TARGET_EDGES = 10_000_000
TARGET_REFERENCED_BLOB_BYTES = 100 * 1024**3
EXPECTED_STANDARD_DATABASE_CAP_BYTES = 4_294_967_296
EXPECTED_LARGE_LOCAL_DATABASE_CAP_BYTES = 68_719_476_736
EXPECTED_LARGE_LOCAL_INITIAL_FREE_BYTES = 322_122_547_200
EXPECTED_LARGE_LOCAL_RUNTIME_RESERVE_BYTES = 17_179_869_184
EXPECTED_LARGE_LOCAL_MAX_ATOMS = 1_250_000
EXPECTED_LARGE_LOCAL_MAX_EDGES = 12_500_000
EXPECTED_LARGE_LOCAL_MAX_REFERENCED_BLOB_BYTES = 137_438_953_472
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_PROBE_OUTPUT_BYTES = 4 * 1024
MAX_TOOL_OUTPUT_BYTES = 64 * 1024
PROBE_TIMEOUT_SECONDS = 900
MULTIHASH = re.compile(r"^1220[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")

TOP_LEVEL_KEYS = {
    "schema_version",
    "result",
    "release_scale_qualified",
    "started_at_unix_nanos",
    "finished_at_unix_nanos",
    "platform_scope",
    "targets",
    "observed",
    "blockers",
    "architecture",
    "capacity_model",
    "source",
    "environment",
    "checks",
    "claims",
    "required_remediation",
    "receipt_id",
}

REQUIRED_REMEDIATION = [
    "provision a native Apple-silicon macOS volume with at least 300 GiB available before large_local activation",
    "run this gate against the installed macOS artifact at 1M atoms, 10M edges, and at least 100GB referenced blobs",
    "verify catalog roots, exact replay, quota enforcement, backup, and restore after the physical scale run",
]

EXPLICIT_SOURCE_INPUTS = (
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "benches/cigarbench/local_scale.py",
    "benches/cigarbench/profiles/large-local-v1.json",
    "benches/cigarbench/performance.py",
    "benches/cigarbench/schemas/local-scale-binding-v1.schema.json",
    "benches/cigarbench/schemas/local-scale-preflight-v1.schema.json",
    "benches/cigarbench/schemas/local-scale-result-v1.schema.json",
    "benches/cigarbench/tests/test_local_scale.py",
    "benches/cigarbench/local_scale_driver/Cargo.lock",
    "benches/cigarbench/local_scale_driver/Cargo.toml",
    "benches/cigarbench/local_scale_driver/src/main.rs",
    "benches/cigarbench/local_scale_probe/Cargo.lock",
    "benches/cigarbench/local_scale_probe/Cargo.toml",
    "benches/cigarbench/local_scale_probe/src/main.rs",
    "crates/cigar-aws-creds/Cargo.toml",
    "crates/cigar-canon/Cargo.toml",
    "crates/cigar-protocol/Cargo.toml",
    "crates/cigar-crypto/Cargo.toml",
    "crates/cigar-rust-s3/Cargo.toml",
    "crates/cigar-store/Cargo.toml",
    "crates/cigar-store/migrations/sqlite/0001_initial.sql",
    "crates/cigar-store/migrations/sqlite/0002_compatibility_ledger.sql",
    "crates/cigar-store/migrations/sqlite/0003_generation_bound_atom_projection.sql",
    "crates/cigar-store/migrations/sqlite/0004_normalized_authoritative_catalog.sql",
    "crates/cigar-store/src/lib.rs",
    "crates/cigar-store/src/backup.rs",
    "crates/cigar-store/src/blob.rs",
    "crates/cigar-store/src/model.rs",
    "crates/cigar-store/src/sqlite.rs",
    "crates/cigar-daemon/src/config.rs",
    "crates/cigar-daemon/src/production_bootstrap.rs",
    "crates/cigar-cli/src/administration.rs",
    "crates/cigar-testkit/Cargo.toml",
    "migrations/authority-v1.json",
    "migrations/sqlite/0001_initial.sql",
    "migrations/sqlite/0002_compatibility_ledger.sql",
    "migrations/sqlite/0003_generation_bound_atom_projection.sql",
    "migrations/sqlite/0004_normalized_authoritative_catalog.sql",
    "scripts/configuration/validate_configuration_authority.py",
    "scripts/release/evidence_workspace.py",
    "spec/configuration/authority-v1.json",
)
SOURCE_TREES = (
    "crates/cigar-aws-creds/src",
    "crates/cigar-canon/src",
    "crates/cigar-crypto/src",
    "crates/cigar-protocol/src",
    "crates/cigar-rust-s3/src",
    "crates/cigar-store/migrations",
    "crates/cigar-store/src",
    "crates/cigar-testkit/src",
)


class LocalScaleError(RuntimeError):
    """One local-scale preflight invariant was not satisfied."""


def fail(message: str) -> Never:
    raise LocalScaleError(message)


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise LocalScaleError("value is not canonical JSON") from error


def multihash_bytes(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def receipt_with_id(body: dict[str, Any]) -> dict[str, Any]:
    if "receipt_id" in body:
        fail("receipt body unexpectedly contains an identity")
    return {**body, "receipt_id": multihash_bytes(canonical_bytes(body))}


def _bounded_regular(path: Path) -> bytes:
    try:
        pathname = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise LocalScaleError("source input is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(pathname.st_mode)
            or not stat.S_ISREG(pathname.st_mode)
            or (pathname.st_dev, pathname.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size < 0
            or opened.st_size > MAX_SOURCE_FILE_BYTES
        ):
            fail("source input is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            payload = stream.read(MAX_SOURCE_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(payload) > MAX_SOURCE_FILE_BYTES:
            fail("source input exceeds its byte bound")
        rebound = path.lstat()
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(opened, field) != getattr(after, field)
            or getattr(opened, field) != getattr(rebound, field)
            for field in stable
        ):
            fail("source input changed while it was read")
        return payload
    except OSError as error:
        raise LocalScaleError("source input could not be read") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def source_paths() -> list[Path]:
    relative_paths = set(EXPLICIT_SOURCE_INPUTS)
    for relative_root in SOURCE_TREES:
        root = REPOSITORY / relative_root
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                relative_paths.add(path.relative_to(REPOSITORY).as_posix())
    paths = [REPOSITORY / relative for relative in sorted(relative_paths)]
    if any(not path.is_file() for path in paths):
        fail("one required source-bound input is absent")
    return paths


def source_file_snapshot() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    digest.update(b"cigar.local-scale-source.v1\0")
    for path in source_paths():
        payload = _bounded_regular(path)
        relative = path.relative_to(REPOSITORY).as_posix()
        sha256 = hashlib.sha256(payload).hexdigest()
        entry = {"path": relative, "sha256": sha256, "bytes": len(payload)}
        entries.append(entry)
        encoded = canonical_bytes(entry)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return {
        "algorithm": "sha256-length-prefixed-canonical-file-inventory-v1",
        "digest": "1220" + digest.hexdigest(),
        "files": entries,
    }


def _run_git(arguments: Sequence[str], maximum: int) -> bytes:
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
    }
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=REPOSITORY,
            env=environment,
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalScaleError("Git source-state capture failed") from error
    if len(result.stdout) > maximum or len(result.stderr) > MAX_TOOL_OUTPUT_BYTES:
        fail("Git source-state output exceeded its bound")
    return result.stdout


def git_state() -> dict[str, Any]:
    commit_bytes = _run_git(("rev-parse", "--verify", "HEAD"), 128).strip()
    if not re.fullmatch(rb"[0-9a-f]{40,64}", commit_bytes):
        fail("Git commit identity is malformed")
    status = _run_git(
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        16 * 1024 * 1024,
    )
    entries = 0 if not status else status.count(b"\0")
    return {
        "commit": commit_bytes.decode("ascii"),
        "clean": not status,
        "status_entry_count": entries,
        "status_sha256": hashlib.sha256(status).hexdigest(),
    }


def _source_text(relative: str) -> str:
    payload = _bounded_regular(REPOSITORY / relative)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LocalScaleError("source invariant input is not UTF-8") from error


def _rust_u64_constant(source: str, name: str) -> int:
    match = re.search(
        rf"pub const {re.escape(name)}: u64 = ([0-9_]+);",
        source,
    )
    if match is None:
        fail("SQLite capacity constant is absent")
    return int(match.group(1).replace("_", ""))


def architecture_evidence() -> dict[str, Any]:
    sqlite_source = _source_text("crates/cigar-store/src/sqlite.rs")
    daemon_config = _source_text("crates/cigar-daemon/src/config.rs")
    daemon_bootstrap = _source_text("crates/cigar-daemon/src/production_bootstrap.rs")
    cli_administration = _source_text("crates/cigar-cli/src/administration.rs")
    configuration_authority = _source_text("spec/configuration/authority-v1.json")
    normalized_migration = _source_text(
        "migrations/sqlite/0004_normalized_authoritative_catalog.sql"
    )
    for migration in (
        "0001_initial.sql",
        "0002_compatibility_ledger.sql",
        "0003_generation_bound_atom_projection.sql",
        "0004_normalized_authoritative_catalog.sql",
    ):
        if _source_text(f"migrations/sqlite/{migration}") != _source_text(
            f"crates/cigar-store/migrations/sqlite/{migration}"
        ):
            fail("SQLite migration mirrors differ")

    constants = {
        "standard_maximum_database_bytes": _rust_u64_constant(
            sqlite_source, "MAX_SQLITE_DATABASE_BYTES"
        ),
        "large_local_maximum_database_bytes": _rust_u64_constant(
            sqlite_source, "MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES"
        ),
        "large_local_minimum_initial_free_bytes": _rust_u64_constant(
            sqlite_source, "MIN_LARGE_LOCAL_AVAILABLE_BYTES"
        ),
        "large_local_minimum_runtime_reserve_bytes": _rust_u64_constant(
            sqlite_source, "MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES"
        ),
        "large_local_maximum_atoms": _rust_u64_constant(
            sqlite_source, "MAX_LARGE_LOCAL_ATOMS"
        ),
        "large_local_maximum_edges": _rust_u64_constant(
            sqlite_source, "MAX_LARGE_LOCAL_EDGES"
        ),
        "large_local_maximum_referenced_blob_bytes": _rust_u64_constant(
            sqlite_source, "MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES"
        ),
    }
    expected_constants = {
        "standard_maximum_database_bytes": EXPECTED_STANDARD_DATABASE_CAP_BYTES,
        "large_local_maximum_database_bytes": EXPECTED_LARGE_LOCAL_DATABASE_CAP_BYTES,
        "large_local_minimum_initial_free_bytes": EXPECTED_LARGE_LOCAL_INITIAL_FREE_BYTES,
        "large_local_minimum_runtime_reserve_bytes": EXPECTED_LARGE_LOCAL_RUNTIME_RESERVE_BYTES,
        "large_local_maximum_atoms": EXPECTED_LARGE_LOCAL_MAX_ATOMS,
        "large_local_maximum_edges": EXPECTED_LARGE_LOCAL_MAX_EDGES,
        "large_local_maximum_referenced_blob_bytes": (
            EXPECTED_LARGE_LOCAL_MAX_REFERENCED_BLOB_BYTES
        ),
    }
    if constants != expected_constants:
        fail("SQLite capacity profile changed without a preflight version change")

    required_sqlite_fragments = (
        "struct CatalogFreeStateV4",
        "INSERT OR IGNORE INTO cigar_catalog_atoms",
        "INSERT OR IGNORE INTO cigar_catalog_edges",
        "FROM cigar_catalog_atoms WHERE published_revision <= ?1",
        "FROM cigar_catalog_edges",
        "activate_normalized_catalog(&mut connection, capacity_profile)?;",
        "enforce_catalog_capacity(&metadata, capacity_profile)?;",
        "catalog_root_from_bucket_states",
    )
    required_schema_fragments = (
        "CREATE TABLE IF NOT EXISTS cigar_catalog_authority",
        "format_version INTEGER NOT NULL CHECK (format_version = 4)",
        "CREATE TABLE IF NOT EXISTS cigar_repository_revisions_v4",
        "CREATE TABLE IF NOT EXISTS cigar_catalog_atoms",
        "CREATE TABLE IF NOT EXISTS cigar_catalog_edges",
        "CREATE TABLE IF NOT EXISTS cigar_catalog_lineage_heads",
        "CREATE TABLE IF NOT EXISTS cigar_catalog_root_buckets",
        "root_bucket INTEGER NOT NULL CHECK (root_bucket BETWEEN 0 AND 65535)",
    )
    if any(fragment not in sqlite_source for fragment in required_sqlite_fragments):
        fail("SQLite normalized persistence invariant changed")
    if any(
        fragment not in normalized_migration for fragment in required_schema_fragments
    ):
        fail("SQLite normalized migration shape changed")
    if (
        "pub local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile"
        not in daemon_config
        or "SqliteCapacityProfile::LargeLocal" not in daemon_config
        or "open_with_blob_repository_and_capacity_profile" not in daemon_bootstrap
        or "config.local_sqlite_capacity_profile" not in daemon_bootstrap
        or "open_with_capacity_profile" not in cli_administration
        or "configuration.local_sqlite_capacity_profile" not in cli_administration
        or '"id": "daemon.local_sqlite_capacity_profile"' not in configuration_authority
    ):
        fail("large-local configuration authority is not wired end to end")

    normalized_atom_inserts = sqlite_source.count(
        "INSERT OR IGNORE INTO cigar_catalog_atoms"
    )
    normalized_edge_inserts = sqlite_source.count(
        "INSERT OR IGNORE INTO cigar_catalog_edges"
    )
    if normalized_atom_inserts != 1 or normalized_edge_inserts != 1:
        fail("normalized catalog write path changed without a preflight version change")

    return {
        **constants,
        "catalog_schema_version": 4,
        "authoritative_state_encoding": "sqlite-v4-normalized-catalog-plus-cbor-residual",
        "commit_rewrites_complete_catalog": False,
        "read_decodes_complete_catalog": False,
        "normalized_catalog_tables_are_authoritative": True,
        "legacy_sql_catalog_tables_are_authoritative": False,
        "normalized_atom_insert_occurrences": normalized_atom_inserts,
        "normalized_edge_insert_occurrences": normalized_edge_inserts,
        "integrity_bucket_count": 65_536,
        "capacity_profile_binding": "immutable-sqlite-authority-singleton",
        "atom_projection_kind": "disposable-generation-bound-sql-and-fts",
    }


def _probe_environment(target_directory: Path) -> dict[str, str]:
    environment: dict[str, str] = {
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": os.fspath(target_directory),
        "HOME": os.environ.get("HOME", ""),
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        "RUST_BACKTRACE": "0",
    }
    for key in ("CARGO_HOME", "RUSTUP_HOME"):
        if value := os.environ.get(key):
            environment[key] = value
    return environment


def run_record_probe() -> dict[str, int | str]:
    cargo = shutil.which("cargo")
    if cargo is None:
        fail("the pinned Rust fixture probe requires cargo")
    manifest = REPOSITORY / "benches/cigarbench/local_scale_probe/Cargo.toml"
    with tempfile.TemporaryDirectory(prefix="cigar-local-scale-probe-") as temporary:
        target = Path(temporary) / "target"
        try:
            result = subprocess.run(
                [
                    cargo,
                    "run",
                    "--locked",
                    "--offline",
                    "--quiet",
                    "--manifest-path",
                    os.fspath(manifest),
                ],
                cwd=REPOSITORY,
                env=_probe_environment(target),
                check=True,
                capture_output=True,
                timeout=PROBE_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LocalScaleError("the exact Rust fixture-size probe failed") from error
    if (
        len(result.stdout) > MAX_PROBE_OUTPUT_BYTES
        or len(result.stderr) > MAX_TOOL_OUTPUT_BYTES
    ):
        fail("the exact Rust fixture-size probe exceeded its output bound")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalScaleError(
            "the Rust fixture-size probe returned invalid JSON"
        ) from error
    expected_keys = {
        "schema_version",
        "atom_cbor_bytes",
        "edge_cbor_bytes",
        "uuid_cbor_text_bytes",
        "version_cbor_text_bytes",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        fail("the Rust fixture-size probe schema is invalid")
    if value["schema_version"] != PROBE_SCHEMA_VERSION:
        fail("the Rust fixture-size probe version is unsupported")
    for key in expected_keys - {"schema_version"}:
        if isinstance(value[key], bool) or not isinstance(value[key], int):
            fail("the Rust fixture-size probe returned a non-integer size")
        if value[key] <= 0 or value[key] > 16 * 1024 * 1024:
            fail("the Rust fixture-size probe returned an unbounded size")
    return value


def capacity_model(
    architecture: dict[str, Any], probe: dict[str, int | str]
) -> dict[str, Any]:
    expected_probe_keys = {
        "schema_version",
        "atom_cbor_bytes",
        "edge_cbor_bytes",
        "uuid_cbor_text_bytes",
        "version_cbor_text_bytes",
    }
    if (
        set(probe) != expected_probe_keys
        or probe.get("schema_version") != PROBE_SCHEMA_VERSION
    ):
        fail("capacity model record probe is invalid")
    for key in expected_probe_keys - {"schema_version"}:
        value = probe[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > 16 * 1024 * 1024
        ):
            fail("capacity model record size is invalid")
    capacity_value = architecture.get("large_local_maximum_database_bytes")
    if (
        isinstance(capacity_value, bool)
        or not isinstance(capacity_value, int)
        or capacity_value <= 0
        or capacity_value > (1 << 63) - 1
    ):
        fail("capacity model database bound is invalid")
    atom_record = int(probe["atom_cbor_bytes"])
    edge_record = int(probe["edge_cbor_bytes"])
    modeled_atoms = atom_record * TARGET_ATOMS
    modeled_edges = edge_record * TARGET_EDGES
    modeled_catalog = modeled_atoms + modeled_edges
    capacity = capacity_value
    target_within_quotas = (
        architecture.get("large_local_maximum_atoms", -1) >= TARGET_ATOMS
        and architecture.get("large_local_maximum_edges", -1) >= TARGET_EDGES
        and architecture.get("large_local_maximum_referenced_blob_bytes", -1)
        >= TARGET_REFERENCED_BLOB_BYTES
    )
    return {
        "model_kind": "normalized-v4-record-cbor-payload-lower-bound",
        "record_probe": probe,
        "per_atom_record_bytes": atom_record,
        "per_edge_record_bytes": edge_record,
        "modeled_atom_record_bytes": modeled_atoms,
        "modeled_edge_record_bytes": modeled_edges,
        "modeled_catalog_record_bytes": modeled_catalog,
        "large_local_database_capacity_bytes": capacity,
        "capacity_headroom_before_excluded_overhead_bytes": max(
            0, capacity - modeled_catalog
        ),
        "capacity_fraction_before_excluded_overhead": modeled_catalog / capacity,
        "record_payload_lower_bound_fits": modeled_catalog <= capacity,
        "logical_targets_within_profile_quotas": target_within_quotas,
        "excluded_overhead": [
            "normalized scalar columns and row headers",
            "SQLite B-tree pages, indexes, checksums, and free space",
            "lineage validity rows and 16-bit integrity buckets",
            "catalog-free residual revisions",
            "generation-bound atom SQL and FTS projections",
            "WAL, rollback anchor, and backup workspace",
            "referenced blob metadata",
        ],
    }


def _tool_version(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=REPOSITORY,
            env={
                "HOME": os.environ.get("HOME", ""),
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", ""),
            },
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalScaleError("toolchain identity capture failed") from error
    output = result.stdout.strip()
    if not output or len(output) > MAX_TOOL_OUTPUT_BYTES:
        fail("toolchain identity output is invalid")
    return output.decode("utf-8", errors="strict")


def host_environment(capacity_path: Path) -> dict[str, Any]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        fail("local-scale preflight currently supports native Apple-silicon macOS only")
    if not capacity_path.is_absolute():
        fail("local-scale capacity path must be absolute")
    try:
        before = capacity_path.lstat()
        resolved = capacity_path.resolve(strict=True)
    except OSError as error:
        raise LocalScaleError("local-scale capacity path is unavailable") from error
    if (
        resolved != capacity_path
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        fail("local-scale capacity path must be canonical and owner-private")
    usage = shutil.disk_usage(capacity_path)
    try:
        after = capacity_path.lstat()
    except OSError as error:
        raise LocalScaleError("local-scale capacity path changed") from error
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
    ):
        fail("local-scale capacity path changed")
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "release": platform.release(),
        "python": platform.python_version(),
        "rustc": _tool_version(("rustc", "--version")),
        "cargo": _tool_version(("cargo", "--version")),
        "logical_cpus": os.cpu_count(),
        "filesystem_path": capacity_path.as_posix(),
        "filesystem_device": before.st_dev,
        "filesystem_inode": before.st_ino,
        "filesystem_total_bytes": usage.total,
        "filesystem_free_bytes": usage.free,
    }


def build_receipt(capacity_path: Path, require_clean_source: bool) -> dict[str, Any]:
    started_ns = time.time_ns()
    source_before = source_file_snapshot()
    architecture = architecture_evidence()
    probe = run_record_probe()
    model = capacity_model(architecture, probe)
    source_after = source_file_snapshot()
    if source_before["digest"] != source_after["digest"]:
        fail("source-bound inputs changed during local-scale preflight")
    repository_state = git_state()
    environment = host_environment(capacity_path)
    blockers: list[str] = []
    if not model["record_payload_lower_bound_fits"]:
        blockers.append("normalized_record_payload_exceeds_large_local_capacity")
    if not model["logical_targets_within_profile_quotas"]:
        blockers.append("large_local_profile_quotas_do_not_cover_target")
    if (
        environment["filesystem_free_bytes"]
        < architecture["large_local_minimum_initial_free_bytes"]
    ):
        blockers.append("large_local_initial_free_space_below_requirement")
    if require_clean_source and not repository_state["clean"]:
        blockers.append("source_worktree_is_not_clean")
    result = "passed-preflight" if not blockers else "blocked"
    body = {
        "schema_version": SCHEMA_VERSION,
        "result": result,
        "release_scale_qualified": False,
        "started_at_unix_nanos": started_ns,
        "finished_at_unix_nanos": time.time_ns(),
        "platform_scope": "aarch64-apple-darwin",
        "targets": {
            "atoms": TARGET_ATOMS,
            "edges": TARGET_EDGES,
            "referenced_blob_bytes": TARGET_REFERENCED_BLOB_BYTES,
            "referenced_blob_unit": "logical bytes",
        },
        "observed": {
            "atoms": None,
            "edges": None,
            "referenced_blob_bytes": None,
        },
        "blockers": blockers,
        "architecture": architecture,
        "capacity_model": model,
        "source": {
            **source_after,
            "git": repository_state,
            "source_descriptor_bound": True,
        },
        "environment": environment,
        "checks": [
            {
                "id": "exact_fixture_cbor_probe",
                "status": "passed",
                "detail": "valid protocol fixtures were serialized by pinned Rust/ciborium code",
            },
            {
                "id": "normalized_v4_authority",
                "status": "passed",
                "detail": "v4 normalized authority, catalog-free residuals, and immutable profile binding are source-bound",
            },
            {
                "id": "large_local_target_bounds",
                "status": (
                    "passed"
                    if model["record_payload_lower_bound_fits"]
                    and model["logical_targets_within_profile_quotas"]
                    else "blocked"
                ),
                "detail": "target counts and valid-record payload lower bound are checked against hard large-local limits",
            },
            {
                "id": "large_local_initial_free_space",
                "status": (
                    "passed"
                    if environment["filesystem_free_bytes"]
                    >= architecture["large_local_minimum_initial_free_bytes"]
                    else "blocked"
                ),
                "detail": "host availability must meet the 300-GiB first-activation requirement",
            },
            {
                "id": "physical_scale_execution",
                "status": "not-run",
                "detail": "physical scale execution is deliberately outside this preflight and was skipped for this run",
            },
        ],
        "claims": {
            "physical_scale_execution_attempted": False,
            "one_million_physical_atoms": False,
            "ten_million_physical_edges": False,
            "one_hundred_gib_referenced_blobs": False,
            "legacy_sql_tables_treated_as_production": False,
            "fuzz_executed": False,
            "soak_executed": False,
        },
        "required_remediation": REQUIRED_REMEDIATION,
    }
    return receipt_with_id(body)


def _validated_source_binding(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "digest",
        "files",
        "git",
        "source_descriptor_bound",
    }:
        fail("local-scale receipt source binding is invalid")
    if (
        value.get("algorithm") != "sha256-length-prefixed-canonical-file-inventory-v1"
        or value.get("source_descriptor_bound") is not True
        or not isinstance(value.get("digest"), str)
        or not MULTIHASH.fullmatch(value["digest"])
    ):
        fail("local-scale receipt source binding is invalid")
    files = value.get("files")
    if not isinstance(files, list) or not files or len(files) > 100_000:
        fail("local-scale receipt source inventory is invalid")
    required_paths = set(EXPLICIT_SOURCE_INPUTS)
    observed_paths: list[str] = []
    digest = hashlib.sha256()
    digest.update(b"cigar.local-scale-source.v1\0")
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            fail("local-scale receipt source inventory entry is invalid")
        path = entry.get("path")
        sha256 = entry.get("sha256")
        byte_count = entry.get("bytes")
        if not isinstance(path, str) or not path or len(path.encode("utf-8")) > 4096:
            fail("local-scale receipt source path is invalid")
        try:
            normalized = "/".join(safe_relative_path(path))
        except EvidenceWorkspaceError as error:
            raise LocalScaleError(
                "local-scale receipt source path is invalid"
            ) from error
        if normalized != path or "\\" in path:
            fail("local-scale receipt source path is not canonical")
        if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            fail("local-scale receipt source digest is invalid")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
            or byte_count > MAX_SOURCE_FILE_BYTES
        ):
            fail("local-scale receipt source byte count is invalid")
        observed_paths.append(path)
        encoded = canonical_bytes(entry)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    if observed_paths != sorted(set(observed_paths)):
        fail("local-scale receipt source inventory is not uniquely ordered")
    if not required_paths.issubset(observed_paths):
        fail("local-scale receipt source inventory is incomplete")
    if value["digest"] != "1220" + digest.hexdigest():
        fail("local-scale receipt source inventory digest does not match")

    git = value.get("git")
    if not isinstance(git, dict) or set(git) != {
        "commit",
        "clean",
        "status_entry_count",
        "status_sha256",
    }:
        fail("local-scale receipt Git binding is invalid")
    commit = git.get("commit")
    clean = git.get("clean")
    status_count = git.get("status_entry_count")
    status_sha256 = git.get("status_sha256")
    if not isinstance(commit, str) or not GIT_OBJECT_ID.fullmatch(commit):
        fail("local-scale receipt Git commit is invalid")
    if not isinstance(clean, bool):
        fail("local-scale receipt Git cleanliness is invalid")
    if (
        isinstance(status_count, bool)
        or not isinstance(status_count, int)
        or status_count < 0
        or status_count > 1_000_000
        or not isinstance(status_sha256, str)
        or not SHA256.fullmatch(status_sha256)
    ):
        fail("local-scale receipt Git status binding is invalid")
    if clean != (status_count == 0):
        fail("local-scale receipt Git cleanliness is inconsistent")
    if clean and status_sha256 != hashlib.sha256(b"").hexdigest():
        fail("local-scale receipt clean Git status digest is invalid")


def _validate_environment(value: Any) -> None:
    expected_keys = {
        "system",
        "machine",
        "release",
        "python",
        "rustc",
        "cargo",
        "logical_cpus",
        "filesystem_path",
        "filesystem_device",
        "filesystem_inode",
        "filesystem_total_bytes",
        "filesystem_free_bytes",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        fail("local-scale receipt environment is invalid")
    if value.get("system") != "Darwin" or value.get("machine") != "arm64":
        fail("local-scale receipt environment is outside the claimed platform")
    for key in ("release", "python", "rustc", "cargo"):
        item = value.get(key)
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > 4096:
            fail("local-scale receipt toolchain identity is invalid")
    filesystem_path = value.get("filesystem_path")
    if (
        not isinstance(filesystem_path, str)
        or not filesystem_path.startswith("/")
        or len(filesystem_path.encode("utf-8")) > 4096
        or "\\" in filesystem_path
        or Path(filesystem_path).as_posix() != filesystem_path
        or any(part in {".", ".."} for part in Path(filesystem_path).parts)
    ):
        fail("local-scale receipt filesystem identity is invalid")
    for key in (
        "logical_cpus",
        "filesystem_device",
        "filesystem_inode",
        "filesystem_total_bytes",
        "filesystem_free_bytes",
    ):
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            fail("local-scale receipt host capacity is invalid")
    if (
        value["logical_cpus"] == 0
        or value["filesystem_inode"] == 0
        or value["filesystem_total_bytes"] == 0
    ):
        fail("local-scale receipt host capacity is invalid")
    if value["filesystem_free_bytes"] > value["filesystem_total_bytes"]:
        fail("local-scale receipt filesystem capacity is inconsistent")


def _validate_checks(
    value: Any,
    *,
    target_bounds_ready: bool,
    initial_free_space_ready: bool,
) -> None:
    expected = (
        ("exact_fixture_cbor_probe", "passed"),
        ("normalized_v4_authority", "passed"),
        ("large_local_target_bounds", "passed" if target_bounds_ready else "blocked"),
        (
            "large_local_initial_free_space",
            "passed" if initial_free_space_ready else "blocked",
        ),
        ("physical_scale_execution", "not-run"),
    )
    if not isinstance(value, list) or len(value) != len(expected):
        fail("local-scale receipt check set is invalid")
    for check, (expected_id, expected_status) in zip(value, expected, strict=True):
        if not isinstance(check, dict) or set(check) != {"id", "status", "detail"}:
            fail("local-scale receipt check is invalid")
        detail = check.get("detail")
        if (
            check.get("id") != expected_id
            or check.get("status") != expected_status
            or not isinstance(detail, str)
            or not detail
            or len(detail.encode("utf-8")) > 1024
        ):
            fail("local-scale receipt check is inconsistent")


def validate_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("local-scale receipt is not an object")
    if set(value) != TOP_LEVEL_KEYS:
        fail("local-scale receipt has an invalid top-level shape")
    if value.get("schema_version") != SCHEMA_VERSION:
        fail("local-scale receipt schema is unsupported")
    receipt_id = value.get("receipt_id")
    if not isinstance(receipt_id, str) or not MULTIHASH.fullmatch(receipt_id):
        fail("local-scale receipt identity is malformed")
    body = dict(value)
    del body["receipt_id"]
    if multihash_bytes(canonical_bytes(body)) != receipt_id:
        fail("local-scale receipt identity does not match its content")
    if value.get("result") not in {"blocked", "passed-preflight"}:
        fail("local-scale receipt result is invalid")
    started = value.get("started_at_unix_nanos")
    finished = value.get("finished_at_unix_nanos")
    if (
        isinstance(started, bool)
        or not isinstance(started, int)
        or started < 0
        or isinstance(finished, bool)
        or not isinstance(finished, int)
        or finished < started
    ):
        fail("local-scale receipt time interval is invalid")
    if value.get("platform_scope") != "aarch64-apple-darwin":
        fail("local-scale receipt platform scope is invalid")
    if value.get("targets") != {
        "atoms": TARGET_ATOMS,
        "edges": TARGET_EDGES,
        "referenced_blob_bytes": TARGET_REFERENCED_BLOB_BYTES,
        "referenced_blob_unit": "logical bytes",
    }:
        fail("local-scale receipt target is invalid")
    if value.get("observed") != {
        "atoms": None,
        "edges": None,
        "referenced_blob_bytes": None,
    }:
        fail("preflight receipt improperly claims observed scale data")
    model = value.get("capacity_model")
    if not isinstance(model, dict):
        fail("local-scale receipt capacity model is absent")
    architecture = value.get("architecture")
    probe = model.get("record_probe")
    if not isinstance(architecture, dict) or not isinstance(probe, dict):
        fail("local-scale receipt model inputs are absent")
    if architecture != {
        "standard_maximum_database_bytes": EXPECTED_STANDARD_DATABASE_CAP_BYTES,
        "large_local_maximum_database_bytes": EXPECTED_LARGE_LOCAL_DATABASE_CAP_BYTES,
        "large_local_minimum_initial_free_bytes": EXPECTED_LARGE_LOCAL_INITIAL_FREE_BYTES,
        "large_local_minimum_runtime_reserve_bytes": (
            EXPECTED_LARGE_LOCAL_RUNTIME_RESERVE_BYTES
        ),
        "large_local_maximum_atoms": EXPECTED_LARGE_LOCAL_MAX_ATOMS,
        "large_local_maximum_edges": EXPECTED_LARGE_LOCAL_MAX_EDGES,
        "large_local_maximum_referenced_blob_bytes": (
            EXPECTED_LARGE_LOCAL_MAX_REFERENCED_BLOB_BYTES
        ),
        "catalog_schema_version": 4,
        "authoritative_state_encoding": "sqlite-v4-normalized-catalog-plus-cbor-residual",
        "commit_rewrites_complete_catalog": False,
        "read_decodes_complete_catalog": False,
        "normalized_catalog_tables_are_authoritative": True,
        "legacy_sql_catalog_tables_are_authoritative": False,
        "normalized_atom_insert_occurrences": 1,
        "normalized_edge_insert_occurrences": 1,
        "integrity_bucket_count": 65_536,
        "capacity_profile_binding": "immutable-sqlite-authority-singleton",
        "atom_projection_kind": "disposable-generation-bound-sql-and-fts",
    }:
        fail("local-scale receipt architecture evidence is invalid")
    expected_model = capacity_model(architecture, probe)
    if canonical_bytes(model) != canonical_bytes(expected_model):
        fail("local-scale receipt capacity model does not reproduce")
    payload_fits = model.get("record_payload_lower_bound_fits")
    logical_target_fits = model.get("logical_targets_within_profile_quotas")
    qualified = value.get("release_scale_qualified")
    if (
        not isinstance(payload_fits, bool)
        or not isinstance(logical_target_fits, bool)
        or qualified is not False
    ):
        fail("local-scale receipt claims are inconsistent")
    blockers = value.get("blockers")
    allowed_blockers = {
        "normalized_record_payload_exceeds_large_local_capacity",
        "large_local_profile_quotas_do_not_cover_target",
        "large_local_initial_free_space_below_requirement",
        "source_worktree_is_not_clean",
    }
    if (
        not isinstance(blockers, list)
        or any(not isinstance(item, str) for item in blockers)
        or len(blockers) != len(set(blockers))
        or set(blockers) - allowed_blockers
    ):
        fail("local-scale receipt blockers are invalid")
    if ("normalized_record_payload_exceeds_large_local_capacity" in blockers) != (
        not payload_fits
    ):
        fail("local-scale receipt record-payload blocker is inconsistent")
    if ("large_local_profile_quotas_do_not_cover_target" in blockers) != (
        not logical_target_fits
    ):
        fail("local-scale receipt logical-quota blocker is inconsistent")
    if value["result"] == "blocked" and not blockers:
        fail("blocked local-scale receipt has no blocker")
    if value["result"] == "passed-preflight" and blockers:
        fail("passing local-scale preflight contains a blocker")
    _validated_source_binding(value.get("source"))
    environment = value.get("environment")
    _validate_environment(environment)
    initial_free_space_ready = (
        environment["filesystem_free_bytes"]
        >= architecture["large_local_minimum_initial_free_bytes"]
    )
    if ("large_local_initial_free_space_below_requirement" in blockers) != (
        not initial_free_space_ready
    ):
        fail("local-scale receipt free-space blocker is inconsistent")
    _validate_checks(
        value.get("checks"),
        target_bounds_ready=payload_fits and logical_target_fits,
        initial_free_space_ready=initial_free_space_ready,
    )
    claims = value.get("claims")
    expected_claims = {
        "physical_scale_execution_attempted",
        "one_million_physical_atoms",
        "ten_million_physical_edges",
        "one_hundred_gib_referenced_blobs",
        "legacy_sql_tables_treated_as_production",
        "fuzz_executed",
        "soak_executed",
    }
    if (
        not isinstance(claims, dict)
        or set(claims) != expected_claims
        or any(value_ is not False for value_ in claims.values())
    ):
        fail("preflight receipt improperly claims an executed scale gate")
    if value.get("required_remediation") != REQUIRED_REMEDIATION:
        fail("local-scale receipt remediation set is invalid")
    return value


def load_receipt(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        fail("local-scale receipt path must be absolute")
    payload = _bounded_regular(path)
    try:
        value = json.loads(
            payload,
            object_pairs_hook=lambda pairs: _reject_duplicates(pairs),
            parse_constant=lambda _value: fail("receipt contains a non-finite number"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalScaleError("local-scale receipt is not strict JSON") from error
    return validate_receipt(value)


def _reject_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("receipt contains a duplicate object key")
        result[key] = value
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Fail-closed Apple-silicon macOS local-scale capacity preflight"
    )
    subcommands = result.add_subparsers(dest="command", required=True)
    preflight = subcommands.add_parser(
        "preflight",
        help="measure current architecture and publish a blocked/pass preflight",
    )
    preflight.add_argument("--evidence-dir", type=Path, required=True)
    preflight.add_argument(
        "--capacity-path",
        type=Path,
        required=True,
        help="absolute canonical owner-private directory on the intended scratch filesystem",
    )
    preflight.add_argument(
        "--output",
        default="local-scale-preflight.json",
        help="safe relative receipt path",
    )
    preflight.add_argument("--require-clean-source", action="store_true")
    verify = subcommands.add_parser(
        "verify", help="verify one immutable preflight receipt"
    )
    verify.add_argument("--receipt", type=Path, required=True)
    return result


def command_preflight(arguments: argparse.Namespace) -> int:
    if not arguments.evidence_dir.is_absolute():
        fail("evidence directory must be absolute")
    output = "/".join(safe_relative_path(arguments.output))
    receipt = build_receipt(arguments.capacity_path, arguments.require_clean_source)
    validate_receipt(receipt)
    with EvidenceWorkspace.create(
        arguments.evidence_dir, repository_root=REPOSITORY
    ) as workspace:
        workspace.write_json(output, receipt)
    print(
        f"local-scale preflight {receipt['result']}; receipt="
        f"{arguments.evidence_dir / output}"
    )
    return 0 if receipt["result"] == "passed-preflight" else 3


def command_verify(arguments: argparse.Namespace) -> int:
    receipt = load_receipt(arguments.receipt)
    print(f"local-scale receipt verified: {receipt['receipt_id']}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "preflight":
            return command_preflight(arguments)
        return command_verify(arguments)
    except (EvidenceWorkspaceError, LocalScaleError, OSError, ValueError):
        print(
            "local-scale preflight error: qualification operation failed",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
