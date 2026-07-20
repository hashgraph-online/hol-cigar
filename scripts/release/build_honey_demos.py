#!/usr/bin/env python3
"""Build the deterministic, network-free CIGAR Honey demo archive."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Never

from build_archives import SourceSnapshot, _snapshot_tree_digest, _write_archive
from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    git_state,
    load_json,
    require_source_date_epoch,
    sha256_bytes,
    sha256_file,
)
from verify_package import verify as verify_package

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_ID = "honey-demos"
ARTIFACT_KIND = "demo-archive"
VERSION = "0.9.1-honey.1"
CONTEXT_ABI = "cigar.context.v1"
FILENAME = "cigar-honey-demos-0.9.1-honey.1.tar.gz"
RECEIPT = "honey-demo-build-receipt.json"
CONTRACT = "packaging/honey/contracts/demos-archive.v1.json"
PROFILE = "packaging/honey/capability-profile.v1.json"
MATRIX = "packaging/honey/artifact-matrix.v1.json"
REQUIREMENTS = "packaging/honey/release-requirements.v1.json"
PRODUCT = "packaging/product-version.v1.json"
PRODUCER_ARGV = ["python3", "scripts/release/build_honey_demos.py"]
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

# Source paths are mapped into one exact public archive. Authority-only inputs are
# snapshotted separately below and never become package members.
PACKAGE_INPUTS: tuple[tuple[str, str, int], ...] = (
    ("README_HONEY.md", "README.md", 0o644),
    ("LICENSE", "LICENSE", 0o644),
    ("NOTICE", "NOTICE", 0o644),
    ("demos/honey-manifest.v1.json", "demos/honey-manifest.v1.json", 0o644),
    ("demos/run_honey.py", "demos/run_honey.py", 0o755),
    ("demos/run.py", "demos/run.py", 0o644),
    (
        "demos/installed_artifact_test.py",
        "demos/installed_artifact_test.py",
        0o644,
    ),
    ("demos/driver_support.py", "demos/driver_support.py", 0o644),
    ("demos/canaries.json", "demos/canaries.json", 0o644),
    ("demos/quickstart/demo.json", "demos/quickstart/demo.json", 0o644),
    ("demos/quickstart/fixture.json", "demos/quickstart/fixture.json", 0o644),
    ("demos/quickstart/driver.py", "demos/quickstart/driver.py", 0o644),
    (
        "demos/prompt-injection-defense/demo.json",
        "demos/prompt-injection-defense/demo.json",
        0o644,
    ),
    (
        "demos/prompt-injection-defense/fixture.json",
        "demos/prompt-injection-defense/fixture.json",
        0o644,
    ),
    (
        "demos/prompt-injection-defense/driver.py",
        "demos/prompt-injection-defense/driver.py",
        0o644,
    ),
    (
        "demos/honey-two-agent/honey-demo.json",
        "demos/honey-two-agent/honey-demo.json",
        0o644,
    ),
    (
        "demos/honey-two-agent/fixture.json",
        "demos/honey-two-agent/fixture.json",
        0o644,
    ),
    (
        "demos/honey-two-agent/driver.py",
        "demos/honey-two-agent/driver.py",
        0o644,
    ),
    (
        "demos/agent-handoff/driver.py",
        "demos/agent-handoff/driver.py",
        0o644,
    ),
    (
        "demos/effect-recovery/demo.json",
        "demos/effect-recovery/demo.json",
        0o644,
    ),
    (
        "demos/effect-recovery/fixture.json",
        "demos/effect-recovery/fixture.json",
        0o644,
    ),
    (
        "demos/effect-recovery/driver.py",
        "demos/effect-recovery/driver.py",
        0o644,
    ),
    (
        "demos/replay-comparison/demo.json",
        "demos/replay-comparison/demo.json",
        0o644,
    ),
    (
        "demos/replay-comparison/fixture.json",
        "demos/replay-comparison/fixture.json",
        0o644,
    ),
    (
        "demos/replay-comparison/driver.py",
        "demos/replay-comparison/driver.py",
        0o644,
    ),
    ("demos/claude-code/demo.json", "demos/claude-code/demo.json", 0o644),
    ("demos/claude-code/fixture.json", "demos/claude-code/fixture.json", 0o644),
    ("demos/claude-code/driver.py", "demos/claude-code/driver.py", 0o644),
    (
        "scripts/release/evidence_workspace.py",
        "scripts/release/evidence_workspace.py",
        0o644,
    ),
)
AUTHORITY_INPUTS = (
    PRODUCT,
    PROFILE,
    MATRIX,
    REQUIREMENTS,
    CONTRACT,
    "scripts/release/build_honey_demos.py",
)


class HoneyDemoBuildError(ReleaseError):
    """The Honey demo producer contract was not satisfied."""


def fail(message: str) -> Never:
    raise HoneyDemoBuildError(message)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source-date-epoch")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute new owner-only evidence root (or CIGAR_EVIDENCE_DIR)",
    )
    return parser.parse_args(argv)


def selected_evidence_directory(arguments: argparse.Namespace) -> Path:
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if arguments.evidence_dir is not None and environment:
        if os.fspath(arguments.evidence_dir) != environment:
            fail("--evidence-dir conflicts with CIGAR_EVIDENCE_DIR")
    selected = arguments.evidence_dir or (Path(environment) if environment else None)
    if selected is None or not selected.is_absolute():
        fail("an absolute --evidence-dir or CIGAR_EVIDENCE_DIR is required")
    return selected


def stable_read(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_SOURCE_BYTES
        ):
            fail(f"{label} is not a bounded regular source file")
        chunks: list[bytes] = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            fail(f"{label} changed while it was read")
        if len(payload) != before.st_size:
            fail(f"{label} exceeded its source bound")
        return payload
    except OSError as error:
        raise HoneyDemoBuildError(f"cannot read {label}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def snapshot(root: Path) -> tuple[list[SourceSnapshot], dict[str, bytes]]:
    payloads: dict[str, bytes] = {}
    package: list[SourceSnapshot] = []
    total = 0
    destinations: set[str] = set()
    for source, destination, mode in PACKAGE_INPUTS:
        if destination in destinations:
            fail("Honey demo package mapping contains a duplicate destination")
        destinations.add(destination)
        payload = stable_read(root / source, source)
        payloads[source] = payload
        total += len(payload)
        package.append(SourceSnapshot(destination, payload, mode))
    for source in AUTHORITY_INPUTS:
        if source in payloads:
            continue
        payload = stable_read(root / source, source)
        payloads[source] = payload
        total += len(payload)
    if total > MAX_TOTAL_BYTES:
        fail("Honey demo producer inputs exceed the aggregate bound")
    package.sort(key=lambda item: item.relative.encode("utf-8"))
    checksums = "".join(
        f"{sha256_bytes(item.payload)}  {item.relative}\n" for item in package
    ).encode("ascii")
    package.append(SourceSnapshot("SHA256SUMS", checksums, 0o644))
    package.sort(key=lambda item: item.relative.encode("utf-8"))
    return package, payloads


def verify_snapshot(root: Path, payloads: dict[str, bytes]) -> None:
    for source, payload in sorted(payloads.items()):
        if stable_read(root / source, source) != payload:
            fail(f"Honey demo producer input changed after snapshot: {source}")


def input_tree(payloads: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, payload in sorted(payloads.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def validate_authority(root: Path) -> dict[str, dict[str, Any]]:
    product = load_json(root / PRODUCT)
    profile = load_json(root / PROFILE)
    matrix = load_json(root / MATRIX)
    requirements = load_json(root / REQUIREMENTS)
    contract = load_json(root / CONTRACT)
    if (
        not isinstance(product, dict)
        or product.get("version") != VERSION
        or product.get("context_abi") != CONTEXT_ABI
        or product.get("channel") != "honey"
        or product.get("release_state") != "developer-preview"
    ):
        fail("central product version is not the Honey authority")
    identity = profile.get("identity") if isinstance(profile, dict) else None
    product_binding = (
        profile.get("product_version_binding") if isinstance(profile, dict) else None
    )
    if (
        not isinstance(profile, dict)
        or profile.get("schema_version") != "cigar.honey.capability-profile.v1"
        or profile.get("profile_id")
        != "cigar.honey.local-developer-preview.macos-arm64.v1"
        or profile.get("fail_closed") is not True
        or not isinstance(identity, dict)
        or identity.get("product_version") != VERSION
        or identity.get("context_abi") != CONTEXT_ABI
        or identity.get("channel") != "honey"
        or identity.get("release_state") != "developer-preview"
        or not isinstance(product_binding, dict)
        or product_binding.get("path") != PRODUCT
        or product_binding.get("sha256") != sha256_file(root / PRODUCT)
        or not isinstance(profile.get("artifact_ids"), list)
        or profile.get("artifact_ids", []).count(ARTIFACT_ID) != 1
    ):
        fail("Honey capability profile identity is stale")
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.honey.artifact-matrix.v1"
        or matrix.get("profile_id") != profile["profile_id"]
        or matrix.get("product_version") != VERSION
        or matrix.get("context_abi") != CONTEXT_ABI
        or matrix.get("release_state") != "developer-preview"
        or matrix.get("fail_closed") is not True
    ):
        fail("Honey artifact matrix identity is stale")
    if (
        not isinstance(requirements, dict)
        or requirements.get("schema_version") != "cigar.honey.release-requirements.v1"
        or requirements.get("profile_id") != profile["profile_id"]
        or requirements.get("evidence_class") != "developer-preview"
        or requirements.get("fail_closed") is not True
    ):
        fail("Honey release requirements authority is stale")
    artifacts = matrix.get("artifacts") if isinstance(matrix, dict) else None
    matches = [
        item
        for item in artifacts or []
        if isinstance(item, dict) and item.get("id") == ARTIFACT_ID
    ]
    if len(matches) != 1:
        fail("Honey artifact matrix has no unique demo artifact")
    artifact = matches[0]
    if artifact != {
        "contract": CONTRACT,
        "filename": FILENAME,
        "generated_by_assembler": False,
        "id": ARTIFACT_ID,
        "kind": ARTIFACT_KIND,
        "order": 10,
        "producer": PRODUCER_ARGV,
        "public_attachment": True,
        "qualification_gate_ids": [
            "two-agent-authority",
            "effect-unknown-recovery",
            "offline-replay",
            "prompt-injection-defense",
        ],
        "receipt": {
            "filename": RECEIPT,
            "required": True,
            "schema_version": "cigar.honey-demo-build.v1",
        },
        "required": True,
        "sha256_required": True,
        "workspace": "demos",
    }:
        fail("Honey demo artifact matrix row is stale")
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id") != "honey-demos-archive-v1"
        or contract.get("version_binding")
        != {
            "path_pattern": "RELEASE-METADATA.json",
            "format": "json",
            "json_pointer": "/product_version",
        }
        or contract.get("abi_binding")
        != {
            "path_pattern": "RELEASE-METADATA.json",
            "format": "json",
            "json_pointer": "/context_abi",
        }
    ):
        fail("Honey demo package contract is stale")
    return {
        relative: {
            "sha256": sha256_file(root / relative),
            "bytes": (root / relative).stat().st_size,
        }
        for relative in (PRODUCT, PROFILE, MATRIX, REQUIREMENTS, CONTRACT)
    }


def build(arguments: argparse.Namespace) -> dict[str, Any]:
    root = arguments.root.resolve(strict=True)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    evidence = selected_evidence_directory(arguments)
    authority = validate_authority(root)
    package, payloads = snapshot(root)
    source = git_state(root, input_tree(payloads))
    if source.get("committed") is not True or source.get("clean") is not True:
        fail("Honey demo archive requires one committed clean source tree")
    contract_path = root / CONTRACT
    metadata = {
        "schema_version": "cigar.release-metadata.v1",
        "artifact_id": ARTIFACT_ID,
        "product_version": VERSION,
        "context_abi": CONTEXT_ABI,
        "source_date_epoch": epoch,
        "source": source,
        "input_tree_sha256": _snapshot_tree_digest(package),
        "input_file_count": len(package),
        "contract": CONTRACT,
        "contract_sha256": sha256_file(contract_path),
    }
    workspace = EvidenceWorkspace.create(evidence, repository_root=root)
    try:
        with tempfile.TemporaryDirectory(prefix="cigar-honey-demos-build-") as raw:
            staging = Path(raw).resolve(strict=True)
            staging.chmod(0o700)
            archive = staging / FILENAME
            _write_archive(archive, package, metadata, epoch, False)
            if archive.stat().st_size > MAX_ARCHIVE_BYTES:
                fail("Honey demo archive exceeds its compressed size bound")
            verify_package(archive, contract_path, VERSION, CONTEXT_ABI, epoch)
            verify_snapshot(root, payloads)
            if git_state(root, input_tree(payloads)) != source:
                fail("Honey source identity changed during demo construction")
            reference = workspace.attach_file(
                archive,
                FILENAME,
                read_only=True,
                expected_sha256=sha256_file(archive),
                expected_bytes=archive.stat().st_size,
            )
        receipt: dict[str, Any] = {
            "schema_version": "cigar.honey-demo-build.v1",
            "status": "built-unqualified",
            "artifact_id": ARTIFACT_ID,
            "artifact_kind": ARTIFACT_KIND,
            "product_version": VERSION,
            "context_abi": CONTEXT_ABI,
            "source_date_epoch": epoch,
            "source": source,
            "archive": reference.as_dict(),
            "contract": {
                "path": CONTRACT,
                "sha256": sha256_file(contract_path),
            },
            "authority": authority,
            "producer": {"argv": PRODUCER_ARGV},
            "scenario_count": 4,
            "run_count_per_scenario": 2,
            "network_required": False,
            "credentials_required": False,
        }
        receipt["receipt_digest"] = "1220" + sha256_bytes(canonical_json_bytes(receipt))
        workspace.write_json(RECEIPT, receipt)
        print(f"built {FILENAME} ({reference.sha256})")
        return receipt
    finally:
        workspace.close()


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    build(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, OSError, ReleaseError) as error:
        raise SystemExit(f"honey-demo-build: {error}") from error
