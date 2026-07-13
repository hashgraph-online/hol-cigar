#!/usr/bin/env python3
"""Validate runbooks statically or execute eight explicit environment-owned live drivers."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from release_lib import (
    ReleaseError,
    file_reference,
    load_json,
    load_json_bytes,
    process_failure_summary,
    repo_root,
    resolve_beneath,
    run_bounded,
    safe_relative_path,
    sha256_file,
    write_json,
)


_REQUIRED_EXERCISES = {
    "backup", "restore", "key-rotation", "migration", "index-rebuild", "unknown-effect",
    "journal-quarantine", "adapter-disable",
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--mode", choices=["static", "live"], required=True)
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--driver-directory", type=Path)
    parser.add_argument("--source-date-epoch", type=int, default=0)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def _source(arguments: argparse.Namespace, root: Path, manifest_path: Path) -> tuple[str, int, list[str]]:
    if arguments.candidate_manifest is None:
        if arguments.mode == "live":
            raise ReleaseError("live exercises require --candidate-manifest")
        return f"development:{sha256_file(manifest_path)}", arguments.source_date_epoch, ["runbook-documentation"]
    if arguments.candidate_manifest.is_symlink():
        raise ReleaseError("candidate manifest must not be a symlink")
    candidate_path = arguments.candidate_manifest.resolve()
    if not candidate_path.is_file():
        raise ReleaseError("candidate manifest must be a regular file")
    candidate = load_json(candidate_path)
    expected_candidate_keys = {
        "schema_version", "product_version", "context_abi", "source_date_epoch", "source", "artifacts",
    }
    if (
        not isinstance(candidate, dict)
        or set(candidate) != expected_candidate_keys
        or candidate.get("schema_version") != "cigar.release-build.v1"
    ):
        raise ReleaseError("live exercises require an exact release build manifest")
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("release_state") != "release"
        or candidate.get("product_version") != matrix.get("product_version")
        or candidate.get("context_abi") != matrix.get("context_abi")
    ):
        raise ReleaseError("candidate build manifest disagrees with the release artifact matrix")
    source = candidate.get("source")
    epoch = candidate.get("source_date_epoch")
    artifacts = candidate.get("artifacts")
    artifact_ids: list[str] = []
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or not isinstance(source.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"]) is None
        or not isinstance(source.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", source["tree_sha256"]) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
        or not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or epoch < 0
        or epoch > 4_294_967_295
        or not isinstance(artifacts, list)
        or not artifacts
    ):
        raise ReleaseError("candidate manifest source identity is invalid")
    matrix_entries = {
        entry["id"]: entry
        for entry in matrix.get("artifacts", [])
        if isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry.get("required_for_release") is True
    }
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {"id", "path", "sha256", "bytes", "contract"}:
            raise ReleaseError("candidate build manifest has an invalid artifact record")
        identifier = record.get("id")
        relative = safe_relative_path(record.get("path", ""))
        digest = record.get("sha256")
        size = record.get("bytes")
        if (
            not isinstance(identifier, str)
            or identifier in artifact_ids
            or identifier not in matrix_entries
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise ReleaseError("candidate build manifest has invalid artifact identity or binding")
        matrix_entry = matrix_entries[identifier]
        if (
            Path(relative).name != matrix_entry.get("filename")
            or record.get("contract") != f"packaging/{matrix_entry.get('contract')}"
        ):
            raise ReleaseError(f"candidate artifact disagrees with the matrix: {identifier}")
        supplied_path = candidate_path.parent
        path_has_symlink = False
        for part in relative.split("/"):
            supplied_path = supplied_path / part
            path_has_symlink = path_has_symlink or supplied_path.is_symlink()
        if path_has_symlink:
            raise ReleaseError(f"candidate artifact must not be a symlink: {relative}")
        artifact_path = resolve_beneath(candidate_path.parent, relative)
        if not artifact_path.is_file() or artifact_path.stat().st_size != size or sha256_file(artifact_path) != digest:
            raise ReleaseError(f"candidate artifact digest or size mismatch: {relative}")
        artifact_ids.append(identifier)
    if set(artifact_ids) != set(matrix_entries):
        raise ReleaseError(
            f"candidate artifact set is incomplete; missing={sorted(set(matrix_entries) - set(artifact_ids))}, "
            f"extra={sorted(set(artifact_ids) - set(matrix_entries))}"
        )
    return source["revision"], epoch, sorted(artifact_ids)


def _validate_driver_receipt(receipt: Any, exercise: str, revision: str, epoch: int, artifact_ids: list[str]) -> dict[str, Any]:
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "cigar.operation-exercise.v1":
        raise ReleaseError(f"live driver {exercise} returned an unsupported receipt")
    expected_keys = {"schema_version", "exercise", "mode", "source_revision", "artifact_ids", "status", "checks", "source_date_epoch"}
    if set(receipt) != expected_keys:
        raise ReleaseError(f"live driver {exercise} returned an unexpected receipt shape")
    if receipt.get("exercise") != exercise or receipt.get("mode") != "live":
        raise ReleaseError(f"live driver {exercise} mislabeled its exercise or mode")
    if receipt.get("source_revision") != revision or receipt.get("source_date_epoch") != epoch:
        raise ReleaseError(f"live driver {exercise} returned stale evidence")
    if receipt.get("artifact_ids") != artifact_ids:
        raise ReleaseError(f"live driver {exercise} returned evidence for the wrong artifact set")
    checks = receipt.get("checks")
    if receipt.get("status") != "passed" or not isinstance(checks, list) or not checks:
        raise ReleaseError(f"live driver {exercise} did not pass")
    if any(not isinstance(check, dict) or set(check) != {"id", "status", "detail"} or check.get("status") != "passed" for check in checks):
        raise ReleaseError(f"live driver {exercise} returned a non-passing check")
    check_ids = [check.get("id") for check in checks]
    if len(set(check_ids)) != len(check_ids) or not all(isinstance(value, str) and value for value in check_ids):
        raise ReleaseError(f"live driver {exercise} returned invalid or duplicate check ids")
    if any(
        not isinstance(check.get("detail"), str) or not check["detail"] or len(check["detail"].encode("utf-8")) > 1024
        or any(ord(character) < 0x20 for character in check["detail"])
        for check in checks
    ):
        raise ReleaseError(f"live driver {exercise} returned an invalid or unbounded check detail")
    return receipt


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    manifest_path = root / "packaging/operation-exercises.v1.json"
    manifest = load_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "exercises"}
        or manifest.get("schema_version") != "cigar.operation-exercises.v1"
    ):
        raise ReleaseError("unsupported operation exercise manifest")
    exercises = manifest.get("exercises")
    if not isinstance(exercises, list) or len(exercises) != 8:
        raise ReleaseError("exactly eight operation exercises are required")
    identifiers = [entry.get("id") for entry in exercises]
    if len(set(identifiers)) != 8 or set(identifiers) != _REQUIRED_EXERCISES:
        raise ReleaseError("operation exercise ids are invalid or duplicated")
    for entry in exercises:
        if not isinstance(entry, dict) or set(entry) != {"id", "document", "required_terms"}:
            raise ReleaseError("operation exercise entry has an unexpected shape")
        document = entry.get("document")
        terms = entry.get("required_terms")
        if (
            not isinstance(document, str)
            or not document.startswith("docs/")
            or not isinstance(terms, list)
            or not terms
            or len(set(terms)) != len(terms)
            or not all(
                isinstance(term, str)
                and term
                and len(term.encode("utf-8")) <= 512
                and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in term)
                for term in terms
            )
        ):
            raise ReleaseError(f"operation exercise entry is invalid: {entry.get('id')}")
        resolve_beneath(root, document)
    revision, epoch, artifact_ids = _source(arguments, root, manifest_path)
    subject_manifest = manifest_path if arguments.candidate_manifest is None else arguments.candidate_manifest.resolve()
    subject_manifest_sha256 = sha256_file(subject_manifest)
    output = arguments.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ReleaseError("operation evidence output directory must be empty")
    receipts: list[dict[str, Any]] = []
    receipt_paths: list[tuple[str, Path]] = []

    if arguments.mode == "static":
        for entry in exercises:
            document = resolve_beneath(root, entry["document"])
            text = document.read_text(encoding="utf-8")
            terms = entry.get("required_terms")
            if not isinstance(terms, list) or not terms or not all(isinstance(term, str) and term in text for term in terms):
                raise ReleaseError(f"runbook {entry['id']} is missing a required stop/recovery term")
            receipt = {
                "schema_version": "cigar.operation-exercise.v1",
                "exercise": entry["id"],
                "mode": "static",
                "source_revision": revision,
                "artifact_ids": artifact_ids,
                "subject_manifest_sha256": subject_manifest_sha256,
                "producer": {"name": Path(__file__).name, "sha256": sha256_file(Path(__file__).resolve())},
                "source_date_epoch": epoch,
                "status": "passed",
                "checks": [
                    {"id": "document-present", "status": "passed", "detail": entry["document"]},
                    {"id": "required-terms", "status": "passed", "detail": f"{len(terms)} required terms present"}
                ]
            }
            receipt_path = output / f"{entry['id']}.static.json"
            write_json(receipt_path, receipt)
            receipts.append(receipt)
            receipt_paths.append((entry["id"], receipt_path))
    else:
        if os.environ.get("CIGAR_OPERATION_SANDBOX_ENFORCED") != "1":
            raise ReleaseError("live exercises require an environment-enforced operation sandbox")
        if arguments.driver_directory is None:
            raise ReleaseError("live exercises require --driver-directory")
        if arguments.driver_directory.is_symlink():
            raise ReleaseError("live driver directory must not be a symlink")
        driver_directory = arguments.driver_directory.resolve()
        if not driver_directory.is_dir():
            raise ReleaseError("live driver directory does not exist")
        with tempfile.TemporaryDirectory(prefix="cigar-operation-drivers-") as temporary:
            staged_directory = Path(temporary)
            for entry in exercises:
                driver = driver_directory / entry["id"]
                if driver.is_symlink() or not driver.is_file() or not os.access(driver, os.X_OK):
                    raise ReleaseError(f"live driver is missing, linked, or not executable: {entry['id']}")
                driver_digest = sha256_file(driver)
                staged_driver = staged_directory / entry["id"]
                shutil.copyfile(driver, staged_driver)
                os.chmod(staged_driver, 0o500)
                if sha256_file(staged_driver) != driver_digest:
                    raise ReleaseError(f"live driver changed while staging: {entry['id']}")
                command = [str(staged_driver), "--candidate-manifest", str(subject_manifest), "--source-date-epoch", str(epoch)]
                result = run_bounded(command, cwd=root, timeout=3600, max_stdout=2 * 1024 * 1024, max_stderr=2 * 1024 * 1024)
                if result.returncode != 0:
                    raise ReleaseError(process_failure_summary(result, f"live driver {entry['id']}"))
                receipt = _validate_driver_receipt(
                    load_json_bytes(result.stdout, f"live driver {entry['id']} stdout"),
                    entry["id"], revision, epoch, artifact_ids,
                )
                if sha256_file(staged_driver) != driver_digest or sha256_file(subject_manifest) != subject_manifest_sha256:
                    raise ReleaseError(f"live driver or candidate manifest changed during exercise: {entry['id']}")
                receipt["subject_manifest_sha256"] = subject_manifest_sha256
                receipt["producer"] = {"name": driver.name, "sha256": driver_digest}
                receipt_path = output / f"{entry['id']}.live.json"
                write_json(receipt_path, receipt)
                receipts.append(receipt)
                receipt_paths.append((entry["id"], receipt_path))

    summary = {
        "schema_version": "cigar.operation-exercise-summary.v1",
        "mode": arguments.mode,
        "source_revision": revision,
        "artifact_ids": artifact_ids,
        "subject_manifest_sha256": subject_manifest_sha256,
        "source_date_epoch": epoch,
        "status": "passed",
        "exercise_count": len(receipts),
        "exercises": sorted(receipt["exercise"] for receipt in receipts),
        "receipts": [
            {"exercise": exercise, **file_reference(path, output)}
            for exercise, path in sorted(receipt_paths)
        ],
    }
    write_json(output / "summary.json", summary)
    print(f"{arguments.mode} operation exercise passed for {len(receipts)} runbooks")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.TimeoutExpired, ReleaseError) as error:
        raise SystemExit(f"operation exercise failed: {error}") from error
