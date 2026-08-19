"""Content-addressed, create-new evidence transport bundles."""

from __future__ import annotations

# ruff: noqa: E402

import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any

from .canonical import identity, load_file
from .schema import SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError

SCHEMA = "evidence-bundle-v1.schema.json"


class ArtifactError(RuntimeError):
    """An evidence bundle is unsafe, mutable, incomplete, or incorrectly bound."""


def _external(root: Path, repository_root: Path, label: str) -> None:
    if not root.is_absolute() or root.is_symlink():
        raise ArtifactError(f"{label} must be an absolute non-symlink path")
    if (
        root == repository_root
        or repository_root in root.parents
        or root in repository_root.parents
    ):
        raise ArtifactError(f"{label} must be external to the repository")


def _inventory(root: Path) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        if parent.is_symlink():
            raise ArtifactError("bundle contains a symlinked directory")
        directories.sort()
        files.sort()
        for name in files:
            path = parent / name
            metadata = path.stat(follow_symlinks=False)
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise ArtifactError("bundle contains a mutable or unsafe file")
            result[path.relative_to(root).as_posix()] = (
                metadata.st_size,
                stat.S_IMODE(metadata.st_mode),
            )
    return result


def create_bundle(
    *,
    repository_root: Path,
    output_root: Path,
    run_id: str,
    evidence_class: str,
    retention_days: int,
    source_revision: str,
    source_tree: str,
    attachments: dict[str, Path],
    policy_id: str,
    authority: str,
) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    _external(output_root, repository_root, "bundle output")
    if output_root.exists():
        raise ArtifactError("bundle output must be create-new")
    if not attachments:
        raise ArtifactError("bundle requires at least one attachment")
    records: list[dict[str, Any]] = []
    try:
        with EvidenceWorkspace.create(
            output_root, repository_root=repository_root
        ) as workspace:
            for name in sorted(attachments):
                if (
                    "/" in name
                    or "\\" in name
                    or name in {"", ".", ".."}
                    or len(name.encode("utf-8")) > 255
                ):
                    raise ArtifactError("bundle attachment name is unsafe")
                source = attachments[name]
                if not source.is_absolute() or source.is_symlink():
                    raise ArtifactError("bundle source must be an absolute real file")
                attached = workspace.attach_file(source, f"attachments/{name}")
                records.append(
                    {
                        "path": attached.path,
                        "sha256": attached.sha256,
                        "bytes": attached.bytes,
                    }
                )
            body = {
                "schema_version": "cigar.refinement-evidence-bundle.v1",
                "bundle_id": "",
                "run_id": run_id,
                "evidence_class": evidence_class,
                "authority": authority,
                "policy_id": policy_id,
                "retention_days": retention_days,
                "source": {
                    "revision": source_revision,
                    "tree": source_tree,
                },
                "attachments": records,
            }
            unsigned = dict(body)
            unsigned.pop("bundle_id")
            body["bundle_id"] = identity(unsigned)
            SchemaRegistry(repository_root / "schemas" / "refinement").validate(
                SCHEMA, body
            )
            workspace.write_json("manifest.json", body)
    except (EvidenceWorkspaceError, OSError, ValueError) as error:
        raise ArtifactError("evidence bundle publication failed") from error
    return verify_bundle(repository_root=repository_root, bundle_root=output_root)


def verify_bundle(*, repository_root: Path, bundle_root: Path) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    _external(bundle_root, repository_root, "bundle")
    try:
        if bundle_root.resolve(strict=True) != bundle_root:
            raise ArtifactError("bundle path contains an alias")
        manifest = load_file(bundle_root / "manifest.json")
        if not isinstance(manifest, dict):
            raise ArtifactError("bundle manifest is not an object")
        SchemaRegistry(repository_root / "schemas" / "refinement").validate(
            SCHEMA, manifest
        )
        unsigned = dict(manifest)
        unsigned.pop("bundle_id")
        if manifest["bundle_id"] != identity(unsigned):
            raise ArtifactError("bundle identity is invalid")
        expected = {"manifest.json"} | {row["path"] for row in manifest["attachments"]}
        if set(_inventory(bundle_root)) != expected:
            raise ArtifactError("bundle inventory differs from its manifest")
        with EvidenceWorkspace.create(
            bundle_root, repository_root=repository_root
        ) as workspace:
            payloads = workspace.read_files(expected, strict_read_only=True)
        for row in manifest["attachments"]:
            payload = payloads[row["path"]]
            if (
                len(payload) != row["bytes"]
                or hashlib.sha256(payload).hexdigest() != row["sha256"]
            ):
                raise ArtifactError("bundle attachment binding is invalid")
        return manifest
    except (EvidenceWorkspaceError, OSError, ValueError) as error:
        if isinstance(error, ArtifactError):
            raise
        raise ArtifactError("evidence bundle cannot be verified") from error
