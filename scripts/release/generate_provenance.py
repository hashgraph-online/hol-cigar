#!/usr/bin/env python3
"""Generate deterministic in-toto/SLSA provenance for already-built artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    git_state,
    repo_root,
    require_distinct_output,
    require_source_date_epoch,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
    write_json,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--material", type=Path, action="append", default=[])
    parser.add_argument("--builder-id", required=True)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument(
        "--network-mode", choices=["disabled", "isolated", "unspecified"], required=True
    )
    parser.add_argument("--command", action="append", required=True)
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external provenance workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    return parser.parse_args()


def selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    """Select one external output root without resolving untrusted components."""

    argument_value = arguments.evidence_dir
    environment_value = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument_value is not None and environment_value:
        if Path(argument_value) != Path(environment_value):
            raise ReleaseError(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide one location"
            )
    raw = argument_value if argument_value is not None else environment_value
    if raw is None or os.fspath(raw) == "":
        return None
    selected = Path(raw)
    if not selected.is_absolute():
        raise ReleaseError("evidence directory must be an absolute path")
    return selected


class ProvenanceOutput:
    """One pinned external or legacy development provenance destination."""

    def __init__(
        self,
        *,
        direct: Path | None,
        workspace: EvidenceWorkspace | None,
        relative: str | None,
    ) -> None:
        self.direct = direct
        self.workspace = workspace
        self.relative = relative

    @classmethod
    def open(
        cls,
        arguments: argparse.Namespace,
        root: Path,
        inputs: list[Path],
    ) -> ProvenanceOutput:
        selected = selected_evidence_directory(arguments)
        if selected is None:
            direct = arguments.out.resolve()
            require_distinct_output(direct, inputs, "provenance")
            return cls(direct=direct, workspace=None, relative=None)
        try:
            parts = safe_evidence_path(os.fspath(arguments.out))
            relative = "/".join(parts)
            workspace = EvidenceWorkspace.create(selected, repository_root=root)
        except EvidenceWorkspaceError as error:
            raise ReleaseError(f"unsafe evidence workspace: {error}") from error
        try:
            require_distinct_output(
                workspace.root.joinpath(*parts), inputs, "provenance"
            )
            return cls(direct=None, workspace=workspace, relative=relative)
        except BaseException:
            workspace.close()
            raise

    def publish(self, provenance: dict[str, Any]) -> None:
        if self.workspace is None:
            assert self.direct is not None
            write_json(self.direct, provenance)
            return
        assert self.relative is not None
        self.workspace.write_json(self.relative, provenance)

    def close(self) -> None:
        if self.workspace is not None:
            self.workspace.close()


def _subject(path: Path, name: str | None = None) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"provenance input is not a regular file: {path}")
    subject_name = safe_relative_path(name or path.name)
    return {"name": subject_name, "digest": {"sha256": sha256_file(path)}}


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    if (
        re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64}|unborn:[0-9a-f]{64})",
            arguments.source_revision,
        )
        is None
    ):
        raise ReleaseError("source revision is invalid")
    for label, value in (
        ("builder id", arguments.builder_id),
        ("workflow id", arguments.workflow_id),
        *(("command", value) for value in arguments.command),
    ):
        maximum = 4096 if label == "command" else 512
        if (
            not value
            or value != value.strip()
            or len(value.encode("utf-8")) > maximum
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            )
        ):
            raise ReleaseError(f"provenance {label} is invalid")
    if (
        arguments.network_mode == "disabled"
        and os.environ.get("CIGAR_NO_EGRESS_ENFORCED") != "1"
    ):
        raise ReleaseError(
            "disabled-network provenance requires an environment-enforced no-egress marker"
        )
    subject_paths = {
        path.absolute().name: path.absolute() for path in arguments.artifact
    }
    if len(subject_paths) != len(arguments.artifact):
        raise ReleaseError("provenance subjects have duplicate basenames")
    subjects = sorted(
        (_subject(path, name) for name, path in subject_paths.items()),
        key=lambda item: item["name"],
    )
    if len({item["name"] for item in subjects}) != len(subjects):
        raise ReleaseError("provenance subjects have duplicate basenames")
    standard_materials = [
        root / "Cargo.lock",
        root / "pnpm-lock.yaml",
        root / "sdk/python/uv.lock",
        root / "sdk/go/go.sum",
    ]
    source_archive = arguments.source_archive.absolute()
    supplied_materials = [
        source_archive,
        *(path.absolute() for path in arguments.material),
    ]
    material_paths = {
        path.absolute() for path in (*standard_materials, *supplied_materials)
    }
    materials = []
    material_paths_by_name: dict[str, Path] = {}
    for path in sorted(material_paths, key=lambda item: item.as_posix()):
        if path == source_archive:
            name = path.name
        else:
            try:
                name = path.relative_to(root).as_posix()
            except ValueError:
                name = path.name
        material = _subject(path, name)
        if material["name"] in material_paths_by_name:
            raise ReleaseError("provenance materials have duplicate names")
        material_paths_by_name[material["name"]] = path
        materials.append(material)
    if len({item["name"] for item in materials}) != len(materials):
        raise ReleaseError("provenance materials have duplicate names")
    source_tree = sha256_bytes(canonical_json_bytes(materials))
    source = git_state(root, source_tree)
    if source["committed"] and source["revision"] != arguments.source_revision:
        raise ReleaseError(
            "explicit source revision disagrees with the checked-out revision"
        )
    invocation = hashlib.sha256(
        (
            arguments.builder_id
            + "\x00"
            + "\x00".join(arguments.command)
            + "\x00"
            + "".join(item["digest"]["sha256"] for item in subjects)
        ).encode("utf-8")
    ).hexdigest()
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://cigar.invalid/build-types/release-archive/v1",
                "externalParameters": {
                    "commands": arguments.command,
                    "sourceDateEpoch": epoch,
                    "sourceRevision": arguments.source_revision,
                    "sourceArchive": _subject(source_archive),
                    "workflowId": arguments.workflow_id,
                },
                "internalParameters": {
                    "network": arguments.network_mode,
                    "locale": "C",
                    "timezone": "UTC",
                },
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {"id": arguments.builder_id},
                "metadata": {
                    "invocationId": f"sha256:{invocation}",
                    "startedOnSourceDateEpoch": epoch,
                    "finishedOnSourceDateEpoch": epoch,
                },
            },
        },
    }
    output = ProvenanceOutput.open(
        arguments,
        root,
        [*arguments.artifact, *material_paths],
    )
    try:
        for subject in subjects:
            path = subject_paths[subject["name"]]
            if sha256_file(path) != subject["digest"]["sha256"]:
                raise ReleaseError(
                    f"provenance subject changed during generation: {path}"
                )
        for material in materials:
            path = material_paths_by_name[material["name"]]
            if sha256_file(path) != material["digest"]["sha256"]:
                raise ReleaseError(
                    f"provenance material changed during generation: {path}"
                )
        output.publish(provenance)
    finally:
        output.close()
    print(f"wrote provenance for {len(subjects)} artifact(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, ReleaseError) as error:
        raise SystemExit(f"provenance generation failed: {error}") from error
