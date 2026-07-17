#!/usr/bin/env python3
"""Build deterministic source-derived CIGAR archives."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import stat
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    digest_secure_file,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    expand_files,
    git_state,
    load_json,
    normalized_mode,
    repo_root,
    require_source_date_epoch,
    resolve_beneath,
    safe_relative_path as safe_package_path,
    sha256_bytes,
    sha256_file,
    write_bytes,
    write_json,
)
from verify_package import verify as verify_package


MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 512 * 1024 * 1024
HONEY_MANIFEST_PATH = "packaging/honey/local-archives.v1.json"
HONEY_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
    HONEY_MANIFEST_PATH,
)
HONEY_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-honey\.[1-9][0-9]*\Z"
)


@dataclass(frozen=True)
class SourceSnapshot:
    """One immutable, stable-read source member used by every output archive."""

    relative: str
    payload: bytes
    mode: int


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--manifest", default="packaging/local-archives.v1.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external archive workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--require-committed-clean", action="store_true")
    parser.add_argument("--replace", action="store_true")
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


class ArchiveOutput:
    """Stage and publish an archive set to direct or protected external storage."""

    def __init__(
        self,
        *,
        output_root: Path,
        workspace: EvidenceWorkspace | None,
        prefix: str | None,
        temporary: tempfile.TemporaryDirectory[str] | None,
    ) -> None:
        self.output_root = output_root
        self.workspace = workspace
        self.prefix = prefix
        self.temporary = temporary

    @classmethod
    def open(
        cls, arguments: argparse.Namespace, *, repository_root: Path
    ) -> ArchiveOutput:
        selected = selected_evidence_directory(arguments)
        if selected is None:
            return cls(
                output_root=arguments.out.resolve(),
                workspace=None,
                prefix=None,
                temporary=None,
            )
        if arguments.replace:
            raise ReleaseError("--replace is forbidden for protected evidence output")
        try:
            parts = safe_evidence_path(os.fspath(arguments.out))
            workspace = EvidenceWorkspace.create(
                selected, repository_root=repository_root
            )
        except EvidenceWorkspaceError as error:
            raise ReleaseError(f"unsafe evidence workspace: {error}") from error
        temporary: tempfile.TemporaryDirectory[str] | None = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix="cigar-local-archives-")
            staging = Path(temporary.name).resolve(strict=True)
            # Archive staging contains unpublished release inputs and is owner-private.
            # 0700 is the intended least-privilege mode, not a permissive default.
            os.chmod(
                staging, 0o700
            )  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            return cls(
                output_root=staging,
                workspace=workspace,
                prefix="/".join(parts),
                temporary=temporary,
            )
        except BaseException:
            if temporary is not None:
                temporary.cleanup()
            workspace.close()
            raise

    def publish(self, names: list[str]) -> None:
        if self.workspace is None:
            return
        assert self.prefix is not None
        if not names or len(names) != len(set(names)):
            raise ReleaseError("archive publication inventory is empty or duplicated")
        aliases: set[str] = set()
        for name in names:
            parts = safe_evidence_path(name)
            if len(parts) != 1:
                raise ReleaseError(
                    f"archive publication name is not a basename: {name}"
                )
            alias = unicodedata.normalize("NFC", name).casefold()
            if alias in aliases:
                raise ReleaseError(
                    f"archive publication inventory has a portable collision: {name}"
                )
            aliases.add(alias)
        for name in names:
            source = self.output_root / name
            expected = digest_secure_file(source)
            attached = self.workspace.attach_file(
                source,
                f"{self.prefix}/{name}",
                read_only=True,
                expected_sha256=expected.sha256,
                expected_bytes=expected.bytes,
            )
            if attached.bytes != expected.bytes or attached.sha256 != expected.sha256:
                raise ReleaseError(f"published archive changed while copying: {name}")

    def close(self) -> None:
        if self.workspace is not None:
            self.workspace.close()
        if self.temporary is not None:
            self.temporary.cleanup()


def _validate_manifest(manifest: Any) -> None:
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "cigar.local-archives.v1"
    ):
        raise ReleaseError("unsupported local archive manifest")
    if not isinstance(manifest.get("archives"), list) or not manifest["archives"]:
        raise ReleaseError("local archive manifest has no archives")
    identifiers: set[str] = set()
    filenames: set[str] = set()
    portable_filenames: set[str] = set()
    for entry in manifest["archives"]:
        if not isinstance(entry, dict):
            raise ReleaseError("archive entry must be an object")
        identifier = entry.get("id")
        filename = entry.get("filename")
        try:
            safe_filename = (
                safe_package_path(filename) if isinstance(filename, str) else None
            )
        except ReleaseError as error:
            raise ReleaseError(f"invalid archive filename: {filename!r}") from error
        portable_filename = (
            unicodedata.normalize("NFC", filename).casefold()
            if isinstance(filename, str)
            else None
        )
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
        ):
            raise ReleaseError(f"invalid or duplicate archive id: {identifier!r}")
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or safe_filename != filename
            or filename in filenames
            or portable_filename in portable_filenames
        ):
            raise ReleaseError(f"invalid or duplicate archive filename: {filename!r}")
        if not isinstance(entry.get("include"), list) or not entry["include"]:
            raise ReleaseError(f"archive {identifier} has no include allowlist")
        identifiers.add(identifier)
        filenames.add(filename)
        assert portable_filename is not None
        portable_filenames.add(portable_filename)
    if "source" not in identifiers:
        raise ReleaseError("local archive manifest must define source identity")


def _add_bytes(
    archive: tarfile.TarFile, relative: str, payload: bytes, epoch: int, mode: int
) -> None:
    information = tarfile.TarInfo(relative)
    information.size = len(payload)
    information.mode = mode
    information.mtime = epoch
    information.uid = 0
    information.gid = 0
    information.uname = ""
    information.gname = ""
    archive.addfile(information, io.BytesIO(payload))


def _stable_source_bytes(path: Path, relative: str) -> bytes:
    """Read one bounded source file without following or racing a replaced path."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        path_before = path.stat(follow_symlinks=False)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(path_before, field) != getattr(before, field)
            for field in identity_fields
        ):
            raise ReleaseError(f"source path changed before snapshot: {relative}")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 0
            or before.st_size > MAX_SOURCE_FILE_BYTES
        ):
            raise ReleaseError(
                f"source member is not a bounded owner-controlled regular file: {relative}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_SOURCE_FILE_BYTES + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_FILE_BYTES:
                raise ReleaseError(f"source member exceeds the byte limit: {relative}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_after = path.stat(follow_symlinks=False)
        if any(
            getattr(before, field) != getattr(after, field)
            or getattr(before, field) != getattr(path_after, field)
            for field in identity_fields
        ):
            raise ReleaseError(f"source member changed while snapshotted: {relative}")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise ReleaseError(f"source member changed length while read: {relative}")
        return payload
    except OSError as error:
        raise ReleaseError(
            f"cannot securely snapshot source member {relative}: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _honey_authority(
    root: Path, manifest: dict[str, Any]
) -> dict[str, dict[str, object]]:
    contract_paths = tuple(entry["contract"] for entry in manifest["archives"])
    paths = (*HONEY_AUTHORITY_PATHS, *contract_paths)
    if len(paths) != len(set(paths)):
        raise ReleaseError("Honey portable authority inventory is duplicated")
    authority: dict[str, dict[str, object]] = {}
    for relative in paths:
        path = resolve_beneath(root, relative)
        payload = _stable_source_bytes(path, relative)
        authority[relative] = {
            "sha256": sha256_bytes(payload),
            "bytes": len(payload),
        }
    return authority


def _snapshot_expanded_files(
    expanded: dict[str, list[tuple[str, Path]]],
) -> tuple[dict[str, list[SourceSnapshot]], dict[str, Path], dict[str, bytes]]:
    """Freeze every unique expanded member once and share it across archives."""

    paths: dict[str, Path] = {}
    for files in expanded.values():
        for relative, path in files:
            previous = paths.setdefault(relative, path)
            if previous != path:
                raise ReleaseError(f"expanded source path is ambiguous: {relative}")
    payloads: dict[str, bytes] = {}
    total = 0
    for relative in sorted(paths, key=lambda value: value.encode("utf-8")):
        payload = _stable_source_bytes(paths[relative], relative)
        total += len(payload)
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise ReleaseError("source snapshot exceeds the aggregate byte limit")
        payloads[relative] = payload
    snapshots = {
        identifier: [
            SourceSnapshot(
                relative=relative,
                payload=payloads[relative],
                mode=normalized_mode(relative),
            )
            for relative, _path in files
        ]
        for identifier, files in expanded.items()
    }
    return snapshots, paths, payloads


def _snapshot_tree_digest(files: list[SourceSnapshot]) -> str:
    digest = hashlib.sha256()
    for entry in files:
        digest.update(entry.relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(len(entry.payload)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(f"{entry.mode:04o}".encode("ascii"))
        digest.update(b"\x00")
        digest.update(bytes.fromhex(sha256_bytes(entry.payload)))
        digest.update(b"\n")
    return digest.hexdigest()


def _verify_source_snapshot(paths: dict[str, Path], payloads: dict[str, bytes]) -> None:
    for relative in sorted(paths, key=lambda value: value.encode("utf-8")):
        if _stable_source_bytes(paths[relative], relative) != payloads[relative]:
            raise ReleaseError(f"source member changed after snapshot: {relative}")


def _write_archive(
    output: Path,
    files: list[SourceSnapshot],
    metadata: dict[str, Any],
    epoch: int,
    replace: bool,
) -> None:
    if output.exists() and not replace:
        raise ReleaseError(
            f"refusing to replace existing archive without --replace: {output}"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output.parent, prefix=f".{output.name}.", delete=False
        ) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    metadata_payload = canonical_json_bytes(metadata)
                    entries: list[tuple[str, bytes, int]] = [
                        ("RELEASE-METADATA.json", metadata_payload, 0o644)
                    ]
                    entries.extend(
                        (entry.relative, entry.payload, entry.mode) for entry in files
                    )
                    for relative, payload, mode in sorted(
                        entries, key=lambda item: item[0].encode("utf-8")
                    ):
                        _add_bytes(archive, relative, payload, epoch, mode)
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve(strict=True)
    output = ArchiveOutput.open(arguments, repository_root=root)
    try:
        return _build(arguments, root=root, output=output)
    finally:
        output.close()


def _build(arguments: argparse.Namespace, *, root: Path, output: ArchiveOutput) -> int:
    manifest_path = resolve_beneath(root, arguments.manifest)
    manifest = load_json(manifest_path)
    _validate_manifest(manifest)
    honey = (
        isinstance(manifest.get("product_version"), str)
        and HONEY_VERSION.fullmatch(manifest["product_version"]) is not None
    )
    if honey and manifest_path != resolve_beneath(root, HONEY_MANIFEST_PATH):
        raise ReleaseError(
            "Honey portable builds require the exact Honey archive manifest authority"
        )
    if honey and not arguments.require_committed_clean:
        raise ReleaseError("Honey portable builds require --require-committed-clean")
    authority = _honey_authority(root, manifest) if honey else None
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    excludes = manifest.get("always_exclude", [])
    if not isinstance(excludes, list) or not all(
        isinstance(value, str) for value in excludes
    ):
        raise ReleaseError("always_exclude must contain strings")

    expanded_paths: dict[str, list[tuple[str, Path]]] = {}
    for entry in manifest["archives"]:
        includes = entry["include"]
        if not all(isinstance(value, str) for value in includes):
            raise ReleaseError(
                f"archive {entry['id']} include patterns must be strings"
            )
        files = expand_files(root, includes, excludes)
        if not files:
            raise ReleaseError(f"archive {entry['id']} expanded to no files")
        expanded_paths[entry["id"]] = files

    expanded, snapshot_paths, snapshot_payloads = _snapshot_expanded_files(
        expanded_paths
    )
    source_tree_digest = _snapshot_tree_digest(expanded["source"])
    source = git_state(root, source_tree_digest)
    if (arguments.require_committed_clean or honey) and (
        not source["committed"] or not source["clean"]
    ):
        raise ReleaseError("release archive requires a committed, clean source tree")

    output_root = output.output_root
    output_root.mkdir(parents=True, exist_ok=True)
    build_records: list[dict[str, Any]] = []
    for entry in manifest["archives"]:
        contract_path = resolve_beneath(root, entry["contract"])
        files = expanded[entry["id"]]
        metadata = {
            "schema_version": "cigar.release-metadata.v1",
            "artifact_id": entry["id"],
            "product_version": manifest["product_version"],
            "context_abi": manifest["context_abi"],
            "source_date_epoch": epoch,
            "source": source,
            "input_tree_sha256": _snapshot_tree_digest(files),
            "input_file_count": len(files),
            "contract": entry["contract"],
            "contract_sha256": sha256_file(contract_path),
        }
        archive_path = output_root / entry["filename"]
        _write_archive(archive_path, files, metadata, epoch, arguments.replace)
        try:
            verify_package(
                archive_path,
                contract_path,
                manifest["product_version"],
                manifest["context_abi"],
                epoch,
            )
        except ReleaseError:
            archive_path.unlink(missing_ok=True)
            raise
        build_records.append(
            {
                "id": entry["id"],
                "path": archive_path.name,
                "sha256": sha256_file(archive_path),
                "bytes": archive_path.stat().st_size,
                "contract": entry["contract"],
            }
        )

    try:
        _verify_source_snapshot(snapshot_paths, snapshot_payloads)
        if authority is not None and _honey_authority(root, manifest) != authority:
            raise ReleaseError("Honey portable authority changed during construction")
    except ReleaseError:
        for record in build_records:
            (output_root / record["path"]).unlink(missing_ok=True)
        raise

    checksums_path = output_root / "SHA256SUMS"
    if checksums_path.exists() and not arguments.replace:
        raise ReleaseError(
            f"refusing to replace existing checksum manifest without --replace: {checksums_path}"
        )
    checksum_payload = "".join(
        f"{record['sha256']}  {record['path']}\n"
        for record in sorted(build_records, key=lambda item: item["path"])
    )
    write_bytes(checksums_path, checksum_payload.encode("ascii"))
    build_manifest_path = output_root / "build-manifest.json"
    if build_manifest_path.exists() and not arguments.replace:
        raise ReleaseError(
            f"refusing to replace existing build manifest without --replace: {build_manifest_path}"
        )
    build_manifest = {
        "schema_version": "cigar.local-archive-build.v1",
        "product_version": manifest["product_version"],
        "context_abi": manifest["context_abi"],
        "source_date_epoch": epoch,
        "source": source,
        "artifacts": sorted(build_records, key=lambda item: item["id"]),
        **({"authority": authority} if authority is not None else {}),
    }
    write_json(build_manifest_path, build_manifest)
    output.publish(
        [
            *[record["path"] for record in build_records],
            checksums_path.name,
            build_manifest_path.name,
        ]
    )
    print(canonical_json_bytes(build_manifest).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, OSError, ReleaseError) as error:
        raise SystemExit(f"release archive build failed: {error}") from error
