#!/usr/bin/env python3
"""Build deterministic source-derived CIGAR archives."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any

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
    sha256_file,
    tree_digest,
    write_bytes,
    write_json,
)
from verify_package import verify as verify_package


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--manifest", default="packaging/local-archives.v1.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--require-committed-clean", action="store_true")
    parser.add_argument("--replace", action="store_true")
    return parser.parse_args()


def _validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "cigar.local-archives.v1":
        raise ReleaseError("unsupported local archive manifest")
    if not isinstance(manifest.get("archives"), list) or not manifest["archives"]:
        raise ReleaseError("local archive manifest has no archives")
    identifiers: set[str] = set()
    filenames: set[str] = set()
    for entry in manifest["archives"]:
        if not isinstance(entry, dict):
            raise ReleaseError("archive entry must be an object")
        identifier = entry.get("id")
        filename = entry.get("filename")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ReleaseError(f"invalid or duplicate archive id: {identifier!r}")
        if not isinstance(filename, str) or Path(filename).name != filename or filename in filenames:
            raise ReleaseError(f"invalid or duplicate archive filename: {filename!r}")
        if not isinstance(entry.get("include"), list) or not entry["include"]:
            raise ReleaseError(f"archive {identifier} has no include allowlist")
        identifiers.add(identifier)
        filenames.add(filename)
    if "source" not in identifiers:
        raise ReleaseError("local archive manifest must define source identity")


def _add_bytes(archive: tarfile.TarFile, relative: str, payload: bytes, epoch: int, mode: int) -> None:
    information = tarfile.TarInfo(relative)
    information.size = len(payload)
    information.mode = mode
    information.mtime = epoch
    information.uid = 0
    information.gid = 0
    information.uname = ""
    information.gname = ""
    archive.addfile(information, io.BytesIO(payload))


def _add_file(archive: tarfile.TarFile, relative: str, path: Path, epoch: int, mode: int) -> None:
    information = tarfile.TarInfo(relative)
    information.size = path.stat().st_size
    information.mode = mode
    information.mtime = epoch
    information.uid = 0
    information.gid = 0
    information.uname = ""
    information.gname = ""
    with path.open("rb") as handle:
        archive.addfile(information, handle)


def _write_archive(
    output: Path,
    files: list[tuple[str, Path]],
    metadata: dict[str, Any],
    epoch: int,
    replace: bool,
) -> None:
    if output.exists() and not replace:
        raise ReleaseError(f"refusing to replace existing archive without --replace: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    metadata_payload = canonical_json_bytes(metadata)
                    entries: list[tuple[str, Path | None, int]] = [("RELEASE-METADATA.json", None, 0o644)]
                    entries.extend((relative, path, normalized_mode(relative)) for relative, path in files)
                    for relative, path, mode in sorted(entries, key=lambda item: item[0].encode("utf-8")):
                        if path is None:
                            _add_bytes(archive, relative, metadata_payload, epoch, mode)
                        else:
                            _add_file(archive, relative, path, epoch, mode)
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
    root = arguments.root.resolve()
    manifest_path = resolve_beneath(root, arguments.manifest)
    manifest = load_json(manifest_path)
    _validate_manifest(manifest)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    excludes = manifest.get("always_exclude", [])
    if not isinstance(excludes, list) or not all(isinstance(value, str) for value in excludes):
        raise ReleaseError("always_exclude must contain strings")

    expanded: dict[str, list[tuple[str, Path]]] = {}
    for entry in manifest["archives"]:
        includes = entry["include"]
        if not all(isinstance(value, str) for value in includes):
            raise ReleaseError(f"archive {entry['id']} include patterns must be strings")
        files = expand_files(root, includes, excludes)
        if not files:
            raise ReleaseError(f"archive {entry['id']} expanded to no files")
        expanded[entry["id"]] = files

    source_tree_digest = tree_digest(expanded["source"])
    source = git_state(root, source_tree_digest)
    if arguments.require_committed_clean and (not source["committed"] or not source["clean"]):
        raise ReleaseError("release archive requires a committed, clean source tree")

    output_root = arguments.out.resolve()
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
            "input_tree_sha256": tree_digest(files),
            "input_file_count": len(files),
            "contract": entry["contract"],
            "contract_sha256": sha256_file(contract_path),
        }
        output = output_root / entry["filename"]
        _write_archive(output, files, metadata, epoch, arguments.replace)
        try:
            verify_package(output, contract_path, manifest["product_version"], manifest["context_abi"], epoch)
        except ReleaseError:
            output.unlink(missing_ok=True)
            raise
        build_records.append(
            {
                "id": entry["id"],
                "path": output.name,
                "sha256": sha256_file(output),
                "bytes": output.stat().st_size,
                "contract": entry["contract"],
            }
        )

    checksums_path = output_root / "SHA256SUMS"
    if checksums_path.exists() and not arguments.replace:
        raise ReleaseError(f"refusing to replace existing checksum manifest without --replace: {checksums_path}")
    checksum_payload = "".join(f"{record['sha256']}  {record['path']}\n" for record in sorted(build_records, key=lambda item: item["path"]))
    write_bytes(checksums_path, checksum_payload.encode("ascii"))
    build_manifest_path = output_root / "build-manifest.json"
    if build_manifest_path.exists() and not arguments.replace:
        raise ReleaseError(f"refusing to replace existing build manifest without --replace: {build_manifest_path}")
    write_json(
        build_manifest_path,
        {
            "schema_version": "cigar.local-archive-build.v1",
            "product_version": manifest["product_version"],
            "context_abi": manifest["context_abi"],
            "source_date_epoch": epoch,
            "source": source,
            "artifacts": sorted(build_records, key=lambda item: item["id"]),
        },
    )
    print(canonical_json_bytes(load_json(build_manifest_path)).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"release archive build failed: {error}") from error
