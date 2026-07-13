#!/usr/bin/env python3
"""Validate an archive against an exact CIGAR package contract without extracting it."""

from __future__ import annotations

import argparse
import calendar
import gzip
import hashlib
import re
import stat
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import Any, IO

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    matches,
    require_distinct_output,
    safe_relative_path,
    scan_payload,
    sha256_file,
    write_json,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-abi")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def _archive_format(path: Path) -> str:
    name = path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".crate")):
        return "tar.gz"
    if name.endswith(".tar"):
        return "tar"
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith(".zip"):
        return "zip"
    raise ReleaseError(f"unsupported archive extension: {path.name}")


_READ_CHUNK_BYTES = 1024 * 1024
_SCAN_OVERLAP_BYTES = 1024
_MAX_RETAINED_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_RETAINED_TOTAL_BYTES = 32 * 1024 * 1024
_OCI_JSON_LIMIT_BYTES = 16 * 1024 * 1024
_TEXT_SUFFIXES = {
    ".bash",
    ".c",
    ".cc",
    ".cmd",
    ".conf",
    ".cpp",
    ".css",
    ".fish",
    ".go",
    ".h",
    ".html",
    ".csv",
    ".graphql",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".mjs",
    ".mod",
    ".proto",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".sql",
    ".sum",
    ".svg",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}
_TEXT_NAMES = {
    ".dockerignore",
    ".gitignore",
    ".npmignore",
    "Dockerfile",
    "LICENSE",
    "Makefile",
    "NOTICE",
    "README",
    "SHA256SUMS",
    "justfile",
}


def _validate_contract(contract: Any) -> dict[str, Any]:
    required_keys = {
        "schema_version",
        "id",
        "formats",
        "allow",
        "deny",
        "required",
        "symlinks",
        "line_endings",
        "modes",
        "max_entries",
        "max_member_bytes",
        "max_total_bytes",
        "content_scan",
        "content_scan_exemptions",
    }
    optional_keys = {
        "required_any",
        "required_patterns",
        "version_binding",
        "abi_binding",
        "checksum_manifest",
        "max_layer_uncompressed_bytes",
    }
    if (
        not isinstance(contract, dict)
        or not required_keys.issubset(contract)
        or not set(contract).issubset(required_keys | optional_keys)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or not isinstance(contract.get("id"), str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]*-v1", contract["id"]) is None
    ):
        raise ReleaseError("package contract has an unexpected shape or identity")

    def string_list(name: str, *, nonempty: bool = False) -> list[str]:
        value = contract.get(name)
        if (
            not isinstance(value, list)
            or (nonempty and not value)
            or not all(
                isinstance(item, str)
                and item
                and len(item.encode("utf-8")) <= 4096
                and not any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in item
                )
                for item in value
            )
            or len(set(value)) != len(value)
        ):
            raise ReleaseError(f"package contract {name} list is invalid")
        return value

    formats = string_list("formats", nonempty=True)
    if not set(formats).issubset({"tar", "tar.gz", "zip", "wheel"}):
        raise ReleaseError("package contract formats are invalid")
    string_list("allow", nonempty=True)
    string_list("deny")
    string_list("required")
    if "required_patterns" in contract:
        string_list("required_patterns")
    required_any = contract.get("required_any", [])
    if not isinstance(required_any, list):
        raise ReleaseError("package contract required-any groups are invalid")
    for group in required_any:
        if (
            not isinstance(group, list)
            or not group
            or not all(isinstance(value, str) and value for value in group)
            or len(set(group)) != len(group)
        ):
            raise ReleaseError("package contract required-any group is invalid")
    modes = string_list("modes", nonempty=True)
    if not set(modes).issubset({"0644", "0755"}):
        raise ReleaseError("package contract modes are invalid")
    limits = [
        contract.get(name)
        for name in ("max_entries", "max_member_bytes", "max_total_bytes")
    ]
    if (
        not all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in limits
        )
        or contract["max_entries"] > 1_000_000
        or contract["max_member_bytes"] > contract["max_total_bytes"]
    ):
        raise ReleaseError("package contract resource limits are invalid")
    layer_limit = contract.get("max_layer_uncompressed_bytes")
    if contract["id"] == "oci-image-v1":
        if (
            not isinstance(layer_limit, int)
            or isinstance(layer_limit, bool)
            or layer_limit <= 0
        ):
            raise ReleaseError(
                "OCI package contract has no valid uncompressed-layer limit"
            )
    elif layer_limit is not None:
        raise ReleaseError("non-OCI package contract declares an OCI layer limit")
    if (
        contract.get("symlinks") != "forbid"
        or contract.get("line_endings") != "lf"
        or contract.get("content_scan") is not True
    ):
        raise ReleaseError("package contract weakens a mandatory content policy")
    exemptions = contract.get("content_scan_exemptions")
    if not isinstance(exemptions, list) or any(
        not isinstance(entry, dict)
        or set(entry) != {"pattern", "reason"}
        or not all(isinstance(value, str) and value for value in entry.values())
        for entry in exemptions
    ):
        raise ReleaseError("package contract content-scan exemptions are invalid")
    for binding_name in ("version_binding", "abi_binding"):
        if binding_name not in contract:
            continue
        binding = contract[binding_name]
        if (
            not isinstance(binding, dict)
            or set(binding) != {"path_pattern", "format", "json_pointer"}
            or not isinstance(binding.get("path_pattern"), str)
            or not binding["path_pattern"]
            or binding.get("format") != "json"
            or not isinstance(binding.get("json_pointer"), str)
            or not binding["json_pointer"].startswith("/")
        ):
            raise ReleaseError(f"package contract {binding_name} is invalid")
    checksum_manifest = contract.get("checksum_manifest")
    if checksum_manifest is not None:
        if (
            not isinstance(checksum_manifest, dict)
            or set(checksum_manifest) != {"path", "scope"}
            or not isinstance(checksum_manifest.get("path"), str)
            or checksum_manifest["path"] not in contract["required"]
            or checksum_manifest.get("scope") != "all-payload-files"
        ):
            raise ReleaseError("package contract checksum manifest binding is invalid")
        safe_relative_path(checksum_manifest["path"])
    return contract


def _binding_value(payloads: dict[str, bytes | None], binding: Any, label: str) -> Any:
    if not isinstance(binding, dict) or set(binding) != {
        "path_pattern",
        "format",
        "json_pointer",
    }:
        raise ReleaseError(f"invalid {label} binding")
    if (
        binding["format"] != "json"
        or not isinstance(binding["path_pattern"], str)
        or not isinstance(binding["json_pointer"], str)
    ):
        raise ReleaseError(f"invalid {label} binding")
    candidates = [name for name in payloads if matches(name, [binding["path_pattern"]])]
    if len(candidates) != 1:
        raise ReleaseError(f"{label} binding matched {len(candidates)} files")
    payload = payloads[candidates[0]]
    if payload is None:
        raise ReleaseError(f"{label} binding payload exceeds the bounded metadata size")
    value = load_json_bytes(payload, candidates[0])
    for encoded in binding["json_pointer"].removeprefix("/").split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            raise ReleaseError(f"{label} JSON pointer is missing")
    return value


def _validate_checksum_manifest(
    payloads: dict[str, bytes | None],
    attributes: dict[str, dict[str, Any]],
    specification: dict[str, str],
) -> None:
    manifest_path = specification["path"]
    payload = payloads.get(manifest_path)
    if payload is None:
        raise ReleaseError(
            "internal checksum manifest is missing or exceeds the metadata size limit"
        )
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ReleaseError("internal checksum manifest is not ASCII") from error
    if not lines:
        raise ReleaseError("internal checksum manifest is empty")
    observed: dict[str, str] = {}
    observed_order: list[str] = []
    for number, line in enumerate(lines, 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None:
            raise ReleaseError(f"internal checksum manifest line {number} is invalid")
        relative = safe_relative_path(fields[1])
        if relative in observed or relative in {manifest_path, "RELEASE-METADATA.json"}:
            raise ReleaseError(
                f"internal checksum manifest path is duplicate or forbidden: {relative}"
            )
        attribute = attributes.get(relative)
        if not isinstance(attribute, dict) or attribute.get("kind") != "file":
            raise ReleaseError(
                f"internal checksum manifest references a missing regular file: {relative}"
            )
        if attribute.get("sha256") != fields[0]:
            raise ReleaseError(
                f"internal checksum manifest digest mismatch: {relative}"
            )
        observed[relative] = fields[0]
        observed_order.append(relative)
    expected_paths = {
        name
        for name, attribute in attributes.items()
        if attribute.get("kind") == "file"
        and name not in {manifest_path, "RELEASE-METADATA.json"}
    }
    if not expected_paths or set(observed) != expected_paths:
        raise ReleaseError(
            f"internal checksum manifest inventory mismatch; missing={sorted(expected_paths - set(observed))}, "
            f"extra={sorted(set(observed) - expected_paths)}"
        )
    if observed_order != sorted(
        observed_order, key=lambda value: value.encode("utf-8")
    ):
        raise ReleaseError(
            "internal checksum manifest paths are not in deterministic UTF-8 byte order"
        )


def _inspect_payload(
    handle: IO[bytes],
    expected_size: int,
    name: str,
    retained_patterns: list[str],
    content_scan: bool,
    exemptions: list[dict[str, str]],
) -> tuple[bytes | None, str, bool, list[str]]:
    retain = matches(name, retained_patterns)
    if retain and expected_size > _MAX_RETAINED_MEMBER_BYTES:
        raise ReleaseError(
            f"metadata-bearing archive member exceeds {_MAX_RETAINED_MEMBER_BYTES} bytes: {name}"
        )
    retained = bytearray() if retain else None
    digest = hashlib.sha256()
    findings: set[str] = set()
    contains_carriage_return = False
    tail = b""
    observed = 0
    while True:
        chunk = handle.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        observed += len(chunk)
        if observed > expected_size:
            raise ReleaseError(f"archive member is extended: {name}")
        digest.update(chunk)
        if retained is not None:
            retained.extend(chunk)
        contains_carriage_return = contains_carriage_return or b"\r" in chunk
        if content_scan:
            window = tail + chunk
            findings.update(scan_payload(name, window, exemptions))
            tail = window[-_SCAN_OVERLAP_BYTES:]
    if observed != expected_size:
        raise ReleaseError(f"archive member is truncated: {name}")
    return (
        bytes(retained) if retained is not None else None,
        digest.hexdigest(),
        contains_carriage_return,
        sorted(findings),
    )


def _read_tar(
    path: Path,
    max_entries: int,
    max_member: int,
    max_total: int,
    retained_patterns: list[str],
    content_scan: bool,
    exemptions: list[dict[str, str]],
) -> tuple[dict[str, bytes | None], dict[str, dict[str, Any]]]:
    payloads: dict[str, bytes | None] = {}
    attributes: dict[str, dict[str, Any]] = {}
    portable_names: dict[str, str] = {}
    total = 0
    retained_total = 0
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                if len(attributes) >= max_entries:
                    raise ReleaseError("archive entry count exceeds contract limit")
                name = member.name.rstrip("/") if member.isdir() else member.name
                name = safe_relative_path(name)
                if name in attributes:
                    raise ReleaseError(f"duplicate archive member: {name}")
                portable_key = name.casefold()
                if portable_key in portable_names:
                    raise ReleaseError(
                        f"archive members collide on a supported case-insensitive filesystem: "
                        f"{portable_names[portable_key]} and {name}"
                    )
                portable_names[portable_key] = name
                if member.issym() or member.islnk():
                    raise ReleaseError(f"archive links are forbidden: {name}")
                if member.isdir():
                    attributes[name] = {
                        "kind": "directory",
                        "mode": member.mode,
                        "mtime": member.mtime,
                        "uid": member.uid,
                        "gid": member.gid,
                    }
                    continue
                if not member.isfile():
                    raise ReleaseError(f"archive member is not a regular file: {name}")
                if member.size < 0 or member.size > max_member:
                    raise ReleaseError(f"archive member exceeds size limit: {name}")
                total += member.size
                if total > max_total:
                    raise ReleaseError("archive expanded size exceeds contract limit")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseError(f"cannot read archive member: {name}")
                with handle:
                    payload, digest, contains_cr, content_findings = _inspect_payload(
                        handle,
                        member.size,
                        name,
                        retained_patterns,
                        content_scan,
                        exemptions,
                    )
                if payload is not None:
                    retained_total += len(payload)
                    if retained_total > _MAX_RETAINED_TOTAL_BYTES:
                        raise ReleaseError(
                            "archive metadata payloads exceed the bounded retention limit"
                        )
                payloads[name] = payload
                attributes[name] = {
                    "kind": "file",
                    "mode": member.mode,
                    "mtime": member.mtime,
                    "uid": member.uid,
                    "gid": member.gid,
                    "size": member.size,
                    "sha256": digest,
                    "contains_cr": contains_cr,
                    "content_findings": content_findings,
                }
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError(f"cannot read tar archive {path}: {error}") from error
    return payloads, attributes


def _read_zip(
    path: Path,
    max_entries: int,
    max_member: int,
    max_total: int,
    retained_patterns: list[str],
    content_scan: bool,
    exemptions: list[dict[str, str]],
) -> tuple[dict[str, bytes | None], dict[str, dict[str, Any]]]:
    payloads: dict[str, bytes | None] = {}
    attributes: dict[str, dict[str, Any]] = {}
    portable_names: dict[str, str] = {}
    total = 0
    retained_total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if len(attributes) >= max_entries:
                    raise ReleaseError("archive entry count exceeds contract limit")
                name = (
                    member.filename.rstrip("/") if member.is_dir() else member.filename
                )
                name = safe_relative_path(name)
                if name in attributes:
                    raise ReleaseError(f"duplicate archive member: {name}")
                portable_key = name.casefold()
                if portable_key in portable_names:
                    raise ReleaseError(
                        f"archive members collide on a supported case-insensitive filesystem: "
                        f"{portable_names[portable_key]} and {name}"
                    )
                portable_names[portable_key] = name
                mode = (member.external_attr >> 16) & 0o7777
                kind_bits = (member.external_attr >> 16) & 0o170000
                if kind_bits == stat.S_IFLNK:
                    raise ReleaseError(f"archive links are forbidden: {name}")
                if member.is_dir():
                    attributes[name] = {
                        "kind": "directory",
                        "mode": mode or 0o755,
                        "mtime": calendar.timegm((*member.date_time, 0, 0, 0)),
                    }
                    continue
                if kind_bits not in {0, stat.S_IFREG}:
                    raise ReleaseError(f"archive member is not a regular file: {name}")
                if member.file_size < 0 or member.file_size > max_member:
                    raise ReleaseError(f"archive member exceeds size limit: {name}")
                total += member.file_size
                if total > max_total:
                    raise ReleaseError("archive expanded size exceeds contract limit")
                with archive.open(member) as handle:
                    payload, digest, contains_cr, content_findings = _inspect_payload(
                        handle,
                        member.file_size,
                        name,
                        retained_patterns,
                        content_scan,
                        exemptions,
                    )
                if payload is not None:
                    retained_total += len(payload)
                    if retained_total > _MAX_RETAINED_TOTAL_BYTES:
                        raise ReleaseError(
                            "archive metadata payloads exceed the bounded retention limit"
                        )
                payloads[name] = payload
                attributes[name] = {
                    "kind": "file",
                    "mode": mode or 0o644,
                    "mtime": calendar.timegm((*member.date_time, 0, 0, 0)),
                    "size": member.file_size,
                    "sha256": digest,
                    "contains_cr": contains_cr,
                    "content_findings": content_findings,
                }
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ReleaseError(f"cannot read zip archive {path}: {error}") from error
    return payloads, attributes


def _read_tar_member_bytes(path: Path, name: str, expected_size: int) -> bytes:
    if expected_size < 0 or expected_size > _OCI_JSON_LIMIT_BYTES:
        raise ReleaseError(f"OCI JSON descriptor payload is too large: {name}")
    try:
        with tarfile.open(path, mode="r:*") as archive:
            member = archive.getmember(name)
            if not member.isfile() or member.size != expected_size:
                raise ReleaseError(
                    f"OCI descriptor payload is not the expected regular file: {name}"
                )
            handle = archive.extractfile(member)
            if handle is None:
                raise ReleaseError(f"cannot read OCI descriptor payload: {name}")
            with handle:
                payload = handle.read(expected_size + 1)
            if len(payload) != expected_size:
                raise ReleaseError(
                    f"OCI descriptor payload is truncated or extended: {name}"
                )
            return payload
    except (KeyError, OSError, tarfile.TarError) as error:
        raise ReleaseError(
            f"cannot read OCI descriptor payload {name}: {error}"
        ) from error


def _oci_descriptor(
    archive_path: Path,
    descriptor: Any,
    attributes: dict[str, dict[str, Any]],
    label: str,
    expected_media_type: str | set[str],
    *,
    parse_json: bool = True,
) -> tuple[str, dict[str, Any] | None]:
    if not isinstance(descriptor, dict):
        raise ReleaseError(f"OCI {label} descriptor is not an object")
    required = {"mediaType", "digest", "size"}
    allowed = required | {"annotations", "platform"}
    if not required.issubset(descriptor) or not set(descriptor).issubset(allowed):
        raise ReleaseError(f"OCI {label} descriptor has an unexpected shape")
    media_type = descriptor.get("mediaType")
    permitted = (
        {expected_media_type}
        if isinstance(expected_media_type, str)
        else expected_media_type
    )
    if media_type not in permitted:
        raise ReleaseError(
            f"OCI {label} descriptor has unsupported media type: {media_type}"
        )
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ReleaseError(f"OCI {label} descriptor digest is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ReleaseError(f"OCI {label} descriptor size is invalid")
    hexadecimal = digest.removeprefix("sha256:")
    blob_name = f"blobs/sha256/{hexadecimal}"
    attribute = attributes.get(blob_name)
    if (
        not isinstance(attribute, dict)
        or attribute.get("kind") != "file"
        or attribute.get("size") != size
        or attribute.get("sha256") != hexadecimal
    ):
        raise ReleaseError(
            f"OCI {label} descriptor does not match its blob: {blob_name}"
        )
    if not parse_json:
        return blob_name, None
    document = load_json_bytes(
        _read_tar_member_bytes(archive_path, blob_name, size), f"OCI {label} blob"
    )
    if not isinstance(document, dict):
        raise ReleaseError(f"OCI {label} blob is not a JSON object")
    return blob_name, document


def _oci_layer_diff_id(
    archive_path: Path,
    blob_name: str,
    compressed_size: int,
    maximum_uncompressed_bytes: int,
) -> str:
    digest = hashlib.sha256()
    observed = 0
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            member = archive.getmember(blob_name)
            if not member.isfile() or member.size != compressed_size:
                raise ReleaseError(
                    f"OCI layer is not the expected regular blob: {blob_name}"
                )
            handle = archive.extractfile(member)
            if handle is None:
                raise ReleaseError(f"cannot read OCI layer blob: {blob_name}")
            with handle, gzip.GzipFile(fileobj=handle, mode="rb") as decompressed:
                while chunk := decompressed.read(_READ_CHUNK_BYTES):
                    observed += len(chunk)
                    if observed > maximum_uncompressed_bytes:
                        raise ReleaseError(
                            f"OCI layer exceeds the uncompressed size limit of {maximum_uncompressed_bytes} bytes: {blob_name}"
                        )
                    digest.update(chunk)
    except (
        EOFError,
        gzip.BadGzipFile,
        KeyError,
        OSError,
        tarfile.TarError,
        zlib.error,
    ) as error:
        raise ReleaseError(
            f"cannot decompress OCI layer {blob_name}: {error}"
        ) from error
    return f"sha256:{digest.hexdigest()}"


def _validate_oci_layer_tar(
    archive_path: Path,
    blob_name: str,
    compressed_size: int,
    maximum_entries: int,
    maximum_member_bytes: int,
    maximum_uncompressed_bytes: int,
    allowed_modes: set[int],
    content_scan_exemptions: list[dict[str, str]],
) -> None:
    names: set[str] = set()
    portable_names: dict[str, str] = {}
    expanded_member_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            member = archive.getmember(blob_name)
            if not member.isfile() or member.size != compressed_size:
                raise ReleaseError(
                    f"OCI layer is not the expected regular blob: {blob_name}"
                )
            handle = archive.extractfile(member)
            if handle is None:
                raise ReleaseError(f"cannot read OCI layer blob: {blob_name}")
            with handle, gzip.GzipFile(fileobj=handle, mode="rb") as decompressed:
                with tarfile.open(fileobj=decompressed, mode="r|") as layer_archive:
                    for layer_member in layer_archive:
                        if len(names) >= maximum_entries:
                            raise ReleaseError(
                                f"OCI layer entry count exceeds the contract limit: {blob_name}"
                            )
                        name = (
                            layer_member.name.rstrip("/")
                            if layer_member.isdir()
                            else layer_member.name
                        )
                        name = safe_relative_path(name)
                        if name in names:
                            raise ReleaseError(
                                f"OCI layer contains a duplicate path: {name}"
                            )
                        names.add(name)
                        portable_key = name.casefold()
                        if portable_key in portable_names:
                            raise ReleaseError(
                                f"OCI layer paths collide on a supported case-insensitive filesystem: "
                                f"{portable_names[portable_key]} and {name}"
                            )
                        portable_names[portable_key] = name
                        if layer_member.issym() or layer_member.islnk():
                            raise ReleaseError(f"OCI layer links are forbidden: {name}")
                        if not layer_member.isfile() and not layer_member.isdir():
                            raise ReleaseError(
                                f"OCI layer entry is not a regular file or directory: {name}"
                            )
                        if layer_member.uid != 0 or layer_member.gid != 0:
                            raise ReleaseError(
                                f"OCI layer entry has a nonzero owner: {name}"
                            )
                        if layer_member.isdir():
                            if layer_member.mode != 0o755:
                                raise ReleaseError(
                                    f"OCI layer directory mode is not 0755: {name}"
                                )
                            continue
                        if layer_member.mode not in allowed_modes:
                            raise ReleaseError(
                                f"OCI layer file mode is not allowlisted: {name}"
                            )
                        if (
                            layer_member.size < 0
                            or layer_member.size > maximum_member_bytes
                        ):
                            raise ReleaseError(
                                f"OCI layer member exceeds the contract size limit: {name}"
                            )
                        expanded_member_bytes += layer_member.size
                        if expanded_member_bytes > maximum_uncompressed_bytes:
                            raise ReleaseError(
                                f"OCI layer members exceed the uncompressed size limit: {blob_name}"
                            )
                        layer_handle = layer_archive.extractfile(layer_member)
                        if layer_handle is None:
                            raise ReleaseError(f"cannot read OCI layer member: {name}")
                        with layer_handle:
                            _, _, contains_cr, content_findings = _inspect_payload(
                                layer_handle,
                                layer_member.size,
                                name,
                                [],
                                True,
                                content_scan_exemptions,
                            )
                        if content_findings:
                            raise ReleaseError(
                                f"OCI layer member failed content scan ({', '.join(content_findings)}): {name}"
                            )
                        if (
                            Path(name).suffix.lower() in _TEXT_SUFFIXES
                            or Path(name).name in _TEXT_NAMES
                        ) and contains_cr:
                            raise ReleaseError(
                                f"OCI layer text member has non-LF line endings: {name}"
                            )
    except (
        EOFError,
        gzip.BadGzipFile,
        KeyError,
        OSError,
        tarfile.TarError,
        zlib.error,
    ) as error:
        raise ReleaseError(
            f"cannot inspect OCI layer tar {blob_name}: {error}"
        ) from error


def _validate_oci_layout(
    archive_path: Path,
    payloads: dict[str, bytes | None],
    attributes: dict[str, dict[str, Any]],
    expected_version: str | None,
    expected_abi: str | None,
    maximum_layer_uncompressed_bytes: int,
    maximum_entries: int,
    maximum_member_bytes: int,
    allowed_modes: set[int],
    content_scan_exemptions: list[dict[str, str]],
) -> dict[str, Any]:
    layout_payload = payloads.get("oci-layout")
    index_payload = payloads.get("index.json")
    if layout_payload is None or index_payload is None:
        raise ReleaseError("OCI layout and index must be bounded JSON payloads")
    layout = load_json_bytes(layout_payload, "oci-layout")
    index = load_json_bytes(index_payload, "OCI index")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ReleaseError("OCI layout version document is invalid")
    if (
        not isinstance(index, dict)
        or not {"schemaVersion", "mediaType", "manifests"}.issubset(index)
        or not set(index).issubset(
            {"schemaVersion", "mediaType", "manifests", "annotations"}
        )
    ):
        raise ReleaseError("OCI index has an unexpected shape")
    if (
        index.get("schemaVersion") != 2
        or index.get("mediaType") != "application/vnd.oci.image.index.v1+json"
    ):
        raise ReleaseError("OCI index identity is invalid")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 2:
        raise ReleaseError(
            "OCI index must contain exactly linux/amd64 and linux/arm64 manifests"
        )
    expected_platforms = {("linux", "amd64"), ("linux", "arm64")}
    observed_platforms: set[tuple[str, str]] = set()
    referenced_blobs: set[str] = set()
    layer_diff_ids: dict[str, str] = {}
    validated_layer_tars: set[str] = set()
    layer_media_types = {
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    }
    for descriptor in manifests:
        platform_value = (
            descriptor.get("platform") if isinstance(descriptor, dict) else None
        )
        if not isinstance(platform_value, dict) or set(platform_value) != {
            "os",
            "architecture",
        }:
            raise ReleaseError("OCI manifest platform descriptor is invalid")
        platform_os = platform_value.get("os")
        platform_architecture = platform_value.get("architecture")
        if not isinstance(platform_os, str) or not isinstance(
            platform_architecture, str
        ):
            raise ReleaseError("OCI manifest platform values must be strings")
        platform_key = (platform_os, platform_architecture)
        if platform_key not in expected_platforms or platform_key in observed_platforms:
            raise ReleaseError(
                f"OCI manifest platform is missing, duplicated, or unsupported: {platform_key}"
            )
        observed_platforms.add(platform_key)
        annotations = descriptor.get("annotations")
        if not isinstance(annotations, dict):
            raise ReleaseError("OCI manifest descriptor annotations are missing")
        if (
            expected_version is not None
            and annotations.get("org.opencontainers.image.version") != expected_version
        ):
            raise ReleaseError(
                f"OCI manifest version annotation mismatch: {platform_key}"
            )
        if (
            expected_abi is not None
            and annotations.get("dev.cigar.context-abi") != expected_abi
        ):
            raise ReleaseError(
                f"OCI manifest Context ABI annotation mismatch: {platform_key}"
            )
        manifest_blob, manifest = _oci_descriptor(
            archive_path,
            descriptor,
            attributes,
            f"manifest {platform_key[0]}/{platform_key[1]}",
            "application/vnd.oci.image.manifest.v1+json",
        )
        referenced_blobs.add(manifest_blob)
        if not isinstance(manifest, dict):
            raise ReleaseError(f"OCI manifest blob is invalid: {platform_key}")
        if not {"schemaVersion", "mediaType", "config", "layers"}.issubset(
            manifest
        ) or not set(manifest).issubset(
            {"schemaVersion", "mediaType", "config", "layers", "annotations"}
        ):
            raise ReleaseError(f"OCI manifest has an unexpected shape: {platform_key}")
        if (
            manifest.get("schemaVersion") != 2
            or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
        ):
            raise ReleaseError(f"OCI manifest identity is invalid: {platform_key}")
        config_blob, config = _oci_descriptor(
            archive_path,
            manifest.get("config"),
            attributes,
            f"config {platform_key[0]}/{platform_key[1]}",
            "application/vnd.oci.image.config.v1+json",
        )
        referenced_blobs.add(config_blob)
        if not isinstance(config, dict):
            raise ReleaseError(f"OCI config blob is invalid: {platform_key}")
        if (
            config.get("os") != platform_key[0]
            or config.get("architecture") != platform_key[1]
        ):
            raise ReleaseError(
                f"OCI config platform disagrees with its index descriptor: {platform_key}"
            )
        runtime = config.get("config")
        if not isinstance(runtime, dict):
            raise ReleaseError(f"OCI runtime config is missing: {platform_key}")
        user = runtime.get("User")
        user_parts = user.split(":", 1) if isinstance(user, str) else []
        if (
            not isinstance(user, str)
            or not user
            or any(part.lower() in {"0", "root"} for part in user_parts)
        ):
            raise ReleaseError(
                f"OCI runtime user is root or unspecified: {platform_key}"
            )
        entrypoint = runtime.get("Entrypoint")
        command = runtime.get("Cmd")
        if not any(
            isinstance(value, list)
            and value
            and all(isinstance(item, str) and item for item in value)
            for value in (entrypoint, command)
        ):
            raise ReleaseError(
                f"OCI runtime has no explicit entrypoint or command: {platform_key}"
            )
        layers = manifest.get("layers")
        rootfs = config.get("rootfs")
        diff_ids = (
            rootfs.get("diff_ids")
            if isinstance(rootfs, dict) and rootfs.get("type") == "layers"
            else None
        )
        if (
            not isinstance(layers, list)
            or not layers
            or not isinstance(diff_ids, list)
            or len(diff_ids) != len(layers)
        ):
            raise ReleaseError(
                f"OCI manifest layers and config diff IDs disagree: {platform_key}"
            )
        for position, layer in enumerate(layers):
            layer_blob, _ = _oci_descriptor(
                archive_path,
                layer,
                attributes,
                f"layer {platform_key[0]}/{platform_key[1]} #{position}",
                layer_media_types,
                parse_json=False,
            )
            referenced_blobs.add(layer_blob)
            if (
                not isinstance(diff_ids[position], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", diff_ids[position]) is None
            ):
                raise ReleaseError(
                    f"OCI config diff ID is invalid: {platform_key} #{position}"
                )
            layer_size = layer.get("size") if isinstance(layer, dict) else None
            if not isinstance(layer_size, int) or isinstance(layer_size, bool):
                raise ReleaseError(
                    f"OCI layer descriptor size is invalid: {platform_key} #{position}"
                )
            if layer_blob not in layer_diff_ids:
                layer_diff_ids[layer_blob] = _oci_layer_diff_id(
                    archive_path,
                    layer_blob,
                    layer_size,
                    maximum_layer_uncompressed_bytes,
                )
            if diff_ids[position] != layer_diff_ids[layer_blob]:
                raise ReleaseError(
                    f"OCI config diff ID does not match the layer bytes: {platform_key} #{position}"
                )
            if layer_blob not in validated_layer_tars:
                _validate_oci_layer_tar(
                    archive_path,
                    layer_blob,
                    layer_size,
                    maximum_entries,
                    maximum_member_bytes,
                    maximum_layer_uncompressed_bytes,
                    allowed_modes,
                    content_scan_exemptions,
                )
                validated_layer_tars.add(layer_blob)
    if observed_platforms != expected_platforms:
        raise ReleaseError("OCI index platform set is incomplete")
    blob_names = {
        name
        for name, attribute in attributes.items()
        if name.startswith("blobs/sha256/") and attribute.get("kind") == "file"
    }
    if blob_names != referenced_blobs:
        raise ReleaseError(
            f"OCI layout contains unreferenced or missing blobs: extra={sorted(blob_names - referenced_blobs)}, missing={sorted(referenced_blobs - blob_names)}"
        )
    return {
        "layers": len(validated_layer_tars),
        "non_root": True,
        "platforms": ["linux/amd64", "linux/arm64"],
        "referenced_blobs": len(referenced_blobs),
    }


def verify(
    archive_path: Path,
    contract_path: Path,
    expected_version: str | None,
    expected_abi: str | None,
    expected_epoch: int | None = None,
) -> dict[str, Any]:
    contract = _validate_contract(load_json(contract_path))
    archive_format = _archive_format(archive_path)
    if archive_format not in contract.get("formats", []):
        raise ReleaseError(
            f"archive format {archive_format} is not permitted by contract"
        )
    maximum_entries = contract.get("max_entries")
    maximum_member = contract.get("max_member_bytes")
    maximum_total = contract.get("max_total_bytes")
    if (
        not isinstance(maximum_entries, int)
        or isinstance(maximum_entries, bool)
        or maximum_entries <= 0
        or not isinstance(maximum_member, int)
        or isinstance(maximum_member, bool)
        or maximum_member <= 0
        or not isinstance(maximum_total, int)
        or isinstance(maximum_total, bool)
        or maximum_total <= 0
    ):
        raise ReleaseError("package contract size limits are invalid")
    allow = contract.get("allow", [])
    deny = contract.get("deny", [])
    if not isinstance(allow, list) or not allow or not isinstance(deny, list):
        raise ReleaseError("package contract allow/deny rules are invalid")
    try:
        allowed_modes = {int(value, 8) for value in contract.get("modes", [])}
    except (TypeError, ValueError) as error:
        raise ReleaseError("package contract modes are invalid") from error
    if (
        not allowed_modes
        or not allowed_modes.issubset({0o644, 0o755})
        or contract.get("symlinks") != "forbid"
    ):
        raise ReleaseError("package contract mode or symlink policy is invalid")
    exemptions = contract.get("content_scan_exemptions", [])
    if not isinstance(exemptions, list) or any(
        not isinstance(entry, dict)
        or set(entry) != {"pattern", "reason"}
        or not all(isinstance(value, str) and value for value in entry.values())
        for entry in exemptions
    ):
        raise ReleaseError("content scan exemptions must be a list")
    if contract.get("content_scan") is not True:
        raise ReleaseError("package contract must enable content scanning")
    retained_patterns = ["RELEASE-METADATA.json"]
    if contract.get("id") == "oci-image-v1":
        retained_patterns.extend(["oci-layout", "index.json"])
    checksum_manifest = contract.get("checksum_manifest")
    if isinstance(checksum_manifest, dict):
        retained_patterns.append(checksum_manifest["path"])
    for binding_name in ("version_binding", "abi_binding"):
        binding = contract.get(binding_name)
        if isinstance(binding, dict) and isinstance(binding.get("path_pattern"), str):
            retained_patterns.append(binding["path_pattern"])
    if archive_format in {"tar", "tar.gz"}:
        payloads, attributes = _read_tar(
            archive_path,
            maximum_entries,
            maximum_member,
            maximum_total,
            retained_patterns,
            True,
            exemptions,
        )
    else:
        payloads, attributes = _read_zip(
            archive_path,
            maximum_entries,
            maximum_member,
            maximum_total,
            retained_patterns,
            True,
            exemptions,
        )

    if isinstance(checksum_manifest, dict):
        _validate_checksum_manifest(payloads, attributes, checksum_manifest)

    findings: list[dict[str, str]] = []
    oci_summary: dict[str, Any] | None = None
    if contract.get("id") == "oci-image-v1":
        if archive_format != "tar":
            findings.append(
                {
                    "path": archive_path.name,
                    "finding": "OCI layout must be an uncompressed outer tar",
                }
            )
        else:
            try:
                layer_limit = contract.get("max_layer_uncompressed_bytes")
                if (
                    not isinstance(layer_limit, int)
                    or isinstance(layer_limit, bool)
                    or layer_limit <= 0
                ):
                    raise ReleaseError(
                        "OCI package contract has no valid uncompressed-layer limit"
                    )
                oci_summary = _validate_oci_layout(
                    archive_path,
                    payloads,
                    attributes,
                    expected_version,
                    expected_abi,
                    layer_limit,
                    maximum_entries,
                    maximum_member,
                    allowed_modes,
                    exemptions,
                )
            except ReleaseError as error:
                findings.append({"path": "index.json", "finding": str(error)})
    for name, attribute in attributes.items():
        directory_allowed = attribute["kind"] == "directory" and any(
            pattern.startswith(f"{name}/") or matches(f"{name}/placeholder", [pattern])
            for pattern in allow
        )
        if not matches(name, allow) and not directory_allowed:
            findings.append({"path": name, "finding": "not-allowlisted"})
        if matches(name, deny):
            findings.append({"path": name, "finding": "denied-path"})
        if attribute["kind"] == "file" and attribute["mode"] not in allowed_modes:
            findings.append(
                {"path": name, "finding": f"mode-{attribute['mode']:04o}-not-allowed"}
            )
        if attribute["kind"] == "directory" and attribute["mode"] != 0o755:
            findings.append(
                {
                    "path": name,
                    "finding": f"directory-mode-{attribute['mode']:04o}-not-allowed",
                }
            )
        if "uid" in attribute and (attribute["uid"] != 0 or attribute["gid"] != 0):
            findings.append({"path": name, "finding": "nonzero-owner"})

    names = set(payloads)
    for required in contract.get("required", []):
        if required not in names:
            findings.append({"path": required, "finding": "required-file-missing"})
    for group in contract.get("required_any", []):
        if (
            not isinstance(group, list)
            or not group
            or not any(value in names for value in group)
        ):
            findings.append(
                {
                    "path": "|".join(group) if isinstance(group, list) else "<invalid>",
                    "finding": "required-choice-missing",
                }
            )
    for pattern in contract.get("required_patterns", []):
        if not any(matches(name, [pattern]) for name in names):
            findings.append({"path": pattern, "finding": "required-pattern-missing"})

    metadata_payload = payloads.get("RELEASE-METADATA.json")
    metadata: dict[str, Any] | None = None
    if "RELEASE-METADATA.json" in payloads:
        if metadata_payload is None:
            findings.append(
                {
                    "path": "RELEASE-METADATA.json",
                    "finding": "release-metadata-exceeds-size-limit",
                }
            )
            loaded = None
        else:
            loaded = load_json_bytes(metadata_payload, "RELEASE-METADATA.json")
        if (
            not isinstance(loaded, dict)
            or loaded.get("schema_version") != "cigar.release-metadata.v1"
        ):
            findings.append(
                {"path": "RELEASE-METADATA.json", "finding": "invalid-release-metadata"}
            )
        else:
            metadata = loaded
            expected_metadata_keys = {
                "schema_version",
                "artifact_id",
                "product_version",
                "context_abi",
                "source_date_epoch",
                "source",
                "input_tree_sha256",
                "input_file_count",
                "contract",
                "contract_sha256",
            }
            if set(metadata) != expected_metadata_keys:
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "unexpected-release-metadata-shape",
                    }
                )
            if (
                expected_version is not None
                and metadata.get("product_version") != expected_version
            ):
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "product-version-mismatch",
                    }
                )
            if expected_abi is not None and metadata.get("context_abi") != expected_abi:
                findings.append(
                    {"path": "RELEASE-METADATA.json", "finding": "context-abi-mismatch"}
                )
            epoch = metadata.get("source_date_epoch")
            if isinstance(epoch, int):
                if expected_epoch is not None and epoch != expected_epoch:
                    findings.append(
                        {
                            "path": "RELEASE-METADATA.json",
                            "finding": "source-date-epoch-mismatch",
                        }
                    )
                for name, attribute in attributes.items():
                    archive_epoch = (
                        epoch
                        if archive_format not in {"zip", "wheel"}
                        else epoch - (epoch % 2)
                    )
                    if "mtime" in attribute and attribute["mtime"] != archive_epoch:
                        findings.append(
                            {"path": name, "finding": "nondeterministic-timestamp"}
                        )
            else:
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "invalid-source-date-epoch",
                    }
                )
            if metadata.get("contract_sha256") != sha256_file(contract_path):
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "package-contract-digest-mismatch",
                    }
                )
            try:
                safe_relative_path(metadata.get("contract", ""))
            except ReleaseError:
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "unsafe-package-contract-reference",
                    }
                )
            source = metadata.get("source")
            if not isinstance(source, dict) or set(source) != {
                "revision",
                "tree_sha256",
                "committed",
                "clean",
            }:
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "invalid-source-identity",
                    }
                )
            elif (
                not isinstance(source.get("revision"), str)
                or not isinstance(source.get("committed"), bool)
                or not isinstance(source.get("clean"), bool)
            ):
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "invalid-source-identity-types",
                    }
                )
            elif (
                not isinstance(source.get("tree_sha256"), str)
                or len(source["tree_sha256"]) != 64
            ):
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "invalid-source-tree-digest",
                    }
                )
            input_digest = hashlib.sha256()
            input_files = sorted(
                name for name in payloads if name != "RELEASE-METADATA.json"
            )
            for name in input_files:
                attribute = attributes[name]
                input_digest.update(name.encode("utf-8"))
                input_digest.update(b"\x00")
                input_digest.update(str(attribute["size"]).encode("ascii"))
                input_digest.update(b"\x00")
                input_digest.update(f"{attribute['mode']:04o}".encode("ascii"))
                input_digest.update(b"\x00")
                input_digest.update(bytes.fromhex(attribute["sha256"]))
                input_digest.update(b"\n")
            calculated_input_digest = input_digest.hexdigest()
            if metadata.get("input_tree_sha256") != calculated_input_digest:
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "input-tree-digest-mismatch",
                    }
                )
            if metadata.get("input_file_count") != len(input_files):
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "input-file-count-mismatch",
                    }
                )
            if (
                metadata.get("artifact_id") == "source"
                and isinstance(source, dict)
                and source.get("tree_sha256") != calculated_input_digest
            ):
                findings.append(
                    {
                        "path": "RELEASE-METADATA.json",
                        "finding": "source-tree-digest-mismatch",
                    }
                )
    elif expected_epoch is not None:
        archive_epoch = (
            expected_epoch
            if archive_format not in {"zip", "wheel"}
            else expected_epoch - (expected_epoch % 2)
        )
        for name, attribute in attributes.items():
            if "mtime" in attribute and attribute["mtime"] != archive_epoch:
                findings.append({"path": name, "finding": "nondeterministic-timestamp"})

    if contract.get("content_scan") is True:
        for name in payloads:
            for finding in attributes[name]["content_findings"]:
                findings.append({"path": name, "finding": finding})
    if contract.get("line_endings") != "lf":
        findings.append(
            {"path": str(contract_path), "finding": "unsupported-line-ending-policy"}
        )
    else:
        for name in payloads:
            if (
                Path(name).suffix.lower() in _TEXT_SUFFIXES
                or Path(name).name in _TEXT_NAMES
            ):
                if attributes[name]["contains_cr"]:
                    findings.append({"path": name, "finding": "non-lf-line-ending"})
    try:
        if "version_binding" in contract and expected_version is not None:
            if (
                _binding_value(payloads, contract["version_binding"], "version")
                != expected_version
            ):
                findings.append(
                    {
                        "path": contract["version_binding"]["path_pattern"],
                        "finding": "product-version-mismatch",
                    }
                )
        if "abi_binding" in contract and expected_abi is not None:
            if (
                _binding_value(payloads, contract["abi_binding"], "Context ABI")
                != expected_abi
            ):
                findings.append(
                    {
                        "path": contract["abi_binding"]["path_pattern"],
                        "finding": "context-abi-mismatch",
                    }
                )
    except ReleaseError as error:
        findings.append({"path": str(contract_path), "finding": str(error)})

    if findings:
        summary = "; ".join(
            f"{item['path']}: {item['finding']}" for item in findings[:20]
        )
        if len(findings) > 20:
            summary += f"; and {len(findings) - 20} more"
        raise ReleaseError(summary)
    return {
        "schema_version": "cigar.package-verification.v1",
        "status": "passed",
        "archive": {
            "name": archive_path.name,
            "sha256": sha256_file(archive_path),
            "bytes": archive_path.stat().st_size,
        },
        "contract": {"id": contract["id"], "sha256": sha256_file(contract_path)},
        "format": archive_format,
        "file_count": len(payloads),
        "expanded_bytes": sum(attributes[name]["size"] for name in payloads),
        "metadata": metadata,
        "oci": oci_summary,
    }


def main() -> int:
    arguments = parse_arguments()
    if arguments.report is not None:
        require_distinct_output(
            arguments.report.resolve(),
            [arguments.archive, arguments.contract],
            "package verification",
        )
    report = verify(
        arguments.archive.resolve(),
        arguments.contract.resolve(),
        arguments.expected_version,
        arguments.expected_abi,
        arguments.source_date_epoch,
    )
    if arguments.report is not None:
        write_json(arguments.report.resolve(), report)
    print(canonical_json_bytes(report).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"package verification failed: {error}") from error
