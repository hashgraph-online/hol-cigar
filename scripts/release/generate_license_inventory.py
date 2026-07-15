#!/usr/bin/env python3
"""Inventory license expressions for locked Cargo, npm, Python, and Go dependencies."""

from __future__ import annotations

import argparse
import base64
import email.parser
import hashlib
import json
import os
import re
import stat
import subprocess
import tomllib
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from generate_sbom import _go_components, _npm_components, _python_components
from release_lib import (
    ReleaseError,
    load_json,
    process_failure_summary,
    repo_root,
    require_distinct_output,
    run_bounded,
    sha256_file,
    write_json,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external inventory workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--require-complete", action="store_true")
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


def _inventory_inputs(root: Path) -> list[Path]:
    return [
        root / "Cargo.lock",
        root / "pnpm-lock.yaml",
        root / "sdk/python/uv.lock",
        root / "sdk/go/go.sum",
        root / "packaging/licenses/third-party-policy.v1.json",
        root / "packaging/licenses/locked-upstream-license-evidence.v1.json",
    ]


_UPSTREAM_EVIDENCE_SCHEMA = "cigar.locked-upstream-license-evidence.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA512 = re.compile(r"^[0-9a-f]{128}$")


def _strict_json(path: Path) -> dict[str, Any]:
    """Load the bounded source authority while rejecting duplicate JSON keys."""

    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise ReleaseError("locked upstream license evidence must be a regular file")
    payload = path.read_bytes()
    if not payload or len(payload) > 1024 * 1024:
        raise ReleaseError("locked upstream license evidence has invalid size")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseError(
                    f"locked upstream license evidence has duplicate key: {key}"
                )
            result[key] = value
        return result

    document = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(document, dict):
        raise ReleaseError("locked upstream license evidence root is invalid")
    return document


def _exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReleaseError(f"{context} has invalid fields")
    return value


def _canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_archive_path(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReleaseError(f"{context} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseError(f"{context} path is invalid")
    return value


def _locked_python_sources(root: Path) -> dict[str, dict[str, Any]]:
    document = tomllib.loads((root / "sdk/python/uv.lock").read_text(encoding="utf-8"))
    result: dict[str, dict[str, Any]] = {}
    for package in document.get("package", []):
        if not isinstance(package, dict):
            raise ReleaseError("uv.lock package inventory is invalid")
        name = package.get("name")
        version = package.get("version")
        source = package.get("sdist")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ReleaseError("uv.lock package identity is invalid")
        if not isinstance(source, dict):
            continue
        url = source.get("url")
        digest = source.get("hash")
        size = source.get("size")
        if (
            not isinstance(url, str)
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise ReleaseError(f"uv.lock sdist identity is invalid: {name}@{version}")
        purl = f"pkg:pypi/{urllib.parse.quote(name, safe='/')}@{urllib.parse.quote(version, safe='.+-_')}"
        if purl in result:
            raise ReleaseError(f"uv.lock has duplicate sdist identity: {purl}")
        result[purl] = {
            "sha256": digest.removeprefix("sha256:"),
            "url": url,
            "bytes": size,
        }
    return result


def _locked_upstream_components(root: Path) -> dict[str, dict[str, Any]]:
    components = _npm_components(root) + _python_components(root)
    result: dict[str, dict[str, Any]] = {}
    python_sources = _locked_python_sources(root)
    for component in components:
        purl = component["purl"]
        if purl in result:
            raise ReleaseError(
                f"locked upstream component identity is duplicate: {purl}"
            )
        locked = dict(component)
        if component["ecosystem"] == "pypi" and purl in python_sources:
            locked.update(python_sources[purl])
        result[purl] = locked
    return result


def _validate_shared_license_files(
    value: Any,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ReleaseError("locked upstream license files are invalid")
    result: dict[str, dict[str, Any]] = {}
    identities: list[str] = []
    for raw in value:
        item = _exact_keys(raw, {"id", "path", "sha256", "bytes"}, "license file")
        identifier = item["id"]
        digest = item["sha256"]
        size = item["bytes"]
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", identifier)
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise ReleaseError("locked upstream license file identity is invalid")
        _safe_archive_path(item["path"], f"license file {identifier}")
        if identifier in result:
            raise ReleaseError(
                f"locked upstream license file identity is duplicate: {identifier}"
            )
        identities.append(identifier)
        result[identifier] = item
    if identities != sorted(identities):
        raise ReleaseError("locked upstream license files are not ordered")
    return result


def _validate_npm_evidence(
    record: dict[str, Any], locked: dict[str, Any], metadata: dict[str, Any]
) -> None:
    lock = _exact_keys(
        record["lock"], {"path", "algorithm", "digest"}, "npm lock binding"
    )
    archive = _exact_keys(record["archive"], {"url", "sha256", "bytes"}, "npm archive")
    subset = _exact_keys(
        metadata["subset"],
        {"name", "version", "license", "dist"},
        "npm metadata subset",
    )
    distribution = _exact_keys(
        subset["dist"], {"integrity", "shasum", "tarball"}, "npm distribution metadata"
    )
    if (
        lock
        != {
            "path": "pnpm-lock.yaml",
            "algorithm": "sha512",
            "digest": locked.get("sha512"),
        }
        or not isinstance(lock["digest"], str)
        or _SHA512.fullmatch(lock["digest"]) is None
    ):
        raise ReleaseError(f"npm evidence lock binding is stale: {record['purl']}")
    integrity = distribution["integrity"]
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise ReleaseError(f"npm evidence integrity is invalid: {record['purl']}")
    try:
        integrity_digest = base64.b64decode(
            integrity.removeprefix("sha512-"), validate=True
        ).hex()
    except ValueError as error:
        raise ReleaseError(
            f"npm evidence integrity is invalid: {record['purl']}"
        ) from error
    expected_metadata_url = (
        "https://registry.npmjs.org/"
        f"{urllib.parse.quote(record['name'], safe='')}/{record['version']}"
    )
    archive_basename = record["name"].rsplit("/", maxsplit=1)[-1]
    expected_archive_url = (
        f"https://registry.npmjs.org/{record['name']}/-/"
        f"{archive_basename}-{record['version']}.tgz"
    )
    if (
        integrity_digest != lock["digest"]
        or subset["name"] != record["name"]
        or subset["version"] != record["version"]
        or subset["license"] != record["license_expression"]
        or metadata["url"] != expected_metadata_url
        or archive["url"] != expected_archive_url
        or distribution["tarball"] != archive["url"]
        or not isinstance(distribution["shasum"], str)
        or re.fullmatch(r"[0-9a-f]{40}", distribution["shasum"]) is None
    ):
        raise ReleaseError(f"npm upstream evidence is inconsistent: {record['purl']}")


def _validate_pypi_evidence(
    record: dict[str, Any], locked: dict[str, Any], metadata: dict[str, Any]
) -> None:
    lock = _exact_keys(
        record["lock"], {"path", "algorithm", "digest"}, "PyPI lock binding"
    )
    archive = _exact_keys(record["archive"], {"url", "sha256", "bytes"}, "PyPI archive")
    subset = _exact_keys(metadata["subset"], {"info", "sdist"}, "PyPI metadata subset")
    info = _exact_keys(
        subset["info"], {"name", "version", "classifiers"}, "PyPI project metadata"
    )
    distribution = _exact_keys(
        subset["sdist"], {"filename", "url", "size", "sha256"}, "PyPI sdist metadata"
    )
    classifiers = info["classifiers"]
    if (
        lock
        != {
            "path": "sdk/python/uv.lock",
            "algorithm": "sha256",
            "digest": locked.get("sha256"),
        }
        or not isinstance(lock["digest"], str)
        or _SHA256.fullmatch(lock["digest"]) is None
    ):
        raise ReleaseError(f"PyPI evidence lock binding is stale: {record['purl']}")
    if (
        info["name"] != record["name"]
        or info["version"] != record["version"]
        or not isinstance(classifiers, list)
        or not all(isinstance(item, str) for item in classifiers)
        or len(set(classifiers)) != len(classifiers)
        or "License :: OSI Approved :: BSD License" not in classifiers
        or record["license_expression"] != "BSD-3-Clause"
        or metadata["url"]
        != f"https://pypi.org/pypi/{record['name']}/{record['version']}/json"
        or distribution["url"] != archive["url"]
        or distribution["url"] != locked.get("url")
        or distribution["size"] != archive["bytes"]
        or distribution["size"] != locked.get("bytes")
        or distribution["sha256"] != archive["sha256"]
        or distribution["sha256"] != lock["digest"]
        or not isinstance(distribution["filename"], str)
        or not distribution["filename"]
    ):
        raise ReleaseError(f"PyPI upstream evidence is inconsistent: {record['purl']}")


def _load_upstream_license_evidence(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "packaging/licenses/locked-upstream-license-evidence.v1.json"
    document = _strict_json(path)
    _exact_keys(
        document,
        {"schema_version", "scope", "limitations", "license_files", "records"},
        "locked upstream license evidence",
    )
    if (
        document["schema_version"] != _UPSTREAM_EVIDENCE_SCHEMA
        or document["scope"] != "locked-source-license-metadata-only"
        or document["limitations"]
        != [
            "This source authority records technical metadata and is not legal approval.",
            "Final packaged bytes and transitive native members require separate reconciliation.",
        ]
    ):
        raise ReleaseError("locked upstream license evidence authority is invalid")
    files = _validate_shared_license_files(document["license_files"])
    records = document["records"]
    if not isinstance(records, list) or not records:
        raise ReleaseError("locked upstream license evidence records are invalid")
    locked_components = _locked_upstream_components(root)
    result: dict[str, dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    referenced_files: set[str] = set()
    for raw in records:
        record = _exact_keys(
            raw,
            {
                "ecosystem",
                "name",
                "version",
                "purl",
                "license_expression",
                "lock",
                "archive",
                "metadata",
                "license_file_ids",
            },
            "locked upstream license record",
        )
        ecosystem = record["ecosystem"]
        name = record["name"]
        version = record["version"]
        purl = record["purl"]
        expression = record["license_expression"]
        if (
            ecosystem not in {"npm", "pypi"}
            or not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or not isinstance(purl, str)
            or not isinstance(expression, str)
            or not expression
        ):
            raise ReleaseError("locked upstream license record identity is invalid")
        expected_purl = (
            f"pkg:{ecosystem}/{urllib.parse.quote(name, safe='/')}@"
            f"{urllib.parse.quote(version, safe='.+-_')}"
        )
        locked = locked_components.get(purl)
        if purl != expected_purl or locked is None:
            raise ReleaseError(
                f"upstream license evidence is stale or substituted: {purl}"
            )
        if (
            locked["ecosystem"] != ecosystem
            or locked["name"] != name
            or locked["version"] != version
        ):
            raise ReleaseError(f"upstream license evidence identity conflicts: {purl}")
        archive = record["archive"]
        if (
            not isinstance(archive, dict)
            or not isinstance(archive.get("sha256"), str)
            or _SHA256.fullmatch(archive["sha256"]) is None
            or not isinstance(archive.get("bytes"), int)
            or isinstance(archive.get("bytes"), bool)
            or archive["bytes"] <= 0
            or not isinstance(archive.get("url"), str)
            or not archive["url"].startswith("https://")
        ):
            raise ReleaseError(f"upstream archive evidence is invalid: {purl}")
        metadata = _exact_keys(
            record["metadata"],
            {"url", "canonical_subset_sha256", "subset"},
            "upstream metadata",
        )
        if not isinstance(metadata["canonical_subset_sha256"], str) or metadata[
            "canonical_subset_sha256"
        ] != _canonical_json_sha256(metadata["subset"]):
            raise ReleaseError(f"upstream metadata digest is invalid: {purl}")
        if ecosystem == "npm":
            _validate_npm_evidence(record, locked, metadata)
        else:
            _validate_pypi_evidence(record, locked, metadata)
        identifiers = record["license_file_ids"]
        if (
            not isinstance(identifiers, list)
            or not identifiers
            or not all(isinstance(item, str) for item in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or identifiers != sorted(identifiers)
            or any(identifier not in files for identifier in identifiers)
        ):
            raise ReleaseError(f"upstream license file references are invalid: {purl}")
        referenced_files.update(identifiers)
        document_names = [
            PurePosixPath(files[identifier]["path"]).name.lower()
            for identifier in identifiers
        ]
        if not any(
            name.startswith(("license", "licence", "copying"))
            for name in document_names
        ):
            raise ReleaseError(f"upstream license text reference is missing: {purl}")
        if purl in result:
            raise ReleaseError(f"upstream license evidence record is duplicate: {purl}")
        notices = [
            files[identifier]["sha256"]
            for identifier in identifiers
            if PurePosixPath(files[identifier]["path"])
            .name.lower()
            .startswith(("notice", "third-party", "third_party"))
        ]
        result[purl] = {
            "license_expression": expression,
            "notice_sha256": notices,
        }
        order.append((ecosystem, name, version))
    if order != sorted(order):
        raise ReleaseError("locked upstream license evidence records are not ordered")
    if referenced_files != set(files):
        raise ReleaseError("locked upstream license files contain unused records")
    return result


def _apply_upstream_license_evidence(
    entries: list[dict[str, Any]], evidence: dict[str, dict[str, Any]]
) -> None:
    aliases = {"3-Clause BSD License": "BSD-3-Clause"}
    by_purl = {entry["purl"]: entry for entry in entries}
    for purl, upstream in evidence.items():
        entry = by_purl.get(purl)
        if entry is None:
            raise ReleaseError(
                f"upstream license evidence component is not inventoried: {purl}"
            )
        observed = aliases.get(entry["license_expression"], entry["license_expression"])
        expected = upstream["license_expression"]
        if observed != "NOASSERTION" and observed != expected:
            raise ReleaseError(
                f"installed license metadata conflicts with evidence: {purl}"
            )
        observed_notices = entry["notice_sha256"]
        expected_notices = upstream["notice_sha256"]
        if observed_notices and sorted(observed_notices) != sorted(expected_notices):
            raise ReleaseError(
                f"installed notice metadata conflicts with evidence: {purl}"
            )
        if observed == "NOASSERTION":
            entry["license_expression"] = expected
            entry["metadata_source"] = "locked-upstream-license-evidence"
            entry["notice_sha256"] = expected_notices


class LicenseInventoryOutput:
    """One protected external or legacy development inventory destination."""

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
    ) -> LicenseInventoryOutput:
        selected = selected_evidence_directory(arguments)
        if selected is None:
            direct = arguments.out.resolve()
            require_distinct_output(direct, inputs, "third-party license inventory")
            return cls(direct=direct, workspace=None, relative=None)

        if arguments.out.is_absolute():
            raise ReleaseError(
                "--out must be relative when an evidence directory is selected"
            )
        parts = safe_evidence_path(os.fspath(arguments.out))
        tentative = selected.joinpath(*parts)
        require_distinct_output(
            tentative,
            inputs,
            "third-party license inventory",
        )
        workspace = EvidenceWorkspace.create(selected, repository_root=root)
        try:
            require_distinct_output(
                workspace.root.joinpath(*parts),
                inputs,
                "third-party license inventory",
            )
            return cls(
                direct=None,
                workspace=workspace,
                relative="/".join(parts),
            )
        except BaseException:
            workspace.close()
            raise

    def publish(self, inventory: dict[str, Any]) -> None:
        if self.workspace is None:
            assert self.direct is not None
            write_json(self.direct, inventory)
            return
        assert self.relative is not None
        self.workspace.write_json(self.relative, inventory)

    def close(self) -> None:
        if self.workspace is not None:
            self.workspace.close()


def _child_environment() -> dict[str, str]:
    """Keep child tooling from inheriting authority over the evidence workspace."""

    environment = os.environ.copy()
    environment.pop("CIGAR_EVIDENCE_DIR", None)
    return environment


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _classify_text(value: str) -> str | None:
    lower = value.lower()
    if "apache license" in lower and "version 2.0" in lower:
        return "Apache-2.0"
    if "mozilla public license" in lower and "2.0" in lower:
        return "MPL-2.0"
    if "permission is hereby granted, free of charge" in lower:
        return "MIT"
    if "redistributions of source code must retain" in lower:
        if (
            "neither the name" in lower
            or "contributors may be used to endorse" in lower
        ):
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "permission to use, copy, modify" in lower and "isc" in lower:
        return "ISC"
    if "python software foundation license" in lower:
        return "PSF-2.0"
    return None


def _notice_digests(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    result: list[str] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name.lower()):
        if path.is_file() and path.name.lower().startswith(
            ("notice", "third-party", "third_party")
        ):
            result.append(sha256_file(path))
    return result


def _cargo_package_identities(
    packages: Any, *, source: str
) -> set[tuple[str, str, str | None]]:
    if not isinstance(packages, list):
        raise ReleaseError(f"{source} package inventory is invalid")
    identities: list[tuple[str, str, str | None]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise ReleaseError(f"{source} package inventory is invalid")
        name = package.get("name")
        version = package.get("version")
        package_source = package.get("source")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or (package_source is not None and not isinstance(package_source, str))
        ):
            raise ReleaseError(f"{source} package identity is invalid")
        identities.append((name, version, package_source))
    if len(set(identities)) != len(identities):
        raise ReleaseError(f"{source} contains duplicate Cargo package identities")
    return set(identities)


def _cargo(root: Path) -> list[dict[str, Any]]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--all-features",
        "--format-version",
        "1",
    ]
    result = run_bounded(
        command,
        cwd=root,
        env=_child_environment(),
        timeout=300,
        max_stdout=32 * 1024 * 1024,
    )
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, "cargo metadata"))
    metadata = json.loads(result.stdout.decode("utf-8"))
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    locked_identities = _cargo_package_identities(
        lock.get("package"), source="Cargo.lock"
    )
    metadata_packages = metadata.get("packages")
    metadata_identities = _cargo_package_identities(
        metadata_packages, source="cargo metadata --all-features"
    )
    if metadata_identities != locked_identities:
        missing = sorted(
            locked_identities - metadata_identities,
            key=lambda item: (item[0], item[1], item[2] or ""),
        )
        extra = sorted(
            metadata_identities - locked_identities,
            key=lambda item: (item[0], item[1], item[2] or ""),
        )
        raise ReleaseError(
            "cargo metadata --all-features differs from Cargo.lock; "
            f"missing_count={len(missing)} missing={missing[:10]}, "
            f"extra_count={len(extra)} extra={extra[:10]}"
        )
    entries: list[dict[str, Any]] = []
    for package in metadata_packages:
        directory = Path(package["manifest_path"]).parent
        ecosystem = "cargo"
        if package.get("source") is None:
            try:
                relative = directory.resolve().relative_to(root)
            except ValueError:
                continue
            if not relative.parts or relative.parts[0] != "vendor":
                continue
            ecosystem = "generic"
        entries.append(
            {
                "ecosystem": ecosystem,
                "name": package["name"],
                "version": package["version"],
                "purl": f"pkg:{ecosystem}/{package['name']}@{package['version']}",
                "license_expression": package.get("license") or "NOASSERTION",
                "metadata_source": "cargo-metadata-locked-offline",
                "notice_sha256": _notice_digests(directory),
            }
        )
    return entries


def _npm_metadata(root: Path) -> dict[tuple[str, str], tuple[str, list[str]]]:
    result: dict[tuple[str, str], tuple[str, list[str]]] = {}
    package_root = root / "node_modules/.pnpm"
    if not package_root.is_dir():
        return result
    for path in package_root.glob("*/node_modules/**/package.json"):
        if (
            not path.is_file()
            or "node_modules" in path.relative_to(package_root).parts[-2:]
        ):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        name = document.get("name")
        version = document.get("version")
        license_value = document.get("license") or document.get("licenses")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if isinstance(license_value, list):
            values = [
                item.get("type") if isinstance(item, dict) else item
                for item in license_value
            ]
            license_expression = (
                " OR ".join(value for value in values if isinstance(value, str))
                or "NOASSERTION"
            )
        elif isinstance(license_value, dict):
            license_expression = license_value.get("type", "NOASSERTION")
        elif isinstance(license_value, str):
            license_expression = license_value
        else:
            license_expression = "NOASSERTION"
        result[(name, version)] = (license_expression, _notice_digests(path.parent))
    return result


def _npm(root: Path) -> list[dict[str, Any]]:
    metadata = _npm_metadata(root)
    entries: list[dict[str, Any]] = []
    for component in _npm_components(root):
        expression, notices = metadata.get(
            (component["name"], component["version"]), ("NOASSERTION", [])
        )
        entries.append(
            {
                "ecosystem": "npm",
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "license_expression": expression,
                "metadata_source": "installed-package-json"
                if expression != "NOASSERTION"
                else "unavailable",
                "notice_sha256": notices,
            }
        )
    return entries


def _python_metadata(root: Path) -> dict[tuple[str, str], tuple[str, list[str]]]:
    result: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for path in (root / "sdk/python/.venv").glob(
        "lib/python*/site-packages/*.dist-info/METADATA"
    ):
        message = email.parser.Parser().parsestr(
            path.read_text(encoding="utf-8", errors="replace")
        )
        name = message.get("Name")
        version = message.get("Version")
        if not name or not version:
            continue
        expression = message.get("License-Expression")
        if not expression:
            legacy = message.get("License", "")
            expression = (
                legacy
                if len(legacy) < 160 and "\n" not in legacy
                else _classify_text(legacy)
            )
        if not expression:
            classifiers = "\n".join(message.get_all("Classifier", []))
            if "Mozilla Public License 2.0" in classifiers:
                expression = "MPL-2.0"
            elif "MIT License" in classifiers:
                expression = "MIT"
            elif "BSD License" in classifiers:
                expression = "BSD-3-Clause"
            elif "Apache Software License" in classifiers:
                expression = "Apache-2.0"
        result[(_normalize_name(name), version)] = (
            expression or "NOASSERTION",
            _notice_digests(path.parent),
        )
    return result


def _python(root: Path) -> list[dict[str, Any]]:
    metadata = _python_metadata(root)
    entries: list[dict[str, Any]] = []
    for component in _python_components(root):
        if component["name"] == "cigar-sdk":
            continue
        expression, notices = metadata.get(
            (_normalize_name(component["name"]), component["version"]),
            ("NOASSERTION", []),
        )
        entries.append(
            {
                "ecosystem": "pypi",
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "license_expression": expression,
                "metadata_source": "installed-wheel-metadata"
                if expression != "NOASSERTION"
                else "unavailable",
                "notice_sha256": notices,
            }
        )
    return entries


def _go_module_directory(cache: Path, name: str, version: str) -> Path:
    escaped = "".join(
        f"!{character.lower()}" if character.isupper() else character
        for character in name
    )
    return cache / f"{escaped}@{version}"


def _go(root: Path) -> list[dict[str, Any]]:
    cache = Path(os.environ.get("GOMODCACHE", str(Path.home() / "go/pkg/mod")))
    entries: list[dict[str, Any]] = []
    for component in _go_components(root):
        directory = _go_module_directory(cache, component["name"], component["version"])
        expression = "NOASSERTION"
        license_directory = directory
        while license_directory != cache and cache in license_directory.parents:
            candidates = [
                path for path in license_directory.glob("LICENSE*") if path.is_file()
            ]
            if candidates:
                expression = (
                    _classify_text(
                        candidates[0].read_text(encoding="utf-8", errors="replace")
                    )
                    or "NOASSERTION"
                )
                directory = license_directory
                break
            license_directory = license_directory.parent
        entries.append(
            {
                "ecosystem": "golang",
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "license_expression": expression,
                "metadata_source": "module-cache-license"
                if expression != "NOASSERTION"
                else "unavailable",
                "notice_sha256": _notice_digests(directory),
            }
        )
    return entries


def _status(expression: str, accepted: set[str], review: set[str]) -> str:
    if expression == "NOASSERTION":
        return "review-required"
    aliases = {"3-Clause BSD License": "BSD-3-Clause"}
    normalized = aliases.get(expression, expression).replace(" / ", " OR ")
    normalized = normalized.replace("MIT/Apache-2.0", "MIT OR Apache-2.0").replace(
        "Unlicense/MIT", "Unlicense OR MIT"
    )
    token_pattern = re.compile(r"\s*(\(|\)|AND|OR|WITH|[A-Za-z0-9][A-Za-z0-9.+-]*)")
    tokens: list[str] = []
    offset = 0
    while offset < len(normalized):
        if not normalized[offset:].strip():
            break
        match = token_pattern.match(normalized, offset)
        if match is None:
            return "review-required"
        tokens.append(match.group(1))
        offset = match.end()
    position = 0

    def primary() -> bool:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("missing license expression operand")
        token = tokens[position]
        position += 1
        if token == "(":
            value = disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unclosed license expression group")
            position += 1
            return value
        if token in {"AND", "OR", "WITH", ")"}:
            raise ValueError("unexpected license expression operator")
        return token in accepted and token not in review

    def with_expression() -> bool:
        nonlocal position
        value = primary()
        while position < len(tokens) and tokens[position] == "WITH":
            position += 1
            right = primary()
            value = value and right
        return value

    def conjunction() -> bool:
        nonlocal position
        value = with_expression()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            right = with_expression()
            value = value and right
        return value

    def disjunction() -> bool:
        nonlocal position
        value = conjunction()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            right = conjunction()
            value = value or right
        return value

    try:
        accepted_expression = bool(tokens) and disjunction() and position == len(tokens)
    except ValueError:
        accepted_expression = False
    return "accepted-by-policy" if accepted_expression else "review-required"


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    inputs = _inventory_inputs(root)
    output = LicenseInventoryOutput.open(arguments, root, inputs)
    try:
        policy_path = root / "packaging/licenses/third-party-policy.v1.json"
        upstream_evidence_path = (
            root / "packaging/licenses/locked-upstream-license-evidence.v1.json"
        )
        policy = load_json(policy_path)
        accepted = set(policy["accepted_expressions"])
        review = set(policy["review_required"])
        entries = _cargo(root) + _npm(root) + _python(root) + _go(root)
        upstream_evidence = _load_upstream_license_evidence(root)
        _apply_upstream_license_evidence(entries, upstream_evidence)
        component_keys = [
            (entry["ecosystem"], entry["name"], entry["version"]) for entry in entries
        ]
        if len(set(component_keys)) != len(component_keys):
            raise ReleaseError(
                "locked license inventory contains ambiguous duplicate component identities"
            )
        unique = {
            key: entry for key, entry in zip(component_keys, entries, strict=True)
        }
        entries = sorted(
            unique.values(),
            key=lambda entry: (entry["ecosystem"], entry["name"], entry["version"]),
        )
        for entry in entries:
            entry["policy_status"] = _status(
                entry["license_expression"], accepted, review
            )
        review_count = sum(
            entry["policy_status"] == "review-required" for entry in entries
        )
        inventory = {
            "schema_version": "cigar.third-party-license-inventory.v1",
            "policy_sha256": sha256_file(policy_path),
            "upstream_evidence_sha256": sha256_file(upstream_evidence_path),
            "upstream_evidence_record_count": len(upstream_evidence),
            "status": "complete" if review_count == 0 else "review-required",
            "component_count": len(entries),
            "review_required_count": review_count,
            "components": entries,
        }
        output.publish(inventory)
    finally:
        output.close()
    if arguments.require_complete and review_count:
        raise ReleaseError(f"{review_count} locked components require license review")
    print(
        f"inventoried {len(entries)} locked components; {review_count} require review"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
        tomllib.TOMLDecodeError,
        EvidenceWorkspaceError,
        ReleaseError,
    ) as error:
        raise SystemExit(f"license inventory failed: {error}") from error
