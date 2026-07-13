#!/usr/bin/env python3
"""Inventory license expressions for locked Cargo, npm, Python, and Go dependencies."""

from __future__ import annotations

import argparse
import email.parser
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from generate_sbom import _go_components, _npm_components, _python_components
from release_lib import ReleaseError, load_json, process_failure_summary, repo_root, require_distinct_output, run_bounded, sha256_file, write_json


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


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
        if "neither the name" in lower or "contributors may be used to endorse" in lower:
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
        if path.is_file() and path.name.lower().startswith(("notice", "third-party", "third_party")):
            result.append(sha256_file(path))
    return result


def _cargo(root: Path) -> list[dict[str, Any]]:
    command = ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"]
    result = run_bounded(command, cwd=root, timeout=300, max_stdout=32 * 1024 * 1024)
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, "cargo metadata"))
    metadata = json.loads(result.stdout.decode("utf-8"))
    entries: list[dict[str, Any]] = []
    for package in metadata.get("packages", []):
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
        entries.append({
            "ecosystem": ecosystem,
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:{ecosystem}/{package['name']}@{package['version']}",
            "license_expression": package.get("license") or "NOASSERTION",
            "metadata_source": "cargo-metadata-locked-offline",
            "notice_sha256": _notice_digests(directory),
        })
    return entries


def _npm_metadata(root: Path) -> dict[tuple[str, str], tuple[str, list[str]]]:
    result: dict[tuple[str, str], tuple[str, list[str]]] = {}
    package_root = root / "node_modules/.pnpm"
    if not package_root.is_dir():
        return result
    for path in package_root.glob("*/node_modules/**/package.json"):
        if not path.is_file() or "node_modules" in path.relative_to(package_root).parts[-2:]:
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
            values = [item.get("type") if isinstance(item, dict) else item for item in license_value]
            license_expression = " OR ".join(value for value in values if isinstance(value, str)) or "NOASSERTION"
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
        expression, notices = metadata.get((component["name"], component["version"]), ("NOASSERTION", []))
        entries.append({
            "ecosystem": "npm", "name": component["name"], "version": component["version"],
            "purl": component["purl"], "license_expression": expression,
            "metadata_source": "installed-package-json" if expression != "NOASSERTION" else "unavailable",
            "notice_sha256": notices,
        })
    return entries


def _python_metadata(root: Path) -> dict[tuple[str, str], tuple[str, list[str]]]:
    result: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for path in (root / "sdk/python/.venv").glob("lib/python*/site-packages/*.dist-info/METADATA"):
        message = email.parser.Parser().parsestr(path.read_text(encoding="utf-8", errors="replace"))
        name = message.get("Name")
        version = message.get("Version")
        if not name or not version:
            continue
        expression = message.get("License-Expression")
        if not expression:
            legacy = message.get("License", "")
            expression = legacy if len(legacy) < 160 and "\n" not in legacy else _classify_text(legacy)
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
        result[(_normalize_name(name), version)] = (expression or "NOASSERTION", _notice_digests(path.parent))
    return result


def _python(root: Path) -> list[dict[str, Any]]:
    metadata = _python_metadata(root)
    entries: list[dict[str, Any]] = []
    for component in _python_components(root):
        if component["name"] == "cigar-sdk":
            continue
        expression, notices = metadata.get((_normalize_name(component["name"]), component["version"]), ("NOASSERTION", []))
        entries.append({
            "ecosystem": "pypi", "name": component["name"], "version": component["version"],
            "purl": component["purl"], "license_expression": expression,
            "metadata_source": "installed-wheel-metadata" if expression != "NOASSERTION" else "unavailable",
            "notice_sha256": notices,
        })
    return entries


def _go_module_directory(cache: Path, name: str, version: str) -> Path:
    escaped = "".join(f"!{character.lower()}" if character.isupper() else character for character in name)
    return cache / f"{escaped}@{version}"


def _go(root: Path) -> list[dict[str, Any]]:
    cache = Path(os.environ.get("GOMODCACHE", str(Path.home() / "go/pkg/mod")))
    entries: list[dict[str, Any]] = []
    for component in _go_components(root):
        directory = _go_module_directory(cache, component["name"], component["version"])
        expression = "NOASSERTION"
        license_directory = directory
        while license_directory != cache and cache in license_directory.parents:
            candidates = [path for path in license_directory.glob("LICENSE*") if path.is_file()]
            if candidates:
                expression = _classify_text(candidates[0].read_text(encoding="utf-8", errors="replace")) or "NOASSERTION"
                directory = license_directory
                break
            license_directory = license_directory.parent
        entries.append({
            "ecosystem": "golang", "name": component["name"], "version": component["version"],
            "purl": component["purl"], "license_expression": expression,
            "metadata_source": "module-cache-license" if expression != "NOASSERTION" else "unavailable",
            "notice_sha256": _notice_digests(directory),
        })
    return entries


def _status(expression: str, accepted: set[str], review: set[str]) -> str:
    if expression == "NOASSERTION":
        return "review-required"
    aliases = {"3-Clause BSD License": "BSD-3-Clause"}
    normalized = aliases.get(expression, expression).replace(" / ", " OR ")
    normalized = normalized.replace("MIT/Apache-2.0", "MIT OR Apache-2.0").replace("Unlicense/MIT", "Unlicense OR MIT")
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
    policy = load_json(root / "packaging/licenses/third-party-policy.v1.json")
    accepted = set(policy["accepted_expressions"])
    review = set(policy["review_required"])
    entries = _cargo(root) + _npm(root) + _python(root) + _go(root)
    component_keys = [(entry["ecosystem"], entry["name"], entry["version"]) for entry in entries]
    if len(set(component_keys)) != len(component_keys):
        raise ReleaseError("locked license inventory contains ambiguous duplicate component identities")
    unique = {key: entry for key, entry in zip(component_keys, entries, strict=True)}
    entries = sorted(unique.values(), key=lambda entry: (entry["ecosystem"], entry["name"], entry["version"]))
    for entry in entries:
        entry["policy_status"] = _status(entry["license_expression"], accepted, review)
    review_count = sum(entry["policy_status"] == "review-required" for entry in entries)
    inventory = {
        "schema_version": "cigar.third-party-license-inventory.v1",
        "policy_sha256": sha256_file(root / "packaging/licenses/third-party-policy.v1.json"),
        "status": "complete" if review_count == 0 else "review-required",
        "component_count": len(entries),
        "review_required_count": review_count,
        "components": entries,
    }
    output = arguments.out.resolve()
    require_distinct_output(
        output,
        [
            root / "Cargo.lock",
            root / "pnpm-lock.yaml",
            root / "sdk/python/uv.lock",
            root / "sdk/go/go.sum",
            root / "packaging/licenses/third-party-policy.v1.json",
        ],
        "third-party license inventory",
    )
    write_json(output, inventory)
    if arguments.require_complete and review_count:
        raise ReleaseError(f"{review_count} locked components require license review")
    print(f"inventoried {len(entries)} locked components; {review_count} require review")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired, tomllib.TOMLDecodeError, ReleaseError) as error:
        raise SystemExit(f"license inventory failed: {error}") from error
