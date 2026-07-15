#!/usr/bin/env python3
"""Propagate and verify the authoritative full-product development identity.

This deliberately uses a closed file and field inventory.  It does not search and replace
version-looking strings across the repository: beta release material, support forks, protocol
versions, compatibility fixtures, historical evidence, and dashboard npm metadata are outside
this authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import tomllib
from typing import Any, Iterable

from release_lib import ReleaseError, reject_evidence_directory


MANIFEST_PATH = "packaging/product-version.v1.json"
EXPECTED_TARGET_RELEASE = "1.0.0"
EXPECTED_CONTEXT_ABI = "cigar.context.v1"
MAX_JSON_BYTES = 16 * 1024 * 1024
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SEMVER_FRAGMENT = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
PRODUCT_VERSION_FRAGMENT = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-dev\.[1-9][0-9]*)?"
)
PYTHON_DISTRIBUTION_VERSION_FRAGMENT = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:\.dev[1-9][0-9]*)?"
)


def _surrounded(prefix: str, suffix: str) -> re.Pattern[str]:
    return re.compile(
        re.escape(prefix)
        + rf"(?P<version>{PRODUCT_VERSION_FRAGMENT})"
        + re.escape(suffix)
    )


ROOT_DEPENDENCIES = (
    "cigar-api",
    "cigar-protocol",
    "cigar-canon",
    "cigar-catalog",
    "cigar-code-intel",
    "cigar-compiler",
    "cigar-crypto",
    "cigar-effects",
    "cigar-mcp",
    "cigar-policy",
    "cigar-replay",
    "cigar-retrieval",
    "cigar-space",
    "cigar-testkit",
    "cigar-store",
    "cigar-sdk",
)
CARGO_DEPENDENCY_BINDINGS: dict[str, tuple[str, ...]] = {
    "Cargo.toml": ROOT_DEPENDENCIES,
    "crates/cigar-cli/Cargo.toml": ("cigar-daemon", "cigar-effects"),
    "crates/cigar-daemon/Cargo.toml": (
        "cigar-api",
        "cigar-compiler",
        "cigar-effects",
        "cigar-replay",
        "cigar-space",
        "cigar-windows-ipc",
    ),
    "sdk/rust/Cargo.toml": (
        "cigar-api",
        "cigar-canon",
        "cigar-daemon",
        "cigar-protocol",
    ),
}

ROOT_CARGO_PACKAGES = (
    "cigar-api",
    "cigar-canon",
    "cigar-catalog",
    "cigar-claude-hook",
    "cigar-cli",
    "cigar-code-intel",
    "cigar-compiler",
    "cigar-conformance",
    "cigar-crypto",
    "cigar-daemon",
    "cigar-dashboard",
    "cigar-effects",
    "cigar-extension-host",
    "cigar-mcp",
    "cigar-observe",
    "cigar-policy",
    "cigar-protocol",
    "cigar-replay",
    "cigar-retrieval",
    "cigar-sdk",
    "cigar-sim",
    "cigar-soak",
    "cigar-space",
    "cigar-store",
    "cigar-testkit",
    "cigar-windows-ipc",
)
CARGO_LOCK_BINDINGS: dict[str, tuple[str, ...]] = {
    "Cargo.lock": ROOT_CARGO_PACKAGES,
    "fuzz/Cargo.lock": (
        "cigar-canon",
        "cigar-catalog",
        "cigar-code-intel",
        "cigar-compiler",
        "cigar-crypto",
        "cigar-effects",
        "cigar-extension-host",
        "cigar-mcp",
        "cigar-policy",
        "cigar-protocol",
        "cigar-replay",
        "cigar-retrieval",
        "cigar-store",
    ),
    "tests/miri/Cargo.lock": ("cigar-canon", "cigar-protocol"),
    "tests/properties/Cargo.lock": (
        "cigar-canon",
        "cigar-catalog",
        "cigar-compiler",
        "cigar-crypto",
        "cigar-effects",
        "cigar-policy",
        "cigar-protocol",
        "cigar-retrieval",
        "cigar-store",
    ),
    "demos/sdk-clients/rust-workflow/Cargo.lock": (
        "cigar-api",
        "cigar-canon",
        "cigar-protocol",
        "cigar-sdk",
    ),
}
UV_LOCK_BINDINGS = {
    "uv.lock": "cigar-workspace",
    "sdk/python/uv.lock": "cigar-sdk",
}

SDK_RELEASE_RECORDS = {
    "sdk/rust/release.json": "cigar-sdk",
    "sdk/typescript/release.json": "@cigar/sdk",
    "sdk/python/src/cigar_sdk/release.json": "cigar-sdk",
    "sdk/go/release.json": "github.com/CIGAR/cigar/sdk/go",
}
CRATE_RELEASE_RECORDS = {
    f"crates/{name}/release.json": name
    for name in (
        "cigar-api",
        "cigar-canon",
        "cigar-catalog",
        "cigar-code-intel",
        "cigar-compiler",
        "cigar-crypto",
        "cigar-daemon",
        "cigar-effects",
        "cigar-policy",
        "cigar-protocol",
        "cigar-replay",
        "cigar-retrieval",
        "cigar-space",
        "cigar-store",
        "cigar-testkit",
        "cigar-windows-ipc",
    )
}
RELEASE_RECORDS = {**SDK_RELEASE_RECORDS, **CRATE_RELEASE_RECORDS}

JSON_VERSION_FIELDS = {
    "sdk/typescript/package.json": ("@cigar/sdk", "name"),
    "adapters/claude-code/.claude-plugin/plugin.json": ("cigar", "name"),
}
TOML_PACKAGE_VERSIONS = {
    "Cargo.toml": ("workspace.package", "cigar"),
    "pyproject.toml": ("project", "cigar-workspace"),
    "sdk/rust/Cargo.toml": ("package", "cigar-sdk"),
    "sdk/python/pyproject.toml": ("project", "cigar-sdk"),
}

PUBLISHABLE_PRODUCT_PACKAGES = (
    "cigar-canon",
    "cigar-protocol",
    "cigar-testkit",
    "cigar-windows-ipc",
    "cigar-crypto",
    "cigar-replay",
    "cigar-policy",
    "cigar-store",
    "cigar-effects",
    "cigar-retrieval",
    "cigar-space",
    "cigar-catalog",
    "cigar-code-intel",
    "cigar-compiler",
    "cigar-api",
    "cigar-daemon",
    "cigar-sdk",
)
_publishable_names = "|".join(re.escape(name) for name in PUBLISHABLE_PRODUCT_PACKAGES)
TEXT_VERSION_BINDINGS: dict[str, tuple[re.Pattern[str], int]] = {
    "crates/cigar-cli/src/lib.rs": (
        _surrounded('assert!(version.stdout.contains("\\"version\\":\\"', '\\""));'),
        1,
    ),
    "crates/cigar-daemon/src/process.rs": (
        _surrounded('assert!(version.stdout.contains("\\"version\\":\\"', '\\""));'),
        1,
    ),
    "sdk/typescript/src/tests/release-contract.test.ts": (
        _surrounded('assert.equal(release.version, "', '");'),
        1,
    ),
    "sdk/go/release_contract_test.go": (
        _surrounded('release.Version != "', '" ||'),
        1,
    ),
    "sdk/README.md": (_surrounded("package version `", "`."), 1),
    "sdk/rust/PUBLISHING.md": (
        re.compile(
            rf"`(?:{_publishable_names}) = (?P<version>{PRODUCT_VERSION_FRAGMENT})`"
        ),
        19,
    ),
    "sdk/rust/qualify_publication_chain.py": (
        _surrounded('PRODUCT_VERSION = "', '"'),
        1,
    ),
    "adapters/claude-code/tests/validate_package.py": (
        _surrounded(
            'require(plugin.get("version") == "', '", "plugin version mismatch")'
        ),
        1,
    ),
    "adapters/claude-code/tests/validate-package.ps1": (
        _surrounded(
            'Require ($plugin.name -eq "cigar" -and $plugin.version -eq "',
            '") "plugin identity mismatch"',
        ),
        1,
    ),
    "docs/site/index.md": (
        _surrounded("This site describes product version ", " and Context ABI"),
        1,
    ),
    "crates/cigar-cli/man/cigar.1": (_surrounded('"CIGAR ', '" "User Commands"'), 1),
    "scripts/release/qualify_install.py": (
        _surrounded('DEFAULT_PRODUCT_VERSION = "', '"'),
        1,
    ),
    "scripts/release/run_local_qualification.py": (
        _surrounded('PRODUCT_VERSION = "', '"'),
        1,
    ),
    "demos/agent-handoff/driver.py": (
        _surrounded('version.get("version") == "', '",'),
        1,
    ),
    "demos/README.md": (
        re.compile(
            rf"(?:--expected-version |cigar-sdk-|cigar-go-sdk-)"
            rf"(?P<version>{PRODUCT_VERSION_FRAGMENT})"
            r"(?=(?:\s|\.crate|\.tgz|-py3-none-any\.whl|\.tar\.gz))"
        ),
        4,
    ),
    "scripts/release/README.md": (
        _surrounded("verify_package.py /tmp/cigar-dist/cigar-", "-source.tar.gz"),
        1,
    ),
}
PYTHON_TEXT_VERSION_BINDINGS: dict[str, tuple[re.Pattern[str], int]] = {
    "demos/README.md": (
        re.compile(
            rf"cigar_sdk-(?P<version>{PYTHON_DISTRIBUTION_VERSION_FRAGMENT})"
            r"(?=-py3-none-any\.whl)"
        ),
        1,
    ),
}
DERIVED_VERSION_CONSUMERS = {
    "scripts/release/check_docs.py": (
        'manifest.get("version_selectors") != [manifest.get("product_version")]',
        1,
    ),
    "sdk/python/tests/test_release_contract.py": (
        'release["version"].replace("-dev.", ".dev")',
        1,
    ),
}

LEGACY_EXACT_VERSION_ALLOWED: dict[str, str] = {
    "Cargo.lock": "third-party package versions",
    "conformance/runner/src/vectors.rs": "frozen conformance minimum implementation",
    "conformance/vectors/v1/fixture.toml": "frozen conformance minimum implementation",
    "crates/cigar-dashboard/src/status.rs": "generic dashboard transport sample",
    "demos/sdk-clients/rust-workflow/Cargo.lock": "recorded demo package identity",
    "demos/sdk-clients/rust-workflow/Cargo.toml": "recorded demo package identity",
    "fuzz/Cargo.lock": "third-party package versions",
    "packaging/beta/build-projection/Cargo.lock": "immutable beta build projection",
    "packaging/beta/build-projection/Cargo.toml": "immutable beta build projection",
    "packaging/beta/cargo-resolution.v1.json": "immutable beta dependency evidence",
    "packaging/licenses/third-party-inventory.v1.json": "third-party package versions",
    "scripts/release/selftest_release_verifier.py": "arbitrary verifier fixture identity",
    "scripts/release/tests/test_beta_artifacts.py": "immutable beta projection fixture",
    "sdk/go/grpc_contract_test.go": "generic transport fixture",
    "sdk/python/tests/test_client.py": "generic transport fixture",
    "sdk/rust/tests/remote_http.rs": "generic transport fixture",
    "todo-launch.md": "historical launch plan",
}
LEGACY_SCAN_ROOTS = (
    "Cargo.lock",
    "adapters/claude-code/tests",
    "conformance",
    "crates",
    "demos",
    "docs",
    "fuzz/Cargo.lock",
    "packaging",
    "scripts/release",
    "sdk",
    "todo-launch.md",
)
LEGACY_EXACT_VERSION = re.compile(r"(?<![0-9A-Za-z.-])0\.1\.0(?![0-9A-Za-z.-])")

ARTIFACT_IDS = (
    "source",
    "docs",
    "schemas",
    "conformance",
    "benchmarks",
    "licenses",
    "cli-daemon-linux-x86_64-gnu",
    "cli-daemon-linux-aarch64-gnu",
    "cli-daemon-macos-x86_64",
    "cli-daemon-macos-aarch64",
    "cigar-conformance-macos-aarch64",
    "cigarbench-macos-aarch64",
    "macos-homebrew-formula-arm64",
    "macos-installer-arm64",
    "cli-daemon-windows-x86_64",
    "typescript-sdk",
    "rust-sdk-crate",
    "python-sdk-sdist",
    "python-sdk-wheel",
    "go-sdk",
    "claude-code-plugin",
    "shared-oci",
)
ARCHIVE_IDS = ("source", "docs", "schemas", "conformance", "benchmarks", "licenses")


def _indices(pointer: str, count: int) -> tuple[str, ...]:
    return tuple(f"/{pointer}/{index}" for index in range(count))


CONTRACT_BINDINGS: dict[str, tuple[str, re.Pattern[str], tuple[str, ...]]] = {
    "packaging/contracts/homebrew-bottle.v1.json": (
        "homebrew-bottle-v1",
        re.compile(r"cigar/([^/]+)/"),
        (
            "/allow/0",
            *_indices("required", 13),
        ),
    ),
    "packaging/contracts/cargo-crate.v1.json": (
        "cargo-crate-v1",
        re.compile(r"cigar-sdk-([^/]+)/"),
        (
            *_indices("allow", 9),
            *_indices("required", 9),
            "/required_patterns/0",
            "/version_binding/path_pattern",
            "/abi_binding/path_pattern",
        ),
    ),
    "packaging/contracts/go-module.v1.json": (
        "go-module-v1",
        re.compile(r"github\.com/CIGAR/cigar/sdk/go@v([^/]+)/"),
        (
            "/allow/0",
            *_indices("required", 5),
            "/required_patterns/0",
            "/version_binding/path_pattern",
            "/abi_binding/path_pattern",
        ),
    ),
    "packaging/contracts/python-sdist.v1.json": (
        "python-sdist-v1",
        re.compile(r"cigar_sdk-([^/]+)/"),
        (
            *_indices("allow", 8),
            *_indices("required", 7),
            "/required_patterns/0",
            "/version_binding/path_pattern",
            "/abi_binding/path_pattern",
        ),
    ),
    "packaging/contracts/python-wheel.v1.json": (
        "python-wheel-v1",
        re.compile(r"cigar_sdk-([^/]+)\.dist-info/"),
        (
            "/allow/1",
            "/required/1",
            "/required/2",
            "/required/3",
            "/required_patterns/0",
        ),
    ),
}

FORBIDDEN_PREFIXES = (
    "packaging/beta/",
    "reports/",
    "artifacts/",
)
FORBIDDEN_FILES = (
    "apps/dashboard/package.json",
    "crates/cigar-aws-creds/Cargo.toml",
    "crates/cigar-aws-creds/release.json",
    "crates/cigar-rust-s3/Cargo.toml",
    "crates/cigar-rust-s3/release.json",
    "conformance/vectors/v1/fixture.toml",
    "schemas/openapi/cigar-v1.json",
)


class VersionError(RuntimeError):
    """A product-version authority or propagation invariant failed."""


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VersionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise VersionError(f"non-finite JSON number at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_nonfinite(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_nonfinite(item, f"{path}.{key}")


def _json_constant(value: str) -> Any:
    raise VersionError(f"non-finite JSON constant: {value}")


def python_distribution_version(version: str) -> str:
    """Return the exact PEP 440 form used in Python archive/member names."""

    match = SEMVER.fullmatch(version)
    if match is None:
        raise VersionError(f"cannot derive Python distribution version: {version!r}")
    base = ".".join(match.group(index) for index in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return base
    development = re.fullmatch(r"dev\.([1-9][0-9]*)", prerelease)
    if development is None:
        raise VersionError(f"unsupported Python distribution prerelease: {version!r}")
    return f"{base}.dev{development.group(1)}"


def _read_json(path: Path) -> Any:
    try:
        payload = path.read_bytes()
        if len(payload) > MAX_JSON_BYTES:
            raise VersionError(
                f"JSON exceeds {MAX_JSON_BYTES} bytes: {path} ({len(payload)} bytes)"
            )
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicates,
            parse_constant=_json_constant,
        )
        _reject_nonfinite(document)
        return document
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VersionError(f"cannot read strict JSON {path}: {error}") from error


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise VersionError(f"cannot read TOML {path}: {error}") from error


def _relative_path(relative: str) -> PurePosixPath:
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise VersionError(f"unsafe managed path: {relative}")
    return candidate


def _safe_regular_file(root: Path, relative: str) -> os.stat_result:
    candidate = _relative_path(relative)
    cursor = root
    try:
        root_status = os.lstat(root)
    except OSError as error:
        raise VersionError(f"cannot inspect product-version root: {error}") from error
    if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
        raise VersionError("product-version root must be a real directory")
    for component in candidate.parts[:-1]:
        cursor /= component
        try:
            parent_status = os.lstat(cursor)
        except OSError as error:
            raise VersionError(
                f"cannot inspect managed parent {cursor}: {error}"
            ) from error
        if not stat.S_ISDIR(parent_status.st_mode) or stat.S_ISLNK(
            parent_status.st_mode
        ):
            raise VersionError(f"managed parent must be a real directory: {cursor}")
        if cursor.resolve(strict=True) != cursor:
            raise VersionError(f"managed parent resolves through a link: {cursor}")
    path = root.joinpath(*candidate.parts)
    try:
        status = os.lstat(path)
    except OSError as error:
        raise VersionError(
            f"cannot inspect managed file {relative}: {error}"
        ) from error
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
        raise VersionError(f"managed path must be a regular file: {relative}")
    if status.st_nlink != 1:
        raise VersionError(f"managed path must have exactly one hard link: {relative}")
    if path.resolve(strict=True) != path:
        raise VersionError(f"managed path resolves through a link: {relative}")
    return status


def _validate_managed_files(root: Path) -> None:
    for relative in managed_paths():
        _safe_regular_file(root, relative)


def _write(path: Path, text: str) -> None:
    if not text.endswith("\n"):
        raise VersionError(f"generated text lacks final newline: {path}")
    try:
        status = os.lstat(path)
    except OSError as error:
        raise VersionError(
            f"cannot inspect generated destination {path}: {error}"
        ) from error
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_nlink != 1
        or path.parent.resolve(strict=True) != path.parent
        or path.resolve(strict=True) != path
    ):
        raise VersionError(
            f"generated destination is not a safe single-link file: {path}"
        )
    payload = text.encode("utf-8")
    if path.read_bytes() == payload:
        return
    descriptor, temporary_raw = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.product-version.", suffix=".tmp"
    )
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            os.fchmod(output.fileno(), stat.S_IMODE(status.st_mode))
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        replacement_status = os.lstat(path)
        if (
            replacement_status.st_dev != status.st_dev
            or replacement_status.st_ino != status.st_ino
            or replacement_status.st_nlink != 1
        ):
            raise VersionError(f"generated destination changed during update: {path}")
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / MANIFEST_PATH
    document = _read_json(path)
    expected_keys = {
        "schema_version",
        "product",
        "version",
        "target_release_version",
        "context_abi",
        "release_state",
        "channel",
        "prerelease",
        "published",
        "supported",
        "tag",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise VersionError("product version manifest has an unexpected key inventory")
    version = document.get("version")
    target = document.get("target_release_version")
    if (
        document.get("schema_version") != "cigar.product-version.v1"
        or document.get("product") != "cigar"
        or target != EXPECTED_TARGET_RELEASE
        or not isinstance(version, str)
        or SEMVER.fullmatch(version) is None
        or not version.startswith(f"{target}-dev.")
        or not version.removeprefix(f"{target}-dev.").isdigit()
        or int(version.removeprefix(f"{target}-dev.")) < 1
        or document.get("context_abi") != EXPECTED_CONTEXT_ABI
        or document.get("release_state") != "development"
        or document.get("channel") != "development"
        or document.get("prerelease") is not True
        or document.get("published") is not False
        or document.get("supported") is not False
        or document.get("tag") is not None
    ):
        raise VersionError(
            "product version manifest is not a non-published 1.0 development identity"
        )
    canonical = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    if path.read_text(encoding="utf-8") != canonical:
        raise VersionError("product version manifest is not canonical JSON")
    return document


def managed_paths() -> tuple[str, ...]:
    paths = {
        MANIFEST_PATH,
        *CARGO_DEPENDENCY_BINDINGS,
        *CARGO_LOCK_BINDINGS,
        *UV_LOCK_BINDINGS,
        *RELEASE_RECORDS,
        *JSON_VERSION_FIELDS,
        *TOML_PACKAGE_VERSIONS,
        *CONTRACT_BINDINGS,
        *TEXT_VERSION_BINDINGS,
        *PYTHON_TEXT_VERSION_BINDINGS,
        *DERIVED_VERSION_CONSUMERS,
        "packaging/artifact-matrix.v1.json",
        "packaging/local-archives.v1.json",
        "docs/site-manifest.v1.json",
        "adapters/claude-code/package-manifest.json",
    }
    return tuple(sorted(paths))


def _assert_inventory() -> None:
    paths = managed_paths()
    if len(paths) != len(set(paths)):
        raise VersionError("managed path inventory contains duplicates")
    for path in paths:
        if path in FORBIDDEN_FILES or any(
            path.startswith(prefix) for prefix in FORBIDDEN_PREFIXES
        ):
            raise VersionError(
                f"managed path enters a forbidden version domain: {path}"
            )


def _toml_section(document: dict[str, Any], dotted: str) -> dict[str, Any]:
    value: Any = document
    for component in dotted.split("."):
        if not isinstance(value, dict) or component not in value:
            raise VersionError(f"missing TOML section: {dotted}")
        value = value[component]
    if not isinstance(value, dict):
        raise VersionError(f"invalid TOML section: {dotted}")
    return value


def _replace_section_version(text: str, section: str, version: str) -> str:
    header = re.search(rf"(?m)^\[{re.escape(section)}\]\s*$", text)
    if header is None:
        raise VersionError(f"missing TOML section [{section}]")
    next_header = re.search(r"(?m)^\[", text[header.end() :])
    end = len(text) if next_header is None else header.end() + next_header.start()
    body = text[header.end() : end]
    pattern = re.compile(r'(?m)^(version\s*=\s*")[^"]+("\s*)$')
    body, count = pattern.subn(rf"\g<1>{version}\g<2>", body)
    if count != 1:
        raise VersionError(
            f"expected one version in TOML section [{section}], found {count}"
        )
    return text[: header.end()] + body + text[end:]


def _replace_dependency_pin(text: str, name: str, version: str) -> str:
    pattern = re.compile(
        rf'(?m)^({re.escape(name)}\s*=\s*\{{[^\n]*\bversion\s*=\s*")=[^"]+("[^\n]*\}}\s*)$'
    )
    result, count = pattern.subn(rf"\g<1>={version}\g<2>", text)
    if count != 1:
        raise VersionError(
            f"expected one exact path dependency pin for {name}, found {count}"
        )
    return result


def _update_toml_manifests(root: Path, version: str, *, write: bool) -> None:
    for relative, (section_name, expected_name) in TOML_PACKAGE_VERSIONS.items():
        path = root / relative
        document = _read_toml(path)
        section = _toml_section(document, section_name)
        if section_name == "workspace.package":
            actual_name = "cigar"
        else:
            actual_name = section.get("name")
        if actual_name != expected_name or not isinstance(section.get("version"), str):
            raise VersionError(f"package identity drift in {relative}")
        if write:
            _write(
                path,
                _replace_section_version(
                    path.read_text(encoding="utf-8"), section_name, version
                ),
            )
        elif section["version"] != version:
            raise VersionError(
                f"product version drift in {relative}: {section['version']!r}"
            )

    for relative, names in CARGO_DEPENDENCY_BINDINGS.items():
        path = root / relative
        document = _read_toml(path)
        dependency_table = (
            _toml_section(document, "workspace.dependencies")
            if relative == "Cargo.toml"
            else _toml_section(document, "dependencies")
        )
        text = path.read_text(encoding="utf-8")
        for name in names:
            value = dependency_table.get(name)
            if (
                relative == "crates/cigar-daemon/Cargo.toml"
                and name == "cigar-windows-ipc"
            ):
                try:
                    value = document["target"]["cfg(windows)"]["dependencies"][name]
                except (KeyError, TypeError):
                    value = None
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("path"), str)
                or not isinstance(value.get("version"), str)
                or not value["version"].startswith("=")
            ):
                raise VersionError(
                    f"exact internal dependency binding missing: {relative}:{name}"
                )
            if write:
                text = _replace_dependency_pin(text, name, version)
            elif value["version"] != f"={version}":
                raise VersionError(
                    f"internal dependency version drift: {relative}:{name}"
                )
        if write:
            _write(path, text)


def _replace_lock_package_versions(
    text: str, names: Iterable[str], version: str
) -> str:
    expected = set(names)
    seen: set[str] = set()
    blocks = re.split(r"(?=^\[\[package\]\]\s*$)", text, flags=re.MULTILINE)
    output: list[str] = []
    for block in blocks:
        name_match = re.search(r'(?m)^name = "([^"]+)"$', block)
        if name_match is not None and name_match.group(1) in expected:
            name = name_match.group(1)
            if name in seen:
                raise VersionError(f"duplicate managed lock package: {name}")
            seen.add(name)
            block, count = re.subn(
                r'(?m)^(version = ")[^"]+("\s*)$',
                rf"\g<1>{version}\g<2>",
                block,
            )
            if count != 1:
                raise VersionError(f"invalid lock package block: {name}")
        output.append(block)
    if seen != expected:
        raise VersionError(
            f"managed lock package inventory drift: missing={sorted(expected - seen)}"
        )
    return "".join(output)


def _update_locks(root: Path, version: str, *, write: bool) -> None:
    for relative, names in CARGO_LOCK_BINDINGS.items():
        path = root / relative
        text = path.read_text(encoding="utf-8")
        generated = _replace_lock_package_versions(text, names, version)
        if write:
            _write(path, generated)
        elif generated != text:
            raise VersionError(f"Cargo lock version drift in {relative}")
        _read_toml(path)
    for relative, name in UV_LOCK_BINDINGS.items():
        path = root / relative
        text = path.read_text(encoding="utf-8")
        generated = _replace_lock_package_versions(text, (name,), version)
        if write:
            _write(path, generated)
        elif generated != text:
            raise VersionError(f"uv lock version drift in {relative}")
        _read_toml(path)


def _replace_json_string_field(
    text: str, key: str, value: str, expected: int = 1
) -> str:
    encoded = json.dumps(value, ensure_ascii=True)
    pattern = re.compile(rf'("{re.escape(key)}"\s*:\s*)"[^"]*"')
    result, count = pattern.subn(rf"\g<1>{encoded}", text)
    if count != expected:
        raise VersionError(
            f"expected {expected} JSON field(s) named {key}, found {count}"
        )
    return result


def _update_release_records(root: Path, version: str, abi: str, *, write: bool) -> None:
    for relative, name in RELEASE_RECORDS.items():
        path = root / relative
        document = _read_json(path)
        schema = (
            "cigar.sdk-release.v1"
            if relative in SDK_RELEASE_RECORDS
            else "cigar.crate-release.v1"
        )
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "name", "version", "context_abi"}
            or document.get("schema_version") != schema
            or document.get("name") != name
        ):
            raise VersionError(f"release record identity drift in {relative}")
        if write:
            text = path.read_text(encoding="utf-8")
            text = _replace_json_string_field(text, "version", version)
            text = _replace_json_string_field(text, "context_abi", abi)
            _write(path, text)
        elif document.get("version") != version or document.get("context_abi") != abi:
            raise VersionError(f"release record version/ABI drift in {relative}")


def _update_json_package_versions(root: Path, version: str, *, write: bool) -> None:
    for relative, (expected_name, name_key) in JSON_VERSION_FIELDS.items():
        path = root / relative
        document = _read_json(path)
        if not isinstance(document, dict) or document.get(name_key) != expected_name:
            raise VersionError(f"JSON package identity drift in {relative}")
        if write:
            _write(
                path,
                _replace_json_string_field(
                    path.read_text(encoding="utf-8"), "version", version
                ),
            )
        elif document.get("version") != version:
            raise VersionError(f"JSON package version drift in {relative}")


def _replace_text_binding(
    text: str,
    pattern: re.Pattern[str],
    expected_count: int,
    desired: str,
    relative: str,
    accepted_version: re.Pattern[str] = SEMVER,
) -> str:
    matches = list(pattern.finditer(text))
    if len(matches) != expected_count:
        raise VersionError(
            f"expected {expected_count} version binding(s) in {relative}, found {len(matches)}"
        )
    versions = {match.group("version") for match in matches}
    if len(versions) != 1 or any(
        accepted_version.fullmatch(version) is None for version in versions
    ):
        raise VersionError(f"inconsistent or invalid version bindings in {relative}")

    def replace(match: re.Match[str]) -> str:
        start, end = match.span("version")
        whole_start, _whole_end = match.span(0)
        relative_start = start - whole_start
        relative_end = end - whole_start
        value = match.group(0)
        return value[:relative_start] + desired + value[relative_end:]

    return pattern.sub(replace, text)


def _update_text_consumers(root: Path, version: str, *, write: bool) -> None:
    for relative, (pattern, expected_count) in TEXT_VERSION_BINDINGS.items():
        path = root / relative
        text = path.read_text(encoding="utf-8")
        generated = _replace_text_binding(
            text, pattern, expected_count, version, relative
        )
        if write:
            _write(path, generated)
        elif generated != text:
            raise VersionError(f"full-product version consumer drift in {relative}")

    python_version = python_distribution_version(version)
    for relative, (pattern, expected_count) in PYTHON_TEXT_VERSION_BINDINGS.items():
        path = root / relative
        text = path.read_text(encoding="utf-8")
        generated = _replace_text_binding(
            text,
            pattern,
            expected_count,
            python_version,
            relative,
            re.compile(PYTHON_DISTRIBUTION_VERSION_FRAGMENT),
        )
        if write:
            _write(path, generated)
        elif generated != text:
            raise VersionError(
                f"Python distribution version consumer drift in {relative}"
            )

    for relative, (snippet, expected_count) in DERIVED_VERSION_CONSUMERS.items():
        count = (root / relative).read_text(encoding="utf-8").count(snippet)
        if count != expected_count:
            raise VersionError(
                f"derived product-version consumer drift in {relative}: "
                f"expected {expected_count}, found {count}"
            )


def legacy_exact_version_paths(root: Path) -> set[str]:
    excluded_directories = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "artifacts",
        "dist",
        "node_modules",
        "reports",
        "target",
    }
    candidates: set[Path] = set()
    for relative in LEGACY_SCAN_ROOTS:
        path = root / relative
        if path.is_file() and not path.is_symlink():
            candidates.add(path)
            continue
        if not path.is_dir() or path.is_symlink():
            continue
        for candidate in path.rglob("*"):
            if any(part in excluded_directories for part in candidate.parts):
                continue
            if candidate.is_file() and not candidate.is_symlink():
                candidates.add(candidate)
    matched: set[str] = set()
    for path in sorted(candidates):
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise VersionError(
                f"cannot scan legacy version consumer {path}: {error}"
            ) from error
        if b"\x00" in payload:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if LEGACY_EXACT_VERSION.search(text) is not None:
            matched.add(path.relative_to(root).as_posix())
    return matched


def _check_legacy_exact_version_consumers(root: Path) -> None:
    observed = legacy_exact_version_paths(root)
    unexpected = observed - set(LEGACY_EXACT_VERSION_ALLOWED)
    if unexpected:
        raise VersionError(
            "unmanaged legacy development-version consumer(s): "
            + ", ".join(sorted(unexpected))
        )


def _pointer(document: Any, pointer: str) -> Any:
    value = document
    for token in pointer.removeprefix("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            try:
                value = value[int(token)]
            except (ValueError, IndexError) as error:
                raise VersionError(f"invalid JSON pointer: {pointer}") from error
        elif isinstance(value, dict) and token in value:
            value = value[token]
        else:
            raise VersionError(f"invalid JSON pointer: {pointer}")
    return value


def _replace_consistent_version(
    path: Path,
    pointers: tuple[str, ...],
    desired: str,
    pattern: re.Pattern[str] | None = None,
    *,
    document: Any | None = None,
    text: str | None = None,
) -> str:
    if document is None:
        document = _read_json(path)
    values = [_pointer(document, pointer) for pointer in pointers]
    if not all(isinstance(value, str) for value in values):
        raise VersionError(f"non-string version binding in {path}")
    if pattern is None:
        old_versions = {str(value) for value in values[:1]}
        old = next(iter(old_versions))
        if any(old not in str(value) for value in values):
            raise VersionError(f"inconsistent version bindings in {path}")
    else:
        matches = [pattern.search(str(value)) for value in values]
        if any(match is None for match in matches):
            raise VersionError(f"missing package-layout version binding in {path}")
        old_versions = {match.group(1) for match in matches if match is not None}
        if len(old_versions) != 1:
            raise VersionError(f"inconsistent package-layout versions in {path}")
        old = next(iter(old_versions))
    if text is None:
        text = path.read_text(encoding="utf-8")
    if old == desired:
        return text
    replacements: dict[str, str] = {}
    occurrences: dict[str, int] = {}
    for value in values:
        current = str(value)
        occurrences[current] = occurrences.get(current, 0) + 1
        if pattern is None:
            replacement = current.replace(old, desired)
        else:
            match = pattern.search(current)
            if match is None:
                raise VersionError(f"missing package-layout version binding in {path}")
            start, end = match.span(1)
            replacement = current[:start] + desired + current[end:]
        previous = replacements.setdefault(current, replacement)
        if previous != replacement:
            raise VersionError(f"ambiguous version replacement in {path}")
    for current, replacement in replacements.items():
        encoded_current = json.dumps(current, ensure_ascii=True)
        expected_count = occurrences[current]
        if text.count(encoded_current) != expected_count:
            raise VersionError(
                f"unmanaged occurrence of version-bound value {current!r} in {path}"
            )
        text = text.replace(encoded_current, json.dumps(replacement, ensure_ascii=True))
    return text


def _update_documents(root: Path, version: str, abi: str, *, write: bool) -> None:
    artifact_path = root / "packaging/artifact-matrix.v1.json"
    artifact = _read_json(artifact_path)
    if (
        not isinstance(artifact, dict)
        or artifact.get("schema_version") != "cigar.artifact-matrix.v1"
        or artifact.get("product") != "cigar"
        or [item.get("id") for item in artifact.get("artifacts", [])]
        != list(ARTIFACT_IDS)
    ):
        raise VersionError("artifact matrix identity/inventory drift")
    python_artifact_indexes = tuple(
        index
        for index, identifier in enumerate(ARTIFACT_IDS)
        if identifier in {"python-sdk-sdist", "python-sdk-wheel"}
    )
    artifact_pointers = ("/product_version",) + tuple(
        f"/artifacts/{index}/filename"
        for index in range(len(ARTIFACT_IDS))
        if index not in python_artifact_indexes
    )
    text = _replace_consistent_version(
        artifact_path,
        artifact_pointers,
        version,
        document=artifact,
    )
    text = _replace_consistent_version(
        artifact_path,
        tuple(f"/artifacts/{index}/filename" for index in python_artifact_indexes),
        python_distribution_version(version),
        re.compile(
            rf"cigar_sdk-({PRODUCT_VERSION_FRAGMENT}|"
            rf"{PYTHON_DISTRIBUTION_VERSION_FRAGMENT})"
            r"(?=\.tar\.gz|-py3-none-any\.whl)"
        ),
        document=artifact,
        text=text,
    )
    text = _replace_json_string_field(text, "context_abi", abi)
    text = _replace_json_string_field(text, "release_state", "development")
    bottle_index = ARTIFACT_IDS.index("macos-installer-arm64")
    text = _replace_consistent_version(
        artifact_path,
        (f"/artifacts/{bottle_index}/install_target",),
        version,
        re.compile(r"homebrew-cellar/cigar/([^/]+)$"),
        document=artifact,
        text=text,
    )
    if write:
        _write(artifact_path, text)
    elif text != artifact_path.read_text(encoding="utf-8"):
        raise VersionError("artifact matrix version/state drift")

    archive_path = root / "packaging/local-archives.v1.json"
    archive = _read_json(archive_path)
    if (
        not isinstance(archive, dict)
        or archive.get("schema_version") != "cigar.local-archives.v1"
        or [item.get("id") for item in archive.get("archives", [])] != list(ARCHIVE_IDS)
    ):
        raise VersionError("local archive identity/inventory drift")
    archive_pointers = ("/product_version",) + tuple(
        f"/archives/{index}/filename" for index in range(len(ARCHIVE_IDS))
    )
    text = _replace_consistent_version(archive_path, archive_pointers, version)
    text = _replace_json_string_field(text, "context_abi", abi)
    if write:
        _write(archive_path, text)
    elif text != archive_path.read_text(encoding="utf-8"):
        raise VersionError("local archive version/ABI drift")

    docs_path = root / "docs/site-manifest.v1.json"
    docs = _read_json(docs_path)
    if not isinstance(docs, dict) or docs.get("schema_version") != "cigar.docs-site.v1":
        raise VersionError("docs site manifest identity drift")
    text = _replace_json_string_field(
        docs_path.read_text(encoding="utf-8"), "product_version", version
    )
    text = _replace_json_string_field(text, "context_abi", abi)
    selector_pattern = re.compile(r'(?m)^(\s*"version_selectors"\s*:\s*)\[[^\n]*\]')
    text, count = selector_pattern.subn(
        rf"\g<1>{json.dumps([version], ensure_ascii=True)}", text
    )
    if count != 1:
        raise VersionError("docs version selector field is not a one-line array")
    if write:
        _write(docs_path, text)
    elif text != docs_path.read_text(encoding="utf-8"):
        raise VersionError("docs site version/ABI drift")

    for relative, (contract_id, pattern, pointers) in CONTRACT_BINDINGS.items():
        path = root / relative
        contract = _read_json(path)
        if (
            not isinstance(contract, dict)
            or contract.get("schema_version") != "cigar.package-contract.v1"
            or contract.get("id") != contract_id
        ):
            raise VersionError(f"package contract identity drift in {relative}")
        desired = (
            python_distribution_version(version)
            if relative
            in {
                "packaging/contracts/python-sdist.v1.json",
                "packaging/contracts/python-wheel.v1.json",
            }
            else version
        )
        text = _replace_consistent_version(path, pointers, desired, pattern)
        if write:
            _write(path, text)
        elif text != path.read_text(encoding="utf-8"):
            raise VersionError(f"package-layout version drift in {relative}")


def _plugin_manifest_document(root: Path) -> dict[str, Any]:
    plugin_root = root / "adapters/claude-code"
    package_manifest = plugin_root / "package-manifest.json"
    files: list[dict[str, Any]] = []
    for path in sorted(
        plugin_root.rglob("*"),
        key=lambda item: item.relative_to(plugin_root).as_posix(),
    ):
        if path == package_manifest:
            continue
        if path.is_symlink():
            raise VersionError(f"symlink is not packageable: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(plugin_root).as_posix()
        _safe_regular_file(root, f"adapters/claude-code/{relative}")
        payload = path.read_bytes()
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    return {"schema_version": "cigar.claude-code-package.v1", "files": files}


def _update_plugin_package_manifest(root: Path, *, write: bool) -> None:
    path = root / "adapters/claude-code/package-manifest.json"
    rendered = json.dumps(_plugin_manifest_document(root), indent=2) + "\n"
    if write:
        _write(path, rendered)
    elif path.read_text(encoding="utf-8") != rendered:
        raise VersionError(
            "Claude plugin package manifest does not bind exact package bytes"
        )


def generate(root: Path) -> None:
    root = root.resolve(strict=True)
    _assert_inventory()
    _validate_managed_files(root)
    manifest = load_manifest(root)
    version = manifest["version"]
    abi = manifest["context_abi"]
    _update_toml_manifests(root, version, write=True)
    _update_locks(root, version, write=True)
    _update_release_records(root, version, abi, write=True)
    _update_json_package_versions(root, version, write=True)
    _update_text_consumers(root, version, write=True)
    _update_documents(root, version, abi, write=True)
    _update_plugin_package_manifest(root, write=True)
    check(root)


def check(root: Path) -> None:
    root = root.resolve(strict=True)
    _assert_inventory()
    _validate_managed_files(root)
    manifest = load_manifest(root)
    version = manifest["version"]
    abi = manifest["context_abi"]
    _update_toml_manifests(root, version, write=False)
    _update_locks(root, version, write=False)
    _update_release_records(root, version, abi, write=False)
    _update_json_package_versions(root, version, write=False)
    _update_text_consumers(root, version, write=False)
    _update_documents(root, version, abi, write=False)
    _update_plugin_package_manifest(root, write=False)
    _check_legacy_exact_version_consumers(root)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
            "version propagation/checking does not emit release evidence"
        ),
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        reject_evidence_directory(arguments.evidence_dir, "product-version operation")
        if arguments.command == "generate":
            generate(arguments.root)
        else:
            check(arguments.root)
    except (ReleaseError, VersionError) as error:
        print(f"product-version: {error}", file=sys.stderr)
        return 1
    manifest = load_manifest(arguments.root.resolve())
    print(
        f"product-version: {arguments.command} passed for {manifest['version']} "
        f"({len(managed_paths())} managed files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
