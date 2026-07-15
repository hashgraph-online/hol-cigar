#!/usr/bin/env python3
"""Run and verify native macOS production-path sanitizer qualification.

This runner is intentionally narrower than the general quality matrix. It runs
only reviewed, exact production-path tests, rebuilds Rust's standard library
under the selected sanitizer, instruments native C dependencies for ASan with
the matching LLVM clang, and emits a content-free create-new receipt outside
the checkout. Rust/macOS UBSan is capability-probed but never claimed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).with_name("production-sanitizers.macos-aarch64.v1.json")
SCHEMA = "cigar.production-sanitizers.macos-aarch64.v1"
RECEIPT_SCHEMA = "cigar.production-sanitizers.receipt.v2"
RUSTUP_NAME = "nightly-2026-07-13"
RUSTC_RELEASE = "1.99.0-nightly"
RUSTC_COMMIT = "77cf889bc178ddb44d6a1c78e5a820b5abb31d8d"
LLVM_VERSION = "22.1.8"
TARGET = "aarch64-apple-darwin"
SCRATCH_ROOT = Path("/private/tmp/cigar-production-sanitizers-v1")
EXPECTED_CASE_IDS = (
    "tsan-production-direct-races",
    "tsan-production-surface-matrix",
    "tsan-effects-claim-fence",
    "tsan-effects-permit-entry",
    "tsan-provider-state-cas",
    "tsan-retrieval-generation-publication",
    "asan-sqlite-service-cas",
    "asan-effects-sqlite-recovery",
    "asan-tree-sitter-language-matrix",
    "asan-catalog-sqlite-invalidation",
)
REQUIRED_SURFACES = {
    "cache_publication",
    "context_revision",
    "effects",
    "event_cursor",
    "invalidation",
    "native_ffi",
    "outbox_fencing",
    "shared_coordination",
    "shutdown",
    "snapshot_visibility",
    "store",
}
FORBIDDEN_COMMAND_TOKENS = {
    "--exclude",
    "--ignored",
    "--skip",
    "--no-run",
    "--workspace",
    "--all-targets",
}
HARNESS_ARGUMENTS = ("--exact", "-Z", "unstable-options", "--format", "json")
UNSAFE_PATTERN = re.compile(
    rb"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)|extern\s+\"C\"|#\s*\[\s*link\b"
)
SANITIZER_DIAGNOSTIC_PATTERN = re.compile(
    rb"(?:address|thread|leak|memory|undefinedbehavior)sanitizer", re.IGNORECASE
)
MAX_CAPTURE_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
BASELINE_ENVIRONMENT_KEYS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "TMPDIR",
    "USER",
)


class QualificationError(RuntimeError):
    """The policy, source, toolchain, command, or result failed closed."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise QualificationError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def output_descriptor(value: bytes) -> dict[str, Any]:
    return {"bytes": len(value), "sha256": sha256_bytes(value)}


def _trusted_file_reference(
    path: Path, *, label: str, executable: bool
) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise QualificationError(f"{label} is unavailable: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or (executable and not before.st_mode & stat.S_IXUSR)
        ):
            raise QualificationError(
                f"{label} is not one owner-controlled regular file"
            )
        payload_parts: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload_parts.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise QualificationError(f"{label} changed while it was hashed")
    finally:
        os.close(descriptor)
    payload = b"".join(payload_parts)
    if len(payload) != before.st_size:
        raise QualificationError(f"{label} size changed while it was hashed")
    return {"path": str(resolved), **output_descriptor(payload)}


def _require_safe_directory_chain(path: Path, *, label: str) -> None:
    if not path.is_absolute():
        raise QualificationError(f"{label} path is not absolute")
    chain = [path, *path.parents]
    for directory in reversed(chain):
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise QualificationError(
                f"{label} ancestor is unavailable: {error}"
            ) from error
        mode = stat.S_IMODE(metadata.st_mode)
        trusted_sticky_root = (
            metadata.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o002)
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or directory.is_symlink()
            or metadata.st_uid not in {0, os.geteuid()}
            or (mode & 0o022 and not trusted_sticky_root)
        ):
            raise QualificationError(f"{label} has an unsafe ancestor: {directory}")


def _require_exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        found = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise QualificationError(
            f"{label} keys are not exact: expected {sorted(keys)}, got {found}"
        )
    return value


def _decode_json(
    payload: bytes, *, label: str, require_canonical: bool
) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError(
            f"cannot decode strict JSON {label}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise QualificationError(f"strict JSON root is not an object: {label}")
    if require_canonical and payload != canonical_json_bytes(value):
        raise QualificationError(f"JSON document is not canonical: {label}")
    return value


def _load_json(path: Path, *, require_canonical: bool) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise QualificationError(f"cannot read strict JSON {path}: {error}") from error
    return _decode_json(payload, label=str(path), require_canonical=require_canonical)


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    manifest = _load_json(path, require_canonical=False)
    validate_manifest(manifest)
    return manifest


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def validate_manifest(manifest: dict[str, Any]) -> None:
    _require_exact_keys(
        manifest,
        {
            "schema_version",
            "evidence_class",
            "platform",
            "toolchain",
            "source_scope",
            "required_surfaces",
            "test_exclusions",
            "scratch_root",
            "cases",
            "ub_equivalent",
        },
        "sanitizer manifest",
    )
    if manifest["schema_version"] != SCHEMA:
        raise QualificationError("unsupported sanitizer manifest schema")
    if manifest["evidence_class"] != "development_diagnostic":
        raise QualificationError(
            "sanitizer evidence must remain development diagnostic"
        )

    platform_binding = _require_exact_keys(
        manifest["platform"], {"system", "machine", "target"}, "platform binding"
    )
    if platform_binding != {
        "system": "Darwin",
        "machine": "arm64",
        "target": TARGET,
    }:
        raise QualificationError("sanitizer platform binding changed")

    toolchain = _require_exact_keys(
        manifest["toolchain"],
        {
            "rustup_name",
            "rustc_release",
            "rustc_commit_hash",
            "llvm_version",
            "required_components",
            "native_cc",
        },
        "toolchain binding",
    )
    if (
        toolchain["rustup_name"] != RUSTUP_NAME
        or toolchain["rustc_release"] != RUSTC_RELEASE
        or toolchain["rustc_commit_hash"] != RUSTC_COMMIT
        or toolchain["llvm_version"] != LLVM_VERSION
    ):
        raise QualificationError("pinned Rust toolchain identity changed")
    components = toolchain["required_components"]
    if (
        not isinstance(components, list)
        or not components
        or components != sorted(set(components))
        or not all(isinstance(item, str) and item for item in components)
        or "rust-src" not in components
    ):
        raise QualificationError("required Rust component inventory is invalid")
    native_cc = _require_exact_keys(
        toolchain["native_cc"], {"path", "version_prefix"}, "native clang binding"
    )
    if native_cc != {
        "path": "/opt/homebrew/opt/llvm/bin/clang",
        "version_prefix": "Homebrew clang version 22.1.8",
    }:
        raise QualificationError(
            "native clang must remain aligned with rustc LLVM 22.1.8"
        )

    scope = manifest["source_scope"]
    if (
        not isinstance(scope, list)
        or scope != list(dict.fromkeys(scope))
        or not all(_valid_relative_path(item) for item in scope)
        or ".cargo/config.toml" not in scope
        or "crates" not in scope
        or "tests/properties" not in scope
        or "tools/quality/production_sanitizers.py" not in scope
    ):
        raise QualificationError("sanitizer source scope is invalid or incomplete")
    if manifest["required_surfaces"] != sorted(REQUIRED_SURFACES):
        raise QualificationError("required sanitizer surface inventory changed")
    if manifest["test_exclusions"] != []:
        raise QualificationError("sanitizer qualification permits no test exclusions")
    if manifest["scratch_root"] != str(SCRATCH_ROOT):
        raise QualificationError("sanitizer scratch root changed")

    cases = manifest["cases"]
    if not isinstance(cases, list) or [
        case.get("id") for case in cases if isinstance(case, dict)
    ] != list(EXPECTED_CASE_IDS):
        raise QualificationError("sanitizer case inventory or ordering changed")
    covered: set[str] = set()
    for case in cases:
        validate_case(case, manifest)
        covered.update(case["surfaces"])
    if covered != REQUIRED_SURFACES:
        raise QualificationError(
            f"sanitizer surface coverage is incomplete: {sorted(REQUIRED_SURFACES - covered)}"
        )

    ub = _require_exact_keys(
        manifest["ub_equivalent"],
        {
            "rust_ubsan_status",
            "rust_ubsan_probe_value",
            "workspace_unsafe_policy",
            "macos_first_party_unsafe_expected",
            "platform_excluded_sources",
            "required_native_dependencies",
            "native_asan_case_ids",
        },
        "UB-equivalent policy",
    )
    if (
        ub["rust_ubsan_status"] != "unsupported_by_rustc_on_selected_target"
        or ub["rust_ubsan_probe_value"] != "undefined"
        or ub["workspace_unsafe_policy"] != "forbid"
        or ub["macos_first_party_unsafe_expected"] != 0
    ):
        raise QualificationError("Rust UB-equivalent policy overclaims support")
    excluded = ub["platform_excluded_sources"]
    if (
        not isinstance(excluded, list)
        or len(excluded) != 1
        or excluded[0].get("path") != "crates/cigar-windows-ipc/src/windows.rs"
        or not isinstance(excluded[0].get("reason"), str)
        or len(excluded[0]["reason"]) < 60
    ):
        raise QualificationError("platform-specific unsafe-source scope is not exact")
    native_dependencies = ub["required_native_dependencies"]
    if (
        not isinstance(native_dependencies, list)
        or native_dependencies != sorted(set(native_dependencies))
        or not native_dependencies
    ):
        raise QualificationError("native dependency inventory is invalid")
    asan_ids = [case["id"] for case in cases if case["sanitizer"] == "address"]
    if ub["native_asan_case_ids"] != asan_ids:
        raise QualificationError(
            "native ASan case inventory is incomplete or reordered"
        )


def validate_case(case: object, manifest: dict[str, Any]) -> None:
    case = _require_exact_keys(
        case,
        {
            "id",
            "sanitizer",
            "surfaces",
            "package",
            "manifest_path",
            "test_target",
            "test_selector",
            "command",
            "environment",
            "timeout_seconds",
            "exclusions",
        },
        "sanitizer case",
    )
    if case["sanitizer"] not in {"address", "thread"}:
        raise QualificationError(f"unsupported sanitizer for {case['id']}")
    if (
        not isinstance(case["surfaces"], list)
        or case["surfaces"] != sorted(set(case["surfaces"]))
        or not set(case["surfaces"]).issubset(REQUIRED_SURFACES)
        or not case["surfaces"]
    ):
        raise QualificationError(f"surface mapping is invalid for {case['id']}")
    for field in ("package", "manifest_path", "test_target", "test_selector"):
        if not isinstance(case[field], str) or not case[field] or "\x00" in case[field]:
            raise QualificationError(f"{field} is invalid for {case['id']}")
    if case["manifest_path"] != "." and not _valid_relative_path(case["manifest_path"]):
        raise QualificationError(f"manifest path is unsafe for {case['id']}")
    if case["exclusions"] != []:
        raise QualificationError(f"case {case['id']} contains a test exclusion")
    if (
        not isinstance(case["timeout_seconds"], int)
        or not 60 <= case["timeout_seconds"] <= 1_800
    ):
        raise QualificationError(f"timeout is invalid for {case['id']}")

    command = case["command"]
    if (
        not isinstance(command, list)
        or not command
        or not all(
            isinstance(argument, str) and argument and "\x00" not in argument
            for argument in command
        )
    ):
        raise QualificationError(f"command selection is not exact for {case['id']}")
    expected_command = [
        "cargo",
        f"+{RUSTUP_NAME}",
        "test",
        "--quiet",
        "-Zbuild-std",
        "--locked",
    ]
    if case["manifest_path"] != ".":
        expected_command.extend(["--manifest-path", case["manifest_path"]])
    expected_command.extend(["--target", TARGET])
    if case["manifest_path"] == ".":
        expected_command.extend(["-p", case["package"]])
    if case["test_target"] == "lib":
        expected_command.append("--lib")
    else:
        expected_command.extend(["--test", case["test_target"]])
    expected_command.extend([case["test_selector"], "--", *HARNESS_ARGUMENTS])
    if command != expected_command:
        raise QualificationError(f"command authority changed for {case['id']}")
    lowered = [argument.lower() for argument in command]
    if any(argument in FORBIDDEN_COMMAND_TOKENS for argument in lowered):
        raise QualificationError(f"forbidden command option in {case['id']}")
    if any("fuzz" in argument or "soak" in argument for argument in lowered):
        raise QualificationError(f"fuzz/soak command path is forbidden in {case['id']}")
    if case["manifest_path"] == ".":
        if (
            "--manifest-path" in command
            or command.count("-p") != 1
            or case["package"] not in command
        ):
            raise QualificationError(
                f"workspace package binding is invalid for {case['id']}"
            )
    elif command.count("--manifest-path") != 1 or case["manifest_path"] not in command:
        raise QualificationError(
            f"isolated manifest binding is invalid for {case['id']}"
        )
    if case["test_target"] == "lib":
        if command.count("--lib") != 1:
            raise QualificationError(
                f"library target binding is invalid for {case['id']}"
            )
    elif command.count("--test") != 1 or case["test_target"] not in command:
        raise QualificationError(
            f"integration target binding is invalid for {case['id']}"
        )

    environment = case["environment"]
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value
        for key, value in environment.items()
    ):
        raise QualificationError(f"environment is invalid for {case['id']}")
    base_keys = {
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "NO_COLOR",
        "RUSTFLAGS",
        "RUST_TEST_THREADS",
    }
    expected_keys = base_keys | (
        {"TSAN_OPTIONS"}
        if case["sanitizer"] == "thread"
        else {"ASAN_OPTIONS", "CC_aarch64_apple_darwin", "CFLAGS_aarch64_apple_darwin"}
    )
    if set(environment) != expected_keys:
        raise QualificationError(f"environment authority is not exact for {case['id']}")
    if (
        environment["CARGO_INCREMENTAL"] != "0"
        or environment["CARGO_NET_OFFLINE"] != "true"
        or environment["CARGO_TERM_COLOR"] != "never"
        or environment["NO_COLOR"] != "1"
        or environment["RUST_TEST_THREADS"] != "1"
    ):
        raise QualificationError(f"base environment changed for {case['id']}")
    target_directory = Path(environment["CARGO_TARGET_DIR"])
    if (
        not target_directory.is_absolute()
        or ".." in target_directory.parts
        or target_directory == Path(manifest["scratch_root"])
    ):
        raise QualificationError(f"target directory is unsafe for {case['id']}")
    try:
        target_directory.relative_to(Path(manifest["scratch_root"]))
    except ValueError as error:
        raise QualificationError(
            f"target directory escapes scratch for {case['id']}"
        ) from error
    if case["sanitizer"] == "thread":
        if (
            environment["RUSTFLAGS"] != "-Zsanitizer=thread -Cdebuginfo=1"
            or environment["TSAN_OPTIONS"] != "halt_on_error=1:exitcode=66"
        ):
            raise QualificationError(f"TSan controls changed for {case['id']}")
    elif (
        environment["RUSTFLAGS"] != "-Zsanitizer=address -Cdebuginfo=1"
        or environment["ASAN_OPTIONS"]
        != "halt_on_error=1:abort_on_error=1:detect_leaks=1:exitcode=67"
        or environment["CC_aarch64_apple_darwin"]
        != manifest["toolchain"]["native_cc"]["path"]
        or environment["CFLAGS_aarch64_apple_darwin"]
        != "-fsanitize=address -fno-omit-frame-pointer -mmacosx-version-min=11.0"
    ):
        raise QualificationError(f"ASan/native controls changed for {case['id']}")


def _run(
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout_seconds: int = 60,
    input_bytes: bytes | None = None,
) -> tuple[int, bool, int, bytes, bytes]:
    started = time.monotonic_ns()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(input=input_bytes, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    if len(stdout) > MAX_CAPTURE_BYTES or len(stderr) > MAX_CAPTURE_BYTES:
        raise QualificationError("child output exceeded the 32 MiB evidence bound")
    return process.returncode, timed_out, duration_ms, stdout, stderr


def _baseline_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key] for key in BASELINE_ENVIRONMENT_KEYS if key in os.environ
    }
    environment.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    environment.setdefault("HOME", str(Path.home()))
    try:
        environment["HOME"] = str(Path(environment["HOME"]).resolve(strict=True))
    except OSError as error:
        raise QualificationError(f"baseline HOME is unavailable: {error}") from error
    return environment


def _text_command(command: list[str], timeout_seconds: int = 60) -> str:
    code, timed_out, _duration, stdout, stderr = _run(
        command, environment=_baseline_environment(), timeout_seconds=timeout_seconds
    )
    if code != 0 or timed_out:
        raise QualificationError(
            f"tool command failed ({code}): {' '.join(command)}: "
            f"{stderr.decode('utf-8', errors='replace')[:500]}"
        )
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationError(
            f"tool output is not UTF-8: {' '.join(command)}"
        ) from error


def _cargo_configuration() -> dict[str, Any]:
    expected_lexical = ROOT / ".cargo/config.toml"
    expected = expected_lexical.resolve(strict=True)
    discovered: list[Path] = []
    for ancestor in (ROOT, *ROOT.parents):
        for name in ("config", "config.toml"):
            candidate = ancestor / ".cargo" / name
            if (
                candidate.exists() or candidate.is_symlink()
            ) and candidate not in discovered:
                discovered.append(candidate)
    baseline_home = Path(_baseline_environment()["HOME"]).resolve(strict=True)
    cargo_home = baseline_home / ".cargo"
    _require_safe_directory_chain(
        expected_lexical.parent, label="repository Cargo configuration"
    )
    _require_safe_directory_chain(cargo_home, label="baseline Cargo home")
    for name in ("config", "config.toml"):
        candidate = cargo_home / name
        if (
            candidate.exists() or candidate.is_symlink()
        ) and candidate not in discovered:
            discovered.append(candidate)
    if discovered != [expected_lexical] or expected_lexical.is_symlink():
        raise QualificationError(
            "Cargo configuration authority is not exact: "
            f"{[str(path) for path in discovered]}"
        )
    return {
        "baseline_home": str(baseline_home),
        "project_config": _trusted_file_reference(
            expected, label="repository Cargo configuration", executable=False
        ),
    }


def probe_toolchain(manifest: dict[str, Any]) -> dict[str, Any]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise QualificationError("sanitizer qualification requires native arm64 macOS")
    rustc_version = _text_command(["rustc", f"+{RUSTUP_NAME}", "-Vv"])
    parsed: dict[str, str] = {}
    lines = rustc_version.splitlines()
    if lines:
        parsed["release_line"] = lines[0]
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            parsed[key] = value
    if (
        parsed.get("release_line") != f"rustc {RUSTC_RELEASE} (77cf889bc 2026-07-12)"
        or parsed.get("commit-hash") != RUSTC_COMMIT
        or parsed.get("host") != TARGET
        or parsed.get("release") != RUSTC_RELEASE
        or parsed.get("LLVM version") != LLVM_VERSION
    ):
        raise QualificationError("installed rustc does not match the manifest identity")
    cargo_version = _text_command(["cargo", f"+{RUSTUP_NAME}", "-V"]).strip()
    components = sorted(
        line.strip()
        for line in _text_command(
            [
                "rustup",
                "component",
                "list",
                "--installed",
                "--toolchain",
                f"{RUSTUP_NAME}-aarch64-apple-darwin",
            ]
        ).splitlines()
        if line.strip()
    )
    missing = sorted(
        set(manifest["toolchain"]["required_components"]) - set(components)
    )
    if missing:
        raise QualificationError(f"pinned nightly components are missing: {missing}")
    sysroot = Path(
        _text_command(["rustc", f"+{RUSTUP_NAME}", "--print", "sysroot"]).strip()
    ).resolve(strict=True)
    runtimes: list[dict[str, Any]] = []
    for sanitizer in ("asan", "tsan"):
        path = (
            sysroot
            / "lib"
            / "rustlib"
            / TARGET
            / "lib"
            / f"librustc-nightly_rt.{sanitizer}.dylib"
        )
        runtimes.append(
            {
                "sanitizer": sanitizer,
                **_trusted_file_reference(
                    path,
                    label=f"Rust {sanitizer.upper()} runtime",
                    executable=False,
                ),
            }
        )
    clang_path = Path(manifest["toolchain"]["native_cc"]["path"])
    clang_reference = _trusted_file_reference(
        clang_path, label="native clang", executable=True
    )
    clang_resolved = Path(clang_reference["path"])
    clang_version = _text_command([str(clang_path), "--version"])
    clang_first_line = clang_version.splitlines()[0] if clang_version else ""
    if not clang_first_line.startswith(
        manifest["toolchain"]["native_cc"]["version_prefix"]
    ):
        raise QualificationError("native clang version does not match rustc LLVM")
    cargo_path = shutil.which("cargo", path=_baseline_environment()["PATH"])
    rustc_path = shutil.which("rustc", path=_baseline_environment()["PATH"])
    rustup_path = shutil.which("rustup", path=_baseline_environment()["PATH"])
    if cargo_path is None or rustc_path is None or rustup_path is None:
        raise QualificationError("cargo/rustc/rustup launchers are unavailable")
    resolved_launchers = {
        Path(cargo_path).resolve(strict=True),
        Path(rustc_path).resolve(strict=True),
        Path(rustup_path).resolve(strict=True),
    }
    if len(resolved_launchers) != 1:
        raise QualificationError("cargo/rustc/rustup do not share one pinned launcher")
    launcher_reference = _trusted_file_reference(
        resolved_launchers.pop(), label="rustup launcher", executable=True
    )
    toolchain_binaries = {
        "rustup_launcher": launcher_reference,
        "toolchain_cargo": _trusted_file_reference(
            sysroot / "bin/cargo", label="toolchain cargo", executable=True
        ),
        "toolchain_rustc": _trusted_file_reference(
            sysroot / "bin/rustc", label="toolchain rustc", executable=True
        ),
    }
    return {
        "rustup_name": RUSTUP_NAME,
        "rustc_release": RUSTC_RELEASE,
        "rustc_commit_hash": RUSTC_COMMIT,
        "rustc_commit_date": parsed.get("commit-date"),
        "host": TARGET,
        "llvm_version": LLVM_VERSION,
        "cargo_version": cargo_version,
        "cargo_path": str(Path(cargo_path).resolve(strict=True)),
        "rustc_path": str(Path(rustc_path).resolve(strict=True)),
        "rustup_path": str(Path(rustup_path).resolve(strict=True)),
        "binaries": toolchain_binaries,
        "cargo_configuration": _cargo_configuration(),
        "components": components,
        "sysroot": str(sysroot),
        "sanitizer_runtimes": runtimes,
        "native_cc": {
            "configured_path": str(clang_path),
            "resolved_path": str(clang_resolved),
            "version_first_line": clang_first_line,
            "bytes": clang_reference["bytes"],
            "sha256": clang_reference["sha256"],
        },
    }


def _git_bytes(arguments: list[str]) -> bytes:
    code, timed_out, _duration, stdout, stderr = _run(
        ["git", *arguments],
        environment=_baseline_environment(),
        timeout_seconds=60,
    )
    if code != 0 or timed_out:
        raise QualificationError(
            f"git source query failed: {stderr.decode('utf-8', errors='replace')[:500]}"
        )
    return stdout


def source_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    revision = _git_bytes(["rev-parse", "HEAD"]).decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise QualificationError("Git source revision is unavailable")
    inventory_raw = _git_bytes(
        [
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *manifest["source_scope"],
        ]
    )
    raw_paths = [item for item in inventory_raw.split(b"\0") if item]
    paths: list[str] = []
    tree = hashlib.sha256()
    for raw_path in sorted(raw_paths):
        try:
            relative = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise QualificationError("source inventory path is not UTF-8") from error
        if not _valid_relative_path(relative):
            raise QualificationError(f"unsafe source inventory path: {relative!r}")
        path = ROOT / relative
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise QualificationError(
                f"source inventory entry is not one regular file: {relative}"
            )
        payload = path.read_bytes()
        encoded = relative.encode("utf-8")
        tree.update(len(encoded).to_bytes(8, "big"))
        tree.update(encoded)
        tree.update(len(payload).to_bytes(8, "big"))
        tree.update(payload)
        paths.append(relative)
    if not paths:
        raise QualificationError("sanitizer source inventory is empty")
    scope_status = _git_bytes(
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            *manifest["source_scope"],
        ]
    )
    repository_status = _git_bytes(
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"]
    )
    return {
        "revision": revision,
        "inventory_count": len(paths),
        "tree_sha256": tree.hexdigest(),
        "scope_clean": not scope_status,
        "scope_status": output_descriptor(scope_status),
        "repository_clean": not repository_status,
        "repository_status": output_descriptor(repository_status),
    }


def _same_source(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(
        left.get(key) == right.get(key)
        for key in ("revision", "inventory_count", "tree_sha256")
    )


def _bound_baseline_environment(
    runtime_environment: dict[str, str], baseline_home: str
) -> dict[str, str]:
    environment = dict(runtime_environment)
    if environment.get("HOME") != baseline_home:
        raise QualificationError("runtime HOME does not match bound baseline HOME")
    return environment


def _case_environment(
    case: dict[str, Any],
    canary: str,
    runtime_environment: dict[str, str],
    baseline_home: str,
) -> dict[str, str]:
    environment = _bound_baseline_environment(runtime_environment, baseline_home)
    environment.update(case["environment"])
    environment["CIGAR_SANITIZER_OUTPUT_CANARY"] = canary
    return environment


def parse_exact_test_harness(stdout: bytes, expected_selector: str) -> dict[str, Any]:
    lines = stdout.splitlines()
    if len(lines) != 4 or any(not line.strip() for line in lines):
        raise QualificationError(
            "test harness output must contain exactly four JSON events"
        )
    events = [
        _decode_json(line, label=f"test harness event {index}", require_canonical=False)
        for index, line in enumerate(lines, start=1)
    ]
    suite_started, test_started, test_finished, suite_finished = events
    if suite_started != {
        "type": "suite",
        "event": "started",
        "test_count": 1,
    }:
        raise QualificationError("test harness did not select exactly one test")
    if test_started != {
        "type": "test",
        "event": "started",
        "name": expected_selector,
    }:
        raise QualificationError("test harness started an unexpected test")
    if (
        test_finished.get("type") != "test"
        or test_finished.get("event") != "ok"
        or test_finished.get("name") != expected_selector
        or not set(test_finished).issubset(
            {"type", "event", "name", "exec_time", "stdout"}
        )
        or not {"type", "event", "name"}.issubset(test_finished)
    ):
        raise QualificationError(
            "selected test did not finish successfully and exactly"
        )
    if (
        suite_finished.get("type") != "suite"
        or suite_finished.get("event") != "ok"
        or suite_finished.get("passed") != 1
        or suite_finished.get("failed") != 0
        or suite_finished.get("ignored") != 0
        or suite_finished.get("measured") != 0
        or not isinstance(suite_finished.get("filtered_out"), int)
        or isinstance(suite_finished.get("filtered_out"), bool)
        or suite_finished["filtered_out"] < 0
        or not set(suite_finished).issubset(
            {
                "type",
                "event",
                "passed",
                "failed",
                "ignored",
                "measured",
                "filtered_out",
                "exec_time",
            }
        )
    ):
        raise QualificationError("test harness suite accounting is not an exact pass")
    return {
        "selector": expected_selector,
        "selected": 1,
        "passed": 1,
        "failed": 0,
        "ignored": 0,
        "measured": 0,
        "filtered_out": suite_finished["filtered_out"],
    }


def sanitizer_diagnostic_observed(stdout: bytes, stderr: bytes) -> bool:
    return SANITIZER_DIAGNOSTIC_PATTERN.search(stdout + b"\n" + stderr) is not None


def run_case(
    case: dict[str, Any],
    runtime_environment: dict[str, str],
    baseline_home: str,
) -> dict[str, Any]:
    canary = f"CIGAR-SANITIZER-CANARY-{os.urandom(24).hex()}"
    code, timed_out, duration_ms, stdout, stderr = _run(
        case["command"],
        environment=_case_environment(case, canary, runtime_environment, baseline_home),
        timeout_seconds=case["timeout_seconds"],
    )
    canary_bytes = canary.encode("ascii")
    canary_observed = canary_bytes in stdout or canary_bytes in stderr
    diagnostic_observed = sanitizer_diagnostic_observed(stdout, stderr)
    harness = parse_exact_test_harness(stdout, case["test_selector"])
    passed = (
        code == 0 and not timed_out and not canary_observed and not diagnostic_observed
    )
    return {
        "id": case["id"],
        "sanitizer": case["sanitizer"],
        "surfaces": case["surfaces"],
        "package": case["package"],
        "manifest_path": case["manifest_path"],
        "test_target": case["test_target"],
        "test_selector": case["test_selector"],
        "command": case["command"],
        "environment": case["environment"],
        "timeout_seconds": case["timeout_seconds"],
        "exclusions": case["exclusions"],
        "status": "passed" if passed else "failed",
        "exit_code": code,
        "timed_out": timed_out,
        "duration_milliseconds": duration_ms,
        "stdout": output_descriptor(stdout),
        "stderr": output_descriptor(stderr),
        "canary_observed": canary_observed,
        "sanitizer_diagnostic_observed": diagnostic_observed,
        "test_harness": harness,
    }


def _native_dependency_inventory(
    manifest: dict[str, Any],
    canary: str,
    runtime_environment: dict[str, str],
    baseline_home: str,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    command = [
        "cargo",
        f"+{RUSTUP_NAME}",
        "metadata",
        "--locked",
        "--offline",
        "--filter-platform",
        TARGET,
        "--format-version",
        "1",
    ]
    environment = _bound_baseline_environment(runtime_environment, baseline_home)
    environment.update({"CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never"})
    environment["CIGAR_SANITIZER_OUTPUT_CANARY"] = canary
    code, timed_out, duration_ms, stdout, stderr = _run(
        command, environment=environment, timeout_seconds=180
    )
    if code != 0 or timed_out or canary.encode("ascii") in stdout + stderr:
        raise QualificationError("locked offline native dependency inventory failed")
    try:
        metadata = json.loads(stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError("Cargo metadata output is malformed") from error
    required = set(manifest["ub_equivalent"]["required_native_dependencies"])
    found = [
        {
            "name": package["name"],
            "version": package["version"],
            "source": package.get("source") or "path",
        }
        for package in metadata.get("packages", [])
        if package.get("name") in required
    ]
    found.sort(
        key=lambda package: (package["name"], package["version"], package["source"])
    )
    if {package["name"] for package in found} != required:
        missing = sorted(required - {package["name"] for package in found})
        raise QualificationError(f"required native dependency is absent: {missing}")
    process = {
        "command": command,
        "environment": {
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
        },
        "exit_code": code,
        "timed_out": timed_out,
        "duration_milliseconds": duration_ms,
        "stdout": output_descriptor(stdout),
        "stderr": output_descriptor(stderr),
        "canary_observed": False,
    }
    return found, process


def perform_ub_equivalent_review(
    manifest: dict[str, Any],
    runtime_environment: dict[str, str],
    baseline_home: str,
) -> dict[str, Any]:
    excluded_paths = {
        item["path"] for item in manifest["ub_equivalent"]["platform_excluded_sources"]
    }
    unsafe_findings: list[dict[str, Any]] = []
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        if relative in excluded_paths:
            continue
        payload = path.read_bytes()
        for match in UNSAFE_PATTERN.finditer(payload):
            unsafe_findings.append(
                {
                    "path": relative,
                    "line": payload.count(b"\n", 0, match.start()) + 1,
                    "token_sha256": sha256_bytes(match.group(0)),
                }
            )
    if (
        len(unsafe_findings)
        != manifest["ub_equivalent"]["macos_first_party_unsafe_expected"]
    ):
        raise QualificationError(
            f"macOS first-party unsafe/FFI inventory changed: {unsafe_findings}"
        )
    cargo_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    unsafe_policy = (
        "[workspace.lints.rust]" in cargo_manifest
        and re.search(r'^unsafe_code\s*=\s*"forbid"\s*$', cargo_manifest, re.MULTILINE)
        is not None
    )
    if not unsafe_policy:
        raise QualificationError("workspace unsafe_code=forbid policy is absent")

    excluded_sources = []
    for item in manifest["ub_equivalent"]["platform_excluded_sources"]:
        path = ROOT / item["path"]
        payload = path.read_bytes()
        if UNSAFE_PATTERN.search(payload) is None:
            raise QualificationError(
                "platform-excluded source no longer contains reviewed FFI"
            )
        excluded_sources.append(
            {
                "path": item["path"],
                "reason": item["reason"],
                **output_descriptor(payload),
            }
        )

    canary = f"CIGAR-UB-REVIEW-CANARY-{os.urandom(24).hex()}"
    native_dependencies, metadata_process = _native_dependency_inventory(
        manifest, canary, runtime_environment, baseline_home
    )
    probe_command = [
        "rustc",
        f"+{RUSTUP_NAME}",
        "-Zsanitizer=undefined",
        "--crate-name",
        "cigar_ubsan_capability_probe",
        "--crate-type",
        "bin",
        "-o",
        str(SCRATCH_ROOT / "rust-ubsan-capability-probe"),
        "-",
    ]
    probe_input = b"fn main() {}\n"
    code, timed_out, duration_ms, stdout, stderr = _run(
        probe_command,
        environment=_bound_baseline_environment(runtime_environment, baseline_home),
        timeout_seconds=60,
        input_bytes=probe_input,
    )
    unsupported = (
        code != 0
        and not timed_out
        and b"incorrect value `undefined` for unstable option `sanitizer`" in stderr
    )
    if not unsupported:
        raise QualificationError(
            "Rust sanitizer capability changed; the reviewed non-UBSan policy is stale"
        )
    return {
        "rust_ubsan_run": False,
        "rust_ubsan_status": "unsupported_by_rustc_on_selected_target",
        "rust_ubsan_probe": {
            "command": probe_command,
            "stdin": output_descriptor(probe_input),
            "exit_code": code,
            "timed_out": timed_out,
            "duration_milliseconds": duration_ms,
            "stdout": output_descriptor(stdout),
            "stderr": output_descriptor(stderr),
            "unsupported_diagnostic_observed": unsupported,
        },
        "workspace_unsafe_code_forbid": True,
        "first_party_macos_unsafe_findings": unsafe_findings,
        "platform_excluded_sources": excluded_sources,
        "native_dependencies": native_dependencies,
        "native_dependency_inventory_process": metadata_process,
        "native_c_and_ffi_asan_case_ids": manifest["ub_equivalent"][
            "native_asan_case_ids"
        ],
    }


def _manifest_reference() -> dict[str, Any]:
    payload = MANIFEST_PATH.read_bytes()
    return {
        "path": MANIFEST_PATH.relative_to(ROOT).as_posix(),
        **output_descriptor(payload),
    }


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _prepare_scratch() -> None:
    if SCRATCH_ROOT.exists() or SCRATCH_ROOT.is_symlink():
        raise QualificationError(
            f"sanitizer scratch must be create-new; remove reviewed prior scratch: {SCRATCH_ROOT}"
        )
    SCRATCH_ROOT.mkdir(mode=0o700, parents=False)
    metadata = SCRATCH_ROOT.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise QualificationError("sanitizer scratch is not an owner-only directory")


def _prepare_receipt_path(path: Path) -> Path:
    if not path.is_absolute():
        raise QualificationError("receipt path must be absolute")
    try:
        root = ROOT.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise QualificationError(f"receipt parent is unavailable: {error}") from error
    try:
        parent.relative_to(root)
    except ValueError:
        pass
    else:
        raise QualificationError("receipt must be outside the source checkout")
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise QualificationError("receipt parent must be an owner-only directory")
    if path.exists() or path.is_symlink():
        raise QualificationError("receipt is create-new and already exists")
    return path


def _write_create_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
        ):
            raise QualificationError("created receipt filesystem identity is unsafe")
    finally:
        os.close(descriptor)


def _load_receipt_document(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise QualificationError("receipt path must be absolute")
    try:
        root = ROOT.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
        parent_metadata = parent.lstat()
    except OSError as error:
        raise QualificationError(f"receipt parent is unavailable: {error}") from error
    try:
        parent.relative_to(root)
    except ValueError:
        pass
    else:
        raise QualificationError("receipt must remain outside the source checkout")
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise QualificationError("receipt parent is not owner-private")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QualificationError(f"receipt is unavailable: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_RECEIPT_BYTES
        ):
            raise QualificationError("receipt filesystem identity is unsafe")
        payload_parts: list[bytes] = []
        remaining = MAX_RECEIPT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            payload_parts.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise QualificationError("receipt changed while it was read")
    finally:
        os.close(descriptor)
    payload = b"".join(payload_parts)
    if len(payload) != before.st_size:
        raise QualificationError("receipt size changed while it was read")
    return _decode_json(payload, label=str(path), require_canonical=True)


def run_qualification(receipt_path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    receipt_path = _prepare_receipt_path(receipt_path)
    _prepare_scratch()
    started = _utc_now()
    toolchain = probe_toolchain(manifest)
    baseline_home = toolchain["cargo_configuration"]["baseline_home"]
    runtime_environment = _baseline_environment()
    _bound_baseline_environment(runtime_environment, baseline_home)
    source_before = source_identity(manifest)
    ub_equivalent = perform_ub_equivalent_review(
        manifest, runtime_environment, baseline_home
    )
    results = []
    for case in manifest["cases"]:
        print(f"running {case['id']}", file=sys.stderr, flush=True)
        results.append(run_case(case, runtime_environment, baseline_home))
    source_after = source_identity(manifest)
    source_stable = _same_source(source_before, source_after)
    checks_passed = (
        source_stable
        and all(result["status"] == "passed" for result in results)
        and not ub_equivalent["rust_ubsan_run"]
        and not ub_equivalent["first_party_macos_unsafe_findings"]
    )
    release_eligible = False
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "manifest": _manifest_reference(),
        "evidence_class": "development_diagnostic",
        "platform": manifest["platform"],
        "toolchain": toolchain,
        "runtime_environment": runtime_environment,
        "source_before": source_before,
        "source_after": source_after,
        "source_stable": source_stable,
        "cases": results,
        "ub_equivalent": ub_equivalent,
        "claims": {
            "sanitizer_checks_passed": checks_passed,
            "release_eligible": release_eligible,
            "rust_ubsan_run": False,
            "fuzz_built_or_run": False,
            "soak_built_or_run": False,
            "test_exclusions": [],
        },
        "started_utc": started,
        "finished_utc": _utc_now(),
    }
    validate_receipt_document(receipt, manifest, current_toolchain=toolchain)
    _write_create_new(receipt_path, canonical_json_bytes(receipt))
    if not checks_passed:
        raise QualificationError(
            f"sanitizer qualification failed; receipt: {receipt_path}"
        )
    return receipt


def _validate_descriptor(value: object, label: str) -> None:
    descriptor = _require_exact_keys(value, {"bytes", "sha256"}, label)
    if (
        not isinstance(descriptor["bytes"], int)
        or isinstance(descriptor["bytes"], bool)
        or descriptor["bytes"] < 0
        or not isinstance(descriptor["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", descriptor["sha256"]) is None
    ):
        raise QualificationError(f"{label} descriptor is invalid")


def validate_receipt_document(
    receipt: dict[str, Any],
    manifest: dict[str, Any],
    *,
    current_source: dict[str, Any] | None = None,
    current_toolchain: dict[str, Any] | None = None,
) -> None:
    _require_exact_keys(
        receipt,
        {
            "schema_version",
            "manifest",
            "evidence_class",
            "platform",
            "toolchain",
            "runtime_environment",
            "source_before",
            "source_after",
            "source_stable",
            "cases",
            "ub_equivalent",
            "claims",
            "started_utc",
            "finished_utc",
        },
        "sanitizer receipt",
    )
    if receipt["schema_version"] != RECEIPT_SCHEMA:
        raise QualificationError("unsupported sanitizer receipt schema")
    if (
        receipt["evidence_class"] != "development_diagnostic"
        or receipt["platform"] != manifest["platform"]
    ):
        raise QualificationError("receipt evidence/platform binding changed")
    if current_toolchain is not None and receipt["toolchain"] != current_toolchain:
        raise QualificationError("sanitizer receipt toolchain is stale or substituted")
    runtime_environment = receipt["runtime_environment"]
    if (
        not isinstance(runtime_environment, dict)
        or not {"HOME", "PATH"}.issubset(runtime_environment)
        or not set(runtime_environment).issubset(BASELINE_ENVIRONMENT_KEYS)
        or not all(
            isinstance(key, str)
            and isinstance(value, str)
            and value
            and "\x00" not in value
            for key, value in runtime_environment.items()
        )
        or not isinstance(receipt["toolchain"], dict)
        or not isinstance(receipt["toolchain"].get("cargo_configuration"), dict)
        or runtime_environment["HOME"]
        != receipt["toolchain"]["cargo_configuration"].get("baseline_home")
    ):
        raise QualificationError("receipt runtime environment authority is invalid")
    reference = _require_exact_keys(
        receipt["manifest"], {"path", "bytes", "sha256"}, "manifest reference"
    )
    expected_reference = _manifest_reference()
    if reference != expected_reference:
        raise QualificationError(
            "receipt is not bound to the current sanitizer manifest"
        )
    for label in ("source_before", "source_after"):
        source = _require_exact_keys(
            receipt[label],
            {
                "revision",
                "inventory_count",
                "tree_sha256",
                "scope_clean",
                "scope_status",
                "repository_clean",
                "repository_status",
            },
            label,
        )
        if (
            re.fullmatch(r"[0-9a-f]{40}", str(source["revision"])) is None
            or not isinstance(source["inventory_count"], int)
            or isinstance(source["inventory_count"], bool)
            or source["inventory_count"] <= 0
            or re.fullmatch(r"[0-9a-f]{64}", str(source["tree_sha256"])) is None
            or not isinstance(source["scope_clean"], bool)
            or not isinstance(source["repository_clean"], bool)
        ):
            raise QualificationError(f"{label} identity is invalid")
        _validate_descriptor(source["scope_status"], f"{label} scope status")
        _validate_descriptor(source["repository_status"], f"{label} repository status")
    if receipt["source_stable"] is not True or not _same_source(
        receipt["source_before"], receipt["source_after"]
    ):
        raise QualificationError("receipt source changed during sanitizer execution")
    if current_source is not None and not _same_source(
        receipt["source_after"], current_source
    ):
        raise QualificationError("sanitizer receipt is stale for the current source")

    cases = receipt["cases"]
    if not isinstance(cases, list) or len(cases) != len(manifest["cases"]):
        raise QualificationError("receipt case inventory is incomplete")
    result_keys = {
        "id",
        "sanitizer",
        "surfaces",
        "package",
        "manifest_path",
        "test_target",
        "test_selector",
        "command",
        "environment",
        "timeout_seconds",
        "exclusions",
        "status",
        "exit_code",
        "timed_out",
        "duration_milliseconds",
        "stdout",
        "stderr",
        "canary_observed",
        "sanitizer_diagnostic_observed",
        "test_harness",
    }
    bound_fields = {
        "id",
        "sanitizer",
        "surfaces",
        "package",
        "manifest_path",
        "test_target",
        "test_selector",
        "command",
        "environment",
        "timeout_seconds",
        "exclusions",
    }
    for case, result in zip(manifest["cases"], cases, strict=True):
        result = _require_exact_keys(result, result_keys, "sanitizer case result")
        if any(result[field] != case[field] for field in bound_fields):
            raise QualificationError(
                f"receipt command binding changed for {case['id']}"
            )
        if (
            result["status"] != "passed"
            or result["exit_code"] != 0
            or result["timed_out"] is not False
            or result["canary_observed"] is not False
            or result["sanitizer_diagnostic_observed"] is not False
            or not isinstance(result["duration_milliseconds"], int)
            or isinstance(result["duration_milliseconds"], bool)
            or result["duration_milliseconds"] < 0
        ):
            raise QualificationError(f"sanitizer case did not pass: {case['id']}")
        harness = _require_exact_keys(
            result["test_harness"],
            {
                "selector",
                "selected",
                "passed",
                "failed",
                "ignored",
                "measured",
                "filtered_out",
            },
            f"{case['id']} test harness",
        )
        if (
            harness["selector"] != case["test_selector"]
            or any(
                not isinstance(harness[field], int) or isinstance(harness[field], bool)
                for field in (
                    "selected",
                    "passed",
                    "failed",
                    "ignored",
                    "measured",
                    "filtered_out",
                )
            )
            or harness["selected"] != 1
            or harness["passed"] != 1
            or harness["failed"] != 0
            or harness["ignored"] != 0
            or harness["measured"] != 0
            or harness["filtered_out"] < 0
        ):
            raise QualificationError(
                f"sanitizer case did not execute exactly once: {case['id']}"
            )
        _validate_descriptor(result["stdout"], f"{case['id']} stdout")
        _validate_descriptor(result["stderr"], f"{case['id']} stderr")

    claims = _require_exact_keys(
        receipt["claims"],
        {
            "sanitizer_checks_passed",
            "release_eligible",
            "rust_ubsan_run",
            "fuzz_built_or_run",
            "soak_built_or_run",
            "test_exclusions",
        },
        "receipt claims",
    )
    if (
        claims["sanitizer_checks_passed"] is not True
        or claims["release_eligible"] is not False
        or claims["rust_ubsan_run"] is not False
        or claims["fuzz_built_or_run"] is not False
        or claims["soak_built_or_run"] is not False
        or claims["test_exclusions"] != []
    ):
        raise QualificationError("receipt claims are false or overbroad")
    ub = _require_exact_keys(
        receipt["ub_equivalent"],
        {
            "rust_ubsan_run",
            "rust_ubsan_status",
            "rust_ubsan_probe",
            "workspace_unsafe_code_forbid",
            "first_party_macos_unsafe_findings",
            "platform_excluded_sources",
            "native_dependencies",
            "native_dependency_inventory_process",
            "native_c_and_ffi_asan_case_ids",
        },
        "UB-equivalent review",
    )
    if (
        ub["rust_ubsan_run"] is not False
        or ub["rust_ubsan_status"] != "unsupported_by_rustc_on_selected_target"
        or ub["workspace_unsafe_code_forbid"] is not True
        or ub["first_party_macos_unsafe_findings"] != []
        or ub["native_c_and_ffi_asan_case_ids"]
        != manifest["ub_equivalent"]["native_asan_case_ids"]
    ):
        raise QualificationError(
            "UB-equivalent review is incomplete or overclaims UBSan"
        )
    expected_excluded_sources = []
    for item in manifest["ub_equivalent"]["platform_excluded_sources"]:
        payload = (ROOT / item["path"]).read_bytes()
        expected_excluded_sources.append(
            {
                "path": item["path"],
                "reason": item["reason"],
                **output_descriptor(payload),
            }
        )
    if ub["platform_excluded_sources"] != expected_excluded_sources:
        raise QualificationError("platform-specific unsafe-source evidence changed")

    probe = _require_exact_keys(
        ub["rust_ubsan_probe"],
        {
            "command",
            "stdin",
            "exit_code",
            "timed_out",
            "duration_milliseconds",
            "stdout",
            "stderr",
            "unsupported_diagnostic_observed",
        },
        "Rust UBSan capability probe",
    )
    expected_probe_command = [
        "rustc",
        f"+{RUSTUP_NAME}",
        "-Zsanitizer=undefined",
        "--crate-name",
        "cigar_ubsan_capability_probe",
        "--crate-type",
        "bin",
        "-o",
        str(SCRATCH_ROOT / "rust-ubsan-capability-probe"),
        "-",
    ]
    if (
        probe["command"] != expected_probe_command
        or not isinstance(probe["exit_code"], int)
        or isinstance(probe["exit_code"], bool)
        or probe["exit_code"] == 0
        or probe["timed_out"] is not False
        or not isinstance(probe["duration_milliseconds"], int)
        or isinstance(probe["duration_milliseconds"], bool)
        or probe["duration_milliseconds"] < 0
        or probe["unsupported_diagnostic_observed"] is not True
    ):
        raise QualificationError("Rust UBSan unsupported capability probe is invalid")
    for key in ("stdin", "stdout", "stderr"):
        _validate_descriptor(probe[key], f"Rust UBSan probe {key}")
    if probe["stdin"] != output_descriptor(b"fn main() {}\n"):
        raise QualificationError("Rust UBSan probe input changed")

    expected_native_names = manifest["ub_equivalent"]["required_native_dependencies"]
    native = ub["native_dependencies"]
    if not isinstance(native, list) or len(native) != len(expected_native_names):
        raise QualificationError("receipt native dependency inventory is incomplete")
    native_names: list[str] = []
    for item in native:
        item = _require_exact_keys(
            item, {"name", "version", "source"}, "native dependency"
        )
        if not all(isinstance(item[key], str) and item[key] for key in item):
            raise QualificationError("native dependency identity is invalid")
        native_names.append(item["name"])
    if native_names != expected_native_names:
        raise QualificationError("receipt native dependency inventory is reordered")

    metadata_process = _require_exact_keys(
        ub["native_dependency_inventory_process"],
        {
            "command",
            "environment",
            "exit_code",
            "timed_out",
            "duration_milliseconds",
            "stdout",
            "stderr",
            "canary_observed",
        },
        "native dependency inventory process",
    )
    if (
        metadata_process["command"]
        != [
            "cargo",
            f"+{RUSTUP_NAME}",
            "metadata",
            "--locked",
            "--offline",
            "--filter-platform",
            TARGET,
            "--format-version",
            "1",
        ]
        or metadata_process["environment"]
        != {"CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never"}
        or metadata_process["exit_code"] != 0
        or metadata_process["timed_out"] is not False
        or metadata_process["canary_observed"] is not False
        or not isinstance(metadata_process["duration_milliseconds"], int)
        or isinstance(metadata_process["duration_milliseconds"], bool)
        or metadata_process["duration_milliseconds"] < 0
    ):
        raise QualificationError("native dependency inventory process is invalid")
    _validate_descriptor(metadata_process["stdout"], "native inventory stdout")
    _validate_descriptor(metadata_process["stderr"], "native inventory stderr")


def verify_receipt(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    receipt = _load_receipt_document(path)
    current_toolchain = probe_toolchain(manifest)
    validate_receipt_document(
        receipt,
        manifest,
        current_source=source_identity(manifest),
        current_toolchain=current_toolchain,
    )
    return receipt


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=MANIFEST_PATH, help=argparse.SUPPRESS
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-manifest")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify-receipt")
    verify_parser.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.manifest.resolve(strict=True) != MANIFEST_PATH.resolve(
            strict=True
        ):
            raise QualificationError("alternate sanitizer manifests are not authorized")
        manifest = load_manifest(arguments.manifest)
        if arguments.command == "verify-manifest":
            result = {
                "schema_version": "cigar.production-sanitizers.manifest-verification.v1",
                "manifest": _manifest_reference(),
                "case_ids": [case["id"] for case in manifest["cases"]],
                "required_surfaces": manifest["required_surfaces"],
                "test_exclusions": [],
                "fuzz_built_or_run": False,
                "soak_built_or_run": False,
            }
        elif arguments.command == "run":
            result = run_qualification(arguments.receipt, manifest)
        elif arguments.command == "verify-receipt":
            receipt = verify_receipt(arguments.receipt, manifest)
            result = {
                "schema_version": "cigar.production-sanitizers.receipt-verification.v1",
                "receipt": {
                    "path": str(arguments.receipt),
                    **output_descriptor(canonical_json_bytes(receipt)),
                },
                "source": receipt["source_after"],
                "claims": receipt["claims"],
            }
        else:
            raise QualificationError("unknown sanitizer command")
    except QualificationError as error:
        print(f"production sanitizer qualification failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
