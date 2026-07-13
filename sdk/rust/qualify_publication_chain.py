#!/usr/bin/env python3
"""Qualify the Rust SDK publication chain against a local Cargo registry.

The local registry must first contain every registry dependency from the workspace lock file:

    cargo local-registry sync Cargo.lock /tmp/cigar-rust-registry

This program then packages the two reviewed support forks, the sixteen CIGAR dependency crates,
and the SDK in publication order. Each freshly produced `.crate` is inserted into the local
registry before its dependants are packaged. Cargo therefore performs the same normalized-manifest
resolution required by crates.io without publishing or contacting an external registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from typing import Any


PACKAGES: tuple[tuple[str, str], ...] = (
    ("cigar-aws-creds", "0.39.1-cigar.1"),
    ("cigar-rust-s3", "0.37.2-cigar.1"),
    ("cigar-canon", "0.1.0"),
    ("cigar-protocol", "0.1.0"),
    ("cigar-testkit", "0.1.0"),
    ("cigar-windows-ipc", "0.1.0"),
    ("cigar-crypto", "0.1.0"),
    ("cigar-replay", "0.1.0"),
    ("cigar-policy", "0.1.0"),
    ("cigar-store", "0.1.0"),
    ("cigar-effects", "0.1.0"),
    ("cigar-retrieval", "0.1.0"),
    ("cigar-space", "0.1.0"),
    ("cigar-catalog", "0.1.0"),
    ("cigar-code-intel", "0.1.0"),
    ("cigar-compiler", "0.1.0"),
    ("cigar-api", "0.1.0"),
    ("cigar-daemon", "0.1.0"),
    ("cigar-sdk", "0.1.0"),
)


def run(command: list[str], *, root: Path, environment: dict[str, str]) -> None:
    subprocess.run(command, cwd=root, env=environment, check=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for source in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        relative = source.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        payload = source.read_bytes()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def dependency_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []

    def collect(table: Any, kind: str | None, target: str | None) -> None:
        if not isinstance(table, dict):
            return
        for alias, raw_specification in table.items():
            specification = (
                {"version": raw_specification}
                if isinstance(raw_specification, str)
                else raw_specification
            )
            if not isinstance(specification, dict):
                raise RuntimeError(f"dependency {alias} has an invalid normalized specification")
            if "path" in specification:
                raise RuntimeError(f"normalized dependency {alias} retained a path")
            package = specification.get("package")
            dependencies.append(
                {
                    "name": alias,
                    "req": specification.get("version", "*"),
                    "features": sorted(specification.get("features", [])),
                    "optional": specification.get("optional", False),
                    "default_features": specification.get(
                        "default-features", specification.get("default_features", True)
                    ),
                    "target": target,
                    "kind": kind,
                    "package": package if package != alias else None,
                }
            )

    collect(manifest.get("dependencies"), None, None)
    collect(manifest.get("build-dependencies"), "build", None)
    collect(manifest.get("dev-dependencies"), "dev", None)
    for target, target_manifest in manifest.get("target", {}).items():
        if not isinstance(target_manifest, dict):
            continue
        collect(target_manifest.get("dependencies"), None, target)
        collect(target_manifest.get("build-dependencies"), "build", target)
        collect(target_manifest.get("dev-dependencies"), "dev", target)
    dependencies.sort(
        key=lambda dependency: (
            dependency["name"],
            dependency["kind"] or "",
            dependency["target"] or "",
        )
    )
    return dependencies


def index_path(registry: Path, package_name: str) -> Path:
    name = package_name.lower()
    if len(name) == 1:
        relative = Path("1", name)
    elif len(name) == 2:
        relative = Path("2", name)
    elif len(name) == 3:
        relative = Path("3", name[0], name)
    else:
        relative = Path(name[:2], name[2:4], name)
    return registry / "index" / relative


def add_to_registry(
    registry: Path, crate_path: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    package = manifest["package"]
    name = package["name"]
    version = package["version"]
    checksum = sha256(crate_path)
    registry_record = {
        "name": name,
        "vers": version,
        "deps": dependency_rows(manifest),
        "cksum": checksum,
        "features": manifest.get("features", {}),
        "yanked": False,
    }
    destination = registry / f"{name}-{version}.crate"
    shutil.copyfile(crate_path, destination)
    destination.chmod(0o644)

    package_index = index_path(registry, name)
    package_index.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, Any]] = []
    if package_index.exists():
        existing = [json.loads(line) for line in package_index.read_text().splitlines() if line]
    existing = [record for record in existing if record.get("vers") != version]
    existing.append(registry_record)
    existing.sort(key=lambda record: record["vers"])
    package_index.write_text(
        "\n".join(json.dumps(record, separators=(",", ":"), sort_keys=True) for record in existing)
        + "\n",
        encoding="utf-8",
    )
    return {"name": name, "version": version, "sha256": checksum}


def inspect_crate(crate_path: Path, expected_name: str, expected_version: str) -> dict[str, Any]:
    expected_root = f"{expected_name}-{expected_version}"
    with tarfile.open(crate_path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError(f"unsafe archive path in {crate_path.name}: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"link in {crate_path.name}: {member.name}")
            if path.parts[0] != expected_root:
                raise RuntimeError(f"unexpected archive root in {crate_path.name}: {member.name}")
        required = {
            f"{expected_root}/Cargo.toml",
            f"{expected_root}/Cargo.toml.orig",
            f"{expected_root}/Cargo.lock",
            f"{expected_root}/LICENSE",
            f"{expected_root}/NOTICE",
            f"{expected_root}/release.json",
            f"{expected_root}/src/lib.rs",
        }
        missing = sorted(required - names)
        if missing:
            raise RuntimeError(f"{crate_path.name} is missing {missing}")
        if any(name.startswith(f"{expected_root}/tests/") for name in names):
            raise RuntimeError(f"{crate_path.name} unexpectedly contains tests")
        manifest_member = archive.getmember(f"{expected_root}/Cargo.toml")
        manifest_file = archive.extractfile(manifest_member)
        if manifest_file is None:
            raise RuntimeError(f"cannot read normalized manifest from {crate_path.name}")
        manifest = tomllib.loads(manifest_file.read().decode("utf-8"))

    package = manifest["package"]
    if package["name"] != expected_name or package["version"] != expected_version:
        raise RuntimeError(f"normalized identity mismatch in {crate_path.name}")
    if package.get("publish") != ["crates-io"]:
        raise RuntimeError(f"{crate_path.name} has an unexpected publication registry")
    dependency_rows(manifest)

    if expected_name == "cigar-aws-creds":
        if manifest["features"].get("default") != ["rustls-tls"]:
            raise RuntimeError("cigar-aws-creds does not default to the reviewed Rustls profile")
        if manifest["features"].get("rustls-tls") != [
            "http-credentials",
            "attohttpc/tls-rustls-webpki-roots-ring",
        ]:
            raise RuntimeError("cigar-aws-creds lost its explicit Ring provider selection")
        if manifest["dependencies"]["quick-xml"]["version"] != "=0.41.0":
            raise RuntimeError("cigar-aws-creds lost its exact quick-xml version")
    elif expected_name == "cigar-rust-s3":
        credential_dependency = manifest["dependencies"]["awscreds"]
        if (
            credential_dependency.get("package") != "cigar-aws-creds"
            or credential_dependency.get("version") != "=0.39.1-cigar.1"
            or credential_dependency.get("default-features") is not False
        ):
            raise RuntimeError("cigar-rust-s3 can fall back to an unreviewed credentials package")
        if "attohttpc/tls-rustls-webpki-roots-ring" not in manifest["features"].get(
            "sync-rustls-tls", []
        ):
            raise RuntimeError("cigar-rust-s3 lost its explicit Ring provider selection")
        if manifest["dependencies"]["quick-xml"]["version"] != "=0.41.0":
            raise RuntimeError("cigar-rust-s3 lost its exact quick-xml version")
        removed_dependencies = {"async-std", "surf"} & set(manifest["dependencies"])
        if removed_dependencies:
            raise RuntimeError(
                "cigar-rust-s3 restored the unmaintained async-std/surf dependency surface: "
                f"{sorted(removed_dependencies)}"
            )
        removed_features = {
            "async-std-native-tls",
            "async-std-rustls-tls",
            "with-async-std",
            "with-async-std-hyper",
        } & set(manifest["features"])
        if removed_features:
            raise RuntimeError(
                "cigar-rust-s3 restored the unmaintained async-std/surf feature surface: "
                f"{sorted(removed_features)}"
            )
    elif expected_name == "cigar-store":
        s3_dependency = manifest["dependencies"]["s3"]
        if (
            s3_dependency.get("package") != "cigar-rust-s3"
            or s3_dependency.get("version") != "=0.37.2-cigar.1"
            or s3_dependency.get("default-features") is not False
            or s3_dependency.get("features") != ["sync-rustls-tls"]
        ):
            raise RuntimeError(
                "cigar-store can fall back to upstream rust-s3 or a non-reviewed transport"
            )
        required_store_files = {
            f"{expected_root}/migrations/sqlite/0001_initial.sql",
            *(f"{expected_root}/migrations/postgres/000{number}_{suffix}.sql" for number, suffix in (
                (1, "shared_metadata"),
                (2, "object_outbox"),
                (3, "atom_projection"),
                (4, "gc_revision_guard"),
            )),
        }
        if not required_store_files.issubset(names):
            raise RuntimeError("cigar-store package omitted one or more migrations")
    elif expected_name == "cigar-api":
        if f"{expected_root}/proto/cigar_service.proto" not in names:
            raise RuntimeError("cigar-api package omitted cigar_service.proto")

    return manifest


def validate_report(report: dict[str, Any]) -> None:
    """Enforce a closed, digest-only evidence shape before writing it to disk."""
    expected_top_level = {
        "schema_version",
        "status",
        "external_publish_performed",
        "package_count",
        "packages",
        "reviewed_source_digests",
        "clean_default_feature_consumer",
        "limitations",
    }
    if set(report) != expected_top_level:
        raise RuntimeError("publication qualification report has an unexpected top-level shape")
    if report["schema_version"] != "cigar.rust-publication-chain-qualification.v1":
        raise RuntimeError("publication qualification report has an unexpected schema version")
    if report["status"] != "passed-local-registry":
        raise RuntimeError("publication qualification report did not pass")
    if report["external_publish_performed"] is not False:
        raise RuntimeError("local qualification must not claim or perform an external publish")
    if report["clean_default_feature_consumer"] != "passed":
        raise RuntimeError("clean default-feature consumer did not pass")

    package_records = report["packages"]
    if report["package_count"] != len(PACKAGES) or len(package_records) != len(PACKAGES):
        raise RuntimeError("publication qualification report has an unexpected package count")
    for record, (expected_name, expected_version) in zip(
        package_records, PACKAGES, strict=True
    ):
        if set(record) != {"name", "version", "sha256"}:
            raise RuntimeError("package evidence must contain identity and digest only")
        if (record["name"], record["version"]) != (expected_name, expected_version):
            raise RuntimeError("package evidence is not in the documented publication order")
        if re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None:
            raise RuntimeError("package evidence has an invalid SHA-256 digest")

    source_records = report["reviewed_source_digests"]
    expected_sources = (
        "vendor/aws-creds-0.39.1/src",
        "vendor/rust-s3-0.37.2/src",
    )
    if len(source_records) != len(expected_sources):
        raise RuntimeError("reviewed source evidence has an unexpected record count")
    for record, expected_source in zip(source_records, expected_sources, strict=True):
        if set(record) != {"vendored", "sha256"}:
            raise RuntimeError("reviewed source evidence must contain path and digest only")
        if record["vendored"] != expected_source:
            raise RuntimeError("reviewed source evidence has an unexpected relative path")
        if re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None:
            raise RuntimeError("reviewed source evidence has an invalid SHA-256 digest")

    expected_limitations = [
        "The workspace has no committed candidate revision, so final .cargo_vcs_info.json binding is not yet testable.",
        "Package names are not reserved until the approved registry owner publishes each exact crate in order.",
        "This local registry proves normalized dependency resolution but is not a crates.io publication receipt.",
    ]
    if report["limitations"] != expected_limitations:
        raise RuntimeError("publication qualification report has unexpected free-form limitations")

    def reject_multiline_strings(value: Any) -> None:
        if isinstance(value, str) and ("\n" in value or "\r" in value):
            raise RuntimeError("publication qualification report contains multiline payload text")
        if isinstance(value, dict):
            for nested in value.values():
                reject_multiline_strings(nested)
        elif isinstance(value, list):
            for nested in value:
                reject_multiline_strings(nested)

    reject_multiline_strings(report)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    registry = arguments.registry.resolve()
    if not (registry / "index").is_dir():
        raise RuntimeError("local registry is missing its index; sync Cargo.lock first")

    source_pairs = (
        (root / "vendor/aws-creds-0.39.1/src", root / "crates/cigar-aws-creds/src"),
        (root / "vendor/rust-s3-0.37.2/src", root / "crates/cigar-rust-s3/src"),
    )
    source_digests = []
    for vendored, publishable in source_pairs:
        vendored_digest = source_tree_digest(vendored)
        publishable_digest = source_tree_digest(publishable)
        if vendored_digest != publishable_digest:
            raise RuntimeError(f"publishable fork source drifted from {vendored}")
        source_digests.append(
            {"vendored": vendored.relative_to(root).as_posix(), "sha256": vendored_digest}
        )

    with tempfile.TemporaryDirectory(prefix="cigar-cargo-home-") as cargo_home_raw:
        cargo_home = Path(cargo_home_raw)
        config = cargo_home / "config.toml"
        config.write_text(
            "[source.crates-io]\n"
            "replace-with = \"cigar-local\"\n\n"
            "[source.cigar-local]\n"
            f"local-registry = {json.dumps(str(registry))}\n\n"
            "[net]\noffline = true\n",
            encoding="utf-8",
        )
        environment = dict(os.environ)
        environment["CARGO_HOME"] = str(cargo_home)
        environment["CARGO_NET_OFFLINE"] = "true"
        environment["CARGO_TARGET_DIR"] = str(root / "target/registry-qualification")

        records = []
        for name, version in PACKAGES:
            run(
                [
                    "cargo",
                    "package",
                    "--locked",
                    "--allow-dirty",
                    "--offline",
                    "-p",
                    name,
                ],
                root=root,
                environment=environment,
            )
            crate_path = Path(environment["CARGO_TARGET_DIR"]) / "package" / f"{name}-{version}.crate"
            manifest = inspect_crate(crate_path, name, version)
            records.append(add_to_registry(registry, crate_path, manifest))

        with tempfile.TemporaryDirectory(prefix="cigar-sdk-consumer-") as consumer_raw:
            consumer = Path(consumer_raw)
            (consumer / "src").mkdir()
            (consumer / "Cargo.toml").write_text(
                "[package]\nname = \"cigar-sdk-clean-consumer\"\nversion = \"0.0.0\"\n"
                "edition = \"2024\"\nrust-version = \"1.92\"\npublish = false\n\n"
                "[dependencies]\ncigar-sdk = \"=0.1.0\"\n",
                encoding="utf-8",
            )
            (consumer / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
            run(
                ["cargo", "check", "--offline", "--manifest-path", str(consumer / "Cargo.toml")],
                root=root,
                environment=environment,
            )

    report = {
        "schema_version": "cigar.rust-publication-chain-qualification.v1",
        "status": "passed-local-registry",
        "external_publish_performed": False,
        "package_count": len(records),
        "packages": records,
        "reviewed_source_digests": source_digests,
        "clean_default_feature_consumer": "passed",
        "limitations": [
            "The workspace has no committed candidate revision, so final .cargo_vcs_info.json binding is not yet testable.",
            "Package names are not reserved until the approved registry owner publishes each exact crate in order.",
            "This local registry proves normalized dependency resolution but is not a crates.io publication receipt.",
        ],
    }
    validate_report(report)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.report:
        report_path = arguments.report
        if not report_path.is_absolute():
            report_path = root / report_path
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
