#!/usr/bin/env python3
"""Generate and validate the fail-closed initial-beta release profile."""

from __future__ import annotations

import argparse
import base64
import binascii
import re
import stat
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    reject_evidence_directory,
    repo_root,
    safe_relative_path,
    sha256_file,
    write_json,
)


PRODUCT = "cigar"
VERSION = "0.1.0-beta.1"
TAG = "v0.1.0-beta.1"
PROFILE_ID = "cigar.beta.embedded-local.linux-x86_64.v1"
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
RUST_TOOLCHAIN_VERSION = "1.92.0"
PYTHON_TOOLCHAIN_VERSION = "3.14.6"
QUALIFIED_DISTRIBUTION = "ubuntu"
QUALIFIED_DISTRIBUTION_VERSION = "24.04"
MINIMUM_GLIBC_VERSION = "2.39"
RUNTIME_BASELINE = "ubuntu-24.04-x86_64-glibc-2.39"
BETA_SLSA_BUILD_TYPE = "urn:cigar:build-type:beta-artifacts:v1"
BETA_BUILD_COMMAND = (
    "cargo",
    "build",
    "--locked",
    "--release",
    "-p",
    "cigar-cli",
    "--no-default-features",
    "--features",
    "beta-embedded",
    "--target",
    TARGET_TRIPLE,
)
BETA_PROJECTION_INCLUDE = (
    "LICENSE",
    "NOTICE",
    "rust-toolchain.toml",
    "crates/cigar-canon/LICENSE",
    "crates/cigar-canon/NOTICE",
    "crates/cigar-canon/src/**",
    "crates/cigar-cli/assets/cigar-help-beta.txt",
    "crates/cigar-cli/src/arguments.rs",
    "crates/cigar-cli/src/beta/**",
    "crates/cigar-cli/src/command.rs",
    "crates/cigar-cli/src/error.rs",
    "crates/cigar-cli/src/lib.rs",
    "crates/cigar-cli/src/main.rs",
    "crates/cigar-cli/src/render.rs",
    "docs/release/BETA_USER_GUIDE.md",
    "packaging/beta/**",
    "packaging/licenses/Apache-2.0.txt",
    "packaging/licenses/beta-third-party-inventory.v1.json",
    "packaging/licenses/beta-third-party-license-files/**",
    "packaging/licenses/beta-third-party-license-manifest.v1.json",
    "packaging/licenses/rust/COPYRIGHT-library.html",
    "packaging/licenses/third-party-policy.v1.json",
    "packaging/schemas/source-descriptor.v1.schema.json",
    "scripts/release/beta_artifacts.py",
    "scripts/release/generate_beta_licenses.py",
    "scripts/release/beta_profile.py",
    "scripts/release/beta_release.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/generate_license_inventory.py",
    "scripts/release/generate_sbom.py",
    "scripts/release/release_lib.py",
    "scripts/release/signatures.py",
    "scripts/release/source_descriptor.py",
    "scripts/release/verify_package.py",
)
BETA_PROJECTION_REMAP = {
    "packaging/beta/build-projection/Cargo.toml": "Cargo.toml",
    "packaging/beta/build-projection/Cargo.lock": "Cargo.lock",
    "packaging/beta/build-projection/cigar-canon.Cargo.toml": "crates/cigar-canon/Cargo.toml",
    "packaging/beta/build-projection/cigar-cli.Cargo.toml": "crates/cigar-cli/Cargo.toml",
}
BETA_COMMAND_PATHS = (
    "init",
    "source.add",
    "source.list",
    "source.remove",
    "project.list",
    "project.attach",
    "project.detach",
    "project.switch",
    "project.link",
    "project.unlink",
    "focus.switch",
    "focus.close",
    "help",
    "version",
)

BETA_EVIDENCE_SCHEMA = "cigar.beta.qualification-evidence.v1"
BETA_RELEASE_EVIDENCE_SCHEMA = "cigar.beta.release-evidence.v1"
BETA_EVIDENCE_PURPOSE = "cigar-beta-qualification-evidence-v1"
BETA_SIGNATURE_PURPOSES = (
    "cigar-beta-qualification-evidence-v1",
    "cigar-beta-release-artifact-v1",
    "cigar-beta-release-checksums-v1",
    "cigar-beta-release-evidence-v1",
    "cigar-beta-release-provenance-v1",
    "cigar-beta-release-sbom-v1",
    "cigar-beta-release-spdx-v1",
)
GA_EVIDENCE_SCHEMAS = (
    "cigar.qualification-evidence.v1",
    "cigar.release-evidence.v1",
)
GA_SIGNATURE_PURPOSES = (
    "release-artifact",
    "release-benchmark",
    "release-checksums",
    "release-conformance",
    "release-evidence",
    "release-provenance",
    "release-sbom",
)

EXCLUDED_CAPABILITIES = (
    (
        "catalog-discovery",
        "Source discovery and refresh are not compiled into the beta command catalog.",
    ),
    ("catalog-ingest", "Catalog ingestion is not a beta capability."),
    ("catalog-query", "Catalog inspection and query are not beta capabilities."),
    (
        "context",
        "Context plan, compile, explain, diff, revalidate, and materialize are excluded.",
    ),
    ("retrieval", "Retrieval and ranking operations are outside the beta boundary."),
    ("handoff", "Handoff create, inspect, accept, revoke, and merge are excluded."),
    (
        "space",
        "Space fork, publish, log, conflict, and checkpoint workflows are excluded.",
    ),
    (
        "replay",
        "Replay reconstruction, execution, comparison, and completeness are excluded.",
    ),
    ("policy", "Policy evaluation and explanation are not beta capabilities."),
    ("daemon", "The beta ships no cigard executable or daemon lifecycle surface."),
    (
        "effects",
        "External effect execution is outside the embedded-local beta boundary.",
    ),
    (
        "extensions",
        "Extension loading and extension distribution are not beta surfaces.",
    ),
    ("installers", "The beta publishes archives only; it has no system installer."),
    (
        "macos",
        "Qualification is restricted to Ubuntu 24.04 x86_64 with glibc 2.39.",
    ),
    ("mcp", "The MCP server and protocol surface are excluded from the beta."),
    ("oci", "No image, image index, or container deployment is a beta artifact."),
    ("otlp", "OTLP export and collector integration are outside the beta boundary."),
    ("plugin", "No plugin package or plugin runtime is distributed in the beta."),
    ("remote", "Remote execution and remote service access are excluded."),
    ("sdk", "Rust, TypeScript, Python, and Go SDK packages are excluded."),
    ("shared", "Shared-service and multi-user deployment modes are excluded."),
    ("vector", "Vector backends, vector indexing, and vector export are excluded."),
    (
        "windows",
        "Qualification is restricted to Ubuntu 24.04 x86_64 with glibc 2.39.",
    ),
    ("arm", "ARM and AArch64 builds are not initial-beta artifacts."),
    ("backup", "Backup and restore administration are not compiled into the beta."),
    ("garbage-collection", "GC planning and execution are not beta capabilities."),
    ("diagnostics", "Diagnostic bundle and doctor operations are excluded."),
    ("serving", "HTTP, gRPC, socket, and other service listeners are excluded."),
    ("completion-man", "Completion and manual-page generator commands are excluded."),
)

MANIFEST_PATHS = {
    "artifact_matrix": "packaging/beta/artifact-matrix.v1.json",
    "capability_policy": "packaging/beta/capability-policy.v1.json",
    "cargo_resolution": "packaging/beta/cargo-resolution.v1.json",
    "build_projection": "packaging/beta/build-projection/projection.v1.json",
    "product_version": "packaging/beta/product-version.v1.json",
    "qualification_policy": "packaging/beta/qualification-policy.v1.json",
    "source_archives": "packaging/beta/source-archives.v1.json",
}

SCHEMA_PATHS = (
    "packaging/beta/schemas/beta-artifact-matrix.v1.schema.json",
    "packaging/beta/schemas/beta-capability-policy.v1.schema.json",
    "packaging/beta/schemas/beta-cargo-resolution.v1.schema.json",
    "packaging/beta/schemas/beta-package-contract.v1.schema.json",
    "packaging/beta/schemas/beta-product-version.v1.schema.json",
    "packaging/beta/schemas/beta-provenance.v1.schema.json",
    "packaging/beta/schemas/beta-qualification-evidence.v1.schema.json",
    "packaging/beta/schemas/beta-qualification-policy.v1.schema.json",
    "packaging/beta/schemas/beta-final-release-verification.v1.schema.json",
    "packaging/beta/schemas/beta-release-metadata.v1.schema.json",
    "packaging/beta/schemas/beta-release-evidence.v1.schema.json",
    "packaging/beta/schemas/beta-release-profile.v1.schema.json",
    "packaging/beta/schemas/beta-release-verification.v1.schema.json",
    "packaging/beta/schemas/beta-sbom.v1.schema.json",
    "packaging/beta/schemas/beta-spdx.v1.schema.json",
    "packaging/beta/schemas/beta-signature-envelope.v1.schema.json",
    "packaging/beta/schemas/beta-source-archives.v1.schema.json",
    "packaging/beta/schemas/beta-trust-policy.v1.schema.json",
    "packaging/beta/schemas/beta-build-manifest.v1.schema.json",
)

# These hashes pin downstream schemas against silent weakening. Updating a schema is an
# intentional contract-version change and must update the corresponding digest here.
EXPECTED_SCHEMA_SHA256 = {
    "packaging/beta/schemas/beta-artifact-matrix.v1.schema.json": (
        "1ca17072e5645e5488b9c3d29c43b6827d47376bce3da467b598fa54dd4b0190"
    ),
    "packaging/beta/schemas/beta-capability-policy.v1.schema.json": (
        "8928adddbd3b9b71d00d9172da688585c39fb0c65d170db1179297b00cd4e726"
    ),
    "packaging/beta/schemas/beta-cargo-resolution.v1.schema.json": (
        "d79ae17ea64b1215206bfe58b998b9d6f0baef12101ee450080950268b869c84"
    ),
    "packaging/beta/schemas/beta-package-contract.v1.schema.json": (
        "3210e9c73676d6f1ad06a11e7f515c999ff6d575122527bb1c4117306e89d186"
    ),
    "packaging/beta/schemas/beta-product-version.v1.schema.json": (
        "fe51b79e2e765e004eb0b2d93ceaafc168246d112f803524dde2b6693937b59d"
    ),
    "packaging/beta/schemas/beta-provenance.v1.schema.json": (
        "f7137a386eb81b5069c8e16cf470ed1286e8a912c47cd397d6bc4ddb4640674b"
    ),
    "packaging/beta/schemas/beta-qualification-evidence.v1.schema.json": (
        "526d067616c58ab20f4740001fe5a85f9b1d3904f24e266d5a3b84a5de162c41"
    ),
    "packaging/beta/schemas/beta-qualification-policy.v1.schema.json": (
        "0077a2a673876539065b7dae81bac2bc9d20999b58a8bd68697b5e824191dd54"
    ),
    "packaging/beta/schemas/beta-final-release-verification.v1.schema.json": (
        "4ec28fc413a56fb06b82cd0a7888baf3b4070e3f8d5311e58c8673bf38cdc535"
    ),
    "packaging/beta/schemas/beta-release-metadata.v1.schema.json": (
        "ed77c6fe8ee408c56fe4e312fa29d4c5727d49f572616cefad5a98d6eba42d37"
    ),
    "packaging/beta/schemas/beta-release-evidence.v1.schema.json": (
        "7a54c65de9f8abb81e60ac51cb02029de5ea2ef1e27fe1f06d1b792c3b25f8f1"
    ),
    "packaging/beta/schemas/beta-release-profile.v1.schema.json": (
        "f78430356626e770cb46ce01adb44f3de88aa18d9b7e0b0b4a7cbede532d75b5"
    ),
    "packaging/beta/schemas/beta-release-verification.v1.schema.json": (
        "3fda7b484bd82bb5f3b73c3ade6eb5d9a055554f8e792f6bf566e628ab49054d"
    ),
    "packaging/beta/schemas/beta-sbom.v1.schema.json": (
        "f58455f95da80095d5330520aa484faefdbb219e1ee083bb2c565ac1e34c7e19"
    ),
    "packaging/beta/schemas/beta-spdx.v1.schema.json": (
        "787b49cd3916ebb80b09a78161769424c61288de9eb15d0c4e1c8b9871de9903"
    ),
    "packaging/beta/schemas/beta-signature-envelope.v1.schema.json": (
        "69998c8df72a925dee00dcfb1e7af28d17cadf6d9a4bd44a311230a3c656af16"
    ),
    "packaging/beta/schemas/beta-source-archives.v1.schema.json": (
        "cd798cedfc33b7aaa4fde6f79fb675f7886c892126e1dda09b469a8e764b0c8f"
    ),
    "packaging/beta/schemas/beta-trust-policy.v1.schema.json": (
        "86b181ddbfd2a7f1328e1da795f9d45cd800e3aa38a563ae81921ea5ec6720d9"
    ),
    "packaging/beta/schemas/beta-build-manifest.v1.schema.json": (
        "be61e8d465912557bb033cef6f88cc31b1f5f3ef18b7fe74393c1119f4853107"
    ),
}

EXPECTED_CONTRACT_SHA256 = {
    "packaging/beta/contracts/source-archive.v1.json": (
        "18887d4f33ed9d260c151261c9bf9c7535e5640fe318fe8a479d316744ccabe7"
    ),
    "packaging/beta/contracts/cigar-binary-archive.v1.json": (
        "f9f8019f54634182cee80b79a0085b335aa50b95bcdbca6ae6879c48a7dc69f5"
    ),
    "packaging/beta/contracts/conformance-archive.v1.json": (
        "224ded8b01dceac34589f3809b9c41444f24539d748d4c8fca1c9279a0484e24"
    ),
    "packaging/beta/contracts/docs-archive.v1.json": (
        "e658697197b6e814844a60b95f39073f2dab272bc0bc86562a4bdae0c0abb358"
    ),
    "packaging/beta/contracts/license-archive.v1.json": (
        "69ddb1330ec280b7c74370d8becbeeb5a799849a350005283b695e379992e1ee"
    ),
    "packaging/beta/contracts/schemas-archive.v1.json": (
        "58ed4ffc1515ea49344a0f5c6c170262a0c2c2112da0df7fac8cb73e589cf26f"
    ),
}

EXPECTED_CARGO_RESOLUTION_SHA256 = (
    "486879346f723babc1c9de481dfbd04f4f0610dca29799de0fcd24e1f7ef95b5"
)


def expected_release_profile() -> dict[str, Any]:
    return {
        "schema_version": "cigar.beta.release-profile.v1",
        "profile_id": PROFILE_ID,
        "product": PRODUCT,
        "version": VERSION,
        "tag": TAG,
        "channel": "beta",
        "prerelease": True,
        "production_ready": False,
        "support": {
            "capability_boundary": "workspace-metadata-only",
            "deployment_mode": "embedded-local",
            "host_arch": "x86_64",
            "host_os": "linux",
            "libc": "gnu",
            "minimum_glibc_version": MINIMUM_GLIBC_VERSION,
            "network_scope": "no-network-service-surface",
            "qualified_distribution": QUALIFIED_DISTRIBUTION,
            "qualified_distribution_version": QUALIFIED_DISTRIBUTION_VERSION,
            "runtime_baseline": RUNTIME_BASELINE,
            "target_triple": TARGET_TRIPLE,
        },
        "manifests": dict(MANIFEST_PATHS),
        "build": {
            "command": list(BETA_BUILD_COMMAND),
            "package": "cigar-cli",
            "binary": "cigar",
            "capability_profile": "workspace-metadata-only",
            "default_features": False,
            "enabled_features": ["beta-embedded"],
            "source_revision_environment": "CIGAR_SOURCE_REVISION",
            "target": TARGET_TRIPLE,
            "rust_toolchain": RUST_TOOLCHAIN_VERSION,
            "python_toolchain": PYTHON_TOOLCHAIN_VERSION,
        },
        "evidence_domain": {
            "schema_version": BETA_EVIDENCE_SCHEMA,
            "release_schema_version": BETA_RELEASE_EVIDENCE_SCHEMA,
            "purpose": BETA_EVIDENCE_PURPOSE,
            "forbidden_ga_schema_versions": list(GA_EVIDENCE_SCHEMAS),
        },
        "signature_domain": {
            "envelope_schema_version": "cigar.signature-envelope.v1",
            "allowed_purposes": list(BETA_SIGNATURE_PURPOSES),
            "forbidden_ga_purposes": list(GA_SIGNATURE_PURPOSES),
        },
    }


def expected_product_version() -> dict[str, Any]:
    profile = expected_release_profile()
    return {
        "schema_version": "cigar.beta.product-version.v1",
        "product": profile["product"],
        "version": profile["version"],
        "tag": profile["tag"],
        "channel": profile["channel"],
        "release_profile": profile["profile_id"],
        "prerelease": profile["prerelease"],
        "production_ready": profile["production_ready"],
        "target_triple": profile["support"]["target_triple"],
    }


def expected_cargo_resolution() -> dict[str, Any]:
    return {
        "schema_version": "cigar.beta.cargo-resolution.v1",
        "release_profile": PROFILE_ID,
        "target": TARGET_TRIPLE,
        "workspace_packages": ["cigar-canon", "cigar-cli"],
        "component_count": 45,
        "dependency_edge_count": 66,
        "sbom_resolution_sha256": (
            "0daf6f21ba9d65f4ef081b3737997bd0d968dce6c03c009bd50a3c2b8bafd8b6"
        ),
        "metadata_resolution_sha256": (
            "d09930c3934c0741e49e1fb3e6778d3857df84fe7e9524ae6e38392e316e4d75"
        ),
    }


def expected_build_projection() -> dict[str, Any]:
    return {
        "schema_version": "cigar.beta.build-projection.v1",
        "release_profile": PROFILE_ID,
        "source": "committed-git-objects",
        "include": list(BETA_PROJECTION_INCLUDE),
        "remap": [
            {"from": source, "to": destination}
            for source, destination in sorted(BETA_PROJECTION_REMAP.items())
        ],
        "excluded_capability_policy": MANIFEST_PATHS["capability_policy"],
        "fail_closed": True,
    }


def _archive(
    identifier: str,
    kind: str,
    filename: str,
    contract: str,
    qualification: list[str],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "kind": kind,
        "filename": filename,
        "contract": contract,
        "required_for_beta": True,
        "qualification": qualification,
    }
    if target is not None:
        result["target"] = target
        result["executables"] = ["bin/cigar"]
    return result


def expected_artifact_matrix() -> dict[str, Any]:
    prefix = f"cigar-{VERSION}"
    common = [
        "archive-contract",
        "license",
        "provenance",
        "reproducibility",
        "sbom",
        "security",
        "signature",
    ]
    return {
        "schema_version": "cigar.beta.artifact-matrix.v1",
        "release_profile": PROFILE_ID,
        "product": PRODUCT,
        "product_version": VERSION,
        "artifacts": [
            _archive(
                "source",
                "source-archive",
                f"{prefix}-source.tar.gz",
                "packaging/beta/contracts/source-archive.v1.json",
                common,
            ),
            _archive(
                "docs",
                "documentation-archive",
                f"{prefix}-docs.tar.gz",
                "packaging/beta/contracts/docs-archive.v1.json",
                ["archive-contract", "docs", *common[1:]],
            ),
            _archive(
                "schemas",
                "schema-archive",
                f"{prefix}-schemas.tar.gz",
                "packaging/beta/contracts/schemas-archive.v1.json",
                ["archive-contract", "conformance", *common[1:]],
            ),
            _archive(
                "conformance",
                "conformance-archive",
                f"{prefix}-conformance.tar.gz",
                "packaging/beta/contracts/conformance-archive.v1.json",
                ["archive-contract", "conformance", *common[1:]],
            ),
            _archive(
                "licenses",
                "license-archive",
                f"{prefix}-licenses.tar.gz",
                "packaging/beta/contracts/license-archive.v1.json",
                common,
            ),
            _archive(
                "cigar-linux-x86_64-gnu",
                "binary-archive",
                f"{prefix}-x86_64-unknown-linux-gnu.tar.gz",
                "packaging/beta/contracts/cigar-binary-archive.v1.json",
                [
                    "archive-contract",
                    "installed-artifact",
                    "license",
                    "offline",
                    "provenance",
                    "reproducibility",
                    "sbom",
                    "security",
                    "signature",
                ],
                target=TARGET_TRIPLE,
            ),
        ],
    }


def expected_qualification_policy() -> dict[str, Any]:
    all_artifacts = [
        "source",
        "docs",
        "schemas",
        "conformance",
        "licenses",
        "cigar-linux-x86_64-gnu",
    ]

    def metric(identifier: str, operator: str, value: int) -> dict[str, Any]:
        return {
            "id": identifier,
            "type": "integer",
            "operator": operator,
            "value": value,
        }

    def category(
        identifier: str,
        artifact_ids: list[str],
        checks: list[str],
        metrics: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "id": identifier,
            "artifact_ids": artifact_ids,
            "required_checks": sorted(checks),
            "metric_gates": sorted(metrics, key=lambda item: item["id"]),
            "minimum_attachments": 1,
        }

    categories = [
        category(
            "archive-contract",
            all_artifacts,
            [
                "canonical-archive-bytes",
                "closed-member-inventory",
                "member-metadata-policy",
                "source-byte-binding",
            ],
            [
                metric("artifact_count", "eq", 6),
                metric("failed_artifact_count", "eq", 0),
            ],
        ),
        category(
            "conformance",
            ["schemas", "conformance"],
            [
                "beta-cli-contract-tests",
                "excluded-surface-negative-tests",
                "schema-contract-validation",
            ],
            [
                metric("executed_check_count", "gte", 3),
                metric("failed_check_count", "eq", 0),
            ],
        ),
        category(
            "docs",
            ["docs"],
            [
                "documented-command-surface",
                "documentation-link-validation",
                "documentation-profile-consistency",
            ],
            [
                metric("broken_link_count", "eq", 0),
                metric("undocumented_command_count", "eq", 0),
            ],
        ),
        category(
            "installed-artifact",
            ["cigar-linux-x86_64-gnu"],
            [
                "installed-command-surface",
                "restart-persistence-permission",
                "runtime-dependency-closure",
                "unprivileged-clean-install",
            ],
            [
                metric("failed_command_count", "eq", 0),
                metric("included_command_count", "eq", 14),
                metric("undeclared_runtime_component_count", "eq", 0),
            ],
        ),
        category(
            "license",
            all_artifacts,
            [
                "exact-cargo-license-inventory",
                "license-notice-reconciliation",
                "sbom-license-parity",
            ],
            [
                metric("missing_inventory_component_count", "eq", 0),
                metric("unapproved_license_count", "eq", 0),
                metric("unresolved_notice_count", "eq", 0),
            ],
        ),
        category(
            "offline",
            ["cigar-linux-x86_64-gnu"],
            [
                "clean-runtime-without-build-tools",
                "offline-command-surface",
                "os-enforced-no-egress",
            ],
            [
                metric("failed_command_count", "eq", 0),
                metric("network_attempt_count", "eq", 0),
                metric("tested_command_count", "gte", 14),
            ],
        ),
        category(
            "provenance",
            all_artifacts,
            [
                "builder-tool-material-binding",
                "reproducibility-claim-binding",
                "six-subject-digest-binding",
                "slsa-v1-statement",
            ],
            [
                metric("material_count", "gte", 1),
                metric("subject_count", "eq", 6),
                metric("tool_count", "gte", 8),
            ],
        ),
        category(
            "reproducibility",
            all_artifacts,
            [
                "all-artifact-byte-comparison",
                "independent-builds",
                "normalization-policy-validation",
            ],
            [
                metric("compared_artifact_count", "eq", 6),
                metric("independent_build_count", "gte", 2),
                metric("mismatch_count", "eq", 0),
            ],
        ),
        category(
            "sbom",
            all_artifacts,
            [
                "cyclonedx-artifact-binding",
                "dependency-closure-reconciliation",
                "native-runtime-component-binding",
                "spdx-artifact-binding",
            ],
            [
                metric("artifact_count", "eq", 6),
                metric("native_component_count", "gte", 1),
                metric("unresolved_component_count", "eq", 0),
            ],
        ),
        category(
            "security",
            all_artifacts,
            [
                "packed-final-byte-scan",
                "secret-endpoint-path-scan",
                "security-finding-disposition",
                "unpacked-final-byte-scan",
                "vulnerability-malware-scan",
            ],
            [
                metric("critical_finding_count", "eq", 0),
                metric("high_finding_count", "eq", 0),
                metric("scanned_artifact_count", "eq", 6),
                metric("skipped_result_count", "eq", 0),
                metric("unknown_result_count", "eq", 0),
            ],
        ),
        category(
            "signature",
            all_artifacts,
            [
                "complete-signature-set",
                "direct-payload-signatures",
                "reserved-purpose-domain",
                "trusted-key-policy",
            ],
            [
                metric("artifact_signature_count", "eq", 6),
                metric("invalid_signature_count", "eq", 0),
                metric("missing_signature_count", "eq", 0),
            ],
        ),
    ]
    categories.sort(key=lambda item: item["id"])
    return {
        "schema_version": "cigar.beta.qualification-policy.v1",
        "release_profile": PROFILE_ID,
        "product_version": VERSION,
        "categories": categories,
    }


def expected_capability_policy() -> dict[str, Any]:
    return {
        "schema_version": "cigar.beta.capability-policy.v1",
        "release_profile": PROFILE_ID,
        "included": [
            {
                "id": "local-workspace-metadata-administration",
                "description": "Local init plus source, project, and focus metadata administration against private workspace state.",
                "command_paths": list(BETA_COMMAND_PATHS),
            }
        ],
        "excluded": [
            {"id": identifier, "reason": reason}
            for identifier, reason in EXCLUDED_CAPABILITIES
        ],
        "fail_closed": True,
    }


def expected_source_archives() -> dict[str, Any]:
    prefix = f"cigar-{VERSION}"
    return {
        "schema_version": "cigar.beta.source-archives.v1",
        "release_profile": PROFILE_ID,
        "product_version": VERSION,
        "archives": [
            {
                "id": "source",
                "filename": f"{prefix}-source.tar.gz",
                "contract": "packaging/beta/contracts/source-archive.v1.json",
                "include": ["**"],
            },
            {
                "id": "docs",
                "filename": f"{prefix}-docs.tar.gz",
                "contract": "packaging/beta/contracts/docs-archive.v1.json",
                "include": [
                    "LICENSE",
                    "NOTICE",
                    "docs/release/BETA_USER_GUIDE.md",
                    "crates/cigar-cli/assets/cigar-help-beta.txt",
                    "packaging/beta/README.md",
                    "packaging/beta/capability-policy.v1.json",
                    "packaging/beta/product-version.v1.json",
                    "packaging/beta/release-profile.v1.json",
                ],
            },
            {
                "id": "schemas",
                "filename": f"{prefix}-schemas.tar.gz",
                "contract": "packaging/beta/contracts/schemas-archive.v1.json",
                "include": [
                    "LICENSE",
                    "NOTICE",
                    "packaging/beta/*.json",
                    "packaging/beta/contracts/**",
                    "packaging/beta/schemas/**",
                ],
            },
            {
                "id": "conformance",
                "filename": f"{prefix}-conformance.tar.gz",
                "contract": "packaging/beta/contracts/conformance-archive.v1.json",
                "include": [
                    "LICENSE",
                    "NOTICE",
                    "crates/cigar-cli/assets/cigar-help-beta.txt",
                    "packaging/beta/conformance/check_beta.py",
                    "packaging/beta/artifact-matrix.v1.json",
                    "packaging/beta/capability-policy.v1.json",
                    "packaging/beta/product-version.v1.json",
                    "packaging/beta/release-profile.v1.json",
                    "scripts/release/release_lib.py",
                ],
            },
            {
                "id": "licenses",
                "filename": f"{prefix}-licenses.tar.gz",
                "contract": "packaging/beta/contracts/license-archive.v1.json",
                "include": [
                    "LICENSE",
                    "NOTICE",
                    "packaging/licenses/Apache-2.0.txt",
                    "packaging/licenses/beta-third-party-inventory.v1.json",
                    "packaging/licenses/beta-third-party-license-files/**",
                    "packaging/licenses/beta-third-party-license-manifest.v1.json",
                    "packaging/licenses/rust/COPYRIGHT-library.html",
                    "packaging/licenses/third-party-policy.v1.json",
                ],
            },
        ],
        "always_exclude": [
            "**/.DS_Store",
            "**/.git/**",
            "**/.idea/**",
            "**/.vscode/**",
            "**/__pycache__/**",
            "**/*.pyc",
            "**/*.pyo",
            "**/*.profraw",
            "**/*.profdata",
            "**/coverage/**",
            "**/dist/**",
            "**/node_modules/**",
            "**/target/**",
            "**/.mypy_cache/**",
            "**/.pytest_cache/**",
            "**/.ruff_cache/**",
            "**/.tmp/**",
            "**/.venv/**",
            "**/.coverage",
            "**/htmlcov/**",
            ".mypy_cache/**",
            ".pytest_cache/**",
            ".ruff_cache/**",
            ".tmp/**",
            ".venv/**",
            "artifacts/**",
            "findings/**",
            "reports/**",
        ],
    }


def _source_derived_contract(
    identifier: str,
    allow: list[str],
    required: list[str],
    *,
    max_entries: int,
    max_total_bytes: int,
    modes: tuple[str, ...] = ("0644",),
) -> dict[str, Any]:
    return {
        "schema_version": "cigar.beta.source-package-contract.v1",
        "id": identifier,
        "release_profile": PROFILE_ID,
        "format": "tar.gz",
        "allow": allow,
        "required": required,
        "deny": [
            "**/.git/**",
            "**/.env*",
            "**/*.key",
            "**/*.pem",
            "**/target/**",
        ],
        "symlinks": "forbid",
        "line_endings": "lf",
        "modes": list(modes),
        "max_entries": max_entries,
        "max_member_bytes": 16 * 1024 * 1024,
        "max_total_bytes": max_total_bytes,
        "content_scan": True,
        "content_scan_exemptions": [],
    }


def expected_source_contract() -> dict[str, Any]:
    return _source_derived_contract(
        "cigar-beta-source-archive-v1",
        [
            "RELEASE-METADATA.json",
            *BETA_PROJECTION_INCLUDE,
            *BETA_PROJECTION_REMAP.values(),
        ],
        [
            "RELEASE-METADATA.json",
            "Cargo.toml",
            "Cargo.lock",
            "LICENSE",
            "NOTICE",
            "rust-toolchain.toml",
            "crates/cigar-canon/Cargo.toml",
            "crates/cigar-canon/src/lib.rs",
            "crates/cigar-cli/Cargo.toml",
            "crates/cigar-cli/assets/cigar-help-beta.txt",
            "crates/cigar-cli/src/lib.rs",
            "crates/cigar-cli/src/main.rs",
            "packaging/beta/build-projection/projection.v1.json",
            "packaging/beta/cargo-resolution.v1.json",
            "scripts/release/beta_artifacts.py",
        ],
        max_entries=4096,
        max_total_bytes=128 * 1024 * 1024,
        modes=("0644", "0755"),
    )


def expected_docs_contract() -> dict[str, Any]:
    return _source_derived_contract(
        "cigar-beta-docs-archive-v1",
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "docs/release/BETA_USER_GUIDE.md",
            "crates/cigar-cli/assets/cigar-help-beta.txt",
            "packaging/beta/README.md",
            "packaging/beta/capability-policy.v1.json",
            "packaging/beta/product-version.v1.json",
            "packaging/beta/release-profile.v1.json",
        ],
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "docs/release/BETA_USER_GUIDE.md",
            "crates/cigar-cli/assets/cigar-help-beta.txt",
            "packaging/beta/README.md",
            "packaging/beta/capability-policy.v1.json",
            "packaging/beta/product-version.v1.json",
            "packaging/beta/release-profile.v1.json",
        ],
        max_entries=256,
        max_total_bytes=32 * 1024 * 1024,
    )


def expected_schemas_contract() -> dict[str, Any]:
    return _source_derived_contract(
        "cigar-beta-schemas-archive-v1",
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "packaging/beta/*.json",
            "packaging/beta/contracts/**",
            "packaging/beta/schemas/**",
        ],
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "packaging/beta/artifact-matrix.v1.json",
            "packaging/beta/capability-policy.v1.json",
            "packaging/beta/cargo-resolution.v1.json",
            "packaging/beta/product-version.v1.json",
            "packaging/beta/qualification-policy.v1.json",
            "packaging/beta/release-profile.v1.json",
            "packaging/beta/source-archives.v1.json",
            "packaging/beta/contracts/cigar-binary-archive.v1.json",
            "packaging/beta/schemas/beta-release-profile.v1.schema.json",
            "packaging/beta/schemas/beta-signature-envelope.v1.schema.json",
        ],
        max_entries=256,
        max_total_bytes=16 * 1024 * 1024,
    )


def expected_conformance_contract() -> dict[str, Any]:
    return _source_derived_contract(
        "cigar-beta-conformance-archive-v1",
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "crates/cigar-cli/assets/cigar-help-beta.txt",
            "packaging/beta/conformance/check_beta.py",
            "packaging/beta/artifact-matrix.v1.json",
            "packaging/beta/capability-policy.v1.json",
            "packaging/beta/product-version.v1.json",
            "packaging/beta/release-profile.v1.json",
            "scripts/release/release_lib.py",
        ],
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "crates/cigar-cli/assets/cigar-help-beta.txt",
            "packaging/beta/conformance/check_beta.py",
            "packaging/beta/artifact-matrix.v1.json",
            "packaging/beta/capability-policy.v1.json",
            "scripts/release/release_lib.py",
        ],
        max_entries=32,
        max_total_bytes=8 * 1024 * 1024,
        modes=("0644", "0755"),
    )


def expected_license_contract() -> dict[str, Any]:
    return _source_derived_contract(
        "cigar-beta-license-archive-v1",
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "packaging/licenses/Apache-2.0.txt",
            "packaging/licenses/beta-third-party-inventory.v1.json",
            "packaging/licenses/beta-third-party-license-files/**",
            "packaging/licenses/beta-third-party-license-manifest.v1.json",
            "packaging/licenses/rust/COPYRIGHT-library.html",
            "packaging/licenses/third-party-policy.v1.json",
        ],
        [
            "RELEASE-METADATA.json",
            "LICENSE",
            "NOTICE",
            "packaging/licenses/Apache-2.0.txt",
            "packaging/licenses/third-party-policy.v1.json",
            "packaging/licenses/beta-third-party-inventory.v1.json",
            "packaging/licenses/beta-third-party-license-manifest.v1.json",
            "packaging/licenses/rust/COPYRIGHT-library.html",
        ],
        max_entries=128,
        max_total_bytes=8 * 1024 * 1024,
    )


def expected_binary_contract() -> dict[str, Any]:
    return {
        "schema_version": "cigar.beta.package-contract.v1",
        "id": "cigar-beta-binary-archive-v1",
        "release_profile": PROFILE_ID,
        "format": "tar.gz",
        "allow": [
            "RELEASE-METADATA.json",
            "bin/cigar",
            "LICENSE",
            "NOTICE",
            "SHA256SUMS",
        ],
        "required": [
            "RELEASE-METADATA.json",
            "bin/cigar",
            "LICENSE",
            "NOTICE",
            "SHA256SUMS",
        ],
        "executables": ["bin/cigar"],
        "deny": [
            "bin/cigard",
            "bin/*.exe",
            "**/.git/**",
            "**/.env*",
            "**/*.dSYM/**",
            "**/*.key",
            "**/*.pdb",
            "**/*.pem",
            "**/*.rlib",
            "**/*.rmeta",
        ],
        "symlinks": "forbid",
        "line_endings": "lf",
        "modes": ["0644", "0755"],
        "max_entries": 64,
        "max_member_bytes": 268435456,
        "max_total_bytes": 536870912,
        "content_scan": True,
        "content_scan_exemptions": [],
        "checksum_manifest": {
            "path": "SHA256SUMS",
            "scope": "all-payload-files",
        },
    }


GENERATED_DOCUMENTS = {
    "packaging/beta/release-profile.v1.json": expected_release_profile,
    MANIFEST_PATHS["artifact_matrix"]: expected_artifact_matrix,
    MANIFEST_PATHS["capability_policy"]: expected_capability_policy,
    MANIFEST_PATHS["build_projection"]: expected_build_projection,
    MANIFEST_PATHS["product_version"]: expected_product_version,
    MANIFEST_PATHS["qualification_policy"]: expected_qualification_policy,
    MANIFEST_PATHS["source_archives"]: expected_source_archives,
    "packaging/beta/contracts/source-archive.v1.json": expected_source_contract,
    "packaging/beta/contracts/docs-archive.v1.json": expected_docs_contract,
    "packaging/beta/contracts/schemas-archive.v1.json": expected_schemas_contract,
    "packaging/beta/contracts/conformance-archive.v1.json": expected_conformance_contract,
    "packaging/beta/contracts/license-archive.v1.json": expected_license_contract,
    "packaging/beta/contracts/cigar-binary-archive.v1.json": expected_binary_contract,
}


def _repository_path(root: Path, relative: str) -> Path:
    """Resolve a fixed repository path while rejecting link-based parent escapes."""
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseError(f"unsafe beta repository path: {relative!r}")
    current = root
    for part in path.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ReleaseError(
                f"cannot inspect beta path parent {current}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseError(f"beta path parent must be a real directory: {current}")
    return root.joinpath(*path.parts)


def _regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(
            f"{label} must be a regular file, not a link or special file"
        )
    if metadata.st_nlink != 1:
        raise ReleaseError(f"{label} must not be hard-linked")


def _load_canonical(path: Path, label: str) -> Any:
    _regular_file(path, label)
    document = load_json(path)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ReleaseError(f"cannot read {label}: {error}") from error
    if payload != canonical_json_bytes(document):
        raise ReleaseError(f"{label} is not canonical JSON")
    return document


def validate_beta_evidence_identity(document: Any) -> None:
    """Reject evidence from another release channel before deeper receipt validation."""
    if not isinstance(document, dict):
        raise ReleaseError("beta evidence must be an object")
    if document.get("schema_version") != BETA_EVIDENCE_SCHEMA:
        raise ReleaseError("evidence is outside the beta evidence schema domain")
    if document.get("release_profile") != PROFILE_ID:
        raise ReleaseError("evidence is bound to a different release profile")
    if document.get("product_version") != VERSION:
        raise ReleaseError("evidence is bound to a different product version")
    if document.get("evidence_purpose") != BETA_EVIDENCE_PURPOSE:
        raise ReleaseError("evidence is outside the beta evidence purpose domain")


def validate_beta_release_evidence_identity(document: Any) -> None:
    """Reject an assembled evidence bundle from another version, profile, or channel."""
    if not isinstance(document, dict):
        raise ReleaseError("beta release evidence must be an object")
    if document.get("schema_version") != BETA_RELEASE_EVIDENCE_SCHEMA:
        raise ReleaseError("release evidence is outside the beta schema domain")
    if document.get("release_profile") != PROFILE_ID:
        raise ReleaseError("release evidence is bound to a different release profile")
    if document.get("product_version") != VERSION or document.get("tag") != TAG:
        raise ReleaseError("release evidence is bound to a different beta version")
    if document.get("prerelease") is not True:
        raise ReleaseError("beta release evidence must identify a prerelease")
    if document.get("production_ready") is not False:
        raise ReleaseError("beta release evidence must not claim production readiness")


def validate_beta_signature_identity(document: Any) -> None:
    """Validate the closed envelope identity before cryptographic verification."""
    required = {
        "schema_version",
        "algorithm",
        "key_id",
        "signer_principal",
        "purpose",
        "signed_at",
        "payload",
        "signature_base64",
    }
    if not isinstance(document, dict):
        raise ReleaseError("beta signature envelope has an unexpected shape")
    keys = frozenset(document)
    if keys not in {frozenset(required), frozenset(required | {"expires_at"})}:
        raise ReleaseError("beta signature envelope has an unexpected shape")
    if document.get("schema_version") != "cigar.signature-envelope.v1":
        raise ReleaseError("signature envelope schema is not supported by the beta")
    if document.get("algorithm") != "Ed25519":
        raise ReleaseError("beta signature algorithm is not Ed25519")
    key_id = document.get("key_id")
    if (
        not isinstance(key_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", key_id) is None
    ):
        raise ReleaseError("beta signature key identifier is invalid")
    signer = document.get("signer_principal")
    if (
        not isinstance(signer, str)
        or not signer
        or signer != signer.strip()
        or len(signer.encode("utf-8")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in signer)
    ):
        raise ReleaseError("beta signature signer principal is invalid")
    if document.get("purpose") not in BETA_SIGNATURE_PURPOSES:
        raise ReleaseError("signature is outside the beta signature purpose domain")

    def timestamp(value: object, label: str) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 253_402_300_799
        ):
            raise ReleaseError(f"beta signature {label} is invalid")
        return value

    signed_at = timestamp(document.get("signed_at"), "signed-at timestamp")
    if "expires_at" in document and (
        timestamp(document["expires_at"], "expiry timestamp") <= signed_at
    ):
        raise ReleaseError("beta signature expiry must be later than signing time")
    payload = document.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"name", "sha256", "bytes"}:
        raise ReleaseError("beta signature payload reference is invalid")
    name = payload.get("name")
    if not isinstance(name, str):
        raise ReleaseError("beta signature payload name is invalid")
    normalized_name = safe_relative_path(name)
    if PurePosixPath(normalized_name).name != normalized_name:
        raise ReleaseError("beta signature payload name must be a basename")
    digest = payload.get("sha256")
    size = payload.get("bytes")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReleaseError("beta signature payload digest is invalid")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ReleaseError("beta signature payload size is invalid")
    encoded = document.get("signature_base64")
    if not isinstance(encoded, str):
        raise ReleaseError("beta signature encoding is invalid")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ReleaseError("beta signature encoding is invalid") from error
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise ReleaseError(
            "beta signature must contain one canonical Ed25519 signature"
        )


def _validate_schema_inventory(root: Path) -> None:
    schema_directory = _repository_path(
        root, "packaging/beta/schemas/schema-inventory-sentinel"
    ).parent
    discovered = {
        path.relative_to(root).as_posix() for path in schema_directory.glob("*.json")
    }
    expected = set(SCHEMA_PATHS)
    if discovered != expected:
        raise ReleaseError(
            "beta schema inventory mismatch; "
            f"missing={sorted(expected - discovered)}, extra={sorted(discovered - expected)}"
        )
    if set(EXPECTED_SCHEMA_SHA256) != expected:
        raise ReleaseError("beta schema digest inventory is incomplete")
    for relative in SCHEMA_PATHS:
        path = _repository_path(root, relative)
        _regular_file(path, relative)
        schema = load_json(path)
        if (
            not isinstance(schema, dict)
            or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or not isinstance(schema.get("$id"), str)
            or not schema["$id"].startswith("https://cigar.invalid/schemas/beta-")
        ):
            raise ReleaseError(f"beta schema has invalid draft or identity: {relative}")
        if sha256_file(path) != EXPECTED_SCHEMA_SHA256[relative]:
            raise ReleaseError(f"beta schema digest mismatch: {relative}")


def generate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError(f"repository root is not a directory: {root}")
    for relative, factory in GENERATED_DOCUMENTS.items():
        destination = _repository_path(resolved, relative)
        if destination.exists() and destination.is_symlink():
            raise ReleaseError(f"refusing to replace symlink: {relative}")
        write_json(destination, factory())


def validate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError(f"repository root is not a directory: {root}")
    for relative, factory in GENERATED_DOCUMENTS.items():
        observed = _load_canonical(_repository_path(resolved, relative), relative)
        expected = factory()
        if observed != expected:
            raise ReleaseError(
                f"beta contract differs from its pinned definition: {relative}"
            )
    cargo_resolution_path = _repository_path(
        resolved, MANIFEST_PATHS["cargo_resolution"]
    )
    cargo_resolution = _load_canonical(
        cargo_resolution_path, MANIFEST_PATHS["cargo_resolution"]
    )
    expected_resolution_summary = expected_cargo_resolution()
    if (
        not isinstance(cargo_resolution, dict)
        or any(
            cargo_resolution.get(key) != value
            for key, value in expected_resolution_summary.items()
        )
        or sha256_file(cargo_resolution_path) != EXPECTED_CARGO_RESOLUTION_SHA256
    ):
        raise ReleaseError("beta Cargo resolution differs from its exact reviewed pin")
    declared_contracts = {
        entry["contract"] for entry in expected_artifact_matrix()["artifacts"]
    }
    if set(EXPECTED_CONTRACT_SHA256) != declared_contracts:
        raise ReleaseError("beta package-contract digest inventory is incomplete")
    for relative, digest in EXPECTED_CONTRACT_SHA256.items():
        path = _repository_path(resolved, relative)
        _regular_file(path, relative)
        if sha256_file(path) != digest:
            raise ReleaseError(f"beta package-contract digest mismatch: {relative}")

    matrix = expected_artifact_matrix()
    identifiers = [entry["id"] for entry in matrix["artifacts"]]
    if identifiers != [
        "source",
        "docs",
        "schemas",
        "conformance",
        "licenses",
        "cigar-linux-x86_64-gnu",
    ]:
        raise ReleaseError(
            "beta artifact allowlist is not the reviewed six-artifact set"
        )
    binary_entries = [
        entry for entry in matrix["artifacts"] if entry["kind"] == "binary-archive"
    ]
    if len(binary_entries) != 1 or binary_entries[0].get("executables") != [
        "bin/cigar"
    ]:
        raise ReleaseError("beta must contain exactly one cigar-only binary archive")
    if binary_entries[0].get("target") != TARGET_TRIPLE:
        raise ReleaseError("beta binary target is outside Linux x86_64 GNU")
    qualification_policy = expected_qualification_policy()
    policy_bindings = {
        category["id"]: category["artifact_ids"]
        for category in qualification_policy["categories"]
    }
    matrix_bindings: dict[str, list[str]] = {}
    for entry in matrix["artifacts"]:
        for category in entry["qualification"]:
            matrix_bindings.setdefault(category, []).append(entry["id"])
    if matrix_bindings != policy_bindings:
        raise ReleaseError(
            "beta artifact matrix differs from the pinned qualification policy"
        )

    capability_ids = [entry["id"] for entry in expected_capability_policy()["excluded"]]
    if capability_ids != [identifier for identifier, _ in EXCLUDED_CAPABILITIES]:
        raise ReleaseError(
            "beta exclusion set differs from the reviewed capability boundary"
        )

    profile = expected_release_profile()
    toolchain_path = _repository_path(resolved, "rust-toolchain.toml")
    _regular_file(toolchain_path, "rust-toolchain.toml")
    try:
        toolchain = tomllib.loads(toolchain_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError(f"cannot read the pinned Rust toolchain: {error}") from error
    if (
        not isinstance(toolchain, dict)
        or not isinstance(toolchain.get("toolchain"), dict)
        or toolchain["toolchain"].get("channel") != RUST_TOOLCHAIN_VERSION
    ):
        raise ReleaseError("rust-toolchain.toml differs from the beta compiler pin")
    if set(profile["signature_domain"]["allowed_purposes"]) & set(
        profile["signature_domain"]["forbidden_ga_purposes"]
    ):
        raise ReleaseError("beta and GA signature domains overlap")
    if {
        profile["evidence_domain"]["schema_version"],
        profile["evidence_domain"]["release_schema_version"],
    } & set(profile["evidence_domain"]["forbidden_ga_schema_versions"]):
        raise ReleaseError("beta and GA evidence domains overlap")
    _validate_schema_inventory(resolved)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "check"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--root", type=Path, default=repo_root())
        subparser.add_argument(
            "--evidence-dir",
            type=Path,
            help=(
                "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
                "profile source generation/checking does not emit release evidence"
            ),
        )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    reject_evidence_directory(arguments.evidence_dir, "beta profile operation")
    if arguments.command == "generate":
        generate(arguments.root)
        print(f"generated beta profile {PROFILE_ID} ({VERSION})")
    else:
        validate(arguments.root)
        print(f"validated beta profile {PROFILE_ID} ({VERSION})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"beta profile operation failed: {error}") from error
