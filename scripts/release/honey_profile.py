#!/usr/bin/env python3
"""Generate and verify the closed CIGAR Honey developer-preview authority."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys
from typing import Any

import product_version
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    reject_evidence_directory,
    repo_root,
    sha256_bytes,
    sha256_file,
    write_json,
)


VERSION = "0.9.4"
PYTHON_VERSION = "0.9.4"
PROFILE_ID = "cigar.honey.local-developer-preview.macos-arm64.v1"
CONTEXT_ABI = "cigar.context.v1"
TARGET = "aarch64-apple-darwin"

PROFILE_PATH = "packaging/honey/capability-profile.v1.json"
MATRIX_PATH = "packaging/honey/artifact-matrix.v1.json"
REQUIREMENTS_PATH = "packaging/honey/release-requirements.v1.json"
OWNERSHIP_PATH = "packaging/honey/capability-ownership.v1.json"
ARCHIVES_PATH = "packaging/honey/local-archives.v1.json"
EVIDENCE_SCHEMA_PATH = "packaging/honey/schemas/honey-evidence.v1.schema.json"
EVIDENCE_SCHEMA_SHA256 = (
    "ed75fc0427913378805f78787772f142a9323ccf3ec7db7f7306dfd6e288db4a"
)

OPERATION_SOURCE = "spec/api/operations-v1.json"
PAYLOAD_SOURCE = "spec/api/operation-payloads-v1.json"
PAYLOAD_SCHEMA_SOURCE = "schemas/json/api-payload-types-v1.schema.json"
OPERATION_SOURCE_SHA256 = (
    "55c8dd34d7c6a62b0c68dce181c80ed8d4815810828476c188df190ef529d07b"
)
PAYLOAD_SOURCE_SHA256 = (
    "4ef0878a35952a98f0e4107e913f7ade8ffc028677974205436318b30b376817"
)
PAYLOAD_SCHEMA_SOURCE_SHA256 = (
    "3160d4c3946a71e7eace1661c525674149d9b7803577c2831f2980178b6b533c"
)
OPERATION_INVENTORY_SHA256 = (
    "361dc4ba4e90263c41cf708f89002c594ad27a9c515fd8ba9e34e69fbf3a1141"
)
PAYLOAD_INVENTORY_SHA256 = (
    "9048b85238371221b68afb7a442d146a810ace22d8d6dae329250f08967b5ec2"
)

SERVICE_OPERATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "CatalogService",
        (
            "discoverSources",
            "ingestCatalog",
            "getSourceStatus",
            "queryCatalog",
            "batchAtoms",
            "tombstoneAtom",
        ),
    ),
    (
        "ContextService",
        (
            "createContextPlan",
            "compileContextBundle",
            "compileContextDelta",
            "getContextBundle",
            "getContextBundleManifest",
            "explainContextBundle",
            "materializeContextBundle",
            "revalidateContextBundle",
        ),
    ),
    (
        "SpaceService",
        (
            "createSpace",
            "forkSpace",
            "publishSpace",
            "getSpaceLog",
            "subscribeSpaceEvents",
            "createSpaceCheckpoint",
            "listSpaceConflicts",
            "resolveSpaceConflict",
        ),
    ),
    (
        "HandoffService",
        (
            "createHandoff",
            "previewHandoff",
            "acceptHandoff",
            "revokeHandoff",
            "recordHandoffResult",
            "mergeHandoff",
        ),
    ),
    (
        "EffectService",
        (
            "prepareEffect",
            "authorizeEffect",
            "dispatchEffect",
            "getEffectStatus",
            "reconcileEffect",
            "compensateEffect",
        ),
    ),
    (
        "ReplayService",
        (
            "createReplay",
            "runObservationalReplay",
            "compareLiveReplay",
            "getReplayCompleteness",
        ),
    ),
    (
        "OperationsService",
        (
            "getLiveness",
            "getReadiness",
            "getVersion",
            "getCapabilities",
            "getConfiguration",
            "getDiagnostics",
            "getMetrics",
        ),
    ),
)

CAPABILITY_IDS = (
    "catalog",
    "governed-context",
    "policy-enforcement",
    "context-spaces",
    "two-agent-handoff",
    "recoverable-effects",
    "observational-replay",
    "operations-observability",
    "cli",
    "local-daemon",
    "mcp",
    "claude-code",
    "typescript-sdk",
    "python-sdk",
    "rust-sdk",
    "filesystem-git-ingestion",
    "filesystem-reference-effect",
)

DEFERRED_IDS = (
    "dashboard",
    "go-sdk",
    "shared-postgresql-s3",
    "compose-kubernetes",
    "oci",
    "linux",
    "macos-x86-64",
    "windows",
    "homebrew",
    "public-crates-io",
    "public-npm",
    "remote-multitenancy",
    "https-effects",
    "arbitrary-extensions",
    "vector-retrieval",
    "live-provider-replay",
    "remote-otlp",
    "cigarbench-claims",
    "seven-day-fuzz",
    "four-hour-mutation",
    "twenty-four-hour-soak",
    "production-chaos-matrix",
    "large-scale-qualification",
    "developer-id-notarization",
    "two-builder-reproducibility",
    "production-support",
)

GATE_IDS = (
    "authority-drift",
    "protocol-drift",
    "clean-committed-source",
    "focused-tests",
    "conformance",
    "archive-contracts",
    "installed-runtime",
    "sdk-clean-installs",
    "claude-lifecycle",
    "two-agent-authority",
    "policy-nondisclosure",
    "effect-unknown-recovery",
    "offline-replay",
    "prompt-injection-defense",
    "docs-commands-links",
    "license-notice",
    "artifact-checksums",
    "storage-format-v5",
    "v4-v5-migration",
    "revision-recovery",
    "storage-amplification",
    "serial-latency",
    "startup-readiness",
    "context-quality-efficiency",
)


class HoneyProfileError(ReleaseError):
    """A Honey authority invariant failed."""


def _artifact(
    order: int,
    identifier: str,
    kind: str,
    filename: str,
    contract: str | None,
    producer: list[str],
    workspace: str,
    gates: list[str],
    *,
    receipt_schema: str | None,
    receipt_filename: str | None,
    generated: bool = False,
) -> dict[str, Any]:
    return {
        "order": order,
        "id": identifier,
        "kind": kind,
        "filename": filename,
        "contract": contract,
        "producer": producer,
        "workspace": workspace,
        "public_attachment": True,
        "required": True,
        "generated_by_assembler": generated,
        "sha256_required": True,
        "receipt": {
            "required": not generated and receipt_schema is not None,
            "schema_version": receipt_schema,
            "filename": receipt_filename,
        },
        "qualification_gate_ids": gates,
    }


def expected_artifact_matrix() -> dict[str, Any]:
    archive_producer = [
        "python3",
        "scripts/release/build_archives.py",
        "--manifest",
        ARCHIVES_PATH,
        "--require-committed-clean",
    ]
    artifacts = [
        _artifact(
            1,
            "source",
            "source-archive",
            f"cigar-{VERSION}-source.tar.gz",
            "packaging/honey/contracts/source-archive.v1.json",
            archive_producer,
            "portable",
            ["archive-contracts", "license-notice"],
            receipt_schema="cigar.local-archive-build.v1",
            receipt_filename="build-manifest.json",
        ),
        _artifact(
            2,
            "docs",
            "docs-archive",
            f"cigar-{VERSION}-docs.tar.gz",
            "packaging/honey/contracts/docs-archive.v1.json",
            archive_producer,
            "portable",
            ["archive-contracts", "docs-commands-links", "license-notice"],
            receipt_schema="cigar.local-archive-build.v1",
            receipt_filename="build-manifest.json",
        ),
        _artifact(
            3,
            "schemas-conformance",
            "schemas-conformance-archive",
            f"cigar-{VERSION}-schemas-conformance.tar.gz",
            "packaging/honey/contracts/schemas-conformance.v1.json",
            archive_producer,
            "portable",
            ["protocol-drift", "conformance", "archive-contracts"],
            receipt_schema="cigar.local-archive-build.v1",
            receipt_filename="build-manifest.json",
        ),
        _artifact(
            4,
            "macos-runtime-aarch64",
            "native-runtime-archive",
            f"cigar-{VERSION}-{TARGET}.tar.gz",
            "packaging/contracts/macos-runtime-archive.v1.json",
            ["python3", "scripts/release/build_macos_aarch64_archive.py"],
            "native",
            [
                "installed-runtime",
                "archive-contracts",
                "policy-nondisclosure",
                "effect-unknown-recovery",
                "offline-replay",
                "storage-format-v5",
                "v4-v5-migration",
                "revision-recovery",
                "storage-amplification",
                "serial-latency",
                "startup-readiness",
                "context-quality-efficiency",
            ],
            receipt_schema="cigar.development-native-archive-build.v1",
            receipt_filename="native-build-receipt.json",
        ),
        _artifact(
            5,
            "typescript-sdk",
            "npm-tarball",
            f"cigar-sdk-{VERSION}.tgz",
            "packaging/contracts/npm-package.v1.json",
            ["python3", "scripts/release/build_typescript_sdk.py"],
            "typescript",
            ["sdk-clean-installs", "archive-contracts"],
            receipt_schema="cigar.development-typescript-sdk-build.v1",
            receipt_filename="typescript-sdk-build-receipt.json",
        ),
        _artifact(
            6,
            "python-sdk-wheel",
            "python-wheel",
            f"hol_cigar-{PYTHON_VERSION}-py3-none-any.whl",
            "packaging/contracts/python-wheel.v1.json",
            ["python3", "scripts/release/build_python_sdk_artifacts.py"],
            "python",
            ["sdk-clean-installs", "archive-contracts"],
            receipt_schema="cigar.development-python-sdk-build.v1",
            receipt_filename="python-sdk-build-receipt.json",
        ),
        _artifact(
            7,
            "python-sdk-sdist",
            "python-sdist",
            f"hol_cigar-{PYTHON_VERSION}.tar.gz",
            "packaging/contracts/python-sdist.v1.json",
            ["python3", "scripts/release/build_python_sdk_artifacts.py"],
            "python",
            ["sdk-clean-installs", "archive-contracts"],
            receipt_schema="cigar.development-python-sdk-build.v1",
            receipt_filename="python-sdk-build-receipt.json",
        ),
        _artifact(
            8,
            "rust-sdk-local-registry",
            "cargo-local-registry-kit",
            f"cigar-rust-sdk-{VERSION}-local-registry.tar.gz",
            "packaging/honey/contracts/rust-sdk-local-registry.v1.json",
            [
                "python3",
                "scripts/release/build_rust_sdk_crate.py",
                "--honey-local-registry-kit",
            ],
            "rust",
            ["sdk-clean-installs", "archive-contracts"],
            receipt_schema="cigar.honey-rust-sdk-local-registry-build.v1",
            receipt_filename="rust-sdk-local-registry-build-receipt.json",
        ),
        _artifact(
            9,
            "claude-code-plugin",
            "plugin-archive",
            f"cigar-claude-code-{VERSION}.tar.gz",
            "packaging/contracts/plugin-archive.v1.json",
            ["python3", "scripts/release/build_claude_code_plugin.py"],
            "claude",
            ["claude-lifecycle", "archive-contracts"],
            receipt_schema="cigar.development-claude-code-plugin-build.v1",
            receipt_filename="claude-code-plugin-build-receipt.json",
        ),
        _artifact(
            10,
            "honey-demos",
            "demo-archive",
            f"cigar-honey-demos-{VERSION}.tar.gz",
            "packaging/honey/contracts/demos-archive.v1.json",
            ["python3", "scripts/release/build_honey_demos.py"],
            "demos",
            [
                "two-agent-authority",
                "effect-unknown-recovery",
                "offline-replay",
                "prompt-injection-defense",
            ],
            receipt_schema="cigar.honey-demo-build.v1",
            receipt_filename="honey-demo-build-receipt.json",
        ),
        _artifact(
            11,
            "release-notes",
            "release-notes",
            "RELEASE_NOTES_HONEY_v0.9.4.md",
            None,
            ["python3", "scripts/release/assemble_honey_release.py"],
            "source-metadata",
            ["docs-commands-links"],
            receipt_schema=None,
            receipt_filename=None,
        ),
        _artifact(
            12,
            "release-manifest",
            "release-manifest",
            "honey-release-manifest.json",
            None,
            ["python3", "scripts/release/assemble_honey_release.py"],
            "assembly",
            ["artifact-checksums"],
            receipt_schema=None,
            receipt_filename=None,
            generated=True,
        ),
        _artifact(
            13,
            "checksums",
            "checksum-manifest",
            "SHA256SUMS",
            None,
            ["python3", "scripts/release/assemble_honey_release.py"],
            "assembly",
            ["artifact-checksums"],
            receipt_schema=None,
            receipt_filename=None,
            generated=True,
        ),
    ]
    internal = [
        ("source-descriptor", "source"),
        ("installed-runtime-report", "install"),
        ("typescript-clean-install", "sdk"),
        ("python-clean-install", "sdk"),
        ("rust-clean-consumer", "sdk"),
        ("claude-lifecycle-report", "adapter"),
        ("two-agent-demo-report", "demo"),
        ("other-demo-reports", "demo"),
        ("documentation-report", "docs"),
        ("bounded-safety-report", "safety"),
        ("efficiency-reliability-report", "efficiency"),
        ("honey-evidence-ledger", "evidence"),
    ]
    return {
        "schema_version": "cigar.honey.artifact-matrix.v1",
        "profile_id": PROFILE_ID,
        "product_version": VERSION,
        "context_abi": CONTEXT_ABI,
        "release_state": "developer-preview",
        "artifacts": artifacts,
        "internal_inputs": [
            {
                "id": internal[0][0],
                "evidence_class": internal[0][1],
                "required": True,
                "public_attachment": False,
            },
            {
                "id": "qualification-tools",
                "evidence_class": "package",
                "required": True,
                "public_attachment": False,
                "artifact_id": "cigar-conformance-macos-aarch64",
                "kind": "conformance-runner-archive",
                "filename": f"cigar-conformance-{VERSION}-{TARGET}.tar.gz",
                "contract": "packaging/contracts/macos-conformance-runner.v1.json",
                "producer": [
                    "python3",
                    "scripts/release/build_macos_qualification_tools.py",
                    "conformance",
                ],
                "target": TARGET,
                "workspace": "qualification-tools",
                "receipt": {
                    "required": True,
                    "schema_version": "cigar.development-qualification-tool-build.v1",
                    "filename": "macos-conformance-development-build.json",
                },
            },
            *[
                {
                    "id": identifier,
                    "evidence_class": evidence_class,
                    "required": True,
                    "public_attachment": False,
                }
                for identifier, evidence_class in internal[1:]
            ],
        ],
        "fail_closed": True,
    }


def expected_capability_profile(root: Path) -> dict[str, Any]:
    services = [
        {
            "name": name,
            "operation_count": len(operations),
            "operation_ids": list(operations),
        }
        for name, operations in SERVICE_OPERATIONS
    ]
    return {
        "schema_version": "cigar.honey.capability-profile.v1",
        "profile_id": PROFILE_ID,
        "identity": {
            "marketing_name": "CIGAR Honey v0.9.4",
            "product_version": VERSION,
            "python_distribution_version": PYTHON_VERSION,
            "tag": f"v{VERSION}",
            "channel": "honey",
            "release_state": "developer-preview",
            "context_abi": CONTEXT_ABI,
            "prerelease": True,
            "published": False,
            "supported": False,
            "production_qualified": False,
            "ecosystem_versions": product_version.derived_versions(VERSION),
        },
        "product_version_binding": {
            "path": product_version.MANIFEST_PATH,
            "sha256": sha256_file(root / product_version.MANIFEST_PATH),
        },
        "platform": {
            "host_os": "macos",
            "host_arch": "arm64",
            "target_triple": TARGET,
            "deployment_modes": ["embedded", "local-sidecar"],
            "trust_model": "single-local-os-user-with-explicit-agent-principals",
            "network_required": False,
        },
        "protocol": {
            "protocol_min": "1.0",
            "protocol_max": "1.x",
            "schema_major": 1,
            "unknown_field_behavior": "reject-unless-explicit-schema-extension-point",
            "operation_registry": {
                "source": OPERATION_SOURCE,
                "source_sha256": OPERATION_SOURCE_SHA256,
                "count": 45,
                "id_inventory_sha256": OPERATION_INVENTORY_SHA256,
            },
            "nominal_payload_registry": {
                "source": PAYLOAD_SOURCE,
                "source_sha256": PAYLOAD_SOURCE_SHA256,
                "schema_source": PAYLOAD_SCHEMA_SOURCE,
                "schema_source_sha256": PAYLOAD_SCHEMA_SOURCE_SHA256,
                "count": 70,
                "id_inventory_sha256": PAYLOAD_INVENTORY_SHA256,
            },
            "services": services,
        },
        "capabilities": [
            {
                "id": identifier,
                "status": "required",
                "support_level": "developer-preview",
            }
            for identifier in CAPABILITY_IDS
        ],
        "integrations": [
            "cli",
            "unix-domain-local-daemon",
            "mcp-2025-06-18-stdio",
            "claude-code",
            "typescript-direct-tarball",
            "python-wheel-sdist",
            "python-pypi-developer-preview",
            "rust-local-registry-kit",
            "filesystem-source",
            "git-source",
            "filesystem-reference-effect",
            "local-content-safe-observability",
            "durable-evidence-replay",
        ],
        "two_agent_profile": {
            "agent_count": 2,
            "autonomous_scheduler_included": False,
            "principal_model": "distinct-authenticated-local-principals",
            "coordination_protocol": "context-space-checkpoint-signed-handoff-result-typed-merge",
            "bindings": [
                "recipient",
                "audience",
                "tenant",
                "nonce",
                "expiry",
                "signature",
            ],
            "attenuation": ["capability", "project", "topic", "budget"],
            "acceptance_reauthorization": True,
            "one_use_replay_protection": True,
            "durable_revocation": True,
            "private_overlay_ownership": True,
            "merge_semantics": "exact-base-optimistic-with-typed-conflict",
            "unrestricted_transcript_allowed": False,
            "evidence_root": "sha256-domain-separated-content-addressed-root",
            "poseidon_required": False,
        },
        "artifact_ids": [
            entry["id"] for entry in expected_artifact_matrix()["artifacts"]
        ],
        "mandatory_gate_ids": list(GATE_IDS),
        "deferrals": [
            {"id": identifier, "selected": False, "advertised": False}
            for identifier in DEFERRED_IDS
        ],
        "fail_closed": True,
    }


def expected_release_requirements(
    profile: dict[str, Any], matrix: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "cigar.honey.release-requirements.v1",
        "profile_id": PROFILE_ID,
        "evidence_class": "developer-preview",
        "authority_bindings": {
            "capability_profile": {
                "path": PROFILE_PATH,
                "sha256": sha256_bytes(canonical_json_bytes(profile)),
            },
            "artifact_matrix": {
                "path": MATRIX_PATH,
                "sha256": sha256_bytes(canonical_json_bytes(matrix)),
            },
        },
        "required_source_state": {
            "committed": True,
            "clean": True,
            "tagged_before_build": False,
        },
        "machine_claims": {
            "prerelease": True,
            "supported": False,
            "production_qualified": False,
        },
        "mandatory_gates": [
            {
                "id": identifier,
                "required": True,
                "evidence_status": "required-not-implied",
            }
            for identifier in GATE_IDS
        ],
        "deferred_gates": [
            {
                "id": identifier,
                "required_for_honey": False,
                "may_be_reported_as_passed_without_evidence": False,
            }
            for identifier in (
                "seven-day-fuzz",
                "four-hour-mutation",
                "twenty-four-hour-soak",
                "production-chaos-matrix",
                "large-scale-qualification",
                "developer-id-notarization",
                "two-builder-reproducibility",
            )
        ],
        "prohibited_claims": [
            "production-ready",
            "production-supported",
            "production-qualified",
            "independently-security-certified",
            "public-multi-tenant-safe",
            "apple-notarized",
            "cross-platform-supported",
            "ga",
        ],
        "publication": {
            "github_prerelease_required": True,
            "pypi_project": "hol-cigar",
            "pypi_distribution_version": PYTHON_VERSION,
            "pypi_release_state": "alpha",
            "pypi_scope": "python-sdk-only",
            "pypi_requires_full_honey_qualification": False,
            "pypi_required_gate_ids": [
                "authority-drift",
                "clean-committed-source",
                "focused-tests",
                "archive-contracts",
                "sdk-clean-installs",
                "docs-commands-links",
                "license-notice",
                "artifact-checksums",
            ],
            "pypi_environment": "pypi",
            "pypi_trusted_publishing_required": True,
            "pypi_attestations_required": True,
            "replace_attachment_bytes": False,
            "owner_authorization_required": True,
        },
        "fail_closed": True,
    }


OWNERSHIP_SPECS: tuple[
    tuple[str, list[str], list[str], list[str], list[str], list[str]], ...
] = (
    (
        "catalog",
        ["crates/cigar-catalog", "crates/cigar-code-intel"],
        ["macos-runtime-aarch64"],
        ["docs/reference/catalog-ingestion.md"],
        ["offline-context-compiler"],
        ["crates/cigar-code-intel/tests/ingestion.rs"],
    ),
    (
        "governed-context",
        ["crates/cigar-compiler", "crates/cigar-retrieval"],
        ["macos-runtime-aarch64"],
        ["docs/reference/deterministic-compiler.md"],
        ["offline-context-compiler"],
        ["crates/cigar-compiler/tests/compiler.rs"],
    ),
    (
        "policy-enforcement",
        ["crates/cigar-policy"],
        ["macos-runtime-aarch64"],
        ["docs/reference/policy-capabilities.md"],
        ["prompt-injection-defense"],
        ["crates/cigar-policy/tests/policy.rs"],
    ),
    (
        "context-spaces",
        ["crates/cigar-space"],
        ["macos-runtime-aarch64"],
        ["docs/reference/context-spaces.md"],
        ["multi-project-isolation"],
        ["crates/cigar-space/tests/space.rs"],
    ),
    (
        "two-agent-handoff",
        ["crates/cigar-space"],
        ["macos-runtime-aarch64", "honey-demos"],
        ["docs/guides/honey-two-agent.md"],
        ["two-agent-handoff"],
        ["crates/cigar-space/tests/handoff.rs"],
    ),
    (
        "recoverable-effects",
        ["crates/cigar-effects"],
        ["macos-runtime-aarch64"],
        ["docs/guides/honey-effects-replay.md"],
        ["effect-crash-recovery"],
        ["crates/cigar-effects/tests/wp12_effects.rs"],
    ),
    (
        "observational-replay",
        ["crates/cigar-replay"],
        ["macos-runtime-aarch64"],
        ["docs/guides/honey-effects-replay.md"],
        ["cross-runtime-replay"],
        ["crates/cigar-replay/tests/wp13_replay_modes.rs"],
    ),
    (
        "operations-observability",
        ["crates/cigar-observe", "crates/cigar-daemon"],
        ["macos-runtime-aarch64"],
        ["docs/reference/configuration-errors-metrics-extensions.md"],
        ["offline-context-compiler"],
        ["crates/cigar-observe/src/lib.rs"],
    ),
    (
        "cli",
        ["crates/cigar-cli"],
        ["macos-runtime-aarch64"],
        ["docs/reference/cli.md"],
        ["offline-context-compiler"],
        ["crates/cigar-cli/src/lib.rs"],
    ),
    (
        "local-daemon",
        ["crates/cigar-daemon", "crates/cigar-api"],
        ["macos-runtime-aarch64"],
        ["docs/operations/daemon-lifecycle.md"],
        ["offline-context-compiler"],
        ["crates/cigar-daemon/tests/deployment_assets.rs"],
    ),
    (
        "mcp",
        ["crates/cigar-mcp"],
        ["macos-runtime-aarch64"],
        ["docs/guides/honey-mcp-claude.md"],
        ["claude-code-experience"],
        ["crates/cigar-mcp/tests/process.rs"],
    ),
    (
        "claude-code",
        ["adapters/claude-code", "crates/cigar-claude-hook"],
        ["claude-code-plugin"],
        ["docs/guides/honey-mcp-claude.md"],
        ["claude-code-experience"],
        ["crates/cigar-cli/tests/claude_plugin.rs"],
    ),
    (
        "typescript-sdk",
        ["sdk/typescript"],
        ["typescript-sdk"],
        ["docs/guides/honey-typescript.md"],
        ["two-agent-handoff"],
        ["sdk/typescript/src/tests/client.test.ts"],
    ),
    (
        "python-sdk",
        ["sdk/python"],
        ["python-sdk-wheel", "python-sdk-sdist"],
        ["docs/guides/honey-python.md"],
        ["two-agent-handoff"],
        ["sdk/python/tests/test_client.py"],
    ),
    (
        "rust-sdk",
        ["sdk/rust"],
        ["rust-sdk-local-registry"],
        ["docs/guides/honey-rust.md"],
        ["two-agent-handoff"],
        ["sdk/rust/tests/client_contract.rs"],
    ),
    (
        "filesystem-git-ingestion",
        ["connectors"],
        ["macos-runtime-aarch64"],
        ["docs/reference/catalog-ingestion.md"],
        ["offline-context-compiler"],
        ["crates/cigar-code-intel/tests/ingestion.rs"],
    ),
    (
        "filesystem-reference-effect",
        ["crates/cigar-effects"],
        ["macos-runtime-aarch64"],
        ["docs/guides/honey-effects-replay.md"],
        ["effect-crash-recovery"],
        ["crates/cigar-effects/tests/wp12_faults.rs"],
    ),
)


def expected_ownership(
    profile: dict[str, Any], matrix: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "cigar.honey.capability-ownership.v1",
        "profile_id": PROFILE_ID,
        "authority_bindings": {
            "capability_profile": {
                "path": PROFILE_PATH,
                "sha256": sha256_bytes(canonical_json_bytes(profile)),
            },
            "artifact_matrix": {
                "path": MATRIX_PATH,
                "sha256": sha256_bytes(canonical_json_bytes(matrix)),
            },
        },
        "surfaces": [
            {
                "id": identifier,
                "implementation_paths": implementation,
                "artifact_ids": artifacts,
                "guide_paths": guides,
                "demo_ids": demos,
                "fast_acceptance_tests": tests,
            }
            for identifier, implementation, artifacts, guides, demos, tests in OWNERSHIP_SPECS
        ],
        "fail_closed": True,
    }


def expected_archives() -> dict[str, Any]:
    excludes = [
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
    ]
    source = [
        ".cargo/**",
        ".config/**",
        ".devcontainer/**",
        ".github/**",
        ".dockerignore",
        ".gitignore",
        ".gitleaks.toml",
        "Cargo.toml",
        "Cargo.lock",
        "IMPLEMENTATION_STATUS.md",
        "README.md",
        "README_HONEY.md",
        "RELEASE_NOTES_HONEY_v0.9.4.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "clippy.toml",
        "deny.toml",
        "go.work",
        "justfile",
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "prd.md",
        "pyproject.toml",
        "rust-toolchain.toml",
        "rustfmt.toml",
        "support.toml",
        "uv.lock",
        "adapters/**",
        "analysis/**",
        "baselines/**",
        "benches/**",
        "conformance/**",
        "connectors/**",
        "crates/**",
        "demos/**",
        "deploy/**",
        "docs/**",
        "fuzz/**",
        "migrations/**",
        "packaging/**",
        "schemas/**",
        "scripts/**",
        "sdk/**",
        "spec/**",
        "tests/**",
        "tools/**",
        "vendor/**",
    ]
    return {
        "schema_version": "cigar.local-archives.v1",
        "product_version": VERSION,
        "context_abi": CONTEXT_ABI,
        "archives": [
            {
                "id": "source",
                "filename": f"cigar-{VERSION}-source.tar.gz",
                "contract": "packaging/honey/contracts/source-archive.v1.json",
                "include": source,
            },
            {
                "id": "docs",
                "filename": f"cigar-{VERSION}-docs.tar.gz",
                "contract": "packaging/honey/contracts/docs-archive.v1.json",
                "include": [
                    "README.md",
                    "README_HONEY.md",
                    "RELEASE_NOTES_HONEY_v0.9.4.md",
                    "LICENSE",
                    "NOTICE",
                    "docs/**",
                    "packaging/licenses/**",
                    "packaging/schemas/**",
                    "schemas/generated-manifest.json",
                    "schemas/json/**",
                    "schemas/openapi/**",
                    "schemas/proto/**",
                    "sdk/README.md",
                    "sdk/typescript/README.md",
                    "sdk/python/README.md",
                    "sdk/rust/README.md",
                ],
            },
            {
                "id": "schemas-conformance",
                "filename": f"cigar-{VERSION}-schemas-conformance.tar.gz",
                "contract": "packaging/honey/contracts/schemas-conformance.v1.json",
                "include": [
                    "LICENSE",
                    "NOTICE",
                    "conformance/**",
                    "schemas/**",
                    "spec/api/**",
                    "spec/errors/**",
                    "packaging/honey/**",
                    "packaging/licenses/**",
                    "packaging/schemas/**",
                ],
            },
        ],
        "always_exclude": excludes,
    }


def expected_contracts() -> dict[str, dict[str, Any]]:
    base = {
        "schema_version": "cigar.package-contract.v1",
        "formats": ["tar.gz"],
        "deny": ["**/.git/**", "**/.env*", "**/*.key", "**/*.pem", "**/target/**"],
        "symlinks": "forbid",
        "line_endings": "lf",
        "modes": ["0644", "0755"],
        "max_entries": 30000,
        "max_member_bytes": 67108864,
        "max_total_bytes": 536870912,
        "content_scan": True,
        "content_scan_exemptions": [],
    }
    source = dict(base)
    source.update(
        {
            "id": "honey-source-archive-v1",
            "content_scan_exemptions": [
                {
                    "pattern": "crates/cigar-catalog/src/secret.rs",
                    "reason": "audited synthetic secret-scanner fixtures",
                },
                {
                    "pattern": "crates/cigar-cli/src/beta_state_compat.rs",
                    "reason": "audited synthetic legacy macOS path fixture",
                    "findings": ["macos-developer-path"],
                },
                {
                    "pattern": "crates/cigar-cli/tests/fixtures/beta-state-v0.1.0-beta.1/*.json",
                    "reason": "audited synthetic legacy macOS state fixtures",
                    "findings": ["macos-developer-path"],
                },
                {
                    "pattern": "crates/cigar-daemon/src/telemetry.rs",
                    "reason": "audited synthetic telemetry redaction canary",
                    "findings": ["private-key"],
                },
                {
                    "pattern": "crates/xtask/native_macos_command_plane.py",
                    "reason": "audited synthetic private-key scanner signatures",
                    "findings": ["private-key"],
                },
                {
                    "pattern": "crates/xtask/tests/test_native_macos_command_plane.py",
                    "reason": "audited synthetic private-key rejection fixture",
                    "findings": ["private-key"],
                },
                {
                    "pattern": "tools/refinement/tests/test_r11_loop.py",
                    "reason": "audited synthetic private-key rejection fixture",
                    "findings": ["private-key"],
                },
                {
                    "pattern": "scripts/release/release_lib.py",
                    "reason": "the scanner contains its own detection signatures",
                },
                {
                    "pattern": "vendor/**",
                    "reason": "pinned upstream source contains documented example credentials",
                },
            ],
            "allow": [
                "RELEASE-METADATA.json",
                ".cargo/**",
                ".config/**",
                ".devcontainer/**",
                ".github/**",
                ".dockerignore",
                ".gitignore",
                ".gitleaks.toml",
                "Cargo.toml",
                "Cargo.lock",
                "IMPLEMENTATION_STATUS.md",
                "README.md",
                "README_HONEY.md",
                "RELEASE_NOTES_HONEY_v0.9.4.md",
                "LICENSE",
                "NOTICE",
                "SECURITY.md",
                "clippy.toml",
                "deny.toml",
                "go.work",
                "justfile",
                "package.json",
                "pnpm-lock.yaml",
                "pnpm-workspace.yaml",
                "prd.md",
                "pyproject.toml",
                "rust-toolchain.toml",
                "rustfmt.toml",
                "support.toml",
                "uv.lock",
                "adapters/**",
                "analysis/**",
                "baselines/**",
                "benches/**",
                "conformance/**",
                "connectors/**",
                "crates/**",
                "demos/**",
                "deploy/**",
                "docs/**",
                "fuzz/**",
                "migrations/**",
                "packaging/**",
                "schemas/**",
                "scripts/**",
                "sdk/**",
                "spec/**",
                "tests/**",
                "tools/**",
                "vendor/**",
            ],
            "required": [
                "RELEASE-METADATA.json",
                "Cargo.toml",
                "Cargo.lock",
                "README.md",
                "README_HONEY.md",
                "RELEASE_NOTES_HONEY_v0.9.4.md",
                "LICENSE",
                "NOTICE",
                "SECURITY.md",
                PROFILE_PATH,
                MATRIX_PATH,
                REQUIREMENTS_PATH,
                "packaging/licenses/Apache-2.0.txt",
                "packaging/licenses/third-party-policy.v1.json",
                "packaging/licenses/third-party-inventory.v1.json",
            ],
            "version_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/product_version",
            },
            "abi_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/context_abi",
            },
        }
    )
    schemas = dict(base)
    schemas.update(
        {
            "id": "honey-schemas-conformance-v1",
            "allow": [
                "RELEASE-METADATA.json",
                "LICENSE",
                "NOTICE",
                "conformance/**",
                "schemas/**",
                "spec/api/**",
                "spec/errors/**",
                "packaging/honey/**",
                "packaging/licenses/**",
                "packaging/schemas/**",
            ],
            "required": [
                "RELEASE-METADATA.json",
                "LICENSE",
                "NOTICE",
                "conformance/runner/Cargo.toml",
                "schemas/openapi/cigar-v1.json",
                "schemas/proto/cigar_service.proto",
                "schemas/proto/context_abi.proto",
                "spec/api/operations-v1.json",
                PROFILE_PATH,
                MATRIX_PATH,
                REQUIREMENTS_PATH,
            ],
            "version_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/product_version",
            },
            "abi_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/context_abi",
            },
        }
    )
    docs = dict(base)
    docs.update(
        {
            "id": "honey-docs-archive-v1",
            "allow": [
                "RELEASE-METADATA.json",
                "README.md",
                "README_HONEY.md",
                "RELEASE_NOTES_HONEY_v0.9.4.md",
                "LICENSE",
                "NOTICE",
                "docs/**",
                "packaging/licenses/**",
                "packaging/schemas/**",
                "schemas/generated-manifest.json",
                "schemas/json/**",
                "schemas/openapi/**",
                "schemas/proto/**",
                "sdk/README.md",
                "sdk/typescript/README.md",
                "sdk/python/README.md",
                "sdk/rust/README.md",
            ],
            "required": [
                "RELEASE-METADATA.json",
                "README_HONEY.md",
                "docs/guides/honey-install.md",
                "docs/guides/honey-quickstart.md",
                "docs/guides/honey-two-agent.md",
                "docs/guides/honey-typescript.md",
                "docs/guides/honey-python.md",
                "docs/guides/honey-rust.md",
                "docs/guides/honey-mcp-claude.md",
                "docs/guides/honey-effects-replay.md",
                "docs/guides/honey-security-limitations.md",
                "docs/guides/honey-troubleshooting.md",
                "LICENSE",
                "NOTICE",
            ],
            "version_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/product_version",
            },
            "abi_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/context_abi",
            },
        }
    )
    rust = dict(base)
    rust.update(
        {
            "id": "honey-rust-sdk-local-registry-v1",
            "allow": [
                "RELEASE-METADATA.json",
                ".cargo/config.toml",
                "registry/**",
                "examples/agent_a_coordinator.rs",
                "examples/consumer/**",
                "README.md",
                "LICENSE",
                "NOTICE",
                "SHA256SUMS",
            ],
            "required": [
                "RELEASE-METADATA.json",
                ".cargo/config.toml",
                "examples/agent_a_coordinator.rs",
                "examples/consumer/Cargo.toml",
                "examples/consumer/Cargo.lock",
                "examples/consumer/src/main.rs",
                "examples/consumer/fixtures/semantic-bundle-v1.json",
                "README.md",
                "LICENSE",
                "NOTICE",
                "SHA256SUMS",
            ],
            "required_patterns": ["registry/*.crate", "registry/index/**"],
            "checksum_manifest": {"path": "SHA256SUMS", "scope": "all-payload-files"},
            "version_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/product_version",
            },
            "abi_binding": {
                "path_pattern": "RELEASE-METADATA.json",
                "format": "json",
                "json_pointer": "/context_abi",
            },
        }
    )
    return {
        "packaging/honey/contracts/source-archive.v1.json": source,
        "packaging/honey/contracts/docs-archive.v1.json": docs,
        "packaging/honey/contracts/schemas-conformance.v1.json": schemas,
        "packaging/honey/contracts/rust-sdk-local-registry.v1.json": rust,
    }


def _schema(identifier: str, title: str, document: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://cigar.invalid/schemas/{identifier}",
        "title": title,
        "const": document,
    }


def expected_documents(root: Path) -> dict[str, dict[str, Any]]:
    matrix = expected_artifact_matrix()
    profile = expected_capability_profile(root)
    requirements = expected_release_requirements(profile, matrix)
    ownership = expected_ownership(profile, matrix)
    archives = expected_archives()
    documents = {
        PROFILE_PATH: profile,
        MATRIX_PATH: matrix,
        REQUIREMENTS_PATH: requirements,
        OWNERSHIP_PATH: ownership,
        ARCHIVES_PATH: archives,
    }
    for path, document in list(documents.items()):
        name = Path(path).name.replace(".json", ".schema.json")
        documents[f"packaging/honey/schemas/{name}"] = _schema(
            name, f"CIGAR Honey {Path(path).stem}", document
        )
    documents.update(expected_contracts())
    return documents


def _regular(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HoneyProfileError(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise HoneyProfileError(f"{label} must be a single-link regular file")


def _validate_protocol(root: Path) -> None:
    for relative, digest in (
        (OPERATION_SOURCE, OPERATION_SOURCE_SHA256),
        (PAYLOAD_SOURCE, PAYLOAD_SOURCE_SHA256),
        (PAYLOAD_SCHEMA_SOURCE, PAYLOAD_SCHEMA_SOURCE_SHA256),
    ):
        _regular(root / relative, relative)
        if sha256_file(root / relative) != digest:
            raise HoneyProfileError(f"Honey protocol authority drift: {relative}")
    catalog = load_json(root / OPERATION_SOURCE)
    if (
        not isinstance(catalog, dict)
        or catalog.get("operation_count") != 45
        or catalog.get("status") != "frozen-v1"
    ):
        raise HoneyProfileError("Honey operation catalog identity drift")
    observed: list[str] = []
    services = catalog.get("services")
    if not isinstance(services, list) or len(services) != 7:
        raise HoneyProfileError("Honey must expose exactly seven protocol services")
    for service, (name, operation_ids) in zip(
        services, SERVICE_OPERATIONS, strict=True
    ):
        if (
            not isinstance(service, dict)
            or service.get("name") != name
            or not isinstance(service.get("operations"), list)
        ):
            raise HoneyProfileError("Honey service inventory drift")
        ids = [
            entry.get("operation_id")
            for entry in service["operations"]
            if isinstance(entry, dict)
        ]
        if ids != list(operation_ids):
            raise HoneyProfileError(f"Honey operation inventory drift for {name}")
        observed.extend(ids)
    if (
        len(observed) != 45
        or sha256_bytes(canonical_json_bytes(observed)) != OPERATION_INVENTORY_SHA256
    ):
        raise HoneyProfileError("Honey 45-operation digest drift")
    payload_schema = load_json(root / PAYLOAD_SCHEMA_SOURCE)
    types = payload_schema.get("types") if isinstance(payload_schema, dict) else None
    if (
        not isinstance(types, dict)
        or len(types) != 70
        or sha256_bytes(canonical_json_bytes(sorted(types))) != PAYLOAD_INVENTORY_SHA256
    ):
        raise HoneyProfileError("Honey 70-payload digest drift")


def _validate_static_authority(root: Path) -> None:
    """Validate hand-maintained Honey authority that generate must not rewrite."""

    path = root / EVIDENCE_SCHEMA_PATH
    _regular(path, EVIDENCE_SCHEMA_PATH)
    if sha256_file(path) != EVIDENCE_SCHEMA_SHA256:
        raise HoneyProfileError(f"Honey static authority drift: {EVIDENCE_SCHEMA_PATH}")


def _reject_production_claims(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            current = f"{path}.{key}"
            if (
                key in {"supported", "production_qualified", "production_ready"}
                and nested is True
            ):
                raise HoneyProfileError(
                    f"Honey authority contains a true production claim at {current}"
                )
            _reject_production_claims(nested, current)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_production_claims(nested, f"{path}[{index}]")


def generate(root: Path) -> None:
    root = root.resolve(strict=True)
    product_version.check(root)
    manifest = product_version.load_manifest(root)
    if manifest.get("version") != VERSION or manifest.get("context_abi") != CONTEXT_ABI:
        raise HoneyProfileError("product-version authority is not exact Honey v0.9.4")
    _validate_protocol(root)
    _validate_static_authority(root)
    for relative, document in expected_documents(root).items():
        write_json(root / relative, document)
    check(root)


def check(root: Path) -> None:
    root = root.resolve(strict=True)
    product_version.check(root)
    manifest = product_version.load_manifest(root)
    if manifest != {
        "schema_version": "cigar.product-version.v1",
        "product": "cigar",
        "version": VERSION,
        "target_release_version": "0.9.4",
        "context_abi": CONTEXT_ABI,
        "release_state": "developer-preview",
        "channel": "honey",
        "prerelease": True,
        "published": False,
        "supported": False,
        "tag": f"v{VERSION}",
    }:
        raise HoneyProfileError(
            "product-version authority is not the exact Honey identity"
        )
    _validate_protocol(root)
    _validate_static_authority(root)
    documents = expected_documents(root)
    for relative, expected in documents.items():
        path = root / relative
        _regular(path, relative)
        observed = load_json(path)
        if observed != expected or path.read_bytes() != canonical_json_bytes(observed):
            raise HoneyProfileError(f"Honey authority drift: {relative}")
    matrix = documents[MATRIX_PATH]
    ids = [entry["id"] for entry in matrix["artifacts"]]
    filenames = [entry["filename"] for entry in matrix["artifacts"]]
    if len(ids) != 13 or len(set(ids)) != 13 or len(set(filenames)) != 13:
        raise HoneyProfileError(
            "Honey artifact inventory is not exactly 13 unique attachments"
        )
    if any(
        entry.get("workspace")
        not in {
            "portable",
            "native",
            "typescript",
            "python",
            "rust",
            "claude",
            "demos",
            "assembly",
            "source-metadata",
        }
        for entry in matrix["artifacts"]
    ):
        raise HoneyProfileError("Honey artifact workspace leaked outside its allowlist")
    if [entry.get("order") for entry in matrix["artifacts"]] != list(range(1, 14)):
        raise HoneyProfileError("Honey artifact order is not deterministic")
    gate_ids = set(GATE_IDS)
    for entry in matrix["artifacts"]:
        producer = entry.get("producer")
        if (
            not isinstance(producer, list)
            or not producer
            or not all(isinstance(item, str) and item for item in producer)
        ):
            raise HoneyProfileError(
                f"Honey artifact {entry.get('id')} has no producer argv"
            )
        if not set(entry.get("qualification_gate_ids", [])).issubset(gate_ids):
            raise HoneyProfileError(
                f"Honey artifact {entry.get('id')} names an unknown gate"
            )
        contract = entry.get("contract")
        if contract is None:
            if entry.get("id") not in {
                "release-notes",
                "release-manifest",
                "checksums",
            }:
                raise HoneyProfileError(
                    f"Honey package artifact {entry.get('id')} lacks a contract"
                )
            continue
        contract_path = root / contract
        _regular(contract_path, f"contract for {entry.get('id')}")
        contract_document = load_json(contract_path)
        if (
            not isinstance(contract_document, dict)
            or contract_document.get("schema_version") != "cigar.package-contract.v1"
        ):
            raise HoneyProfileError(
                f"Honey artifact {entry.get('id')} contract is invalid"
            )
    profile = documents[PROFILE_PATH]
    capability_ids = [entry["id"] for entry in profile["capabilities"]]
    ownership_ids = [entry["id"] for entry in documents[OWNERSHIP_PATH]["surfaces"]]
    if capability_ids != list(CAPABILITY_IDS) or ownership_ids != list(CAPABILITY_IDS):
        raise HoneyProfileError(
            "unknown, duplicate, missing, or reordered Honey capability"
        )
    claims = documents[REQUIREMENTS_PATH]["machine_claims"]
    if claims != {
        "prerelease": True,
        "supported": False,
        "production_qualified": False,
    }:
        raise HoneyProfileError("Honey authority contains a production-support claim")
    for relative in (PROFILE_PATH, MATRIX_PATH, REQUIREMENTS_PATH, OWNERSHIP_PATH):
        _reject_production_claims(documents[relative], relative)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--evidence-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        reject_evidence_directory(arguments.evidence_dir, "Honey authority operation")
        if arguments.command == "generate":
            generate(arguments.root)
        else:
            check(arguments.root)
    except (ReleaseError, product_version.VersionError) as error:
        print(f"honey-profile: {error}", file=sys.stderr)
        return 1
    print(
        f"honey-profile: {arguments.command} passed for {VERSION} "
        f"({len(expected_documents(arguments.root.resolve())) + 1} authority files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
