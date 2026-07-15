#!/usr/bin/env python3
"""Generate and validate the fail-closed post-beta macOS arm64 capability ledger."""

from __future__ import annotations

import argparse
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from beta_profile import EXCLUDED_CAPABILITIES, validate as validate_beta_profile
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


PROFILE_ID = "cigar.post-beta.macos-arm64.v1"
PROFILE_PATH = "packaging/post-beta-capability-profile.v1.json"
SCHEMA_PATH = "packaging/schemas/post-beta-capability-profile.v1.schema.json"
SCHEMA_SHA256 = "2042dbeca0b4f3af25978aa59f630cb60f5fdee50427bd3a918bdd499ef0877b"
OWNERSHIP_PATH = "packaging/post-beta-capability-ownership.v1.json"
OWNERSHIP_SCHEMA_PATH = (
    "packaging/schemas/post-beta-capability-ownership.v1.schema.json"
)
OWNERSHIP_SCHEMA_SHA256 = (
    "16dd226cb969adcbd7886e5f54c88a7e6021509de6f38585338fbccf98d6425f"
)
OWNERSHIP_REGISTRY_SHA256 = (
    "52586180411055d96776ae32a33e0c49a32cd385fec2e62f467c747c6b28af5b"
)
CAPABILITY_PROFILE_SHA256 = (
    "f7b24ccdda679a7046db4d016db349e15ef462c2ea58221821cbda7113ef61ae"
)
ARTIFACT_MATRIX_PATH = "packaging/artifact-matrix.v1.json"
ARTIFACT_ID_INVENTORY_SHA256 = (
    "b5f25d88f278943ff7f3fe9cea42d335df272913afa4538d1acb30071ecec1c7"
)
BETA_POLICY_PATH = "packaging/beta/capability-policy.v1.json"
BETA_POLICY_SHA256 = "262abc5d6a026ca895a905509436463dc24bd7c60bc94cb42c56978e07c66568"

STATE_ORDER = (
    "specified",
    "implemented_source",
    "integrated",
    "packaged",
    "qualified",
    "published",
    "supported",
)
CAPABILITY_IDS = tuple(identifier for identifier, _ in EXCLUDED_CAPABILITIES)

# Every selected capability now has a checked-in source implementation. Later lifecycle states
# remain false until their distinct integration, artifact, qualification, publication, and support
# evidence is independently accepted.
UNSPECIFIED = frozenset()
SOURCE_INCOMPLETE = frozenset()


def expected_profile() -> dict[str, Any]:
    """Return the reviewed inventory-only profile; later states remain false by design."""
    capabilities: list[dict[str, Any]] = []
    for identifier in CAPABILITY_IDS:
        capabilities.append(
            {
                "id": identifier,
                "specified": identifier not in UNSPECIFIED,
                "implemented_source": identifier not in SOURCE_INCOMPLETE,
                "integrated": False,
                "packaged": False,
                "qualified": False,
                "published": False,
                "supported": False,
            }
        )
    return {
        "schema_version": "cigar.post-beta.capability-profile.v1",
        "profile_id": PROFILE_ID,
        "source_capability_policy": {
            "path": BETA_POLICY_PATH,
            "sha256": BETA_POLICY_SHA256,
        },
        "platform_scope": {
            "host_os": "macos",
            "host_arch": "arm64",
            "target_triple": "aarch64-apple-darwin",
        },
        "state_order": list(STATE_ORDER),
        "fail_closed": True,
        "capabilities": capabilities,
    }


def _selected_scope() -> dict[str, str]:
    return {
        "disposition": "selected",
        "profile_id": PROFILE_ID,
        "target_triple": "aarch64-apple-darwin",
    }


def _deferred_scope(platform: str, reason: str) -> dict[str, str]:
    return {
        "disposition": "deferred-separate-profile",
        "platform": platform,
        "reason": reason,
    }


def _ownership_entry(
    identifier: str,
    *,
    code_owner: str,
    support_owner: str,
    authority_boundary: str,
    persistence_boundary: str,
    artifact_set: tuple[tuple[str, str], ...],
    test_inventory: tuple[str, ...],
    operations_docs: tuple[str, ...],
    rollback_or_disable: str,
    profile_scope: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "code_owner": code_owner,
        "support_owner": support_owner,
        "authority_boundary": authority_boundary,
        "persistence_boundary": persistence_boundary,
        "artifact_set": [
            {"id": artifact_id, "status": status}
            for artifact_id, status in artifact_set
        ],
        "profile_scope": profile_scope or _selected_scope(),
        "test_inventory": list(test_inventory),
        "operations_docs": list(operations_docs),
        "rollback_or_disable": rollback_or_disable,
    }


def expected_ownership_registry() -> dict[str, Any]:
    """Return ownership without implying released artifacts or staffed support."""
    binary = (("cli-daemon-macos-aarch64", "planned"),)
    capabilities = [
        _ownership_entry(
            "catalog-discovery",
            code_owner="catalog-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Discovery may read only explicitly configured source roots through bounded "
                "connector capabilities; it cannot grant policy authority or execute effects."
            ),
            persistence_boundary=(
                "Source registrations and refresh cursors are durable store records; scan "
                "scratch data and ignore evaluation are disposable."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-code-intel/tests/ingestion.rs",),
            operations_docs=(
                "docs/reference/catalog-ingestion.md",
                "docs/operations/index-rebuild.md",
            ),
            rollback_or_disable=(
                "Disable the source or discovery worker, retain durable registrations, and "
                "rebuild disposable indexes before re-enabling."
            ),
        ),
        _ownership_entry(
            "catalog-ingest",
            code_owner="catalog-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Ingestion accepts only connector-produced observations that pass provenance, "
                "secret, policy, and tenant checks."
            ),
            persistence_boundary=(
                "Canonical atoms, lineage, tombstones, and publication outbox records are "
                "durable; parser buffers are ephemeral."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-code-intel/tests/ingestion.rs",),
            operations_docs=(
                "docs/reference/catalog-ingestion.md",
                "docs/operations/blob-corruption.md",
            ),
            rollback_or_disable=(
                "Stop ingestion publication, quarantine the offending source revision, and "
                "restore the last verified catalog checkpoint."
            ),
        ),
        _ownership_entry(
            "catalog-query",
            code_owner="catalog-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Queries are tenant-, lifecycle-, and policy-scoped reads and cannot reveal "
                "denied record existence."
            ),
            persistence_boundary=(
                "Queries read durable catalog state and disposable indexes without creating "
                "new catalog authority."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-api/tests/typed_payload_contract.rs",),
            operations_docs=(
                "docs/reference/catalog-ingestion.md",
                "docs/operations/index-rebuild.md",
            ),
            rollback_or_disable=(
                "Disable catalog-query routes and fall back only to authenticated metadata "
                "administration while indexes are rebuilt."
            ),
        ),
        _ownership_entry(
            "context",
            code_owner="context-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Compilation consumes only policy-approved atoms and target contracts; emitted "
                "bundles carry no authority beyond their signed manifest."
            ),
            persistence_boundary=(
                "Manifests and provenance are durable; plans, token estimates, materialization "
                "buffers, and caches are reproducible and disposable."
            ),
            artifact_set=(
                ("cli-daemon-macos-aarch64", "planned"),
                ("schemas", "planned"),
            ),
            test_inventory=(
                "crates/cigar-compiler/tests/compiler.rs",
                "crates/cigar-compiler/tests/materialization_delta_cache.rs",
            ),
            operations_docs=(
                "docs/reference/deterministic-compiler.md",
                "docs/operations/degraded-compiler.md",
            ),
            rollback_or_disable=(
                "Disable the affected materializer or compiler profile, invalidate derived "
                "caches, reject external-provider targets, and permit only an explicitly pinned "
                "provider-neutral exact reference profile."
            ),
        ),
        _ownership_entry(
            "retrieval",
            code_owner="context-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Retrieval can rank only caller-authorized atom projections inside the selected "
                "tenant and context space."
            ),
            persistence_boundary=(
                "Catalog records remain durable truth; lexical, temporal, graph, and active "
                "index generations are disposable derivatives."
            ),
            artifact_set=binary,
            test_inventory=("tests/properties/tests/semantic_properties.rs",),
            operations_docs=(
                "docs/reference/retrieval-indexes.md",
                "docs/operations/index-rebuild.md",
            ),
            rollback_or_disable=(
                "Deactivate the suspect generation and use the bounded exact or lexical fallback "
                "until a verified index rebuild completes."
            ),
        ),
        _ownership_entry(
            "handoff",
            code_owner="state-workflow-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "A handoff may only attenuate the sender's capabilities and requires signed, "
                "target-bound acceptance before merge."
            ),
            persistence_boundary=(
                "Signed handoff envelopes, acknowledgements, revocations, and merge receipts are "
                "durable; previews are ephemeral."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-space/tests/handoff.rs",),
            operations_docs=(
                "docs/reference/handoffs.md",
                "docs/operations/revocation-propagation.md",
            ),
            rollback_or_disable=(
                "Revoke the handoff before acceptance or block merge and restore the target space "
                "from its pre-merge checkpoint."
            ),
        ),
        _ownership_entry(
            "space",
            code_owner="state-workflow-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Space mutations require tenant-scoped leases and policy capabilities; forks "
                "cannot raise inherited authority."
            ),
            persistence_boundary=(
                "Space events, checkpoints, conflicts, and lease epochs are durable; working "
                "projections are rebuildable."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-space/tests/space.rs",),
            operations_docs=(
                "docs/reference/context-spaces.md",
                "docs/runbooks/local-storage-recovery.md",
            ),
            rollback_or_disable=(
                "Stop new leases and publication, then activate the last verified checkpoint or "
                "create a compensating fork."
            ),
        ),
        _ownership_entry(
            "replay",
            code_owner="state-workflow-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Recorded replay is structurally offline; any live provider comparison requires "
                "a separately enabled provider capability."
            ),
            persistence_boundary=(
                "Replay evidence, invocation records, completeness records, and provider receipts "
                "are durable; reconstructed execution state is ephemeral."
            ),
            artifact_set=binary,
            test_inventory=(
                "crates/cigar-replay/tests/wp13_replay_modes.rs",
                "crates/cigar-replay/tests/wp13_no_egress.rs",
            ),
            operations_docs=("docs/reference/decision-replay.md",),
            rollback_or_disable=(
                "Disable live comparison and replay execution, retaining read-only evidence "
                "inspection and recorded-provider verification."
            ),
        ),
        _ownership_entry(
            "policy",
            code_owner="policy-security-maintainers",
            support_owner="security-operations",
            authority_boundary=(
                "Only trusted policy profiles and capability grants can authorize observations, "
                "mutations, disclosures, or effects."
            ),
            persistence_boundary=(
                "Policy versions, grants, revocations, and audit decisions are durable; evaluation "
                "caches are disposable and version-bound."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-policy/tests/policy.rs",),
            operations_docs=(
                "docs/reference/policy-capabilities.md",
                "docs/operations/security-hardening.md",
            ),
            rollback_or_disable=(
                "Activate the last reviewed policy version, revoke newly introduced grants, and "
                "invalidate all policy-decision caches."
            ),
        ),
        _ownership_entry(
            "daemon",
            code_owner="runtime-platform-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "The daemon composes services only from explicit configuration, authenticated "
                "principals, and least-privilege repository capabilities."
            ),
            persistence_boundary=(
                "Repositories and migration state are durable; workers, listeners, readiness, and "
                "in-memory coordination are process-local."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-daemon/tests/deployment_assets.rs",),
            operations_docs=("docs/operations/daemon-lifecycle.md",),
            rollback_or_disable=(
                "Stop listeners and workers through graceful shutdown, restore the prior config "
                "and binary, and restart only after readiness checks pass."
            ),
        ),
        _ownership_entry(
            "effects",
            code_owner="effects-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Effect dispatch requires policy, capability, approval, expiry, precondition, "
                "credential, and fencing checks bound to one intent."
            ),
            persistence_boundary=(
                "Intents, approvals, attempts, receipts, UNKNOWN state, reconciliation, and "
                "compensation records are durable journal entries."
            ),
            artifact_set=binary,
            test_inventory=(
                "crates/cigar-effects/tests/wp12_effects.rs",
                "crates/cigar-effects/tests/wp12_faults.rs",
            ),
            operations_docs=(
                "docs/reference/effect-journal.md",
                "docs/operations/unknown-effect.md",
            ),
            rollback_or_disable=(
                "Disable the connector and new dispatch, reconcile UNKNOWN attempts, and use only "
                "reviewed compensating intents for reversible completed effects."
            ),
        ),
        _ownership_entry(
            "extensions",
            code_owner="extension-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Extensions receive only manifest-granted broker capabilities and bounded data; "
                "host ambient authority is never inherited."
            ),
            persistence_boundary=(
                "Signed manifests, approvals, and invocation observations are durable; sandbox "
                "processes and invocation scratch state are ephemeral."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-extension-host/src/tests.rs",),
            operations_docs=(
                "docs/reference/configuration-errors-metrics-extensions.md",
                "docs/operations/adapter-disable.md",
            ),
            rollback_or_disable=(
                "Revoke the extension manifest, disable its host profile, terminate running "
                "sandboxes, and retain observations for investigation."
            ),
        ),
        _ownership_entry(
            "installers",
            code_owner="release-engineering",
            support_owner="release-engineering",
            authority_boundary=(
                "An installer may place only manifest-allowlisted, signed, notarized package "
                "members and may not silently change system or user policy."
            ),
            persistence_boundary=(
                "Installed files and package receipts are durable; staging directories must be "
                "private, verified, and atomically removed."
            ),
            artifact_set=(
                ("macos-homebrew-formula-arm64", "planned"),
                ("macos-installer-arm64", "planned"),
            ),
            test_inventory=("tests/installation/matrix-v1.json",),
            operations_docs=(
                "docs/guides/install.md",
                "docs/release/verification.md",
            ),
            rollback_or_disable=(
                "Do not offer either development artifact until its external signing, notarization, "
                "and installed-byte qualification evidence exists; uninstall only receipt-owned "
                "files and restore the previously verified bottle if rollback is requested."
            ),
        ),
        _ownership_entry(
            "macos",
            code_owner="release-engineering",
            support_owner="release-engineering",
            authority_boundary=(
                "macOS delivery is limited to Developer-ID-signed, notarized, stapled artifacts "
                "whose exact bytes passed installed qualification."
            ),
            persistence_boundary=(
                "Installed binaries, configuration, and launch receipts are durable; build and "
                "notarization staging are external release evidence."
            ),
            artifact_set=binary,
            test_inventory=("tests/installation/matrix-v1.json",),
            operations_docs=(
                "docs/guides/install.md",
                "docs/release/reproducibility-signing.md",
            ),
            rollback_or_disable=(
                "Withdraw the affected macOS artifact, disable its download claim, and reinstall "
                "the last notarized and verified candidate."
            ),
        ),
        _ownership_entry(
            "mcp",
            code_owner="adapter-maintainers",
            support_owner="adapter-support",
            authority_boundary=(
                "The MCP process exposes only its fixed bounded tool and resource catalog and "
                "delegates all domain authority to an authenticated CIGAR backend."
            ),
            persistence_boundary=(
                "MCP framing and request state are ephemeral; durable state remains exclusively in "
                "the backend repositories and audit journal."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-mcp/tests/process.rs",),
            operations_docs=(
                "docs/reference/public-api.md",
                "docs/operations/adapter-disable.md",
            ),
            rollback_or_disable=(
                "Disable the configured MCP server and terminate the stdio process on incident; "
                "withdraw the enclosing runtime archive if its MCP bytes are affected."
            ),
        ),
        _ownership_entry(
            "oci",
            code_owner="release-engineering",
            support_owner="release-engineering",
            authority_boundary=(
                "The image must run non-root with a read-only allowlisted filesystem and explicit "
                "network, secret, and volume capabilities."
            ),
            persistence_boundary=(
                "OCI layers are immutable artifacts; application durability belongs only to "
                "explicit external database and object-storage volumes."
            ),
            artifact_set=(("shared-oci", "planned"),),
            test_inventory=("crates/cigar-daemon/tests/deployment_assets.rs",),
            operations_docs=(
                "docs/guides/deployment.md",
                "docs/runbooks/shared-deployment.md",
            ),
            rollback_or_disable=(
                "Do not publish from the macOS profile; a future OCI profile must roll back by "
                "digest to the previously qualified immutable image index."
            ),
            profile_scope=_deferred_scope(
                "linux-oci-multiarch",
                "OCI is a Linux amd64/arm64 distribution and requires a separate qualified profile.",
            ),
        ),
        _ownership_entry(
            "otlp",
            code_owner="observability-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Export is allowlisted to content-safe metric and event fields and an explicitly "
                "configured authenticated TLS collector."
            ),
            persistence_boundary=(
                "Application truth never resides in telemetry; bounded queues and retry state are "
                "ephemeral and may be dropped under policy."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-observe/src/lib.rs",),
            operations_docs=(
                "docs/reference/configuration-errors-metrics-extensions.md",
                "docs/operations/capacity-and-queue-age.md",
            ),
            rollback_or_disable=(
                "Disable the OTLP endpoint and drain or discard bounded telemetry queues without "
                "affecting authoritative service state."
            ),
        ),
        _ownership_entry(
            "plugin",
            code_owner="adapter-maintainers",
            support_owner="adapter-support",
            authority_boundary=(
                "The Claude Code plugin is limited to documented hooks, skills, agents, and the "
                "configured MCP command; backend policy remains authoritative."
            ),
            persistence_boundary=(
                "Plugin configuration and verified package files are durable; hook request state "
                "and prompt materialization are bounded and ephemeral."
            ),
            artifact_set=(
                ("claude-code-plugin", "planned"),
                ("cli-daemon-macos-aarch64", "planned"),
            ),
            test_inventory=(
                "crates/cigar-cli/tests/claude_plugin.rs",
                "adapters/claude-code/tests/validate_package.py",
            ),
            operations_docs=(
                "docs/guides/claude-code.md",
                "docs/operations/adapter-disable.md",
            ),
            rollback_or_disable=(
                "Disable the plugin and MCP registration, remove only manifest-owned plugin files, "
                "and restore the last compatibility-qualified plugin package."
            ),
        ),
        _ownership_entry(
            "remote",
            code_owner="runtime-platform-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Remote calls require explicit HTTPS identity, authentication, tenant scope, "
                "deadlines, bounded bodies, and operation-specific authorization."
            ),
            persistence_boundary=(
                "Remote clients persist no server authority; durable idempotency and operation "
                "state remain server-owned."
            ),
            artifact_set=binary,
            test_inventory=("sdk/rust/tests/remote_http.rs",),
            operations_docs=(
                "docs/reference/public-api.md",
                "docs/operations/transport-identity.md",
            ),
            rollback_or_disable=(
                "Disable the remote endpoint or client profile, revoke its credentials, and route "
                "only to the previous compatibility-qualified service."
            ),
        ),
        _ownership_entry(
            "sdk",
            code_owner="sdk-maintainers",
            support_owner="sdk-support",
            authority_boundary=(
                "SDKs expose only the frozen public operation registry and require explicit "
                "embedded, sidecar, or authenticated remote transports."
            ),
            persistence_boundary=(
                "SDK clients own no authoritative state; cursor, retry, and stream state are "
                "bounded projections of backend-owned records."
            ),
            artifact_set=(
                ("rust-sdk-crate", "planned"),
                ("typescript-sdk", "planned"),
                ("python-sdk-sdist", "planned"),
                ("python-sdk-wheel", "planned"),
                ("go-sdk", "planned"),
            ),
            test_inventory=(
                "sdk/rust/tests/client_contract.rs",
                "sdk/typescript/src/tests/client.test.ts",
                "sdk/python/tests/test_client.py",
                "sdk/go/client_test.go",
            ),
            operations_docs=(
                "docs/guides/sdks.md",
                "docs/operations/sdk-compatibility.md",
            ),
            rollback_or_disable=(
                "Yank or deprecate the affected package version without replacing bytes, pin the "
                "last compatible SDK, and disable incompatible operations client-side."
            ),
        ),
        _ownership_entry(
            "shared",
            code_owner="storage-maintainers",
            support_owner="storage-operations",
            authority_boundary=(
                "Shared mode requires authenticated tenant identity, PostgreSQL row-level controls, "
                "encrypted object storage, and service-owned migrations."
            ),
            persistence_boundary=(
                "PostgreSQL and encrypted object storage are durable truth; outbox consumers, "
                "indexes, and service caches are rebuildable."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-store/tests/postgres_shared.rs",),
            operations_docs=(
                "docs/runbooks/shared-deployment.md",
                "docs/runbooks/shared-rolling-migration.md",
            ),
            rollback_or_disable=(
                "Stop shared writes, preserve the outbox, roll services back within the migration "
                "compatibility window, or restore a verified backup."
            ),
        ),
        _ownership_entry(
            "vector",
            code_owner="context-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "A vector backend may receive only processor-approved representations and exact "
                "model, dimension, preprocessing, distance, and generation fingerprints."
            ),
            persistence_boundary=(
                "Vector generations are disposable derived indexes; catalog atoms and approved "
                "representation provenance remain durable truth."
            ),
            artifact_set=binary,
            test_inventory=(
                "crates/cigar-retrieval/src/vector.rs",
                "crates/cigar-retrieval/src/local_vector.rs",
                "crates/cigar-retrieval/src/durable_vector.rs",
                "crates/cigar-daemon/src/production_vector.rs",
            ),
            operations_docs=(
                "docs/reference/retrieval-indexes.md",
                "docs/operations/index-rebuild.md",
            ),
            rollback_or_disable=(
                "Keep the local adapter disabled by default; on incident deactivate its suspect "
                "generation and use only the explicitly permitted exact or lexical fallback."
            ),
        ),
        _ownership_entry(
            "windows",
            code_owner="runtime-platform-maintainers",
            support_owner="release-engineering",
            authority_boundary=(
                "Windows execution requires native ACL, named-pipe identity, signing, installation, "
                "and non-admin qualification in its own profile."
            ),
            persistence_boundary=(
                "Windows files, service configuration, and ACLs are durable platform state; no such "
                "state is produced by the macOS profile."
            ),
            artifact_set=(("cli-daemon-windows-x86_64", "planned"),),
            test_inventory=("tests/installation/matrix-v1.json",),
            operations_docs=(
                "docs/guides/install.md",
                "docs/release/verification.md",
            ),
            rollback_or_disable=(
                "Do not claim Windows support from this profile; a future Windows profile must "
                "disable its service and restore the prior signed package."
            ),
            profile_scope=_deferred_scope(
                "windows-x86_64",
                "Windows requires native execution and a separate qualification profile.",
            ),
        ),
        _ownership_entry(
            "arm",
            code_owner="release-engineering",
            support_owner="release-engineering",
            authority_boundary=(
                "This profile permits only native Apple-silicon aarch64 builds; cross-architecture "
                "or emulated results cannot qualify installed bytes."
            ),
            persistence_boundary=(
                "Architecture identity is bound into immutable artifacts and qualification receipts; "
                "build caches are non-authoritative."
            ),
            artifact_set=binary,
            test_inventory=("tests/installation/matrix-v1.json",),
            operations_docs=(
                "docs/guides/install.md",
                "docs/release/verification.md",
            ),
            rollback_or_disable=(
                "Withdraw the affected arm64 digest and reinstall the previously qualified native "
                "Apple-silicon artifact without rebuilding it."
            ),
        ),
        _ownership_entry(
            "backup",
            code_owner="storage-maintainers",
            support_owner="storage-operations",
            authority_boundary=(
                "Backup creation and restore require dedicated operator authority, signed inventory, "
                "tenant scope, and empty or explicitly prepared destinations."
            ),
            persistence_boundary=(
                "Signed manifests, database snapshots, and referenced encrypted objects are durable; "
                "temporary copy directories are private and disposable."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-store/src/backup.rs",),
            operations_docs=(
                "docs/runbooks/shared-backup-restore.md",
                "docs/runbooks/local-storage-recovery.md",
            ),
            rollback_or_disable=(
                "Disable new backup or restore operations, retain verified archives, and reactivate "
                "only the last pre-operation store after integrity verification."
            ),
        ),
        _ownership_entry(
            "garbage-collection",
            code_owner="storage-maintainers",
            support_owner="storage-operations",
            authority_boundary=(
                "Physical deletion requires store-owned reachability, retention, legal-hold, backup, "
                "tenant, and exclusive-writer checks."
            ),
            persistence_boundary=(
                "GC plans and deletion receipts are durable; candidate scans are bounded and must be "
                "recomputed against current roots before execution."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-store/tests/store_owned_gc.rs",),
            operations_docs=(
                "docs/reference/store-contracts.md",
                "docs/runbooks/local-storage-recovery.md",
            ),
            rollback_or_disable=(
                "Disable GC execution and retain dry-run planning; restore mistakenly deleted data "
                "only from a verified backup and reconcile durable receipts."
            ),
        ),
        _ownership_entry(
            "diagnostics",
            code_owner="runtime-platform-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Diagnostics are content-free, bounded, explicitly requested views and may not "
                "include secrets, paths, source text, prompts, or denied-existence data."
            ),
            persistence_boundary=(
                "Support bundles are operator-created immutable outputs; readiness and doctor "
                "snapshots are ephemeral observations."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-cli/src/lib.rs",),
            operations_docs=(
                "docs/reference/configuration-errors-metrics-extensions.md",
                "docs/operations/security-hardening.md",
            ),
            rollback_or_disable=(
                "Disable bundle generation and deep probes, delete unshared local outputs, and use "
                "only minimal readiness codes until redaction is revalidated."
            ),
        ),
        _ownership_entry(
            "serving",
            code_owner="runtime-platform-maintainers",
            support_owner="runtime-operations",
            authority_boundary=(
                "Listeners require explicit bind addresses, TLS or local peer identity, authn, "
                "operation authorization, quotas, deadlines, and bounded streams."
            ),
            persistence_boundary=(
                "Listeners and connections are ephemeral; durable mutations, idempotency, audit, "
                "and cursor state remain repository-owned."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-api/tests/transport_conformance.rs",),
            operations_docs=(
                "docs/reference/public-api.md",
                "docs/operations/transport-identity.md",
            ),
            rollback_or_disable=(
                "Stop affected listeners, revoke exposed credentials, restore the prior transport "
                "configuration, and restart only after identity checks pass."
            ),
        ),
        _ownership_entry(
            "completion-man",
            code_owner="release-engineering",
            support_owner="release-engineering",
            authority_boundary=(
                "Completion and manual generation are pure outputs of the closed command catalog "
                "and may not execute shell input or discover ambient commands."
            ),
            persistence_boundary=(
                "Generated completion and manual files are immutable package members; generation "
                "scratch state is disposable."
            ),
            artifact_set=binary,
            test_inventory=("crates/cigar-cli/src/command.rs",),
            operations_docs=(
                "docs/reference/cli.md",
                "docs/guides/install.md",
            ),
            rollback_or_disable=(
                "Remove the generated files from the package manifest or restore the previous "
                "catalog-derived assets without changing the executable."
            ),
        ),
    ]
    return {
        "schema_version": "cigar.post-beta.capability-ownership.v1",
        "profile_id": PROFILE_ID,
        "capability_profile": {
            "path": PROFILE_PATH,
            "sha256": CAPABILITY_PROFILE_SHA256,
        },
        "artifact_matrix": {
            "path": ARTIFACT_MATRIX_PATH,
            "schema_version": "cigar.artifact-matrix.v1",
            "artifact_id_inventory_sha256": ARTIFACT_ID_INVENTORY_SHA256,
        },
        "release_claimed": False,
        "support_claimed": False,
        "fail_closed": True,
        "capabilities": capabilities,
    }


def _repository_path(root: Path, relative: str) -> Path:
    """Resolve a fixed path while rejecting link-based parent substitution."""
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseError(f"unsafe post-beta repository path: {relative!r}")
    current = root
    for part in path.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ReleaseError(
                f"cannot inspect post-beta path parent {current}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseError(
                f"post-beta path parent must be a real directory: {current}"
            )
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


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReleaseError(f"{label} has missing or unexpected fields")
    return value


def _validate_document(document: Any) -> None:
    top = _require_exact_keys(
        document,
        {
            "schema_version",
            "profile_id",
            "source_capability_policy",
            "platform_scope",
            "state_order",
            "fail_closed",
            "capabilities",
        },
        "post-beta profile",
    )
    if top.get("schema_version") != "cigar.post-beta.capability-profile.v1":
        raise ReleaseError("post-beta profile schema identity is invalid")
    if top.get("profile_id") != PROFILE_ID:
        raise ReleaseError("post-beta profile identity is invalid")
    policy = _require_exact_keys(
        top.get("source_capability_policy"), {"path", "sha256"}, "source policy"
    )
    if policy != {"path": BETA_POLICY_PATH, "sha256": BETA_POLICY_SHA256}:
        raise ReleaseError("post-beta profile is bound to a different beta policy")
    platform = _require_exact_keys(
        top.get("platform_scope"),
        {"host_os", "host_arch", "target_triple"},
        "platform scope",
    )
    if platform != {
        "host_os": "macos",
        "host_arch": "arm64",
        "target_triple": "aarch64-apple-darwin",
    }:
        raise ReleaseError("post-beta profile platform scope is not macOS arm64")
    if top.get("state_order") != list(STATE_ORDER):
        raise ReleaseError("post-beta capability state order is invalid")
    if top.get("fail_closed") is not True:
        raise ReleaseError("post-beta profile must fail closed")

    capabilities = top.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) != len(CAPABILITY_IDS):
        raise ReleaseError("post-beta profile must contain exactly 29 capabilities")
    capability_keys = {"id", *STATE_ORDER}
    observed_ids: list[str] = []
    for index, (entry, expected_identifier) in enumerate(
        zip(capabilities, CAPABILITY_IDS, strict=True)
    ):
        capability = _require_exact_keys(
            entry, capability_keys, f"post-beta capability at index {index}"
        )
        identifier = capability.get("id")
        if identifier != expected_identifier:
            raise ReleaseError(
                "post-beta capability IDs are missing, extra, duplicate, or reordered"
            )
        observed_ids.append(identifier)
        values: list[bool] = []
        for state in STATE_ORDER:
            value = capability.get(state)
            if type(value) is not bool:
                raise ReleaseError(
                    f"post-beta capability {identifier} state {state} must be Boolean"
                )
            values.append(value)
        seen_false = False
        for state, value in zip(STATE_ORDER, values, strict=True):
            if not value:
                seen_false = True
            elif seen_false:
                raise ReleaseError(
                    f"post-beta capability {identifier} has a non-monotonic {state} state"
                )
    if observed_ids != list(CAPABILITY_IDS) or len(set(observed_ids)) != len(
        observed_ids
    ):
        raise ReleaseError("post-beta capability inventory is not exact")


def _require_nonempty_string(value: Any, label: str, *, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise ReleaseError(f"{label} must be a bounded nonempty string")
    return value


def _validate_inventory_paths(
    root: Path, value: Any, label: str, allowed_prefixes: tuple[str, ...]
) -> None:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 16
        or not all(isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
    ):
        raise ReleaseError(f"{label} must be a nonempty unique path inventory")
    for relative in value:
        if not relative.startswith(allowed_prefixes):
            raise ReleaseError(f"{label} contains a path outside its allowed roots")
        path = _repository_path(root, relative)
        _regular_file(path, f"{label} path {relative}")


def _artifact_matrix_ids(root: Path) -> set[str]:
    path = _repository_path(root, ARTIFACT_MATRIX_PATH)
    _regular_file(path, ARTIFACT_MATRIX_PATH)
    matrix = load_json(path)
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or not isinstance(matrix.get("artifacts"), list)
    ):
        raise ReleaseError("post-beta artifact matrix is invalid")
    identifiers = [
        entry.get("id") for entry in matrix["artifacts"] if isinstance(entry, dict)
    ]
    if (
        len(identifiers) != len(matrix["artifacts"])
        or not all(isinstance(item, str) and item for item in identifiers)
        or len(set(identifiers)) != len(identifiers)
    ):
        raise ReleaseError("post-beta artifact matrix IDs are invalid")
    if sha256_bytes(canonical_json_bytes(identifiers)) != ARTIFACT_ID_INVENTORY_SHA256:
        raise ReleaseError("post-beta artifact matrix ID inventory digest mismatch")
    return set(identifiers)


def _validate_ownership_document(root: Path, document: Any) -> None:
    top = _require_exact_keys(
        document,
        {
            "schema_version",
            "profile_id",
            "capability_profile",
            "artifact_matrix",
            "release_claimed",
            "support_claimed",
            "fail_closed",
            "capabilities",
        },
        "post-beta ownership registry",
    )
    if top.get("schema_version") != "cigar.post-beta.capability-ownership.v1":
        raise ReleaseError("post-beta ownership schema identity is invalid")
    if top.get("profile_id") != PROFILE_ID:
        raise ReleaseError("post-beta ownership profile identity is invalid")
    profile_binding = _require_exact_keys(
        top.get("capability_profile"), {"path", "sha256"}, "capability profile binding"
    )
    if profile_binding != {
        "path": PROFILE_PATH,
        "sha256": CAPABILITY_PROFILE_SHA256,
    }:
        raise ReleaseError("post-beta ownership capability-profile binding is invalid")
    matrix_binding = _require_exact_keys(
        top.get("artifact_matrix"),
        {"path", "schema_version", "artifact_id_inventory_sha256"},
        "artifact matrix binding",
    )
    if matrix_binding != {
        "path": ARTIFACT_MATRIX_PATH,
        "schema_version": "cigar.artifact-matrix.v1",
        "artifact_id_inventory_sha256": ARTIFACT_ID_INVENTORY_SHA256,
    }:
        raise ReleaseError("post-beta ownership artifact-matrix binding is invalid")
    if (
        top.get("release_claimed") is not False
        or top.get("support_claimed") is not False
        or top.get("fail_closed") is not True
    ):
        raise ReleaseError(
            "post-beta ownership registry must remain nonclaiming and fail closed"
        )

    matrix_ids = _artifact_matrix_ids(root)
    capabilities = top.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) != len(CAPABILITY_IDS):
        raise ReleaseError(
            "post-beta ownership registry must contain exactly 29 capabilities"
        )
    expected_keys = {
        "id",
        "code_owner",
        "support_owner",
        "authority_boundary",
        "persistence_boundary",
        "artifact_set",
        "profile_scope",
        "test_inventory",
        "operations_docs",
        "rollback_or_disable",
    }
    deferred = {
        "oci": "linux-oci-multiarch",
        "windows": "windows-x86_64",
    }
    for index, (value, expected_identifier) in enumerate(
        zip(capabilities, CAPABILITY_IDS, strict=True)
    ):
        entry = _require_exact_keys(
            value, expected_keys, f"post-beta ownership capability at index {index}"
        )
        identifier = entry.get("id")
        if identifier != expected_identifier:
            raise ReleaseError(
                "post-beta ownership capability IDs are missing, extra, or reordered"
            )
        for field in (
            "code_owner",
            "support_owner",
            "authority_boundary",
            "persistence_boundary",
            "rollback_or_disable",
        ):
            _require_nonempty_string(entry.get(field), f"{identifier} {field}")

        scope = entry.get("profile_scope")
        if identifier in deferred:
            scoped = _require_exact_keys(
                scope, {"disposition", "platform", "reason"}, f"{identifier} scope"
            )
            if (
                scoped.get("disposition") != "deferred-separate-profile"
                or scoped.get("platform") != deferred[identifier]
            ):
                raise ReleaseError(
                    f"{identifier} must use its separate deferred profile"
                )
            _require_nonempty_string(scoped.get("reason"), f"{identifier} scope reason")
        else:
            scoped = _require_exact_keys(
                scope,
                {"disposition", "profile_id", "target_triple"},
                f"{identifier} scope",
            )
            if scoped != _selected_scope():
                raise ReleaseError(f"{identifier} broadens the macOS arm64 profile")

        artifacts = entry.get("artifact_set")
        if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 16:
            raise ReleaseError(f"{identifier} artifact set must be nonempty")
        artifact_ids: list[str] = []
        for artifact in artifacts:
            item = _require_exact_keys(
                artifact, {"id", "status"}, f"{identifier} artifact"
            )
            artifact_id = _require_nonempty_string(
                item.get("id"), f"{identifier} artifact ID", maximum=128
            )
            status = item.get("status")
            if status not in {"existing", "planned", "missing"}:
                raise ReleaseError(f"{identifier} artifact has an invalid status")
            if status in {"existing", "planned"} and artifact_id not in matrix_ids:
                raise ReleaseError(
                    f"{identifier} artifact {artifact_id} is absent from the matrix"
                )
            if status == "missing" and artifact_id in matrix_ids:
                raise ReleaseError(
                    f"{identifier} missing artifact {artifact_id} already exists in the matrix"
                )
            artifact_ids.append(artifact_id)
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ReleaseError(f"{identifier} artifact set contains duplicates")

        _validate_inventory_paths(
            root,
            entry.get("test_inventory"),
            f"{identifier} test inventory",
            ("adapters/", "conformance/", "crates/", "sdk/", "tests/", "tools/"),
        )
        _validate_inventory_paths(
            root,
            entry.get("operations_docs"),
            f"{identifier} operations documentation",
            ("docs/",),
        )

    by_id = {entry["id"]: entry for entry in capabilities}
    installer_artifacts = by_id["installers"]["artifact_set"]
    mcp_artifacts = by_id["mcp"]["artifact_set"]
    if installer_artifacts != [
        {"id": "macos-homebrew-formula-arm64", "status": "planned"},
        {"id": "macos-installer-arm64", "status": "planned"},
    ]:
        raise ReleaseError("planned macOS Homebrew artifacts are not explicit")
    if mcp_artifacts != [{"id": "cli-daemon-macos-aarch64", "status": "planned"}]:
        raise ReleaseError("packaged cigar-mcp runtime ownership is not explicit")


def validate_transition(previous: Any, current: Any) -> None:
    """Reject state regression or an in-place change to profile identity and scope."""
    _validate_document(previous)
    _validate_document(current)
    immutable_fields = {
        "schema_version",
        "profile_id",
        "source_capability_policy",
        "platform_scope",
        "state_order",
        "fail_closed",
    }
    for field in immutable_fields:
        if previous[field] != current[field]:
            raise ReleaseError(
                f"post-beta transition changed immutable profile field {field}"
            )
    for old_entry, new_entry in zip(
        previous["capabilities"], current["capabilities"], strict=True
    ):
        if old_entry["id"] != new_entry["id"]:
            raise ReleaseError("post-beta transition changed capability identity")
        for state in STATE_ORDER:
            if old_entry[state] and not new_entry[state]:
                raise ReleaseError(
                    f"post-beta transition regressed {old_entry['id']} state {state}"
                )


def _validate_schema(root: Path) -> None:
    path = _repository_path(root, SCHEMA_PATH)
    _regular_file(path, SCHEMA_PATH)
    schema = load_json(path)
    if (
        not isinstance(schema, dict)
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != "https://cigar.invalid/schemas/post-beta-capability-profile.v1.schema.json"
    ):
        raise ReleaseError("post-beta capability schema identity is invalid")
    if sha256_file(path) != SCHEMA_SHA256:
        raise ReleaseError("post-beta capability schema digest mismatch")


def _validate_ownership_schema(root: Path) -> None:
    path = _repository_path(root, OWNERSHIP_SCHEMA_PATH)
    _regular_file(path, OWNERSHIP_SCHEMA_PATH)
    schema = load_json(path)
    if (
        not isinstance(schema, dict)
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != "https://cigar.invalid/schemas/post-beta-capability-ownership.v1.schema.json"
    ):
        raise ReleaseError("post-beta ownership schema identity is invalid")
    if sha256_file(path) != OWNERSHIP_SCHEMA_SHA256:
        raise ReleaseError("post-beta ownership schema digest mismatch")


def _validate_beta_binding(root: Path) -> None:
    policy_path = _repository_path(root, BETA_POLICY_PATH)
    _regular_file(policy_path, BETA_POLICY_PATH)
    if sha256_file(policy_path) != BETA_POLICY_SHA256:
        raise ReleaseError("post-beta source beta-policy digest mismatch")
    policy = load_json(policy_path)
    excluded = policy.get("excluded") if isinstance(policy, dict) else None
    identifiers = (
        [entry.get("id") for entry in excluded]
        if isinstance(excluded, list)
        and all(isinstance(entry, dict) for entry in excluded)
        else None
    )
    if identifiers != list(CAPABILITY_IDS):
        raise ReleaseError("post-beta source beta-policy capability inventory drifted")


def generate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError(f"repository root is not a directory: {root}")
    validate_beta_profile(resolved)
    _validate_schema(resolved)
    _validate_ownership_schema(resolved)
    _validate_beta_binding(resolved)
    destination = _repository_path(resolved, PROFILE_PATH)
    if destination.exists():
        _regular_file(destination, PROFILE_PATH)
    write_json(destination, expected_profile())
    ownership_destination = _repository_path(resolved, OWNERSHIP_PATH)
    if ownership_destination.exists():
        _regular_file(ownership_destination, OWNERSHIP_PATH)
    write_json(ownership_destination, expected_ownership_registry())


def validate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError(f"repository root is not a directory: {root}")
    validate_beta_profile(resolved)
    _validate_schema(resolved)
    _validate_ownership_schema(resolved)
    _validate_beta_binding(resolved)
    observed = _load_canonical(_repository_path(resolved, PROFILE_PATH), PROFILE_PATH)
    _validate_document(observed)
    if observed != expected_profile():
        raise ReleaseError(
            "post-beta capability profile differs from its reviewed state"
        )
    if (
        sha256_file(_repository_path(resolved, PROFILE_PATH))
        != CAPABILITY_PROFILE_SHA256
    ):
        raise ReleaseError("post-beta capability profile digest mismatch")
    ownership = _load_canonical(
        _repository_path(resolved, OWNERSHIP_PATH), OWNERSHIP_PATH
    )
    _validate_ownership_document(resolved, ownership)
    if ownership != expected_ownership_registry():
        raise ReleaseError(
            "post-beta ownership registry differs from its reviewed state"
        )
    if (
        sha256_file(_repository_path(resolved, OWNERSHIP_PATH))
        != OWNERSHIP_REGISTRY_SHA256
    ):
        raise ReleaseError("post-beta ownership registry digest mismatch")


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
                "capability-ledger source generation/checking emits no release evidence"
            ),
        )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    reject_evidence_directory(
        arguments.evidence_dir,
        "post-beta capability-profile operation",
    )
    if arguments.command == "generate":
        generate(arguments.root)
        print(f"generated post-beta capability profile {PROFILE_ID}")
    else:
        validate(arguments.root)
        print(f"validated post-beta capability profile {PROFILE_ID}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"post-beta profile operation failed: {error}") from error
