#!/usr/bin/env python3
"""Operate refinement quotas, evidence bundles, dashboards, and CI boundaries."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
import hashlib
import hmac
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.artifacts import (
    ArtifactError,
    create_bundle,
    verify_bundle,
)
from tools.refinement.canonical import (
    canonical_bytes,
    identity,
    load_file,
    multihash_bytes,
    secure_read,
)
from tools.refinement.dashboard import DashboardError, project
from tools.refinement.quota import QuotaError, QuotaLedger
from tools.refinement.schema import SchemaRegistry
from tools.refinement.workflow_audit import WorkflowAuditError, audit


class OperationsError(RuntimeError):
    """An operational request is incomplete, unsafe, or outside its authority."""


def _absolute(path: Path, label: str, *, must_exist: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise OperationsError(f"{label} must be an absolute real path")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise OperationsError(f"{label} cannot be resolved") from error
    if resolved != path:
        raise OperationsError(f"{label} must not contain aliases")
    return path


def _ledger(arguments: argparse.Namespace) -> QuotaLedger:
    repository = _absolute(arguments.repository, "repository", must_exist=True)
    return QuotaLedger(
        _absolute(arguments.quota_root, "quota root", must_exist=False),
        repository_root=repository,
        policy_path=_absolute(arguments.policy, "operations policy", must_exist=True),
    )


def _resource_arguments(arguments: argparse.Namespace) -> dict[str, int]:
    return {
        "input_tokens": arguments.input_tokens,
        "output_tokens": arguments.output_tokens,
        "cost_microusd": arguments.cost_microusd,
        "compute_milliseconds": arguments.compute_milliseconds,
    }


def quota_reserve(arguments: argparse.Namespace) -> dict[str, Any]:
    return _ledger(arguments).reserve(
        utc_day=arguments.utc_day,
        provider_id=arguments.provider,
        reservation_id=arguments.reservation_id,
        requested=_resource_arguments(arguments),
    )


def quota_settle(arguments: argparse.Namespace) -> dict[str, Any]:
    return _ledger(arguments).finish(
        arguments.reservation_id,
        actual=_resource_arguments(arguments),
    )


def quota_cancel(arguments: argparse.Namespace) -> dict[str, Any]:
    return _ledger(arguments).finish(
        arguments.reservation_id,
        actual=None,
        cancelled=True,
    )


def quota_usage(arguments: argparse.Namespace) -> dict[str, Any]:
    return _ledger(arguments).usage(arguments.utc_day)


def quota_replay(arguments: argparse.Namespace) -> dict[str, Any]:
    ledger = _ledger(arguments)
    events = ledger.replay()
    body = {
        "schema_version": "cigar.refinement-quota-replay.v1",
        "policy_id": ledger.policy["policy_id"],
        "event_count": len(events),
        "head": events[-1]["event_id"] if events else None,
    }
    return {**body, "replay_id": identity(body)}


def workflow_audit(arguments: argparse.Namespace) -> dict[str, Any]:
    return audit(
        _absolute(arguments.repository, "repository", must_exist=True),
        _absolute(arguments.policy, "workflow policy", must_exist=True),
    )


def _attachments(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise OperationsError("attachment must use name=/absolute/path")
        name, raw_path = value.split("=", 1)
        if name in result:
            raise OperationsError("attachment name is duplicated")
        result[name] = _absolute(Path(raw_path), "attachment", must_exist=True)
    return result


def bundle_create(arguments: argparse.Namespace) -> dict[str, Any]:
    return create_bundle(
        repository_root=_absolute(arguments.repository, "repository", must_exist=True),
        output_root=_absolute(arguments.output_root, "bundle output", must_exist=False),
        run_id=arguments.run_id,
        evidence_class=arguments.evidence_class,
        retention_days=arguments.retention_days,
        source_revision=arguments.source_revision,
        source_tree=arguments.source_tree,
        attachments=_attachments(arguments.attachment),
        policy_id=arguments.policy_id,
        authority=arguments.authority,
    )


def bundle_verify(arguments: argparse.Namespace) -> dict[str, Any]:
    return verify_bundle(
        repository_root=_absolute(arguments.repository, "repository", must_exist=True),
        bundle_root=_absolute(arguments.bundle_root, "bundle root", must_exist=True),
    )


def _create_new(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise OperationsError("output must be an absolute create-new path")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o400)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OperationsError("output write was incomplete")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
        ):
            raise OperationsError("output metadata is unsafe")
    except OSError as error:
        raise OperationsError("output cannot be published create-new") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def dashboard_project(arguments: argparse.Namespace) -> dict[str, Any]:
    result = project(
        repository_root=_absolute(arguments.repository, "repository", must_exist=True),
        ledger_root=_absolute(arguments.ledger_root, "ledger root", must_exist=True),
        facts_path=_absolute(arguments.facts, "dashboard facts", must_exist=True),
    )
    if arguments.output is not None:
        _create_new(arguments.output, canonical_bytes(result))
    return result


def receipt(arguments: argparse.Namespace) -> dict[str, Any]:
    body = {
        "schema_version": "cigar.refinement-operation-receipt.v1",
        "run_id": arguments.run_id,
        "authority": arguments.authority,
        "status": arguments.status,
        "source": {
            "revision": arguments.source_revision,
            "tree": arguments.source_tree,
        },
        "no_promotion": True,
        "publication_authority": False,
    }
    return {**body, "receipt_id": identity(body)}


def promotion_payload(arguments: argparse.Namespace) -> dict[str, Any]:
    repository = _absolute(arguments.repository, "repository", must_exist=True)
    registry = SchemaRegistry(repository / "schemas" / "refinement")
    try:
        comparison = load_file(
            _absolute(arguments.comparison, "comparison", must_exist=True)
        )
        decision = load_file(_absolute(arguments.decision, "decision", must_exist=True))
        registry.validate("comparison-v1.schema.json", comparison)
        registry.validate("decision-v1.schema.json", decision)
    except (OSError, ValueError) as error:
        raise OperationsError("promotion evidence is malformed") from error
    if (
        not isinstance(comparison, dict)
        or not isinstance(decision, dict)
        or decision["decision"] != "promote"
        or decision["comparison_id"] != comparison["comparison_id"]
    ):
        raise OperationsError("promotion evidence does not authorize preparation")
    unsigned = {
        "schema_version": "cigar.refinement-promotion-payload.v1",
        "trial_id": arguments.trial_id,
        "candidate_source": comparison["candidate_source"],
        "comparison_id": comparison["comparison_id"],
        "decision_id": decision["decision_id"],
        "target_branch": arguments.target_branch,
        "operation": "prepare-review-only",
        "merge_authority": False,
        "publication_authority": False,
    }
    key = secure_read(
        _absolute(arguments.attestation_key, "attestation key", must_exist=True),
        maximum_bytes=1024,
    )
    if len(key) < 32:
        raise OperationsError("attestation key is shorter than 32 bytes")
    payload_id = identity(unsigned)
    attested = canonical_bytes({**unsigned, "payload_id": payload_id})
    body = {
        **unsigned,
        "payload_id": payload_id,
        "attestation": {
            "algorithm": "hmac-sha256",
            "key_id": arguments.key_id,
            "key_fingerprint": multihash_bytes(key),
            "mac": hmac.new(key, attested, hashlib.sha256).hexdigest(),
        },
    }
    registry.validate("promotion-payload-v1.schema.json", body)
    return body


def promotion_verify(arguments: argparse.Namespace) -> dict[str, Any]:
    repository = _absolute(arguments.repository, "repository", must_exist=True)
    try:
        payload = load_file(
            _absolute(arguments.payload, "promotion payload", must_exist=True)
        )
        SchemaRegistry(repository / "schemas" / "refinement").validate(
            "promotion-payload-v1.schema.json", payload
        )
    except (OSError, ValueError) as error:
        raise OperationsError("promotion payload is malformed") from error
    if not isinstance(payload, dict):
        raise OperationsError("promotion payload is not an object")
    unsigned = dict(payload)
    attestation = unsigned.pop("attestation")
    payload_id = unsigned.pop("payload_id")
    if payload_id != identity(unsigned):
        raise OperationsError("promotion payload identity is invalid")
    key = secure_read(
        _absolute(arguments.attestation_key, "attestation key", must_exist=True),
        maximum_bytes=1024,
    )
    if (
        len(key) < 32
        or attestation["key_fingerprint"] != multihash_bytes(key)
        or not hmac.compare_digest(
            attestation["mac"],
            hmac.new(
                key,
                canonical_bytes({**unsigned, "payload_id": payload_id}),
                hashlib.sha256,
            ).hexdigest(),
        )
    ):
        raise OperationsError("promotion payload attestation is invalid")
    return {
        "schema_version": "cigar.refinement-promotion-payload-verification.v1",
        "status": "passed",
        "payload_id": payload_id,
        "decision_id": payload["decision_id"],
        "merge_authority": False,
        "publication_authority": False,
    }


def _repository(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", type=Path, default=ROOT)


def _quota_common(parser: argparse.ArgumentParser) -> None:
    _repository(parser)
    parser.add_argument("--quota-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)


def _quota_resources(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-tokens", type=int, required=True)
    parser.add_argument("--output-tokens", type=int, required=True)
    parser.add_argument("--cost-microusd", type=int, required=True)
    parser.add_argument("--compute-milliseconds", type=int, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    audit_parser = commands.add_parser("audit-workflows")
    _repository(audit_parser)
    audit_parser.add_argument("--policy", type=Path, required=True)
    audit_parser.set_defaults(handler=workflow_audit)

    quota_parser = commands.add_parser("quota")
    quotas = quota_parser.add_subparsers(dest="quota_command", required=True)
    reserve_parser = quotas.add_parser("reserve")
    _quota_common(reserve_parser)
    reserve_parser.add_argument("--utc-day", required=True)
    reserve_parser.add_argument("--provider", required=True)
    reserve_parser.add_argument("--reservation-id", required=True)
    _quota_resources(reserve_parser)
    reserve_parser.set_defaults(handler=quota_reserve)
    settle_parser = quotas.add_parser("settle")
    _quota_common(settle_parser)
    settle_parser.add_argument("--reservation-id", required=True)
    _quota_resources(settle_parser)
    settle_parser.set_defaults(handler=quota_settle)
    cancel_parser = quotas.add_parser("cancel")
    _quota_common(cancel_parser)
    cancel_parser.add_argument("--reservation-id", required=True)
    cancel_parser.set_defaults(handler=quota_cancel)
    usage_parser = quotas.add_parser("usage")
    _quota_common(usage_parser)
    usage_parser.add_argument("--utc-day", required=True)
    usage_parser.set_defaults(handler=quota_usage)
    replay_parser = quotas.add_parser("replay")
    _quota_common(replay_parser)
    replay_parser.set_defaults(handler=quota_replay)

    bundle_parser = commands.add_parser("bundle")
    bundle_commands = bundle_parser.add_subparsers(dest="bundle_command", required=True)
    create_parser = bundle_commands.add_parser("create")
    _repository(create_parser)
    create_parser.add_argument("--output-root", type=Path, required=True)
    create_parser.add_argument("--run-id", required=True)
    create_parser.add_argument(
        "--evidence-class",
        required=True,
        choices=("diagnostic", "development", "shadow", "promotion"),
    )
    create_parser.add_argument("--retention-days", type=int, required=True)
    create_parser.add_argument("--source-revision", required=True)
    create_parser.add_argument("--source-tree", required=True)
    create_parser.add_argument("--policy-id", required=True)
    create_parser.add_argument(
        "--authority",
        required=True,
        choices=(
            "diagnostic-only",
            "development-only",
            "shadow-nomination",
            "promotion-preparation",
        ),
    )
    create_parser.add_argument("--attachment", action="append", required=True)
    create_parser.set_defaults(handler=bundle_create)
    verify_parser = bundle_commands.add_parser("verify")
    _repository(verify_parser)
    verify_parser.add_argument("--bundle-root", type=Path, required=True)
    verify_parser.set_defaults(handler=bundle_verify)

    dashboard_parser = commands.add_parser("dashboard")
    _repository(dashboard_parser)
    dashboard_parser.add_argument("--ledger-root", type=Path, required=True)
    dashboard_parser.add_argument("--facts", type=Path, required=True)
    dashboard_parser.add_argument("--output", type=Path)
    dashboard_parser.set_defaults(handler=dashboard_project)

    receipt_parser = commands.add_parser("receipt")
    receipt_parser.add_argument("--run-id", required=True)
    receipt_parser.add_argument(
        "--authority",
        required=True,
        choices=("diagnostic", "development", "shadow", "promotion"),
    )
    receipt_parser.add_argument("--status", required=True, choices=("passed", "failed"))
    receipt_parser.add_argument("--source-revision", required=True)
    receipt_parser.add_argument("--source-tree", required=True)
    receipt_parser.set_defaults(handler=receipt)

    promotion_parser = commands.add_parser("promotion-payload")
    _repository(promotion_parser)
    promotion_parser.add_argument("--comparison", type=Path, required=True)
    promotion_parser.add_argument("--decision", type=Path, required=True)
    promotion_parser.add_argument("--trial-id", required=True)
    promotion_parser.add_argument("--target-branch", required=True)
    promotion_parser.add_argument("--attestation-key", type=Path, required=True)
    promotion_parser.add_argument("--key-id", required=True)
    promotion_parser.set_defaults(handler=promotion_payload)
    verification_parser = commands.add_parser("promotion-verify")
    _repository(verification_parser)
    verification_parser.add_argument("--payload", type=Path, required=True)
    verification_parser.add_argument("--attestation-key", type=Path, required=True)
    verification_parser.set_defaults(handler=promotion_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        result = arguments.handler(arguments)
    except (
        ArtifactError,
        DashboardError,
        OperationsError,
        QuotaError,
        WorkflowAuditError,
        OSError,
        ValueError,
    ) as error:
        print(f"refinement operations: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
