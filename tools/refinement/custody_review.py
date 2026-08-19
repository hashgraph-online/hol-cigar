#!/usr/bin/env python3
"""Prepare a content-free packet for independent holdout and metric review."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import canonical_bytes, identity, load_file, secure_read
from tools.refinement.experiment import load_families
from tools.refinement.schema import SchemaRegistry
from tools.refinement.workflow_audit import audit
from tools.refinement.workspace import repository_identity

ASSETS = (
    ".github/workflows/refinement-promotion.yml",
    ".github/workflows/refinement-shadow.yml",
    "refinement/corpus/sealed-manifest-v1.json",
    "refinement/corpus/shadow-manifest-v1.json",
    "refinement/operations/workflow-policy-v1.json",
    "refinement/policy/promotion-v1.json",
    "schemas/refinement/comparison-v1.schema.json",
    "schemas/refinement/decision-v1.schema.json",
    "schemas/refinement/evaluation-v2.schema.json",
    "schemas/refinement/observation-v2.schema.json",
    "tools/refinement/evaluator.py",
    "tools/refinement/promotion.py",
    "tools/refinement/statistics.py",
)
REVIEW_ASSERTIONS = (
    "The reviewer is independent of proposal generation and did not author the candidate patch.",
    "Shadow and sealed task, oracle, fixture, prompt, annotation, and canary bytes remain outside every proposal-visible path and credential domain.",
    "Manifest commitments resolve to the exact private packs under reviewer custody without disclosing private content into this packet.",
    "Every promotion metric is derived from raw observations, oracle/verifier results, and declared attachments rather than consumer self-attestation.",
    "The comparison and decision replay exactly under the bound evaluator, schemas, promotion policy, task assignments, and consumer pins.",
    "The reviewer inspected protected-environment reviewers, prevent-self-review, branch restrictions, runner separation, mounts, and secret handles in live platform configuration.",
    "Any custody, derivation, contamination, or key-separation exception is recorded as a blocking finding rather than waived by the optimizer.",
)


class CustodyReviewError(RuntimeError):
    """A public review packet could not prove its static prerequisites."""


def _asset(repository: Path, relative: str) -> dict[str, Any]:
    payload = secure_read(
        (repository / relative).absolute(), maximum_bytes=16 * 1024 * 1024
    )
    return {
        "path": relative,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def prepare(repository: Path, *, require_clean: bool = True) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    source = repository_identity(
        repository,
        require_clean=require_clean,
        allow_detached=True,
    )
    registry = SchemaRegistry(repository / "schemas" / "refinement")
    manifests = [
        load_file(repository / "refinement/corpus/shadow-manifest-v1.json"),
        load_file(repository / "refinement/corpus/sealed-manifest-v1.json"),
    ]
    for manifest in manifests:
        registry.validate("corpus-manifest-v1.schema.json", manifest)
    if any(
        manifest["disclosure"] != "commitments-only"
        or any(
            pack["reference"] is not None or pack["custody"] != "external-owner-only"
            for pack in manifest["packs"]
        )
        for manifest in manifests
    ):
        raise CustodyReviewError("hidden corpus manifests disclose custody content")
    partitions = [manifest["partition"] for manifest in manifests]
    if partitions != ["shadow", "sealed"]:
        raise CustodyReviewError("hidden corpus partitions are missing or reordered")
    if any(not all(manifest["integrity"].values()) for manifest in manifests):
        raise CustodyReviewError("hidden corpus static integrity is not qualified")
    families = load_families(
        repository / "refinement/profiles/intervention-families.v1.json"
    )
    if any(
        family["trial_class"] == "product"
        and (
            "refinement" not in family["forbidden_paths"]
            or "schemas/refinement" not in family["forbidden_paths"]
        )
        for family in families
    ):
        raise CustodyReviewError("proposal family can access evaluator control data")
    workflow = audit(
        repository,
        repository / "refinement/operations/workflow-policy-v1.json",
    )
    evaluator_source = secure_read(
        (repository / "tools/refinement/evaluator.py").absolute()
    )
    if not all(
        marker in evaluator_source
        for marker in (
            b"def _derive_metrics(",
            b'"verified_task_success"',
            b'"numerator"',
            b'"denominator"',
            b"verify_attestation",
        )
    ):
        raise CustodyReviewError("metric derivation source markers are incomplete")
    checks = [
        {
            "name": "commitments-only-manifests",
            "status": "passed",
            "evidence": "Shadow and sealed manifests contain commitments and null pack references only.",
        },
        {
            "name": "external-owner-custody",
            "status": "passed",
            "evidence": "Every hidden pack declares external-owner-only custody.",
        },
        {
            "name": "partition-integrity",
            "status": "passed",
            "evidence": "Both hidden manifests retain all declared integrity gates.",
        },
        {
            "name": "proposal-control-separation",
            "status": "passed",
            "evidence": "Every product intervention family forbids refinement and evaluator schemas.",
        },
        {
            "name": "raw-metric-derivation",
            "status": "passed",
            "evidence": "Bound evaluator source contains numerator/denominator derivation and verifier attestation paths.",
        },
        {
            "name": "workflow-secret-separation",
            "status": "passed",
            "evidence": f"Static workflow audit {workflow['audit_id']} passed.",
        },
    ]
    body = {
        "schema_version": "cigar.refinement-custody-review-packet.v1",
        "source": {
            "revision": source["revision"],
            "tree": source["tree"],
        },
        "source_clean": source["clean"],
        "workflow_audit_id": workflow["audit_id"],
        "assets": [_asset(repository, relative) for relative in ASSETS],
        "checks": checks,
        "required_reviewer_assertions": list(REVIEW_ASSERTIONS),
        "contains_private_content": False,
        "review_status": "awaiting-independent-review",
    }
    result = {**body, "packet_id": identity(body)}
    registry.validate("custody-review-packet-v1.schema.json", result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = prepare(arguments.repository, require_clean=True)
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0
    except (CustodyReviewError, OSError, ValueError) as error:
        print(f"custody review: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
