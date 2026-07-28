"""Static trust-boundary audit for refinement GitHub Actions workflows."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical import identity, load_file, secure_read
from .schema import SchemaRegistry

POLICY_SCHEMA = "workflow-policy-v1.schema.json"
ACTION = re.compile(r"uses:\s+[^@\s]+@([^\s#]+)")
SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Z][A-Z0-9_]*)\s*\}\}")
DANGEROUS = (
    "contents: write",
    "pull-requests: write",
    "packages: write",
    "id-token: write",
    "gh pr merge",
    "git push",
    "cargo publish",
    "npm publish",
    "twine upload",
    "maturin publish",
    "gh-action-pypi-publish",
)


class WorkflowAuditError(RuntimeError):
    """A workflow grants authority outside its declared refinement lane."""


def _load_policy(path: Path, schemas: Path) -> dict[str, Any]:
    try:
        value = load_file(path)
        SchemaRegistry(schemas).validate(POLICY_SCHEMA, value)
    except (OSError, ValueError) as error:
        raise WorkflowAuditError("workflow policy is malformed") from error
    if not isinstance(value, dict):
        raise WorkflowAuditError("workflow policy is not an object")
    unsigned = dict(value)
    unsigned.pop("policy_id")
    if value["policy_id"] != identity(unsigned):
        raise WorkflowAuditError("workflow policy identity is invalid")
    filenames = [row["filename"] for row in value["workflows"]]
    if filenames != sorted(set(filenames)):
        raise WorkflowAuditError("managed workflow names must be sorted and unique")
    return value


def audit(repository_root: Path, policy_path: Path) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    schemas = repository_root / "schemas" / "refinement"
    policy = _load_policy(policy_path, schemas)
    workflow_root = repository_root / ".github" / "workflows"
    all_workflows = sorted(workflow_root.glob("*.yml"))
    for path in all_workflows:
        text = secure_read(path.absolute(), maximum_bytes=2 * 1024 * 1024).decode(
            "utf-8", errors="strict"
        )
        if "\n  pull_request:" in text and SECRET.search(text):
            raise WorkflowAuditError(
                f"pull-request workflow references a secret: {path.name}"
            )
        if "\n  schedule:" in text and any(token in text for token in DANGEROUS):
            raise WorkflowAuditError(
                f"scheduled workflow has mutation/publication authority: {path.name}"
            )

    audited: list[dict[str, Any]] = []
    for contract in policy["workflows"]:
        path = workflow_root / contract["filename"]
        try:
            text = secure_read(path.absolute(), maximum_bytes=2 * 1024 * 1024).decode(
                "utf-8", errors="strict"
            )
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise WorkflowAuditError(
                f"managed workflow cannot be read: {contract['filename']}"
            ) from error
        if "permissions:\n  contents: read\n" not in text:
            raise WorkflowAuditError("managed workflow lacks read-only permissions")
        if any(token in text for token in DANGEROUS):
            raise WorkflowAuditError(
                f"managed workflow has mutation/publication authority: {path.name}"
            )
        actual_triggers = sorted(
            trigger
            for trigger in ("pull_request", "schedule", "workflow_dispatch")
            if f"\n  {trigger}:" in text
        )
        if actual_triggers != contract["triggers"]:
            raise WorkflowAuditError(f"workflow triggers disagree: {path.name}")
        authority = f'CIGAR_RUN_AUTHORITY: "{contract["authority"]}"'
        if authority not in text or 'CIGAR_NO_PROMOTION: "1"' not in text:
            raise WorkflowAuditError(
                f"workflow lacks its fail-closed authority markers: {path.name}"
            )
        environment = contract["environment"]
        if environment is None:
            if re.search(r"^\s+environment:", text, flags=re.MULTILINE):
                raise WorkflowAuditError(
                    f"unprivileged workflow declares an environment: {path.name}"
                )
        elif f"environment: {environment}" not in text:
            raise WorkflowAuditError(f"workflow environment disagrees: {path.name}")
        secrets = sorted(set(SECRET.findall(text)))
        if secrets != contract["allowed_secret_handles"]:
            raise WorkflowAuditError(f"workflow secret handles disagree: {path.name}")
        for revision in ACTION.findall(text):
            if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                raise WorkflowAuditError(
                    f"workflow action is not commit-pinned: {path.name}"
                )
        retention = f"retention-days: {contract['retention_days']}"
        if retention not in text:
            raise WorkflowAuditError(f"workflow retention disagrees: {path.name}")
        timeout_matches = [
            int(value) for value in re.findall(r"timeout-minutes:\s*([0-9]+)", text)
        ]
        if (
            not timeout_matches
            or max(timeout_matches) > contract["max_timeout_minutes"]
        ):
            raise WorkflowAuditError(
                f"workflow timeout exceeds its contract: {path.name}"
            )
        audited.append(
            {
                "filename": path.name,
                "authority": contract["authority"],
                "environment": environment,
                "secret_handles": secrets,
                "triggers": actual_triggers,
            }
        )
    body = {
        "schema_version": "cigar.refinement-workflow-audit.v1",
        "policy_id": policy["policy_id"],
        "status": "passed",
        "workflows": audited,
    }
    return {**body, "audit_id": identity(body)}
