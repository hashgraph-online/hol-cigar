"""Static trust-boundary audit for refinement GitHub Actions workflows."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical import identity, load_file, secure_read
from .schema import SchemaRegistry

POLICY_SCHEMA = "workflow-policy-v1.schema.json"
ACTION = re.compile(
    r"(?:^|[\s{,])(?:uses|'uses'|\"uses\")\s*:\s*['\"]?"
    r"[^@\s'\"]+@([^#\s'\",}\]]+)",
    flags=re.MULTILINE | re.IGNORECASE,
)
SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Z][A-Z0-9_]*)\s*\}\}")
SECRET_CONTEXT = re.compile(r"\bsecrets\b", flags=re.IGNORECASE)
SECRET_DECLARATION = re.compile(
    r"(?:^|[\s{,?])(?:secrets|'secrets'|\"secrets\")\s*:",
    flags=re.MULTILINE | re.IGNORECASE,
)
YAML_ALIAS = re.compile(
    r"(?:^|[\s{\[,])(?:&|\*)[A-Za-z0-9_-]+(?=[\s}\],]|$)",
    flags=re.MULTILINE,
)
YAML_CODEPOINT_ESCAPE = re.compile(
    r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})"
)
YAML_LINE_FOLD = re.compile(r"\\(?:\r\n|\n|\r)[ \t]*")
CANDIDATE_REF = re.compile(r"\$\{\{\s*inputs\.candidate_ref\s*\}\}")
DANGEROUS = (
    "gh pr merge",
    "git push",
    "cargo publish",
    "npm publish",
    "twine upload",
    "maturin publish",
    "gh-action-pypi-publish",
)
WRITE_PERMISSION = re.compile(
    r"(?:^|[\s{,])['\"]?"
    r"(?:contents|pull-requests|packages|id-token)['\"]?\s*:\s*"
    r"['\"]?write['\"]?(?=$|[\s,}#])",
    flags=re.MULTILINE | re.IGNORECASE,
)
WRITE_ALL = re.compile(
    r"(?:^|[\s{,])['\"]?permissions['\"]?\s*:\s*"
    r"['\"]?write-all['\"]?(?=$|[\s,}#])",
    flags=re.MULTILINE | re.IGNORECASE,
)
ON_LINE = re.compile(r"^(?:on|'on'|\"on\")\s*:\s*(?:#.*)?$", re.IGNORECASE)
EVENT_LINE = re.compile(
    r"^  (?:'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9_-]+))\s*:",
    re.IGNORECASE,
)


class WorkflowAuditError(RuntimeError):
    """A workflow grants authority outside its declared refinement lane."""


def _expressions(text: str) -> list[tuple[str, str]]:
    """Return complete GitHub expressions and quote-masked forms."""
    expressions: list[tuple[str, str]] = []
    cursor = 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            return expressions
        index = start + 3
        in_string = False
        masked = ["$", "{", "{"]
        while index < len(text):
            character = text[index]
            if character == "'":
                masked.append(" ")
                if in_string and index + 1 < len(text) and text[index + 1] == "'":
                    masked.append(" ")
                    index += 2
                    continue
                in_string = not in_string
                index += 1
                continue
            if in_string:
                masked.append(" ")
                index += 1
                continue
            if text.startswith("}}", index):
                end = index + 2
                masked.extend(("}", "}"))
                expressions.append((text[start:end], "".join(masked)))
                cursor = end
                break
            masked.append(character)
            index += 1
        else:
            raise WorkflowAuditError("workflow contains an unterminated expression")


def _secret_expressions(text: str) -> list[str]:
    return [
        expression
        for expression, masked in _expressions(text)
        if SECRET_CONTEXT.search(masked)
    ]


def _yaml_decoded_view(text: str) -> str:
    """Expose YAML scalar encodings that can conceal expression syntax."""

    def decode_codepoint(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(0)[2:], 16))
        except ValueError as error:
            raise WorkflowAuditError(
                "workflow contains an invalid YAML escape"
            ) from error

    decoded = YAML_LINE_FOLD.sub("", text)
    decoded = YAML_CODEPOINT_ESCAPE.sub(decode_codepoint, decoded)
    return decoded.replace("''", "'")


def _secret_usage(text: str) -> tuple[list[str], bool, bool]:
    raw_expressions = _secret_expressions(text)
    raw_declaration = SECRET_DECLARATION.search(text) is not None
    decoded = _yaml_decoded_view(text)
    if decoded == text:
        return raw_expressions, raw_declaration, False
    decoded_expressions = _secret_expressions(decoded)
    decoded_declaration = SECRET_DECLARATION.search(decoded) is not None
    encoded_expression = decoded_expressions != raw_expressions
    return (
        raw_expressions,
        raw_declaration or decoded_declaration,
        encoded_expression,
    )


def _has_mutation_authority(text: str) -> bool:
    decoded = _yaml_decoded_view(text)
    lowered = decoded.lower()
    return (
        WRITE_PERMISSION.search(decoded) is not None
        or WRITE_ALL.search(decoded) is not None
        or any(token in lowered for token in DANGEROUS)
    )


def _declared_triggers(text: str) -> list[str]:
    lines = _yaml_decoded_view(text).splitlines()
    on_lines = [index for index, line in enumerate(lines) if ON_LINE.fullmatch(line)]
    if len(on_lines) != 1:
        raise WorkflowAuditError("workflow trigger block is malformed")
    triggers: list[str] = []
    for line in lines[on_lines[0] + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation == 0:
            break
        if indentation > 2:
            continue
        match = EVENT_LINE.fullmatch(line)
        if indentation != 2 or match is None:
            raise WorkflowAuditError("workflow trigger block is malformed")
        triggers.append(next(value for value in match.groups() if value is not None))
    if not triggers or len(triggers) != len(set(triggers)):
        raise WorkflowAuditError("workflow trigger block is malformed")
    return sorted(triggers)


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
        secret_expressions, secret_declaration, encoded_expression = _secret_usage(
            text
        )
        triggers = _declared_triggers(text)
        if "pull_request" in triggers and (
            secret_expressions
            or secret_declaration
            or encoded_expression
            or YAML_ALIAS.search(text)
        ):
            raise WorkflowAuditError(
                f"pull-request workflow references a secret: {path.name}"
            )
        if "schedule" in triggers and _has_mutation_authority(text):
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
        if _has_mutation_authority(text):
            raise WorkflowAuditError(
                f"managed workflow has mutation/publication authority: {path.name}"
            )
        actual_triggers = _declared_triggers(text)
        unsupported_triggers = set(actual_triggers) - {
            "pull_request",
            "schedule",
            "workflow_dispatch",
        }
        if unsupported_triggers:
            raise WorkflowAuditError(f"workflow has an unsupported trigger: {path.name}")
        if actual_triggers != contract["triggers"]:
            raise WorkflowAuditError(f"workflow triggers disagree: {path.name}")
        if YAML_ALIAS.search(text):
            raise WorkflowAuditError(
                f"workflow uses an unsupported YAML alias: {path.name}"
            )
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
        secret_expressions, secret_declaration, encoded_expression = _secret_usage(
            text
        )
        if secret_declaration:
            raise WorkflowAuditError(
                f"workflow uses an unsupported secret declaration: {path.name}"
            )
        if encoded_expression:
            raise WorkflowAuditError(
                f"workflow uses an encoded secret expression: {path.name}"
            )
        if any(SECRET.fullmatch(expression) is None for expression in secret_expressions):
            raise WorkflowAuditError(
                f"workflow uses an unsupported secret expression: {path.name}"
            )
        secrets = sorted(set(SECRET.findall(text)))
        if (
            contract["authority"] == "shadow"
            and CANDIDATE_REF.search(text)
            and secret_expressions
        ):
            raise WorkflowAuditError(
                f"candidate-ref shadow workflow references a secret: {path.name}"
            )
        if secrets != contract["allowed_secret_handles"]:
            raise WorkflowAuditError(f"workflow secret handles disagree: {path.name}")
        for revision in ACTION.findall(_yaml_decoded_view(text)):
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
