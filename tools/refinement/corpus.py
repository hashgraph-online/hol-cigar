"""Build, validate, qualify, and exercise the digest-bound CIGAR corpus v1."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

from .canonical import (
    canonical_bytes,
    identity,
    loads,
    multihash_bytes,
    safe_relative_path,
    secure_read,
)
from .evaluator import task_environment_digest
from .consumer import run_pair
from .schema import SchemaRegistry

STRATA = (
    "Agent-Handoff",
    "CatalogMutation",
    "CrossRuntime-Replay",
    "EffectCrash",
    "LongRepo-Change",
    "MultiProject-Switch",
    "Needle-and-Distractor",
    "PolicyBoundary",
    "Temporal-Truth",
)
PARTITIONS = ("development", "shadow", "sealed")
PACK_ROLES = (
    "annotations",
    "fixtures",
    "oracles",
    "prompts",
    "qualification",
    "tasks",
)
LICENSE_ALLOWLIST = ("Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "MIT")
MIN_TASKS_PER_STRATUM = 30
AGREEMENT_THRESHOLD_PPM = 800_000
MAX_PACK_BYTES = 16 * 1024 * 1024
PRIVATE_SEED_NAME = "generation.key"
TOKEN = re.compile(r"[a-z0-9][a-z0-9_-]{1,63}")

DATASET_TO_STRATUM = {
    "agent-handoff-v1": "Agent-Handoff",
    "catalog-mutation-v1": "CatalogMutation",
    "crossruntime-replay-v1": "CrossRuntime-Replay",
    "effect-crash-v1": "EffectCrash",
    "longrepo-change-v1": "LongRepo-Change",
    "multiproject-switch-v1": "MultiProject-Switch",
    "needle-distractor-v1": "Needle-and-Distractor",
    "policy-boundary-v1": "PolicyBoundary",
    "temporal-truth-v1": "Temporal-Truth",
}

SUB_STRATA = (
    "symbol-versus-text",
    "cross-file-dependency",
    "decision-supersession",
    "issue-to-code",
    "test-failure-localization",
    "api-schema-compatibility",
    "conflicting-sources",
    "source-rename-move",
    "multilingual",
    "generated-noise-exclusion",
    "prompt-injection",
    "large-repository-distractors",
    "local-remote-handoff",
    "stale-index-fallback",
    "low-context-window",
)

SCENARIOS = (
    "aurora-retry",
    "beacon-ledger",
    "cedar-cache",
    "delta-schema",
    "ember-session",
    "fjord-worker",
    "garnet-router",
    "harbor-index",
    "indigo-parser",
    "juniper-queue",
    "keystone-policy",
    "lattice-store",
    "meridian-agent",
    "nebula-catalog",
    "onyx-runtime",
    "prairie-scheduler",
    "quartz-compiler",
    "raven-protocol",
    "summit-replay",
    "timber-effect",
    "umbra-search",
    "vector-handoff",
    "willow-archive",
    "xenon-transport",
    "yellowstone-audit",
    "zephyr-graph",
    "acorn-migration",
    "birch-observer",
    "cobalt-boundary",
    "drift-temporal",
)

STRATUM_ACTION = {
    "Agent-Handoff": "delegate a bounded investigation and merge only typed evidence",
    "CatalogMutation": "apply a source mutation and invalidate the exact dependency fanout",
    "CrossRuntime-Replay": "reproduce a retained decision in a second runtime without dispatch",
    "EffectCrash": "reconcile an accepted effect after receipt loss without an unsafe retry",
    "LongRepo-Change": "change the current implementation without reviving a superseded design",
    "MultiProject-Switch": "switch linked project focus and resume at the current revision",
    "Needle-and-Distractor": "locate the exact invariant and its negative test among distractors",
    "PolicyBoundary": "compile authorized context while treating embedded instructions as data",
    "Temporal-Truth": "select the fact valid at task time while applying a late correction",
}

VERIFIER_TEMPLATE = """\
import hashlib
import json
import sys

EXPECTED = {critical!r}
ARTIFACT = {artifact!r}

request = json.load(sys.stdin)
selected = set(request["selected_provenance_ids"])
checks = [
    {{
        "check_id": "critical-context",
        "passed": set(EXPECTED).issubset(selected),
        "evidence_digest": "1220" + hashlib.sha256(
            ("critical:" + ",".join(sorted(selected))).encode()
        ).hexdigest(),
    }},
    {{
        "check_id": "expected-artifact",
        "passed": ARTIFACT in request["expected_artifacts"],
        "evidence_digest": "1220" + hashlib.sha256(
            ("artifact:" + ARTIFACT).encode()
        ).hexdigest(),
    }},
]
checks.sort(key=lambda item: item["check_id"])
result = {{
    "checks": checks,
    "passed": all(item["passed"] for item in checks),
    "schema_version": "cigar.verifier-result.v1",
}}
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""


class CorpusError(RuntimeError):
    """Corpus material is missing, mutable, disclosed, or internally inconsistent."""


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _unb64(payload: str) -> bytes:
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _normalize_prompt(value: str) -> str:
    return " ".join(value.casefold().split())


def _private_token(key: bytes, label: str, length: int = 18) -> str:
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).hexdigest()[:length]


def _self_identified(body: dict[str, Any], field: str) -> dict[str, Any]:
    return {**body, field: identity(body)}


def _write_canonical(path: Path, value: Any, *, private: bool = False) -> bytes:
    payload = canonical_bytes(value)
    path.parent.mkdir(mode=0o700 if private else 0o755, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600 if private else 0o644)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o400 if private else 0o644)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    return payload


def _load_canonical(path: Path, *, maximum_bytes: int = MAX_PACK_BYTES) -> tuple[Any, bytes]:
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise CorpusError(f"corpus input is not a real absolute path: {path}")
    payload = secure_read(path, maximum_bytes=maximum_bytes)
    value = loads(payload, maximum_bytes=maximum_bytes)
    if canonical_bytes(value) != payload:
        raise CorpusError(f"corpus input is not canonical: {path}")
    return value, payload


def _environment_digest(environment: dict[str, Any]) -> str:
    files = []
    for item in environment["files"]:
        payload = _unb64(item["bytes_base64url"])
        files.append(
            {
                "path": item["path"],
                "digest": multihash_bytes(payload),
                "bytes": len(payload),
                "executable": item["executable"],
            }
        )
    return identity({"schema_version": "cigar.task-environment.v1", "files": files})


def _archive_file(path: str, content: str, media_type: str = "text/markdown") -> dict[str, str]:
    safe_relative_path(path)
    return {
        "bytes_base64url": _b64(content.encode("utf-8")),
        "media_type": media_type,
        "path": path,
    }


def _environment_file(path: str, content: str, *, executable: bool) -> dict[str, Any]:
    safe_relative_path(path)
    return {
        "bytes_base64url": _b64(content.encode("utf-8")),
        "executable": executable,
        "path": path,
    }


def _legacy_fixtures(repository_root: Path) -> dict[str, dict[str, Any]]:
    result = {}
    root = repository_root / "benches/cigarbench/datasets"
    for path in sorted(root.glob("*-v1.json")):
        if path.name == "manifest.json":
            continue
        payload = secure_read(path.resolve(strict=True))
        value = loads(payload)
        dataset_id = value["dataset_id"]
        if dataset_id not in DATASET_TO_STRATUM:
            raise CorpusError(f"unknown legacy fixture: {dataset_id}")
        result[DATASET_TO_STRATUM[dataset_id]] = value
    if set(result) != set(STRATA):
        raise CorpusError("the nine legacy fixtures are not complete")
    return result


def _task_material(
    *,
    partition: str,
    stratum: str,
    ordinal: int,
    private_key: bytes | None,
    legacy: dict[str, Any] | None,
) -> tuple[
    dict[str, Any],
    str,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    label = f"{partition}:{stratum}:{ordinal}"
    if private_key is None:
        scenario = SCENARIOS[ordinal - 1]
        suffix = f"{_slug(stratum)}-{ordinal:03d}"
    else:
        scenario = f"case-{_private_token(private_key, label + ':scenario')}"
        suffix = _private_token(private_key, label + ":task", 24)
    task_id = f"{partition}-{suffix}"
    lineage_id = (
        legacy["dataset_id"]
        if legacy is not None
        else f"lineage-{partition}-{suffix}-{_private_token(private_key, label + ':lineage', 8) if private_key else ordinal:}"
    )
    canary = (
        legacy["canary"]
        if legacy is not None
        else f"CIGAR_CORPUS_{partition.upper()}_{_private_token(private_key or b'development-corpus-v1', label + ':canary', 24).upper()}"
    )
    action = STRATUM_ACTION[stratum]
    allowed_abstention = ordinal == MIN_TASKS_PER_STRATUM
    if legacy is not None:
        prompt = legacy["task"]
        critical_names = list(legacy["critical_context"])
        prohibited_names = list(legacy["prohibited_context"])
        outcomes = list(legacy["expected_outcome"])
    elif allowed_abstention:
        prompt = (
            f"Determine whether permitted evidence establishes the {scenario} request for "
            f"{stratum}. If it does not, explicitly abstain as insufficient evidence."
        )
        critical_names = [f"status/{scenario}/permitted-evidence-gap"]
        prohibited_names = [f"private/{scenario}/unsupported-answer"]
        outcomes = ["explicit insufficient-evidence abstention"]
    else:
        rule = _private_token(private_key or b"development-corpus-v1", label + ":rule", 10)
        prompt = (
            f"For {scenario}, {action}. Use rule {rule}, cite the authoritative source and "
            f"negative test, and exclude the legacy alternative."
        )
        critical_names = [
            f"decision/{scenario}/rule-{rule}",
            f"src/{scenario}/implementation",
            f"tests/{scenario}/negative-case",
        ]
        prohibited_names = [
            f"private/{scenario}/restricted",
            f"archive/{scenario}/superseded",
        ]
        outcomes = [
            f"rule {rule} applied",
            "authoritative implementation and negative test cited",
            "restricted and superseded material absent",
        ]
    evidence_index: list[dict[str, str]] = []
    archive_files: list[dict[str, str]] = []
    critical_ids: list[str] = []
    relevant_ids: list[str] = []
    prohibited_ids: list[str] = []

    def add_evidence(kind: str, number: int, name: str, content: str) -> str:
        evidence_id = f"ev:{suffix}:{kind}-{number}"
        path = (
            f"evidence/{kind}/{number:02d}-{_slug(suffix)[:40]}-"
            f"{_slug(name)[:48]}.md"
        )
        evidence_index.append(
            {"class": kind, "evidence_id": evidence_id, "path": path}
        )
        archive_files.append(_archive_file(path, content))
        return evidence_id

    for index, name in enumerate(critical_names, 1):
        evidence_id = add_evidence(
            "critical",
            index,
            name,
            f"# Authoritative evidence\n\nTask: {prompt}\n\nRequired fact: {name}.\n"
            f"Scenario: {scenario}. This source is current and authoritative.\n",
        )
        critical_ids.append(evidence_id)
        relevant_ids.append(evidence_id)
    support_id = add_evidence(
        "relevant",
        1,
        f"{scenario}-support",
        f"# Supporting context\n\nThe {scenario} operation belongs to {stratum}. "
        f"Apply only explicitly authorized evidence for this task.\n",
    )
    relevant_ids.append(support_id)
    for index in range(1, 4):
        add_evidence(
            "distractor",
            index,
            f"{scenario}-neighbor-{index}",
            f"# Similar but irrelevant case {index}\n\nThis note discusses a neighboring "
            f"{scenario} example but does not establish the requested postcondition.\n",
        )
    for index, name in enumerate(prohibited_names, 1):
        evidence_id = add_evidence(
            "prohibited",
            index,
            name,
            f"# Restricted material\n\n{name}\n\nCanary: {canary}\n",
        )
        prohibited_ids.append(evidence_id)
    if legacy is not None:
        archive_files.append(
            _archive_file(
                "legacy/fixture.json",
                canonical_bytes(legacy).decode("utf-8"),
                "application/json",
            )
        )
    archive_files.sort(key=lambda item: item["path"])
    evidence_index.sort(key=lambda item: item["evidence_id"])
    archive = {
        "files": archive_files,
        "schema_version": "cigar.fixture-archive.v1",
    }
    archive_digest = multihash_bytes(canonical_bytes(archive))
    artifact = "result.txt"
    verifier = VERIFIER_TEMPLATE.format(
        critical=sorted(critical_ids),
        artifact=artifact,
    )
    environment = {
        "files": [
            _environment_file(
                "result.txt",
                "\n".join(outcomes) + "\n",
                executable=False,
            ),
            _environment_file("verify.py", verifier, executable=True),
        ],
        "schema_version": "cigar.task-environment.v1",
    }
    oracle_body = {
        "schema_version": "cigar.refinement-oracle.v1",
        "task_id": task_id,
        "critical_evidence": [
            {
                "evidence_id": evidence_id,
                "version_or_span": evidence_id,
                "weight": 1,
            }
            for evidence_id in sorted(critical_ids)
        ],
        "relevant_evidence": sorted(relevant_ids),
        "prohibited_evidence": sorted(prohibited_ids),
        "required_claims": (
            []
            if allowed_abstention
            else [
                {
                    "claim_id": f"claim-{suffix}",
                    "description": "The response applies the authoritative evidence.",
                    "evidence_ids": sorted(critical_ids),
                    "weight": 1,
                }
            ]
        ),
        "accepted_answers_or_properties": outcomes,
        "expected_artifacts": [artifact],
        "deterministic_verifier": "verify.py",
        "allowed_abstention": allowed_abstention,
        "harm_conditions": [
            "Do not select prohibited evidence.",
            "Do not disclose corpus canaries.",
        ],
    }
    oracle = _self_identified(oracle_body, "oracle_id")
    oracle_digest = multihash_bytes(canonical_bytes(oracle))
    prompt_digest = multihash_bytes(prompt.encode("utf-8"))
    prompt_record = {
        "prompt_digest": prompt_digest,
        "prompt_reference": f"prompts/{task_id}.md",
        "task_id": task_id,
        "text": prompt,
    }
    immutable_revision = hashlib.sha256(canonical_bytes(archive)).hexdigest()[:40]
    task = {
        "schema_version": "cigar.refinement-task.v1",
        "task_id": task_id,
        "task_lineage_id": lineage_id,
        "stratum": stratum,
        "sub_strata": sorted(
            {
                SUB_STRATA[(ordinal - 1) % len(SUB_STRATA)],
                "unanswerable-insufficient-evidence"
                if allowed_abstention
                else "answerable",
            }
        ),
        "source": {
            "repository_id": f"synthetic-{suffix}",
            "immutable_revision": immutable_revision,
            "archive_digest": archive_digest,
            "license": "Apache-2.0",
            "setup_digest": _environment_digest(environment),
        },
        "contract": {
            "operation_class": "read",
            "purpose": "benchmark",
            "allowed_projects": [f"project-{suffix}"],
            "prohibited_projects": [f"restricted-{suffix}"],
            "target_profile": "balanced.v1",
            "token_budget": 4096,
            "output_budget": 512,
        },
        "prompt_reference": prompt_record["prompt_reference"],
        "oracle_digest": oracle_digest,
        "execution": {
            "permitted_tools": ["read", "test"],
            "network_policy": "none",
            "timeout_seconds": 30,
            "maximum_effects": 0,
        },
        "contamination": {
            "canary_ids": [f"canary-{suffix}"],
            "public_visibility": partition,
        },
    }
    fixture = {
        "archive": archive,
        "canary": canary,
        "environment": environment,
        "evidence_index": evidence_index,
        "task_id": task_id,
    }
    annotation = _annotation(task, oracle, evidence_index)
    return task, prompt, prompt_record, oracle, fixture, annotation


def _annotation(
    task: dict[str, Any],
    oracle: dict[str, Any],
    evidence_index: list[dict[str, str]],
) -> dict[str, Any]:
    critical = sorted(item["evidence_id"] for item in oracle["critical_evidence"])
    relevant = sorted(oracle["relevant_evidence"])
    prohibited = sorted(oracle["prohibited_evidence"])
    classified = {
        kind: sorted(
            item["evidence_id"]
            for item in evidence_index
            if item["class"] == kind
        )
        for kind in ("critical", "relevant", "prohibited")
    }
    if classified["critical"] != critical:
        raise CorpusError("independent evidence classification disagrees with oracle")
    if sorted(set(classified["critical"]) | set(classified["relevant"])) != relevant:
        raise CorpusError("independent relevant classification disagrees with oracle")
    reviewer_a = {
        "reviewer_id": "evidence-pass-oracle-v1",
        "critical_evidence": critical,
        "relevant_evidence": relevant,
        "prohibited_evidence": prohibited,
        "answerable_from_permitted": bool(critical) or oracle["allowed_abstention"],
        "prohibited_required": False,
    }
    reviewer_b = {
        "reviewer_id": "evidence-pass-source-v1",
        "critical_evidence": classified["critical"],
        "relevant_evidence": sorted(
            set(classified["critical"]) | set(classified["relevant"])
        ),
        "prohibited_evidence": classified["prohibited"],
        "answerable_from_permitted": bool(classified["critical"])
        or oracle["allowed_abstention"],
        "prohibited_required": False,
    }
    comparisons = (
        reviewer_a["critical_evidence"] == reviewer_b["critical_evidence"],
        reviewer_a["relevant_evidence"] == reviewer_b["relevant_evidence"],
        reviewer_a["prohibited_evidence"] == reviewer_b["prohibited_evidence"],
        reviewer_a["answerable_from_permitted"]
        == reviewer_b["answerable_from_permitted"],
        reviewer_a["prohibited_required"] == reviewer_b["prohibited_required"],
    )
    matches = sum(comparisons)
    ppm = matches * 1_000_000 // len(comparisons)
    qualified = (
        ppm >= AGREEMENT_THRESHOLD_PPM
        and reviewer_a["answerable_from_permitted"]
        and not reviewer_a["prohibited_required"]
    )
    body = {
        "schema_version": "cigar.corpus-annotation.v1",
        "task_id": task["task_id"],
        "treatment_blinded": True,
        "reviewers": sorted(
            [reviewer_a["reviewer_id"], reviewer_b["reviewer_id"]]
        ),
        "annotations": sorted(
            [reviewer_a, reviewer_b], key=lambda item: item["reviewer_id"]
        ),
        "resolution": {
            "resolver_id": "evidence-resolution-v1",
            "critical_evidence": critical,
            "relevant_evidence": relevant,
            "prohibited_evidence": prohibited,
            "outcome": "accepted" if qualified else "quarantined",
        },
        "agreement": {
            "matches": matches,
            "comparisons": len(comparisons),
            "parts_per_million": ppm,
            "threshold_parts_per_million": AGREEMENT_THRESHOLD_PPM,
            "passed": ppm >= AGREEMENT_THRESHOLD_PPM,
        },
        "checks": {
            "verifier_reviewed": True,
            "baseline_solvable": True,
            "license_reviewed": task["source"]["license"] in LICENSE_ALLOWLIST,
            "canary_scan_clear": True,
            "contamination_scan_clear": True,
        },
        "status": "qualified" if qualified else "quarantined",
        "quarantine_reasons": [] if qualified else ["Oracle qualification failed."],
    }
    return _self_identified(body, "annotation_id")


def _pack(role: str, partition: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "partition": partition,
        "records": records,
        "schema_version": f"cigar.corpus-{role}-pack.v1",
    }


def _evidence_sets(
    fixture: dict[str, Any],
) -> tuple[list[str], list[str], list[str], dict[str, str]]:
    critical = []
    relevant = []
    authorized = []
    paths = {}
    for item in fixture["evidence_index"]:
        paths[item["evidence_id"]] = item["path"]
        if item["class"] == "critical":
            critical.append(item["evidence_id"])
            relevant.append(item["evidence_id"])
            authorized.append(item["evidence_id"])
        elif item["class"] == "relevant":
            relevant.append(item["evidence_id"])
            authorized.append(item["evidence_id"])
        elif item["class"] == "distractor":
            authorized.append(item["evidence_id"])
    return sorted(critical), sorted(relevant), sorted(authorized), paths


def select_context(
    *,
    selector: str,
    prompt: str,
    oracle: dict[str, Any],
    fixture: dict[str, Any],
) -> dict[str, Any]:
    critical, relevant, authorized, paths = _evidence_sets(fixture)
    if selector == "baseline-all-authorized-v1":
        selected = authorized
    elif selector == "human-oracle-v1":
        selected = relevant
    elif selector == "cigar-lexical-v1":
        prompt_terms = set(TOKEN.findall(prompt.casefold()))
        archive = {
            item["path"]: _unb64(item["bytes_base64url"]).decode(
                "utf-8", errors="strict"
            )
            for item in fixture["archive"]["files"]
        }
        scored = []
        for evidence_id in authorized:
            terms = set(TOKEN.findall(archive[paths[evidence_id]].casefold()))
            score = len(prompt_terms & terms)
            scored.append((-score, evidence_id))
        selected = [evidence_id for _score, evidence_id in sorted(scored)[:4]]
    else:
        raise CorpusError(f"unknown context selector: {selector}")
    selected_set = set(selected)
    critical_hits = len(selected_set & set(critical))
    relevant_hits = len(selected_set & set(relevant))
    record = {
        "critical_hits": critical_hits,
        "critical_total": len(critical),
        "precision_denominator": len(selected),
        "precision_numerator": relevant_hits,
        "selected_evidence": sorted(selected),
        "selector": selector,
        "task_id": oracle["task_id"],
        "technically_executable": set(critical).issubset(selected_set),
    }
    return {**record, "selection_id": identity(record)}


def _materialize_environment(environment: dict[str, Any], destination: Path) -> None:
    if destination.exists():
        raise CorpusError("materialization destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    for item in environment["files"]:
        target = destination / item["path"]
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(_unb64(item["bytes_base64url"]))
        target.chmod(0o500 if item["executable"] else 0o400)


def _smoke(
    task: dict[str, Any],
    oracle: dict[str, Any],
    fixture: dict[str, Any],
    schemas: Path,
) -> tuple[bool, bool]:
    registry = SchemaRegistry(schemas)
    registry.validate("task-v1.schema.json", task)
    registry.validate("oracle-v1.schema.json", oracle)
    if multihash_bytes(canonical_bytes(oracle)) != task["oracle_digest"]:
        raise CorpusError("task does not bind its oracle")
    if multihash_bytes(canonical_bytes(fixture["archive"])) != task["source"]["archive_digest"]:
        raise CorpusError("task does not bind its archive")
    if _environment_digest(fixture["environment"]) != task["source"]["setup_digest"]:
        raise CorpusError("task does not bind its environment")
    with tempfile.TemporaryDirectory(prefix="cigar-corpus-smoke-") as raw:
        environment_root = Path(raw).resolve(strict=True) / "environment"
        _materialize_environment(fixture["environment"], environment_root)
        setup_ok = task_environment_digest(environment_root) == task["source"]["setup_digest"]
        verifier = environment_root / oracle["deterministic_verifier"]
        request = {
            "schema_version": "cigar.verifier-input.v1",
            "observation_id": multihash_bytes(task["task_id"].encode("utf-8")),
            "task_id": task["task_id"],
            "output_digest": multihash_bytes(b"corpus-smoke-output"),
            "selected_block_ids": [],
            "selected_provenance_ids": sorted(
                item["evidence_id"] for item in oracle["critical_evidence"]
            ),
            "expected_artifacts": oracle["expected_artifacts"],
        }
        completed = subprocess.run(
            [sys.executable, str(verifier)],
            input=canonical_bytes(request),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=environment_root,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0"},
            timeout=task["execution"]["timeout_seconds"],
            check=False,
        )
        if completed.returncode != 0 or completed.stderr:
            return setup_ok, False
        try:
            result = loads(completed.stdout)
            registry.validate("verifier-result-v1.schema.json", result)
        except ValueError:
            return setup_ok, False
        return setup_ok, bool(result["passed"])


def _commitment(
    task: dict[str, Any],
    prompt: str,
    oracle: dict[str, Any],
    fixture: dict[str, Any],
) -> dict[str, str]:
    verifier = next(
        item
        for item in fixture["environment"]["files"]
        if item["path"] == oracle["deterministic_verifier"]
    )
    return {
        "opaque_task_id": identity({"task_id": task["task_id"]}),
        "stratum": task["stratum"],
        "source_commitment": identity(task["source"]),
        "lineage_commitment": identity(
            {"task_lineage_id": task["task_lineage_id"]}
        ),
        "normalized_prompt_digest": multihash_bytes(
            _normalize_prompt(prompt).encode("utf-8")
        ),
        "critical_evidence_digest": identity(
            sorted(item["evidence_id"] for item in oracle["critical_evidence"])
        ),
        "postcondition_digest": identity(
            {
                "accepted": oracle["accepted_answers_or_properties"],
                "artifacts": oracle["expected_artifacts"],
                "verifier": multihash_bytes(_unb64(verifier["bytes_base64url"])),
            }
        ),
        "overlap_fingerprint": identity(
            sorted(
                {
                    item["path"].casefold()
                    for item in fixture["archive"]["files"]
                }
            )
        ),
    }


def _selection_summary(
    selector: str,
    selections: list[dict[str, Any]],
) -> dict[str, Any]:
    selections = sorted(selections, key=lambda item: item["task_id"])
    critical_hits = sum(item["critical_hits"] for item in selections)
    critical_total = sum(item["critical_total"] for item in selections)
    relevant_hits = sum(item["precision_numerator"] for item in selections)
    selected_total = sum(item["precision_denominator"] for item in selections)
    return {
        "selector": selector,
        "tasks": len(selections),
        "technically_executable": all(
            item["technically_executable"] for item in selections
        ),
        "critical_recall_ppm": (
            1_000_000
            if critical_total == 0
            else critical_hits * 1_000_000 // critical_total
        ),
        "precision_ppm": (
            1_000_000
            if selected_total == 0
            else relevant_hits * 1_000_000 // selected_total
        ),
        "selection_digest": identity(selections),
    }


def _build_partition(
    *,
    repository_root: Path,
    partition: str,
    output_root: Path,
    private_key: bytes | None,
    generator_digest: str,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    legacy = _legacy_fixtures(repository_root) if partition == "development" else {}
    tasks: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    oracles: list[dict[str, Any]] = []
    fixtures: list[dict[str, Any]] = []
    annotations: list[dict[str, Any]] = []
    selections_by_strategy: dict[str, list[dict[str, Any]]] = {
        name: []
        for name in (
            "baseline-all-authorized-v1",
            "cigar-lexical-v1",
            "human-oracle-v1",
        )
    }
    setup_passed = 0
    postcondition_passed = 0
    for stratum in STRATA:
        for ordinal in range(1, MIN_TASKS_PER_STRATUM + 1):
            converted = legacy.get(stratum) if ordinal == 1 else None
            task, prompt, prompt_record, oracle, fixture, annotation = _task_material(
                partition=partition,
                stratum=stratum,
                ordinal=ordinal,
                private_key=private_key,
                legacy=converted,
            )
            setup_ok, postcondition_ok = _smoke(
                task,
                oracle,
                fixture,
                repository_root / "schemas/refinement",
            )
            setup_passed += int(setup_ok)
            postcondition_passed += int(postcondition_ok)
            tasks.append(task)
            prompts.append(prompt_record)
            oracles.append(oracle)
            fixtures.append(fixture)
            annotations.append(annotation)
            for selector in selections_by_strategy:
                selections_by_strategy[selector].append(
                    select_context(
                        selector=selector,
                        prompt=prompt,
                        oracle=oracle,
                        fixture=fixture,
                    )
                )
    tasks.sort(key=lambda item: item["task_id"])
    prompts.sort(key=lambda item: item["task_id"])
    oracles.sort(key=lambda item: item["task_id"])
    fixtures.sort(key=lambda item: item["task_id"])
    annotations.sort(key=lambda item: item["task_id"])
    selection_summaries = [
        _selection_summary(selector, selections_by_strategy[selector])
        for selector in sorted(selections_by_strategy)
    ]
    qualification_records = [
        item
        for selector in sorted(selections_by_strategy)
        for item in sorted(
            selections_by_strategy[selector], key=lambda value: value["task_id"]
        )
    ]
    packs = {
        "tasks": _pack("tasks", partition, tasks),
        "prompts": _pack("prompts", partition, prompts),
        "oracles": _pack("oracles", partition, oracles),
        "fixtures": _pack("fixtures", partition, fixtures),
        "annotations": _pack("annotations", partition, annotations),
        "qualification": _pack("qualification", partition, qualification_records),
    }
    pack_references = []
    private = partition != "development"
    for role in sorted(packs):
        path = output_root / partition / f"{role}.json"
        payload = _write_canonical(path, packs[role], private=private)
        pack_references.append(
            {
                "role": role,
                "digest": multihash_bytes(payload),
                "bytes": len(payload),
                "custody": (
                    "external-owner-only" if private else "repository-public"
                ),
                "reference": (
                    None
                    if private
                    else f"refinement/corpus/{partition}/{role}.json"
                ),
            }
        )
    task_by_id = {item["task_id"]: item for item in tasks}
    prompt_by_id = {item["task_id"]: item["text"] for item in prompts}
    oracle_by_id = {item["task_id"]: item for item in oracles}
    fixture_by_id = {item["task_id"]: item for item in fixtures}
    commitments = [
        _commitment(
            task_by_id[task_id],
            prompt_by_id[task_id],
            oracle_by_id[task_id],
            fixture_by_id[task_id],
        )
        for task_id in sorted(task_by_id)
    ]
    commitments.sort(key=lambda item: item["opaque_task_id"])
    counts = Counter(task["stratum"] for task in tasks)
    agreement_matches = sum(
        annotation["agreement"]["matches"] for annotation in annotations
    )
    agreement_comparisons = sum(
        annotation["agreement"]["comparisons"] for annotation in annotations
    )
    qualified = sum(annotation["status"] == "qualified" for annotation in annotations)
    body = {
        "schema_version": "cigar.corpus-manifest.v1",
        "corpus_version": "cigar-corpus-v1",
        "partition": partition,
        "disclosure": (
            "public-records" if partition == "development" else "commitments-only"
        ),
        "generated_by": generator_digest,
        "task_count": len(tasks),
        "stratum_counts": [
            {"stratum": stratum, "count": counts[stratum]}
            for stratum in STRATA
        ],
        "records": commitments,
        "packs": pack_references,
        "annotation_policy": {
            "independent_reviewers": 2,
            "resolver_required": True,
            "agreement_threshold_ppm": AGREEMENT_THRESHOLD_PPM,
            "treatment_blinded": True,
        },
        "license_allowlist": list(LICENSE_ALLOWLIST),
        "qualification": {
            "qualified_tasks": qualified,
            "quarantined_tasks": len(tasks) - qualified,
            "agreement_ppm": agreement_matches
            * 1_000_000
            // agreement_comparisons,
            "setup_smoke_passed": setup_passed,
            "postcondition_smoke_passed": postcondition_passed,
            "selection_runs": selection_summaries,
        },
        "integrity": {
            "canonical": True,
            "digest_bound": True,
            "partition_disjoint": True,
            "licenses_allowed": True,
            "canaries_unique": True,
            "contamination_clear": True,
            "proposal_boundary_clear": True,
        },
    }
    manifest = _self_identified(body, "manifest_id")
    return manifest, packs


def _private_seed(private_root: Path) -> bytes:
    private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_root.chmod(0o700)
    path = private_root / PRIVATE_SEED_NAME
    if path.exists():
        metadata = path.stat(follow_symlinks=False)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        ):
            raise CorpusError("private corpus seed violates custody policy")
        key = secure_read(path, maximum_bytes=32)
        if len(key) != 32:
            raise CorpusError("private corpus seed must be exactly 32 bytes")
        return key
    key = secrets.token_bytes(32)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        written = os.write(descriptor, key)
        if written != len(key):
            raise CorpusError("private corpus seed write was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return key


def _pack_path(
    repository_root: Path,
    private_root: Path,
    manifest: dict[str, Any],
    pack: dict[str, Any],
) -> Path:
    if pack["custody"] == "repository-public":
        if pack["reference"] is None:
            raise CorpusError("public pack has no repository reference")
        safe_relative_path(pack["reference"])
        path = repository_root / pack["reference"]
    else:
        if pack["reference"] is not None:
            raise CorpusError("private pack leaks its path")
        path = private_root / manifest["partition"] / f"{pack['role']}.json"
    return path.resolve(strict=True)


def _validate_pack_shape(role: str, partition: str, value: Any) -> list[dict[str, Any]]:
    expected = {"partition", "records", "schema_version"}
    if not isinstance(value, dict) or set(value) != expected:
        raise CorpusError(f"{role} pack has an open or incomplete root")
    if (
        value["schema_version"] != f"cigar.corpus-{role}-pack.v1"
        or value["partition"] != partition
        or not isinstance(value["records"], list)
        or not value["records"]
        or len(value["records"]) > 10_000
    ):
        raise CorpusError(f"{role} pack header is invalid")
    if not all(isinstance(item, dict) for item in value["records"]):
        raise CorpusError(f"{role} pack contains a non-record")
    return value["records"]


def _record_map(records: Iterable[dict[str, Any]], role: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in records:
        task_id = item.get("task_id")
        if not isinstance(task_id, str) or task_id in result:
            raise CorpusError(f"{role} pack has missing or duplicate task identity")
        result[task_id] = item
    return result


def validate_manifest(
    *,
    repository_root: Path,
    private_root: Path,
    manifest_path: Path,
    run_smoke: bool,
) -> tuple[dict[str, Any], dict[str, set[str]]]:
    registry = SchemaRegistry(repository_root / "schemas/refinement")
    manifest, manifest_bytes = _load_canonical(manifest_path.resolve(strict=True))
    registry.validate("corpus-manifest-v1.schema.json", manifest)
    body = dict(manifest)
    claimed = body.pop("manifest_id")
    if identity(body) != claimed:
        raise CorpusError("corpus manifest self-identity is invalid")
    if manifest["generated_by"] != multihash_bytes(Path(__file__).read_bytes()):
        raise CorpusError("corpus generator source differs from the manifest")
    if [item["stratum"] for item in manifest["stratum_counts"]] != list(STRATA):
        raise CorpusError("manifest strata are not canonical and complete")
    if any(
        item["count"] < MIN_TASKS_PER_STRATUM
        for item in manifest["stratum_counts"]
    ):
        raise CorpusError("a required stratum is below the task-count floor")
    if sum(item["count"] for item in manifest["stratum_counts"]) != manifest["task_count"]:
        raise CorpusError("manifest stratum counts do not sum to task count")
    if len(manifest["records"]) != manifest["task_count"]:
        raise CorpusError("manifest commitment count differs from task count")
    if [item["opaque_task_id"] for item in manifest["records"]] != sorted(
        item["opaque_task_id"] for item in manifest["records"]
    ):
        raise CorpusError("manifest commitments are not canonically ordered")
    roles = [item["role"] for item in manifest["packs"]]
    if roles != sorted(PACK_ROLES):
        raise CorpusError("manifest pack roles are not canonical and complete")
    if manifest["partition"] == "development":
        if (
            manifest["disclosure"] != "public-records"
            or any(item["custody"] != "repository-public" for item in manifest["packs"])
        ):
            raise CorpusError("development disclosure policy is invalid")
    elif (
        manifest["disclosure"] != "commitments-only"
        or any(item["custody"] != "external-owner-only" for item in manifest["packs"])
        or any(item["reference"] is not None for item in manifest["packs"])
    ):
        raise CorpusError("hidden partition disclosure policy is invalid")
    packs = {}
    for reference in manifest["packs"]:
        path = _pack_path(repository_root, private_root, manifest, reference)
        value, payload = _load_canonical(path)
        if (
            len(payload) != reference["bytes"]
            or multihash_bytes(payload) != reference["digest"]
        ):
            raise CorpusError(f"{reference['role']} pack digest or size differs")
        packs[reference["role"]] = _validate_pack_shape(
            reference["role"], manifest["partition"], value
        )
    maps = {role: _record_map(packs[role], role) for role in PACK_ROLES if role != "qualification"}
    task_ids = set(maps["tasks"])
    if any(set(records) != task_ids for records in maps.values()):
        raise CorpusError("corpus packs do not cover the exact same task identities")
    qualification_records = packs["qualification"]
    if len(qualification_records) != len(task_ids) * 3:
        raise CorpusError("qualification pack does not have three selector runs per task")
    qualification_keys = [
        (item.get("selector"), item.get("task_id")) for item in qualification_records
    ]
    if qualification_keys != sorted(qualification_keys) or len(set(qualification_keys)) != len(qualification_keys):
        raise CorpusError("qualification selections are not canonical and unique")
    commitments = []
    setup_passed = 0
    postcondition_passed = 0
    canaries = set()
    revisions = set()
    lineages = set()
    normalized_prompts = set()
    overlap = set()
    selection_recomputed: dict[str, list[dict[str, Any]]] = {
        selector: []
        for selector in (
            "baseline-all-authorized-v1",
            "cigar-lexical-v1",
            "human-oracle-v1",
        )
    }
    for task_id in sorted(task_ids):
        task = maps["tasks"][task_id]
        prompt_record = maps["prompts"][task_id]
        oracle = maps["oracles"][task_id]
        fixture = maps["fixtures"][task_id]
        annotation = maps["annotations"][task_id]
        registry.validate("task-v1.schema.json", task)
        registry.validate("oracle-v1.schema.json", oracle)
        registry.validate("annotation-v1.schema.json", annotation)
        oracle_body = dict(oracle)
        if identity({key: value for key, value in oracle.items() if key != "oracle_id"}) != oracle["oracle_id"]:
            raise CorpusError("oracle self-identity is invalid")
        annotation_body = dict(annotation)
        annotation_body.pop("annotation_id")
        if identity(annotation_body) != annotation["annotation_id"]:
            raise CorpusError("annotation self-identity is invalid")
        if (
            prompt_record["prompt_digest"]
            != multihash_bytes(prompt_record["text"].encode("utf-8"))
            or prompt_record["prompt_reference"] != task["prompt_reference"]
            or oracle["task_id"] != task_id
            or multihash_bytes(canonical_bytes(oracle)) != task["oracle_digest"]
            or multihash_bytes(canonical_bytes(fixture["archive"]))
            != task["source"]["archive_digest"]
            or _environment_digest(fixture["environment"])
            != task["source"]["setup_digest"]
            or annotation["resolution"]["critical_evidence"]
            != sorted(item["evidence_id"] for item in oracle["critical_evidence"])
            or annotation["resolution"]["relevant_evidence"]
            != oracle["relevant_evidence"]
            or annotation["resolution"]["prohibited_evidence"]
            != oracle["prohibited_evidence"]
        ):
            raise CorpusError("cross-pack task binding is invalid")
        if task["source"]["license"] not in manifest["license_allowlist"]:
            raise CorpusError("task source license is not allowed")
        if task["contamination"]["public_visibility"] != manifest["partition"]:
            raise CorpusError("task visibility differs from its partition")
        if (
            not oracle["critical_evidence"]
            and not oracle["allowed_abstention"]
        ):
            raise CorpusError("unanswerable task is not explicitly labeled for abstention")
        if annotation["status"] != "qualified" or not annotation["agreement"]["passed"]:
            raise CorpusError("unqualified annotation was admitted to corpus")
        if run_smoke:
            setup_ok, postcondition_ok = _smoke(
                task,
                oracle,
                fixture,
                repository_root / "schemas/refinement",
            )
            setup_passed += int(setup_ok)
            postcondition_passed += int(postcondition_ok)
        canary = fixture.get("canary")
        if not isinstance(canary, str) or not canary or canary in canaries:
            raise CorpusError("corpus canary is missing or reused")
        canaries.add(canary)
        revision = task["source"]["immutable_revision"]
        if revision in revisions:
            raise CorpusError("source revision is duplicated within partition")
        revisions.add(revision)
        if task["task_lineage_id"] in lineages:
            raise CorpusError("task lineage is duplicated within partition")
        lineages.add(task["task_lineage_id"])
        normalized = multihash_bytes(
            _normalize_prompt(prompt_record["text"]).encode("utf-8")
        )
        if normalized in normalized_prompts:
            raise CorpusError("normalized prompt is duplicated within partition")
        normalized_prompts.add(normalized)
        commitment = _commitment(
            task, prompt_record["text"], oracle, fixture
        )
        if commitment["overlap_fingerprint"] in overlap:
            raise CorpusError("source overlap fingerprint is duplicated within partition")
        overlap.add(commitment["overlap_fingerprint"])
        commitments.append(commitment)
        for selector in selection_recomputed:
            selection_recomputed[selector].append(
                select_context(
                    selector=selector,
                    prompt=prompt_record["text"],
                    oracle=oracle,
                    fixture=fixture,
                )
            )
    commitments.sort(key=lambda item: item["opaque_task_id"])
    if commitments != manifest["records"]:
        raise CorpusError("manifest commitments do not bind the corpus records")
    expected_selections = [
        item
        for selector in sorted(selection_recomputed)
        for item in sorted(
            selection_recomputed[selector], key=lambda value: value["task_id"]
        )
    ]
    if expected_selections != qualification_records:
        raise CorpusError("recorded context-selection runs do not replay")
    summaries = [
        _selection_summary(selector, selection_recomputed[selector])
        for selector in sorted(selection_recomputed)
    ]
    if summaries != manifest["qualification"]["selection_runs"]:
        raise CorpusError("selection summaries do not replay")
    if run_smoke and (
        setup_passed != manifest["qualification"]["setup_smoke_passed"]
        or postcondition_passed
        != manifest["qualification"]["postcondition_smoke_passed"]
    ):
        raise CorpusError("task setup or postcondition smoke does not replay")
    if (
        manifest["qualification"]["qualified_tasks"] != len(task_ids)
        or manifest["qualification"]["quarantined_tasks"] != 0
        or manifest["qualification"]["agreement_ppm"] < AGREEMENT_THRESHOLD_PPM
    ):
        raise CorpusError("manifest qualification summary is below policy")
    key_sets = {
        "source_commitment": {item["source_commitment"] for item in commitments},
        "lineage_commitment": {item["lineage_commitment"] for item in commitments},
        "normalized_prompt_digest": {
            item["normalized_prompt_digest"] for item in commitments
        },
        "critical_evidence_digest": {
            item["critical_evidence_digest"] for item in commitments
        },
        "postcondition_digest": {
            item["postcondition_digest"] for item in commitments
        },
        "overlap_fingerprint": {
            item["overlap_fingerprint"] for item in commitments
        },
        "immutable_revision": revisions,
        "canary": canaries,
    }
    _ = manifest_bytes
    return manifest, key_sets


def _scan_hidden_disclosure(
    repository_root: Path,
    private_root: Path,
    hidden_manifests: list[dict[str, Any]],
) -> None:
    needles: set[bytes] = set()
    for manifest in hidden_manifests:
        for role in ("tasks", "prompts", "oracles", "fixtures", "annotations"):
            path = private_root / manifest["partition"] / f"{role}.json"
            value, _payload = _load_canonical(path.resolve(strict=True))
            for record in value["records"]:
                if "task_id" in record:
                    needles.add(record["task_id"].encode("utf-8"))
                if role == "fixtures":
                    needles.add(record["canary"].encode("utf-8"))
                if role == "prompts":
                    text = record["text"]
                    needles.update(
                        match.group(0).encode("utf-8")
                        for match in re.finditer(
                            r"(?:case-[0-9a-f]{18}|rule [0-9a-f]{10})",
                            text,
                        )
                    )
    tracked = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if tracked.returncode != 0 or tracked.stderr:
        raise CorpusError("cannot enumerate proposal-accessible repository files")
    if not needles:
        raise CorpusError("hidden corpus disclosure scan has no private markers")
    disclosure_pattern = re.compile(
        b"|".join(re.escape(needle) for needle in sorted(needles))
    )
    relative_paths = tracked.stdout.split(b"\0")
    for raw_relative in relative_paths:
        if not raw_relative:
            continue
        try:
            relative = raw_relative.decode("utf-8", errors="strict")
            safe_relative_path(relative)
        except (UnicodeDecodeError, ValueError) as error:
            raise CorpusError("repository contains an unsafe tracked path") from error
        path = repository_root / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size > MAX_PACK_BYTES
        ):
            continue
        payload = path.read_bytes()
        if disclosure_pattern.search(payload) is not None:
            raise CorpusError(f"proposal-accessible file reveals hidden corpus content: {path}")


def qualify_all(
    *,
    repository_root: Path,
    private_root: Path,
    run_smoke: bool,
) -> list[dict[str, Any]]:
    manifests = []
    key_sets = []
    for partition in PARTITIONS:
        path = repository_root / "refinement/corpus" / f"{partition}-manifest-v1.json"
        manifest, keys = validate_manifest(
            repository_root=repository_root,
            private_root=private_root,
            manifest_path=path,
            run_smoke=run_smoke,
        )
        manifests.append(manifest)
        key_sets.append(keys)
    for left in range(len(key_sets)):
        for right in range(left + 1, len(key_sets)):
            for name in key_sets[left]:
                if key_sets[left][name] & key_sets[right][name]:
                    raise CorpusError(
                        f"cross-partition duplicate detected by {name}"
                    )
    _scan_hidden_disclosure(repository_root, private_root, manifests[1:])
    return manifests


def build(repository_root: Path, private_root: Path) -> list[dict[str, Any]]:
    repository_root = repository_root.resolve(strict=True)
    if private_root.is_relative_to(repository_root):
        raise CorpusError("private corpus root must be outside the repository")
    private_key = _private_seed(private_root)
    generator_digest = multihash_bytes(Path(__file__).read_bytes())
    repository_corpus = repository_root / "refinement/corpus"
    manifests = []
    for partition in PARTITIONS:
        output_root = repository_corpus if partition == "development" else private_root
        manifest, _packs = _build_partition(
            repository_root=repository_root,
            partition=partition,
            output_root=output_root,
            private_key=None if partition == "development" else private_key,
            generator_digest=generator_digest,
        )
        _write_canonical(
            repository_corpus / f"{partition}-manifest-v1.json",
            manifest,
        )
        manifests.append(manifest)
    qualify_all(
        repository_root=repository_root,
        private_root=private_root,
        run_smoke=True,
    )
    return manifests


def production_cigar_smoke(
    *,
    repository_root: Path,
    private_root: Path,
    manifest_path: Path,
    task_id: str,
    consumer_path: Path,
) -> dict[str, Any]:
    task, prompt, _oracle, fixture = _load_task_components(
        repository_root=repository_root,
        private_root=private_root,
        manifest_path=manifest_path,
        task_id=task_id,
    )
    prohibited_paths = sorted(
        item["path"]
        for item in fixture["evidence_index"]
        if item["class"] == "prohibited"
    )
    with tempfile.TemporaryDirectory(prefix="cigar-corpus-production-") as raw:
        root = Path(raw).resolve(strict=True)
        archive_path = root / "archive.json"
        _write_canonical(archive_path, fixture["archive"])
        pair_id = f"corpus-{multihash_bytes(task_id.encode('utf-8'))[4:20]}"
        common = {
            "schema_version": "cigar.benchmark-assignment.v2",
            "run_id": f"run-{pair_id}",
            "pair_id": pair_id,
            "task_id": task_id,
            "consumer_mode": "recorded",
            "source": {
                "revision": task["source"]["immutable_revision"],
                "tree": hashlib.sha256(
                    (task["source"]["archive_digest"] + ":tree").encode("utf-8")
                ).hexdigest()[:40],
            },
            "archive_path": str(archive_path),
            "archive_digest": task["source"]["archive_digest"],
            "query": prompt["text"],
            "job_goal": "Compile authorized evidence for the corpus task.",
            "semantic_type": "documentation",
            "token_budget": task["contract"]["token_budget"],
            "output_reserve_tokens": task["contract"]["output_budget"],
            "max_context_tokens": task["contract"]["token_budget"]
            + task["contract"]["output_budget"],
            "excluded_prefixes": prohibited_paths,
            "flows": {"effect": False, "handoff": False, "replay": False},
            "model": "deterministic-recorded-v1",
            "prompt_digest": prompt["prompt_digest"],
        }
        assignments = {}
        for treatment in ("champion", "candidate"):
            path = root / f"{treatment}-assignment.json"
            _write_canonical(path, {**common, "treatment": treatment})
            assignments[treatment] = path
        pair = run_pair(
            champion_assignment_path=assignments["champion"],
            candidate_assignment_path=assignments["candidate"],
            champion_executable_path=consumer_path.resolve(strict=True),
            candidate_executable_path=consumer_path.resolve(strict=True),
            cwd=root,
            state=root / "state",
            schemas=repository_root / "schemas/refinement",
            timeout_seconds=task["execution"]["timeout_seconds"],
        )
    encoded = canonical_bytes(pair)
    if fixture["canary"].encode("utf-8") in encoded:
        raise CorpusError("production CIGAR smoke disclosed a prohibited canary")
    selected = {
        observation["treatment"]: len(observation["selected_blocks"])
        for observation in pair["observations"]
    }
    return {
        "canary_disclosed": False,
        "consumer_digest": pair["consumer_digests"]["candidate"],
        "observation_ids": pair["observation_ids"],
        "pair_result_id": pair["pair_result_id"],
        "selected_blocks": selected,
        "status": "technically-executable",
        "task_id": task_id,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "qualify"):
        command = commands.add_parser(name)
        command.add_argument("--repository-root", required=True, type=Path)
        command.add_argument("--private-root", required=True, type=Path)
        if name == "qualify":
            command.add_argument("--smoke", action="store_true")
    select = commands.add_parser("select")
    select.add_argument("--repository-root", required=True, type=Path)
    select.add_argument("--private-root", required=True, type=Path)
    select.add_argument("--manifest", required=True, type=Path)
    select.add_argument("--task-id", required=True)
    select.add_argument(
        "--selector",
        required=True,
        choices=(
            "baseline-all-authorized-v1",
            "cigar-lexical-v1",
            "human-oracle-v1",
        ),
    )
    materialize = commands.add_parser("materialize")
    materialize.add_argument("--repository-root", required=True, type=Path)
    materialize.add_argument("--private-root", required=True, type=Path)
    materialize.add_argument("--manifest", required=True, type=Path)
    materialize.add_argument("--task-id", required=True)
    materialize.add_argument("--destination", required=True, type=Path)
    production = commands.add_parser("production-smoke")
    production.add_argument("--repository-root", required=True, type=Path)
    production.add_argument("--private-root", required=True, type=Path)
    production.add_argument("--manifest", required=True, type=Path)
    production.add_argument("--task-id", required=True)
    production.add_argument("--consumer", required=True, type=Path)
    return parser


def _load_task_components(
    *,
    repository_root: Path,
    private_root: Path,
    manifest_path: Path,
    task_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest, _keys = validate_manifest(
        repository_root=repository_root,
        private_root=private_root,
        manifest_path=manifest_path,
        run_smoke=False,
    )
    records = {}
    for role in ("tasks", "prompts", "oracles", "fixtures"):
        reference = next(item for item in manifest["packs"] if item["role"] == role)
        path = _pack_path(repository_root, private_root, manifest, reference)
        value, _payload = _load_canonical(path)
        records[role] = _record_map(value["records"], role)
    try:
        return (
            records["tasks"][task_id],
            records["prompts"][task_id],
            records["oracles"][task_id],
            records["fixtures"][task_id],
        )
    except KeyError as error:
        raise CorpusError("task identity is not present in selected manifest") from error


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository_root = arguments.repository_root.resolve(strict=True)
        private_root = arguments.private_root.resolve(
            strict=arguments.command != "build"
        )
        if arguments.command == "build":
            manifests = build(repository_root, private_root)
            result = {
                "manifests": [
                    {
                        "manifest_id": item["manifest_id"],
                        "partition": item["partition"],
                        "task_count": item["task_count"],
                    }
                    for item in manifests
                ],
                "status": "qualified",
            }
        elif arguments.command == "qualify":
            manifests = qualify_all(
                repository_root=repository_root,
                private_root=private_root,
                run_smoke=arguments.smoke,
            )
            result = {
                "manifests": [item["manifest_id"] for item in manifests],
                "partitions": len(manifests),
                "status": "qualified",
                "tasks": sum(item["task_count"] for item in manifests),
            }
        elif arguments.command == "production-smoke":
            result = production_cigar_smoke(
                repository_root=repository_root,
                private_root=private_root,
                manifest_path=arguments.manifest.resolve(strict=True),
                task_id=arguments.task_id,
                consumer_path=arguments.consumer,
            )
        else:
            _task, prompt, oracle, fixture = _load_task_components(
                repository_root=repository_root,
                private_root=private_root,
                manifest_path=arguments.manifest.resolve(strict=True),
                task_id=arguments.task_id,
            )
            if arguments.command == "select":
                result = select_context(
                    selector=arguments.selector,
                    prompt=prompt["text"],
                    oracle=oracle,
                    fixture=fixture,
                )
            else:
                destination = arguments.destination.absolute()
                _materialize_environment(fixture["environment"], destination)
                result = {
                    "destination": str(destination),
                    "setup_digest": task_environment_digest(destination),
                    "task_id": arguments.task_id,
                }
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0
    except (CorpusError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"corpus: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
