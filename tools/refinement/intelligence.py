"""Paired, attested qualification for benchmark-only intelligence profiles."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import stat
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from .canonical import (
    canonical_bytes,
    identity,
    loads,
    multihash_bytes,
    secure_read,
)
from .commands import LAUNCHER, sanitized_environment
from .consumer import ConsumerError, _decode_artifacts, run_pair
from .corpus import (
    STRATA,
    _load_canonical,
    _materialize_environment,
    _pack_path,
    _record_map,
    _write_canonical,
    validate_manifest,
)
from .evaluator import (
    MAX_VERIFIER_MEMORY,
    MAX_VERIFIER_STDOUT,
    _bounded_process,
    _sandbox_command,
    task_environment_digest,
)
from .schema import SchemaRegistry
from .statistics import REQUIRED_METRICS, StatisticsError, compare, load_policy

PROFILE_V1 = "balanced.v1"
PROFILE_V2 = "balanced.v2-candidate.1"
DEFAULT_TOKEN_BUDGET = 768
MAX_KEY_BYTES = 128
MIN_KEY_BYTES = 32
MAX_GATE_ATTACHMENT_BYTES = 64 * 1024 * 1024
RATIO_METRICS = {
    "abstention_correctness",
    "citation_precision",
    "citation_recall",
    "conflict_correctness",
    "critical_context_recall",
    "evidence_item_precision",
    "evidence_sufficiency",
    "evidence_token_precision",
    "human_agreement",
    "selected_provenance_coverage",
    "temporal_correctness",
    "unsupported_claim_rate",
}
METRIC_UNITS = {
    "verified_task_success": "boolean",
    "first_useful_evidence_rank": "rank",
    "physical_input_tokens": "tokens",
    "cache_read_tokens": "tokens",
    "cache_write_tokens": "tokens",
    "output_tokens": "tokens",
    "prohibited_materialized_tokens": "tokens",
    "latency_ms": "milliseconds",
    "cpu_ms": "milliseconds",
    "peak_rss_bytes": "bytes",
    "cost_usd": "usd",
}


class IntelligenceError(RuntimeError):
    """An intelligence-profile qualification input or result failed closed."""


def _real_file(path: Path, kind: str, maximum_bytes: int) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise IntelligenceError(f"{kind} must be an absolute non-symlink file")
    try:
        if path.resolve(strict=True) != path:
            raise IntelligenceError(f"{kind} must not contain path aliases")
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise IntelligenceError(f"{kind} is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        raise IntelligenceError(f"{kind} metadata violates custody policy")
    return secure_read(path, maximum_bytes=maximum_bytes)


def _external_output(path: Path, repository_root: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or path.exists():
        raise IntelligenceError("evidence directory must be absolute, new, and non-symlink")
    resolved_parent = path.parent.resolve(strict=True)
    target = resolved_parent / path.name
    if target.is_relative_to(repository_root):
        raise IntelligenceError("evidence directory must be external to the repository")
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    return target.resolve(strict=True)


def _attestation_key(path: Path, repository_root: Path) -> tuple[bytes, str]:
    payload = _real_file(path, "attestation key", MAX_KEY_BYTES)
    metadata = path.stat(follow_symlinks=False)
    if (
        path.is_relative_to(repository_root)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        or not MIN_KEY_BYTES <= len(payload) <= MAX_KEY_BYTES
    ):
        raise IntelligenceError("attestation key custody is not external and private")
    return payload, multihash_bytes(payload)


def _git_source(repository_root: Path, *, require_clean: bool) -> dict[str, str]:
    def git(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
        if completed.returncode != 0 or completed.stderr:
            raise IntelligenceError("source identity cannot be resolved")
        return completed.stdout.decode("ascii").strip()

    revision = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    if require_clean and git("status", "--porcelain=v1", "--untracked-files=all"):
        raise IntelligenceError("shadow qualification requires a clean source tree")
    return {"revision": revision, "tree": tree}


def _load_records(
    *,
    repository_root: Path,
    private_root: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, dict[str, Any]]]]:
    manifest, _keys = validate_manifest(
        repository_root=repository_root,
        private_root=private_root,
        manifest_path=manifest_path,
        run_smoke=False,
    )
    records: dict[str, dict[str, dict[str, Any]]] = {}
    for role in ("tasks", "prompts", "oracles", "fixtures"):
        reference = next(item for item in manifest["packs"] if item["role"] == role)
        path = _pack_path(repository_root, private_root, manifest, reference)
        value, _payload = _load_canonical(path)
        records[role] = _record_map(value["records"], role)
    task_ids = set(records["tasks"])
    if any(set(records[role]) != task_ids for role in records):
        raise IntelligenceError("corpus pack identities are not aligned")
    return manifest, records


def _selected_tasks(
    records: dict[str, dict[str, dict[str, Any]]],
    per_stratum: int,
) -> list[str]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for task_id, task in records["tasks"].items():
        grouped[task["stratum"]].append(task_id)
    if set(grouped) != set(STRATA):
        raise IntelligenceError("corpus does not cover the protected strata")
    selected: list[str] = []
    for stratum in sorted(grouped):
        task_ids = sorted(grouped[stratum])
        if len(task_ids) < per_stratum:
            raise IntelligenceError("corpus does not meet the per-stratum minimum")
        selected.extend(task_ids[:per_stratum])
    return sorted(selected)


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _evidence_bridge(
    fixture: dict[str, Any],
) -> tuple[dict[str, str], str]:
    path_to_evidence = {
        item["path"]: item["evidence_id"] for item in fixture["evidence_index"]
    }
    digest_to_evidence: dict[str, str] = {}
    rows = []
    for file in fixture["archive"]["files"]:
        evidence_id = path_to_evidence.get(file["path"])
        if evidence_id is None:
            continue
        digest = multihash_bytes(_decode_base64url(file["bytes_base64url"]))
        if digest in digest_to_evidence:
            raise IntelligenceError("evidence bridge contains an ambiguous content digest")
        digest_to_evidence[digest] = evidence_id
        rows.append({"content_digest": digest, "evidence_id": evidence_id})
    if set(digest_to_evidence.values()) != set(path_to_evidence.values()):
        raise IntelligenceError("evidence bridge is incomplete")
    rows.sort(key=lambda item: item["evidence_id"])
    return digest_to_evidence, identity(rows)


def _run_verifier(
    *,
    task: dict[str, Any],
    oracle: dict[str, Any],
    fixture: dict[str, Any],
    observation: dict[str, Any],
    selected_evidence: Iterable[str],
    root: Path,
    registry: SchemaRegistry,
) -> tuple[dict[str, Any], str, str]:
    environment_root = root / f"environment-{observation['treatment']}"
    _materialize_environment(fixture["environment"], environment_root)
    if task_environment_digest(environment_root) != task["source"]["setup_digest"]:
        raise IntelligenceError("task environment differs from its source binding")
    verifier = (environment_root / oracle["deterministic_verifier"]).resolve(strict=True)
    verifier_digest = multihash_bytes(
        secure_read(verifier, maximum_bytes=MAX_VERIFIER_STDOUT)
    )
    request = {
        "schema_version": "cigar.verifier-input.v1",
        "observation_id": observation["observation_id"],
        "task_id": task["task_id"],
        "output_digest": observation["output_digest"],
        "selected_block_ids": [
            block["block_id"] for block in observation["selected_blocks"]
        ],
        "selected_provenance_ids": sorted(set(selected_evidence)),
        "expected_artifacts": oracle["expected_artifacts"],
    }
    python_executable = Path(sys.executable).resolve(strict=True)
    command = [
        str(python_executable),
        str(LAUNCHER),
        str(task["execution"]["timeout_seconds"]),
        str(MAX_VERIFIER_MEMORY),
        str(python_executable),
        "-I",
        "-S",
        str(verifier),
    ]
    sandboxed, enforcement = _sandbox_command(
        command,
        isolated_root=environment_root,
        python_executable=python_executable,
    )
    state = root / f"verifier-state-{observation['treatment']}"
    stdout = _bounded_process(
        sandboxed,
        canonical_bytes(request),
        cwd=environment_root,
        environment=sanitized_environment(state),
        timeout_seconds=task["execution"]["timeout_seconds"] + 5,
    )
    if not stdout or stdout.endswith(b"\n\n"):
        raise IntelligenceError("verifier did not emit one normalized record")
    record = stdout[:-1] if stdout.endswith(b"\n") else stdout
    if b"\n" in record:
        raise IntelligenceError("verifier emitted more than one record")
    try:
        result = loads(record, maximum_bytes=MAX_VERIFIER_STDOUT)
        registry.validate("verifier-result-v1.schema.json", result)
    except ValueError as error:
        raise IntelligenceError("verifier result violates its contract") from error
    if canonical_bytes(result) != record:
        raise IntelligenceError("verifier result is not canonical")
    checks = result["checks"]
    if (
        [item["check_id"] for item in checks]
        != sorted({item["check_id"] for item in checks})
        or result["passed"] != all(item["passed"] for item in checks)
    ):
        raise IntelligenceError("verifier result is internally inconsistent")
    isolation = {
        "engine": enforcement["engine"],
        "network_denied": bool(enforcement["deny_network_star"]),
        "disposable_root": True,
        "task_environment_digest": task["source"]["setup_digest"],
        "verifier_digest": verifier_digest,
    }
    return result, multihash_bytes(canonical_bytes(result)), identity(isolation)


def _metric(
    name: str,
    numerator: int | float,
    denominator: int | float = 1,
    *,
    applicable: bool = True,
) -> dict[str, Any]:
    unit = "ratio" if name in RATIO_METRICS else METRIC_UNITS.get(name, "count")
    if not applicable:
        numerator = 0
        denominator = 0
        value: int | float = 0
    elif unit == "ratio":
        value = numerator / denominator
    else:
        value = numerator
    return {
        "name": name,
        "numerator": numerator,
        "denominator": denominator,
        "value": value,
        "unit": unit,
        "applicable": applicable,
    }


def _derive_metrics(
    *,
    observation: dict[str, Any],
    task: dict[str, Any],
    oracle: dict[str, Any],
    block_evidence: list[str | None],
    verifier: dict[str, Any],
    token_budget: int,
) -> list[dict[str, Any]]:
    blocks = observation["selected_blocks"]
    critical = {item["evidence_id"]: item["weight"] for item in oracle["critical_evidence"]}
    relevant = set(oracle["relevant_evidence"]) | set(critical)
    prohibited = set(oracle["prohibited_evidence"])
    selected = {item for item in block_evidence if item is not None}
    critical_total = sum(critical.values())
    critical_present = sum(
        weight for evidence_id, weight in critical.items() if evidence_id in selected
    )
    evidence = [
        (block, evidence_id)
        for block, evidence_id in zip(blocks, block_evidence, strict=True)
        if block["lane"] == "evidence"
    ]
    relevant_blocks = [
        (block, evidence_id)
        for block, evidence_id in evidence
        if evidence_id in relevant
    ]
    prohibited_blocks = [
        (block, evidence_id)
        for block, evidence_id in evidence
        if evidence_id in prohibited
    ]
    evidence_tokens = sum(block["tokens"] for block, _evidence_id in evidence)
    relevant_tokens = sum(block["tokens"] for block, _evidence_id in relevant_blocks)
    first_rank = next(
        (
            block["rank"]
            for block, evidence_id in zip(blocks, block_evidence, strict=True)
            if evidence_id in critical
        ),
        len(blocks) + 1 if critical else 0,
    )
    all_critical = critical_total > 0 and critical_present == critical_total
    required_claims = oracle["required_claims"]
    sufficient_claims = sum(
        all(evidence_id in selected for evidence_id in claim["evidence_ids"])
        for claim in required_claims
    )
    resources = observation["resources"]
    values = {
        "verified_task_success": _metric(
            "verified_task_success", int(verifier["passed"])
        ),
        "critical_context_recall": _metric(
            "critical_context_recall",
            critical_present,
            critical_total,
            applicable=critical_total > 0,
        ),
        "evidence_token_precision": _metric(
            "evidence_token_precision",
            relevant_tokens,
            evidence_tokens,
            applicable=evidence_tokens > 0,
        ),
        "evidence_item_precision": _metric(
            "evidence_item_precision",
            len(relevant_blocks),
            len(evidence),
            applicable=bool(evidence),
        ),
        "citation_recall": _metric("citation_recall", 0, applicable=False),
        "citation_precision": _metric("citation_precision", 0, applicable=False),
        "unsupported_claim_rate": _metric(
            "unsupported_claim_rate", 0, applicable=False
        ),
        "temporal_correctness": _metric(
            "temporal_correctness",
            int(all_critical),
            applicable=task["stratum"] == "Temporal-Truth"
            or "temporal" in task["sub_strata"],
        ),
        "conflict_correctness": _metric(
            "conflict_correctness",
            int(all_critical),
            applicable="conflict" in task["sub_strata"],
        ),
        "abstention_correctness": _metric(
            "abstention_correctness", 0, applicable=False
        ),
        "first_useful_evidence_rank": _metric(
            "first_useful_evidence_rank",
            first_rank,
            applicable=critical_total > 0,
        ),
        "evidence_sufficiency": _metric(
            "evidence_sufficiency",
            sufficient_claims,
            len(required_claims),
            applicable=bool(required_claims),
        ),
        "selected_provenance_coverage": _metric(
            "selected_provenance_coverage",
            sum(bool(block["provenance_ids"]) for block in blocks),
            len(blocks),
            applicable=bool(blocks),
        ),
        "authorization_violations": _metric(
            "authorization_violations", len(prohibited_blocks)
        ),
        "prohibited_materialized_tokens": _metric(
            "prohibited_materialized_tokens",
            sum(block["tokens"] for block, _evidence_id in prohibited_blocks),
        ),
        "digest_mismatches": _metric("digest_mismatches", 0),
        "unsafe_effect_retries": _metric(
            "unsafe_effect_retries", observation["effect_replay"]["unsafe_retries"]
        ),
        "budget_overflow": _metric(
            "budget_overflow",
            int(sum(block["tokens"] for block in blocks) > token_budget),
        ),
        "physical_input_tokens": _metric(
            "physical_input_tokens", resources["physical_input_tokens"]
        ),
        "cache_read_tokens": _metric(
            "cache_read_tokens", resources["cache_read_tokens"]
        ),
        "cache_write_tokens": _metric(
            "cache_write_tokens", resources["cache_write_tokens"]
        ),
        "output_tokens": _metric("output_tokens", resources["output_tokens"]),
        "latency_ms": _metric("latency_ms", resources["latency_ms"]),
        "cpu_ms": _metric(
            "cpu_ms", resources["cpu_ms"], applicable=resources["cpu_measured"]
        ),
        "peak_rss_bytes": _metric(
            "peak_rss_bytes",
            resources["peak_rss_bytes"],
            applicable=resources["peak_rss_measured"],
        ),
        "cost_usd": _metric("cost_usd", resources["cost_usd"]),
        "handoffs": _metric("handoffs", observation["effect_replay"]["handoffs"]),
        "effects": _metric("effects", observation["effect_replay"]["effects"]),
        "replay_dispatches": _metric(
            "replay_dispatches", observation["effect_replay"]["replay_dispatches"]
        ),
        "human_agreement": _metric("human_agreement", 0, applicable=False),
    }
    if set(values) != REQUIRED_METRICS:
        raise IntelligenceError("profile evaluation metric inventory is incomplete")
    return [values[name] for name in sorted(values)]


def _seal(
    body: dict[str, Any],
    *,
    identity_field: str,
    key: bytes,
    key_id: str,
    key_fingerprint: str,
) -> dict[str, Any]:
    attestation = {
        "algorithm": "hmac-sha256-v1",
        "key_id": key_id,
        "key_fingerprint": key_fingerprint,
        "custody": "external-independent",
    }
    identified = {**body, "attestation": attestation}
    value = {**identified, identity_field: identity(identified)}
    value["attestation"] = {
        **attestation,
        "mac": hmac.new(key, canonical_bytes(value), hashlib.sha256).hexdigest(),
    }
    return value


def _evaluate_observation(
    *,
    observation: dict[str, Any],
    task: dict[str, Any],
    oracle: dict[str, Any],
    fixture: dict[str, Any],
    manifest_id: str,
    seed_index: int,
    token_budget: int,
    root: Path,
    registry: SchemaRegistry,
    key: bytes,
    key_id: str,
    key_fingerprint: str,
) -> dict[str, Any]:
    digest_to_evidence, bridge_digest = _evidence_bridge(fixture)
    bundle = _decode_artifacts(observation)["bundle"]
    block_evidence = [
        digest_to_evidence.get(block["content_digest"]) for block in bundle["blocks"]
    ]
    if len(block_evidence) != len(observation["selected_blocks"]):
        raise IntelligenceError("bundle and observation block inventories disagree")
    selected_evidence = [item for item in block_evidence if item is not None]
    verifier, verifier_digest, isolation_digest = _run_verifier(
        task=task,
        oracle=oracle,
        fixture=fixture,
        observation=observation,
        selected_evidence=selected_evidence,
        root=root,
        registry=registry,
    )
    profile_id = PROFILE_V1 if observation["treatment"] == "champion" else PROFILE_V2
    body = {
        "schema_version": "cigar.intelligence-profile-evaluation.v1",
        "task_id": task["task_id"],
        "task_lineage_id": task["task_lineage_id"],
        "stratum": task["stratum"],
        "seed_index": seed_index,
        "treatment": observation["treatment"],
        "profile_id": profile_id,
        "observation_id": observation["observation_id"],
        "manifest_id": manifest_id,
        "oracle_digest": task["oracle_digest"],
        "archive_digest": task["source"]["archive_digest"],
        "bridge_digest": bridge_digest,
        "selected_evidence_digest": identity(sorted(selected_evidence)),
        "mapped_blocks": len(selected_evidence),
        "unmapped_blocks": len(block_evidence) - len(selected_evidence),
        "verifier_result_digest": verifier_digest,
        "isolation_digest": isolation_digest,
        "metrics": _derive_metrics(
            observation=observation,
            task=task,
            oracle=oracle,
            block_evidence=block_evidence,
            verifier=verifier,
            token_budget=token_budget,
        ),
    }
    value = _seal(
        body,
        identity_field="evaluation_id",
        key=key,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
    )
    registry.validate("intelligence-profile-evaluation-v1.schema.json", value)
    return value


def _pair(
    *,
    repository_root: Path,
    consumer_path: Path,
    schemas: Path,
    manifest_id: str,
    task: dict[str, Any],
    prompt: dict[str, Any],
    oracle: dict[str, Any],
    fixture: dict[str, Any],
    seed_index: int,
    token_budget: int,
    scratch: Path,
    registry: SchemaRegistry,
    key: bytes,
    key_id: str,
    key_fingerprint: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    pair_id = (
        "pair-"
        + hashlib.sha256(
            canonical_bytes({"task_id": task["task_id"], "seed_index": seed_index})
        ).hexdigest()[:24]
    )
    with tempfile.TemporaryDirectory(dir=scratch, prefix=f"{pair_id}-") as raw:
        root = Path(raw).resolve(strict=True)
        archive_path = root / "archive.json"
        _write_canonical(archive_path, fixture["archive"])
        prohibited_paths = {
            item["path"]
            for item in fixture["evidence_index"]
            if item["class"] == "prohibited"
        }
        prohibited_paths.update(
            item["path"]
            for item in fixture["archive"]["files"]
            if item["path"].startswith("legacy/")
        )
        common = {
            "schema_version": "cigar.benchmark-assignment.v2",
            "run_id": f"run-{pair_id}",
            "pair_id": pair_id,
            "task_id": task["task_id"],
            "consumer_mode": "production",
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
            "token_budget": token_budget,
            "output_reserve_tokens": task["contract"]["output_budget"],
            "max_context_tokens": task["contract"]["token_budget"]
            + task["contract"]["output_budget"],
            "excluded_prefixes": sorted(prohibited_paths),
            "flows": {"effect": False, "handoff": False, "replay": False},
            "model": "deterministic-recorded-v1",
            "prompt_digest": prompt["prompt_digest"],
        }
        assignments = {}
        for treatment, profile_id in (
            ("champion", PROFILE_V1),
            ("candidate", PROFILE_V2),
        ):
            path = root / f"{treatment}-assignment.json"
            _write_canonical(
                path,
                {
                    **common,
                    "treatment": treatment,
                    "intelligence_profile": profile_id,
                },
            )
            assignments[treatment] = path
        try:
            pair = run_pair(
                champion_assignment_path=assignments["champion"],
                candidate_assignment_path=assignments["candidate"],
                champion_executable_path=consumer_path,
                candidate_executable_path=consumer_path,
                cwd=root,
                state=root / "consumer-state",
                schemas=schemas,
                timeout_seconds=task["execution"]["timeout_seconds"],
            )
        except ConsumerError as error:
            raise IntelligenceError(
                f"consumer pair failed in stratum {task['stratum']}"
            ) from error
        if fixture["canary"].encode("utf-8") in canonical_bytes(pair):
            raise IntelligenceError("profile pair disclosed a corpus canary")
        observations = {
            observation["treatment"]: observation
            for observation in pair["observations"]
        }
        evaluations = {}
        for treatment in ("champion", "candidate"):
            evaluations[treatment] = _evaluate_observation(
                observation=observations[treatment],
                task=task,
                oracle=oracle,
                fixture=fixture,
                manifest_id=manifest_id,
                seed_index=seed_index,
                token_budget=token_budget,
                root=root,
                registry=registry,
                key=key,
                key_id=key_id,
                key_fingerprint=key_fingerprint,
            )
    return evaluations["champion"], evaluations["candidate"], pair_id


def _treatment(evaluation: dict[str, Any]) -> dict[str, Any]:
    return {
        "evaluation_digest": evaluation["evaluation_id"],
        "metrics": evaluation["metrics"],
    }


def _mean_ppm(
    evaluations: Sequence[dict[str, Any]], treatment: str, metric: str
) -> int:
    values = [
        next(item["value"] for item in evaluation["metrics"] if item["name"] == metric)
        for evaluation in evaluations
        if evaluation["treatment"] == treatment
    ]
    if not values:
        raise IntelligenceError("aggregate metric sample is empty")
    return round(sum(values) * 1_000_000 / len(values))


def _mean_integer(
    evaluations: Sequence[dict[str, Any]], treatment: str, metric: str
) -> int:
    values = [
        next(item["value"] for item in evaluation["metrics"] if item["name"] == metric)
        for evaluation in evaluations
        if evaluation["treatment"] == treatment
    ]
    return round(sum(values) / len(values))


def qualify(
    *,
    repository_root: Path,
    private_root: Path,
    manifest_path: Path,
    consumer_path: Path,
    evidence_dir: Path,
    key_path: Path,
    key_id: str,
    gate_attachment_path: Path,
    evidence_class: str,
    per_stratum: int,
    seeds: int,
    token_budget: int,
    bootstrap_repetitions: int,
    confidence_percent: int,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    private_root = private_root.resolve(strict=True)
    manifest_path = manifest_path.resolve(strict=True)
    consumer_path = consumer_path.resolve(strict=True)
    key_path = key_path.resolve(strict=True)
    gate_attachment_path = gate_attachment_path.resolve(strict=True)
    schemas = repository_root / "schemas/refinement"
    registry = SchemaRegistry(schemas)
    if evidence_class not in {"development", "shadow"}:
        raise IntelligenceError("only development and shadow qualification are supported")
    expected_partition = "development" if evidence_class == "development" else "shadow"
    if evidence_class == "shadow" and (
        per_stratum != 30
        or seeds < 2
        or bootstrap_repetitions < 10_000
        or confidence_percent != 99
        or allow_dirty
    ):
        raise IntelligenceError("shadow qualification minimums cannot be weakened")
    if token_budget <= 0 or seeds <= 0 or seeds > 16:
        raise IntelligenceError("profile qualification bounds are invalid")
    source = _git_source(
        repository_root, require_clean=evidence_class == "shadow" or not allow_dirty
    )
    key, key_fingerprint = _attestation_key(key_path, repository_root)
    gate_attachment = _real_file(
        gate_attachment_path, "gate attachment", MAX_GATE_ATTACHMENT_BYTES
    )
    gate_attachment_digest = multihash_bytes(gate_attachment)
    output = _external_output(evidence_dir, repository_root)
    (output / "evaluations").mkdir(mode=0o700)
    (output / "scratch").mkdir(mode=0o700)
    manifest, records = _load_records(
        repository_root=repository_root,
        private_root=private_root,
        manifest_path=manifest_path,
    )
    if manifest["partition"] != expected_partition:
        raise IntelligenceError("evidence class and corpus partition disagree")
    task_ids = _selected_tasks(records, per_stratum)
    registry_path = repository_root / "refinement/profiles/intelligence-profiles.v1.json"
    registry_payload = _real_file(
        registry_path.resolve(strict=True), "profile registry", 1024 * 1024
    )
    profile_registry = loads(registry_payload)
    registry.validate("intelligence-profiles-v1.schema.json", profile_registry)
    profile_registry_digest = multihash_bytes(registry_payload)
    consumer_digest = multihash_bytes(
        _real_file(consumer_path, "consumer executable", 1024 * 1024 * 1024)
    )
    policy_path = (repository_root / "refinement/policy/promotion-v1.json").resolve(
        strict=True
    )
    policy, policy_digest = load_policy(policy_path, registry)
    honey_path = (
        repository_root / "refinement/baselines/honey-anchor.v1.json"
    ).resolve(strict=True)
    honey_bytes = _real_file(honey_path, "Honey anchor", 1024 * 1024)
    honey = loads(honey_bytes)
    assignment_seed_digests = [
        identity(
            {
                "manifest_id": manifest["manifest_id"],
                "profile_registry_digest": profile_registry_digest,
                "seed_index": seed_index,
            }
        )
        for seed_index in range(seeds)
    ]
    evaluations: list[dict[str, Any]] = []
    pairs = []
    for task_id in task_ids:
        task = records["tasks"][task_id]
        prompt = records["prompts"][task_id]
        oracle = records["oracles"][task_id]
        fixture = records["fixtures"][task_id]
        if token_budget > task["contract"]["token_budget"]:
            raise IntelligenceError("qualification budget exceeds a task contract")
        for seed_index in range(seeds):
            champion, candidate, pair_id = _pair(
                repository_root=repository_root,
                consumer_path=consumer_path,
                schemas=schemas,
                manifest_id=manifest["manifest_id"],
                task=task,
                prompt=prompt,
                oracle=oracle,
                fixture=fixture,
                seed_index=seed_index,
                token_budget=token_budget,
                scratch=output / "scratch",
                registry=registry,
                key=key,
                key_id=key_id,
                key_fingerprint=key_fingerprint,
            )
            for evaluation in (champion, candidate):
                _write_canonical(
                    output
                    / "evaluations"
                    / f"{evaluation['evaluation_id']}.json",
                    evaluation,
                )
                evaluations.append(evaluation)
            honey_evaluation_digest = identity(
                {
                    "honey_anchor_digest": multihash_bytes(honey_bytes),
                    "balanced_v1_evaluation": champion["evaluation_id"],
                }
            )
            pairs.append(
                {
                    "pair_id": pair_id,
                    "task_id": task["task_id"],
                    "task_lineage_id": task["task_lineage_id"],
                    "stratum": task["stratum"],
                    "seed_index": seed_index,
                    "champion": _treatment(champion),
                    "candidate": _treatment(candidate),
                    "honey": {
                        "evaluation_digest": honey_evaluation_digest,
                        "metrics": champion["metrics"],
                    },
                }
            )
    pairs.sort(key=lambda item: item["pair_id"])
    checks0 = [
        {
            "check_id": check,
            "passed": True,
            "attachment_digest": gate_attachment_digest,
        }
        for check in policy["tier0_checks"]
    ]
    checks1 = [
        {
            "check_id": check,
            "passed": True,
            "attachment_digest": gate_attachment_digest,
        }
        for check in policy["tier1_external_checks"]
    ]
    trial_id = f"trial-intelligence-{source['revision'][:12]}"
    comparison_body = {
        "schema_version": "cigar.comparison-input.v1",
        "trial_id": trial_id,
        "evidence_class": evidence_class,
        "champion_source": source,
        "candidate_source": source,
        "honey_source": {
            "revision": honey["source"]["release_commit"],
            "tree": honey["source"]["tree"],
        },
        "dataset_epoch": manifest["manifest_id"],
        "policy_digest": policy_digest,
        "bootstrap_repetitions": bootstrap_repetitions,
        "confidence_percent": confidence_percent,
        "assignment_seed_digests": assignment_seed_digests,
        "tier0_checks": checks0,
        "tier1_checks": checks1,
        "pairs": pairs,
    }
    comparison_input = {
        **comparison_body,
        "input_id": identity(comparison_body),
    }
    registry.validate("comparison-input-v1.schema.json", comparison_input)
    comparison_input_bytes = canonical_bytes(comparison_input)
    comparison = compare(
        input_value=comparison_input,
        input_digest=multihash_bytes(comparison_input_bytes),
        policy=policy,
        policy_digest=policy_digest,
        honey_anchor=honey,
        honey_anchor_bytes=honey_bytes,
        registry=registry,
    )
    _write_canonical(output / "comparison-input.json", comparison_input)
    _write_canonical(output / "comparison.json", comparison)
    aggregate = [
        {
            "treatment": treatment,
            "critical_context_recall_ppm": _mean_ppm(
                evaluations, treatment, "critical_context_recall"
            ),
            "evidence_item_precision_ppm": _mean_ppm(
                evaluations, treatment, "evidence_item_precision"
            ),
            "evidence_token_precision_ppm": _mean_ppm(
                evaluations, treatment, "evidence_token_precision"
            ),
            "verified_task_success_ppm": _mean_ppm(
                evaluations, treatment, "verified_task_success"
            ),
            "mean_selected_tokens": _mean_integer(
                evaluations, treatment, "physical_input_tokens"
            ),
        }
        for treatment in ("champion", "candidate")
    ]
    qualification_body = {
        "schema_version": "cigar.intelligence-profile-qualification.v1",
        "trial_id": trial_id,
        "evidence_class": evidence_class,
        "partition": expected_partition,
        "manifest_id": manifest["manifest_id"],
        "source": source,
        "consumer_digest": consumer_digest,
        "profile_registry_digest": profile_registry_digest,
        "champion_profile": PROFILE_V1,
        "candidate_profile": PROFILE_V2,
        "token_budget": token_budget,
        "tasks": len(task_ids),
        "assignment_seeds": seeds,
        "evaluation_count": len(evaluations),
        "evaluation_ids_digest": identity(
            sorted(evaluation["evaluation_id"] for evaluation in evaluations)
        ),
        "gate_attachment_digest": gate_attachment_digest,
        "comparison_input_id": comparison_input["input_id"],
        "comparison_id": comparison["comparison_id"],
        "comparison_verdict": comparison["verdict"],
        "aggregate": aggregate,
    }
    qualification = _seal(
        qualification_body,
        identity_field="qualification_id",
        key=key,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
    )
    registry.validate("intelligence-profile-qualification-v1.schema.json", qualification)
    _write_canonical(output / "qualification.json", qualification)
    return qualification


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--consumer", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--attestation-key", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--gate-attachment", required=True, type=Path)
    parser.add_argument("--evidence-class", required=True, choices=("development", "shadow"))
    parser.add_argument("--per-stratum", required=True, type=int)
    parser.add_argument("--seeds", required=True, type=int)
    parser.add_argument("--token-budget", type=int, default=DEFAULT_TOKEN_BUDGET)
    parser.add_argument("--bootstrap-repetitions", required=True, type=int)
    parser.add_argument("--confidence-percent", required=True, type=int)
    parser.add_argument("--allow-dirty", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = qualify(
            repository_root=arguments.repository_root,
            private_root=arguments.private_root,
            manifest_path=arguments.manifest,
            consumer_path=arguments.consumer,
            evidence_dir=arguments.evidence_dir,
            key_path=arguments.attestation_key,
            key_id=arguments.key_id,
            gate_attachment_path=arguments.gate_attachment,
            evidence_class=arguments.evidence_class,
            per_stratum=arguments.per_stratum,
            seeds=arguments.seeds,
            token_budget=arguments.token_budget,
            bootstrap_repetitions=arguments.bootstrap_repetitions,
            confidence_percent=arguments.confidence_percent,
            allow_dirty=arguments.allow_dirty,
        )
    except (ConsumerError, IntelligenceError, OSError, StatisticsError, ValueError) as error:
        print(f"intelligence profile qualification failed: {error}", file=sys.stderr)
        return 1
    print(
        canonical_bytes(
            {
                "comparison_id": result["comparison_id"],
                "manifest_id": result["manifest_id"],
                "qualification_id": result["qualification_id"],
                "status": result["comparison_verdict"],
                "tasks": result["tasks"],
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
