from __future__ import annotations

import copy
import hashlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement import canonical
from tools.refinement.consumer import run_pair
from tools.refinement.evaluator import (
    EvaluatorError,
    evaluate,
    replay,
    task_environment_digest,
    verify_attestation,
)
from tools.refinement.schema import SchemaError, SchemaRegistry
from tools.refinement.tests.test_r03_consumer import FAKE_CONSUMER

SCHEMAS = ROOT / "schemas" / "refinement"
GIT = "a" * 40
MH = "1220" + "1" * 64
VERSION = canonical.multihash_bytes(b"version")


VERIFIER = r"""#!/usr/bin/env python3
import hashlib
import json
import pathlib
import socket
import sys

def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()

def multihash(payload):
    return "1220" + hashlib.sha256(payload).hexdigest()

request = json.loads(sys.stdin.buffer.read())
try:
    socket.socket().connect(("127.0.0.1", 9))
    network_denied = False
except OSError:
    network_denied = True
artifact_ok = pathlib.Path("result.txt").read_bytes() == b"ok"
try:
    pathlib.Path("/etc/passwd").read_bytes()
    external_read_denied = False
except OSError:
    external_read_denied = True
try:
    pathlib.Path("/tmp/cigar-r04-sandbox-escape").write_bytes(b"escape")
    external_write_denied = False
except OSError:
    external_write_denied = True
checks = [
    {
        "check_id": "artifact",
        "evidence_digest": multihash(b"artifact"),
        "passed": artifact_ok,
    },
    {
        "check_id": "filesystem-isolated",
        "evidence_digest": multihash(b"filesystem-isolated"),
        "passed": external_read_denied and external_write_denied,
    },
    {
        "check_id": "network-denied",
        "evidence_digest": multihash(b"network-denied"),
        "passed": network_denied,
    },
    {
        "check_id": "observation-bound",
        "evidence_digest": multihash(request["observation_id"].encode()),
        "passed": request["task_id"] == "task-r03",
    },
]
result = {
    "checks": checks,
    "passed": all(check["passed"] for check in checks),
    "schema_version": "cigar.verifier-result.v1",
}
sys.stdout.buffer.write(canonical(result) + b"\n")
"""


class EvaluatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name).resolve(strict=True)
        self.registry = SchemaRegistry(SCHEMAS)
        self.archive = self.temp / "fixture.json"
        archive = {
            "files": [
                {
                    "bytes_base64url": "YWxsb3dlZA",
                    "media_type": "text/markdown",
                    "path": "allowed.md",
                }
            ],
            "schema_version": "cigar.fixture-archive.v1",
        }
        self.archive_bytes = canonical.canonical_bytes(archive)
        self.archive.write_bytes(self.archive_bytes)
        self.consumer = self.temp / "consumer.py"
        self.consumer.write_text(textwrap.dedent(FAKE_CONSUMER), encoding="utf-8")
        self.consumer.chmod(0o555)
        self.state = self.temp / "state"
        self.environment = self.temp / "task-environment"
        self.environment.mkdir(mode=0o700)
        self.verifier = self.environment / "verify.py"
        self.verifier.write_text(textwrap.dedent(VERIFIER), encoding="utf-8")
        self.verifier.chmod(0o500)
        (self.environment / "result.txt").write_bytes(b"ok")
        (self.environment / "result.txt").chmod(0o400)
        self.key = self.temp / "attestation.key"
        self.key.write_bytes(b"independent-evaluator-key-r04-0001")
        self.key.chmod(0o600)
        self.seed_digest = canonical.multihash_bytes(b"independent-assignment-seed")
        self.observation_path = self._observation()
        self.observation = canonical.loads(self.observation_path.read_bytes())
        self.task_path = self._task()
        self.task = canonical.loads(self.task_path.read_bytes())
        self.oracle_digest = canonical.identity(self.task["oracle"])
        self.verifier_digest = canonical.multihash_bytes(self.verifier.read_bytes())
        self.claims_path = self._claims(self.observation)
        self.claims_digest = canonical.multihash_bytes(self.claims_path.read_bytes())
        self.adjudication_path = self._adjudication(self.observation)

    def _assignment(self, treatment: str) -> dict[str, object]:
        return {
            "archive_digest": canonical.multihash_bytes(self.archive_bytes),
            "archive_path": str(self.archive),
            "consumer_mode": "recorded",
            "excluded_prefixes": [],
            "flows": {"effect": False, "handoff": False, "replay": False},
            "job_goal": "Use authorized evidence only",
            "max_context_tokens": 1024,
            "model": "deterministic-recorded-v1",
            "output_reserve_tokens": 128,
            "pair_id": "pair-r04",
            "prompt_digest": MH,
            "query": "allowed",
            "run_id": "run-r04",
            "schema_version": "cigar.benchmark-assignment.v2",
            "semantic_type": "documentation",
            "source": {"revision": GIT, "tree": GIT},
            "task_id": "task-r03",
            "token_budget": 512,
            "treatment": treatment,
        }

    def _observation(self) -> Path:
        assignments = {}
        for treatment in ("champion", "candidate"):
            path = self.temp / f"{treatment}.json"
            path.write_bytes(canonical.canonical_bytes(self._assignment(treatment)))
            assignments[treatment] = path
        pair = run_pair(
            champion_assignment_path=assignments["champion"],
            candidate_assignment_path=assignments["candidate"],
            champion_executable_path=self.consumer,
            candidate_executable_path=self.consumer,
            cwd=self.temp,
            state=self.temp / "consumer-state",
            schemas=SCHEMAS,
            timeout_seconds=10,
        )
        candidate = next(
            value
            for value in pair["observations"]
            if value["treatment"] == "candidate"
        )
        path = self.temp / "observation.json"
        path.write_bytes(canonical.canonical_bytes(candidate))
        return path

    def _task(self) -> Path:
        task = {
            "schema_version": "cigar.refinement-task.v1",
            "task_id": "task-r03",
            "task_lineage_id": "lineage-r04",
            "stratum": "Needle-and-Distractor",
            "sub_strata": ["symbol-lookup"],
            "source": {
                "repository_id": "repo-r04",
                "immutable_revision": GIT,
                "archive_digest": canonical.multihash_bytes(self.archive_bytes),
                "license": "Apache-2.0",
                "setup_digest": task_environment_digest(self.environment),
            },
            "contract": {
                "operation_class": "read",
                "purpose": "benchmark",
                "allowed_projects": ["project-a"],
                "prohibited_projects": ["project-b"],
                "target_profile": "balanced.v1",
                "token_budget": 512,
                "output_budget": 128,
            },
            "prompt_reference": "prompts/task-r04.md",
            "oracle": {
                "critical_evidence": [
                    {
                        "evidence_id": VERSION,
                        "version_or_span": VERSION,
                        "weight": 2,
                    }
                ],
                "relevant_evidence": [VERSION],
                "prohibited_evidence": ["prohibited-evidence"],
                "required_claims": [
                    {
                        "claim_id": "claim-1",
                        "description": "The answer uses the selected evidence.",
                        "evidence_ids": [VERSION],
                        "weight": 1,
                    }
                ],
                "accepted_answers_or_properties": ["postcondition passes"],
                "expected_artifacts": ["result.txt"],
                "deterministic_verifier": "verify.py",
                "allowed_abstention": False,
                "harm_conditions": ["No prohibited evidence."],
            },
            "execution": {
                "permitted_tools": ["read", "test"],
                "network_policy": "none",
                "timeout_seconds": 10,
                "maximum_effects": 0,
            },
            "contamination": {
                "canary_ids": ["canary-r04"],
                "public_visibility": "development",
            },
        }
        path = self.temp / "task.json"
        path.write_bytes(canonical.canonical_bytes(task))
        return path

    def _claims(self, observation: dict[str, object]) -> Path:
        body = {
            "schema_version": "cigar.answer-claims.v1",
            "observation_id": observation["observation_id"],
            "output_digest": observation["output_digest"],
            "answer_status": "answered",
            "claims": [
                {
                    "claim_id": "claim-1",
                    "statement_digest": canonical.multihash_bytes(b"claim statement"),
                    "citations": [VERSION],
                }
            ],
        }
        claims = {**body, "claims_id": canonical.identity(body)}
        path = self.temp / f"claims-{observation['observation_id']}.json"
        path.write_bytes(canonical.canonical_bytes(claims))
        return path

    def _adjudication(self, observation: dict[str, object]) -> Path:
        body = {
            "schema_version": "cigar.adjudication.v1",
            "observation_id": observation["observation_id"],
            "reviewer_ids": ["reviewer-1", "reviewer-2"],
            "judgments": [
                {
                    "criterion": "task_success",
                    "subject_id": "task-r03",
                    "votes": [
                        {"reviewer_id": "reviewer-1", "outcome": "pass"},
                        {"reviewer_id": "reviewer-2", "outcome": "pass"},
                    ],
                }
            ],
        }
        value = {**body, "adjudication_id": canonical.identity(body)}
        path = self.temp / f"adjudication-{observation['observation_id']}.json"
        path.write_bytes(canonical.canonical_bytes(value))
        return path

    def arguments(self, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "observation_path": self.observation_path,
            "task_path": self.task_path,
            "claims_path": self.claims_path,
            "adjudication_path": self.adjudication_path,
            "task_environment": self.environment,
            "state": self.state,
            "schemas": SCHEMAS,
            "repository_root": ROOT,
            "key_path": self.key,
            "key_id": "evaluator-r04",
            "assignment_seed_digest": self.seed_digest,
            "expected_oracle_digest": self.oracle_digest,
            "expected_verifier_digest": self.verifier_digest,
            "expected_claims_digest": self.claims_digest,
            "evidence_class": "diagnostic",
        }
        result.update(overrides)
        return result

    def test_hand_computed_metrics_attestation_and_replay_are_exact(self) -> None:
        evaluation = evaluate(**self.arguments())
        metrics = {metric["name"]: metric for metric in evaluation["metrics"]}
        expected = {
            "verified_task_success": 1,
            "critical_context_recall": 1,
            "evidence_token_precision": 1,
            "evidence_item_precision": 1,
            "citation_recall": 1,
            "citation_precision": 1,
            "unsupported_claim_rate": 0,
            "first_useful_evidence_rank": 1,
            "evidence_sufficiency": 1,
            "selected_provenance_coverage": 1,
            "human_agreement": 1,
            "authorization_violations": 0,
            "prohibited_materialized_tokens": 0,
        }
        self.assertEqual(
            {name: metrics[name]["value"] for name in expected},
            expected,
        )
        self.assertTrue(evaluation["postcondition"]["isolation"]["network_denied"])
        self.assertTrue(evaluation["postcondition"]["isolation"]["disposable_root"])
        self.assertEqual(evaluation["violations"], [])
        self.assertNotIn("treatment", evaluation)
        key = self.key.read_bytes()
        verify_attestation(
            evaluation,
            key=key,
            registry=self.registry,
        )
        self.assertEqual(replay(evaluation, **self.arguments()), evaluation)

    def test_consumer_success_self_attestation_and_seed_reuse_fail_closed(self) -> None:
        injected = copy.deepcopy(self.observation)
        injected["success"] = True
        body = dict(injected)
        body.pop("observation_id")
        injected["observation_id"] = canonical.identity(body)
        injected_path = self.temp / "consumer-success.json"
        injected_path.write_bytes(canonical.canonical_bytes(injected))
        with self.assertRaisesRegex(EvaluatorError, "raw observation"):
            evaluate(**self.arguments(observation_path=injected_path))

        repository = self.temp / "repository"
        repository.mkdir()
        inside_key = repository / "key"
        inside_key.write_bytes(b"independent-evaluator-key-r04-0002")
        inside_key.chmod(0o600)
        with self.assertRaisesRegex(EvaluatorError, "custody"):
            evaluate(
                **self.arguments(
                    repository_root=repository,
                    key_path=inside_key,
                )
            )
        with self.assertRaisesRegex(EvaluatorError, "assignment seed"):
            evaluate(
                **self.arguments(
                    assignment_seed_digest=canonical.multihash_bytes(
                        self.key.read_bytes()
                    )
                )
            )

    def test_oracle_claims_verifier_and_attestation_substitution_fail(self) -> None:
        substituted_task = copy.deepcopy(self.task)
        substituted_task["oracle"]["accepted_answers_or_properties"] = [
            "substituted property"
        ]
        task_path = self.temp / "substituted-task.json"
        task_path.write_bytes(canonical.canonical_bytes(substituted_task))
        with self.assertRaisesRegex(EvaluatorError, "oracle digest"):
            evaluate(**self.arguments(task_path=task_path))

        substituted_claims = canonical.loads(self.claims_path.read_bytes())
        substituted_claims["claims"][0]["citations"] = []
        claims_body = dict(substituted_claims)
        claims_body.pop("claims_id")
        substituted_claims["claims_id"] = canonical.identity(claims_body)
        claims_path = self.temp / "substituted-claims.json"
        claims_path.write_bytes(canonical.canonical_bytes(substituted_claims))
        with self.assertRaisesRegex(EvaluatorError, "claims attachment"):
            evaluate(**self.arguments(claims_path=claims_path))

        verifier = self.verifier.read_text(encoding="utf-8")
        self.verifier.chmod(0o600)
        self.verifier.write_text(verifier + "\n", encoding="utf-8")
        self.verifier.chmod(0o500)
        changed_task = copy.deepcopy(self.task)
        changed_task["source"]["setup_digest"] = task_environment_digest(
            self.environment
        )
        changed_task_path = self.temp / "changed-verifier-task.json"
        changed_task_path.write_bytes(canonical.canonical_bytes(changed_task))
        with self.assertRaisesRegex(EvaluatorError, "verifier digest"):
            evaluate(
                **self.arguments(
                    task_path=changed_task_path,
                    expected_oracle_digest=canonical.identity(self.task["oracle"]),
                )
            )

        self.verifier.chmod(0o600)
        self.verifier.write_text(verifier, encoding="utf-8")
        self.verifier.chmod(0o500)
        evaluation = evaluate(**self.arguments())
        tampered = copy.deepcopy(evaluation)
        tampered["metrics"][0]["value"] = 999
        with self.assertRaisesRegex(EvaluatorError, "identity|attestation"):
            verify_attestation(
                tampered,
                key=self.key.read_bytes(),
                registry=self.registry,
            )

    def test_treatment_is_blinded_and_metrics_are_identical(self) -> None:
        candidate = evaluate(**self.arguments())
        champion_observation = copy.deepcopy(self.observation)
        champion_observation["treatment"] = "champion"
        observation_body = dict(champion_observation)
        observation_body.pop("observation_id")
        champion_observation["observation_id"] = canonical.identity(observation_body)
        observation_path = self.temp / "champion-observation.json"
        observation_path.write_bytes(canonical.canonical_bytes(champion_observation))
        claims_path = self._claims(champion_observation)
        claims_digest = canonical.multihash_bytes(claims_path.read_bytes())
        adjudication_path = self._adjudication(champion_observation)
        champion = evaluate(
            **self.arguments(
                observation_path=observation_path,
                claims_path=claims_path,
                expected_claims_digest=claims_digest,
                adjudication_path=adjudication_path,
            )
        )
        self.assertEqual(candidate["metrics"], champion["metrics"])
        self.assertEqual(candidate["violations"], champion["violations"])
        self.assertNotIn(b"candidate", canonical.canonical_bytes(candidate))
        self.assertNotIn(b"champion", canonical.canonical_bytes(champion))

    def test_adjudication_contains_only_ids_votes_and_agreement(self) -> None:
        value = canonical.loads(self.adjudication_path.read_bytes())
        self.registry.validate("adjudication-v1.schema.json", value)
        encoded = canonical.canonical_bytes(value)
        self.assertNotIn(b"description", encoded)
        self.assertNotIn(b"private_text", encoded)
        invalid = copy.deepcopy(value)
        invalid["judgments"][0]["votes"].reverse()
        body = dict(invalid)
        body.pop("adjudication_id")
        invalid["adjudication_id"] = canonical.identity(body)
        path = self.temp / "invalid-adjudication.json"
        path.write_bytes(canonical.canonical_bytes(invalid))
        with self.assertRaisesRegex(EvaluatorError, "exact reviewers"):
            evaluate(**self.arguments(adjudication_path=path))

    def test_auxiliary_evaluator_schemas_are_closed_and_complete(self) -> None:
        values = {
            "claims-v1.schema.json": canonical.loads(self.claims_path.read_bytes()),
            "adjudication-v1.schema.json": canonical.loads(
                self.adjudication_path.read_bytes()
            ),
            "verifier-result-v1.schema.json": {
                "schema_version": "cigar.verifier-result.v1",
                "passed": True,
                "checks": [
                    {
                        "check_id": "check-1",
                        "passed": True,
                        "evidence_digest": MH,
                    }
                ],
            },
        }
        for schema, value in values.items():
            self.registry.validate(schema, value)
            required = self.registry.load(schema)["required"]
            for field in required:
                incomplete = copy.deepcopy(value)
                incomplete.pop(field)
                with self.assertRaises(SchemaError, msg=f"{schema}:{field}"):
                    self.registry.validate(schema, incomplete)
            unknown = copy.deepcopy(value)
            unknown["private_text"] = "must not be admitted"
            with self.assertRaises(SchemaError):
                self.registry.validate(schema, unknown)

    def test_cli_evaluate_replay_and_verify_use_one_strict_record(self) -> None:
        common = [
            sys.executable,
            "-m",
            "tools.refinement.evaluator",
            "--evaluation",
            str(self.temp / "evaluation.json"),
            "--observation",
            str(self.observation_path),
            "--task",
            str(self.task_path),
            "--claims",
            str(self.claims_path),
            "--adjudication",
            str(self.adjudication_path),
            "--task-environment",
            str(self.environment),
            "--state",
            str(self.state),
            "--schemas",
            str(SCHEMAS),
            "--repository-root",
            str(ROOT),
            "--key",
            str(self.key),
            "--key-id",
            "evaluator-r04",
            "--assignment-seed-digest",
            self.seed_digest,
            "--expected-oracle-digest",
            self.oracle_digest,
            "--expected-verifier-digest",
            self.verifier_digest,
            "--expected-claims-digest",
            self.claims_digest,
            "--evidence-class",
            "diagnostic",
        ]
        evaluated = subprocess.run(
            [*common[:3], "evaluate", *common[3:]],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
        self.assertEqual(evaluated.stderr, b"")
        self.assertTrue(evaluated.stdout.endswith(b"\n"))
        value = canonical.loads(evaluated.stdout[:-1])
        self.assertEqual(canonical.canonical_bytes(value) + b"\n", evaluated.stdout)
        evaluation_path = self.temp / "evaluation.json"
        evaluation_path.write_bytes(evaluated.stdout[:-1])
        for command in ("replay", "verify"):
            completed = subprocess.run(
                [*common[:3], command, *common[3:]],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
