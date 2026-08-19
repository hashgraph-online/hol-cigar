from __future__ import annotations

# ruff: noqa: E402

import base64
import copy
import os
import shutil
import stat
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import (
    canonical_bytes,
    identity,
    load_file,
    multihash_bytes,
)
from tools.refinement.intelligence import (
    IntelligenceError,
    _derive_metrics,
    _evidence_bridge,
    _failed_evaluation,
    _qualification_token_budget,
    _seal,
    _validate_gate_attachment,
)
from tools.refinement.gate_evidence import (
    MAXIMUM_COMMAND_STATE_PATH_BYTES,
    _short_command_state_root,
)
from tools.refinement.schema import SchemaError, SchemaRegistry


class IntelligenceProfileContractTests(unittest.TestCase):
    def test_tier1_command_state_root_is_private_and_socket_safe(self) -> None:
        root = _short_command_state_root(
            {"revision": "a" * 40, "tree": "b" * 40}
        )
        try:
            self.assertTrue(root.is_absolute())
            self.assertEqual(root.resolve(strict=True), root)
            self.assertLessEqual(
                len(os.fsencode(root)), MAXIMUM_COMMAND_STATE_PATH_BYTES
            )
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        finally:
            shutil.rmtree(root)

    def test_qualification_inherits_the_frozen_task_contract_budget(self) -> None:
        records = {
            "tasks": {
                "task-a": {"contract": {"token_budget": 4096}},
                "task-b": {"contract": {"token_budget": 4096}},
            }
        }
        task_ids = ["task-a", "task-b"]
        self.assertEqual(
            _qualification_token_budget(records, task_ids, requested=None), 4096
        )
        self.assertEqual(
            _qualification_token_budget(records, task_ids, requested=768), 768
        )
        with self.assertRaisesRegex(IntelligenceError, "exceeds a task contract"):
            _qualification_token_budget(records, task_ids, requested=4097)

        records["tasks"]["task-b"]["contract"]["token_budget"] = 2048
        with self.assertRaisesRegex(IntelligenceError, "do not share"):
            _qualification_token_budget(records, task_ids, requested=None)

    def test_profile_treatment_failures_are_signed_and_profile_bound(self) -> None:
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        key = b"profile-failure-test-key-32-bytes"
        key_fingerprint = multihash_bytes(key)
        failure = {
            "category": "process-exit",
            "exit_code": 1,
            "failure_code": "ingestCatalog:api-1400",
            "stdout_bytes": 0,
            "stdout_digest": multihash_bytes(b""),
            "stderr_bytes": 1,
            "stderr_digest": multihash_bytes(b"x"),
            "duration_ms": 7,
        }
        arguments = {
            "treatment": "candidate",
            "profile_id": "balanced.v2-candidate.1",
            "source": {"revision": "a" * 40, "tree": "b" * 40},
            "assignment_digest": "1220" + "1" * 64,
            "consumer_digest": "1220" + "2" * 64,
            "failure": failure,
            "task": {
                "task_id": "profile-failure-task",
                "task_lineage_id": "profile-failure-lineage",
                "stratum": "Agent-Handoff",
                "sub_strata": [],
            },
            "oracle": {
                "critical_evidence": [{"weight": 1}],
                "required_claims": [],
            },
            "manifest_id": "1220" + "3" * 64,
            "seed_index": 0,
            "registry": registry,
            "key": key,
            "key_id": "profile-failure-test",
            "key_fingerprint": key_fingerprint,
        }
        evaluation = _failed_evaluation(**arguments)
        registry.validate(
            "honey-treatment-failure-evaluation-v1.schema.json", evaluation
        )
        self.assertEqual(evaluation["profile_id"], "balanced.v2-candidate.1")
        self.assertEqual(evaluation["failure"], failure)
        unsigned = dict(evaluation)
        claimed = unsigned.pop("evaluation_id")
        attestation = dict(unsigned["attestation"])
        attestation.pop("mac")
        unsigned["attestation"] = attestation
        self.assertEqual(claimed, identity(unsigned))
        arguments["profile_id"] = "balanced.v3"
        v3_evaluation = _failed_evaluation(**arguments)
        self.assertEqual(v3_evaluation["profile_id"], "balanced.v3")

    def test_gate_attachment_is_canonical_source_bound_and_explicitly_passed(
        self,
    ) -> None:
        source = {"revision": "a" * 40, "tree": "b" * 40}
        plan_id = "1220" + "1" * 64
        build_set_id = "1220" + "2" * 64
        policy_digest = "1220" + "3" * 64
        key = b"gate-receipt-test-key-32-bytes!"
        key_fingerprint = multihash_bytes(key)
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        receipts = []
        for gate_id in ("conformance", "required-tests"):
            result_body = {
                "command_id": f"command-{gate_id}",
                "command_sha256": "4" * 64,
                "tool_digest": "1220" + "7" * 64,
                "exit_code": 0,
                "timed_out": False,
                "output_overflow": False,
                "stdout_bytes": 0,
                "stdout_sha256": "5" * 64,
                "stderr_bytes": 0,
                "stderr_sha256": "6" * 64,
                "status": "passed",
            }
            receipt_body = {
                "schema_version": "cigar.intelligence-gate-receipt.v1",
                "purpose": "private-candidate-tier1-gate",
                "gate_id": gate_id,
                "source": source,
                "plan_id": plan_id,
                "build_set_id": build_set_id,
                "policy_digest": policy_digest,
                "command_results": [
                    {**result_body, "result_id": identity(result_body)}
                ],
                "attachment_digests": [],
                "status": "passed",
            }
            receipts.append(
                _seal(
                    receipt_body,
                    identity_field="receipt_id",
                    key=key,
                    key_id="gate-test-v1",
                    key_fingerprint=key_fingerprint,
                )
            )
        body = {
            "schema_version": "cigar.intelligence-gate-evidence.v2",
            "purpose": "private-candidate-nomination-only",
            "source": source,
            "plan_id": plan_id,
            "build_set_id": build_set_id,
            "policy_digest": policy_digest,
            "receipts": receipts,
        }
        attachment = {**body, "evidence_id": identity(body)}
        _validate_gate_attachment(
            canonical_bytes(attachment),
            source=source,
            plan_id=plan_id,
            build_set_id=build_set_id,
            policy_digest=policy_digest,
            required_checks=("conformance", "required-tests"),
            key=key,
            key_fingerprint=key_fingerprint,
            registry=registry,
        )
        wrong_source = copy.deepcopy(attachment)
        wrong_source["source"]["tree"] = "c" * 40
        with self.assertRaises(IntelligenceError):
            _validate_gate_attachment(
                canonical_bytes(wrong_source),
                source=source,
                plan_id=plan_id,
                build_set_id=build_set_id,
                policy_digest=policy_digest,
                required_checks=("conformance", "required-tests"),
                key=key,
                key_fingerprint=key_fingerprint,
                registry=registry,
            )
        tampered = copy.deepcopy(attachment)
        tampered["receipts"][0]["command_results"][0]["stdout_bytes"] = 1
        tampered_body = dict(tampered)
        tampered_body.pop("evidence_id")
        tampered["evidence_id"] = identity(tampered_body)
        with self.assertRaises(IntelligenceError):
            _validate_gate_attachment(
                canonical_bytes(tampered),
                source=source,
                plan_id=plan_id,
                build_set_id=build_set_id,
                policy_digest=policy_digest,
                required_checks=("conformance", "required-tests"),
                key=key,
                key_fingerprint=key_fingerprint,
                registry=registry,
            )

    def test_registry_exposes_replay_profiles_and_balanced_v3_default(self) -> None:
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        profiles = load_file(
            (ROOT / "refinement/profiles/intelligence-profiles.v1.json").resolve()
        )
        registry.validate("intelligence-profiles-v1.schema.json", profiles)
        self.assertEqual(
            [item["profile_id"] for item in profiles["profiles"]],
            [
                "balanced.v1",
                "balanced.v2-candidate.1",
                "balanced.v2-candidate.2",
                "balanced.v3",
            ],
        )
        self.assertEqual(
            profiles["profiles"][0]["status"], "release_default_compatible"
        )
        self.assertEqual(profiles["profiles"][0]["selection_surface"], "all")
        self.assertEqual(profiles["profiles"][1]["status"], "experimental_opt_in")
        self.assertEqual(
            profiles["profiles"][1]["selection_surface"],
            "all",
        )
        self.assertNotEqual(
            profiles["profiles"][0]["retrieval_digest"],
            profiles["profiles"][1]["retrieval_digest"],
        )
        self.assertNotEqual(
            profiles["profiles"][0]["compiler_digest"],
            profiles["profiles"][1]["compiler_digest"],
        )
        self.assertNotEqual(
            profiles["profiles"][1]["retrieval_digest"],
            profiles["profiles"][2]["retrieval_digest"],
        )
        self.assertNotEqual(
            profiles["profiles"][1]["compiler_digest"],
            profiles["profiles"][2]["compiler_digest"],
        )
        self.assertEqual(
            profiles["profiles"][3]["status"], "release_default_compatible"
        )
        self.assertEqual(profiles["profiles"][3]["selection_surface"], "all")
        self.assertEqual(
            profiles["profiles"][2]["retrieval_digest"],
            profiles["profiles"][3]["retrieval_digest"],
        )
        self.assertNotEqual(
            profiles["profiles"][2]["compiler_digest"],
            profiles["profiles"][3]["compiler_digest"],
        )

    def test_assignment_profile_is_optional_closed_and_digest_bound(self) -> None:
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        base = {
            "schema_version": "cigar.benchmark-assignment.v2",
            "run_id": "r09",
            "pair_id": "r09-pair",
            "task_id": "r09-task",
            "treatment": "candidate",
            "consumer_mode": "recorded",
            "source": {"revision": "a" * 40, "tree": "b" * 40},
            "archive_path": "/private/tmp/fixture",
            "archive_digest": "1220" + "1" * 64,
            "query": "exact symbol",
            "job_goal": "retrieve exact symbol evidence",
            "semantic_type": "source_code",
            "token_budget": 512,
            "output_reserve_tokens": 128,
            "max_context_tokens": 1024,
            "excluded_prefixes": [],
            "flows": {"handoff": False, "effect": False, "replay": False},
            "model": "deterministic-recorded-v1",
            "prompt_digest": "1220" + "2" * 64,
        }
        registry.validate("assignment-v2.schema.json", base)
        candidate = copy.deepcopy(base)
        candidate["intelligence_profile"] = "balanced.v2-candidate.1"
        registry.validate("assignment-v2.schema.json", candidate)
        candidate["intelligence_profile"] = "balanced.v2-candidate.2"
        registry.validate("assignment-v2.schema.json", candidate)
        candidate["intelligence_profile"] = "balanced.v3"
        registry.validate("assignment-v2.schema.json", candidate)
        candidate["intelligence_profile"] = "balanced.v4"
        with self.assertRaises(SchemaError):
            registry.validate("assignment-v2.schema.json", candidate)

    def test_content_digest_bridge_and_profile_metrics_are_oracle_bound(self) -> None:
        payloads = {
            "critical.md": b"critical evidence",
            "distractor.md": b"irrelevant evidence",
        }
        fixture = {
            "archive": {
                "files": [
                    {
                        "bytes_base64url": base64.urlsafe_b64encode(payload)
                        .decode("ascii")
                        .rstrip("="),
                        "media_type": "text/markdown",
                        "path": path,
                    }
                    for path, payload in sorted(payloads.items())
                ],
                "schema_version": "cigar.fixture-archive.v1",
            },
            "evidence_index": [
                {
                    "class": "critical",
                    "evidence_id": "ev:critical",
                    "path": "critical.md",
                },
                {
                    "class": "distractor",
                    "evidence_id": "ev:distractor",
                    "path": "distractor.md",
                },
            ],
        }
        bridge, bridge_digest = _evidence_bridge(fixture)
        self.assertEqual(len(bridge), 2)
        self.assertTrue(bridge_digest.startswith("1220"))
        blocks = [
            {
                "block_id": "block-1",
                "lane": "evidence",
                "provenance_ids": ["version-1"],
                "rank": 1,
                "tokens": 20,
            }
        ]
        observation = {
            "selected_blocks": blocks,
            "resources": {
                "physical_input_tokens": 20,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 5,
                "cpu_ms": 0,
                "cpu_measured": False,
                "peak_rss_bytes": 0,
                "peak_rss_measured": False,
                "cost_usd": 0,
            },
            "effect_replay": {
                "handoffs": 0,
                "effects": 0,
                "unsafe_retries": 0,
                "replay_dispatches": 0,
            },
        }
        task = {"stratum": "Needle-and-Distractor", "sub_strata": []}
        oracle = {
            "critical_evidence": [{"evidence_id": "ev:critical", "weight": 1}],
            "relevant_evidence": ["ev:critical"],
            "prohibited_evidence": ["ev:prohibited"],
            "required_claims": [
                {"claim_id": "claim-1", "evidence_ids": ["ev:critical"]}
            ],
        }
        candidate = _derive_metrics(
            observation=observation,
            task=task,
            oracle=oracle,
            block_evidence=["ev:critical"],
            verifier={"passed": True},
            token_budget=1280,
        )
        candidate_values = {item["name"]: item for item in candidate}
        self.assertEqual(candidate_values["critical_context_recall"]["value"], 1)
        self.assertEqual(candidate_values["evidence_token_precision"]["value"], 1)
        self.assertEqual(candidate_values["first_useful_evidence_rank"]["value"], 1)
        champion = _derive_metrics(
            observation=observation,
            task=task,
            oracle=oracle,
            block_evidence=["ev:distractor"],
            verifier={"passed": False},
            token_budget=1280,
        )
        champion_values = {item["name"]: item for item in champion}
        self.assertEqual(champion_values["critical_context_recall"]["value"], 0)
        self.assertTrue(champion_values["first_useful_evidence_rank"]["applicable"])
        self.assertEqual(champion_values["first_useful_evidence_rank"]["value"], 2)


if __name__ == "__main__":
    unittest.main()
