from __future__ import annotations

# ruff: noqa: E402

import base64
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import load_file
from tools.refinement.intelligence import _derive_metrics, _evidence_bridge
from tools.refinement.schema import SchemaError, SchemaRegistry


class IntelligenceProfileContractTests(unittest.TestCase):
    def test_registry_and_benchmark_only_selection_are_closed(self) -> None:
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        profiles = load_file(
            (ROOT / "refinement/profiles/intelligence-profiles.v1.json").resolve()
        )
        registry.validate("intelligence-profiles-v1.schema.json", profiles)
        self.assertEqual(
            [item["profile_id"] for item in profiles["profiles"]],
            ["balanced.v1", "balanced.v2-candidate.1"],
        )
        self.assertEqual(profiles["profiles"][0]["status"], "frozen_default")
        self.assertEqual(
            profiles["profiles"][1]["selection_surface"],
            "cigarbench_consumer_only",
        )
        self.assertNotEqual(
            profiles["profiles"][0]["retrieval_digest"],
            profiles["profiles"][1]["retrieval_digest"],
        )
        self.assertNotEqual(
            profiles["profiles"][0]["compiler_digest"],
            profiles["profiles"][1]["compiler_digest"],
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
        candidate["intelligence_profile"] = "balanced.v3"
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
