from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from tools.refinement import canonical
from tools.refinement.corpus import (
    AGREEMENT_THRESHOLD_PPM,
    MIN_TASKS_PER_STRATUM,
    PACK_ROLES,
    STRATA,
    CorpusError,
    _load_canonical,
    _materialize_environment,
    _private_token,
    _record_map,
    _smoke,
    production_cigar_smoke,
    select_context,
    validate_manifest,
)
from tools.refinement.evaluator import task_environment_digest
from tools.refinement.schema import SchemaError, SchemaRegistry

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "refinement/corpus"
SCHEMAS = ROOT / "schemas/refinement"
DEVELOPMENT_MANIFEST = CORPUS / "development-manifest-v1.json"


def load(path: Path) -> dict[str, object]:
    value, _payload = _load_canonical(path.resolve(strict=True))
    return value


class CorpusQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = SchemaRegistry(SCHEMAS)
        cls.manifest = load(DEVELOPMENT_MANIFEST)
        cls.packs = {
            role: load(CORPUS / "development" / f"{role}.json")
            for role in PACK_ROLES
        }
        cls.maps = {
            role: _record_map(cls.packs[role]["records"], role)
            for role in PACK_ROLES
            if role != "qualification"
        }

    def test_development_manifest_replays_every_digest_and_binding(self) -> None:
        manifest, keys = validate_manifest(
            repository_root=ROOT,
            private_root=ROOT.parent / "not-used-for-development",
            manifest_path=DEVELOPMENT_MANIFEST,
            run_smoke=False,
        )
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(manifest["task_count"], len(self.maps["tasks"]))
        self.assertTrue(all(len(values) == 270 for values in keys.values()))

    def test_every_stratum_has_thirty_independent_tasks(self) -> None:
        counts = {
            item["stratum"]: item["count"]
            for item in self.manifest["stratum_counts"]
        }
        self.assertEqual(set(counts), set(STRATA))
        self.assertTrue(
            all(count == MIN_TASKS_PER_STRATUM for count in counts.values())
        )
        tasks = list(self.maps["tasks"].values())
        for field in ("repository_id", "immutable_revision", "archive_digest", "setup_digest"):
            values = [task["source"][field] for task in tasks]
            self.assertEqual(len(values), len(set(values)), field)
        lineages = [task["task_lineage_id"] for task in tasks]
        self.assertEqual(len(lineages), len(set(lineages)))

    def test_nine_legacy_fixtures_were_converted_without_losing_semantics(self) -> None:
        converted = {
            task["task_lineage_id"]: task
            for task in self.maps["tasks"].values()
            if task["task_lineage_id"].endswith("-v1")
        }
        legacy_paths = sorted((ROOT / "benches/cigarbench/datasets").glob("*-v1.json"))
        self.assertEqual(len(converted), 9)
        for path in legacy_paths:
            legacy = canonical.loads(path.read_bytes())
            task = converted[legacy["dataset_id"]]
            prompt = self.maps["prompts"][task["task_id"]]
            fixture = self.maps["fixtures"][task["task_id"]]
            oracle = self.maps["oracles"][task["task_id"]]
            self.assertEqual(prompt["text"], legacy["task"])
            self.assertEqual(fixture["canary"], legacy["canary"])
            self.assertEqual(
                len(oracle["critical_evidence"]), len(legacy["critical_context"])
            )
            self.assertEqual(
                len(oracle["prohibited_evidence"]),
                len(legacy["prohibited_context"]),
            )
            self.assertEqual(
                oracle["accepted_answers_or_properties"],
                legacy["expected_outcome"],
            )

    def test_annotation_agreement_and_abstention_quarantine_policy(self) -> None:
        annotations = self.maps["annotations"]
        self.assertEqual(
            self.manifest["qualification"]["agreement_ppm"], 1_000_000
        )
        for task_id, task in self.maps["tasks"].items():
            annotation = annotations[task_id]
            oracle = self.maps["oracles"][task_id]
            self.registry.validate("annotation-v1.schema.json", annotation)
            self.assertGreaterEqual(
                annotation["agreement"]["parts_per_million"],
                AGREEMENT_THRESHOLD_PPM,
            )
            self.assertTrue(annotation["treatment_blinded"])
            self.assertEqual(annotation["status"], "qualified")
            if "unanswerable-insufficient-evidence" in task["sub_strata"]:
                self.assertTrue(oracle["allowed_abstention"])
        abstention_tasks = [
            task
            for task in self.maps["tasks"].values()
            if "unanswerable-insufficient-evidence" in task["sub_strata"]
        ]
        self.assertEqual(len(abstention_tasks), len(STRATA))

    def test_baseline_cigar_proxy_and_oracle_selections_replay(self) -> None:
        summaries = {
            item["selector"]: item
            for item in self.manifest["qualification"]["selection_runs"]
        }
        self.assertEqual(
            set(summaries),
            {
                "baseline-all-authorized-v1",
                "cigar-lexical-v1",
                "human-oracle-v1",
            },
        )
        self.assertTrue(all(item["technically_executable"] for item in summaries.values()))
        self.assertEqual(summaries["human-oracle-v1"]["precision_ppm"], 1_000_000)
        task_id = sorted(self.maps["tasks"])[0]
        prompt = self.maps["prompts"][task_id]
        oracle = self.maps["oracles"][task_id]
        fixture = self.maps["fixtures"][task_id]
        for selector in summaries:
            selection = select_context(
                selector=selector,
                prompt=prompt["text"],
                oracle=oracle,
                fixture=fixture,
            )
            self.assertEqual(selection["selector"], selector)
            self.assertEqual(selection["task_id"], task_id)

    def test_setup_materialization_and_postcondition_are_executable(self) -> None:
        task_id = sorted(self.maps["tasks"])[0]
        task = self.maps["tasks"][task_id]
        oracle = self.maps["oracles"][task_id]
        fixture = self.maps["fixtures"][task_id]
        self.assertEqual(_smoke(task, oracle, fixture, SCHEMAS), (True, True))
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw).resolve(strict=True) / "environment"
            _materialize_environment(fixture["environment"], destination)
            self.assertEqual(
                task_environment_digest(destination),
                task["source"]["setup_digest"],
            )

    def test_production_rust_cigar_is_executable_without_canary_disclosure(self) -> None:
        configured = os.environ.get("CIGARBENCH_CONSUMER")
        if configured is None:
            self.skipTest("set CIGARBENCH_CONSUMER for production corpus qualification")
        result = production_cigar_smoke(
            repository_root=ROOT,
            private_root=ROOT.parent / "not-used-for-development",
            manifest_path=DEVELOPMENT_MANIFEST,
            task_id="development-agent-handoff-001",
            consumer_path=Path(configured).resolve(strict=True),
        )
        self.assertEqual(result["status"], "technically-executable")
        self.assertFalse(result["canary_disclosed"])
        self.assertEqual(
            result["consumer_digest"],
            "1220343ecc927586ae9f58cd91e9610bad9dc4af18238076b538f0baaa923078a116",
        )

    def test_canaries_licenses_and_pack_contracts_are_complete(self) -> None:
        fixtures = list(self.maps["fixtures"].values())
        canaries = [fixture["canary"] for fixture in fixtures]
        self.assertEqual(len(canaries), len(set(canaries)))
        self.assertTrue(
            all(
                task["source"]["license"] in self.manifest["license_allowlist"]
                for task in self.maps["tasks"].values()
            )
        )
        self.assertEqual(
            [pack["role"] for pack in self.manifest["packs"]],
            sorted(PACK_ROLES),
        )
        self.assertEqual(
            self.manifest["qualification"]["setup_smoke_passed"], 270
        )
        self.assertEqual(
            self.manifest["qualification"]["postcondition_smoke_passed"], 270
        )

    def test_shadow_and_sealed_manifests_disclose_commitments_only(self) -> None:
        manifests = [
            load(CORPUS / f"{partition}-manifest-v1.json")
            for partition in ("development", "shadow", "sealed")
        ]
        for manifest in manifests[1:]:
            self.registry.validate("corpus-manifest-v1.schema.json", manifest)
            self.assertEqual(manifest["disclosure"], "commitments-only")
            self.assertTrue(
                all(pack["reference"] is None for pack in manifest["packs"])
            )
            self.assertTrue(
                all(
                    pack["custody"] == "external-owner-only"
                    for pack in manifest["packs"]
                )
            )
        dedup_fields = (
            "source_commitment",
            "lineage_commitment",
            "normalized_prompt_digest",
            "critical_evidence_digest",
            "postcondition_digest",
            "overlap_fingerprint",
        )
        for field in dedup_fields:
            partitions = [
                {record[field] for record in manifest["records"]}
                for manifest in manifests
            ]
            self.assertFalse(partitions[0] & partitions[1], field)
            self.assertFalse(partitions[0] & partitions[2], field)
            self.assertFalse(partitions[1] & partitions[2], field)
        self.assertFalse((CORPUS / "shadow").exists())
        self.assertFalse((CORPUS / "sealed").exists())

    def test_private_generation_is_not_reproducible_without_external_seed(self) -> None:
        label = "shadow:Agent-Handoff:1"
        self.assertNotEqual(
            _private_token(b"a" * 32, label),
            _private_token(b"b" * 32, label),
        )

    def test_tampered_manifest_and_open_annotation_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.manifest)
        tampered["stratum_counts"][0]["count"] = 29
        tampered.pop("manifest_id")
        tampered["manifest_id"] = canonical.identity(tampered)
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw).resolve(strict=True) / "manifest.json"
            path.write_bytes(canonical.canonical_bytes(tampered))
            with self.assertRaisesRegex(CorpusError, "task-count floor"):
                validate_manifest(
                    repository_root=ROOT,
                    private_root=ROOT.parent / "not-used",
                    manifest_path=path,
                    run_smoke=False,
                )
        annotation = copy.deepcopy(next(iter(self.maps["annotations"].values())))
        annotation["reviewer_notes"] = "hidden prose is forbidden"
        with self.assertRaises(SchemaError):
            self.registry.validate("annotation-v1.schema.json", annotation)


if __name__ == "__main__":
    unittest.main()
