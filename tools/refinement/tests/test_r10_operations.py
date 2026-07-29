from __future__ import annotations

# ruff: noqa: E402

import hashlib
import hmac
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement import config
from tools.refinement.artifacts import (
    ArtifactError,
    create_bundle,
    verify_bundle,
)
from tools.refinement.canonical import canonical_bytes, identity, multihash_bytes
from tools.refinement.dashboard import DashboardError, project
from tools.refinement.ledger import Ledger
from tools.refinement.operations import OperationsError, promotion_verify
from tools.refinement.quota import QuotaError, QuotaLedger, load_policy
from tools.refinement.schema import SchemaRegistry
from tools.refinement.workflow_audit import WorkflowAuditError, audit

SCHEMAS = ROOT / "schemas" / "refinement"
LIMITS = ROOT / "refinement" / "operations" / "limits-v1.json"
WORKFLOW_POLICY = ROOT / "refinement" / "operations" / "workflow-policy-v1.json"
NEW_SCHEMAS = (
    "dashboard-facts-v1.schema.json",
    "dashboard-projection-v1.schema.json",
    "draft-pr-preview-v1.schema.json",
    "draft-pr-receipt-v1.schema.json",
    "evidence-bundle-v1.schema.json",
    "opportunity-candidates-v1.schema.json",
    "opportunity-mining-policy-v1.schema.json",
    "opportunity-review-v1.schema.json",
    "operations-policy-v1.schema.json",
    "pr-payload-v1.schema.json",
    "promotion-payload-v1.schema.json",
    "quota-event-v1.schema.json",
    "workflow-policy-v1.schema.json",
)


def git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class R10OperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.external = Path(self.temporary.name).resolve(strict=True)
        self.revision = git("rev-parse", "HEAD")
        self.tree = git("rev-parse", "HEAD^{tree}")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def quota(self, name: str = "quota") -> QuotaLedger:
        return QuotaLedger(
            self.external / name,
            repository_root=ROOT,
            policy_path=LIMITS,
        )

    def test_new_schemas_are_closed_and_configs_bind_the_operations_policy(
        self,
    ) -> None:
        registry = SchemaRegistry(SCHEMAS)
        for filename in NEW_SCHEMAS:
            registry.load(filename)
        policy = load_policy(LIMITS, SCHEMAS)
        self.assertEqual(
            policy["policy_id"],
            "12208a2a78fc556005bdbc91b1b70006fff6ba6e2ec6cd2488cd4133e9f7c0833dcf",
        )
        for filename in (
            "default-v1.toml",
            "fast-v1.toml",
            "shadow-v1.toml",
            "promotion-v1.toml",
        ):
            loaded = config.load((ROOT / "refinement" / "config" / filename).absolute())
            self.assertEqual(
                loaded["paths"]["operations_policy"],
                "refinement/operations/limits-v1.json",
            )
        altered = json.loads(LIMITS.read_text(encoding="utf-8"))
        altered["global"]["max_concurrent_reservations"] += 1
        path = self.external / "altered-policy.json"
        path.write_bytes(canonical_bytes(altered))
        with self.assertRaisesRegex(QuotaError, "identity"):
            load_policy(path, SCHEMAS)

    def test_quota_reservations_enforce_daily_provider_and_concurrency_limits(
        self,
    ) -> None:
        quota = self.quota()
        reserved = quota.reserve(
            utc_day="2026-07-27",
            provider_id="openai-responses-tools-v1",
            reservation_id="hosted-one",
            requested={
                "input_tokens": 2_000_000,
                "output_tokens": 250_000,
                "cost_microusd": 25_000_000,
                "compute_milliseconds": 1_000,
            },
        )
        self.assertEqual(reserved["kind"], "reserved")
        with self.assertRaisesRegex(QuotaError, "input_tokens|concurrency"):
            quota.reserve(
                utc_day="2026-07-27",
                provider_id="openai-responses-tools-v1",
                reservation_id="hosted-two",
                requested={
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "cost_microusd": 0,
                    "compute_milliseconds": 1,
                },
            )
        settled = quota.finish(
            "hosted-one",
            actual={
                "input_tokens": 1_500_000,
                "output_tokens": 200_000,
                "cost_microusd": 20_000_000,
                "compute_milliseconds": 900,
            },
        )
        self.assertEqual(settled["kind"], "settled")
        usage = quota.usage("2026-07-27")
        hosted = next(
            row
            for row in usage["providers"]
            if row["provider_id"] == "openai-responses-tools-v1"
        )
        self.assertEqual(hosted["input_tokens"], 1_500_000)
        self.assertEqual(hosted["active_reservations"], 0)
        with self.assertRaisesRegex(QuotaError, "settlement|active"):
            quota.finish(
                "hosted-one",
                actual={
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_microusd": 0,
                    "compute_milliseconds": 0,
                },
            )
        self.assertEqual(len(quota.replay()), 2)

    def test_quota_enforces_global_compute_and_fails_on_tamper(self) -> None:
        quota = self.quota("global-quota")
        quota.reserve(
            utc_day="2026-07-27",
            provider_id="recorded-proposal-v1",
            reservation_id="all-compute",
            requested={
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_microusd": 0,
                "compute_milliseconds": 86_400_000,
            },
        )
        with self.assertRaisesRegex(QuotaError, "global daily compute"):
            quota.reserve(
                utc_day="2026-07-27",
                provider_id="subprocess-jsonl-v1",
                reservation_id="one-more",
                requested={
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_microusd": 0,
                    "compute_milliseconds": 1,
                },
            )
        event = quota.root / "entries" / "00000000000000000000.json"
        event.chmod(0o600)
        with self.assertRaisesRegex(QuotaError, "unsafe entry"):
            quota.replay()

    def test_evidence_bundle_is_create_new_content_bound_and_read_only(self) -> None:
        receipt = self.external / "receipt.json"
        receipt.write_bytes(canonical_bytes({"status": "passed"}))
        receipt.chmod(0o400)
        output = self.external / "bundle"
        manifest = create_bundle(
            repository_root=ROOT,
            output_root=output,
            run_id="r10-bundle",
            evidence_class="diagnostic",
            retention_days=14,
            source_revision=self.revision,
            source_tree=self.tree,
            attachments={"receipt.json": receipt},
            policy_id=load_policy(LIMITS, SCHEMAS)["policy_id"],
            authority="diagnostic-only",
        )
        self.assertEqual(
            verify_bundle(repository_root=ROOT, bundle_root=output), manifest
        )
        for path in output.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        with self.assertRaisesRegex(ArtifactError, "create-new"):
            create_bundle(
                repository_root=ROOT,
                output_root=output,
                run_id="r10-duplicate",
                evidence_class="diagnostic",
                retention_days=14,
                source_revision=self.revision,
                source_tree=self.tree,
                attachments={"receipt.json": receipt},
                policy_id=load_policy(LIMITS, SCHEMAS)["policy_id"],
                authority="diagnostic-only",
            )
        attachment = output / "attachments" / "receipt.json"
        attachment.chmod(0o600)
        with self.assertRaisesRegex(ArtifactError, "mutable|unsafe"):
            verify_bundle(repository_root=ROOT, bundle_root=output)

    def _dashboard_fixture(self) -> tuple[Path, Path, dict[str, object]]:
        ledger_root = self.external / "ledger"
        comparison_id = "1220" + "1" * 64
        decision_id = "1220" + "2" * 64
        entry = Ledger(ledger_root, repository_root=ROOT).append(
            event_type="trial_promoted",
            iteration_id="r10-known-good",
            source_revision=self.revision,
            source_tree=self.tree,
            artifact_ids=[comparison_id, decision_id],
            evidence_class="promotion",
            decision="promote",
        )
        fact_body: dict[str, object] = {
            "fact_id": "",
            "iteration_id": "r10-known-good",
            "ledger_entry_id": entry["entry_id"],
            "status": "promoted",
            "family_id": "packing-dependency",
            "adapter": "recorded-proposal-v1",
            "provider_id": "recorded-proposal-v1",
            "failure_class": None,
            "comparison_id": comparison_id,
            "decision_id": decision_id,
            "source_artifact_ids": [comparison_id, decision_id],
            "resources": {
                "input_tokens": 100,
                "output_tokens": 20,
                "cost_microusd": 0,
                "compute_milliseconds": 500,
            },
            "metrics": [
                {
                    "name": "critical_context_recall",
                    "direction": "higher",
                    "value_ppm": 1_000_000,
                }
            ],
        }
        unsigned_fact = dict(fact_body)
        unsigned_fact.pop("fact_id")
        fact_body["fact_id"] = identity(unsigned_fact)
        facts_body: dict[str, object] = {
            "schema_version": "cigar.refinement-dashboard-facts.v1",
            "facts_id": "",
            "ledger_head": entry["entry_id"],
            "facts": [fact_body],
        }
        unsigned_facts = dict(facts_body)
        unsigned_facts.pop("facts_id")
        facts_body["facts_id"] = identity(unsigned_facts)
        facts_path = self.external / "dashboard-facts.json"
        facts_path.write_bytes(canonical_bytes(facts_body))
        return ledger_root, facts_path, facts_body

    def test_dashboard_is_read_only_and_reconstructs_champion_kpis_and_cost(
        self,
    ) -> None:
        ledger_root, facts_path, facts = self._dashboard_fixture()
        before_facts = facts_path.read_bytes()
        before_inventory = sorted(
            (path.relative_to(ledger_root).as_posix(), path.stat().st_mtime_ns)
            for path in ledger_root.rglob("*")
        )
        projection = project(
            repository_root=ROOT,
            ledger_root=ledger_root,
            facts_path=facts_path,
        )
        self.assertEqual(projection["champion"]["iteration_id"], "r10-known-good")
        self.assertEqual(projection["champion"]["revision"], self.revision)
        self.assertEqual(
            projection["kpi_trends"][0]["name"],
            "critical_context_recall",
        )
        self.assertEqual(projection["provider_costs"][0]["input_tokens"], 100)
        self.assertEqual(facts_path.read_bytes(), before_facts)
        self.assertEqual(
            sorted(
                (path.relative_to(ledger_root).as_posix(), path.stat().st_mtime_ns)
                for path in ledger_root.rglob("*")
            ),
            before_inventory,
        )
        altered = dict(facts)
        altered["ledger_head"] = "1220" + "3" * 64
        altered["facts_id"] = identity(
            {key: value for key, value in altered.items() if key != "facts_id"}
        )
        bad = self.external / "bad-dashboard-facts.json"
        bad.write_bytes(canonical_bytes(altered))
        with self.assertRaisesRegex(DashboardError, "ledger head"):
            project(
                repository_root=ROOT,
                ledger_root=ledger_root,
                facts_path=bad,
            )

    def test_workflow_audit_proves_lane_separation_and_rejects_pr_secrets(
        self,
    ) -> None:
        result = audit(ROOT, WORKFLOW_POLICY)
        self.assertEqual(result["status"], "passed")
        by_name = {row["filename"]: row for row in result["workflows"]}
        self.assertEqual(by_name["refinement-fast.yml"]["secret_handles"], [])
        self.assertEqual(
            by_name["refinement-promotion.yml"]["environment"],
            "refinement-promotion",
        )
        nightly = (ROOT / ".github" / "workflows" / "refinement-nightly.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("python3 tools/refinement/loop.py", nightly)
        self.assertIn("--mode suggest", nightly)
        self.assertIn("--no-promotion", nightly)
        self.assertIn("CIGAR_REFINEMENT_STATE_ROOT", nightly)
        self.assertNotIn("operations.py quota reserve", nightly)
        self.assertNotIn(
            'run_id="nightly-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            nightly,
        )

        fixture = self.external / "repository"
        (fixture / ".github").mkdir(parents=True)
        shutil.copytree(ROOT / "schemas", fixture / "schemas")
        shutil.copytree(
            ROOT / ".github" / "workflows",
            fixture / ".github" / "workflows",
        )
        copied_policy = fixture / "workflow-policy.json"
        shutil.copyfile(WORKFLOW_POLICY, copied_policy)
        fast = fixture / ".github" / "workflows" / "refinement-fast.yml"
        with fast.open("a", encoding="utf-8") as stream:
            stream.write("\n# ${{ secrets.CIGAR_SHADOW_ATTESTATION_KEY }}\n")
        with self.assertRaisesRegex(WorkflowAuditError, "pull-request workflow"):
            audit(fixture, copied_policy)

    def test_workflow_policy_and_managed_workflows_are_stable(self) -> None:
        policy = json.loads(WORKFLOW_POLICY.read_text(encoding="utf-8"))
        unsigned = dict(policy)
        unsigned.pop("policy_id")
        self.assertEqual(policy["policy_id"], identity(unsigned))
        managed = {row["filename"] for row in policy["workflows"]}
        self.assertEqual(
            managed,
            {
                "refinement-fast.yml",
                "refinement-nightly.yml",
                "refinement-shadow.yml",
                "refinement-promotion.yml",
            },
        )
        fast = (ROOT / ".github/workflows/refinement-fast.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("${{ secrets.", fast)
        for filename in ("refinement-nightly.yml",):
            text = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            self.assertNotIn("contents: write", text)
            self.assertNotIn("git push", text)
            self.assertNotIn("publish", text)

    def test_review_only_promotion_payload_attestation_replays(self) -> None:
        key = self.external / "promotion.key"
        key_bytes = b"r10-promotion-attestation-key-0001"
        key.write_bytes(key_bytes)
        key.chmod(0o400)
        unsigned = {
            "schema_version": "cigar.refinement-promotion-payload.v1",
            "trial_id": "r10-known-good",
            "candidate_source": {
                "revision": self.revision,
                "tree": self.tree,
            },
            "comparison_id": "1220" + "1" * 64,
            "decision_id": "1220" + "2" * 64,
            "target_branch": "refinement/r10-known-good",
            "operation": "prepare-review-only",
            "merge_authority": False,
            "publication_authority": False,
        }
        payload_id = identity(unsigned)
        payload = {
            **unsigned,
            "payload_id": payload_id,
            "attestation": {
                "algorithm": "hmac-sha256",
                "key_id": "r10-test-key",
                "key_fingerprint": multihash_bytes(key_bytes),
                "mac": hmac.new(
                    key_bytes,
                    canonical_bytes({**unsigned, "payload_id": payload_id}),
                    hashlib.sha256,
                ).hexdigest(),
            },
        }
        path = self.external / "promotion-payload.json"
        path.write_bytes(canonical_bytes(payload))
        arguments = SimpleNamespace(
            repository=ROOT,
            payload=path,
            attestation_key=key,
        )
        result = promotion_verify(arguments)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["merge_authority"])
        self.assertFalse(result["publication_authority"])
        payload["attestation"]["mac"] = "0" * 64
        tampered = self.external / "tampered-promotion-payload.json"
        tampered.write_bytes(canonical_bytes(payload))
        arguments.payload = tampered
        with self.assertRaisesRegex(OperationsError, "attestation"):
            promotion_verify(arguments)


if __name__ == "__main__":
    unittest.main()
