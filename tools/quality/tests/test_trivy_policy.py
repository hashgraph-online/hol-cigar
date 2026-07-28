from __future__ import annotations

import datetime as dt
import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/quality/trivy_policy.py"
SPEC = importlib.util.spec_from_file_location("trivy_policy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
trivy_policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trivy_policy)


class TrivyPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = trivy_policy.load_policy()

    def fixture_report(self) -> dict[str, object]:
        results: list[dict[str, object]] = []
        for required in self.policy["required_scan_targets"]:
            results.append(
                {
                    "Class": required["class"],
                    "Target": required["path"],
                    "Type": required["type"],
                    "Vulnerabilities": [],
                }
            )
        return {
            "ArtifactName": ".",
            "ArtifactType": "filesystem",
            "Results": results,
            "SchemaVersion": 2,
        }

    def distribution_fixture(self, destination: Path) -> Path:
        distribution = self.policy["distribution_reachability"]
        paths = {
            "Cargo.lock",
            "pnpm-lock.yaml",
            "sdk/go/go.sum",
            "sdk/python/uv.lock",
            distribution["artifact_matrix"]["path"],
            distribution["development_profile"]["path"],
            distribution["sbom"]["generator_path"],
            distribution["source_archive"]["builder_path"],
            distribution["source_archive"]["manifest_path"],
            "scripts/release/evidence_workspace.py",
            "scripts/release/release_lib.py",
        }
        matrix = trivy_policy._load_json_object(  # noqa: SLF001
            ROOT / distribution["artifact_matrix"]["path"], "artifact matrix"
        )
        selected = set(distribution["development_profile"]["selected_artifact_ids"])
        for row in matrix["artifacts"]:
            if row["id"] in selected:
                paths.add(f"packaging/{row['contract']}")
        for relative in sorted(paths):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        (destination / "vendor/aws-creds-0.39.1").mkdir(parents=True)
        return destination

    def test_policy_pins_scanner_full_scan_and_no_ignores(self) -> None:
        self.assertEqual(
            self.policy["scanner"],
            {
                "max_database_age_hours": 48,
                "name": "trivy",
                "version": "0.69.2",
            },
        )
        scan = self.policy["scan"]
        self.assertEqual(scan["scanners"], ["vuln"])
        self.assertEqual(scan["severities"], ["HIGH", "CRITICAL"])
        self.assertFalse(scan["ignore_unfixed"])
        self.assertEqual(scan["skip_directories"], [])
        self.assertEqual(scan["skip_files"], [])

    def test_vulnerable_provenance_lock_was_removed_without_a_waiver(self) -> None:
        self.assertEqual(self.policy["candidate_dispositions"], [])
        self.assertFalse((ROOT / "vendor/aws-creds-0.39.1/Cargo.lock").exists())
        self.assertNotIn(
            "vendor/aws-creds-0.39.1/Cargo.lock",
            {target["path"] for target in self.policy["required_scan_targets"]},
        )

    def test_current_source_authority_and_cargo_graph_prove_non_reachability(
        self,
    ) -> None:
        repository = trivy_policy.verify_repository_authority(self.policy)
        self.assertTrue(repository["workspace_excluded"])
        self.assertFalse(repository["beta_source_contains_snapshot"])
        self.assertTrue(repository["development_source_contains_snapshot"])
        self.assertFalse(repository["resolved_lock_forbidden_versions_present"])

        metadata = trivy_policy.cargo_metadata_evidence(self.policy)
        self.assertFalse(metadata["forbidden_versions_present"])
        self.assertTrue(metadata["patched_package_resolved"])
        self.assertGreater(metadata["package_count"], 100)

        distribution = trivy_policy.distribution_reachability_evidence(self.policy)
        self.assertEqual(distribution["profile"]["selected_artifact_count"], 17)
        self.assertEqual(
            distribution["snapshot_distribution"],
            {
                "source_artifact_ids": ["source"],
                "stale_lock_artifact_contract_ids": ["source"],
                "stale_lock_present": False,
            },
        )
        self.assertFalse(distribution["sbom"]["forbidden_versions_present"])
        self.assertTrue(distribution["sbom"]["required_replacements_present"])
        self.assertGreater(distribution["sbom"]["component_count"], 100)

    def test_distribution_proof_rejects_reintroduced_lock_contract_drift_and_sbom_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.distribution_fixture(Path(raw))
            evidence = trivy_policy.distribution_reachability_evidence(
                self.policy, fixture
            )
            self.assertEqual(evidence["profile"]["selected_artifact_count"], 17)

            stale_lock = fixture / "vendor/aws-creds-0.39.1/Cargo.lock"
            stale_lock.write_text("version = 4\n", encoding="utf-8")
            with self.assertRaisesRegex(
                trivy_policy.PolicyError,
                "stale provenance snapshot lock must be absent",
            ):
                trivy_policy.distribution_reachability_evidence(self.policy, fixture)
            stale_lock.unlink()

            docs_contract = fixture / "packaging/contracts/docs-archive.v1.json"
            contract = trivy_policy._load_json_object(  # noqa: SLF001
                docs_contract, "docs contract"
            )
            contract["allow"].append("vendor/**")
            docs_contract.write_bytes(trivy_policy.canonical_json_bytes(contract))
            with self.assertRaisesRegex(
                trivy_policy.PolicyError, "selectable by an unexpected artifact"
            ):
                trivy_policy.distribution_reachability_evidence(self.policy, fixture)
            shutil.copy2(
                ROOT / "packaging/contracts/docs-archive.v1.json", docs_contract
            )

            cargo_lock = fixture / "Cargo.lock"
            cargo_lock.write_text(
                cargo_lock.read_text(encoding="utf-8").replace(
                    'name = "openssl"\nversion = "0.10.80"',
                    'name = "openssl"\nversion = "0.10.66"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                trivy_policy.PolicyError,
                "SBOM dependency union contains a stale package",
            ):
                trivy_policy.distribution_reachability_evidence(self.policy, fixture)

    def test_changed_snapshot_or_workspace_exclusion_fails_closed(self) -> None:
        required = [
            "Cargo.lock",
            "Cargo.toml",
            "crates/cigar-aws-creds/Cargo.toml",
            "packaging/beta/contracts/source-archive.v1.json",
            "packaging/local-archives.v1.json",
            "vendor/aws-creds-0.39.1/Cargo.toml",
        ]
        with tempfile.TemporaryDirectory() as raw:
            fixture = Path(raw)
            for relative in required:
                destination = fixture / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)

            manifest = fixture / "vendor/aws-creds-0.39.1/Cargo.toml"
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                trivy_policy.PolicyError, "provenance snapshot changed"
            ):
                trivy_policy.verify_repository_authority(self.policy, fixture)

            shutil.copy2(ROOT / "vendor/aws-creds-0.39.1/Cargo.toml", manifest)
            workspace = fixture / "Cargo.toml"
            workspace.write_text(
                workspace.read_text(encoding="utf-8").replace(
                    'exclude = ["vendor/aws-creds-0.39.1", "vendor/rust-s3-0.37.2"]',
                    'exclude = ["vendor/rust-s3-0.37.2"]',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(trivy_policy.PolicyError, "no longer excluded"):
                trivy_policy.verify_repository_authority(self.policy, fixture)

    def test_zero_findings_are_eligible_only_for_a_clean_source(self) -> None:
        assessment = trivy_policy.evaluate_report(
            self.fixture_report(), self.policy, source_clean=True
        )
        self.assertEqual(assessment["finding_count"], 0)
        self.assertEqual(assessment["status"], "eligible")
        self.assertTrue(assessment["release_eligible"])
        self.assertEqual(assessment["unclassified_findings"], [])
        self.assertEqual(assessment["missing_candidate_findings"], [])

        dirty = trivy_policy.evaluate_report(
            self.fixture_report(), self.policy, source_clean=False
        )
        self.assertEqual(dirty["status"], "diagnostic_dirty_source")
        self.assertFalse(dirty["release_eligible"])

    def test_report_identity_is_exactly_the_pinned_filesystem_scan(self) -> None:
        for field, value in (
            ("SchemaVersion", 3),
            ("ArtifactName", "subdirectory"),
            ("ArtifactType", "repository"),
        ):
            with self.subTest(field=field):
                report = self.fixture_report()
                report[field] = value
                with self.assertRaisesRegex(
                    trivy_policy.PolicyError, "report identity is unsupported"
                ):
                    trivy_policy.evaluate_report(report, self.policy, source_clean=True)

    def test_any_finding_blocks_without_a_disposition(self) -> None:
        report = self.fixture_report()
        results = report["Results"]
        assert isinstance(results, list)
        root_result = results[0]
        assert isinstance(root_result, dict)
        vulnerabilities = root_result["Vulnerabilities"]
        assert isinstance(vulnerabilities, list)
        vulnerabilities.append(
            {
                "FixedVersion": "",
                "InstalledVersion": "9.9.9",
                "PkgName": "unexpected-package",
                "Severity": "CRITICAL",
                "VulnerabilityID": "CVE-2099-99999",
            }
        )
        assessment = trivy_policy.evaluate_report(
            report, self.policy, source_clean=True
        )
        self.assertEqual(assessment["status"], "blocked_unclassified_findings")
        self.assertFalse(assessment["release_eligible"])
        self.assertEqual(len(assessment["unclassified_findings"]), 1)

    def test_required_dependency_target_cannot_disappear(self) -> None:
        report = self.fixture_report()
        results = report["Results"]
        assert isinstance(results, list)
        results[:] = [
            result
            for result in results
            if not (isinstance(result, dict) and result.get("Target") == "Cargo.lock")
        ]
        with self.assertRaisesRegex(trivy_policy.PolicyError, "omitted required"):
            trivy_policy.evaluate_report(report, self.policy, source_clean=True)

    def test_scan_command_uses_isolated_config_without_suppressions(self) -> None:
        command = trivy_policy.build_scan_command(
            "trivy",
            self.policy,
            Path("/private/config.yml"),
            Path("/private/empty.ignore"),
            Path("/private/report.json"),
        )
        self.assertIn("--offline-scan", command)
        self.assertIn("--disable-telemetry", command)
        self.assertIn("--ignorefile", command)
        self.assertNotIn("--ignore-unfixed", command)
        self.assertNotIn("--skip-dirs", command)
        self.assertNotIn("--skip-files", command)
        self.assertEqual(command[-1], ".")

        previous = os.environ.get("TRIVY_IGNORE_UNFIXED")
        os.environ["TRIVY_IGNORE_UNFIXED"] = "true"
        try:
            self.assertNotIn("TRIVY_IGNORE_UNFIXED", trivy_policy.scanner_environment())
        finally:
            if previous is None:
                os.environ.pop("TRIVY_IGNORE_UNFIXED", None)
            else:
                os.environ["TRIVY_IGNORE_UNFIXED"] = previous

    def test_stale_vulnerability_database_fails_closed(self) -> None:
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=49)
        metadata = {
            "VulnerabilityDB": {
                "DownloadedAt": old.isoformat(),
                "UpdatedAt": old.isoformat(),
                "Version": 2,
            }
        }
        with self.assertRaisesRegex(
            trivy_policy.PolicyError, "stale or from the future"
        ):
            trivy_policy.validate_database_metadata(metadata, 48)

    def test_evidence_output_requires_an_owner_private_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "evidence"
            parent.mkdir(mode=0o755)
            os.chmod(parent, 0o755)
            with self.assertRaisesRegex(trivy_policy.PolicyError, "owner-private"):
                trivy_policy.require_private_directory(parent, "test evidence")

            os.chmod(parent, 0o700)
            trivy_policy.require_private_directory(parent, "test evidence")
            output = parent / "receipt.json"
            trivy_policy.write_new_private(output, b"{}\n")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(trivy_policy.PolicyError, "non-new"):
                trivy_policy.write_new_private(output, b"changed\n")

    def test_ci_pins_setup_action_scanner_and_fail_closed_wrapper(self) -> None:
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertIn(
            "aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567",
            workflow,
        )
        self.assertIn('version: "v0.69.2"', workflow)
        self.assertIn("tools/quality/trivy_policy.py scan", workflow)
        self.assertNotIn("--skip-dirs vendor", workflow)
        self.assertNotIn("--ignore-unfixed", workflow)


if __name__ == "__main__":
    unittest.main()
