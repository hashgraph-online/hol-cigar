from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import context_distribution as distribution  # noqa: E402
import context_distribution_release as release  # noqa: E402
import context_registry_readback as registry  # noqa: E402
from context_sdk_cases import build_cases  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes  # noqa: E402


class InstalledEvidenceTests(unittest.TestCase):
    """A passed summary cannot hide failed, absent, or substituted raw results."""

    def setUp(self):
        self.files = {}
        self.candidate = {
            "source_binding": {"commit": "1" * 40},
            "artifacts": {"archive": "digest"},
        }
        cases = build_cases(release.ROOT)
        self.put("cases.json", cases)
        self.put("programs.json", ["/fixture/python", "/fixture/node"])
        oracle = [{"error": "RequiredUnavailable"} for _ in cases]
        self.put("offline/rust-oracle.json", oracle)
        policy = {
            "kind": "macos-sandbox-deny-network",
            "provider_calls": 0,
            "probes": [
                {"address": address, "errno": 1, "denied": True}
                for address in ("1.1.1.1", "127.0.0.1")
            ],
        }
        self.put("offline/network-policy.json", policy)
        checks = [f"workflow-fixture-{i}" for i in range(13)]
        self.report = {
            "schema": "cigar.context-distribution-qualification.v1",
            "status": "passed",
            "diagnostic": False,
            "platform": "darwin-arm64",
            "runtime": "minimum",
            "versions": release.RUNTIMES["minimum"],
            "source_binding": self.candidate["source_binding"],
            "candidate_artifacts": self.candidate["artifacts"],
            "cases": 172,
            "comparisons": 516,
            "rust_successes": 0,
            "expected_errors": 172,
            "network_policy": policy,
            "full_workflow_checks": checks,
            "legacy_exports": {},
        }
        install = []
        for kind in ("wheel", "sdist"):
            for name in ("venv", "install", "tests", "legacy-entrypoint"):
                install.append(self.log("logs/", f"{kind}-{name}", b"passed\n"))
        install.extend(
            self.log("logs/", name, b"passed\n")
            for name in ("npm-install", "npm-installed-tests")
        )
        offline = []
        for kind in ("wheel", "sdist", "npm"):
            self.report["legacy_exports"][kind] = ["FixtureExport"]
            for name, value, code in (
                (
                    "offline-oracle",
                    {"results": oracle, "exports": ["FixtureExport"]},
                    0,
                ),
                (
                    "doctor",
                    {
                        "status": "ready",
                        "compile_verified": True,
                        "capabilities": {"requires_hol_services": False},
                    },
                    0,
                ),
                (
                    "demo",
                    {
                        "status": "passed",
                        "reviewer": "scripted-fixture",
                        "checks": checks,
                    },
                    0,
                ),
                (
                    "missing-worker",
                    {"error_code": "WorkerUnavailable", "compile_verified": False},
                    1,
                ),
            ):
                offline.append(
                    self.log(
                        "offline/logs/",
                        f"{kind}-{name}",
                        canonical_json_bytes(value),
                        code,
                    )
                )
        self.report["installation_checks"] = install
        self.report["offline_checks"] = offline
        prepared = {
            key: self.report[key]
            for key in (
                "source_binding",
                "candidate_artifacts",
                "diagnostic",
                "platform",
                "runtime",
                "versions",
            )
        }
        prepared.update(
            schema="cigar.context-distribution-install.v1",
            status="installed-tests-passed",
            checks=install,
        )
        prepared.update(
            {
                name: self.record(self.files[f"{name}.json"])
                for name in ("cases", "programs")
            }
        )
        self.put("prepare.json", prepared)
        self.put("qualification.json", self.report)

    def put(self, name, value):
        self.files[name] = canonical_json_bytes(value)

    @staticmethod
    def record(content):
        return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}

    def log(self, prefix, name, content, code=0):
        self.files[f"{prefix}{name}.stdout"] = content
        self.files[f"{prefix}{name}.stderr"] = b""
        return {
            "name": name,
            "exit_code": code,
            "expected_exit": code,
            "stdout": self.record(content),
            "stderr": self.record(b""),
        }

    def verify(self):
        return release.validate_qualification(
            self.files, "", self.candidate, "darwin-arm64", "minimum"
        )

    def test_complete_retained_results_pass(self):
        self.assertEqual(self.verify(), self.report)

    def test_failed_or_omitted_checks_cannot_hide_behind_passed_summary(self):
        for change in ("failed", "omitted", "duplicate"):
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                if change == "failed":
                    report["offline_checks"][0]["exit_code"] = 2
                elif change == "omitted":
                    report["offline_checks"].pop()
                else:
                    report["offline_checks"][-1] = report["offline_checks"][0]
                self.put("qualification.json", report)
                with self.assertRaises(ReleaseError):
                    self.verify()

    def test_raw_consumer_corruption_is_rejected_even_with_updated_log_hash(self):
        name = "npm-offline-oracle"
        result = {
            "results": [{"error": "InvalidInput"}] * 172,
            "exports": ["FixtureExport"],
        }
        content = canonical_json_bytes(result)
        self.files[f"offline/logs/{name}.stdout"] = content
        for row in self.report["offline_checks"]:
            if row["name"] == name:
                row["stdout"] = self.record(content)
        self.put("qualification.json", self.report)
        with self.assertRaisesRegex(ReleaseError, "differs from native oracle"):
            self.verify()

    def test_missing_raw_network_probes_cannot_claim_offline_success(self):
        self.report["network_policy"]["probes"] = []
        self.put("offline/network-policy.json", self.report["network_policy"])
        self.put("qualification.json", self.report)
        with self.assertRaisesRegex(ReleaseError, "offline policy"):
            self.verify()

    def test_another_archive_or_runtime_cannot_reuse_the_evidence(self):
        self.candidate["artifacts"] = {"archive": "different-digest"}
        with self.assertRaisesRegex(ReleaseError, "different source or archives"):
            self.verify()


class RegistryReadbackTests(unittest.TestCase):
    def test_published_version_with_old_default_tag_is_not_success(self):
        metadata = {
            "name": "@hol-org/cigar",
            "dist-tags": {"latest": "0.9.4"},
            "versions": {"0.11.0": {}},
        }
        with mock.patch.object(registry, "metadata", return_value=metadata):
            with self.assertRaisesRegex(ReleaseError, "default install"):
                registry.readback({"payloads": []}, "npm")

    def test_registry_metadata_cannot_hide_changed_downloaded_bytes(self):
        expected = {
            "file": "archive.tgz",
            "bytes": 4,
            "sha256": hashlib.sha256(b"good").hexdigest(),
        }
        with mock.patch.object(registry, "fetch", return_value=b"evil"):
            with self.assertRaisesRegex(ReleaseError, "signed bytes"):
                registry.check_archive(
                    "https://registry.npmjs.org/archive.tgz",
                    "registry.npmjs.org",
                    expected,
                )

    def test_partial_pypi_publication_cannot_pass(self):
        info = {"name": "hol-cigar", "version": "0.11.0"}
        with mock.patch.object(
            registry, "metadata", return_value={"info": info, "urls": []}
        ):
            with self.assertRaisesRegex(ReleaseError, "complete seven-wheel"):
                registry.readback({"payloads": []}, "pypi")


class IndependentBuildTests(unittest.TestCase):
    def test_all_platforms_are_required_by_public_release_profile(self):
        self.assertEqual(len(release.PROFILE.payloads), 14)
        self.assertEqual(
            sum(name.endswith(".whl") for name in release.PROFILE.payloads), 7
        )
        self.assertIn(
            "hol_cigar-0.11.0-py3-none-win_amd64.whl", release.PROFILE.payloads
        )

    def test_same_build_cannot_be_its_own_comparison(self):
        with self.assertRaisesRegex(ReleaseError, "distinct"):
            distribution.compare_candidates(Path("one"), Path("one"), "1" * 40)

    def test_different_worker_or_archive_bytes_block_assembly(self):
        left = {
            "builder": "first",
            "source_binding": {"commit": "1" * 40},
            "artifacts": {"archive": "same"},
            "platforms": ["darwin-arm64"],
            "workers": {"darwin-arm64": {"worker": {"sha256": "same"}}},
        }
        for changed in ("artifacts", "workers"):
            right = copy.deepcopy(left)
            right["builder"] = "second"
            if changed == "artifacts":
                right["artifacts"]["archive"] = "different"
            else:
                right["workers"]["darwin-arm64"]["worker"]["sha256"] = "different"
            with (
                self.subTest(changed=changed),
                mock.patch.object(
                    distribution, "verify_candidate", side_effect=[left, right]
                ),
            ):
                with self.assertRaisesRegex(ReleaseError, "bytes differ"):
                    distribution.compare_candidates(Path("one"), Path("two"), "1" * 40)


if __name__ == "__main__":
    unittest.main()
