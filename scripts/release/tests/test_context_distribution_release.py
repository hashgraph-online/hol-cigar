from __future__ import annotations

import copy
import hashlib
import json
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
        receipts = {}
        for kind in ("wheel", "sdist"):
            for name in ("venv", "install", "tests", "legacy-entrypoint"):
                install.append(self.log("logs/", f"{kind}-{name}", b"passed\n"))
            receipts[kind] = {
                "schema": "cigar.installed-runtime-dependencies.v1",
                "ecosystem": "pypi",
                "name": "hol-cigar",
                "version": distribution.VERSION,
                "requirements": ["protobuf<8,>=6.33.5"],
                "components": [
                    {
                        "name": "protobuf",
                        "version": release.PROTOBUF_VERSIONS["minimum"],
                        "license": "3-Clause BSD License",
                        "metadata_sha256": "2" * 64,
                        "record_sha256": "3" * 64,
                    }
                ],
            }
        receipts["npm"] = {
            "schema": "cigar.installed-runtime-dependencies.v1",
            "ecosystem": "npm",
            "name": "@hol-org/cigar",
            "version": distribution.VERSION,
            "requirements": {"@bufbuild/protobuf": "2.11.0"},
            "components": [
                {
                    "name": "@bufbuild/protobuf",
                    "version": "2.11.0",
                    "license": "Apache-2.0",
                    "metadata_sha256": "4" * 64,
                    "integrity": "sha512-fixture",
                }
            ],
        }
        self.report["runtime_dependencies"] = receipts
        for kind, receipt in receipts.items():
            install.append(
                self.log("logs/", f"{kind}-dependencies", canonical_json_bytes(receipt))
            )
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
                "runtime_dependencies",
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

    def test_dependency_summary_cannot_substitute_installed_versions(self):
        self.report["runtime_dependencies"]["wheel"]["components"][0]["version"] = (
            "7.36.2"
        )
        self.put("qualification.json", self.report)
        with self.assertRaisesRegex(ReleaseError, "runtime dependency evidence"):
            self.verify()

    def test_sbom_uses_installed_versions_and_requires_complete_dependency_evidence(
        self,
    ):
        native = {
            "darwin-arm64": [
                {
                    "name": "cigar-context",
                    "version": distribution.VERSION,
                    "license": "Apache-2.0",
                    "dependencies": [],
                }
            ]
        }
        candidate = {"platforms": ["darwin-arm64"], "artifacts": {"fixture.whl": {}}}
        npm = {
            "name": "@hol-org/cigar",
            "version": distribution.VERSION,
            "dependencies": {"@bufbuild/protobuf": "2.11.0"},
            "license": "Apache-2.0",
        }
        wheel = (
            f"Name: hol-cigar\nVersion: {distribution.VERSION}\n"
            "Requires-Dist: protobuf<8,>=6.33.5\nLicense-Expression: Apache-2.0\n\n"
        ).encode()

        def archives(path):
            return (
                {"package/package.json": json.dumps(npm).encode()}
                if str(path).endswith(".tgz")
                else {"fixture.dist-info/METADATA": wheel}
            )

        with mock.patch.object(distribution, "archive_files", side_effect=archives):
            sbom = release.make_sbom(
                Path("fixture"), candidate, [self.report], inventories=native
            )
            refs = {item["purl"] for item in sbom["components"]}
            self.assertIn("pkg:pypi/protobuf@6.33.5", refs)
            self.assertIn("pkg:npm/%40bufbuild/protobuf@2.11.0", refs)
            edges = {item["ref"]: item["dependsOn"] for item in sbom["dependencies"]}
            self.assertIn(
                "pkg:pypi/protobuf@6.33.5",
                edges[f"pkg:pypi/hol-cigar@{distribution.VERSION}"],
            )
            spdx = release.legacy.make_spdx(sbom, "1" * 40, 1, release.PROFILE)
            self.assertTrue(
                any(
                    item["relationshipType"] == "DEPENDS_ON"
                    for item in spdx["relationships"]
                )
            )
            for mutation in ("version", "missing", "license"):
                changed = copy.deepcopy(self.report)
                package = changed["runtime_dependencies"]["npm"]["components"][0]
                if mutation == "version":
                    package["version"] = "2.12.0"
                elif mutation == "missing":
                    changed["runtime_dependencies"]["npm"]["components"] = []
                else:
                    package["license"] = None
                with self.subTest(mutation=mutation), self.assertRaises(ReleaseError):
                    release.make_sbom(
                        Path("fixture"), candidate, [changed], inventories=native
                    )


class RegistryReadbackTests(unittest.TestCase):
    def test_published_version_with_old_default_tag_is_not_success(self):
        metadata = {
            "name": "@hol-org/cigar",
            "dist-tags": {"latest": "0.9.4"},
            "versions": {"0.12.0": {}},
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
        info = {"name": "hol-cigar", "version": "0.12.0"}
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
            "hol_cigar-0.12.0-py3-none-win_amd64.whl", release.PROFILE.payloads
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
