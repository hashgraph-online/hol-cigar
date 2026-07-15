#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / "scripts/release"
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import generate_license_inventory as inventory  # noqa: E402
from release_lib import ReleaseError, sha256_file  # noqa: E402


class LockedUpstreamLicenseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-license-authority-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "packaging/licenses").mkdir(parents=True)
        (self.root / "sdk/python").mkdir(parents=True)
        for relative in (
            "pnpm-lock.yaml",
            "sdk/python/uv.lock",
            "packaging/licenses/locked-upstream-license-evidence.v1.json",
        ):
            shutil.copyfile(ROOT / relative, self.root / relative)

    @property
    def authority_path(self) -> Path:
        return self.root / "packaging/licenses/locked-upstream-license-evidence.v1.json"

    def authority(self) -> dict[str, object]:
        return json.loads(self.authority_path.read_text(encoding="utf-8"))

    def write_authority(self, document: dict[str, object]) -> None:
        self.authority_path.write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )

    def test_repository_authority_is_lock_bound_and_complete(self) -> None:
        evidence = inventory._load_upstream_license_evidence(ROOT)

        self.assertEqual(len(evidence), 20)
        self.assertEqual(
            evidence["pkg:npm/%40typescript/typescript-aix-ppc64@7.0.2"],
            {
                "license_expression": "Apache-2.0",
                "notice_sha256": [
                    "f5c708b59114507b8b27b48181b6883d106bbca0c1634bbee45b5e344237b66b"
                ],
            },
        )
        self.assertEqual(
            evidence["pkg:pypi/colorama@0.4.6"],
            {"license_expression": "BSD-3-Clause", "notice_sha256": []},
        )

    def test_committed_inventory_exactly_binds_the_source_authority(self) -> None:
        authority_path = (
            ROOT / "packaging/licenses/locked-upstream-license-evidence.v1.json"
        )
        evidence = inventory._load_upstream_license_evidence(ROOT)
        committed = json.loads(
            (ROOT / "packaging/licenses/third-party-inventory.v1.json").read_text(
                encoding="utf-8"
            )
        )
        fallbacks = {
            entry["purl"]: entry
            for entry in committed["components"]
            if entry["metadata_source"] == "locked-upstream-license-evidence"
        }

        self.assertEqual(committed["status"], "complete")
        self.assertEqual(committed["review_required_count"], 0)
        self.assertEqual(committed["upstream_evidence_record_count"], len(evidence))
        self.assertEqual(
            committed["upstream_evidence_sha256"], sha256_file(authority_path)
        )
        self.assertEqual(set(fallbacks), set(evidence))
        for purl, upstream in evidence.items():
            self.assertEqual(
                fallbacks[purl]["license_expression"],
                upstream["license_expression"],
            )
            self.assertEqual(fallbacks[purl]["policy_status"], "accepted-by-policy")

    def test_lock_digest_and_identity_substitution_fail_closed(self) -> None:
        for mutation, expected in (
            (
                lambda document: document["records"][0]["lock"].update(
                    {"digest": "0" * 128}
                ),
                "lock binding is stale",
            ),
            (
                lambda document: document["records"][0].update({"version": "7.0.3"}),
                "stale or substituted",
            ),
        ):
            with self.subTest(expected=expected):
                document = self.authority()
                mutation(document)
                self.write_authority(document)
                with self.assertRaisesRegex(ReleaseError, expected):
                    inventory._load_upstream_license_evidence(self.root)
                shutil.copyfile(
                    ROOT
                    / "packaging/licenses/locked-upstream-license-evidence.v1.json",
                    self.authority_path,
                )

    def test_archive_and_registry_metadata_substitution_fail_closed(self) -> None:
        document = self.authority()
        record = document["records"][0]
        replacement = "https://registry.npmjs.org/substituted/-/substituted-7.0.2.tgz"
        record["archive"]["url"] = replacement
        record["metadata"]["subset"]["dist"]["tarball"] = replacement
        record["metadata"]["canonical_subset_sha256"] = (
            inventory._canonical_json_sha256(record["metadata"]["subset"])
        )
        self.write_authority(document)

        with self.assertRaisesRegex(ReleaseError, "upstream evidence is inconsistent"):
            inventory._load_upstream_license_evidence(self.root)

        document = self.authority()
        record = document["records"][0]
        record["metadata"]["subset"]["license"] = "MIT"
        self.write_authority(document)
        with self.assertRaisesRegex(ReleaseError, "metadata digest is invalid"):
            inventory._load_upstream_license_evidence(self.root)

    def test_pypi_size_substitution_fails_against_uv_lock(self) -> None:
        document = self.authority()
        record = document["records"][-1]
        record["archive"]["bytes"] += 1
        record["metadata"]["subset"]["sdist"]["size"] += 1
        record["metadata"]["canonical_subset_sha256"] = (
            inventory._canonical_json_sha256(record["metadata"]["subset"])
        )
        self.write_authority(document)

        with self.assertRaisesRegex(
            ReleaseError, "PyPI upstream evidence is inconsistent"
        ):
            inventory._load_upstream_license_evidence(self.root)

    def test_duplicate_records_files_and_json_keys_are_rejected(self) -> None:
        document = self.authority()
        document["records"].append(copy.deepcopy(document["records"][-1]))
        self.write_authority(document)
        with self.assertRaisesRegex(ReleaseError, "record is duplicate"):
            inventory._load_upstream_license_evidence(self.root)

        document = self.authority()
        document["license_files"].append(copy.deepcopy(document["license_files"][-1]))
        self.write_authority(document)
        with self.assertRaisesRegex(ReleaseError, "file identity is duplicate"):
            inventory._load_upstream_license_evidence(self.root)

        self.authority_path.write_text(
            '{"schema_version":"first","schema_version":"second"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReleaseError, "duplicate key"):
            inventory._load_upstream_license_evidence(self.root)

    def test_unsafe_license_path_is_rejected(self) -> None:
        document = self.authority()
        document["license_files"][0]["path"] = "../LICENSE"
        self.write_authority(document)

        with self.assertRaisesRegex(ReleaseError, "path is invalid"):
            inventory._load_upstream_license_evidence(self.root)

    def test_fallback_requires_an_archive_license_text_reference(self) -> None:
        document = self.authority()
        document["records"][0]["license_file_ids"] = ["typescript-7.0.2-notice"]
        self.write_authority(document)

        with self.assertRaisesRegex(ReleaseError, "license text reference is missing"):
            inventory._load_upstream_license_evidence(self.root)

    def test_fallback_is_exact_and_local_conflicts_fail_closed(self) -> None:
        purl = "pkg:npm/%40typescript/typescript-aix-ppc64@7.0.2"
        upstream = {
            purl: {
                "license_expression": "Apache-2.0",
                "notice_sha256": ["a" * 64],
            }
        }
        unavailable = [
            {
                "purl": purl,
                "license_expression": "NOASSERTION",
                "metadata_source": "unavailable",
                "notice_sha256": [],
            }
        ]

        inventory._apply_upstream_license_evidence(unavailable, upstream)

        self.assertEqual(unavailable[0]["license_expression"], "Apache-2.0")
        self.assertEqual(
            unavailable[0]["metadata_source"], "locked-upstream-license-evidence"
        )
        self.assertEqual(unavailable[0]["notice_sha256"], ["a" * 64])

        conflicting_license = copy.deepcopy(unavailable)
        conflicting_license[0]["license_expression"] = "MIT"
        with self.assertRaisesRegex(ReleaseError, "license metadata conflicts"):
            inventory._apply_upstream_license_evidence(conflicting_license, upstream)

        conflicting_notice = copy.deepcopy(unavailable)
        conflicting_notice[0]["notice_sha256"] = ["b" * 64]
        with self.assertRaisesRegex(ReleaseError, "notice metadata conflicts"):
            inventory._apply_upstream_license_evidence(conflicting_notice, upstream)


if __name__ == "__main__":
    unittest.main()
