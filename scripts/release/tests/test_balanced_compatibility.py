#!/usr/bin/env python3
from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class BalancedCompatibilityContractTests(unittest.TestCase):
    def test_balanced_v1_is_the_only_release_profile(self) -> None:
        document = json.loads(
            (ROOT / "packaging/honey/compatibility-matrix.v1.json").read_bytes()
        )
        self.assertEqual(
            set(document),
            {"schema_version", "release", "upgrade_from", "compatibility", "rollback"},
        )
        self.assertEqual(
            document["schema_version"], "cigar.honey.compatibility-matrix.v1"
        )
        self.assertEqual(document["release"]["version"], "0.9.2")
        self.assertEqual(
            document["release"]["intelligence"],
            "balanced_v1 only",
        )
        self.assertEqual(document["release"]["release_state"], "developer-preview")
        self.assertFalse(document["release"]["supported"])
        self.assertFalse(document["release"]["production_qualified"])
        self.assertEqual(document["upgrade_from"]["version"], "0.9.1")

        compatibility = document["compatibility"]
        self.assertEqual(compatibility["context_abi"]["before"], "cigar.context.v1")
        self.assertEqual(compatibility["context_abi"]["after"], "cigar.context.v1")
        self.assertEqual(compatibility["public_api"]["before_operations"], 45)
        self.assertEqual(compatibility["public_api"]["after_operations"], 45)
        self.assertEqual(compatibility["python"]["import_before"], "cigar_sdk")
        self.assertEqual(compatibility["python"]["import_after"], "cigar_sdk")
        self.assertTrue(compatibility["configuration"]["existing_configuration_valid"])
        self.assertEqual(
            compatibility["configuration"]["omitted_field_behavior"],
            "balanced_v1",
        )
        self.assertEqual(
            compatibility["configuration"]["accepted_values"], ["balanced_v1"]
        )
        self.assertTrue(
            compatibility["configuration"]["unsupported_values_rejected"]
        )
        self.assertTrue(
            all(
                not value["breaking"]
                for value in compatibility.values()
                if "breaking" in value
            )
        )
        self.assertFalse(document["rollback"]["in_place_state_downgrade_allowed"])

    def test_balanced_release_has_one_exact_0_9_2_python_publication_chain(self) -> None:
        product = json.loads(
            (ROOT / "packaging/product-version.v1.json").read_bytes()
        )
        requirements = json.loads(
            (ROOT / "packaging/honey/release-requirements.v1.json").read_bytes()
        )
        matrix = json.loads(
            (ROOT / "packaging/honey/artifact-matrix.v1.json").read_bytes()
        )
        python_project = tomllib.loads(
            (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
        )
        workflow = (ROOT / ".github/workflows/pypi-honey.yml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(product["version"], "0.9.2")
        self.assertEqual(product["tag"], "v0.9.2")
        self.assertEqual(python_project["project"]["name"], "hol-cigar")
        self.assertEqual(python_project["project"]["version"], "0.9.2")
        self.assertEqual(
            requirements["publication"]["pypi_distribution_version"],
            "0.9.2",
        )
        self.assertEqual(len(matrix["artifacts"]), 13)
        self.assertEqual(
            [
                artifact["filename"]
                for artifact in matrix["artifacts"]
                if artifact["id"] in {"python-sdk-wheel", "python-sdk-sdist"}
            ],
            ["hol_cigar-0.9.2-py3-none-any.whl", "hol_cigar-0.9.2.tar.gz"],
        )
        for binding in (
            "ref: v0.9.2",
            'test "${GITHUB_REF}" = "refs/heads/main"',
            'test "${CONFIRM}" = "publish hol-cigar 0.9.2"',
            '"${candidate_dir}/hol_cigar-0.9.2-py3-none-any.whl"',
            '"${candidate_dir}/hol_cigar-0.9.2.tar.gz"',
            'python3 scripts/release/verify_honey_release.py "${candidate_dir}"',
            "python3 -m twine check --strict dist/*",
            "skip-existing: false",
        ):
            self.assertIn(binding, workflow)


if __name__ == "__main__":
    unittest.main()
