from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import unittest


RELEASE = Path(__file__).resolve().parents[1]
ROOT = RELEASE.parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import honey_profile  # noqa: E402
import product_version  # noqa: E402
from release_lib import canonical_json_bytes, load_json, write_json  # noqa: E402


class HoneyProfileTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    fixture: Path

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-honey-authority-")
        self.fixture = Path(self.temporary.name)
        shutil.copytree(
            ROOT / "adapters/claude-code", self.fixture / "adapters/claude-code"
        )
        paths = set(product_version.managed_paths())
        paths.update(
            {
                honey_profile.OPERATION_SOURCE,
                honey_profile.PAYLOAD_SOURCE,
                honey_profile.PAYLOAD_SCHEMA_SOURCE,
                honey_profile.EVIDENCE_SCHEMA_PATH,
                "packaging/honey/contracts/demos-archive.v1.json",
                "packaging/contracts/source-archive.v1.json",
                "packaging/contracts/docs-archive.v1.json",
                "packaging/contracts/macos-runtime-archive.v1.json",
                "packaging/contracts/npm-package.v1.json",
                "packaging/contracts/plugin-archive.v1.json",
            }
        )
        paths.update(honey_profile.expected_documents(ROOT))
        for relative in sorted(paths):
            if relative.startswith("adapters/claude-code/"):
                continue
            source = ROOT / relative
            destination = self.fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _mutate(self, relative: str, callback) -> None:  # type: ignore[no-untyped-def]
        path = self.fixture / relative
        document = load_json(path)
        callback(document)
        write_json(path, document)

    def _authority_bytes(self) -> dict[str, bytes]:
        return {
            relative: (self.fixture / relative).read_bytes()
            for relative in honey_profile.expected_documents(self.fixture)
        }

    def test_checked_in_authority_is_exact_and_non_mutating(self) -> None:
        before = {
            relative: (ROOT / relative).read_bytes()
            for relative in honey_profile.expected_documents(ROOT)
        }
        honey_profile.check(ROOT)
        after = {
            relative: (ROOT / relative).read_bytes()
            for relative in honey_profile.expected_documents(ROOT)
        }
        self.assertEqual(after, before)
        matrix = load_json(ROOT / honey_profile.MATRIX_PATH)
        self.assertEqual(len(matrix["artifacts"]), 13)
        self.assertEqual(
            [entry["order"] for entry in matrix["artifacts"]], list(range(1, 14))
        )
        portable = matrix["artifacts"][:3]
        self.assertTrue(
            all("--require-committed-clean" in row["producer"] for row in portable)
        )
        qualification = next(
            row
            for row in matrix["internal_inputs"]
            if row["id"] == "qualification-tools"
        )
        self.assertEqual(
            qualification["artifact_id"], "cigar-conformance-macos-aarch64"
        )
        self.assertEqual(
            qualification["producer"],
            [
                "python3",
                "scripts/release/build_macos_qualification_tools.py",
                "conformance",
            ],
        )
        source_contract = load_json(
            ROOT / "packaging/honey/contracts/source-archive.v1.json"
        )
        exemptions = {
            row["pattern"]: row for row in source_contract["content_scan_exemptions"]
        }
        self.assertIn("scripts/release/release_lib.py", exemptions)
        for relative in (
            "crates/xtask/native_macos_command_plane.py",
            "crates/xtask/tests/test_native_macos_command_plane.py",
            "tools/refinement/tests/test_r11_loop.py",
        ):
            self.assertEqual(exemptions[relative]["findings"], ["private-key"])

    def test_generation_is_deterministic_and_schemas_are_exact(self) -> None:
        static_before = (self.fixture / honey_profile.EVIDENCE_SCHEMA_PATH).read_bytes()
        honey_profile.generate(self.fixture)
        first = self._authority_bytes()
        honey_profile.generate(self.fixture)
        self.assertEqual(self._authority_bytes(), first)
        self.assertEqual(
            (self.fixture / honey_profile.EVIDENCE_SCHEMA_PATH).read_bytes(),
            static_before,
        )
        for relative, document in honey_profile.expected_documents(
            self.fixture
        ).items():
            self.assertEqual(
                (self.fixture / relative).read_bytes(), canonical_json_bytes(document)
            )
            if "/schemas/" in relative:
                self.assertEqual(
                    load_json(self.fixture / relative)["const"],
                    document_for_schema(relative, self.fixture),
                )

    def test_static_evidence_schema_is_digest_bound_and_not_generated(self) -> None:
        self.assertNotIn(
            honey_profile.EVIDENCE_SCHEMA_PATH,
            honey_profile.expected_documents(self.fixture),
        )
        schema = self.fixture / honey_profile.EVIDENCE_SCHEMA_PATH
        schema.write_bytes(schema.read_bytes() + b"\n")
        with self.assertRaisesRegex(
            honey_profile.HoneyProfileError,
            "Honey static authority drift",
        ):
            honey_profile.check(self.fixture)
        with self.assertRaisesRegex(
            honey_profile.HoneyProfileError,
            "Honey static authority drift",
        ):
            honey_profile.generate(self.fixture)

    def test_rejects_unknown_capability(self) -> None:
        self._mutate(
            honey_profile.PROFILE_PATH,
            lambda document: document["capabilities"][0].update(
                id="unknown-capability"
            ),
        )
        with self.assertRaisesRegex(honey_profile.HoneyProfileError, "authority drift"):
            honey_profile.check(self.fixture)

    def test_rejects_duplicate_artifact(self) -> None:
        self._mutate(
            honey_profile.MATRIX_PATH,
            lambda document: document["artifacts"][1].update(
                id=document["artifacts"][0]["id"]
            ),
        )
        with self.assertRaisesRegex(honey_profile.HoneyProfileError, "authority drift"):
            honey_profile.check(self.fixture)

    def test_rejects_stale_honey_filename(self) -> None:
        self._mutate(
            honey_profile.MATRIX_PATH,
            lambda document: document["artifacts"][0].update(
                filename="cigar-0.9.0-honey.1-source.tar.gz"
            ),
        )
        with self.assertRaisesRegex(honey_profile.HoneyProfileError, "authority drift"):
            honey_profile.check(self.fixture)

    def test_rejects_operation_drift(self) -> None:
        path = self.fixture / honey_profile.OPERATION_SOURCE
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(
            honey_profile.HoneyProfileError, "protocol authority drift"
        ):
            honey_profile.check(self.fixture)

    def test_rejects_deferred_platform_leakage(self) -> None:
        self._mutate(
            honey_profile.MATRIX_PATH,
            lambda document: document["artifacts"][3].update(workspace="windows"),
        )
        with self.assertRaisesRegex(honey_profile.HoneyProfileError, "authority drift"):
            honey_profile.check(self.fixture)

    def test_rejects_true_production_support_claim(self) -> None:
        self._mutate(
            honey_profile.REQUIREMENTS_PATH,
            lambda document: document["machine_claims"].update(supported=True),
        )
        with self.assertRaisesRegex(honey_profile.HoneyProfileError, "authority drift"):
            honey_profile.check(self.fixture)

    def test_rejects_missing_contract(self) -> None:
        (self.fixture / "packaging/honey/contracts/demos-archive.v1.json").unlink()
        with self.assertRaisesRegex(
            honey_profile.HoneyProfileError, "contract for honey-demos"
        ):
            honey_profile.check(self.fixture)


def document_for_schema(relative: str, root: Path) -> dict[str, object]:
    filename = Path(relative).name.replace(".schema.json", ".json")
    mapping = {
        Path(honey_profile.PROFILE_PATH).name: honey_profile.PROFILE_PATH,
        Path(honey_profile.MATRIX_PATH).name: honey_profile.MATRIX_PATH,
        Path(honey_profile.REQUIREMENTS_PATH).name: honey_profile.REQUIREMENTS_PATH,
        Path(honey_profile.OWNERSHIP_PATH).name: honey_profile.OWNERSHIP_PATH,
        Path(honey_profile.ARCHIVES_PATH).name: honey_profile.ARCHIVES_PATH,
    }
    return load_json(root / mapping[filename])


if __name__ == "__main__":
    unittest.main()
