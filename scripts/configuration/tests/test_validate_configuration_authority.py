from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "scripts/configuration/validate_configuration_authority.py"
SPEC = importlib.util.spec_from_file_location("configuration_authority", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("configuration authority validator is unavailable")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ConfigurationAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority_path = REPO_ROOT / "spec/configuration/authority-v1.json"
        self.schema_path = REPO_ROOT / "spec/configuration/authority-v1.schema.json"
        self.authority = validator.load_json(self.authority_path)

    def setting(self, setting_id: str) -> dict[str, object]:
        return next(
            setting
            for setting in self.authority["settings"]
            if setting["id"] == setting_id
        )

    def assert_invalid(self, mutation) -> None:
        candidate = copy.deepcopy(self.authority)
        mutation(candidate)
        with self.assertRaises(validator.AuthorityError):
            validator.validate_document(candidate, REPO_ROOT, source_checks=False)

    def test_checked_in_authority_schema_and_source_inventory_validate(self) -> None:
        validator.validate_schema_document(validator.load_json(self.schema_path))
        validator.validate_document(self.authority, REPO_ROOT, source_checks=True)

    def test_duplicate_json_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"schema_version":"one","schema_version":"two"}', encoding="utf-8"
            )
            with self.assertRaises(validator.AuthorityError):
                validator.load_json(path)

    def test_unknown_authority_and_setting_fields_fail_closed(self) -> None:
        self.assert_invalid(lambda candidate: candidate.__setitem__("unknown", True))
        self.assert_invalid(
            lambda candidate: candidate["settings"][0].__setitem__("unknown", True)
        )

    def test_precedence_reordering_and_duplicate_sources_fail_closed(self) -> None:
        self.assert_invalid(
            lambda candidate: candidate.__setitem__(
                "precedence_order", list(reversed(candidate["precedence_order"]))
            )
        )
        self.assert_invalid(
            lambda candidate: candidate["settings"][0].__setitem__(
                "allowed_sources",
                candidate["settings"][0]["allowed_sources"]
                + [candidate["settings"][0]["allowed_sources"][0]],
            )
        )

    def test_secret_raw_values_and_project_authority_fail_closed(self) -> None:
        def raw_value(candidate) -> None:
            setting = next(
                item
                for item in candidate["settings"]
                if item["id"] == "cli.authorization_file"
            )
            setting["value_form"] = "typed_value"

        def project_secret(candidate) -> None:
            setting = next(
                item
                for item in candidate["settings"]
                if item["id"] == "cli.authorization_file"
            )
            setting["project_configuration_forbidden"] = False
            setting["allowed_sources"].insert(2, "project_config")
            setting["precedence"].insert(2, "project_config")

        self.assert_invalid(raw_value)
        self.assert_invalid(project_secret)

    def test_unknown_classification_and_value_form_fail_closed(self) -> None:
        self.assert_invalid(
            lambda candidate: candidate["settings"][0].__setitem__(
                "secret_classification", "raw_secret"
            )
        )
        self.assert_invalid(
            lambda candidate: candidate["settings"][0].__setitem__(
                "value_form", "raw_value"
            )
        )

    def test_mode_incompatible_setting_profile_fails_closed(self) -> None:
        def mutate(candidate) -> None:
            setting = next(
                item for item in candidate["settings"] if item["id"] == "daemon.tls"
            )
            setting["profiles"] = ["local_sidecar"]

        self.assert_invalid(mutate)

    def test_source_inventory_requires_every_rust_configuration_field(self) -> None:
        candidate = copy.deepcopy(self.authority)
        candidate["settings"] = [
            setting
            for setting in candidate["settings"]
            if setting["id"] != "daemon.shared_storage.object.endpoint"
        ]
        with self.assertRaises(validator.AuthorityError):
            validator.validate_document(candidate, REPO_ROOT, source_checks=True)

    def test_large_local_sqlite_capacity_authority_is_explicit_local_and_non_secret(
        self,
    ) -> None:
        setting = self.setting("daemon.local_sqlite_capacity_profile")
        self.assertEqual(setting["profiles"], ["embedded", "local_sidecar"])
        self.assertEqual(setting["allowed_sources"], ["explicit_config"])
        self.assertEqual(setting["precedence"], ["explicit_config"])
        self.assertEqual(setting["default_semantics"], "standard_when_absent")
        self.assertEqual(setting["secret_classification"], "non_secret")
        self.assertTrue(setting["project_configuration_forbidden"])

    def test_intelligence_profile_is_explicit_closed_and_available_to_every_daemon_profile(
        self,
    ) -> None:
        setting = self.setting("daemon.intelligence_profile")
        self.assertEqual(
            setting["profiles"], ["embedded", "local_sidecar", "shared_service"]
        )
        self.assertEqual(setting["allowed_sources"], ["explicit_config"])
        self.assertEqual(setting["precedence"], ["explicit_config"])
        self.assertEqual(setting["default_semantics"], "balanced_v3_when_absent")
        self.assertEqual(
            setting["required_semantics"],
            "closed_balanced_v1_balanced_v3_balanced_v4",
        )
        self.assertEqual(setting["secret_classification"], "non_secret")
        self.assertTrue(setting["project_configuration_forbidden"])

    def test_source_inventory_paths_reject_absolute_traversal_and_symlink_escape(
        self,
    ) -> None:
        for invalid in [
            "/tmp/source.rs",
            "../source.rs",
            "crates/../source.rs",
            "crates//source.rs",
            "crates\\source.rs",
        ]:
            with self.assertRaises(validator.AuthorityError):
                validator._inventory_source_path(REPO_ROOT, invalid)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            outside = Path(directory) / "outside.rs"
            outside.write_text("struct Outside {}\n", encoding="utf-8")
            (root / "linked.rs").symlink_to(outside)
            with self.assertRaises(validator.AuthorityError):
                validator._inventory_source_path(root, "linked.rs")

    def test_file_policy_shape_identity_and_descriptor_binding_fail_closed(
        self,
    ) -> None:
        self.assert_invalid(
            lambda candidate: candidate["file_policies"][0].__setitem__("unknown", True)
        )
        self.assert_invalid(
            lambda candidate: candidate["file_policies"][0].__setitem__(
                "links", "regular file"
            )
        )
        self.assert_invalid(lambda candidate: candidate["file_policies"].pop())

    def test_provider_records_are_closed_unique_and_profile_bounded(self) -> None:
        self.assert_invalid(
            lambda candidate: candidate["secret_provider_qualification"]["frozen"][
                0
            ].__setitem__("unknown", True)
        )
        self.assert_invalid(
            lambda candidate: candidate["secret_provider_qualification"]["open"][
                0
            ].__setitem__("profiles", ["windows_service"])
        )
        self.assert_invalid(
            lambda candidate: candidate["secret_provider_qualification"]["open"][
                0
            ].__setitem__(
                "provider",
                candidate["secret_provider_qualification"]["frozen"][0]["provider"],
            )
        )

    def test_ambient_proxy_credential_and_netrc_inventory_is_complete(self) -> None:
        self.assert_invalid(
            lambda candidate: candidate["ambient_authority"][
                "proxy_environment"
            ].remove("http_proxy")
        )
        self.assert_invalid(
            lambda candidate: candidate["ambient_authority"][
                "credential_environment"
            ].remove("CIGAR_TOKEN")
        )
        self.assert_invalid(
            lambda candidate: candidate["ambient_authority"][
                "filesystem_conventions"
            ].remove("$HOME/.netrc")
        )

    def test_schema_mirror_rejects_enum_drift(self) -> None:
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        schema["$defs"]["setting"]["properties"]["secret_classification"][
            "enum"
        ].append("raw_secret")
        with self.assertRaises(validator.AuthorityError):
            validator.validate_schema_document(schema)


if __name__ == "__main__":
    unittest.main()
