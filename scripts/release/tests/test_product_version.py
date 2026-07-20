#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
ROOT = RELEASE.parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import product_version  # noqa: E402


EXPECTED_MANAGED_PATHS = {
    "Cargo.lock",
    "Cargo.toml",
    "adapters/claude-code/.claude-plugin/plugin.json",
    "adapters/claude-code/package-manifest.json",
    "adapters/claude-code/tests/validate-package.ps1",
    "adapters/claude-code/tests/validate_package.py",
    "benches/cigarbench/local_scale_driver/Cargo.lock",
    "conformance/runner/Cargo.toml",
    "crates/cigar-api/release.json",
    "crates/cigar-canon/release.json",
    "crates/cigar-catalog/release.json",
    "crates/cigar-cli/Cargo.toml",
    "crates/cigar-cli/man/cigar.1",
    "crates/cigar-cli/src/lib.rs",
    "crates/cigar-code-intel/release.json",
    "crates/cigar-compiler/release.json",
    "crates/cigar-crypto/release.json",
    "crates/cigar-daemon/Cargo.toml",
    "crates/cigar-daemon/release.json",
    "crates/cigar-daemon/src/process.rs",
    "crates/cigar-effects/release.json",
    "crates/cigar-observe/release.json",
    "crates/cigar-policy/release.json",
    "crates/cigar-protocol/release.json",
    "crates/cigar-replay/release.json",
    "crates/cigar-retrieval/release.json",
    "crates/cigar-space/release.json",
    "crates/cigar-store/release.json",
    "crates/cigar-testkit/release.json",
    "crates/cigar-windows-ipc/release.json",
    "demos/sdk-clients/rust-workflow/Cargo.lock",
    "demos/README.md",
    "demos/agent-handoff/driver.py",
    "demos/storage-migration/run.py",
    "docs/site/index.md",
    "docs/site-manifest.v1.json",
    "fuzz/Cargo.lock",
    "packaging/artifact-matrix.v1.json",
    "packaging/contracts/cargo-crate.v1.json",
    "packaging/contracts/go-module.v1.json",
    "packaging/contracts/homebrew-bottle.v1.json",
    "packaging/contracts/python-sdist.v1.json",
    "packaging/contracts/python-wheel.v1.json",
    "packaging/local-archives.v1.json",
    "packaging/product-version.v1.json",
    "pyproject.toml",
    "scripts/release/README.md",
    "scripts/release/check_docs.py",
    "scripts/release/qualify_install.py",
    "scripts/release/run_local_qualification.py",
    "sdk/go/release.json",
    "sdk/go/release_contract_test.go",
    "sdk/python/pyproject.toml",
    "sdk/python/src/cigar_sdk/release.json",
    "sdk/python/tests/test_release_contract.py",
    "sdk/python/uv.lock",
    "sdk/rust/Cargo.toml",
    "sdk/rust/PUBLISHING.md",
    "sdk/rust/qualify_publication_chain.py",
    "sdk/rust/release.json",
    "sdk/README.md",
    "sdk/typescript/package.json",
    "sdk/typescript/release.json",
    "sdk/typescript/src/tests/release-contract.test.ts",
    "tests/miri/Cargo.lock",
    "tests/properties/Cargo.lock",
    "uv.lock",
}

EXCLUDED_FIXTURES = (
    "apps/dashboard/package.json",
    "crates/cigar-aws-creds/Cargo.toml",
    "crates/cigar-aws-creds/release.json",
    "crates/cigar-rust-s3/Cargo.toml",
    "crates/cigar-rust-s3/release.json",
    "conformance/vectors/v1/fixture.toml",
    "crates/cigar-dashboard/src/status.rs",
    "demos/sdk-clients/rust-workflow/Cargo.toml",
    "packaging/beta/product-version.v1.json",
    "schemas/openapi/cigar-v1.json",
    "scripts/release/selftest_release_verifier.py",
    "sdk/go/grpc_contract_test.go",
    "sdk/python/tests/test_client.py",
    "sdk/rust/tests/remote_http.rs",
)


class ProductVersionTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    fixture: Path

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-product-version-")
        self.fixture = Path(self.temporary.name)
        shutil.copytree(
            ROOT / "adapters/claude-code", self.fixture / "adapters/claude-code"
        )
        for relative in sorted(EXPECTED_MANAGED_PATHS):
            if relative.startswith("adapters/claude-code/"):
                continue
            source = ROOT / relative
            destination = self.fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        for relative in EXCLUDED_FIXTURES:
            source = ROOT / relative
            destination = self.fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manifest(self) -> dict[str, object]:
        return json.loads(
            (self.fixture / product_version.MANIFEST_PATH).read_text(encoding="utf-8")
        )

    def _write_manifest(self, document: dict[str, object]) -> None:
        (self.fixture / product_version.MANIFEST_PATH).write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

    def _managed_bytes(self) -> dict[str, bytes]:
        return {
            relative: (self.fixture / relative).read_bytes()
            for relative in EXPECTED_MANAGED_PATHS
        }

    def test_authority_and_managed_inventory_are_exact(self) -> None:
        self.assertEqual(set(product_version.managed_paths()), EXPECTED_MANAGED_PATHS)
        self.assertEqual(
            self._manifest(),
            {
                "schema_version": "cigar.product-version.v1",
                "product": "cigar",
                "version": "0.9.1-honey.1",
                "target_release_version": "0.9.1",
                "context_abi": "cigar.context.v1",
                "release_state": "developer-preview",
                "channel": "honey",
                "prerelease": True,
                "published": False,
                "supported": False,
                "tag": "v0.9.1-honey.1",
            },
        )
        self.assertEqual(
            (self.fixture / product_version.MANIFEST_PATH)
            .read_text(encoding="utf-8")
            .count('"tag"'),
            1,
        )
        self.assertEqual(
            product_version.python_distribution_version("0.9.1-honey.1"),
            "0.9.1.dev1",
        )
        self.assertEqual(
            product_version.derived_versions("0.9.1-honey.1"),
            {
                "typescript": "0.9.1-honey.1",
                "python": "0.9.1.dev1",
                "rust": "0.9.1-honey.1",
                "plugin": "0.9.1-honey.1",
                "archive": "0.9.1-honey.1",
            },
        )
        matrix = json.loads(
            (self.fixture / "packaging/artifact-matrix.v1.json").read_text(
                encoding="utf-8"
            )
        )
        filenames = {entry["id"]: entry["filename"] for entry in matrix["artifacts"]}
        self.assertEqual(filenames["python-sdk-sdist"], "cigar_sdk-0.9.1.dev1.tar.gz")
        self.assertEqual(
            filenames["python-sdk-wheel"],
            "cigar_sdk-0.9.1.dev1-py3-none-any.whl",
        )
        self.assertEqual(
            filenames["macos-installer-arm64"],
            "cigar--0.9.1-honey.1.arm64_sequoia.bottle.tar.gz",
        )
        product_version.check(self.fixture)

    def test_generation_is_deterministic_and_propagates_one_increment(self) -> None:
        manifest = self._manifest()
        manifest["version"] = "0.9.1-honey.2"
        manifest["tag"] = "v0.9.1-honey.2"
        self._write_manifest(manifest)
        product_version.generate(self.fixture)
        first = self._managed_bytes()
        product_version.generate(self.fixture)
        self.assertEqual(self._managed_bytes(), first)
        self.assertEqual(list(self.fixture.rglob("*.product-version.*.tmp")), [])
        self.assertIn(b'version = "0.9.1-honey.2"', first["Cargo.toml"])
        self.assertIn(b'version = "0.9.1.dev2"', first["sdk/python/pyproject.toml"])
        self.assertIn(
            b'"product_version": "0.9.1-honey.2"',
            first["packaging/artifact-matrix.v1.json"],
        )
        self.assertIn(
            b'"filename": "cigar_sdk-0.9.1.dev2.tar.gz"',
            first["packaging/artifact-matrix.v1.json"],
        )
        self.assertIn(
            b'"filename": "cigar--0.9.1-honey.2.arm64_sequoia.bottle.tar.gz"',
            first["packaging/artifact-matrix.v1.json"],
        )
        self.assertIn(
            b'"install_target": "homebrew-cellar/cigar/0.9.1-honey.2"',
            first["packaging/artifact-matrix.v1.json"],
        )
        self.assertIn(
            b"cigar_sdk-0.9.1.dev2.dist-info/",
            first["packaging/contracts/python-wheel.v1.json"],
        )
        self.assertIn(
            b"cigar_sdk-0.9.1.dev2-py3-none-any.whl",
            first["demos/README.md"],
        )
        self.assertIn(
            b'"version": "0.9.1-honey.2"', first["sdk/typescript/package.json"]
        )

    def test_generator_does_not_mutate_excluded_version_domains(self) -> None:
        before = {
            relative: (self.fixture / relative).read_bytes()
            for relative in EXCLUDED_FIXTURES
        }
        manifest = self._manifest()
        manifest["version"] = "0.9.1-honey.2"
        manifest["tag"] = "v0.9.1-honey.2"
        self._write_manifest(manifest)
        product_version.generate(self.fixture)
        after = {
            relative: (self.fixture / relative).read_bytes()
            for relative in EXCLUDED_FIXTURES
        }
        self.assertEqual(after, before)

    def test_check_rejects_managed_drift(self) -> None:
        path = self.fixture / "sdk/typescript/package.json"
        path.write_text(
            path.read_text(encoding="utf-8").replace("0.9.1-honey.1", "9.9.9"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(product_version.VersionError, "version drift"):
            product_version.check(self.fixture)

    def test_manifest_rejects_publication_and_duplicate_keys(self) -> None:
        manifest = self._manifest()
        manifest["published"] = True
        self._write_manifest(manifest)
        with self.assertRaisesRegex(product_version.VersionError, "non-published"):
            product_version.check(self.fixture)

        manifest["published"] = False
        self._write_manifest(manifest)
        path = self.fixture / product_version.MANIFEST_PATH
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '  "tag": "v0.9.1-honey.1"\n',
                '  "tag": "v0.9.1-honey.1",\n  "tag": "v0.9.1-honey.1"\n',
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(product_version.VersionError, "duplicate JSON key"):
            product_version.check(self.fixture)

    def test_json_rejects_nonfinite_and_oversized_documents(self) -> None:
        package = self.fixture / "sdk/typescript/package.json"
        package.write_text(
            package.read_text(encoding="utf-8").replace(
                '  "sideEffects": false,\n',
                '  "sideEffects": false,\n  "probe": NaN,\n',
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(product_version.VersionError, "non-finite"):
            product_version.check(self.fixture)

        shutil.copy2(ROOT / "sdk/typescript/package.json", package)
        with mock.patch.object(product_version, "MAX_JSON_BYTES", 64):
            with self.assertRaisesRegex(product_version.VersionError, "JSON exceeds"):
                product_version.check(self.fixture)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_check_and_generate_reject_managed_symlink(self) -> None:
        path = self.fixture / "sdk/typescript/package.json"
        target = path.with_name("package.target.json")
        path.rename(target)
        path.symlink_to(target.name)
        for operation in (product_version.check, product_version.generate):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(
                    product_version.VersionError, "regular file"
                ):
                    operation(self.fixture)

    @unittest.skipUnless(hasattr(os, "link"), "hard links are unavailable")
    def test_check_and_generate_reject_managed_hardlink(self) -> None:
        path = self.fixture / "sdk/typescript/package.json"
        alias = path.with_name("package.hardlink.json")
        os.link(path, alias)
        for operation in (product_version.check, product_version.generate):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(
                    product_version.VersionError, "exactly one hard link"
                ):
                    operation(self.fixture)

    def test_remaining_legacy_version_paths_are_exact_exclusions(self) -> None:
        self.assertEqual(
            product_version.legacy_exact_version_paths(ROOT),
            set(product_version.LEGACY_EXACT_VERSION_ALLOWED),
        )


if __name__ == "__main__":
    unittest.main()
