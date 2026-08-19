from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIRI_ROOT = ROOT / "tests" / "miri"
UNSAFE_RUST = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)")


class MiriContractTests(unittest.TestCase):
    def test_isolated_dependency_surface_excludes_native_runtime_crates(self) -> None:
        manifest = tomllib.loads((MIRI_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            set(manifest["dependencies"]),
            {"cigar-canon", "cigar-protocol", "serde", "serde_json"},
        )
        lock = tomllib.loads((MIRI_ROOT / "Cargo.lock").read_text(encoding="utf-8"))
        packages = {package["name"] for package in lock["package"]}
        self.assertTrue({"cigar-canon", "cigar-protocol"}.issubset(packages))
        self.assertTrue(
            {
                "cigar-api",
                "cigar-compiler",
                "keyring",
                "libsqlite3-sys",
                "ring",
                "rusqlite",
                "rustls",
                "zstd-sys",
            }.isdisjoint(packages)
        )

    def test_exact_production_sources_are_compiled_into_the_slice(self) -> None:
        source = (MIRI_ROOT / "memory_model.rs").read_text(encoding="utf-8")
        self.assertIn(
            '#[path = "../../crates/cigar-daemon/src/workflow_context_session.rs"]',
            source,
        )
        self.assertIn(
            '#[path = "../../crates/cigar-windows-ipc/src/pointer.rs"]',
            source,
        )

    def test_unsafe_rust_remains_confined_to_the_audited_windows_adapter(self) -> None:
        unsafe_paths = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "crates").rglob("*.rs")
            if UNSAFE_RUST.search(path.read_text(encoding="utf-8"))
        }
        self.assertEqual(
            unsafe_paths,
            {
                "crates/cigar-windows-ipc/src/pointer.rs",
                "crates/cigar-windows-ipc/src/windows.rs",
            },
        )


if __name__ == "__main__":
    unittest.main()
