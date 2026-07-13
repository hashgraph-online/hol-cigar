from __future__ import annotations

import contextlib
import http.client
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


demos = load("cigar_demo_runner", ROOT / "demos" / "run.py")
driver_support = load("cigar_demo_driver_support", ROOT / "demos" / "driver_support.py")
installed = load(
    "cigar_installed_driver", ROOT / "demos" / "installed_artifact_test.py"
)
quickstarts = load("cigar_sdk_quickstarts", ROOT / "demos" / "sdk-clients" / "run.py")
live_smoke = load(
    "cigar_claude_live_smoke", ROOT / "demos" / "claude-code" / "live_smoke.py"
)


class DemoHarnessTests(unittest.TestCase):
    def test_inventory_is_exactly_seven_and_validate_records_are_deterministic(
        self,
    ) -> None:
        manifests = demos.load_manifests()
        self.assertEqual(len(manifests), 7)
        registry = demos.canaries()
        path, manifest = manifests["effect-crash-recovery"]
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
        ):
            one = demos.run_demo(path, manifest, Path(first), True, False, registry)
            two = demos.run_demo(path, manifest, Path(second), True, False, registry)
        self.assertEqual(one, two)
        self.assertEqual(one["mode"], "validation_only")
        self.assertIsNone(one["scenario_driver"])
        self.assertFalse(one["release_demo_qualified"])
        self.assertTrue(
            all(item["status"] == "validated" for item in one["assertions"])
        )

    def test_release_qualification_requires_every_fixture_assertion_on_product_surface(
        self,
    ) -> None:
        product = {"status": "product_observed"}
        fixture = {"status": "fixture_observed"}
        driver = {
            "no_egress_enforcement": "darwin-loopback-only-v1",
            "setup": [fixture, product],
            "flow": [product, product],
            "assertions": [product, product],
            "teardown": [fixture],
        }
        self.assertTrue(demos.driver_release_qualified(driver))
        driver["assertions"][0] = fixture
        self.assertFalse(demos.driver_release_qualified(driver))
        driver["assertions"][0] = product
        driver["flow"][1] = fixture
        self.assertFalse(demos.driver_release_qualified(driver))
        driver["flow"][1] = product
        driver["no_egress_enforcement"] = "unavailable"
        self.assertFalse(demos.driver_release_qualified(driver))

    def test_recorded_api_fails_closed_on_tampering_and_unsafe_files(self) -> None:
        operation = driver_support.RecordedOperation(
            "getReadiness",
            "GET",
            "/v1/readiness",
            None,
            {"ready": True},
        )
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with driver_support.RecordedApi(state, [operation]) as api:
                endpoint = urlsplit(api.base_url())
                connection = http.client.HTTPConnection(
                    endpoint.hostname, endpoint.port, timeout=2
                )
                connection.request(
                    "GET",
                    "/v1/readiness",
                    headers={
                        "Authorization": "Bearer forged",
                        "x-cigar-operation-id": "getReadiness",
                        "x-cigar-timeout-ms": "1000",
                    },
                )
                response = connection.getresponse()
                response.read()
                connection.close()
                self.assertEqual(response.status, 503)
                with self.assertRaisesRegex(
                    driver_support.DriverError, "did not complete exactly"
                ):
                    api.assert_complete()
            self.assertFalse((state / "recorded-api-token").exists())

            target = state / "outside"
            target.mkdir()
            (state / "recorded-api-requests").symlink_to(
                target, target_is_directory=True
            )
            with self.assertRaisesRegex(driver_support.DriverError, "unsafe"):
                driver_support.write_request(state, "probe", {"safe": True})
            self.assertEqual(list(target.iterdir()), [])

        with self.assertRaisesRegex(driver_support.DriverError, "non-canonical"):
            driver_support.RecordedOperation(
                "getReadiness",
                "GET",
                "/v1/readiness",
                None,
                {"ready": None},
            )

    def test_every_demo_has_a_bounded_regular_fixture_driver(self) -> None:
        for manifest_path, manifest in demos.load_manifests().values():
            driver = manifest_path.parent / manifest["driver"]
            self.assertTrue(driver.is_file())
            self.assertFalse(driver.is_symlink())
            self.assertLessEqual(driver.stat().st_size, demos.MAX_JSON)

        manifest_path = ROOT / "demos" / "quickstart" / "demo.json"
        manifest = demos.load_json(manifest_path)
        manifest["driver_digest"] = "1220" + "0" * 64
        with self.assertRaisesRegex(demos.DemoError, "does not match"):
            demos.validate_manifest(manifest, manifest_path)

    def test_product_check_requires_a_real_test_and_scans_output_canaries(self) -> None:
        registry = demos.canaries()
        passing = {
            "check_id": "fake-product-check",
            "command": [
                "python3",
                "-c",
                "print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')",
            ],
            "timeout_seconds": 10,
            "minimum_passed_tests": 1,
            "assertions": ["fake-assertion"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = demos.run_check(
                passing, Path(temporary), ["effect-secret"], registry
            )
            self.assertEqual(result["passed_tests"], 1)
            no_tests = dict(passing)
            no_tests["command"] = ["python3", "-c", "print('ok')"]
            with self.assertRaisesRegex(demos.DemoError, "required tests"):
                demos.run_check(no_tests, Path(temporary), ["effect-secret"], registry)
            leak = dict(passing)
            leak["command"] = [
                "python3",
                "-c",
                "print('DEMO_CANARY_EFFECT_SECRET_460A3D')",
            ]
            with self.assertRaises(demos.DemoError) as failure:
                demos.run_check(leak, Path(temporary), ["effect-secret"], registry)
            self.assertNotIn("DEMO_CANARY", str(failure.exception))

    def test_quickstart_inventory_binds_all_four_runtimes_to_recorded_workflow(
        self,
    ) -> None:
        manifest = quickstarts.load_manifest()
        self.assertEqual(
            {item["language"] for item in manifest["quickstarts"]},
            {"rust", "typescript", "python", "go"},
        )
        self.assertRegex(manifest["expected_bundle_id"], r"^1220[0-9a-f]{64}$")
        self.assertTrue(
            all("recorded" in item["mode"] for item in manifest["quickstarts"])
        )
        expected_operations = [
            "discoverSources",
            "ingestCatalog",
            "createContextPlan",
            "compileContextBundle",
            "getContextBundleManifest",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sdk-report.json"
            with io.StringIO() as stdout, contextlib.redirect_stdout(stdout):
                self.assertEqual(quickstarts.main(["--output", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            report["qualification_scope"], "recorded-ingest-compile-manifest"
        )
        self.assertTrue(report["sdk_workflow_qualified"])
        self.assertFalse(report["installed_artifact_qualified"])
        self.assertFalse(report["release_qualified"])
        self.assertEqual(report["operations"], expected_operations)
        self.assertEqual(len(report["quickstarts"]), 4)
        self.assertTrue(
            all(
                item["status"] == "recorded_workflow_passed"
                and item["operations"] == expected_operations
                for item in report["quickstarts"]
            )
        )

    def test_installed_driver_rejects_archive_traversal_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traversal = root / "traversal.tar"
            with tarfile.open(traversal, "w") as archive:
                info = tarfile.TarInfo("../escape")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            with self.assertRaisesRegex(installed.InstallError, "unsafe member"):
                installed.unpack(traversal, root / "out")
            linked = root / "linked.tar"
            with tarfile.open(linked, "w") as archive:
                info = tarfile.TarInfo("package/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
                archive.addfile(info)
            (root / "linked-out").mkdir()
            with self.assertRaisesRegex(installed.InstallError, "link or special"):
                installed.unpack(linked, root / "linked-out")

    def test_installed_identity_parser_is_exact(self) -> None:
        completed = type(
            "Completed", (), {"stdout": (installed.EXPECTED + "\n").encode()}
        )()
        self.assertEqual(installed.identity(completed), installed.EXPECTED)
        bad = type(
            "Completed", (), {"stdout": (installed.EXPECTED + "\nextra\n").encode()}
        )()
        with self.assertRaises(installed.InstallError):
            installed.identity(bad)

    def test_isolated_environments_and_live_result_parser_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            demo_environment = demos.clean_environment(state)
            source_environment = quickstarts.clean_environment(state)
            installed_environment = installed.clean_environment(state)
        self.assertEqual(demo_environment["HOME"], str(state / "home"))
        self.assertEqual(source_environment["HOME"], str(state / "home"))
        self.assertEqual(installed_environment["HOME"], str(state))
        self.assertTrue(live_smoke.accepted_outcome({"status": "ok"}))
        self.assertTrue(
            live_smoke.accepted_outcome(
                {"type": "result", "structured_output": {"status": "ok"}}
            )
        )
        self.assertFalse(live_smoke.accepted_outcome({"nested": {"status": "ok"}}))


if __name__ == "__main__":
    unittest.main()
