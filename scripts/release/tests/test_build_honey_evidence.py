from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
sys.path.insert(0, str(RELEASE_SCRIPTS))

import build_honey_evidence as honey  # noqa: E402
import build_honey_gate_reports as gate_reports  # noqa: E402
from release_lib import canonical_json_bytes  # noqa: E402


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


demo = _load_module(
    "cigar_honey_evidence_demo_contract_tests",
    REPOSITORY_ROOT / "demos" / "run_honey.py",
)


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(payload)
    path.chmod(0o400)


def _replace_private(path: Path, payload: bytes) -> None:
    path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)


class HoneyEvidenceFixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.control_root = base / "control"
        self.source_root = base / "source"
        self.candidate_root = base / "candidate"
        self.reports_root = base / "reports"
        self.output_root = base / "output"
        for path in (
            self.control_root,
            self.source_root,
            self.candidate_root,
            self.reports_root,
        ):
            _private_directory(path)
        self.authority = honey._load_authority(REPOSITORY_ROOT)
        self.artifact_payloads: dict[str, bytes] = {}
        artifacts: list[dict[str, object]] = []
        for row in self.authority.matrix["artifacts"]:
            payload = f"fixture artifact: {row['id']}\n".encode("utf-8")
            self.artifact_payloads[row["id"]] = payload
            _write_private(self.candidate_root / row["filename"], payload)
            artifacts.append(
                {
                    "id": row["id"],
                    "workspace": "candidate",
                    "path": row["filename"],
                }
            )
        checksum_payload = b"".join(
            f"{hashlib.sha256(self.artifact_payloads[row['id']]).hexdigest()}  {row['filename']}\n".encode(
                "ascii"
            )
            for row in sorted(
                (
                    item
                    for item in self.authority.matrix["artifacts"]
                    if item["id"] != "checksums"
                ),
                key=lambda item: item["filename"].encode("utf-8"),
            )
        )
        checksum_row = next(
            row
            for row in self.authority.matrix["artifacts"]
            if row["id"] == "checksums"
        )
        self.artifact_payloads["checksums"] = checksum_payload
        _replace_private(
            self.candidate_root / checksum_row["filename"], checksum_payload
        )

        source_payload = self.artifact_payloads["source"]
        source_row = next(
            row for row in self.authority.matrix["artifacts"] if row["id"] == "source"
        )
        empty_digest = hashlib.sha256(b"").hexdigest()
        descriptor = {
            "schema_version": "cigar.source-descriptor.v1",
            "generated_at": "2026-07-14T12:00:00Z",
            "git": {
                "revision": "a" * 40,
                "tree": "b" * 40,
                "committed": True,
                "clean": True,
                "status_entry_count": 0,
                "status_sha256": empty_digest,
            },
            "source_archive": {
                "name": source_row["filename"],
                "sha256": hashlib.sha256(source_payload).hexdigest(),
                "bytes": len(source_payload),
            },
            "policy_inputs": [
                {"path": "policy.json", "sha256": empty_digest, "bytes": 0}
            ],
            "tool_inputs": [{"path": "tool.py", "sha256": empty_digest, "bytes": 0}],
        }
        _write_private(
            self.source_root / "source-descriptor.json",
            canonical_json_bytes(descriptor),
        )

        capability_ids = sorted(
            (row["id"] for row in self.authority.profile["capabilities"]),
            key=lambda item: item.encode("utf-8"),
        )
        evidence: list[dict[str, object]] = []
        first_capability = capability_ids[0]
        for index, identifier in enumerate(sorted(honey.REQUIRED_EVIDENCE)):
            schema = honey.ACCEPTED_REPORT_SCHEMAS[identifier]
            security = honey.REQUIRED_EVIDENCE[identifier] == "security"
            tool = (
                {
                    "name": f"fixture-{identifier}",
                    "version": "1.0.0",
                    "database_updated_at": None,
                    "database_freshness": "not-applicable",
                    "offline": True,
                }
                if security
                else None
            )
            report = {"schema_version": schema, "status": "passed"}
            if security:
                report["tool"] = tool
            path = f"{identifier}.json"
            _write_private(self.reports_root / path, canonical_json_bytes(report))
            evidence.append(
                {
                    "id": identifier,
                    "category": honey.REQUIRED_EVIDENCE[identifier],
                    "workspace": "reports",
                    "path": path,
                    "schema_version": schema,
                    "artifact_ids": sorted(honey.EVIDENCE_ARTIFACT_POLICY[identifier]),
                    "capability_ids": (
                        capability_ids if index == 0 else [first_capability]
                    ),
                    "mandatory_gate_ids": sorted(
                        honey.EVIDENCE_GATE_POLICY[identifier]
                    ),
                    "tool": tool,
                }
            )
        self.control = {
            "schema_version": honey.INPUT_SCHEMA_VERSION,
            "source": {
                "workspace": "source",
                "path": "source-descriptor.json",
            },
            "artifacts": artifacts,
            "evidence": evidence,
        }
        self.write_control()

    def write_control(self) -> None:
        path = self.control_root / honey.INPUT_NAME
        payload = canonical_json_bytes(self.control)
        if path.exists():
            _replace_private(path, payload)
        else:
            _write_private(path, payload)

    @property
    def selections(self) -> list[honey.WorkspaceSelection]:
        return [
            honey.WorkspaceSelection("candidate", self.candidate_root),
            honey.WorkspaceSelection("reports", self.reports_root),
            honey.WorkspaceSelection("source", self.source_root),
        ]

    def build_arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            root=REPOSITORY_ROOT,
            control_workspace=self.control_root,
            workspace=self.selections,
            evidence_dir=self.output_root,
            out=honey.LEDGER_NAME,
        )

    def check_arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            root=REPOSITORY_ROOT,
            control_workspace=self.control_root,
            workspace=self.selections,
            ledger_workspace=self.output_root,
            ledger=honey.LEDGER_NAME,
        )


class HoneyEvidenceTests(unittest.TestCase):
    def _fixture(self, raw: str) -> HoneyEvidenceFixture:
        base = Path(raw) / "honey-evidence"
        _private_directory(base)
        return HoneyEvidenceFixture(base)

    def test_build_records_exact_bytes_capability_stages_and_deferred_gates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            with mock.patch.object(honey, "_validate_evidence_report"):
                ledger = honey._build(fixture.build_arguments())
            self.assertEqual(len(ledger["artifacts"]), 13)
            self.assertEqual(
                {row["id"] for row in ledger["evidence"]},
                set(honey.REQUIRED_EVIDENCE),
            )
            self.assertTrue(
                all(
                    row["stages"]
                    == {
                        "specified": True,
                        "implemented_source": True,
                        "integrated": True,
                        "packaged": True,
                        "honey_smoke_passed": True,
                        "v1_qualified": False,
                        "v1_supported": False,
                    }
                    for row in ledger["capabilities"]
                )
            )
            self.assertTrue(
                all(row["status"] == "passed" for row in ledger["mandatory_gates"])
            )
            self.assertTrue(
                all(
                    row["status"] == "not-run-deferred"
                    for row in ledger["deferred_gates"]
                )
            )
            stored = (fixture.output_root / honey.LEDGER_NAME).read_bytes()
            self.assertEqual(stored, canonical_json_bytes(ledger))
            self.assertEqual(
                stat.S_IMODE((fixture.output_root / honey.LEDGER_NAME).stat().st_mode),
                0o400,
            )

    def test_non_mutating_check_reconstructs_exact_ledger(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            with mock.patch.object(honey, "_validate_evidence_report"):
                honey._build(fixture.build_arguments())
                before = {
                    path.relative_to(fixture.base).as_posix(): (
                        path.read_bytes(),
                        path.stat().st_mtime_ns,
                        stat.S_IMODE(path.stat().st_mode),
                    )
                    for path in fixture.base.rglob("*")
                    if path.is_file()
                }
                result = honey._check(fixture.check_arguments())
            after = {
                path.relative_to(fixture.base).as_posix(): (
                    path.read_bytes(),
                    path.stat().st_mtime_ns,
                    stat.S_IMODE(path.stat().st_mode),
                )
                for path in fixture.base.rglob("*")
                if path.is_file()
            }
            self.assertEqual(result["status"], "passed-developer-preview")
            self.assertFalse(result["production_qualified"])
            self.assertEqual(before, after)

    def test_candidate_workspace_uses_the_artifact_contract_size_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            base = Path(raw).resolve(strict=True)
            accepted_root = base / "accepted"
            _private_directory(accepted_root)
            accepted = accepted_root / "artifact.bin"
            with accepted.open("wb") as output:
                output.truncate((64 * 1024 * 1024) + 1)
            accepted.chmod(0o400)

            with ExitStack() as stack:
                _, payloads = honey._open_exact_workspace(
                    stack,
                    accepted_root,
                    REPOSITORY_ROOT,
                    {accepted.name},
                    limits=honey.CANDIDATE_WORKSPACE_LIMITS,
                )
                self.assertEqual(len(payloads[accepted.name]), accepted.stat().st_size)

            rejected_root = base / "rejected"
            _private_directory(rejected_root)
            rejected = rejected_root / "artifact.bin"
            with rejected.open("wb") as output:
                output.truncate(honey.MAX_ARTIFACT_BYTES + 1)
            rejected.chmod(0o400)

            with (
                ExitStack() as stack,
                self.assertRaisesRegex(
                    honey.HoneyEvidenceError, "exceeds the per-file limit"
                ),
            ):
                honey._open_exact_workspace(
                    stack,
                    rejected_root,
                    REPOSITORY_ROOT,
                    {rejected.name},
                    limits=honey.CANDIDATE_WORKSPACE_LIMITS,
                )

        self.assertEqual(
            honey.CANDIDATE_WORKSPACE_LIMITS.max_file_bytes,
            honey.MAX_ARTIFACT_BYTES,
        )
        self.assertEqual(
            honey.CANDIDATE_WORKSPACE_LIMITS.max_total_bytes,
            honey.MAX_CANDIDATE_TOTAL_BYTES,
        )
        self.assertEqual(honey.CANDIDATE_WORKSPACE_LIMITS.max_files, 13)
        self.assertEqual(honey.CANDIDATE_WORKSPACE_LIMITS.max_directories, 1)
        self.assertEqual(honey.CANDIDATE_WORKSPACE_LIMITS.max_path_depth, 1)
        self.assertEqual(honey.EvidenceLimits().max_file_bytes, 64 * 1024 * 1024)

    def test_only_candidate_inputs_receive_the_expanded_workspace_limits(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            with (
                mock.patch.object(
                    honey,
                    "_open_exact_workspace",
                    wraps=honey._open_exact_workspace,
                ) as opened,
                mock.patch.object(honey, "_validate_evidence_report"),
            ):
                honey._build(fixture.build_arguments())

        candidate_calls = [
            call
            for call in opened.call_args_list
            if call.args[1] == fixture.candidate_root
        ]
        self.assertEqual(len(candidate_calls), 1)
        self.assertIs(
            candidate_calls[0].kwargs["limits"],
            honey.CANDIDATE_WORKSPACE_LIMITS,
        )
        self.assertTrue(
            all(
                call.kwargs.get("limits") is None
                for call in opened.call_args_list
                if call.args[1] != fixture.candidate_root
            )
        )

    def test_claude_plugin_producer_matches_the_evidence_attachment_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            source = {
                "revision": "1" * 40,
                "tree_sha256": "2" * 64,
                "committed": True,
                "clean": True,
            }
            binaries = {
                "mcp": root / "cigar-mcp",
                "hook": root / "cigar-claude-hook",
            }
            binaries["mcp"].write_bytes(b"fixture mcp\n")
            binaries["hook"].write_bytes(b"fixture hook\n")
            plugin_root = "cigar-honey-plugin"
            payloads = {
                f"{plugin_root}/.claude-plugin/plugin.json": demo.canonical(
                    {"version": demo.PRODUCT_VERSION}
                ),
                f"{plugin_root}/compatibility.json": demo.canonical(
                    {"context_abi": demo.CONTEXT_ABI}
                ),
                f"{plugin_root}/RELEASE-METADATA.json": demo.canonical(
                    {
                        "product_version": demo.PRODUCT_VERSION,
                        "source": source,
                    }
                ),
                f"{plugin_root}/bin/cigar-mcp": binaries["mcp"].read_bytes(),
                f"{plugin_root}/bin/cigar-claude-hook": binaries["hook"].read_bytes(),
            }
            archive = root / "claude-plugin.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                for relative, payload in sorted(payloads.items()):
                    member = tarfile.TarInfo(relative)
                    member.size = len(payload)
                    member.mode = 0o755 if "/bin/" in relative else 0o644
                    handle.addfile(member, io.BytesIO(payload))

            digest = demo.sha256_bytes(archive.read_bytes())
            identity, installed_root = demo.install_plugin(
                archive,
                digest,
                root / "installed-plugin",
                binaries,
                source,
            )
            artifact = {
                "filename": archive.name,
                "sha256": digest,
                "bytes": archive.stat().st_size,
            }
            runtime_identity = {"sha256": "4" * 64, "bytes": 1}
            artifacts = {
                "macos-runtime-aarch64": {
                    "filename": "runtime.tar.gz",
                    **runtime_identity,
                },
                "claude-code-plugin": artifact,
            }
            self.assertEqual(
                identity,
                {"sha256": digest, "bytes": archive.stat().st_size},
            )
            self.assertEqual(installed_root, root / "installed-plugin" / plugin_root)
            self.assertTrue(
                honey._attachment_matches(identity, artifact, require_path=False)
            )

            scenario_ids = [
                "offline-context",
                "effect-recovery-replay",
                "claude-mcp",
            ]
            report = {
                "schema_version": "cigar.honey-installed-demo-report.v1",
                "status": "installed_demo_passed",
                "product_version": demo.PRODUCT_VERSION,
                "context_abi": demo.CONTEXT_ABI,
                "evidence_class": demo.EVIDENCE_CLASS,
                "suite": {
                    "manifest": "demos/honey-manifest.v1.json",
                    "sha256": "5" * 64,
                },
                "selected_scenarios": scenario_ids,
                "runtime": runtime_identity,
                "source": source,
                "supporting_artifacts": {"claude_plugin": identity},
                "scenarios": [
                    {
                        "scenario_id": scenario_id,
                        "status": "installed_story_passed_twice",
                        "components": [{"status": "installed_component_passed_twice"}],
                    }
                    for scenario_id in scenario_ids
                ],
                "installed_artifact_qualified": True,
            }
            report["report_digest"] = demo.multihash(demo.canonical(report))
            honey._validate_demo("other-demo-reports", report, artifacts, source)

            legacy_report = json.loads(json.dumps(report))
            legacy_report["supporting_artifacts"]["claude_plugin"]["source"] = source
            legacy_report["report_digest"] = demo.multihash(
                demo.canonical(
                    {
                        key: value
                        for key, value in legacy_report.items()
                        if key != "report_digest"
                    }
                )
            )
            with self.assertRaisesRegex(
                honey.HoneyEvidenceError,
                "other Honey demos are not bound",
            ):
                honey._validate_demo(
                    "other-demo-reports",
                    legacy_report,
                    artifacts,
                    source,
                )

            stale_source = dict(source)
            stale_source["revision"] = "3" * 40
            with self.assertRaisesRegex(
                demo.HoneyDemoError,
                "plugin identity does not match",
            ):
                demo.install_plugin(
                    archive,
                    digest,
                    root / "stale-plugin",
                    binaries,
                    stale_source,
                )

    def test_true_production_claim_in_bound_report_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            row = fixture.control["evidence"][0]
            path = fixture.reports_root / row["path"]
            report = json.loads(path.read_text(encoding="utf-8"))
            report["production_ready"] = True
            _replace_private(path, canonical_json_bytes(report))
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "production claim"):
                honey._build(fixture.build_arguments())

    def test_extra_workspace_file_and_missing_reference_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            _write_private(fixture.reports_root / "unreviewed.json", b"{}\n")
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "inventory mismatch"):
                honey._build(fixture.build_arguments())

        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            fixture.control["evidence"].pop()
            fixture.write_control()
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "missing or extra"):
                honey._build(fixture.build_arguments())

    def test_stale_artifact_and_duplicate_report_reference_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            fixture.control["artifacts"][0]["path"] = fixture.control["artifacts"][1][
                "path"
            ]
            fixture.write_control()
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "does not name"):
                honey._build(fixture.build_arguments())

        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            fixture.control["evidence"][1]["path"] = fixture.control["evidence"][0][
                "path"
            ]
            fixture.write_control()
            with self.assertRaisesRegex(
                honey.HoneyEvidenceError, "referenced more than once"
            ):
                honey._build(fixture.build_arguments())

    def test_checksum_and_security_freshness_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            checksum = fixture.candidate_root / "SHA256SUMS"
            _replace_private(checksum, checksum.read_bytes() + b"0" * 64 + b"  extra\n")
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "SHA256SUMS"):
                honey._build(fixture.build_arguments())

        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            row = next(
                item
                for item in fixture.control["evidence"]
                if item["id"] == "secret-scan"
            )
            row["tool"]["database_freshness"] = "stale"
            fixture.write_control()
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "tool metadata"):
                honey._build(fixture.build_arguments())

    def test_noncanonical_report_and_mutated_ledger_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            row = fixture.control["evidence"][0]
            path = fixture.reports_root / row["path"]
            report = json.loads(path.read_text(encoding="utf-8"))
            _replace_private(path, (json.dumps(report, indent=2) + "\n").encode())
            with self.assertRaisesRegex(honey.HoneyEvidenceError, "not canonical JSON"):
                honey._build(fixture.build_arguments())

        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            with mock.patch.object(honey, "_validate_evidence_report"):
                ledger = honey._build(fixture.build_arguments())
                ledger["aggregate"]["sha256"] = "0" * 64
                _replace_private(
                    fixture.output_root / honey.LEDGER_NAME,
                    canonical_json_bytes(ledger),
                )
                with self.assertRaisesRegex(
                    honey.HoneyEvidenceError, "aggregate digest"
                ):
                    honey._check(fixture.check_arguments())

    def test_schema_is_strict_and_forbids_true_release_claims(self) -> None:
        schema = json.loads((REPOSITORY_ROOT / honey.SCHEMA_PATH).read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["$defs"]["artifact"]["properties"]["bytes"]["maximum"],
            honey.MAX_ARTIFACT_BYTES,
        )
        product = schema["$defs"]["product"]
        self.assertEqual(product["properties"]["supported"], {"const": False})
        self.assertEqual(
            product["properties"]["production_qualified"], {"const": False}
        )
        stages = schema["$defs"]["stages"]["properties"]
        self.assertEqual(stages["honey_smoke_passed"], {"const": True})
        self.assertEqual(stages["v1_qualified"], {"const": False})
        closed_branches = schema["$defs"]["evidence"]["allOf"][1]["oneOf"]
        schema_by_id = {
            branch["properties"]["id"]["const"]: branch["properties"]["report"][
                "properties"
            ]["schema_version"]["const"]
            for branch in closed_branches
        }
        category_by_id = {
            branch["properties"]["id"]["const"]: branch["properties"]["category"][
                "const"
            ]
            for branch in closed_branches
        }
        self.assertEqual(schema_by_id, honey.ACCEPTED_REPORT_SCHEMAS)
        self.assertEqual(category_by_id, honey.REQUIRED_EVIDENCE)

    def test_trivial_status_only_report_is_rejected_for_every_evidence_id(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            artifacts = {
                row["id"]: {
                    "id": row["id"],
                    "filename": row["filename"],
                    "kind": row["kind"],
                    "sha256": hashlib.sha256(
                        fixture.artifact_payloads[row["id"]]
                    ).hexdigest(),
                    "bytes": len(fixture.artifact_payloads[row["id"]]),
                    "source_revision": "a" * 40,
                    "source_tree": "b" * 40,
                }
                for row in fixture.authority.matrix["artifacts"]
            }
            source = {
                "revision": "a" * 40,
                "tree": "b" * 40,
                "committed": True,
                "clean": True,
            }
            references = {row["id"]: row for row in fixture.control["evidence"]}
            with mock.patch.object(
                honey,
                "GATE_REPORT_PRODUCER",
                "scripts/release/build_honey_evidence.py",
            ):
                for identifier in sorted(honey.REQUIRED_EVIDENCE):
                    with self.subTest(identifier=identifier):
                        trivial = {
                            "schema_version": honey.ACCEPTED_REPORT_SCHEMAS[identifier],
                            "status": "passed",
                        }
                        with self.assertRaises(honey.HoneyEvidenceError):
                            honey._validate_evidence_report(
                                identifier,
                                trivial,
                                references[identifier],
                                artifacts,
                                source,
                                fixture.authority,
                            )

    def test_gate_assignment_and_schema_are_closed_by_evidence_id(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            docs = next(
                row
                for row in fixture.control["evidence"]
                if row["id"] == "documentation-report"
            )
            docs["mandatory_gate_ids"] = ["conformance"]
            fixture.write_control()
            with self.assertRaisesRegex(
                honey.HoneyEvidenceError, "unrelated mandatory gate"
            ):
                honey._build(fixture.build_arguments())

        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            runtime = next(
                row
                for row in fixture.control["evidence"]
                if row["id"] == "installed-runtime-report"
            )
            runtime["mandatory_gate_ids"].remove("archive-contracts")
            fixture.write_control()
            with self.assertRaisesRegex(
                honey.HoneyEvidenceError, "stale mandatory-gate"
            ):
                honey._build(fixture.build_arguments())

        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            docs = next(
                row
                for row in fixture.control["evidence"]
                if row["id"] == "documentation-report"
            )
            docs["schema_version"] = "cigar.arbitrary-passed.v1"
            fixture.write_control()
            with self.assertRaisesRegex(
                honey.HoneyEvidenceError, "closed accepted schema"
            ):
                honey._build(fixture.build_arguments())

    def test_existing_conformance_and_license_producer_documents_validate(self) -> None:
        conformance = json.loads(
            (REPOSITORY_ROOT / "reports/conformance-result.v1.json").read_text()
        )
        licenses = json.loads(
            (
                REPOSITORY_ROOT / "packaging/licenses/third-party-inventory.v1.json"
            ).read_text()
        )
        honey._validate_conformance(conformance)
        honey._validate_license(licenses)

    def test_gate_producer_and_evidence_consumer_contracts_are_aligned(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            fixture = self._fixture(raw)
            artifacts = {
                row["id"]: {
                    "id": row["id"],
                    "filename": row["filename"],
                    "kind": row["kind"],
                    "sha256": hashlib.sha256(
                        fixture.artifact_payloads[row["id"]]
                    ).hexdigest(),
                    "bytes": len(fixture.artifact_payloads[row["id"]]),
                    "source_revision": "a" * 40,
                    "source_tree": "b" * 40,
                }
                for row in fixture.authority.matrix["artifacts"]
            }
            source = {
                "revision": "a" * 40,
                "tree": "b" * 40,
                "committed": True,
                "clean": True,
            }
            artifact_rows = honey._gate_artifact_rows(artifacts)
            bounded = {
                "checks": [
                    {
                        "id": identifier,
                        "status": "passed",
                        "exit_code": 0,
                        "command_sha256": "1" * 64,
                        "stdout_sha256": "2" * 64,
                        "stderr_sha256": "3" * 64,
                    }
                    for identifier in honey.BOUNDED_SAFETY_CHECKS
                ],
                "failed_checks": 0,
            }
            security_tool = {
                "name": "fixture-offline-tool",
                "version": "1",
                "database_updated_at": None,
                "database_freshness": "not-applicable",
                "offline": True,
            }
            cases = (
                ("bounded-safety-report", "bounded-safety", bounded, None),
                (
                    "secret-scan",
                    "secret-scan",
                    {
                        "source_scanned": True,
                        "artifacts_scanned": True,
                        "files_scanned": 1,
                        "bytes_scanned": 1,
                        "findings": 0,
                        "suppressions": 0,
                        "suppression_records": [],
                    },
                    security_tool,
                ),
                (
                    "offline-dependency-check",
                    "offline-dependency-check",
                    {
                        "lockfiles": [
                            "Cargo.lock",
                            "pnpm-lock.yaml",
                            "sdk/python/uv.lock",
                        ],
                        "ecosystems": ["cargo", "npm", "python"],
                        "lock_integrity_passed": True,
                        "offline_resolution_passed": True,
                        "resolved_dependencies": 1,
                        "unresolved_dependencies": 0,
                        "advisory_database_available": False,
                    },
                    security_tool,
                ),
            )
            references = {row["id"]: row for row in fixture.control["evidence"]}
            for identifier, kind, assertions, tool in cases:
                with self.subTest(identifier=identifier):
                    report = gate_reports._report(
                        kind,
                        source,
                        artifact_rows,
                        assertions,
                        tool,
                        REPOSITORY_ROOT,
                    )
                    reference = dict(references[identifier])
                    reference["tool"] = tool
                    honey._validate_gate_report(
                        identifier,
                        report,
                        reference,
                        artifacts,
                        source,
                        fixture.authority,
                    )


if __name__ == "__main__":
    unittest.main()
