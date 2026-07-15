from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "crates/xtask/native_macos_command_plane.py"
SPEC = importlib.util.spec_from_file_location("native_macos_command_plane", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def clean_source() -> dict[str, object]:
    return {
        "kind": "git",
        "revision": "1" * 40,
        "tree": "2" * 40,
        "committed": True,
        "clean": True,
        "status_entry_count": 0,
        "status_sha256": hashlib.sha256(b"").hexdigest(),
    }


class NativeCommandAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-xtask-native-authority-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name).resolve(strict=True)
        os.chmod(self.root, 0o700)
        self.source = clean_source()
        self.saved_selector = os.environ.pop(MODULE.SELECTOR, None)
        self.saved_selector_sha256 = os.environ.pop(MODULE.SELECTOR_SHA256, None)

    def tearDown(self) -> None:
        os.environ.pop(MODULE.SELECTOR, None)
        os.environ.pop(MODULE.SELECTOR_SHA256, None)
        if self.saved_selector is not None:
            os.environ[MODULE.SELECTOR] = self.saved_selector
        if self.saved_selector_sha256 is not None:
            os.environ[MODULE.SELECTOR_SHA256] = self.saved_selector_sha256
        self.temporary.cleanup()

    def directory(self, name: str, *, empty: bool = True) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700)
        if not empty:
            self.file(path / "sentinel", b"sentinel")
        return path

    def file(self, path: Path, payload: bytes = b"{}\n", *, mode: int = 0o600) -> Path:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, mode)
        return path.resolve(strict=True)

    def input_file(self, name: str, payload: bytes = b"{}\n") -> str:
        return os.fspath(self.file(self.root / name, payload))

    def executable(self, name: str) -> str:
        return os.fspath(
            self.file(self.root / name, b"#!/bin/sh\nexit 0\n", mode=0o700)
        )

    def write_authority(
        self,
        route: str,
        inputs: dict[str, object],
        *,
        source: dict[str, object] | None = None,
        extra: dict[str, object] | None = None,
        canonical: bool = True,
    ) -> Path:
        document: dict[str, object] = {
            "schema_version": MODULE.SCHEMA,
            "route": route,
            "source": source or self.source,
            "inputs": inputs,
        }
        if extra:
            document.update(extra)
        payload = (
            MODULE.canonical_json_bytes(document)
            if canonical
            else json.dumps(document, indent=3).encode() + b"\n"
        )
        path = self.file(self.root / "authority.json", payload)
        os.environ[MODULE.SELECTOR] = os.fspath(path)
        os.environ[MODULE.SELECTOR_SHA256] = hashlib.sha256(payload).hexdigest()
        return path

    def micro_inputs(self) -> dict[str, object]:
        inputs: dict[str, object] = {}
        for name, secret in MODULE.MICRO_FILES.items():
            if name == "comparison_report":
                payload = MODULE.canonical_json_bytes(
                    {
                        "schema_version": "cigar.performance-report.v1",
                        "report_id": "sha256:" + "a" * 64,
                        "report_type": "comparison",
                        "decision": "pass",
                        "reasons": [],
                        "thresholds": {},
                        "candidate": {},
                        "baseline": {},
                        "comparisons": {},
                    }
                )
            elif secret:
                payload = f"secret-evaluator-material-{name}".encode()
            else:
                payload = MODULE.canonical_json_bytes({"fixture": name})
            inputs[name] = self.input_file(name, payload)
        return inputs

    def route_inputs(self, route: str) -> dict[str, object]:
        if route == "bench-micro-verify":
            return self.micro_inputs()
        if route == "bench-macro-verify":
            return {
                **self.micro_inputs(),
                "local_scale_driver": self.executable("local-scale-driver"),
                "local_scale_profile": self.input_file("scale-profile"),
                "local_scale_binding": self.input_file("scale-binding"),
                "local_scale_receipt": self.input_file("scale-receipt"),
            }
        if route == "bench-efficacy":
            return {
                "evidence_root": os.fspath(self.directory("efficacy-evidence")),
                "environment": self.input_file("efficacy-environment"),
                "seed_file": self.input_file("efficacy-seed", b"s" * 32),
                "attestation_key_file": self.input_file("efficacy-key", b"k" * 32),
                "matrix_report": self.input_file("efficacy-report"),
            }
        if route == "package-all":
            names = (
                "portable_workspace",
                "native_workspace",
                "conformance_workspace",
                "cigarbench_workspace",
                "homebrew_workspace",
                "typescript_workspace",
                "rust_workspace",
                "python_workspace",
                "go_workspace",
                "claude_workspace",
            )
            tools = (
                "cargo",
                "rustc",
                "protoc",
                "cargo_local_registry",
                "node",
                "pnpm",
                "npm",
                "uv",
                "python",
                "go",
            )
            dependencies = (
                "cargo_cache",
                "rustup_home",
                "uv_cache_dir",
                "go_dependency_proxy",
            )
            return {
                **{name: os.fspath(self.directory(name)) for name in names},
                **{name: self.executable(f"tool-{name}") for name in tools},
                **{
                    name: os.fspath(self.directory(name, empty=False))
                    for name in dependencies
                },
                "output_root": os.fspath(self.directory("package-output")),
                "source_date_epoch": 1_700_000_000,
            }
        if route == "package-smoke":
            return {
                "artifact_root": os.fspath(self.directory("package-artifact-root")),
                "runtime_build_receipt": self.input_file("runtime-receipt"),
                "qualification_tool_build_receipt": self.input_file("tool-receipt"),
                "install_evidence_root": os.fspath(self.directory("install-evidence")),
            }
        if route in {"release-sbom", "release-attest"}:
            inputs: dict[str, object] = {
                "artifact_root": os.fspath(self.directory(f"{route}-artifact-root")),
                "artifact_directory": "dist",
                "source_date_epoch": 1_700_000_000,
                "output_path": "provenance.json"
                if route == "release-attest"
                else "sbom",
            }
            if route == "release-attest":
                inputs.update(
                    {
                        "builder_id": "builder.example",
                        "workflow_id": "workflow.example",
                        "network_mode": "disabled",
                        "commands": [{"tool_id": "cargo", "argv_sha256": "c" * 64}],
                        "materials": [self.input_file("release-material")],
                    }
                )
            return inputs
        if route == "release-sign":
            artifact_root = self.directory("sign-artifact-root")
            payload = self.file(artifact_root / "dist/payload.bin", b"payload")
            self.directory("sign-artifact-root/dist/evidence")
            openssl = Path(self.executable("reviewed-openssl"))
            public_key = Path(self.input_file("public-key", b"opaque-public-key"))
            trust_policy = self.input_file(
                "signing-trust-policy",
                MODULE.canonical_json_bytes(
                    {
                        "schema_version": "cigar.release-trust-policy.v1",
                        "keys": [
                            {
                                "key_id": "sha256:" + "b" * 64,
                                "public_key": public_key.name,
                                "public_key_sha256": hashlib.sha256(
                                    public_key.read_bytes()
                                ).hexdigest(),
                                "signer_principal": "release-owner",
                                "purposes": ["release-artifact"],
                                "status": "active",
                                "active_from": 1_600_000_000,
                            }
                        ],
                    }
                ),
            )
            return {
                "artifact_root": os.fspath(artifact_root),
                "artifact_directory": "dist",
                "private_key_file": self.input_file(
                    "private-key", b"opaque-key-handle"
                ),
                "public_key_file": os.fspath(public_key),
                "trust_policy": trust_policy,
                "signer_principal": "release-owner",
                "openssl": os.fspath(openssl),
                "openssl_sha256": hashlib.sha256(openssl.read_bytes()).hexdigest(),
                "signed_at": 1_700_000_000,
                "expires_at": 1_800_000_000,
                "signature_directory": "signatures",
                "evidence_directory": "evidence",
                "signing_phase": "supporting",
                "payloads": [
                    {
                        "path": payload.relative_to(artifact_root / "dist").as_posix(),
                        "purpose": "release-artifact",
                    }
                ],
            }
        if route == "release-verify":
            openssl = Path(self.executable("offline-reviewed-openssl"))
            return {
                "artifact_root": os.fspath(self.directory("verify-artifact-root")),
                "trust_policy": self.input_file("trust-policy"),
                "openssl": os.fspath(openssl),
                "openssl_sha256": hashlib.sha256(openssl.read_bytes()).hexdigest(),
                "verification_time": 1_700_000_000,
                "verification_evidence_root": os.fspath(
                    self.directory("verification-evidence")
                ),
            }
        raise AssertionError(route)

    def load(self, route: str, inputs: dict[str, object] | None = None):
        self.write_authority(
            route, inputs if inputs is not None else self.route_inputs(route)
        )
        return MODULE._load_authority(route, self.source)

    def test_every_external_route_has_one_closed_loadable_authority_schema(
        self,
    ) -> None:
        for route in sorted(MODULE.ROUTES - {"test-sanitizers"}):
            with self.subTest(route=route):
                # Each route gets a distinct authority pathname because publication is create-new.
                os.environ.pop(MODULE.SELECTOR, None)
                authority_path = self.root / "authority.json"
                if authority_path.exists():
                    authority_path.unlink()
                authority = self.load(route)
                self.assertEqual(authority.route, route)
                self.assertEqual(authority.source, self.source)
                self.assertRegex(authority.binding["sha256"], r"^[0-9a-f]{64}$")

    def test_missing_selector_has_no_ambient_fallback(self) -> None:
        os.environ["CIGAR_RELEASE_TRUST_POLICY"] = self.input_file("ambient-trust")
        self.addCleanup(os.environ.pop, "CIGAR_RELEASE_TRUST_POLICY", None)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "unavailable"):
            MODULE._load_authority("release-verify", self.source)

    def test_authority_and_artifact_roots_must_be_external_to_source(self) -> None:
        with self.assertRaisesRegex(MODULE.NativeCommandError, "outside"):
            MODULE._open_file_snapshot(
                os.fspath(MODULE_PATH), "repository-local authority"
            )
        with self.assertRaisesRegex(MODULE.NativeCommandError, "outside"):
            MODULE._open_directory(os.fspath(ROOT / "crates"), "artifact root")

    def test_authority_rejects_unknown_field_wrong_route_and_stale_source(self) -> None:
        cases = (
            ({"unexpected": True}, "unsupported identity|unknown or missing"),
            (None, "another route"),
        )
        for index, (extra, expected) in enumerate(cases):
            with self.subTest(index=index):
                path = self.root / "authority.json"
                if path.exists():
                    path.unlink()
                self.write_authority(
                    "bench-micro-verify" if extra else "bench-macro-verify",
                    self.micro_inputs(),
                    extra=extra,
                )
                with self.assertRaisesRegex(MODULE.NativeCommandError, expected):
                    MODULE._load_authority("bench-micro-verify", self.source)
        (self.root / "authority.json").unlink()
        stale = dict(self.source)
        stale["revision"] = "3" * 40
        self.write_authority("bench-micro-verify", self.micro_inputs(), source=stale)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "exact clean source"):
            MODULE._load_authority("bench-micro-verify", self.source)

    def test_every_route_rejects_unknown_input_fields(self) -> None:
        for route in sorted(MODULE.ROUTES - {"test-sanitizers"}):
            with self.subTest(route=route):
                authority_path = self.root / "authority.json"
                if authority_path.exists():
                    authority_path.unlink()
                inputs = self.route_inputs(route)
                inputs["ignored_flag"] = True
                self.write_authority(route, inputs)
                with self.assertRaisesRegex(
                    MODULE.NativeCommandError, "unknown or missing fields"
                ):
                    MODULE._load_authority(route, self.source)

    def test_authority_rejects_noncanonical_and_embedded_private_key_bytes(
        self,
    ) -> None:
        self.write_authority("bench-micro-verify", self.micro_inputs(), canonical=False)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "canonical JSON"):
            MODULE._load_authority("bench-micro-verify", self.source)
        (self.root / "authority.json").unlink()
        self.write_authority(
            "bench-micro-verify",
            self.micro_inputs(),
            extra={"-----BEGIN PRIVATE KEY-----": "forbidden"},
        )
        with self.assertRaisesRegex(MODULE.NativeCommandError, "embeds secret"):
            MODULE._load_authority("bench-micro-verify", self.source)

    def test_authority_requires_independently_reviewed_exact_digest(self) -> None:
        self.write_authority("bench-micro-verify", self.micro_inputs())
        os.environ.pop(MODULE.SELECTOR_SHA256)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "unavailable"):
            MODULE._load_authority("bench-micro-verify", self.source)
        os.environ[MODULE.SELECTOR_SHA256] = "0" * 64
        with self.assertRaisesRegex(MODULE.NativeCommandError, "operator-reviewed"):
            MODULE._load_authority("bench-micro-verify", self.source)

    def test_authority_file_rejects_symlink_hardlink_and_unsafe_mode(self) -> None:
        original = self.write_authority("bench-micro-verify", self.micro_inputs())
        for kind in ("symlink", "hardlink", "mode"):
            with self.subTest(kind=kind):
                selected = self.root / f"authority-{kind}.json"
                if kind == "symlink":
                    selected.symlink_to(original)
                elif kind == "hardlink":
                    os.link(original, selected)
                else:
                    selected.write_bytes(original.read_bytes())
                    os.chmod(selected, 0o622)
                os.environ[MODULE.SELECTOR] = os.fspath(selected)
                with self.assertRaises(MODULE.NativeCommandError):
                    MODULE._load_authority("bench-micro-verify", self.source)
                if selected.exists() or selected.is_symlink():
                    selected.unlink()
        # Remove the hardlink so the original regains its required single link.
        self.assertEqual(original.stat().st_nlink, 1)

    def test_authority_and_secret_inputs_reject_sparse_oversized_files(self) -> None:
        authority = self.root / "oversized-authority.json"
        with authority.open("wb") as stream:
            stream.truncate(MODULE.MAX_AUTHORITY_BYTES + 1)
        os.chmod(authority, 0o600)
        os.environ[MODULE.SELECTOR] = os.fspath(authority)
        os.environ[MODULE.SELECTOR_SHA256] = "0" * 64
        with self.assertRaisesRegex(MODULE.NativeCommandError, "size|single-link"):
            MODULE._load_authority("bench-micro-verify", self.source)

        inputs = self.micro_inputs()
        oversized_key = self.root / "oversized-evaluator-key"
        with oversized_key.open("wb") as stream:
            stream.truncate(1024 * 1024 + 1)
        os.chmod(oversized_key, 0o600)
        inputs["candidate_attestation_key_file"] = os.fspath(oversized_key)
        authority.unlink()
        self.write_authority("bench-micro-verify", inputs)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "single-link"):
            MODULE._load_authority("bench-micro-verify", self.source)

    def test_referenced_paths_reject_a_symlinked_parent_component(self) -> None:
        inputs = self.micro_inputs()
        actual = self.directory("actual-input-parent")
        selected = self.root / "selected-input-parent"
        selected.symlink_to(actual, target_is_directory=True)
        manifest = self.file(
            actual / "manifest.json", b'{"fixture":"symlink-parent"}\n'
        )
        inputs["candidate_manifest"] = os.fspath(selected / manifest.name)
        self.write_authority("bench-micro-verify", inputs)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "symlink|alias"):
            MODULE._load_authority("bench-micro-verify", self.source)

    def test_configured_non_homebrew_runtime_is_live_bound_and_rechecked(self) -> None:
        version = MODULE.REQUIRED_PYTHON_VERSION
        hosted = self.root / "hostedtoolcache/python/3.14.6/arm64/bin"
        hosted.mkdir(parents=True, mode=0o700)
        runtime = self.file(
            hosted / "python3",
            f"#!/bin/sh\nprintf 'Python {version}\\n'\n".encode(),
            mode=0o700,
        )
        digest = hashlib.sha256(runtime.read_bytes()).hexdigest()

        with mock.patch.object(MODULE.sys, "executable", os.fspath(runtime)):
            snapshot = MODULE._snapshot_runtime(os.fspath(runtime), digest, version)
            MODULE._recheck_runtime(snapshot)
        self.assertEqual(snapshot.path, runtime)
        self.assertEqual(snapshot.version, version)
        self.assertEqual(snapshot.version_probe["exit_code"], 0)
        self.assertNotIn("homebrew", os.fspath(snapshot.path).casefold())

    def test_configured_runtime_rejects_wrong_digest_and_group_writable_parent(
        self,
    ) -> None:
        version = MODULE.REQUIRED_PYTHON_VERSION
        hostile = self.root / "group-writable"
        hostile.mkdir(mode=0o700)
        os.chmod(hostile, 0o770)
        runtime = self.file(
            hostile / "python3",
            f"#!/bin/sh\nprintf 'Python {version}\\n'\n".encode(),
            mode=0o700,
        )
        digest = hashlib.sha256(runtime.read_bytes()).hexdigest()

        with mock.patch.object(MODULE.sys, "executable", os.fspath(runtime)):
            with self.assertRaisesRegex(MODULE.NativeCommandError, "unprotected"):
                MODULE._snapshot_runtime(os.fspath(runtime), digest, version)

        os.chmod(hostile, 0o700)
        with mock.patch.object(MODULE.sys, "executable", os.fspath(runtime)):
            with self.assertRaisesRegex(MODULE.NativeCommandError, "SHA-256"):
                MODULE._snapshot_runtime(os.fspath(runtime), "0" * 64, version)

    def test_referenced_file_rejects_link_and_mutation_after_preflight(self) -> None:
        inputs = self.micro_inputs()
        target = Path(str(inputs["candidate_manifest"]))
        alias = self.root / "candidate-hardlink"
        os.link(target, alias)
        inputs["candidate_manifest"] = os.fspath(alias)
        self.write_authority("bench-micro-verify", inputs)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "single-link"):
            MODULE._load_authority("bench-micro-verify", self.source)
        alias.unlink()
        (self.root / "authority.json").unlink()
        authority = self.load("bench-micro-verify")
        mutable = authority.files["candidate_samples"].path
        replacement = mutable.with_name("replacement")
        replacement.write_bytes(mutable.read_bytes())
        os.chmod(replacement, 0o600)
        os.replace(replacement, mutable)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "changed|substituted"):
            authority.recheck()

    def test_portable_alias_check_is_fail_closed(self) -> None:
        self.write_authority("bench-micro-verify", self.micro_inputs())
        with mock.patch.object(MODULE, "_portable_key", return_value="same"):
            with self.assertRaisesRegex(MODULE.NativeCommandError, "alias"):
                MODULE._load_authority("bench-micro-verify", self.source)

    def test_distinct_directory_roles_cannot_alias_one_location(self) -> None:
        inputs = self.route_inputs("package-all")
        inputs["output_root"] = inputs["portable_workspace"]
        self.write_authority("package-all", inputs)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "alias one location"):
            MODULE._load_authority("package-all", self.source)

    def test_benchmark_candidate_and_baseline_must_be_independent(self) -> None:
        inputs = self.micro_inputs()
        inputs["baseline_samples"] = inputs["candidate_samples"]
        self.write_authority("bench-micro-verify", inputs)
        with self.assertRaisesRegex(MODULE.NativeCommandError, "not independent"):
            MODULE._load_authority("bench-micro-verify", self.source)

    def test_signing_trust_policy_rejects_revoked_wrong_scope_and_stale_identity(
        self,
    ) -> None:
        inputs = self.route_inputs("release-sign")
        policy_path = Path(str(inputs["trust_policy"]))
        baseline = json.loads(policy_path.read_bytes())

        self.write_authority("release-sign", inputs)
        authority = MODULE._load_authority("release-sign", self.source)
        with mock.patch.object(
            MODULE, "release_public_key_id", return_value="sha256:" + "b" * 64
        ):
            MODULE._validate_signing_trust_policy(authority)

        cases = {
            "revoked": lambda entry: entry.update(status="revoked"),
            "principal": lambda entry: entry.update(signer_principal="other-owner"),
            "purpose": lambda entry: entry.update(purposes=["release-sbom"]),
            "activation": lambda entry: entry.update(active_from=1_800_000_001),
            "retired": lambda entry: entry.update(retired_at=1_650_000_000),
            "key-id": lambda entry: entry.update(key_id="sha256:" + "c" * 64),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                document = json.loads(json.dumps(baseline))
                mutate(document["keys"][0])
                policy_path.write_bytes(MODULE.canonical_json_bytes(document))
                os.chmod(policy_path, 0o600)
                authority_path = self.root / "authority.json"
                authority_path.unlink()
                self.write_authority("release-sign", inputs)
                candidate = MODULE._load_authority("release-sign", self.source)
                with (
                    mock.patch.object(
                        MODULE,
                        "release_public_key_id",
                        return_value="sha256:" + "b" * 64,
                    ),
                    self.assertRaises(MODULE.NativeCommandError),
                ):
                    MODULE._validate_signing_trust_policy(candidate)

    def test_supporting_signature_set_is_exact_and_rejects_missing_or_extra(
        self,
    ) -> None:
        inputs = self.route_inputs("release-sign")
        dist = Path(str(inputs["artifact_root"])) / "dist"
        required: dict[str, str] = {"payload.bin": "release-artifact"}
        for name, purpose in (
            ("SHA256SUMS", "release-checksums"),
            ("sbom.spdx.json", "release-sbom"),
            ("sbom.cyclonedx.json", "release-sbom"),
            ("sbom-artifacts.json", "release-sbom"),
            ("provenance.json", "release-provenance"),
        ):
            self.file(dist / name, f"fixture:{name}".encode())
            required[name] = purpose
        for category in ("conformance", "benchmark"):
            attachment_relative = f"evidence/{category}.raw"
            attachment = self.file(
                dist / attachment_relative, f"{category}-evidence".encode()
            )
            receipt_relative = f"evidence/{category}.json"
            receipt = {
                "schema_version": "cigar.qualification-evidence.v1",
                "id": f"{category}-fixture",
                "category": category,
                "source_revision": self.source["revision"],
                "status": "passed",
                "artifact_ids": ["fixture"],
                "producer": {"name": "fixture"},
                "checks": [],
                "metrics": {},
                "attachments": [
                    {
                        "path": attachment_relative,
                        "sha256": hashlib.sha256(attachment.read_bytes()).hexdigest(),
                        "bytes": attachment.stat().st_size,
                        "media_type": "application/octet-stream",
                    }
                ],
            }
            self.file(dist / receipt_relative, MODULE.canonical_json_bytes(receipt))
            required[receipt_relative] = f"release-{category}"
            required[attachment_relative] = f"release-{category}"
        inputs["payloads"] = [
            {"path": path, "purpose": purpose}
            for path, purpose in sorted(required.items())
        ]
        self.write_authority("release-sign", inputs)
        authority = MODULE._load_authority("release-sign", self.source)
        MODULE._require_exact_supporting_signature_set(
            authority, dist, [{"path": "payload.bin"}]
        )

        original = list(authority.inputs["payloads"])
        authority.inputs["payloads"] = original[:-1]
        with self.assertRaisesRegex(MODULE.NativeCommandError, "exact supporting"):
            MODULE._require_exact_supporting_signature_set(
                authority, dist, [{"path": "payload.bin"}]
            )
        authority.inputs["payloads"] = [
            *original,
            {"path": "unreviewed.bin", "purpose": "release-artifact"},
        ]
        with self.assertRaisesRegex(MODULE.NativeCommandError, "exact supporting"):
            MODULE._require_exact_supporting_signature_set(
                authority, dist, [{"path": "payload.bin"}]
            )

    def test_safe_relative_directory_rejects_escape_absolute_and_ambiguity(
        self,
    ) -> None:
        for value in (
            "",
            ".",
            "..",
            "../dist",
            "dist/../x",
            "dist//x",
            "/private/tmp/dist",
            "C:/dist",
            "dist\\x",
        ):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.NativeCommandError):
                    MODULE._safe_relative(value, "candidate")
        root = MODULE.DirectorySnapshot(
            self.root,
            self.root.stat().st_dev,
            self.root.stat().st_ino,
            self.root.stat().st_mode,
            os.geteuid(),
        )
        candidate = self.directory("dist")
        self.assertEqual(MODULE._resolve_beneath(root, "dist", "candidate"), candidate)

    def test_child_environment_removes_authority_and_execution_controls(self) -> None:
        hostile = {
            MODULE.SELECTOR: "/private/tmp/secret-authority",
            "CIGAR_EVIDENCE_DIR": "/private/tmp/evidence",
            "PYTHONPATH": "/attacker",
            "RUSTFLAGS": "--cfg attacker",
            "HTTP_PROXY": "http://attacker.invalid",
            "https_proxy": "http://attacker.invalid",
            "OPENSSL_CONF": "/attacker/openssl.cnf",
            "OPENSSL_MODULES": "/attacker/modules",
            "DYLD_INSERT_LIBRARIES": "/attacker/inject.dylib",
            "AWS_SECRET_ACCESS_KEY": "never-forward",
            "GITHUB_TOKEN": "never-forward",
            "SSH_AUTH_SOCK": "/attacker/agent",
            "PATH": "/attacker/bin",
            "HOME": "/attacker/home",
            "CARGO_HOME": "/attacker/cargo",
        }
        with mock.patch.dict(
            os.environ,
            hostile,
        ):
            environment = MODULE._child_environment(source_date_epoch=123)
        for name in hostile:
            if name in {"HOME", "PATH"}:
                self.assertNotEqual(environment[name], hostile[name])
                continue
            self.assertNotIn(name, environment)
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "123")
        self.assertEqual(environment["PATH"], MODULE.SYSTEM_PATH)

    def test_content_free_raw_retains_no_authority_or_secret_path(self) -> None:
        evidence = self.directory("command-evidence")
        secret_path = self.input_file("never-retained-key", b"secret")
        MODULE._publish_raw(
            evidence,
            "bench-micro-verify",
            self.source,
            {
                "path": os.fspath(Path(sys.executable).resolve(strict=True)),
                "bytes": Path(sys.executable).resolve(strict=True).stat().st_size,
                "sha256": hashlib.sha256(
                    Path(sys.executable).resolve(strict=True).read_bytes()
                ).hexdigest(),
                "authority": "operator-reviewed-sha256",
                "limitation": "transitive-runtime-files-not-bound",
                "version": MODULE.REQUIRED_PYTHON_VERSION,
                "version_probe": {
                    "exit_code": 0,
                    "stdout_bytes": len(
                        f"Python {MODULE.REQUIRED_PYTHON_VERSION}\n".encode()
                    ),
                    "stdout_sha256": hashlib.sha256(
                        f"Python {MODULE.REQUIRED_PYTHON_VERSION}\n".encode()
                    ).hexdigest(),
                    "stderr_bytes": 0,
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "version": MODULE.REQUIRED_PYTHON_VERSION,
                },
            },
            {
                "closure": {
                    relative: {
                        "bytes": (ROOT / relative).stat().st_size,
                        "sha256": hashlib.sha256(
                            (ROOT / relative).read_bytes()
                        ).hexdigest(),
                    }
                    for relative in MODULE.PRODUCER_CLOSURE
                }
            },
            {"bytes": 42, "sha256": "a" * 64},
            [
                MODULE.Execution(
                    "qualified performance replay",
                    0,
                    0,
                    hashlib.sha256(b"").hexdigest(),
                    0,
                    hashlib.sha256(b"").hexdigest(),
                )
            ],
            [{"role": "comparison", "bytes": 9, "sha256": "b" * 64}],
            {"qualified": True},
        )
        raw_path = evidence / "command-plane/bench-micro-verify.raw.json"
        payload = raw_path.read_bytes()
        self.assertEqual(stat.S_IMODE(raw_path.stat().st_mode), 0o400)
        self.assertNotIn(os.fspath(self.root).encode(), payload)
        self.assertNotIn(secret_path.encode(), payload)
        document = json.loads(payload)
        self.assertFalse(document["details"]["fuzz_executed"])
        self.assertFalse(document["details"]["soak_executed"])
        self.assertFalse(document["details"]["hundred_gib_scale_executed"])

    def test_tool_runner_caps_output_and_kills_descendant_group_on_timeout(
        self,
    ) -> None:
        with mock.patch.object(MODULE, "MAX_TOOL_OUTPUT_BYTES", 1024):
            with self.assertRaisesRegex(
                MODULE.NativeCommandError, "could not complete"
            ):
                MODULE._run_tool(
                    "oversized-output fixture",
                    [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2048)"],
                    10,
                    MODULE._child_environment(),
                )

        marker = self.root / "timeout-grandchild-marker"
        child = (
            "import pathlib,time; "
            "time.sleep(0.6); "
            f"pathlib.Path({os.fspath(marker)!r}).write_text('survived')"
        )
        parent = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
            "time.sleep(10)"
        )
        with self.assertRaisesRegex(MODULE.NativeCommandError, "could not complete"):
            MODULE._run_tool(
                "timeout process-group fixture",
                [sys.executable, "-c", parent],
                0.1,
                MODULE._child_environment(),
            )
        time.sleep(0.8)
        self.assertFalse(marker.exists())

    def test_micro_and_macro_dispatch_only_replay_and_verify_existing_evidence(
        self,
    ) -> None:
        for route, expected_tools in (
            ("bench-micro-verify", ["qualified performance replay"]),
            (
                "bench-macro-verify",
                [
                    "qualified performance replay",
                    "physical local-scale receipt verifier",
                ],
            ),
        ):
            with self.subTest(route=route):
                authority_path = self.root / "authority.json"
                if authority_path.exists():
                    authority_path.unlink()
                authority = self.load(route)
                observed: list[tuple[str, list[str]]] = []

                def runner(tool, command, _timeout, _environment):
                    observed.append((tool, list(command)))
                    empty = hashlib.sha256(b"").hexdigest()
                    return MODULE.Execution(tool, 0, 0, empty, 0, empty), b""

                executions, _outputs, details = MODULE._execute_route(
                    authority, None, runner
                )
                self.assertEqual([item.tool for item in executions], expected_tools)
                self.assertIn("replay", observed[0][1])
                self.assertNotIn("attest", observed[0][1])
                if route == "bench-macro-verify":
                    self.assertEqual(observed[1][1][1], "verify")
                    self.assertTrue(details["physical_scale_receipt_verified"])

    def test_performance_route_rejects_legacy_status_only_report(self) -> None:
        inputs = self.micro_inputs()
        inputs["comparison_report"] = self.input_file(
            "legacy-comparison-report",
            MODULE.canonical_json_bytes({"status": "pass"}),
        )
        authority = self.load("bench-micro-verify", inputs)

        def runner(tool, _command, _timeout, _environment):
            empty = hashlib.sha256(b"").hexdigest()
            return MODULE.Execution(tool, 0, 0, empty, 0, empty), b""

        with self.assertRaisesRegex(MODULE.NativeCommandError, "not passing"):
            MODULE._execute_route(authority, None, runner)

    def test_package_all_runs_all_producers_then_assembly_without_ambient_state(
        self,
    ) -> None:
        authority = self.load("package-all")
        observed: list[tuple[str, list[str], dict[str, str]]] = []
        hostile_names = {
            "HTTP_PROXY",
            "OPENSSL_CONF",
            "OPENSSL_MODULES",
            "DYLD_INSERT_LIBRARIES",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            MODULE.SELECTOR,
        }

        def runner(tool, command, _timeout, environment):
            selected = dict(environment)
            observed.append((tool, list(command), selected))
            self.assertTrue(hostile_names.isdisjoint(selected))
            empty = hashlib.sha256(b"").hexdigest()
            execution = MODULE.Execution(tool, 0, 0, empty, 0, empty)
            if tool == "17-artifact macOS assembler":
                output = authority.directories["output_root"].path
                self.file(output / "release-build.json", b'{"fixture":"manifest"}\n')
                self.file(output / "SHA256SUMS", b"a" * 64 + b"  fixture\n")
            if tool == "17-artifact assembly verifier":
                payload = {
                    "status": "verified-development-only",
                    "artifact_count": 17,
                    "source": {
                        "revision": self.source["revision"],
                        "committed": True,
                        "clean": True,
                    },
                }
                return execution, MODULE.canonical_json_bytes(payload)
            return execution, b""

        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://attacker.invalid",
                "OPENSSL_CONF": "/attacker/openssl.cnf",
                "OPENSSL_MODULES": "/attacker/modules",
                "DYLD_INSERT_LIBRARIES": "/attacker/inject.dylib",
                "AWS_SECRET_ACCESS_KEY": "never-forward",
                "GITHUB_TOKEN": "never-forward",
            },
        ):
            executions, _outputs, details = MODULE._execute_route(
                authority, None, runner
            )
        self.assertEqual(len(executions), 12)
        self.assertEqual(details["producer_count"], 10)
        self.assertEqual(observed[-2][0], "17-artifact macOS assembler")
        self.assertEqual(observed[-1][0], "17-artifact assembly verifier")
        rendered = " ".join(" ".join(command) for _, command, _ in observed)
        for producer in (
            "build_archives.py",
            "build_macos_aarch64_archive.py",
            "build_macos_qualification_tools.py",
            "build_macos_homebrew_artifacts.py",
            "build_typescript_sdk.py",
            "build_rust_sdk_crate.py",
            "build_python_sdk_artifacts.py",
            "build_go_sdk.py",
            "build_claude_code_plugin.py",
        ):
            self.assertIn(producer, rendered)
        self.assertNotIn("fuzz", rendered)
        self.assertNotIn("soak", rendered)

    def test_sanitizer_route_rejects_unrelated_authority_and_has_no_fuzz_or_soak(
        self,
    ) -> None:
        os.environ[MODULE.SELECTOR] = self.input_file("unrelated-authority")
        with self.assertRaisesRegex(MODULE.NativeCommandError, "rejects"):
            MODULE.main(
                [
                    "run",
                    "--root",
                    os.fspath(MODULE.REPOSITORY_ROOT),
                    "--route",
                    "test-sanitizers",
                    "--expected-source",
                    json.dumps(self.source),
                    "--evidence-dir",
                    os.fspath(self.directory("sanitizer-evidence")),
                    "--expected-python-path",
                    os.fspath(Path(sys.executable).resolve(strict=True)),
                    "--expected-python-sha256",
                    hashlib.sha256(
                        Path(sys.executable).resolve(strict=True).read_bytes()
                    ).hexdigest(),
                    "--expected-python-version",
                    MODULE.REQUIRED_PYTHON_VERSION,
                ]
            )

    def test_sanitizer_dispatch_uses_only_public_manifest_run_verify_contract(
        self,
    ) -> None:
        observed: list[list[str]] = []

        def runner(tool, command, _timeout, _environment):
            rendered = list(command)
            observed.append(rendered)
            empty = hashlib.sha256(b"").hexdigest()
            execution = MODULE.Execution(tool, 0, 0, empty, 0, empty)
            action = rendered[2]
            if action == "verify-manifest":
                payload = {
                    "case_ids": [f"case-{index}" for index in range(10)],
                    "test_exclusions": [],
                    "fuzz_built_or_run": False,
                    "soak_built_or_run": False,
                }
            elif action == "run":
                receipt = Path(rendered[rendered.index("--receipt") + 1])
                receipt.write_bytes(b'{"receipt":"content-free"}\n')
                os.chmod(receipt, 0o600)
                payload = {}
            else:
                payload = {
                    "source": {"revision": self.source["revision"]},
                    "claims": {
                        "sanitizer_checks_passed": True,
                        "release_eligible": False,
                        "fuzz_built_or_run": False,
                        "soak_built_or_run": False,
                        "test_exclusions": [],
                    },
                }
            return execution, MODULE.canonical_json_bytes(payload)

        executions, outputs, details = MODULE._execute_sanitizers(self.source, runner)
        self.assertEqual(
            [command[2] for command in observed],
            ["verify-manifest", "run", "verify-receipt"],
        )
        self.assertEqual(len(executions), 3)
        self.assertEqual(details["case_count"], 10)
        self.assertEqual(len(outputs), 1)
        rendered = " ".join(" ".join(command) for command in observed)
        self.assertNotIn("fuzz", rendered)
        self.assertNotIn("soak", rendered)


if __name__ == "__main__":
    unittest.main()
