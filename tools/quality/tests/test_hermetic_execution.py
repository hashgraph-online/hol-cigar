from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.quality import hermetic_execution


class HermeticExecutionTests(unittest.TestCase):
    def test_generated_cargo_wrapper_injects_global_locked_offline_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            real_cargo = base / "real-cargo"
            real_cargo.write_text(
                f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n",
                encoding="utf-8",
            )
            real_cargo.chmod(0o700)
            wrapper = base / "cargo"
            wrapper.write_bytes(
                hermetic_execution.cargo_wrapper_source(
                    real_cargo=str(real_cargo), python=sys.executable
                )
            )
            wrapper.chmod(0o700)

            def arguments(*items: str) -> list[str]:
                process = subprocess.run(
                    [str(wrapper), *items],
                    cwd=base,
                    env={"PATH": os.environ.get("PATH", "")},
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return json.loads(process.stdout)

            self.assertEqual(
                arguments("+nightly", "fuzz", "cmin", "target"),
                ["+nightly", "--locked", "--offline", "fuzz", "cmin", "target"],
            )
            self.assertEqual(
                arguments("metadata", "--no-deps"),
                ["--locked", "--offline", "metadata", "--no-deps"],
            )
            self.assertEqual(
                arguments("run", "--package", "xtask"),
                ["--locked", "--offline", "run", "--package", "xtask"],
            )

    def test_direct_cargo_fuzz_forces_inner_cargo_through_nightly_wrapper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            capture = base / "inner-cargo.json"
            real_cargo = base / "real-cargo"
            real_cargo.write_text(
                "\n".join(
                    (
                        f"#!{sys.executable}",
                        "import json, os, pathlib, sys",
                        f"capture = pathlib.Path({str(capture)!r})",
                        "with capture.open('a', encoding='utf-8') as handle:",
                        "    handle.write(json.dumps({'argv': sys.argv[1:], 'toolchain': os.environ.get('RUSTUP_TOOLCHAIN')}) + '\\n')",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            real_cargo.chmod(0o700)
            wrapper = base / "cargo"
            wrapper.write_bytes(
                hermetic_execution.cargo_wrapper_source(
                    real_cargo=str(real_cargo), python=sys.executable
                )
            )
            wrapper.chmod(0o700)
            fake_cargo_fuzz = base / "cargo-fuzz"
            fake_cargo_fuzz.write_text(
                "\n".join(
                    (
                        f"#!{sys.executable}",
                        "import os, subprocess",
                        "subprocess.run(['cargo', 'build', '--manifest-path', 'fuzz/Cargo.toml'], check=True)",
                        "subprocess.run([os.environ['CARGO'], 'metadata', '--no-deps'], check=True)",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            fake_cargo_fuzz.chmod(0o700)
            home = base / "home"
            temporary = base / "tmp"
            home.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            base_environment = hermetic_execution.sanitized_environment(
                private_home=home,
                private_tmp=temporary,
                ambient={"PATH": str(base) + os.pathsep + "/usr/bin"},
            )
            environment = hermetic_execution.direct_cargo_fuzz_environment(
                base_environment, cargo_wrapper=wrapper
            )
            subprocess.run(
                [str(fake_cargo_fuzz), "run", "target"],
                cwd=base,
                env=environment,
                check=True,
            )
            observed = [
                json.loads(line)
                for line in capture.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                observed[0]["argv"],
                [
                    "--locked",
                    "--offline",
                    "build",
                    "--manifest-path",
                    "fuzz/Cargo.toml",
                ],
            )
            self.assertEqual(
                observed[1]["argv"],
                ["--locked", "--offline", "metadata", "--no-deps"],
            )
            self.assertEqual(
                [entry["toolchain"] for entry in observed],
                ["nightly", "nightly"],
            )
            self.assertEqual(environment["PATH"], str(base) + os.pathsep + "/usr/bin")
            self.assertEqual(environment["CARGO"], str(wrapper))
            self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "nightly")

    def test_environment_drops_credentials_proxies_cloud_ci_and_ssh_agent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            home = base / "home"
            temporary = base / "tmp"
            home.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            environment = hermetic_execution.sanitized_environment(
                private_home=home,
                private_tmp=temporary,
                ambient={
                    "PATH": "/usr/bin",
                    "CARGO_HOME": "/cache/cargo",
                    "RUSTUP_HOME": "/cache/rustup",
                    "SSH_AUTH_SOCK": "/private/agent",
                    "AWS_SECRET_ACCESS_KEY": "secret",
                    "HTTPS_PROXY": "https://credential@example.invalid",
                    "CI_JOB_TOKEN": "token",
                    "GITHUB_TOKEN": "token",
                },
            )
            self.assertEqual(environment["PATH"], "/usr/bin")
            self.assertEqual(environment["HOME"], str(home))
            self.assertEqual(environment["TMPDIR"], str(temporary))
            self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
            for forbidden in (
                "SSH_AUTH_SOCK",
                "AWS_SECRET_ACCESS_KEY",
                "HTTPS_PROXY",
                "CI_JOB_TOKEN",
                "GITHUB_TOKEN",
            ):
                self.assertNotIn(forbidden, environment)

    def test_unreviewed_override_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            home = base / "home"
            temporary = base / "tmp"
            home.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            with self.assertRaises(hermetic_execution.HermeticExecutionError):
                hermetic_execution.sanitized_environment(
                    private_home=home,
                    private_tmp=temporary,
                    overrides={"AWS_ACCESS_KEY_ID": "forbidden"},
                    ambient={},
                )

    def test_darwin_wrapper_is_content_bound_and_other_hosts_fail_closed(self) -> None:
        command, enforcement = hermetic_execution.no_network_command(
            ["/usr/bin/true"], system="Darwin"
        )
        self.assertEqual(command[0], "/usr/bin/sandbox-exec")
        self.assertEqual(enforcement["engine"], "darwin-sandbox-exec")
        self.assertTrue(enforcement["deny_network_star"])
        with self.assertRaises(hermetic_execution.HermeticExecutionError):
            hermetic_execution.no_network_command(["true"], system="Linux")


if __name__ == "__main__":
    unittest.main()
