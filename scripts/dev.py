#!/usr/bin/env python3
"""Ordinary source diagnostics; these commands do not create release qualification receipts."""
from __future__ import annotations

import argparse
import os
import json
from pathlib import Path
import shutil
import re
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("context", "compiler", "workspace"), nargs="?", default="context")
    parser.add_argument("--cargo", default=shutil.which("cargo"))
    parser.add_argument("--tests-only", action="store_true", help="Run tests and documentation examples without formatting/lint steps")
    parser.add_argument("--test-threads", type=int, default=1 if sys.platform == "darwin" else None,
                        help="Test-harness concurrency; defaults to 1 on macOS to match .config/nextest.toml qualification isolation")
    parser.add_argument("--log-dir", type=Path, help="Create a new directory with complete logs and exit-code/test-count records")
    args = parser.parse_args()
    if args.test_threads is not None and args.test_threads < 1:
        parser.error("--test-threads must be positive")
    if not args.cargo:
        parser.error("Cargo is not on PATH; pass --cargo /absolute/toolchain/bin/cargo")
    # Preserve argv[0] for rustup's cargo symlink; resolving it to "rustup" changes dispatch.
    cargo = Path(args.cargo).absolute()
    if not cargo.is_file():
        parser.error("Cargo executable does not exist")
    root = Path(__file__).resolve().parent.parent
    environment = dict(os.environ)
    environment["PATH"] = str(cargo.parent) + os.pathsep + environment.get("PATH", "")
    selection = {
        "context": ["-p", "cigar-context", "--all-features"],
        "compiler": ["-p", "cigar-compiler"],
        "workspace": ["--workspace"],
    }[args.suite]
    fmt = ["fmt", "--all", "--", "--check"] if args.suite == "workspace" else ["fmt", "-p", "cigar-" + args.suite, "--", "--check"]
    lint = ["clippy", "--locked", *selection, "--all-targets"]
    if args.suite == "workspace":
        lint += ["--exclude", "cigar-soak"]
    commands = [] if args.tests_only else [fmt, [*lint, "--", "-D", "warnings"]]
    commands.append(["test", "--locked", *selection, "--all-targets", "--no-fail-fast"])
    commands.append(["test", "--locked", *selection, "--doc"])
    if args.suite == "context":
        commands.append(["test", "--locked", "-p", "cigar-context", "--no-default-features"])
    if args.test_threads is not None:
        for command in commands:
            if command[0] == "test": command.extend(["--", f"--test-threads={args.test_threads}"])
    records = []
    if args.log_dir:
        args.log_dir.mkdir(parents=True, exist_ok=False)
    for index, command in enumerate(commands):
        print("+ " + " ".join([str(cargo), *command]), flush=True)
        result = subprocess.run([str(cargo), *command], cwd=root, env=environment, check=False,
                                stdout=subprocess.PIPE if args.log_dir else None,
                                stderr=subprocess.STDOUT if args.log_dir else None, text=True)
        if args.log_dir:
            log_name = f"{index:02d}-{command[0]}.log"
            (args.log_dir/log_name).write_text(result.stdout)
            totals = [tuple(map(int,m)) for m in re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;',result.stdout)]
            record = {"command":command,"exit_code":result.returncode,"log":log_name,
                      "passed_invocations":sum(x[0] for x in totals),
                      "failed_invocations":sum(x[1] for x in totals),"ignored_invocations":sum(x[2] for x in totals)}
            records.append(record)
            (args.log_dir/'validation.json').write_text(json.dumps(records,indent=2)+'\n')
            print(json.dumps(record),flush=True)
            if result.returncode: print(result.stdout,flush=True)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
