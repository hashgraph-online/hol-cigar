#!/usr/bin/env python3
"""Build each version's unchanged worker source against its exact local core."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "LANG", "USER", "LOGNAME") if key in os.environ}
    env.update({"PATH": str(args.cargo.parent) + os.pathsep + env.get("PATH", ""), "CARGO_NET_OFFLINE": "true"})
    receipt = {"schema": "cigar.tracking-workers.v1", "builds": {}}
    for name, checkout, version in [("baseline", args.baseline, "0.10.0-beta.1"), ("candidate", ROOT, "0.11.0")]:
        package = checkout / "crates/cigar-context"
        assert tomllib.loads((package / "Cargo.toml").read_text())["package"]["version"] == version
        path = args.output / name
        path.mkdir()
        manifest = f'''[package]
name = "cigar-tracking-worker"
version = {json.dumps(version)}
edition = "2024"
[workspace]
[dependencies]
cigar-context = {{ path = {json.dumps(str(package))}, features = ["bpe"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
[[bin]]
name = "cigar-context-worker"
path = {json.dumps(str(package / "src/worker.rs"))}
[profile.release]
codegen-units = 1
lto = "thin"
'''
        (path / "Cargo.toml").write_text(manifest)
        (path / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        # Normalize the seed workspace lock offline once, then enforce it for the build.
        for command in [[str(args.cargo), "generate-lockfile", "--offline"], [str(args.cargo), "build", "--release", "--offline", "--locked"]]:
            result = subprocess.run(command, cwd=path, env=env, capture_output=True, check=False)
            (path / ("lock.log" if "generate-lockfile" in command else "build.log")).write_bytes(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(result.stderr.decode())
        lock = tomllib.loads((path / "Cargo.lock").read_text())
        core = [p for p in lock["package"] if p["name"] == "cigar-context"]
        assert len(core) == 1 and core[0]["version"] == version and "source" not in core[0]
        binary = path / "target/release/cigar-context-worker"
        files = [package / "Cargo.toml", *sorted((package / "src").glob("*.rs"))]
        receipt["builds"][name] = {
            "version": version, "binary": str(binary),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source": {str(p.relative_to(checkout)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
            "source_root": str(checkout),
            "checkout_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip(),
            "registry": [p for p in lock["package"] if p.get("source")],
            "provenance": "Unmodified version-specific worker.rs compiled in an isolated package with the same version, against that exact path dependency; identical release settings and registry records.",
        }
        print(json.dumps({"built": name, "version": version}), flush=True)
    assert receipt["builds"]["baseline"]["registry"] == receipt["builds"]["candidate"]["registry"]
    (args.output / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
