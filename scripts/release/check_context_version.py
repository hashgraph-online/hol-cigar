"""Validate the existing local SDK identity and reviewed tool policy before builds."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys
import tomllib

from release_lib import reject_evidence_directory

ROOT = Path(__file__).resolve().parents[2]


def validate(root: Path = ROOT, expected: str | None = None) -> dict:
    if sys.flags.optimize:
        raise RuntimeError("release checks require assertions enabled")
    identity = json.loads((root / "sdk/local-context-release.v1.json").read_bytes())
    version = identity["core_version"]
    assert expected is None or version == expected, "unexpected local SDK release"
    assert re.fullmatch(r"0\.\d+\.\d+", version), "invalid local SDK version"
    assert identity["versions"] == {"python": version, "typescript": version}, (
        "SDK identity drift"
    )
    python = tomllib.loads((root / "sdk/python/pyproject.toml").read_text())
    node = json.loads((root / "sdk/typescript/package.json").read_bytes())
    cargo = tomllib.loads((root / "crates/cigar-context/Cargo.toml").read_text())
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    assert (
        python["project"]["version"]
        == node["version"]
        == cargo["package"]["version"]
        == version
    ), "package version drift"
    assert [
        item["version"] for item in lock["package"] if item["name"] == "cigar-context"
    ] == [version], "Cargo lock drift"
    for path in (
        "sdk/python/src/cigar_sdk/release.json",
        "sdk/typescript/release.json",
    ):
        release = json.loads((root / path).read_bytes())
        assert release["version"] == release["local_context_core_version"] == version, (
            path
        )
        assert release["local_context_protocol"] == identity["protocol"], path
        assert (
            release["context_abi"] == identity["context_abi"] == "cigar.context.v1"
        ), path
    tree = ast.parse((root / "sdk/python/src/cigar_sdk/local_runtime.py").read_text())
    constants = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.startswith("LOCAL_CONTEXT_")
    }
    assert constants["LOCAL_CONTEXT_CORE_VERSION"] == version, (
        "Python worker constant drift"
    )
    assert constants["LOCAL_CONTEXT_PROTOCOL"] == identity["protocol"], (
        "Python protocol drift"
    )
    text = (root / "sdk/typescript/src/local-runtime.ts").read_text()
    assert f'LOCAL_CONTEXT_CORE_VERSION = "{version}"' in text, (
        "Node worker constant drift"
    )
    assert f'LOCAL_CONTEXT_PROTOCOL = "{identity["protocol"]}"' in text, (
        "Node protocol drift"
    )
    assert (root / f"docs/release/context-sdk-{version}-notes.md").is_file(), (
        "missing current release notes"
    )
    policy = json.loads((root / "sdk/context-toolchain.v1.json").read_bytes())
    dev = python["dependency-groups"]["dev"]
    for name in ("pytest", "mypy", "ruff"):
        assert f"{name}=={policy['python'][name]}" in dev, f"{name} tool drift"
    assert python["build-system"]["requires"] == [
        f"hatchling=={policy['python']['hatchling']}"
    ], "build tool drift"
    minimum = policy["python"]["protobuf_minimum"]
    assert python["project"]["dependencies"] == [f"protobuf>={minimum},<8"], (
        "runtime dependency range drift"
    )
    checked = 0
    for path in (root / ".github/workflows").glob("*.yml"):
        source = path.read_text()
        for block in re.findall(
            r"uses: astral-sh/setup-uv@[^\n]+\n((?:[ \t]+[^\n]*\n){1,8})", source
        ):
            found = re.search(r'version:\s*["\']([^"\']+)', block)
            assert found and found.group(1) == policy["uv"], (
                f"uv tool drift: {path.name}"
            )
            checked += 1
    assert checked, "no reviewed installer pins found"
    container = (
        root / "scripts/release/containers/context-consumer.Dockerfile"
    ).read_text()
    assert f"ghcr.io/astral-sh/uv:{policy['uv']}@sha256:" in container, (
        "uv container drift"
    )
    return {
        "release": version,
        "protocol": identity["protocol"],
        "uv_pins": checked,
        "status": "passed",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected")
    parser.add_argument(
        "--evidence-dir", type=Path, help="inapplicable to source checks"
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "source version check")
    print(json.dumps(validate(expected=args.expected), sort_keys=True))
