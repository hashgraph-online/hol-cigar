"""Freeze and run the registered offline retrieval study with exact SDK bytes.

Freeze before acquiring/preparing the held-out corpus. The run command reads
only queries and corpus; score is a separate invocation after prediction sealing.
No downloaded program is executed. SDKs/workers are explicit caller-trusted
artifacts and run with local privileges, just as in ordinary SDK qualification.
"""

from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

from scifact import CONFIG, decode, encoded, file_digest, require, source_identity

ROOT = Path(__file__).resolve().parents[1]


def freeze(args):
    output = args.output.resolve()
    require(not output.exists(), "study directory already exists")
    require(
        args.python.is_file() and args.candidate_worker.is_file(),
        "explicit runtime unavailable",
    )
    output.mkdir(mode=0o700)
    for path in (
        "benchmarks/scifact.py",
        "benchmarks/run_scifact.py",
        "benches/context-evaluation/evaluation.py",
        "benches/context-evaluation/import_scifact.py",
        "sdk/python/src/cigar_sdk/examples/scoped_retrieval.py",
        "docs/proposals/context-retrieval-evaluation-0.14.0.md",
    ):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    artifacts = []

    def artifact(name, role, path):
        artifacts.append(
            {
                "id": name,
                "role": role,
                "path": path.relative_to(output).as_posix(),
                "sha256": file_digest(path),
                "bytes": path.stat().st_size,
            }
        )

    baseline_root = output / "runtimes/v012/cigar_sdk"
    baseline_root.mkdir(parents=True)
    wheel = output / "baseline.whl"
    shutil.copyfile(args.baseline_wheel, wheel)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(
            len(names) == len(set(names))
            and len(names) <= 10_000
            and sum(info.file_size for info in archive.infolist()) <= 1024**3,
            "invalid wheel inventory",
        )
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "wheel metadata missing")
        fields = BytesParser().parsebytes(archive.read(metadata[0]))
        require(
            fields["Name"] == "hol-cigar" and fields["Version"] == "0.12.0",
            "baseline must be exact v0.12 distribution",
        )
        workers = []
        for name in names:
            if not name.startswith("cigar_sdk/") or name.endswith("/"):
                continue
            pieces = name.removeprefix("cigar_sdk/").split("/")
            require(
                all(
                    part
                    and part not in {".", ".."}
                    and "\\" not in part
                    and ":" not in part
                    for part in pieces
                ),
                "invalid wheel member path",
            )
            if "_native" in pieces:
                if pieces[-1] in {"cigar-context-worker", "cigar-context-worker.exe"}:
                    workers.append(archive.read(name))
            elif "__pycache__" not in pieces and not name.endswith(".pyc"):
                target = baseline_root.joinpath(*pieces)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
        require(len(workers) == 1, "baseline must have exactly one native worker")
    baseline_worker = output / "runtimes/v012/worker"
    baseline_worker.write_bytes(workers[0])
    baseline_worker.chmod(0o700)
    artifact("baseline-package", "package", wheel)
    candidate_root = output / "runtimes/v014/cigar_sdk"
    candidate_root.mkdir(parents=True)
    for source in sorted(args.candidate_sdk.rglob("*")):
        parts = source.relative_to(args.candidate_sdk).parts
        if (
            not source.is_file()
            or "_native" in parts
            or "__pycache__" in parts
            or source.suffix == ".pyc"
        ):
            continue
        require(not source.is_symlink(), "candidate SDK symlink not allowed")
        target = candidate_root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    candidate_worker = output / "runtimes/v014/worker"
    shutil.copyfile(args.candidate_worker, candidate_worker)
    candidate_worker.chmod(0o700)
    artifact("candidate-worker", "worker", candidate_worker)
    package = output / "candidate-sdk.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(candidate_root.rglob("*")):
            if source.is_file():
                entry = zipfile.ZipInfo(
                    "cigar_sdk/" + source.relative_to(candidate_root).as_posix(),
                    date_time=(2000, 1, 1, 0, 0, 0),
                )
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, source.read_bytes())
    artifact("candidate-package", "package", package)
    recipe = output / "sdk/python/src/cigar_sdk/examples/scoped_retrieval.py"
    artifact("adapter", "harness", recipe)
    identities = {}
    for label, version, commit, sdk, worker in (
        ("v012", "0.12.0", args.baseline_commit, baseline_root, baseline_worker),
        (
            "v014",
            "0.14.0-development",
            args.candidate_commit,
            candidate_root,
            candidate_worker,
        ),
    ):
        require(
            len(commit) == 40
            and all(character in "0123456789abcdef" for character in commit),
            "invalid source commit",
        )
        identities[label] = {
            "version": version,
            "source_commit": commit,
            "worker_source_commit": args.baseline_commit
            if label == "v012"
            else args.candidate_worker_commit,
            "sdk_source_sha256": source_identity(sdk),
            "worker_sha256": file_digest(worker),
            "recipe_sha256": file_digest(recipe),
            "harness_sha256": file_digest(output / "benchmarks/scifact.py"),
        }
        (output / f"{label}-identity.json").write_bytes(encoded(identities[label]))
    treatments = []
    for label, mode in (
        ("v012", "default"),
        ("v014", "default"),
        ("v012", "ranked"),
        ("v014", "ranked"),
        ("v012", "flat"),
    ):
        identity = identities[label]
        bindings = (
            ["baseline-package"]
            if label == "v012"
            else ["candidate-package", "candidate-worker"]
        )
        if mode != "default":
            bindings.append("adapter")
        treatments.append(
            {
                "id": f"{label}-{mode}",
                "version": identity["version"],
                "source_commit": identity["source_commit"],
                "artifacts": bindings,
                "settings": {"mode": mode, "identity": identity},
            }
        )
    registration = {
        "schema": "cigar.scifact-study.v1",
        "configuration": CONFIG,
        "harness_sha256": file_digest(output / "benchmarks/scifact.py"),
        "scorer_sha256": file_digest(
            output / "benches/context-evaluation/import_scifact.py"
        ),
        "artifacts": artifacts,
        "treatments": treatments,
        "python": str(args.python.absolute()),
    }
    (output / "registration.json").write_bytes(encoded(registration))
    print(
        encoded(
            {
                "registration_sha256": file_digest(output / "registration.json"),
                "study": str(output),
            }
        ).decode(),
        end="",
    )


def run(study: Path):
    study = study.resolve()
    require(
        not (study / "predictions-frozen.json").exists(), "predictions already sealed"
    )
    registration_bytes = (study / "registration.json").read_bytes()
    registration = decode(registration_bytes)
    require(registration["configuration"] == CONFIG, "configuration mismatch")
    cells = []
    for budget in CONFIG["budgets"]:
        for treatment in registration["treatments"]:
            label = treatment["id"].split("-")[0]
            destination = study / f"predictions/{treatment['id']}-{budget}"
            require(not destination.exists(), "prediction cell already exists")
            destination.parent.mkdir(exist_ok=True)
            command = [
                registration["python"],
                str(study / "benchmarks/scifact.py"),
                "consume",
                "--data",
                str(study / "data"),
                "--identity",
                str(study / f"{label}-identity.json"),
                "--recipe",
                str(study / "sdk/python/src/cigar_sdk/examples/scoped_retrieval.py"),
                "--worker",
                str(study / f"runtimes/{label}/worker"),
                "--mode",
                treatment["settings"]["mode"],
                "--budget",
                str(budget),
                "--output",
                str(destination),
            ]
            environment = {
                "PATH": os.defpath,
                "PYTHONPATH": str(study / f"runtimes/{label}"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "LC_ALL": "C",
            }
            with (destination.parent / (destination.name + ".log")).open("xb") as log:
                result = subprocess.run(
                    command,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=1800,
                )
            require(
                result.returncode == 0, f"prediction cell failed: {destination.name}"
            )
            path = destination / "summary.json"
            cells.append(
                {
                    "treatment": treatment["id"],
                    "budget": budget,
                    "summary_path": path.relative_to(study).as_posix(),
                    "summary_sha256": file_digest(path),
                }
            )
            print(destination.name, flush=True)
    require(
        (study / "registration.json").read_bytes() == registration_bytes,
        "registration changed during predictions",
    )
    seal = {
        "schema": "cigar.scifact-prediction-seal.v1",
        "registration_sha256": hashlib.sha256(registration_bytes).hexdigest(),
        "cells": cells,
    }
    with (study / "predictions-frozen.json").open("xb") as stream:
        stream.write(encoded(seal))


def score(study: Path):
    study = study.resolve()
    registration = json.loads((study / "registration.json").read_bytes())
    output = study / "comparisons"
    output.mkdir()
    for baseline, candidate in (
        ("v012-default", "v014-default"),
        ("v014-default", "v014-ranked"),
        ("v012-ranked", "v014-ranked"),
        ("v012-flat", "v014-ranked"),
    ):
        for budget in CONFIG["budgets"]:
            destination = output / f"{baseline}-{candidate}-{budget}"
            subprocess.run(
                [
                    registration["python"],
                    str(study / "benches/context-evaluation/import_scifact.py"),
                    "--study",
                    str(study),
                    "--baseline",
                    baseline,
                    "--candidate",
                    candidate,
                    "--budget",
                    str(budget),
                    "--output",
                    str(destination),
                ],
                check=True,
                timeout=600,
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freezing = commands.add_parser("freeze")
    for name in (
        "output",
        "python",
        "baseline-wheel",
        "candidate-sdk",
        "candidate-worker",
    ):
        freezing.add_argument(f"--{name}", type=Path, required=True)
    for name in ("baseline-commit", "candidate-commit", "candidate-worker-commit"):
        freezing.add_argument(f"--{name}", required=True)
    for name in ("run", "score"):
        commands.add_parser(name).add_argument("--study", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze(args)
    elif args.command == "run":
        run(args.study)
    else:
        score(args.study)


if __name__ == "__main__":
    main()
