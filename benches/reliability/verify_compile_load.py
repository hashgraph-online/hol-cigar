#!/usr/bin/env python3
"""Independent verifier for bound full/delta compile-load evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

MODULE = Path(__file__).with_name("compile_load.py")
SPEC = importlib.util.spec_from_file_location("cigar_compile_load", MODULE)
assert SPEC is not None and SPEC.loader is not None
compile_load = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compile_load
SPEC.loader.exec_module(compile_load)


def verify(report_path: Path) -> str:
    report = compile_load.load_json(report_path)
    required = {
        "schema_version", "status", "source_revision", "configuration", "driver", "candidate",
        "raw", "queue_capacity_fixed", "all_cells_deterministic", "cells", "report_id",
        "allocation_probe",
    }
    if set(report) != required:
        compile_load.fail("bound compile report fields are invalid")
    report_id = report.pop("report_id")
    if not isinstance(report_id, str) or report_id != hashlib.sha256(compile_load.canonical(report)).hexdigest():
        compile_load.fail("bound compile report identity disagrees")
    if (
        report["schema_version"] != "cigar.h094-bound-compile-load-result.v1"
        or report["status"] != "passed"
        or re.fullmatch(r"[0-9a-f]{40,64}", report["source_revision"]) is None
        or report["queue_capacity_fixed"] is not True
        or report["all_cells_deterministic"] is not True
    ):
        compile_load.fail("bound compile report status is invalid")
    configuration_path = compile_load.fingerprint(Path(report["configuration"]["path"]))
    driver = compile_load.fingerprint(Path(report["driver"]["path"]))
    candidate = compile_load.fingerprint(Path(report["candidate"]["path"]))
    raw_binding = compile_load.fingerprint(Path(report["raw"]["path"]))
    for observed, expected in (
        (configuration_path, report["configuration"]),
        (driver, report["driver"]),
        (candidate, report["candidate"]),
        (raw_binding, report["raw"]),
    ):
        if observed != expected:
            compile_load.fail("bound compile file changed")
    configuration = compile_load.load_json(Path(configuration_path["path"]))
    raw = compile_load.load_json(Path(raw_binding["path"]))
    compile_load.validate_raw(raw, configuration)
    if report["cells"] != raw["cells"] or report["allocation_probe"] != raw["allocation_probe"]:
        compile_load.fail("aggregate compile evidence differs from raw evidence")
    return report_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report_id = verify(arguments.report)
    except compile_load.CompileLoadError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"compile-load evidence verified: {report_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
